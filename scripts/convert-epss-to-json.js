#!/usr/bin/env node

const fs = require('fs/promises');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);
const Papa = require('papaparse');

const DEFAULT_INPUT = 'src/epss_scores-current.csv';
const DEFAULT_OUTPUT = 'src/epss_scores-current.json';
const CVE_ID_PATTERN = /^CVE-(\d{4})-(\d{4,})$/i;
const CVSS_KEYS = ['cvssV4_0', 'cvssV4', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'];
const DEFAULT_VULNREICHMENT_ROOT = path.resolve(process.cwd(), '.cache', 'vulnrichment');
const VULNREICHMENT_REPO = 'https://github.com/cisagov/vulnrichment.git';
const VULNREICHMENT_BRANCH = process.env.VULNREICHMENT_BRANCH || 'develop';

// CONFIGURATION: Edit these constants to enable features
const VERBOSE = true; // Set to true for detailed enrichment logs for every CVE
const ENABLE_NVD = true; // Set to true to fetch missing enrichment from NVD API
const NVD_LIMIT = 100; // Max number of NVD fetches when ENABLE_NVD is true

function printUsage() {
  console.log(`
Usage: node scripts/convert-epss-to-json.js [input] [output] [vulnrichment-path]

Arguments:
  input                 Path to EPSS CSV file (default: src/epss_scores-current.csv)
  output                Path to output JSON file (default: src/epss_scores-current.json)
  vulnrichment-path     Path to vulnrichment dataset (default: auto-downloaded)

Configuration:
  Edit the constants VERBOSE, ENABLE_NVD, NVD_LIMIT in the script to enable features.

Examples:
  npm run convert-epss-json
  npm run convert-epss-json custom.csv custom.json /path/to/vulnrichment
`);
}

const args = process.argv.slice(2);
if (args.includes('--help')) {
  printUsage();
  process.exit(0);
}

let inputPath = DEFAULT_INPUT;
let outputPath = DEFAULT_OUTPUT;
let vulnrichmentPath = null;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (!inputPath || inputPath === DEFAULT_INPUT) {
    inputPath = ensureAbsolute(arg, DEFAULT_INPUT);
  } else if (!outputPath || outputPath === DEFAULT_OUTPUT) {
    outputPath = ensureAbsolute(arg, DEFAULT_OUTPUT);
  } else {
    vulnrichmentPath = resolveOptionalPath(arg);
  }
}

const requestedEnrichmentRoot = vulnrichmentPath || process.env.VULNREICHMENT_DIR;

function resolveOptionalPath(value) {
  if (!value) {
    return null;
  }
  return path.isAbsolute(value) ? value : path.resolve(process.cwd(), value);
}

function ensureAbsolute(value, fallbackRelativePath) {
  const resolved = resolveOptionalPath(value);
  if (resolved) {
    return resolved;
  }
  return path.resolve(process.cwd(), fallbackRelativePath);
}

function parseMeta(line) {
  if (!line || !line.startsWith('#')) {
    return {};
  }

  return line
    .slice(1)
    .split(',')
    .reduce((acc, pair) => {
      const [key = '', value = ''] = pair.split(':');
      const trimmedKey = key.trim();
      if (trimmedKey) {
        acc[trimmedKey] = value.trim();
      }
      return acc;
    }, {});
}

async function pathExists(dirPath) {
  try {
    const stats = await fs.stat(dirPath);
    return stats.isDirectory();
  } catch (error) {
    if (error.code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

async function runGit(args, options = {}) {
  try {
    await execFileAsync('git', args, {
      maxBuffer: 1024 * 1024 * 64,
      ...options,
    });
  } catch (error) {
    const stderr = error.stderr?.toString?.().trim();
    const stdout = error.stdout?.toString?.().trim();
    const details = stderr || stdout || error.message;
    throw new Error(`git ${args.join(' ')} failed: ${details}`);
  }
}

async function cloneVulnrichment(targetDir) {
  await fs.mkdir(path.dirname(targetDir), { recursive: true });
  const relativeTarget = path.relative(process.cwd(), targetDir) || targetDir;
  console.log(`[vulnrichment] Cloning dataset into ${relativeTarget}`);
  await runGit(
    ['clone', '--depth', '1', '--single-branch', '--branch', VULNREICHMENT_BRANCH, VULNREICHMENT_REPO, targetDir],
    { cwd: process.cwd() }
  );
}

async function updateVulnrichment(targetDir) {
  const relativeTarget = path.relative(process.cwd(), targetDir) || targetDir;
  console.log(`[vulnrichment] Updating dataset in ${relativeTarget}`);
  await runGit(['-C', targetDir, 'pull', '--ff-only'], { cwd: process.cwd() });
}

async function bootstrapDefaultVulnrichment(targetDir) {
  const exists = await pathExists(targetDir);
  if (exists) {
    console.log(`[vulnrichment] Dataset already exists at ${targetDir}. Skipping update.`);
    return;
  }

  await cloneVulnrichment(targetDir);
}

async function prepareEnrichmentRoot(requestedPath) {
  if (requestedPath) {
    return requestedPath;
  }

  try {
    await bootstrapDefaultVulnrichment(DEFAULT_VULNREICHMENT_ROOT);
    return DEFAULT_VULNREICHMENT_ROOT;
  } catch (error) {
    console.warn(`[vulnrichment] Auto-setup failed: ${error.message}. Continuing without enrichment.`);
    return null;
  }
}

function toNumber(value) {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }
  const num = Number(value);
  return Number.isNaN(num) ? undefined : num;
}

function buildMetaFromCveId(cveId) {
  if (!cveId || typeof cveId !== 'string') {
    return null;
  }
  const match = CVE_ID_PATTERN.exec(cveId.toUpperCase());
  if (!match) {
    return null;
  }
  const year = match[1];
  const sequenceRaw = match[2];
  const sequenceNumber = Number.parseInt(sequenceRaw, 10);
  if (Number.isNaN(sequenceNumber)) {
    return null;
  }
  const bucketPrefix = Math.floor(sequenceNumber / 1000);
  return {
    key: `CVE-${year}-${sequenceRaw}`,
    year,
    bucket: `${bucketPrefix}xxx`,
    fileName: `CVE-${year}-${sequenceRaw}.json`,
  };
}

function pickAdpEntry(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return null;
  }

  const prioritized = entries.find((entry) => {
    const shortName = entry?.providerMetadata?.shortName;
    return typeof shortName === 'string' && shortName.toLowerCase().includes('cisa');
  });

  if (prioritized) {
    return prioritized;
  }

  return entries.find((entry) => entry.affected || entry.problemTypes || entry.metrics) || entries[0];
}

function extractAffected(affected) {
  if (!Array.isArray(affected)) {
    return [];
  }

  return affected.map((item) => ({
    vendor: item?.vendor ?? null,
    product: item?.product ?? null,
    versions: Array.isArray(item?.versions) ? item.versions.map((details) => ({ ...details })) : [],
    cpes: Array.isArray(item?.cpes) ? [...item.cpes] : [],
    defaultStatus: item?.defaultStatus ?? null,
  }));
}

function extractCvss(metrics) {
  if (!Array.isArray(metrics)) {
    return [];
  }

  const collected = [];

  for (const metric of metrics) {
    for (const key of CVSS_KEYS) {
      if (metric[key]) {
        collected.push({
          type: key,
          format: metric.format ?? null,
          data: metric[key],
        });
      }
    }
  }

  return collected;
}

function extractKev(metrics) {
  if (!Array.isArray(metrics)) {
    return [];
  }

  return metrics
    .map((metric) => {
      const block = metric?.other;
      if (!block?.type || typeof block.type !== 'string') {
        return null;
      }
      if (block.type.toLowerCase() !== 'kev') {
        return null;
      }
      return block.content ?? {};
    })
    .filter(Boolean);
}

async function fetchNVD(cveId) {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
  try {
    const response = await fetch(url);
    if (!response.ok) return null;
    const data = await response.json();
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
      const vuln = data.vulnerabilities[0];
      return {
        cveMetadata: vuln.cve?.metadata,
        title: vuln.cve?.descriptions?.find(d => d.lang === 'en')?.value,
        orgId: vuln.cve?.sourceIdentifier,
        provider: 'NVD',
        vendorProducts: vuln.cve?.configurations?.flatMap(c => c.nodes?.map(n => ({
          vendor: n.cpeMatch?.map(m => m.cpe23Uri?.split(':')[3]).filter(Boolean)[0],
          product: n.cpeMatch?.map(m => m.cpe23Uri?.split(':')[4]).filter(Boolean)[0],
          versions: n.cpeMatch?.flatMap(m => m.versionStartIncluding ? [{ status: 'affected', version: m.versionStartIncluding }] : []),
          cpes: n.cpeMatch?.map(m => m.cpe23Uri).filter(Boolean) || [],
          defaultStatus: n.operator || 'unknown'
        })) || []),
        problemTypes: vuln.cve?.weaknesses?.map(w => ({ descriptions: w.description })) || [],
        cvss: [
          ...(vuln.cve?.metrics?.cvssMetricV31?.map(m => ({ type: 'cvssV3_1', data: m.cvssData })) || []),
          ...(vuln.cve?.metrics?.cvssMetricV30?.map(m => ({ type: 'cvssV3_0', data: m.cvssData })) || []),
          ...(vuln.cve?.metrics?.cvssMetricV2?.map(m => ({ type: 'cvssV2_0', data: m.cvssData })) || [])
        ],
        kev: []
      };
    }
  } catch (e) {
    console.warn(`[NVD] Failed to fetch ${cveId}: ${e.message}`);
  }
  return null;
}

function createVulnrichmentLoader(root) {
  const bucketCache = new Map();
  const recordCache = new Map();

  async function ensureBucketSet(year, bucket) {
    const cacheKey = `${year}/${bucket}`;
    if (bucketCache.has(cacheKey)) {
      return bucketCache.get(cacheKey);
    }

    const bucketPath = path.join(root, year, bucket);
    try {
      const entries = await fs.readdir(bucketPath);
      const entrySet = new Set(entries);
      bucketCache.set(cacheKey, entrySet);
      return entrySet;
    } catch (error) {
      if (error.code === 'ENOENT') {
        bucketCache.set(cacheKey, null);
        return null;
      }
      throw error;
    }
  }

  function extractEnrichment(record) {
    const adpEntry = pickAdpEntry(record?.containers?.adp);
    const basePayload = {
      cveMetadata: record?.cveMetadata ?? null,
    };

    if (!adpEntry) {
      return basePayload.cveMetadata ? basePayload : null;
    }

    return {
      ...basePayload,
      title: adpEntry.title ?? null,
      orgId: adpEntry.providerMetadata?.orgId ?? null,
      provider: adpEntry.providerMetadata?.shortName ?? null,
      vendorProducts: extractAffected(adpEntry.affected),
      problemTypes: Array.isArray(adpEntry.problemTypes) ? adpEntry.problemTypes : [],
      cvss: extractCvss(adpEntry.metrics),
      kev: extractKev(adpEntry.metrics),
    };
  }

  return async function loadVulnrichment(cveId) {
    const cveMeta = buildMetaFromCveId(cveId);
    if (!cveMeta) {
      return null;
    }

    if (recordCache.has(cveMeta.key)) {
      return recordCache.get(cveMeta.key);
    }

    const entries = await ensureBucketSet(cveMeta.year, cveMeta.bucket);
    if (!entries || !entries.has(cveMeta.fileName)) {
      recordCache.set(cveMeta.key, null);
      return null;
    }

    const filePath = path.join(root, cveMeta.year, cveMeta.bucket, cveMeta.fileName);
    const rawRecord = await fs.readFile(filePath, 'utf8');
    const parsedRecord = JSON.parse(rawRecord);
    const payload = extractEnrichment(parsedRecord);
    recordCache.set(cveMeta.key, payload);
    return payload;
  };
}

async function convertCsvToJson({ enrichmentRoot } = {}) {
  let loader = null;
  let activeRoot = enrichmentRoot;

  if (activeRoot) {
    try {
      const stats = await fs.stat(activeRoot);
      if (!stats.isDirectory()) {
        console.warn(`[vulnrichment] ${activeRoot} is not a directory. Skipping enrichment.`);
        activeRoot = null;
      }
    } catch (error) {
      if (error.code === 'ENOENT') {
        console.warn(`[vulnrichment] Directory not found at ${activeRoot}. Skipping enrichment.`);
      } else {
        console.warn(`[vulnrichment] Unable to access ${activeRoot}: ${error.message}. Skipping enrichment.`);
      }
      activeRoot = null;
    }
  }

  if (activeRoot) {
    loader = createVulnrichmentLoader(activeRoot);
    const relativeRoot = path.relative(process.cwd(), activeRoot) || activeRoot;
    console.log(`[vulnrichment] Enrichment enabled via ${relativeRoot}`);
  }

  const raw = await fs.readFile(inputPath, 'utf8');
  const [maybeMetaLine, ...rest] = raw.split(/\r?\n/);
  const meta = parseMeta(maybeMetaLine);
  const csvBody = [maybeMetaLine.startsWith('#') ? '' : maybeMetaLine, ...rest]
    .filter((line) => line.trim().length > 0 && !line.startsWith('#'))
    .join('\n');

  const { data, errors } = Papa.parse(csvBody, {
    header: true,
    skipEmptyLines: true,
    dynamicTyping: false,
  });

  if (errors.length > 0) {
    const [{ message, row }] = errors;
    throw new Error(`Failed to parse CSV (row ${row}): ${message}`);
  }

  // Sort data by year descending (newest to oldest)
  data.sort((a, b) => {
    const yearA = parseInt(a.cve.split('-')[1]);
    const yearB = parseInt(b.cve.split('-')[1]);
    return yearB - yearA;
  });

  const records = [];
  let enrichedCount = 0;
  let nvdCount = 0;
  let processed = 0;
  let currentYear = null;

  for (const row of data) {
    if (!row.cve) {
      continue;
    }

    const year = parseInt(row.cve.split('-')[1]);
    if (year !== currentYear) {
      console.log(`Processing CVEs for year ${year}...`);
      currentYear = year;
    }

    const record = {
      cve: row.cve,
      epss: toNumber(row.epss),
      percentile: toNumber(row.percentile),
    };

    if (loader) {
      try {
        const enrichment = await loader(row.cve);
        if (enrichment) {
          record.vulnrichment = enrichment;
          enrichedCount += 1;
          if (VERBOSE) {
            console.log(`[vulnrichment] Enriched ${row.cve}`);
          }
        }
      } catch (error) {
        console.warn(`[vulnrichment] Failed to enrich ${row.cve}: ${error.message}`);
      }
      // Add a small delay to slow down processing for better enrichment
      await new Promise(r => setTimeout(r, 30));
    }

    if (!record.vulnrichment && ENABLE_NVD && nvdCount < NVD_LIMIT) {
      console.log(`[NVD] Fetching enrichment for ${row.cve}...`);
      await new Promise(r => setTimeout(r, 2000)); // Increased delay to 2 seconds
      const enrichment = await fetchNVD(row.cve);
      if (enrichment) {
        record.vulnrichment = enrichment;
        enrichedCount += 1;
        nvdCount += 1;
        console.log(`[NVD] Successfully enriched ${row.cve} from NVD`);
      } else {
        console.log(`[NVD] No data found for ${row.cve}`);
      }
    }

    records.push(record);
    processed++;
    if (processed % 1000 === 0) {
      console.log(`Processed ${processed} CVEs...`);
    }
  }

    const payload = {
      meta,
      records,
    };

    await fs.writeFile(outputPath, JSON.stringify(payload, null, 2));
    const relativeInput = path.relative(process.cwd(), inputPath) || inputPath;
    const relativeOutput = path.relative(process.cwd(), outputPath) || outputPath;
    const baseMessage = `Converted ${records.length} rows from ${relativeInput} to ${relativeOutput}`;
    let enrichmentMessage = '';
    if (loader && nvdCount > 0) {
      enrichmentMessage = ` (enriched ${enrichedCount - nvdCount} from vulnrichment, ${nvdCount} from NVD)`;
    } else if (loader) {
      enrichmentMessage = ` (enriched ${enrichedCount} from vulnrichment)`;
    } else if (nvdCount > 0) {
      enrichmentMessage = ` (enriched ${nvdCount} from NVD)`;
    }
    console.log(baseMessage + enrichmentMessage);
  }

  async function main() {
    const enrichmentRoot = await prepareEnrichmentRoot(requestedEnrichmentRoot);
    await convertCsvToJson({ enrichmentRoot });
  }

  main().catch((error) => {
    console.error(error.message || error);
    process.exit(1);
  });
