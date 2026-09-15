#!/usr/bin/env node
// Pulls Available + Inbound WholeCell inventory, dedupes, gzips, encrypts (public key
// only — this script can never decrypt anything), writes data/inventory.jwe.
// Fetch/retry/pagination logic and the dedupe-by-id logic are ported from the private
// dashboard repo's scripts/full-sync.js + scripts/merge-partials.js — same shape, same
// behavior, just relocated and combined into one in-memory pass.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { importSPKI, CompactEncrypt } from 'jose';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_PATH = path.join(__dirname, '..', 'data', 'inventory.jwe');
const PUBLIC_KEY_PATH = path.join(__dirname, '..', 'keys', 'public-key.pem');

const APP_ID = process.env.WHOLECELL_APP_ID;
const APP_SECRET = process.env.WHOLECELL_APP_SECRET;
if (!APP_ID || !APP_SECRET) { console.error('Set WHOLECELL_APP_ID and WHOLECELL_APP_SECRET.'); process.exit(1); }
const API_BASE = 'https://api.wholecell.io/api/v1/inventories';
const AUTH = 'Basic ' + Buffer.from(APP_ID + ':' + APP_SECRET).toString('base64');
const HEADERS = { Authorization: AUTH, 'X-App-Id': APP_ID, Accept: 'application/json' };

const RATE_LIMIT_MS = 550;
const STATUSES = ['Available', 'Inbound'];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchPage(url, attempt = 1) {
  try {
    const res = await fetch(url, { headers: HEADERS, signal: AbortSignal.timeout(45000) });
    if (!res.ok) {
      if (attempt < 3) {
        const delay = attempt * 2000;
        console.warn(`  HTTP ${res.status}, retry ${attempt}/3 in ${delay}ms...`);
        await sleep(delay);
        return fetchPage(url, attempt + 1);
      }
      throw new Error(`HTTP ${res.status} fetching ${url}`);
    }
    return res.json();
  } catch (err) {
    if (attempt < 3 && err.name !== 'AbortError') {
      const delay = attempt * 2000;
      console.warn(`  Fetch error (${err.message}), retry ${attempt}/3 in ${delay}ms...`);
      await sleep(delay);
      return fetchPage(url, attempt + 1);
    }
    throw err;
  }
}

async function fetchAllByStatus(status) {
  const all = [];
  let page = 1;
  while (true) {
    const url = `${API_BASE}?status=${encodeURIComponent(status)}&page=${page}`;
    const json = await fetchPage(url);
    if (!json.data || json.data.length === 0) break;
    all.push(...json.data);
    const totalPages = json.pages || 1;
    if (page % 25 === 0 || page === totalPages) {
      console.log(`  ${status} page ${page}/${totalPages} (${all.length} items)`);
    }
    if (page >= totalPages) break;
    page++;
    await sleep(RATE_LIMIT_MS);
  }
  return all;
}

function mergeAndDedupe(byStatus) {
  const partials = STATUSES.map((s) => ({ status: s, items: byStatus[s] }));
  const items = partials.flatMap((p) => p.items);
  const seen = new Set();
  const deduped = [];
  for (const it of items) {
    if (seen.has(it.id)) continue;
    seen.add(it.id);
    deduped.push(it);
  }
  const now = new Date().toISOString();
  return {
    metadata: {
      timestamp: now,
      totalItems: deduped.length,
      source: 'wholecell-direct',
      syncType: 'full',
      partials: partials.map((p) => ({ status: p.status, timestamp: now, count: p.items.length })),
    },
    count: deduped.length,
    data: deduped,
  };
}

async function encryptPayload(snapshotObject, publicKeyPem) {
  const publicKey = await importSPKI(publicKeyPem, 'ECDH-ES+A256KW');
  const gzipped = gzipSync(Buffer.from(JSON.stringify(snapshotObject)), { level: 9 });
  return new CompactEncrypt(gzipped)
    .setProtectedHeader({ alg: 'ECDH-ES+A256KW', enc: 'A256GCM' })
    .encrypt(publicKey);
}

async function main() {
  const byStatus = {};
  for (const status of STATUSES) {
    console.log(`=== Full pull: ${status} ===`);
    byStatus[status] = await fetchAllByStatus(status);
  }

  const snapshot = mergeAndDedupe(byStatus);
  console.log(`Merged ${snapshot.count} items from ${STATUSES.join(' + ')}`);

  const publicKeyPem = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
  const jwe = await encryptPayload(snapshot, publicKeyPem);

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  const tmpPath = OUT_PATH + '.tmp';
  fs.writeFileSync(tmpPath, jwe);
  fs.renameSync(tmpPath, OUT_PATH);

  const sizeKB = (fs.statSync(OUT_PATH).size / 1024).toFixed(0);
  console.log(`Wrote ${snapshot.count} items (${sizeKB} KB ciphertext) -> ${path.relative(process.cwd(), OUT_PATH)}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
