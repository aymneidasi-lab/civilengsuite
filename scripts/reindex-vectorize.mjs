#!/usr/bin/env node
// reindex-vectorize.mjs — Phase 2 of the Vectorize project (see
// CONTINUATION_PROMPT.md). Standalone script, NOT a Worker route: run it
// locally (or from CI) after every `python build_kb_data.py` to push the
// full KB into Vectorize. Deliberately NOT deployed as an admin endpoint on
// the public Worker — that would be new attack surface for zero benefit,
// since this only needs to run on your machine when the KB changes.
//
// EXPECTED LOCATION (per this repo's real structure, 2_-_REPO_STRUCTURE.txt):
// civilengsuite/scripts/reindex-vectorize.mjs — a sibling of functions/, not
// inside it. This is plain Node tooling that calls Cloudflare's REST API
// from the outside; it never runs on Cloudflare's infrastructure, so it
// does not belong under functions/ (Pages would upload it alongside real
// routes for no reason) or public/ (nothing here is served to visitors).
// The default --kb-path below already points at this repo's real
// functions/api/kb-data.js, resolved relative to THIS file's own location —
// so `node scripts/reindex-vectorize.mjs` works out of the box from the
// repo root with no flags needed.
//
// USAGE (from the repo root):
//   CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_API_TOKEN=... node scripts/reindex-vectorize.mjs
//   node scripts/reindex-vectorize.mjs --dry-run     # no network calls, see below
//   node scripts/reindex-vectorize.mjs --kb-path=functions/api/kb-data.js --index=my-index-name
//
// Requires: Node 18+ (native fetch).
//
// OPERATIONAL RULE (per CONTINUATION_PROMPT.md Phase 1 decision): this is
// always a FULL reindex, never incremental. Vector IDs are the chunk's
// position in the KB_CHUNKS array, which is only stable within one build of
// kb-data.js — run this every time after rebuilding, not on a schedule
// decoupled from the build step.

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Config ──────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const DRY_RUN = args.includes('--dry-run');
const getArg = (name, fallback) => {
  const hit = args.find(a => a.startsWith(`--${name}=`));
  return hit ? hit.split('=').slice(1).join('=') : fallback;
};
const INDEX_NAME = getArg('index', 'civil-suite-kb');
const EMBED_MODEL = getArg('embed-model', '@cf/baai/bge-m3');
const BATCH_SIZE = parseInt(getArg('batch-size', '50'), 10);
const MAX_RETRIES = 3;
const METADATA_H_MAX_CHARS = 300; // defensive cap — metadata is a convenience
// copy for debugging only; the real content lookup in chat.js always goes
// through KB_CHUNKS[id], never through Vectorize metadata. No confirmed
// Vectorize metadata-value length ceiling was found during planning — this
// stays conservative until a real limit is confirmed against the live API.

// v_fix (found while answering "where does this file go"): --kb-path was
// PREVIOUSLY DOCUMENTED BUT NEVER WIRED UP — the original version had a
// static `import ... from './kb-data.js'` at the top of the file, and a
// static ES import is resolved before argv is even parsed, so no runtime
// flag could ever have redirected it. This was a real, shipped defect, not
// a hypothetical one — caught only once a real file layout (this repo's)
// made the wrong default observable. Fixed with a dynamic import that
// resolves AFTER args are parsed, defaulting to this repo's real path.
const KB_PATH_ARG = getArg('kb-path', null);
const defaultKbPath = path.resolve(__dirname, '../functions/api/kb-data.js');
const kbPath = KB_PATH_ARG ? path.resolve(process.cwd(), KB_PATH_ARG) : defaultKbPath;
let KB_CHUNKS;
try {
  ({ KB_CHUNKS } = await import(pathToFileURL(kbPath).href));
} catch (err) {
  console.error(`Could not load KB_CHUNKS from ${kbPath}\n` +
                `  (${err.message})\n` +
                `Pass the correct location with --kb-path=path/to/kb-data.js`);
  process.exit(1);
}

const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
const API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;

// [MERGE ADDITION] A kb-data.js that loaded successfully but parsed to zero
// chunks (a broken/truncated build, wrong file, etc.) would otherwise
// proceed to "successfully" upsert nothing and exit 0 — silently leaving a
// real, populated index untouched rather than erroring, which is the
// SAFEST failure mode for a read-only mistake but the WORST one for this
// specific script if a future version of it is ever extended to also prune
// stale ids: an empty-chunks run could then read as "the KB is now empty,
// delete everything." Refusing outright removes that risk category
// entirely rather than relying on this script never growing that feature.
if (KB_CHUNKS.length === 0) {
  console.error(`${kbPath} loaded but produced zero chunks — refusing to run. ` +
                `This is very likely a broken build, not an intentionally empty KB.`);
  process.exit(1);
}

if (!DRY_RUN && (!ACCOUNT_ID || !API_TOKEN)) {
  console.error(
    'Missing CLOUDFLARE_ACCOUNT_ID and/or CLOUDFLARE_API_TOKEN env vars.\n' +
    'Set both, or run with --dry-run to verify the script offline first.'
  );
  process.exit(1);
}

const EMBED_URL = ACCOUNT_ID
  ? `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/ai/run/${EMBED_MODEL}`
  : null;
const UPSERT_URL = ACCOUNT_ID
  ? `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/vectorize/v2/indexes/${INDEX_NAME}/upsert`
  : null;

// ── Helpers ─────────────────────────────────────────────────────────────

// Very rough token estimate (chars/4) — good enough for a pre-flight sanity
// check against bge-m3's 8,192-token context window, not for billing math.
const roughTokens = (str) => Math.ceil(str.length / 4);

function chunkText(c) {
  return `${c.h}\n${c.t}`;
}

function buildMetadata(c) {
  const h = c.h.length > METADATA_H_MAX_CHARS
    ? c.h.slice(0, METADATA_H_MAX_CHARS - 1).trimEnd() + '…'
    : c.h;
  return { s: c.s, h };
}

async function withRetries(fn, label) {
  let lastErr;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      console.warn(`  [retry ${attempt}/${MAX_RETRIES}] ${label} failed: ${err.message}`);
      if (attempt < MAX_RETRIES) {
        await new Promise(r => setTimeout(r, 500 * 2 ** (attempt - 1))); // 500ms, 1s, 2s
      }
    }
  }
  throw lastErr;
}

async function embedBatch(texts) {
  if (DRY_RUN) {
    // Deterministic fake vector so dry-run output is reproducible and
    // inspectable, without pretending a real API call happened.
    return texts.map(() => new Array(1024).fill(0));
  }
  return withRetries(async () => {
    const res = await fetch(EMBED_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text: texts }),
    });
    if (!res.ok) {
      throw new Error(`embed HTTP ${res.status}: ${await res.text()}`);
    }
    const json = await res.json();
    if (!json.success || !json.result || !json.result.data) {
      throw new Error(`embed API error: ${JSON.stringify(json.errors || json)}`);
    }
    return json.result.data;
  }, 'embed');
}

async function upsertBatch(ndjson) {
  if (DRY_RUN) {
    return { mutationId: '[dry-run, not sent]' };
  }
  return withRetries(async () => {
    const res = await fetch(UPSERT_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${API_TOKEN}`,
        'Content-Type': 'application/x-ndjson',
      },
      body: ndjson,
    });
    if (!res.ok) {
      throw new Error(`upsert HTTP ${res.status}: ${await res.text()}`);
    }
    const json = await res.json();
    if (!json.success) {
      throw new Error(`upsert API error: ${JSON.stringify(json.errors || json)}`);
    }
    return json.result;
  }, 'upsert');
}

// ── Main ────────────────────────────────────────────────────────────────

async function main() {
  console.log(`${DRY_RUN ? '[DRY RUN] ' : ''}Reindexing ${KB_CHUNKS.length} chunks into ` +
              `Vectorize index "${INDEX_NAME}" using ${EMBED_MODEL} (batch size ${BATCH_SIZE})`);

  // Pre-flight sanity check: flag (don't block on) any chunk that's
  // suspiciously close to bge-m3's 8,192-token context window.
  const TOKEN_WARN_THRESHOLD = 7000;
  let longChunkWarnings = 0;
  KB_CHUNKS.forEach((c, i) => {
    const t = roughTokens(chunkText(c));
    if (t > TOKEN_WARN_THRESHOLD) {
      console.warn(`  [warn] chunk ${i} (~${t} tokens) is close to the 8,192-token embed limit: "${c.h.slice(0, 60)}..."`);
      longChunkWarnings++;
    }
  });
  if (longChunkWarnings === 0) console.log('Pre-flight: no chunk close to the embedding token limit.');

  const batches = [];
  for (let i = 0; i < KB_CHUNKS.length; i += BATCH_SIZE) {
    batches.push(KB_CHUNKS.slice(i, i + BATCH_SIZE).map((c, j) => ({ chunk: c, id: i + j })));
  }

  let totalUpserted = 0;
  let totalInputTokens = 0;
  const failedBatches = [];
  const dryRunNdjsonLines = [];

  for (let b = 0; b < batches.length; b++) {
    const batch = batches[b];
    const texts = batch.map(({ chunk }) => chunkText(chunk));
    totalInputTokens += texts.reduce((sum, t) => sum + roughTokens(t), 0);

    try {
      const vectors = await embedBatch(texts);
      const lines = batch.map(({ chunk, id }, idx) => JSON.stringify({
        id: String(id),
        values: vectors[idx],
        metadata: buildMetadata(chunk),
      }));
      const ndjson = lines.join('\n') + '\n';

      if (DRY_RUN) dryRunNdjsonLines.push(...lines);
      else await upsertBatch(ndjson);

      totalUpserted += batch.length;
      console.log(`  batch ${b + 1}/${batches.length}: ${batch.length} chunks ` +
                  `(ids ${batch[0].id}-${batch[batch.length - 1].id}) OK`);
    } catch (err) {
      console.error(`  batch ${b + 1}/${batches.length} FAILED after retries: ${err.message}`);
      failedBatches.push({ batchIndex: b, ids: batch.map(x => x.id), error: err.message });
    }
  }

  if (DRY_RUN) {
    const fs = await import('node:fs/promises');
    const outPath = getArg('dry-run-out', './dry-run-vectors.ndjson');
    await fs.writeFile(outPath, dryRunNdjsonLines.join('\n') + '\n', 'utf-8');
    console.log(`[DRY RUN] Wrote ${dryRunNdjsonLines.length} NDJSON lines to ${outPath} for inspection.`);
  }

  const estimatedNeurons = Math.ceil((totalInputTokens / 1_000_000) * 1075);
  console.log('\n── Summary ──');
  console.log(`Upserted: ${totalUpserted}/${KB_CHUNKS.length} chunks`);
  console.log(`Estimated input tokens: ~${totalInputTokens.toLocaleString()} ` +
              `(~${estimatedNeurons} Neurons at bge-m3's published rate — ` +
              `verify against your live dashboard, this is a planning estimate)`);
  if (failedBatches.length > 0) {
    console.error(`FAILED batches: ${failedBatches.length}. IDs affected: ` +
                   failedBatches.flatMap(f => f.ids).join(', '));
    process.exitCode = 1;
  } else {
    console.log('All batches succeeded.');
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
