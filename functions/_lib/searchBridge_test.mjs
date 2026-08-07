// Plain-node test, no framework — run with: node _lib/searchBridge_test.mjs
// Mirrors this codebase's existing testing convention (see factGuard.test.mjs:
// "run node factGuard.test.mjs before every wrangler deploy").
import assert from 'node:assert/strict';
import { extractGeminiDelta } from './providerDeltas.mjs';

let passed = 0;
let failed = 0;

async function check(name, fn) {
  try {
    await fn(); // awaiting a non-promise return value is a harmless no-op
    passed++;
    console.log(`ok — ${name}`);
  } catch (err) {
    failed++;
    console.error(`FAIL — ${name}\n  ${err.stack || err.message}`);
  }
}

// ── extractGeminiDelta ──────────────────────────────────────────────────────

await check('extractGeminiDelta: plain text chunk, no grounding (regression)', () => {
  const d = extractGeminiDelta(JSON.stringify({
    candidates: [{ content: { parts: [{ text: 'punching shear is checked at d/2 from the column face' }] } }],
  }));
  assert.equal(d.text, 'punching shear is checked at d/2 from the column face');
  assert.equal(d.finished, false);
  assert.equal(d.groundingMetadata, null);
});

await check('extractGeminiDelta: terminal chunk with finishReason, no grounding (regression)', () => {
  const d = extractGeminiDelta(JSON.stringify({
    candidates: [{ content: { parts: [{ text: '.' }] }, finishReason: 'STOP' }],
  }));
  assert.equal(d.finished, true);
  assert.equal(d.finishReason, 'STOP');
  assert.equal(d.groundingMetadata, null);
});

await check('extractGeminiDelta: bare thoughtSignature chunk does not throw (existing edge case)', () => {
  const d = extractGeminiDelta(JSON.stringify({
    candidates: [{ content: { parts: [{ thought: true, thoughtSignature: 'abc' }] } }],
  }));
  assert.equal(d.text, '');
  assert.equal(d.groundingMetadata, null);
});

await check('extractGeminiDelta: malformed JSON still reports parseError (regression)', () => {
  const d = extractGeminiDelta('{not json');
  assert.equal(d.parseError, true);
});

await check('extractGeminiDelta: grounded terminal chunk extracts groundingMetadata', () => {
  const gm = {
    webSearchQueries: ['current ECP 203 rebar cover requirements'],
    groundingChunks: [{ web: { uri: 'https://example.com/ecp203', title: 'ECP 203 amendment notes' } }],
  };
  const d = extractGeminiDelta(JSON.stringify({
    candidates: [{ content: { parts: [{ text: 'the cover requirement is' }] }, finishReason: 'STOP', groundingMetadata: gm }],
  }));
  assert.equal(d.finished, true);
  assert.deepEqual(d.groundingMetadata, gm);
});

await check('extractGeminiDelta: groundingChunks missing from groundingMetadata does not throw (known Gemini 3.x instability)', () => {
  const d = extractGeminiDelta(JSON.stringify({
    candidates: [{ content: { parts: [{ text: 'x' }] }, finishReason: 'STOP', groundingMetadata: { webSearchQueries: ['q'] } }],
  }));
  assert.equal(d.groundingMetadata.groundingChunks, undefined);
});

// ── callGeminiStreaming end-to-end via a synthetic SSE Response (no network
//    call — fetch is monkey-patched for the duration of each check) ────────

function sseBody(events) {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const ev of events) controller.enqueue(encoder.encode(`data: ${ev}\n\n`));
      controller.close();
    },
  });
}

async function withFakeFetch(handler, run) {
  const real = global.fetch;
  global.fetch = handler;
  try { return await run(); } finally { global.fetch = real; }
}

const { callGeminiStreaming } = await import('./streamingProviders.mjs');

await check('callGeminiStreaming: ungrounded reply returns groundingMetadata:null (regression)', async () => {
  const res = await withFakeFetch(
    async () => new Response(sseBody([
      JSON.stringify({ candidates: [{ content: { parts: [{ text: 'hello ' }] } }] }),
      JSON.stringify({ candidates: [{ content: { parts: [{ text: 'world' }] }, finishReason: 'STOP' }] }),
    ]), { status: 200 }),
    () => callGeminiStreaming('fake-key', 'gemini-3.5-flash', [{ role: 'user', parts: [{ text: 'hi' }] }],
      'sys', { maxOutputTokens: 16 }, { take: () => true }, () => {}, undefined, [{ google_search: {} }]),
  );
  assert.equal(res.ok, true);
  assert.equal(res.reply, 'hello world');
  assert.equal(res.groundingMetadata, null);
});

await check('callGeminiStreaming: grounded reply surfaces groundingMetadata from terminal chunk', async () => {
  const gm = { webSearchQueries: ['q'], groundingChunks: [{ web: { uri: 'https://a.test', title: 'A' } }] };
  const res = await withFakeFetch(
    async () => new Response(sseBody([
      JSON.stringify({ candidates: [{ content: { parts: [{ text: 'answer text' }] } }] }),
      JSON.stringify({ candidates: [{ content: { parts: [{ text: '.' }] }, finishReason: 'STOP', groundingMetadata: gm }] }),
    ]), { status: 200 }),
    () => callGeminiStreaming('fake-key', 'gemini-3.5-flash', [], 'sys', {}, { take: () => true }, () => {}, undefined, [{ google_search: {} }]),
  );
  assert.equal(res.ok, true);
  assert.equal(res.reply, 'answer text.');
  assert.deepEqual(res.groundingMetadata, gm);
});

await check('callGeminiStreaming: request payload includes tools when passed', async () => {
  let capturedBody = null;
  await withFakeFetch(
    async (_url, init) => {
      capturedBody = JSON.parse(init.body);
      return new Response(sseBody([JSON.stringify({ candidates: [{ content: { parts: [{ text: 'x' }] }, finishReason: 'STOP' }] })]), { status: 200 });
    },
    () => callGeminiStreaming('k', 'gemini-3.5-flash', [], 'sys', {}, { take: () => true }, () => {}, undefined, [{ google_search: {} }]),
  );
  assert.deepEqual(capturedBody.tools, [{ google_search: {} }]);
});

await check('callGeminiStreaming: omitting tools omits it from payload (vision.js / pre-patch call-shape regression)', async () => {
  let capturedBody = null;
  await withFakeFetch(
    async (_url, init) => {
      capturedBody = JSON.parse(init.body);
      return new Response(sseBody([JSON.stringify({ candidates: [{ content: { parts: [{ text: 'x' }] }, finishReason: 'STOP' }] })]), { status: 200 });
    },
    // Exactly the 8-arg call shape vision.js and pre-patch chat.js use.
    () => callGeminiStreaming('k', 'gemini-3.5-flash', [], 'sys', {}, { take: () => true }, () => {}, undefined),
  );
  assert.equal('tools' in capturedBody, false);
});

// ── extractGroundingSources (copied verbatim from chat.js — a local,
//    unexported helper; chat.js is a Cloudflare Pages Function module and
//    cannot run standalone under plain node, since it expects Workers-
//    runtime request/env globals this harness does not provide). Keep this
//    block byte-for-byte in sync with chat.js if either changes. ──────────
function extractGroundingSources(groundingMetadata, maxSources = 5) {
  const chunks = groundingMetadata && groundingMetadata.groundingChunks;
  if (!Array.isArray(chunks) || chunks.length === 0) return [];
  const seen = new Set();
  const out = [];
  for (const chunk of chunks) {
    const uri = chunk && chunk.web && chunk.web.uri;
    if (!uri || seen.has(uri)) continue;
    seen.add(uri);
    const title = (chunk.web && chunk.web.title) || uri;
    out.push({ uri, title });
    if (out.length >= maxSources) break;
  }
  return out;
}

await check('extractGroundingSources: null groundingMetadata -> []', () => {
  assert.deepEqual(extractGroundingSources(null), []);
});

await check('extractGroundingSources: missing groundingChunks (known Gemini 3.x instability) -> []', () => {
  assert.deepEqual(extractGroundingSources({ webSearchQueries: ['q'] }), []);
});

await check('extractGroundingSources: dedupes repeated uri across chunks', () => {
  const gm = { groundingChunks: [
    { web: { uri: 'https://a.test', title: 'A' } },
    { web: { uri: 'https://a.test', title: 'A again' } },
    { web: { uri: 'https://b.test', title: 'B' } },
  ] };
  assert.deepEqual(extractGroundingSources(gm), [
    { uri: 'https://a.test', title: 'A' },
    { uri: 'https://b.test', title: 'B' },
  ]);
});

await check('extractGroundingSources: caps at maxSources', () => {
  const gm = { groundingChunks: Array.from({ length: 9 }, (_, i) => ({ web: { uri: `https://s${i}.test`, title: `S${i}` } })) };
  assert.equal(extractGroundingSources(gm, 5).length, 5);
});

await check('extractGroundingSources: missing web.title falls back to uri', () => {
  const gm = { groundingChunks: [{ web: { uri: 'https://a.test' } }] };
  assert.deepEqual(extractGroundingSources(gm), [{ uri: 'https://a.test', title: 'https://a.test' }]);
});

console.log(`\n${passed} passed, ${failed} failed.`);
if (failed > 0) process.exit(1);
