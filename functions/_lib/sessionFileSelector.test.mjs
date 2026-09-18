import assert from 'node:assert/strict';
import { selectRelevantFiles, __testables } from './sessionFileSelector.mjs';

const { cosineSimilarity } = __testables();

let passed = 0;
let failed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok  - ${name}`);
  } catch (err) {
    failed++;
    failures.push({ name, err });
    console.log(`FAIL  - ${name}`);
    console.log(`        ${err.message}`);
  }
}

// Deterministic mock: env.AI.run returns a vector per input text looked up
// by substring match against `table`. Tracks call count and, per call, which
// model/text-count it was invoked with, so tests can assert "no call made"
// (cache hit) as precisely as "call made" (cache miss).
function makeMockAI(table, opts = {}) {
  const calls = [];
  return {
    calls,
    run: async (model, { text }) => {
      calls.push({ model, count: text.length, texts: text });
      if (opts.hang) return new Promise(() => {}); // never settles
      if (opts.badShape) return { data: 'not-an-array' };
      if (opts.rejectOnce && calls.length === opts.rejectOnce) {
        throw new Error('SIMULATED_PROVIDER_ERROR');
      }
      const data = text.map((t) => {
        const hit = Object.entries(table).find(([key]) => t.includes(key));
        return hit ? hit[1] : null; // null -> "no usable embedding" for that input
      });
      return { data };
    },
  };
}

// ── cosineSimilarity sanity ─────────────────────────────────────────────
await test('cosineSimilarity: identical vectors -> 1', () => {
  assert.equal(cosineSimilarity([1, 0, 0], [1, 0, 0]), 1);
});
await test('cosineSimilarity: orthogonal vectors -> 0', () => {
  assert.equal(cosineSimilarity([1, 0], [0, 1]), 0);
});
await test('cosineSimilarity: opposite vectors -> -1', () => {
  assert.equal(cosineSimilarity([1, 0], [-1, 0]), -1);
});
await test('cosineSimilarity: zero-magnitude vector -> 0, not NaN/throw', () => {
  assert.equal(cosineSimilarity([0, 0], [1, 1]), 0);
});

// ── 1. Single file, relevant message -> selected, not passthrough ──────
await test('single file + relevant message -> kept', async () => {
  const ai = makeMockAI({
    'rebar spacing question': [1, 0, 0],
    'beam.txt': [1, 0, 0],
  });
  const files = [{ name: 'beam.txt', content: 'rebar spacing calcs' }];
  const r = await selectRelevantFiles({ AI: ai }, 'rebar spacing question', files, {});
  assert.equal(r.selected.length, 1);
  assert.equal(r.selected[0].name, 'beam.txt');
  assert.equal(r.scores[0].measured, true);
});

// ── 2. Single file, unrelated message -> empty, no mercy at length 1 ───
await test('single file + unrelated message -> empty (no length-1 mercy)', async () => {
  const ai = makeMockAI({
    'what is the weather today': [0, 1, 0],
    'beam.txt': [1, 0, 0],
  });
  const files = [{ name: 'beam.txt', content: 'rebar spacing calcs' }];
  const r = await selectRelevantFiles({ AI: ai }, 'what is the weather today', files, {});
  assert.equal(r.selected.length, 0);
  assert.match(r.reason, /kept 0 of 1/);
});

// ── 3. Multi-file, one relevant -> only that one kept ───────────────────
await test('3 files, 1 relevant -> only that one kept', async () => {
  const ai = makeMockAI({
    'slab question': [0, 1, 0],
    'beam.txt': [1, 0, 0],
    'slab.txt': [0, 1, 0],
    'column.txt': [0, 0, 1],
  });
  const files = [
    { name: 'beam.txt', content: 'x' },
    { name: 'slab.txt', content: 'x' },
    { name: 'column.txt', content: 'x' },
  ];
  const r = await selectRelevantFiles({ AI: ai }, 'slab question', files, {});
  assert.deepEqual(r.selected.map((f) => f.name), ['slab.txt']);
});

// ── 4. Multi-file, none clear threshold -> mercy keeps highest-scoring ──
await test('3 files, none clear threshold -> mercy keeps single highest', async () => {
  const deg = Math.PI / 180;
  const ai = makeMockAI({
    'ambiguous question': [1, 0],
    'a.txt': [Math.cos(80 * deg), Math.sin(80 * deg)], // cos80 ~ 0.1736
    'b.txt': [Math.cos(70 * deg), Math.sin(70 * deg)], // cos70 ~ 0.3420
    'c.txt': [Math.cos(65 * deg), Math.sin(65 * deg)], // cos65 ~ 0.4226 (highest, still <0.45)
  });
  const files = [
    { name: 'a.txt', content: 'x' },
    { name: 'b.txt', content: 'x' },
    { name: 'c.txt', content: 'x' },
  ];
  const r = await selectRelevantFiles({ AI: ai }, 'ambiguous question', files, { threshold: 0.45 });
  assert.deepEqual(r.selected.map((f) => f.name), ['c.txt']);
  assert.match(r.reason, /no file cleared threshold/);
});

// ── 5. Embedding cache: second turn makes no new file-embedding call ───
await test('cached file embeddings -> no file-batch call, only message call', async () => {
  const ai = makeMockAI({
    'second turn question': [1, 0, 0],
  });
  const files = [{ name: 'beam.txt', content: 'x' }];
  const cachedEmbeddings = { 'beam.txt': [1, 0, 0] };
  const r = await selectRelevantFiles({ AI: ai }, 'second turn question', files, { cachedEmbeddings });
  assert.equal(ai.calls.length, 1, 'expected exactly one env.AI.run call (message only)');
  assert.equal(ai.calls[0].count, 1);
  assert.equal(r.selected.length, 1);
  assert.deepEqual(r.embeddings, { 'beam.txt': [1, 0, 0] });
});

// ── 6. Timeout: hung call falls back to all files, doesn't hang ────────
await test('hung env.AI.run -> fail-open within timeout, all files kept', async () => {
  const ai = makeMockAI({}, { hang: true });
  const files = [
    { name: 'beam.txt', content: 'x' },
    { name: 'slab.txt', content: 'x' },
  ];
  const start = Date.now();
  const r = await selectRelevantFiles({ AI: ai }, 'anything', files, { timeoutMs: 80 });
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 1000, `expected fast fail-open, took ${elapsed}ms`);
  assert.equal(r.selected.length, 2);
  assert.match(r.reason, /EMBED_TIMEOUT/);
});

// ── 7. Fail-open: env.AI unavailable ────────────────────────────────────
await test('missing env.AI -> fail-open, all files reach the prompt', async () => {
  const files = [{ name: 'beam.txt', content: 'x' }];
  const r = await selectRelevantFiles({}, 'anything', files, {});
  assert.equal(r.selected.length, 1);
  assert.match(r.reason, /env\.AI not bound/);
});

// ── 8. Malformed response shape -> fail-open ────────────────────────────
await test('malformed embedding response shape -> fail-open, all files kept', async () => {
  const ai = makeMockAI({}, { badShape: true });
  const files = [{ name: 'beam.txt', content: 'x' }, { name: 'slab.txt', content: 'x' }];
  const r = await selectRelevantFiles({ AI: ai }, 'anything', files, {});
  assert.equal(r.selected.length, 2);
  assert.match(r.reason, /message embedding failed/);
});

// ── 8b. Thrown provider error (not just bad shape / timeout) -> fail-open
await test('env.AI.run throws -> fail-open, all files kept', async () => {
  const ai = makeMockAI({}, { rejectOnce: 1 });
  const files = [{ name: 'beam.txt', content: 'x' }];
  const r = await selectRelevantFiles({ AI: ai }, 'anything', files, {});
  assert.equal(r.selected.length, 1);
  assert.match(r.reason, /SIMULATED_PROVIDER_ERROR/);
});

// ── 9. maxFiles cap: more clear threshold than maxFiles allows ──────────
await test('4 files all relevant, maxFiles=3 -> top 3 by score kept', async () => {
  const ai = makeMockAI({
    'strong match': [1, 0],
    'a.txt': [Math.cos(10 * Math.PI / 180), Math.sin(10 * Math.PI / 180)], // ~0.985
    'b.txt': [Math.cos(20 * Math.PI / 180), Math.sin(20 * Math.PI / 180)], // ~0.940
    'c.txt': [Math.cos(30 * Math.PI / 180), Math.sin(30 * Math.PI / 180)], // ~0.866
    'd.txt': [Math.cos(40 * Math.PI / 180), Math.sin(40 * Math.PI / 180)], // ~0.766 (lowest, should be dropped)
  });
  const files = [
    { name: 'a.txt', content: 'x' },
    { name: 'b.txt', content: 'x' },
    { name: 'c.txt', content: 'x' },
    { name: 'd.txt', content: 'x' },
  ];
  const r = await selectRelevantFiles({ AI: ai }, 'strong match', files, { maxFiles: 3, threshold: 0.45 });
  assert.deepEqual(r.selected.map((f) => f.name).sort(), ['a.txt', 'b.txt', 'c.txt']);
  assert.match(r.reason, /capped to top 3/);
});

// ── 10. Adversarial cached embedding entry is not trusted as-is ────────
await test('malformed cached embedding (NaN) is treated as uncached, re-embedded', async () => {
  const ai = makeMockAI({
    'question': [1, 0, 0],
    'beam.txt': [1, 0, 0],
  });
  const files = [{ name: 'beam.txt', content: 'x' }];
  const cachedEmbeddings = { 'beam.txt': [NaN, 0, 0] }; // adversarial/corrupt cache entry
  const r = await selectRelevantFiles({ AI: ai }, 'question', files, { cachedEmbeddings });
  // Expect 2 calls: message + file-batch (cache entry rejected, re-embedded)
  assert.equal(ai.calls.length, 2);
  assert.equal(r.selected.length, 1);
  assert.deepEqual(r.embeddings['beam.txt'], [1, 0, 0]); // fresh value, not the NaN one
});

// ── 11. Files with no usable embedding are always kept ──────────────────
await test('file with unembeddable content -> kept unconditionally, score 1', async () => {
  const ai = makeMockAI({
    'question': [1, 0, 0],
    // 'mystery.txt' deliberately has no table entry -> mock returns null
  });
  const files = [
    { name: 'beam.txt', content: 'x' },
    { name: 'mystery.txt', content: 'x' },
  ];
  const r = await selectRelevantFiles({ AI: ai }, 'question', files, {});
  const mystery = r.scores.find((s) => s.name === 'mystery.txt');
  assert.equal(mystery.measured, false);
  assert.equal(mystery.score, 1);
  assert.ok(r.selected.some((f) => f.name === 'mystery.txt'));
});

// ── 12. Empty files array -> short-circuit, no AI call at all ──────────
await test('empty files array -> no env.AI.run call, empty selection', async () => {
  const ai = makeMockAI({});
  const r = await selectRelevantFiles({ AI: ai }, 'question', [], {});
  assert.equal(ai.calls.length, 0);
  assert.deepEqual(r.selected, []);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
  for (const f of failures) console.log(`\n--- ${f.name} ---\n${f.err.stack}`);
  process.exit(1);
}
