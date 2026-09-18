// functions/_lib/sessionFileSelector.mjs
//
// Server-side half of "Semantic Session File Persistence". The client keeps
// every session-scoped file in sessionStorage and sends ALL of them in
// body.files on every turn (see chat.js's onRequestPost patch and the
// footing_pro/pc_suite client patch) — that's free, it's HTTP body, not LLM
// token cost. This module is what keeps the LLM PROMPT itself clean on a
// turn that has nothing to do with any stored file: it embeds the user's
// message with the same bge-m3 model chat.js's semanticKbSearch() already
// uses, cosine-scores it against each file's embedding, and returns only the
// files worth spending prompt tokens on. Dropped files stay in the request
// body (available next turn) but never reach buildTextFilesBlock().
//
// No file-count shortcut anywhere in here — a session holding exactly one
// file is scored exactly like a session holding three. v1 of this feature
// shipped a "single file -> skip scoring, always inject" bypass that
// silently reproduced the "zero token tax on unrelated turns" bug this
// whole feature exists to fix, for the single most common case. See the
// prompt's own CHANGELOG for the full contradiction this closes.
//
// Pure-ish (one external effect: env.AI.run), fail-open by construction —
// same contract chat.js's scoreKbForQueryHybrid() already relies on for its
// own bge-m3 call: any failure here must degrade to "keep everything",
// never to a broken or hung turn.

'use strict';

// Mirrors chat.js's PROVIDER_TIMEOUT_MS (8000). chat.js does not export that
// constant (grep confirms no `export` on it), so it's redeclared here and
// must be kept in sync by hand — same hand-copied-constant convention this
// repo already uses for PROVIDER_TIMEOUT_MS/MAX_IMAGES_PER_REQUEST across
// chat.js and vision.js. options.timeoutMs overrides this per call; chat.js
// passes 8000 explicitly at its call site, so this default only matters for
// a caller (a test, a future script) that omits the option.
const DEFAULT_TIMEOUT_MS = 8000;

const DEFAULT_THRESHOLD = 0.45;
const DEFAULT_MAX_FILES = 3;

// First 8000 chars of `name\ncontent` per file, per the prompt spec — bounds
// both the embedding call's payload size and (indirectly) latency, same
// motivation as MAX_CHARS_PER_TEXT_FILE elsewhere in chat.js, but this cap
// is independent of that one: a file already truncated to
// MAX_CHARS_PER_TEXT_FILE (6000) server-side, or DEV_MAX_CHARS_PER_TEXT_FILE
// (Infinity) for elevated tier, still gets its OWN separate cut here before
// embedding — embedding quality past a few thousand chars adds little for a
// relevance signal, and elevated-tier files can be arbitrarily large.
const MAX_EMBED_CHARS = 8000;

// A cached/hand-supplied embedding crosses a trust boundary — cachedEmbeddings
// arrives as body.fileEmbeddings, straight off the wire, never validated by
// anything upstream of this module. A malformed entry (wrong length, a
// string, a NaN) must not corrupt cosineSimilarity's dot product (NaN
// silently poisons every downstream comparison, it doesn't throw) or crash
// the scoring loop somewhere this module's own try/catch can't attribute.
// Checked once, here, so every read of an embeddings map elsewhere in this
// file can assume "usable" already means "safe to do arithmetic on".
function isUsableVector(v) {
  return Array.isArray(v) && v.length > 0 && v.every((n) => typeof n === 'number' && Number.isFinite(n));
}

// No external library, per spec — a dot-product loop and Math.sqrt is all
// bge-m3's fixed-length output vectors need. Mismatched lengths (should
// never happen for two outputs of the same model, but a stale cached
// embedding from a future model swap is exactly the kind of thing that
// SILENTLY wouldn't happen until it did) are handled by scoring only over
// the shared prefix rather than throwing — a degraded score is safer than a
// crash this deep inside a fail-open path.
function cosineSimilarity(a, b) {
  const len = Math.min(a.length, b.length);
  let dot = 0;
  let magA = 0;
  let magB = 0;
  for (let i = 0; i < len; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }
  if (magA === 0 || magB === 0) return 0;
  return dot / (Math.sqrt(magA) * Math.sqrt(magB));
}

// Narrows an embeddings map down to just the files this call was actually
// asked about. Used on every return path (success, mercy-rule, fail-open)
// so a name that fell out of the session (evicted client-side, or simply
// never part of `files` this call) can never resurface via a stale
// cachedEmbeddings passthrough — the client's own Object.assign(
// sessionFileEmbeddings, doneEvent.fileEmbeddings) merges whatever this
// returns straight into its persistent cache without a matching prune step,
// so this module is the only place that can stop a deleted key from
// reappearing.
function pickEmbeddingsForFiles(source, files) {
  const out = {};
  for (const f of files) {
    if (isUsableVector(source[f.name])) out[f.name] = source[f.name];
  }
  return out;
}

/**
 * @param {*} env - Cloudflare Pages Function env; needs env.AI.
 * @param {string} userMessage - this turn's typed message (already trimmed
 *   by chat.js — see const userMessage = body.message.trim() at the call
 *   site).
 * @param {Array<{name:string, content:string}>} files - allIncomingFiles:
 *   textFilesResult.files.concat(kvFilesResult.files). Only .name/.content
 *   are read; extra fields (truncated, originalLength) are ignored here and
 *   untouched on the returned `selected` entries.
 * @param {{threshold?:number, maxFiles?:number, cachedEmbeddings?:Object,
 *   timeoutMs?:number}} [options]
 * @returns {Promise<{selected:Array, embeddings:Object,
 *   scores:Array<{name:string,score:number,measured:boolean}>,
 *   reason:string}>}
 */
export async function selectRelevantFiles(env, userMessage, files, options = {}) {
  const threshold = typeof options.threshold === 'number' ? options.threshold : DEFAULT_THRESHOLD;
  const maxFiles = typeof options.maxFiles === 'number' ? options.maxFiles : DEFAULT_MAX_FILES;
  const timeoutMs = typeof options.timeoutMs === 'number' ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
  const suppliedCache = (options.cachedEmbeddings && typeof options.cachedEmbeddings === 'object')
    ? options.cachedEmbeddings
    : {};

  if (!Array.isArray(files) || files.length === 0) {
    return { selected: [], embeddings: {}, scores: [], reason: 'no files to select from' };
  }

  // Same missing-binding fail-open scoreKbForQueryHybrid() uses for the
  // identical model (`if (!env || !env.AI || !env.VECTORIZE) return
  // keywordScored`) — this module has no VECTORIZE dependency, only AI.
  if (!env || !env.AI) {
    return {
      selected: files,
      embeddings: pickEmbeddingsForFiles(suppliedCache, files),
      scores: [],
      reason: 'env.AI not bound — fail-open, all files kept',
    };
  }

  // Tracks which stage failed so the fail-open catch below can report a
  // useful reason instead of a bare "something threw" — the three stages
  // (embed the message, embed uncached files, score) fail for different
  // operational reasons and get diagnosed differently in logs.
  let stage = 'message embedding';
  try {
    const embedMessageResult = await Promise.race([
      env.AI.run('@cf/baai/bge-m3', { text: [userMessage] }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('EMBED_TIMEOUT')), timeoutMs)),
    ]);
    const queryVector = embedMessageResult?.data?.[0];
    if (!isUsableVector(queryVector)) {
      throw new Error(`unexpected message embedding shape (${JSON.stringify(embedMessageResult)?.slice(0, 200)})`);
    }

    stage = 'file embedding';
    // Start from the caller's cache, then fill in only what's missing —
    // this is the mechanism that makes "a second turn referencing the same
    // file triggers no new bge-m3 call" true. isUsableVector, not a bare
    // truthy/array check, is deliberate here: an untrusted cached entry
    // that LOOKS like a vector but isn't (see that function's own comment)
    // must be treated as absent and re-embedded, not trusted as-is.
    const embeddings = { ...suppliedCache };
    const uncached = files.filter((f) => !isUsableVector(embeddings[f.name]));

    if (uncached.length > 0) {
      const texts = uncached.map((f) => `${f.name}\n${f.content || ''}`.slice(0, MAX_EMBED_CHARS));
      const embedFilesResult = await Promise.race([
        env.AI.run('@cf/baai/bge-m3', { text: texts }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('EMBED_TIMEOUT')), timeoutMs)),
      ]);
      const vectors = embedFilesResult?.data;
      if (!Array.isArray(vectors) || vectors.length !== uncached.length) {
        throw new Error(`unexpected file embedding response shape (${JSON.stringify(embedFilesResult)?.slice(0, 200)})`);
      }
      uncached.forEach((f, i) => {
        // A single bad vector in an otherwise-good batch does not throw —
        // that file just falls through to the "no usable embedding, score
        // 1.0, kept" rule below instead of failing the whole turn's
        // selection over one model hiccup on one file.
        if (isUsableVector(vectors[i])) embeddings[f.name] = vectors[i];
      });
    }

    stage = 'scoring';
    const scores = [];
    let selected = [];
    for (const f of files) {
      const vec = embeddings[f.name];
      if (!isUsableVector(vec)) {
        // "Kept, never drop what you can't measure" is unconditional — NOT
        // implemented as score>=threshold, so it holds even if a caller
        // ever passed threshold>1. Applies at files.length===1 too: an
        // unmeasurable lone file is still kept; only a MEASURED lone file
        // below threshold produces an empty selection (see the
        // files.length===1 contract below).
        scores.push({ name: f.name, score: 1, measured: false });
        selected.push(f);
        continue;
      }
      const score = cosineSimilarity(queryVector, vec);
      scores.push({ name: f.name, score, measured: true });
      if (score >= threshold) selected.push(f);
    }

    // Mercy rule — reachable ONLY when every file this turn was both
    // measured and below threshold (any unmeasured file already made
    // `selected` non-empty above, unconditionally). Explicitly excluded at
    // files.length===1: with one file there is no "highest-scoring of the
    // set" to fall back to, just that one score against the threshold, so
    // the mercy rule would silently re-create the exact per-file token tax
    // constraint 1 forbids for the single-file case — see the prompt's own
    // CHANGELOG item 1.
    let reason;
    if (selected.length === 0 && files.length >= 2) {
      let best = scores[0];
      for (const s of scores) if (s.score > best.score) best = s;
      const bestFile = files.find((f) => f.name === best.name);
      if (bestFile) {
        selected = [bestFile];
        reason = `no file cleared threshold ${threshold} — kept highest-scoring (${best.name}, ${best.score.toFixed(3)})`;
      }
    }
    if (reason === undefined) {
      reason = selected.length === files.length
        ? `all ${files.length} file(s) kept (threshold ${threshold})`
        : `kept ${selected.length} of ${files.length} file(s) (threshold ${threshold})`;
    }

    // maxFiles is an independent hard cap on prompt injection, not a
    // threshold parameter — chat.js's call site passes maxFiles:3
    // unconditionally, including for hasElevatedAccess sessions where
    // extractTextFiles' own ceiling is Infinity, so more than maxFiles
    // files can legitimately all clear the threshold in one turn (e.g. a
    // dev session with 5 freshly-attached, all-relevant files). Ranked by
    // score, not original order, when the cap actually bites — unmeasured
    // files (score 1) sort first and are therefore the last to be dropped
    // by this cap, consistent with "never drop what you can't measure"
    // still winning out under a tight cap.
    if (selected.length > maxFiles) {
      const scoreByName = new Map(scores.map((s) => [s.name, s.score]));
      selected = [...selected]
        .sort((a, b) => (scoreByName.get(b.name) ?? 0) - (scoreByName.get(a.name) ?? 0))
        .slice(0, maxFiles);
      reason += `; capped to top ${maxFiles} by score`;
    }

    return {
      selected,
      embeddings: pickEmbeddingsForFiles(embeddings, files),
      scores,
      reason,
    };
  } catch (err) {
    // Same top-level fail-open contract semanticKbSearch's caller
    // (scoreKbForQueryHybrid) applies to that function: ANY throw here —
    // including a timeout rejection, which becomes a throw via Promise.race
    // rather than an indefinite hang — degrades to "keep everything",
    // logged with which stage failed. chat.js's own call site also wraps
    // this function in try/catch (belt-and-suspenders): that outer catch
    // exists for a bug in THIS module raising something unexpected; this
    // one is the documented, primary fail-open path.
    console.warn(`[sessionFileSelector] ${stage} failed — fail-open, all files kept:`, err && err.message);
    return {
      selected: files,
      embeddings: pickEmbeddingsForFiles(suppliedCache, files),
      scores: [],
      reason: `${stage} failed (${(err && err.message) || 'unknown error'}) — fail-open, all files kept`,
    };
  }
}

// Exposed for a sibling *.test.mjs only, mirrors contextAnchor.mjs's own
// __testables() convention — not part of the surface chat.js calls.
export function __testables() {
  return { cosineSimilarity, isUsableVector, pickEmbeddingsForFiles };
}
