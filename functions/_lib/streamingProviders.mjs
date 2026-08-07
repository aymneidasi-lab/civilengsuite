// Streaming replacements for chat.js's callGeminiWithRetry / callGroqWithRetry
// / callOpenRouterWithRetry / callWorkersAIWithRetry. Same external contract
// as far as onRequestPost is concerned (an {ok, ...} result object) PLUS
// live onDelta(text) callbacks as text arrives, so the caller can relay to
// the client without waiting for the full reply.
//
// COMMITMENT SEMANTICS (read before wiring into onRequestPost):
// `committed` goes true the instant the FIRST delta is emitted to onDelta.
// Before that point, any failure (HTTP error, network drop, timeout) is a
// clean, ordinary `{ok:false}` -- nothing has reached the client yet, so
// onRequestPost's existing fallback-to-next-provider loop behaves exactly
// as it does today. AFTER that point, this attempt owns the client's
// stream: a failure can no longer silently fall back to a different
// provider (the client has already rendered part of an answer from THIS
// one), so it resolves `{ok:true, reply, interrupted:true}` instead of
// `{ok:false}` -- onRequestPost must treat that as a completed turn (send
// the stream-end event) rather than retrying, and the client is expected
// to show a short "connection interrupted" trailer (see chat.js patch UI
// section) rather than silently losing the partial answer.
import { iterSseEvents } from './sseStream.mjs';
import { extractGeminiDelta, extractOpenAiCompatDelta, extractWorkersAiDelta } from './providerDeltas.mjs';

// Combines a fixed timeout with an externally-supplied AbortSignal (from
// raceKeyPool's per-attempt controller) into a single signal, without
// relying on AbortSignal.any() -- not universally confirmed across Workers
// runtime versions -- and without relying on AbortSignal.timeout() alone,
// which has a documented un-catchable-rejection quirk under `wrangler dev`
// --local (cloudflare/workerd#1020; does not reproduce under --remote or in
// production, but a manual controller sidesteps it either way).
function timeoutSignal(ms, externalSignal) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('PROVIDER_TIMEOUT')), ms);
  const onExternalAbort = () => controller.abort(externalSignal.reason);
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort(externalSignal.reason);
    else externalSignal.addEventListener('abort', onExternalAbort, { once: true });
  }
  return {
    signal: controller.signal,
    // [PATCH] Resource-lifecycle fix -- split from the original single
    // cleanup(). The original called removeEventListener on externalSignal
    // as soon as fetch() resolved (headers back), which is BEFORE the body
    // is read. Once that listener is gone, a losing racer's cancelOthers()
    // (raceKeyPool.mjs) firing mid-body-read no longer reaches this
    // `controller` at all -- the fetch's own AbortSignal binding is now
    // permanently deaf to the external cancel, so the losing racer's
    // reader keeps consuming network + CPU (parsing every remaining SSE
    // frame, discarded) all the way to its own natural stream end instead
    // of stopping the instant it loses the race. Call this once headers
    // are back; it only stops the fixed-duration connect-timeout, which no
    // longer applies once the response has started.
    clearConnectTimeout() {
      clearTimeout(timer);
    },
    // Call this once the body is fully done being read (success, error, or
    // externally cancelled) -- detaches the forwarding listener so it does
    // not outlive the request. Safe to call more than once.
    release() {
      clearTimeout(timer);
      if (externalSignal) externalSignal.removeEventListener('abort', onExternalAbort);
    },
  };
}

function withJitterLocal(ms) {
  return ms + Math.floor(Math.random() * 250);
}

// [PATCH] `signal` param added -- when the caller's combined signal (still
// live for the whole body read now that release() is deferred, see above)
// aborts mid-stream, proactively cancel the reader instead of relying only
// on the implicit fetch-body-abort binding, so a losing racer's connection
// and per-chunk parsing stop within one microtask of losing, not whenever
// its own upstream response happens to finish.
async function runStream(res, { extractDelta, onDelta, isDoneMarker, signal }) {
  const reader = res.body.getReader();
  let full = '';
  let committed = false;
  let finishReason = null;
  // [PATCH — search bridge] Only ever set by extractGeminiDelta, and only on
  // grounded turns; stays null for every non-grounded reply and for the
  // other two providers' extractors, which never populate this key on `d`.
  let groundingMetadata = null;
  let externallyCancelled = false;
  const onAbort = () => {
    externallyCancelled = true;
    try { reader.cancel(signal && signal.reason); } catch { /* already closed */ }
  };
  if (signal) {
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  }
  try {
    for await (const dataStr of iterSseEvents(reader)) {
      const d = extractDelta(dataStr);
      if (d.parseError) continue; // skip one malformed frame, do not abort the whole stream over it
      if (d.text) {
        full += d.text;
        committed = true;
        onDelta(d.text);
      }
      // [PATCH — search bridge] Keep the latest non-null value rather than
      // only reading it off the terminal chunk: Google's docs don't commit
      // to which chunk carries it in streaming mode, so this is correct
      // whether it lands once on the last chunk or is repeated earlier.
      if (d.groundingMetadata) groundingMetadata = d.groundingMetadata;
      if (d.finished || (isDoneMarker && d.done)) {
        finishReason = d.finishReason || (d.done ? 'DONE' : 'STOP');
        break;
      }
    }
  } catch (err) {
    if (committed) return { ok: true, reply: full, interrupted: true, errStatus: 'STREAM_DROPPED', errBody: String(err && err.message || err), groundingMetadata };
    return { ok: false, httpStatus: 0, errStatus: 'STREAM_NETWORK_ERROR', errBody: String(err && err.message || err) };
  } finally {
    if (signal) signal.removeEventListener('abort', onAbort);
    try { reader.releaseLock(); } catch { /* already released/closed */ }
  }
  if (externallyCancelled) {
    // reader.cancel() resolves the pending read() instead of rejecting it,
    // so this exits through the normal path above, not the catch{} block --
    // verified empirically, not assumed (see testonly/integration_test.mjs).
    // Report it through the same shape the catch{} branch uses for a
    // mid-stream drop, so nothing downstream (onAttemptSettled, logging)
    // has to special-case a third result shape for what is, from their
    // point of view, the same "cut short after committing" event.
    return committed
      ? { ok: true, reply: full, interrupted: true, errStatus: 'RACE_CANCELLED', errBody: '', groundingMetadata }
      : { ok: false, httpStatus: 0, errStatus: 'RACE_CANCELLED', errBody: '' };
  }
  if (!full.trim()) return { ok: false, httpStatus: res.status, errStatus: 'EMPTY_REPLY', errBody: '' };
  return { ok: true, reply: full, finishReason, groundingMetadata };
}

// ── Gemini (:streamGenerateContent?alt=sse) ────────────────────────────────
// generationConfig is fully caller-specified (not merged with a default) —
// chat.js and vision.js need materially different objects (thinkingBudget
// vs thinkingLevel are mutually exclusive on the 3.x model family; a
// request carrying both is a hard 400 — see vision.js's own header note),
// so silently merging defaults here would risk producing an invalid
// combination for whichever caller didn't expect the merge.
// [PATCH — search bridge] `tools` param appended at the END of the existing
// positional list (not inserted, not converted to an options object) so the
// two existing call sites — chat.js's text tier and vision.js's image tier —
// need zero changes and simply pass `undefined`, same as any other JS call
// with a missing trailing arg. Caller-supplied for the same reason
// generationConfig already is (see header comment above): the google_search
// tool is chat.js-only for now (see chat.js's own GOOGLE_SEARCH_TOOL
// comment for why vision.js is deliberately excluded), and hardcoding it
// here would silently turn it on for every future caller of this function.
export async function callGeminiStreaming(apiKey, model, contents, systemPrompt, generationConfig, budget, onDelta, externalSignal, tools) {
  if (!budget.take()) return { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };

  const payload = JSON.stringify({
    system_instruction: { parts: [{ text: systemPrompt }] },
    contents,
    generationConfig,
    // Gemini API rejects mixing google_search with function-calling tools in
    // one request (not applicable here — this codebase declares no function
    // tools) but is otherwise a plain top-level sibling of generationConfig;
    // confirmed against the current v1beta REST wire format, not the SDK's
    // camelCase binding — this file talks to the raw endpoint directly.
    ...(tools && { tools }),
  });

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${apiKey}`;
  const RETRY_DELAYS_MS = [1500, 3500];
  let attempt = 0;
  for (;;) {
    // [MERGE] budget-accounting fix: each retry is a REAL, separate
    // fetch() and must draw its own unit from `budget`, or the app's own
    // SUBREQUEST_BUDGET_FREE_PLAN counter (48, a 2-request margin under
    // Cloudflare's real 50/invocation free-plan ceiling) undercounts
    // actual usage by up to 2x whenever a key hits 500/503 and retries --
    // large enough on its own to trip the platform's hard, non-catchable
    // per-invocation limit while the app's tracker still reports budget
    // remaining. Independent of, and additive with, this file's own
    // reader.cancel()-based abort fix above.
    if (attempt > 0 && !budget.take()) {
      return { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };
    }
    const { signal, clearConnectTimeout, release } = timeoutSignal(8000, externalSignal);
    let res;
    try {
      res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload, signal });
    } catch (err) {
      release();
      if (externalSignal && externalSignal.aborted) return { ok: false, httpStatus: 0, errStatus: 'RACE_CANCELLED', errBody: '' };
      return { ok: false, httpStatus: 0, errStatus: 'NETWORK_ERROR', errBody: String(err && err.message || err) };
    }
    if (res.ok) {
      clearConnectTimeout();
      return runStream(res, { extractDelta: extractGeminiDelta, onDelta, signal }).finally(release);
    }
    release();
    if ((res.status === 500 || res.status === 503) && attempt < RETRY_DELAYS_MS.length) {
      await new Promise((r) => setTimeout(r, withJitterLocal(RETRY_DELAYS_MS[attempt])));
      attempt++;
      continue;
    }
    let errBody = '', errStatus = '';
    try { errBody = await res.text(); errStatus = JSON.parse(errBody)?.error?.status || ''; } catch { /* non-JSON error body */ }
    return { ok: false, httpStatus: res.status, errStatus, errBody };
  }
}

// ── Groq / OpenRouter (OpenAI-compatible chat.completions, stream:true) ────
// One function for both -- identical wire format, only url/model differ.
// Preserves the "13 keys" retry-per-key structure at the onRequestPost
// level; this function itself does 500/503 backoff exactly like Gemini's.
export async function callOpenAiCompatStreaming(url, apiKey, model, messages, budget, onDelta, externalSignal, { maxTokens = 2048, temperature = 0.35 } = {}) {
  if (budget && !budget.take()) return { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };

  const payload = JSON.stringify({ model, messages, stream: true, max_tokens: maxTokens, temperature });
  const RETRY_DELAYS_MS = [1500, 3500];
  let attempt = 0;
  for (;;) {
    // [MERGE] same budget-accounting fix as callGeminiStreaming above.
    if (attempt > 0 && budget && !budget.take()) {
      return { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };
    }
    const { signal, clearConnectTimeout, release } = timeoutSignal(8000, externalSignal);
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
        body: payload,
        signal,
      });
    } catch (err) {
      release();
      if (externalSignal && externalSignal.aborted) return { ok: false, httpStatus: 0, errStatus: 'RACE_CANCELLED', errBody: '' };
      return { ok: false, httpStatus: 0, errStatus: 'NETWORK_ERROR', errBody: String(err && err.message || err) };
    }
    if (res.ok) {
      clearConnectTimeout();
      return runStream(res, { extractDelta: extractOpenAiCompatDelta, onDelta, isDoneMarker: true, signal }).finally(release);
    }
    release();
    if ((res.status === 500 || res.status === 503) && attempt < RETRY_DELAYS_MS.length) {
      await new Promise((r) => setTimeout(r, withJitterLocal(RETRY_DELAYS_MS[attempt])));
      attempt++;
      continue;
    }
    let errBody = '', errStatus = '';
    try { errBody = await res.text(); errStatus = JSON.parse(errBody)?.error?.type || JSON.parse(errBody)?.error?.code || ''; } catch { /* non-JSON error body */ }
    return { ok: false, httpStatus: res.status, errStatus, errBody };
  }
}

// ── Cloudflare Workers AI (env.AI.run(model, {stream:true})) ───────────────
// No fetch(), no URL, no subrequest-budget draw -- same as the non-streaming
// original. env.AI.run() returns a ReadableStream directly when stream:true.
export async function callWorkersAIStreaming(aiBinding, messages, onDelta, { maxTokens = 2048 } = {}) {
  if (!aiBinding) return { ok: false, httpStatus: 0, errStatus: 'NOT_BOUND', errBody: '' };
  let stream;
  try {
    stream = await aiBinding.run('@cf/meta/llama-3.1-8b-instruct', { messages, stream: true, max_tokens: maxTokens });
  } catch (err) {
    return { ok: false, httpStatus: 0, errStatus: 'WORKERS_AI_ERROR', errBody: String(err && err.message || err) };
  }
  const res = new Response(stream); // reuse the exact same reader/parsing path as fetch()-based providers
  return runStream(res, { extractDelta: extractWorkersAiDelta, onDelta, isDoneMarker: true });
}
