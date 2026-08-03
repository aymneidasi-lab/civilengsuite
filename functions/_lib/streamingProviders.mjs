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
    cleanup() {
      clearTimeout(timer);
      if (externalSignal) externalSignal.removeEventListener('abort', onExternalAbort);
    },
  };
}

function withJitterLocal(ms) {
  return ms + Math.floor(Math.random() * 250);
}

async function runStream(res, { extractDelta, onDelta, isDoneMarker }) {
  const reader = res.body.getReader();
  let full = '';
  let committed = false;
  let finishReason = null;
  try {
    for await (const dataStr of iterSseEvents(reader)) {
      const d = extractDelta(dataStr);
      if (d.parseError) continue; // skip one malformed frame, do not abort the whole stream over it
      if (d.text) {
        full += d.text;
        committed = true;
        onDelta(d.text);
      }
      if (d.finished || (isDoneMarker && d.done)) {
        finishReason = d.finishReason || (d.done ? 'DONE' : 'STOP');
        break;
      }
    }
  } catch (err) {
    if (committed) return { ok: true, reply: full, interrupted: true, errStatus: 'STREAM_DROPPED', errBody: String(err && err.message || err) };
    return { ok: false, httpStatus: 0, errStatus: 'STREAM_NETWORK_ERROR', errBody: String(err && err.message || err) };
  } finally {
    try { reader.releaseLock(); } catch { /* already released/closed */ }
  }
  if (!full.trim()) return { ok: false, httpStatus: res.status, errStatus: 'EMPTY_REPLY', errBody: '' };
  return { ok: true, reply: full, finishReason };
}

// ── Gemini (:streamGenerateContent?alt=sse) ────────────────────────────────
// generationConfig is fully caller-specified (not merged with a default) —
// chat.js and vision.js need materially different objects (thinkingBudget
// vs thinkingLevel are mutually exclusive on the 3.x model family; a
// request carrying both is a hard 400 — see vision.js's own header note),
// so silently merging defaults here would risk producing an invalid
// combination for whichever caller didn't expect the merge.
export async function callGeminiStreaming(apiKey, model, contents, systemPrompt, generationConfig, budget, onDelta, externalSignal) {
  if (!budget.take()) return { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };

  const payload = JSON.stringify({
    system_instruction: { parts: [{ text: systemPrompt }] },
    contents,
    generationConfig,
  });

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${apiKey}`;
  const RETRY_DELAYS_MS = [1500, 3500];
  let attempt = 0;
  for (;;) {
    const { signal, cleanup } = timeoutSignal(8000, externalSignal);
    let res;
    try {
      res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload, signal });
    } catch (err) {
      cleanup();
      if (externalSignal && externalSignal.aborted) return { ok: false, httpStatus: 0, errStatus: 'RACE_CANCELLED', errBody: '' };
      return { ok: false, httpStatus: 0, errStatus: 'NETWORK_ERROR', errBody: String(err && err.message || err) };
    }
    if (res.ok) { cleanup(); return runStream(res, { extractDelta: extractGeminiDelta, onDelta }); }
    cleanup();
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
export async function callOpenAiCompatStreaming(url, apiKey, model, messages, budget, onDelta, externalSignal, { maxTokens = 900, temperature = 0.35 } = {}) {
  if (budget && !budget.take()) return { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };

  const payload = JSON.stringify({ model, messages, stream: true, max_tokens: maxTokens, temperature });
  const RETRY_DELAYS_MS = [1500, 3500];
  let attempt = 0;
  for (;;) {
    const { signal, cleanup } = timeoutSignal(8000, externalSignal);
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
        body: payload,
        signal,
      });
    } catch (err) {
      cleanup();
      if (externalSignal && externalSignal.aborted) return { ok: false, httpStatus: 0, errStatus: 'RACE_CANCELLED', errBody: '' };
      return { ok: false, httpStatus: 0, errStatus: 'NETWORK_ERROR', errBody: String(err && err.message || err) };
    }
    if (res.ok) { cleanup(); return runStream(res, { extractDelta: extractOpenAiCompatDelta, onDelta, isDoneMarker: true }); }
    cleanup();
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
export async function callWorkersAIStreaming(aiBinding, messages, onDelta) {
  if (!aiBinding) return { ok: false, httpStatus: 0, errStatus: 'NOT_BOUND', errBody: '' };
  let stream;
  try {
    stream = await aiBinding.run('@cf/meta/llama-3.1-8b-instruct', { messages, stream: true, max_tokens: 900 });
  } catch (err) {
    return { ok: false, httpStatus: 0, errStatus: 'WORKERS_AI_ERROR', errBody: String(err && err.message || err) };
  }
  const res = new Response(stream); // reuse the exact same reader/parsing path as fetch()-based providers
  return runStream(res, { extractDelta: extractWorkersAiDelta, onDelta, isDoneMarker: true });
}
