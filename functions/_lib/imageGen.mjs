// functions/_lib/imageGen.mjs
// Zero-cost text-to-image generation via Cloudflare Workers AI — the SAME
// env.AI binding chat.js's callWorkersAIWithRetry already uses for the
// Layer-3 text fallback. No new API key, no new secret, no wrangler.toml
// change. Binding calls do not draw from SUBREQUEST_BUDGET_FREE_PLAN —
// that counter is fetch()-only (see streamingProviders.mjs's own comment
// on callWorkersAIStreaming for the identical point re: text) — so
// nothing here takes a `budget` param.
//
// MODEL: '@cf/black-forest-labs/flux-1-schnell' only. Verified against
// developers.cloudflare.com/workers-ai/models/flux-1-schnell (Aug 2026):
// Input { prompt: string, required, max 2048 chars; steps: 1-8, default
// 4 }. Output { image: <base64-encoded JPEG> }.
//
// NO FALLBACK MODEL, DELIBERATELY. The obvious second choice,
// '@cf/bytedance/stable-diffusion-xl-lightning', does NOT share this
// output contract — Cloudflare's own usage example for it returns the
// raw binary response directly:
//   const response = await env.AI.run("@cf/bytedance/...-lightning", inputs);
//   return new Response(response, { headers: { "content-type": "image/jpg" } });
// — not `{ image: <base64> }`. A same-shape fallback wired in without
// handling that conversion (stream/ArrayBuffer -> base64, chunked to
// avoid a stack overflow on `String.fromCharCode(...largeArray)` for a
// multi-hundred-KB image) would silently return EMPTY_IMAGE on every
// fallback attempt. It also takes `num_steps` (default 20, max 20), not
// `steps` — a second reason a shared call path across both models is not
// a small change. A correctly-handled fallback is a reasonable future
// addition; it needs its own conversion path, not a shared one with this
// function.
const IMAGE_MODEL = '@cf/black-forest-labs/flux-1-schnell';
const IMAGE_GEN_STEPS = 4;    // model default; hard ceiling per docs is 8
const MAX_PROMPT_CHARS = 500; // UX bound for a chat text field, not a cost lever — diffusion cost scales with steps/resolution, not prompt length
const RETRY_DELAY_MS = 1200;  // matches callWorkersAIWithRetry's own retry delay

// Returns { ok: true, prompt } or { ok: false, code, maxChars? }. Codes
// only, no user-facing text — chat.js already owns the likelyArabic /
// English message choice for every other validation error on this
// endpoint (see its rate-limit and devCommand branches); duplicating that
// decision in here would just be a second place for the two languages to
// drift out of sync.
export function validateImagePrompt(raw) {
  const prompt = typeof raw === 'string' ? raw.trim() : '';
  if (!prompt) {
    return { ok: false, code: 'PROMPT_REQUIRED' };
  }
  if (prompt.length > MAX_PROMPT_CHARS) {
    return { ok: false, code: 'PROMPT_TOO_LONG', maxChars: MAX_PROMPT_CHARS };
  }
  return { ok: true, prompt };
}

// One attempt, bounded by a non-cancelling timeout — env.AI.run() has no
// documented AbortSignal parameter (verified Aug 2026), so this only
// bounds how long THIS function waits, not the call's own server-side
// lifetime (see chat.js's Resource Lifecycle notes at the call site).
// Both handlers are attached directly to aiBinding.run()'s own promise —
// not a bare Promise.race against a timer with the run() promise left
// bare — so a late settlement after the timeout has already won never
// has zero listeners; nothing here can produce an unhandled-rejection
// warning.
function runOnce(aiBinding, prompt, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('WORKERS_AI_IMAGE_TIMEOUT')), timeoutMs);
    aiBinding.run(IMAGE_MODEL, { prompt, steps: IMAGE_GEN_STEPS }).then(
      (res) => { clearTimeout(timer); resolve(res); },
      (err) => { clearTimeout(timer); reject(err); },
    );
  });
}

// Returns { ok: true, base64, mime, model } or
//         { ok: false, httpStatus: 0, errStatus, errBody }
export async function generateImageWorkersAI(aiBinding, prompt, opts = {}) {
  if (!aiBinding) {
    return { ok: false, httpStatus: 0, errStatus: 'NOT_BOUND', errBody: 'env.AI is not bound on this Pages project.' };
  }
  const timeoutMs = opts.timeoutMs ?? 20000; // diffusion is slower than chat.js's PROVIDER_TIMEOUT_MS (8000ms, sized for an LLM text reply)

  let result;
  try {
    result = await runOnce(aiBinding, prompt, timeoutMs);
  } catch (err) {
    console.warn('[imageGen.mjs] attempt 1 failed:', err.message);
    await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
    try {
      result = await runOnce(aiBinding, prompt, timeoutMs);
    } catch (err2) {
      console.error('[imageGen.mjs] failed after retry:', err2.message);
      return { ok: false, httpStatus: 0, errStatus: 'WORKERS_AI_IMAGE_ERROR', errBody: err2.message };
    }
  }

  const base64 = result && typeof result.image === 'string' ? result.image : '';
  if (!base64) {
    return { ok: false, httpStatus: 0, errStatus: 'EMPTY_IMAGE', errBody: '' };
  }
  return { ok: true, base64, mime: 'image/jpeg', model: IMAGE_MODEL };
}
