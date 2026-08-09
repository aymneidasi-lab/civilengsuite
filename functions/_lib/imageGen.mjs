// functions/_lib/imageGen.mjs
// Zero-cost text-to-image generation via Cloudflare Workers AI — the SAME
// env.AI binding chat.js's callWorkersAIWithRetry already uses for the
// Layer-3 text fallback. No new API key, no new secret, no wrangler.toml
// change. Binding calls do not draw from SUBREQUEST_BUDGET_FREE_PLAN —
// that counter is fetch()-only (see streamingProviders.mjs's own comment
// on callWorkersAIStreaming for the identical point re: text) — so
// nothing here takes a `budget` param.
//
// TWO MODELS, TRIED IN ORDER, SAME env.AI BINDING, SAME FREE NEURON POOL:
//   1. '@cf/black-forest-labs/flux-1-schnell' — fast, cheap (4 steps by
//      design), primary.
//   2. '@cf/bytedance/stable-diffusion-xl-lightning' — different model
//      family, used only if #1 throws/times out/returns something
//      unusable. A different model, not a same-model retry: recovers
//      from an outage or deprecation of #1 specifically, which a retry
//      against the same model does nothing for.
//
// A single-model version of this file (and two independent attempts at
// adding this exact fallback before it) assumed both models return
// { image: <base64 string> }. Verified against Cloudflare's own docs and
// two independent official usage examples that this is wrong for #2:
//   - developers.cloudflare.com/workers-ai/models/stable-diffusion-xl-base-1.0
//     and .../stable-diffusion-v1-5-img2img (same Stable Diffusion
//     pipeline family as the Lightning model): "The binding returns a
//     ReadableStream with the output."
//   - Cloudflare's own blog usage example for that family:
//       const response = await env.AI.run("@cf/bytedance/stable-diffusion-xl-lightning", inputs);
//       return new Response(response, { headers: { "content-type": "image/jpg" } });
//     — response is passed directly as a Response body, not read as
//     response.image.
// normalizeImageResult() below handles both shapes so this fallback
// actually works instead of silently returning EMPTY_IMAGE whenever it's
// reached. It also takes `num_steps` (not `steps`) — a second, unrelated
// reason a shared call path across both models needs to be parameterized
// per-model, not copy-pasted.
//
// PROMPT STEERING (added after a live-traffic report: "draw combined
// footing" produced a cartoon foot kicking a ball, not a foundation
// diagram). Both models are general-purpose consumer/art diffusion
// models — neither has meaningful training on engineering-drawing
// datasets — so raw user prompts get mapped to whatever the model's
// broadest, most common association with the words is. That is
// especially bad for this app specifically: "footing" (this app's own
// namesake term) reads as feet/shoes/sports far more often in general
// image-caption data than as a foundation element. buildEngineeringPrompt()
// wraps every prompt in blueprint/line-drawing style framing plus an
// explicit civil-engineering reading of the common ambiguous terms; the
// Stable-Diffusion-family fallback additionally gets a real
// negative_prompt (flux-1-schnell's documented input schema is prompt +
// steps only — no negative_prompt field — so its steering is
// positive-language-only). This raises the odds of an on-topic,
// technical-looking illustration; it does not make either model capable
// of a dimensionally-correct or professionally-accurate engineering
// drawing — both are fast/cheap models traded for speed over precision,
// and neither should be treated as a substitute for actual drafting.
// PROMPT ITERATION 2 (after a second live report): the v1 template above
// asked for "labeled cross-section, dimension lines" — which is exactly
// what produced a diagram with a fake "50mm" width callout, a "6m" label
// on an unrelated segment, and garbled text ("bem", "Slad", "Slap" for
// "beam"/"slab") dressed up in confident technical typography. This is
// not a prompt-wording problem: diffusion models of this class do not
// compose or spell text reliably at all — they paint plausible-looking
// glyph shapes, not characters — and neither model here has any grounding
// in real structural magnitudes to begin with, so any number they render
// is invented regardless of phrasing. A wrong-but-confident-looking
// dimension on a foundation is worse than no dimension, so the fix is to
// stop asking for labels/numbers entirely rather than trying to get them
// right. buildEngineeringPrompt() below asks for a clean unlabeled
// outline; NEGATIVE_PROMPT explicitly excludes text/digits for the model
// that supports it. The frontend also carries a fixed disclaimer under
// every generated image now (see appendBotImageBubble in pc_suite/
// footing_pro) — this reduces the odds of fabricated numbers, it does
// not guarantee a completely text-free result, and a user should never
// treat a generated image as a source of actual dimensions.
function buildEngineeringPrompt(userPrompt) {
  return `Technical civil/structural engineering line-art diagram, drafting/blueprint style, black-and-white: ${userPrompt}. Interpret every term in a civil engineering and construction context (e.g. "footing", "column", "beam", "pile", "slab" are structural or foundation elements — not feet, furniture, light, or unrelated meanings). Clean geometric outline only, hatching to indicate concrete/material sections, no text, no numbers, no dimension labels, no measurements, no annotations, no watermark — a pure unlabeled line-art schematic on a white background.`;
}
const NEGATIVE_PROMPT = 'cartoon, comic, anime, photo, photorealistic, people, hands, faces, feet, shoes, sports, sketchbook, colored pencils, watercolor, painting, colorful, playful, cute, watermark, signature, text, numbers, digits, dimension labels, measurements, handwritten text, illegible writing, gibberish text, blurry';

const MODEL_ATTEMPTS = [
  { model: '@cf/black-forest-labs/flux-1-schnell',
    buildParams: (p) => ({ prompt: buildEngineeringPrompt(p), steps: 4 }) },                                              // max 8 per docs; 4 is the model's own default
  { model: '@cf/bytedance/stable-diffusion-xl-lightning',
    buildParams: (p) => ({ prompt: buildEngineeringPrompt(p), num_steps: 4, negative_prompt: NEGATIVE_PROMPT }) },        // max 20 per docs; 4 is the commonly-recommended value for this "few-step" model, not its own default of 20
];

const MAX_PROMPT_CHARS = 500; // UX bound for a chat text field, not a cost lever — diffusion cost scales with steps/resolution, not prompt length
const RETRY_DELAY_MS = 1200;  // matches callWorkersAIWithRetry's own retry delay, applied between model attempts

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

// String.fromCharCode.apply(null, hugeArray) can overflow the call stack
// for a full-size image (a few hundred KB of bytes) — chunking keeps
// every call well under any engine's argument-count limit. btoa/
// ReadableStream/Response are Workers-runtime globals; no import needed.
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const CHUNK = 8192;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

// Normalizes either of Workers AI's known text-to-image output shapes —
// { image: <base64> } (flux-1-schnell) or a ReadableStream / ArrayBuffer /
// TypedArray of raw bytes (the Stable-Diffusion-family models, including
// stable-diffusion-xl-lightning — see the header comment) — to a plain
// base64 string. Returns null, not a throw, if the shape is unrecognized:
// an unrecognized response is a "try the next model" condition for the
// caller, not a hard failure.
async function normalizeImageResult(result) {
  if (result && typeof result.image === 'string' && result.image) {
    return result.image;
  }
  let buffer = null;
  if (result instanceof ReadableStream) {
    buffer = await new Response(result).arrayBuffer();
  } else if (result instanceof ArrayBuffer) {
    buffer = result;
  } else if (ArrayBuffer.isView(result)) {
    buffer = result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength);
  }
  if (!buffer || buffer.byteLength === 0) return null;
  return arrayBufferToBase64(buffer);
}

// One attempt against one model, bounded by a non-cancelling timeout —
// env.AI.run() has no documented AbortSignal parameter (verified Aug
// 2026), so this only bounds how long THIS function waits, not the
// call's own server-side lifetime (see chat.js's Resource Lifecycle notes
// at the call site). Both handlers are attached directly to
// aiBinding.run()'s own promise — not a bare Promise.race against a timer
// with the run() promise left bare — so a late settlement after the
// timeout has already won never has zero listeners; nothing here can
// produce an unhandled-rejection warning.
function runOnce(aiBinding, model, params, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('WORKERS_AI_IMAGE_TIMEOUT')), timeoutMs);
    aiBinding.run(model, params).then(
      (res) => { clearTimeout(timer); resolve(res); },
      (err) => { clearTimeout(timer); reject(err); },
    );
  });
}

// Tries each entry in MODEL_ATTEMPTS in order, moving to the next on
// either a thrown error (timeout, transient Workers AI failure) or a
// successful call whose output normalizeImageResult() can't parse.
// Returns { ok: true, base64, mime, model } — model is whichever one
// actually produced the image, for the response's `source` field and
// server-side logs — or { ok: false, httpStatus: 0, errStatus, errBody }
// once every entry has failed.
export async function generateImageWorkersAI(aiBinding, prompt, opts = {}) {
  if (!aiBinding) {
    return { ok: false, httpStatus: 0, errStatus: 'NOT_BOUND', errBody: 'env.AI is not bound on this Pages project.' };
  }
  const timeoutMs = opts.timeoutMs ?? 20000; // diffusion is slower than chat.js's PROVIDER_TIMEOUT_MS (8000ms, sized for an LLM text reply)

  let lastErr = '';
  for (let i = 0; i < MODEL_ATTEMPTS.length; i++) {
    const { model, buildParams } = MODEL_ATTEMPTS[i];
    if (i > 0) await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
    try {
      const raw = await runOnce(aiBinding, model, buildParams(prompt), timeoutMs);
      const base64 = await normalizeImageResult(raw);
      if (base64) {
        return { ok: true, base64, mime: 'image/jpeg', model };
      }
      lastErr = `${model}: response had no recognizable image payload`;
      console.warn(`[imageGen.mjs] ${lastErr}`);
    } catch (err) {
      lastErr = `${model}: ${err.message}`;
      console.warn(`[imageGen.mjs] attempt failed — ${lastErr}`);
    }
  }
  console.error('[imageGen.mjs] all models failed:', lastErr);
  return { ok: false, httpStatus: 0, errStatus: 'WORKERS_AI_IMAGE_ERROR', errBody: lastErr };
}
