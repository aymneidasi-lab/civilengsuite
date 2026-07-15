// functions/api/vision.js
// =============================================================================
// Civil Engineering Suite — Vision API (Cloudflare Pages Function)
// v1.0 — "Insert Image" feature backend.
//
// Provider: Google Gemini, reusing the EXISTING 13-key GEMINI_API_KEY ring
// already configured for chat.js (same Cloudflare env vars, no new keys).
// Stays on Cloudflare Pages Free plan — no server-side image decode/resize.
//
// Reused, byte-identical to chat.js, NOT re-derived: rotateStart,
// makeFetchBudget, fetchWithTimeout, checkRateLimit, buildGeminiKeyPool,
// keyTagFor, GEMINI_API_URL shape, ?key= auth, thinkingConfig fix, empty-
// reply/thought-filtering, getCorsHeaders pattern, json() helper shape,
// isArabicText pattern. See CORRECTIONS block below for the handful of
// places this deliberately does NOT match chat.js, and why.
//
// CORRECTIONS vs. the original feature spec (see also chat.js patch notes):
//   1. Model: gemini-2.5-flash (spec's example) is scheduled for shutdown
//      2026-10-16 per chat.js's own migration-history comment, and was
//      independently confirmed still-current-but-sunsetting via a live
//      model-docs check. Using it in NEW code today would work for ~3
//      months and then silently break. Using gemini-3.5-flash instead —
//      chat.js's own current GEMINI_MODEL_PRIMARY, GA since 2026-05-19,
//      confirmed image-input-capable. Isolated to GEMINI_VISION_MODEL
//      below either way, so this is a one-line change if that ever stops
//      being true.
//   2. Auth: Gemini's key goes in the URL (?key=), not an x-goog-api-key
//      header — matches chat.js's actual, working callGeminiWithRetry, not
//      the header-based shape the spec assumed.
//   3. thinkingConfig: { thinkingBudget: 0 } is REQUIRED, not optional polish.
//      Gemini 3.x models think by default; thinking tokens share the same
//      maxOutputTokens budget as the visible answer. chat.js hit exactly
//      this bug once already (v19: intermittent truncation / leaked
//      reasoning-looking text) before adding this line. Vision prompts are
//      at least as likely to trigger "complex enough to think" as a FAQ
//      chat turn, so this is ported over as a fix, not a style choice.
//   4. Size guard math: the spec set the server Content-Length ceiling and
//      the VBA pre-flight file-size guard to the SAME literal number
//      (~1.8MB), but they measure different things — VBA checks the RAW
//      file (it doesn't resize, unlike the web client's canvas step);
//      base64 inflates that by 4/3 before it reaches this endpoint's JSON
//      body. A raw file between ~1.35MB and 1.8MB would pass the VBA
//      pre-flight check, then get rejected here anyway after the user
//      already waited through the upload. Fixed: MAX_BODY_BYTES is derived
//      from MAX_RAW_IMAGE_BYTES via the same 4/3 factor, not restated as
//      an independent number.
//   5. Timeout-stacking: the spec's 45s per-attempt AbortController timeout,
//      combined with retrying across multiple keys, means a genuinely slow
//      (not erroring) upstream could compound to attempts × 45s — several
//      minutes in the worst case — while the VBA client itself only waits
//      45s (modSTTAPI.bas's TIMEOUT_RECEIVE, the correct sibling to match:
//      it's also an upload-shaped endpoint, unlike modChatAPI.bas's 60s,
//      which is long-REPLY-shaped). Fixed two ways: (a) FETCH_TIMEOUT_MS
//      trimmed to 40s, leaving 5s headroom under the VBA client's 45s
//      window; (b) on a timeout specifically, the rotation loop BREAKS
//      instead of rotating to the next key — there is no time budget left
//      for another 40s attempt within any reasonable caller's patience.
//      Fast failures (429 / 5xx) still rotate immediately, matching
//      chat.js. Same-key backoff-retry for 500/503 (chat.js does this,
//      2 attempts with jitter) is deliberately NOT ported — at chat's 8s
//      per-attempt timeout that's safely bounded; at vision's 40s it is
//      not, so 500/503 here is treated the same as 429 (rotate, don't
//      retry in place).
//   6. Rate limiting: the spec didn't mention it, but chat.js has its own
//      IP-based limiter specifically because CORS is not a server-side
//      control and the 13-key pool is a shared, abusable resource. Vision
//      requests plausibly cost more per call than a short chat turn, so
//      leaving this endpoint unthrottled would be a regression, not
//      neutral. Reuses checkRateLimit with the SAME key (CF-Connecting-IP)
//      chat.js uses, so one visitor draws from one combined per-minute
//      budget across both endpoints, rather than getting two.
//   7. Bilingual errors: this product's own chat.js localizes even its
//      rate-limit message (EGP pricing / Arabic UI throughout — this is
//      not incidental). Vision's user-facing errors follow the same
//      isArabicText(message) pattern for consistency.
// =============================================================================

import {
  rotateStart,
  makeFetchBudget,
  SUBREQUEST_BUDGET_FREE_PLAN,
  fetchWithTimeout,
  checkRateLimit,
  buildGeminiKeyPool,
  keyTagFor,
} from '../_lib/rotation.mjs';

// ── Model ────────────────────────────────────────────────────────────────
// Matches chat.js's GEMINI_MODEL_PRIMARY exactly (see CORRECTIONS #1).
// Migration history: gemini-2.0-flash -> shut down 2026-06-01.
//                    gemini-2.5-flash -> shut down 2026-10-16, do not use.
//                    gemini-3.5-flash -> current GA, free tier, image-input
//                    capable, active from 2026-05-19. Do not revert.
const GEMINI_VISION_MODEL = 'gemini-3.5-flash';
const GEMINI_API_URL = model =>
  `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

// ── Timeouts (see CORRECTIONS #5) ───────────────────────────────────────
let FETCH_TIMEOUT_MS = 40000;
// Test-only seam — production code never calls this. ES module imports are
// read-only live bindings, so a test file cannot reassign FETCH_TIMEOUT_MS
// directly; this setter is how test-vision.mjs shrinks it to make the
// timeout test fast instead of waiting 40 real seconds.
export function _setFetchTimeoutForTesting(ms) { FETCH_TIMEOUT_MS = ms; }

// ── Size guard (see CORRECTIONS #4) ─────────────────────────────────────
// Raw photo ceiling — matches modVisionAPI.bas's MAX_IMAGE_BYTES exactly.
// Both sides limit the ORIGINAL file; only the VBA path can actually reach
// this in practice, since the web client canvas-resizes first.
const MAX_RAW_IMAGE_BYTES = 1_800_000;
// Base64 inflates payload size by exactly 4/3. +4096 is headroom for the
// JSON envelope (message + mimeType fields, punctuation — a few hundred
// bytes at most for realistic inputs).
const MAX_BODY_BYTES = Math.ceil(MAX_RAW_IMAGE_BYTES * 4 / 3) + 4096; // 2,404,096
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

// ── CORS — copied from chat.js's getCorsHeaders, not extracted ─────────
// (Extracting stateless, pure, trivially-copyable helpers like this one
// and json() below would touch chat.js more than the spec asked for, for
// no real benefit — unlike checkRateLimit, there's no shared-state drift
// risk from two copies of a pure function. See rotation.mjs's header
// comment for the line this project draws between "extract" and "copy".)
const ALLOWED_ORIGINS = new Set(['https://civilengsuite.pages.dev']);
function getCorsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const isLocal =
    origin.startsWith('http://localhost:') ||
    origin.startsWith('http://127.0.0.1:');
  const allowed = ALLOWED_ORIGINS.has(origin) || isLocal ? origin : ALLOWED_ORIGINS.values().next().value;
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Client-Date',
    'Vary': 'Origin',
  };
}

function json(data, status = 200, extraHeaders, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...getCorsHeaders(request),
      ...(extraHeaders || {}),
    },
  });
}

// Same Arabic-range test as chat.js's isArabicText — good enough to pick
// ONE reply language, not meant to classify mixed-script input.
function isArabicText(str) {
  return /[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]/.test(str || '');
}

// ── Gemini call ──────────────────────────────────────────────────────────
// Returns { ok: true, reply } or { ok: false, httpStatus, errStatus, errBody }.
async function callGeminiVision(apiKey, model, promptText, base64Image, mimeType, budget) {
  const payload = JSON.stringify({
    contents: [{
      parts: [
        { text: promptText },
        { inline_data: { mime_type: mimeType, data: base64Image } },
      ],
    }],
    generationConfig: {
      // Vision answers (describing/critiquing a technical image) tend to
      // run longer than chat's FAQ replies (900) — 1536 as a safety
      // margin now that thinking isn't silently eating the same budget.
      maxOutputTokens: 1536,
      temperature: 0.4,
      topP: 0.9,
      // REQUIRED — see CORRECTIONS #3.
      thinkingConfig: { thinkingBudget: 0 },
    },
  });

  if (!budget.take()) {
    return { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };
  }

  let res;
  try {
    res = await fetchWithTimeout(`${GEMINI_API_URL(model)}?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: payload,
    }, FETCH_TIMEOUT_MS);
  } catch (err) {
    const isTimeout = err.name === 'AbortError';
    if (!isTimeout) {
      console.error(`[vision.js] Network error calling Gemini (${model}):`, err.message);
    }
    return {
      ok: false,
      httpStatus: 0,
      errStatus: isTimeout ? 'TIMEOUT' : 'NETWORK_ERROR',
      errBody: err.message,
    };
  }

  if (!res.ok) {
    let errBody = '';
    let errStatus = '';
    try {
      errBody = await res.text();
      errStatus = JSON.parse(errBody)?.error?.status || '';
    } catch { /* non-fatal — body may be non-JSON */ }
    if (res.status !== 429) {
      console.error(`[vision.js] Gemini HTTP ${res.status} for model ${model}:`, errBody.slice(0, 500));
    }
    return { ok: false, httpStatus: res.status, errStatus, errBody };
  }

  const data = await res.json();
  const finishReason = data?.candidates?.[0]?.finishReason;
  if (finishReason === 'MAX_TOKENS') {
    console.warn(`[vision.js] Gemini ${model} hit MAX_TOKENS (budget: 1536) — reply may be truncated.`);
  }
  // Filter out any `thought: true` part (defense in depth even with
  // thinkingBudget: 0) — matches chat.js's v19 fix exactly.
  const parts = data?.candidates?.[0]?.content?.parts || [];
  const reply = parts
    .filter(p => !p?.thought && typeof p?.text === 'string')
    .map(p => p.text)
    .join('')
    .trim();
  if (!reply) {
    // Empty-after-filter (safety block, blank candidate) is a FAILURE, not
    // a successful 200 with nothing in it — see CORRECTIONS block preamble.
    return { ok: false, httpStatus: res.status, errStatus: 'EMPTY_REPLY', errBody: '' };
  }
  return { ok: true, reply };
}

// ── Friendly error builder (bilingual — see CORRECTIONS #7) ────────────
function buildFriendlyError(result, ar) {
  if (result.errStatus === 'SUBREQUEST_BUDGET_EXHAUSTED' || result.errStatus === 'TIMEOUT') {
    return ar
      ? 'الخدمة بطيئة شوية دلوقتي، جرب تاني بعد لحظات.'
      : 'The vision service is slow to respond right now. Please try again shortly.';
  }
  if (result.errStatus === 'EMPTY_REPLY') {
    return ar
      ? 'معرفتش أوصف الصورة دي، جرب صورة تانية أو سؤال أوضح.'
      : "Couldn't get a usable answer for that image. Try a different image or a more specific question.";
  }
  const byStatus = {
    429: {
      en: 'Too many requests. Please wait a moment and try again.',
      ar: 'طلبات كتير بسرعة، استنى لحظة وجرب تاني.',
    },
    502: { en: 'The vision service is temporarily unavailable. Please try again in a minute.',
           ar: 'الخدمة مش متاحة دلوقتي، جرب تاني بعد دقيقة.' },
    503: { en: 'The vision service is temporarily unavailable. Please try again in a minute.',
           ar: 'الخدمة مش متاحة دلوقتي، جرب تاني بعد دقيقة.' },
  };
  const matched = byStatus[result.httpStatus];
  if (matched) return ar ? matched.ar : matched.en;
  return ar
    ? 'حصل مشكلة في تحليل الصورة، حاول مرة أخرى.'
    : 'Something went wrong analyzing that image. Please try again.';
}

// ── Handler ──────────────────────────────────────────────────────────────
export async function onRequestPost(context) {
  const { request, env } = context;

  // 1. Content-Length guard FIRST, before touching the body at all — the
  //    whole point is avoiding the cost of reading/parsing a huge payload.
  const declaredLength = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (declaredLength > MAX_BODY_BYTES) {
    return json(
      { error: 'Image is too large. Please pick a smaller photo (original under ~1.8MB). / الصورة كبيرة، اختار صورة أصغر.' },
      413, undefined, request,
    );
  }

  // 2. Rate limit — same clientIp key as chat.js, see rotation.mjs header
  //    comment for why this is shared rather than vision-specific.
  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateCheck = await checkRateLimit(env, clientIp);
  if (rateCheck.limited) {
    return json(
      { error: 'Too many requests too quickly. Please wait a moment and try again. / طلبات كتير بسرعة، استنى لحظة.' },
      429, undefined, request,
    );
  }

  // 3. Validate at least one Gemini key exists before doing anything else.
  if (!env.GEMINI_API_KEY) {
    return json(
      { error: 'No AI provider configured. Set GEMINI_API_KEY in Cloudflare Pages environment variables.' },
      500, undefined, request,
    );
  }

  // 4. Read raw body (no Content-Type gate — VBA and browser callers both
  //    just work) and defense-in-depth length guard for the case
  //    Content-Length was absent or understated (chunked transfer, proxy
  //    rewrite, lying client) — a cheap string-length check before the
  //    real cost, JSON.parse, runs.
  let rawBody;
  try {
    rawBody = await request.text();
  } catch {
    return json({ error: 'Could not read request body.' }, 400, undefined, request);
  }
  if (rawBody.length > MAX_BODY_BYTES * 1.05) {
    return json(
      { error: 'Image is too large. Please pick a smaller photo (original under ~1.8MB). / الصورة كبيرة، اختار صورة أصغر.' },
      413, undefined, request,
    );
  }

  let body;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return json({ error: 'Request body must be valid JSON.' }, 400, undefined, request);
  }

  const likelyArabic = isArabicText(body?.message);

  const promptText = (typeof body?.message === 'string' && body.message.trim().slice(0, 2000)) || 'Describe this image.';
  let imageBase64 = body?.image;
  const mimeType = body?.mimeType || 'image/jpeg';

  if (!imageBase64 || typeof imageBase64 !== 'string') {
    return json({ error: 'Missing image data.' }, 400, undefined, request);
  }
  // Defensive: strip a data: URL prefix if a caller forgot to (both
  // shipped frontends already strip it client-side — see CORRECTIONS
  // preamble; this only guards a future/other caller).
  if (imageBase64.startsWith('data:') && imageBase64.includes(',')) {
    imageBase64 = imageBase64.split(',')[1];
  }
  if (imageBase64.length < 100 || !/^[A-Za-z0-9+/]+=*$/.test(imageBase64)) {
    return json({ error: 'Image data is not valid base64.' }, 400, undefined, request);
  }
  if (!ALLOWED_MIME_TYPES.includes(mimeType)) {
    return json({ error: 'Unsupported image type. Use JPEG, PNG, or WebP.' }, 400, undefined, request);
  }

  // 5. Rotation loop — full filtered pool, gated by shared subrequest
  //    budget, matching chat.js's Gemini-layer structure (see rotation.mjs
  //    buildGeminiKeyPool/keyTagFor). Single model per key (no primary/
  //    fallback doubling like chat.js's two-model layer) — deliberate
  //    simplification, see CORRECTIONS preamble.
  const budget = makeFetchBudget(SUBREQUEST_BUDGET_FREE_PLAN);
  const geminiPool = rotateStart(buildGeminiKeyPool(env));

  let lastResult = { ok: false, httpStatus: 0, errStatus: 'NOT_ATTEMPTED', errBody: '' };
  for (const { key: gKey, originalIndex } of geminiPool) {
    if (budget.remaining() <= 0) {
      lastResult = { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };
      break;
    }
    const keyTag = keyTagFor(originalIndex);
    const res = await callGeminiVision(gKey, GEMINI_VISION_MODEL, promptText, imageBase64, mimeType, budget);
    if (res.ok) {
      return json({ reply: res.reply }, 200, { 'X-CES-Vision-Source': `gemini-${keyTag}vision` }, request);
    }
    if (res.errStatus !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
      console.warn(`[vision.js] Gemini ${keyTag || 'key1-'}vision failed:`, res.errStatus, res.httpStatus);
    }
    lastResult = res;
    // See CORRECTIONS #5 — a timeout means the shared budget for THIS
    // request is spent on wall time, not attempts; stop instead of
    // compounding another 40s attempt on top of it.
    if (res.errStatus === 'TIMEOUT') break;
  }

  return json({ error: buildFriendlyError(lastResult, likelyArabic) }, 502, undefined, request);
}

export async function onRequestOptions(context) {
  return new Response(null, { headers: getCorsHeaders(context.request) });
}
