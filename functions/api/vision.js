/**
 * functions/api/vision.js — v2.0 (merged synthesis, 2026-07-16)
 * ─────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — "Insert Image" backend for Civil Engineering
 * Suite chat (web + VBA desktop). Route: POST /api/vision.
 *
 * Sibling to functions/api/chat.js — separate file/route so a vision bug
 * cannot take down text chat. Reuses chat.js's Gemini key ring (same 13
 * env vars, no new provider/signup/cost) and the shared rotation/subrequest
 * helpers in functions/_lib/rotation.mjs.
 *
 * ── This file supersedes 5 independently-drafted candidates. Where they
 *    disagreed, the choice below was settled by live verification (web
 *    search, 2026-07-16), not majority vote — three concrete corrections
 *    that vote would have gotten wrong:
 *
 *   1. Payload field casing. 4/5 candidates mixed casing; 1/5 was uniform
 *      camelCase. Confirmed against ai.google.dev's OWN curl examples
 *      (Image understanding + System instructions pages, current as of
 *      this writing): raw REST calls to generateContent use SNAKE_CASE for
 *      message-level fields — `system_instruction`, `inline_data`,
 *      `mime_type` — but CAMELCASE inside `generationConfig`
 *      (`maxOutputTokens`, `topP`, `thinkingConfig`). A mismatched
 *      generationConfig field is silently ignored, not rejected (confirmed
 *      via a live langchain4j bug report: a snake_cased thinkingConfig was
 *      dropped with no error) — exactly the kind of silent failure that
 *      would reintroduce chat.js's v19 truncation bug. Every candidate
 *      that used camelCase for generationConfig was already safe there;
 *      the fix is confined to the inline_data/mime_type/system_instruction
 *      layer.
 *   2. Image-before-text ordering. One candidate claimed Google recommends
 *      text-before-image for a single-image prompt and reordered the parts
 *      array on that basis. The current official guidance (ai.google.dev,
 *      Image Understanding) says the opposite: place the text prompt AFTER
 *      the image for a single-image request. Reverted to image-then-text,
 *      which is also what 4/5 candidates already did.
 *   3. Cloudflare Free plan limits. Verified current (2026-07): 10ms CPU
 *      time/invocation, 50 EXTERNAL subrequests/invocation (a Feb-2026
 *      changelog removed a *different*, internal 1000-subrequest ceiling —
 *      it did not touch the external-fetch limit these files size their
 *      budgets against). CPU time excludes time spent awaiting fetch(),
 *      confirming the "large wall-clock timeout is fine, large CPU-bound
 *      work is not" design load-bearing in every candidate's header.
 *
 * ── Other merge decisions, none individually load-bearing enough for a
 *    numbered correction above, but each picked from whichever candidate
 *    argued it best:
 *   - Body reading: streaming reader with a hard byte cap (one candidate),
 *     not read-then-measure (four candidates) — the only approach that
 *     avoids fully buffering an oversized/spoofed-Content-Length body.
 *   - Gemini payload JSON.stringify()'d ONCE outside the retry loop (one
 *     candidate) — the request body never varies across the up-to-26
 *     key/model attempts; only the URL does. Re-stringifying per-attempt
 *     (four candidates) repeats ~1.7MB-string CPU work up to 26x against a
 *     10ms/invocation ceiling.
 *   - No in-place backoff-retry on 500/503 (one candidate's simplification,
 *     adopted): with 13 keys in the pool, rotating to the next key already
 *     gets the retry effect without paying the 1.5-3.5s in-place delay —
 *     strictly faster for both the per-key-blip case and the
 *     provider-wide-outage case.
 *   - System instruction kept as its own field, separate from the user's
 *     message (three candidates did this correctly; two folded persona
 *     text into the default prompt, which is silently discarded the
 *     moment the caller supplies its own message/question).
 *   - HEIC/HEIF added to the MIME allow-list — confirmed supported Gemini
 *     input formats (one candidate had this; the other four only allowed
 *     jpeg/png/webp).
 *   - Request field names: accepts BOTH `message`/`prompt` and BOTH
 *     `mimeType`/`mime` — the 5 candidates disagreed on which the actual
 *     client sends and this file can't see chat.js/the HTML clients to
 *     settle it, so both aliases are accepted rather than guessing wrong.
 *   - Pre-body-parse errors (size/JSON/rate-limit/no-key) are bilingual
 *     (language truly unknown at that point); post-parse errors use the
 *     detected language only (nicer UX once it's known).
 * ─────────────────────────────────────────────────────────────────────────
 */

import {
  rotateStart,
  makeFetchBudget,
  fetchWithTimeout,
  checkRateLimit,
} from '../_lib/rotation.mjs';

// ── Models — same pair chat.js uses. gemini-3.5-flash confirmed current
// GA/multimodal (ai.google.dev, 2026-07). gemini-2.5-flash is NOT used here
// per chat.js's own migration-history comment (shutdown 2026-10-16).
const GEMINI_MODEL_PRIMARY  = 'gemini-3.5-flash';
const GEMINI_MODEL_FALLBACK = 'gemini-3.1-flash-lite';
const GEMINI_API_URL = model =>
  `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
const GEMINI_MAX_OUTPUT_TOKENS = 1536; // vision replies run longer than chat's FAQ turns

// ── Size / MIME guards ──────────────────────────────────────────────────
// ~1.8MB JSON-body ceiling (base64 image + small text fields). Base64
// inflates raw bytes by ~4/3, so this implies a ~1.3MB raw-image budget —
// that's the number the client-side compressors (web canvas, VBA) target.
// This endpoint never resizes server-side: Cloudflare Free plan's 10ms CPU
// ceiling makes that 18-72x over budget (measured 178-720ms for decode+
// resize) — resize must happen client-side, before the request is sent.
const MAX_BODY_BYTES = 1_800_000;
const MIME_ALLOWLIST = new Set([
  'image/jpeg', 'image/png', 'image/webp', 'image/heic', 'image/heif',
]);
const MESSAGE_MAX_LEN = 2000;

// ── Timeouts ─────────────────────────────────────────────────────────────
// Per-attempt: long enough for one multimodal call under normal conditions,
// short enough to fail over to another key rather than hang. Overall
// deadline: once elapsed time crosses this, stop STARTING new attempts (an
// attempt already in flight is left to finish or hit its own per-attempt
// ceiling) — bounds the worst case across a 13-key x 2-model pool without
// aborting a request that's actually about to succeed.
const PER_ATTEMPT_TIMEOUT_MS = 25_000;
const OVERALL_DEADLINE_MS    = 40_000;

// Worst case: 13 keys x 2 models = 26 — comfortably under the Free plan's
// 50-external-subrequest ceiling (verified 2026-07) with no shaving needed.
const SUBREQUEST_BUDGET_VISION = 26;

const ASSISTANT_NAME = 'Eng_pro assist';
const VISION_SYSTEM_PROMPT = `You are ${ASSISTANT_NAME}, the AI assistant for Civil Engineering Suite \
(civilengsuite.pages.dev), built by Eng. Aymn Asi — a practicing Licensed Structural Engineer. You are \
looking at a photo, drawing, or screenshot a member of a civil/structural engineering team has attached \
in chat, together with their question or instruction.

Describe what you actually see first — element type, visible condition, and any labels, dimensions, or \
numbers legible in the image — then answer the specific question asked, if one was given. If the image \
shows a possible structural, safety, or code-compliance concern, say so plainly and recommend it be \
verified by a licensed engineer on site before anyone acts on it: you are giving a preliminary visual \
read, not a substitute for an in-person inspection or a stamped calculation. If the image is blurry, too \
dark, or you are not confident about a measurement or defect, say so directly instead of guessing a \
specific number.

Reply in the SAME language as the person's own message (Arabic or English) — never mix both in one \
reply. Keep the reply focused and practical: this is a working engineer reading a chat reply, not a \
report.`;

function isArabicText(str) {
  return /[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]/.test(str || '');
}

// ── CORS — copied locally rather than assumed-shared (see header: this
// file can't verify whether a shared cors.mjs exists in the real project,
// and a wrong import would break the build outright). ───────────────────
const ALLOWED_ORIGINS = new Set(['https://civilengsuite.pages.dev']);
function getCorsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const isLocal =
    origin.startsWith('http://localhost:') ||
    origin.startsWith('http://127.0.0.1:');
  const allowed = ALLOWED_ORIGINS.has(origin) || isLocal ? origin : ALLOWED_ORIGINS.values().next().value;
  return {
    'Access-Control-Allow-Origin' : allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Client-Date',
    'Vary'                        : 'Origin',
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

// Errors that can occur before the body is parsed — language is genuinely
// unknown at that point, so both languages are shown together.
function prevalidationError(en, ar) {
  return `${en} / ${ar}`;
}

// ── Friendly, bilingual (language-detected) error builder for everything
// that happens AFTER the user's message has been parsed. ────────────────
function buildFriendlyVisionError(result, ar) {
  if (result.errStatus === 'RESOURCE_EXHAUSTED') {
    return ar
      ? 'الحصة اليومية لتحليل الصور اتخلصت — بترجع بعد منتصف الليل UTC. للأسئلة العاجلة: واتساب +201287232413 · aymneidasi@gmail.com.'
      : 'Daily image-analysis quota reached — resets after midnight UTC. For urgent questions: WhatsApp +201287232413 · aymneidasi@gmail.com.';
  }
  if (result.errStatus === 'RATE_LIMIT_EXCEEDED') {
    return ar
      ? 'في طلبات كتير دلوقتي. استنى 30-60 ثانية وحاول تاني.'
      : 'Too many requests right now. Please wait 30-60 seconds and try again.';
  }
  if (result.errStatus === 'SUBREQUEST_BUDGET_EXHAUSTED' || result.errStatus === 'OVERALL_DEADLINE_EXCEEDED') {
    return ar
      ? 'المساعد مشغول جداً دلوقتي. حاول تاني بعد لحظات.'
      : 'The assistant is extremely busy right now. Please try again in a moment.';
  }
  if (result.errStatus === 'TIMEOUT') {
    return ar
      ? 'الخدمة بطيئة شوية دلوقتي. جرب تاني بعد لحظات.'
      : 'The vision service is slow to respond right now. Please try again shortly.';
  }
  if (result.errStatus === 'EMPTY_REPLY') {
    return ar
      ? 'معرفتش أوصف الصورة دي. جرب صورة تانية أو وضّح سؤالك.'
      : "Couldn't get a usable answer for that image. Try a different image or a more specific question.";
  }
  if ((result.errStatus || '').startsWith('BLOCKED_')) {
    return ar
      ? 'تعذّر تحليل هذه الصورة (تم حظرها من قبل فلتر المحتوى).'
      : 'This image could not be analyzed (content filter).';
  }
  if (result.httpStatus === 400) {
    return ar
      ? 'الطلب المرسل إلى نموذج الرؤية غير صالح.'
      : 'The request to the vision model was malformed.';
  }
  const byStatus = {
    401: { en: 'API authentication failed. Please contact site admin.', ar: 'فشل المصادقة، تواصل مع المسؤول.' },
    403: { en: 'API access denied. Please contact site admin.',          ar: 'الوصول محجوب، تواصل مع المسؤول.' },
    404: { en: 'Vision model unavailable. Please contact site admin.',   ar: 'نموذج تحليل الصور غير متاح، تواصل مع المسؤول.' },
    500: { en: 'The image-analysis service encountered an error. Please try again.', ar: 'حصل خطأ في خدمة تحليل الصورة، حاول مرة أخرى.' },
    503: { en: 'The image-analysis service is temporarily unavailable. Please try again in a minute.', ar: 'خدمة تحليل الصورة مش متاحة دلوقتي، جرب تاني بعد دقيقة.' },
  };
  const matched = byStatus[result.httpStatus];
  if (matched) return ar ? matched.ar : matched.en;

  return ar
    ? 'حصل مشكلة أثناء تحليل الصورة، حاول مرة أخرى، أو تواصل معنا: واتساب +201287232413 · aymneidasi@gmail.com.'
    : 'Something went wrong analyzing the image. Please try again, or contact us: WhatsApp +201287232413 · aymneidasi@gmail.com.';
}

// ── Body reader with a hard byte cap enforced on ACTUAL bytes received,
// independent of the (possibly absent or spoofed) Content-Length header —
// the Content-Length check in onRequestPost is only a cheap fast path. ──
async function readBodyWithCap(request, capBytes) {
  if (!request.body) return await request.text();
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > capBytes) {
      try { await reader.cancel(); } catch { /* best-effort */ }
      throw new Error('PAYLOAD_TOO_LARGE');
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { merged.set(c, offset); offset += c.byteLength; }
  return new TextDecoder('utf-8').decode(merged);
}

// ── Provider call — single attempt, no in-place backoff-retry (see header
// rationale). payloadString is pre-built ONCE by the caller and reused
// verbatim across every key/model attempt; only the URL varies. ─────────
async function callGeminiVisionOnce(apiKey, model, payloadString, budget) {
  if (!budget.take()) {
    return { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };
  }

  let res;
  try {
    res = await fetchWithTimeout(
      `${GEMINI_API_URL(model)}?key=${apiKey}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payloadString },
      PER_ATTEMPT_TIMEOUT_MS,
    );
  } catch (err) {
    const isTimeout = err.name === 'AbortError';
    if (!isTimeout) {
      console.error(`[vision.js] Network error calling Gemini (${model}):`, err.message);
    }
    return { ok: false, httpStatus: 0, errStatus: isTimeout ? 'TIMEOUT' : 'NETWORK_ERROR', errBody: err.message };
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

  let data;
  try {
    data = await res.json();
  } catch (err) {
    return { ok: false, httpStatus: res.status, errStatus: 'BAD_JSON_RESPONSE', errBody: err.message };
  }

  const blockReason = data?.promptFeedback?.blockReason;
  if (blockReason) {
    return { ok: false, httpStatus: res.status, errStatus: `BLOCKED_${blockReason}`, errBody: '' };
  }

  const candidate = data?.candidates?.[0];
  const finishReason = candidate?.finishReason;
  if (finishReason === 'SAFETY' || finishReason === 'PROHIBITED_CONTENT' || finishReason === 'BLOCKLIST') {
    return { ok: false, httpStatus: res.status, errStatus: `BLOCKED_${finishReason}`, errBody: '' };
  }
  if (finishReason === 'MAX_TOKENS') {
    console.warn(`[vision.js] Gemini ${model} hit MAX_TOKENS (budget: ${GEMINI_MAX_OUTPUT_TOKENS}) — reply may be truncated.`);
  }

  const parts = candidate?.content?.parts || [];
  const reply = parts
    .filter(p => !p?.thought && typeof p?.text === 'string')
    .map(p => p.text)
    .join('')
    .trim();
  if (!reply) {
    return { ok: false, httpStatus: res.status, errStatus: 'EMPTY_REPLY', errBody: '' };
  }
  return { ok: true, reply };
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // 0. Cheapest possible reject — Content-Length header, before any body
  //    read at all. Fast path only; the real guard is readBodyWithCap.
  const declaredLength = Number(request.headers.get('content-length') || 0);
  if (declaredLength > MAX_BODY_BYTES) {
    return json(
      { error: prevalidationError(
          'Image is too large. Please use a photo under ~1.3MB (the app compresses this automatically).',
          'الصورة كبيرة جدًا. الرجاء استخدام صورة أصغر من ١.٣ ميغابايت تقريبًا.',
        ) },
      413, undefined, request,
    );
  }

  // 1. Rate limit — namespaced 'vision:' so an image-upload burst and a
  //    text-chat burst from the same IP draw from separate budgets: image
  //    requests are heavier (bigger payload, slower provider call) and
  //    would otherwise throttle unrelated chat traffic from the same user.
  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateCheck = await checkRateLimit(env, `vision:${clientIp}`);
  if (rateCheck.limited) {
    return json(
      { error: prevalidationError(
          'Too many image requests too quickly. Please wait a moment and try again.',
          'صور كتير بسرعة. استنى لحظة وحاول تاني.',
        ) },
      429, undefined, request,
    );
  }

  // 2. Gemini configured at all — cheap env read, no I/O.
  const baseGeminiKey = env.GEMINI_API_KEY || '';
  if (!baseGeminiKey) {
    return json(
      { error: prevalidationError(
          'No AI provider configured. Set GEMINI_API_KEY in Cloudflare Pages environment variables.',
          'لا يوجد مزود ذكاء اصطناعي مُهيأ. الرجاء ضبط GEMINI_API_KEY في إعدادات Cloudflare Pages.',
        ) },
      500, undefined, request,
    );
  }

  // 3. Read body under a hard cap enforced on actual bytes received.
  let rawBody;
  try {
    rawBody = await readBodyWithCap(request, MAX_BODY_BYTES);
  } catch (err) {
    if (err.message === 'PAYLOAD_TOO_LARGE') {
      return json(
        { error: prevalidationError(
            'Image is too large. Please use a photo under ~1.3MB.',
            'الصورة كبيرة جدًا. الرجاء استخدام صورة أصغر من ١.٣ ميغابايت تقريبًا.',
          ) },
        413, undefined, request,
      );
    }
    return json({ error: prevalidationError('Could not read the request body.', 'تعذّرت قراءة الطلب.') }, 400, undefined, request);
  }

  // 4. Parse — read raw text first regardless of Content-Type (a VBA
  //    MSXML2 caller has no reason to send one), then JSON.parse manually.
  let body;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return json({ error: prevalidationError('Request body must be valid JSON.', 'يجب أن يكون محتوى الطلب بصيغة JSON صحيحة.') }, 400, undefined, request);
  }

  // 5. Extract fields. Both `message`/`prompt` and `mimeType`/`mime` are
  //    accepted — see header note on why this file can't be sure which
  //    the real client sends without seeing chat.js/the HTML clients.
  let userMessage =
    (typeof body?.message === 'string' && body.message.trim()) ||
    (typeof body?.prompt === 'string' && body.prompt.trim()) ||
    '';
  if (!userMessage) {
    userMessage = 'Please review this image and share your engineering observations.';
  }
  if (userMessage.length > MESSAGE_MAX_LEN) {
    userMessage = userMessage.slice(0, MESSAGE_MAX_LEN);
  }

  const lang = body?.lang === 'ar' ? 'ar' : body?.lang === 'en' ? 'en' : null;
  const likelyArabic = lang ? lang === 'ar' : isArabicText(userMessage);
  if (lang === 'ar') {
    userMessage += '\n\n[الرجاء الرد باللغة العربية فقط]';
  } else if (lang === 'en') {
    userMessage += '\n\n[Please reply in English only]';
  }

  let imageBase64 = typeof body?.image === 'string' ? body.image.trim() : '';
  if (imageBase64.startsWith('data:') && imageBase64.includes(',')) {
    imageBase64 = imageBase64.split(',')[1];
  }
  if (!imageBase64) {
    return json({ error: buildFriendlyVisionError({ httpStatus: 400, errStatus: '' }, likelyArabic) }, 400, undefined, request);
  }
  if (imageBase64.length < 100 || !/^[A-Za-z0-9+/]+=*$/.test(imageBase64)) {
    return json({ error: likelyArabic ? 'بيانات الصورة ليست Base64 صالحة.' : 'Image data is not valid base64.' }, 400, undefined, request);
  }

  const mimeType = (
    (typeof body?.mimeType === 'string' && body.mimeType.trim().toLowerCase()) ||
    (typeof body?.mime === 'string' && body.mime.trim().toLowerCase()) ||
    ''
  );
  if (!MIME_ALLOWLIST.has(mimeType)) {
    return json({
      error: likelyArabic
        ? 'نوع صورة غير مدعوم. استخدم JPEG أو PNG أو WEBP أو HEIC أو HEIF.'
        : 'Unsupported image type. Use JPEG, PNG, WEBP, HEIC, or HEIF.',
    }, 400, undefined, request);
  }

  // 6. Build the outbound Gemini payload ONCE — identical across every
  //    key/model attempt (only the URL varies), see header note on why
  //    this matters under a 10ms/invocation CPU ceiling. Casing verified
  //    2026-07 against ai.google.dev's own curl examples: snake_case for
  //    system_instruction/inline_data/mime_type, camelCase inside
  //    generationConfig.
  const payloadString = JSON.stringify({
    system_instruction: { parts: [{ text: VISION_SYSTEM_PROMPT }] },
    contents: [{
      role: 'user',
      parts: [
        { inline_data: { mime_type: mimeType, data: imageBase64 } }, // image before text — see header note
        { text: userMessage },
      ],
    }],
    generationConfig: {
      maxOutputTokens: GEMINI_MAX_OUTPUT_TOKENS,
      temperature    : 0.35,
      topP           : 0.9,
      // Disables Gemini 3.x's default "thinking" tokens, which otherwise
      // draw from the SAME maxOutputTokens budget as the visible answer
      // (chat.js's v19 fix). Single-shot description/QA has no need for
      // multi-step reasoning, so this has only downside here.
      thinkingConfig : { thinkingBudget: 0 },
    },
  });

  // 7. Build the key pool — SAME 13 keys chat.js reads. Built inline
  //    rather than imported from an assumed rotation.mjs helper whose
  //    exact export name/shape this file can't verify.
  const geminiKeysIndexed = [
    env.GEMINI_API_KEY    || '',
    env.GEMINI_API_KEY_2  || '',
    env.GEMINI_API_KEY_3  || '',
    env.GEMINI_API_KEY_4  || '',
    env.GEMINI_API_KEY_5  || '',
    env.GEMINI_API_KEY_6  || '',
    env.GEMINI_API_KEY_7  || '',
    env.GEMINI_API_KEY_8  || '',
    env.GEMINI_API_KEY_9  || '',
    env.GEMINI_API_KEY_10 || '',
    env.GEMINI_API_KEY_11 || '',
    env.GEMINI_API_KEY_12 || '',
    env.GEMINI_API_KEY_13 || '',
  ]
    .map((key, originalIndex) => ({ key, originalIndex }))
    .filter(k => k.key);

  const geminiPool = rotateStart(geminiKeysIndexed);
  const budget = makeFetchBudget(SUBREQUEST_BUDGET_VISION);
  const startTime = Date.now();

  let lastResult = { ok: false, httpStatus: 0, errStatus: 'NOT_ATTEMPTED', errBody: '' };

  outer:
  for (const { key: gKey, originalIndex } of geminiPool) {
    const keyTag = originalIndex === 0 ? '' : `key${originalIndex + 1}-`;

    for (const [model, modelTag] of [[GEMINI_MODEL_PRIMARY, 'primary'], [GEMINI_MODEL_FALLBACK, 'fallback']]) {
      if (budget.remaining() <= 0) {
        console.warn('[vision.js] Subrequest budget exhausted — stopping early.');
        lastResult = { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };
        break outer;
      }
      if (Date.now() - startTime > OVERALL_DEADLINE_MS) {
        console.warn('[vision.js] Overall deadline exceeded — stopping rotation, not starting a new attempt.');
        lastResult = { ok: false, httpStatus: 0, errStatus: 'OVERALL_DEADLINE_EXCEEDED', errBody: '' };
        break outer;
      }

      const result = await callGeminiVisionOnce(gKey, model, payloadString, budget);
      if (result.ok) {
        return json({ reply: result.reply }, 200, { 'X-CES-Vision-Source': `gemini-${keyTag}${modelTag}` }, request);
      }

      if (result.errStatus !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
        console.warn(`[vision.js] Gemini ${keyTag || 'key1-'}${model} failed:`, result.errStatus, result.httpStatus);
      }
      lastResult = result;

      // Safety-filter block or malformed request: every key/model would
      // fail identically, so rotating further only burns the budget.
      if ((result.errStatus || '').startsWith('BLOCKED_') || result.httpStatus === 400) {
        break outer;
      }
      // Otherwise (429, 403, 5xx, NETWORK_ERROR, TIMEOUT, EMPTY_REPLY):
      // fall through to the fallback model, then the next key.
    }
  }

  const status =
    lastResult.httpStatus === 400 ? 400
    : (lastResult.errStatus || '').startsWith('BLOCKED_') ? 422
    : (lastResult.errStatus === 'RESOURCE_EXHAUSTED' || lastResult.errStatus === 'RATE_LIMIT_EXCEEDED') ? 429
    : (lastResult.httpStatus && lastResult.httpStatus !== 0) ? lastResult.httpStatus
    : 502;

  return json(
    { error: buildFriendlyVisionError(lastResult, likelyArabic) },
    status, undefined, request,
  );
}

export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}
