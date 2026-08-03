// functions/api/chat/dev-upload.js
// =============================================================================
// POST /api/chat/dev-upload — developer-only staging endpoint for large file
// uploads that would otherwise be truncated by chat.js's DEV_MAX_CHARS_PER_
// TEXT_FILE / DEV_MAX_TOTAL_TEXT_FILE_CHARS caps (20,000 / 40,000 chars —
// chat.js lines ~1450-1459). Stores raw content in a DEDICATED KV namespace
// (env.CES_DEV_UPLOADS, NOT env.CES_CHAT_KV — see rationale below) under a
// random UUID key with a short TTL. functions/api/chat.js later resolves
// body.kvFileIds against this same namespace (resolveKvFiles(), added next
// to extractTextFiles()) and merges the content into the prompt under its
// own separate, larger cap (DEV_KV_MAX_TOTAL_CONTEXT_CHARS), sized to the
// smallest context window in the active provider fallback chain — see that
// constant's derivation comment in chat.js for the full reasoning.
//
// WHY A SEPARATE KV NAMESPACE, NOT env.CES_CHAT_KV:
// env.CES_CHAT_KV is already documented elsewhere in this codebase as
// running close to the Workers KV Free-plan cap of 1,000 writes/day (see
// chat.js's rate-limiter comment and functions/api/factGuard.mjs, which
// explicitly avoided adding KV usage for the same reason). This feature is
// developer-triggered and low-frequency, but there is no reason to let it
// compete with production chat traffic for that quota when a second
// Free-plan KV namespace costs nothing extra. Add this binding via the
// Cloudflare Pages dashboard exactly the way CES_CHAT_KV and CES_SESSIONS
// were added (Pages project -> Settings -> Functions -> KV namespace
// bindings; variable name CES_DEV_UPLOADS). This repo has no wrangler.toml
// — consistent with the other two bindings, there is no config file to
// edit for this.
//
// WHY X-Developer-Token (A HEADER) INSTEAD OF chat.js's BODY-FIELD
// devPassword CONVENTION:
// This endpoint's body IS the uploaded file content — keeping the secret
// out of that body, rather than mixing it in as another JSON field next to
// a few hundred KB of pasted code, is simply better hygiene, and headers
// are the conventional home for bearer-style credentials. This is NOT a
// second secret: the header value is checked against the exact same
// env.DEVELOPER_PASSWORD used everywhere else in this codebase, via a
// byte-for-byte copy of chat.js's own hmacTimingSafeEqual() constant-time
// comparison (chat.js line ~3544). Duplicated rather than imported, to
// avoid changing chat.js's existing export surface on an actively-
// developed v35 file — same hand-copied-helper tradeoff already accepted
// elsewhere in this repo (rotation.mjs's own header comment on
// PROVIDER_TIMEOUT_MS / MAX_IMAGES_PER_REQUEST makes the identical
// trade-off explicitly). If hmacTimingSafeEqual() is ever promoted into
// rotation.mjs or a shared _lib module, delete the copy below and import
// it from there instead.
//
// CORS: a browser preflight (OPTIONS) rejects any request header the
// client sends that isn't explicitly listed in Access-Control-Allow-
// Headers. chat.js's own getCorsHeaders() only lists Content-Type and
// X-Client-Date — it does not know about X-Developer-Token, and this file
// does not import or modify that function. getCorsHeaders() below is a
// local, minimal copy for this route only, with X-Developer-Token added.
// Same ALLOWED_ORIGINS set as chat.js (kept in sync manually — same
// no-shared-constant caveat as every other hand-copied literal in this
// repo).
// =============================================================================

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
    'Access-Control-Allow-Headers': 'Content-Type, X-Developer-Token',
    'Vary'                        : 'Origin',
  };
}

function json(data, status, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...getCorsHeaders(request) },
  });
}

// Byte-for-byte copy of chat.js's hmacTimingSafeEqual (chat.js line ~3544).
// See file header for why this is duplicated rather than imported. Signs
// both inputs under a fresh, ephemeral, per-call HMAC key so they compare
// as fixed-length 32-byte digests, then compares those digests without
// short-circuiting — avoids both the variable-length-input and the
// early-exit timing side-channels a naive `a === b` string compare has.
async function hmacTimingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const [sigA, sigB] = await Promise.all([
    crypto.subtle.sign('HMAC', key, enc.encode(a)),
    crypto.subtle.sign('HMAC', key, enc.encode(b)),
  ]);
  const arrA = new Uint8Array(sigA);
  const arrB = new Uint8Array(sigB);
  // HMAC-SHA256 always returns 32 bytes — lengths are always identical.
  let diff = 0;
  for (let i = 0; i < arrA.length; i++) diff |= arrA[i] ^ arrB[i];
  return diff === 0;
}

// Raw ceiling on what this endpoint accepts into KV at all, independent of
// the smaller prompt-budget cap applied later in chat.js. Generous
// (2,000,000 chars covers a genuinely enormous single VBA project — roughly
// 40,000 lines at 50 chars/line) while still bounded: this guards KV
// storage and the JSON-parse cost of the upload request itself, not the
// eventual prompt size. Deliberately larger than chat.js's
// DEV_KV_MAX_TOTAL_CONTEXT_CHARS — the merge step there truncates-with-
// warning down to what the model can actually use, the same two-stage
// pattern chat.js's own extractTextFiles() already applies on the inline
// body.files[] path (accept generously here, budget precisely at merge
// time).
const RAW_UPLOAD_MAX_CHARS = 2_000_000;

// KV TTL for staged uploads, in seconds. 300s (5 min) — the short end of
// the 5-10 minute window requested: long enough to cover "upload, then
// immediately ask a question about it," short enough to bound how long an
// intercepted fileId stays valid if one ever leaked (e.g. via a proxy
// log). Cloudflare KV's minimum expirationTtl is 60s
// (developers.cloudflare.com/kv/api/write-key-value-pairs/, confirmed
// current as of this writing) — 300 comfortably clears that floor. Keep
// this in sync with the "5 minutes" wording in chat.js's resolveKvFiles()
// not-found error message if you change it.
const UPLOAD_TTL_SECONDS = 300;

// Mirrors rotation.mjs's checkRateLimit() KV-fallback fixed-window logic
// (same bucket math, same TTL-as-2x-window, same fail-open-on-error
// posture) but is a separate, local function — NOT a call to
// checkRateLimit() itself — and does not touch env.CES_CHAT_KV. See the
// file header's "WHY A SEPARATE KV NAMESPACE" note: reusing checkRateLimit
// unmodified would draw this endpoint's counters from CES_CHAT_KV in the
// no-RATE_LIMITER-binding case, working against the exact quota-isolation
// this file exists to provide. Generous threshold: this is a manual,
// low-frequency developer action (attach one big file, maybe retry once),
// not a per-message call like /api/chat's own rate limit.
async function checkUploadRateLimit(env, key) {
  if (!env.CES_DEV_UPLOADS) return { limited: false, mechanism: 'no-kv' };
  try {
    const windowSeconds = 60;
    const maxPerWindow = 6;
    const bucket = Math.floor(Date.now() / 1000 / windowSeconds);
    const kvKey = `rl:${key}:${bucket}`;
    const rawCurrent = await env.CES_DEV_UPLOADS.get(kvKey);
    const parsed = parseInt(rawCurrent || '0', 10);
    const current = Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
    if (current >= maxPerWindow) return { limited: true, mechanism: 'kv' };
    await env.CES_DEV_UPLOADS.put(kvKey, String(current + 1), { expirationTtl: windowSeconds * 2 });
    return { limited: false, mechanism: 'kv' };
  } catch (err) {
    console.error('[dev-upload.js] CES_DEV_UPLOADS rate-limit error (failing open):', err.message);
    return { limited: false, mechanism: 'kv-error' };
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';

  // 1. Rate limit FIRST, before auth. This deliberately mirrors chat.js's
  //    own onRequestPost ordering (its checkRateLimit() runs at step 1,
  //    before the devPassword check at step 3a) — not an arbitrary choice.
  //    If auth ran first, this endpoint would be an UNTHROTTLED oracle for
  //    guessing DEVELOPER_PASSWORD: hmacTimingSafeEqual() defeats a timing
  //    side-channel, it does not defeat brute force, and chat.js's own
  //    devPassword check relies on ITS step-1 rate limit for that, not on
  //    the comparison itself. This endpoint needs the equivalent before
  //    its own auth check for the same reason.
  const rateCheck = await checkUploadRateLimit(env, clientIp);
  if (rateCheck.limited) {
    return json({ error: 'Too many uploads too quickly. Wait a moment and try again.', code: 'RATE_LIMITED' }, 429, request);
  }

  // 2. Auth — a structural gate, not a countermanding instruction, matching
  //    chat.js v35's own most recent design philosophy (exclude, don't
  //    override; see that file's CHANGELOG v35).
  const incomingToken = request.headers.get('X-Developer-Token') || '';
  const configuredPw  = typeof env.DEVELOPER_PASSWORD === 'string' ? env.DEVELOPER_PASSWORD : '';
  let authed = false;
  if (incomingToken && configuredPw) {
    try {
      authed = await hmacTimingSafeEqual(incomingToken, configuredPw);
    } catch (_) {
      // Same defensive fallback as chat.js's isDeveloperMode computation:
      // crypto.subtle unavailable should never happen on Workers, but if it
      // does, fall back to a direct (non-timing-safe) compare rather than
      // hard-failing the endpoint. The rate limit above still bounds how
      // many attempts this can be tried per minute either way.
      authed = (incomingToken === configuredPw);
    }
  }
  if (!authed) {
    console.warn('[dev-upload.js] Rejected upload: bad/missing X-Developer-Token from', clientIp);
    return json({ error: 'Developer authentication required.', code: 'DEV_AUTH_REQUIRED' }, 403, request);
  }

  if (!env.CES_DEV_UPLOADS) {
    return json(
      {
        error: 'CES_DEV_UPLOADS KV namespace is not bound. Add it in Cloudflare Pages -> Settings -> Functions -> KV namespace bindings.',
        code: 'KV_NOT_BOUND',
      },
      500,
      request,
    );
  }

  // 3. Parse body. { name?: string, content: string }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Request body must be valid JSON.' }, 400, request);
  }

  const name = typeof body?.name === 'string' && body.name.trim()
    ? body.name.trim().slice(0, 200)
    : 'attachment.txt';
  const content = typeof body?.content === 'string' ? body.content : '';

  if (!content.trim()) {
    return json({ error: 'No content provided.' }, 400, request);
  }
  if (content.length > RAW_UPLOAD_MAX_CHARS) {
    return json(
      {
        error: `File too large (${content.length} chars). Maximum ${RAW_UPLOAD_MAX_CHARS.toLocaleString()} chars per upload.`,
        code: 'TOO_LARGE',
      },
      413,
      request,
    );
  }

  // 4. Store. Key is a fresh random UUID — unguessable, and KV's 1-write-
  //    per-key-per-second limit is a non-issue since no two uploads ever
  //    share a key.
  const fileId = crypto.randomUUID();
  const kvKey = `devupload:${fileId}`;
  try {
    await env.CES_DEV_UPLOADS.put(
      kvKey,
      JSON.stringify({ name, content, uploadedAt: Date.now() }),
      { expirationTtl: UPLOAD_TTL_SECONDS },
    );
  } catch (err) {
    console.error('[dev-upload.js] KV put failed:', err.message);
    return json({ error: 'Storage error. Please retry.', code: 'KV_WRITE_FAILED' }, 500, request);
  }

  console.info('[dev-upload.js] Staged', content.length, 'chars as', fileId, 'for', clientIp);
  return json(
    {
      ok: true,
      fileId,
      name,
      charCount: content.length,
      expiresIn: UPLOAD_TTL_SECONDS,
      expiresAt: new Date(Date.now() + UPLOAD_TTL_SECONDS * 1000).toISOString(),
    },
    200,
    request,
  );
}

export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}
