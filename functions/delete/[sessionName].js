// ============================================================================
// SAVE THIS FILE AS:  functions/delete/[sessionName].js
// (relative to your Cloudflare Pages project root — sibling of functions/api/
// and functions/_lib/). The [brackets] in the filename are what makes
// Cloudflare Pages Functions treat sessionName as a dynamic path segment —
// see https://developers.cloudflare.com/pages/functions/routing/#dynamic-routes
// ============================================================================
//
// Dedicated literal endpoint: DELETE /delete/{sessionName}
//
// This is the literal REST-shaped endpoint from the original spec
// (`DELETE /delete/{sessionName}`), provided as an ALTERNATIVE to the
// devCommand:'delete' branch in functions/api/chat.js — NOT a replacement
// for it, and the chat widget's own /delete slash command (see the frontend
// patch) deliberately keeps using the devCommand path, not this file.
// Reasons to still have this file:
//   - it's what the spec literally asked for (real DELETE verb, real
//     RESTful path) — useful if some other tool (curl, Postman, an admin
//     script, a future non-chat admin UI) wants to call this without
//     constructing a POST /api/chat devCommand envelope.
//   - Cloudflare Pages route specificity makes /delete/all (a STATIC file,
//     see the sibling functions/delete/all.js) win over this dynamic route
//     automatically — "more specific routes (fewer wildcards) take
//     precedence" per Cloudflare's own Pages Functions routing docs — so
//     there is no special-casing needed here for the literal path segment
//     "all"; that request never reaches this file. The `DEV_SESSION_RESERVED_NAMES`
//     guard in _lib/sessions.mjs additionally makes sure no *real* session
//     can ever be named "all" in the first place, so this isn't relying on
//     routing precedence alone.
//
// This file is deliberately SELF-CONTAINED (its own CORS/auth helpers,
// duplicated rather than imported from functions/api/chat.js) — see the
// note at the bottom of this file for why, and what to do if you'd rather
// not have that duplication.
//
// Session-store logic (deleteConversation) is NOT duplicated — it's
// imported from functions/_lib/sessions.mjs, the same module
// functions/api/chat.js uses, so there is exactly one implementation of
// "what deleting a session means" regardless of which endpoint triggered it.

import { deleteConversation } from '../_lib/sessions.mjs';

// ── CORS — same allow-listed production origin as functions/api/chat.js.
// Kept as a literal here rather than imported so this file has no
// compile-time dependency on chat.js's internals; if you change the
// allowed origin, change it in both places (or extract both files' CORS
// logic into functions/_lib/http.mjs the way sessions.mjs was extracted —
// worth doing if you end up with a third endpoint file).
const ALLOWED_ORIGINS = new Set(['https://civilengsuite.pages.dev']);

function getCorsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const isLocal = origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:');
  const allowed = ALLOWED_ORIGINS.has(origin) || isLocal ? origin : ALLOWED_ORIGINS.values().next().value;
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    Vary: 'Origin',
  };
}

function json(data, status, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...getCorsHeaders(request) },
  });
}

// Same timing-safe comparison as chat.js's hmacTimingSafeEqual — HMAC-sign
// both strings with a random per-comparison key so the comparison itself
// (the XOR loop below) always walks the same fixed 32-byte output
// regardless of where the real strings first differ, instead of a plain
// `a === b` whose short-circuit-on-first-mismatch timing can leak how many
// leading characters were correct.
async function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const [sigA, sigB] = await Promise.all([
    crypto.subtle.sign('HMAC', key, enc.encode(a)),
    crypto.subtle.sign('HMAC', key, enc.encode(b)),
  ]);
  const arrA = new Uint8Array(sigA);
  const arrB = new Uint8Array(sigB);
  let diff = 0;
  for (let i = 0; i < arrA.length; i++) diff |= arrA[i] ^ arrB[i];
  return diff === 0;
}

export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}

export async function onRequestDelete(context) {
  const { request, env, params } = context;

  const sessionName = typeof params.sessionName === 'string' ? decodeURIComponent(params.sessionName) : '';
  if (!sessionName) {
    return json({ error: 'sessionName path segment is required.', code: 'SESSION_KEY_REQUIRED' }, 400, request);
  }
  if (sessionName.length > 128) {
    return json({ error: 'sessionName must be 128 characters or fewer.', code: 'SESSION_KEY_TOO_LONG' }, 400, request);
  }

  let body = {};
  try {
    const rawBody = await request.text();
    if (rawBody) body = JSON.parse(rawBody);
  } catch {
    return json({ error: 'Request body, if present, must be valid JSON.' }, 400, request);
  }

  const incomingDevPw = typeof body.devPassword === 'string' ? body.devPassword : '';
  const configuredDevPw = typeof env.DEVELOPER_PASSWORD === 'string' ? env.DEVELOPER_PASSWORD : '';
  let authed = false;
  if (incomingDevPw && configuredDevPw) {
    try {
      authed = await timingSafeEqual(incomingDevPw, configuredDevPw);
    } catch {
      authed = incomingDevPw === configuredDevPw;
    }
  }
  if (!authed) {
    console.warn('[delete/sessionName] Unauthenticated or wrong-password delete attempt for', sessionName);
    return json({ error: 'Developer authentication required.', code: 'DEV_AUTH_REQUIRED' }, 403, request);
  }

  if (!env.CES_SESSIONS) {
    console.error('[delete/sessionName] CES_SESSIONS KV binding missing.');
    return json(
      { error: 'Session storage is not configured on the server (bind CES_SESSIONS).', code: 'KV_NOT_CONFIGURED' },
      500,
      request,
    );
  }

  const result = await deleteConversation(env.CES_SESSIONS, sessionName);
  if (!result.ok) {
    return json(
      { error: result.error, code: result.code },
      result.code === 'SESSION_NOT_FOUND' ? 404 : 500,
      request,
    );
  }
  console.warn('[delete/sessionName] Session deleted:', sessionName);
  return json({ ok: true, sessionKey: sessionName }, 200, request);
}

// ── On the CORS/auth duplication with functions/api/chat.js ────────────────
// This file and functions/delete/all.js each carry their own ~30-line copy
// of getCorsHeaders/json/timingSafeEqual instead of importing chat.js's
// versions. That's a deliberate choice, not an oversight: chat.js does not
// currently export them (only onRequestPost/onRequestOptions), and adding
// exports to a file that already works, purely to satisfy two OPTIONAL
// endpoints, is a bigger change to your primary file than this feature
// needs. If you later add a third endpoint file, or these two see real
// use, the next step is to promote this trio into functions/_lib/http.mjs —
// same move already made once in this codebase for rotation.mjs and again
// for sessions.mjs — and have all three route files import from there.
