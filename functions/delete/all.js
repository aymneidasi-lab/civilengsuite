// ============================================================================
// SAVE THIS FILE AS:  functions/delete/all.js
// (sibling of functions/delete/[sessionName].js — see that file's header
// comment for the full rationale on why both this and the dynamic route
// exist alongside the devCommand:'delete_all' branch in functions/api/chat.js)
// ============================================================================
//
// Dedicated literal endpoint: DELETE /delete/all
//
// Cloudflare Pages Functions route specificity guarantees this STATIC file
// is matched before the DYNAMIC functions/delete/[sessionName].js for the
// literal path /delete/all — "more specific routes (fewer wildcards) take
// precedence over less specific routes" (Cloudflare Pages Functions
// routing docs). No sessionName === 'all' special-casing is needed here.
//
// STABILITY: the actual pagination/batching/partial-failure-reporting logic
// lives in deleteAllConversations() in functions/_lib/sessions.mjs — see
// that function's doc comment for the full design (two-phase enumerate-
// then-delete, batched Promise.allSettled, MAX_PAGES hard stop). This file
// is just the HTTP wrapper: auth, confirmation-phrase gate, response shape.

import { deleteAllConversations, DEV_SESSION_KV_PREFIX } from '../_lib/sessions.mjs';

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

const DELETE_ALL_CONFIRM_PHRASE = 'DELETE ALL SESSIONS';

export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}

export async function onRequestDelete(context) {
  const { request, env } = context;

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
    console.warn('[delete/all] Unauthenticated or wrong-password delete-all attempt.');
    return json({ error: 'Developer authentication required.', code: 'DEV_AUTH_REQUIRED' }, 403, request);
  }

  // Same deliberate friction as the devCommand:'delete_all' branch: the
  // devPassword alone is not enough to wipe everything, an exact-match
  // confirmation phrase is also required, so this can never be triggered
  // by a single automated/mistaken request even from an authenticated caller.
  const confirmText = typeof body.confirm === 'string' ? body.confirm : '';
  if (confirmText !== DELETE_ALL_CONFIRM_PHRASE) {
    return json(
      {
        error: `Send { "confirm": "${DELETE_ALL_CONFIRM_PHRASE}" } in the request body to delete all sessions.`,
        code: 'DELETE_ALL_CONFIRMATION_REQUIRED',
      },
      400,
      request,
    );
  }

  if (!env.CES_SESSIONS) {
    console.error('[delete/all] CES_SESSIONS KV binding missing.');
    return json(
      { error: 'Session storage is not configured on the server (bind CES_SESSIONS).', code: 'KV_NOT_CONFIGURED' },
      500,
      request,
    );
  }

  const result = await deleteAllConversations(env.CES_SESSIONS, DEV_SESSION_KV_PREFIX);
  if (!result.ok) {
    return json(
      { error: result.error, code: result.code, deletedCount: result.deletedCount, failures: result.failures },
      500,
      request,
    );
  }
  console.warn('[delete/all] ALL sessions deleted:', result.deletedCount);
  return json({ ok: true, deletedCount: result.deletedCount }, 200, request);
}
