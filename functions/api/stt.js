/**
 * functions/api/stt.js  —  v1.4  (2026-07-04)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — STT Proxy
 * Route:  POST /api/stt   { "audio": "<base64>", "mime": "audio/wav", "lang": "ar" }
 *
 * Companion to functions/api/tts.js — SAME ElevenLabs account, SAME
 * ELEVEN_API_KEY secret. No second provider signup needed: the key already
 * configured for /api/tts (Bella/Adam voices) is reused here for Scribe
 * transcription. This is the "use the same chat online TTS backend" fix for
 * the reported Arabic-STT bug — frmCESChat's local Windows recognizer has no
 * Arabic language pack installed on the affected machine (see frmCESChat.frm
 * v5.0 changelog / the reported Settings screenshots); this endpoint gives
 * it a cloud path that needs no local language pack at all.
 *
 * v1.4 [QUOTA-DIAGNOSTIC-FIX]: v1.3's tier1/tier2 header diagnostics reused
 * a fixed HTTP-status -> hint table (401/422/429/other) that assumed
 * ElevenLabs always reports quota exhaustion as HTTP 429. Live traffic
 * showed that's wrong: a direct curl reproduction against
 * https://api.elevenlabs.io/v1/speech-to-text with a fully valid,
 * correctly-permissioned key returned a *body* of
 *   { "detail": { "type": "invalid_request", "code": "quota_exceeded",
 *                  "status": "quota_exceeded",
 *                  "message": "This request exceeds your quota of 10000.
 *                  You have 0 credits remaining, while 9 credits are
 *                  required for this request." } }
 * under an HTTP status this file's old table mapped straight to
 * "invalid or missing ELEVEN_API_KEY" -- three separate live debugging
 * sessions chased a phantom key/permissions bug because the true cause
 * (0 ElevenLabs credits remaining) was sitting in the response body the
 * whole time and was never read. FIX: fetchElevenSTT/fetchOpenAiSTT now
 * read+parse the JSON error body FIRST and check for a quota/credit
 * signal there before falling back to the old status-code table. Response
 * bodies returned to the VBA client are still byte-identical to v1 (this
 * is a header-only diagnostic change, same as v1.3) — only the
 * X-STT-Tier1-Reason / X-STT-Tier2-Reason header values are more accurate
 * now. modSTTAPI.bas needs no change: it already just relays whatever
 * string is in those headers.
 *
 * ── ARCHITECTURE ──────────────────────────────────────────────────────────
 *
 *   TIER 1  ElevenLabs Scribe v2 — batch speech-to-text
 *   ─────────────────────────────────────────────────────────
 *   Endpoint : POST https://api.elevenlabs.io/v1/speech-to-text
 *   Auth     : xi-api-key header (SAME key as tts.js's ELEVEN_API_KEY)
 *   Model    : scribe_v2 — NOT scribe_v1, which ElevenLabs is deprecating
 *              and removing on 2026-07-09. Supports 90+ languages incl.
 *              Arabic, with no client/OS language pack required.
 *   Input    : multipart/form-data — file + model_id (+ optional
 *              language_code, ISO 639-1 e.g. "ar"/"en" or ISO 639-3).
 *   Output   : { text, language_code, language_probability, words: [...] }
 *              -- only `text` is forwarded to the VBA client.
 *
 *   TIER 2  OpenAI Whisper — optional fallback
 *   ─────────────────────────────────────────────────────────
 *   Activated ONLY when OPENAI_API_KEY is configured AND Tier 1 is absent
 *   or fails. Entirely optional -- if OPENAI_API_KEY is not set, Tier 2 is
 *   skipped and a Tier-1 failure is reported directly to the client instead
 *   (same "STT provider unavailable" contract either way).
 *
 * ── SETUP ─────────────────────────────────────────────────────────────────
 *   Nothing new to configure if ELEVEN_API_KEY is already set for tts.js --
 *   this route reuses it as-is. Optional Tier 2:
 *     Cloudflare Pages → your project → Settings → Environment variables
 *     Add: OPENAI_API_KEY = <paste key>   (mark as Secret)
 *
 * ── REQUEST CONTRACT (matches modSTTAPI.bas.CallSTTEndpoint exactly) ──────
 *   POST body : { "audio": "<base64 audio bytes>",
 *                 "mime":  "audio/wav",              // any Scribe-supported type
 *                 "lang":  "ar"  }                     // OPTIONAL, ISO 639-1
 *
 * ── RESPONSE CONTRACT ────────────────────────────────────────────────────
 *   200  { "text": "<transcript>" }        text MAY legitimately be ""
 *   4xx/5xx  { "error": "<human-readable message>" }
 *
 * ── RESPONSE HEADERS ─────────────────────────────────────────────────────
 *   X-STT-Engine : 'elevenlabs' | 'whisper'
 *   X-STT-Tier1-Status / X-STT-Tier1-Reason : present only on the final
 *     503 path (see v1.3/v1.4 notes above). Tier2 equivalents likewise.
 *
 * ── CSP NOTE ─────────────────────────────────────────────────────────────
 *   Called from the VBA client via MSXML2.ServerXMLHTTP, not from a browser
 *   page -- CORS headers below matter only if this route is ever also
 *   called from the site's own front-end JS.
 */

// ── CORS — same-origin restriction (production + localhost dev) ───────────
// Identical policy to tts.js -- kept duplicated here (not shared-imported)
// to match this repo's existing per-function convention.
const ALLOWED_ORIGINS = new Set(['https://civilengsuite.pages.dev']);

function getCorsHeaders(request) {
  const origin  = request?.headers?.get('Origin') || '';
  const isLocal =
    origin.startsWith('http://localhost:') ||
    origin.startsWith('http://127.0.0.1:');
  const allowed = ALLOWED_ORIGINS.has(origin) || isLocal
    ? origin
    : ALLOWED_ORIGINS.values().next().value;
  return {
    'Access-Control-Allow-Origin' : allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary'                        : 'Origin',
  };
}

function jsonResponse(status, body, request, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...getCorsHeaders(request),
      ...(extraHeaders || {}),
    },
  });
}

// ── Limits / constants ──────────────────────────────────────────────────
const MAX_AUDIO_BASE64_CHARS = 34_000_000; // ~25 MB decoded
const ELEVEN_STT_URL = 'https://api.elevenlabs.io/v1/speech-to-text';
const ELEVEN_STT_MODEL = 'scribe_v2'; // scribe_v1 is deprecated (removed 2026-07-09) -- do not use
const OPENAI_STT_URL = 'https://api.openai.com/v1/audio/transcriptions';
const OPENAI_STT_MODEL = 'whisper-1';

const ALLOWED_LANGS = new Set(['ar', 'en']); // extend as needed; "" = auto-detect

function extForMime(mime) {
  const m = (mime || '').toLowerCase();
  if (m.includes('wav')) return 'wav';
  if (m.includes('mpeg') || m.includes('mp3')) return 'mp3';
  if (m.includes('webm')) return 'webm';
  if (m.includes('ogg')) return 'ogg';
  if (m.includes('m4a') || m.includes('mp4')) return 'm4a';
  if (m.includes('flac')) return 'flac';
  return 'wav';
}

function base64ToUint8Array(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * v1.4: Read a failed fetch Response body ONCE, safely, and pull out
 * whatever quota/credit signal ElevenLabs (or OpenAI) put there. Returns
 * null if the body isn't JSON or doesn't look quota-related -- callers
 * fall back to their existing HTTP-status table in that case.
 *
 * IMPORTANT: a Response body can only be read once. This function OWNS
 * that read for the error path -- callers must not also call res.json()
 * or res.text() on the same Response after calling this.
 *
 * @param {Response} res
 * @returns {Promise<{ raw: any, quotaMessage: string|null }>}
 */
async function readErrorBody(res) {
  let raw = null;
  try {
    raw = await res.json();
  } catch (_e) {
    return { raw: null, quotaMessage: null };
  }

  // ElevenLabs shape: { detail: { code, status, message, type } }
  const detail = raw?.detail;
  const code   = detail?.code || detail?.status || raw?.code || raw?.status || '';
  const msg    = detail?.message || raw?.message || '';

  const looksLikeQuota =
    /quota_exceeded/i.test(String(code)) ||
    /quota/i.test(String(msg)) ||
    /credits?\s+remaining/i.test(String(msg)) ||
    /insufficient_quota/i.test(String(code)); // OpenAI's equivalent code

  if (looksLikeQuota) {
    // Keep this short and account-agnostic -- never forward raw provider
    // text verbatim (may vary in format/wording), just the fixed category
    // plus the numeric credit counts if present (safe, non-identifying).
    const creditsMatch = String(msg).match(/(\d+)\s+credits?\s+remaining/i);
    const remaining = creditsMatch ? creditsMatch[1] : null;
    return {
      raw,
      quotaMessage: remaining !== null
        ? `quota exceeded (${remaining} credits remaining)`
        : 'quota exceeded (0 credits remaining)',
    };
  }

  return { raw, quotaMessage: null };
}

// ── TIER 1 — ElevenLabs Scribe v2 ──────────────────────────────────────────
/**
 * @param {Uint8Array} audioBytes
 * @param {string} mime
 * @param {string} lang   '' | 'ar' | 'en'
 * @param {string} apiKey ElevenLabs key (same as tts.js's ELEVEN_API_KEY)
 * @returns {Promise<string>} transcript text (may be "")
 */
async function fetchElevenSTT(audioBytes, mime, lang, apiKey) {
  const form = new FormData();
  form.append('file', new Blob([audioBytes], { type: mime }), `audio.${extForMime(mime)}`);
  form.append('model_id', ELEVEN_STT_MODEL);
  if (lang) form.append('language_code', lang);

  const res = await fetch(ELEVEN_STT_URL, {
    method: 'POST',
    headers: { 'xi-api-key': apiKey },
    body: form,
  });

  if (!res.ok) {
    // v1.4: check the response BODY for a quota signal before trusting
    // the HTTP status code alone -- see readErrorBody() header comment
    // for why the old status-only table was actively misleading.
    const { quotaMessage } = await readErrorBody(res);

    const hint =
      quotaMessage ? `ElevenLabs ${quotaMessage}` :
      res.status === 401 ? 'invalid or missing ELEVEN_API_KEY' :
      res.status === 422 ? 'unsupported/unreadable audio for Scribe v2' :
      res.status === 429 ? 'ElevenLabs quota exceeded' :
      `HTTP ${res.status}`;
    // Never forward the raw ElevenLabs error body to the client -- `hint`
    // is a fixed, pre-sanitized category string (no account info, no
    // request IDs, no provider response text), so it is safe to surface
    // via a response header for client-side diagnostics.
    const err = new Error(`ElevenLabs STT: ${hint}`);
    err.httpStatus = res.status;
    err.category = hint;
    throw err;
  }

  const payload = await res.json();
  return typeof payload.text === 'string' ? payload.text : '';
}

// ── TIER 2 — OpenAI Whisper (optional fallback) ────────────────────────────
/**
 * @returns {Promise<string>} transcript text (may be "")
 */
async function fetchOpenAiSTT(audioBytes, mime, lang, apiKey) {
  const form = new FormData();
  form.append('file', new Blob([audioBytes], { type: mime }), `audio.${extForMime(mime)}`);
  form.append('model', OPENAI_STT_MODEL);
  form.append('response_format', 'json');
  if (lang) form.append('language', lang);

  const res = await fetch(OPENAI_STT_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}` },
    body: form,
  });

  if (!res.ok) {
    // v1.4: same body-first quota check as fetchElevenSTT. OpenAI reports
    // quota exhaustion as code "insufficient_quota", almost always under
    // HTTP 429 already -- but check the body anyway for consistency and
    // in case that changes upstream.
    const { quotaMessage } = await readErrorBody(res);

    const hint =
      quotaMessage ? `OpenAI ${quotaMessage}` :
      res.status === 401 ? 'invalid or missing OPENAI_API_KEY' :
      res.status === 429 ? 'OpenAI quota exceeded' :
      `HTTP ${res.status}`;
    const err = new Error(`OpenAI STT: ${hint}`);
    err.httpStatus = res.status;
    err.category = hint;
    throw err;
  }

  const payload = await res.json();
  return typeof payload.text === 'string' ? payload.text : '';
}

// ── POST handler ────────────────────────────────────────────────────────
export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse(400, { error: 'Malformed JSON body.' }, request);
  }

  const audioB64 = typeof body.audio === 'string' ? body.audio : '';
  const mime = typeof body.mime === 'string' && body.mime.length > 0 ? body.mime : 'audio/wav';
  const langRaw = typeof body.lang === 'string' ? body.lang.trim().toLowerCase() : '';

  if (audioB64.length === 0) {
    return jsonResponse(400, { error: 'Empty audio.' }, request);
  }
  if (audioB64.length > MAX_AUDIO_BASE64_CHARS) {
    return jsonResponse(413, { error: 'Audio file too large.' }, request);
  }
  if (langRaw.length > 0 && !ALLOWED_LANGS.has(langRaw)) {
    // Unknown hint -- don't fail the request, just fall back to auto-detect,
    // exactly like tts.js falls back to its default lang on an unknown code.
    console.error(`[stt.js v1.4] Unrecognized lang "${langRaw}" -- using auto-detect.`);
  }
  const lang = ALLOWED_LANGS.has(langRaw) ? langRaw : '';

  let audioBytes;
  try {
    audioBytes = base64ToUint8Array(audioB64);
  } catch (e) {
    return jsonResponse(400, { error: 'Audio is not valid base64.' }, request);
  }
  if (audioBytes.length === 0) {
    return jsonResponse(400, { error: 'Empty audio.' }, request);
  }

  const elevenKey = env?.ELEVEN_API_KEY?.trim() || '';
  const openAiKey = env?.OPENAI_API_KEY?.trim() || '';

  // v1.3/v1.4 [ARABIC-CLOUD-DIAGNOSTICS]: capture (not just console.error)
  // each tier's failure so the final 502/503 response can carry a safe,
  // category-only diagnostic header. The VBA client has no access to
  // Cloudflare's function logs, so "no key configured" vs "key present but
  // ElevenLabs rejected the request" vs "quota exhausted" previously all
  // looked identical client-side ("STT provider unavailable. Retry
  // shortly."). v1.4 additionally fixed quota_exceeded being misreported
  // as an auth failure -- see the v1.4 header note above. Still never
  // exposes raw provider response bodies, account details, or request
  // IDs -- only the fixed category strings this file already computed.
  let tier1Err = null;
  let tier2Err = null;

  // TIER 1 — ElevenLabs Scribe v2 (same key/account as tts.js)
  if (elevenKey) {
    try {
      const text = await fetchElevenSTT(audioBytes, mime, lang, elevenKey);
      return jsonResponse(200, { text }, request, { 'X-STT-Engine': 'elevenlabs' });
    } catch (elErr) {
      console.error('[stt.js v1.4] ElevenLabs Scribe failed, trying fallback.', elErr.message);
      tier1Err = elErr;
    }
  }

  // TIER 2 — OpenAI Whisper (only if configured)
  if (openAiKey) {
    try {
      const text = await fetchOpenAiSTT(audioBytes, mime, lang, openAiKey);
      return jsonResponse(200, { text }, request, { 'X-STT-Engine': 'whisper' });
    } catch (oaErr) {
      console.error('[stt.js v1.4] OpenAI Whisper also failed.', oaErr.message);
      tier2Err = oaErr;
    }
  }

  const diagHeaders = {};
  if (tier1Err) {
    diagHeaders['X-STT-Tier1-Status'] = String(tier1Err.httpStatus ?? 'network');
    diagHeaders['X-STT-Tier1-Reason'] = tier1Err.category || tier1Err.message;
  }
  if (tier2Err) {
    diagHeaders['X-STT-Tier2-Status'] = String(tier2Err.httpStatus ?? 'network');
    diagHeaders['X-STT-Tier2-Reason'] = tier2Err.category || tier2Err.message;
  }

  if (!elevenKey && !openAiKey) {
    return jsonResponse(502, { error: 'STT provider not configured on the server.' }, request);
  }
  return jsonResponse(503, { error: 'STT provider unavailable. Retry shortly.' }, request, diagHeaders);
}

// ── OPTIONS preflight ─────────────────────────────────────────────────────
export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}

// GET is not supported on this route (mirrors tts.js's onRequestGet, but
// this route is POST-only since it carries an audio body, not query params).
export async function onRequestGet({ request }) {
  return jsonResponse(405, { error: 'Use POST.' }, request);
}
