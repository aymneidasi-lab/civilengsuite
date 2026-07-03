/**
 * functions/api/stt.js  —  v1  (2026-07-02)
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

// ── TIER 1 — ElevenLabs Scribe v2 ──────────────────────────────────────────
/**
 * @param {Uint8Array} audioBytes
 * @param {string} mime
 * @param {string} lang   '' | 'ar' | 'en'
 * @param {string} apiKey ElevenLabs key (same as tts.js's ELEVEN_API_KEY)
 * @returns {Promise<string>} transcript text (may be "")
 */
// [ARABIC-STT-DIAGNOSABILITY] Every failure branch previously collapsed into
// the single client-facing string "STT provider unavailable. Retry shortly."
// -- indistinguishable in modSTTAPI's debug log whether the cause was a bad
// key, a key scoped to TTS-only (ElevenLabs keys support per-endpoint scope
// restriction -- a key that works fine for tts.js's /v1/text-to-speech can
// still 401/403 on this route's /v1/speech-to-text if it was never granted
// STT scope), a quota ceiling, unreadable audio, or a genuine network blip.
// That ambiguity is why the Arabic-STT investigation kept landing on the
// local-recognizer fallback instead of the actual cloud-call failure. FIX:
// classify the failure into a small, closed set of NON-SENSITIVE reason
// codes (never raw provider response text/JSON) and thread that code to the
// client via X-STT-Fail-Reason, so the next failure comes with an actual
// diagnosis instead of a dead end.
function classifyEleven(status) {
  switch (status) {
    case 401: return 'auth';       // bad key OR key not scoped for STT
    case 403: return 'permission'; // key valid but lacks STT scope/IP allowlist
    case 422: return 'audio';      // unreadable/unsupported audio for Scribe v2
    case 429: return 'quota';      // rate limit / credits exhausted
    default:  return 'upstream';
  }
}

function classifyOpenAi(status) {
  switch (status) {
    case 401: return 'auth';
    case 429: return 'quota';
    default:  return 'upstream';
  }
}

/**
 * @returns {Promise<string>} transcript text (may be "")
 * @throws {Error} with .reasonCode set to one of classifyEleven()'s codes
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
    const reasonCode = classifyEleven(res.status);
    // Never forward the raw ElevenLabs error body to the client -- log it
    // server-side only, where it's actually actionable.
    let bodySnippet = '';
    try { bodySnippet = (await res.text()).slice(0, 300); } catch (_) { /* ignore */ }
    const err = new Error(`ElevenLabs STT HTTP ${res.status}: ${bodySnippet}`);
    err.reasonCode = reasonCode;
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
    const reasonCode = classifyOpenAi(res.status);
    let bodySnippet = '';
    try { bodySnippet = (await res.text()).slice(0, 300); } catch (_) { /* ignore */ }
    const err = new Error(`OpenAI STT HTTP ${res.status}: ${bodySnippet}`);
    err.reasonCode = reasonCode;
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
    console.error(`[stt.js v1] Unrecognized lang "${langRaw}" -- using auto-detect.`);
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

  let lastReasonCode = '';

  // TIER 1 — ElevenLabs Scribe v2 (same key/account as tts.js -- NOTE this
  // assumes that key carries STT scope; a key restricted to TTS-only at
  // creation time will 401/403 here even though tts.js works fine with it.
  // See classifyEleven's 'auth'/'permission' codes below.)
  if (elevenKey) {
    try {
      const text = await fetchElevenSTT(audioBytes, mime, lang, elevenKey);
      return jsonResponse(200, { text }, request, { 'X-STT-Engine': 'elevenlabs' });
    } catch (elErr) {
      lastReasonCode = elErr.reasonCode || 'upstream';
      console.error('[stt.js v1] ElevenLabs Scribe failed, trying fallback.', lastReasonCode, elErr.message);
    }
  }

  // TIER 2 — OpenAI Whisper (only if configured)
  if (openAiKey) {
    try {
      const text = await fetchOpenAiSTT(audioBytes, mime, lang, openAiKey);
      return jsonResponse(200, { text }, request, { 'X-STT-Engine': 'whisper' });
    } catch (oaErr) {
      lastReasonCode = oaErr.reasonCode || 'upstream';
      console.error('[stt.js v1] OpenAI Whisper also failed.', lastReasonCode, oaErr.message);
    }
  }

  if (!elevenKey && !openAiKey) {
    return jsonResponse(502, { error: 'STT provider not configured on the server.' }, request,
      { 'X-STT-Fail-Reason': 'not_configured' });
  }

  // [ARABIC-STT-DIAGNOSABILITY] reasonCode is one of a small closed set
  // ('auth'|'permission'|'audio'|'quota'|'upstream') -- safe to expose, it
  // carries no provider response content, just a category modSTTAPI can log
  // and a human can act on (e.g. 'permission' -> go check the ElevenLabs key
  // scope in the dashboard instead of assuming the network is down).
  const humanMsg =
    lastReasonCode === 'auth'       ? 'STT provider rejected the API key.' :
    lastReasonCode === 'permission' ? 'STT provider key lacks permission for this operation.' :
    lastReasonCode === 'audio'      ? 'STT provider could not read the audio.' :
    lastReasonCode === 'quota'      ? 'STT provider quota exceeded.' :
                                       'STT provider unavailable. Retry shortly.';

  return jsonResponse(503, { error: humanMsg }, request,
    { 'X-STT-Fail-Reason': lastReasonCode || 'upstream' });
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
