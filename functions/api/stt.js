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
    // Never forward the raw ElevenLabs error body to the client.
    const hint =
      res.status === 401 ? 'invalid or missing ELEVEN_API_KEY' :
      res.status === 422 ? 'unsupported/unreadable audio for Scribe v2' :
      res.status === 429 ? 'ElevenLabs quota exceeded' :
      `HTTP ${res.status}`;
    throw new Error(`ElevenLabs STT: ${hint}`);
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
    const hint =
      res.status === 401 ? 'invalid or missing OPENAI_API_KEY' :
      res.status === 429 ? 'OpenAI quota exceeded' :
      `HTTP ${res.status}`;
    throw new Error(`OpenAI STT: ${hint}`);
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

  // TIER 1 — ElevenLabs Scribe v2 (same key/account as tts.js)
  if (elevenKey) {
    try {
      const text = await fetchElevenSTT(audioBytes, mime, lang, elevenKey);
      return jsonResponse(200, { text }, request, { 'X-STT-Engine': 'elevenlabs' });
    } catch (elErr) {
      console.error('[stt.js v1] ElevenLabs Scribe failed, trying fallback.', elErr.message);
    }
  }

  // TIER 2 — OpenAI Whisper (only if configured)
  if (openAiKey) {
    try {
      const text = await fetchOpenAiSTT(audioBytes, mime, lang, openAiKey);
      return jsonResponse(200, { text }, request, { 'X-STT-Engine': 'whisper' });
    } catch (oaErr) {
      console.error('[stt.js v1] OpenAI Whisper also failed.', oaErr.message);
    }
  }

  if (!elevenKey && !openAiKey) {
    return jsonResponse(502, { error: 'STT provider not configured on the server.' }, request);
  }
  return jsonResponse(503, { error: 'STT provider unavailable. Retry shortly.' }, request);
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
