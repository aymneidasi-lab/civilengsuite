/**
 * functions/api/stt.js  —  v1.6  (2026-07-04)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — STT Proxy
 * Route:  POST /api/stt   { "audio": "<base64>", "mime": "audio/wav", "lang": "ar" }
 *
 * Companion to functions/api/tts.js — TTS is unchanged by this revision.
 *
 * v1.4 [QUOTA-DIAGNOSTIC-FIX]: fetchElevenSTT/fetchOpenAiSTT read the JSON
 * error body and detect provider-specific quota/credit-exhaustion codes
 * BEFORE falling back to an HTTP-status-only hint table. See readErrorBody()
 * below for why: a live reproduction showed ElevenLabs returning a
 * 401-range status for a quota-exhausted account, which the old table
 * mapped straight to "invalid or missing key".
 *
 * v1.5 [KEY-POOL-ROTATION]: Tier 1 (ElevenLabs) accepts up to 13
 * independent API keys via ELEVEN_API_KEY_1..ELEVEN_API_KEY_13 (one per
 * team member's own account), tried in a round-robin + quota-failover ring.
 * See getElevenKeyRing()/fetchElevenSTTRotating() below.
 *
 * v1.6 [DEEPGRAM-TIER3]: Adds Deepgram as a THIRD, fully independent
 * provider, tried only after the entire Tier 1 ElevenLabs ring AND Tier 2
 * OpenAI Whisper have both failed (absent, misconfigured, or exhausted).
 * Unlike v1.5's ElevenLabs key pool (many accounts on the SAME provider),
 * this is one account on a DIFFERENT provider entirely -- ordinary
 * multi-vendor redundancy, not quota-limit circumvention; each provider's
 * own free-tier terms govern its own account independently.
 *   - Endpoint: POST https://api.deepgram.com/v1/listen (see Deepgram's
 *     "Pre-Recorded Audio" docs). Auth via `Authorization: Token <key>`.
 *   - Deepgram's pre-recorded endpoint takes the RAW audio bytes as the
 *     request body with Content-Type set to the audio's own mime type --
 *     NOT multipart/form-data like ElevenLabs/OpenAI. This is Deepgram's
 *     documented pattern (curl --data-binary @file.wav --header
 *     'Content-Type: audio/wav'), not a guess -- getting this wrong
 *     (e.g. wrapping it in FormData) is a common integration mistake that
 *     produces a generic 400 with no useful hint.
 *   - model=nova-2 is used deliberately, NOT the newer nova-3: at time of
 *     writing nova-3 only covers a handful of languages while nova-2 covers
 *     ~36 including Arabic. Using nova-3 here would silently regress
 *     Arabic support. Re-check Deepgram's current per-model language table
 *     before ever bumping this -- language coverage per model changes
 *     between Deepgram model generations.
 *   - language=ar / language=en-US is set explicitly from the same lang
 *     hint already used for Tier 1/2. When no hint is available,
 *     detect_language=true is set instead of omitting language entirely --
 *     Deepgram defaults to English if neither is provided, which would
 *     silently break Arabic auto-detection.
 *   - readErrorBody() is extended (not duplicated) to also recognize
 *     Deepgram's err_code/err_msg error shape, so quota/credit exhaustion
 *     on Deepgram gets the same accurate diagnostic treatment Tier 1/2
 *     already have, instead of a generic "HTTP 402" guess.
 *
 * ── SETUP ─────────────────────────────────────────────────────────────────
 *   Tier 1 (existing): ELEVEN_API_KEY, optionally ELEVEN_API_KEY_1..13.
 *   Tier 2 (existing, optional): OPENAI_API_KEY.
 *   Tier 3 (new, optional): DEEPGRAM_API_KEY -- sign up at deepgram.com
 *     (free $200 signup credit as of this writing), API Keys page, create
 *     a key, paste into Cloudflare Pages → Settings → Environment
 *     variables as DEEPGRAM_API_KEY (Secret), redeploy.
 *   Every tier is independently optional -- absent env vars are skipped
 *   silently, exactly as before.
 *
 * ── ARCHITECTURE ──────────────────────────────────────────────────────────
 *
 *   TIER 1  ElevenLabs Scribe v2 — key-pool round-robin + quota-failover
 *   TIER 2  OpenAI Whisper — single key, optional
 *   TIER 3  Deepgram Nova-2 — single key, optional, tried last
 *
 * ── REQUEST CONTRACT (matches modSTTAPI.bas.CallSTTEndpoint exactly) ──────
 *   POST body : { "audio": "<base64 audio bytes>",
 *                 "mime":  "audio/wav",              // any supported type
 *                 "lang":  "ar"  }                     // OPTIONAL, ISO 639-1
 *
 * ── RESPONSE CONTRACT ────────────────────────────────────────────────────
 *   200  { "text": "<transcript>" }        text MAY legitimately be ""
 *   4xx/5xx  { "error": "<human-readable message>" }
 *
 * ── RESPONSE HEADERS ─────────────────────────────────────────────────────
 *   X-STT-Engine            : 'elevenlabs' | 'whisper' | 'deepgram'
 *   X-STT-Eleven-KeyIndex   : ring slot that answered (elevenlabs 200 only)
 *   X-STT-Eleven-KeysTried  : how many ElevenLabs ring keys were attempted
 *   X-STT-Tier1-Status / X-STT-Tier1-Reason : present only on the final
 *     503 path. Tier2/Tier3 equivalents likewise.
 *
 * ── CSP NOTE ─────────────────────────────────────────────────────────────
 *   Called from the VBA client via MSXML2.ServerXMLHTTP, not from a browser
 *   page -- CORS headers below matter only if this route is ever also
 *   called from the site's own front-end JS.
 */

// ── CORS — same-origin restriction (production + localhost dev) ───────────
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
const DEEPGRAM_STT_URL = 'https://api.deepgram.com/v1/listen';
const DEEPGRAM_MODEL = 'nova-2'; // NOT nova-3 -- nova-3 covers far fewer languages; nova-2 covers Arabic
const MAX_ELEVEN_KEY_SLOTS = 13;

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
 * v1.4/v1.6: Read a failed fetch Response body ONCE, safely, and pull out
 * whatever quota/credit signal the provider put there. Returns null if the
 * body isn't JSON or doesn't look quota-related -- callers fall back to
 * their existing HTTP-status table in that case.
 *
 * Recognizes three provider error shapes seen in production:
 *   ElevenLabs : { detail: { code, status, message } }
 *   OpenAI     : { error: { code, message, type } }  (code: insufficient_quota)
 *   Deepgram   : { err_code, err_msg, request_id }
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

  const detail = raw?.detail;
  const code = detail?.code || detail?.status || raw?.error?.code ||
               raw?.err_code || raw?.code || raw?.status || '';
  const msg  = detail?.message || raw?.error?.message || raw?.err_msg ||
               raw?.message || '';

  const looksLikeQuota =
    /quota_exceeded/i.test(String(code)) ||
    /insufficient_quota/i.test(String(code)) ||   // OpenAI
    /insufficient/i.test(String(code)) ||          // Deepgram-style err_code
    /quota/i.test(String(msg)) ||
    /credits?\s+remaining/i.test(String(msg)) ||
    /out of credit/i.test(String(msg));

  if (looksLikeQuota) {
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

// ── v1.5 — ElevenLabs key-pool ring ─────────────────────────────────────
/**
 * Build the ordered, de-duplicated ElevenLabs key ring from env.
 * Order: legacy ELEVEN_API_KEY first (zero-migration compatibility), then
 * ELEVEN_API_KEY_1 .. ELEVEN_API_KEY_13 in numeric order. Blank/unset slots
 * are skipped. Exact-duplicate values are skipped.
 *
 * @param {object} env
 * @returns {string[]} ordered list of trimmed, non-empty, unique keys
 */
function getElevenKeyRing(env) {
  const keys = [];
  const seen = new Set();

  const legacy = env?.ELEVEN_API_KEY?.trim();
  if (legacy && !seen.has(legacy)) {
    keys.push(legacy);
    seen.add(legacy);
  }

  for (let i = 1; i <= MAX_ELEVEN_KEY_SLOTS; i++) {
    const v = env?.[`ELEVEN_API_KEY_${i}`]?.trim();
    if (v && !seen.has(v)) {
      keys.push(v);
      seen.add(v);
    }
  }

  return keys;
}

// Module-scoped ring pointer -- best-effort load spreading across requests
// within a reused isolate (see v1.5 note in prior revision for the
// isolate-persistence caveat; unchanged here).
let elevenRingPointer = 0;

/**
 * Try each ElevenLabs key in the ring, starting at the current round-robin
 * position, advancing on key-specific failures (quota exhausted / that key
 * invalid), stopping immediately on non-key-specific failures (e.g. bad
 * audio -- every key would fail identically).
 *
 * @returns {Promise<{ text: string, keyIndex: number, keysTried: number }>}
 */
async function fetchElevenSTTRotating(audioBytes, mime, lang, keys) {
  if (keys.length === 0) {
    const err = new Error('ElevenLabs STT: no ELEVEN_API_KEY(_N) configured');
    err.category = 'no keys configured';
    err.httpStatus = 'network';
    throw err;
  }

  const startIdx = elevenRingPointer % keys.length;
  elevenRingPointer = (elevenRingPointer + 1) % keys.length;

  const attemptErrors = [];
  for (let step = 0; step < keys.length; step++) {
    const idx = (startIdx + step) % keys.length;
    try {
      const text = await fetchElevenSTT(audioBytes, mime, lang, keys[idx]);
      return { text, keyIndex: idx, keysTried: step + 1 };
    } catch (err) {
      attemptErrors.push({ idx, category: err.category || err.message, httpStatus: err.httpStatus });

      const isKeySpecific =
        /quota exceeded/i.test(err.category || '') ||
        err.httpStatus === 401;
      if (!isKeySpecific) break; // e.g. 422 bad audio -- every key fails the same way
    }
  }

  const summary = attemptErrors.map(e => `key#${e.idx}:${e.category}`).join(', ');
  const last = attemptErrors[attemptErrors.length - 1];
  const err = new Error(`ElevenLabs STT: ${attemptErrors.length} key(s) tried, all failed [${summary}]`);
  err.category = attemptErrors.length > 1
    ? `${attemptErrors.length} keys exhausted (last: ${last?.category})`
    : (last?.category || 'unknown');
  err.httpStatus = last?.httpStatus ?? 'network';
  throw err;
}

// ── TIER 1 — ElevenLabs Scribe v2 (single-key call, used by the ring) ─────
/**
 * @param {Uint8Array} audioBytes
 * @param {string} mime
 * @param {string} lang   '' | 'ar' | 'en'
 * @param {string} apiKey one ElevenLabs key from the ring
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
    const { quotaMessage } = await readErrorBody(res);

    const hint =
      quotaMessage ? `ElevenLabs ${quotaMessage}` :
      res.status === 401 ? 'invalid or missing ELEVEN_API_KEY' :
      res.status === 422 ? 'unsupported/unreadable audio for Scribe v2' :
      res.status === 429 ? 'ElevenLabs quota exceeded' :
      `HTTP ${res.status}`;
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

// ── TIER 3 — Deepgram Nova-2 (new in v1.6, optional fallback) ─────────────
/**
 * Deepgram's pre-recorded endpoint takes RAW audio bytes as the body (NOT
 * multipart/form-data) with Content-Type set to the audio's own mime type.
 * Language/model are passed as URL query params, not body fields.
 *
 * @param {Uint8Array} audioBytes
 * @param {string} mime
 * @param {string} lang   '' | 'ar' | 'en'
 * @param {string} apiKey Deepgram key
 * @returns {Promise<string>} transcript text (may be "")
 */
async function fetchDeepgramSTT(audioBytes, mime, lang, apiKey) {
  const params = new URLSearchParams();
  params.set('model', DEEPGRAM_MODEL);
  params.set('smart_format', 'true');
  params.set('punctuate', 'true');

  if (lang === 'ar') {
    params.set('language', 'ar');
  } else if (lang === 'en') {
    params.set('language', 'en-US');
  } else {
    // No hint available -- must explicitly request detection, otherwise
    // Deepgram defaults to English and would silently mis-transcribe Arabic.
    params.set('detect_language', 'true');
  }

  const url = `${DEEPGRAM_STT_URL}?${params.toString()}`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Token ${apiKey}`,
      'Content-Type' : mime || 'audio/wav',
    },
    body: audioBytes,
  });

  if (!res.ok) {
    const { quotaMessage } = await readErrorBody(res);

    const hint =
      quotaMessage ? `Deepgram ${quotaMessage}` :
      res.status === 401 ? 'invalid or missing DEEPGRAM_API_KEY' :
      res.status === 400 ? 'unsupported/unreadable audio for Deepgram' :
      res.status === 429 ? 'Deepgram rate limit exceeded' :
      `HTTP ${res.status}`;
    const err = new Error(`Deepgram STT: ${hint}`);
    err.httpStatus = res.status;
    err.category = hint;
    throw err;
  }

  const payload = await res.json();
  const transcript = payload?.results?.channels?.[0]?.alternatives?.[0]?.transcript;
  return typeof transcript === 'string' ? transcript : '';
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
    console.error(`[stt.js v1.6] Unrecognized lang "${langRaw}" -- using auto-detect.`);
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

  const elevenKeys  = getElevenKeyRing(env);
  const openAiKey   = env?.OPENAI_API_KEY?.trim() || '';
  const deepgramKey = env?.DEEPGRAM_API_KEY?.trim() || '';

  let tier1Err = null;
  let tier2Err = null;
  let tier3Err = null;

  // TIER 1 — ElevenLabs Scribe v2, round-robin + quota-failover across
  // the full key ring.
  if (elevenKeys.length > 0) {
    try {
      const { text, keyIndex, keysTried } =
        await fetchElevenSTTRotating(audioBytes, mime, lang, elevenKeys);
      return jsonResponse(200, { text }, request, {
        'X-STT-Engine'          : 'elevenlabs',
        'X-STT-Eleven-KeyIndex' : String(keyIndex),
        'X-STT-Eleven-KeysTried': String(keysTried),
      });
    } catch (elErr) {
      console.error('[stt.js v1.6] ElevenLabs key ring exhausted, trying Tier 2.', elErr.message);
      tier1Err = elErr;
    }
  }

  // TIER 2 — OpenAI Whisper (only if configured)
  if (openAiKey) {
    try {
      const text = await fetchOpenAiSTT(audioBytes, mime, lang, openAiKey);
      return jsonResponse(200, { text }, request, { 'X-STT-Engine': 'whisper' });
    } catch (oaErr) {
      console.error('[stt.js v1.6] OpenAI Whisper failed, trying Tier 3.', oaErr.message);
      tier2Err = oaErr;
    }
  }

  // TIER 3 — Deepgram Nova-2 (only if configured) -- v1.6
  if (deepgramKey) {
    try {
      const text = await fetchDeepgramSTT(audioBytes, mime, lang, deepgramKey);
      return jsonResponse(200, { text }, request, { 'X-STT-Engine': 'deepgram' });
    } catch (dgErr) {
      console.error('[stt.js v1.6] Deepgram also failed.', dgErr.message);
      tier3Err = dgErr;
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
  if (tier3Err) {
    diagHeaders['X-STT-Tier3-Status'] = String(tier3Err.httpStatus ?? 'network');
    diagHeaders['X-STT-Tier3-Reason'] = tier3Err.category || tier3Err.message;
  }

  if (elevenKeys.length === 0 && !openAiKey && !deepgramKey) {
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
