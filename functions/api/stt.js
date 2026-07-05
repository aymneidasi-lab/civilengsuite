/**
 * functions/api/stt.js  —  v1.9  (2026-07-04)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — STT Proxy
 * Route:  POST /api/stt   { "audio": "<base64>", "mime": "audio/wav", "lang": "ar" }
 *
 * Companion to functions/api/tts.js — TTS is unchanged by this revision.
 *
 * v1.4 [QUOTA-DIAGNOSTIC-FIX] / v1.5 [KEY-POOL-ROTATION] /
 * v1.6 [DEEPGRAM-TIER3] / v1.7 [SPEECHMATICS-TIER2] / v1.8 [CASING-FIX]:
 * see prior revisions' history for the incremental path here. Short
 * version: three independent, free-tier STT providers (ElevenLabs,
 * Speechmatics, Deepgram), each with its own key ring, tried strictly in
 * that order.
 *
 * v1.9 [CASE-INSENSITIVE-KEY-DISCOVERY]: v1.8 hardcoded the EXACT env var
 * names as read off a Cloudflare dashboard screenshot (e.g.
 * "Speechmatics_API_KEY_3"). Two problems with that, discovered before it
 * shipped rather than after: (1) the dashboard's list view truncates long
 * names with "...", so the exact text of the numbered slots' suffixes was
 * never actually confirmed, only the unsuffixed base name was fully
 * visible; (2) with 13 different team members each hand-typing their own
 * key into the dashboard, there is no guarantee every person used
 * identical casing -- one exact hardcoded string cannot match 13
 * potentially-inconsistent spellings of "the same" variable name.
 *
 * FIX: buildKeyRing() no longer looks up specific property names at all.
 * It enumerates EVERY key actually present on env and case-insensitively
 * regex-matches each one against `^<baseName>(_\d+)?$`. This finds
 * ELEVEN_API_KEY_7, Eleven_Api_Key_7, or eleven_api_key_7 equally well --
 * whatever any individual person actually typed -- with zero dependency
 * on reading dashboard screenshots correctly ever again. Response headers
 * now also report how many keys were actually discovered per tier
 * (X-STT-*-KeysAvailable), so this can be verified with one curl request
 * instead of a dashboard screenshot.
 *
 * ── SETUP ─────────────────────────────────────────────────────────────────
 *   Every tier is independently optional. For each tier, set an unsuffixed
 *   key (any casing) and/or as many "<name>_<number>" keys (any casing,
 *   any numbering -- 1, 2, 3... need not be contiguous or start at 1) as
 *   you want, using the base names below as a case-insensitive guide:
 *   Tier 1 : ELEVEN_API_KEY[_N]
 *   Tier 2 : SPEECHMATICS_API_KEY[_N]
 *   Tier 3 : DEEPGRAM_API_KEY[_N]
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
 *   X-STT-Engine                  : 'elevenlabs' | 'speechmatics' | 'deepgram'
 *   X-STT-KeyIndex                : ring slot that answered, winning tier
 *   X-STT-KeysTried               : keys attempted in the winning tier's ring
 *   X-STT-Eleven-KeysAvailable    : how many ElevenLabs keys were discovered
 *   X-STT-Speechmatics-KeysAvailable, X-STT-Deepgram-KeysAvailable : ditto
 *     (present on EVERY response, success or failure -- cheapest possible
 *     way to confirm key discovery is working: `curl -I` the endpoint)
 *   X-STT-Tier1/2/3-Status / -Reason : present only on the final 503 path.
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
const DEEPGRAM_STT_URL = 'https://api.deepgram.com/v1/listen';
const DEEPGRAM_MODEL = 'nova-2'; // NOT nova-3 -- nova-3 covers far fewer languages; nova-2 covers Arabic
const SPEECHMATICS_JOBS_URL = 'https://asr.api.speechmatics.com/v2/jobs/';
const SPEECHMATICS_POLL_INTERVAL_MS = 1500;
const SPEECHMATICS_POLL_MAX_ATTEMPTS = 14; // ~21s budget -- raise for longer audio

const ALLOWED_LANGS = new Set(['ar', 'en']); // extend as needed; "" = auto-detect

// v1.9: case-insensitive base names -- see buildKeyRing() for how these
// are matched. Casing here is purely for readability; it has no effect
// on which actual env vars get discovered.
const PROVIDER_BASE_NAMES = {
  eleven      : 'ELEVEN_API_KEY',
  speechmatics: 'SPEECHMATICS_API_KEY',
  deepgram    : 'DEEPGRAM_API_KEY',
};

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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * v1.4/v1.6/v1.7: Read a failed fetch Response body ONCE, safely, and pull
 * out whatever quota/credit signal the provider put there.
 *
 * IMPORTANT: a Response body can only be read once. This function OWNS
 * that read for the error path.
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
  const msg  = detail?.message || raw?.error?.message ||
               (typeof raw?.error === 'string' ? raw.error : '') ||
               raw?.err_msg || raw?.message || '';

  const looksLikeQuota =
    /quota_exceeded/i.test(String(code)) ||
    /insufficient_quota/i.test(String(code)) ||
    /insufficient/i.test(String(code)) ||
    /quota/i.test(String(msg)) ||
    /credits?\s+remaining/i.test(String(msg)) ||
    /out of credit/i.test(String(msg)) ||
    /usage remaining/i.test(String(msg));

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

// ── v1.9 — case-insensitive key-ring discovery, shared by all 3 tiers ────
/**
 * Discover every env var matching `<baseName>` or `<baseName>_<digits>`,
 * CASE-INSENSITIVELY, regardless of exact casing used when each secret was
 * created. This replaces exact-string lookups entirely -- there is no
 * dependency on knowing the precise spelling of any numbered slot.
 *
 * @param {object} env
 * @param {string} baseName  e.g. 'ELEVEN_API_KEY' (case is irrelevant)
 * @returns {{ keys: string[], matchedNames: string[] }}
 *   keys: de-duplicated, trimmed, non-empty values, in the order their
 *         matching env var names sort (case-insensitively) -- the
 *         unsuffixed base name sorts first if present.
 *   matchedNames: the ACTUAL env var names that matched, for diagnostics.
 */
function buildKeyRing(env, baseName) {
  const pattern = new RegExp(`^${baseName}(?:_(\\d+))?$`, 'i');
  const found = []; // { name, suffix: number|-1 (for base), value }

  for (const name of Object.keys(env || {})) {
    const m = pattern.exec(name);
    if (!m) continue;
    const value = env[name]?.trim?.();
    if (!value) continue;
    const suffix = m[1] !== undefined ? parseInt(m[1], 10) : -1;
    found.push({ name, suffix, value });
  }

  // Base name (suffix -1) first, then numbered slots in ascending order.
  found.sort((a, b) => a.suffix - b.suffix);

  const keys = [];
  const matchedNames = [];
  const seenValues = new Set();
  for (const f of found) {
    if (seenValues.has(f.value)) continue; // protects against the same key pasted into two slots
    seenValues.add(f.value);
    keys.push(f.value);
    matchedNames.push(f.name);
  }

  return { keys, matchedNames };
}

/**
 * Shared rotation + quota-failover logic for any provider's key ring.
 * `pointerState` is a small mutable object ({ i: 0 }) private to each
 * tier, so each tier's round-robin position advances independently.
 *
 * @param {{i: number}} pointerState
 * @param {string[]} keys
 * @param {(audioBytes: Uint8Array, mime: string, lang: string, key: string) => Promise<string>} singleFetch
 * @returns {Promise<{ text: string, keyIndex: number, keysTried: number }>}
 */
async function rotateAndFetch(pointerState, keys, singleFetch, audioBytes, mime, lang, providerLabel) {
  if (keys.length === 0) {
    const err = new Error(`${providerLabel} STT: no keys configured`);
    err.category = 'no keys configured';
    err.httpStatus = 'network';
    throw err;
  }

  const startIdx = pointerState.i % keys.length;
  pointerState.i = (pointerState.i + 1) % keys.length;

  const attemptErrors = [];
  for (let step = 0; step < keys.length; step++) {
    const idx = (startIdx + step) % keys.length;
    try {
      const text = await singleFetch(audioBytes, mime, lang, keys[idx]);
      return { text, keyIndex: idx, keysTried: step + 1 };
    } catch (err) {
      attemptErrors.push({ idx, category: err.category || err.message, httpStatus: err.httpStatus });

      const isKeySpecific =
        /quota exceeded/i.test(err.category || '') ||
        err.httpStatus === 401;
      if (!isKeySpecific) break; // non-key-specific failure (e.g. bad audio) -- every key would fail identically
    }
  }

  const summary = attemptErrors.map(e => `key#${e.idx}:${e.category}`).join(', ');
  const last = attemptErrors[attemptErrors.length - 1];
  const err = new Error(`${providerLabel} STT: ${attemptErrors.length} key(s) tried, all failed [${summary}]`);
  err.category = attemptErrors.length > 1
    ? `${attemptErrors.length} keys exhausted (last: ${last?.category})`
    : (last?.category || 'unknown');
  err.httpStatus = last?.httpStatus ?? 'network';
  throw err;
}

// Module-scoped, per-tier ring pointers -- best-effort load spreading
// across requests within a reused isolate (not relied on for correctness).
const ringPointers = {
  eleven      : { i: 0 },
  speechmatics: { i: 0 },
  deepgram    : { i: 0 },
};

// ── TIER 1 — ElevenLabs Scribe v2 (single-key call, used by the ring) ─────
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
      res.status === 401 ? 'invalid or missing key' :
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

// ── TIER 2 — Speechmatics (single-key call, used by the ring) ────────────
/**
 * Speechmatics batch transcription is an async job API: submit, poll,
 * fetch. This wrapper performs all three steps and returns a plain
 * transcript string, so the ring sees the same shape as the other tiers.
 */
async function fetchSpeechmaticsSTT(audioBytes, mime, lang, apiKey) {
  const effectiveLang = lang || 'ar'; // no true auto-detect in batch V2 -- default to Arabic, this route's primary purpose
  const authHeader = { Authorization: `Bearer ${apiKey}` };

  const config = JSON.stringify({
    type: 'transcription',
    transcription_config: { language: effectiveLang },
  });
  const submitForm = new FormData();
  submitForm.append('data_file', new Blob([audioBytes], { type: mime }), `audio.${extForMime(mime)}`);
  submitForm.append('config', config);

  const submitRes = await fetch(SPEECHMATICS_JOBS_URL, {
    method: 'POST',
    headers: authHeader,
    body: submitForm,
  });

  if (!submitRes.ok) {
    const { quotaMessage } = await readErrorBody(submitRes);
    const hint =
      quotaMessage ? `Speechmatics ${quotaMessage}` :
      submitRes.status === 401 ? 'invalid or missing key' :
      submitRes.status === 400 ? 'unsupported/unreadable audio for Speechmatics' :
      submitRes.status === 403 ? 'Speechmatics quota or plan restriction' :
      `HTTP ${submitRes.status}`;
    const err = new Error(`Speechmatics STT (submit): ${hint}`);
    err.httpStatus = submitRes.status;
    err.category = hint;
    throw err;
  }

  const submitPayload = await submitRes.json();
  const jobId = submitPayload?.id || submitPayload?.job?.id;
  if (!jobId) {
    const err = new Error('Speechmatics STT: submit response had no job id');
    err.httpStatus = 'network';
    err.category = 'malformed submit response';
    throw err;
  }

  let jobStatus = 'running';
  for (let attempt = 0; attempt < SPEECHMATICS_POLL_MAX_ATTEMPTS; attempt++) {
    await sleep(SPEECHMATICS_POLL_INTERVAL_MS);

    const pollRes = await fetch(`${SPEECHMATICS_JOBS_URL}${jobId}`, { headers: authHeader });
    if (!pollRes.ok) {
      const { quotaMessage } = await readErrorBody(pollRes);
      const hint = quotaMessage ? `Speechmatics ${quotaMessage}` : `HTTP ${pollRes.status}`;
      const err = new Error(`Speechmatics STT (poll): ${hint}`);
      err.httpStatus = pollRes.status;
      err.category = hint;
      throw err;
    }

    const pollPayload = await pollRes.json();
    jobStatus = pollPayload?.job?.status || 'running';

    if (jobStatus === 'done') break;
    if (jobStatus === 'rejected' || jobStatus === 'deleted') {
      const err = new Error(`Speechmatics STT: job ended with status "${jobStatus}"`);
      err.httpStatus = 'network';
      err.category = `job ${jobStatus}`;
      throw err;
    }
  }

  if (jobStatus !== 'done') {
    const err = new Error('Speechmatics STT: job did not finish within poll budget');
    err.httpStatus = 'network';
    err.category = 'poll timeout';
    throw err;
  }

  const transcriptRes = await fetch(`${SPEECHMATICS_JOBS_URL}${jobId}/transcript?format=txt`, {
    headers: authHeader,
  });
  if (!transcriptRes.ok) {
    const err = new Error(`Speechmatics STT (transcript): HTTP ${transcriptRes.status}`);
    err.httpStatus = transcriptRes.status;
    err.category = `HTTP ${transcriptRes.status}`;
    throw err;
  }

  const text = await transcriptRes.text();
  return typeof text === 'string' ? text.trim() : '';
}

// ── TIER 3 — Deepgram Nova-2 (single-key call, used by the ring) ─────────
/**
 * Deepgram's pre-recorded endpoint takes RAW audio bytes as the body (NOT
 * multipart/form-data) with Content-Type set to the audio's own mime type.
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
      res.status === 401 ? 'invalid or missing key' :
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
    console.error(`[stt.js v1.9] Unrecognized lang "${langRaw}" -- using auto-detect.`);
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

  const eleven       = buildKeyRing(env, PROVIDER_BASE_NAMES.eleven);
  const speechmatics = buildKeyRing(env, PROVIDER_BASE_NAMES.speechmatics);
  const deepgram     = buildKeyRing(env, PROVIDER_BASE_NAMES.deepgram);

  // v1.9: always-present discovery counts -- lets anyone verify key
  // pickup with `curl -I`, no dashboard screenshot needed.
  const keyCountHeaders = {
    'X-STT-Eleven-KeysAvailable'      : String(eleven.keys.length),
    'X-STT-Speechmatics-KeysAvailable': String(speechmatics.keys.length),
    'X-STT-Deepgram-KeysAvailable'    : String(deepgram.keys.length),
  };

  let tier1Err = null;
  let tier2Err = null;
  let tier3Err = null;

  // TIER 1 — ElevenLabs ring
  if (eleven.keys.length > 0) {
    try {
      const { text, keyIndex, keysTried } =
        await rotateAndFetch(ringPointers.eleven, eleven.keys, fetchElevenSTT, audioBytes, mime, lang, 'ElevenLabs');
      return jsonResponse(200, { text }, request, {
        ...keyCountHeaders,
        'X-STT-Engine'   : 'elevenlabs',
        'X-STT-KeyIndex' : String(keyIndex),
        'X-STT-KeysTried': String(keysTried),
      });
    } catch (elErr) {
      console.error('[stt.js v1.9] ElevenLabs ring exhausted, trying Tier 2.', elErr.message);
      tier1Err = elErr;
    }
  }

  // TIER 2 — Speechmatics ring
  if (speechmatics.keys.length > 0) {
    try {
      const { text, keyIndex, keysTried } =
        await rotateAndFetch(ringPointers.speechmatics, speechmatics.keys, fetchSpeechmaticsSTT, audioBytes, mime, lang, 'Speechmatics');
      return jsonResponse(200, { text }, request, {
        ...keyCountHeaders,
        'X-STT-Engine'   : 'speechmatics',
        'X-STT-KeyIndex' : String(keyIndex),
        'X-STT-KeysTried': String(keysTried),
      });
    } catch (smErr) {
      console.error('[stt.js v1.9] Speechmatics ring exhausted, trying Tier 3.', smErr.message);
      tier2Err = smErr;
    }
  }

  // TIER 3 — Deepgram ring
  if (deepgram.keys.length > 0) {
    try {
      const { text, keyIndex, keysTried } =
        await rotateAndFetch(ringPointers.deepgram, deepgram.keys, fetchDeepgramSTT, audioBytes, mime, lang, 'Deepgram');
      return jsonResponse(200, { text }, request, {
        ...keyCountHeaders,
        'X-STT-Engine'   : 'deepgram',
        'X-STT-KeyIndex' : String(keyIndex),
        'X-STT-KeysTried': String(keysTried),
      });
    } catch (dgErr) {
      console.error('[stt.js v1.9] Deepgram ring also exhausted.', dgErr.message);
      tier3Err = dgErr;
    }
  }

  const diagHeaders = { ...keyCountHeaders };
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

  if (eleven.keys.length === 0 && speechmatics.keys.length === 0 && deepgram.keys.length === 0) {
    return jsonResponse(502, { error: 'STT provider not configured on the server.' }, request, diagHeaders);
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
