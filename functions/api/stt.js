/**
 * functions/api/stt.js  —  v1.7  (2026-07-04)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — STT Proxy
 * Route:  POST /api/stt   { "audio": "<base64>", "mime": "audio/wav", "lang": "ar" }
 *
 * Companion to functions/api/tts.js — TTS is unchanged by this revision.
 *
 * v1.4 [QUOTA-DIAGNOSTIC-FIX]: read the JSON error body and detect
 * provider-specific quota/credit-exhaustion codes BEFORE falling back to
 * an HTTP-status-only hint table. See readErrorBody() below.
 *
 * v1.5 [KEY-POOL-ROTATION]: Tier 1 (ElevenLabs) accepts up to 13
 * independent API keys via ELEVEN_API_KEY_1..ELEVEN_API_KEY_13, tried in a
 * round-robin + quota-failover ring. See getElevenKeyRing()/
 * fetchElevenSTTRotating() below.
 *
 * v1.6 [DEEPGRAM-TIER3]: Added Deepgram Nova-2 as a third, independent
 * provider, tried only after Tier 1 and Tier 2 both fail.
 *
 * v1.7 [SPEECHMATICS-REPLACES-OPENAI / ALL-$0-STACK]: Tier 2 is now
 * Speechmatics instead of OpenAI Whisper. Reasoning: OpenAI has no free
 * tier at all (requires a card on file and prepayment before any request
 * succeeds), so it did not belong in an explicitly $0-cost stack. All
 * THREE tiers are now free-tier-only, no card required anywhere:
 *   Tier 1  ElevenLabs   10,000 credits/month, recurring monthly
 *   Tier 2  Speechmatics 480 minutes/month,   recurring monthly
 *   Tier 3  Deepgram     $200 one-time signup credit, non-recurring
 *
 *   Speechmatics is architecturally different from both other tiers: it is
 *   an ASYNC job API, not a single synchronous call --
 *     1. POST /v2/jobs/  (multipart: data_file + config JSON string)
 *        -> 201, body contains the new job's `id`
 *     2. Poll GET /v2/jobs/{id} until job.status === 'done'
 *        (status starts 'running'; 'rejected' means it failed)
 *     3. GET /v2/jobs/{id}/transcript?format=txt -> plain-text transcript
 *        body (NOT JSON -- format=txt returns raw text directly)
 *   fetchSpeechmaticsSTT() implements all three steps internally so the
 *   Tier 2 call site still looks like a single async function to the rest
 *   of this file. Polling uses a bounded budget (see SPEECHMATICS_POLL_*
 *   constants) -- short voice-chat clips finish in a few seconds, but if
 *   you start feeding this longer audio, raise the attempt count/interval
 *   accordingly or this will time out on legitimately-still-running jobs.
 *   Speechmatics' documented language field only needs a plain ISO 639-1
 *   code ("ar"/"en"); when no lang hint is available this defaults to
 *   "ar" (not a true auto-detect -- Speechmatics batch V2 requires an
 *   explicit language), since this endpoint's entire reason for existing
 *   is the Arabic path the local Windows recognizer cannot handle.
 *   readErrorBody() is broadened (not duplicated) to also recognize a
 *   plain string raw.error field, in addition to ElevenLabs/OpenAI/
 *   Deepgram's shapes, since Speechmatics' exact quota-exceeded error body
 *   shape was not confirmed against a live account at time of writing --
 *   worth re-verifying the very first time Tier 2 actually fails in
 *   production, the same way the ElevenLabs quota shape was confirmed by a
 *   live curl earlier in this project.
 *
 * ── SETUP ─────────────────────────────────────────────────────────────────
 *   Tier 1 (existing): ELEVEN_API_KEY, optionally ELEVEN_API_KEY_1..13.
 *   Tier 2 (new, v1.7): SPEECHMATICS_API_KEY -- signup at speechmatics.com,
 *     dashboard -> API Keys, no card required.
 *   Tier 3 (existing, v1.6): DEEPGRAM_API_KEY -- signup at deepgram.com,
 *     console -> API Keys, no card required.
 *   Every tier is independently optional -- absent env vars are skipped
 *   silently.
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
 *   X-STT-Engine            : 'elevenlabs' | 'speechmatics' | 'deepgram'
 *   X-STT-Eleven-KeyIndex   : ring slot that answered (elevenlabs 200 only)
 *   X-STT-Eleven-KeysTried  : how many ElevenLabs ring keys were attempted
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * v1.4/v1.6/v1.7: Read a failed fetch Response body ONCE, safely, and pull
 * out whatever quota/credit signal the provider put there. Returns null if
 * the body isn't JSON or doesn't look quota-related -- callers fall back
 * to their existing HTTP-status table in that case.
 *
 * Recognizes four provider error shapes:
 *   ElevenLabs   : { detail: { code, status, message } }
 *   OpenAI-style : { error: { code, message, type } }
 *   Deepgram     : { err_code, err_msg, request_id }
 *   Speechmatics : { error: "<plain string message>" }  (shape not yet
 *                  confirmed against a live quota-exhausted account --
 *                  re-verify on first real Tier 2 failure)
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

// ── v1.5 — ElevenLabs key-pool ring ─────────────────────────────────────
/**
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
// within a reused isolate.
let elevenRingPointer = 0;

/**
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
      if (!isKeySpecific) break;
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

// ── TIER 2 — Speechmatics (new in v1.7, replaces OpenAI Whisper) ──────────
/**
 * Speechmatics batch transcription is an async job API: submit, poll,
 * fetch. This wrapper performs all three steps and returns a plain
 * transcript string, so the call site sees the same shape as Tier 1/3.
 *
 * @param {Uint8Array} audioBytes
 * @param {string} mime
 * @param {string} lang   '' | 'ar' | 'en'  -- '' defaults to 'ar', see v1.7 note
 * @param {string} apiKey Speechmatics key
 * @returns {Promise<string>} transcript text (may be "")
 */
async function fetchSpeechmaticsSTT(audioBytes, mime, lang, apiKey) {
  const effectiveLang = lang || 'ar'; // no true auto-detect in batch V2 -- default to Arabic, this route's primary purpose
  const authHeader = { Authorization: `Bearer ${apiKey}` };

  // ── Step 1: submit job ──
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
      submitRes.status === 401 ? 'invalid or missing SPEECHMATICS_API_KEY' :
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

  // ── Step 2: poll until done ──
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
    // else 'running' -- loop again
  }

  if (jobStatus !== 'done') {
    const err = new Error('Speechmatics STT: job did not finish within poll budget');
    err.httpStatus = 'network';
    err.category = 'poll timeout';
    throw err;
  }

  // ── Step 3: fetch transcript as plain text ──
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

// ── TIER 3 — Deepgram Nova-2 (optional fallback) ──────────────────────────
/**
 * Deepgram's pre-recorded endpoint takes RAW audio bytes as the body (NOT
 * multipart/form-data) with Content-Type set to the audio's own mime type.
 *
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
    console.error(`[stt.js v1.7] Unrecognized lang "${langRaw}" -- using auto-detect.`);
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

  const elevenKeys      = getElevenKeyRing(env);
  const speechmaticsKey = env?.SPEECHMATICS_API_KEY?.trim() || '';
  const deepgramKey     = env?.DEEPGRAM_API_KEY?.trim() || '';

  let tier1Err = null;
  let tier2Err = null;
  let tier3Err = null;

  // TIER 1 — ElevenLabs Scribe v2, round-robin + quota-failover ring
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
      console.error('[stt.js v1.7] ElevenLabs key ring exhausted, trying Tier 2.', elErr.message);
      tier1Err = elErr;
    }
  }

  // TIER 2 — Speechmatics (v1.7, replaces OpenAI Whisper)
  if (speechmaticsKey) {
    try {
      const text = await fetchSpeechmaticsSTT(audioBytes, mime, lang, speechmaticsKey);
      return jsonResponse(200, { text }, request, { 'X-STT-Engine': 'speechmatics' });
    } catch (smErr) {
      console.error('[stt.js v1.7] Speechmatics failed, trying Tier 3.', smErr.message);
      tier2Err = smErr;
    }
  }

  // TIER 3 — Deepgram Nova-2
  if (deepgramKey) {
    try {
      const text = await fetchDeepgramSTT(audioBytes, mime, lang, deepgramKey);
      return jsonResponse(200, { text }, request, { 'X-STT-Engine': 'deepgram' });
    } catch (dgErr) {
      console.error('[stt.js v1.7] Deepgram also failed.', dgErr.message);
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

  if (elevenKeys.length === 0 && !speechmaticsKey && !deepgramKey) {
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
