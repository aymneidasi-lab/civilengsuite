/**
 * functions/api/tts.js  —  v5  (2026-07-04)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — TTS Proxy
 * Route:  GET /api/tts?text=...&lang=ar-EG[&voice=female|male]
 *
 * ── v4 → v5: added Deepgram Aura as a language-gated Tier 2 ───────────────
 *
 * Research before building this (not assumed) turned up two facts that
 * shape the architecture:
 *
 *   1. Deepgram Aura (their TTS product) draws from the SAME $200 signup
 *      credit already shared with Deepgram STT (confirmed on Deepgram's
 *      own pricing page: the credit "can be used for any Deepgram
 *      service: Speech-to-Text, Text-to-Speech, Voice Agent API..."). The
 *      Deepgram key ring already built for stt.js works here unchanged --
 *      genuinely zero new cost, consistent with every other tier in this
 *      project.
 *   2. Speechmatics' TTS product, by contrast, now carries REAL per-
 *      character pricing ($0.011/1,000 chars) on their own product page --
 *      it launched as a free preview but that preview-to-billing
 *      transition (announced for Oct 2025) has evidently completed. Unlike
 *      every other provider wired into this project, enabling it would be
 *      the first genuine per-request cost. It is intentionally NOT wired
 *      in by default -- see fetchSpeechmaticsTTS() below, present but
 *      unused unless ENABLE_SPEECHMATICS_TTS=true is explicitly set.
 *
 *   Neither Deepgram Aura nor Speechmatics TTS support Arabic (Aura:
 *   English/Spanish/Dutch/French/German/Italian/Japanese; Speechmatics:
 *   English US/UK only) -- confirmed from each vendor's own docs. So this
 *   is NOT a blind copy of stt.js's 3-tier structure. Tiers are
 *   LANGUAGE-GATED: Deepgram Aura is only ever attempted for English
 *   requests. For Arabic, the cascade is unchanged from v4: ElevenLabs
 *   ring -> Google Translate TTS. Calling an English-only engine with
 *   Arabic text would be a guaranteed, pointless failure -- gating it out
 *   entirely is both faster and more correct than "try everything".
 *
 * ── ARCHITECTURE ──────────────────────────────────────────────────────────
 *
 *   TIER 1  ElevenLabs — eleven_multilingual_v2, key-pool ring, ALL langs
 *   ─────────────────────────────────────────────────────────
 *   Endpoint : POST https://api.elevenlabs.io/v1/text-to-speech/{voice_id}
 *   Voice settings tuned for Arabic engineering narration (see
 *   fetchElevenTTS for the stability/similarity_boost/style rationale).
 *
 *   TIER 2  Deepgram Aura-2 — key-pool ring, ENGLISH ONLY (v5, new)
 *   ─────────────────────────────────────────────────────────
 *   Endpoint : POST https://api.deepgram.com/v1/speak
 *   Auth     : Authorization: Token <key> -- rotated across the SAME
 *              Deepgram key ring already configured for stt.js.
 *   Model    : aura-2 (default voice: asteria, English)
 *   Only attempted when the resolved language is English -- see
 *   isEnglish() gate in onRequestGet.
 *
 *   TIER 3  Google Translate TTS — zero-setup fallback, ALL langs
 *   ─────────────────────────────────────────────────────────
 *   Unchanged from v3/v4. Public, unauthenticated, no quota concept.
 *
 *   NOT WIRED IN BY DEFAULT: Speechmatics TTS (real per-character cost --
 *   see fetchSpeechmaticsTTS() and ENABLE_SPEECHMATICS_TTS below).
 *
 * ── SETUP ─────────────────────────────────────────────────────────────────
 *   Uses the SAME Cloudflare secrets already added for stt.js -- nothing
 *   new to add for Tier 1 or Tier 2. Discovery is case-insensitive (any
 *   casing any team member actually used):
 *     ELEVEN_API_KEY(_1..12)     -- Tier 1, all languages
 *     DEEPGRAM_API_KEY(_1..12)   -- Tier 2, English only
 *
 *   Optional voice override:
 *      ELEVEN_VOICE_ID_F / ELEVEN_VOICE_ID_M   (see resolveVoiceId)
 *
 *   OPTIONAL, OFF BY DEFAULT, REAL COST: to enable Speechmatics TTS as an
 *   additional English-only tier between Deepgram and Google despite its
 *   $0.011/1,000-char pricing, set:
 *      ENABLE_SPEECHMATICS_TTS = "true"
 *   using the SAME Speechmatics_API_KEY(_1..12) already configured for
 *   stt.js. Left unset, this tier never activates and never bills.
 *
 * ── RESPONSE HEADERS ─────────────────────────────────────────────────────
 *   X-TTS-Engine                : 'elevenlabs' | 'deepgram' | 'speechmatics' | 'gtts'
 *   X-TTS-Voice                 : voice_id used (ElevenLabs only)
 *   X-TTS-Lang                  : resolved language code
 *   X-TTS-KeyIndex/KeysTried    : ring stats for whichever tier answered
 *   X-TTS-Eleven-KeysAvailable  : always present
 *   X-TTS-Deepgram-KeysAvailable: always present
 *   (cheapest way to confirm pool pickup: `curl -sI ".../api/tts?text=x"`)
 *
 * ── CSP NOTE ─────────────────────────────────────────────────────────────
 *   Audio is served from /api/tts (same origin). media-src 'self' is correct.
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
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary'                        : 'Origin',
  };
}

// ── Allowed TTS languages ─────────────────────────────────────────────────
const ALLOWED_LANGS = new Set([
  'ar', 'ar-EG', 'ar-SA', 'ar-MA', 'ar-JO', 'ar-DZ', 'ar-IQ',
  'en', 'en-US', 'en-GB', 'en-AU',
]);

const MAX_TEXT_LENGTH = 200;

/** True for any resolved lang code starting with 'en' -- gates Tier 2/opt-in Speechmatics. */
function isEnglish(lang) {
  return lang.toLowerCase().startsWith('en');
}

// ── ElevenLabs constants ──────────────────────────────────────────────────
const ELEVEN_API_URL    = 'https://api.elevenlabs.io/v1/text-to-speech';
const ELEVEN_MODEL      = 'eleven_multilingual_v2';
const ELEVEN_OUT_FORMAT = 'mp3_44100_128';
const ELEVEN_DEFAULT_F  = 'EXAVITQu4vr4xnSDxMaL';   // Bella (female)
const ELEVEN_DEFAULT_M  = 'pNInz6obpgDQGcFmaJgB';   // Adam  (male)
const ELEVEN_BASE_NAME  = 'ELEVEN_API_KEY';

// ── Deepgram constants (v5) ────────────────────────────────────────────────
const DEEPGRAM_SPEAK_URL = 'https://api.deepgram.com/v1/speak';
const DEEPGRAM_TTS_MODEL = 'aura-2'; // English default (asteria voice) -- do NOT send this to Arabic requests, unsupported
const DEEPGRAM_BASE_NAME = 'DEEPGRAM_API_KEY'; // same ring already built for stt.js

// ── Speechmatics constants (v5, OPT-IN ONLY -- see header note on cost) ───
const SPEECHMATICS_TTS_URL_BASE = 'https://preview.tts.speechmatics.com/generate';
const SPEECHMATICS_TTS_VOICE    = 'sarah'; // only voice name confirmed from Speechmatics' own docs at time of writing
const SPEECHMATICS_BASE_NAME    = 'SPEECHMATICS_API_KEY'; // same ring already built for stt.js

// ── Utilities ─────────────────────────────────────────────────────────────

/**
 * Preprocess Arabic text before sending to any TTS engine. See v3 for full
 * rationale per step (control-char stripping, Arabic-Indic and Extended
 * Arabic-Indic digit normalisation, whitespace collapsing).
 */
function preprocessText(text) {
  return text
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ' ')
    .replace(/[٠١٢٣٤٥٦٧٨٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d).toString())
    .replace(/[۰۱۲۳۴۵۶۷۸۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d).toString())
    .replace(/[ \t]+/g, ' ')
    .trim();
}

/** Resolve voice ID from env or fall back to hardcoded default. */
function resolveVoiceId(genderKey, env) {
  if (genderKey === 'male') {
    return (env?.ELEVEN_VOICE_ID_M?.trim() || '') || ELEVEN_DEFAULT_M;
  }
  return (env?.ELEVEN_VOICE_ID_F?.trim() || '') || ELEVEN_DEFAULT_F;
}

/**
 * Ported verbatim from stt.js v1.9: read a failed fetch Response body ONCE
 * and pull out a quota/credit signal if present, before guessing from the
 * HTTP status code alone.
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

/**
 * Ported verbatim from stt.js v1.9: discover every env var matching
 * `<baseName>` or `<baseName>_<digits>`, CASE-INSENSITIVELY. See stt.js
 * for the full rationale (13 different people, 13 possible casings).
 *
 * @param {object} env
 * @param {string} baseName
 * @returns {{ keys: string[], matchedNames: string[] }}
 */
function buildKeyRing(env, baseName) {
  const pattern = new RegExp(`^${baseName}(?:_(\\d+))?$`, 'i');
  const found = [];

  for (const name of Object.keys(env || {})) {
    const m = pattern.exec(name);
    if (!m) continue;
    const value = env[name]?.trim?.();
    if (!value) continue;
    const suffix = m[1] !== undefined ? parseInt(m[1], 10) : -1;
    found.push({ name, suffix, value });
  }

  found.sort((a, b) => a.suffix - b.suffix);

  const keys = [];
  const matchedNames = [];
  const seenValues = new Set();
  for (const f of found) {
    if (seenValues.has(f.value)) continue;
    seenValues.add(f.value);
    keys.push(f.value);
    matchedNames.push(f.name);
  }

  return { keys, matchedNames };
}

// Module-scoped ring pointers -- one per tier, independent of stt.js's own
// pointers (separate files/module instances). Best-effort load spreading
// across requests within a reused isolate; not relied on for correctness.
const ringPointers = {
  eleven  : { i: 0 },
  deepgram: { i: 0 },
};

/**
 * Generic round-robin + quota-failover walk over ANY provider's key ring.
 * `singleFetchFn` takes just the key (text/voice/etc are pre-bound by the
 * caller via closure) and returns a Promise<Response>.
 *
 * @param {{i:number}} pointerState
 * @param {string[]} keys
 * @param {(key: string) => Promise<Response>} singleFetchFn
 * @param {string} providerLabel  used only in error messages
 * @returns {Promise<{ response: Response, keyIndex: number, keysTried: number }>}
 */
async function rotateAndFetchTTS(pointerState, keys, singleFetchFn, providerLabel) {
  if (keys.length === 0) {
    const err = new Error(`${providerLabel} TTS: no keys configured`);
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
      const response = await singleFetchFn(keys[idx]);
      return { response, keyIndex: idx, keysTried: step + 1 };
    } catch (err) {
      attemptErrors.push({ idx, category: err.category || err.message, httpStatus: err.httpStatus });

      const isKeySpecific =
        /quota exceeded/i.test(err.category || '') ||
        err.httpStatus === 401;
      if (!isKeySpecific) break; // non-key-specific failure -- every key would fail identically
    }
  }

  const summary = attemptErrors.map(e => `key#${e.idx}:${e.category}`).join(', ');
  const last = attemptErrors[attemptErrors.length - 1];
  const err = new Error(`${providerLabel} TTS: ${attemptErrors.length} key(s) tried, all failed [${summary}]`);
  err.category = attemptErrors.length > 1
    ? `${attemptErrors.length} keys exhausted (last: ${last?.category})`
    : (last?.category || 'unknown');
  err.httpStatus = last?.httpStatus ?? 'network';
  throw err;
}

// ── TIER 1 — ElevenLabs neural TTS (single-key call, used by the ring) ───
/**
 * Model: eleven_multilingual_v2 (see v3 for why over eleven_flash_v2_5).
 * Voice settings tuned for Arabic engineering narration:
 *   stability=0.75, similarity_boost=0.85, style=0, use_speaker_boost=true.
 *
 * @returns {Promise<Response>} Audio response, Content-Type audio/mpeg
 */
async function fetchElevenTTS(text, apiKey, voiceId) {
  const url = `${ELEVEN_API_URL}/${voiceId}?output_format=${ELEVEN_OUT_FORMAT}`;

  const elRes = await fetch(url, {
    method : 'POST',
    headers: {
      'xi-api-key'  : apiKey,
      'Content-Type': 'application/json',
      'Accept'      : 'audio/mpeg',
    },
    body: JSON.stringify({
      text,
      model_id: ELEVEN_MODEL,
      voice_settings: {
        stability        : 0.75,
        similarity_boost : 0.85,
        style            : 0.0,
        use_speaker_boost: true,
      },
    }),
  });

  if (!elRes.ok) {
    const { quotaMessage } = await readErrorBody(elRes);
    const hint =
      quotaMessage ? `ElevenLabs ${quotaMessage}` :
      elRes.status === 401 ? 'invalid or missing key' :
      elRes.status === 422 ? 'invalid voice_id — check ELEVEN_VOICE_ID_F/M' :
      elRes.status === 429 ? 'ElevenLabs quota exceeded' :
      `HTTP ${elRes.status}`;
    const err = new Error(`ElevenLabs TTS: ${hint}`);
    err.httpStatus = elRes.status;
    err.category = hint;
    throw err;
  }

  return elRes;
}

// ── TIER 2 — Deepgram Aura-2 (v5, new; single-key call, used by the ring) ─
/**
 * Deepgram's TTS REST endpoint (confirmed from Deepgram's own blog post
 * announcing Aura-2's multi-language expansion): POST /v1/speak, JSON
 * body of { model, text } (optionally "language" for the 6 non-English
 * Aura-2 languages -- NOT used here since this tier is English-only).
 * Auth: Authorization: Token <key> (same header style as Deepgram STT).
 *
 * ENGLISH ONLY -- caller (onRequestGet) must not invoke this for Arabic;
 * Aura-2 has no Arabic model and would simply error.
 *
 * @returns {Promise<Response>} Audio response, Content-Type audio/mpeg
 */
async function fetchDeepgramTTS(text, apiKey) {
  const res = await fetch(DEEPGRAM_SPEAK_URL, {
    method : 'POST',
    headers: {
      'Authorization': `Token ${apiKey}`,
      'Content-Type' : 'application/json',
    },
    body: JSON.stringify({ model: DEEPGRAM_TTS_MODEL, text }),
  });

  if (!res.ok) {
    const { quotaMessage } = await readErrorBody(res);
    const hint =
      quotaMessage ? `Deepgram ${quotaMessage}` :
      res.status === 401 ? 'invalid or missing key' :
      res.status === 400 ? 'unsupported text/model for Aura-2' :
      res.status === 429 ? 'Deepgram rate limit exceeded' :
      `HTTP ${res.status}`;
    const err = new Error(`Deepgram TTS: ${hint}`);
    err.httpStatus = res.status;
    err.category = hint;
    throw err;
  }

  return res;
}

// ── OPT-IN ONLY — Speechmatics TTS (v5, real per-character cost) ─────────
/**
 * NOT called anywhere unless env.ENABLE_SPEECHMATICS_TTS === 'true'.
 * Confirmed endpoint from Speechmatics' own quickstart docs:
 *   POST https://preview.tts.speechmatics.com/generate/{voice}
 *   Authorization: Bearer <key>,  body: { "text": "..." },  raw WAV response.
 * Only the "sarah" voice name is confirmed from Speechmatics' own example
 * at time of writing -- used for both genders here since no second voice
 * name could be confirmed; check the Speechmatics portal for additional
 * voices and update SPEECHMATICS_TTS_VOICE (or add gender branching) if
 * you actually enable this tier.
 * ENGLISH ONLY -- same constraint as Deepgram Aura, for the same reason.
 *
 * @returns {Promise<Response>} Audio response, Content-Type audio/wav
 */
async function fetchSpeechmaticsTTS(text, apiKey) {
  const url = `${SPEECHMATICS_TTS_URL_BASE}/${SPEECHMATICS_TTS_VOICE}`;

  const res = await fetch(url, {
    method : 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type' : 'application/json',
    },
    body: JSON.stringify({ text }),
  });

  if (!res.ok) {
    const { quotaMessage } = await readErrorBody(res);
    const hint =
      quotaMessage ? `Speechmatics ${quotaMessage}` :
      res.status === 401 ? 'invalid or missing key' :
      res.status === 400 ? 'unsupported text for Speechmatics TTS' :
      `HTTP ${res.status}`;
    const err = new Error(`Speechmatics TTS: ${hint}`);
    err.httpStatus = res.status;
    err.category = hint;
    throw err;
  }

  return res;
}

// ── FINAL FALLBACK — Google Translate TTS (unchanged, not pooled) ────────
/**
 * Public, unauthenticated, no per-account quota concept -- key rotation
 * does not apply here. See v3 for the client=tw-ob / ttsspeed rationale.
 */
async function fetchGoogleTTS(text, lang) {
  const url = new URL('https://translate.google.com/translate_tts');
  url.searchParams.set('ie',       'UTF-8');
  url.searchParams.set('client',   'tw-ob');
  url.searchParams.set('tl',       lang);
  url.searchParams.set('q',        text);
  url.searchParams.set('ttsspeed', '1');

  const res = await fetch(url.toString(), {
    headers: {
      'Referer'   : 'https://translate.google.com/',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
                    'AppleWebKit/537.36 (KHTML, like Gecko) ' +
                    'Chrome/125.0.0.0 Safari/537.36',
    },
    cf: { cacheEverything: true, cacheTtl: 3600 },
  });

  if (!res.ok) throw new Error(`gTTS upstream HTTP ${res.status}`);
  return res;
}

// ── GET handler ───────────────────────────────────────────────────────────
export async function onRequestGet(context) {
  const { request, env } = context;
  const url              = new URL(request.url);
  const rawText          = url.searchParams.get('text') || '';
  const langParam        = (url.searchParams.get('lang')  || 'ar-EG').trim();
  const voiceParam       = (url.searchParams.get('voice') || 'female').toLowerCase().trim();

  const text = preprocessText(rawText);
  if (!text) {
    return new Response(
      JSON.stringify({ error: 'Missing or empty text parameter.' }),
      { status: 400, headers: { 'Content-Type': 'application/json', ...getCorsHeaders(request) } },
    );
  }
  if (text.length > MAX_TEXT_LENGTH) {
    return new Response(
      JSON.stringify({ error: `Text exceeds ${MAX_TEXT_LENGTH}-char limit. Caller must pre-chunk.` }),
      { status: 400, headers: { 'Content-Type': 'application/json', ...getCorsHeaders(request) } },
    );
  }

  const safeLang     = ALLOWED_LANGS.has(langParam) ? langParam : 'ar-EG';
  const genderKey    = voiceParam === 'male' ? 'male' : 'female';
  const voiceId      = resolveVoiceId(genderKey, env);
  const englishOnly  = isEnglish(safeLang);

  const eleven   = buildKeyRing(env, ELEVEN_BASE_NAME);
  const deepgram = buildKeyRing(env, DEEPGRAM_BASE_NAME);
  const speechmaticsEnabled = (env?.ENABLE_SPEECHMATICS_TTS || '').trim().toLowerCase() === 'true';
  const speechmatics = speechmaticsEnabled ? buildKeyRing(env, SPEECHMATICS_BASE_NAME) : { keys: [] };

  const keyCountHeaders = {
    'X-TTS-Eleven-KeysAvailable'  : String(eleven.keys.length),
    'X-TTS-Deepgram-KeysAvailable': String(deepgram.keys.length),
  };

  // TIER 1 — ElevenLabs ring (all languages)
  if (eleven.keys.length > 0) {
    try {
      const { response, keyIndex, keysTried } = await rotateAndFetchTTS(
        ringPointers.eleven, eleven.keys, (key) => fetchElevenTTS(text, key, voiceId), 'ElevenLabs',
      );
      return new Response(response.body, {
        status : 200,
        headers: {
          'Content-Type' : 'audio/mpeg',
          'Cache-Control': 'public, max-age=3600',
          'X-TTS-Engine' : 'elevenlabs',
          'X-TTS-Voice'  : voiceId,
          'X-TTS-Lang'   : safeLang,
          'X-TTS-KeyIndex' : String(keyIndex),
          'X-TTS-KeysTried': String(keysTried),
          ...keyCountHeaders,
          ...getCorsHeaders(request),
        },
      });
    } catch (elErr) {
      console.error('[tts.js v5] ElevenLabs ring exhausted, trying Tier 2 (if applicable).', elErr.message);
    }
  }

  // TIER 2 — Deepgram Aura-2 ring, ENGLISH ONLY (v5)
  if (englishOnly && deepgram.keys.length > 0) {
    try {
      const { response, keyIndex, keysTried } = await rotateAndFetchTTS(
        ringPointers.deepgram, deepgram.keys, (key) => fetchDeepgramTTS(text, key), 'Deepgram',
      );
      return new Response(response.body, {
        status : 200,
        headers: {
          'Content-Type' : 'audio/mpeg',
          'Cache-Control': 'public, max-age=3600',
          'X-TTS-Engine' : 'deepgram',
          'X-TTS-Lang'   : safeLang,
          'X-TTS-KeyIndex' : String(keyIndex),
          'X-TTS-KeysTried': String(keysTried),
          ...keyCountHeaders,
          ...getCorsHeaders(request),
        },
      });
    } catch (dgErr) {
      console.error('[tts.js v5] Deepgram Aura ring exhausted, trying next tier.', dgErr.message);
    }
  }

  // OPT-IN TIER — Speechmatics TTS, ENGLISH ONLY, only if explicitly enabled (v5)
  if (englishOnly && speechmaticsEnabled && speechmatics.keys.length > 0) {
    try {
      const { response, keyIndex, keysTried } = await rotateAndFetchTTS(
        { i: 0 }, speechmatics.keys, (key) => fetchSpeechmaticsTTS(text, key), 'Speechmatics',
      );
      return new Response(response.body, {
        status : 200,
        headers: {
          'Content-Type' : 'audio/wav',
          'Cache-Control': 'public, max-age=3600',
          'X-TTS-Engine' : 'speechmatics',
          'X-TTS-Lang'   : safeLang,
          'X-TTS-KeyIndex' : String(keyIndex),
          'X-TTS-KeysTried': String(keysTried),
          ...keyCountHeaders,
          ...getCorsHeaders(request),
        },
      });
    } catch (smErr) {
      console.error('[tts.js v5] Speechmatics TTS also failed, falling back to gTTS.', smErr.message);
    }
  }

  // TIER 3 — Google Translate TTS (zero-setup fallback, all languages, not pooled)
  let gttsRes;
  try {
    gttsRes = await fetchGoogleTTS(text, safeLang);
  } catch (gttsErr) {
    console.error('[tts.js v5] gTTS also failed:', gttsErr.message);
    return new Response(
      JSON.stringify({ error: 'TTS service unreachable.' }),
      { status: 502, headers: { 'Content-Type': 'application/json', ...keyCountHeaders, ...getCorsHeaders(request) } },
    );
  }

  return new Response(gttsRes.body, {
    status : 200,
    headers: {
      'Content-Type' : 'audio/mpeg',
      'Cache-Control': 'public, max-age=3600',
      'X-TTS-Engine' : 'gtts',
      'X-TTS-Lang'   : safeLang,
      ...keyCountHeaders,
      ...getCorsHeaders(request),
    },
  });
}

// ── OPTIONS preflight ─────────────────────────────────────────────────────
export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}
