/**
 * functions/api/tts.js  —  v3  (2026-06-27)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — TTS Proxy
 * Route:  GET /api/tts?text=...&lang=ar-EG[&voice=female|male]
 *
 * ── UPGRADE v2 → v3: Azure replaced by ElevenLabs ────────────────────────
 *
 * WHY ELEVENLABS INSTEAD OF AZURE:
 *   Both provide neural Arabic voices of identical quality.
 *   ElevenLabs advantages:
 *     • Sign-up at elevenlabs.io — no credit card, no portal complexity.
 *     • 10,000 characters/month free (personal use). For an engineering
 *       chatbot serving repeated queries, Cloudflare's 1-hour edge cache
 *       means the effective unique-char count is a fraction of real traffic.
 *     • Single global HTTP endpoint — no region configuration.
 *     • xi-api-key header auth — one env var, no subscription management.
 *
 * ── ARCHITECTURE ──────────────────────────────────────────────────────────
 *
 *   TIER 1  ElevenLabs — eleven_multilingual_v2 neural voice
 *   ─────────────────────────────────────────────────────────
 *   Endpoint : POST https://api.elevenlabs.io/v1/text-to-speech/{voice_id}
 *   Auth     : xi-api-key header (free account key from elevenlabs.io)
 *   Model    : eleven_multilingual_v2 — best quality for Arabic narration
 *   Output   : mp3_44100_128 (128 kbps, 44.1 kHz — near-transparent quality)
 *   Voices   : Bella (female) / Adam (male) — stable pre-made multilingual
 *              voices available on every plan including free.
 *              Override anytime via ELEVEN_VOICE_ID_F / ELEVEN_VOICE_ID_M.
 *
 *   Voice settings tuned for Arabic engineering content:
 *     stability=0.75        → consistent pronunciation, no random variation
 *     similarity_boost=0.85 → stays close to voice character
 *     style=0               → no emotional exaggeration (professional tone)
 *     use_speaker_boost     → applies ElevenLabs post-processing for clarity
 *
 *   TIER 2  Google Translate TTS — zero-setup fallback
 *   ───────────────────────────────────────────────────
 *   Identical to v2. Activated when ELEVEN_API_KEY is absent or Tier 1 fails.
 *   Text preprocessing (digit normalisation, whitespace) still applied.
 *
 * ── SETUP (5 minutes, no credit card) ────────────────────────────────────
 *   1. Go to  elevenlabs.io  →  sign up with email + password
 *   2. Profile → API Keys → Generate API Key → copy it
 *   3. Cloudflare Pages → your project → Settings → Environment variables
 *      Add:  ELEVEN_API_KEY = <paste key>   (mark as Secret)
 *   Done. X-TTS-Engine: elevenlabs in the response confirms Tier 1 is live.
 *
 *   Optional voice override (browse voices at elevenlabs.io/voice-library):
 *      ELEVEN_VOICE_ID_F = <voice_id>   (female voice, default: Bella)
 *      ELEVEN_VOICE_ID_M = <voice_id>   (male voice,   default: Adam)
 *
 * ── NEW QUERY PARAMS ─────────────────────────────────────────────────────
 *   voice=female|male   Selects gender voice (Tier 1 only). Default: female.
 *
 * ── RESPONSE HEADERS ─────────────────────────────────────────────────────
 *   X-TTS-Engine  : 'elevenlabs' | 'gtts'
 *   X-TTS-Voice   : voice_id used (Tier 1 only)
 *   X-TTS-Lang    : resolved language code
 *
 * ── ENV VARS ─────────────────────────────────────────────────────────────
 *   ELEVEN_API_KEY     Required for Tier 1. Absent → silent Tier 2 fallback.
 *   ELEVEN_VOICE_ID_F  Optional. Female voice ID. Default: EXAVITQu4vr4xnSDxMaL
 *   ELEVEN_VOICE_ID_M  Optional. Male voice ID.   Default: pNInz6obpgDQGcFmaJgB
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

// ── ElevenLabs constants ──────────────────────────────────────────────────
const ELEVEN_API_URL    = 'https://api.elevenlabs.io/v1/text-to-speech';
const ELEVEN_MODEL      = 'eleven_multilingual_v2';
const ELEVEN_OUT_FORMAT = 'mp3_44100_128';           // 128 kbps, 44.1 kHz

// Default pre-made voices — available on free tier, stable multilingual.
// Browse alternatives at elevenlabs.io/voice-library, then set env vars.
const ELEVEN_DEFAULT_F = 'EXAVITQu4vr4xnSDxMaL';   // Bella (female)
const ELEVEN_DEFAULT_M = 'pNInz6obpgDQGcFmaJgB';   // Adam  (male)

// ── Utilities ─────────────────────────────────────────────────────────────

/**
 * Preprocess Arabic text before sending to any TTS engine.
 *
 * 1. Strip ASCII control chars (null, BEL, DEL…) — TTS engines silently
 *    abort or emit garbage audio on hidden control characters.
 * 2. Normalise Arabic-Indic numerals ٠١٢٣٤٥٦٧٨٩ → 0-9.
 *    Both ElevenLabs multilingual_v2 and Google TTS read Western Arabic
 *    numerals more reliably in Arabic context. Engineering output from
 *    the chatbot frequently contains values like "٣٠٠ كيلونيوتن".
 * 3. Normalise Extended Arabic-Indic / Persian digits ۰-۹ → 0-9.
 *    These appear in Farsi-influenced Arabic text and some technical PDFs.
 * 4. Collapse runs of whitespace → single space.
 *    Alignment padding and table formatting in engineering responses
 *    wastes the 200-char budget and disrupts TTS prosody models.
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

// ── TIER 1 — ElevenLabs neural TTS ───────────────────────────────────────
/**
 * Calls ElevenLabs REST TTS API and returns the audio Response.
 *
 * Model: eleven_multilingual_v2
 *   Selected over eleven_flash_v2_5 (lower-latency option) because:
 *   - Chatbot TTS is not real-time conversation; 1-2 s latency is fine.
 *   - multilingual_v2 has higher overall naturalness for Arabic narration.
 *   - Flash is recommended for streaming agent pipelines, not one-shot audio.
 *
 * Voice settings rationale (for Arabic engineering narration):
 *   stability=0.75       Consistent articulation across engineering terms.
 *                        Lower values introduce prosodic variation that suits
 *                        storytelling but sounds inconsistent in factual TTS.
 *   similarity_boost=0.85 Keeps voice character without overfitting to the
 *                         reference, which can introduce artefacts on Arabic.
 *   style=0              Zero style exaggeration. Neutral professional tone
 *                        matching civil-engineering chatbot persona.
 *   use_speaker_boost    ElevenLabs post-processing filter — reduces noise
 *                        and improves high-frequency clarity. Always enable.
 *
 * output_format=mp3_44100_128:
 *   128 kbps at 44.1 kHz is perceptually transparent for speech. This is
 *   the highest quality format available on the free plan without streaming.
 *
 * @param {string} text     Pre-processed Arabic text (≤200 chars)
 * @param {string} apiKey   ElevenLabs API key (xi-api-key)
 * @param {string} voiceId  ElevenLabs voice ID
 * @returns {Promise<Response>} Audio response with Content-Type audio/mpeg
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
    // Map ElevenLabs status codes to operator-useful log messages.
    // Never forward the raw ElevenLabs error body to the client (may leak key context).
    const hint =
      elRes.status === 401 ? 'invalid or missing ELEVEN_API_KEY'   :
      elRes.status === 422 ? 'invalid voice_id — check ELEVEN_VOICE_ID_F/M' :
      elRes.status === 429 ? 'monthly quota exceeded (10k chars free tier)' :
      `HTTP ${elRes.status}`;
    throw new Error(`ElevenLabs TTS: ${hint}`);
  }

  return elRes;   // caller streams .body directly to client
}

// ── TIER 2 — Google Translate TTS (fallback) ──────────────────────────────
/**
 * Unchanged stable endpoint from v1/v2.
 *
 * client=tw-ob: Standard Google Translate widget client — verified stable
 * since 2010, used by the gTTS library (github.com/pndurette/gTTS).
 * ttsspeed=1: Official values are 0 (slow) or 1 (normal). Intermediate float
 * values are undocumented and unreliable across regions; do not change.
 *
 * Cache: identical text+lang pairs are served from Cloudflare's edge for
 * 1 hour (cf.cacheEverything + cacheTtl). Repeated engineering phrases
 * (formulas, definitions) do not hit Google at all after the first request.
 *
 * @param {string} text  Pre-processed text
 * @param {string} lang  Safe language code (from ALLOWED_LANGS)
 * @returns {Promise<Response>}
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

  // 1. Pre-process + validate
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

  // 2. Resolve safe lang + voice
  const safeLang   = ALLOWED_LANGS.has(langParam) ? langParam : 'ar-EG';
  const genderKey  = voiceParam === 'male' ? 'male' : 'female';
  const voiceId    = resolveVoiceId(genderKey, env);
  const elevenKey  = env?.ELEVEN_API_KEY?.trim() || '';

  // 3. TIER 1 — ElevenLabs (only when key is configured)
  if (elevenKey) {
    try {
      const elRes = await fetchElevenTTS(text, elevenKey, voiceId);
      return new Response(elRes.body, {
        status : 200,
        headers: {
          'Content-Type' : 'audio/mpeg',
          'Cache-Control': 'public, max-age=3600',
          'X-TTS-Engine' : 'elevenlabs',
          'X-TTS-Voice'  : voiceId,
          'X-TTS-Lang'   : safeLang,
          ...getCorsHeaders(request),
        },
      });
    } catch (elErr) {
      // Log for operator; never expose key or ElevenLabs detail to client.
      console.error('[tts.js v3] ElevenLabs failed, falling back to gTTS.', elErr.message);
    }
  }

  // 4. TIER 2 — Google Translate TTS (zero-setup fallback)
  let gttsRes;
  try {
    gttsRes = await fetchGoogleTTS(text, safeLang);
  } catch (gttsErr) {
    console.error('[tts.js v3] gTTS also failed:', gttsErr.message);
    return new Response(
      JSON.stringify({ error: 'TTS service unreachable.' }),
      { status: 502, headers: { 'Content-Type': 'application/json', ...getCorsHeaders(request) } },
    );
  }

  return new Response(gttsRes.body, {
    status : 200,
    headers: {
      'Content-Type' : 'audio/mpeg',
      'Cache-Control': 'public, max-age=3600',
      'X-TTS-Engine' : 'gtts',
      'X-TTS-Lang'   : safeLang,
      ...getCorsHeaders(request),
    },
  });
}

// ── OPTIONS preflight ─────────────────────────────────────────────────────
export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}
