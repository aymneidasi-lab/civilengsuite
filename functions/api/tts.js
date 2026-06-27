/**
 * functions/api/tts.js  —  v2  (2026-06-27)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — TTS Proxy
 * Route:  GET /api/tts?text=...&lang=ar-EG[&voice=female|male]
 *
 * ── UPGRADE v1 → v2 ───────────────────────────────────────────────────────
 *
 * WHY v1 GOOGLE TTS SOUNDS ROBOTIC:
 *   Google Translate TTS (translate.google.com/translate_tts) uses a
 *   concatenative synthesis model — it stitches together pre-recorded
 *   phoneme segments. The result has no learned prosody, no coarticulation
 *   modelling, and no vowel reduction — all critical for natural Arabic.
 *
 * v2 SOLUTION — TWO-TIER ARCHITECTURE:
 *
 *   TIER 1 (optional, best quality): Azure Cognitive Services TTS
 *   ─────────────────────────────────────────────────────────────
 *   • Voices: ar-EG-SalmaNeural (female) / ar-EG-ShakirNeural (male)
 *   • True neural TTS: deep-learning acoustic model, correct Egyptian Arabic
 *     dialect phonology, natural prosody, coarticulation, vowel reduction.
 *   • HTTP REST (not WebSocket) → works from Cloudflare datacenter IPs.
 *     Note: Microsoft's public Edge TTS WebSocket endpoint (speech.platform
 *     .bing.com) returns 403 for cloud/datacenter IPs. Azure Cognitive
 *     Services is Microsoft's official API and has no IP restrictions.
 *   • Free tier: 500,000 characters / month (F0 plan) — zero cost for a
 *     civil-engineering chatbot volume.
 *   • SETUP: Add one secret to your Cloudflare Pages project:
 *       AZURE_TTS_KEY   = <your F0 subscription key>
 *       AZURE_TTS_REGION = <region, default: eastus>
 *                          Nearest for Egypt: uaenorth (Dubai, ~50ms RTT)
 *     Without these vars the function falls through to Tier 2 silently.
 *
 *   TIER 2 (zero-setup fallback): Google Translate TTS — improved
 *   ──────────────────────────────────────────────────────────────
 *   • Same stable endpoint as v1 (no key, no setup).
 *   • Improvements over v1:
 *       1. Arabic-Indic digit normalisation: ٣٠٠ → 300
 *          (GTts reads Western numerals more reliably for Arabic text)
 *       2. Persian digit normalisation: ۱۵۰ → 150
 *       3. Control character stripping
 *       4. Whitespace collapse
 *   • Quality: unchanged concatenative synthesis — better than Web Speech
 *     API but not neural. Tier 1 is the path to human-sounding Arabic.
 *
 * ── NEW QUERY PARAMS (v2) ─────────────────────────────────────────────────
 *   voice=female|male   Selects the neural voice gender (Tier 1 only).
 *                       Default: female (Salma / Jenny)
 *
 * ── RESPONSE HEADERS (new) ───────────────────────────────────────────────
 *   X-TTS-Engine : 'azure' | 'gtts'   — which engine served the request
 *   X-TTS-Voice  : voice name (Tier 1 only)
 *   X-TTS-Lang   : resolved language code
 *
 * ── ENV VARS ─────────────────────────────────────────────────────────────
 *   AZURE_TTS_KEY     required for Tier 1. Absent → silent Tier 2 fallback.
 *   AZURE_TTS_REGION  optional. Default: eastus. Use uaenorth for Egypt.
 *
 * ── HOW TO GET A FREE AZURE KEY ──────────────────────────────────────────
 *   1. portal.azure.com → Create resource → "Speech" → F0 (free) tier
 *   2. Copy "Key 1" from the resource's Keys and Endpoint blade
 *   3. Cloudflare Pages → your project → Settings → Environment variables
 *      → Add variable: AZURE_TTS_KEY = <key>, AZURE_TTS_REGION = uaenorth
 *   Total setup time: ~5 minutes, zero cost, 500k chars/month free.
 *
 * ── CSP NOTE ─────────────────────────────────────────────────────────────
 *   Audio plays from /api/tts (same origin). media-src 'self' is correct.
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

// ── Language allowlist & voice map ────────────────────────────────────────
const ALLOWED_LANGS = new Set([
  'ar', 'ar-EG', 'ar-SA', 'ar-MA', 'ar-JO', 'ar-DZ', 'ar-IQ',
  'en', 'en-US', 'en-GB', 'en-AU',
]);

const MAX_TEXT_LENGTH = 200;

/**
 * Azure Cognitive Services neural voice names per lang × gender.
 * Egyptian Arabic (ar-EG) is the primary dialect for this chatbot.
 * All other Arabic dialects fall back to ar-EG if voice not found.
 * Voice names match the Azure Speech Service voice catalogue (June 2026).
 */
const AZURE_VOICE_MAP = {
  'ar'    : { female: 'ar-EG-SalmaNeural',    male: 'ar-EG-ShakirNeural'   },
  'ar-EG' : { female: 'ar-EG-SalmaNeural',    male: 'ar-EG-ShakirNeural'   },
  'ar-SA' : { female: 'ar-SA-ZariyahNeural',  male: 'ar-SA-HamedNeural'    },
  'ar-MA' : { female: 'ar-MA-MounaNeural',    male: 'ar-MA-JamalNeural'    },
  'ar-JO' : { female: 'ar-JO-SanaNeural',     male: 'ar-JO-TaimNeural'     },
  'ar-DZ' : { female: 'ar-DZ-AminaNeural',    male: 'ar-DZ-IsmaelNeural'   },
  'ar-IQ' : { female: 'ar-IQ-RanaNeural',     male: 'ar-IQ-BasselNeural'   },
  'en'    : { female: 'en-US-JennyNeural',    male: 'en-US-GuyNeural'      },
  'en-US' : { female: 'en-US-JennyNeural',    male: 'en-US-GuyNeural'      },
  'en-GB' : { female: 'en-GB-SoniaNeural',    male: 'en-GB-RyanNeural'     },
  'en-AU' : { female: 'en-AU-NatashaNeural',  male: 'en-AU-WilliamNeural'  },
};

// ── Utilities ─────────────────────────────────────────────────────────────

/**
 * Preprocess Arabic text before sending to any TTS engine.
 *
 * 1. Strip ASCII control characters (null, BEL, DEL, etc.) — these can
 *    cause TTS engines to emit garbage audio or abort silently.
 * 2. Normalise Arabic-Indic numerals (٠–٩) to Western Arabic numerals
 *    (0–9). Google TTS and Azure TTS both read Western numerals more
 *    reliably in Arabic context (e.g. "٣٠٠ متر" → "300 متر" → "ثلاثمئة متر").
 * 3. Normalise Extended Arabic-Indic / Persian numerals (۰–۹) to Western.
 *    These appear in Farsi-influenced Arabic text and in some Arabic PDFs.
 * 4. Collapse multiple consecutive spaces or tabs to a single space.
 *    Run-on whitespace in engineering output (tables, alignment) confuses
 *    TTS prosody models and wastes the 200-char budget.
 */
function preprocessText(text) {
  return text
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ' ')      // strip control chars
    .replace(/[٠١٢٣٤٥٦٧٨٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d).toString())
    .replace(/[۰۱۲۳۴۵۶۷۸۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d).toString())
    .replace(/[ \t]+/g, ' ')
    .trim();
}

/** Escape XML special characters for SSML body text. */
function escapeXml(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// ── TIER 1 — Azure Cognitive Services TTS ─────────────────────────────────
/**
 * Calls Azure Cognitive Services Speech REST API to synthesise neural audio.
 *
 * Endpoint:  https://{region}.tts.speech.microsoft.com/cognitiveservices/v1
 * Auth:      Ocp-Apim-Subscription-Key header (F0 key from Azure portal)
 * Output:    audio-16khz-32kbitrate-mono-mp3 (good quality, ~2 KB/s)
 *
 * Prosody tuning:
 *   rate="-5%"  — 5% slower than the neural voice's natural cadence.
 *                 For Arabic engineering terms (فولاذ، خرسانة، ضغط) this
 *                 adds 40–60 ms per word — enough for clarity, undetectable
 *                 as "slowed" to the listener.
 *   pitch="0%"  — preserves the voice's learned Egyptian dialect intonation.
 *                 Do NOT adjust pitch: neural voices model intonation
 *                 patterns; shifting pitch decouples F0 from formants and
 *                 reintroduces a synthetic quality.
 *
 * On non-200 Azure response: throws, caller falls through to gTTS.
 *
 * @param {string} text        Pre-processed text (≤200 chars)
 * @param {string} voiceName   e.g. 'ar-EG-SalmaNeural'
 * @param {string} apiKey      Azure subscription key (F0 or S0)
 * @param {string} region      Azure region slug, e.g. 'eastus', 'uaenorth'
 * @returns {Promise<Response>} Resolved Response with audio/mpeg body
 */
async function fetchAzureTTS(text, voiceName, apiKey, region) {
  const lang = voiceName.slice(0, 5);   // 'ar-EG-SalmaNeural' → 'ar-EG'

  const ssml = [
    `<speak version='1.0' xmlns='http://www.w3.org/2001/10/synthesis' xml:lang='${lang}'>`,
    `<voice name='${voiceName}'>`,
    `<prosody rate='-5%' pitch='0%'>${escapeXml(text)}</prosody>`,
    `</voice>`,
    `</speak>`,
  ].join('');

  const endpoint = `https://${region}.tts.speech.microsoft.com/cognitiveservices/v1`;

  const azRes = await fetch(endpoint, {
    method : 'POST',
    headers: {
      'Ocp-Apim-Subscription-Key': apiKey,
      'Content-Type'             : 'application/ssml+xml',
      'X-Microsoft-OutputFormat' : 'audio-16khz-32kbitrate-mono-mp3',
      'User-Agent'               : 'civilengsuite-tts/2.0',
    },
    body: ssml,
  });

  if (!azRes.ok) {
    // Surface the Azure error code for operator diagnostics without leaking key.
    const body = await azRes.text().catch(() => '');
    throw new Error(
      `Azure TTS HTTP ${azRes.status}: ${body.slice(0, 120)}`,
    );
  }

  return azRes;    // caller streams .body
}

// ── TIER 2 — Google Translate TTS (fallback) ──────────────────────────────
/**
 * Unchanged stable endpoint from v1, plus text preprocessing improvements.
 *
 * client=tw-ob: The standard identifier used by Google's own Translate
 * widget and the gTTS library — verified stable since 2010.
 *
 * ttsspeed=1: Google TTS officially accepts 0 (slow) or 1 (normal).
 * Values between 0–1 are undocumented and unreliable across regions.
 * Clarity improvement is achieved via text preprocessing (digit
 * normalisation, whitespace collapse) rather than speed reduction.
 *
 * Cache: Cloudflare edge caches identical text+lang pairs for 1 hour.
 * Repeated phrases (greetings, product names, fixed engineering terms)
 * hit the cache and never reach Google.
 *
 * @param {string} text      Pre-processed text
 * @param {string} lang      Safe language code (from ALLOWED_LANGS)
 * @returns {Promise<Response>} Resolved Response with audio/mpeg body
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

  // 1. Preprocess & validate text
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

  // 2. Resolve safe lang + Azure voice
  const safeLang    = ALLOWED_LANGS.has(langParam) ? langParam : 'ar-EG';
  const genderKey   = voiceParam === 'male' ? 'male' : 'female';
  const voiceEntry  = AZURE_VOICE_MAP[safeLang] ?? AZURE_VOICE_MAP['ar-EG'];
  const azureVoice  = voiceEntry[genderKey];

  // 3. TIER 1 — Azure neural TTS (only if key is configured)
  const azureKey    = env?.AZURE_TTS_KEY?.trim()    || '';
  const azureRegion = (env?.AZURE_TTS_REGION?.trim() || 'eastus');

  if (azureKey) {
    try {
      const azRes = await fetchAzureTTS(text, azureVoice, azureKey, azureRegion);
      return new Response(azRes.body, {
        status : 200,
        headers: {
          'Content-Type' : 'audio/mpeg',
          'Cache-Control': 'public, max-age=3600',
          'X-TTS-Engine' : 'azure',
          'X-TTS-Voice'  : azureVoice,
          'X-TTS-Lang'   : safeLang,
          ...getCorsHeaders(request),
        },
      });
    } catch (azErr) {
      // Log for operator, silently fall through to gTTS.
      // Never leak the key or full Azure error to the client.
      console.error('[tts.js v2] Azure TTS failed, falling back to gTTS.', azErr.message);
    }
  }

  // 4. TIER 2 — Google Translate TTS (fallback / zero-setup path)
  let gttsRes;
  try {
    gttsRes = await fetchGoogleTTS(text, safeLang);
  } catch (gttsErr) {
    console.error('[tts.js v2] gTTS also failed:', gttsErr.message);
    return new Response(
      JSON.stringify({ error: 'TTS service unreachable.' }),
      {
        status : 502,
        headers: { 'Content-Type': 'application/json', ...getCorsHeaders(request) },
      },
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
