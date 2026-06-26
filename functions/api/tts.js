/**
 * functions/api/tts.js  —  v1  (2026-06-26)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — Google Translate TTS proxy
 * Route:  GET /api/tts?text=...&lang=ar-EG
 *
 * PURPOSE:
 *   Browser Web Speech API voices for Arabic are robotic and machine-like
 *   on most platforms. This function proxies Google Translate's TTS engine
 *   (the same engine powering translate.google.com's speaker icon) and returns
 *   the audio/mpeg binary to the client. The client plays it via HTMLAudioElement,
 *   giving users a natural, human-sounding Arabic voice with zero cost and no
 *   API key.
 *
 * DESIGN NOTES:
 *   • Google Translate TTS URL: https://translate.google.com/translate_tts
 *     Params: ie=UTF-8, client=tw-ob, tl={lang}, q={text}, ttsspeed=1
 *     'tw-ob' is the standard client string used by Google's own translate widget
 *     and the widely-used gTTS Python library (verified June 2026).
 *   • Text limit: 200 chars per request — callers (the HTML chatbot) pre-chunk.
 *   • No API key or registration. Google's public TTS endpoint is free and
 *     has been stable since 2010. Not guaranteed by Google but widely relied on.
 *   • Cloudflare edge caches identical text/lang pairs for 1 hour (cf.cacheEverything).
 *     Repeated phrases (greetings, product names) hit the cache, not Google.
 *   • CORS restricted to production domain and localhost dev.
 *   • Sanitised lang allowlist prevents header injection.
 *
 * ENV VARS: None required.
 *
 * CSP NOTE: The caller must have `media-src 'self'` in its Content-Security-Policy.
 *   (Change from `media-src 'none'` — see [[path]].js changelog [V2-TTS].)
 *   Audio plays from /api/tts (same origin), so 'self' is the correct directive.
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
// Explicit allowlist — prevents header injection via the lang parameter.
// ar-EG is the primary target (Egyptian dialect, matches the chatbot persona).
const ALLOWED_LANGS = new Set([
  'ar', 'ar-EG', 'ar-SA', 'ar-MA', 'ar-JO', 'ar-DZ', 'ar-IQ',
  'en', 'en-US', 'en-GB', 'en-AU',
]);
const MAX_TEXT_LENGTH = 200;

// ── GET handler ───────────────────────────────────────────────────────────
export async function onRequestGet(context) {
  const { request } = context;
  const url  = new URL(request.url);
  const text = (url.searchParams.get('text') || '').trim();
  const lang = (url.searchParams.get('lang') || 'ar-EG').trim();

  // 1. Input validation
  if (!text) {
    return new Response(JSON.stringify({ error: 'Missing text parameter.' }), {
      status : 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(request) },
    });
  }
  if (text.length > MAX_TEXT_LENGTH) {
    return new Response(
      JSON.stringify({ error: `Text exceeds ${MAX_TEXT_LENGTH} char limit. Pre-chunk before calling.` }),
      { status: 400, headers: { 'Content-Type': 'application/json', ...getCorsHeaders(request) } },
    );
  }

  const safeLang = ALLOWED_LANGS.has(lang) ? lang : 'ar-EG';

  // 2. Build Google Translate TTS URL
  // ttsspeed=1 = normal speed (0 = slow mode).
  // ie=UTF-8   = input encoding.
  // client=tw-ob is the standard identifier used by Google's own Translate
  // widget and the gTTS library (github.com/pndurette/gTTS).
  const gttsUrl = new URL('https://translate.google.com/translate_tts');
  gttsUrl.searchParams.set('ie',       'UTF-8');
  gttsUrl.searchParams.set('client',   'tw-ob');
  gttsUrl.searchParams.set('tl',       safeLang);
  gttsUrl.searchParams.set('q',        text);
  gttsUrl.searchParams.set('ttsspeed', '1');

  // 3. Proxy fetch — mimic a browser to satisfy Google's endpoint
  let gttsRes;
  try {
    gttsRes = await fetch(gttsUrl.toString(), {
      headers: {
        'Referer'   : 'https://translate.google.com/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
                      'AppleWebKit/537.36 (KHTML, like Gecko) ' +
                      'Chrome/125.0.0.0 Safari/537.36',
      },
      // Let Cloudflare's edge cache the upstream response so identical
      // text+lang pairs don't hit Google on every request.
      cf: { cacheEverything: true, cacheTtl: 3600 },
    });
  } catch (err) {
    console.error('[tts.js] Network error fetching Google TTS:', err.message);
    return new Response(JSON.stringify({ error: 'TTS service unreachable.' }), {
      status : 502,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(request) },
    });
  }

  if (!gttsRes.ok) {
    console.error('[tts.js] Google TTS returned', gttsRes.status, 'for lang:', safeLang);
    return new Response(
      JSON.stringify({ error: `TTS upstream HTTP ${gttsRes.status}.` }),
      { status: 502, headers: { 'Content-Type': 'application/json', ...getCorsHeaders(request) } },
    );
  }

  // 4. Stream audio back to the client
  return new Response(gttsRes.body, {
    status : 200,
    headers: {
      'Content-Type' : 'audio/mpeg',
      'Cache-Control': 'public, max-age=3600',
      'X-TTS-Lang'   : safeLang,
      ...getCorsHeaders(request),
    },
  });
}

// ── OPTIONS preflight ─────────────────────────────────────────────────────
export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}
