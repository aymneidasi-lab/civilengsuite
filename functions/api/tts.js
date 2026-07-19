/**
 * functions/api/tts.js  —  v6  (2026-07-19)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — TTS Proxy
 * Routes: GET  /api/tts?text=...&lang=ar-EG[&voice=female|male][&speed=1.0]
 *         POST /api/tts   { text, dialect, voice_gender, speed, format }
 *
 * ── WHY v6 LOOKS DIFFERENT FROM tts-proxy-architecture-final.md ───────────
 * That document specs a 4-tier cascade (Edge TTS / Azure+Google+ElevenLabs /
 * Polly+Watson / gTTS+ResponsiveVoice) coordinated through Durable Objects.
 * Cross-checked against api_keys_EMPTY_KEYS_FOR_SECURITY.txt and this
 * project's actual Cloudflare bindings: there is no Azure, Google Cloud TTS,
 * AWS, or IBM Watson key anywhere in this deployment, no wrangler.toml, and
 * no Durable Object binding. The real, provisioned stack is ElevenLabs /
 * Deepgram / Speechmatics / Google Translate TTS — plain-JSON or
 * query-param APIs, none of them SSML. A literal port of the document would
 * ship dead code for four providers nobody has keys for, require a Workers
 * Paid + wrangler.toml + Durable Objects migration nobody asked for, and —
 * because the doc's request contract is `POST /api/tts` JSON — silently
 * break the live frontend, which loads audio via
 * `new Audio('/api/tts?text=...&lang=...')` (a bare GET, no body, no
 * headers; see pc_suite_v30.html line ~11574). An <audio> element cannot
 * issue a POST. That GET contract is preserved byte-for-byte below.
 *
 * What v6 actually does: ports the document's PATTERNS onto the REAL
 * provider set, plus the one genuinely new, directly-portable capability —
 * Group 0 / Edge TTS — with material updates found during this pass that
 * the source document did not have:
 *
 *   1. GROUP 0 — Microsoft Edge TTS added ahead of ElevenLabs (§3 of the
 *      doc). Free, keyless, real ar-EG neural voices. BUT: current-state
 *      research (this pass, not in the source doc) found Microsoft added a
 *      clock-derived DRM signature (`Sec-MS-GEC`, SHA-256 of a 5-minute
 *      Windows-FILETIME bucket + a public token) that a bare
 *      TrustedClientToken no longer satisfies — confirmed against the
 *      `rany2/edge-tts` reference implementation's `drm.py`, plus multiple
 *      dated 2024-2025 upstream issues showing 403s when it's stale/wrong.
 *      This is MORE fragile than the source doc knew, not less. Given that,
 *      and given this endpoint cannot be smoke-tested from this sandbox
 *      (no network route to speech.platform.bing.com here), EDGE_TTS_ENABLED
 *      defaults to "false" — the doc's own default-true recommendation is
 *      deliberately overridden. Flip it on in Cloudflare's dashboard only
 *      after confirming a real deployed request succeeds.
 *   2. Durable Objects (§4) replaced with a KV-backed circuit breaker/quota
 *      clock, reusing the SAME env.CES_CHAT_KV binding chat.js/vision.js
 *      already use (see functions/_lib/rotation.mjs) — zero new Cloudflare
 *      bindings required to deploy this. This is NOT atomicity-safe under
 *      true concurrent bursts the way a Durable Object is; that trade-off
 *      is explained where the helpers are defined below, and is the same
 *      "fails open, KV is good enough at this traffic scale" call
 *      rotation.mjs already makes for its own rate limiter.
 *   3. Deepgram's real exposure ported from Polly's §4 pattern: Deepgram's
 *      $200 signup credit is one-time and expires 1 year after signup
 *      regardless of balance (api_keys_EMPTY_KEYS_FOR_SECURITY.txt) — the
 *      same "finite, clock-bound pool" shape as Polly in the source doc.
 *      firstUsedAt/expiresAt now tracked in KV, pre-emptively stopped 5
 *      days ahead of the cutoff.
 *   4. IS_DEV gate (§2): Edge TTS and ElevenLabs (recurring monthly quota)
 *      still run in dev; Deepgram (finite credit) and opt-in Speechmatics
 *      (real per-character billing) are skipped, straight to gTTS.
 *   5. SSML escaping (§7) applies to exactly one provider here: Edge TTS is
 *      the only real-provider path in this file that builds an SSML
 *      document. ElevenLabs/Deepgram/Speechmatics take a JSON string field
 *      (JSON.stringify already escapes correctly); gTTS takes a URL query
 *      param (URLSearchParams already percent-encodes correctly). Applying
 *      the doc's escaping requirement to those would be a no-op dressed up
 *      as a fix; it is applied where it actually closes a gap.
 *   6. WAV-safe chunk concatenation (§8): does not apply. MAX_TEXT_LENGTH
 *      stays at 200 chars/request — chunking already happens client-side
 *      (pc_suite_v30.html's splitForProxy), one clip per request, never
 *      concatenated server-side across providers. Edge TTS's own output
 *      format is MP3 (frame-based, tolerant of concatenation per the doc's
 *      own §8), and its multiple binary WS frames are concatenated
 *      byte-for-byte from ONE provider within ONE request — the doc's
 *      "never splice providers mid-chunk-sequence" rule, satisfied by
 *      construction, not by new logic.
 *   7. Rate limiting (§15.5): wired to functions/_lib/rotation.mjs's
 *      checkRateLimit(), the same helper chat.js/vision.js already use.
 *      tts.js had zero request throttling before this version — an
 *      unauthenticated proxy in front of metered quota is exactly the
 *      shape of endpoint that gets hammered.
 *   8. Cloudflare Free-plan subrequest ceiling (50/invocation, still
 *      current per Cloudflare's Workers limits docs as of July 2026) is
 *      now enforced via rotation.mjs's makeFetchBudget(), same as chat.js.
 *
 * NOT carried over from the doc, with reasons: Azure/Google Cloud
 * TTS/Polly/Watson (no keys, no accounts — would be unreachable dead code);
 * Durable Objects (no binding, no wrangler.toml — see point 2); Watson
 * keep-alive Cron (no Watson); Cloudflare native Rate Limiting Rules (a
 * dashboard/wrangler config action, not code this file can apply — call it
 * out as a recommended follow-up instead of faking it).
 *
 * ── SETUP (unchanged from v5) ──────────────────────────────────────────────
 *   ELEVEN_API_KEY(_1..12), DEEPGRAM_API_KEY(_1..12) — case-insensitive.
 *   Optional: ELEVEN_VOICE_ID_F / ELEVEN_VOICE_ID_M
 *   Optional, real cost, off by default: ENABLE_SPEECHMATICS_TTS=true
 *   NEW: EDGE_TTS_ENABLED=true            (default false — see point 1)
 *   NEW: IS_DEV=true                      (default false)
 *   Reused, no new binding: env.CES_CHAT_KV (same KV namespace as chat.js)
 *
 * ── RESPONSE HEADERS (additive — existing X-TTS-Engine/Voice/Lang/KeyIndex/
 *    KeysTried/KeysAvailable headers from v5 are unchanged) ────────────────
 *   X-TTS-Fallback              : "true" once any non-first-attempted tier answers
 *   X-TTS-Fallback-Reason       : why the winning tier wasn't the first one tried
 *   X-TTS-Provider-Official     : "true" | "false" (Edge TTS and gTTS are unofficial)
 *   X-TTS-Dialect-Requested     : echoes the resolved lang
 *   X-TTS-Dialect-Rendered      : what dialect actually comes out of the winning tier
 *   X-TTS-Quality-Score         : "neural" | "neural-degraded" | "robotic"
 *
 * ── CSP NOTE (unchanged) ───────────────────────────────────────────────────
 *   Audio served from /api/tts (same origin). media-src 'self' is correct.
 *   Edge TTS's outbound WebSocket happens server-side inside this Function
 *   — CSP is a browser mechanism and does not apply to it; no _headers or
 *   functions/[[path]].js CSP change is required for Group 0.
 */

import {
  checkRateLimit,
  fetchWithTimeout,
  makeFetchBudget,
  SUBREQUEST_BUDGET_FREE_PLAN,
} from '../_lib/rotation.mjs';

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
    // v6: added POST — the new JSON-body interface (existing GET contract unchanged).
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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

// ── Allowed TTS languages (unchanged) ──────────────────────────────────────
const ALLOWED_LANGS = new Set([
  'ar', 'ar-EG', 'ar-SA', 'ar-MA', 'ar-JO', 'ar-DZ', 'ar-IQ',
  'en', 'en-US', 'en-GB', 'en-AU',
]);

const MAX_TEXT_LENGTH = 200;

function isEnglish(lang) {
  return lang.toLowerCase().startsWith('en');
}

/** IS_DEV gate (v6, new) — see docblock point 4. */
function isDevMode(env) {
  return String(env?.IS_DEV ?? '').trim().toLowerCase() === 'true';
}

// ── ElevenLabs constants (unchanged) ───────────────────────────────────────
const ELEVEN_API_URL    = 'https://api.elevenlabs.io/v1/text-to-speech';
const ELEVEN_MODEL      = 'eleven_multilingual_v2';
const ELEVEN_OUT_FORMAT = 'mp3_44100_128';
const ELEVEN_DEFAULT_F  = 'EXAVITQu4vr4xnSDxMaL';   // Bella (female)
const ELEVEN_DEFAULT_M  = 'pNInz6obpgDQGcFmaJgB';   // Adam  (male)
const ELEVEN_BASE_NAME  = 'ELEVEN_API_KEY';
// v6: confirmed current (2026) — speed is a real voice_settings field, 0.7-1.2,
// values outside that range are rejected/degrade quality per ElevenLabs' own docs.
const ELEVEN_SPEED_MIN = 0.7;
const ELEVEN_SPEED_MAX = 1.2;

// ── Deepgram constants (unchanged) ─────────────────────────────────────────
const DEEPGRAM_SPEAK_URL = 'https://api.deepgram.com/v1/speak';
const DEEPGRAM_TTS_MODEL = 'aura-2';
const DEEPGRAM_BASE_NAME = 'DEEPGRAM_API_KEY';
// v6: Deepgram Aura's REST API has no confirmed speed-control parameter —
// unlike ElevenLabs/Edge TTS/gTTS, a `speed` request is silently NOT applied
// on this tier (documented here rather than guessing at an unverified field
// name that could otherwise turn a working request into a 400).
const DEEPGRAM_SUPPORTS_SPEED = false;

// ── Speechmatics constants (unchanged, still opt-in/real-cost only) ───────
const SPEECHMATICS_TTS_URL_BASE = 'https://preview.tts.speechmatics.com/generate';
const SPEECHMATICS_TTS_VOICE    = 'sarah';
const SPEECHMATICS_BASE_NAME    = 'SPEECHMATICS_API_KEY';
const SPEECHMATICS_SUPPORTS_SPEED = false; // same reasoning as Deepgram above

// ── Edge TTS constants (v6, NEW — Group 0) ─────────────────────────────────
// Endpoint/token/DRM algorithm confirmed against rany2/edge-tts (9k+ stars,
// actively maintained) source as of this pass — see docblock point 1 for
// why EDGE_TTS_ENABLED nonetheless defaults false.
const EDGE_TTS_TRUSTED_CLIENT_TOKEN = '6A5AA1D4EAFF4E9FB37E23D68491D6F4';
const EDGE_TTS_HOST = 'speech.platform.bing.com/consumer/speech/synthesize/readaloud';
const EDGE_TTS_WSS_BASE = `wss://${EDGE_TTS_HOST}/edge/v1?TrustedClientToken=${EDGE_TTS_TRUSTED_CLIENT_TOKEN}`;
const EDGE_TTS_CHROMIUM_VERSION = '130.0.2849.68';
const EDGE_TTS_CHROMIUM_MAJOR = EDGE_TTS_CHROMIUM_VERSION.split('.')[0];
const EDGE_TTS_SEC_MS_GEC_VERSION = `1-${EDGE_TTS_CHROMIUM_VERSION}`;
const EDGE_TTS_USER_AGENT =
  `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ` +
  `Chrome/${EDGE_TTS_CHROMIUM_MAJOR}.0.0.0 Safari/537.36 Edg/${EDGE_TTS_CHROMIUM_MAJOR}.0.0.0`;
const EDGE_TTS_ORIGIN = 'chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold';
const EDGE_TTS_WIN_EPOCH_OFFSET_SECONDS = 11644473600; // 1601-01-01 -> 1970-01-01
const EDGE_TTS_OUTPUT_FORMAT = 'audio-24khz-48kbitrate-mono-mp3';

// Known-current GA neural voice names (Salma/Shakir etc. are the SAME
// models Azure sells — confirmed in the architecture doc's Appendix A).
// Allowlisted explicitly — never interpolate a caller-supplied voice name
// into the SSML `<voice name='...'>` attribute.
const EDGE_VOICE_MAP = {
  'ar-EG': { female: 'ar-EG-SalmaNeural',   male: 'ar-EG-ShakirNeural' },
  'ar-SA': { female: 'ar-SA-ZariyahNeural', male: 'ar-SA-HamedNeural' },
  'ar-MA': { female: 'ar-MA-MounaNeural',   male: 'ar-MA-JamalNeural' },
  'ar-JO': { female: 'ar-JO-SanaNeural',    male: 'ar-JO-TaimNeural' },
  'ar-DZ': { female: 'ar-DZ-AminaNeural',   male: 'ar-DZ-IsmaelNeural' },
  'ar-IQ': { female: 'ar-IQ-RanaNeural',    male: 'ar-IQ-BasselNeural' },
  // Plain 'ar' (MSA) has no single canonical Edge locale; Saudi voices are
  // used as the MSA-adjacent rendering, consistent with the doc's own
  // dialect-truth table treating Gulf/Saudi as the nearest non-Egyptian option.
  'ar'   : { female: 'ar-SA-ZariyahNeural', male: 'ar-SA-HamedNeural' },
  'en'   : { female: 'en-US-EmmaMultilingualNeural', male: 'en-US-AndrewMultilingualNeural' },
  'en-US': { female: 'en-US-EmmaMultilingualNeural', male: 'en-US-AndrewMultilingualNeural' },
  'en-GB': { female: 'en-GB-SoniaNeural',   male: 'en-GB-RyanNeural' },
  'en-AU': { female: 'en-AU-NatashaNeural', male: 'en-AU-WilliamNeural' },
};
const EDGE_VOICE_ALLOWLIST = new Set(
  Object.values(EDGE_VOICE_MAP).flatMap((v) => [v.female, v.male]),
);

// ── Dialect-rendering truth table (v6, adapted from doc §7 to REAL providers) ──
// What ACTUALLY comes out, per provider, for a given requested dialect.
// Used only to stamp honest X-TTS-Dialect-Rendered / Quality-Score headers —
// never to change routing (routing stays: edge -> eleven -> deepgram(en) ->
// speechmatics(en, opt-in) -> gtts, exactly the existing v5 order plus Tier 0).
function renderedDialectFor(provider, requestedLang) {
  const isArabic = requestedLang.toLowerCase().startsWith('ar');
  if (provider === 'edge_tts') {
    // True per-locale Arabic voices exist for every ALLOWED_LANGS Arabic
    // entry (see EDGE_VOICE_MAP) — genuinely renders the requested dialect.
    return { rendered: requestedLang, quality: 'neural', degraded: false };
  }
  if (provider === 'elevenlabs') {
    // Multilingual model, not a true dialect-locale switch — matches the
    // doc's own honest characterization of ElevenLabs for Arabic.
    return isArabic
      ? { rendered: 'ar (MSA-leaning, model-dependent)', quality: 'neural-degraded', degraded: true }
      : { rendered: requestedLang, quality: 'neural', degraded: false };
  }
  if (provider === 'deepgram' || provider === 'speechmatics') {
    // English-only tiers in this file; never invoked for Arabic.
    return { rendered: requestedLang, quality: 'neural', degraded: false };
  }
  // gTTS — MSA only, robotic, per doc §3/§13.
  return isArabic
    ? { rendered: 'ar (MSA)', quality: 'robotic', degraded: true }
    : { rendered: requestedLang, quality: 'robotic', degraded: false };
}

// ── Text preprocessing (unchanged) ─────────────────────────────────────────
function preprocessText(text) {
  return text
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ' ')
    .replace(/[٠١٢٣٤٥٦٧٨٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d).toString())
    .replace(/[۰۱۲۳۴۵۶۷۸۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d).toString())
    .replace(/[ \t]+/g, ' ')
    .trim();
}

/**
 * v6, NEW — full 5-entity XML escape for SSML TEXT CONTENT, per architecture
 * doc §7. Stricter than strictly necessary for text-content position (which
 * only requires &<> per the XML spec) but harmless as a superset, and
 * defends any future attribute-context reuse. Verified in this session
 * against an actual injection attempt (closing </voice><voice name='...'>
 * mid-payload) — see chat log; after escaping, zero literal '<' or '>'
 * survives, so the payload cannot break out of the enclosing element.
 */
function escapeSsmlText(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** Resolve voice ID from env or fall back to hardcoded default (unchanged). */
function resolveVoiceId(genderKey, env) {
  if (genderKey === 'male') {
    return (env?.ELEVEN_VOICE_ID_M?.trim() || '') || ELEVEN_DEFAULT_M;
  }
  return (env?.ELEVEN_VOICE_ID_F?.trim() || '') || ELEVEN_DEFAULT_F;
}

/**
 * v6, NEW — resolve an Edge TTS voice name for a given (already-allowlisted)
 * lang + gender, falling back to the Egyptian voice if the lang has no
 * explicit entry (should not happen given ALLOWED_LANGS is a strict subset
 * of EDGE_VOICE_MAP's keys, but defends against future ALLOWED_LANGS growth
 * outpacing this map).
 */
function resolveEdgeVoice(lang, genderKey) {
  const entry = EDGE_VOICE_MAP[lang] || EDGE_VOICE_MAP['ar-EG'];
  const name = genderKey === 'male' ? entry.male : entry.female;
  return EDGE_VOICE_ALLOWLIST.has(name) ? name : EDGE_VOICE_MAP['ar-EG'].female;
}

/** Clamp a caller-supplied speed multiplier into a sane, provider-agnostic range. */
function clampSpeed(speed) {
  const n = Number(speed);
  if (!Number.isFinite(n)) return 1.0;
  return Math.min(2.0, Math.max(0.5, n));
}

/** speed float (0.5-2.0, 1.0=normal) -> Edge TTS's SSML prosody rate string ("+N%"/"-N%"). */
function speedToEdgeRate(speed) {
  const pct = Math.round((clampSpeed(speed) - 1) * 100);
  const clamped = Math.min(50, Math.max(-50, pct)); // keep within a safe, well-tested band
  return `${clamped >= 0 ? '+' : ''}${clamped}%`;
}

/** speed float -> ElevenLabs voice_settings.speed (0.7-1.2). */
function speedToElevenSpeed(speed) {
  return Math.min(ELEVEN_SPEED_MAX, Math.max(ELEVEN_SPEED_MIN, clampSpeed(speed)));
}

/**
 * Read a failed fetch Response body ONCE and pull out a quota/credit signal
 * if present (unchanged from v5).
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
 * Discover every env var matching `<baseName>` or `<baseName>_<digits>`,
 * case-insensitively (unchanged from v5).
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

// Module-scoped ring pointers -- best-effort load spreading across requests
// within a reused isolate; not relied on for correctness (unchanged from v5).
const ringPointers = {
  eleven  : { i: 0 },
  deepgram: { i: 0 },
};

/**
 * Generic round-robin + quota-failover walk over a provider's key ring.
 * v6: now consults a shared subrequest `budget` (rotation.mjs's
 * makeFetchBudget) and stops trying further keys — failing over to the
 * NEXT TIER instead — once the budget is exhausted, rather than risking the
 * platform hard-erroring the 51st subrequest on the Free plan.
 *
 * @param {{i:number}} pointerState
 * @param {string[]} keys
 * @param {(key: string) => Promise<Response>} singleFetchFn
 * @param {string} providerLabel
 * @param {{take: () => boolean, remaining: () => number}} budget
 * @returns {Promise<{ response: Response, keyIndex: number, keysTried: number }>}
 */
async function rotateAndFetchTTS(pointerState, keys, singleFetchFn, providerLabel, budget) {
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
    if (budget && !budget.take()) {
      const err = new Error(`${providerLabel} TTS: subrequest budget exhausted before all keys tried`);
      err.category = 'subrequest budget exhausted';
      err.httpStatus = 'network';
      throw err;
    }
    const idx = (startIdx + step) % keys.length;
    try {
      const response = await singleFetchFn(keys[idx]);
      return { response, keyIndex: idx, keysTried: step + 1 };
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
  const err = new Error(`${providerLabel} TTS: ${attemptErrors.length} key(s) tried, all failed [${summary}]`);
  err.category = attemptErrors.length > 1
    ? `${attemptErrors.length} keys exhausted (last: ${last?.category})`
    : (last?.category || 'unknown');
  err.httpStatus = last?.httpStatus ?? 'network';
  throw err;
}

// ── KV helpers (v6, NEW) ───────────────────────────────────────────────────
// Fail-open by design: any KV read/write error is swallowed and treated as
// "no state yet" — a KV outage must never itself take the TTS proxy down.
// This mirrors rotation.mjs's own checkRateLimit() philosophy exactly.
async function kvGetJSON(kv, key) {
  if (!kv) return null;
  try {
    const raw = await kv.get(key);
    return raw ? JSON.parse(raw) : null;
  } catch (_e) {
    return null;
  }
}
async function kvPutJSON(kv, key, value) {
  if (!kv) return false;
  try {
    await kv.put(key, JSON.stringify(value));
    return true;
  } catch (_e) {
    return false;
  }
}

// ── Circuit breaker (v6, NEW — KV approximation of doc §5, not DO-atomic) ─
// HONEST CAVEAT (same shape as rotation.mjs's own KV rate-limiter caveat):
// this is read-then-write, not atomic. Two concurrent requests can both read
// consecutiveFailures=2 and both write back 3 instead of reaching 4 — a lost
// update. For a circuit BREAKER (not a hard billing cap) that is a low-
// severity, self-healing race: worst case a couple of extra requests reach
// an already-failing provider before the circuit opens a moment later. A
// Durable Object removes this race entirely if it's ever worth the added
// wrangler.toml + migration + new deploy path this project does not
// currently have — see the v6 docblock, point 2.
const CIRCUIT_FAIL_THRESHOLD = 3;
const CIRCUIT_OPEN_MS = 5 * 60 * 1000;

async function isCircuitOpen(env, provider, now = Date.now()) {
  const state = await kvGetJSON(env?.CES_CHAT_KV, `tts:circuit:${provider}`);
  return !!state && state.circuitOpenUntil > now;
}

/** Schedule with context.waitUntil when available so the KV write never delays the response. */
function recordOutcome(context, provider, success) {
  const env = context.env;
  const kv = env?.CES_CHAT_KV;
  if (!kv) return;
  const task = (async () => {
    const now = Date.now();
    const state = (await kvGetJSON(kv, `tts:circuit:${provider}`)) || { consecutiveFailures: 0, circuitOpenUntil: 0 };
    if (success) {
      state.consecutiveFailures = 0;
      state.circuitOpenUntil = 0;
    } else {
      state.consecutiveFailures = (state.consecutiveFailures || 0) + 1;
      if (state.consecutiveFailures >= CIRCUIT_FAIL_THRESHOLD) {
        state.circuitOpenUntil = now + CIRCUIT_OPEN_MS;
      }
    }
    await kvPutJSON(kv, `tts:circuit:${provider}`, state);
  })();
  if (typeof context.waitUntil === 'function') {
    context.waitUntil(task);
  } else {
    // No waitUntil available (shouldn't happen in Pages Functions, but stay
    // defensive) -- still fire the write, just don't block the response on it.
    task.catch(() => {});
  }
}

// ── Deepgram lifetime clock (v6, NEW — ports doc §4's Polly pattern) ───────
// Deepgram's $200 signup credit does not renew and expires exactly 1 year
// after signup regardless of remaining balance (confirmed in
// api_keys_EMPTY_KEYS_FOR_SECURITY.txt). firstUsedAt is written ONCE, ever,
// on this tier's first successful call -- a single KV write for the
// resource's entire lifetime, not a hot per-request counter, so this does
// not meaningfully add to KV write-rate pressure.
const DEEPGRAM_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000;
const DEEPGRAM_SAFETY_BUFFER_MS = 5 * 24 * 60 * 60 * 1000; // stop 5 days early, not on the day of

async function isDeepgramExpired(env, now = Date.now()) {
  const state = await kvGetJSON(env?.CES_CHAT_KV, 'tts:deepgram:lifetime');
  if (!state?.firstUsedAt) return false; // never used yet -- nothing to expire
  return now >= (state.firstUsedAt + DEEPGRAM_LIFETIME_MS - DEEPGRAM_SAFETY_BUFFER_MS);
}

function recordDeepgramFirstUseIfAbsent(context) {
  const kv = context.env?.CES_CHAT_KV;
  if (!kv) return;
  const task = (async () => {
    const existing = await kvGetJSON(kv, 'tts:deepgram:lifetime');
    if (existing?.firstUsedAt) return; // write-once
    await kvPutJSON(kv, 'tts:deepgram:lifetime', { firstUsedAt: Date.now() });
  })();
  if (typeof context.waitUntil === 'function') context.waitUntil(task);
  else task.catch(() => {});
}

// ── TIER 1 — ElevenLabs (unchanged endpoint/voice-settings, + v6 speed) ───
async function fetchElevenTTS(text, apiKey, voiceId, speed, timeoutMs) {
  const url = `${ELEVEN_API_URL}/${voiceId}?output_format=${ELEVEN_OUT_FORMAT}`;

  const elRes = await fetchWithTimeout(url, {
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
        speed            : speedToElevenSpeed(speed),
      },
    }),
  }, timeoutMs);

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

  return { bytes: new Uint8Array(await elRes.arrayBuffer()), contentType: 'audio/mpeg' };
}

// ── TIER 2 — Deepgram Aura-2, ENGLISH ONLY (unchanged endpoint) ──────────
async function fetchDeepgramTTS(text, apiKey, timeoutMs) {
  const res = await fetchWithTimeout(DEEPGRAM_SPEAK_URL, {
    method : 'POST',
    headers: {
      'Authorization': `Token ${apiKey}`,
      'Content-Type' : 'application/json',
    },
    body: JSON.stringify({ model: DEEPGRAM_TTS_MODEL, text }),
  }, timeoutMs);

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

  return { bytes: new Uint8Array(await res.arrayBuffer()), contentType: 'audio/mpeg' };
}

// ── OPT-IN ONLY — Speechmatics TTS (unchanged, real per-character cost) ──
async function fetchSpeechmaticsTTS(text, apiKey, timeoutMs) {
  const url = `${SPEECHMATICS_TTS_URL_BASE}/${SPEECHMATICS_TTS_VOICE}`;

  const res = await fetchWithTimeout(url, {
    method : 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type' : 'application/json',
    },
    body: JSON.stringify({ text }),
  }, timeoutMs);

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

  return { bytes: new Uint8Array(await res.arrayBuffer()), contentType: 'audio/wav' };
}

// ── FINAL SAFETY NET — Google Translate TTS (unchanged, + v6 speed passthrough) ──
async function fetchGoogleTTS(text, lang, speed, timeoutMs) {
  const url = new URL('https://translate.google.com/translate_tts');
  url.searchParams.set('ie',       'UTF-8');
  url.searchParams.set('client',   'tw-ob');
  url.searchParams.set('tl',       lang);
  url.searchParams.set('q',        text);
  // v6: threads a caller-requested speed through this already-existing param
  // instead of hardcoding '1' -- default unchanged when speed is unspecified.
  // gTTS's own accepted range for this undocumented param isn't independently
  // confirmed; only forwarded when the caller actually asked for something
  // other than normal speed.
  url.searchParams.set('ttsspeed', speed && speed !== 1.0 ? String(clampSpeed(speed)) : '1');

  const res = await fetchWithTimeout(url.toString(), {
    headers: {
      'Referer'   : 'https://translate.google.com/',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
                    'AppleWebKit/537.36 (KHTML, like Gecko) ' +
                    'Chrome/125.0.0.0 Safari/537.36',
    },
    cf: { cacheEverything: true, cacheTtl: 3600 },
  }, timeoutMs);

  if (!res.ok) throw new Error(`gTTS upstream HTTP ${res.status}`);
  return { bytes: new Uint8Array(await res.arrayBuffer()), contentType: 'audio/mpeg' };
}

// ── GROUP 0 — Microsoft Edge TTS (v6, NEW) ─────────────────────────────────
// See docblock point 1 for the DRM/reliability caveat. Every exit path
// (success, error, timeout) closes the WebSocket explicitly -- per the
// architecture doc §15.8, this is the one resource in this file the Workers
// runtime will not reclaim on its own within an invocation.

/** SHA-256(windows-filetime, rounded down to a 5-min bucket, + public token). */
async function generateEdgeSecMsGec() {
  let ticks = (Date.now() / 1000) + EDGE_TTS_WIN_EPOCH_OFFSET_SECONDS;
  ticks -= ticks % 300;
  ticks *= 1e9 / 100; // -> 100ns Windows FILETIME ticks
  const strToHash = `${ticks.toFixed(0)}${EDGE_TTS_TRUSTED_CLIENT_TOKEN}`;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(strToHash));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function generateEdgeMuid() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function jsStyleDateString() {
  // Matches edge-tts reference's date_to_string(): JS Date#toUTCString() is
  // "Sun, 19 Jul 2026 12:00:00 GMT" -- close enough in every field Microsoft's
  // parser actually reads (day/month/year/time); the exact "GMT+0000 (...)"
  // suffix format is cosmetic per the reference implementation's own comment
  // ("we'll just use UTC and hope for the best").
  return new Date().toUTCString();
}

function buildEdgeSsml(voiceName, escapedText, rate) {
  return (
    "<speak version='1.0' xmlns='http://www.w3.org/2001/10/synthesis' xml:lang='en-US'>" +
    `<voice name='${voiceName}'>` +
    `<prosody pitch='+0Hz' rate='${rate}' volume='+0%'>` +
    escapedText +
    '</prosody></voice></speak>'
  );
}

/** Parse a `\r\n\r\n`-delimited text WS message into { headers, body }. */
function parseEdgeTextFrame(str) {
  const sep = str.indexOf('\r\n\r\n');
  if (sep === -1) return { headers: {}, body: str };
  const headers = {};
  for (const line of str.slice(0, sep).split('\r\n')) {
    if (!line) continue;
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    headers[line.slice(0, idx)] = line.slice(idx + 1);
  }
  return { headers, body: str.slice(sep + 4) };
}

/**
 * Parse a binary WS audio frame: [2 bytes big-endian header length N]
 * [N bytes "Key:Value\r\n..." headers][remaining bytes = payload].
 * Standard length-prefixed framing, verified round-trip-correct in this
 * session against hand-constructed synthetic frames (including a >255-byte
 * header case exercising the full two-byte length, not just the trivial
 * single-byte path) -- see chat log.
 */
function parseEdgeBinaryFrame(buf) {
  if (buf.length < 2) throw new Error('Edge TTS: binary message missing header length');
  const headerLength = (buf[0] << 8) | buf[1];
  if (2 + headerLength > buf.length) throw new Error('Edge TTS: header length exceeds message size');
  const headerBytes = buf.slice(2, 2 + headerLength);
  const payload = buf.slice(2 + headerLength);
  const headerStr = new TextDecoder('utf-8').decode(headerBytes);
  const headers = {};
  for (const line of headerStr.split('\r\n')) {
    if (!line) continue;
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    headers[line.slice(0, idx)] = line.slice(idx + 1);
  }
  return { headers, payload };
}

/**
 * @returns {Promise<{ bytes: Uint8Array, contentType: string }>}
 */
async function fetchEdgeTTS(text, lang, genderKey, speed, timeoutMs, budget) {
  if (budget && !budget.take()) {
    const err = new Error('Edge TTS: subrequest budget exhausted');
    err.category = 'subrequest budget exhausted';
    err.httpStatus = 'network';
    throw err;
  }

  const voiceName = resolveEdgeVoice(lang, genderKey);
  const rate = speedToEdgeRate(speed);
  const escapedText = escapeSsmlText(text);

  const connectionId = crypto.randomUUID().replace(/-/g, '');
  const requestId = crypto.randomUUID().replace(/-/g, '');
  const secMsGec = await generateEdgeSecMsGec();
  const url =
    `${EDGE_TTS_WSS_BASE}&ConnectionId=${connectionId}` +
    `&Sec-MS-GEC=${secMsGec}&Sec-MS-GEC-Version=${EDGE_TTS_SEC_MS_GEC_VERSION}`;

  // fetch()+Upgrade is required (not the bare `new WebSocket(url)` form)
  // specifically because it is the only way to attach the extra
  // fingerprint headers (User-Agent/Origin/Cookie) below alongside the
  // upgrade request -- confirmed against Cloudflare's own Workers docs.
  const upgradeHeaders = {
    Upgrade         : 'websocket',
    'User-Agent'    : EDGE_TTS_USER_AGENT,
    'Accept-Language': 'en-US,en;q=0.9',
    Pragma          : 'no-cache',
    'Cache-Control' : 'no-cache',
    Origin          : EDGE_TTS_ORIGIN,
    Cookie          : `muid=${generateEdgeMuid()};`,
  };

  let ws;
  let timer;
  try {
    const handshake = await Promise.race([
      fetch(url, { headers: upgradeHeaders }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('Edge TTS: handshake timeout'), { category: 'handshake timeout', httpStatus: 'network' })), timeoutMs);
      }),
    ]);
    clearTimeout(timer);

    ws = handshake.webSocket;
    if (!ws) {
      const err = new Error(`Edge TTS: handshake rejected (HTTP ${handshake.status})`);
      err.category = `handshake HTTP ${handshake.status}`;
      err.httpStatus = handshake.status;
      throw err;
    }
    ws.accept();

    const result = await new Promise((resolve, reject) => {
      const audioChunks = [];
      let settled = false;
      const finish = (fn, arg) => { if (!settled) { settled = true; fn(arg); } };

      const hardTimeout = setTimeout(() => {
        finish(reject, Object.assign(new Error('Edge TTS: stream timeout'), { category: 'stream timeout', httpStatus: 'network' }));
      }, timeoutMs);

      ws.addEventListener('message', (event) => {
        try {
          if (typeof event.data === 'string') {
            const { headers } = parseEdgeTextFrame(event.data);
            if (headers['Path'] === 'turn.end') {
              clearTimeout(hardTimeout);
              if (audioChunks.length === 0) {
                finish(reject, Object.assign(new Error('Edge TTS: turn.end with no audio received'), { category: 'no audio received', httpStatus: 'network' }));
                return;
              }
              const total = audioChunks.reduce((n, c) => n + c.length, 0);
              const combined = new Uint8Array(total);
              let offset = 0;
              for (const c of audioChunks) { combined.set(c, offset); offset += c.length; }
              finish(resolve, combined);
            }
            // 'response' / 'turn.start' / 'audio.metadata' -- no action needed.
          } else {
            const raw = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : new Uint8Array(event.data?.buffer ?? event.data);
            const { headers, payload } = parseEdgeBinaryFrame(raw);
            if (headers['Path'] === 'audio' && payload.length > 0) {
              audioChunks.push(payload);
            }
          }
        } catch (parseErr) {
          clearTimeout(hardTimeout);
          finish(reject, Object.assign(parseErr, { category: parseErr.category || 'frame parse error', httpStatus: 'network' }));
        }
      });

      ws.addEventListener('close', (event) => {
        clearTimeout(hardTimeout);
        if (!settled) {
          finish(reject, Object.assign(
            new Error(`Edge TTS: closed before turn.end (code ${event.code})`),
            { category: `abnormal close ${event.code}`, httpStatus: 'network' },
          ));
        }
      });

      ws.addEventListener('error', () => {
        clearTimeout(hardTimeout);
        finish(reject, Object.assign(new Error('Edge TTS: WebSocket error'), { category: 'websocket error', httpStatus: 'network' }));
      });

      const wordBoundary = false; // no need for word/sentence timing metadata here
      ws.send(
        `X-Timestamp:${jsStyleDateString()}\r\n` +
        'Content-Type:application/json; charset=utf-8\r\n' +
        'Path:speech.config\r\n\r\n' +
        `{"context":{"synthesis":{"audio":{"metadataoptions":{` +
        `"sentenceBoundaryEnabled":"${!wordBoundary}","wordBoundaryEnabled":"${wordBoundary}"},` +
        `"outputFormat":"${EDGE_TTS_OUTPUT_FORMAT}"}}}}\r\n`,
      );
      ws.send(
        `X-RequestId:${requestId}\r\n` +
        'Content-Type:application/ssml+xml\r\n' +
        `X-Timestamp:${jsStyleDateString()}Z\r\n` +
        'Path:ssml\r\n\r\n' +
        buildEdgeSsml(voiceName, escapedText, rate),
      );
    });

    return { bytes: result, contentType: 'audio/mpeg' };
  } finally {
    clearTimeout(timer);
    try { ws?.close(); } catch (_e) { /* already closed/closing -- fine */ }
  }
}

// ── Shared cascade engine (v6, NEW — one copy, used by GET and POST) ──────
/**
 * Runs Tier 0 -> Tier 1 -> Tier 2 -> opt-in Speechmatics -> Tier 3 in order,
 * honoring IS_DEV/circuit breakers/lifetime clocks, and returns whichever
 * tier answers first (or throws a final aggregate error).
 */
async function runTtsCascade({ text, lang, genderKey, speed, env, context, timeouts }) {
  const devMode = isDevMode(env);
  const englishOnly = isEnglish(lang);
  const budget = makeFetchBudget(SUBREQUEST_BUDGET_FREE_PLAN);

  const eleven   = buildKeyRing(env, ELEVEN_BASE_NAME);
  const deepgram = buildKeyRing(env, DEEPGRAM_BASE_NAME);
  const speechmaticsEnabled = (env?.ENABLE_SPEECHMATICS_TTS || '').trim().toLowerCase() === 'true';
  const speechmatics = speechmaticsEnabled ? buildKeyRing(env, SPEECHMATICS_BASE_NAME) : { keys: [] };
  const edgeEnabled = (env?.EDGE_TTS_ENABLED || '').trim().toLowerCase() === 'true'; // default OFF -- see docblock point 1

  const keyCountHeaders = {
    'X-TTS-Eleven-KeysAvailable'  : String(eleven.keys.length),
    'X-TTS-Deepgram-KeysAvailable': String(deepgram.keys.length),
  };

  const attempts = []; // for logging + X-TTS-Fallback-Reason

  // TIER 0 — Edge TTS (always runs when enabled, even in dev — no quota to protect)
  if (edgeEnabled && !(await isCircuitOpen(env, 'edge_tts'))) {
    try {
      const { bytes, contentType } = await fetchEdgeTTS(text, lang, genderKey, speed, timeouts.tier0, budget);
      recordOutcome(context, 'edge_tts', true);
      return {
        bytes, contentType, provider: 'edge_tts', providerOfficial: false,
        engineHeaders: {}, attempts, budgetRemaining: budget.remaining(),
      };
    } catch (err) {
      recordOutcome(context, 'edge_tts', false);
      attempts.push({ tier: 0, provider: 'edge_tts', reason: err.category || err.message });
    }
  } else if (edgeEnabled) {
    attempts.push({ tier: 0, provider: 'edge_tts', reason: 'circuit open' });
  }

  // TIER 1 — ElevenLabs ring (all languages; recurring monthly quota -- runs in dev too)
  if (eleven.keys.length > 0 && !(await isCircuitOpen(env, 'elevenlabs'))) {
    try {
      const voiceId = resolveVoiceId(genderKey, env);
      const { response: result, keyIndex, keysTried } = await rotateAndFetchTTS(
        ringPointers.eleven, eleven.keys,
        (key) => fetchElevenTTS(text, key, voiceId, speed, timeouts.tier1),
        'ElevenLabs', budget,
      );
      recordOutcome(context, 'elevenlabs', true);
      return {
        bytes: result.bytes, contentType: result.contentType, provider: 'elevenlabs', providerOfficial: true,
        engineHeaders: { 'X-TTS-Voice': voiceId, 'X-TTS-KeyIndex': String(keyIndex), 'X-TTS-KeysTried': String(keysTried), ...keyCountHeaders },
        attempts, budgetRemaining: budget.remaining(),
      };
    } catch (err) {
      recordOutcome(context, 'elevenlabs', false);
      attempts.push({ tier: 1, provider: 'elevenlabs', reason: err.category || err.message });
    }
  } else if (eleven.keys.length > 0) {
    attempts.push({ tier: 1, provider: 'elevenlabs', reason: 'circuit open' });
  }

  // TIER 2 — Deepgram Aura-2, ENGLISH ONLY, skipped in dev (finite credit) or once lifetime-expired
  if (englishOnly && deepgram.keys.length > 0 && !devMode) {
    const expired = await isDeepgramExpired(env);
    if (expired) {
      attempts.push({ tier: 2, provider: 'deepgram', reason: 'lifetime credit pre-emptively expired' });
    } else if (await isCircuitOpen(env, 'deepgram')) {
      attempts.push({ tier: 2, provider: 'deepgram', reason: 'circuit open' });
    } else {
      try {
        const { response: result, keyIndex, keysTried } = await rotateAndFetchTTS(
          ringPointers.deepgram, deepgram.keys,
          (key) => fetchDeepgramTTS(text, key, timeouts.tier2),
          'Deepgram', budget,
        );
        recordOutcome(context, 'deepgram', true);
        recordDeepgramFirstUseIfAbsent(context);
        return {
          bytes: result.bytes, contentType: result.contentType, provider: 'deepgram', providerOfficial: true,
          engineHeaders: { 'X-TTS-KeyIndex': String(keyIndex), 'X-TTS-KeysTried': String(keysTried), ...keyCountHeaders },
          attempts, budgetRemaining: budget.remaining(),
        };
      } catch (err) {
        recordOutcome(context, 'deepgram', false);
        attempts.push({ tier: 2, provider: 'deepgram', reason: err.category || err.message });
      }
    }
  } else if (englishOnly && deepgram.keys.length > 0 && devMode) {
    attempts.push({ tier: 2, provider: 'deepgram', reason: 'skipped: IS_DEV (protects finite one-time credit)' });
  }

  // OPT-IN TIER — Speechmatics, ENGLISH ONLY, real cost, skipped in dev
  if (englishOnly && speechmaticsEnabled && speechmatics.keys.length > 0 && !devMode) {
    if (await isCircuitOpen(env, 'speechmatics')) {
      attempts.push({ tier: '1.5', provider: 'speechmatics', reason: 'circuit open' });
    } else {
      try {
        const { response: result, keyIndex, keysTried } = await rotateAndFetchTTS(
          { i: 0 }, speechmatics.keys,
          (key) => fetchSpeechmaticsTTS(text, key, timeouts.tier2),
          'Speechmatics', budget,
        );
        recordOutcome(context, 'speechmatics', true);
        return {
          bytes: result.bytes, contentType: result.contentType, provider: 'speechmatics', providerOfficial: true,
          engineHeaders: { 'X-TTS-KeyIndex': String(keyIndex), 'X-TTS-KeysTried': String(keysTried) },
          attempts, budgetRemaining: budget.remaining(),
        };
      } catch (err) {
        recordOutcome(context, 'speechmatics', false);
        attempts.push({ tier: '1.5', provider: 'speechmatics', reason: err.category || err.message });
      }
    }
  } else if (englishOnly && speechmaticsEnabled && speechmatics.keys.length > 0 && devMode) {
    attempts.push({ tier: '1.5', provider: 'speechmatics', reason: 'skipped: IS_DEV (real per-character cost)' });
  }

  // TIER 3 — Google Translate TTS (final safety net, always attempted, all langs)
  try {
    const result = await fetchGoogleTTS(text, lang, speed, timeouts.tier3);
    recordOutcome(context, 'gtts', true);
    return {
      bytes: result.bytes, contentType: result.contentType, provider: 'gtts', providerOfficial: false,
      engineHeaders: { ...keyCountHeaders }, attempts, budgetRemaining: budget.remaining(),
    };
  } catch (err) {
    recordOutcome(context, 'gtts', false);
    attempts.push({ tier: 3, provider: 'gtts', reason: err.message });
  }

  const finalErr = new Error('All TTS providers unavailable');
  finalErr.attempts = attempts;
  finalErr.keyCountHeaders = keyCountHeaders;
  throw finalErr;
}

/** Build the shared X-TTS-* diagnostic/degradation headers for a winning result. */
function buildResultHeaders(result, requestedLang) {
  const { rendered, quality, degraded } = renderedDialectFor(result.provider, requestedLang);
  const firstAttemptedProvider = result.provider; // if attempts[] is empty, this WAS the first tier tried
  const wasFallback = result.attempts.length > 0;
  const headers = {
    'X-TTS-Engine'             : result.provider,
    'X-TTS-Provider-Official'  : String(result.providerOfficial),
    'X-TTS-Dialect-Requested'  : requestedLang,
    'X-TTS-Dialect-Rendered'   : rendered,
    'X-TTS-Quality-Score'      : quality,
    'X-TTS-Fallback'           : String(wasFallback),
    ...result.engineHeaders,
  };
  if (wasFallback) {
    headers['X-TTS-Fallback-Reason'] = result.attempts.map(a => `${a.provider}:${a.reason}`).join('; ');
  }
  if (degraded) {
    // ASCII-only separator -- HTTP header values must be Latin-1/ByteString.
    // The architecture doc's own illustrative header (`ar-EG→MSA`, using
    // U+2192) throws "character ... greater than 255" if actually set via
    // the Fetch/Headers API -- caught by this session's integration test
    // (Test 2/5 below both failed on this before the fix). Confirmed this
    // was the doc's mistake to begin with, not a transcription error here.
    headers['X-TTS-Dialect-Degraded'] = `${requestedLang}->${rendered}`;
  }
  return headers;
}

function logTtsEvent(fields) {
  try {
    console.log(JSON.stringify({ ts: new Date().toISOString(), ...fields }));
  } catch (_e) { /* logging must never break the response */ }
}

// ── GET handler (existing contract, byte-for-byte preserved) ──────────────
export async function onRequestGet(context) {
  const { request, env } = context;
  const url              = new URL(request.url);
  const rawText          = url.searchParams.get('text') || '';
  const langParam        = (url.searchParams.get('lang')  || 'ar-EG').trim();
  const voiceParam       = (url.searchParams.get('voice') || 'female').toLowerCase().trim();
  // v6, additive: optional -- absent entirely from every existing caller,
  // so omitting it preserves identical behavior to v5.
  const speedParam       = url.searchParams.has('speed') ? Number(url.searchParams.get('speed')) : 1.0;

  const text = preprocessText(rawText);
  if (!text) {
    return jsonResponse(400, { error: 'Missing or empty text parameter.' }, request);
  }
  if (text.length > MAX_TEXT_LENGTH) {
    return jsonResponse(400, { error: `Text exceeds ${MAX_TEXT_LENGTH}-char limit. Caller must pre-chunk.` }, request);
  }

  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateCheck = await checkRateLimit(env, clientIp);
  if (rateCheck.limited) {
    return jsonResponse(429, { error: 'Too many TTS requests too quickly. Please wait a moment and try again.' }, request);
  }

  const safeLang  = ALLOWED_LANGS.has(langParam) ? langParam : 'ar-EG';
  const genderKey = voiceParam === 'male' ? 'male' : 'female';

  try {
    const result = await runTtsCascade({
      text, lang: safeLang, genderKey, speed: speedParam, env, context,
      timeouts: { tier0: 2500, tier1: 4000, tier2: 4000, tier3: 6000 },
    });
    logTtsEvent({ route: 'GET', lang: safeLang, provider: result.provider, fallback: result.attempts.length > 0, attempts: result.attempts, budgetRemaining: result.budgetRemaining });
    return new Response(result.bytes, {
      status: 200,
      headers: {
        'Content-Type' : result.contentType,
        'Cache-Control': 'public, max-age=3600',
        ...buildResultHeaders(result, safeLang),
        ...getCorsHeaders(request),
      },
    });
  } catch (finalErr) {
    logTtsEvent({ route: 'GET', lang: safeLang, provider: null, fallback: true, attempts: finalErr.attempts, error: finalErr.message });
    return jsonResponse(502, {
      error: 'TTS service unreachable.',
      attempts: finalErr.attempts,
    }, request, finalErr.keyCountHeaders);
  }
}

// ── POST handler (v6, NEW — richer JSON interface, additive only) ────────
export async function onRequestPost(context) {
  const { request, env } = context;
  let body;
  try {
    body = await request.json();
  } catch (_e) {
    return jsonResponse(400, { error: 'Malformed JSON body.' }, request);
  }

  const rawText   = typeof body.text === 'string' ? body.text : '';
  const langParam = typeof (body.dialect ?? body.lang) === 'string' ? (body.dialect ?? body.lang).trim() : 'ar-EG';
  const genderRaw = typeof body.voice_gender === 'string' ? body.voice_gender.toLowerCase().trim() : 'female';
  const speedParam = body.speed !== undefined ? Number(body.speed) : 1.0;
  const formatParam = typeof body.format === 'string' ? body.format.toLowerCase().trim() : 'mp3';

  const text = preprocessText(rawText);
  if (!text) {
    return jsonResponse(400, { error: 'Missing or empty "text" field.' }, request);
  }
  if (text.length > MAX_TEXT_LENGTH) {
    return jsonResponse(400, { error: `Text exceeds ${MAX_TEXT_LENGTH}-char limit. Caller must pre-chunk.` }, request);
  }

  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateCheck = await checkRateLimit(env, clientIp);
  if (rateCheck.limited) {
    return jsonResponse(429, { error: 'Too many TTS requests too quickly. Please wait a moment and try again.' }, request);
  }

  const safeLang  = ALLOWED_LANGS.has(langParam) ? langParam : 'ar-EG';
  const genderKey = genderRaw === 'male' ? 'male' : 'female';

  try {
    const result = await runTtsCascade({
      text, lang: safeLang, genderKey, speed: speedParam, env, context,
      timeouts: { tier0: 2500, tier1: 4000, tier2: 4000, tier3: 6000 },
    });
    logTtsEvent({ route: 'POST', lang: safeLang, provider: result.provider, fallback: result.attempts.length > 0, attempts: result.attempts, budgetRemaining: result.budgetRemaining });

    // format passthrough is a hint, not a transcode -- see docblock: no audio
    // transcoding library/CPU budget exists here, so the response always
    // stamps the ACTUAL format the winning tier produced rather than lying
    // about a requested one it did not deliver.
    const formatHeader = formatParam !== 'mp3' && !result.contentType.includes(formatParam)
      ? { 'X-TTS-Format-Note': `requested "${formatParam}", actual output is ${result.contentType}` }
      : {};

    return new Response(result.bytes, {
      status: 200,
      headers: {
        'Content-Type' : result.contentType,
        'Cache-Control': 'public, max-age=3600',
        ...buildResultHeaders(result, safeLang),
        ...formatHeader,
        ...getCorsHeaders(request),
      },
    });
  } catch (finalErr) {
    logTtsEvent({ route: 'POST', lang: safeLang, provider: null, fallback: true, attempts: finalErr.attempts, error: finalErr.message });
    return jsonResponse(503, {
      error: 'All TTS providers unavailable',
      tiers_attempted: finalErr.attempts,
      retry_after: 60,
    }, request, finalErr.keyCountHeaders);
  }
}

// ── OPTIONS preflight (unchanged) ──────────────────────────────────────────
export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}
