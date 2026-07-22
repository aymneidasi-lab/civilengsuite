// functions/_lib/rotation.mjs
// =============================================================================
// Shared concurrency / traffic-safety helpers — extracted from chat.js's own
// "v13 CONCURRENCY HELPERS" (rotateStart, makeFetchBudget, fetchWithTimeout)
// and "v13 RATE LIMITER" (checkRateLimit) sections, byte-identical logic.
// Imported by chat.js, functions/api/vision.js, and (as of tts.js v6)
// functions/api/tts.js. Do not re-implement any of this in a calling file —
// import from here.
//
// File name stays "rotation.mjs" (matching the original deliverable name),
// even though it now covers the whole v13 concurrency/rate-limit group, not
// only rotation — chat.js's own comments already treat these as one unit.
//
// Also added here (new, not a chat.js extraction): buildGeminiKeyPool() and
// keyTagFor(). chat.js builds its 13-entry Gemini key array as a literal
// inline block; vision.js needs the exact same array. Leaving it as a
// second hand-copied literal risks the two files drifting on Gemini's ring
// numbering, which is NOT the same pattern Groq/OpenRouter use — see the
// comment on buildGeminiKeyPool below. One canonical copy, in both places.
// =============================================================================

// ── Key rotation ─────────────────────────────────────────────────────────
// The Gemini/Groq/OpenRouter key pools are iterated as an ORDERED FAILOVER
// LIST: every request, from every concurrent user, starts at keys[0]. That
// is correct for surviving one key's daily quota exhaustion, but it means
// concurrent traffic never spreads across the other keys until key 0 is
// already failing — effective concurrent throughput is bounded by ONE
// upstream account's per-minute limit, not by the pool. rotateStart() picks
// a random starting offset per request so simultaneous requests fan out
// across the whole pool from the first attempt. Order within the rotation
// is preserved (still tries every key exactly once), so daily-quota
// failover behaviour is unchanged — this only changes which key is tried
// *first* on any given request.
export function rotateStart(arr) {
  if (arr.length <= 1) return arr.slice();
  const offset = Math.floor(Math.random() * arr.length);
  return arr.slice(offset).concat(arr.slice(0, offset));
}

// Adds ±20% jitter to a backoff delay so concurrent requests retrying the
// same saturated key do not all wake up and retry in lockstep (thundering
// herd). Exported for completeness / future reuse; vision.js does not call
// this — see the corrections note on why vision.js does not do same-key
// backoff retries the way callGeminiWithRetry does.
export function withJitter(ms) {
  const jitter = ms * 0.2 * (Math.random() * 2 - 1);
  return Math.max(0, Math.round(ms + jitter));
}

// ── Subrequest budget ────────────────────────────────────────────────────
// Cloudflare Workers/Pages Functions Free plan caps a single invocation at
// 50 fetch() subrequests (Paid: 10,000, $5/mo). A simple mutable counter
// threaded through onRequestPost; every helper that issues a fetch() takes
// from it first and refuses to call out once it hits zero, so the request
// fails over to a friendly error deterministically instead of relying on
// the platform to reject the 51st call.
export function makeFetchBudget(max) {
  let remaining = max;
  return {
    take() { if (remaining <= 0) return false; remaining--; return true; },
    remaining() { return remaining; },
  };
}
// Free-plan ceiling is 50; stop two attempts short so the final friendly-
// error response itself is never the thing that trips the platform limit.
export const SUBREQUEST_BUDGET_FREE_PLAN = 48;

// ── Fetch timeout ────────────────────────────────────────────────────────
// Every provider call previously had no upper bound on wall time. A stalled
// upstream connection held the invocation open indefinitely (no CPU billed
// while awaiting I/O, but the user-visible widget just hangs with no
// error). timeoutMs has no default here (chat.js's PROVIDER_TIMEOUT_MS is
// 8000 for short text completions; vision.js needs a longer, separately-
// reasoned value — see corrections note — so the caller must always pass
// one explicitly rather than inherit a text-shaped default).
export async function fetchWithTimeout(url, init, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ── Rate limiter ─────────────────────────────────────────────────────────
// CORS is a browser-enforced policy, not a server-side control — any script
// can POST directly to /api/chat or /api/vision from outside a browser
// entirely, bypassing it. Combined with the 13-key pool, an unthrottled
// client can burn through the ENTIRE shared free-tier quota — every
// account — in well under a minute. checkRateLimit is shared (not
// duplicated) specifically so chat.js and vision.js draw down ONE combined
// per-visitor budget instead of each getting its own — otherwise adding
// vision.js would silently double both the effective abuse ceiling per
// visitor AND the KV write pressure noted below.
//
// Preferred: Cloudflare's native Workers Rate Limiting binding
// (env.RATE_LIMITER) — in-isolate counters, no added latency, no extra
// subrequest cost. Requires Workers PAID plan + a `ratelimits` block in
// wrangler config; not configurable from the Pages dashboard alone.
//
// Fallback: if env.RATE_LIMITER is absent but env.CES_CHAT_KV is bound
// (dashboard-addable, Free plan), a coarse fixed-window counter is used.
// HONEST CAVEAT: Workers KV Free plan caps writes at 1,000/day. A 60s
// window with one write per request hits that ceiling at ~42
// messages/HOUR sustained — a KV-only limiter can itself start failing
// during the exact heavy-traffic conditions it exists to guard against.
// Fails OPEN (KV error => not rate limited): availability for real
// visitors takes priority over strict enforcement for a sales chatbot.
//
// `key` is the caller-supplied identifier (IP via CF-Connecting-IP).
//
// `opts` (added for tts.js, v7 -- optional, backward compatible): a route
// whose traffic shape is "many small calls per one user action" (e.g. a
// single spoken chat reply needing several sequential /api/tts calls,
// since MAX_TEXT_LENGTH forces the caller to pre-chunk) doesn't fit the
// same window/threshold tuned for "one call per user action" (a chat
// message, a vision request). Omitting opts reproduces the exact prior
// hardcoded behavior (60s / 8 requests) -- chat.js and vision.js's
// existing two-argument calls are unaffected by this. Only the KV-fallback
// branch reads opts; the native RATE_LIMITER binding's threshold is set in
// wrangler config/dashboard and cannot be overridden from a call site --
// a genuinely separate allowance there needs its own binding.
export async function checkRateLimit(env, key, opts = {}) {
  // Defensive: opts can be explicitly passed as null from a caller; ?? on
  // a null object throws. Default-param only catches undefined.
  opts = opts || {};
  if (!env) {
    if (!checkRateLimit._warned) {
      checkRateLimit._warned = true;
      console.warn('[rotation.mjs] No env provided — endpoint is unthrottled.');
    }
    return { limited: false, mechanism: 'no-env' };
  }

  if (env.RATE_LIMITER) {
    try {
      const { success } = await env.RATE_LIMITER.limit({ key });
      return { limited: !success, mechanism: 'binding' };
    } catch (err) {
      console.error('[rotation.mjs] RATE_LIMITER binding error (failing open):', err.message);
      return { limited: false, mechanism: 'binding-error' };
    }
  }

  if (env.CES_CHAT_KV) {
    try {
      const windowSeconds = opts.windowSeconds ?? 60;
      const maxPerWindow  = opts.maxPerWindow  ?? 8; // ~1 action every 7.5s sustained, generous for one real user
      const bucket = Math.floor(Date.now() / 1000 / windowSeconds);
      const kvKey = `rl:${key}:${bucket}`;
      // BUG FIX: parseInt on a corrupted/truthy non-numeric KV value
      // (e.g. "NaN", "abc", or a manual dashboard edit) returns NaN.
      // NaN >= maxPerWindow is always false, so the limiter silently
      // becomes a no-op for that bucket's TTL. Guard against it.
      const rawCurrent = await env.CES_CHAT_KV.get(kvKey);
      const parsed = parseInt(rawCurrent || '0', 10);
      const current = Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
      if (current >= maxPerWindow) {
        return { limited: true, mechanism: 'kv' };
      }
      await env.CES_CHAT_KV.put(kvKey, String(current + 1), { expirationTtl: windowSeconds * 2 });
      return { limited: false, mechanism: 'kv' };
    } catch (err) {
      console.error('[rotation.mjs] CES_CHAT_KV error (failing open):', err.message);
      return { limited: false, mechanism: 'kv-error' };
    }
  }

  if (!checkRateLimit._warned) {
    checkRateLimit._warned = true;
    console.warn('[rotation.mjs] No rate limiter bound (RATE_LIMITER or CES_CHAT_KV) — endpoint is unthrottled.');
  }
  return { limited: false, mechanism: 'none' };
}

// ── Gemini key pool ──────────────────────────────────────────────────────
// CORRECTED: The actual Cloudflare dashboard env vars are:
//   GEMINI_API_KEY          = Google account 1  (unsuffixed)
//   GEMINI_API_KEY_1        = Google account 2
//   GEMINI_API_KEY_2        = Google account 3
//   ...
//   GEMINI_API_KEY_12       = Google account 13
// The previous version incorrectly skipped _1 and looked for a non-existent
// _13, meaning GEMINI_API_KEY_1 (a real, configured key) was never used,
// and GEMINI_API_KEY_13 (which does not exist) was searched instead.
// This now matches the live dashboard exactly: 1 unsuffixed + _1.._12.
export function buildGeminiKeyPool(env) {
  if (!env) return [];
  return [
    env.GEMINI_API_KEY    || '',
    env.GEMINI_API_KEY_1  || '',
    env.GEMINI_API_KEY_2  || '',
    env.GEMINI_API_KEY_3  || '',
    env.GEMINI_API_KEY_4  || '',
    env.GEMINI_API_KEY_5  || '',
    env.GEMINI_API_KEY_6  || '',
    env.GEMINI_API_KEY_7  || '',
    env.GEMINI_API_KEY_8  || '',
    env.GEMINI_API_KEY_9  || '',
    env.GEMINI_API_KEY_10 || '',
    env.GEMINI_API_KEY_11 || '',
    env.GEMINI_API_KEY_12 || '',
  ]
    .map((key, originalIndex) => ({ key, originalIndex }))
    .filter(k => k.key);
}

// keyTag matches chat.js's own X-CES-AI-Source tagging exactly:
// originalIndex 0 (unsuffixed account) -> '', originalIndex N -> 'keyN+1-'.
// e.g. 'gemini-' + keyTagFor(0) + 'primary' = 'gemini-primary'
//      'gemini-' + keyTagFor(1) + 'primary' = 'gemini-key2-primary'
export function keyTagFor(originalIndex) {
  return originalIndex === 0 ? '' : `key${originalIndex + 1}-`;
}