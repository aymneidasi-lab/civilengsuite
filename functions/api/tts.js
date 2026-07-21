/**
 * functions/api/tts.js  —  v9  (2026-07-20)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — TTS Proxy
 * Routes: GET  /api/tts?text=...&lang=ar-EG[&voice=female|male][&speed=1.0]
 *         POST /api/tts   { text, dialect, voice_gender, speed, format }
 *
 * ── HOW v8 GOT HERE ─────────────────────────────────────────────────────────
 * Two independent passes forked from the same v5 after this file was first
 * reviewed: this session's own v6/v7 (Deepgram model-string fix, real
 * fetchWithTimeout signature, tts:-namespaced rate limiting, in-memory
 * circuit breaker) and a separately-supplied "v6" (tts-1.js: Edge TTS as a
 * new free Tier 0, a POST/JSON interface, a KV-backed circuit breaker, and
 * proactive Deepgram credit-lifetime tracking). Both are real engineering,
 * pointed at different gaps, and neither superset of the other. v8 merges
 * them, keeping whichever side got a given thing right and fixing what
 * neither side had fully closed. Per-item reconciliation:
 *
 *   1. [CARRIED FROM tts-1.js, verified] Group 0 — Microsoft Edge TTS. Free,
 *      keyless, real per-dialect neural voices (the SalmaNeural/ShakirNeural
 *      family — the same models Azure sells). Independently re-verified,
 *      not just read, in this pass:
 *        - The Sec-MS-GEC signature function actually runs and produces a
 *          64-char uppercase hex SHA-256 digest, deterministic within its
 *          5-minute bucket (measured directly, not assumed).
 *        - Both frame parsers (text `\r\n\r\n`-delimited, and binary
 *          2-byte-length-prefixed) were re-tested against hand-built
 *          synthetic frames independently of tts-1.js's own claimed test,
 *          including the >255-byte header case that exercises the full
 *          two-byte length field rather than just the trivial one-byte path.
 *          All pass.
 *        - The Cloudflare WebSocket pattern (fetch()+Upgrade header to get
 *          a `.webSocket` on the Response, then `.accept()`) is the correct
 *          API for attaching custom upgrade headers, which a bare
 *          `new WebSocket(url)` cannot do.
 *      What was NOT and could not be verified from this sandbox: an actual
 *      network round trip to speech.platform.bing.com (egress here is
 *      restricted to package registries). EDGE_TTS_ENABLED still defaults
 *      to "false" for exactly that reason — enable it in a preview
 *      deployment and confirm one real request succeeds before relying on
 *      it in production.
 *   2. [CARRIED FROM tts-1.js, with one fix] KV-backed circuit breaker,
 *      replacing this session's own in-memory version. On reflection this
 *      is the better default: it survives cold starts and different edge
 *      PoPs, which an in-memory breaker fundamentally cannot, and it needs
 *      no new Cloudflare binding beyond the CES_CHAT_KV already required
 *      for rate limiting. tts-1.js's own comment is honest about the
 *      read-then-write race (lost updates under true concurrency) and
 *      correctly calls it low-severity for a breaker rather than a hard
 *      cap. What it didn't account for: recordOutcome() wrote to KV on
 *      EVERY successful request, not only on failures or recoveries —
 *      meaning a fully healthy system still spent one write per request,
 *      competing with rotation.mjs's own rate-limiter for the same
 *      Free-plan 1,000-writes/day ceiling that project's comments already
 *      flag as tight. Fixed: the write is now skipped entirely when the
 *      state has nothing to reset (already-healthy stays a read-only path).
 *   3. [CARRIED FROM tts-1.js, verified] Deepgram's $200 signup credit is
 *      one-time and expires 1 year after signup regardless of remaining
 *      balance — proactively stopped 5 days early via a KV-tracked clock,
 *      instead of finding out reactively via a failed request. Precision
 *      caveat, stated plainly: the tracked clock starts at this tier's
 *      first SUCCESSFUL call through this proxy, not the true Deepgram
 *      account signup date — if this code was deployed some time after
 *      that account was actually created, the proactive cutoff fires later
 *      than the true expiry, which just means Deepgram itself rejects the
 *      request at that point exactly as it would have before this feature
 *      existed (silent degradation to the old reactive behavior, not a new
 *      failure mode). Added DEEPGRAM_SIGNUP_DATE_ISO as an optional env
 *      override for anyone who wants to set the real date once instead of
 *      relying on first-use inference.
 *   4. [CARRIED FROM tts-1.js] IS_DEV gate distinguishing recurring-quota
 *      providers (Eleven, Edge TTS — safe to exercise in dev) from
 *      finite/metered ones (Deepgram's one-time credit, Speechmatics' real
 *      per-character billing — skipped in dev, straight to gTTS).
 *   5. [CARRIED FROM tts-1.js, independently re-verified] HTTP header
 *      VALUES are Latin-1/ByteString, not Unicode — confirmed by actually
 *      trying to set a header containing U+2192 (→) in this pass: it throws
 *      `TypeError: Cannot convert argument to a ByteString...`, exactly as
 *      tts-1.js's comment claimed. The source architecture doc's own
 *      illustrative header (`ar-EG→MSA`) would have shipped a request-time
 *      crash on the very first fallback. Every degradation header here
 *      uses ASCII "->" instead.
 *   6. [FIX, this pass — regression in tts-1.js relative to this session's
 *      own v7] tts-1.js called checkRateLimit(env, clientIp) — the bare,
 *      unprefixed form. That reintroduces the exact problem this session's
 *      v7 fixed: TTS sharing chat.js/vision.js's combined per-visitor
 *      budget, when a single spoken reply can legitimately need several
 *      sequential /api/tts calls (MAX_TEXT_LENGTH forces pre-chunking).
 *      Restored the `tts:${clientIp}` namespacing plus rotation.mjs's
 *      backward-compatible opts argument ({windowSeconds, maxPerWindow}),
 *      same as v7 — see rotation.mjs's own diff.
 *   7. [FIX, this pass — same bug independently reappeared] DEEPGRAM_TTS_MODEL
 *      was still the bare string 'aura-2' here too. Same fix as v7:
 *      'aura-2-asteria-en', Deepgram's own documented model+voice+language
 *      syntax, matching the voice this file already intended.
 *   8. [FIX, this pass — same bug independently reappeared] ringPointers had
 *      no `speechmatics` entry; rotateAndFetchTTS was called with a fresh
 *      `{ i: 0 }` literal every request for that tier, so it never actually
 *      rotated its starting key across requests. Same fix as v7: added
 *      ringPointers.speechmatics and wired it in.
 *   9. [CORRECTION, this pass] tts-1.js's comment claimed ElevenLabs'
 *      speed field rejects values outside 0.7-1.2 "per ElevenLabs' own
 *      docs." Checked directly: ElevenLabs' own REST API reference states
 *      the field's actual range is 0.25-4.0; 0.7-1.2 is where their Agents
 *      Platform UI clamps its slider, not a REST API ceiling. The 0.7-1.2
 *      clamp is kept here regardless — ElevenLabs' own guidance is that
 *      extreme values degrade quality well before the technical limits, and
 *      the caller-facing clampSpeed() is already a conservative 0.5-2.0 —
 *      but the justification is corrected: a deliberate quality choice, not
 *      an API-enforced rejection.
 *  10. [CARRIED FROM tts-1.js] makeFetchBudget/SUBREQUEST_BUDGET_FREE_PLAN
 *      now guards rotateAndFetchTTS and fetchEdgeTTS — this session's v7
 *      flagged the same Free-plan 50-subrequest edge case (many keys, every
 *      tier simultaneously quota-exhausted) but declined to wire in a
 *      guard to avoid touching the shared ring-walk function. Given a
 *      working version already exists, adopting it here closes that gap
 *      rather than leaving it as a documented-but-unfixed risk.
 *  11. [ADDED, this pass] X-TTS-Request-Id (crypto.randomUUID(), threaded
 *      through every log line for the request) and X-TTS-Latency-Ms
 *      (total elapsed) on every response — this session's own v7 additions,
 *      not present in tts-1.js, ported over for the same reason: cheap,
 *      and it is exactly what you want already present the one time a
 *      request actually needs debugging.
 *  12. [KEPT, decision stated plainly] The POST interface is currently
 *      unused — the live frontend calls the GET form
 *      (`new Audio('/api/tts?text=...')`, confirmed against
 *      pc_suite_v30.html). Kept because it's purely additive and doesn't
 *      touch the GET contract at all, but it is genuinely optional: if the
 *      preference is a smaller surface area to maintain and test, it can be
 *      deleted with no effect on anything that currently calls this file.
 *
 * ── HOW v9 GOT HERE ──────────────────────────────────────────────────────────
 * Requested: confirm/enforce "recurring-quota providers rank above one-time-
 * trial providers" and improve ar-EG pronunciation quality. Per-item:
 *
 *   1. [CONFIRMED, not changed] Execution order already satisfies the rule as
 *      asked: Group 0 (Edge TTS, no quota) -> Tier 1 (ElevenLabs, recurring
 *      monthly quota) -> Tier 2 (Deepgram, one-time credit, untouched exactly
 *      as requested) -> opt-in Speechmatics -> Tier 3 (gTTS). Added
 *      PROVIDER_TIERS as the single source of truth for the diagnostic tier
 *      label each attempts.push() reports, so this ordering is machine-
 *      checkable instead of only true by construction.
 *   2. [FIX] Speechmatics' attempts[].tier literal was '1.5' (implying it
 *      runs between Tier 1 and Tier 2) but the code has always CALLED it
 *      after the Deepgram block — i.e. after Tier 2. The execution order
 *      itself is correct (spend the free one-time Deepgram credit before
 *      touching a metered provider) — only the label lied about it. Now
 *      reads '2.5' from PROVIDER_TIERS, matching real call order.
 *   3. [THE ACTUAL PRONUNCIATION FIX] renderedDialectFor() already documents
 *      that ElevenLabs renders Arabic as MSA-leaning regardless of the
 *      requested dialect — it has no ar-EG-specific model. Edge TTS
 *      (SalmaNeural/ShakirNeural) is the only tier with genuine Egyptian-
 *      dialect acoustic models, so priority-ordering ElevenLabs has no effect
 *      on dialect accuracy; only Edge TTS does. Checked buildEdgeSsml's wire
 *      format against the current reference client implementations
 *      (msedge-tts/ms-edge-tts): both set the outer <speak xml:lang> to the
 *      SELECTED VOICE's own locale, never a fixed value. This file hardcoded
 *      'en-US' on every request regardless of voice — for ar-EG-SalmaNeural
 *      that's a real mismatch against what genuine Edge traffic sends, and
 *      Microsoft's service is documented (rany2/edge-tts README, v5.0.0+) to
 *      reject any SSML shape it would not itself generate. Fixed: xml:lang
 *      now derives from the resolved voice name via the new edgeVoiceLocale()
 *      helper, and the missing xmlns:mstts declaration (present on every
 *      reference client's default template, even when unused) was added.
 *      Structure is still exactly one <voice>/<prosody> pair — the only
 *      shape Microsoft's service currently accepts — so this is a stricter
 *      match to genuine Edge output, not a new capability. Still blocked on
 *      the same real-network verification as v8 point 1 (this sandbox cannot
 *      reach speech.platform.bing.com) — confirm in a preview deploy.
 *   4. [CORRECTION, sourced] Deepgram's own current pricing page
 *      (deepgram.com/pricing, checked 2026-07-20) states the Pay-As-You-Go
 *      $200 credit has "No expiration" — contradicting the 1-year-lifetime
 *      assumption this file has carried since v7/tts-1.js. That 1-year term
 *      applies to Growth-plan ANNUAL pre-paid credits, not this credit; a
 *      few third-party sources conflate the two. Left ON by default (isDeep-
 *      gramExpired's behavior is UNCHANGED unless explicitly opted out) since
 *      this specific account's history can't be verified from here — added
 *      DEEPGRAM_CREDIT_EXPIRES=false as an explicit env override for once
 *      that's confirmed against the account's own dashboard.
 *   5. [CORRECTION, sourced, NOT wired in — see prose] Speechmatics' own
 *      pricing page (speechmatics.com/pricing) offers 8hrs/480min FREE per
 *      month, recurring — i.e. it fits 'recurring-monthly', the same bucket
 *      as ElevenLabs, not pure "real per-character cost" as previously
 *      labeled here. Comment corrected. Enablement/ordering deliberately NOT
 *      changed: Speechmatics auto-converts to billed usage on overage if a
 *      card is on file (unlike ElevenLabs, which just stops), so flipping
 *      ENABLE_SPEECHMATICS_TTS or reordering it ahead of Deepgram is a real-
 *      money decision for a human, not a default this file should silently
 *      change.
 *
 * ── HOW v10 GOT HERE ─────────────────────────────────────────────────────────
 * Requested: a strict 4-tier priority hierarchy — (1) recurring-monthly
 * default service until exhausted, (2) Google TTS as the unlimited
 * continuous provider, (3) one-time/welcome-quota reserve triggered ONLY by
 * Tier-2 429/outage, (4) a final fallback that cannot itself fail. This
 * REVERSES the v9-confirmed rule ("recurring-quota providers rank above
 * one-time-trial providers") for Deepgram specifically — stated plainly,
 * not silently, because v9 point 1 explicitly locked that ordering in one
 * revision ago. The reversal is deliberate and, on inspection, the more
 * defensible resource policy: v9's order spent Deepgram's non-renewing
 * one-time credit immediately on every Tier-1 miss, ahead of the free-
 * unlimited gTTS tier — burning an irreplaceable resource before a
 * replaceable one. v10 spends the free/unlimited tier first and holds the
 * one-time credit in reserve for when even that is degraded. "Google TTS"
 * here means the gTTS/Google Translate endpoint already implemented as the
 * old Tier 3 (fetchGoogleTTS) — confirmed against chat.js's own developer-
 * mode text, which separately lists "Google Cloud Text-to-Speech (not
 * Translate)" as a NEVER-integrated alternative requiring GOOGLE_TTS_API_KEY;
 * no such key or client exists anywhere in this file, and the official
 * product is quota/billing-bound, contradicting the "unlimited, no quota"
 * requirement. Per-item:
 *
 *   1. [RE-ARCHITECTURE] Cascade reordered: Group 0 (Edge TTS, unchanged,
 *      opt-in, off by default) -> Tier 1 (ElevenLabs) -> Tier 2 (gTTS,
 *      PROMOTED from old Tier 3) -> Tier 3 (Deepgram, then opt-in
 *      Speechmatics — DEMOTED from old Tier 2, now conditionally gated) ->
 *      Tier 4 (new — guaranteed local fallback). PROVIDER_TIERS relabeled
 *      to match; quotaModel gains 'always-available-local' for Tier 4.
 *   2. [ADDED] Tier 1 monthly-exhaustion cache. Previously every request
 *      re-attempted ElevenLabs even after a confirmed quota_exceeded body,
 *      paying a full round trip (and, with N keys all exhausted, N round
 *      trips) before falling through. isElevenLabsMonthlyExhausted() now
 *      short-circuits straight to Tier 2 once genuine exhaustion is seen,
 *      via a KV flag namespaced `tts:elevenlabs:quota:<UTC YYYY-MM>` — the
 *      calendar-month key means it self-clears at the next month boundary
 *      with no cron/reset code needed (mirrors the Deepgram lifetime clock's
 *      existing KV-flag pattern, one more read, no new binding). Gated
 *      strictly on a BODY-CONFIRMED quota signal (see point 3) — never on a
 *      bare status code — so one transient failure can't wrongly blacklist
 *      the tier for the rest of the month. Manual remedy if the account is
 *      topped up or upgraded mid-month: delete that KV key from CES_CHAT_KV
 *      via the dashboard to force an immediate retry; otherwise it clears
 *      itself at the next UTC month rollover.
 *   3. [CORRECTION, sourced] fetchElevenTTS's fallback hint mislabeled bare
 *      HTTP 429 as "ElevenLabs quota exceeded". Checked against ElevenLabs'
 *      own current error docs (elevenlabs.io/docs/eleven-api/resources/
 *      errors; help.elevenlabs.io API-Error-Code-429): 429 means
 *      rate_limit_exceeded, concurrent_limit_exceeded, or system_busy — all
 *      transient, all retryable, NONE of them quota exhaustion. The real
 *      quota signal is HTTP 401 with `detail.status === "quota_exceeded"`
 *      (confirmed against ElevenLabs' own docs and independently against a
 *      live user-reported 401 body in the wild). This distinction is now
 *      load-bearing, not cosmetic: point 2's monthly cache would otherwise
 *      blacklist ElevenLabs for a month over one concurrency blip. Fixed:
 *      the 429 hint now names it correctly as a transient limit; only a
 *      body-confirmed quota/credit message (readErrorBody's quotaMessage)
 *      sets the new quotaConfirmed flag that feeds the monthly cache. Either
 *      failure mode still fails over to Tier 2 for THIS request — only the
 *      month-long cache write is gated on the stricter signal.
 *   4. [FIX] fetchGoogleTTS previously threw a bare Error with no
 *      httpStatus/category — every other provider function in this file
 *      sets both. Harmless while gTTS was the unconditional final tier;
 *      load-bearing now, because Tier 3's trigger condition (429 or outage)
 *      and the subrequest budget both need to read those fields. Fixed, and
 *      added: (a) budget.take() — gTTS previously did not draw from the
 *      shared subrequest budget at all, safe when it ran once per exhausted
 *      request, not safe now that it runs on every Tier-1 miss; (b) response
 *      validation — an unofficial, unauthenticated endpoint under automated
 *      load can return HTTP 200 with an HTML interstitial/anti-abuse page
 *      instead of audio (this is a documented failure class for scraped
 *      Google endpoints generally, not something this specific file had
 *      re-verified against a live request from this sandbox — flagging
 *      that rather than asserting it). Previously this would have been
 *      silently served to the browser as "successful" broken audio with no
 *      fallback triggered. Now checked: Content-Type must contain "audio",
 *      and the body must clear a minimum plausible byte floor, or it's
 *      treated as a failure and handed to the same classification as any
 *      other gTTS error.
 *   5. [ADDED] isOutageOrRateLimited(err) — the single predicate gating
 *      Tier 3: true for HTTP 429, HTTP 5xx, or the 'network' sentinel
 *      (timeout/DNS/connection-level failures, the same sentinel
 *      rotateAndFetchTTS and fetchEdgeTTS already use). For gTTS
 *      specifically — keyless, unauthenticated, no request-shape the
 *      caller controls beyond `q`/`tl` — this is close to its entire
 *      realistic failure surface; there is no quota/auth-style failure mode
 *      for this endpoint the way there is for ElevenLabs. Stated plainly:
 *      the condition is implemented exactly as specified, not loosened to
 *      "any gTTS failure", even though in practice those two are nearly the
 *      same set for this particular provider.
 *   6. [ADDED] Tier 2 (gTTS) now participates in the KV circuit breaker
 *      (isCircuitOpen/recordOutcome, same mechanism, provider key 'gtts').
 *      Not applicable under v9 ("no circuit breaker: nothing to fall back
 *      to" — the old Tier-3-final comment, now removed because it's no
 *      longer true). A known-bad gTTS is now skipped outright rather than
 *      re-timing-out on every request, and — same as any circuit-open tier
 *      elsewhere in this file — that itself counts as satisfying point 5's
 *      condition, so Tier 3 still gets a chance while the circuit is open.
 *   7. [ADDED] Tier 4 — runFinalFallback(): tries one best-effort KV read
 *      (env.CES_CHAT_KV key `tts:tier4:cached_audio`, operator-populated
 *      `{base64, contentType}`, satisfies the spec's "cached default audio"
 *      half) and, on any miss/error/empty decode, falls through to a
 *      locally generated, dependency-free silent 16-bit PCM WAV (satisfies
 *      the "silent response" half). The WAV is built once per isolate
 *      (module-scope cache, same reuse pattern as ringPointers) and costs a
 *      DataView write over ~13KB, not a network call — genuinely
 *      sub-millisecond CPU time, unlike any tier before it. This path
 *      cannot throw barring a runtime-level failure; runTtsCascade's
 *      contract changes accordingly (point 8).
 *   8. [BEHAVIOR CHANGE] runTtsCascade no longer throws on the expected
 *      "every network tier failed" path — Tier 4 always resolves it. The
 *      GET/POST 502/503 catch blocks are retained as defense-in-depth for
 *      genuinely unexpected internal errors (a bug, not a provider outage),
 *      and are now expected to be effectively unreachable in normal
 *      operation rather than a routine "everything's down" outcome.
 *   9. [BREAKING — ENV VAR RENAME] Timeout env vars renamed to match the new
 *      tier numbers: TTS_TIER2_TIMEOUT_MS now governs gTTS (was
 *      TTS_GTTS_TIMEOUT_MS, default lowered 10000ms -> 7000ms — see prose
 *      below); TTS_TIER3_TIMEOUT_MS now governs Deepgram/Speechmatics (was
 *      TTS_TIER2_TIMEOUT_MS, default unchanged at 6000ms). Any deployment
 *      with these set to non-default values in the Cloudflare dashboard
 *      needs those values moved to the new names or they silently revert to
 *      default on this deploy. The 10000ms -> 7000ms default change on the
 *      gTTS slot is deliberate, not cosmetic: v9's comment justified 10s
 *      specifically because gTTS was the final tier ("a late success beats
 *      an early failure" — nothing else to try, so wait it out). That
 *      reasoning no longer holds now that Tier 3 and Tier 4 exist behind
 *      it; a long hang on Tier 2 now delays reaching them for no benefit.
 *  10. [RISK, stated for the record — see also the delivered risk analysis]
 *      Promoting gTTS to the primary continuous tier concentrates far more
 *      traffic onto an unofficial, unauthenticated, no-SLA endpoint than it
 *      carried as a last resort. Cloudflare Workers egress IPs are shared
 *      across unrelated tenants; rate-limiting Google applies to that
 *      shared IP space in response to OTHER customers' traffic is
 *      indistinguishable, from this code's position, from rate-limiting
 *      caused by this project's own volume. This is a real dependency
 *      concentration risk inherent to the requested reordering, not
 *      something this revision can engineer away — it is exactly why Tier 3
 *      and Tier 4 now matter architecturally rather than being decorative.
 *
 * ── SETUP ─────────────────────────────────────────────────────────────────
 *   ELEVEN_API_KEY(_1..12), DEEPGRAM_API_KEY(_1..12) — case-insensitive.
 *   Optional: ELEVEN_VOICE_ID_F / ELEVEN_VOICE_ID_M
 *   Optional, free up to 480min/mo then billed, off by default (see v9 point
 *     5): ENABLE_SPEECHMATICS_TTS=true
 *   Optional, off by default, see point 1: EDGE_TTS_ENABLED=true
 *   Optional, see point 4: IS_DEV=true
 *   Optional, see v8 point 3: DEEPGRAM_SIGNUP_DATE_ISO=2026-03-14 (or any
 *     Date.parse-able string) — precise alternative to first-use inference.
 *   Optional, default "true" (unchanged behavior), see v9 point 4:
 *     DEEPGRAM_CREDIT_EXPIRES=false — disables the proactive 1-year cutoff
 *     once confirmed against Deepgram's current account-level terms.
 *   Optional, all env-overridable, defaults shown:
 *     TTS_TIER0_TIMEOUT_MS=4000   (Edge TTS handshake+stream)
 *     TTS_TIER1_TIMEOUT_MS=6000   (ElevenLabs)
 *     TTS_TIER2_TIMEOUT_MS=6000   (Deepgram / opt-in Speechmatics)
 *     TTS_GTTS_TIMEOUT_MS=10000   (last resort — no fallback after this,
 *                                  so failing fast has no value; a late
 *                                  success beats an early failure)
 *     TTS_RATE_LIMIT_WINDOW_SECONDS=60
 *     TTS_RATE_LIMIT_MAX_PER_WINDOW=40
 *   Reused, no new binding beyond what chat.js/vision.js already need:
 *     env.CES_CHAT_KV (rate limiter, circuit breaker, Deepgram lifetime clock)
 *   Requires the v7+ rotation.mjs (checkRateLimit's third `opts` argument).
 *
 * ── RESPONSE HEADERS ─────────────────────────────────────────────────────
 *   X-TTS-Engine, X-TTS-Voice, X-TTS-KeyIndex/KeysTried, X-TTS-*-KeysAvailable
 *   X-TTS-Provider-Official  : "true" | "false" (Edge TTS and gTTS are unofficial)
 *   X-TTS-Dialect-Requested / X-TTS-Dialect-Rendered / X-TTS-Quality-Score
 *   X-TTS-Fallback / X-TTS-Fallback-Reason
 *   X-TTS-Dialect-Degraded   : ASCII "->" only — see point 5
 *   X-TTS-Request-Id, X-TTS-Latency-Ms : every response
 *
 * ── CSP NOTE ───────────────────────────────────────────────────────────────
 *   Audio served from /api/tts (same origin). media-src 'self' is correct.
 *   Edge TTS's outbound WebSocket happens server-side inside this Function —
 *   CSP is a browser mechanism and does not apply to it.
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

function intFromEnv(env, name, fallback) {
  const raw = env?.[name];
  const n = raw !== undefined ? parseInt(raw, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

// ── Allowed TTS languages ───────────────────────────────────────────────────
const ALLOWED_LANGS = new Set([
  'ar', 'ar-EG', 'ar-SA', 'ar-MA', 'ar-JO', 'ar-DZ', 'ar-IQ',
  'en', 'en-US', 'en-GB', 'en-AU',
]);

const MAX_TEXT_LENGTH = 200;

function isEnglish(lang) {
  return lang.toLowerCase().startsWith('en');
}

/** IS_DEV gate — see changelog point 4. */
function isDevMode(env) {
  return String(env?.IS_DEV ?? '').trim().toLowerCase() === 'true';
}

// ── ElevenLabs constants ────────────────────────────────────────────────────
const ELEVEN_API_URL    = 'https://api.elevenlabs.io/v1/text-to-speech';
const ELEVEN_MODEL      = 'eleven_multilingual_v2';
const ELEVEN_OUT_FORMAT = 'mp3_44100_128';
const ELEVEN_DEFAULT_F  = 'EXAVITQu4vr4xnSDxMaL';   // Bella (female)
const ELEVEN_DEFAULT_M  = 'pNInz6obpgDQGcFmaJgB';   // Adam  (male)
const ELEVEN_BASE_NAME  = 'ELEVEN_API_KEY';
// v8: ElevenLabs' own REST API reference documents 0.25-4.0 as the field's
// actual accepted range; 0.7-1.2 is where their Agents Platform UI clamps
// its slider, not a REST ceiling (checked directly — see changelog point 9).
// Kept at 0.7-1.2 anyway: ElevenLabs' own guidance is that extreme values
// degrade quality well before the technical limits, and this is a
// conservative, safe band, not a required one.
const ELEVEN_SPEED_MIN = 0.7;
const ELEVEN_SPEED_MAX = 1.2;

// ── Deepgram constants ──────────────────────────────────────────────────────
const DEEPGRAM_SPEAK_URL = 'https://api.deepgram.com/v1/speak';
// v8: fully-qualified model+voice+language string — see changelog point 7.
const DEEPGRAM_TTS_MODEL = 'aura-2-asteria-en';
const DEEPGRAM_BASE_NAME = 'DEEPGRAM_API_KEY';
// Deepgram Aura's REST API has no confirmed speed-control parameter — a
// `speed` request is silently NOT applied on this tier (documented rather
// than guessing at an unverified field name that could turn a working
// request into a 400).
const DEEPGRAM_SUPPORTS_SPEED = false;

// ── Speechmatics constants (opt-in; 480min/mo free, then billed if a card
//    is on file — see v9 changelog point 5) ────────────────────────────────
const SPEECHMATICS_TTS_URL_BASE = 'https://preview.tts.speechmatics.com/generate';
const SPEECHMATICS_TTS_VOICE    = 'sarah';
const SPEECHMATICS_BASE_NAME    = 'SPEECHMATICS_API_KEY';
const SPEECHMATICS_SUPPORTS_SPEED = false; // same reasoning as Deepgram above

// ── Edge TTS constants (Group 0) ───────────────────────────────────────────
// Endpoint/token/DRM algorithm verified against the rany2/edge-tts reference
// implementation's approach; the signature FUNCTION itself was independently
// re-run and checked in this pass (see changelog point 1) — the one thing
// that could not be checked is a real network round trip.
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

// Allowlisted explicitly — never interpolate a caller-supplied voice name
// into the SSML `<voice name='...'>` attribute.
const EDGE_VOICE_MAP = {
  'ar-EG': { female: 'ar-EG-SalmaNeural',   male: 'ar-EG-ShakirNeural' },
  'ar-SA': { female: 'ar-SA-ZariyahNeural', male: 'ar-SA-HamedNeural' },
  'ar-MA': { female: 'ar-MA-MounaNeural',   male: 'ar-MA-JamalNeural' },
  'ar-JO': { female: 'ar-JO-SanaNeural',    male: 'ar-JO-TaimNeural' },
  'ar-DZ': { female: 'ar-DZ-AminaNeural',   male: 'ar-DZ-IsmaelNeural' },
  'ar-IQ': { female: 'ar-IQ-RanaNeural',    male: 'ar-IQ-BasselNeural' },
  // Plain 'ar' (MSA) has no single canonical Edge locale; Saudi voices used
  // as the MSA-adjacent rendering.
  'ar'   : { female: 'ar-SA-ZariyahNeural', male: 'ar-SA-HamedNeural' },
  'en'   : { female: 'en-US-EmmaMultilingualNeural', male: 'en-US-AndrewMultilingualNeural' },
  'en-US': { female: 'en-US-EmmaMultilingualNeural', male: 'en-US-AndrewMultilingualNeural' },
  'en-GB': { female: 'en-GB-SoniaNeural',   male: 'en-GB-RyanNeural' },
  'en-AU': { female: 'en-AU-NatashaNeural', male: 'en-AU-WilliamNeural' },
};
const EDGE_VOICE_ALLOWLIST = new Set(
  Object.values(EDGE_VOICE_MAP).flatMap((v) => [v.female, v.male]),
);

// ── Dialect-rendering truth table (honest headers only — never changes routing) ─
function renderedDialectFor(provider, requestedLang) {
  const isArabic = requestedLang.toLowerCase().startsWith('ar');
  if (provider === 'edge_tts') {
    return { rendered: requestedLang, quality: 'neural', degraded: false };
  }
  if (provider === 'elevenlabs') {
    return isArabic
      ? { rendered: 'ar (MSA-leaning, model-dependent)', quality: 'neural-degraded', degraded: true }
      : { rendered: requestedLang, quality: 'neural', degraded: false };
  }
  if (provider === 'deepgram' || provider === 'speechmatics') {
    return { rendered: requestedLang, quality: 'neural', degraded: false };
  }
  // gTTS — MSA only, robotic.
  return isArabic
    ? { rendered: 'ar (MSA)', quality: 'robotic', degraded: true }
    : { rendered: requestedLang, quality: 'robotic', degraded: false };
}

// ── Text preprocessing ──────────────────────────────────────────────────────
function preprocessText(text) {
  return text
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ' ')
    .replace(/[٠١٢٣٤٥٦٧٨٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d).toString())
    .replace(/[۰۱۲۳۴۵۶۷۸۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d).toString())
    .replace(/[ \t]+/g, ' ')
    .trim();
}

/**
 * Full 5-entity XML escape for SSML text content (Edge TTS only — the sole
 * provider here building an SSML document; ElevenLabs/Deepgram/Speechmatics
 * take a JSON string field, gTTS a URL query param, both already correctly
 * escaped by JSON.stringify/URLSearchParams). Re-verified in this pass with
 * an injection attempt (`</voice><voice name='x'>`) — after escaping, zero
 * literal '<' or '>' survives, so the payload cannot break out of the
 * enclosing element.
 */
function escapeSsmlText(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function resolveVoiceId(genderKey, env) {
  if (genderKey === 'male') {
    return (env?.ELEVEN_VOICE_ID_M?.trim() || '') || ELEVEN_DEFAULT_M;
  }
  return (env?.ELEVEN_VOICE_ID_F?.trim() || '') || ELEVEN_DEFAULT_F;
}

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
  const clamped = Math.min(50, Math.max(-50, pct));
  return `${clamped >= 0 ? '+' : ''}${clamped}%`;
}

/** speed float -> ElevenLabs voice_settings.speed (clamped 0.7-1.2, see const comment above). */
function speedToElevenSpeed(speed) {
  return Math.min(ELEVEN_SPEED_MAX, Math.max(ELEVEN_SPEED_MIN, clampSpeed(speed)));
}

/**
 * Read a failed fetch Response body ONCE and pull out a quota/credit signal
 * if present.
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
 * case-insensitively.
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
// within a reused isolate; not relied on for correctness.
// v8: added `speechmatics` -- see changelog point 8.
const ringPointers = {
  eleven      : { i: 0 },
  deepgram    : { i: 0 },
  speechmatics: { i: 0 },
};

// ── Provider tier registry (v9) ────────────────────────────────────────────
// Single source of truth for the diagnostic `tier` label every
// attempts.push() below reports. Execution order in runTtsCascade is NOT
// driven by this table (the cascade is a fixed sequence of if-blocks, same
// as v8) -- this exists so the reported label can never drift out of sync
// with real call order the way the hand-typed '1.5' literal did for
// Speechmatics (it executes after Tier 2, but was labeled as if it ran
// between Tier 1 and 2 -- see v9 changelog point 2).
//
// quotaModel documents the business rule behind the ordering:
//   'unlimited-unofficial'      : no publisher-enforced quota (Edge TTS, gTTS)
//   'recurring-monthly'         : free allowance that resets every billing
//                                 cycle (ElevenLabs: 10k chars/mo)
//   'one-time-trial'            : a single non-renewing free allowance
//                                 (Deepgram: $200 signup credit)
//   'metered-recurring-partial' : free monthly allowance, then real billing
//                                 on overage if a card is on file
//                                 (Speechmatics: 480 free min/mo)
// Providers with 'recurring-monthly' or 'unlimited-unofficial' models are
// intentionally ordered ahead of 'one-time-trial' ones; a 'metered-*'
// provider is opt-in and its position is a cost decision, not a quota one --
// see v9 changelog point 5 for why that was not reordered here.
const PROVIDER_TIERS = Object.freeze({
  edge_tts    : { label: '0',   quotaModel: 'unlimited-unofficial' },
  elevenlabs  : { label: '1',   quotaModel: 'recurring-monthly' },
  deepgram    : { label: '2',   quotaModel: 'one-time-trial' },
  speechmatics: { label: '2.5', quotaModel: 'metered-recurring-partial' },
  gtts        : { label: '3',   quotaModel: 'unlimited-unofficial' },
});

/**
 * Generic round-robin + quota-failover walk over a provider's key ring.
 * Consults a shared subrequest `budget` (rotation.mjs's makeFetchBudget) and
 * stops trying further keys -- failing over to the NEXT TIER instead --
 * once the budget is exhausted, rather than risking the platform
 * hard-erroring the 51st subrequest on the Free plan.
 *
 * @param {{i:number}} pointerState
 * @param {string[]} keys
 * @param {(key: string) => Promise<{bytes:Uint8Array, contentType:string}>} singleFetchFn
 * @param {string} providerLabel
 * @param {{take: () => boolean, remaining: () => number}} budget
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

// Test-only export. Not used by any request-handling path -- exists so a
// test file can unit-test the subrequest-budget-exhaustion branch directly
// (48 real key attempts would be impractical to exercise end-to-end).
export { rotateAndFetchTTS as __rotateAndFetchTTSForTests };

// ── KV helpers ───────────────────────────────────────────────────────────
// Fail-open by design: any KV read/write error is swallowed and treated as
// "no state yet" — a KV outage must never itself take the TTS proxy down.
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

// ── Circuit breaker (KV-backed) ───────────────────────────────────────────
// HONEST CAVEAT: read-then-write, not atomic. Two concurrent requests can
// both read consecutiveFailures=2 and both write back 3 instead of reaching
// 4 -- a lost update. For a circuit BREAKER (not a hard billing cap) this is
// low-severity and self-healing: worst case a couple of extra requests
// reach an already-failing provider before the circuit opens a moment
// later. A Durable Object removes this race entirely if it's ever worth a
// new binding + migration this project does not currently have.
const CIRCUIT_FAIL_THRESHOLD = 3;
const CIRCUIT_OPEN_MS = 5 * 60 * 1000;

async function isCircuitOpen(env, provider, now = Date.now()) {
  const state = await kvGetJSON(env?.CES_CHAT_KV, `tts:circuit:${provider}`);
  return !!state && state.circuitOpenUntil > now;
}

/** Schedule with context.waitUntil so the KV write never delays the response. */
function recordOutcome(context, provider, success) {
  const env = context.env;
  const kv = env?.CES_CHAT_KV;
  if (!kv) return;
  const task = (async () => {
    const now = Date.now();
    const state = (await kvGetJSON(kv, `tts:circuit:${provider}`)) || { consecutiveFailures: 0, circuitOpenUntil: 0 };
    if (success) {
      // v8: skip the write entirely when there's nothing to reset. Without
      // this, a fully healthy system still spent one KV write per request
      // -- competing with rotation.mjs's own rate-limiter for the same
      // Free-plan 1,000-writes/day ceiling. Only a genuine RECOVERY (state
      // had recorded failures) needs to write anything; steady-state
      // healthy traffic is now read-only here.
      if (state.consecutiveFailures === 0 && state.circuitOpenUntil === 0) return;
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
    task.catch(() => {});
  }
}

// ── Deepgram lifetime clock ────────────────────────────────────────────────
// Deepgram's $200 signup credit does not renew and expires exactly 1 year
// after signup regardless of remaining balance. firstUsedAt is written ONCE,
// ever, on this tier's first successful call -- a single KV write for the
// resource's entire lifetime, not a hot per-request counter.
const DEEPGRAM_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000;
const DEEPGRAM_SAFETY_BUFFER_MS = 5 * 24 * 60 * 60 * 1000; // stop 5 days early

/**
 * v8: prefer an explicit DEEPGRAM_SIGNUP_DATE_ISO env override (the real
 * account-creation date) over inferring it from first proxy use, which can
 * lag the true signup date by however long this code went undeployed after
 * the account was created. Falls back to the original write-once
 * first-use tracking when unset -- fully backward compatible.
 */
async function getDeepgramClockStart(env) {
  const override = env?.DEEPGRAM_SIGNUP_DATE_ISO?.trim?.();
  if (override) {
    const parsed = Date.parse(override);
    if (Number.isFinite(parsed)) return parsed;
  }
  const state = await kvGetJSON(env?.CES_CHAT_KV, 'tts:deepgram:lifetime');
  return state?.firstUsedAt ?? null;
}

async function isDeepgramExpired(env, now = Date.now()) {
  // v9: default "true" reproduces v8's behavior exactly -- this only takes
  // effect if explicitly set to "false" once the 1-year assumption below is
  // confirmed against this specific account's actual terms (see v9 changelog
  // point 4: Deepgram's current public pricing states no expiration).
  const expiryEnabled = (env?.DEEPGRAM_CREDIT_EXPIRES ?? 'true').trim().toLowerCase() !== 'false';
  if (!expiryEnabled) return false;
  const clockStart = await getDeepgramClockStart(env);
  if (!clockStart) return false; // no override, never used yet -- nothing to expire
  return now >= (clockStart + DEEPGRAM_LIFETIME_MS - DEEPGRAM_SAFETY_BUFFER_MS);
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

// ── TIER 1 — ElevenLabs ──────────────────────────────────────────────────
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

// ── TIER 2 — Deepgram Aura-2, ENGLISH ONLY ────────────────────────────────
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

// ── OPT-IN ONLY — Speechmatics TTS (480min/mo free, then billed) ─────────
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

// ── FINAL SAFETY NET — Google Translate TTS ───────────────────────────────
async function fetchGoogleTTS(text, lang, speed, timeoutMs) {
  const url = new URL('https://translate.google.com/translate_tts');
  url.searchParams.set('ie',       'UTF-8');
  url.searchParams.set('client',   'tw-ob');
  url.searchParams.set('tl',       lang);
  url.searchParams.set('q',        text);
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

// ── GROUP 0 — Microsoft Edge TTS ────────────────────────────────────────────
// Every exit path (success, error, timeout) closes the WebSocket explicitly
// -- the one resource in this file the Workers runtime will not reclaim on
// its own within an invocation.

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
  return new Date().toUTCString();
}

/**
 * BCP-47 locale prefix of an Edge voice name, e.g. 'ar-EG-SalmaNeural' ->
 * 'ar-EG'. Every EDGE_VOICE_MAP entry follows the {lang}-{REGION}-{Name}
 * shape, and buildEdgeSsml is only ever called with a name that already
 * passed EDGE_VOICE_ALLOWLIST, so the 'en-US' fallback below is defensive,
 * not reachable in practice (verified against every current entry — see
 * __edgeVoiceLocaleForTests).
 */
function edgeVoiceLocale(voiceName) {
  const parts = String(voiceName).split('-');
  return parts.length >= 2 ? `${parts[0]}-${parts[1]}` : 'en-US';
}

/**
 * v9: xml:lang now matches the SELECTED VOICE's own locale instead of a
 * hardcoded 'en-US' — reference client implementations (msedge-tts,
 * ms-edge-tts) set this dynamically per voice, and Microsoft's service is
 * documented to reject SSML shapes it would not itself generate. xmlns:mstts
 * is declared (even though no mstts:-namespaced element is used here) because
 * every reference client's default template includes it. Structure is still
 * exactly one <voice> wrapping one <prosody> — the only shape currently
 * accepted — so this only tightens conformance, it doesn't add capability.
 */
function buildEdgeSsml(voiceName, escapedText, rate) {
  return (
    "<speak version='1.0' xmlns='http://www.w3.org/2001/10/synthesis' " +
    `xmlns:mstts='https://www.w3.org/2001/mstts' xml:lang='${edgeVoiceLocale(voiceName)}'>` +
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
 * Re-verified in this pass against hand-constructed synthetic frames,
 * including a >255-byte header case exercising the full two-byte length.
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
  // fingerprint headers (User-Agent/Origin/Cookie) alongside the upgrade
  // request -- confirmed against Cloudflare's own Workers docs.
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

      const wordBoundary = false;
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

// Test-only exports. Not used by any request-handling path -- these give
// the Edge TTS wire-protocol logic (the one thing in this file that cannot
// be verified against the real network from this environment) permanent
// regression coverage rather than a one-time, throwaway check.
export {
  parseEdgeTextFrame as __parseEdgeTextFrameForTests,
  parseEdgeBinaryFrame as __parseEdgeBinaryFrameForTests,
  escapeSsmlText as __escapeSsmlTextForTests,
  generateEdgeSecMsGec as __generateEdgeSecMsGecForTests,
  edgeVoiceLocale as __edgeVoiceLocaleForTests,
  buildEdgeSsml as __buildEdgeSsmlForTests,
};

// Test-only export (v9). isDeepgramExpired's new DEEPGRAM_CREDIT_EXPIRES
// branch and the pre-existing clock-math branch both need direct coverage —
// exercising the 1-year boundary through a real KV round trip isn't
// practical in a unit test.
export { isDeepgramExpired as __isDeepgramExpiredForTests };

// ── Shared cascade engine (one copy, used by GET and POST) ────────────────
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
  const edgeEnabled = (env?.EDGE_TTS_ENABLED || '').trim().toLowerCase() === 'true';

  const keyCountHeaders = {
    'X-TTS-Eleven-KeysAvailable'  : String(eleven.keys.length),
    'X-TTS-Deepgram-KeysAvailable': String(deepgram.keys.length),
  };

  const attempts = [];

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
      attempts.push({ tier: PROVIDER_TIERS.edge_tts.label, provider: 'edge_tts', reason: err.category || err.message });
    }
  } else if (edgeEnabled) {
    attempts.push({ tier: PROVIDER_TIERS.edge_tts.label, provider: 'edge_tts', reason: 'circuit open' });
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
      attempts.push({ tier: PROVIDER_TIERS.elevenlabs.label, provider: 'elevenlabs', reason: err.category || err.message });
    }
  } else if (eleven.keys.length > 0) {
    attempts.push({ tier: PROVIDER_TIERS.elevenlabs.label, provider: 'elevenlabs', reason: 'circuit open' });
  }

  // TIER 2 — Deepgram Aura-2, ENGLISH ONLY, skipped in dev (finite credit) or once lifetime-expired
  if (englishOnly && deepgram.keys.length > 0 && !devMode) {
    const expired = await isDeepgramExpired(env);
    if (expired) {
      attempts.push({ tier: PROVIDER_TIERS.deepgram.label, provider: 'deepgram', reason: 'lifetime credit pre-emptively expired' });
    } else if (await isCircuitOpen(env, 'deepgram')) {
      attempts.push({ tier: PROVIDER_TIERS.deepgram.label, provider: 'deepgram', reason: 'circuit open' });
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
        attempts.push({ tier: PROVIDER_TIERS.deepgram.label, provider: 'deepgram', reason: err.category || err.message });
      }
    }
  } else if (englishOnly && deepgram.keys.length > 0 && devMode) {
    attempts.push({ tier: PROVIDER_TIERS.deepgram.label, provider: 'deepgram', reason: 'skipped: IS_DEV (protects finite one-time credit)' });
  }

  // OPT-IN TIER — Speechmatics, ENGLISH ONLY, 480min/mo free then billed, skipped in dev
  if (englishOnly && speechmaticsEnabled && speechmatics.keys.length > 0 && !devMode) {
    if (await isCircuitOpen(env, 'speechmatics')) {
      attempts.push({ tier: PROVIDER_TIERS.speechmatics.label, provider: 'speechmatics', reason: 'circuit open' });
    } else {
      try {
        const { response: result, keyIndex, keysTried } = await rotateAndFetchTTS(
          ringPointers.speechmatics, speechmatics.keys,
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
        attempts.push({ tier: PROVIDER_TIERS.speechmatics.label, provider: 'speechmatics', reason: err.category || err.message });
      }
    }
  } else if (englishOnly && speechmaticsEnabled && speechmatics.keys.length > 0 && devMode) {
    attempts.push({ tier: PROVIDER_TIERS.speechmatics.label, provider: 'speechmatics', reason: 'skipped: IS_DEV (protects the 480min/mo free allowance from dev traffic)' });
  }

  // TIER 3 — Google Translate TTS (final safety net, always attempted, all langs, no circuit breaker: nothing to fall back to)
  try {
    const result = await fetchGoogleTTS(text, lang, speed, timeouts.tier3);
    recordOutcome(context, 'gtts', true);
    return {
      bytes: result.bytes, contentType: result.contentType, provider: 'gtts', providerOfficial: false,
      engineHeaders: { ...keyCountHeaders }, attempts, budgetRemaining: budget.remaining(),
    };
  } catch (err) {
    recordOutcome(context, 'gtts', false);
    attempts.push({ tier: PROVIDER_TIERS.gtts.label, provider: 'gtts', reason: err.message });
  }

  const finalErr = new Error('All TTS providers unavailable');
  finalErr.attempts = attempts;
  finalErr.keyCountHeaders = keyCountHeaders;
  throw finalErr;
}

/** Build the shared X-TTS-* diagnostic/degradation headers for a winning result. */
function buildResultHeaders(result, requestedLang) {
  const { rendered, quality, degraded } = renderedDialectFor(result.provider, requestedLang);
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
    // ASCII-only separator — see changelog point 5: a literal U+2192 arrow
    // in a header value throws at the Fetch/Headers API layer, confirmed
    // directly in this pass, not just carried over as a claim.
    headers['X-TTS-Dialect-Degraded'] = `${requestedLang}->${rendered}`;
  }
  return headers;
}

function logTtsEvent(fields) {
  try {
    console.log(JSON.stringify({ ts: new Date().toISOString(), ...fields }));
  } catch (_e) { /* logging must never break the response */ }
}

function rateLimitOpts(env) {
  return {
    windowSeconds: intFromEnv(env, 'TTS_RATE_LIMIT_WINDOW_SECONDS', 60),
    maxPerWindow : intFromEnv(env, 'TTS_RATE_LIMIT_MAX_PER_WINDOW', 40),
  };
}

function resolveTimeouts(env) {
  return {
    tier0: intFromEnv(env, 'TTS_TIER0_TIMEOUT_MS', 4000),
    tier1: intFromEnv(env, 'TTS_TIER1_TIMEOUT_MS', 6000),
    tier2: intFromEnv(env, 'TTS_TIER2_TIMEOUT_MS', 6000),
    tier3: intFromEnv(env, 'TTS_GTTS_TIMEOUT_MS', 10000),
  };
}

// ── GET handler (existing contract, byte-for-byte preserved) ──────────────
export async function onRequestGet(context) {
  const { request, env } = context;
  const requestId = crypto.randomUUID();
  const t0 = Date.now();
  const url = new URL(request.url);

  const rawText    = url.searchParams.get('text') || '';
  const langParam  = (url.searchParams.get('lang')  || 'ar-EG').trim();
  const voiceParam = (url.searchParams.get('voice') || 'female').toLowerCase().trim();
  const speedParam = url.searchParams.has('speed') ? Number(url.searchParams.get('speed')) : 1.0;

  const text = preprocessText(rawText);
  if (!text) {
    return jsonResponse(400, { error: 'Missing or empty text parameter.', requestId }, request, { 'X-TTS-Request-Id': requestId });
  }
  if (text.length > MAX_TEXT_LENGTH) {
    return jsonResponse(400, { error: `Text exceeds ${MAX_TEXT_LENGTH}-char limit. Caller must pre-chunk.`, requestId }, request, { 'X-TTS-Request-Id': requestId });
  }

  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateCheck = await checkRateLimit(env, `tts:${clientIp}`, rateLimitOpts(env));
  if (rateCheck?.limited) {
    return jsonResponse(429, { error: 'Too many TTS requests too quickly. Please wait a moment and try again.', requestId }, request, {
      'X-TTS-Request-Id': requestId, 'X-TTS-Latency-Ms': String(Date.now() - t0),
    });
  }

  const safeLang  = ALLOWED_LANGS.has(langParam) ? langParam : 'ar-EG';
  const genderKey = voiceParam === 'male' ? 'male' : 'female';

  try {
    const result = await runTtsCascade({
      text, lang: safeLang, genderKey, speed: speedParam, env, context,
      timeouts: resolveTimeouts(env),
    });
    logTtsEvent({ requestId, route: 'GET', lang: safeLang, provider: result.provider, fallback: result.attempts.length > 0, attempts: result.attempts, budgetRemaining: result.budgetRemaining });
    return new Response(result.bytes, {
      status: 200,
      headers: {
        'Content-Type' : result.contentType,
        'Cache-Control': 'public, max-age=3600',
        'X-TTS-Request-Id' : requestId,
        'X-TTS-Latency-Ms' : String(Date.now() - t0),
        ...buildResultHeaders(result, safeLang),
        ...getCorsHeaders(request),
      },
    });
  } catch (finalErr) {
    logTtsEvent({ requestId, route: 'GET', lang: safeLang, provider: null, fallback: true, attempts: finalErr.attempts, error: finalErr.message });
    return jsonResponse(502, {
      error: 'TTS service unreachable.',
      requestId,
      attempts: finalErr.attempts,
    }, request, { ...finalErr.keyCountHeaders, 'X-TTS-Request-Id': requestId, 'X-TTS-Latency-Ms': String(Date.now() - t0) });
  }
}

// ── POST handler (richer JSON interface, additive only — see changelog point 12) ──
export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = crypto.randomUUID();
  const t0 = Date.now();

  let body;
  try {
    body = await request.json();
  } catch (_e) {
    return jsonResponse(400, { error: 'Malformed JSON body.', requestId }, request, { 'X-TTS-Request-Id': requestId });
  }

  const rawText   = typeof body.text === 'string' ? body.text : '';
  const langParam = typeof (body.dialect ?? body.lang) === 'string' ? (body.dialect ?? body.lang).trim() : 'ar-EG';
  const genderRaw = typeof body.voice_gender === 'string' ? body.voice_gender.toLowerCase().trim() : 'female';
  const speedParam = body.speed !== undefined ? Number(body.speed) : 1.0;
  const formatParam = typeof body.format === 'string' ? body.format.toLowerCase().trim() : 'mp3';

  const text = preprocessText(rawText);
  if (!text) {
    return jsonResponse(400, { error: 'Missing or empty "text" field.', requestId }, request, { 'X-TTS-Request-Id': requestId });
  }
  if (text.length > MAX_TEXT_LENGTH) {
    return jsonResponse(400, { error: `Text exceeds ${MAX_TEXT_LENGTH}-char limit. Caller must pre-chunk.`, requestId }, request, { 'X-TTS-Request-Id': requestId });
  }

  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateCheck = await checkRateLimit(env, `tts:${clientIp}`, rateLimitOpts(env));
  if (rateCheck?.limited) {
    return jsonResponse(429, { error: 'Too many TTS requests too quickly. Please wait a moment and try again.', requestId }, request, {
      'X-TTS-Request-Id': requestId, 'X-TTS-Latency-Ms': String(Date.now() - t0),
    });
  }

  const safeLang  = ALLOWED_LANGS.has(langParam) ? langParam : 'ar-EG';
  const genderKey = genderRaw === 'male' ? 'male' : 'female';

  try {
    const result = await runTtsCascade({
      text, lang: safeLang, genderKey, speed: speedParam, env, context,
      timeouts: resolveTimeouts(env),
    });
    logTtsEvent({ requestId, route: 'POST', lang: safeLang, provider: result.provider, fallback: result.attempts.length > 0, attempts: result.attempts, budgetRemaining: result.budgetRemaining });

    const formatHeader = formatParam !== 'mp3' && !result.contentType.includes(formatParam)
      ? { 'X-TTS-Format-Note': `requested "${formatParam}", actual output is ${result.contentType}` }
      : {};

    return new Response(result.bytes, {
      status: 200,
      headers: {
        'Content-Type' : result.contentType,
        'Cache-Control': 'public, max-age=3600',
        'X-TTS-Request-Id' : requestId,
        'X-TTS-Latency-Ms' : String(Date.now() - t0),
        ...buildResultHeaders(result, safeLang),
        ...formatHeader,
        ...getCorsHeaders(request),
      },
    });
  } catch (finalErr) {
    logTtsEvent({ requestId, route: 'POST', lang: safeLang, provider: null, fallback: true, attempts: finalErr.attempts, error: finalErr.message });
    return jsonResponse(503, {
      error: 'All TTS providers unavailable',
      requestId,
      tiers_attempted: finalErr.attempts,
      retry_after: 60,
    }, request, { ...finalErr.keyCountHeaders, 'X-TTS-Request-Id': requestId, 'X-TTS-Latency-Ms': String(Date.now() - t0) });
  }
}

// ── OPTIONS preflight ──────────────────────────────────────────────────────
export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}
