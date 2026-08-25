/**
 * functions/api/tts.js  —  v12  (2026-07-29)
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
 * ── HOW v11 GOT HERE ─────────────────────────────────────────────────────────
 * Requested: "achieve normal natural voice" for Egyptian Arabic. This session
 * had live network access to raw.githubusercontent.com (unlike every prior
 * pass, which could reach only package registries) and used it to check
 * Group 0 — Edge TTS — against the current upstream rany2/edge-tts source,
 * the one thing v8/v9/v10 each flagged as unverifiable from their sandboxes.
 * Per-item:
 *
 *   1. [CORRECTION — header label] Top-of-file version line had read "v9"
 *      since v10's own changes landed — PROVIDER_TIERS, both handlers'
 *      catch-block comments, and half the changelog already said v10.
 *      Corrected to v11 here, not just bumped.
 *   2. [FIX, sourced against live upstream] EDGE_TTS_CHROMIUM_VERSION was
 *      '130.0.2849.68'. Fetched constants.py from rany2/edge-tts's master
 *      branch directly (raw.githubusercontent.com, allowlisted in this
 *      sandbox's egress) rather than trusting a cached blog post: current
 *      upstream value is '143.0.3650.75', with two independent intermediate
 *      bumps confirmed via release notes (PR #417 set 140.0.3485.14; a
 *      further bump to the 143 line landed after that). This constant only
 *      feeds the User-Agent string and the Sec-MS-GEC-Version query param —
 *      NOT the Sec-MS-GEC hash itself, which hashes only the 5-minute-
 *      bucketed timestamp and TRUSTED_CLIENT_TOKEN (confirmed by reading
 *      upstream's drm.py directly: no Chromium version enters that
 *      computation) — so this was a stale fingerprint, not a broken
 *      signature. Whether Microsoft's endpoint actually rejects the old
 *      fingerprint or just logs it oddly could not be determined without a
 *      live request either way; fixed regardless, since "match current
 *      genuine Edge traffic" is this file's own already-established standard
 *      (see v9 point 3's xml:lang fix — identical reasoning, same tier).
 *   3. [FIX, sourced against live upstream] upgradeHeaders was missing
 *      Sec-WebSocket-Version. Confirmed present in the current reference
 *      client's WSS_HEADERS (constants.py) and independently corroborated by
 *      the edge-tts-universal npm package's own changelog, which added it
 *      specifically because non-browser WebSocket clients don't send it the
 *      way a real browser's native WebSocket implementation does — and
 *      Cloudflare Workers' fetch()+Upgrade pattern is not a browser
 *      WebSocket client. Added as '13' (the only valid value per RFC 6455,
 *      so it cannot conflict with anything Workers' own runtime might also
 *      set on the handshake). Accept-Encoding was similarly absent here but
 *      present upstream ('gzip, deflate, br, zstd') — added for the same
 *      request-shape-fidelity reason as point 2; lower confidence this one
 *      matters (Workers may normalize this header on outbound fetch
 *      regardless), included because matching costs nothing and not
 *      matching is one more unverified variable sitting in front of Tier 1.
 *   4. [RE-ARCHITECTURE — the actual "natural voice" fix] EDGE_TTS_ENABLED
 *      flips from opt-in (default false) to opt-out (default true, the same
 *      `?? 'true' ... !== 'false'` idiom this file already uses for
 *      DEEPGRAM_CREDIT_EXPIRES). This is the one flag actually gating the
 *      outcome that was asked for: renderedDialectFor already documents, and
 *      nothing in this pass found reason to dispute, that Edge TTS
 *      (SalmaNeural/ShakirNeural) is the only tier in this file with a
 *      genuine ar-EG acoustic model — ElevenLabs renders Arabic MSA-leaning
 *      regardless of parameters (a training-data property, not a
 *      voice_settings knob — see point 5), and gTTS is flatly non-neural
 *      (see point 6). Leaving Group 0 off by default was the correct call
 *      across v8-v10 for exactly the reason each of those passes gave — an
 *      unverified live round trip — but that gap is now partially closed
 *      (points 2-3) rather than merely documented. It is NOT fully closed:
 *      this sandbox still cannot reach speech.platform.bing.com (egress
 *      remains limited to package registries plus raw.githubusercontent.com),
 *      so the WebSocket round trip itself, as opposed to the request-
 *      construction logic feeding it, is still unconfirmed — see the
 *      Resource Lifecycle / Verification note accompanying this revision.
 *      Blast radius if it is still broken for some other reason is bounded,
 *      not open-ended: TTS_TIER0_TIMEOUT_MS (4s default) caps the delay
 *      before falling through to Tier 1 exactly as before, and the existing
 *      KV circuit breaker (3 consecutive failures -> 5min open) suppresses
 *      repeat attempts after that — a still-broken Group 0 degrades to
 *      today's exact behavior plus at most a few extra seconds of latency on
 *      the first few requests, not an outage. First real verification is a
 *      preview deploy — unchanged advice from every prior pass, now against
 *      fixed request construction instead of known-stale construction.
 *   5. [ADDED, sourced] ElevenLabs' own current docs (elevenlabs.io/docs/
 *      api-reference/voices/settings/get-default; eleven-agents/customization/
 *      voice/best-practices/conversational-voice-design) place this file's
 *      hardcoded stability (0.75) inside their own documented "higher
 *      values… potentially monotonous" band, and recommend roughly 0.3-0.5
 *      for natural, non-monotonous delivery. similarity_boost (0.85) sat
 *      above ElevenLabs' own stated default (0.75) and inside the range
 *      independent sources flag for audible artifacts at long-form lengths.
 *      Neither change touches dialect accuracy (see point 4 — that is not a
 *      parameter this tier exposes) — this is strictly about the ElevenLabs
 *      fallback sounding less flat on however many requests still land on
 *      it. Both now read from env (ELEVEN_STABILITY, ELEVEN_SIMILARITY_BOOST)
 *      via the new floatFromEnv helper, defaulting to 0.45 / 0.75, so a
 *      Cloudflare-dashboard change doesn't need a redeploy to A/B. style
 *      stays hardcoded at 0.0 — ElevenLabs' own guidance is to leave it
 *      near-zero outside deliberately theatrical delivery, and nothing about
 *      "natural" calls for exaggeration.
 *   6. [FIX] fetchGoogleTTS's `tl` param was passed the full requested tag
 *      ('ar-EG') verbatim. Every working example of this undocumented
 *      endpoint found, including the one crowdsourced language table that
 *      tracks it (Google documents none of this), uses a bare base-language
 *      subtag ('ar', 'en') — not independently confirmed that 'ar-EG'
 *      specifically fails on this endpoint (no live request from this
 *      sandbox either), but the bare subtag is the only form actually
 *      evidenced to work, so this now sends `lang.split('-')[0]`. Stated
 *      plainly: this is a robustness fix, not a quality one — gTTS has
 *      exactly one Arabic voice regardless of which Arabic tag reaches it,
 *      so renderedDialectFor correctly keeps labeling this tier "ar (MSA),
 *      robotic" for every Arabic dialect, unchanged.
 *
 * ── HOW v12 GOT HERE ─────────────────────────────────────────────────────────
 * Requested: emotionally expressive prosody ("إنفعالية") to reduce the
 * flat/robotic quality of replies, at zero added cost. Per-item:
 *
 *   1. [ROOT CAUSE] Neither Edge TTS's buildEdgeSsml nor ElevenLabs'
 *      voice_settings varied AT ALL by message content prior to this pass
 *      -- Edge TTS's <prosody> always emitted the literal strings
 *      pitch='+0Hz' and volume='+0%' regardless of text, and `style` in
 *      the ElevenLabs body was a hardcoded 0.0 (see v11 point 5 -- a
 *      deliberate, well-reasoned choice for a DIFFERENT problem, dialect-
 *      neutral "naturalness," not this one). Separately, the front-end's
 *      splitForProxy() already chunks every reply into ~200-char pieces
 *      before this endpoint ever sees them and its browser-TTS fallback
 *      (speakChunks) hardcodes utt.pitch=1.0 unconditionally -- so the
 *      flatness this pass addresses existed on both the primary proxy path
 *      and the last-resort browser path, in three independent hardcoded
 *      spots, not one.
 *   2. [ADDED] inferProsody(): a small, zero-dependency, zero-latency
 *      lexicon+punctuation classifier (see its own doc-comment for the
 *      full rationale, including why substring match over \b-word-boundary
 *      regex, and the explicit false-negative on negation e.g. "لا يوجد
 *      خطأ"). Categorizes into neutral/excited/empathetic/warning plus an
 *      additive question modifier, each mapped to small, individually-
 *      justified pitch/rate/volume/style/stability deltas in
 *      PROSODY_PROFILES -- `neutral` is the exact zero vector, so text
 *      matching no lexicon entry reproduces today's flat output exactly,
 *      not an approximation of it.
 *   3. [VERIFIED, sourced against live upstream -- same standard as v11
 *      points 2-3] Edge TTS's <prosody> pitch/volume string format was NOT
 *      assumed: fetched data_classes.py from rany2/edge-tts's master
 *      branch directly (raw.githubusercontent.com, allowlisted) and read
 *      TTSConfig.__post_init__'s actual validation regexes --
 *      rate/volume: ^[+-]\d+%$, pitch: ^[+-]\d+Hz$, all three always
 *      signed integers, matching exactly what hzToEdgeProsody/
 *      pctToEdgeProsody now emit. communicate.py's mkssml() confirms the
 *      accepted SSML shape is still exactly one <voice>/<prosody> pair
 *      with all three attributes on it (pitch/rate/volume together) --
 *      the reference client never emits <break>/<emphasis>/multiple
 *      <prosody> runs, so this pass does not add them either: extending
 *      the one already-verified-accepted element with two more attributes
 *      is a materially smaller, more defensible bet than adding new SSML
 *      element types this codebase has zero evidence Microsoft's consumer
 *      endpoint (as opposed to full Azure Cognitive Services SSML) accepts.
 *      What is NOT verified, same standing caveat as v11 point 4: an
 *      actual network round trip, still unreachable from this sandbox
 *      (speech.platform.bing.com is not on the egress allowlist here
 *      either). First real verification is a preview deploy with a
 *      before/after audio diff on a few chunks per PROSODY_PROFILES
 *      category, same standard as every prior Edge TTS pass.
 *   4. [SAFETY CEILINGS] PROSODY_*_MAX consts bound inferProsody()'s output
 *      independent of the authored PROSODY_PROFILES values -- worked
 *      arithmetic: worst case is `excited` + question modifier + jitter =
 *      pitch 14+6+3=23Hz (ceiling 30), rate 8+2=10% (ceiling 20, and this
 *      composes ADDITIVELY with any caller-supplied `speed` inside
 *      speedToEdgeRate's pre-existing ±50% ceiling, so an adversarial
 *      speed+excited combination still can't exceed what this function
 *      already enforced pre-v12), volume 6+2=8% (ceiling 15). All four
 *      ceilings are env-overridable (nonNegFloatFromEnv, new in this pass,
 *      generalizes floatFromEnv beyond its hardcoded [0,1] band) for the
 *      same "A/B without a redeploy" reason v11 point 5 made stability/
 *      similarity_boost env-overridable.
 *   5. [ELEVENLABS] style is no longer hardcoded 0.0; it now receives
 *      PROSODY_PROFILES[emotion].elevenStyle, capped at PROSODY_STYLE_MAX
 *      (0.30 default). This does not contradict v11 point 5's "leave it
 *      near-zero outside deliberately theatrical delivery" -- the default
 *      (neutral) path is still exactly 0.0; style only rises for text this
 *      pass's lexicon actually classifies as excited (0.18) or empathetic
 *      (0.05), and 0.30 stays well short of ElevenLabs' own "theatrical"
 *      framing. stability is now nudged by a small per-category delta
 *      (±0.05-0.08) that keeps the effective value inside [0.35, 0.55] --
 *      entirely inside ElevenLabs' own cited 0.3-0.5 "natural" band from
 *      v11 point 5, never approaching their cited 0.75 "monotonous" one.
 *      NOTE: ElevenLabs is Tier 1 (after Edge TTS), so in the now-typical
 *      case where Group 0 answers, this tier's prosody handling is a
 *      fallback safety net, not the primary experience -- see point 6.
 *   6. [CONSIDERED, NOT ADOPTED] ElevenLabs' eleven_v3 model supports
 *      inline bracketed audio tags ([excited], [whispers], [sighs]) with
 *      confirmed Arabic support -- a materially richer expressiveness
 *      mechanism than voice_settings alone. Not adopted this pass: (a) it
 *      is a different model from this file's ELEVEN_MODEL
 *      ('eleven_multilingual_v2', explicitly documented elsewhere as ElevenLabs'
 *      "most stable" option vs v3's expressiveness-first, still-maturing
 *      positioning), a model swap on the PAID/quota-metered fallback tier
 *      is a bigger decision than this zero-cost prosody pass scoped for;
 *      (b) audio tags are additional characters billed against the same
 *      10k-char/month free allowance this file already carefully guards
 *      (isElevenLabsMonthlyExhausted et al.) -- "zero marginal cost" stops
 *      being true once tags meaningfully inflate character counts; (c) no
 *      live-request verification of latency/quality on THIS file's stock
 *      voice IDs was possible from this sandbox. Left as a flagged,
 *      deliberately-not-taken option -- see the response accompanying this
 *      revision -- rather than silently adopted or silently ignored.
 *   7. [FRONT-END, pc_suite_v35-4-1-2.html, companion change] Ported a
 *      same-logic prosody classifier into the browser-TTS fallback
 *      (speakChunks) so utt.pitch/utt.rate vary the same way the proxy
 *      path's SSML does, and made playChunksViaProxy's fixed 130ms
 *      inter-chunk pause vary slightly by the JUST-FINISHED chunk's
 *      trailing punctuation (longer after ./؟/!, shorter after ،/,).
 *      Zero new network calls either way. chat-17_fixed.js was checked and
 *      contains no /api/tts call site (it is the /api/chat reply-generation
 *      function, not the TTS client) -- correctly out of scope, left
 *      untouched. stt.js is speech-to-text, unrelated, also untouched.
 *
 * ── SETUP ─────────────────────────────────────────────────────────────────
 *   ELEVEN_API_KEY(_1..12), DEEPGRAM_API_KEY(_1..12) — case-insensitive.
 *   Optional: ELEVEN_VOICE_ID_F / ELEVEN_VOICE_ID_M
 *   Optional, free up to 480min/mo then billed, off by default (see v9 point
 *     5): ENABLE_SPEECHMATICS_TTS=true
 *   Optional, default true as of v11 (point 4) — set to the literal string
 *     "false" to opt back out: EDGE_TTS_ENABLED=false
 *   Optional, see point 4: IS_DEV=true
 *   Optional, see v8 point 3: DEEPGRAM_SIGNUP_DATE_ISO=2026-03-14 (or any
 *     Date.parse-able string) — precise alternative to first-use inference.
 *   Optional, default "true" (unchanged behavior), see v9 point 4:
 *     DEEPGRAM_CREDIT_EXPIRES=false — disables the proactive 1-year cutoff
 *     once confirmed against Deepgram's current account-level terms.
 *   Optional, v11 — ElevenLabs voice_settings, see point 5, defaults shown:
 *     ELEVEN_STABILITY=0.45
 *     ELEVEN_SIMILARITY_BOOST=0.75
 *   Optional, v12 -- prosody-inference safety ceilings, see "HOW v12 GOT
 *     HERE" point 4, defaults shown (tightening these is always safe;
 *     loosening past the authored PROSODY_PROFILES deltas has no further
 *     effect since the ceiling would no longer be the binding constraint):
 *     TTS_PROSODY_PITCH_MAX_HZ=30
 *     TTS_PROSODY_RATE_MAX_PCT=20
 *     TTS_PROSODY_VOLUME_MAX_PCT=15
 *     TTS_PROSODY_STYLE_MAX=0.30
 *     TTS_PROSODY_STABILITY_DELTA_MAX=0.10
 *   Optional, v12 -- POST body field / GET query param, both default "auto":
 *     emotion=neutral|excited|empathetic|warning|auto -- forces
 *     inferProsody()'s category instead of running the lexicon scorer; an
 *     unrecognized value silently falls back to "auto" (see inferProsody's
 *     forcedEmotion guard).
 *   Optional, all env-overridable, defaults shown:
 *     TTS_TIER0_TIMEOUT_MS=4000   (Edge TTS handshake+stream)
 *     TTS_TIER1_TIMEOUT_MS=6000   (ElevenLabs)
 *     TTS_TIER2_TIMEOUT_MS=7000   (gTTS — v10 RENAME, was TTS_GTTS_TIMEOUT_MS;
 *                                  default also lowered from 10000, see v10
 *                                  point 9 — no longer the last tier, so a
 *                                  long hang here just delays Tier 3/4)
 *     TTS_TIER3_TIMEOUT_MS=6000   (Deepgram / opt-in Speechmatics — v10
 *                                  RENAME, was TTS_TIER2_TIMEOUT_MS)
 *     TTS_RATE_LIMIT_WINDOW_SECONDS=60
 *     TTS_RATE_LIMIT_MAX_PER_WINDOW=40
 *   v10, optional, no new binding: env.CES_CHAT_KV key
 *     `tts:tier4:cached_audio` = JSON {"base64":"<audio bytes>",
 *     "contentType":"audio/mpeg"} — operator-populated "cached default
 *     audio" override for Tier 4. Unset is fully supported and is the
 *     default: Tier 4 then serves a generated silent WAV, never a failure.
 *   Reused, no new binding beyond what chat.js/vision.js already need:
 *     env.CES_CHAT_KV (rate limiter, circuit breakers incl. new 'gtts' key,
 *     Deepgram lifetime clock, v10: ElevenLabs monthly-exhaustion cache,
 *     v10: Tier 4 cached-audio override)
 *   Requires the v7+ rotation.mjs (checkRateLimit's third `opts` argument).
 *
 * ── RESPONSE HEADERS ─────────────────────────────────────────────────────
 *   X-TTS-Engine, X-TTS-Voice, X-TTS-KeyIndex/KeysTried, X-TTS-*-KeysAvailable
 *   X-TTS-Provider-Official  : "true" | "false" (Edge TTS, gTTS, and the v10
 *                              Tier-4 fallback are all unofficial/local)
 *   X-TTS-Dialect-Requested / X-TTS-Dialect-Rendered / X-TTS-Quality-Score
 *   X-TTS-Fallback / X-TTS-Fallback-Reason
 *   X-TTS-Dialect-Degraded   : ASCII "->" only — see point 5
 *   X-TTS-Guaranteed-Fallback : "true", v10, present ONLY when Tier 4 served
 *                               the response — the signal worth alerting on
 *   X-TTS-Request-Id, X-TTS-Latency-Ms : every response
 *   X-TTS-Prosody-Emotion/-Pitch/-Rate/-Volume/-Style : v12, every response
 *                              from edge_tts or elevenlabs (ASCII-only
 *                              values -- see v8 changelog point 5)
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

/**
 * v11: parallel to intFromEnv, for the new ElevenLabs voice_settings
 * overrides. Clamped to [0, 1] -- both stability and similarity_boost are
 * documented 0-1 fields; a typo'd env value (e.g. "45" meaning 0.45) fails
 * closed to `fallback` rather than silently sending an out-of-range float
 * ElevenLabs would 422 on.
 */
function floatFromEnv(env, name, fallback) {
  const raw = env?.[name];
  const n = raw !== undefined ? parseFloat(raw) : NaN;
  return Number.isFinite(n) && n >= 0 && n <= 1 ? n : fallback;
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
// v11 point 5: was hardcoded 0.75/0.85. ElevenLabs' own docs place 0.75
// stability inside their documented "higher values… potentially monotonous"
// band and recommend ~0.3-0.5 for natural, non-monotonous delivery;
// similarity_boost 0.85 sat above ElevenLabs' own stated default (0.75).
// Env-overridable via floatFromEnv (ELEVEN_STABILITY / ELEVEN_SIMILARITY_BOOST).
const ELEVEN_STABILITY_DEFAULT = 0.45;
const ELEVEN_SIMILARITY_BOOST_DEFAULT = 0.75;

// ── v12: Prosody-inference constants ────────────────────────────────────────
// Ceilings on how far inferProsody() is allowed to push any one request away
// from today's flat baseline (pitch/rate/volume delta magnitude, ElevenLabs
// style, ElevenLabs stability delta). Deliberately conservative and
// independent of any single category's authored values below (see
// PROSODY_PROFILES) -- these exist so a bad lexicon edit or a mis-set env
// override fails closed into "slightly off" rather than "audibly broken."
// Same idiom as ELEVEN_SPEED_MIN/MAX: a safe band, not a hard technical
// ceiling (Edge TTS's own validator -- confirmed directly against
// rany2/edge-tts's data_classes.py TTSConfig.__post_init__ in this pass,
// not assumed -- accepts any integer Hz/percent with a sign, e.g. "+999Hz"
// would pass ITS regex; the tighter numbers below are this file's own
// quality judgment, not Microsoft's ceiling).
const PROSODY_PITCH_MAX_HZ    = 30;   // env: TTS_PROSODY_PITCH_MAX_HZ
const PROSODY_RATE_MAX_PCT    = 20;   // env: TTS_PROSODY_RATE_MAX_PCT (additive with `speed`, pre-existing ±50% Edge ceiling in speedToEdgeRate still applies after combining)
const PROSODY_VOLUME_MAX_PCT  = 15;   // env: TTS_PROSODY_VOLUME_MAX_PCT
const PROSODY_STYLE_MAX       = 0.30; // env: TTS_PROSODY_STYLE_MAX -- ElevenLabs' own guidance (see v11 point 5 above) is near-zero outside deliberately theatrical delivery; 0.30 stays well short of "theatrical," see PROSODY_PROFILES.excited below (0.18) for the actual authored ceiling this cap is guarding against a bad override.
const PROSODY_STABILITY_DELTA_MAX = 0.10; // keeps stability inside [0.35, 0.55] given the 0.45 default -- entirely inside ElevenLabs' own cited 0.3-0.5 "natural, non-monotonous" band, never approaching the 0.75 "monotonous" band their docs flag.

/**
 * Per-category authored deltas. Values are *deltas* added to today's flat
 * baseline (pitch +0Hz, volume +0%, style 0.0, stability unchanged), not
 * replacement values, so text matching no lexicon entry (`neutral`)
 * reproduces exactly today's output -- the zero-regression case is the
 * literal zero vector, not a fifth code path.
 */
const PROSODY_PROFILES = Object.freeze({
  neutral: {
    pitchHz: 0, ratePct: 0, volumePct: 0, elevenStyle: 0.0, stabilityDelta: 0,
  },
  // Good news, confirmations, congratulations. Pitch is the dominant
  // arousal cue in vocal-emotion-acoustics literature (more than loudness),
  // so it carries most of this profile's weight; rate/volume move less.
  excited: {
    pitchHz: 14, ratePct: 8, volumePct: 6, elevenStyle: 0.18, stabilityDelta: -0.05,
  },
  // Apologies, delays, bad news, expressions of understanding. Softer and
  // slower reads as sincerity; stability moves UP (steadier), not down --
  // an unstable "sorry" reads as nervous, not warm.
  empathetic: {
    pitchHz: -8, ratePct: -6, volumePct: -4, elevenStyle: 0.05, stabilityDelta: 0.05,
  },
  // Warnings, error text, "must/required" language, safety-relevant civil-
  // engineering caveats. Slower and marginally firmer, explicitly NOT
  // exaggerated (style stays at today's 0.0) -- a theatrical warning reads
  // as less credible, not more.
  warning: {
    pitchHz: -4, ratePct: -8, volumePct: 3, elevenStyle: 0.0, stabilityDelta: 0.08,
  },
});
// Additive modifier, not a fifth exclusive category -- a question can also
// be excited/empathetic/warning-flavored. Approximates the rising terminal
// contour of an Arabic/English yes-no or wh-question with a whole-utterance
// pitch nudge (see inferProsody's own comment for why a true per-word
// rising SSML <prosody contour=...> was rejected for this pass).
const PROSODY_QUESTION_PITCH_HZ = 6;
// Per-request cosmetic jitter -- NOT emotion-derived, purely anti-monotony
// (two consecutive `neutral` chunks should not sound bit-for-bit identical).
// Small enough that the PROSODY_*_MAX headroom above always has margin left
// even at max(|category delta|) + question + jitter combined -- see the
// worked arithmetic in the v12 changelog entry.
const PROSODY_JITTER_PITCH_HZ = 3;
const PROSODY_JITTER_RATE_PCT = 2;
const PROSODY_JITTER_VOLUME_PCT = 2;

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
const EDGE_TTS_CHROMIUM_VERSION = '143.0.3650.75'; // v11: was '130.0.2849.68' — see changelog point 2
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
  // v10: Tier 4 guaranteed fallback -- explicit case so this doesn't fall
  // into the gTTS/MSA branch below and get mislabeled "robotic" with an
  // Arabic-specific rendering note that doesn't apply to silence.
  if (provider === 'fallback_final') {
    return { rendered: 'silent', quality: 'silent', degraded: true };
  }
  // gTTS — MSA only, robotic.
  return isArabic
    ? { rendered: 'ar (MSA)', quality: 'robotic', degraded: true }
    : { rendered: requestedLang, quality: 'robotic', degraded: false };
}

// ── Text preprocessing ──────────────────────────────────────────────────────
// [PATCH] True-Unicode super/subscript -> plain ASCII, reverse direction
// from notationNormalizer.mjs's toSubscriptForm/toSuperscriptForm. Needed
// here because this endpoint's job is speakable text, not typography:
// five different engines (Edge/Eleven/Deepgram/Speechmatics/gTTS) each
// have their own undocumented, near-certainly inconsistent handling of
// exotic subscript/superscript codepoints -- not verifiable from this
// sandbox against real audio output (network egress here is limited to
// package registries, same constraint already noted above for Edge TTS).
// Normalizing to plain ASCII sidesteps guessing at five black boxes.
const SUPERSUB_TO_ASCII = Object.freeze({
  '\u2080':'0','\u2081':'1','\u2082':'2','\u2083':'3','\u2084':'4',
  '\u2085':'5','\u2086':'6','\u2087':'7','\u2088':'8','\u2089':'9',
  '\u208A':'+','\u208B':'-','\u208C':'=','\u208D':'(','\u208E':')',
  '\u2090':'a','\u2091':'e','\u2095':'h','\u1D62':'i','\u2C7C':'j',
  '\u2096':'k','\u2097':'l','\u2098':'m','\u2099':'n','\u2092':'o',
  '\u209A':'p','\u1D63':'r','\u209B':'s','\u209C':'t','\u1D64':'u',
  '\u1D65':'v','\u2093':'x',
  '\u2070':'0','\u00B9':'1','\u00B2':'2','\u00B3':'3','\u2074':'4',
  '\u2075':'5','\u2076':'6','\u2077':'7','\u2078':'8','\u2079':'9',
  '\u207A':'+','\u207B':'-','\u207C':'=','\u207D':'(','\u207E':')',
});
const SUPERSUB_RE = new RegExp('[' + Object.keys(SUPERSUB_TO_ASCII).join('') + ']', 'g');

// [ADDED] Fenced ```...``` code blocks and inline `...` spans -- mirrors
// the client's _cesStripCodeMarkers (see that function's own comment for
// the empirical case that motivated it: a Dev-mode reply embedding a JS
// snippet whose string/regex literals used `\frac`, `\left(`, `\\`, and
// `$`, every one of which survived every other pass in this file and was
// read verbatim). This endpoint has no 'plain'/download mode to spare, so
// unlike the client's version this one always applies.
const CODE_FENCE_RE = /```[A-Za-z0-9_-]*\r?\n?[\s\S]*?```/g;
const INLINE_CODE_RE = /`([^`\r\n]+)`/g;
function stripCodeMarkers(text) {
  const isAr = /[\u0600-\u06FF]/.test(text);
  return text
    .replace(CODE_FENCE_RE, isAr ? ' كود برمجي ' : ' code block ')
    // [ADDED] Routed through the same math resolver a live $...$ span
    // gets, not a bare unwrap -- mirrors the client's identical change to
    // _cesStripCodeMarkers; see that function's own comment.
    .replace(INLINE_CODE_RE, (_m, code) => resolveMathInnerForSpeech(code, isAr));
}

// Marker fallback (base_sub, base_{sub}, base^sup, base^{sup}) is meant
// for the frontend's <sub>/<sup> HTML upgrade in _cesRenderBotHtml
// (footing_pro/pc_suite) -- there's no HTML here for it to upgrade into,
// so it's collapsed to a plain space instead: correct for every engine
// because it's just whitespace. Same character classes as
// notationNormalizer.mjs's LATEX_SUBSCRIPT_RE/LATEX_SUPERSCRIPT_RE and
// _cesRenderBotHtml's mirror of them -- keep these three in sync if any
// changes.
function stripSuperSubMarkers(text) {
  return text
    .replace(/([A-Za-z\u03B2\u03B3\u03B5\u03BB\u03C1\u03C4\u03C8])[_^]\{([A-Za-z0-9+\-=()]{1,8})\}/g, '$1 $2')
    .replace(/([A-Za-z0-9\u03B2\u03B3\u03B5\u03BB\u03C1\u03C4\u03C8])[_^]([A-Za-z0-9+\-]{1,3})(?![A-Za-z0-9])/g, '$1 $2')
    .replace(SUPERSUB_RE, ch => SUPERSUB_TO_ASCII[ch]);
}

// [PATCH — LaTeX read-aloud fix, defense-in-depth] chat.js's NOTATION rule
// now has the model wrap every math symbol in real LaTeX ($...$/$$...$$,
// \frac{}{}, \left(...\right), \sqrt{}, \cdot, \phi, etc.) for the client's
// KaTeX renderer. speakText() in pc_suite_v71.html / footing_pro_v71.html
// (same function names, byte-identical in both — see that pair's own
// header comment) already flattens this to natural words BEFORE ever
// calling this endpoint, so in the normal flow the pass below is
// redundant by design. It exists here purely as defense-in-depth for any
// caller that reaches onRequestGet/onRequestPost directly with un-flattened
// LaTeX still in `text` — the GET query-param entry point in particular has
// no client-side pass in front of it at all, and this endpoint has no way
// to know whether a given caller ran one. Same bounded, finite-construct-
// set scope as every other pass in this file and in notationNormalizer.mjs
// — not a LaTeX parser. Mirrors that client pair's _cesResolveMathInner /
// _cesFlattenMathSpans (mode:'speech') construct-for-construct; keep the
// two in sync if either changes.
const GREEK_MACRO_SPEECH_WORDS = {
  '\\alpha': { ar: 'ألفا', en: 'alpha' }, '\\beta': { ar: 'بيتا', en: 'beta' },
  '\\gamma': { ar: 'جاما', en: 'gamma' }, '\\delta': { ar: 'دلتا', en: 'delta' },
  '\\Delta': { ar: 'دلتا', en: 'delta' }, '\\phi': { ar: 'فاي', en: 'phi' },
  '\\rho': { ar: 'رو', en: 'rho' }, '\\lambda': { ar: 'لامدا', en: 'lambda' },
  '\\mu': { ar: 'ميو', en: 'mu' }, '\\sigma': { ar: 'سيجما', en: 'sigma' },
  '\\tau': { ar: 'تاو', en: 'tau' }, '\\psi': { ar: 'باي', en: 'psi' },
  '\\epsilon': { ar: 'إبسيلون', en: 'epsilon' }, '\\varepsilon': { ar: 'إبسيلون', en: 'epsilon' },
  '\\pi': { ar: 'باي', en: 'pi' }, '\\theta': { ar: 'ثيتا', en: 'theta' },
  '\\omega': { ar: 'أوميجا', en: 'omega' }, '\\Omega': { ar: 'أوميجا', en: 'omega' },
  // [ADDED] \Phi/\eta -- mirrors the client's identical addition; see that
  // table's comment for the empirical case (capital-Phi as this domain's
  // rebar-diameter symbol) and the reasoning for reusing \phi's word.
  '\\Phi': { ar: 'فاي', en: 'Phi' }, '\\eta': { ar: 'إيتا', en: 'eta' },
};
const GREEK_MACRO_SPEECH_RE = /\\(?:alpha|beta|gamma|delta|Delta|phi|rho|lambda|mu|sigma|tau|psi|varepsilon|epsilon|pi|theta|omega|Omega|Phi|eta)(?![A-Za-z])/g;
// One level of nested braces (see the client's identical comment on its own
// CES_FRAC_RE/CES_SQRT_RE/CES_SUP_RE) — a subscript inside a frac numerator
// (\frac{M_{cr}}{M_a}) is routine in real replies; a plain [^{}]* argument
// class would refuse to match it and leave the whole \frac un-flattened.
const FRAC_SPEECH_RE = /\\frac\{((?:[^{}]|\{[^{}]*\})*)\}\{((?:[^{}]|\{[^{}]*\})*)\}/g;
const SQRT_SPEECH_RE = /\\sqrt\{((?:[^{}]|\{[^{}]*\})*)\}/g;
// [ADDED] \sqrt[n]{...} (nth root) -- SQRT_SPEECH_RE above requires \sqrt{
// immediately, so \sqrt[3]{8} (bracketed order argument) never matched it
// and fell through to the generic backslash/brace-strip safety net at the
// end of flattenLatexForSpeech as the broken, literal "sqrt[3]8" (verified
// empirically before this fix). Mirrors the client's CES_NTH_ROOT_RE.
const NTH_ROOT_SPEECH_RE = /\\sqrt\[((?:[^\[\]]|\[[^\[\]]*\])*)\]\{((?:[^{}]|\{[^{}]*\})*)\}/g;
const SUP_SPEECH_RE = /\^\{((?:[^{}]|\{[^{}]*\})*)\}|\^([+\-0-9A-Za-z])(?![A-Za-z0-9])/g;
// [ADDED] \text{}/\mathrm{}/\mathbf{}/\mathit{}/\boldsymbol{}/\overline{}/
// \bar{}/\hat{}/\underline{}/\mathcal{} -- typographic wrappers with no
// spoken content of their own. Previously unhandled: fell through to the
// same safety net as \sqrt[n]{} above, producing "textapplied moment"
// (command name and argument fused with no space -- verified empirically
// as the actual broken output before this fix). Mirrors the client's
// CES_TYPEWRAP_RE.
const TYPEWRAP_SPEECH_RE = /\\(?:text|mathrm|mathbf|mathit|boldsymbol|overline|bar|hat|underline|mathcal)\{((?:[^{}]|\{[^{}]*\})*)\}/g;
// [ADDED] Matrix/array environment -- mirrors the client's CES_MATRIX_ENV_RE.
// \1 backreference requires the \end{} to name the same environment the
// \begin{} opened.
const MATRIX_SPEECH_RE = /\\begin\{(pmatrix|bmatrix|vmatrix|Vmatrix|matrix|array)\}([\s\S]*?)\\end\{\1\}/g;
// [ADDED] Braced OR bare subscript -- mirrors the client's CES_SUB_RE;
// see that regex's own comment for the full reasoning (absorbs subscript
// resolution into this function so it survives a Greek-letter
// substitution running later in the same pass).
const SUB_SPEECH_RE = /_\{((?:[^{}]|\{[^{}]*\})*)\}|_([+\-0-9A-Za-z])(?![A-Za-z0-9])/g;
// [ADDED] Leibniz partial-derivative quotient: \partial NUM / \partial VAR.
// Mirrors the client's identical CES_PARTIAL_DERIV_RE addition -- see that
// const's own comment for the full "why not generic bare-slash, why not
// d.../d... too" reasoning. Keep the two in sync if either changes.
const PARTIAL_DERIV_SPEECH_RE = /\\partial\s*([^\/]+?)\s*\/\s*\\partial\s*([A-Za-z](?:_[A-Za-z0-9]+)?)/g;
// [ADDED] Generic bare "/" division -- mirrors the client's identical
// CES_BARE_DIV_RE addition; see that const's own comment for the nesting
// bound and the accepted "km/hr -> km over hr" tradeoff.
// [ROUND 2] '* after the base run -- w_c/f'_c (found via this exact pair's
// own test battery) truncated the match at the prime, stranding "_c"
// outside the wrap ("(f) c" instead of "(f'_c)" / "(f) over c" instead of
// "(w_c) over (f_c)"). A prime between a variable and its subscript is
// this domain's routine strength notation (f'_c, f'_y, f'_t), not an edge
// case -- worth handling in the token grammar itself rather than pushing
// callers to pre-sanitize.
const BARE_DIV_SPEECH_RE = /(\([^()]*(?:\([^()]*\)[^()]*)*\)|[A-Za-z0-9\u0370-\u03FF]+'*(?:_[A-Za-z0-9]+)?)\s*\/\s*(\([^()]*(?:\([^()]*\)[^()]*)*\)|[A-Za-z0-9\u0370-\u03FF]+'*(?:_[A-Za-z0-9]+)?)/g;
// [ADDED] \, \; \! \: -- LaTeX inter-symbol spacing commands (thin/medium/
// negative/thick space), zero semantic content. Found leaking literally as
// "\,dt" into the TTS stream while re-testing this pair's own \int
// regression case (\int_0^infty psi(t)\,dt) -- the generic backslash-strip
// safety net only strips a backslash followed by LETTERS, so a spacing
// command (backslash + punctuation) survives it untouched. Collapsed to a
// single space; never carries meaning worth preserving.
const LATEX_SPACING_RE = /\\[,;:!]/g;

// [ROUND 2 — bare-prose defense-in-depth] Mirrors the client's identical
// addition; see CES_PRIME_SUBSCRIPT_RE's own comment block for the full
// "why these four are safe on prose, why the blanket strip isn't" reasoning.
const PRIME_CALL_RE = /([A-Za-z\u0370-\u03FF])('{1,3})(?=\()/g;
function primeCallWord(base, primes, isAr) {
  const n = primes.length;
  const word = isAr
    ? (n === 1 ? ' مشتقة ' : n === 2 ? ' مشتقة ثانية ' : ` مشتقة من الرتبة ${n} `)
    : (n === 1 ? ' prime ' : n === 2 ? ' double prime ' : ` order-${n} prime `);
  return base + word;
}
const PRIME_SUBSCRIPT_RE = /([A-Za-z\u0370-\u03FF])'(?=_)/g;
const PROSE_SLASH_STOPWORDS = new Set(['and','or','he','she','his','her','him','yes','no','on','off','pass','fail','true','false','up','down','in','out','a','an']);
const UNIT_RESPELL_RE = /(\d[\d,.]*)\s*\b(psi|ksi)\b/gi;
const UNIT_RESPELL_WORDS = { psi: { ar: 'بي إس آي', en: 'P S I' }, ksi: { ar: 'كيه إس آي', en: 'K S I' } };
function respellUnits(s, isAr) {
  return s.replace(UNIT_RESPELL_RE, (_m, numPart, unit) =>
    numPart + ' ' + UNIT_RESPELL_WORDS[unit.toLowerCase()][isAr ? 'ar' : 'en'] + ' ');
}

// Mirrors the client's _cesEndsInMacroName -- see that function's own
// comment.
function _endsInMacroName(str, idx) {
  let j = idx;
  while (j >= 0 && /[A-Za-z]/.test(str.charAt(j))) j--;
  return j >= 0 && str.charAt(j) === '\\';
}

// English ordinal suffix (2nd, 3rd, 4th...) for \sqrt[n]{} when n isn't 2
// or 3 (those two get "square root"/"cube root" instead, for consistency
// with the plain \sqrt{} wording above). Mirrors the client's _cesOrdinal.
function ordinalSpeech(n) {
  const s = String(n), last2 = Number(s.slice(-2));
  if (last2 >= 11 && last2 <= 13) return s + 'th';
  switch (s[s.length - 1]) {
    case '1': return s + 'st';
    case '2': return s + 'nd';
    case '3': return s + 'rd';
    default: return s + 'th';
  }
}

// [ADDED] Mirrors the client's identical _cesWrapOperand -- see that
// function's own comment for the double-parens defect it closes and why
// the exact-char check is safe (not a general balanced-paren check) given
// both callers' capture shapes.
function _wrapOperand(x) {
  return (x.charAt(0) === '(' && x.charAt(x.length - 1) === ')') ? x : '(' + x + ')';
}

function resolveMathInnerForSpeech(inner, isAr) {
  // [ADDED] `\_` (LaTeX's escaped-literal-underscore) always means "print
  // an underscore", never a subscript delimiter -- mirrors the client's
  // identical normalization. See that function's own comment for the
  // empirical case ("$q_{allowable\_net}$" -> literally "q_allowable\_net",
  // a raw backslash reaching the TTS engine, before this fix).
  let s = inner.replace(/\\_/g, ' ');
  for (let pass = 0; pass < 4; pass++) {
    const before = s;
    // [ADDED] Matrix/array environment -- see MATRIX_SPEECH_RE's own
    // comment. Runs first so LaTeX surviving inside a cell (a subscript, a
    // unit) still gets the usual passes below on this same iteration.
    s = s.replace(MATRIX_SPEECH_RE, (_m, _env, body) => {
      const sep = isAr ? '، ' : ', ';
      const rows = body.split('\\\\')
        .map(r => r.replace(/&/g, isAr ? ' و ' : ' and ').replace(/\s+/g, ' ').trim())
        .filter(r => r.length > 0);
      return (isAr ? ' المصفوفة: ' : ' the matrix: ') + rows.join(sep) + ' ';
    });
    s = s.replace(TYPEWRAP_SPEECH_RE, (_m, arg) => ' ' + arg + ' ');
    s = s.replace(NTH_ROOT_SPEECH_RE, (_m, order, x) => {
      if (order === '2') return isAr ? ` الجذر التربيعي لـ (${x}) ` : ` square root of (${x}) `;
      if (order === '3') return isAr ? ` الجذر التكعيبي لـ (${x}) ` : ` cube root of (${x}) `;
      return isAr ? ` الجذر رقم ${order} لـ (${x}) ` : ` the ${ordinalSpeech(order)} root of (${x}) `;
    });
    s = s.replace(SQRT_SPEECH_RE, (_m, x) =>
      isAr ? ` الجذر التربيعي لـ (${x}) ` : ` square root of (${x}) `);
    s = s.replace(FRAC_SPEECH_RE, (_m, num, den) =>
      isAr ? ` (${num}) على (${den}) ` : ` (${num}) over (${den}) `);
    // [ADDED] \partial NUM / \partial VAR -- mirrors the client's identical
    // addition; must run before BARE_DIV_SPEECH_RE and the standalone
    // \partial mapping below for the same two-word-denominator reason
    // documented on the client's CES_PARTIAL_DERIV_RE.
    s = s.replace(PARTIAL_DERIV_SPEECH_RE, (_m, num, denomVar) => {
      num = num.trim();
      const n = _wrapOperand(num);
      return isAr
        ? ` المشتقة الجزئية لـ ${n} بالنسبة لـ ${denomVar} `
        : ` the partial derivative of ${n} with respect to ${denomVar} `;
    });
    // [ADDED] Generic bare "/" division -- mirrors the client's identical
    // addition; see BARE_DIV_SPEECH_RE's own comment.
    s = s.replace(BARE_DIV_SPEECH_RE, (_m, num, den) =>
      isAr ? ` ${_wrapOperand(num)} على ${_wrapOperand(den)} ` : ` ${_wrapOperand(num)} over ${_wrapOperand(den)} `);
    s = s.replace(/\\left(?=[(\[{])/g, '').replace(/\\right(?=[)\]}])/g, '');
    s = s.replace(LATEX_SPACING_RE, ' ');
    // [ADDED] Standalone `\\` -- mirrors the client's identical addition;
    // see that line's own comment.
    s = s.replace(/\\\\/g, () => (isAr ? ' سطر جديد ' : ' new line '));
    // [ADDED] Subscript resolution -- mirrors the client's identical
    // CES_SUB_RE callback; see that callback's own comment for the full
    // fuse-vs-spaced reasoning and the empirical cases it closes.
    s = s.replace(SUB_SPEECH_RE, (_m, braced, bare, offset, str) => {
      const sub = braced !== undefined ? braced : bare;
      const prevChar = offset > 0 ? str.charAt(offset - 1) : '';
      const adjacent = /[A-Za-z0-9]/.test(prevChar) && !_endsInMacroName(str, offset - 1);
      if (adjacent && /^[A-Za-z0-9+\-=()]{1,8}$/.test(sub)) return sub;
      const spoken = sub.replace(/,\s*/g, isAr ? '، ' : ', ').replace(/_/g, ' ').replace(/\s+/g, ' ').trim();
      return ' ' + spoken + ' ';
    });
    s = s.replace(SUP_SPEECH_RE, (_m, braced, bare) => {
      const exp = braced !== undefined ? braced : bare;
      if (exp === '2') return isAr ? ' تربيع ' : ' squared ';
      if (exp === '3') return isAr ? ' تكعيب ' : ' cubed ';
      return isAr ? ` أُس ${exp} ` : ` to the power ${exp} `;
    });
    // [ADDED] Isolated `^`/`_` -- mirrors the client's identical fallback;
    // see that pair's own comment.
    s = s.replace(/\^(?![A-Za-z0-9{])/g, () => (isAr ? ' إشارة الأس ' : ' the caret symbol '));
    s = s.replace(/_(?![A-Za-z0-9{])/g, () => (isAr ? ' الشرطة السفلية ' : ' the underscore symbol '));
    s = s.replace(/\\cdot|\\times/g, () => (isAr ? ' في ' : ' times '));
    s = s.replace(/\\leq/g, () => (isAr ? ' أصغر من أو يساوي ' : ' less than or equal to '));
    s = s.replace(/\\geq/g, () => (isAr ? ' أكبر من أو يساوي ' : ' greater than or equal to '));
    // [ADDED] \neq/\approx/\infty/\sum/\int/\prod/\% -- previously absent;
    // each fell through to the bare-word safety net ("neq", "infty" --
    // not real words in either language, verified empirically). Mirrors
    // the client's matching additions.
    s = s.replace(/\\neq/g, () => (isAr ? ' لا يساوي ' : ' not equal to '));
    s = s.replace(/\\approx/g, () => (isAr ? ' يساوي تقريبًا ' : ' approximately equal to '));
    s = s.replace(/\\infty/g, () => (isAr ? ' لانهاية ' : ' infinity '));
    s = s.replace(/\\sum/g, () => (isAr ? ' مجموع ' : ' sum '));
    s = s.replace(/\\int/g, () => (isAr ? ' تكامل ' : ' integral '));
    s = s.replace(/\\prod/g, () => (isAr ? ' حاصل ضرب ' : ' product '));
    // [ADDED] \partial/\nabla -- mirrors the client's identical addition.
    // Any \partial that's half of a Leibniz quotient is already fully
    // consumed by PARTIAL_DERIV_SPEECH_RE above; this only catches a
    // \partial/\nabla mentioned standalone.
    s = s.replace(/\\partial(?![A-Za-z])/g, () => (isAr ? ' جزئي ' : ' partial '));
    s = s.replace(/\\nabla(?![A-Za-z])/g, () => (isAr ? ' نابلا ' : ' nabla '));
    s = s.replace(/\\%/g, () => (isAr ? ' بالمئة ' : ' percent '));
    s = s.replace(/\\pm/g,  () => (isAr ? ' زائد أو ناقص ' : ' plus or minus '));
    // [ADDED] \min/\max/\Sigma/\forall/\in -- mirrors the client's
    // identical additions; see that file's comments for the empirical
    // cases and the reasoning for \Sigma's dedicated (not Greek-table)
    // mapping.
    s = s.replace(/\\max(?![A-Za-z])/g, () => (isAr ? ' القيمة الأكبر من ' : ' the greater of '));
    s = s.replace(/\\min(?![A-Za-z])/g, () => (isAr ? ' القيمة الأصغر من ' : ' the smaller of '));
    s = s.replace(/\\Sigma(?![A-Za-z])/g, () => (isAr ? ' مجموع ' : ' sum '));
    s = s.replace(/\\forall/g, () => (isAr ? ' لكل ' : ' for all '));
    s = s.replace(/\\in(?![A-Za-z])/g, () => (isAr ? ' تنتمي إلى ' : ' belongs to '));
    s = s.replace(GREEK_MACRO_SPEECH_RE, (m) => {
      const w = GREEK_MACRO_SPEECH_WORDS[m];
      return w ? ` ${isAr ? w.ar : w.en} ` : m;
    });
    if (s === before) break;
  }
  return s
    // [ADDED] Prime(s) immediately followed by "(" -- unambiguous calculus
    // derivative-of-function notation (f'(x), f''(x)); mirrors the
    // client's identical addition -- see that block's own comment for why
    // this must run before the blanket strip just below.
    .replace(/([A-Za-z\u0370-\u03FF])('{1,3})(?=\()/g, (_m, base, primes) => primeCallWord(base, primes, isAr))
    .replace(/'/g, '') // prime marks read as "apostrophe" on every engine -- see stripSuperSubMarkers's own header for the same "don't trust five black boxes" reasoning
    // Same orphaned-underscore fix as the client's _cesResolveMathInner:
    // a Greek base subscripted by another Greek letter (lambda_Delta) has
    // both sides expanded to spoken words above, stranding the underscore
    // with no adjacent letter for stripSuperSubMarkers's own base-lookbehind
    // to match — only an underscore with NO letter/digit on either side is
    // touched here, so an intact "M_cr" (letter immediately adjacent) is
    // left alone for stripSuperSubMarkers to collapse as it already does.
    .replace(/(?<![A-Za-z0-9])_(?![A-Za-z0-9])/g, ' ');
}

// [ADDED] Bare comparison/operator GLYPHS -- what notationNormalizer.mjs's
// own BARE_LATEX_MACROS table already substitutes for \leq/\geq/\pm/etc.
// on text OUTSIDE any $...$ span. flattenLatexForSpeech below only ever
// looks INSIDE $...$, so a glyph like this reached the TTS engine
// completely untouched -- verified empirically (a bare "≤" outside $
// survived every pass unchanged before this addition). This endpoint is
// speech-only (no 'plain'/download mode exists server-side), so unlike
// the client's identical table this one always applies, unconditionally.
const BARE_GLYPH_RE = /[\u2264\u2265\u00B1\u2260\u2248\u221E\u00D7\u00F7]/g;
const BARE_GLYPH_WORDS_AR = { '\u2264':' أصغر من أو يساوي ', '\u2265':' أكبر من أو يساوي ', '\u00B1':' زائد أو ناقص ', '\u2260':' لا يساوي ', '\u2248':' يساوي تقريبًا ', '\u221E':' لانهاية ', '\u00D7':' في ', '\u00F7':' على ' };
const BARE_GLYPH_WORDS_EN = { '\u2264':' less than or equal to ', '\u2265':' greater than or equal to ', '\u00B1':' plus or minus ', '\u2260':' not equal to ', '\u2248':' approximately equal to ', '\u221E':' infinity ', '\u00D7':' times ', '\u00F7':' divided by ' };

// Same $/$$ walk as notationNormalizer.mjs's walkMathSpans (see that
// module's own header for the escaping/pairing rules this mirrors exactly),
// simplified to non-streaming: this runs on the complete text a caller
// posted in one request, never a partial chunk, so no holdback buffering
// is needed to decide where a span ends.
function flattenLatexForSpeech(text) {
  const isAr = /[\u0600-\u06FF]/.test(text);
  let out = '', i = 0;
  while (i < text.length) {
    if (text[i] === '$' && text[i - 1] !== '\\') {
      const isDisplay = text[i + 1] === '$';
      const delim = isDisplay ? '$$' : '$';
      let close = text.indexOf(delim, i + delim.length);
      while (close !== -1 && text[close - 1] === '\\') close = text.indexOf(delim, close + 1);
      if (close !== -1) {
        let resolved = resolveMathInnerForSpeech(text.slice(i + delim.length, close), isAr);
        // Same "the equation:" / "المعادلة:" lead-in as the client's
        // _cesFlattenMathSpans for a DISPLAY ($$...$$) block -- kept in
        // sync so a reply spoken via this defense-in-depth path sounds
        // the same as one already flattened client-side before arriving.
        if (isDisplay) resolved = (isAr ? ' المعادلة: ' : ' the equation: ') + resolved;
        out += resolved;
        i = close + delim.length;
        continue;
      }
    }
    out += text[i];
    i++;
  }
  out = out.replace(BARE_GLYPH_RE, (m) => (isAr ? BARE_GLYPH_WORDS_AR : BARE_GLYPH_WORDS_EN)[m]);
  // [ROUND 2] Bare-prose pass -- mirrors the client's identical addition in
  // _cesFlattenMathSpans; see PRIME_CALL_RE's own comment block for the
  // full reasoning. This endpoint is speech-only, so unlike the client's
  // mode-gated version this always applies (same asymmetry as BARE_GLYPH_RE
  // just above).
  out = out.replace(PRIME_CALL_RE, (_m, base, primes) => primeCallWord(base, primes, isAr));
  out = out.replace(PRIME_SUBSCRIPT_RE, (_m, base) => base);
  out = out.replace(PARTIAL_DERIV_SPEECH_RE, (_m, num, denomVar) => {
    num = num.trim();
    const n = _wrapOperand(num);
    return isAr
      ? ` المشتقة الجزئية لـ ${n} بالنسبة لـ ${denomVar} `
      : ` the partial derivative of ${n} with respect to ${denomVar} `;
  });
  out = out.replace(BARE_DIV_SPEECH_RE, (_m, num, den) => {
    const nLower = /^[A-Za-z]+$/.test(num) ? num.toLowerCase() : null;
    const dLower = /^[A-Za-z]+$/.test(den) ? den.toLowerCase() : null;
    if ((nLower && PROSE_SLASH_STOPWORDS.has(nLower)) || (dLower && PROSE_SLASH_STOPWORDS.has(dLower))) return _m;
    return isAr ? ` ${_wrapOperand(num)} على ${_wrapOperand(den)} ` : ` ${_wrapOperand(num)} over ${_wrapOperand(den)} `;
  });
  out = out.replace(/\\partial(?![A-Za-z])/g, () => (isAr ? ' جزئي ' : ' partial '));
  out = out.replace(/\\nabla(?![A-Za-z])/g, () => (isAr ? ' نابلا ' : ' nabla '));
  out = out.replace(LATEX_SPACING_RE, ' ');
  out = respellUnits(out, isAr);
  return out
    .replace(/\$(?!\d)/g, '')          // stray delimiter, not currency (same guard as notationNormalizer.mjs's stripBareDollar)
    .replace(/\\([A-Za-z]+)/g, '$1')   // unmapped macro outside the documented set -> bare word, never a leaked backslash
    .replace(/[{}]/g, '')              // leftover braces nothing above consumed
    .replace(/[ \t]{2,}/g, ' ');       // collapse the doubled spacing the word substitutions above introduce
}

function preprocessText(text) {
  return stripSuperSubMarkers(flattenLatexForSpeech(stripCodeMarkers(text)))
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

/**
 * v12: generalized sibling of floatFromEnv (above) for values whose valid
 * range isn't ElevenLabs' fixed [0,1] -- prosody ceilings go up to tens of
 * Hz/percent. Same fail-closed idiom: non-numeric or out-of-[0,max] env
 * input is ignored in favor of `fallback`, never forwarded as-is.
 */
function nonNegFloatFromEnv(env, name, fallback, max) {
  const raw = env?.[name];
  const n = raw !== undefined ? parseFloat(raw) : NaN;
  return Number.isFinite(n) && n >= 0 && n <= max ? n : fallback;
}

// ── v12: Rule-based emotional-prosody inference ────────────────────────────
// Zero-cost (pure string ops -- no model call, no extra network round trip,
// no added latency worth measuring), Egyptian-Arabic-weighted lexicon
// (substring match, see rationale below). Deliberately NOT a sentiment
// model: no dependency, no inference cost, fully auditable in a code
// review, and its only effect is a bounded nudge to pitch/rate/volume/style
// -- never content, never routing, never which provider tier is tried.
//
// Substring match, not \b-word-boundary regex: Arabic attaches prefixes/
// conjunctions/possessives directly onto stems (و-, ف-, ب-, ال-, -ها, -كم,
// -ين...), so a boundary-anchored match on "مبروك" misses "ومبروك" ("and
// congratulations") constantly. Substring matching trades a small, bounded
// false-positive rate for materially better recall -- acceptable because a
// false positive here costs a few Hz/percent of prosody drift, never a
// wrong transcription or a wrong routing decision.
//
// Lexicon curation note (v12): earlier drafts of this list included تمام
// ("OK/fine," near-universal as a bare neutral acknowledgment in Egyptian
// Arabic), الحمد لله (frequently just a formulaic "I'm well, thanks" filler,
// not an excitement marker), and يجب/ضروري ("must/necessary" -- appears in
// nearly every routine input-requirement sentence this specific tool
// produces, e.g. footing-pro/beam-pro unit instructions). All four were
// dropped: each fires on genuinely neutral, high-frequency sentences for
// THIS deployment's actual content, which would have made "excited" and
// "warning" the default rather than the exception. What remains below is
// deliberately precision-leaning over recall-leaning.
//
// Known limitation, stated plainly rather than silently: no negation
// handling. "لا يوجد خطأ" ("no error found" -- reassuring) still matches
// the warning-lexicon stem "خطأ" and gets the slower/firmer warning
// profile. Accepted for this pass: the failure mode is a few Hz/percent of
// mismatched tone, not a content or safety error, and real negation
// detection (scope, multi-word "لا...إطلاقاً" patterns, etc.) is a
// meaningfully bigger, not-zero-cost feature in its own right.
const PROSODY_LEXICON = Object.freeze({
  excited: ['رائع', 'ممتاز', 'مبروك', 'تهانين', 'برافو', 'يا سلام', 'جامد', 'حلو أوي', 'بنجاح', 'فخم'],
  empathetic: ['آسف', 'اسف', 'معلش', 'للأسف', 'نعتذر', 'نأسف', 'مضايق', 'حزين', 'تعبان'],
  warning: ['تنبيه', 'تحذير', 'احترس', 'خطأ', 'ممنوع', 'خطر'],
});

/**
 * Classify one already-preprocessText()-ed chunk into a prosody profile.
 * Pure function of its three arguments -- no I/O, no Date.now(), no shared
 * mutable state beyond Math.random() for jitter -- see __inferProsodyForTests.
 *
 * @param {string} text
 * @param {{pitchMaxHz:number, rateMaxPct:number, volumeMaxPct:number, styleMax:number, stabilityDeltaMax:number}} limits
 * @param {string} [forcedEmotion] one of PROSODY_PROFILES's keys, or
 *   'auto'/undefined/anything unrecognized to run the lexicon scorer --
 *   an unrecognized value degrades to today's inference, never a 400.
 * @returns {{
 *   emotion: string, isQuestion: boolean,
 *   pitchHz: number, ratePct: number, volumePct: number,
 *   elevenStyle: number, stabilityDelta: number,
 * }}
 */
function inferProsody(text, limits, forcedEmotion) {
  const isQuestion = /[؟?]\s*$/.test(text);

  let emotion;
  if (forcedEmotion && forcedEmotion !== 'auto' && PROSODY_PROFILES[forcedEmotion]) {
    emotion = forcedEmotion;
  } else {
    const bangCount = (text.match(/!/g) || []).length;
    const scores = { excited: bangCount >= 2 ? 1 : 0, empathetic: 0, warning: 0 };
    for (const category of Object.keys(PROSODY_LEXICON)) {
      for (const stem of PROSODY_LEXICON[category]) {
        if (text.includes(stem)) scores[category] += 1;
      }
    }
    // Fixed tie-break priority when multiple categories score >0:
    // empathetic (sincerity/safety-adjacent) > warning (safety-relevant) >
    // excited (cosmetic upside only) > neutral.
    const priority = ['empathetic', 'warning', 'excited'];
    emotion = 'neutral';
    let best = 0;
    for (const category of priority) {
      if (scores[category] > best) { best = scores[category]; emotion = category; }
    }
  }

  const base = PROSODY_PROFILES[emotion] || PROSODY_PROFILES.neutral;
  const questionPitch = isQuestion ? PROSODY_QUESTION_PITCH_HZ : 0;
  // Math.random(): cosmetic jitter only, never a security- or fairness-
  // relevant draw, so the platform's non-CSPRNG RNG is the right, simplest
  // tool -- crypto.getRandomValues would be pointless overhead here.
  const jitterPitch  = (Math.random() * 2 - 1) * PROSODY_JITTER_PITCH_HZ;
  const jitterRate   = (Math.random() * 2 - 1) * PROSODY_JITTER_RATE_PCT;
  const jitterVolume = (Math.random() * 2 - 1) * PROSODY_JITTER_VOLUME_PCT;

  const clamp = (n, max) => Math.max(-max, Math.min(max, n));

  return {
    emotion,
    isQuestion,
    pitchHz   : Math.round(clamp(base.pitchHz + questionPitch + jitterPitch, limits.pitchMaxHz)),
    ratePct   : Math.round(clamp(base.ratePct + jitterRate, limits.rateMaxPct)),
    volumePct : Math.round(clamp(base.volumePct + jitterVolume, limits.volumeMaxPct)),
    elevenStyle    : Math.max(0, Math.min(limits.styleMax, base.elevenStyle)),
    stabilityDelta : clamp(base.stabilityDelta, limits.stabilityDeltaMax),
  };
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

/**
 * speed float (0.5-2.0, 1.0=normal) + optional additive prosody-derived
 * percent -> Edge TTS's SSML prosody rate string ("+N%"/"-N%").
 * v12: `extraPct` param added (default 0, fully backward compatible with
 * every existing call site) -- composes inferProsody()'s ratePct with the
 * pre-existing speed-derived rate in the same percent-delta unit space
 * before the combined value hits the ORIGINAL ±50% ceiling below, so a
 * caller-supplied `speed` extreme plus an `excited` chunk still can't
 * exceed the ceiling this function already enforced pre-v12.
 */
function speedToEdgeRate(speed, extraPct) {
  const pct = Math.round((clampSpeed(speed) - 1) * 100) + Math.round(extraPct || 0);
  const clamped = Math.min(50, Math.max(-50, pct));
  return `${clamped >= 0 ? '+' : ''}${clamped}%`;
}

/**
 * v12: integer Hz delta -> Edge TTS's SSML prosody pitch string.
 * Format verified directly against rany2/edge-tts's data_classes.py
 * TTSConfig.__post_init__ validator in this pass: `^[+-]\d+Hz$`, always
 * signed (including zero -- the reference default is the literal string
 * "+0Hz", not "0Hz"), always an integer (no decimal point permitted by
 * that pattern).
 */
function hzToEdgeProsody(deltaHz) {
  const n = Math.round(deltaHz || 0);
  return `${n >= 0 ? '+' : ''}${n}Hz`;
}

/**
 * v12: integer percent delta -> Edge TTS's SSML prosody volume string.
 * Same verified pattern family as hzToEdgeProsody: `^[+-]\d+%$`, always
 * signed, always an integer.
 */
function pctToEdgeProsody(deltaPct) {
  const n = Math.round(deltaPct || 0);
  return `${n >= 0 ? '+' : ''}${n}%`;
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

// ── Provider tier registry (v10) ───────────────────────────────────────────
// Single source of truth for the diagnostic `tier` label every
// attempts.push() below reports. Execution order in runTtsCascade is NOT
// driven by this table (the cascade is a fixed sequence of if-blocks) --
// this exists so the reported label can never drift out of sync with real
// call order the way the hand-typed '1.5' literal did for Speechmatics in
// v8 (see v9 changelog point 2 -- the exact failure mode this table exists
// to prevent).
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
//   'always-available-local'    : v10, Tier 4 only -- no network dependency,
//                                 cannot be exhausted or rate-limited
//
// v10 REORDERING (see changelog "HOW v10 GOT HERE" for the full rationale
// and the explicit reversal of v9 point 1's "recurring/unlimited ranks
// above one-time-trial" rule as it applied to Deepgram): gTTS promoted from
// old Tier 3 (final safety net) to Tier 2 (primary continuous fallback,
// all languages). Deepgram/Speechmatics demoted from old Tier 2/2.5 to
// Tier 3, now an emergency reserve gated on isOutageOrRateLimited(tier2Err)
// rather than run unconditionally on every Tier-1 miss. Tier 4 is new.
const PROVIDER_TIERS = Object.freeze({
  edge_tts      : { label: '0 (opt-in, pre-Tier-1)', quotaModel: 'unlimited-unofficial' },
  elevenlabs    : { label: '1',   quotaModel: 'recurring-monthly' },
  gtts          : { label: '2',   quotaModel: 'unlimited-unofficial' },
  deepgram      : { label: '3',   quotaModel: 'one-time-trial' },
  speechmatics  : { label: '3.5', quotaModel: 'metered-recurring-partial' },
  fallback_final: { label: '4',   quotaModel: 'always-available-local' },
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
      // v10 [BUG FIX, found by executing the test harness, not by review]:
      // this previously captured only category/httpStatus. The final
      // aggregate error below is a brand-new Error object, so any OTHER
      // property a singleFetchFn sets on its per-key error (e.g.
      // fetchElevenTTS's quotaConfirmed) was silently dropped -- meaning
      // Tier 1's monthly-exhaustion cache could never fire for a key ring
      // of any size, since runTtsCascade only ever sees this generic
      // wrapper's error, never the original. Now the last attempt's raw
      // error is kept and quotaConfirmed is forwarded generically (this
      // function is shared by ElevenLabs/Deepgram/Speechmatics rings; the
      // field is simply undefined/falsy for the latter two, harmless).
      attemptErrors.push({ idx, category: err.category || err.message, httpStatus: err.httpStatus, raw: err });

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
  err.quotaConfirmed = last?.raw?.quotaConfirmed;
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
// v10: optional third arg (e.g. { expirationTtl: seconds }) -- passed
// straight through to the KV binding's own put() options. Omitting it
// reproduces the exact prior behavior; existing call sites are unaffected.
async function kvPutJSON(kv, key, value, opts) {
  if (!kv) return false;
  try {
    await kv.put(key, JSON.stringify(value), opts);
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
/**
 * v12: `style` and `stabilityDelta` params added (both default 0 if the
 * caller omits them -- an old-style 6-arg call reproduces the pre-v12
 * request body byte-for-byte, since style:0.0 was this function's hardcoded
 * value already and +0 leaves `stability` unchanged).
 */
async function fetchElevenTTS(text, apiKey, voiceId, speed, timeoutMs, stability, similarityBoost, style, stabilityDelta) {
  const url = `${ELEVEN_API_URL}/${voiceId}?output_format=${ELEVEN_OUT_FORMAT}`;
  // Defensive re-clamp to ElevenLabs' documented [0,1] field range even
  // though inferProsody() already bounds stabilityDelta to
  // ±PROSODY_STABILITY_DELTA_MAX (0.10) -- two independent authors of the
  // 0.45 base and the delta should never be able to jointly walk this
  // outside [0,1] and reach ElevenLabs at all, cost-free to guard twice.
  const effectiveStability = Math.min(1, Math.max(0, stability + (stabilityDelta || 0)));

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
        // v11 point 5: env-overridable, evidence-based defaults -- see the
        // ELEVEN_STABILITY_DEFAULT/ELEVEN_SIMILARITY_BOOST_DEFAULT comment.
        // v12: stability now additionally nudged per-request by
        // inferProsody()'s stabilityDelta (see PROSODY_PROFILES); style is
        // no longer hardcoded to 0.0 -- see PROSODY_STYLE_MAX and the v12
        // changelog entry for why this doesn't contradict v11 point 5's
        // "leave it near-zero outside deliberately theatrical delivery"
        // guidance.
        stability        : effectiveStability,
        similarity_boost : similarityBoost,
        style            : style || 0.0,
        use_speaker_boost: true,
        speed            : speedToElevenSpeed(speed),
      },
    }),
  }, timeoutMs);

  if (!elRes.ok) {
    const { quotaMessage } = await readErrorBody(elRes);
    // v10 point 3 [CORRECTION, sourced]: ElevenLabs' own docs (eleven-api/
    // resources/errors; API-Error-Code-429) document HTTP 429 as
    // rate_limit_exceeded / concurrent_limit_exceeded / system_busy -- all
    // transient, none of them quota exhaustion. The real quota signal is
    // HTTP 401 with body `detail.status === "quota_exceeded"`, which
    // readErrorBody already parses into quotaMessage (checked first, below,
    // so a genuine quota-exceeded 401 is never shadowed by the generic
    // "invalid key" 401 hint). Previously this fallback mislabeled bare 429
    // as "quota exceeded" -- harmless as a log string alone, but load-bearing
    // now that quotaConfirmed (not this hint string) gates the new monthly
    // exhaustion cache below.
    const hint =
      quotaMessage ? `ElevenLabs ${quotaMessage}` :
      elRes.status === 401 ? 'invalid or missing key' :
      elRes.status === 422 ? 'invalid voice_id — check ELEVEN_VOICE_ID_F/M' :
      elRes.status === 429 ? 'ElevenLabs rate/concurrency limit (429, transient -- not a quota signal)' :
      `HTTP ${elRes.status}`;
    const err = new Error(`ElevenLabs TTS: ${hint}`);
    err.httpStatus = elRes.status;
    err.category = hint;
    // v10: true ONLY when readErrorBody found a genuine body-confirmed
    // quota/credit message -- never inferred from a bare status code. This
    // is what runTtsCascade's Tier 1 block checks before writing the
    // monthly-exhaustion KV flag; a bare 429/5xx/network failure still
    // fails over to Tier 2 for this request but does not blacklist the
    // tier for the rest of the calendar month.
    err.quotaConfirmed = !!quotaMessage;
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

// ── TIER 2 — Google Translate TTS (v10: PROMOTED from final safety net) ───
// v10 point 4 [FIX]: three gaps that were harmless as the unconditional
// final tier and are load-bearing now that Tier 3's trigger condition reads
// this function's thrown error: (a) budget.take() was never called here --
// fine when this ran once per exhausted request, not fine now that it runs
// on every Tier-1 miss; (b) errors carried no httpStatus/category, so
// isOutageOrRateLimited() had nothing to classify; (c) no response
// validation -- an unofficial, unauthenticated endpoint under automated
// load can return HTTP 200 with an HTML interstitial/anti-abuse page
// instead of audio (a documented failure class for scraped Google
// endpoints generally; NOT independently re-verified against a live
// request from this sandbox, flagged rather than asserted). That would
// previously have been served to the browser as "successful" broken audio
// with zero fallback triggered.
const GTTS_MIN_PLAUSIBLE_BYTES = 256; // shortest real utterance is still >1 audio frame

async function fetchGoogleTTS(text, lang, speed, timeoutMs, budget) {
  if (budget && !budget.take()) {
    const err = new Error('gTTS: subrequest budget exhausted');
    err.category = 'subrequest budget exhausted';
    err.httpStatus = 'network';
    throw err;
  }

  const url = new URL('https://translate.google.com/translate_tts');
  url.searchParams.set('ie',       'UTF-8');
  url.searchParams.set('client',   'tw-ob');
  // v11 point 6: bare base-language subtag, not the full 'ar-EG'-style tag --
  // every evidenced-working example of this undocumented endpoint uses e.g.
  // 'ar'/'en', never a regional suffix. Purely a robustness fix: gTTS has
  // exactly one Arabic voice regardless, so this does not change output
  // quality (see renderedDialectFor, unchanged: still "ar (MSA), robotic").
  url.searchParams.set('tl',       lang.split('-')[0]);
  url.searchParams.set('q',        text);
  url.searchParams.set('ttsspeed', speed && speed !== 1.0 ? String(clampSpeed(speed)) : '1');

  let res;
  try {
    res = await fetchWithTimeout(url.toString(), {
      headers: {
        'Referer'   : 'https://translate.google.com/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
                      'AppleWebKit/537.36 (KHTML, like Gecko) ' +
                      'Chrome/125.0.0.0 Safari/537.36',
      },
      cf: { cacheEverything: true, cacheTtl: 3600 },
    }, timeoutMs);
  } catch (networkErr) {
    // AbortError (timeout) or any connection-level failure -- no HTTP
    // status exists yet, so use the same 'network' sentinel as every other
    // tier's timeout/connection errors in this file.
    const err = new Error(`gTTS: ${networkErr.name === 'AbortError' ? 'timeout' : networkErr.message}`);
    err.category = networkErr.name === 'AbortError' ? 'timeout' : 'network error';
    err.httpStatus = 'network';
    throw err;
  }

  if (!res.ok) {
    const err = new Error(`gTTS upstream HTTP ${res.status}`);
    err.httpStatus = res.status;
    err.category = res.status === 429 ? 'rate limited (429)' : `HTTP ${res.status}`;
    throw err;
  }

  const contentType = res.headers.get('Content-Type') || '';
  const bytes = new Uint8Array(await res.arrayBuffer());

  if (!contentType.toLowerCase().includes('audio') || bytes.length < GTTS_MIN_PLAUSIBLE_BYTES) {
    const err = new Error(
      `gTTS: HTTP 200 but response is not plausible audio (Content-Type="${contentType}", ${bytes.length} bytes) -- likely an interstitial/anti-abuse page, not synthesized speech`,
    );
    err.httpStatus = 200;
    err.category = 'invalid response body (non-audio 200)';
    throw err;
  }

  return { bytes, contentType: 'audio/mpeg' };
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
function buildEdgeSsml(voiceName, escapedText, rate, pitch, volume) {
  return (
    "<speak version='1.0' xmlns='http://www.w3.org/2001/10/synthesis' " +
    `xmlns:mstts='https://www.w3.org/2001/mstts' xml:lang='${edgeVoiceLocale(voiceName)}'>` +
    `<voice name='${voiceName}'>` +
    `<prosody pitch='${pitch}' rate='${rate}' volume='${volume}'>` +
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
/**
 * v12: `prosody` param added (default {} -- every field optional, missing
 * fields resolve to today's flat 0/0/0 via the `|| 0` in the formatters
 * below, so an old call site omitting it entirely still produces the
 * pre-v12 SSML byte-for-byte).
 * @returns {Promise<{ bytes: Uint8Array, contentType: string }>}
 */
async function fetchEdgeTTS(text, lang, genderKey, speed, timeoutMs, budget, prosody) {
  if (budget && !budget.take()) {
    const err = new Error('Edge TTS: subrequest budget exhausted');
    err.category = 'subrequest budget exhausted';
    err.httpStatus = 'network';
    throw err;
  }

  const p = prosody || {};
  const voiceName = resolveEdgeVoice(lang, genderKey);
  const rate = speedToEdgeRate(speed, p.ratePct);
  const pitch = hzToEdgeProsody(p.pitchHz);
  const volume = pctToEdgeProsody(p.volumePct);
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
  // v11 points 2-3: header set re-verified against rany2/edge-tts's current
  // constants.py (BASE_HEADERS + WSS_HEADERS) rather than the version this
  // file previously carried. Sec-WebSocket-Version was absent -- a real
  // browser's native WebSocket implementation sends it automatically, but
  // Workers' fetch()+Upgrade path is not a browser WebSocket client and was
  // never confirmed to add it. '13' is the only valid value per RFC 6455.
  const upgradeHeaders = {
    Upgrade                 : 'websocket',
    'Sec-WebSocket-Version' : '13',
    'User-Agent'            : EDGE_TTS_USER_AGENT,
    'Accept-Encoding'       : 'gzip, deflate, br, zstd',
    'Accept-Language'       : 'en-US,en;q=0.9',
    Pragma                  : 'no-cache',
    'Cache-Control'         : 'no-cache',
    Origin                  : EDGE_TTS_ORIGIN,
    Cookie                  : `muid=${generateEdgeMuid()};`,
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
        buildEdgeSsml(voiceName, escapedText, rate, pitch, volume),
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

// Test-only exports (v12) -- inferProsody is pure and the highest-value
// thing in this revision to pin with real regression coverage: a silent
// lexicon/weight change six months from now should fail a test, not just
// quietly retune production tone.
export {
  inferProsody as __inferProsodyForTests,
  hzToEdgeProsody as __hzToEdgeProsodyForTests,
  pctToEdgeProsody as __pctToEdgeProsodyForTests,
};

// Test-only export (v9). isDeepgramExpired's new DEEPGRAM_CREDIT_EXPIRES
// branch and the pre-existing clock-math branch both need direct coverage —
// exercising the 1-year boundary through a real KV round trip isn't
// practical in a unit test.
export { isDeepgramExpired as __isDeepgramExpiredForTests };

// ── v10: Tier 2 -> Tier 3 trigger condition ────────────────────────────────
// "Triggered only if Tier 2 encounters Rate Limiting (HTTP 429) or temporary
// service outages" -- implemented literally, not loosened to "any Tier 2
// failure". True for: HTTP 429; any 5xx; the 'network' sentinel this file
// already uses for timeouts/connection failures (fetchGoogleTTS, Edge TTS,
// rotateAndFetchTTS's budget-exhaustion case all set this). An open circuit
// breaker on 'gtts' is treated the same as a fresh outage, consistent with
// how every other circuit-broken tier in this file is handled -- it already
// IS the outcome of repeated recent 429/5xx/network failures.
function isOutageOrRateLimited(err) {
  if (!err) return false;
  if (err.httpStatus === 429) return true;
  if (err.httpStatus === 'network') return true;
  if (typeof err.httpStatus === 'number' && err.httpStatus >= 500) return true;
  return false;
}

// ── v10: Tier 1 monthly-exhaustion cache ───────────────────────────────────
// Namespaced by UTC calendar month so the flag self-clears at the next
// month boundary with no cron/reset code -- same reasoning as the Deepgram
// lifetime clock's KV-flag pattern, one more read, no new binding. Gated
// strictly on quotaConfirmed (a real body-confirmed quota/credit signal),
// never a bare status code -- see fetchElevenTTS's v10 point 3 fix for why
// that distinction matters here specifically.
function getElevenLabsQuotaMonthKey(now = new Date()) {
  return `tts:elevenlabs:quota:${now.toISOString().slice(0, 7)}`; // "YYYY-MM"
}

async function isElevenLabsMonthlyExhausted(env) {
  const state = await kvGetJSON(env?.CES_CHAT_KV, getElevenLabsQuotaMonthKey());
  return !!state?.exhausted;
}

/** Fire-and-forget, same waitUntil pattern as recordOutcome/recordDeepgramFirstUseIfAbsent. */
function markElevenLabsMonthlyExhausted(context) {
  const kv = context.env?.CES_CHAT_KV;
  if (!kv) return;
  const key = getElevenLabsQuotaMonthKey();
  const task = (async () => {
    const existing = await kvGetJSON(kv, key);
    if (existing?.exhausted) return; // already recorded this month -- skip the write
    // 32 days comfortably covers a month + buffer; avoids relying on any
    // cleanup job to expire stale month-keys.
    await kvPutJSON(kv, key, { exhausted: true, since: Date.now() }, { expirationTtl: 32 * 24 * 60 * 60 });
  })();
  if (typeof context.waitUntil === 'function') context.waitUntil(task);
  else task.catch(() => {});
}

// ── TIER 4 — Guaranteed final fallback (v10, new) ──────────────────────────
// Cannot fail in normal operation: no network call on the guaranteed path,
// no auth, no quota, no upstream to be down. The one optional step (a KV
// read for an operator-supplied override) is wrapped fail-open, exactly
// like every other KV read in this file -- any error there falls straight
// through to the generated silence rather than propagating.
const TIER4_KV_CACHE_KEY = 'tts:tier4:cached_audio'; // operator-set: {base64, contentType}
const TIER4_SILENCE_DURATION_MS = 800;
const TIER4_SAMPLE_RATE = 8000; // minimum viable -- keeps the generated buffer tiny

/**
 * Builds a canonical, always-valid 16-bit mono PCM WAV of pure silence.
 * Zero dependencies, zero I/O, deterministic. The data section is an
 * ArrayBuffer's native zero-initialization -- never explicitly written --
 * so the only work done is a 44-byte RIFF/fmt/data header write.
 */
function buildSilentWav(durationMs = TIER4_SILENCE_DURATION_MS, sampleRate = TIER4_SAMPLE_RATE) {
  const numSamples = Math.round(sampleRate * (durationMs / 1000));
  const dataSize = numSamples * 2; // 16-bit mono => 2 bytes/sample
  const buffer = new ArrayBuffer(44 + dataSize);
  const view = new DataView(buffer);
  const writeAscii = (offset, str) => {
    for (let i = 0; i < str.length; i++) view.setUint8(offset + i, str.charCodeAt(i));
  };
  writeAscii(0, 'RIFF');
  view.setUint32(4, 36 + dataSize, true);
  writeAscii(8, 'WAVE');
  writeAscii(12, 'fmt ');
  view.setUint32(16, 16, true);              // fmt chunk size
  view.setUint16(20, 1, true);               // PCM
  view.setUint16(22, 1, true);               // mono
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);  // byte rate (sampleRate * blockAlign)
  view.setUint16(32, 2, true);               // block align
  view.setUint16(34, 16, true);              // bits per sample
  writeAscii(36, 'data');
  view.setUint32(40, dataSize, true);
  return new Uint8Array(buffer);             // bytes 44.. are already zero => silence
}

// Module-scoped, same reuse pattern as ringPointers -- computed once per
// isolate, not per request.
let _cachedSilentWavBytes = null;
function getSilentWavBytes() {
  if (!_cachedSilentWavBytes) _cachedSilentWavBytes = buildSilentWav();
  return _cachedSilentWavBytes;
}

/**
 * Never throws. Tries one best-effort KV read for an operator-configured
 * override (satisfies the spec's "cached default audio" half); any miss,
 * parse failure, or empty decode falls through to the generated silent WAV
 * (satisfies the "silent response" half). Returns the same result shape
 * every other tier returns so callers don't need a special case.
 */
async function runFinalFallback(env) {
  try {
    const cached = await kvGetJSON(env?.CES_CHAT_KV, TIER4_KV_CACHE_KEY);
    if (cached?.base64 && cached?.contentType) {
      const binary = atob(cached.base64);
      if (binary.length > 0) {
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return { bytes, contentType: cached.contentType, source: 'kv_cached_override' };
      }
    }
  } catch (_e) {
    // Fail open -- malformed base64, missing key, KV error: all fall
    // through to the guaranteed branch below. Never rethrow from Tier 4.
  }
  return { bytes: getSilentWavBytes(), contentType: 'audio/wav', source: 'generated_silence' };
}

// Test-only exports. Pure functions -- cheap to give permanent regression
// coverage rather than relying on end-to-end exercising.
export {
  isOutageOrRateLimited as __isOutageOrRateLimitedForTests,
  buildSilentWav as __buildSilentWavForTests,
  getElevenLabsQuotaMonthKey as __getElevenLabsQuotaMonthKeyForTests,
};

// ── Shared cascade engine (one copy, used by GET and POST) ────────────────
/**
 * v10: Group 0 (Edge TTS, opt-in, unchanged) -> Tier 1 (ElevenLabs, recurring
 * monthly quota, monthly-exhaustion-cached) -> Tier 2 (gTTS, PROMOTED,
 * unlimited/unofficial, all languages) -> Tier 3 (Deepgram then opt-in
 * Speechmatics, DEMOTED, english-only, gated on isOutageOrRateLimited(tier2
 * error)) -> Tier 4 (guaranteed local fallback, cannot fail). Returns
 * whichever tier answers first. Does NOT throw on the "every network tier
 * degraded" path -- Tier 4 always resolves that case; see v10 changelog
 * point 8. A thrown error here is now an unexpected internal fault, not a
 * routine outcome.
 */
async function runTtsCascade({ text, lang, genderKey, speed, emotion, env, context, timeouts }) {
  const devMode = isDevMode(env);
  const englishOnly = isEnglish(lang);
  const budget = makeFetchBudget(SUBREQUEST_BUDGET_FREE_PLAN);

  const eleven   = buildKeyRing(env, ELEVEN_BASE_NAME);
  const deepgram = buildKeyRing(env, DEEPGRAM_BASE_NAME);
  // v11 point 5.
  const elevenStability = floatFromEnv(env, 'ELEVEN_STABILITY', ELEVEN_STABILITY_DEFAULT);
  const elevenSimilarityBoost = floatFromEnv(env, 'ELEVEN_SIMILARITY_BOOST', ELEVEN_SIMILARITY_BOOST_DEFAULT);
  const speechmaticsEnabled = (env?.ENABLE_SPEECHMATICS_TTS || '').trim().toLowerCase() === 'true';
  const speechmatics = speechmaticsEnabled ? buildKeyRing(env, SPEECHMATICS_BASE_NAME) : { keys: [] };
  // v11 point 4: default flipped true -> opt OUT with EDGE_TTS_ENABLED=false.
  // Same idiom as isDeepgramExpired's DEEPGRAM_CREDIT_EXPIRES a few dozen
  // lines up -- ?? 'true' so an unset env var defaults on, explicit 'false'
  // (any case) is the only way to turn it back off.
  const edgeEnabled = (env?.EDGE_TTS_ENABLED ?? 'true').trim().toLowerCase() !== 'false';

  // v12: computed once per request, reused by both Group 0 and Tier 1 below
  // -- the SAME classification should not silently differ between a Tier-0
  // attempt and a Tier-1 fallback for the identical input text.
  const prosodyLimits = {
    pitchMaxHz       : nonNegFloatFromEnv(env, 'TTS_PROSODY_PITCH_MAX_HZ', PROSODY_PITCH_MAX_HZ, 200),
    rateMaxPct       : nonNegFloatFromEnv(env, 'TTS_PROSODY_RATE_MAX_PCT', PROSODY_RATE_MAX_PCT, 50),
    volumeMaxPct     : nonNegFloatFromEnv(env, 'TTS_PROSODY_VOLUME_MAX_PCT', PROSODY_VOLUME_MAX_PCT, 50),
    styleMax         : nonNegFloatFromEnv(env, 'TTS_PROSODY_STYLE_MAX', PROSODY_STYLE_MAX, 1),
    stabilityDeltaMax: nonNegFloatFromEnv(env, 'TTS_PROSODY_STABILITY_DELTA_MAX', PROSODY_STABILITY_DELTA_MAX, 1),
  };
  const prosody = inferProsody(text, prosodyLimits, emotion);
  // ASCII-only values throughout (emotion is one of PROSODY_PROFILES's
  // English keys, the rest are signed integers/floats) -- see v8 changelog
  // point 5 on why a non-Latin-1 header value throws at the Fetch API layer.
  const prosodyHeaders = {
    'X-TTS-Prosody-Emotion': prosody.emotion + (prosody.isQuestion ? '+question' : ''),
    'X-TTS-Prosody-Pitch'  : hzToEdgeProsody(prosody.pitchHz),
    'X-TTS-Prosody-Rate'   : pctToEdgeProsody(prosody.ratePct),
    'X-TTS-Prosody-Volume' : pctToEdgeProsody(prosody.volumePct),
    'X-TTS-Prosody-Style'  : String(prosody.elevenStyle),
  };

  const keyCountHeaders = {
    'X-TTS-Eleven-KeysAvailable'  : String(eleven.keys.length),
    'X-TTS-Deepgram-KeysAvailable': String(deepgram.keys.length),
  };

  const attempts = [];

  // GROUP 0 — Edge TTS (unchanged from v9: opt-in, off by default, always
  // runs when enabled even in dev -- no quota to protect). Sits outside the
  // requested 1-4 numbering; see PROVIDER_TIERS label.
  if (edgeEnabled && !(await isCircuitOpen(env, 'edge_tts'))) {
    try {
      const { bytes, contentType } = await fetchEdgeTTS(text, lang, genderKey, speed, timeouts.tier0, budget, prosody);
      recordOutcome(context, 'edge_tts', true);
      return {
        bytes, contentType, provider: 'edge_tts', providerOfficial: false,
        engineHeaders: { ...prosodyHeaders }, attempts, budgetRemaining: budget.remaining(),
      };
    } catch (err) {
      recordOutcome(context, 'edge_tts', false);
      attempts.push({ tier: PROVIDER_TIERS.edge_tts.label, provider: 'edge_tts', reason: err.category || err.message });
    }
  } else if (edgeEnabled) {
    attempts.push({ tier: PROVIDER_TIERS.edge_tts.label, provider: 'edge_tts', reason: 'circuit open' });
  }

  // TIER 1 — ElevenLabs ring (all languages; recurring monthly quota -- runs
  // in dev too). v10: cheap KV pre-check skips the whole ring the moment a
  // genuine quota_exceeded body has already been seen this UTC calendar
  // month, saving a doomed round trip (or N doomed round trips, one per
  // configured key) on every subsequent request until the month rolls over.
  const monthlyExhausted = eleven.keys.length > 0 && !devMode ? await isElevenLabsMonthlyExhausted(env) : false;
  if (eleven.keys.length > 0 && monthlyExhausted) {
    attempts.push({ tier: PROVIDER_TIERS.elevenlabs.label, provider: 'elevenlabs', reason: 'monthly quota pre-emptively exhausted (cached; resets next UTC month, or delete the KV key to force an early retry)' });
  } else if (eleven.keys.length > 0 && !(await isCircuitOpen(env, 'elevenlabs'))) {
    try {
      const voiceId = resolveVoiceId(genderKey, env);
      const { response: result, keyIndex, keysTried } = await rotateAndFetchTTS(
        ringPointers.eleven, eleven.keys,
        (key) => fetchElevenTTS(text, key, voiceId, speed, timeouts.tier1, elevenStability, elevenSimilarityBoost, prosody.elevenStyle, prosody.stabilityDelta),
        'ElevenLabs', budget,
      );
      recordOutcome(context, 'elevenlabs', true);
      return {
        bytes: result.bytes, contentType: result.contentType, provider: 'elevenlabs', providerOfficial: true,
        engineHeaders: { 'X-TTS-Voice': voiceId, 'X-TTS-KeyIndex': String(keyIndex), 'X-TTS-KeysTried': String(keysTried), ...keyCountHeaders, ...prosodyHeaders },
        attempts, budgetRemaining: budget.remaining(),
      };
    } catch (err) {
      recordOutcome(context, 'elevenlabs', false);
      // v10: only a BODY-CONFIRMED quota signal writes the month-long cache
      // (see fetchElevenTTS's quotaConfirmed, point 3) -- a bare 429/5xx/
      // network failure still fails over to Tier 2 for this request but
      // does not blacklist the tier for the rest of the month.
      if (err.quotaConfirmed) markElevenLabsMonthlyExhausted(context);
      attempts.push({ tier: PROVIDER_TIERS.elevenlabs.label, provider: 'elevenlabs', reason: err.category || err.message });
    }
  } else if (eleven.keys.length > 0) {
    attempts.push({ tier: PROVIDER_TIERS.elevenlabs.label, provider: 'elevenlabs', reason: 'circuit open' });
  }

  // TIER 2 — Google Translate TTS (v10: PROMOTED, all languages, unlimited/
  // unofficial, primary continuous fallback). Now circuit-broken like every
  // other tier (v9's "nothing to fall back to" rationale no longer holds --
  // Tier 3 and Tier 4 exist behind it). tier2Err is captured (not just
  // logged) because Tier 3's trigger condition reads it directly.
  let tier2Err = null;
  const gttsCircuitOpen = await isCircuitOpen(env, 'gtts');
  if (!gttsCircuitOpen) {
    try {
      const result = await fetchGoogleTTS(text, lang, speed, timeouts.tier2, budget);
      recordOutcome(context, 'gtts', true);
      return {
        bytes: result.bytes, contentType: result.contentType, provider: 'gtts', providerOfficial: false,
        engineHeaders: { ...keyCountHeaders }, attempts, budgetRemaining: budget.remaining(),
      };
    } catch (err) {
      recordOutcome(context, 'gtts', false);
      tier2Err = err;
      attempts.push({ tier: PROVIDER_TIERS.gtts.label, provider: 'gtts', reason: err.category || err.message });
    }
  } else {
    attempts.push({ tier: PROVIDER_TIERS.gtts.label, provider: 'gtts', reason: 'circuit open' });
  }

  // TIER 3 — Emergency reserve: Deepgram (one-time credit), then opt-in
  // Speechmatics (metered-partial). v10: DEMOTED from the old Tier 2 --
  // now gated strictly on "Tier 2 encountered 429 or a temporary outage",
  // exactly as specified, not on "Tier 1 failed" as in v9. A circuit-open
  // Tier 2 counts as satisfying that condition (it IS the accumulated
  // result of recent 429/5xx/network failures). Internal Deepgram/
  // Speechmatics logic (lifetime clock, circuit breakers, dev-mode gating,
  // key-ring rotation) is unchanged from v9.
  const tier2QualifiesForReserve = gttsCircuitOpen || isOutageOrRateLimited(tier2Err);

  // [MERGE — round 5, entire feature was missing] Global (not per-IP) gate
  // on the reserve tier itself — see tier3RateLimitOpts's own header for
  // why per-IP alone doesn't protect a shared, finite resource.
  // checkRateLimit is imported from rotation.mjs already (see this file's
  // import block) — reused here with a fixed key instead of clientIp,
  // everything else about the call is identical to every other
  // checkRateLimit call site in this codebase. A trip here skips BOTH
  // Deepgram and Speechmatics for this request (they share the one
  // resource this protects) and falls through directly to Tier 4,
  // recording why — same attempts.push() pattern every other skip reason
  // in this cascade already uses. On a rate-limiter failure itself (KV
  // unavailable), this fails OPEN (still attempts the reserve tier) —
  // consistent with this file's OWN existing fail-open pattern on the
  // blanket per-IP check above, not a new inconsistency introduced here.
  const tier3GloballyThrottled = tier2QualifiesForReserve
    ? (await checkRateLimit(env, 'tts:tier3:global', tier3RateLimitOpts(env)))?.limited
    : false;

  if (tier2QualifiesForReserve && tier3GloballyThrottled) {
    attempts.push({
      tier: `${PROVIDER_TIERS.deepgram.label}/${PROVIDER_TIERS.speechmatics.label}`,
      provider: 'reserve',
      reason: 'skipped: global tier-3 rate limit reached (protects the shared Deepgram credit / Speechmatics allowance from aggregate drain across all callers, not just one IP)',
    });
  } else if (tier2QualifiesForReserve) {
    // TIER 3a — Deepgram Aura-2, ENGLISH ONLY, skipped in dev (finite
    // credit) or once lifetime-expired.
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
            (key) => fetchDeepgramTTS(text, key, timeouts.tier3),
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
    } else if (!englishOnly && deepgram.keys.length > 0) {
      // v10, small addition for observability (see changelog): previously
      // silent. Deepgram's Aura-2 model here is English-only by capability,
      // not by policy -- this doesn't change with the reorder.
      attempts.push({ tier: PROVIDER_TIERS.deepgram.label, provider: 'deepgram', reason: `skipped: english-only provider, requested lang is ${lang}` });
    }

    // TIER 3b — opt-in Speechmatics, ENGLISH ONLY, 480min/mo free then
    // billed, skipped in dev.
    if (englishOnly && speechmaticsEnabled && speechmatics.keys.length > 0 && !devMode) {
      if (await isCircuitOpen(env, 'speechmatics')) {
        attempts.push({ tier: PROVIDER_TIERS.speechmatics.label, provider: 'speechmatics', reason: 'circuit open' });
      } else {
        try {
          const { response: result, keyIndex, keysTried } = await rotateAndFetchTTS(
            ringPointers.speechmatics, speechmatics.keys,
            (key) => fetchSpeechmaticsTTS(text, key, timeouts.tier3),
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
  } else if (tier2Err) {
    // Tier 2 failed but not via 429/5xx/network -- per spec, Tier 3's
    // reserve is not consulted. Realistically near-unreachable for gTTS
    // specifically (see changelog point 5) but implemented as specified
    // rather than silently widened.
    attempts.push({ tier: `${PROVIDER_TIERS.deepgram.label}/${PROVIDER_TIERS.speechmatics.label}`, provider: 'reserve', reason: 'skipped: Tier 2 failure was not rate-limit/outage-class, reserve not consulted per policy' });
  }

  // TIER 4 — Guaranteed final fallback (v10, new). Cannot fail; always
  // returns. See runFinalFallback's own doc comment.
  const finalResult = await runFinalFallback(env);
  attempts.push({ tier: PROVIDER_TIERS.fallback_final.label, provider: 'fallback_final', reason: `serving ${finalResult.source}` });
  return {
    bytes: finalResult.bytes, contentType: finalResult.contentType, provider: 'fallback_final', providerOfficial: false,
    engineHeaders: { ...keyCountHeaders, 'X-TTS-Guaranteed-Fallback': 'true' },
    attempts, budgetRemaining: budget.remaining(),
  };
}

// Test-only export (v10). Not used by any request-handling path -- lets a
// test harness drive the full tier cascade with a mocked env/context/fetch
// instead of only its individual pure-function pieces, the same rationale
// as every other __xForTests export in this file.
export { runTtsCascade as __test_runTtsCascade };

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

// v10 [FIX]: both handlers previously applied the same `public, max-age=3600`
// to every 200 response, including gTTS-circuit-open/reserve fallbacks and
// (new in v10) the guaranteed Tier 4 silence. Caching a Tier-4 response as
// if it were real audio means a transient full-outage for one piece of text
// gets frozen into up to an hour of cached SILENCE for that exact query
// even after every provider recovers -- caching is supposed to save
// redundant upstream calls for a GOOD result, not preserve a degraded one.
// Only the guaranteed fallback is excluded; a genuine Tier 2/3 audio
// response is exactly as cacheable as Tier 1's, unchanged from v9.
function cacheControlFor(result) {
  return result.provider === 'fallback_final' ? 'no-store' : 'public, max-age=3600';
}

function logTtsEvent(fields) {
  try {
    console.log(JSON.stringify({ ts: new Date().toISOString(), ...fields }));
  } catch (_e) { /* logging must never break the response */ }
}

// [MERGE — round 5, regression: entire feature was missing, not just
// recalibrated] Blanket per-IP gate, checked once before any provider is
// chosen — protects against one IP hammering /api/tts in general,
// independent of which tier serves the request. Does NOT by itself
// protect the Deepgram/Speechmatics credit specifically (see
// tier3RateLimitOpts below for the mechanism that actually targets that
// risk). Default tightened 40->12 on its own merits, independent of the
// tier-3 question.
function rateLimitOpts(env) {
  return {
    windowSeconds: intFromEnv(env, 'TTS_RATE_LIMIT_WINDOW_SECONDS', 60),
    maxPerWindow : intFromEnv(env, 'TTS_RATE_LIMIT_MAX_PER_WINDOW', 12),
  };
}

// [MERGE — round 5] Gates Deepgram + Speechmatics TOGETHER, GLOBALLY —
// not per-IP. This is the actual credit-protection mechanism. Per-IP
// limiting is the wrong shape for this specific risk: the Deepgram
// credit and Speechmatics' allowance are each ONE shared resource across
// every visitor, not a per-user allocation — many different IPs, each
// individually well under any per-IP cap, can still drain a shared
// resource in aggregate if Tier 2 becomes unreliable for an extended
// window (Google Translate TTS is unofficial/undocumented; nothing
// guarantees it stays reliable). isDeepgramExpired()'s time-based clock
// caps how LONG Deepgram stays reachable, not how FAST the credit can be
// spent once reachable — nothing before this gate capped spend rate at
// all. Reuses the same checkRateLimit(env, key, opts) already used
// everywhere else in this codebase; the only difference from every other
// call site is a fixed key instead of a clientIp-derived one, which is
// what makes the limit global instead of per-visitor.
//
// Default calibrated against confirmed real pricing (Deepgram Aura-2:
// $0.030/1,000 chars; MAX_TEXT_LENGTH below caps one request at 200
// chars, so worst case is $0.006/request). At 5/min, continuous
// saturation 24/7 gives a worst-case ceiling of ~$43.20/day — the full
// $200 one-time credit would take ~4.6 days to drain even under that
// theoretical continuous-worst-case, comfortably past a week of margin.
// (An earlier default of 10/min was rejected after this same math showed
// only a ~2.3-day worst-case ceiling — short of the intended margin.)
// Both figures describe a worst-case bound (requires Tier 2 unavailable
// continuously for days, every request hitting the 200-char cap), not an
// expected cost. Override via TTS_TIER3_RATE_LIMIT_MAX_PER_WINDOW for a
// tighter/looser ceiling.
function tier3RateLimitOpts(env) {
  return {
    windowSeconds: intFromEnv(env, 'TTS_TIER3_RATE_LIMIT_WINDOW_SECONDS', 60),
    maxPerWindow : intFromEnv(env, 'TTS_TIER3_RATE_LIMIT_MAX_PER_WINDOW', 5),
  };
}

// Speechmatics (was TTS_TIER2_TIMEOUT_MS, default unchanged at 6000). A
// deployment relying on the old names' non-default values needs those
// values moved to the new names.
function resolveTimeouts(env) {
  return {
    tier0: intFromEnv(env, 'TTS_TIER0_TIMEOUT_MS', 4000),
    tier1: intFromEnv(env, 'TTS_TIER1_TIMEOUT_MS', 6000),
    tier2: intFromEnv(env, 'TTS_TIER2_TIMEOUT_MS', 7000),
    tier3: intFromEnv(env, 'TTS_TIER3_TIMEOUT_MS', 6000),
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
  // v12: optional, additive-only param -- absent/unrecognized both mean
  // "auto" (run the lexicon scorer). See inferProsody's forcedEmotion guard
  // for why an invalid value here degrades rather than 400s.
  const emotionParam = (url.searchParams.get('emotion') || 'auto').toLowerCase().trim();

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
      text, lang: safeLang, genderKey, speed: speedParam, emotion: emotionParam, env, context,
      timeouts: resolveTimeouts(env),
    });
    logTtsEvent({ requestId, route: 'GET', lang: safeLang, provider: result.provider, fallback: result.attempts.length > 0, attempts: result.attempts, budgetRemaining: result.budgetRemaining });
    return new Response(result.bytes, {
      status: 200,
      headers: {
        'Content-Type' : result.contentType,
        'Cache-Control': cacheControlFor(result),
        'X-TTS-Request-Id' : requestId,
        'X-TTS-Latency-Ms' : String(Date.now() - t0),
        ...buildResultHeaders(result, safeLang),
        ...getCorsHeaders(request),
      },
    });
  } catch (finalErr) {
    // v10: runTtsCascade no longer throws on the routine "every network
    // tier degraded" path (Tier 4 always resolves that) -- reaching this
    // block now means an unexpected internal fault, not a provider outage.
    logTtsEvent({ requestId, route: 'GET', lang: safeLang, provider: null, fallback: true, attempts: finalErr.attempts, error: finalErr.message });
    return jsonResponse(502, {
      error: 'Unexpected internal error -- all managed tiers including the guaranteed fallback failed.',
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
  // v12: optional, additive-only field -- see GET handler's matching comment.
  const emotionParam = typeof body.emotion === 'string' ? body.emotion.toLowerCase().trim() : 'auto';

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
      text, lang: safeLang, genderKey, speed: speedParam, emotion: emotionParam, env, context,
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
        'Cache-Control': cacheControlFor(result),
        'X-TTS-Request-Id' : requestId,
        'X-TTS-Latency-Ms' : String(Date.now() - t0),
        ...buildResultHeaders(result, safeLang),
        ...formatHeader,
        ...getCorsHeaders(request),
      },
    });
  } catch (finalErr) {
    // v10: see GET handler's matching comment -- this is now an unexpected
    // internal fault path, not a routine "all providers down" outcome.
    logTtsEvent({ requestId, route: 'POST', lang: safeLang, provider: null, fallback: true, attempts: finalErr.attempts, error: finalErr.message });
    return jsonResponse(503, {
      error: 'Unexpected internal error -- all managed tiers including the guaranteed fallback failed.',
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
