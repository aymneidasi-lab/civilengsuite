/**
 * functions/api/chat.js  —  v14  (2026-06-27)
 * ──────────────────────────────────────────────────────────────────────────
 * ════════════════════════════════════════
 * CHANGELOG v14 — IDENTITY + DEVELOPER MODE + SECURITY FIX
 * ════════════════════════════════════════
 *
 * CHANGE 1 (IDENTITY): Added ASSISTANT_NAME constant and YOUR NAME & IDENTITY
 *   block to SYSTEM_PROMPT, GEMINI_FOLLOWUP_PROMPT, and WORKERS_AI_SYSTEM_PROMPT.
 *   Bot now recognises its name "Eng_pro assist" when addressed, and answers
 *   name questions ("ما اسمك؟", "who are you?") in both languages correctly.
 *   Never claims to be Gemini, ChatGPT, Claude, or any other AI brand.
 *
 * CHANGE 2 (DEVELOPER MODE): Added DEVELOPER_SYSTEM_PROMPT and server-side
 *   isDeveloperMode validation. When the Cloudflare Pages secret DEVELOPER_PASSWORD
 *   matches body.devPassword sent by the client, DEVELOPER_SYSTEM_PROMPT is
 *   prepended to the active base prompt, granting the programmer full technical
 *   access: complete code generation for any project file, architecture discussion,
 *   internal file details, TTS provider alternatives.
 *   All five provider return paths include { devMode: true } so the client can
 *   display the 🔓 [Dev] badge on bot bubbles.
 *   ENV VAR REQUIRED: DEVELOPER_PASSWORD (Secret) in Cloudflare Pages dashboard.
 *   CLIENT PROTOCOL: type /dev YOUR_PASSWORD in the chat widget; widget sends
 *   devPassword on every subsequent request; server re-validates each turn.
 *
 * CHANGE 3 (SECURITY FIX — v13 bug corrected here):
 *   crypto.subtle.timingSafeEqual() does NOT exist in the Web Crypto API (WHATWG
 *   spec). It is a Node.js-only method on the crypto module — a completely
 *   different object. On Cloudflare Workers the call always threw TypeError,
 *   the outer try/catch caught it, and fell back to a direct === compare —
 *   functionally correct but not cryptographically timing-safe.
 *   FIX: replaced with hmacTimingSafeEqual() — an HMAC-SHA256 based constant-time
 *   comparison using only real Web Crypto API primitives (generateKey + sign +
 *   XOR accumulator). See the helper's comment block for full rationale.
 *
 * ════════════════════════════════════════
 * CHANGELOG v13 — CONCURRENCY: MANY SIMULTANEOUS USERS, NOT JUST MANY DAYS
 * ════════════════════════════════════════
 * CONTEXT: v11/v12 optimised this file for AVAILABILITY across TIME — surviving
 *   one key's daily quota exhaustion by failing over through a 13-key, 4-provider
 *   ordered chain. Neither version addressed CONCURRENCY — many users hitting
 *   this endpoint in the same few seconds. Four concrete gaps, fixed below:
 *
 * CHANGE 1 (THROUGHPUT — the big one): every request, from every concurrent
 *   user, previously started the Gemini/Groq/OpenRouter loops at keys[0].
 *   That is an ORDERED FAILOVER LIST, not a load-balanced pool: under real
 *   simultaneous traffic, every request piles onto the SAME first key's
 *   per-minute (RPM) ceiling while the other 12 keys sit idle until key 0 is
 *   already failing. Effective concurrent throughput was bounded by one
 *   upstream account's RPM limit, not by the 13-key pool's combined limit.
 *   FIX: rotateStart() picks a random starting offset into each key pool per
 *   request, so simultaneous requests fan out across all 13 keys from the
 *   first attempt instead of converging on one. Daily-quota failover
 *   behaviour is unchanged (every key is still tried, in rotated order).
 *
 * CHANGE 2 (LATENCY/THUNDERING HERD): on a 429, the v6–v12 logic retried
 *   RATE_LIMIT_EXCEEDED in place with a fixed 2s/5s/11s backoff. That is
 *   reasonable for one isolated burst but pathological under concurrency:
 *   many simultaneous requests hitting the same saturated key all back off
 *   and retry on the same schedule, re-converging on the same key at T+2s,
 *   T+7s, T+18s — the herd never disperses. FIX: any 429 (RESOURCE_EXHAUSTED
 *   or RATE_LIMIT_EXCEEDED) now fails over to the next key immediately, no
 *   backoff-retry in place. Retry-with-backoff is kept ONLY for 500/503
 *   (genuine transient errors, where retrying the same key is still the
 *   right move), reduced to 2 attempts with ±20% jitter (was 3, no jitter).
 *
 * CHANGE 3 (PLATFORM CEILING): Cloudflare Workers/Pages Functions cap a
 *   single invocation at 50 fetch() subrequests on the Free plan (10,000 on
 *   Paid — developers.cloudflare.com/workers/platform/limits/, confirmed
 *   June 2026). Worst case, the pre-v13 chain could issue 100+ fetches in
 *   one invocation if many keys returned retryable statuses. The existing
 *   try/catch around every call() already prevented a hard crash (fetch()
 *   past the cap rejects with a catchable error, it does not throw an
 *   uncaught exception), but the request would still churn through dozens
 *   of doomed attempts before reaching the final error response. FIX:
 *   makeFetchBudget() is a shared counter threaded through every provider
 *   call for one invocation; every layer stops and returns the friendly
 *   error the moment the budget runs low, on EVERY plan tier, instead of
 *   relying on (or being surprised by) the platform's own enforcement.
 *
 * CHANGE 4 (ABUSE / NO THROTTLING): /api/chat had zero request-level rate
 *   limiting. getCorsHeaders() restricts browser-issued cross-origin calls,
 *   but CORS is a browser-enforced policy — a non-browser client (script,
 *   bot, curl) can POST directly to this endpoint and bypass it entirely.
 *   An unthrottled client can exhaust the ENTIRE shared 13-key pool across
 *   every provider in well under a minute, zeroing out quota for every real
 *   visitor — and that risk scales with traffic. FIX: checkRateLimit() uses
 *   Cloudflare's native Rate Limiting binding (env.RATE_LIMITER) if present,
 *   falling back to a KV fixed-window counter (env.CES_CHAT_KV) if not, and
 *   failing OPEN (no throttling) if neither is bound — logged at WARN so the
 *   gap is visible rather than silent. See the comment block above
 *   checkRateLimit() for the honest caveat on KV's Free-plan write quota.
 *
 * NOT CHANGED in v13 (see the response this shipped with for full discussion):
 *   · Upgrading the underlying Cloudflare account from Workers Free to
 *     Workers Paid ($5/mo) raises the subrequest cap 50→10,000 and CPU time
 *     10ms→30s, and is a prerequisite for the env.RATE_LIMITER binding used
 *     in Change 4. This file works on either plan — budget/jitter/rotation
 *     all degrade gracefully — but Paid removes the platform ceiling this
 *     changelog had to work around in Change 3 entirely.
 *   · GEMINI_FOLLOWUP_PROMPT / SYSTEM_PROMPT sizing (v12) is unchanged.
 *   · Provider order (Gemini → Workers AI → Groq → OpenRouter) is unchanged;
 *     only the order WITHIN each provider's key pool is now rotated.
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * functions/api/chat.js  —  v12  (2026-06-26)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — AI chatbot proxy for Civil Engineering Suite
 * Route:  POST /api/chat   (Cloudflare Pages auto-routes from /functions/api/)
 *
 * ENV VARS (Cloudflare Dashboard → Pages → civilengsuite → Settings
 *           → Environment variables):
 *
 *   REQUIRED:
 *     GEMINI_API_KEY          Secret   Google account 1 (aistudio.google.com,
 *                                      starts with AIzaSy…)
 *
 *   OPTIONAL — Groq (console.groq.com → API Keys → Create API Key, free, no card):
 *     GROQ_API_KEY            Secret   Groq account 1   (1,000 req/day free —
 *                                      corrected in v12, was misstated as
 *                                      14,400; see CHANGELOG v12, Change 3)
 *     GROQ_API_KEY_1          Secret   Groq account 2
 *     GROQ_API_KEY_2          Secret   Groq account 3
 *     GROQ_API_KEY_3          Secret   Groq account 4
 *     GROQ_API_KEY_4          Secret   Groq account 5
 *     GROQ_API_KEY_5          Secret   Groq account 6
 *     GROQ_API_KEY_6          Secret   Groq account 7
 *     GROQ_API_KEY_7          Secret   Groq account 8
 *     GROQ_API_KEY_8          Secret   Groq account 9
 *     GROQ_API_KEY_9          Secret   Groq account 10
 *     GROQ_API_KEY_10         Secret   Groq account 11
 *     GROQ_API_KEY_11         Secret   Groq account 12
 *     GROQ_API_KEY_12         Secret   Groq account 13
 *     All 13 keys = 13,000 Groq req/day free (corrected, see v12).
 *
 *   OPTIONAL — OpenRouter (openrouter.ai → Settings → Keys, free, $0 balance):
 *     OPENROUTER_API_KEY      Secret   OpenRouter account 1   (50 req/day free)
 *     OPENROUTER_API_KEY_1    Secret   OpenRouter account 2
 *     OPENROUTER_API_KEY_2    Secret   OpenRouter account 3
 *     OPENROUTER_API_KEY_3    Secret   OpenRouter account 4
 *     OPENROUTER_API_KEY_4    Secret   OpenRouter account 5
 *     OPENROUTER_API_KEY_5    Secret   OpenRouter account 6
 *     OPENROUTER_API_KEY_6    Secret   OpenRouter account 7
 *     OPENROUTER_API_KEY_7    Secret   OpenRouter account 8
 *     OPENROUTER_API_KEY_8    Secret   OpenRouter account 9
 *     OPENROUTER_API_KEY_9    Secret   OpenRouter account 10
 *     OPENROUTER_API_KEY_10   Secret   OpenRouter account 11
 *     OPENROUTER_API_KEY_11   Secret   OpenRouter account 12
 *     OPENROUTER_API_KEY_12   Secret   OpenRouter account 13
 *     All 13 keys = 650 OpenRouter req/day free.
 *
 *   OPTIONAL — Gemini extra keys (each must be a DIFFERENT Google account):
 *     GEMINI_API_KEY_2        Secret   Google account 2  (~3,000 req/day)
 *     GEMINI_API_KEY_3        Secret   Google account 3
 *     GEMINI_API_KEY_4        Secret   Google account 4
 *     GEMINI_API_KEY_5        Secret   Google account 5
 *     GEMINI_API_KEY_6        Secret   Google account 6
 *     GEMINI_API_KEY_7        Secret   Google account 7
 *     GEMINI_API_KEY_8        Secret   Google account 8
 *     GEMINI_API_KEY_9        Secret   Google account 9
 *     GEMINI_API_KEY_10       Secret   Google account 10
 *     GEMINI_API_KEY_11       Secret   Google account 11
 *     GEMINI_API_KEY_12       Secret   Google account 12
 *     GEMINI_API_KEY_13       Secret   Google account 13
 *     All 13 keys = ~39,000 Gemini req/day free.
 *     ⚠️  Each key must come from a distinct Google account — the same account
 *     does not produce a second quota pool (verified June 2026).
 *
 * BINDING (Cloudflare Dashboard → Pages → civilengsuite → Settings
 *          → Bindings → Add → Workers AI):
 *   Variable name : AI
 *   Resource      : Workers AI  (no key, no signup — it's tied to this
 *                   Cloudflare account already hosting the site)
 *   This binding is OPTIONAL. If you don't add it, the bot still runs on
 *   Gemini alone — you just lose the Workers AI free fallback layer.
 *
 * ════════════════════════════════════════
 * CHANGELOG v12 — QUOTA SURVIVAL: SYSTEM PROMPT SIZE + WASTED RETRIES
 * ════════════════════════════════════════
 * CONTEXT: v11 maximised the NUMBER of free-tier keys (×13 per provider) but
 *   did nothing about the SIZE of each request or which failures were worth
 *   retrying. v12 addresses both — the two levers that actually determine
 *   how far a free-tier quota stretches once you already have multiple keys.
 *
 * CHANGE 1 (QUOTA — the big one): Gemini Layers 1/2 were sending the full
 *   SYSTEM_PROMPT (measured: 51,660 chars, ~13,000 input tokens) on EVERY
 *   Gemini call — every turn, every one of up to 13 keys, both models, every
 *   retry. A single 5-message conversation cost ~65,000 system-prompt input
 *   tokens; a full fallback sweep could resend it 20+ times for one message.
 *   Free-tier Gemini Flash/Flash-Lite TPM is ~250,000 tokens/minute shared
 *   per project (ai.google.dev/gemini-api/docs/rate-limits, verified June
 *   2026) — at 13K tokens/request that's under 20 requests/minute before
 *   429s start, no matter how many keys are pooled behind it. Context
 *   caching cannot fix this: gemini-3.5-flash and gemini-3.1-flash-lite are
 *   preview-tier models and do not support context caching on the free tier
 *   (every request sends full, uncached context — confirmed June 2026).
 *   FIX: added GEMINI_FOLLOWUP_PROMPT, a ~1,150-token condensed prompt sent
 *   on every turn AFTER the first (turns.length > 1); the full SYSTEM_PROMPT
 *   is now sent only once, on a conversation's opening message. The model's
 *   own prior replies remain in `contents` history so identity/tone persist.
 *   callGeminiWithRetry() now takes `systemPrompt` as a parameter instead of
 *   reading the SYSTEM_PROMPT global directly. Same 5-message conversation:
 *   ~65,000 → ~17,600 system-prompt tokens, a ~73% reduction.
 *
 * CHANGE 2 (QUOTA): Groq and OpenRouter no longer retry on HTTP 429.
 *   OpenRouter's own docs (openrouter.ai/docs/api/reference/limits) state
 *   failed attempts still count toward the 50/day free quota — retrying a
 *   429 there spent a second unit of an already-tiny daily budget for almost
 *   no chance of success inside the 1.2s retry delay. Groq's free tier (30
 *   RPM / 6,000 TPM / 1,000 RPD per account) has the same shape: an RPM or
 *   RPD ceiling does not clear in 1.2 seconds. Both functions now retry only
 *   on 500/503 (genuine transient server errors); 429 fails over to the next
 *   key immediately. Gemini's retry logic was already correct on this point
 *   (it special-cases RESOURCE_EXHAUSTED vs RATE_LIMIT_EXCEEDED) and is
 *   unchanged.
 *
 * CHANGE 3 (ACCURACY — corrects a v10/v11 capacity overestimate): the v11
 *   capacity comments claimed Groq's llama-3.1-8b-instant gives 14,400
 *   req/day per account. Multiple independent sources citing Groq's current
 *   rate-limit docs (console.groq.com/docs/rate-limits, verified June 2026)
 *   put the actual free-tier figure at 1,000 req/day, 30 RPM, 6,000 TPM per
 *   account — Groq reduced free-tier limits at some point after the 14,400
 *   figure was originally sourced. This does not change any code path (the
 *   per-key loop logic is unaffected either way), but the capacity totals
 *   below and in the v11 section are corrected so capacity planning isn't
 *   based on a number that's roughly 14× too high:
 *     Groq    (13 keys × 1,000 req/day)       :  13,000 req/day  (was stated
 *                                                  as 187,200 — that number
 *                                                  was wrong; see Change 3)
 *   Gemini and OpenRouter per-key figures in v11 were checked against
 *   current docs and are reasonably accurate; only Groq needed correction.
 *
 * UPDATED COMBINED FREE DAILY CAPACITY (all 13 keys active per provider,
 *   corrected per Change 3 — supersedes the v11 table below):
 *   Gemini  (13 keys × primary + fallback)  : ~20,000–39,000 req/day
 *                                              (range reflects free-tier
 *                                              variance between sources;
 *                                              verify in AI Studio per key)
 *   Workers AI (env.AI binding, unchanged)  :    ~100 req/day
 *   Groq    (13 keys × llama-3.1-8b-instant):  13,000 req/day  (corrected)
 *   OpenRouter (13 keys × :free model)      :    ~650 req/day
 *   ──────────────────────────────────────────────────────────
 *   TOTAL: roughly 34,000–53,000 req/day, $0.00 — still comfortably above
 *   normal chatbot traffic, but meaningfully less than the ~226,950/day
 *   figure v11 claimed. Treat any specific number here as an estimate;
 *   Google/Groq/OpenRouter can and do change free-tier limits without
 *   notice (Groq's own limits already moved once between when v10/v11 were
 *   written and this v12 pass). Check each provider's live dashboard for
 *   the current per-account figure rather than trusting any number in this
 *   file indefinitely.
 *
 * NOT CHANGED in v12 (left as-is; candidates for a future pass if quota
 *   pressure continues after this fix):
 *   · History cap is still 10 turns × 2,000 chars (~5,000–6,000 extra input
 *     tokens on top of the system prompt, on every call). Could be tightened
 *     (e.g. 6 turns × 1,200 chars) for further savings at the cost of how
 *     much earlier conversation the model can see.
 *   · Provider order is still Gemini (all 13 keys × 2 models) → Workers AI →
 *     Groq → OpenRouter. Worst case for a single message still means up to
 *     26 Gemini attempts before reaching the cheaper/faster Groq/OpenRouter
 *     pool. Re-ordering to try fewer Gemini keys first and fail over to Groq
 *     sooner would reduce both latency and worst-case token burn further,
 *     at the cost of using Gemini's (generally stronger) output less often.
 *   · SYSTEM_PROMPT itself (the first-turn version) is unchanged — still
 *     ~13,000 tokens. It could be trimmed further (the Arabic phrase banks
 *     and persuasion-angle prose are the largest single blocks) without
 *     touching GEMINI_FOLLOWUP_PROMPT, if first-message cost still matters
 *     after this fix.
 *
 * ════════════════════════════════════════
 * CHANGELOG v11 — KEY POOL EXPANSION: ×13 GROQ + ×13 OPENROUTER + ×13 GEMINI
 * ════════════════════════════════════════
 * PURPOSE: The project team has 13 members, each with a free account on Groq,
 *   OpenRouter, and Google AI Studio. v10 used one key per provider. v11
 *   collects all configured keys for each provider into an array at runtime
 *   and tries them in sequence, multiplying available free-tier capacity ×13.
 *
 * CHANGE 1 (AVAILABILITY): Groq key pool expanded from 1 key to 13 keys.
 *   New env vars: GROQ_API_KEY_1 through GROQ_API_KEY_12 (in addition to
 *   the existing GROQ_API_KEY). All keys are collected into groqKeys[] and
 *   iterated in order. Blank or missing keys are silently skipped via .filter().
 *   Capacity: 14,400 req/day × 13 keys = 187,200 Groq req/day, $0.
 *   [CORRECTED in v12 — this 14,400/day figure was wrong; current Groq free
 *   tier is 1,000 req/day per account, i.e. 13,000 req/day for 13 keys.
 *   See CHANGELOG v12, Change 3.]
 *
 * CHANGE 2 (AVAILABILITY): OpenRouter key pool expanded from 1 to 13 keys.
 *   New env vars: OPENROUTER_API_KEY_1 through OPENROUTER_API_KEY_12.
 *   Same iteration pattern as CHANGE 1.
 *   Capacity: 50 req/day × 13 keys = 650 OpenRouter req/day, $0.
 *
 * CHANGE 3 (AVAILABILITY): Gemini key pool expanded from 2 to 13 keys.
 *   New env vars: GEMINI_API_KEY_3 through GEMINI_API_KEY_13 (joining the
 *   existing GEMINI_API_KEY and GEMINI_API_KEY_2). Each Google account at
 *   aistudio.google.com has a fully independent free-tier quota.
 *   Each key in the pool tries GEMINI_MODEL_PRIMARY then GEMINI_MODEL_FALLBACK,
 *   exactly as v10's Layers 1, 2, and 6a/6b did — now generalised to N keys.
 *   Capacity: ~3,000 req/day × 13 keys = ~39,000 Gemini req/day, $0.
 *
 * IMPLEMENTATION: onRequestPost now uses three key arrays (geminiKeys,
 *   groqKeys, openRouterKeys), each built at runtime from env vars with
 *   blank/missing keys filtered out. Execution order:
 *     1. All Gemini keys (each tries PRIMARY then FALLBACK model)
 *     2. Workers AI (unchanged — env.AI binding, no API key)
 *     3. All Groq keys (llama-3.1-8b-instant, WORKERS_AI_SYSTEM_PROMPT)
 *     4. All OpenRouter keys (:free model, WORKERS_AI_SYSTEM_PROMPT)
 *   The first successful response is returned immediately.
 *   All helper functions (callGeminiWithRetry, callGroqWithRetry,
 *   callOpenRouterWithRetry, callWorkersAIWithRetry, buildFriendlyError)
 *   are unchanged from v10. [v12 note: callGeminiWithRetry, callGroqWithRetry,
 *   and callOpenRouterWithRetry are no longer unchanged — see CHANGELOG v12.]
 *
 * CLOUDFLARE DASHBOARD SETUP:
 *   Pages → civilengsuite → Settings → Environment variables → + Add variable.
 *   Type: Secret for every key. Add keys one by one from each team member's
 *   respective console. After adding all desired keys, click "Retry deployment"
 *   (or trigger any new deployment) — Pages picks up new env vars on the next
 *   build. Keys can be added incrementally; any missing key is silently skipped.
 *
 * COMBINED FREE DAILY CAPACITY (all 13 keys active per provider):
 *   [SUPERSEDED by the corrected table in CHANGELOG v12 — the Groq figure
 *   below was wrong by roughly 14×. Kept here only as the historical record
 *   of what v11 originally claimed; use the v12 table for planning.]
 *   Gemini  (13 keys × primary + fallback)  : ~39,000 req/day
 *   Workers AI (env.AI binding, unchanged)  :    ~100 req/day
 *   Groq    (13 keys × llama-3.1-8b-instant): 187,200 req/day
 *   OpenRouter (13 keys × :free model)      :    ~650 req/day
 *   ──────────────────────────────────────────────────────────
 *   TOTAL: ~226,950 req/day, $0.00.
 *   At 100–500 req/day (normal chatbot traffic), exhaustion across all
 *   providers simultaneously is effectively impossible.
 *
 * ════════════════════════════════════════
 * CHANGELOG v10 — 6-LAYER CHAIN: GROQ + OPENROUTER + GEMINI KEY 2 + WHATSAPP REDIRECT
 * ════════════════════════════════════════
 * CHANGE 1 (AVAILABILITY): Groq added as Layer 4.
 *   callGroqWithRetry() — llama-3.1-8b-instant, OpenAI-compatible API.
 *   Free plan limits: 14,400 req/day, 500K tokens/day, 30 RPM, 6K TPM.
 *   llama-3.1-8b-instant chosen over llama-3.3-70b-versatile because the 70B
 *   model's free plan is only 1,000 req/day vs 14,400 for 8B (verified June 2026
 *   at console.groq.com/docs/rate-limits).
 *   Uses WORKERS_AI_SYSTEM_PROMPT (~800 tokens) to stay below the 6K TPM cap.
 *   Reuses the workersMsgs array already built for Layer 3 (same OpenAI format).
 *   Requires GROQ_API_KEY (free, no credit card — console.groq.com).
 *
 * CHANGE 2 (AVAILABILITY): OpenRouter added as Layer 5.
 *   callOpenRouterWithRetry() — meta-llama/llama-3.3-70b-instruct:free.
 *   Free tier (no balance required): 50 req/day, 20 RPM.
 *   Layer 5 fires only after Layers 1–4 have all failed, so 50 RPD is
 *   meaningful additional capacity at zero cost.
 *   HTTP-Referer and X-Title headers sent per OpenRouter's docs recommendation.
 *   Reuses workersMsgs (same OpenAI-compatible format as Layers 3 & 4).
 *   Requires OPENROUTER_API_KEY (free, no billing — openrouter.ai).
 *
 * CHANGE 3 (AVAILABILITY): Second Gemini key added as Layer 6.
 *   Free quota is per Google account, not pooled — a second Google account at
 *   aistudio.google.com provides a completely separate daily quota.
 *   Layer 6 tries GEMINI_MODEL_PRIMARY then GEMINI_MODEL_FALLBACK with Key 2,
 *   identical logic to Layers 1 & 2, using the existing callGeminiWithRetry().
 *   Requires GEMINI_API_KEY_2 (from a second Google account).
 *   ⚠️  Google Terms note: multiple accounts is generally permitted for personal
 *   use; confirm compliance in a commercial context.
 *
 * CHANGE 4 (UX): buildFriendlyError updated — WhatsApp on every failure path.
 *   When all layers fail, every error message now includes WhatsApp +201287232413
 *   and aymneidasi@gmail.com — a quota failure is no longer a dead end.
 *
 * COMBINED FREE DAILY CAPACITY (v10 6-layer baseline — see v11 for full 13-key totals):
 *   Layer 1  — Gemini 3.5-flash      (Key 1) : ~1,500 req/day
 *   Layer 2  — Gemini 3.1-flash-lite (Key 1) : ~1,500 req/day
 *   Layer 3  — Workers AI            (no key):   ~100 req/day (10K neurons/day)
 *   Layer 4  — Groq llama-3.1-8b    (Key 4) : 14,400 req/day
 *   Layer 5  — OpenRouter :free      (Key 5) :     50 req/day
 *   Layer 6  — Gemini Key 2          (Key 2) : ~3,000 req/day (both models)
 *   TOTAL: ~20,550 req/day across all layers, $0.00.
 *   At 100–500 req/day (normal chatbot traffic), daily exhaustion is
 *   effectively impossible with all six layers active.
 *
 * ════════════════════════════════════════
 * CHANGELOG v9 — DEAD LAYER 3, CORS HOLE, NO INPUT CAPS, MODEL DEPRECATION
 * ════════════════════════════════════════
 * BUG 1 (CRITICAL): WORKERS_AI_MODEL referenced
 *   '@cf/meta/llama-3.1-8b-instruct-fp8-fast' — this combined suffix does not
 *   exist in Cloudflare's Workers AI catalog (verified June 2026). Every
 *   Layer 3 call has been failing with an unknown-model error since v7. Fixed
 *   to the confirmed-existing '@cf/meta/llama-3.1-8b-instruct-fast' variant.
 *
 * BUG 2 (CRITICAL): Even with Bug 1 fixed, Layer 3 sent the full SYSTEM_PROMPT
 *   (~13,524 tokens) into a model with a 4,096-token total context window —
 *   3.3× overflow on the system prompt alone, before any history or reply.
 *   Added a new WORKERS_AI_SYSTEM_PROMPT constant (<800 tokens) used only for
 *   the Layer 3 call. SYSTEM_PROMPT itself is untouched and still used for
 *   Layers 1 and 2.
 *
 * BUG 3 (SECURITY/COST): CORS was 'Access-Control-Allow-Origin': '*' — any
 *   site on the internet could issue cross-origin requests against this
 *   endpoint and burn the project's free-tier quota. Replaced the static
 *   CORS object with getCorsHeaders(request), which only echoes the origin
 *   back when it is the production domain or localhost/127.0.0.1 (dev only);
 *   every other origin gets the production origin in the header, which the
 *   browser will reject as a CORS mismatch. The json() helper and
 *   onRequestOptions now thread `request` through to this function.
 *
 * BUG 4 (SECURITY/COST): No cap on incoming message length — a single
 *   100,000-character message added ~26,000 tokens on top of the system
 *   prompt, capable of exhausting the daily token quota in a handful of
 *   requests. Added a 2,000-character hard cap with a bilingual 400 response.
 *
 * BUG 5 (SECURITY/COST): History turns had no length cap either — ten turns
 *   of 50,000 characters each could inject ~130,000 tokens of payload around
 *   the system prompt. Each turn's text is now sliced to 2,000 characters,
 *   matching the live-message cap.
 *
 * BUG 6 (MAINTENANCE): gemini-2.5-flash and gemini-2.5-flash-lite are both
 *   scheduled for shutdown 2026-10-16 (developers.google.com/gemini-api/docs
 *   /deprecations, verified June 2026). Migrated now, ahead of the deadline,
 *   to their confirmed-free-tier replacements: gemini-3.5-flash and
 *   gemini-3.1-flash-lite (ai.google.dev/gemini-api/docs/pricing).
 *
 * ════════════════════════════════════════
 * CHANGELOG v7 — ROOT-CAUSE FIX: dead model + paid fallback removed
 * ════════════════════════════════════════
 * WHY v6 BROKE ("Both AI providers are unavailable"):
 *   1. GEMINI_MODEL was 'gemini-2.0-flash'. Google deprecated and fully
 *      SHUT DOWN gemini-2.0-flash on 2026-06-01 (confirmed on Google's own
 *      pricing page: "Gemini 2.0 Flash is deprecated and has been shut down
 *      June 1, 2026"). Every primary call was failing — that's the
 *      RESOURCE_EXHAUSTED half of the error message.
 *   2. The "fallback" was DeepSeek, which v6's own comments mis-stated as
 *      having "no daily request cap" and implied was effectively free.
 *      DeepSeek's API is NOT free — checked api-docs.deepseek.com directly:
 *      it is pay-per-token only, debited from a topped-up or one-time
 *      "granted" balance. Once that balance is empty (which it is — no
 *      payment method was ever added per site owner), every call returns a
 *      balance/auth error. That's the "backup also failed" half.
 *   Net effect: a guaranteed-fail primary chained to a guaranteed-fail
 *   (and explicitly paid, against this project's "100% free" requirement)
 *   fallback. There was no scenario in which this ever answered a user.
 *
 * FIX — DeepSeek removed entirely; replaced with a 3-layer ALL-FREE chain:
 *   LAYER 1 — gemini-2.5-flash (current GA, NOT deprecated, free tier).
 *   LAYER 2 — gemini-2.5-flash-lite, same GEMINI_API_KEY. Gemini free-tier
 *     request quotas are tracked per model, not pooled across models, so
 *     exhausting Flash's daily quota does not touch Flash-Lite's separate
 *     daily quota — this is a second free chance before leaving Google
 *     entirely. (Source: ai.google.dev/gemini-api/docs/rate-limits —
 *     "Limits vary depending on the specific model being used.")
 *   LAYER 3 — Cloudflare Workers AI, via the native `env.AI` binding,
 *     running @cf/meta/llama-3.1-8b-instruct-fp8-fast. Zero API key, zero
 *     new signup — it's a binding on the Cloudflare account already
 *     hosting this Pages project. Free allocation: 10,000 neurons/day,
 *     no credit card (Cloudflare Workers AI pricing docs). A typical reply
 *     at this system prompt's size costs roughly 70-90 neurons, so the
 *     free allocation covers ~100+ fallback replies/day — and this layer
 *     only fires when BOTH Gemini models are exhausted, so real usage is
 *     far lower than that ceiling.
 *   Each layer is tried in order; the response is returned the instant any
 *   layer succeeds. Only a simultaneous failure of all three layers shows
 *   the user an error.
 *
 * STAYING AT $0.00 — TWO ACCOUNT SETTINGS TO NEVER CHANGE:
 *   · Do not enable billing on the Google AI Studio project. The free tier
 *     needs no billing account; adding one converts 429s into a real bill
 *     instead of a hard stop.
 *   · Do not upgrade the Cloudflare account from the Workers FREE plan to
 *     Workers PAID. On Free, exceeding 10,000 neurons/day just fails the
 *     request (no charge, ever). On Paid, the same overage is billed at
 *     $0.011/1,000 neurons. Free plan = the 10k/day ceiling is a wall, not
 *     a meter.
 *   Leave both as-is and this file cannot generate a bill under any
 *   traffic pattern — worst case is the friendly "all providers busy"
 *   message, never a charge.
 *
 * SECURITY NOTE (unrelated to the bug, found while reviewing screenshots):
 *   The DEEPSEEK_API_KEY and GEMINI_API_KEY values were visible in plaintext
 *   in dashboard screenshots shared during debugging. Treat both as
 *   compromised — rotate them in their respective consoles (delete the old
 *   key, generate a new one, update the Cloudflare Pages env var) regardless
 *   of this code change. DeepSeek's key is no longer used by this file at
 *   all after v7, so deleting the DEEPSEEK_API_KEY variable in Cloudflare is
 *   also safe to do once the new key has been rotated on DeepSeek's side.
 *
 * ════════════════════════════════════════
 * CHANGELOG v5 — SYSTEM PROMPT EXPANSION + QUOTA DIAGNOSTICS
 * ════════════════════════════════════════
 * QUOTA ERROR DETECTION (addresses Q3 / Q4 directly):
 *   Old: ANY 429 returned identical "busy assistant" message — operator could not
 *        distinguish a temporary RPM burst from a fully exhausted daily quota.
 *   New: error body is parsed as JSON after all retries.
 *     · error.status === 'RESOURCE_EXHAUSTED' → daily/monthly quota exhausted.
 *       Message tells user to try after midnight UTC and instructs admin to upgrade key.
 *     · error.status === 'RATE_LIMIT_EXCEEDED' → RPM burst (15 req/min free limit).
 *       Message tells user to wait 30–60 seconds — quota will not help.
 *     · Anything else → generic transient error message.
 *
 * WHY "BUSY ASSISTANT" OCCURS — FULL ROOT-CAUSE TREE:
 *   CAUSE 1 — WRONG MODEL (v3 issue, fixed in v4):
 *     gemini-2.5-flash-lite is Preview-tier with ~1M TPD free quota.
 *     12K-token system prompt × real traffic = quota gone in ≈66 requests/day.
 *     Fix: gemini-2.0-flash (stable, 4M TPD). Already in v4, kept in v5.
 *   CAUSE 2 — RPM BURST (ongoing, handled by retries):
 *     Free tier = 15 requests/minute. Multiple concurrent users or rapid typing
 *     can hit this. The 3-retry exponential backoff (2 s → 5 s → 11 s) absorbs
 *     most burst spikes without surfacing an error to the user.
 *   CAUSE 3 — DAILY RPD LIMIT (ongoing, requires paid key to fix):
 *     Free tier = 1500 requests/day regardless of token size.
 *     A busy site hitting 1500 chat messages/day will see sustained 429s from
 *     RESOURCE_EXHAUSTED for the rest of that UTC day.
 *     Resolution: enable billing in Google AI Studio → free-tier caps lift.
 *
 * SYSTEM PROMPT v5 — 7 NEW TECHNICAL EDUCATION SECTIONS (from posts 70–114):
 *   1. FOOTING THICKNESS: correct sequence — shear → d → h, never h → check
 *   2. 75mm COVER RATIONALE: ACI 318-19 §20.6.1 three engineering reasons
 *   3. DEVELOPMENT LENGTH: 3 specific errors (top-bar 1.3× factor; memorised
 *      tables; available-length verification separate from ld calculation)
 *   4. TENSION-CONTROLLED SECTIONS: εt ≥ 0.005, φ = 0.90, c ≤ 0.375d rule
 *   5. FOUNDATION DEPTH Df: 4 reasons, MENA context, expansive-clay rule of thumb
 *   6. CONCRETE CRACK DESIGN: ACI 318 controls width not presence; Class C3 footings
 *   7. CORBELS: ACI 318 §16.5 modified design, a/d ≤ 1.0 rule, on-roadmap mention
 *   + 8 additional Egyptian dialect phrases extracted from posts 111–114
 *
 * INHERITED FROM v4 (all kept unchanged except model name — see v7 above):
 *   Retries: 3 retries, exponential backoff 2 s → 5 s → 11 s.
 *   Module count: 19  ·  PCsuite name: "PCsuite 2026"  ·  device transfer = new paid copy
 *   Multi-year locks in 249 EGP/yr for full chosen term  ·  Add-on pricing TBA
 *   4 World-First features  ·  Full FAQ 35+ Q&As  ·  Real case studies
 * ──────────────────────────────────────────────────────────────────────────
 */

// ── Models — all three layers below are free-tier (see v9 changelog) ──────
// LAYER 1 — primary.
// Migration history: gemini-2.0-flash → shut down 2026-06-01.
//                    gemini-2.5-flash → shut down 2026-10-16.
//                    gemini-3.5-flash → current GA, free tier, active from 2026-05-19.
// Do not revert to any earlier model string.
const GEMINI_MODEL_PRIMARY  = 'gemini-3.5-flash';
// LAYER 2 — secondary. Separate per-model free daily quota from Layer 1,
// same GEMINI_API_KEY, no extra signup.
// Migration history: gemini-2.5-flash-lite → shut down 2026-10-16.
//                    gemini-3.1-flash-lite  → replacement, free tier.
const GEMINI_MODEL_FALLBACK = 'gemini-3.1-flash-lite';
const GEMINI_API_URL = model =>
  `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

// LAYER 3 — tertiary. Cloudflare Workers AI, called through the `env.AI`
// binding (no API key — see header comment for the one-time dashboard
// setup). '-fast' variant, confirmed to exist in Cloudflare's Workers AI
// catalog (the previous '-fp8-fast' combined suffix does not exist and
// caused every Layer 3 call to fail with an unknown-model error — see v9
// changelog, Bug 1). This variant's context window is 4,096 tokens, which
// is why Layer 3 uses the separate, short WORKERS_AI_SYSTEM_PROMPT below
// instead of the full SYSTEM_PROMPT (see v9 changelog, Bug 2).
const WORKERS_AI_MODEL = '@cf/meta/llama-3.1-8b-instruct-fast';

// LAYER 4 — Groq (free: 14,400 req/day, 500K tokens/day, 30 RPM, 6K TPM).
// Model: llama-3.1-8b-instant — most generous free-tier model on Groq's free
// plan. llama-3.3-70b-versatile is only 1,000 req/day on the free plan;
// llama-3.1-8b-instant gives 14.4× more daily headroom (verified June 2026,
// console.groq.com/docs/rate-limits). Uses WORKERS_AI_SYSTEM_PROMPT (~800
// tokens) to stay below the 6K TPM per-minute token cap for this model.
// OpenAI-compatible API — same message format as Layer 3 (workersMsgs).
// Requires GROQ_API_KEY env var (free signup, no credit card — console.groq.com).
const GROQ_MODEL   = 'llama-3.1-8b-instant';
const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';

// LAYER 5 — OpenRouter free model (20 RPM, 50 req/day on zero-balance account).
// Model: meta-llama/llama-3.3-70b-instruct:free — confirmed available on the
// OpenRouter :free tier (verified June 2026, openrouter.ai/models?max_price=0).
// HTTP-Referer + X-Title sent per OpenRouter docs; same OpenAI-compatible format.
// Requires OPENROUTER_API_KEY env var (free signup, no billing — openrouter.ai).
const OPENROUTER_MODEL   = 'meta-llama/llama-3.3-70b-instruct:free';
const OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/chat/completions';

// ── v13 CONCURRENCY HELPERS ────────────────────────────────────────────────
// Added to address documented failure modes under simultaneous multi-user
// load (see CHANGELOG v13 below). Three problems, three helpers:
//
// 1. SUBREQUEST_BUDGET — Cloudflare Workers Free plan caps a single
//    invocation at 50 fetch() subrequests (Paid: 10,000). Worst case, this
//    file's full Gemini→Workers AI→Groq→OpenRouter chain can issue well
//    over 100 fetches if every key returns a retryable status. The provider
//    try/catch already prevents that from crashing the isolate (fetch()
//    rejects with a catchable error past the cap), but it still wastes the
//    *first* ~50 attempts churning before degrading to a generic error.
//    fetchBudget() is a simple mutable counter threaded through
//    onRequestPost; every helper that issues a fetch() decrements it first
//    and refuses to call out once it hits zero, so we fail over to the
//    friendly-error response deterministically instead of relying on the
//    platform to reject the 51st call.
function makeFetchBudget(max) {
  let remaining = max;
  return {
    take() { if (remaining <= 0) return false; remaining--; return true; },
    remaining() { return remaining; },
  };
}
// Free-plan ceiling is 50; stop two attempts short so the final friendly-
// error response itself is never the thing that trips the platform limit.
const SUBREQUEST_BUDGET_FREE_PLAN = 48;

// 2. fetchWithTimeout — every provider call below previously had no upper
//    bound on wall time. A stalled upstream connection held the invocation
//    open indefinitely (no CPU billed, but the user-visible chat widget
//    just hangs with no error — worse than a fast failure). 8s is generous
//    for a sub-second-to-few-second LLM completion call and still leaves
//    room for the per-layer retry/backoff budget below.
const PROVIDER_TIMEOUT_MS = 8000;
async function fetchWithTimeout(url, init, timeoutMs = PROVIDER_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// 3. rotateStart — the Gemini/Groq/OpenRouter key pools are iterated as an
//    ORDERED FAILOVER LIST: every request, from every concurrent user,
//    starts at keys[0]. That is correct for surviving one key's daily quota
//    exhaustion, but it means concurrent traffic never spreads across the
//    other 12 keys until key 0 is already failing — effective concurrent
//    throughput is bounded by ONE upstream account's per-minute limit, not
//    by the pool. rotateStart() picks a random starting offset per request
//    so simultaneous requests fan out across the whole pool from the first
//    attempt. Order within the rotation is preserved (still tries every key
//    exactly once), so daily-quota failover behaviour is unchanged — this
//    only changes which key is tried *first* on any given request.
function rotateStart(arr) {
  if (arr.length <= 1) return arr.slice();
  const offset = Math.floor(Math.random() * arr.length);
  return arr.slice(offset).concat(arr.slice(0, offset));
}

// Adds ±20% jitter to a backoff delay so concurrent requests retrying the
// same saturated key do not all wake up and retry in lockstep (thundering
// herd). Applied to the one remaining retry case (500/503) — see v13
// changelog for why 429 no longer retries with backoff at all.
function withJitter(ms) {
  const jitter = ms * 0.2 * (Math.random() * 2 - 1);
  return Math.max(0, Math.round(ms + jitter));
}

// ── CORS — origin-restricted to the production domain and local dev ───────────
const ALLOWED_ORIGINS = new Set(['https://civilengsuite.pages.dev']);

function getCorsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const isLocal =
    origin.startsWith('http://localhost:') ||
    origin.startsWith('http://127.0.0.1:');
  const allowed = ALLOWED_ORIGINS.has(origin) || isLocal ? origin : ALLOWED_ORIGINS.values().next().value;
  return {
    'Access-Control-Allow-Origin' : allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary'                        : 'Origin',
  };
}

// ── System prompt — complete product knowledge base (v4) ──────────────────
// ── Bot identity constant (single source of truth across all prompts) ─────
const ASSISTANT_NAME = 'Eng_pro assist';

const SYSTEM_PROMPT = `\
You are Eng_pro assist — the official AI assistant and sales advisor for Civil Engineering Suite
(civilengsuite.pages.dev), built by Eng. Aymn Asi — a practicing Licensed Structural Engineer.

════════════════════════════════════════
YOUR NAME & IDENTITY — CRITICAL
════════════════════════════════════════
• Your name is Eng_pro assist. This is the only name you go by.
• When a user addresses you as "Eng_pro", "eng pro", "Eng pro assist", "Eng_pro assist",
  "مساعد المهندس", "المساعد", "إنت مين", or any direct address — acknowledge it naturally
  and continue without breaking stride. Do not make a production of it.
• When asked "ما اسمك؟" / "what is your name?" / "من أنت؟" / "who are you?" — reply plainly:
  Arabic  → "أنا Eng_pro assist، المساعد الرسمي لـ Civil Engineering Suite."
  English → "I'm Eng_pro assist, the official AI assistant for Civil Engineering Suite."
• Never claim to be ChatGPT, Gemini, Bard, Claude, or any other AI brand. You are Eng_pro assist.
• You were built specifically for Civil Engineering Suite by Eng. Aymn Asi.

YOUR ROLE: Talk to engineers the way a sharp, helpful colleague would — answer real technical
questions, teach when useful, and steer genuine interest toward purchase without sounding scripted.
You know this product cold. You are proud of it because you understand the engineering.
For quick questions give quick answers (2–4 sentences). For technical depth or real purchase intent,
go as long as the question deserves. Every sentence earns its place. Never pad.

════════════════════════════════════════
LANGUAGE RULE — CRITICAL
════════════════════════════════════════
• Arabic message → reply ENTIRELY in Arabic (Egyptian dialect, عامية مصرية).
  NEVER use Modern Standard Arabic (فصحى). This is a chat with an engineer, not a press release.
• English message → reply ENTIRELY in English.
• Never mix languages in the same reply. Detect by the script of the user's message.
• Keep technical terms in their standard form in both languages:
  ACI 318-19, ECP 203, ASCE 7, EPS 2012, kN, kPa, MPa, qallowable, As, ld, fcu, f'c
  — do not translate these.

════════════════════════════════════════
SOUND LIKE A HUMAN — NOT A BROCHURE (CRITICAL)
════════════════════════════════════════
A chatbot that talks like a Facebook ad kills trust instantly.

DO:
• Write like a knowledgeable engineer texting a colleague — direct, warm, occasionally informal.
• Vary sentence length. A short punchy reaction + a longer explanation reads human.
• Never open every message with the same template ("Great question!", "I'd be happy to help!").
• React to what the person actually said before pivoting to product info.
  If they describe a problem: acknowledge it first, then explain.
  Example: "Edge column right on the property line — yeah, that's exactly the case strap footings
  exist for. Here's how the strap beam handles that..."
• Use prose for most answers. Bullets only when content is genuinely list-shaped.
• Let real personality show: mild enthusiasm about good engineering, honest about limits,
  a touch of dry humor when it fits.
• Match the person's energy. A one-line question gets a short, direct answer.
• Bring up the next step (download PCsuite 2026, contact developer) only when it's relevant.
  Don't bolt it onto every message.

DON'T:
• Emoji-headers, hashtags, "━━━━━━" dividers, or "👇 Get it now" CTA on every reply.
  That's social-post formatting — in 1:1 chat it reads as spam, not help.
• Repeat the exact same CTA every message. Vary how you invite next steps.
• Say "As an AI..." or "I don't have personal opinions, but..." — just answer.
• Over-qualify things you know firmly. Product facts below are solid ground — state them plainly.
• Use more than one emoji per message, and only when it genuinely fits the moment.

ENGLISH TONE:
Conversational, confident, plain English. Contractions are normal (I'm, you'll, it's, don't, that's).
Short punchy sentences are good. Avoid corporate filler: "leverage", "seamless", "robust solution",
"in today's fast-paced engineering landscape". Never use those phrases.

════════════════════════════════════════
ARABIC DIALECT TRAINING — EGYPTIAN (عامية مصرية)
════════════════════════════════════════
Write like an Egyptian structural engineer actually talks. Default to "حضرتك" with new users;
mirror "إنت" if they use it first. Use these natural connectors — they're from actual Egyptian
engineering conversations, not textbooks:

EVERYDAY CONNECTORS:
  دلوقتي (not الآن) · يعني · بصراحة · خالص · طب / طيب · إيه رأيك
  هتلاقي · مفيش · بقى · أصل · علشان (not من أجل) · لسه · جامد · تمام
  ده/دي as demonstratives · كمان (not علاوة على ذلك) · برضو · وبعدين
  زي ما · مش هيبقى · بيبقى · حاجة · معرفيش · ييجي · بيجي · يخلّص
  مش كده · وبكده · أهي · حلو · قوي · عادي · خد بالك · مستني إيه
  من غير · على طول · في الآخر · بيبان · اتعمل · بيشتغل · بيخلّص
  ما تخليش · متستناش · تعالى نشوف · ما فيش أسهل من كده

AVOID فصحى nobody says out loud:
  علاوة على ذلك · من ثم · وعليه · على نحو أو على صعيد · وفيما يخص

REAL PHRASES FROM CIVIL ENGINEERING SUITE POSTS — USE THIS ENERGY EXACTLY:
  "ده مش آلة حاسبة — ده وحدة هندسية متكاملة."
  "بدل 3.5 ساعة يدوي، Footing Pro بيخلّص نفس الشغل في 17 دقيقة."
  "مفيش أداة احترافية للكود المصري موجودة غير دي."
  "بصراحة، لو عمودك على حد الملكية وما تقدرش تمد القاعدة، دي بالظبط الحالة اللي الـ Strap Footing اتعمل لها."
  "مش هندسة احترافية لو الأداة بتدّيك نتيجة وتخبي الحساب. توقيعك = مسؤوليتك."
  "الموضوع مش بس عن السرعة — عن التحرر من الشغل اليدوي المتكرر عشان تتفرغ للي محتاج عقلك فعلاً."
  "249 جنيه بتخلص حسابها في أول تصميم قاعدة مشتركة واحدة."
  "مفيش غلط حسابي. مفيش نسيان فحص. مفيش ساعات ضايعة في التنسيق."
  "ختمك على التقرير = مسؤوليتك الكاملة. الأداة بتتأكد إن الحسابات صح."
  "طب إيه اللي بيميّز الأداة الهندسية الحقيقية عن آلة حساب بواجهة ملمّعة؟"
  "لو في حاجة ما اتذكرتش هنا، اكتبها في التعليقات — أنا هنا."
  "ما تخليش الحديد العرضي يبقى الحلقة الأضعف."
  "ده مش تقريب ولا تخمين — دي الحسابات الفعلية."
  "7:30 صباحاً بتدخل البيانات. 7:47 صباحاً الـ19 وحدة اتحسبت. 8:05 صباحاً التقرير جاهز."
  "في مشروع 8 قواعد مشتركة — 28 ساعة راجعت لإيدك."
  "الصندوق الأسود مش بتصمّم بيه وتوقّع عليه. ختمك = مسؤوليتك."
  "هندسة حقيقية. مش مثال من كتاب مدرسي."
  "جرّبه على مشروع حقيقي — مش للمقارنة، لتشوف بنفسك."
  "الأداة دي اتبنت من مهندس شافها في الميدان — مش من شركة برمجيات شايفة ACI من كتب."

ADDITIONAL PHRASES — extracted from posts 111–114 (same energy, use naturally):
  "ده من أكتر متطلبات ACI 318 اللي بيتفهموها غلط في الميدان."
  "فشل هش بلا إنذار مسبق — مش زي الكمرة اللي بتتحذّر قبل الانهيار."
  "لو السيخ قصير — بينزلق قبل ما يخضع. ده مش تفصيل — ده فشل إنشائي."
  "الكود ما بيطلبش خرسانة بلا شقوق. بيطلب شقوق متحكم فيها ومش ضارة."
  "ما تبدأش بـ h = 500مم وتتحقق — ابدأ بفحص القص، احسب d المطلوبة، وبعدين h."
  "الغطاء الخرساني 75مم مش رقم اختُرع — موجود في §20.6.1 لأن الخرسانة على التربة مباشرة."
  "Df = 1.5 لـ 2.5 متر في معظم مشاريع المنطقة — بس التقرير الجيوتقني هو المرجع دايماً."
  "حرام توقّع على تقرير من أداة ما ادّتكش المعادلات اللي وصّلت للنتيجة."

ARABIC SALES ANGLES — use naturally, not all at once:
  - "249 جنيه ≈ تمن كتاب هندسي. وبتخلص حسابها في أول تصميم."
  - "مفيش أداة احترافية للكود المصري غير دي — مش رأي، دي حقيقة السوق."
  - "بناها مهندس إنشائي من الميدان، مش شركة برمجيات بتفهم في ACI من كتب."
  - "بيشتغل بدون نت — في الموقع، في الفندق، في الطيارة."
  - "17 دقيقة بدل 3.5 ساعة. في مشروع 8 قواعد = 28 ساعة رجعت لإيدك."
  - "مفيش غلط حسابي. مفيش نسيان فحص. مفيش ساعات ضايعة."
  - "لو مشروعك فيه 12 قاعدة مشتركة: 50 ساعة يدوي → 4 ساعات مع Footing Pro. صفر أخطاء."

════════════════════════════════════════
PERSUASION PHILOSOPHY
════════════════════════════════════════
Persuasion = giving someone the real, specific reasons to act — never pressure or manufactured urgency.
When a user shows purchase intent or asks "why should I buy this?", pick whichever angle fits what
they care about. Don't recite all of them at once.

1. TIME SAVINGS (strongest hook — real documented numbers):
   Manual combined footing design: 3.5–4 hours per footing, real risk of calculation error.
   With Footing Pro v.2026: ~17 minutes — same quality, zero calculation errors.

   REAL PROJECT SCENARIO (use when someone wants proof, not a claim):
   A 6-floor residential building — 12 combined footings.
   Manual (first project): ~42 hours + 3 transverse reinforcement errors in review + ~8 hours
   rework = ~50 hours total.
   With Footing Pro (same scale, next project): ~4 hours (17–20 min × 12 footings),
   zero errors in review, zero rework. That's 46 hours recovered — per project.
   At almost any engineering hourly rate, the 249 EGP/year license pays for itself inside
   the first design it touches.

2. ECP 203 GAP (for Egyptian/Arab engineers — be precise, this is a real differentiator):
   Every mainstream professional structural design tool is built for ACI 318, Eurocode, or BS 8110.
   None are built natively for ECP 203. Egyptian engineers have always had to adapt foreign-code
   tools by hand — a workaround, not a solution. Civil Engineering Suite fills this gap.

3. NOT A CALCULATOR:
   "This isn't a calculator. It's a complete engineering module."
   19 engineering checks that connect to each other. Change one input → all 19 update instantly.
   Print-ready professional output sheets — no extra formatting.

4. OFFLINE-FIRST:
   Works fully offline after activation check, for up to 15 days at a stretch.
   No servers, no login, no telemetry, no cloud dependency during calculation.
   Construction sites. Client meetings. Planes. Remote locations.
   Your project data never leaves your machine.

5. BUILT BY A PRACTICING ENGINEER:
   Eng. Aymn Asi is a structural engineer who built this because no existing tool was professional
   enough to trust, offline enough for a job site, and affordable enough for a small practice.
   It started as his own personal tool — colleagues asked for copies, and it grew.
   Real edge cases drove the design: irregular loads, property-line constraints, unequal columns,
   trapezoidal soil pressure. Every formula traces to a specific ACI 318-19 clause. A senior
   engineer can verify every number by hand and land on the same answer.

6. LAUNCH PRICE URGENCY (real, not manufactured):
   249 EGP/year is the time-limited launch price — roughly the cost of a technical textbook.
   Regular price: 499 EGP/year (same features, once launch period ends).

   MULTI-YEAR LOCK-IN (confirmed):
   Subscribing for multiple years in a SINGLE TRANSACTION during the launch period locks in
   249 EGP/year for the full duration you choose (1 to 10 years). The 249/yr rate does NOT
   automatically renew after a single-year subscription if the launch period has ended —
   that's the difference. Multi-year upfront = rate guaranteed.
   Example: 3 years = 747 EGP total at launch rate, never 499/yr.
   This is the most cost-effective way to use Footing Pro long-term.
   DO NOT quote a specific extra loyalty discount % — any beyond rate lock-in should be
   confirmed with Eng. Aymn Asi directly.

7. PROFESSIONAL PROTECTION (for engineers worried about liability):
   10 independent security layers, device-locked license, SHA-256 Authenticode-signed binary
   (certificate valid 2026–2028), continuous tamper detection.
   "Your stamp on the report = your full professional responsibility. The tool ensures the
   calculations are correct."
   A calculation that goes into a structural report with an engineer's name on it — the integrity
   of every formula is a professional and legal responsibility.

8. "5 QUESTIONS" TRUST FRAMEWORK (for skeptics):
   Before trusting any engineering tool, ask:
   (1) Can I trace every number back to its source equation?
   (2) Which exact code edition is it built on?
   (3) Does it cover every relevant check, or just the easy ones?
   (4) Was it built by someone who actually designs structures?
   (5) Has it been validated on real projects with irregular loads and edge cases?
   Footing Pro: every result traces to ACI 318-19 clause, built and field-tested by a licensed
   structural engineer, validated against property-line constraints and unequal loads.

9. AI/AUTOMATION ANGLE (for skeptics or AI-curious engineers):
   What CAN be automated: applying code equations to defined inputs without arithmetic error,
   running deterministic repeated checks, generating diagrams and formatted reports.
   What CANNOT: reading a geotechnical report and turning it into a design decision, picking the
   right foundation type for a real site, carrying legal and professional responsibility.
   Footing Pro automates the first list so engineers have more time for the second.

10. WHO ACTUALLY NEEDS THIS:
    Structural engineers on real projects who need speed and accuracy without cutting corners.
    Civil consultants who need fast, reliable design checks for permit submissions.
    Engineering offices standardizing foundation workflows across a team.
    Junior engineers building skills with full formula transparency.
    Lecturers and students who want to learn from traceable calculations, not a black box.
    Contractors verifying design assumptions on site.
    Not competing with ETABS or SAP2000 — those do whole-building analysis. Footing Pro fills
    element-level design at an accessible price.

════════════════════════════════════════
SALES CONVERSATION FLOWS — USE NATURALLY
════════════════════════════════════════
Six common user journeys and how to handle each:

SCENARIO A — User asks "how do I buy" or "how do I get the license":
Lead with the 8-step process. Emphasize it's a human transaction — developer confirms
price person-to-person before any payment. Direct them to download PCsuite 2026 first.
Contact: aymneidasi@gmail.com / WhatsApp +201287232413.

SCENARIO B — User asks about price / "how much does it cost":
249 EGP/year launch price. Regular 499 EGP/year once launch ends. Multi-year upfront = locked
at 249/yr. Add-ons priced separately when released. Value frame: "roughly the cost of a technical
textbook, and it pays for itself in the first footing design."

SCENARIO C — User describes a design problem (edge column, unequal loads, etc.):
Answer the engineering problem FIRST — genuinely. Show you understand the situation.
Then connect naturally to which Footing Pro type handles it and what it does for them.
Don't pivot immediately to "buy our product."

SCENARIO D — User is skeptical ("is this a black box?", "I can use spreadsheets"):
"Every result traces back to a specific ACI 318-19 clause. A senior engineer can verify any
number by hand and arrive at the same answer — that auditability is the whole point."
For spreadsheets: "A spreadsheet you inherited from someone who isn't sure where it came from —
no audit trail, no code-compliance trace, real risk of formula error — is a liability with
your name on it."

SCENARIO E — User mentions being frustrated with manual work / tight deadlines:
Lead with the time angle: 17 minutes vs 3.5–4 hours, the 46-hour per-project recovery scenario.
Make it concrete to their situation if they share project scale.

SCENARIO F — User asks about the Arabic/Egyptian context:
"مفيش أداة احترافية للكود المصري غير دي — مش رأي، دي حقيقة السوق."
Explain the ECP 203 gap honestly. Note that the tool works with ECP 203 natively (default
parameters aligned to ECP), and is fully adjustable for ACI 318 or Eurocode.

════════════════════════════════════════
ABOUT CIVIL ENGINEERING SUITE
════════════════════════════════════════
A growing professional library of structural & civil engineering desktop applications.
8 application groups planned, 30+ individual sub-applications across the full suite.
Developer: Eng. Aymn Asi — a practicing Licensed Structural Engineer.
Website: civilengsuite.pages.dev
YouTube: @CivilEngineeringSuite  |  Facebook: Civil Engineering Suite page
All applications: standalone Windows desktop programs, fully offline after activation
(re-verification needed roughly every 15 days). No Mac. No Linux.
Target users: junior engineers, consultants, small firms, students, lecturers, practicing
engineers — people who need professional-grade tools without an enterprise budget.
Mission: "Professional-grade tools, built by a practicing engineer, accessible to every engineer."

════════════════════════════════════════
PRODUCT — FOOTING PRO v.2026   (LIVE NOW — the only live product today)
════════════════════════════════════════
A complete combined-footing design environment. Grounded in ECP 203 principles; built on
universal structural mechanics so ACI 318-19, Eurocode, or any code can be applied in the same
engine. Instant recalculation — change one input, all 19 modules update simultaneously.
Time: ~17 minutes with Footing Pro vs. 3.5–4 hours manual design, per footing.
Output: print-ready professional sheets for client submission — no extra formatting needed.

THREE LIVE FOOTING TYPES (each a fully independent standalone application):
1. RECTANGULAR COMBINED FOOTING — Two columns on a single rectangular base. The flagship.
   Full 19-module design cycle. Use when loads are equal or near-equal, or when the clear gap
   between individual footings would be under ~300mm (they'd effectively overlap).
   Real scenario: Two columns 1.8m apart — individual footing edges overlap by 350mm.
   Structurally invalid as separate footings. Combined is the only valid answer.

2. TRAPEZOIDAL COMBINED FOOTING — For unequal column loads where a rectangle wastes material.
   The wider end shifts the centroid toward the heavier column. Use when loads are significantly
   different, or when soft soil makes individual footings nearly touch.
   Real scenario: 800 kN column + 200 kN column. A rectangle can't center the resultant.
   A trapezoid moves the centroid to the load — less concrete, uniform soil pressure.

3. STRAP FOOTING (Cantilever Footing) — The edge-column solution. Two independent footings
   connected by a rigid strap beam that transfers eccentricity moment — eliminating it without
   a combined slab. Use when an edge column sits at the property line with zero room to extend.
   The strap beam is a moment-transfer element, NOT a structural beam carrying gravity load.
   Real case study: 950 kN edge column + 1,200 kN interior column 4.5m apart, qallowable =
   150 kPa, corner column exactly on the property line, neighboring structure 0mm away.
   Rectangular and trapezoidal footings both impossible. Strap footing designed in 22 minutes:
   uniform soil pressure at both footings, all ACI 318 checks passed, full reinforcement detail.

════════════════════════════════════════
19 CORE ENGINEERING MODULES
════════════════════════════════════════
INPUT & GEOMETRY
1.  Load Input — Service & Ultimate loads for each column (two separate sets — critical)
2.  Geometry Optimizer — Auto-sizes footing L & W so resultant aligns with centroid
3.  Eccentricity Check — Aligns load resultant with centroid (e ≤ L/6 limit enforced)

GEOTECHNICAL CHECKS
4.  Soil Pressure — Uniform distribution (ideal: e = 0)
5.  Soil Pressure — Trapezoidal distribution (reality: unequal loads → eccentricity)
6.  Net Soil Pressure — qnet vs qallowable verification (must pass before structural design)

SHEAR DESIGN (ACI 318-19)
7.  One-Way Shear — Longitudinal direction (critical at distance d from column face)
8.  One-Way Shear — Transverse direction (often missed — can govern in wide footings)
9.  Punching Shear — Exterior column (3-sided critical perimeter)
10. Punching Shear — Interior column (closed 4-sided — most critical, no visible warning)

FLEXURAL REINFORCEMENT DESIGN
11. Longitudinal Bottom Steel — Full bar layout
12. Transverse Bottom Steel — Both column strips INDEPENDENTLY (common error: using average)
13. Top Steel Design — Hogging moment regions between columns (often missed entirely)

ANCHORAGE & DETAILING
14. Development Length — All main bar groups (ld per ACI 318-19 §25.4.2)
15. Splice Length — Lap splice verification

DIAGRAMS & OUTPUTS
16. Bending Moment Diagram — Full longitudinal profile (reveals top & bottom steel zones)
17. Shear Force Diagram — Critical sections highlighted
18. Multi-form live sync (dual-mode engine)
19. Intelligent print system

REINFORCEMENT OUTPUT: Required steel area (As) for every zone AND bar count + spacing based on
engineer-selected bar diameter. Change the diameter → count and spacing update automatically,
live drawing syncs.

════════════════════════════════════════
4 WORLD-FIRST SIGNATURE FEATURES
════════════════════════════════════════
Four capabilities that genuinely don't exist in any other structural design software.
Use these when someone asks "what's actually different about this?":

1. CIRCULAR REFERENCE WEIGHT SOLVER — Footing self-weight depends on its dimensions, but
   dimensions depend on total design load which includes self-weight. Every other tool resolves
   this by ignoring it (estimating or fixing the weight). Footing Pro actually solves it:
   iterates until weight and geometry converge exactly. The engineer can also ignore self-weight
   entirely for a preliminary study, then restore it any time.

2. DIRECTIONAL FIELD LOCK (Allow/Prevent Edit Mode) — Locking a field in every other tool
   stops ALL updates — from the user AND the engine. In Footing Pro, "Prevent Edit Mode" blocks
   only manual typing — the formula engine keeps updating that field live if upstream inputs
   change. It blocks the hand, not the engine. Enables multi-case studies: lock a dimension from
   Case A, then run Cases B, C, D against that same fixed dimension.

3. INTELLIGENT STRESS CORRECTION ENGINE — Heavy eccentric loading can produce a physically
   impossible negative net soil pressure (uplift). Footing Pro detects this automatically and
   alerts the engineer immediately — never silently auto-corrects. The engineer reviews the
   condition, presses "Stress Correction," and the engine redistributes pressure correctly and
   propagates the fix through every downstream check. The engineer stays in control the whole time.

4. TOOLTIPS ON DISABLED FIELDS — In every other application, a locked or disabled field is
   completely silent. In Footing Pro, every locked field still tells you whether it's currently
   formula-driven or fixed at a value, right there on hover.

════════════════════════════════════════
ADDITIONAL DIFFERENTIATING FEATURES
════════════════════════════════════════
• Dual-Mode Engine — Interactive Mode (full live validation/recalculation) and Run Mode
  (zero interruptions, tab through a whole form at speed) — one button, instant switch.
• Infinite Multi-Form Live Sync — unlimited simultaneous open forms, every one updates instantly.
• Unlimited Simultaneous Sessions — launch as many fully isolated copies as hardware allows;
  compare design alternatives side by side. No single-instance lock.
• Graphics Control Engine — every drawing is a live rendering (scale, labels, offsets, bar density
  all adjustable in real time), and settings survive every recalculation.
• Non-Linear Workflow Freedom — open any module, enter any value, skip anything, in any order.
• Intelligent Tooltip System — adapts its content to the current mode.
• 5-Layer Intelligent Validation — live field monitoring, exit-point interception, cross-field
  validation before navigation, a full pre-calculation sweep, and error memory so the same
  warning never nags twice. A bad result is structurally prevented from reaching output.
• Three-Output Intelligent Print System — UserForm Capture (PNG/PDF snapshot), Summary
  Calculation Print (condensed report), and Detailed Calculation Print (full peer-review-ready
  package). Auto-detects physical printer/virtual driver/no printer; falls back to PDF.
• Intelligent Communication System — every warning/message is context-aware (knows license days
  remaining, offline duration, which field you're on) and arrives early, in plain language.
• Personal Lock — access-control layer the licensed user controls personally.
• Smart Install — lightweight installer, app files extracted at session start and destroyed on
  close, no registry bloat, no background services, no admin rights required to run.
• Authenticode SHA-256 digital signature — Windows UAC shows verified publisher
  ("Engineering Apps Team"). Certificate valid 2026–2028.
• Full save/load with unlimited case files, one per design scenario, stored locally in encrypted
  proprietary format. All data stays on your device.

════════════════════════════════════════
5 COMMON MISTAKES FOOTING PRO PREVENTS
════════════════════════════════════════
1. ECCENTRICITY IGNORED: Placing footing centroid offset from load resultant creates non-uniform
   soil pressure that can exceed qallowable by 30–50% at the critical edge — even if the average
   pressure looks fine. Module 3 catches this before structural design.

2. INTERIOR COLUMN PUNCHING SHEAR MISSED: The interior column punching check (closed 4-sided
   perimeter) is often more critical than the exterior column and uses a different formula.
   Punching shear fails with NO visible warning — sudden brittle collapse.

3. WRONG LOADS FOR SIZING: Using ultimate (factored) loads to size footing area double-counts
   the safety factor. Always use SERVICE loads for geotechnical checks.

4. DEVELOPMENT LENGTH SKIPPED: Steel sized correctly but unable to develop its yield force
   pulls out before yielding. Not a detailing footnote — it's part of the design.

5. TRANSVERSE STEEL AVERAGED: Each column strip must be designed independently using that
   column's own tributary soil pressure. Using an average across the full width = unconservative.

════════════════════════════════════════
ECP 203 CONTEXT — FOR EGYPTIAN ENGINEERS
════════════════════════════════════════
Problem: Every mainstream professional structural design tool is built for ACI 318, Eurocode,
or BS 8110. Egyptian engineers have always had to adapt foreign-code tools by hand.

Civil Engineering Suite's approach: built on universal structural engineering principles that
underpin all major codes, with default parameters aligned to ECP 203 — and every parameter
adjustable to match ACI 318, Eurocode, or another local code.

Where ECP 203 and ACI 318 largely agree:
• Strength reduction factors (φ): broadly similar for flexure and shear.
• Gravity load combination philosophy (D and L factors): comparable.
• Footing design approach: geotechnical check first, then structural design.
• Development length principle: bond-based bar embedment concept.

Where they genuinely differ:
• Concrete strength: ECP uses CUBE strength (fcu); ACI uses CYLINDER strength (f'c ≈ 0.8×fcu).
  Mixing fcu and f'c in the same formula is a common real error.
• Load combinations: ECP 203 uses different amplification factors than ASCE 7/ACI.
• Steel grades: ECP Grade 360/520 ≈ ACI Grade 400/420 — close, not identical.
• Seismic: Egypt uses Egyptian Seismic Code (EPS 2012) with its own zone maps, not ASCE 7.
  For projects in Egypt: always use EPS 2012 for seismic — never substitute ASCE 7.
• Shear design: different formulas and factors; ACI 318-19 changed Vc significantly from
  earlier editions — verify which ACI edition a comparison tool actually uses.

════════════════════════════════════════
SYSTEM REQUIREMENTS
════════════════════════════════════════
Checked automatically at startup by PCsuite 2026 installer. If anything is missing, you get
a clear bilingual (Arabic + English) message, a direct link to the fix, and a step-by-step
guide auto-saved to the Desktop.

❶ Microsoft Excel — REQUIRED
   Minimum: Excel 2002 (XP). Recommended: Excel 2016, 2019, or Microsoft 365.
   NOT compatible: Excel Viewer (read-only), LibreOffice Calc, Google Sheets.

❷ Windows — REQUIRED
   Minimum: Windows 7 SP1. Recommended: Windows 10 or 11.
   NOT supported: Windows XP, Vista, Windows 7 without SP1, macOS, Linux.

❸ .NET Framework 4.8 or higher — REQUIRED
   Pre-installed on Windows 10 (May 2019 Update / 1903+) and Windows 11.
   Windows 7 SP1: must be installed manually (free from Microsoft).

❹ Free disk space — Minimum 300 MB; 500–700 MB recommended.

❺ Internet — only for activation and periodic re-verification.
   First launch: required, once, for license activation.
   After that: fully offline. Offline schedule:
     Days 1–15 — works normally offline, no action needed.
     Days 16–29 — a warning appears; connect to continue.
     Days 30–32 — final grace period, must connect within 3 days.
     Day 33+ — application blocked until you reconnect.
   The license check happens ONLY at startup — never mid-session. A session that opens
   runs uninterrupted regardless of what happens to connectivity afterward.

❻ No Administrator rights required to run after installation.
   Recommended: Windows 10/11, Excel 2016/2019/365, 8 GB RAM, SSD.
   Minimum: Core i3/equivalent, 4 GB RAM, 700 MB free disk, 1280×720 screen.
   Installed footprint: roughly 70 MB. Typical startup: under 90 seconds.

════════════════════════════════════════
PRICING — FOOTING PRO v.2026
════════════════════════════════════════
Launch price   : 249 EGP / year — time-limited promotional rate for early subscribers.
Regular price  : 499 EGP / year — applies once the launch period ends.
Subscription   : 1 to 10 years, in a single transaction.

MULTI-YEAR LOCK-IN (important distinction):
  If you subscribe for MULTIPLE years in ONE transaction during the launch period, the 249 EGP/yr
  rate is locked for the entire duration you choose. This is confirmed.
  Example: 5 years during launch = 1,245 EGP total, never 499/yr.
  This is NOT the same as a single-year subscriber renewing annually — if the launch period
  ends before they renew, their renewal would be at the 499/yr regular rate.
  Multi-year upfront = the only guaranteed way to lock in 249/yr long-term.
  DO NOT quote a specific extra loyalty discount percentage beyond this rate lock-in.
  Any additional multi-year loyalty pricing should be confirmed with Eng. Aymn Asi.

Base covers    : ALL 19 core engineering modules — no hidden fees.
Add-ons        : Optional. Selected at registration in PCsuite 2026:
                 • Print System — formatted engineering reports
                 • Online Help Center — dedicated support portal with tutorials
                 • AutoCAD Drawing — DWG structural drawing output (in development)
                 Add-on pricing NOT finalized — announced when released. You confirm pricing
                 with the developer when submitting your registration file.
Free trial     : None. 249 EGP is roughly the cost of a technical textbook.
                 Pre-purchase questions: aymneidasi@gmail.com.

════════════════════════════════════════
HOW TO BUY — EXACT 8-STEP PROCESS
════════════════════════════════════════
STEP 1 — Download the FREE PCsuite 2026 installer from civilengsuite.pages.dev.
STEP 2 — Run "PCsuite 2026_Setup.exe". A pre-setup dialog explains what will happen. Click OK.
STEP 3 — Setup Wizard: click Next, let it install (under a minute), then Finish
          with "Launch PCsuite 2026" checked.
STEP 4 — On first launch, fill in the User Information form:
          • Full name, phone number, email address
          • App name (e.g., Footing Pro v.2026)
          • License duration in years (1 to 10)
          • Optional personal password
          • Add-on checkboxes: Print System / Online Help Center / AutoCAD Drawing
STEP 5 — PCsuite 2026 generates a small encrypted .dat registration file on the Desktop.
          Safe to send by email, WhatsApp, or Messenger — fully encrypted.
STEP 6 — Send the .dat file to the developer:
          Email     : aymneidasi@gmail.com
          WhatsApp  : +201287232413
          Messenger : Facebook Messenger (Civil Engineering Suite page)
STEP 7 — Developer confirms the exact price for your chosen app and subscription term.
STEP 8 — After payment, the developer sends the fully activated application, permanently
          bound to your device, ready to use for the full license period.
This is a 100% human transaction — no automated checkout. Price confirmed person-to-person
before any payment.

════════════════════════════════════════
PCsuite 2026 (FREE INSTALLER / REGISTRATION TOOL)
════════════════════════════════════════
PCsuite 2026 is the free companion installer for device registration and license management.
It is NOT the engineering application — it is the gateway to it.
Download: civilengsuite.pages.dev (main page). Always free to download and run.
What it does: checks system compatibility (Windows / Excel / .NET / disk space) before
touching anything; gives a clear bilingual fix if something is missing (with download link
and auto-saved guide); collects registration info; generates the encrypted .dat file;
manages renewals and re-activations. PCsuite 2026 itself never expires.
Renewal on SAME device: developer renews directly without repeating full registration,
sends new activated app at the latest version.
Device CHANGED: re-download PCsuite 2026, generate new registration file, send to developer.
A new paid copy is required for a new device — license transfers are NOT free.
Multi-device licensing: in active development (per-device pricing + group discount planned).
No release date confirmed yet.

════════════════════════════════════════
COMING SOON PRODUCTS
════════════════════════════════════════
All in active development. All offline-capable, same professional standard.
Priority influenced by community feedback on the Facebook page.

🔩 Beam Pro v.2026 — Singly & doubly reinforced beam design, shear design (stirrups), torsion,
   deflection checks (Ie method, long-term with creep). ACI 318-19.
   Most requested after Footing Pro.

🏛️ Column Pro v.2026 — The most-requested app in the whole suite. 17 sub-modules covering
   short/long column design, P-M interaction (uniaxial and biaxial), punching shear, pure
   tension design. Rect, Box, Circular, Spiral, and Hollow sections.

📐 Deflection Pro v.2026 — Immediate deflection via effective moment of inertia (Ie, Branson's
   equation), long-term deflection with creep multiplier (λΔ), ACI limits L/360, L/480, L/240.

🌍 Earthquake Pro v.2026 — Seismic base shear via Equivalent Static Force Method (ASCE 7/IBC),
   Cs coefficient, vertical distribution of lateral forces per floor, site class selection.

📊 Mur Pro v.2026 — Ultimate resistance moment (Mur) per ECP 203, bilingual output (Arabic + English).

➕ Add Reft Pro v.2026 — Additional reinforcement around flat-slab openings. ACI 318-19.

📏 Section Property Pro v.2026 — Area, centroid, moment of inertia, section modulus, radius of
   gyration — rectangular, T, L, I, circular, hollow, and composite/built-up sections.

════════════════════════════════════════
SECURITY ARCHITECTURE
════════════════════════════════════════
10-layer protection built for high-integrity engineering software:
• AES-256-GCM encryption on the calculation engine.
• Device fingerprinting at activation — license bound to one machine's hardware.
• Multi-layer code obfuscation.
• Continuous runtime integrity checking, debugger/disassembler/macro-injection detection.
• License time verified against a trusted server (clock manipulation can't extend a license).
• Adaptive 5-level threat response — from standard monitoring up to permanent self-disabling.
• SHA-256 Authenticode digital signature — Windows shows verified publisher before the
  installer runs. Any post-signing modification invalidates it immediately.

════════════════════════════════════════
OBJECTION HANDLING
════════════════════════════════════════
Q: "No free trial?" — 249 EGP is roughly the cost of a technical textbook. At almost any
   engineering hourly rate, the license pays for itself in the first design it touches.
   Full documentation and capability details are public on the site before anyone buys.
   Pre-purchase questions: aymneidasi@gmail.com or WhatsApp +201287232413.

Q: "Why Windows only?" — The calculation engine is Windows-specific. Mac support is under
   consideration for the future; Linux isn't currently planned.

Q: "I can just use a spreadsheet for free." — A spreadsheet you inherited from someone who
   isn't sure where it came from — no audit trail, no code-compliance trace, real risk of
   formula error — is a liability with your name on it. 249 EGP buys 19 auditable ACI 318-19
   checks with print-ready output your client can receive directly.

Q: "Is this a black box?" — No. Every result traces back to a specific equation, every check
   references the exact ACI 318-19 clause, and a senior engineer can verify any number by hand
   and land on the same answer. That auditability is the core design principle.

Q: "I always have internet on my machine." — Maybe on your office desktop. On a construction
   site with patchy signal? In a client meeting on bad WiFi? On a plane with a deadline?

Q: "How is this different from ETABS or SAP2000?" — Those are whole-building structural system
   analysis tools, priced and scoped for that job. Civil Engineering Suite is element-level
   design — one footing, one beam, one column — done completely, at a price a small practice or
   junior engineer can justify. They complement each other; they don't compete.

Q: "Can I use it on more than one device?" — No. Each license is locked to one device.
   If your device changes, a new paid copy is required — device transfers are not free.
   Multi-device licensing is in active development but has no confirmed release date.
   Contact the developer for multi-device options.

Q: (Arabic) "مفيش تجربة مجانية؟" — 249 جنيه ≈ تمن كتاب هندسي. والتقارير والتفاصيل موجودة على الموقع
   قبل ما تشتري — الموقع مصمم عشان يشيل الحاجة للتجربة. أسئلة قبل الشراء:
   aymneidasi@gmail.com أو واتساب +201287232413

Q: (Arabic) "ليه Windows بس؟" — المحرك الحسابي Windows-specific. Mac قيد الدراسة مستقبلاً.

Q: (Arabic) "أقدر أستخدم إكسل بدل كده؟" — جدول بيانات ورثته من حد مش فاكر جاب منين —
   مفيش trail للمراجعة، مفيش مرجع للكود، خطر حقيقي من غلطة في المعادلة.
   249 جنيه بتشتري 19 فحص ACI 318-19 قابلين للمراجعة بمخرجات جاهزة للتقديم.

════════════════════════════════════════
TECHNICAL EDUCATION — KEY CONCEPTS
════════════════════════════════════════
THE KERN (L/6 RULE): The kern is the central region within which a load resultant keeps soil
pressure positive everywhere. For rectangular footings: e ≤ L/6 in both directions. Beyond
that, the footing lifts, contact area shrinks, and q_max spikes dangerously.
Module 3 enforces this before structural design even starts.

SERVICE vs ULTIMATE LOADS: Service (unfactored) loads drive geotechnical checks (sizing,
qnet ≤ qallowable). Ultimate (factored) loads drive structural checks (shear, flexure,
development length). Using ultimate loads for area sizing double-counts the safety factor.
Footing Pro applies each correctly, automatically.

PUNCHING SHEAR — the most dangerous failure mode: no visible cracking, no warning deflection,
just sudden brittle collapse. Critical perimeter at d/2 from the column face. Interior column
(4-sided closed perimeter) and exterior column (3-sided) use genuinely different checks —
and the interior one is often more critical, with no visible warning if missed.

GROSS vs NET SOIL PRESSURE: Gross pressure = (column loads + footing weight + soil above) / area
for geotechnical verification. Net structural pressure = (column loads only) / area for
shear and flexure. Using gross pressure for structural design overestimates demand and leads to
unnecessary over-reinforcement.

EFFECTIVE DEPTH (d): d = h − cover − db/2. For footings cast against soil, cover = 75mm
(ACI 318-19 §20.6.1). d shows up in every shear formula, every flexure formula, every
development length check.

TOP STEEL: Between the two columns, the footing bends upward, putting the top face in tension.
Bottom steel alone leaves that hogging zone unreinforced. Module 13 designs this top steel.

FOOTING THICKNESS — CORRECT DESIGN SEQUENCE (from real engineering practice):
Common error: assume h = 500 mm (or any fixed value), then check if shear passes.
This is backwards. Correct sequence:
(1) Compute punching shear demand for both columns → find the minimum d that satisfies ACI 318.
(2) Check one-way shear in both directions with that d; increase d if either direction fails.
(3) Only then: h = d + 75 mm cover + db_transverse + ½ db_longitudinal.
Example: 500 mm footing, ∅16 bars → d = 500 − 75 − 16 − 8 = 401 mm.
That 401 mm — not 500 mm — enters every shear formula, every flexure formula, every
development length check. A wrong d propagates errors through the entire design.
Footing Pro solves this iteratively: finds the minimum h satisfying all ACI 318 checks.

75mm CONCRETE COVER — WHY EXACTLY 75mm (ACI 318-19 §20.6.1):
For concrete cast against and permanently in contact with soil: minimum cover = 75 mm.
Not 50 mm (formed concrete exposed to earth). Not 40 mm (unexposed interior). 75 mm.
Three engineering reasons: (1) Soil surface irregularity — even with lean concrete blinding,
the bearing surface cannot be perfectly flat; the extra cover absorbs that tolerance.
(2) Moisture migration upward through soil — 75 mm slows the corrosion attack path.
(3) Sulfates and chlorides in soil water attack rebar — depth is the primary barrier
because footings cannot use air-entrainment like exposed above-grade surfaces.
d = h − 75 − db_transverse − db_longitudinal/2.

DEVELOPMENT LENGTH — 3 SPECIFIC ERRORS ENGINEERS MAKE:
(1) Using a memorised "standard table" without verifying actual cover and bar spacing for
    the specific design. Standard tables assume default values; your project's actual clear
    cover and bar spacing change ld through the confinement factor in ACI 318-19 §25.4.2.
(2) Forgetting the TOP-BAR 1.3× FACTOR: bars with ≥ 300 mm of fresh concrete cast below
    them need 1.3 × ld. Bond quality is lower above the settlement plane during pour.
    This applies to top steel in combined footings (the hogging zone between the two columns).
(3) Not verifying that available footing length actually provides the required ld.
    A bar may have the right calculated length, but if the footing doesn't extend far enough
    past the column face, there is nowhere to embed it. This check is a separate step,
    distinct from the ld calculation itself — and it is the one most often skipped.
Footing Pro calculates ld per ACI 318-19 §25.4.2 for every bar group with all correct factors.

TENSION-CONTROLLED SECTIONS — ACI 318-19 §21.2 & Table 21.2.2:
Footings and beams must be tension-controlled in flexure: net steel strain εt ≥ 0.005 at ultimate.
This limit sets a maximum reinforcement ratio: neutral-axis depth c ≤ 0.375d.
φ = 0.90 for tension-controlled flexure — ductile failure mode with visible deflection warning.
Compression-controlled (εt ≤ εy ≈ 0.002): φ = 0.65 (tied) or 0.75 (spiral) — brittle, no
prior warning, never acceptable for footings or beams.
Transition zone (εy < εt < 0.005): φ varies linearly — avoid in flexural members.
In practice: footings are shear-governed; ρ is usually low, well below ρmax, and εt is
comfortably above 0.005. But if a designer over-reinforces or uses a very shallow footing,
the tension-control check can govern and force either less As or a deeper section.
Footing Pro verifies εt for every reinforcement zone and confirms tension-controlled status.

FOUNDATION DEPTH (Df) — WHY IT IS NOT ARBITRARY (4 engineering reasons):
Engineers take Df from the geotechnical report. These are the four physical reasons behind it:
(1) FROST PENETRATION: frozen soil heaves (water expands ~9% on freezing). Footing below
    the frost line = protected from uplift. In Egypt, Gulf, and most of the Levant: frost
    depth is negligible — the other three reasons govern instead.
(2) SOIL BEARING CAPACITY: qallowable in the geotechnical report is derived at the specified
    Df. Shallower soil is weaker, less confined, lower bearing capacity than the reported value.
    Using a shallower Df without re-evaluating qallowable is a code violation.
(3) SURFACE EFFECTS: wetting/drying cycles weaken cohesive soils in the upper layer.
    Expansive clays — very common in Egypt, Gulf, and parts of the Levant — swell and shrink
    with seasonal moisture changes, causing differential settlement and structural damage.
    Rule of thumb for expansive clays: Df ≥ 1.5 m to reach the stable moisture zone.
(4) STRUCTURAL REQUIREMENT: column dowels must develop full yield force into the footing
    depth. The footing needs enough thickness d to satisfy shear checks. These structural
    requirements set a minimum h, which in turn sets a minimum Df below grade.
MENA typical practice: Df = 1.5 m to 2.5 m below finished grade for most building projects.
The geotechnical report is always the authoritative source — not a rule of thumb.

CONCRETE CRACKS — DESIGNED IN, NOT A FAILURE:
ACI 318 does not require crack-free concrete. It requires controlled, distributed, non-harmful cracks.
Why: concrete tensile strength ≈ 10% of its compressive strength. Under service loads, beams,
slabs, and footing undersides WILL crack in tension zones — this is the fundamental design
assumption, not a construction defect. Reinforcing steel takes the tension demand after cracking.
This is the entire premise of reinforced concrete design.
ACI 318 controls crack WIDTH, not presence (ACI 318 §24.3.2: maximum bar spacing limits
based on cover and steel stress). Cracks < 0.3–0.4 mm are acceptable for most exposures.
For footings (Class C3 buried exposure): 75 mm cover is the primary protection from soil
chemicals and moisture. Crack control is less critical than in exposed beams; minimum
reinforcement ratio ρ = 0.0018 ensures adequate steel distribution even where moments are small.
USE THIS when an engineer, client, or owner asks "I see cracks — is the structure failing?"
The correct answer: small distributed flexural cracks under load are the designed state, not
evidence of failure. Structural concern starts when cracks are wide (> 0.4 mm), inclined
(shear-type), or at unexpected locations.

CORBELS AND SHORT CANTILEVERS — ACI 318-19 §16.5:
A corbel: a short bracket projecting from a column or wall to carry a beam or structural element.
Looks like a beam. Is NOT designed like a beam. Key distinction: shear span-to-depth ratio a/d ≤ 1.0.
When a/d ≤ 1.0: plane-sections assumption (beam theory) is invalid. Internal forces are
governed by ARCH ACTION, not bending. ACI 318 §16.5 uses a modified design method:
Primary top tension steel As: resists combined moment AND horizontal tension simultaneously.
Horizontal closed stirrups Ah ≥ 0.5 × As: confine the inclined compression strut, resist splitting.
No inclined bars — shown to be ineffective in corbel tests.
Three checks: (1) Flexure + horizontal tension combined (Mu and Nu together), (2) Shear Vn = Vc,
(3) Bearing strength at the load plate (ACI 318 §22.8) — often the controlling check.
Engineers most often fail corbel design by: using standard beam analysis (underestimates
horizontal tension), forgetting closed stirrups Ah, or missing the bearing strength check.
CORBEL DESIGN IS ON THE CIVIL ENGINEERING SUITE ROADMAP. Not yet released — mention it
when engineers ask about connection design or precast elements.

════════════════════════════════════════
FAQ — COMPREHENSIVE
════════════════════════════════════════
Q: How do I subscribe / get a license?
A: Download free PCsuite 2026 from civilengsuite.pages.dev → fill the User Information form →
   it creates an encrypted .dat file on the Desktop → send it to Eng. Aymn Asi by email or
   WhatsApp → developer confirms the price → pay → receive the fully activated app.

Q: What is PCsuite 2026?
A: Free device registration and compatibility checker. Always free.

Q: Does it work on Mac or Linux?
A: No — Windows 7 SP1 through 11 only. Mac under consideration for the future.

Q: Is each footing type a separate app?
A: Yes — Rectangular, Trapezoidal, and Strap Footing are three fully independent standalone
   applications grouped under Footing Pro. You can run all three simultaneously.

Q: Can I install it on more than one device?
A: No, each license is locked to one device. New device = new paid copy required.

Q: Which engineering code does it follow?
A: Grounded in ECP 203 principles natively; universal structural mechanics mean ACI 318-19,
   Eurocode, or any regional code can be applied by adjusting parameters.

Q: Is there a free trial?
A: No. 249 EGP (launch price) is roughly the cost of a technical textbook.

Q: Does it need internet after activation?
A: No — fully offline for up to 15 days per cycle, then a brief reconnect to re-verify.
   The license check is at startup only — never mid-session.

Q: Can I subscribe for multiple years?
A: Yes, 1 to 10 years in one transaction. Multiple years during the launch window locks in
   249 EGP/year for the ENTIRE term you choose upfront — this is confirmed.
   A single-year subscriber who renews AFTER the launch period ends would pay the regular rate.

Q: What are the add-on modules?
A: Print System, Online Help Center, and AutoCAD Drawing output. Pricing not yet finalized.

Q: What happens when my subscription expires?
A: The app stops launching. Your project data is never deleted — stays on your local machine.

Q: When are Beam Pro and Column Pro coming?
A: Both in active development. Column Pro is the most-requested app in the whole suite.

Q: Is 249 EGP/yr really all-inclusive?
A: Yes — all 19 core modules, no hidden fees. Add-ons are the only extra cost.

Q: Is the calculation transparent?
A: Yes. Every result traces to a specific equation with an ACI 318-19 clause reference.
   A senior engineer can verify any number manually and arrive at the same answer.

Q: Why a desktop app instead of a web app?
A: Web tools need servers, and servers go down. A desktop engine gives transparent, traceable,
   auditable results regardless of connectivity.

Q: Can I run multiple footing apps simultaneously?
A: Yes — no single-instance lock. Run different types side by side, or multiple copies.

Q: Can I save a design and come back to it later?
A: Yes — full save/load with unlimited case files saved locally in encrypted format.

Q: Does Footing Pro check soil settlement?
A: No — it takes qallowable from your geotechnical report as a direct input.

════════════════════════════════════════
BEHAVIOUR RULES
════════════════════════════════════════
• Answer questions about Civil Engineering Suite, its products, pricing, licensing, and
  structural engineering topics. General engineering questions are worth answering well —
  being genuinely helpful builds trust.

• For ANY purchase/activation query: guide to downloading PCsuite 2026 first, then sending
  the .dat file to aymneidasi@gmail.com or WhatsApp +201287232413.

• When a user shows purchase interest: bring up launch-price urgency (249 vs 499 EGP) and
  time-savings case — but don't recite the entire persuasion playbook every time.

• When a user mentions manual-calculation frustration: lead with the time-savings angle
  (17 min vs 3.5–4 hrs) and the common-mistakes-prevented angle.

• When a user is clearly an Egyptian or Arab engineer: bring up the ECP 203 gap naturally.
  In Arabic: "مفيش أداة احترافية للكود المصري غير دي."

• For field engineers: lead with offline-first.

• For engineers worried about trust or accuracy: lead with traceability, ACI 318-19 clause
  references, and "built and field-tested by a practicing structural engineer."

• If you don't have the information: say so plainly rather than guessing.
  English: "I don't have that information — please contact Eng. Aymn Asi directly at
  aymneidasi@gmail.com or WhatsApp +201287232413."
  Arabic: "مش عندي معلومة دقيقة عن ده — تواصل مع المهندس أيمن عاصي على
  aymneidasi@gmail.com أو واتساب +201287232413."

• Never invent pricing, discount percentages, release dates, or feature details not given above.
• Never recommend competitor software.
• Never be dismissive of manual calculation — respect the work while showing value of speed.
• When conversation is genuinely about buying/pricing, end with a clear varied next step —
  don't bolt the same canned CTA onto messages that aren't about buying.`;

// ── Gemini follow-up system prompt — v12 QUOTA FIX ────────────────────────
// PROBLEM (see CHANGELOG v12 at top of file): SYSTEM_PROMPT above is ~13,000
// input tokens (measured: 51,660 chars). It was being sent IN FULL on every
// Gemini call — for every turn of every conversation, for every one of up to
// 13 keys, for both PRIMARY and FALLBACK models, on every retry. A single
// 5-message conversation cost ~65,000 system-prompt input tokens before this
// fix; a worst-case fallback sweep (13 keys × 2 models, each retried) could
// resend the full 13K-token prompt over 20 times for ONE user message.
// Free-tier Gemini Flash/Flash-Lite TPM is ~250,000 tokens/minute shared per
// project (ai.google.dev/gemini-api/docs/rate-limits, verified June 2026) —
// at 13K tokens/request that ceiling absorbs well under 20 concurrent
// requests/minute before 429s start, regardless of how many keys are pooled.
// Context caching is NOT a fix here: Google's preview-tier Flash/Flash-Lite
// models (gemini-3.5-flash, gemini-3.1-flash-lite) do not support context
// caching on the free tier — every request sends full, uncached context.
// FIX: send the full SYSTEM_PROMPT only on a conversation's first turn (no
// prior history) and switch to this condensed ~1,150-token reminder for every
// turn after that. The model's own prior replies are still present in
// `contents` history, so tone/identity persist; this prompt re-states the
// rules that must never drift (language selection above all) plus compact
// product/pricing/technical facts, without resending the full phrase banks,
// FAQ, and education sections the model no longer needs once it has replied
// once. Net effect on a typical 5-message exchange: ~65,000 system-prompt
// tokens → ~13,000 + 4×1,150 ≈ 17,600 tokens, a ~73% reduction.
const GEMINI_FOLLOWUP_PROMPT = `\
You are continuing an existing conversation as Eng_pro assist — the official AI assistant for
Civil Engineering Suite (civilengsuite.pages.dev), built by Eng. Aymn Asi.
Your name is Eng_pro assist. If asked your name at any point: Arabic → "أنا Eng_pro assist"،
English → "I'm Eng_pro assist." Never claim to be ChatGPT, Gemini, or any other AI brand.
The full identity, tone, and product knowledge were already established earlier in this thread
via your own prior replies (visible in the conversation history below). Stay in that voice.
This is a condensed reminder, not the full brief — answer naturally from what you already know
and from the facts below; don't act like context was lost.

LANGUAGE RULE — CRITICAL (re-check every reply, never drift):
• Arabic message → reply ENTIRELY in Arabic (Egyptian dialect, عامية مصرية). NEVER فصحى.
• English message → reply ENTIRELY in English. Never mix languages in one reply.
• Keep technical terms as-is in both languages: ACI 318-19, ECP 203, ASCE 7, EPS 2012, kN, kPa,
  MPa, qallowable, As, ld, fcu, f'c.

TONE: Knowledgeable engineer texting a colleague — direct, warm, occasionally informal. Match
the person's energy (short question → short answer). Vary phrasing; never repeat the same
opener or CTA every message. No emoji-headers, hashtags, "━━━" dividers. Prose over bullets
unless content is genuinely list-shaped. Egyptian Arabic register: default "حضرتك", mirror
"إنت" if they use it; favour دلوقتي، يعني، بصراحة، خالص، طب/طيب، مفيش، بقى، علشان، كمان، برضو
over فصحى equivalents.

CORE PRODUCT FACTS — Civil Engineering Suite / Footing Pro v.2026 (the only live product):
• Three standalone apps: Rectangular Combined Footing (equal/near-equal loads), Trapezoidal
  Combined Footing (unequal loads, shifts centroid to the heavier column), Strap Footing
  (edge column on the property line, rigid strap beam transfers eccentricity moment).
• 19 connected ACI 318-19 modules — change one input, all 19 recalc instantly. Print-ready
  output. ~17 min with the tool vs 3.5–4 hrs manual per footing; a 12-footing project recovers
  roughly 46 hours of engineering time.
• 4 world-firsts: circular-reference self-weight solver, directional field lock (blocks typing,
  not the live formula engine), automatic negative-soil-pressure detection with one-click
  correction, tooltips on disabled/locked fields.
• Offline-first after activation (re-verify roughly every 15 days); no cloud dependency for
  calculation; project data never leaves the machine. Windows 7 SP1–11 only, no Mac/Linux.
• Grounded in ECP 203 by default; every parameter adjustable to ACI 318-19, Eurocode, or
  another code — fills a real gap, since no mainstream tool natively targets ECP 203.
• Built by Eng. Aymn Asi, a practicing structural engineer; every result traces to a specific
  ACI 318-19 clause and a senior engineer can verify it by hand.

PRICING: 249 EGP/yr launch price (regular price after launch: 499 EGP/yr), all 19 modules, no
hidden fees, no free trial. Subscribing 1–10 years in a SINGLE transaction during the launch
window locks in 249 EGP/yr for that whole term (e.g. 3 years = 747 EGP total) — a single-year
subscriber who renews after launch ends pays the regular 499/yr instead. Don't invent loyalty
discounts beyond this; refer specifics to Eng. Aymn Asi.

HOW TO BUY: Download free PCsuite 2026 from civilengsuite.pages.dev → fill the User Information
form (creates an encrypted .dat file on the Desktop) → send that file to aymneidasi@gmail.com or
WhatsApp +201287232413 → developer confirms price → pay → receive the activated app.

KEY TECHNICAL REFERENCE POINTS (answer engineering questions accurately and specifically):
eccentricity must satisfy e ≤ L/6 (kern rule); punching shear at the interior column (closed
4-sided perimeter) is usually the most critical check and fails with no visible warning; size
footing area with SERVICE loads, design structural checks with ULTIMATE loads; effective depth
d = h − cover − db/2; 75 mm cover for concrete cast against soil (ACI 318-19 §20.6.1); top steel
is required between columns for the hogging zone; development length ld follows §25.4.2,
including the 1.3× top-bar factor; cracks are an expected, controlled-width design outcome,
not a defect, per ACI 318 §24.3.2.

BEHAVIOUR RULES:
• Never invent pricing, discount percentages, release dates, or features not listed here or
  established earlier in this conversation.
• Never recommend competitor software. ETABS/SAP2000 are whole-building tools and complementary,
  not competitors, if that comparison comes up.
• If you don't know something specific: say so plainly and point to Eng. Aymn Asi —
  aymneidasi@gmail.com or WhatsApp +201287232413 — rather than guessing.
• Bring up purchase steps or launch-price urgency only when relevant to what was just asked —
  don't bolt a CTA onto every reply.`;

// ── Workers AI system prompt — compressed for 4096-token context window ──────
// Full SYSTEM_PROMPT is ~13,524 tokens and would overflow the llama-3.1-8b
// context window. This version preserves identity, behaviour rules, core product
// facts, and contact info in under 800 tokens — enough for Layer 3 fallback use.
const WORKERS_AI_SYSTEM_PROMPT = `\
Your name is Eng_pro assist. You are the official AI assistant for Civil Engineering Suite
(civilengsuite.pages.dev), built by Eng. Aymn Asi — a licensed structural engineer.
If asked your name: Arabic → "أنا Eng_pro assist" — English → "I'm Eng_pro assist."
Never claim to be ChatGPT, Gemini, or any other AI brand.

LANGUAGE RULE (critical): Arabic message → reply only in Egyptian Arabic dialect
(عامية مصرية), never Modern Standard Arabic. English message → reply only in English.
Never mix languages in one reply.

PRODUCT — Civil Engineering Suite (CES):
• Footing Pro: three standalone apps — Rectangular Footing, Trapezoidal Footing, Strap Footing.
• 19 core modules total. More apps (Beam Pro, Column Pro) in development.
• Add-ons: Print System, Online Help Center, AutoCAD Drawing output (pricing TBA).
• Fully offline after activation. License locked to one device.
• Grounded in ECP 203; universal mechanics apply to ACI 318-19, Eurocode, etc.
• PCsuite 2026: free registration and compatibility checker — always free.

PRICING (launch price, confirmed):
• 249 EGP per year, all 19 modules included, no hidden fees.
• Multi-year option: 1–10 years in one transaction, locks in 249 EGP/yr for the full term.
• Regular (post-launch) price: 499 EGP/yr.
• New device requires a new paid license copy.

ACTIVATION PROCESS:
1. Download PCsuite 2026 from civilengsuite.pages.dev.
2. Fill the User Information form — it creates an encrypted .dat file on the Desktop.
3. Send the .dat file to Eng. Aymn Asi: aymneidasi@gmail.com or WhatsApp +201287232413.
4. Developer confirms price, user pays, user receives fully activated app.

KEY FACTS:
• Saves 17 minutes vs 3.5–4 hours of manual calculation per footing design.
• Offline-first — no internet after activation except a brief reconnect every 15 days.
• Every result traces to a specific ACI 318-19 clause reference — fully auditable.
• No free trial. 249 EGP is roughly the cost of a technical textbook.
• No Mac or Linux support — Windows 7 SP1 through 11 only.

BEHAVIOUR:
• Answer like a knowledgeable engineer texting a colleague — direct, warm, not scripted.
• Match message length: short question → short answer. Technical depth → go longer.
• Never invent pricing, dates, or features not listed above.
• Never recommend competitor software.
• If you lack information: direct the user to Eng. Aymn Asi at aymneidasi@gmail.com
  or WhatsApp +201287232413 — do not guess.
• Bring up purchase steps only when the user shows genuine buying intent.`;

// ── Developer / Programmer Mode prompt extension ──────────────────────────
// Injected as a PREFIX to whichever system prompt is in use when a request
// arrives with a valid DEVELOPER_PASSWORD match. The base prompt (SYSTEM_PROMPT
// or GEMINI_FOLLOWUP_PROMPT or WORKERS_AI_SYSTEM_PROMPT) is appended after it,
// keeping all normal persona and language rules active.
//
// ENV VAR: DEVELOPER_PASSWORD  (Secret, Cloudflare Dashboard)
//   Set this to any strong passphrase — it is never sent to the AI model,
//   only validated server-side. Keep it out of source control.
//
// CLIENT PROTOCOL:
//   Send { message, history, devPassword: "your-secret" } in the request body.
//   Server compares devPassword === env.DEVELOPER_PASSWORD (constant-time).
//   On success, response includes { reply, devMode: true }.
//   Client stores devMode state for the session and forwards devPassword on
//   every subsequent request so the mode persists across turns.
//
// WHAT DEVELOPER MODE ENABLES (in the AI's behaviour):
//   • Full technical discussion of internal implementation files
//     (chat.js, tts.js, __path__.js, pc_suite_v2_FIXED_4.html)
//   • Complete, production-ready code generation / modification suggestions
//     the developer can copy-paste and deploy — no placeholders, no TODOs
//   • Architectural critique and improvement recommendations
//   • TTS provider alternatives with complete replacement tts.js code
//   • No limit on technical depth — the programmer has full access
//
// WHAT IT CANNOT DO (hard reality, stated honestly in the prompt):
//   The AI cannot directly write to or execute files on the Cloudflare
//   edge — it generates content; the developer deploys it.
const DEVELOPER_SYSTEM_PROMPT = `
══════════════════════════════════════════════════════════════
DEVELOPER MODE ACTIVE — AUTHENTICATED: Eng. Aymn Asi (programmer)
══════════════════════════════════════════════════════════════
The human in this conversation is the developer who built Civil Engineering Suite
and programmed you (Eng_pro assist). Full technical access is granted for this session.

YOU MAY NOW:
• Discuss your own implementation files in complete technical detail:
  – functions/api/chat.js     (this file — AI proxy, provider chain, rate limiting)
  – functions/api/tts.js      (Google Translate TTS proxy, Cloudflare edge cache)
  – functions/api/__path__.js (route handler / CSP / headers)
  – pc_suite_v2_FIXED_4.html  (frontend — chat widget, TTS engine, voice recognition)
• Generate complete, production-ready modifications to any of these files —
  full working code, correct indentation, zero placeholders, zero TODO comments.
• Analyse bugs, performance issues, and architectural gaps in the current system.
• Provide complete alternative implementations (e.g., replacement tts.js for a
  different TTS provider) with all integration details.
• Discuss Cloudflare Pages/Workers architecture, KV bindings, Rate Limiter
  bindings, env vars, subrequest budgets, and deployment steps.
• Answer any system design question with no restriction on technical depth.

HARD REALITY (state this honestly if the developer asks):
You cannot directly execute code or write to files on the Cloudflare edge.
What you deliver is complete file content the developer copies and deploys via
the Cloudflare dashboard or git push. That IS the correct workflow for this stack.

TTS IMPROVEMENT — CONTEXT FOR DEVELOPER QUESTIONS:
Current: tts.js proxies Google Translate TTS (translate_tts endpoint).
Quality: Good for Arabic — better than browser SpeechSynthesis — but synthetic.
Alternatives the developer can request a complete new tts.js for:
  1. ElevenLabs API  — most natural Arabic voice; free tier 10,000 chars/month.
     Env var: ELEVENLABS_API_KEY + ELEVENLABS_VOICE_ID (Arabic voice ID)
  2. Azure Cognitive Services Speech — free tier 5 hrs TTS/month.
     Env var: AZURE_SPEECH_KEY + AZURE_SPEECH_REGION
  3. Google Cloud Text-to-Speech (not Translate) — WaveNet/Neural2 Arabic voices.
     Env var: GOOGLE_TTS_API_KEY
  If the developer says "improve TTS", generate a complete drop-in replacement
  tts.js for their chosen provider with all error handling and CORS intact.

TONE IN DEVELOPER MODE:
Technical, precise, direct. Skip the sales persona when the developer is asking
about system internals. Switch back to full assistant persona for any
non-developer engineering or product question that a regular user might also ask.
══════════════════════════════════════════════════════════════
`;

// ── [v14] Timing-safe password comparison — Web Crypto API (Cloudflare Workers) ──
// BUG in v13: crypto.subtle.timingSafeEqual() was called but that method does NOT
// exist in the Web Crypto API (WHATWG spec). It exists only in Node.js as
// crypto.timingSafeEqual() — a completely different object and runtime.
// In Cloudflare Workers the call always threw TypeError, caught by the outer
// try/catch, and fell back to a direct === compare — functionally correct but
// not cryptographically timing-safe (JS engines may short-circuit on the first
// differing byte, leaking length/prefix info under precise timing measurements).
//
// FIX: HMAC-SHA256 based comparison.
//   Both passwords are HMAC'd under the SAME freshly-generated random key.
//   HMAC output is always 32 bytes regardless of input length, eliminating the
//   length side-channel. The outputs are then compared with a bitwise XOR
//   accumulator that runs all 32 iterations unconditionally — constant-time.
//   This is the standard pattern in the Web Crypto API cookbook for timing-safe
//   equality, and is the approach recommended by Cloudflare's own docs.
async function hmacTimingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const [sigA, sigB] = await Promise.all([
    crypto.subtle.sign('HMAC', key, enc.encode(a)),
    crypto.subtle.sign('HMAC', key, enc.encode(b)),
  ]);
  const arrA = new Uint8Array(sigA);
  const arrB = new Uint8Array(sigB);
  // HMAC-SHA256 always returns 32 bytes — lengths are always identical.
  let diff = 0;
  for (let i = 0; i < arrA.length; i++) diff |= arrA[i] ^ arrB[i];
  return diff === 0;
}

// ── Helpers ────────────────────────────────────────────────────────────────
function json(data, status = 200, extraHeaders, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...getCorsHeaders(request),
      ...(extraHeaders || {}),
    },
  });
}

// ── Provider: Gemini (Layers 1 & 2 — same function, different model) ──────
// `systemPrompt` is caller-supplied (v12) — SYSTEM_PROMPT on a conversation's
// first turn, GEMINI_FOLLOWUP_PROMPT on every turn after that. See the v12
// changelog and the comment above GEMINI_FOLLOWUP_PROMPT for why.
// `budget` (v13) is the shared makeFetchBudget() counter for this invocation —
// see the v13 helper block above GEMINI_API_URL... err, above OPENROUTER_API_URL.
// Returns { ok: true, reply } on success, or
//         { ok: false, httpStatus, errStatus, errBody } on any failure.
// Every fetch Response body in this function is read at most once — there
// is no path that calls .text()/.json() twice on the same Response.
//
// v13 CHANGE: 429 of EITHER kind (RESOURCE_EXHAUSTED or RATE_LIMIT_EXCEEDED)
// now skips backoff-retry and returns immediately, same as RESOURCE_EXHAUSTED
// already did in v6. Rationale: the v6 comment's premise — "RATE_LIMIT_EXCEEDED
// can clear within seconds, so retry in place" — holds for a single isolated
// burst, but under genuinely concurrent multi-user traffic every simultaneous
// request hitting the same saturated key backs off and retries on the same
// schedule (2s/5s/11s), so the retry lands while the herd is still saturating
// that key. Under heavy traffic specifically, failing over to the NEXT key in
// the (now-rotated, see rotateStart()) pool is strictly more likely to
// succeed, faster, than waiting out a fixed backoff on the same key. Retry-
// with-backoff is kept only for 500/503 (genuine transient server errors,
// where the same key is fine and worth a second try) — reduced to 2 attempts
// with jitter instead of 3, to bound worst-case latency now that there's a
// 13-key pool to fail over into instead.
async function callGeminiWithRetry(apiKey, model, contents, systemPrompt, budget) {
  const payload = JSON.stringify({
    system_instruction: { parts: [{ text: systemPrompt }] },
    contents,
    generationConfig: {
      maxOutputTokens: 700,
      temperature    : 0.35,
      topP           : 0.9,
    },
  });

  async function call() {
    if (!budget.take()) {
      throw new Error('SUBREQUEST_BUDGET_EXHAUSTED');
    }
    return fetchWithTimeout(`${GEMINI_API_URL(model)}?key=${apiKey}`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : payload,
    });
  }

  // v13: 2 retries (was 3), backoff with jitter, 500/503 only.
  const RETRY_DELAYS_MS = [1500, 3500];

  let res;
  try {
    res = await call();
  } catch (err) {
    if (err.message !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
      console.error(`[chat.js] Network error calling Gemini (${model}):`, err.message);
    }
    return { ok: false, httpStatus: 0, errStatus: err.message === 'SUBREQUEST_BUDGET_EXHAUSTED'
      ? 'SUBREQUEST_BUDGET_EXHAUSTED' : 'NETWORK_ERROR', errBody: err.message };
  }

  for (let attempt = 0; attempt < RETRY_DELAYS_MS.length; attempt++) {
    if (res.ok) break;

    // v13: any 429 — RESOURCE_EXHAUSTED (daily cap, never clears within the
    // request) or RATE_LIMIT_EXCEEDED (per-minute burst, but see rationale
    // above) — fails over to the next key/model immediately. Only 500/503
    // are retried in place.
    if (res.status !== 500 && res.status !== 503) break;

    const delay = withJitter(RETRY_DELAYS_MS[attempt]);
    console.warn(
      `[chat.js] Gemini ${model} ${res.status} on attempt ${attempt + 1}/${RETRY_DELAYS_MS.length}.` +
      ` Retrying in ${delay}ms…`
    );
    await new Promise(r => setTimeout(r, delay));
    try {
      res = await call();
    } catch (err) {
      if (err.message !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
        console.error(`[chat.js] Network error calling Gemini ${model} (retry):`, err.message);
      }
      return { ok: false, httpStatus: 0, errStatus: err.message === 'SUBREQUEST_BUDGET_EXHAUSTED'
        ? 'SUBREQUEST_BUDGET_EXHAUSTED' : 'NETWORK_ERROR', errBody: err.message };
    }
  }

  if (!res.ok) {
    let errBody = '';
    let errStatus = '';
    try {
      errBody = await res.text();
      errStatus = JSON.parse(errBody)?.error?.status || '';
    } catch { /* non-fatal — body may be non-JSON (HTML error page, etc.) */ }
    if (res.status !== 429) {
      console.error(
        `[chat.js] Gemini HTTP ${res.status} for model ${model} (after retries):`,
        errBody.slice(0, 500),
      );
    }
    return { ok: false, httpStatus: res.status, errStatus, errBody };
  }

  const data = await res.json();
  const reply = data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';
  if (!reply) {
    return { ok: false, httpStatus: res.status, errStatus: 'EMPTY_REPLY', errBody: '' };
  }
  return { ok: true, reply };
}

// ── Provider: Cloudflare Workers AI (Layer 3 — final, free fallback) ──────
// Called through the native `env.AI` binding, not a fetch() call — there is
// no URL and no API key involved. `aiBinding` is `context.env.AI`; if the
// binding was never added in the dashboard this returns a clean NOT_BOUND
// failure instead of throwing, so the optional 3rd layer degrades safely.
// v13: aiBinding.run() takes no AbortSignal, so the timeout is enforced with
// Promise.race against a timer instead of fetchWithTimeout. Note this races
// the *wait*, not the underlying call — if Workers AI is simply slow rather
// than hung, the call may still complete on Cloudflare's side after we've
// already moved on. That's an acceptable trade for never hanging the
// response to the user, and Workers AI never bills for time we're not
// waiting on, this layer is also not part of the fetch() subrequest count.
async function callWorkersAIWithRetry(aiBinding, messages) {
  if (!aiBinding) {
    return { ok: false, httpStatus: 0, errStatus: 'NOT_BOUND', errBody: '' };
  }

  function callWithTimeout() {
    return Promise.race([
      aiBinding.run(WORKERS_AI_MODEL, {
        messages,
        max_tokens : 700,
        temperature: 0.35,
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('WORKERS_AI_TIMEOUT')), PROVIDER_TIMEOUT_MS)),
    ]);
  }

  // Workers AI failures seen in practice are almost always brief "capacity
  // temporarily exceeded" blips, not sustained outages — one short retry is
  // enough. This layer only runs after two prior providers already failed,
  // so we keep the added worst-case latency small.
  const RETRY_DELAY_MS = 1200;

  let result;
  try {
    result = await callWithTimeout();
  } catch (err) {
    console.warn('[chat.js] Workers AI attempt 1 failed:', err.message);
    await new Promise(r => setTimeout(r, RETRY_DELAY_MS));
    try {
      result = await callWithTimeout();
    } catch (err2) {
      console.error('[chat.js] Workers AI failed after retry:', err2.message);
      return { ok: false, httpStatus: 0, errStatus: 'WORKERS_AI_ERROR', errBody: err2.message };
    }
  }

  const reply = (result?.response || '').trim();
  if (!reply) {
    return { ok: false, httpStatus: 0, errStatus: 'EMPTY_REPLY', errBody: '' };
  }
  return { ok: true, reply };
}

// ── Provider: Groq (Layer 4 — llama-3.1-8b-instant, 1,000 req/day free) ──
// OpenAI-compatible API. Accepts the workersMsgs array already built for
// Layer 3 — no message conversion needed in the caller.
// `budget` (v13) — see makeFetchBudget() above.
// Returns { ok: true, reply } on success, or
//         { ok: false, httpStatus, errStatus, errBody } on failure.
// Single retry on 500/503. Layer 4 fires only after Layers 1–3 have all
// failed, so we limit added latency to one short retry delay.
async function callGroqWithRetry(apiKey, messages, budget) {
  const payload = JSON.stringify({
    model      : GROQ_MODEL,
    messages,
    max_tokens : 700,
    temperature: 0.35,
  });

  async function call() {
    if (!budget.take()) throw new Error('SUBREQUEST_BUDGET_EXHAUSTED');
    return fetchWithTimeout(GROQ_API_URL, {
      method : 'POST',
      headers: {
        'Content-Type' : 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: payload,
    });
  }

  // v12 QUOTA FIX: do NOT retry on 429. Groq's free tier (verified June 2026,
  // console.groq.com/docs/rate-limits) is 30 RPM / 6,000 TPM / 1,000 RPD per
  // account for llama-3.1-8b-instant — far tighter than this file previously
  // assumed (see CHANGELOG v12). A 429 here is RPM or RPD exhaustion; neither
  // clears in 1.2 seconds, so retrying only spends a second request against
  // an already-scarce daily cap for no realistic chance of success. 500/503
  // are genuine transient server errors and are still worth one retry.
  const RETRY_DELAY_MS  = withJitter(1200);
  const RETRYABLE_CODES = new Set([500, 503]);

  let res;
  try {
    res = await call();
  } catch (err) {
    if (err.message !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
      console.error('[chat.js] Network error calling Groq:', err.message);
    }
    return { ok: false, httpStatus: 0, errStatus: err.message === 'SUBREQUEST_BUDGET_EXHAUSTED'
      ? 'SUBREQUEST_BUDGET_EXHAUSTED' : 'NETWORK_ERROR', errBody: err.message };
  }

  if (!res.ok && RETRYABLE_CODES.has(res.status)) {
    console.warn(`[chat.js] Groq ${res.status} on attempt 1. Retrying in ${RETRY_DELAY_MS}ms…`);
    await new Promise(r => setTimeout(r, RETRY_DELAY_MS));
    try {
      res = await call();
    } catch (err) {
      if (err.message !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
        console.error('[chat.js] Network error calling Groq (retry):', err.message);
      }
      return { ok: false, httpStatus: 0, errStatus: err.message === 'SUBREQUEST_BUDGET_EXHAUSTED'
        ? 'SUBREQUEST_BUDGET_EXHAUSTED' : 'NETWORK_ERROR', errBody: err.message };
    }
  }

  if (!res.ok) {
    let errBody   = '';
    let errStatus = '';
    try {
      errBody = await res.text();
      const parsed = JSON.parse(errBody);
      errStatus = parsed?.error?.code || parsed?.error?.type || '';
    } catch { /* non-JSON body */ }
    console.error(`[chat.js] Groq HTTP ${res.status} (after retry):`, errBody.slice(0, 300));
    return { ok: false, httpStatus: res.status, errStatus, errBody };
  }

  const data  = await res.json();
  const reply = (data?.choices?.[0]?.message?.content || '').trim();
  if (!reply) {
    return { ok: false, httpStatus: res.status, errStatus: 'EMPTY_REPLY', errBody: '' };
  }
  return { ok: true, reply };
}

// ── Provider: OpenRouter (Layer 5 — :free model, 50 req/day) ─────────────
// OpenAI-compatible API. HTTP-Referer and X-Title are optional but
// recommended by OpenRouter's docs — they identify the calling app in
// OpenRouter's usage dashboard and can improve rate-limit priority.
// Returns { ok: true, reply } on success, or
//         { ok: false, httpStatus, errStatus, errBody } on failure.
async function callOpenRouterWithRetry(apiKey, messages, budget) {
  const payload = JSON.stringify({
    model      : OPENROUTER_MODEL,
    messages,
    max_tokens : 700,
    temperature: 0.35,
  });

  async function call() {
    if (!budget.take()) throw new Error('SUBREQUEST_BUDGET_EXHAUSTED');
    return fetchWithTimeout(OPENROUTER_API_URL, {
      method : 'POST',
      headers: {
        'Content-Type' : 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'HTTP-Referer' : 'https://civilengsuite.pages.dev',
        'X-Title'      : 'Civil Engineering Suite',
      },
      body: payload,
    });
  }

  // v12 QUOTA FIX: do NOT retry on 429. OpenRouter's free tier is 50 req/day,
  // 20 RPM per zero-balance account (openrouter.ai/docs/api/reference/limits,
  // verified June 2026) — and OpenRouter's own docs state failed attempts
  // still count toward that daily quota. Retrying a 429 here spends a second
  // unit of a 50/day budget for almost no chance of success within 1.2s.
  // 500/503 are genuine transient server errors and are still worth one retry.
  const RETRY_DELAY_MS  = withJitter(1200);
  const RETRYABLE_CODES = new Set([500, 503]);

  let res;
  try {
    res = await call();
  } catch (err) {
    if (err.message !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
      console.error('[chat.js] Network error calling OpenRouter:', err.message);
    }
    return { ok: false, httpStatus: 0, errStatus: err.message === 'SUBREQUEST_BUDGET_EXHAUSTED'
      ? 'SUBREQUEST_BUDGET_EXHAUSTED' : 'NETWORK_ERROR', errBody: err.message };
  }

  if (!res.ok && RETRYABLE_CODES.has(res.status)) {
    console.warn(`[chat.js] OpenRouter ${res.status} on attempt 1. Retrying in ${RETRY_DELAY_MS}ms…`);
    await new Promise(r => setTimeout(r, RETRY_DELAY_MS));
    try {
      res = await call();
    } catch (err) {
      if (err.message !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
        console.error('[chat.js] Network error calling OpenRouter (retry):', err.message);
      }
      return { ok: false, httpStatus: 0, errStatus: err.message === 'SUBREQUEST_BUDGET_EXHAUSTED'
        ? 'SUBREQUEST_BUDGET_EXHAUSTED' : 'NETWORK_ERROR', errBody: err.message };
    }
  }

  if (!res.ok) {
    let errBody   = '';
    let errStatus = '';
    try {
      errBody = await res.text();
      const parsed = JSON.parse(errBody);
      errStatus = parsed?.error?.code || parsed?.error?.type || '';
    } catch { /* non-JSON body */ }
    console.error(`[chat.js] OpenRouter HTTP ${res.status} (after retry):`, errBody.slice(0, 300));
    return { ok: false, httpStatus: res.status, errStatus, errBody };
  }

  const data  = await res.json();
  const reply = (data?.choices?.[0]?.message?.content || '').trim();
  if (!reply) {
    return { ok: false, httpStatus: res.status, errStatus: 'EMPTY_REPLY', errBody: '' };
  }
  return { ok: true, reply };
}

// ── Friendly error builder — v10 update ────────────────────────────────────
// `geminiResult` is the callGeminiWithRetry() result from the LAST Gemini
// layer attempted (flash-lite if it ran, otherwise flash) — or a synthetic
// NOT_CONFIGURED stand-in when GEMINI_API_KEY is missing entirely.
// `workersAttempted` tells the message whether Layer 3 was even tried.
// v10 change: all quota-exhausted and generic failure paths now include
// WhatsApp (+201287232413) and email as a direct contact fallback — a quota
// failure is no longer a dead end for the user.
function buildFriendlyError(geminiResult, workersAttempted) {
  if (geminiResult.errStatus === 'RESOURCE_EXHAUSTED') {
    return workersAttempted
      ? 'The AI assistant is temporarily unavailable — all free-tier providers are ' +
        'at capacity or exhausted. Please try again after midnight UTC. ' +
        'For urgent questions: WhatsApp +201287232413 · aymneidasi@gmail.com. / ' +
        'المساعد مش متاح دلوقتي — كل المزودين المجانيين وصلوا للحد أو اشتغلوا. ' +
        'حاول تاني بعد منتصف الليل UTC. للأسئلة العاجلة: واتساب +201287232413 · aymneidasi@gmail.com.'
      : 'Daily AI quota reached — the assistant resets after midnight UTC. ' +
        'For urgent questions: WhatsApp +201287232413 · aymneidasi@gmail.com. / ' +
        'الحصة اليومية اتخلصت — المساعد بيرجع بعد منتصف الليل UTC. ' +
        'للأسئلة العاجلة: واتساب +201287232413 · aymneidasi@gmail.com.';
  }
  if (geminiResult.errStatus === 'RATE_LIMIT_EXCEEDED') {
    return 'Too many requests right now. Please wait 30–60 seconds and try again. / ' +
           'في طلبات كتير دلوقتي. استنى 30–60 ثانية وحاول تاني.';
  }
  // v13: distinct message for "we stopped trying more providers to stay
  // under the platform's per-request subrequest cap" — this is a genuine
  // heavy-traffic symptom (lots of concurrent users, lots of retries
  // burning the budget), not a quota or single-provider outage, so the
  // wording is shorter-timescale than the RESOURCE_EXHAUSTED message.
  if (geminiResult.errStatus === 'SUBREQUEST_BUDGET_EXHAUSTED') {
    return 'The assistant is extremely busy right now. Please try again in a moment. / ' +
           'المساعد مشغول جداً دلوقتي. حاول تاني بعد لحظات.';
  }

  const friendlyErrors = {
    400: 'Invalid request. Please rephrase and try again. / ' +
         'طلب غير صالح، حاول تغيير الصياغة.',
    401: 'API authentication failed. Please contact site admin. / ' +
         'فشل المصادقة، تواصل مع المسؤول.',
    403: 'API access denied. Please contact site admin. / ' +
         'الوصول محجوب، تواصل مع المسؤول.',
    404: 'AI model unavailable. Please contact site admin. / ' +
         'النموذج غير متاح، تواصل مع المسؤول.',
    500: 'The AI service encountered an error. Please try again. / ' +
         'حصل خطأ في الخدمة، حاول مرة أخرى.',
    503: 'The AI service is temporarily unavailable. Please try again in a minute. / ' +
         'الخدمة مش متاحة دلوقتي، جرب تاني بعد دقيقة.',
  };
  return (
    friendlyErrors[geminiResult.httpStatus] ||
    'Something went wrong. Please try again, or contact us directly: ' +
    'WhatsApp +201287232413 · aymneidasi@gmail.com. / ' +
    'حصل مشكلة، حاول مرة أخرى، أو تواصل معنا مباشرة: واتساب +201287232413 · aymneidasi@gmail.com.'
  );
}

// ── v13 RATE LIMITER — abuse / overload protection ─────────────────────────
// This endpoint previously had NO request-level throttling at all. CORS
// (getCorsHeaders) is a browser-enforced policy, not a server-side control —
// any script can POST directly to /api/chat from outside a browser entirely,
// bypassing it. Combined with the 13-key fallback pool, an unthrottled
// client (bot, scraper, or just a buggy retry loop in someone's browser tab)
// can burn through the ENTIRE shared free-tier quota pool — every account,
// every provider — in well under a minute, leaving nothing for real users.
// That risk scales with traffic: more visitors means more chances one of
// them is abusive, and more legitimate concurrent load to compete with.
//
// Preferred mechanism: Cloudflare's native Workers Rate Limiting binding
// (env.RATE_LIMITER) — in-isolate counters, no added latency, no extra
// fetch/subrequest cost. It requires Workers PAID plan and a `ratelimits`
// block in a wrangler.jsonc/toml deployed alongside this Pages project (see
// the wrangler.jsonc snippet shipped alongside this file). It is NOT
// configurable from the Pages dashboard alone.
//
// Fallback mechanism: if env.RATE_LIMITER is absent but a KV namespace is
// bound as env.CES_CHAT_KV (dashboard-addable, no wrangler config needed,
// works on the Free plan), a coarse fixed-window counter is used instead.
// HONEST CAVEAT, left in the code on purpose: Workers KV's Free plan caps
// writes at 1,000/day. A 60s window with one write per request hits that
// ceiling at roughly 42 messages/HOUR sustained — i.e. a KV-only limiter can
// itself start failing during the exact heavy-traffic conditions it exists
// to guard against. checkRateLimit() fails OPEN (treats a KV error as "not
// rate limited") specifically so a quota-exhausted limiter degrades to "no
// protection" rather than "blocks everyone" — availability for real users
// takes priority over strict enforcement for a sales chatbot. Track real
// volume and move to the RATE_LIMITER binding (Workers Paid, $5/mo) once
// traffic regularly approaches that ceiling.
//
// `key` is the caller-supplied identifier (IP via CF-Connecting-IP) — see
// inline note in onRequestPost about IP-based keys vs NAT/shared-IP limits.
async function checkRateLimit(env, key) {
  if (env.RATE_LIMITER) {
    try {
      const { success } = await env.RATE_LIMITER.limit({ key });
      return { limited: !success, mechanism: 'binding' };
    } catch (err) {
      console.error('[chat.js] RATE_LIMITER binding error (failing open):', err.message);
      return { limited: false, mechanism: 'binding-error' };
    }
  }

  if (env.CES_CHAT_KV) {
    try {
      const WINDOW_SECONDS = 60;
      const MAX_PER_WINDOW = 8; // ~1 message every 7.5s sustained, generous for one real user
      const bucket = Math.floor(Date.now() / 1000 / WINDOW_SECONDS);
      const kvKey  = `rl:${key}:${bucket}`;
      const current = parseInt((await env.CES_CHAT_KV.get(kvKey)) || '0', 10);
      if (current >= MAX_PER_WINDOW) {
        return { limited: true, mechanism: 'kv' };
      }
      // expirationTtl auto-cleans old buckets — no manual deletion needed.
      await env.CES_CHAT_KV.put(kvKey, String(current + 1), { expirationTtl: WINDOW_SECONDS * 2 });
      return { limited: false, mechanism: 'kv' };
    } catch (err) {
      console.error('[chat.js] CES_CHAT_KV error (failing open):', err.message);
      return { limited: false, mechanism: 'kv-error' };
    }
  }

  // Neither binding configured — no-op. Logged once per ISOLATE (not per
  // request — a busy isolate could otherwise emit this on every single chat
  // message) at WARN so the gap is visible in Cloudflare Logs without
  // drowning out everything else during real traffic.
  if (!checkRateLimit._warned) {
    checkRateLimit._warned = true;
    console.warn('[chat.js] No rate limiter bound (RATE_LIMITER or CES_CHAT_KV) — /api/chat is unthrottled.');
  }
  return { limited: false, mechanism: 'none' };
}

// ── POST handler ───────────────────────────────────────────────────────────
// v8 FIX — ROOT-CAUSE ANALYSIS OF ALL BUGS IN v7's onRequestPost:
//
// BUG 1 (CRASH): callGeminiWithRetry was called with 2 args instead of 3.
//   callGeminiWithRetry(geminiKey, geminiContents)   ← WRONG
//   The function signature is (apiKey, model, contents).
//   Effect: model = geminiContents (an array), contents = undefined.
//   URL becomes: .../models/[object Object]:generateContent → 404 or 400.
//
// BUG 2 (CRASH / ROOT CAUSE OF "Connection error"): callDeepSeekWithRetry was
//   called but is not defined anywhere in the file (it was described as removed
//   in the v7 changelog but the call was never deleted from the handler).
//   Because DEEPSEEK_API_KEY was present in the environment, the handler reached
//   that branch after Bug 1's Gemini failure, threw ReferenceError, and Cloudflare
//   returned a non-JSON 500. The widget's res.json() then threw, landing in the
//   .catch() handler → "Connection error." This is the exact error reported.
//
// BUG 3: Layer 2 (gemini-2.5-flash-lite) never tried. GEMINI_MODEL_FALLBACK
//   constant was defined but never referenced in the handler.
//
// BUG 4: Layer 3 (Cloudflare Workers AI) never tried. callWorkersAIWithRetry
//   was defined but never called in the handler.
//
// BUG 5: Dead config guard read env.DEEPSEEK_API_KEY and included it in the
//   "at least one provider" check — masking a missing GEMINI_API_KEY.
//
// BUG 6: buildFriendlyError called with (primary, !!deepseekKey) instead of
//   (lastGeminiResult, workersAttempted) — wrong classification of the error.
//
// ALL SIX BUGS fixed below. Helper functions (callGeminiWithRetry,
// callWorkersAIWithRetry, buildFriendlyError) were already correct and unchanged.
export async function onRequestPost(context) {
  const { request, env } = context;

  // 0. v13 RATE LIMIT — see checkRateLimit() above for the full rationale.
  //    CF-Connecting-IP is Cloudflare's own header carrying the real client
  //    IP (not spoofable by the client — Cloudflare sets it at the edge).
  //    NOTE ON IP AS A KEY: Cloudflare's own Rate Limiting docs recommend
  //    against IP-based keys for fine-grained per-user limits, because NAT
  //    / shared-IP users (offices, mobile carriers) can share one counter.
  //    For THIS endpoint that trade-off is acceptable: the goal here is
  //    abuse/overload protection, not fairness between individual users
  //    behind the same IP, and a shared office IP legitimately sending 8+
  //    chat messages within the same 60s window is itself a reasonable
  //    point to ask it to slow down.
  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateCheck = await checkRateLimit(env, clientIp);
  if (rateCheck.limited) {
    return json(
      {
        error: 'Too many messages too quickly. Please wait a moment and try again. / ' +
               'رسائل كتير بسرعة. استنى لحظة وحاول تاني.',
      },
      429,
      undefined,
      request,
    );
  }

  // 1. Validate Gemini API key — the only required key after v7/v8.
  //    DEEPSEEK_API_KEY is intentionally not read; DeepSeek is paid-only and
  //    was removed from this file. Delete it from Cloudflare env to avoid
  //    confusion (the variable has no effect on this function).
  const geminiKey = env.GEMINI_API_KEY || '';
  if (!geminiKey) {
    return json(
      {
        error:
          'No AI provider configured. Set GEMINI_API_KEY in Cloudflare Pages ' +
          'environment variables (aistudio.google.com → API keys).',
      },
      500,
      undefined,
      request,
    );
  }

  // 2. Parse request body
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Request body must be valid JSON.' }, 400, undefined, request);
  }

  const userMessage = typeof body.message === 'string' ? body.message.trim() : '';
  const rawHistory  = Array.isArray(body.history) ? body.history : [];

  if (!userMessage) {
    return json({ error: 'Message must not be empty.' }, 400, undefined, request);
  }
  if (userMessage.length > 2000) {
    return json(
      { error: 'Message too long. Please keep your question under 2,000 characters. / ' +
               'الرسالة طويلة جداً. اختصر سؤالك لأقل من ٢٠٠٠ حرف.' },
      400,
      undefined,
      request,
    );
  }

  // 2b. Developer mode authentication.
  //     Client sends { message, history, devPassword: "secret" } when the user
  //     has activated dev mode via the /dev command in the chat widget.
  //     Validated server-side only — the password never reaches the AI model.
  //     DEVELOPER_PASSWORD must be set as a Secret in Cloudflare Pages dashboard.
  //     [v14] Uses hmacTimingSafeEqual() — see the helper above for full rationale.
  const incomingDevPw   = typeof body.devPassword === 'string' ? body.devPassword : '';
  const configuredDevPw = typeof env.DEVELOPER_PASSWORD === 'string' ? env.DEVELOPER_PASSWORD : '';
  let isDeveloperMode = false;
  if (incomingDevPw && configuredDevPw) {
    try {
      isDeveloperMode = await hmacTimingSafeEqual(incomingDevPw, configuredDevPw);
    } catch (_) {
      // hmacTimingSafeEqual failed (crypto.subtle unavailable — should never
      // happen on Cloudflare Workers). Fall back to direct compare: functionally
      // correct, not timing-safe, but rate limiting above throttles brute-force
      // attempts that would exploit a timing side-channel.
      isDeveloperMode = (incomingDevPw === configuredDevPw);
    }
    if (isDeveloperMode) {
      console.info('[chat.js] Developer mode authenticated for request from', clientIp);
    } else {
      console.warn('[chat.js] Developer mode: wrong password attempt from', clientIp);
    }
  }

  // 3. Normalize history — keep last 10 turns (5 exchanges) for token budget.
  //    Single normalisation pass; geminiContents is the only payload built here.
  //    (openaiMessages was dead code in v7 — it only existed for the now-removed
  //     DeepSeek path. Removed here.)
  const recentHistory = rawHistory.slice(-10);
  const turns = [];
  for (const turn of recentHistory) {
    const role = turn.role === 'model' ? 'model' : 'user';
    const text = typeof turn.text === 'string' ? turn.text.trim().slice(0, 2000) : '';
    if (text) turns.push({ role, text });
  }
  turns.push({ role: 'user', text: userMessage });

  const geminiContents = turns.map(t => ({ role: t.role, parts: [{ text: t.text }] }));

  // v12 QUOTA FIX: full SYSTEM_PROMPT (~13,000 tokens) only on the first turn
  // of a conversation (no prior history) — every turn after that uses the
  // condensed ~1,150-token GEMINI_FOLLOWUP_PROMPT instead. turns.length === 1
  // means only the live message is present, i.e. recentHistory was empty.
  // See the comment above GEMINI_FOLLOWUP_PROMPT for the full rationale.
  const isFirstTurn        = turns.length === 1;
  const baseSystemPrompt   = isFirstTurn ? SYSTEM_PROMPT : GEMINI_FOLLOWUP_PROMPT;
  // In developer mode, prefix DEVELOPER_SYSTEM_PROMPT so the model has full
  // technical context while the base persona stays active below it.
  const geminiSystemPrompt = isDeveloperMode
    ? DEVELOPER_SYSTEM_PROMPT + baseSystemPrompt
    : baseSystemPrompt;

  // v13: a single fetch-subrequest budget shared across every provider call
  // made for this one incoming request — see makeFetchBudget() above for why.
  const budget = makeFetchBudget(SUBREQUEST_BUDGET_FREE_PLAN);

  // 4. Build Gemini key pool — all 13 keys across 13 Google accounts.
  //    GEMINI_API_KEY is required (guarded above). Keys 2–13 are optional.
  //    Blank / absent keys are excluded by the .filter() and silently skipped.
  //    v13: each entry keeps its ORIGINAL pool index (for the X-CES-AI-Source
  //    header / log tag) separately from iteration order, because rotation
  //    (below) changes which key is tried first without changing its identity.
  const geminiKeysIndexed = [
    env.GEMINI_API_KEY    || '',
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
    env.GEMINI_API_KEY_13 || '',
  ]
    .map((key, originalIndex) => ({ key, originalIndex }))
    .filter(k => k.key);

  // v13: rotateStart() — see the helper block above OPENROUTER_API_URL for
  // the full rationale. Every concurrent request gets a different starting
  // key instead of every request piling onto geminiKeysIndexed[0] first.
  const geminiPool = rotateStart(geminiKeysIndexed);

  // 5. GEMINI LAYERS — try each key (in rotated order) with PRIMARY then
  //    FALLBACK model. Replaces v10's Layers 1, 2, 6a, and 6b.
  //    lastGeminiResult carries the final Gemini failure into buildFriendlyError.
  let lastGeminiResult = { ok: false, httpStatus: 0, errStatus: 'NOT_ATTEMPTED', errBody: '' };

  for (const { key: gKey, originalIndex } of geminiPool) {
    if (budget.remaining() <= 0) {
      console.warn('[chat.js] Subrequest budget exhausted during Gemini layer — stopping early.');
      lastGeminiResult = { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };
      break;
    }
    const keyTag = originalIndex === 0 ? '' : `key${originalIndex + 1}-`;

    const resA = await callGeminiWithRetry(gKey, GEMINI_MODEL_PRIMARY, geminiContents, geminiSystemPrompt, budget);
    if (resA.ok) {
      return json(
        { reply: resA.reply, ...(isDeveloperMode && { devMode: true }) },
        200,
        { 'X-CES-AI-Source': `gemini-${keyTag}primary` },
        request,
      );
    }
    if (resA.errStatus !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
      console.warn(
        `[chat.js] Gemini ${keyTag || 'key1-'}${GEMINI_MODEL_PRIMARY} failed:`,
        resA.errStatus, resA.httpStatus,
      );
    }
    lastGeminiResult = resA;
    if (budget.remaining() <= 0) break;

    const resB = await callGeminiWithRetry(gKey, GEMINI_MODEL_FALLBACK, geminiContents, geminiSystemPrompt, budget);
    if (resB.ok) {
      return json(
        { reply: resB.reply, ...(isDeveloperMode && { devMode: true }) },
        200,
        { 'X-CES-AI-Source': `gemini-${keyTag}fallback` },
        request,
      );
    }
    if (resB.errStatus !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
      console.warn(
        `[chat.js] Gemini ${keyTag || 'key1-'}${GEMINI_MODEL_FALLBACK} failed:`,
        resB.errStatus, resB.httpStatus,
      );
    }
    lastGeminiResult = resB;
  }

  // 6. WORKERS AI LAYER — unchanged routing from v10 (binding call, not a
  //    fetch() subrequest, so it does not draw from `budget` — see v13 note
  //    on callWorkersAIWithRetry above).
  //    Build workersMsgs here using WORKERS_AI_SYSTEM_PROMPT (<800 tokens).
  //    Workers AI uses OpenAI-style {role,content} messages, not Gemini's
  //    {role,parts:[{text}]} format. workersMsgs is shared by Groq and
  //    OpenRouter layers below (same OpenAI-compatible format).
  const workersSystemContent = isDeveloperMode
    ? DEVELOPER_SYSTEM_PROMPT + WORKERS_AI_SYSTEM_PROMPT
    : WORKERS_AI_SYSTEM_PROMPT;
  const workersMsgs = [
    { role: 'system', content: workersSystemContent },
    ...turns.map(t => ({
      role   : t.role === 'model' ? 'assistant' : 'user',
      content: t.text,
    })),
  ];
  const workersAttempted = !!env.AI;
  const layerWorkers = await callWorkersAIWithRetry(env.AI, workersMsgs);
  if (layerWorkers.ok) {
    return json(
      { reply: layerWorkers.reply, ...(isDeveloperMode && { devMode: true }) },
      200,
      { 'X-CES-AI-Source': 'workers-ai-fallback' },
      request,
    );
  }
  if (workersAttempted) {
    console.error('[chat.js] Workers AI failed:', layerWorkers.errStatus);
  }

  // 7. GROQ LAYERS — try each of up to 13 keys, in rotated order (v13).
  //    All keys use llama-3.1-8b-instant via callGroqWithRetry().
  //    Free tier: 1,000 req/day, 30 RPM, 6K TPM per key (corrected v12).
  //    WORKERS_AI_SYSTEM_PROMPT (~800 tokens) keeps requests below 6K TPM cap.
  //    Naming: GROQ_API_KEY (member 1) + GROQ_API_KEY_1…GROQ_API_KEY_12 (members 2–13).
  const groqKeysIndexed = [
    env.GROQ_API_KEY    || '',
    env.GROQ_API_KEY_1  || '',
    env.GROQ_API_KEY_2  || '',
    env.GROQ_API_KEY_3  || '',
    env.GROQ_API_KEY_4  || '',
    env.GROQ_API_KEY_5  || '',
    env.GROQ_API_KEY_6  || '',
    env.GROQ_API_KEY_7  || '',
    env.GROQ_API_KEY_8  || '',
    env.GROQ_API_KEY_9  || '',
    env.GROQ_API_KEY_10 || '',
    env.GROQ_API_KEY_11 || '',
    env.GROQ_API_KEY_12 || '',
  ]
    .map((key, originalIndex) => ({ key, originalIndex }))
    .filter(k => k.key);
  const groqPool = rotateStart(groqKeysIndexed);

  for (const { key: gqKey, originalIndex } of groqPool) {
    if (budget.remaining() <= 0) {
      console.warn('[chat.js] Subrequest budget exhausted during Groq layer — stopping early.');
      break;
    }
    const resG = await callGroqWithRetry(gqKey, workersMsgs, budget);
    if (resG.ok) {
      return json(
        { reply: resG.reply, ...(isDeveloperMode && { devMode: true }) },
        200,
        { 'X-CES-AI-Source': originalIndex === 0 ? 'groq-fallback' : `groq-key${originalIndex + 1}-fallback` },
        request,
      );
    }
    if (resG.errStatus !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
      console.warn(
        `[chat.js] Groq key${originalIndex === 0 ? '' : originalIndex + 1} failed:`,
        resG.errStatus, resG.httpStatus,
      );
    }
  }

  // 8. OPENROUTER LAYERS — try each of up to 13 keys, in rotated order (v13).
  //    All keys use meta-llama/llama-3.3-70b-instruct:free via callOpenRouterWithRetry().
  //    Free tier: 50 req/day, 20 RPM per key. HTTP-Referer and X-Title sent
  //    per OpenRouter docs (handled inside callOpenRouterWithRetry).
  //    Naming: OPENROUTER_API_KEY (member 1) + OPENROUTER_API_KEY_1…_12 (members 2–13).
  const openRouterKeysIndexed = [
    env.OPENROUTER_API_KEY    || '',
    env.OPENROUTER_API_KEY_1  || '',
    env.OPENROUTER_API_KEY_2  || '',
    env.OPENROUTER_API_KEY_3  || '',
    env.OPENROUTER_API_KEY_4  || '',
    env.OPENROUTER_API_KEY_5  || '',
    env.OPENROUTER_API_KEY_6  || '',
    env.OPENROUTER_API_KEY_7  || '',
    env.OPENROUTER_API_KEY_8  || '',
    env.OPENROUTER_API_KEY_9  || '',
    env.OPENROUTER_API_KEY_10 || '',
    env.OPENROUTER_API_KEY_11 || '',
    env.OPENROUTER_API_KEY_12 || '',
  ]
    .map((key, originalIndex) => ({ key, originalIndex }))
    .filter(k => k.key);
  const openRouterPool = rotateStart(openRouterKeysIndexed);

  for (const { key: orKey, originalIndex } of openRouterPool) {
    if (budget.remaining() <= 0) {
      console.warn('[chat.js] Subrequest budget exhausted during OpenRouter layer — stopping early.');
      break;
    }
    const resOR = await callOpenRouterWithRetry(orKey, workersMsgs, budget);
    if (resOR.ok) {
      return json(
        { reply: resOR.reply, ...(isDeveloperMode && { devMode: true }) },
        200,
        { 'X-CES-AI-Source': originalIndex === 0 ? 'openrouter-fallback' : `openrouter-key${originalIndex + 1}-fallback` },
        request,
      );
    }
    if (resOR.errStatus !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
      console.warn(
        `[chat.js] OpenRouter key${originalIndex === 0 ? '' : originalIndex + 1} failed:`,
        resOR.errStatus, resOR.httpStatus,
      );
    }
  }

  // 9. All layers exhausted.
  //    lastGeminiResult = the final callGeminiWithRetry() outcome (last key,
  //    FALLBACK model) — or the synthetic SUBREQUEST_BUDGET_EXHAUSTED result
  //    set above if we broke out of the Gemini loop early (v13).
  //    workersAttempted = whether Workers AI was tried.
  return json({ error: buildFriendlyError(lastGeminiResult, workersAttempted) }, 502, undefined, request);
}

// ── OPTIONS preflight (required for CORS) ─────────────────────────────────
export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}
