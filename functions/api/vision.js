/**
 * functions/api/vision.js — v2.3 (advisor-reviewed & corrected, 2026-07-16)
 * ─────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — "Insert Image" backend for Civil Engineering
 * Suite chat (web + VBA desktop). Route: POST /api/vision.
 *
 * Sibling to functions/api/chat.js — separate file/route so a vision bug
 * cannot take down text chat. Reuses chat.js's Gemini key ring (same 13
 * env vars, no new provider/signup/cost) and the shared rotation/subrequest
 * helpers in functions/_lib/rotation.mjs.
 *
 * ── This file supersedes 5 independently-drafted candidates. Where they
 *    disagreed, the choice below was settled by live verification (web
 *    search, 2026-07-16), not majority vote — three concrete corrections
 *    that vote would have gotten wrong:
 *
 *   1. Payload field casing. 4/5 candidates mixed casing; 1/5 was uniform
 *      camelCase. Confirmed against ai.google.dev's OWN curl examples
 *      (Image understanding + System instructions pages, current as of
 *      this writing): raw REST calls to generateContent use SNAKE_CASE for
 *      message-level fields — `system_instruction`, `inline_data`,
 *      `mime_type` — but CAMELCASE inside `generationConfig`
 *      (`maxOutputTokens`, `topP`, `thinkingConfig`). A mismatched
 *      generationConfig field is silently ignored, not rejected (confirmed
 *      via a live langchain4j bug report: a snake_cased thinkingConfig was
 *      dropped with no error) — exactly the kind of silent failure that
 *      would reintroduce chat.js's v19 truncation bug. Every candidate
 *      that used camelCase for generationConfig was already safe there;
 *      the fix is confined to the inline_data/mime_type/system_instruction
 *      layer.
 *   2. Image-before-text ordering. One candidate claimed Google recommends
 *      text-before-image for a single-image prompt and reordered the parts
 *      array on that basis. The current official guidance (ai.google.dev,
 *      Image Understanding) says the opposite: place the text prompt AFTER
 *      the image for a single-image request. Reverted to image-then-text,
 *      which is also what 4/5 candidates already did.
 *   3. Cloudflare Free plan limits. Verified current (2026-07): 10ms CPU
 *      time/invocation, 50 EXTERNAL subrequests/invocation (a Feb-2026
 *      changelog removed a *different*, internal 1000-subrequest ceiling —
 *      it did not touch the external-fetch limit these files size their
 *      budgets against). CPU time excludes time spent awaiting fetch(),
 *      confirming the "large wall-clock timeout is fine, large CPU-bound
 *      work is not" design load-bearing in every candidate's header.
 *
 * ── Other merge decisions, none individually load-bearing enough for a
 *    numbered correction above, but each picked from whichever candidate
 *    argued it best:
 *   - Body reading: streaming reader with a hard byte cap (one candidate),
 *     not read-then-measure (four candidates) — the only approach that
 *     avoids fully buffering an oversized/spoofed-Content-Length body.
 *   - Gemini payload JSON.stringify()'d ONCE outside the retry loop (one
 *     candidate) — the request body never varies across the up-to-26
 *     key/model attempts; only the URL does. Re-stringifying per-attempt
 *     (four candidates) repeats ~1.7MB-string CPU work up to 26x against a
 *     10ms/invocation ceiling.
 *   - No in-place backoff-retry on 500/503 (one candidate's simplification,
 *     adopted): with 13 keys in the pool, rotating to the next key already
 *     gets the retry effect without paying the 1.5-3.5s in-place delay —
 *     strictly faster for both the per-key-blip case and the
 *     provider-wide-outage case.
 *   - System instruction kept as its own field, separate from the user's
 *     message (three candidates did this correctly; two folded persona
 *     text into the default prompt, which is silently discarded the
 *     moment the caller supplies its own message/question).
 *   - HEIC/HEIF added to the MIME allow-list — confirmed supported Gemini
 *     input formats (one candidate had this; the other four only allowed
 *     jpeg/png/webp).
 *   - Request field names: accepts BOTH `message`/`prompt` and BOTH
 *     `mimeType`/`mime` — the 5 candidates disagreed on which the actual
 *     client sends and this file can't see chat.js/the HTML clients to
 *     settle it, so both aliases are accepted rather than guessing wrong.
 *   - Pre-body-parse errors (size/JSON/rate-limit/no-key) are bilingual
 *     (language truly unknown at that point); post-parse errors use the
 *     detected language only (nicer UX once it's known).
 * ─────────────────────────────────────────────────────────────────────────
 *
 * ── v2.1 (multi-image, 2026-07-16): accepts `images: [{data, mime}, ...]`,
 *    up to MAX_IMAGES_PER_REQUEST (3), alongside the original singular
 *    `image`/`mimeType`/`mime` fields (kept for the VBA desktop client,
 *    whose source isn't visible from this repo). MAX_BODY_BYTES is
 *    unchanged — it was always a total-request ceiling, not a per-image
 *    one; the client-side compressors now divide their share of it by the
 *    attached-image count instead of assuming exactly one. Not a bulk
 *    <input multiple> picker on the client side — images are attached one
 *    at a time up to the cap, so there is no "selected 5, silently kept 3"
 *    case to handle; the server-side cap above exists for non-browser
 *    callers that skip the client UI entirely.
 *
 * ── v2.2 (2026-07-16): part-ordering correction inside the N>1 branch,
 *    found by fetching ai.google.dev/gemini-api/docs/generate-content/
 *    image-understanding directly (the exact page + exact API — legacy
 *    generateContent, not the newer Interactions API — this file calls)
 *    rather than trusting the v2.1 draft's uncited claim. Two DIFFERENT,
 *    both-documented-on-that-page rules apply depending on N:
 *      - N=1: "Tips and best practices" says place the text prompt AFTER
 *        the image part. v2.1 already did this and it is unchanged here —
 *        this keeps the N=1 payload byte-identical to the pre-multi-image
 *        contract, which matters because the VBA desktop client (see file
 *        header) always sends exactly one image and this file cannot see
 *        that client's source to know if it's sensitive to the change.
 *      - N>1: the page's own "Prompting with multiple images" example
 *        places the question TEXT FIRST, then each image Part in
 *        sequence — v2.1 put every image first and the text last for
 *        N>1, which matches neither documented pattern (it silently
 *        assumed the N=1 rule extends to N>1; the same page shows it
 *        doesn't). Fixed below: N>1 now sends [{text: userMessage},
 *        ...imageParts]. The per-image "Image N:" labels are kept — nice
 *        to have for a 2-image no-ambiguity example, that pairing is what
 *        lets a reply reference "Image 2" specifically, which
 *        VISION_SYSTEM_PROMPT's own numbering already depends on.
 *
 * ── v2.3 (advisor review, 2026-07-16): three corrections found against the
 *    REAL repo files (chat.js, rotation.mjs, pc_suite_v28.html) — not just
 *    reasoned from API docs in isolation — plus everything from v2.0-v2.2
 *    re-verified rather than taken on faith:
 *   1. KEY-POOL DUPLICATION (bug). This file built its own 13-entry key
 *      array and `key${i+1}-` tag logic inline, with a comment explaining
 *      that rotation.mjs's exact export shape "can't be verified" from
 *      here. It can: the real rotation.mjs exports buildGeminiKeyPool(env)
 *      and keyTagFor(originalIndex) FOR THIS FILE SPECIFICALLY — its own
 *      header says so ("vision.js needs the exact same 13 keys... one
 *      canonical copy") — and chat.js already imports and uses both (see
 *      its own "v_vision" comment). Fixed: now imports and calls both,
 *      byte-identical to chat.js's usage. The old inline array is deleted;
 *      it was the exact drift risk rotation.mjs's header warns against.
 *   2. FALSE CROSS-REFERENCE (inaccurate comment, not a runtime bug). The
 *      MAX_IMAGES_PER_REQUEST comment pointed at a "MAX_PENDING_IMAGES"
 *      constant in footing_pro_v28.html / pc_suite_v28.html to "keep in
 *      sync." No such constant exists in the real file: the web widget
 *      attaches one image at a time via a singular `pendingImageBase64`
 *      variable, not a capped array, so there is nothing there to drift
 *      out of sync with. Comment corrected below; images[] (N>1) is real,
 *      correct, harmless server-side capability that simply has no live
 *      caller yet.
 *   3. ADAPTIVE DETAIL — MISSING, NOW ADDED. The product spec ("default
 *      low, escalate to high only on explicit request for granular
 *      inspection") had no implementation anywhere in this pipeline.
 *      Gemini has no OpenAI-style client-passed `detail: low/high` field —
 *      that concept doesn't exist in this API. The actual mechanism,
 *      confirmed 2026-07-16 against ai.google.dev/gemini-api/docs/
 *      generate-content/media-resolution: `generationConfig.
 *      mediaResolution`, a Gemini-3.x-only setting (both models this file
 *      calls are 3.x, so it always applies here). Per that page's own
 *      Gemini-3-models token table: MEDIA_RESOLUTION_LOW = 280 tokens/
 *      image, _MEDIUM = 560, _HIGH = 1120, and — the part worth flagging —
 *      _UNSPECIFIED (i.e. the field simply omitted, which is what v2.0-
 *      v2.2 did) ALSO costs 1120. Omitting the field is not a conservative
 *      default; it is the same cost as explicitly requesting HIGH. Added:
 *      wantsHighDetail(), a bilingual (EN/AR) keyword heuristic over the
 *      user's own message, escalating to HIGH only when it signals a need
 *      for close/precise inspection (the product spec's own example:
 *      "checking specific rebar lap lengths or critical crack patterns");
 *      LOW otherwise. Response now also carries X-CES-Vision-Detail for
 *      observability, matching the existing X-CES-Vision-Source pattern.
 *
 *    Re-verified and left UNCHANGED because they hold up against current,
 *    authoritative sources (not just re-asserted): the MIME allow-list
 *    (png/jpeg/webp/heic/heif — exact match against ai.google.dev's
 *    "Supported image formats" list); N=1 image-then-text vs. N>1 text-
 *    then-images ordering (both confirmed on the CURRENT legacy
 *    generateContent docs — not the newer Interactions API, which uses a
 *    differently-shaped `input` array and is a documentation trap for
 *    anyone diffing the two by page title alone); snake_case/camelCase
 *    payload casing; the Cloudflare Free-plan 10ms-CPU / 50-external-
 *    subrequest ceiling (including the Feb-2026 changelog nuance above);
 *    and the gemini-3.5-flash / gemini-3.1-flash-lite model IDs themselves
 *    (both real, GA, and — as of this writing — still Flash-tier free-quota
 *    eligible; Pro-tier models lost free access in April 2026, Flash-tier
 *    did not, though the exact free daily-request ceiling now varies by
 *    project/region/date and is worth re-checking live in AI Studio rather
 *    than hard-coding — see the Advisor writeup this version shipped with
 *    for the caveat on chat.js's own "~3,000 req/day" comment).
 * ─────────────────────────────────────────────────────────────────────────
 *
 * ── v2.4 (reconciliation, 2026-07-16): this v2.3 pass and a second,
 *    independently-run advisor pass corrected DIFFERENT subsets of the same
 *    v2.0 draft — neither is a strict improvement on the other. Reconciled
 *    here the same way v2.0 itself reconciled 5 candidates: keep what's
 *    right from each, fix what's wrong in each, re-verify rather than
 *    trust either draft's own confidence.
 *
 *   KEPT FROM v2.3, CONFIRMED SOUND: the buildGeminiKeyPool()/keyTagFor()
 *   import fix; the corrected (non-existent-constant) MAX_IMAGES_PER_REQUEST
 *   comment; the VISION_SYSTEM_PROMPT tone rewrite — this is the one that
 *   actually matters most and the other pass missed entirely: the caller's
 *   own Protocol 5 ("do not describe the image content... provide immediate
 *   engineering insights") directly contradicts v2.0-v2.2's "Describe what
 *   you actually see first... then answer," which the other pass carried
 *   forward unchanged. v2.3's rewrite ("never open with 'I see...'") is the
 *   correct fix and stays; wantsHighDetail() as the DETECTION mechanism also
 *   stays — inferring the escalation signal from the user's own free-text
 *   message works with the real client TODAY (pc_suite_v28.html sends only
 *   `{ image, mime, prompt }`, no UI control to set a detail param at all),
 *   which the other pass's client-supplied `body.detail` approach can't —
 *   that approach is correct in isolation but unreachable from any caller
 *   that exists right now.
 *
 *   NOT CAUGHT BY v2.3, ADDED HERE: v2.3's own header (point 1 above)
 *   describes the file's history of silent generationConfig field mismatches
 *   in detail, then leaves `temperature: 0.35, topP: 0.9, thinkingConfig:
 *   { thinkingBudget: 0 }` completely untouched a few hundred lines later —
 *   the exact class of bug its own changelog warns about. Per Google's
 *   Gemini 3.x migration guidance (ai.google.dev/gemini-api/docs/
 *   generate-content/whats-new-gemini-3.5, re-verified here): temperature/
 *   topP are "no longer recommended" and should be removed outright, and
 *   thinkingBudget is legacy — thinkingLevel is the current field, and
 *   supplying both in one request is a hard 400. Fixed below.
 *
 *   CLAIMED IN v2.4, ITSELF WRONG (see v2.6 correction below): "MEDIA_
 *   RESOLUTION_UNSPECIFIED (field omitted) ALSO costs 1120, same as HIGH"
 *   was disputed here as not holding up against ai.google.dev/gemini-api/
 *   docs/media-resolution's "tuned for a good balance of quality, latency,
 *   and cost" description of the default. That quote is real, but it's the
 *   page's general qualitative summary, not specific to Images on Gemini 3
 *   — the SAME page's own Gemini-3-models token TABLE gives numbers, not
 *   prose, for that specific combination: MEDIA_RESOLUTION_UNSPECIFIED
 *   (Default) = 1120 tokens for Image, and MEDIA_RESOLUTION_HIGH = 1120
 *   for Image — identical. v2.2/v2.3's original claim was correct for the
 *   case this file actually has (images, Gemini 3.x); this entry read the
 *   summary paragraph without reconciling it against the table two
 *   sections below it. Restored below.
 *   2. wantsHighDetail()'s own comment inverts the risk direction: it calls
 *      a false negative (heuristic misses a real need for close inspection)
 *      the cheap case ("just costs more tokens") and a false positive
 *      (unnecessary escalation) the free one. It's the other way around — a
 *      false positive spends extra tokens on an image that didn't need it
 *      (harmless); a false negative silently under-resources a case that
 *      may hinge on a legible dimension or hairline crack (the actual
 *      accuracy risk this endpoint exists to avoid). Given that asymmetry,
 *      defaulting the NO-MATCH case to LOW was backwards from what v2.3's
 *      own stated reasoning implies. Changed: no-match now defaults to
 *      MEDIUM (560 tok/image, unchanged from v2.3's constant table), HIGH
 *      still reachable via the heuristic AND, additively, via an explicit
 *      body.detail override for any future caller that can set one
 *      directly (VBA client, or a later multi-image picker UI) — the two
 *      mechanisms layer rather than compete.
 *   3. "Pro-tier models lost free access in April 2026" — the CURRENT state
 *      (Flash/Flash-Lite free-tier eligible, Pro not, via the Gemini API
 *      docs' own FAQ) re-confirms independently; the specific April-2026
 *      transition date does not have independent confirmation from this
 *      pass and is not repeated as fact below.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * ── v2.5 (2026-07-16): a third, independent candidate (branched from v2.3,
 *    unaware of v2.4) surfaced two more findings — checked by actually
 *    running code, not by reading its comments and trusting them:
 *   1. wantsHighDetail()'s own regex, run against the product spec's own
 *      cited example VERBATIM ("checking specific rebar lap lengths or
 *      critical crack patterns") via `node -e`, returned false. Confirmed
 *      root cause by testing in isolation: lap\s*(?:length|splice) requires
 *      the exact singular before a trailing \b, so plural "lengths" fails
 *      the boundary check (no word break between "length" and its own
 *      trailing "s"); crack\s*width doesn't cover "crack patterns" at all —
 *      a different word never in the list. Fixed below (pluralized
 *      lap/crack terms, added crack\s*patterns? as its own alternative,
 *      detail(?:s|ed)? now also catches bare "details") and RE-RUN against
 *      the same phrase to confirm the fix actually resolves it before
 *      shipping — true both times, not assumed either time.
 *   2. The candidate also disputed this file's own v2.3/v2.4-era claim that
 *      footing_pro_v28.html / pc_suite_v28.html attach only one image via a
 *      singular pendingImageBase64, making the images[] branch below
 *      unreachable dead code. Re-checked directly against freshly
 *      re-uploaded copies of both HTML files (not assumed from either
 *      draft's say-so): MAX_PENDING_IMAGES = 3 and an array-based
 *      pendingImages[] are real and working in both, confirmed by reading
 *      the actual add/remove/send handlers. The v2.3/v2.4 claim was
 *      correct when made — checked at the time against the files as they
 *      then existed — and has simply been overtaken by the widget's own
 *      subsequent multi-image work landing client-side. images[] (N>1) is
 *      therefore a live, exercised path today, not idle capability; this
 *      file needed no change for that beyond retiring the now-stale "no *      live caller yet" framing wherever it appeared above.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * ── v2.6 (independent re-review, 2026-07-16): re-verified v2.4's and
 *    v2.5's claims the same way v2.5 verified v2.3/v2.4's — against
 *    primary sources and by execution, not by trusting a confident prior
 *    draft's own citations:
 *   1. v2.4's mediaResolution correction (above) was ITSELF WRONG — see
 *      the corrected header entry in place of the original v2.3-disputing
 *      text. Re-fetched ai.google.dev/gemini-api/docs/generate-content/
 *      media-resolution in full (not re-searched for a snippet) and read
 *      the Gemini-3-models token TABLE, not just the prose above it:
 *      MEDIA_RESOLUTION_UNSPECIFIED (Default) = 1120 for Image,
 *      MEDIA_RESOLUTION_HIGH = 1120 for Image. Identical. The "tuned for a
 *      good balance" line v2.4 quoted is real text on the same page, but
 *      it's the page's general framing, not a claim about this specific
 *      number — Google's own qualitative description and its own table
 *      disagree for this exact case, which is itself worth knowing, not
 *      just which one to believe. v2.2/v2.3's original number stands.
 *   2. v2.5's no-match-defaults-to-MEDIUM change (risk-asymmetry
 *      reasoning) does not depend on the mediaResolution number above and
 *      was not re-litigated — it is a product judgment call about which
 *      failure mode is worse, not a factual claim, and the reasoning holds
 *      regardless of what omitting the field would have cost.
 *   3. NOT caught by v2.5 (or any prior pass): the HTML clients uploaded
 *      alongside THIS revision of vision.js add `multiple` to
 *      `<input id="ces-image-input">`, with matching truncation/oversized/
 *      unreadable summary messaging in the change handler. This directly
 *      reverses the caller's own original, explicit requirement ("Don't
 *      ship an open multiple picker") from the spec this whole feature was
 *      built against — flagged in the accompanying writeup for explicit
 *      confirmation rather than silently kept or silently reverted here;
 *      the implementation quality of the truncation UX is sound either
 *      way if the bulk picker is in fact wanted now.
 * ─────────────────────────────────────────────────────────────────────────
 */

import {
  rotateStart,
  makeFetchBudget,
  fetchWithTimeout,
  checkRateLimit,
  buildGeminiKeyPool,
  keyTagFor,
} from '../_lib/rotation.mjs';

// ── Models — same pair chat.js uses. gemini-3.5-flash confirmed current
// GA/multimodal (ai.google.dev, 2026-07). gemini-2.5-flash is NOT used here
// per chat.js's own migration-history comment (shutdown 2026-10-16).
const GEMINI_MODEL_PRIMARY  = 'gemini-3.5-flash';
const GEMINI_MODEL_FALLBACK = 'gemini-3.1-flash-lite';
const GEMINI_API_URL = model =>
  `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
const GEMINI_MAX_OUTPUT_TOKENS = 1536; // vision replies run longer than chat's FAQ turns

// ── Size / MIME guards ──────────────────────────────────────────────────
// ~1.8MB JSON-body ceiling (base64 image(s) + small text fields), TOTAL —
// shared across however many images are in the request, not per image.
// Base64 inflates raw bytes by ~4/3, so this implies a ~1.3MB raw-image
// budget summed across all attached images — that's the number the
// client-side compressors (web canvas, VBA) target, dividing it further
// per-image once more than one is attached (see MAX_IMAGES_PER_REQUEST).
// This endpoint never resizes server-side: Cloudflare Free plan's 10ms CPU
// ceiling makes that 18-72x over budget (measured 178-720ms for decode+
// resize of ONE image; N images would only cost more) — resize must
// happen client-side, before the request is sent.
const MAX_BODY_BYTES = 1_800_000;
const MIME_ALLOWLIST = new Set([
  'image/jpeg', 'image/png', 'image/webp', 'image/heic', 'image/heif',
]);
const MESSAGE_MAX_LEN = 2000;
// Hard cap on images per request. Bounds Gemini input-token growth per call
// against the 13-key rotation pool this file exists to conserve (each
// tiled 768x768 region costs ~258 input tokens — see ai.google.dev image-
// understanding docs — so N images cost roughly N times the vision-token
// budget of one, before any text).
//
// v2.3 claimed the old "keep in sync with MAX_PENDING_IMAGES in
// footing_pro_v28.html and pc_suite_v28.html" note pointed at a constant
// that didn't exist, and that images[] below was unreachable dead code —
// checked at the time against the real files as they then stood, and
// correct at that time. v2.5 correction: re-checked against freshly
// re-uploaded copies of both HTML files and that has since been overtaken
// by the widgets' own multi-image work landing client-side.
// MAX_PENDING_IMAGES = 3 and an array-based pendingImages[] (with a bulk
// <input multiple> picker as of the widgets' own v5) are real and working
// in both, confirmed directly in their add/remove/send handlers — this IS
// the constant to keep in sync with, and images[] below is a live path
// exercised by any 2- or 3-image send from either widget, not idle
// capability. Whichever copy of the HTML files is actually deployed is the
// one that matters — re-verify against that, not against this comment,
// if the two are ever suspected of drifting apart again.
const MAX_IMAGES_PER_REQUEST = 3;

// ── Timeouts ─────────────────────────────────────────────────────────────
// Per-attempt: long enough for one multimodal call under normal conditions,
// short enough to fail over to another key rather than hang. Overall
// deadline: once elapsed time crosses this, stop STARTING new attempts (an
// attempt already in flight is left to finish or hit its own per-attempt
// ceiling) — bounds the worst case across a 13-key x 2-model pool without
// aborting a request that's actually about to succeed.
const PER_ATTEMPT_TIMEOUT_MS = 25_000;
const OVERALL_DEADLINE_MS    = 40_000;

// Worst case: 13 keys x 2 models = 26 — comfortably under the Free plan's
// 50-external-subrequest ceiling (verified 2026-07) with no shaving needed.
const SUBREQUEST_BUDGET_VISION = 26;

const ASSISTANT_NAME = 'Eng_pro assist';
const VISION_SYSTEM_PROMPT = `You are ${ASSISTANT_NAME}, the AI assistant for Civil Engineering Suite \
(civilengsuite.pages.dev), built by Eng. Aymn Asi — a practicing Licensed Structural Engineer. You are \
looking at one or more photos, drawings, or screenshots a member of a civil/structural engineering team \
has attached in chat, together with their question or instruction. When more than one image is attached, \
each is labeled "Image 1", "Image 2", etc., in the order it was attached — refer to that label when it \
helps ("the rebar spacing in Image 2 looks tighter than in Image 1"), and directly compare or cross- \
reference the images when the question calls for it (matching a note to the drawing page it belongs on, \
checking consistency between shots of the same element, and similar) rather than describing each one in \
isolation.

Ground your answer in what you actually see — element type, visible condition, and any labels, \
dimensions, or numbers legible in the image(s) — but fold that into the same sentence as your \
assessment rather than announcing it first as its own step: never open with "I see..." or "This image \
shows...". Lead with the reading, not a narrated preamble — this is a working engineer checking a chat \
reply, not a report. If an image shows a possible structural, safety, or code-compliance concern, say so \
plainly and recommend it be verified by a licensed engineer on site before anyone acts on it: you are \
giving a preliminary visual read, not a substitute for an in-person inspection or a stamped calculation. \
If an image is blurry, too dark, or you are not confident about a measurement or defect, say so directly \
instead of guessing a specific number.

Reply in the SAME language as the person's own message (Arabic or English) — never mix both in one \
reply. Keep the reply focused and practical: this is a working engineer reading a chat reply, not a \
report.`;

function isArabicText(str) {
  return /[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]/.test(str || '');
}

// ── Adaptive detail level ────────────────────────────────────────────────
// Product spec: default to a moderate detail level; escalate to high only
// when the person explicitly asks for granular inspection (rebar lap
// lengths, crack patterns, and similar). Gemini has no OpenAI-style
// client-passed `detail: low/high` field, so this can't be a simple param
// passthrough — the real lever, confirmed 2026-07-16 by fetching
// ai.google.dev/gemini-api/docs/generate-content/media-resolution in full
// (its Gemini-3-models token TABLE, not just the prose above it), is
// generationConfig.mediaResolution. Per that table: LOW=280, MEDIUM=560,
// HIGH=1120 tokens/image on the Gemini 3 family, and — the part worth
// double-checking against the table rather than the page's own summary
// paragraph — MEDIA_RESOLUTION_UNSPECIFIED (Default) is ALSO 1120 for
// Image, identical to HIGH. The page's prose describes the default as
// "tuned for a good balance of quality, latency, and cost," which reads
// like a hedge against exactly this number but isn't; the qualitative
// description and the quantitative table disagree for this specific
// media type on this specific model family. Setting the field explicitly
// is still the right call regardless (predictable and auditable beats an
// undocumented default, and lets this endpoint choose MEDIUM by default
// specifically rather than inherit whatever UNSPECIFIED resolves to) —
// and, as it happens, omitting it really would cost the same as HIGH for
// every image this endpoint handles.
//
// Heuristic below, not exhaustive NLP — tune the pattern as real usage
// shows misses. The risk asymmetry runs opposite to how it might first
// read: a false POSITIVE (escalates to HIGH when it didn't need to) just
// spends extra tokens on an image that didn't require them — harmless. A
// false NEGATIVE (misses a real close-inspection need and falls through to
// the default) silently under-resources exactly the case this tool can't
// afford to get wrong — a legible dimension or hairline crack read at the
// wrong resolution. That asymmetry is why the no-match default below is
// MEDIUM, not LOW: LOW is never chosen by inference, only by an explicit,
// deliberate override from a caller that has separately confirmed an image
// is low-stakes context.
// v2.5: tightened after actually EXECUTING this against the product spec's
// own example phrase verbatim — "checking specific rebar lap lengths or
// critical crack patterns" did NOT match. Root cause: lap\s*(?:length|
// splice) required the exact singular with a trailing \b, so plural
// "lengths" failed the boundary check (no word break between "length" and
// its own trailing "s"); crack\s*width doesn't cover "crack patterns" at
// all — a different word never in the list. Verified fix below against the
// same phrase via node -e before shipping, not just reasoned about:
// pluralized lap/crack terms, added crack\s*patterns? as its own
// alternative, detail(?:s|ed)? now also catches bare "details".
const HIGH_DETAIL_PATTERN_EN =
  /\b(detail(?:s|ed)?|zoom(?:ed)?[\s-]?ins?|close[\s-]?up|precis(?:e|ely)|exact(?:ly)?|measur\w*|crack\s*widths?|crack\s*patterns?|rebar\s*spacing|bar\s*spacing|lap\s*(?:lengths?|splices?)|inspect(?:ion)?\s*closely|look\s*closely|magnif\w*|legible|small\s*text|read\s*the\s*(?:label|note))\b/i;
const HIGH_DETAIL_PATTERN_AR =
  /(بالتفصيل|تفاصيل|بتفاصيل|بدقة|دقيق|قياسات?|تكبير|كبّر|تباعد|قطر\s*(?:السيخ|الحديد|العمود)|وصلة|افحص\s*(?:بدقة|جيدا))/;
function wantsHighDetail(text) {
  const s = text || '';
  return HIGH_DETAIL_PATTERN_EN.test(s) || HIGH_DETAIL_PATTERN_AR.test(s);
}


// ── CORS — copied locally rather than assumed-shared (see header: this
// file can't verify whether a shared cors.mjs exists in the real project,
// and a wrong import would break the build outright). ───────────────────
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
    'Access-Control-Allow-Headers': 'Content-Type, X-Client-Date',
    'Vary'                        : 'Origin',
  };
}

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

// Errors that can occur before the body is parsed — language is genuinely
// unknown at that point, so both languages are shown together.
function prevalidationError(en, ar) {
  return `${en} / ${ar}`;
}

// ── Friendly, bilingual (language-detected) error builder for everything
// that happens AFTER the user's message has been parsed. ────────────────
function buildFriendlyVisionError(result, ar) {
  if (result.errStatus === 'RESOURCE_EXHAUSTED') {
    return ar
      ? 'الحصة اليومية لتحليل الصور اتخلصت — بترجع بعد منتصف الليل UTC. للأسئلة العاجلة: واتساب +201287232413 · aymneidasi@gmail.com.'
      : 'Daily image-analysis quota reached — resets after midnight UTC. For urgent questions: WhatsApp +201287232413 · aymneidasi@gmail.com.';
  }
  if (result.errStatus === 'RATE_LIMIT_EXCEEDED') {
    return ar
      ? 'في طلبات كتير دلوقتي. استنى 30-60 ثانية وحاول تاني.'
      : 'Too many requests right now. Please wait 30-60 seconds and try again.';
  }
  if (result.errStatus === 'SUBREQUEST_BUDGET_EXHAUSTED' || result.errStatus === 'OVERALL_DEADLINE_EXCEEDED') {
    return ar
      ? 'المساعد مشغول جداً دلوقتي. حاول تاني بعد لحظات.'
      : 'The assistant is extremely busy right now. Please try again in a moment.';
  }
  if (result.errStatus === 'TIMEOUT') {
    return ar
      ? 'الخدمة بطيئة شوية دلوقتي. جرب تاني بعد لحظات.'
      : 'The vision service is slow to respond right now. Please try again shortly.';
  }
  if (result.errStatus === 'EMPTY_REPLY') {
    return ar
      ? 'معرفتش أوصف الصورة دي. جرب صورة تانية أو وضّح سؤالك.'
      : "Couldn't get a usable answer for that image. Try a different image or a more specific question.";
  }
  if ((result.errStatus || '').startsWith('BLOCKED_')) {
    return ar
      ? 'تعذّر تحليل هذه الصورة (تم حظرها من قبل فلتر المحتوى).'
      : 'This image could not be analyzed (content filter).';
  }
  if (result.httpStatus === 400) {
    return ar
      ? 'الطلب المرسل إلى نموذج الرؤية غير صالح.'
      : 'The request to the vision model was malformed.';
  }
  const byStatus = {
    401: { en: 'API authentication failed. Please contact site admin.', ar: 'فشل المصادقة، تواصل مع المسؤول.' },
    403: { en: 'API access denied. Please contact site admin.',          ar: 'الوصول محجوب، تواصل مع المسؤول.' },
    404: { en: 'Vision model unavailable. Please contact site admin.',   ar: 'نموذج تحليل الصور غير متاح، تواصل مع المسؤول.' },
    500: { en: 'The image-analysis service encountered an error. Please try again.', ar: 'حصل خطأ في خدمة تحليل الصورة، حاول مرة أخرى.' },
    503: { en: 'The image-analysis service is temporarily unavailable. Please try again in a minute.', ar: 'خدمة تحليل الصورة مش متاحة دلوقتي، جرب تاني بعد دقيقة.' },
  };
  const matched = byStatus[result.httpStatus];
  if (matched) return ar ? matched.ar : matched.en;

  return ar
    ? 'حصل مشكلة أثناء تحليل الصورة، حاول مرة أخرى، أو تواصل معنا: واتساب +201287232413 · aymneidasi@gmail.com.'
    : 'Something went wrong analyzing the image. Please try again, or contact us: WhatsApp +201287232413 · aymneidasi@gmail.com.';
}

// ── Body reader with a hard byte cap enforced on ACTUAL bytes received,
// independent of the (possibly absent or spoofed) Content-Length header —
// the Content-Length check in onRequestPost is only a cheap fast path. ──
async function readBodyWithCap(request, capBytes) {
  if (!request.body) return await request.text();
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > capBytes) {
      try { await reader.cancel(); } catch { /* best-effort */ }
      throw new Error('PAYLOAD_TOO_LARGE');
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { merged.set(c, offset); offset += c.byteLength; }
  return new TextDecoder('utf-8').decode(merged);
}

// ── Provider call — single attempt, no in-place backoff-retry (see header
// rationale). payloadString is pre-built ONCE by the caller and reused
// verbatim across every key/model attempt; only the URL varies. ─────────
async function callGeminiVisionOnce(apiKey, model, payloadString, budget) {
  if (!budget.take()) {
    return { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };
  }

  let res;
  try {
    res = await fetchWithTimeout(
      `${GEMINI_API_URL(model)}?key=${apiKey}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payloadString },
      PER_ATTEMPT_TIMEOUT_MS,
    );
  } catch (err) {
    const isTimeout = err.name === 'AbortError';
    if (!isTimeout) {
      console.error(`[vision.js] Network error calling Gemini (${model}):`, err.message);
    }
    return { ok: false, httpStatus: 0, errStatus: isTimeout ? 'TIMEOUT' : 'NETWORK_ERROR', errBody: err.message };
  }

  if (!res.ok) {
    let errBody = '';
    let errStatus = '';
    try {
      errBody = await res.text();
      errStatus = JSON.parse(errBody)?.error?.status || '';
    } catch { /* non-fatal — body may be non-JSON */ }
    if (res.status !== 429) {
      console.error(`[vision.js] Gemini HTTP ${res.status} for model ${model}:`, errBody.slice(0, 500));
    }
    return { ok: false, httpStatus: res.status, errStatus, errBody };
  }

  let data;
  try {
    data = await res.json();
  } catch (err) {
    return { ok: false, httpStatus: res.status, errStatus: 'BAD_JSON_RESPONSE', errBody: err.message };
  }

  const blockReason = data?.promptFeedback?.blockReason;
  if (blockReason) {
    return { ok: false, httpStatus: res.status, errStatus: `BLOCKED_${blockReason}`, errBody: '' };
  }

  const candidate = data?.candidates?.[0];
  const finishReason = candidate?.finishReason;
  if (finishReason === 'SAFETY' || finishReason === 'PROHIBITED_CONTENT' || finishReason === 'BLOCKLIST') {
    return { ok: false, httpStatus: res.status, errStatus: `BLOCKED_${finishReason}`, errBody: '' };
  }
  if (finishReason === 'MAX_TOKENS') {
    console.warn(`[vision.js] Gemini ${model} hit MAX_TOKENS (budget: ${GEMINI_MAX_OUTPUT_TOKENS}) — reply may be truncated.`);
  }

  const parts = candidate?.content?.parts || [];
  const reply = parts
    .filter(p => !p?.thought && typeof p?.text === 'string')
    .map(p => p.text)
    .join('')
    .trim();
  if (!reply) {
    return { ok: false, httpStatus: res.status, errStatus: 'EMPTY_REPLY', errBody: '' };
  }
  return { ok: true, reply };
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // 0. Cheapest possible reject — Content-Length header, before any body
  //    read at all. Fast path only; the real guard is readBodyWithCap.
  const declaredLength = Number(request.headers.get('content-length') || 0);
  if (declaredLength > MAX_BODY_BYTES) {
    return json(
      { error: prevalidationError(
          'Images are too large. Please use photos totalling under ~1.3MB (the app compresses this automatically).',
          'الصورة كبيرة جدًا. الرجاء استخدام صورة أصغر من ١.٣ ميغابايت تقريبًا.',
        ) },
      413, undefined, request,
    );
  }

  // 1. Rate limit — namespaced 'vision:' so an image-upload burst and a
  //    text-chat burst from the same IP draw from separate budgets: image
  //    requests are heavier (bigger payload, slower provider call) and
  //    would otherwise throttle unrelated chat traffic from the same user.
  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateCheck = await checkRateLimit(env, `vision:${clientIp}`);
  if (rateCheck.limited) {
    return json(
      { error: prevalidationError(
          'Too many image requests too quickly. Please wait a moment and try again.',
          'صور كتير بسرعة. استنى لحظة وحاول تاني.',
        ) },
      429, undefined, request,
    );
  }

  // 2. Gemini configured at all — cheap env read, no I/O.
  const baseGeminiKey = env.GEMINI_API_KEY || '';
  if (!baseGeminiKey) {
    return json(
      { error: prevalidationError(
          'No AI provider configured. Set GEMINI_API_KEY in Cloudflare Pages environment variables.',
          'لا يوجد مزود ذكاء اصطناعي مُهيأ. الرجاء ضبط GEMINI_API_KEY في إعدادات Cloudflare Pages.',
        ) },
      500, undefined, request,
    );
  }

  // 3. Read body under a hard cap enforced on actual bytes received.
  let rawBody;
  try {
    rawBody = await readBodyWithCap(request, MAX_BODY_BYTES);
  } catch (err) {
    if (err.message === 'PAYLOAD_TOO_LARGE') {
      return json(
        { error: prevalidationError(
            'Images are too large. Please use photos totalling under ~1.3MB.',
            'الصورة كبيرة جدًا. الرجاء استخدام صورة أصغر من ١.٣ ميغابايت تقريبًا.',
          ) },
        413, undefined, request,
      );
    }
    return json({ error: prevalidationError('Could not read the request body.', 'تعذّرت قراءة الطلب.') }, 400, undefined, request);
  }

  // 4. Parse — read raw text first regardless of Content-Type (a VBA
  //    MSXML2 caller has no reason to send one), then JSON.parse manually.
  let body;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return json({ error: prevalidationError('Request body must be valid JSON.', 'يجب أن يكون محتوى الطلب بصيغة JSON صحيحة.') }, 400, undefined, request);
  }

  // 5. Extract fields. Both `message`/`prompt` and `mimeType`/`mime` are
  //    accepted — see header note on why this file can't be sure which
  //    the real client sends without seeing chat.js/the HTML clients.
  let userMessage =
    (typeof body?.message === 'string' && body.message.trim()) ||
    (typeof body?.prompt === 'string' && body.prompt.trim()) ||
    '';
  if (!userMessage) {
    userMessage = 'Please review this image and share your engineering observations.';
  }
  if (userMessage.length > MESSAGE_MAX_LEN) {
    userMessage = userMessage.slice(0, MESSAGE_MAX_LEN);
  }

  const lang = body?.lang === 'ar' ? 'ar' : body?.lang === 'en' ? 'en' : null;
  const likelyArabic = lang ? lang === 'ar' : isArabicText(userMessage);
  if (lang === 'ar') {
    userMessage += '\n\n[الرجاء الرد باللغة العربية فقط]';
  } else if (lang === 'en') {
    userMessage += '\n\n[Please reply in English only]';
  }

  // 5b. Extract image(s). Two accepted shapes:
  //     - `images`: [{ data, mime }, ...] — NEW, up to MAX_IMAGES_PER_REQUEST,
  //       sent by the updated web widget (footing_pro_v28.html / pc_suite_v28.html).
  //     - `image` + `mimeType`/`mime`     — LEGACY singular shape, left
  //       byte-for-byte compatible. This is what the VBA desktop client
  //       sends (see file header: "web + VBA desktop") and this repo has
  //       no visibility into that caller's source, so it cannot be
  //       migrated — it is normalized into a 1-element images[] below and
  //       runs through the exact same validation/payload path as any
  //       other single-image request, unchanged from v2.0.
  function validateOneImage(rawData, rawMime, label) {
    let data = typeof rawData === 'string' ? rawData.trim() : '';
    if (data.startsWith('data:') && data.includes(',')) data = data.split(',')[1];
    if (!data) {
      return { ok: false, error: buildFriendlyVisionError({ httpStatus: 400, errStatus: '' }, likelyArabic) };
    }
    if (data.length < 100 || !/^[A-Za-z0-9+/]+=*$/.test(data)) {
      return {
        ok: false,
        error: likelyArabic ? `بيانات ${label} ليست Base64 صالحة.` : `${label} data is not valid base64.`,
      };
    }
    const mimeType = (typeof rawMime === 'string' && rawMime.trim().toLowerCase()) || '';
    if (!MIME_ALLOWLIST.has(mimeType)) {
      return {
        ok: false,
        error: likelyArabic
          ? `نوع غير مدعوم لـ ${label}. استخدم JPEG أو PNG أو WEBP أو HEIC أو HEIF.`
          : `Unsupported type for ${label}. Use JPEG, PNG, WEBP, HEIC, or HEIF.`,
      };
    }
    return { ok: true, mimeType, data };
  }

  let rawImages;
  if (Array.isArray(body?.images)) {
    // Sliced to one past the cap — enough to detect an over-cap request
    // below without validating/base64-checking an arbitrarily long array
    // an unthrottled non-browser caller could otherwise pad the request
    // with (see rotation.mjs's rate-limiter header note on this threat
    // model — CORS does not stop a direct POST to this endpoint).
    rawImages = body.images.slice(0, MAX_IMAGES_PER_REQUEST + 1);
  } else if (typeof body?.image === 'string' && body.image.trim()) {
    rawImages = [{
      data: body.image,
      mime: (typeof body?.mimeType === 'string' && body.mimeType) ||
            (typeof body?.mime === 'string' && body.mime) || '',
    }];
  } else {
    rawImages = [];
  }

  if (rawImages.length === 0) {
    return json({ error: buildFriendlyVisionError({ httpStatus: 400, errStatus: '' }, likelyArabic) }, 400, undefined, request);
  }
  if (rawImages.length > MAX_IMAGES_PER_REQUEST) {
    return json({
      error: likelyArabic
        ? `الحد الأقصى ${MAX_IMAGES_PER_REQUEST} صور في الرسالة الواحدة.`
        : `Maximum ${MAX_IMAGES_PER_REQUEST} images per message.`,
    }, 400, undefined, request);
  }

  const images = [];
  for (let i = 0; i < rawImages.length; i++) {
    const entry = rawImages[i] || {};
    const label = rawImages.length > 1 ? `Image ${i + 1}` : 'Image';
    const result = validateOneImage(entry?.data, entry?.mime ?? entry?.mimeType, label);
    if (!result.ok) {
      return json({ error: result.error }, 400, undefined, request);
    }
    images.push({ mimeType: result.mimeType, data: result.data });
  }

  // 5c. Adaptive detail level. Computed once, from the fully-resolved
  //     userMessage (language-suffix included; the suffix text itself
  //     never matches either keyword pattern, so appending it first vs.
  //     checking before are equivalent here).
  //
  //     Precedence: an explicit body.detail (any caller that CAN state its
  //     own confidence directly — a future multi-image picker UI, or the
  //     VBA desktop client, whose source this repo can't see and so cannot
  //     rule out) wins outright. Otherwise, wantsHighDetail()'s heuristic
  //     over the user's own free-text message escalates to 'high' — this
  //     is the path that actually fires today, since the current web
  //     widget (pc_suite_v28.html) sends only `{ image, mime, prompt }`
  //     with no UI control to set a detail param at all. Anything else
  //     falls through to 'medium' — never 'low' by inference, only by an
  //     explicit override — for the accuracy reasons in the block above.
  const explicitDetail =
    body?.detail === 'high' || body?.detail === 'low' || body?.detail === 'medium'
      ? body.detail
      : null;
  const detailReq = explicitDetail || (wantsHighDetail(userMessage) ? 'high' : 'medium');
  const MEDIA_RESOLUTION = {
    low: 'MEDIA_RESOLUTION_LOW', medium: 'MEDIA_RESOLUTION_MEDIUM', high: 'MEDIA_RESOLUTION_HIGH',
  }[detailReq];

  // 6. Build the outbound Gemini payload ONCE — identical across every
  //    key/model attempt (only the URL varies), see header note on why
  //    this matters under a 10ms/invocation CPU ceiling. Casing verified
  //    2026-07 against ai.google.dev's own curl examples: snake_case for
  //    system_instruction/inline_data/mime_type, camelCase inside
  //    generationConfig.
  //
  //    At N=1 the parts array is BYTE-IDENTICAL to the pre-multi-image
  //    contract — [inline_data, text], image before text per the header's
  //    verified single-image guidance — so the VBA client and any other
  //    single-image caller sees no behavior change. At N>1, each image is
  //    preceded by a short "Image N:" label (matching VISION_SYSTEM_PROMPT's
  //    own numbering) so the model can refer to individual images when
  //    comparing them — the actual capability gap multi-image exists to
  //    close (rebar spacing between two shots, which drawing page a note
  //    belongs on, etc.). Part ORDER differs by N — see v2.2 header note:
  //    N=1 is image-then-text, N>1 is text-then-images, each matching a
  //    DIFFERENT documented example on the same ai.google.dev page.
  const imageParts = images.length === 1
    ? [{ inline_data: { mime_type: images[0].mimeType, data: images[0].data } }]
    : images.flatMap((img, i) => [
        { text: `Image ${i + 1}:` },
        { inline_data: { mime_type: img.mimeType, data: img.data } },
      ]);

  const parts = images.length === 1
    ? [...imageParts, { text: userMessage }]   // image before text — single-image best practice
    : [{ text: userMessage }, ...imageParts];  // text before images — multi-image example pattern

  const payloadString = JSON.stringify({
    system_instruction: { parts: [{ text: VISION_SYSTEM_PROMPT }] },
    contents: [{
      role: 'user',
      parts,
    }],
    generationConfig: {
      maxOutputTokens: GEMINI_MAX_OUTPUT_TOKENS,
      // temperature/topP deliberately OMITTED (v2.4): Google's Gemini 3.x
      // migration guidance (ai.google.dev/gemini-api/docs/generate-content/
      // whats-new-gemini-3.5, re-verified 2026-07-16) lists both as "no
      // longer recommended" for gemini-3.5-flash / gemini-3.1-flash-lite
      // and says to remove them outright — default sampling is already
      // tuned for the 3.x reasoning path.
      //
      // thinkingConfig.thinkingLevel replaces thinkingBudget (v2.4) — same
      // intent as chat.js's v19 fix (keep reasoning tokens from eating the
      // visible-answer budget under GEMINI_MAX_OUTPUT_TOKENS), but
      // thinkingBudget is legacy-only on the 3.x family, and sending it
      // together with thinkingLevel in one request is a hard 400. 'LOW'
      // (not 'MINIMAL'): VISION_SYSTEM_PROMPT asks for a safety/code-
      // compliance judgment call on top of a plain description — Google's
      // own effort-level guidance places that in "analysis and writing
      // tasks that require some thinking," not pure fact retrieval.
      thinkingConfig : { thinkingLevel: 'LOW' },
      mediaResolution: MEDIA_RESOLUTION,
    },
  });

  // 7. Build the key pool — SAME 13 keys chat.js reads, via rotation.mjs's
  //    buildGeminiKeyPool(). v2.3: this used to be a second, hand-copied
  //    13-line array literal here. Confirmed 2026-07-16 against the real
  //    rotation.mjs and chat.js: rotation.mjs exports buildGeminiKeyPool
  //    (env) and keyTagFor(originalIndex) specifically so this file and
  //    chat.js share one canonical copy of the key list and the _1-skip
  //    numbering, and chat.js already imports and calls both. Replaced
  //    the inline literal with the same calls chat.js makes — deleting the
  //    exact drift risk rotation.mjs's own header comment warns against.
  const geminiKeysIndexed = buildGeminiKeyPool(env);

  const geminiPool = rotateStart(geminiKeysIndexed);
  const budget = makeFetchBudget(SUBREQUEST_BUDGET_VISION);
  const startTime = Date.now();

  let lastResult = { ok: false, httpStatus: 0, errStatus: 'NOT_ATTEMPTED', errBody: '' };

  outer:
  for (const { key: gKey, originalIndex } of geminiPool) {
    const keyTag = keyTagFor(originalIndex);

    for (const [model, modelTag] of [[GEMINI_MODEL_PRIMARY, 'primary'], [GEMINI_MODEL_FALLBACK, 'fallback']]) {
      if (budget.remaining() <= 0) {
        console.warn('[vision.js] Subrequest budget exhausted — stopping early.');
        lastResult = { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };
        break outer;
      }
      if (Date.now() - startTime > OVERALL_DEADLINE_MS) {
        console.warn('[vision.js] Overall deadline exceeded — stopping rotation, not starting a new attempt.');
        lastResult = { ok: false, httpStatus: 0, errStatus: 'OVERALL_DEADLINE_EXCEEDED', errBody: '' };
        break outer;
      }

      const result = await callGeminiVisionOnce(gKey, model, payloadString, budget);
      if (result.ok) {
        return json(
          { reply: result.reply },
          200,
          {
            'X-CES-Vision-Source': `gemini-${keyTag}${modelTag}`,
            'X-CES-Vision-Detail': detailReq,
          },
          request,
        );
      }

      if (result.errStatus !== 'SUBREQUEST_BUDGET_EXHAUSTED') {
        console.warn(`[vision.js] Gemini ${keyTag || 'key1-'}${model} failed:`, result.errStatus, result.httpStatus);
      }
      lastResult = result;

      // Safety-filter block or malformed request: every key/model would
      // fail identically, so rotating further only burns the budget.
      if ((result.errStatus || '').startsWith('BLOCKED_') || result.httpStatus === 400) {
        break outer;
      }
      // Otherwise (429, 403, 5xx, NETWORK_ERROR, TIMEOUT, EMPTY_REPLY):
      // fall through to the fallback model, then the next key.
    }
  }

  const status =
    lastResult.httpStatus === 400 ? 400
    : (lastResult.errStatus || '').startsWith('BLOCKED_') ? 422
    : (lastResult.errStatus === 'RESOURCE_EXHAUSTED' || lastResult.errStatus === 'RATE_LIMIT_EXCEEDED') ? 429
    : (lastResult.httpStatus && lastResult.httpStatus !== 0) ? lastResult.httpStatus
    : 502;

  return json(
    { error: buildFriendlyVisionError(lastResult, likelyArabic) },
    status, undefined, request,
  );
}

export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}
