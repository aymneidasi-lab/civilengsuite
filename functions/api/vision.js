/**
 * functions/api/vision.js — v3.0 (text file attachments, 2026-07-20)
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
 *
 * ── v3.0 (text file attachments, 2026-07-20): banner corrected from v2.3 to
 *    v3.0 as part of this change — the header above already documented
 *    v2.4/v2.5/v2.6 reconciliation passes (mediaResolution table fix,
 *    wantsHighDetail() risk-direction and regex fixes, multi-image
 *    confirmation) that the top-of-file version line was never bumped to
 *    reflect; confirmed by reading this file directly rather than trusting
 *    line 2. This version's actual change:
 *
 *    BUG: pc_suite_v33.html sends body.files: [{name, content}, ...]
 *    alongside images whenever text files are attached to the same send
 *    (its own comment names this file's expected counterpart directly:
 *    "vision.js v3.0's extractTextFiles()/buildTextFilesBlock()"). This
 *    file never read body.files — confirmed against the real field-
 *    extraction block (step 5/5b), which only ever read message/prompt/
 *    lang/images/image/mimeType/mime/detail. Attached text content was
 *    silently dropped on any combined image+file send.
 *
 *    FIX: same MAX_TEXT_FILES/MAX_CHARS_PER_TEXT_FILE/
 *    MAX_TOTAL_TEXT_FILE_CHARS caps, looksLikeBinaryContent(),
 *    extractTextFiles(), and buildTextFilesBlock() as chat.js v24 —
 *    duplicated locally rather than added to rotation.mjs (that file isn't
 *    visible from here; this follows the same
 *    copied-locally-rather-than-assumed-shared convention already used for
 *    getCorsHeaders() above). New step 5d runs AFTER detailReq (5c) is
 *    computed — wantsHighDetail() must see only the person's own words,
 *    never file content that could accidentally contain a matching
 *    keyword — and merges into a new modelMessageText variable used only
 *    at the parts-array construction below; userMessage itself is
 *    unchanged (its last real read is wantsHighDetail() above this point).
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
import { raceKeyPool } from '../_lib/raceKeyPool.mjs';
import { callGeminiStreaming } from '../_lib/streamingProviders.mjs';
import { SseChunkWriter } from '../_lib/resumableSse.mjs'; // [PATCH] resume-mechanism chunkIndex writer
import { PDF_MIME_TYPE, validatePdfDocument } from '../_lib/documentGuard.mjs'; // NEW — "Insert Text / PDF"

// ── Models — same pair chat.js uses. gemini-3.5-flash confirmed current
// GA/multimodal (ai.google.dev, 2026-07). gemini-2.5-flash is NOT used here
// per chat.js's own migration-history comment (shutdown 2026-10-16).
const GEMINI_MODEL_PRIMARY  = 'gemini-3.5-flash';
const GEMINI_MODEL_FALLBACK = 'gemini-3.1-flash-lite';
const GEMINI_API_URL = model =>
  `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
const GEMINI_MAX_OUTPUT_TOKENS = 1536; // vision replies run longer than chat's FAQ turns

// [PATCH] Same concurrency rationale as chat.js's identical constant — see
// that file's own comment. Kept as a separate local constant rather than a
// shared _lib export since it's a single primitive value, not worth a
// module just to avoid one line of duplication.
const RACE_CONCURRENCY = 3;

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
// Raised from 1,800,000 (NEW — PDF support): the streaming body-cap reader
// runs BEFORE JSON.parse, so at read time we cannot yet know whether this
// request carries a PDF (which needs headroom up to documentGuard.mjs's
// MAX_PDF_BASE64_CHARS = 18,000,000) or is a plain image/text request (which
// never gets near this ceiling). One shared cap, sized for the PDF case, is
// simpler and safer than guessing from Content-Length before parsing — the
// cost is a bigger worst-case bound on how much a spoofed/oversized junk
// body can make this Worker read before rejecting it. Still fully bounded.
// NEEDS LOAD-TESTING on the actual Cloudflare account: the Free-plan 10ms
// CPU/invocation ceiling this file's header already documents was verified
// against ~1.8MB base64 image payloads, not an ~18MB PDF one — decoding/
// JSON-parsing a string an order of magnitude larger is synchronous CPU
// work this repo has not yet measured. If it blows the CPU budget, the fix
// is a lower MAX_PDF_BASE64_CHARS in documentGuard.mjs, not a change here.
const MAX_BODY_BYTES = 19_000_000;
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

// ── Text file attachments ("Insert Text File") — NEW v3.0 ──────────────────
// Same three caps, same two helpers, as chat.js v24's identical block —
// duplicated locally rather than added to functions/_lib/rotation.mjs
// (not visible from this file; follows the same copied-locally-rather-
// than-assumed-shared convention already used for getCorsHeaders() below,
// and for buildGeminiKeyPool()/keyTagFor() before those were confirmed
// real exports and actually imported — see v2.3 above). Keep these three
// values in sync with pc_suite_v33.html's MAX_PENDING_TEXT_FILES /
// MAX_TEXT_FILE_CHARS_PER_FILE / MAX_TOTAL_TEXT_FILE_CHARS and with
// chat.js's identical copy — client caps are UX only, a direct POST to
// this endpoint bypasses them entirely, same threat model as
// MAX_IMAGES_PER_REQUEST above.
const MAX_TEXT_FILES            = 3;
const MAX_CHARS_PER_TEXT_FILE   = 6000;
const MAX_TOTAL_TEXT_FILE_CHARS = 12000;

// Cheap heuristic, not a MIME sniff — body.files[].content always arrives as
// an already-decoded JS string (JSON.parse output), never raw bytes, so
// there is no header/magic-number to check here. A renamed .docx/.pdf/.exe
// read client-side via FileReader.readAsText() decodes as mojibake: a high
// density of U+FFFD replacement characters and C0 control codes outside
// whitespace. Threshold kept loose (15%) to avoid false positives on
// legitimate content with heavy non-ASCII (Arabic diacritics, math symbols,
// box-drawing characters in a pasted table).
function looksLikeBinaryContent(str) {
  if (!str) return false;
  const len = str.length;
  let suspicious = 0;
  for (let i = 0; i < len; i++) {
    const code = str.charCodeAt(i);
    if (code === 0xFFFD || (code < 32 && code !== 9 && code !== 10 && code !== 13)) {
      suspicious++;
    }
  }
  return len > 0 && (suspicious / len) > 0.15;
}

// Validates + normalizes body.files into a clean {name, content, truncated}[]
// array, enforcing the three caps above server-side. Returns
// { ok:true, files } or { ok:false, error } — error is the bilingual string
// ready to drop straight into a 400 json({error}) response, matching this
// file's existing validation-error style (see MAX_IMAGES_PER_REQUEST's
// rejection in onRequestPost). Count violations reject outright (same
// pattern as MAX_IMAGES_PER_REQUEST — a caller sending more than the UI
// allows is bypassing the UI, worth a loud error); per-file/total character
// overflows truncate instead of rejecting (same pattern as this file's own
// MESSAGE_MAX_LEN silent-truncate) and are flagged inline by
// buildTextFilesBlock() below so the model never treats truncated content
// as complete.
function extractTextFiles(body, likelyArabicMsg) {
  if (!Array.isArray(body?.files) || body.files.length === 0) {
    return { ok: true, files: [] };
  }
  if (body.files.length > MAX_TEXT_FILES) {
    return {
      ok: false,
      error: likelyArabicMsg
        ? `الحد الأقصى ${MAX_TEXT_FILES} ملفات في الرسالة الواحدة.`
        : `Maximum ${MAX_TEXT_FILES} files per message.`,
    };
  }
  const files = [];
  let totalChars = 0;
  for (const raw of body.files) {
    const name = typeof raw?.name === 'string' && raw.name.trim()
      ? raw.name.trim().slice(0, 200)
      : 'attachment.txt';
    let content = typeof raw?.content === 'string' ? raw.content : '';
    if (!content.trim()) continue; // empty file — skip, not a rejection reason
    let truncated = false;
    if (content.length > MAX_CHARS_PER_TEXT_FILE) {
      content = content.slice(0, MAX_CHARS_PER_TEXT_FILE);
      truncated = true;
    }
    const roomLeft = MAX_TOTAL_TEXT_FILE_CHARS - totalChars;
    if (roomLeft <= 0) break; // combined cap already reached — drop remaining files silently
    if (content.length > roomLeft) {
      content = content.slice(0, roomLeft);
      truncated = true;
    }
    if (!content) continue;
    // Binary-check runs AFTER both truncation steps, never on raw
    // pre-truncation content — bounds the scan to at most
    // MAX_CHARS_PER_TEXT_FILE chars regardless of how large the caller's
    // raw content string is. MAX_BODY_BYTES already bounds the overall
    // request here (unlike chat.js, which has no such cap), but this
    // ordering is still strictly more correct: it checks binary-ness of
    // exactly what will be sent to the model, not a discarded tail.
    if (looksLikeBinaryContent(content)) {
      return {
        ok: false,
        error: likelyArabicMsg
          ? `الملف "${name}" لا يبدو ملف نصي صالح.`
          : `"${name}" doesn't look like a valid text file.`,
      };
    }
    totalChars += content.length;
    files.push({ name, content, truncated });
  }
  return { ok: true, files };
}

// Formats validated files into the block appended ONLY to the model-bound
// copy of the message (modelMessageText below) — never to userMessage
// itself. userMessage stays the bare resolved caption everywhere else it's
// used (wantsHighDetail()'s keyword heuristic, the MESSAGE_MAX_LEN cap) so
// none of that logic sees file content it was never designed to handle.
function buildTextFilesBlock(files) {
  if (!files || files.length === 0) return '';
  return files.map(f =>
    `\n\n--- Attached file: ${f.name}${f.truncated ? ' (truncated)' : ''} ---\n${f.content}` +
    (f.truncated ? '\n[... file truncated at the server-side size limit ...]' : '') +
    `\n--- End of ${f.name} ---`
  ).join('');
}

// ── KV-staged files (v36) ────────────────────────────────────────────────
// Companion to POST /api/chat/dev-upload (functions/api/chat/dev-upload.js)
// and chat.js's own resolveKvFiles(), which this mirrors. A developer
// uploads a large file once via /api/chat/dev-upload (X-Developer-Token
// header, checked there against env.DEVELOPER_PASSWORD), gets back a
// fileId, and can send that fileId to EITHER /api/chat OR this endpoint
// (whichever one ends up handling the message, depending on whether an
// image is also attached) via body.kvFileIds.
//
// NO isDeveloperMode GATE HERE, UNLIKE chat.js's VERSION — deliberate, not
// an oversight: this file has no devPassword/isDeveloperMode concept at
// all (MAX_TEXT_FILES/MAX_CHARS_PER_TEXT_FILE/MAX_TOTAL_TEXT_FILE_CHARS
// above are fixed, never elevated — see that block's own comment). Adding
// one just for this would mean porting chat.js's hmacTimingSafeEqual() +
// isDeveloperMode computation into a file that currently has neither,
// which is a materially bigger and more invasive change than "apply the
// fix." Instead, this relies on the fileId itself as the capability: it is
// a crypto.randomUUID() (122 bits of randomness) that could only have been
// minted by a caller who already passed the X-Developer-Token check at
// upload time — nothing here re-derives or re-checks that password, but
// nothing here can be reached without having passed it once, upstream. If
// you want this file to require its OWN devPassword on top of that (full
// symmetry with chat.js), that is a separate, larger change — say so and
// it can be added as its own patch rather than folded into this one.
//
// DEV_KV_MAX_TOTAL_CONTEXT_CHARS reuses chat.js's exact 350,000-char
// value for consistency, even though this file's OWN fallback chain
// (GEMINI_MODEL_PRIMARY / GEMINI_MODEL_FALLBACK — both Gemini 3.x Flash,
// ~1M-token context, no Workers AI/Groq/OpenRouter step) could in
// principle support a much larger figure — chat.js's number is bottlenecked
// by Workers AI's 128K-token floor, which this file never routes through.
// Kept the same anyway rather than re-deriving a vision.js-specific number:
// one constant to reason about beats two similar-but-different ones, and
// this file's own MAX_BODY_BYTES (1,800,000 — see above) already caps the
// realistic ceiling for the request as a whole once image payloads are
// factored in.
const DEV_KV_MAX_TOTAL_CONTEXT_CHARS = 350000;

// REMOVED (v37): DEV_KV_MAX_FILES_PER_MESSAGE, formerly hardcoded to 3 —
// same value, same non-issue, same fix as chat.js's identical constant;
// see that file's own removal comment for the full Cloudflare-subrequest-
// budget reasoning (50 external/invocation vs. 1,000 Cloudflare-service/
// invocation — KV calls draw from the latter). This file's own
// SUBREQUEST_BUDGET_VISION comment above already independently states the
// same 50-external-subrequest figure, "verified 2026-07" — consistent
// with that. This function never had an isDeveloperMode gate (see block
// comment above) because it didn't need one: the count cap was gating a
// path already gated by possession of a fileId, obtainable only via
// authenticated dev-upload.js — a gate behind a gate, same shape as
// chat.js's version, same fix.
async function resolveKvFiles(body, env) {
  const ids = Array.isArray(body?.kvFileIds)
    ? body.kvFileIds.filter((x) => typeof x === 'string' && x)
    : [];
  if (ids.length === 0) return { ok: true, files: [] };
  if (!env.CES_DEV_UPLOADS) {
    return { ok: false, error: 'CES_DEV_UPLOADS KV namespace is not bound on the server.' };
  }

  // Concurrent GET, same rationale as chat.js's identical block: the old
  // sequential per-id loop made wall-clock cost scale linearly with file
  // count, invisible at the old 3-file ceiling but not once it's gone.
  const settled = await Promise.all(ids.map(async (fileId) => {
    let raw = null;
    for (let attempt = 0; attempt < 2 && raw === null; attempt++) {
      if (attempt > 0) await new Promise((r) => setTimeout(r, 400));
      try {
        raw = await env.CES_DEV_UPLOADS.get(`devupload:${fileId}`);
      } catch (err) {
        console.error('[vision.js] CES_DEV_UPLOADS.get failed:', err.message);
      }
    }
    if (!raw) {
      return {
        ok: false,
        fileId,
        error: `Uploaded file ${fileId} was not found — it may have expired (uploads are ` +
          `deleted after 5 minutes). Please attach it again.`,
      };
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { ok: false, fileId, error: `Uploaded file ${fileId} is corrupted. Please attach it again.` };
    }
    const name = typeof parsed?.name === 'string' && parsed.name ? parsed.name : 'attachment.txt';
    const content = typeof parsed?.content === 'string' ? parsed.content : '';
    return { ok: true, fileId, name, content };
  }));

  // Fail fast on the first bad id in ids[] order, deterministic regardless
  // of settle order. Returns before any deletes fire, same improvement as
  // chat.js: a sibling id's failure no longer deletes-then-discards a
  // successfully-read file's KV entry.
  const firstBad = settled.find((r) => !r.ok);
  if (firstBad) return { ok: false, error: firstBad.error };

  // Best-effort delete-after-read, concurrent, allSettled so one KV
  // hiccup can't fail the batch — same contract as the original per-file
  // try/catch.
  const deletions = await Promise.allSettled(
    settled.map((r) => env.CES_DEV_UPLOADS.delete(`devupload:${r.fileId}`))
  );
  deletions.forEach((d, i) => {
    if (d.status === 'rejected') {
      console.warn('[vision.js] CES_DEV_UPLOADS.delete (non-fatal):', settled[i].fileId, d.reason?.message);
    }
  });

  // Sequential, order-preserving budget pass — see chat.js's identical
  // comment for why this stays synchronous. NOTE: still no originalLength
  // field — this file's buildTextFilesBlock() uses the older generic
  // truncation notice, not chat.js's percentage-based one, so it doesn't
  // read that field (unchanged from the pre-v37 version).
  const files = [];
  let totalChars = 0;
  for (const r of settled) {
    let content = r.content;
    let truncated = false;
    const roomLeft = DEV_KV_MAX_TOTAL_CONTEXT_CHARS - totalChars;
    if (roomLeft <= 0) break;
    if (content.length > roomLeft) {
      content = content.slice(0, roomLeft);
      truncated = true;
    }
    totalChars += content.length;
    files.push({ name: r.name, content, truncated });
  }
  return { ok: true, files };
}

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

When this same message also carries a PDF document (labeled "Document:") and/or one or more attached \
text files (each wrapped "--- Attached file: NAME ---" ... "--- End of NAME ---"), treat every one of \
them as required material, not background for the image — a document or text file attached alongside \
a photo is often the more decisive source (full source code, a complete spec, a multi-page drawing set) \
and the image can just as easily be the secondary item. Address content from each attachment that's \
actually present; do not let the image become the default focus purely because it renders first. If the \
person's question doesn't point you at one specific attachment, cover all of them, briefly where needed, \
rather than answering from one and treating the rest as unread.

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
report.

If you're given internal context about which checks on a currently-open calculator form are passing \
or failing, use it to explain the ENGINEERING reason a check fails and what to change — never the \
software mechanism behind it. Never mention a control, label, or note identifier, a worksheet or cell \
reference, or a form, module, or file name, and never describe the internal update or command protocol \
these run on. Explain what is wrong and why, in the same engineering vocabulary a structural engineer \
would use discussing the calculation itself — never how the screen produces that text.`;

// ── Structured extraction (Footing Pro autofill) ─────────────────────────
// Deliberately a SEPARATE call from VISION_SYSTEM_PROMPT's conversational
// reply, not a trailing-JSON-line convention appended to it. Two reasons,
// both load-bearing:
//   1. responseMimeType:'application/json' + responseSchema makes Gemini
//      emit ONLY schema-conformant JSON for the entire turn (ai.google.dev
//      "Structured output" guide, current as of 2026-08) — it cannot also
//      stream the Arabic/English engineering explanation in that same
//      response. A prompt-only "put JSON on the last line" convention is
//      the documented fallback for when responseSchema ISN'T used, and
//      Google's own docs are explicit that this fallback is NOT guaranteed
//      to produce clean, parseable JSON — schema mode exists specifically
//      to replace it.
//   2. Even with schema mode, keep this prompt SMALL and dedicated rather
//      than reusing VISION_SYSTEM_PROMPT: a reported bug (Google AI
//      Developer Forum thread opened ~2026-07-29) has responseSchema + a
//      large, mostly-static system prompt on the gemini-3.x family
//      occasionally returning content belonging to a DIFFERENT prior
//      request. No confirmation this is fixed — a small, purpose-built
//      prompt is a different shape than the repro and is also just
//      cheaper/faster for a 6-field lookup. Treat the result as unverified
//      model output regardless (sanitizeExtracted below), same posture as
//      any other Gemini response, bug or not.
const FOOTING_EXTRACT_FIELDS = ['w', 'l', 'q', 'd', 'as_top', 'as_bot'];
// Fields that cannot legitimately be zero on a real footing — a 0 here
// means the model emitted a number where it should have emitted null.
// as_top/as_bot are excluded on purpose: zero top or zero bottom steel is
// a real design value (unreinforced footing, or no moment reversal).
const FOOTING_EXTRACT_NONZERO_FIELDS = new Set(['w', 'l', 'q', 'd']);
const FOOTING_EXTRACT_UNITS = ['mm', 'cm', 'm', 'in', 'ft'];
const FOOTING_EXTRACT_SYSTEM_PROMPT =
  'Extract isolated-footing design values visible in the image(s): plan width (w), ' +
  'plan length (l), applied load or allowable bearing pressure (q), effective depth ' +
  'or main bar diameter (d), top reinforcement area (as_top), bottom reinforcement ' +
  'area (as_bot), and the unit system the drawing itself uses (units). Read values ' +
  'exactly as labeled on the drawing; do not convert or unit-normalize them. If a ' +
  'value is not visible or not legible, return null for it — never guess or ' +
  'substitute a default, and never invent a unit system that is not shown.';
// propertyOrdering pins field order explicitly — Gemini's docs warn a
// responseSchema/prompt property-order mismatch can degrade output
// quality, and the REST default (alphabetical, required-first) would
// otherwise scramble this relative to the prompt's own w/l/q/d/... order.
const FOOTING_EXTRACT_SCHEMA = {
  type: 'object',
  properties: {
    ...Object.fromEntries(FOOTING_EXTRACT_FIELDS.map(f => [f, { type: 'number', nullable: true }])),
    units: { type: 'string', nullable: true, enum: FOOTING_EXTRACT_UNITS },
  },
  propertyOrdering: [...FOOTING_EXTRACT_FIELDS, 'units'],
  required: [...FOOTING_EXTRACT_FIELDS, 'units'],
};
const FOOTING_EXTRACT_TIMEOUT_MS   = 8_000;  // per attempt — small schema-locked lookup, not open-ended prose
const FOOTING_EXTRACT_OVERALL_CAP_MS = 12_000; // hard ceiling regardless of attempt count, see runFootingExtraction

function buildFootingExtractPayloadString(imageParts, mediaResolution) {
  return JSON.stringify({
    system_instruction: { parts: [{ text: FOOTING_EXTRACT_SYSTEM_PROMPT }] },
    contents: [{ role: 'user', parts: imageParts }],
    generationConfig: {
      responseMimeType: 'application/json',
      responseSchema: FOOTING_EXTRACT_SCHEMA,
      maxOutputTokens: 256, // six numbers + a unit string — generous headroom, still tiny
      thinkingConfig: { thinkingLevel: 'LOW' }, // structured lookup, not a judgment call
      mediaResolution,
    },
  });
}

// Never throws. Unknown/extra keys dropped. Non-finite/non-numeric values,
// and zero on a NONZERO_FIELDS entry, sanitize to null rather than passing
// through — a malformed or bug-triggered model response can never reach
// the calculator looking like a real reading.
function sanitizeExtractedFooting(parsed) {
  const out = {};
  for (const f of FOOTING_EXTRACT_FIELDS) {
    const v = parsed && typeof parsed === 'object' ? parsed[f] : undefined;
    const num = typeof v === 'number' && Number.isFinite(v) ? v : null;
    out[f] = num !== null && FOOTING_EXTRACT_NONZERO_FIELDS.has(f) && num === 0 ? null : num;
  }
  const u = parsed && typeof parsed === 'object' ? parsed.units : undefined;
  out.units = typeof u === 'string' && FOOTING_EXTRACT_UNITS.includes(u) ? u : null;
  return out;
}

// ── Structured extraction (generic — any form, any host application) ────
// Replaces an earlier, now-removed version of this block that hard-coded
// field names (I1, I2, ComboBox1, ComboBox2) for one specific form.
// Real finding that killed that approach: a SECOND form's own
// CesChat_GetFieldSchema uses the SAME key names (I1, I2) for completely
// different quantities ("Top RFT diameter"/"Bottom RFT diameter" there vs.
// "longitudinal"/"transverse reinforcement diameter" on the first form).
// Control-name keys are not stable even across two forms of the same host
// application, let alone across the ~30 separate applications this
// endpoint serves — no fixed per-field schema can generalize, and hand-
// maintaining one schema per form does not scale past a handful of forms.
//
// This block never encodes a field name. It reads whatever is labeled on
// screen, and — only when the caller supplies the CURRENTLY-OPEN form's
// own live CesChat_GetFieldSchema() text as formSchemaText — asks the
// model to match each reading against that specific form's OWN
// descriptions by MEANING, not by symbol or spelling. No form or
// application is named anywhere below; the same code path serves any of
// them unchanged. Kept as a separate function from Footing Pro's
// fixed-schema extraction above rather than replacing it: Footing Pro's
// path is presumed live/working and this file cannot be executed against
// a real Gemini key from where it was written, so leaving a working path
// untouched is the safer choice.
const GENERIC_EXTRACT_TIMEOUT_MS = 8_000;
const GENERIC_EXTRACT_OVERALL_CAP_MS = 12_000;
// Defensive cap on the caller-supplied schema text -- a real form schema
// (even Moment_design's, the largest seen so far at ~14 lines) is nowhere
// near this; the cap exists so a malformed or hostile request body can't
// inflate the outbound Gemini payload.
const GENERIC_EXTRACT_MAX_SCHEMA_CHARS = 4_000;

const GENERIC_EXTRACT_SCHEMA = {
  type: 'array',
  items: {
    type: 'object',
    properties: {
      label_on_screen: { type: 'string' },
      value: { type: 'string' },
      matched_field_key: { type: 'string', nullable: true },
      match_confidence: { type: 'string', nullable: true, enum: ['high', 'low'] },
    },
    required: ['label_on_screen', 'value', 'matched_field_key', 'match_confidence'],
  },
};

function buildGenericExtractSystemPrompt(liveSchemaText) {
  const colorRule =
    'These forms draw every live, user-editable input as a text box filled pink/beige (tan) \u2014 ' +
    'that fill color is the ONLY reliable signal that a value is a real input, not its position, ' +
    'not its symbol, not how similar it looks to one. A value that is NOT inside a pink/beige box \u2014 ' +
    'plain text on the diagram background, a value in a white/gray/disabled box, or a colored ' +
    '(often red) "actual", "computed", or result readout sitting right next to a real input, even ' +
    'using the exact same symbol \u2014 is a computed or informational value, never an input. Still ' +
    'report it (label and value), just never as a match (see below). If a box\u2019s fill color is not ' +
    'clearly visible in the image, treat it as NOT confirmed pink/beige rather than assuming it is. ' +
    'When a value sits on the same line as inline validation or comparison text (for example ' +
    '"30 > 20" or a value immediately followed by "Unsafe..."), report only the editable number ' +
    'itself as value \u2014 never concatenate the comparison/status text into it.';

  const schemaBlock = liveSchemaText
    ? 'The form currently open has these fields (key: description | current value):\n' +
      liveSchemaText + '\n' +
      'For each PINK/BEIGE-BOXED value you read, set matched_field_key to the single closest key ' +
      'above ONLY if its description clearly refers to the same real-world quantity as the label ' +
      'you read \u2014 compare meaning, not spelling or symbol (a screen label "\u03a6L actual" and a ' +
      'schema description "longitudinal reinforcement diameter" can be the same quantity; two ' +
      'fields both named "I1" on two different forms usually are NOT). A value that is not in a ' +
      'pink/beige box must always get matched_field_key null, with no exception, even if its label ' +
      'text closely resembles a key\u2019s description \u2014 color rules this out before meaning is even ' +
      'considered. Set match_confidence to "high" only when you are genuinely confident, "low" for ' +
      'a plausible-but-uncertain guess. Leave matched_field_key null whenever nothing above is a ' +
      'clear match \u2014 null is always the safe default; a wrong guess is worse than no guess.'
    : 'No form field schema was supplied for this request \u2014 leave matched_field_key and ' +
      'match_confidence null for every row, just report what is visible.';

  return 'Read every labeled numeric value, dropdown selection, or short text field visible in ' +
    'the image(s). Report each exactly as shown on screen \u2014 never convert units, never compute ' +
    'a derived value, never guess an illegible or ambiguous value (omit that row instead of ' +
    'inventing one).\n\n' + colorRule + '\n\n' + schemaBlock;
}


// Pulls the "- KEY:" token from the start of each schema line (the exact,
// consistent format CesChat_GetFieldSchema uses on every form seen so
// far). Generic on purpose: this reads whatever schema text the caller
// supplied, no form's key list is known in advance or hard-coded here.
function extractKnownKeysFromSchemaText(schemaText) {
  if (typeof schemaText !== 'string' || !schemaText) return [];
  const keys = [];
  for (const line of schemaText.split('\n')) {
    const m = /^-\s*([A-Za-z0-9_]+)\s*:/.exec(line);
    if (m) keys.push(m[1]);
  }
  return keys;
}

function buildGenericExtractPayloadString(imageParts, mediaResolution, liveSchemaText) {
  return JSON.stringify({
    system_instruction: { parts: [{ text: buildGenericExtractSystemPrompt(liveSchemaText) }] },
    contents: [{ role: 'user', parts: imageParts }],
    generationConfig: {
      responseMimeType: 'application/json',
      responseSchema: GENERIC_EXTRACT_SCHEMA,
      maxOutputTokens: 1024, // an array, not a fixed handful of fields -- a busy screen can carry 15-20+ labeled values
      thinkingConfig: { thinkingLevel: 'LOW' },
      mediaResolution,
    },
  });
}

// Never throws. Drops malformed rows outright rather than passing them
// through half-populated. matched_field_key sanitizes to null unless it is
// literally one of the keys THIS caller supplied for THIS request -- never
// trust the model's own copy of a key back without checking it against the
// real list -- same "never trust unchecked model output" posture as
// sanitizeExtractedFooting before it.
function sanitizeGenericExtraction(parsed, knownKeys) {
  if (!Array.isArray(parsed)) return [];
  return parsed
    .filter((row) => row && typeof row === 'object' && !Array.isArray(row))
    .map((row) => ({
      label: typeof row.label_on_screen === 'string' ? row.label_on_screen.trim() : '',
      value: typeof row.value === 'string' ? row.value.trim() : '',
      matchedFieldKey: (typeof row.matched_field_key === 'string' && knownKeys.includes(row.matched_field_key))
        ? row.matched_field_key : null,
      confidence: row.match_confidence === 'high' ? 'high' : (row.match_confidence === 'low' ? 'low' : null),
    }))
    .filter((row) => row.label && row.value);
}

function parseGenericExtractReply(reply, knownKeys) {
  if (typeof reply !== 'string' || !reply.trim()) return { ok: false, reason: 'EMPTY' };
  let text = reply.trim();
  const fenced = text.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  if (fenced) text = fenced[1].trim();
  let parsed;
  try { parsed = JSON.parse(text); }
  catch { return { ok: false, reason: 'BAD_JSON' }; }
  if (!Array.isArray(parsed)) return { ok: false, reason: 'NOT_AN_ARRAY' };
  return { ok: true, extracted: sanitizeGenericExtraction(parsed, knownKeys) };
}

async function runGenericExtraction(geminiPool, budget, imageParts, mediaResolution, liveSchemaText) {
  const knownKeys = extractKnownKeysFromSchemaText(liveSchemaText);
  const payloadString = buildGenericExtractPayloadString(imageParts, mediaResolution, liveSchemaText);
  async function attempt() {
    try {
      for (const { key } of geminiPool.slice(0, 2)) {
        if (budget.remaining() <= 0) return { status: 'budget_exhausted', extracted: null };
        const res = await callGeminiVisionOnce(key, GEMINI_MODEL_FALLBACK, payloadString, budget, GENERIC_EXTRACT_TIMEOUT_MS);
        if (res.ok) {
          const parsed = parseGenericExtractReply(res.reply, knownKeys);
          if (parsed.ok) return { status: 'ok', extracted: parsed.extracted };
          console.warn('[vision.js] generic extraction: schema-mode reply failed to parse:', parsed.reason);
          return { status: 'parse_failed', extracted: null };
        }
        if (res.errStatus === 'SUBREQUEST_BUDGET_EXHAUSTED') return { status: 'budget_exhausted', extracted: null };
      }
      return { status: 'all_attempts_failed', extracted: null };
    } catch (err) {
      console.warn('[vision.js] generic extraction: attempt() threw:', err?.message);
      return { status: 'error', extracted: null };
    }
  }
  return new Promise(resolve => {
    const t = setTimeout(() => resolve({ status: 'overall_cap_exceeded', extracted: null }), GENERIC_EXTRACT_OVERALL_CAP_MS);
    attempt().then(r => { clearTimeout(t); resolve(r); });
  });
}
// Note: no formatXForConfirmation helper here on purpose -- the previous
// version's equivalent hard-coded per-field human labels (exactly the
// pattern this whole rewrite removes). Building "here's what I read, want
// me to apply it" text from a generic {label, value, matchedFieldKey,
// confidence}[] array is a straight iteration the caller (VBA side or a
// follow-up conversational turn) can do directly from the label/value text
// itself -- nothing form-specific left to hard-code.

// ── Calculator-internals confidentiality (deterministic backstop) ────────
// VISION_SYSTEM_PROMPT above now carries the prompt-level rule; this is
// the backstop that runs regardless of whether the model followed it —
// same posture as chat.js's AI_DISCLOSURE_BLOCKLIST/sanitizeAiReply,
// scoped to VBA/UserForm-shaped identifiers instead of infra terms. Kept
// as a local copy rather than imported from chat.js, matching this file's
// existing policy on ALLOWED_ORIGINS/isArabicText above: an unverifiable
// cross-file import risks breaking the build outright. Known tradeoff:
// the two copies (here and in chat.js) can drift if one is updated and
// not the other -- worth collapsing into one shared module once a safe
// import path between these two Functions is confirmed in the real
// deployment; not attempted here for the same reason noted above.
const CALCULATOR_DISCLOSURE_BLOCKLIST_LITERALS = [
  // Bridge/infrastructure names: the SAME chatbot codebase (frmCESChat,
  // modVisionAPI, the CES_SET protocol) is reused across every host
  // application, so these stay as literals regardless of which app is
  // involved. Deliberately NOT listing any specific form/app name here
  // (an earlier version had 'check_depth.frm') -- '.frm'/'.bas'/'userform'
  // below already catch any form or app's file name generically; hand-
  // listing one app's form name doesn't scale to the other ~29.
  'frmceschat', 'modvisionapi', 'modchatapi', 'modvisionextractapply',
  'userform', '.frm', '.bas', 'ces_set', 'buttonregistry', 'ceschat_',
];
const CALCULATOR_DISCLOSURE_BLOCKLIST_PATTERNS = [
  /\bnote_\d+\b/i,
  /\blabel\d+\b/i,
  /\b(txt|cmd|btn|lbl|cmb|fra)[a-zA-Z][a-zA-Z0-9]{0,40}\b/i,
  /\bsheet\d+\s*\.\s*range\s*\(/i,
];
function containsCalculatorDisclosure(text) {
  const lower = text.toLowerCase();
  return CALCULATOR_DISCLOSURE_BLOCKLIST_LITERALS.some((t) => lower.includes(t))
      || CALCULATOR_DISCLOSURE_BLOCKLIST_PATTERNS.some((re) => re.test(text));
}
const CALCULATOR_SANITIZER_FALLBACK_AR =
  '\u0627\u0644\u0634\u0631\u062d \u062f\u0647 \u0628\u064a\u0631\u062c\u0639 \u0644\u062a\u0641\u0627\u0635\u064a\u0644 \u062f\u0627\u062e\u0644\u064a\u0629 \u0641\u064a \u0627\u0644\u0628\u0631\u0646\u0627\u0645\u062c\u060c \u062e\u0644\u064a\u0646\u064a \u0623\u0648\u0636\u062d\u0644\u0643 \u0627\u0644\u0633\u0628\u0628 \u0627\u0644\u0647\u0646\u062f\u0633\u064a \u0628\u062f\u0644 \u0643\u062f\u0647.';
const CALCULATOR_SANITIZER_FALLBACK_EN =
  "That explanation touches the program's internal workings \u2014 let me give you the engineering reason instead.";

// Streaming-safe holdback wrapper around vision.js's own relay(text)
// closure (see the delta-relay loop below) -- a post-hoc full-string check
// does NOT work here: relay() fires chunk-by-chunk DURING generation, so
// by the time a complete reply string existed to scan, every chunk would
// already be on the wire.
//
// Correctness argument: every relay() call immediately re-scans the FULL
// current `held` buffer (carried-over tail + new text) before any release
// decision, and a release only ever drops characters that leave at least
// CALC_SANITIZER_HOLDBACK_CHARS still buffered behind them. So any match
// up to that length is necessarily still fully inside `held` -- and
// therefore gets scanned -- at the moment its last character arrives,
// strictly before any of its own characters could have been released in
// an earlier call. This covers chunk-boundary splits (a match arriving as
// "no" then "te_7" across two calls) by the same argument: nothing is
// released until it has survived a full-buffer scan taken after
// CALC_SANITIZER_HOLDBACK_CHARS more characters arrived behind it.
// Verified against adversarial char-by-char and random chunking, not just
// reasoned about -- see test_streaming_sanitizer.js.
//
// Known, unavoidable limit of ANY real-time character-streaming filter:
// text already flushed to the client before a later chunk completes a
// match cannot be recalled. The holdback window only has to exceed the
// longest blocklist match (bounded at 44 chars by the capped Hungarian-
// prefix pattern above); it is not and cannot be a buffer of the whole
// reply.
const CALC_SANITIZER_HOLDBACK_CHARS = 64;

// Returns { relay, flush }. flush() MUST be called exactly once, after the
// last relay() call and before the SSE stream closes: it releases whatever
// is still sitting in the holdback buffer, after one final full-buffer
// scan (a match can be completed by a reply's very last characters).
// Skipping flush() does not create a leak risk, only silently drops up to
// CALC_SANITIZER_HOLDBACK_CHARS characters of legitimate trailing text.
function makeCalculatorSafeRelay(innerRelay) {
  let held = '';
  let tripped = false;
  function trip(flaggedText) {
    tripped = true;
    held = '';
    innerRelay(isArabicText(flaggedText) ? CALCULATOR_SANITIZER_FALLBACK_AR : CALCULATOR_SANITIZER_FALLBACK_EN);
  }
  return {
    relay(text) {
      if (tripped || !text) return;
      held += text;
      if (containsCalculatorDisclosure(held)) { trip(held); return; }
      if (held.length > CALC_SANITIZER_HOLDBACK_CHARS) {
        const releaseLen = held.length - CALC_SANITIZER_HOLDBACK_CHARS;
        innerRelay(held.slice(0, releaseLen));
        held = held.slice(releaseLen);
      }
    },
    flush() {
      if (tripped || !held) return;
      if (containsCalculatorDisclosure(held)) { trip(held); return; }
      innerRelay(held);
      held = '';
    },
  };
}

// Handles the well-formed case (bare JSON — schema mode should never emit
// a fence) and defensively strips one anyway per the bug note above.
function parseFootingExtractReply(reply) {
  if (typeof reply !== 'string' || !reply.trim()) return { ok: false, reason: 'EMPTY' };
  let text = reply.trim();
  const fenced = text.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  if (fenced) text = fenced[1].trim();
  let parsed;
  try { parsed = JSON.parse(text); }
  catch { return { ok: false, reason: 'BAD_JSON' }; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, reason: 'NOT_AN_OBJECT' };
  }
  return { ok: true, extracted: sanitizeExtractedFooting(parsed) };
}

// Best-effort side-channel: tries up to 2 keys from the SAME pool/budget
// the conversational call uses (sequential, not raced — this is enrichment,
// not the primary reply, so it doesn't warrant its own concurrent-race
// machinery). Bounded overall by FOOTING_EXTRACT_OVERALL_CAP_MS regardless
// of how the two attempts split that time, so a hung key can never push
// the terminal SSE event out by more than that ceiling. NEVER throws and
// NEVER returns a status that blocks or delays the conversational reply
// the caller already relayed — this function's result is only merged into
// the terminal `done` event, never the `delta` stream.
async function runFootingExtraction(geminiPool, budget, imageParts, mediaResolution) {
  const payloadString = buildFootingExtractPayloadString(imageParts, mediaResolution);
  async function attempt() {
    try {
      for (const { key } of geminiPool.slice(0, 2)) {
        if (budget.remaining() <= 0) return { status: 'budget_exhausted', extracted: null };
        const res = await callGeminiVisionOnce(key, GEMINI_MODEL_FALLBACK, payloadString, budget, FOOTING_EXTRACT_TIMEOUT_MS);
        if (res.ok) {
          const parsed = parseFootingExtractReply(res.reply);
          if (parsed.ok) return { status: 'ok', extracted: parsed.extracted };
          console.warn('[vision.js] footing extraction: schema-mode reply failed to parse:', parsed.reason);
          return { status: 'parse_failed', extracted: null };
        }
        if (res.errStatus === 'SUBREQUEST_BUDGET_EXHAUSTED') return { status: 'budget_exhausted', extracted: null };
        // otherwise fall through and try the next key (transient/HTTP/timeout failure)
      }
      return { status: 'all_attempts_failed', extracted: null };
    } catch (err) {
      // Defensive only — callGeminiVisionOnce/parseFootingExtractReply/
      // sanitizeExtractedFooting are all written to never throw, but this
      // function's caller (the Promise executor below) has no rejection
      // handler on attempt()'s result, so a stray throw here MUST be
      // caught locally rather than left to become an unhandled rejection.
      console.warn('[vision.js] footing extraction: attempt() threw:', err?.message);
      return { status: 'error', extracted: null };
    }
  }
  // resolve() is the only exit from this executor — attempt() can no
  // longer reject (see try/catch above), so this Promise itself can never
  // reject either; the caller can safely `await` it with no try/catch.
  return new Promise(resolve => {
    const t = setTimeout(() => resolve({ status: 'overall_cap_exceeded', extracted: null }), FOOTING_EXTRACT_OVERALL_CAP_MS);
    attempt().then(r => { clearTimeout(t); resolve(r); });
  });
}

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
async function callGeminiVisionOnce(apiKey, model, payloadString, budget, timeoutMs = PER_ATTEMPT_TIMEOUT_MS) {
  if (!budget.take()) {
    return { ok: false, httpStatus: 0, errStatus: 'SUBREQUEST_BUDGET_EXHAUSTED', errBody: '' };
  }

  let res;
  try {
    res = await fetchWithTimeout(
      `${GEMINI_API_URL(model)}?key=${apiKey}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payloadString },
      timeoutMs,
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

  // 5b-ii. Document (PDF) attachment — NEW, "Insert Text / PDF". Singular
  // (body.document, not an array): one engineering document per message.
  // Mutually exclusive with nothing — an image AND a document can both be
  // present in the same request; the parts-array builder below handles
  // that combination. See documentGuard.mjs for the full validation
  // (magic-byte sniff, byte-size cap, heuristic page-count soft-cap).
  let pdfDoc = null;
  if (body?.document && typeof body.document === 'object') {
    const docResult = validatePdfDocument(body.document, likelyArabic);
    if (!docResult.ok) {
      return json({ error: docResult.error }, 400, undefined, request);
    }
    pdfDoc = docResult;
  }

  // Requires at least one image OR one document — the endpoint's whole
  // purpose. Checked here, after both extraction blocks, rather than
  // right after rawImages like the pre-PDF version did, since a
  // document-only request is now a valid, non-empty request.
  if (rawImages.length === 0 && !pdfDoc) {
    return json({ error: buildFriendlyVisionError({ httpStatus: 400, errStatus: '' }, likelyArabic) }, 400, undefined, request);
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

  // 5d. Text file attachments ("Insert Text File") — NEW v3.0. Extracted
  //     AFTER detailReq (5c) is computed: wantsHighDetail() must run on the
  //     person's own words only, never on file content that could
  //     accidentally contain a matching keyword. Merged into a separate
  //     modelMessageText variable below, never into userMessage itself —
  //     userMessage is done being consumed after this point in the
  //     function (its last read was wantsHighDetail() above).
  const textFilesResult = extractTextFiles(body, likelyArabic);
  if (!textFilesResult.ok) {
    return json({ error: textFilesResult.error }, 400, undefined, request);
  }
  // [v36] KV-staged files — see resolveKvFiles() above. Combined into the
  // SAME buildTextFilesBlock() call below rather than a second block, so
  // the model sees one uniform "attached file" formatting regardless of
  // which path a file came in on.
  const kvFilesResult = await resolveKvFiles(body, env);
  if (!kvFilesResult.ok) {
    return json({ error: kvFilesResult.error }, 400, undefined, request);
  }
  const textFilesBlock = buildTextFilesBlock(textFilesResult.files.concat(kvFilesResult.files));
  const modelMessageText = userMessage + textFilesBlock;

  // 5e. Structured-extraction opt-in — NEW. Only footing_pro's "read from
  //     photo" autofill sends this; the general vision chat (this same
  //     endpoint, called from pc_suite and elsewhere) never sets it, so it
  //     never pays the extra subrequest/latency cost below. Closed allow-
  //     list on purpose — this is a route selector, not free text, so
  //     anything else is silently ignored rather than erroring.
  const extractMode = ['footing', 'form'].includes(body?.extract) ? body.extract : null;
  // Only meaningful when extractMode === 'form': the CURRENTLY-OPEN VBA
  // form's own live CesChat_GetFieldSchema() text, if the caller has one
  // to send (frmCESChat already fetches this same text for
  // BuildAugmentedMessage — this is the same string, not a new call).
  // Absent or malformed input degrades to '' rather than erroring: a
  // missing schema just means matched_field_key comes back null for
  // every row (see buildGenericExtractSystemPrompt), not a failed request.
  const formSchemaText =
    typeof body?.formSchema === 'string' ? body.formSchema.slice(0, GENERIC_EXTRACT_MAX_SCHEMA_CHARS) : '';

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
  // totalMediaCount includes the optional PDF alongside images — the
  // documented Gemini ordering rule (media-before-text at N=1, text-before-
  // media at N>1) is keyed off "how many media parts", not "how many
  // images", so a single lone PDF (images.length===0, pdfDoc set) must
  // still take the N=1 branch, and an image+PDF combo must take the N>1
  // branch exactly like two images would.
  const totalMediaCount = images.length + (pdfDoc ? 1 : 0);
  const imageParts = images.length === 0
    ? []
    : (totalMediaCount === 1
        ? [{ inline_data: { mime_type: images[0].mimeType, data: images[0].data } }]
        : images.flatMap((img, i) => [
            { text: `Image ${i + 1}:` },
            { inline_data: { mime_type: img.mimeType, data: img.data } },
          ]));
  const documentParts = pdfDoc
    ? (totalMediaCount === 1
        ? [{ inline_data: { mime_type: PDF_MIME_TYPE, data: pdfDoc.data } }]
        : [{ text: 'Document:' }, { inline_data: { mime_type: PDF_MIME_TYPE, data: pdfDoc.data } }])
    : [];
  const mediaParts = [...imageParts, ...documentParts];

  const parts = totalMediaCount <= 1
    ? [...mediaParts, { text: modelMessageText }]   // media before text — single-item best practice
    : [{ text: modelMessageText }, ...mediaParts];  // text before media — multi-item example pattern

  // [PATCH] callGeminiStreaming() takes contents/generationConfig as
  // separate parameters (see streamingProviders.mjs) rather than a single
  // pre-built JSON string, so it can serve both chat.js's and this file's
  // differently-shaped generationConfig without duplicating the retry/
  // timeout/SSE-parsing code. Values below are byte-for-byte what the old
  // payloadString sent — see the original inline comments (now attached
  // here) for the thinkingLevel/mediaResolution/omitted-temperature
  // rationale, unchanged.
  const visionContents = [{ role: 'user', parts }];
  const visionGenerationConfig = {
    maxOutputTokens: GEMINI_MAX_OUTPUT_TOKENS,
    // temperature/topP deliberately OMITTED (v2.4): Google's Gemini 3.x
    // migration guidance says both are "no longer recommended" for
    // gemini-3.5-flash / gemini-3.1-flash-lite and to remove them outright.
    //
    // thinkingConfig.thinkingLevel replaces thinkingBudget (v2.4) — sending
    // both in one request is a hard 400. 'LOW' (not 'MINIMAL'):
    // VISION_SYSTEM_PROMPT asks for a safety/code-compliance judgment call
    // on top of a plain description, which Google's own effort-level
    // guidance places in "analysis and writing tasks that require some
    // thinking," not pure fact retrieval.
    thinkingConfig : { thinkingLevel: 'LOW' },
    mediaResolution: MEDIA_RESOLUTION,
  };

  // ============================================================================
  // [PATCH — streaming rewrite] Same latency audit / fix applied to
  // functions/api/chat.js, adapted here: single provider (Gemini only, no
  // Groq/OpenRouter/Workers AI — vision has never had those tiers), so no
  // StreamingSanitizer is needed (vision.js has no confidentiality-blocklist
  // gate to begin with — verified: the only "BLOCKLIST" in this file is
  // Gemini's own SAFETY finishReason enum value, unrelated). Racing order
  // changed from the original's per-key (primary-then-fallback-same-key,
  // then next key) to per-model-tier-across-all-keys (primary raced across
  // every key first, fallback tier only if every primary attempt failed) —
  // matches chat.js's pattern exactly; a deliberate alignment, not an
  // oversight. X-CES-Vision-Source moves from a response header (impossible
  // to know before the stream starts) to a field on the terminal SSE event.
  // X-CES-Vision-Detail is known upfront and stays a real header.
  // ============================================================================
  const geminiKeysIndexed = buildGeminiKeyPool(env);
  const geminiPool = rotateStart(geminiKeysIndexed);
  const budget = makeFetchBudget(SUBREQUEST_BUDGET_VISION);
  const startTime = Date.now();

  // Fires immediately, alongside (not after) the conversational race below
  // — same geminiPool/budget, so it draws against the SAME
  // SUBREQUEST_BUDGET_VISION ceiling rather than a separate allowance.
  // Awaited once, right before the terminal SSE event is built (both the
  // early-error and normal-completion paths converge there) — never joins
  // the `delta` relay, so it cannot leak into what the user sees mid-
  // stream even in principle.
  // NOTE (PDF patch, unverified): both runFootingExtraction() and
  // runGenericExtraction() still read only imageParts. A document-only send
  // (pdfDoc set, images.length===0) with extract:'footing' OR extract:
  // 'form' will call whichever one with an EMPTY array — behavior in that
  // case depends on that function's own internals, not reviewed as part of
  // this patch. If either extraction feature is expected to also work from
  // an uploaded PDF (a site plan for 'footing', a scanned form for 'form'),
  // both functions need extending to accept documentParts too — separate,
  // scoped change, not made here.
  const extractionPromise =
    extractMode === 'footing' ? runFootingExtraction(geminiPool, budget, imageParts, MEDIA_RESOLUTION) :
    extractMode === 'form' ? runGenericExtraction(geminiPool, budget, imageParts, MEDIA_RESOLUTION, formSchemaText) :
    null;

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      let lastResult = { ok: false, httpStatus: 0, errStatus: 'NOT_ATTEMPTED', errBody: '' };
      let structuralFailure = false; // BLOCKED_*/400 -- every key/model would fail identically
      let streamClosed = false;
      let sentAnything = false;

      function closeStream() { if (!streamClosed) { streamClosed = true; controller.close(); } }
      // [PATCH] Manual `data: ...` framing replaced by SseChunkWriter (see
      // functions/_lib/resumableSse.mjs) — assigns the client-facing
      // chunkIndex/finalChunkIndex the frontend's resume handshake reads.
      // The streamClosed guard + enqueue try/catch that used to live
      // inside sendEvent() move into this write callback unchanged: they
      // guard this Worker invocation's own controller, which
      // SseChunkWriter is deliberately agnostic to (see its constructor's
      // `write` param doc) — not a loss of resilience, just relocated one
      // level out to where streamClosed/controller already live.
      const sseWriter = new SseChunkWriter((chunk) => {
        if (streamClosed) return;
        try { controller.enqueue(chunk); }
        catch { streamClosed = true; }
      }, encoder);
      // [CHAT-VISION] Every delta this endpoint ever relays now passes
      // through the streaming-safe holdback wrapper first -- applied
      // unconditionally rather than only when checkState-flavoured context
      // is detected, since the added latency is a fixed ~64 characters
      // (imperceptible) and unconditional is simpler and safer than trying
      // to infer per-request whether calculator context is present.
      // relay(text)'s own signature/behaviour is unchanged for every
      // existing call site below.
      const calculatorRelay = makeCalculatorSafeRelay((text) => {
        if (text) { sseWriter.writeDelta(text); sentAnything = true; }
      });
      function relay(text) { calculatorRelay.relay(text); }
      function deadlineOrBudgetExceeded() {
        if (budget.remaining() <= 0) return 'SUBREQUEST_BUDGET_EXHAUSTED';
        if (Date.now() - startTime > OVERALL_DEADLINE_MS) return 'OVERALL_DEADLINE_EXCEEDED';
        return null;
      }

      let winner = null; // { originalIndex, modelTag }
      for (const [model, modelTag] of [[GEMINI_MODEL_PRIMARY, 'primary'], [GEMINI_MODEL_FALLBACK, 'fallback']]) {
        if (winner || structuralFailure) break;
        const stopReason = deadlineOrBudgetExceeded();
        if (stopReason) {
          console.warn(`[vision.js] ${stopReason === 'OVERALL_DEADLINE_EXCEEDED' ? 'Overall deadline exceeded' : 'Subrequest budget exhausted'} — stopping before ${modelTag} tier.`);
          lastResult = { ok: false, httpStatus: 0, errStatus: stopReason, errBody: '' };
          break;
        }

        // [PATCH] BUG 1 FIX (ported from chat.js — same raceKeyPool
        // concurrency issue, same fix). relay() used to be passed straight
        // through as onDelta to every one of the RACE_CONCURRENCY keys
        // racing this tier; with no gate, any two of them mid-stream at the
        // same time would both call relay(), interleaving text from two
        // unrelated Gemini responses into the same SSE stream before
        // raceKeyPool ever resolved a winner. Reset per tier (fresh pool
        // race each iteration of the primary/fallback loop above).
        let committedCanceller = null;
        const { winner: tierWinner, lastResult: tierLastResult } = await raceKeyPool(
          geminiPool,
          async ({ key: gKey, originalIndex }, signal, cancelOthers) => {
            const keyTag = keyTagFor(originalIndex);
            const res = await callGeminiStreaming(gKey, model, visionContents, VISION_SYSTEM_PROMPT, visionGenerationConfig, budget, (text) => {
              if (committedCanceller === null) { committedCanceller = cancelOthers; cancelOthers(); }
              if (committedCanceller !== cancelOthers) return; // a losing racer's delta — never relayed
              relay(text);
            }, signal);
            if (!res.ok && res.errStatus !== 'SUBREQUEST_BUDGET_EXHAUSTED' && res.errStatus !== 'RACE_CANCELLED') {
              console.warn(`[vision.js] Gemini ${keyTag || 'key1-'}${model} failed:`, res.errStatus, res.httpStatus);
            }
            if ((res.errStatus || '').startsWith('BLOCKED_') || res.httpStatus === 400) {
              structuralFailure = true;
            }
            return { ...res, originalIndex, keyTag, modelTag };
          },
          {
            concurrency: RACE_CONCURRENCY,
            shouldStop: () => structuralFailure || !!deadlineOrBudgetExceeded(),
            onAttemptSettled: (_item, res) => { lastResult = res; },
          },
        );

        if (tierWinner) { winner = tierWinner; break; }
        if (tierLastResult) lastResult = tierLastResult;
      }

      // Single await point for both paths below — by the time the primary/
      // fallback loop above has finished, every delta the conversational
      // reply will ever produce has already been relayed (or the winner
      // failed outright), so waiting here adds latency only to the
      // terminal event, never to the visible token stream.
      const extractionResult =
        (extractMode === 'footing' || extractMode === 'form') ? await extractionPromise : null;

      // [CHAT-VISION] Release whatever's still sitting in the holdback
      // buffer, exactly once, after the last possible relay() call above
      // and before either writeDone() path below. Safe to call regardless
      // of which path follows (including the failure path) -- flush() is a
      // no-op if nothing was ever relayed.
      calculatorRelay.flush();

      if (!winner || !winner.ok) {
        if (!sentAnything) {
          const status =
            lastResult.httpStatus === 400 ? 400
            : (lastResult.errStatus || '').startsWith('BLOCKED_') ? 422
            : (lastResult.errStatus === 'RESOURCE_EXHAUSTED' || lastResult.errStatus === 'RATE_LIMIT_EXCEEDED') ? 429
            : (lastResult.httpStatus && lastResult.httpStatus !== 0) ? lastResult.httpStatus
            : 502;
          sseWriter.writeError(buildFriendlyVisionError(lastResult, likelyArabic), { status });
          sseWriter.writeDone({
            extracted: extractionResult?.extracted ?? undefined,
            extractStatus: extractionResult?.status ?? undefined,
          });
          closeStream();
          return;
        }
        // Committed-then-interrupted (see streamingProviders.mjs's commitment
        // note) — winner.ok is false but text already reached the client;
        // fall through and close cleanly rather than emitting a second,
        // contradictory error on top of a partial answer.
      }

      // [PATCH] BUG 4 FIX — same finishReason gap as chat.js had: without
      // this, an image analysis that hits MAX_TOKENS looks identical to one
      // that finished cleanly, and the frontend has no way to mark the
      // resulting history turn as truncated for a later "كمل".
      // 'length' removed from this check — vision.js only ever calls Gemini
      // (never Groq/OpenRouter), and Gemini's finishReason enum has no
      // 'length' value; that string only ever appears on the OpenAI-
      // compatible wire format chat.js's fallback tiers use. Keeping it
      // here was a harmless dead branch (visionFinishReason can never
      // equal it), but misleading — it implied a fallback tier that
      // doesn't exist on this endpoint.
      // `interrupted` was missing entirely: streamingProviders.mjs's
      // commitment semantics mark a connection dropped mid-stream AFTER
      // commitment as {interrupted:true} with no finishReason at all (see
      // runStream()'s catch block) — distinct from a clean MAX_TOKENS
      // cutoff, and previously had zero client-visible signal on this
      // endpoint even though chat.js has surfaced it since the earlier fix.
      const visionFinishReason = winner && winner.finishReason;
      const visionTruncated = visionFinishReason === 'MAX_TOKENS';
      sseWriter.writeDone({
        source: winner ? `gemini-${winner.keyTag}${winner.modelTag}` : undefined,
        detail: detailReq,
        finishReason: visionFinishReason,
        truncated: visionTruncated,
        interrupted: !!(winner && winner.interrupted),
        // undefined when extractMode wasn't requested — JSON.stringify
        // drops undefined keys, so a plain chat turn's done event is
        // byte-identical to today's, same as `source`'s existing pattern
        // above for a no-winner turn.
        extracted: extractionResult?.extracted ?? undefined,
        extractStatus: extractionResult?.status ?? undefined,
      });
      closeStream();
    },
  });

  return new Response(stream, {
    status: 200,
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-CES-Vision-Detail': detailReq,
      ...getCorsHeaders(request),
    },
  });
}

export async function onRequestOptions({ request }) {
  return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}
