// Corrected replica of the client-side table + inline-formatting + in-cell
// KaTeX pipeline, re-extracted verbatim (by line range, not brace-counting --
// the earlier extraction attempt mis-split on a regex literal's own { }
// pairs) from the ACTUAL footing_pro_v71-1-2-1.html this session was given.
// Supersedes ces_client_replica_harness-1.mjs, which predates both the
// in-cell KaTeX fix and the cell dir="auto"/isArabic() fix -- see the
// accompanying writeup for exactly what it was missing and why that made it
// give a false negative on the stress test's own Regression Checks table.
// window.katex is a real katex npm install, not a mock -- this exercises
// actual rendering output, not just whether the right span/class gets built.

import katex from 'katex';
globalThis.window = { katex };

export function isArabic(text) {
    return /[\u0600-\u06FF]/.test(text);
  }

  // ── Auto-resize textarea ──────────────────────────────────────────────────
  function resizeInput() {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 90) + 'px';
  }

  // ── Scroll messages to bottom ─────────────────────────────────────────────
  function scrollBottom() {
    msgs.scrollTop = msgs.scrollHeight;
  }

  // ── Wrap plain text for the chat "download reply" .txt file ────────────────
  // Plain-text viewers cannot be relied on to word-wrap: Notepad's Word Wrap
  // is a user toggle (often off), and a chat reply with no embedded line
  // breaks -- e.g. one long sentence -- downloads as a single line that runs
  // off the screen with no CRLF, wrap setting, or window width fixing it.
  // Hard-wrapping at a fixed column, the same way plain-text mail/README/
  // commit-message conventions do, makes the file readable in ANY viewer
  // regardless of its wrap setting. Existing breaks (bot replies can already
  // contain \n between points) are preserved as paragraph breaks; wrapping
  // only ever happens at an existing space, so no word -- and no multi-code-
  // unit character such as an emoji -- is ever split across two lines.
  function _cesWrapForDownload(text, maxLineLen) {
    maxLineLen = maxLineLen || 80;
    var paragraphs = String(text).split(/\r\n|\r|\n/);
    var outLines = [];
    for (var p = 0; p < paragraphs.length; p++) {
      var para = paragraphs[p];
      if (para === '') { outLines.push(''); continue; }
      var words = para.split(' ');
      var line = '';
      for (var w = 0; w < words.length; w++) {
        var word = words[w];
        var candidate = line === '' ? word : (line + ' ' + word);
        if (candidate.length > maxLineLen && line !== '') {
          outLines.push(line);
          line = word;
        } else {
          line = candidate;
        }
      }
      outLines.push(line);
    }
    // CRLF, not LF: bare \n renders as no break at all in Notepad builds
    // older than the 2018 Windows 10 update -- this app explicitly supports
    // Windows 7 SP1, so that install base is not a rounding error here.
    return outLines.join('\r\n');
  }

  // ── Bot-reply markdown -> safe HTML (bold-term highlighting) ───────────────
  // chat.js's SYSTEM_PROMPT now tells the model to wrap engineering codes/
  // terms/values in **double asterisks**; this is the ONLY markdown this
  // widget understands, and turns it into a highlighted <strong>. Escaping
  // runs FIRST, on the raw text, before the ** conversion -- appendBubble
  // used to set bub.textContent for every role (no HTML parsing at all, so
  // any character in a reply was always inert); moving bot bubbles to
  // innerHTML means anything in the text that looks like a tag has to be
  // neutralized before it reaches innerHTML, or this becomes a stored-DOM-
  // injection bug the day a reply happens to echo something like "<img>".
  // The ** conversion runs AFTER escaping and only ever introduces the one
  // <strong class="ces-hl"> tag this function writes itself, so nothing in
  // the source text can inject an attribute or a different tag.

export function _cesEscapeHtml(text) {
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }


export function _cesRenderBotHtml(text) {
    // .ces-bubble already has white-space:pre-wrap (see CSS) so a literal \n
    // in the escaped string renders as a real line break on its own --
    // converting to <br> here as well would double every line break.
    // Non-greedy + requires >=1 char between markers, so a stray unmatched
    // "**" (or an accidental "****") is left as literal, visible asterisks
    // instead of silently swallowing text or matching across a paragraph
    // break -- "." doesn't match "\n", so an unclosed ** can't eat the rest
    // of a multi-paragraph reply either.
    //
    // [PATCH] Subscript pass (engineering notation, e.g. fcu -> f_{cu} from
    // functions/_lib/notationNormalizer.mjs) runs on the ALREADY-escaped
    // string, same shape as the bold pass below -- _, {, } are never
    // touched by _cesEscapeHtml (it only escapes & < > " '), so this can
    // only ever match literal underscore-delimited marker text the server
    // sent, never anything that was originally a real "<" or ">" in the
    // AI's own output; no new HTML-injection surface. \b before the base
    // letter keeps it from firing mid-identifier (e.g. the "l" in
    // "Pool_test" -- "l" is preceded by "o", a word character, so \b fails
    // there). Braced form first (self-terminating on "}", unambiguous);
    // un-braced form second, with a trailing lookahead so a longer
    // identifier's tail can't get truncated into a false subscript.
    // [PATCH] Base class widened to the same 7 Greek letters
    // notationNormalizer.mjs's GREEK_SUBSCRIPT_BASES now covers (gamma,
    // lambda, psi, rho, beta, tau, epsilon -- keep these two tables in
    // sync if either changes). \b swapped for a negative lookbehind: \b is
    // defined only against ASCII \w ([A-Za-z0-9_]), so a Greek letter is
    // always \W to it and \b can never match immediately before one --
    // not after a space, not after another Greek letter, not at the start
    // of the string. Real reply evidence (ces-reply-2026-08-09T08-42-05.txt)
    // showed this exact gap: psi_t/psi_e/psi_s from a live ACI 318
    // development-length formula were left as literal underscores.
    // [PATCH — alpha_s] Base class gets an 8th Greek letter, \u03B1 (α),
    // matching the identical addition to notationNormalizer.mjs's
    // GREEK_SUBSCRIPT_BASES -- ACI 318's two-way shear equation uses
    // alpha_s as the column-location factor; keep these two tables in
    // sync, same as the note above.
    // [PATCH — f'_c prime notation] Base group gets an optional trailing
    // prime between the letter and the underscore -- the ACI f'_c
    // convention (concrete compressive strength), mirrors the identical,
    // identically-reasoned change to notationNormalizer.mjs's
    // LATEX_SUBSCRIPT_RE; see that file's comment for the full trace of
    // why the prime has to sit INSIDE the base group (it comes between
    // the base letter and the underscore, so a group requiring the
    // underscore immediately after the base letter could never match
    // "f'_c" at all).
    // This function runs on text _cesEscapeHtml has ALREADY processed
    // (see the call below), and that function escapes a straight
    // apostrophe into the literal 5-character string "&#39;" -- so
    // matching only a raw "'" here, as the first version of this patch
    // did, silently never fired on the single most common real case
    // (straight-quote f'_c is what the model actually writes; caught by
    // this function's own test suite, not just reasoned through). The
    // alternation below covers, in order: the escaped entity (the real
    // case), a raw quote (dead in this call path today since escaping
    // always runs first, kept only in case this pattern is ever reused
    // somewhere that doesn't pre-escape), and the typographic prime
    // U+2019 (never touched by _cesEscapeHtml -- it only escapes
    // & < > " ', not U+2019 -- so it survives to reach this regex as-is
    // either way).
    // [PATCH] Superscript pass, added alongside the subscript pair above
    // for the same reason (modifier-letter Unicode is banned in
    // notationNormalizer.mjs -- see that file's comments -- so ^-marker
    // fallback needs the same <sup> upgrade _-marker fallback already
    // gets). Base alternates digit-run vs single letter/Greek
    // (\d+|[A-Za-z...]) rather than reusing the subscript base class
    // alone: a multi-digit base is common for superscript (10^-3
    // scientific notation) but never needed for subscript.
    // [PATCH — bracketed-base exponent] Base alternation gets a third,
    // un-guarded branch: a bare ')' or ']'. Mirrors the identical fix in
    // notationNormalizer.mjs's LATEX_SUPERSCRIPT_RE -- see that file's
    // comment for the full rationale (Branson's equation's own
    // (M_cr / M_a)^3 is the motivating case: the server-side normalizer
    // already emits a literal "^3" straight through when its base can't
    // match, and until this line that literal "^3" also failed this
    // client-side upgrade pass, so it reached the bubble completely
    // unconverted). No `(?<![A-Za-z0-9_])` on the bracket branch, same
    // reasoning as the server-side fix: a closing bracket is preceded by
    // whatever the group wrapped, not by more of the "base" itself, so
    // the lookbehind would only ever wrongly block the common case
    // instead of guarding anything.
    // [PATCH — square root] No corresponding client-side pass needed:
    // '\sqrt' -> '√' (U+221A) is a plain, unconditional glyph
    // substitution in notationNormalizer.mjs's BARE_LATEX_MACROS, same
    // mechanism as '\times' -> '×'. Unlike subscript/superscript
    // LETTERS, √ has no coverage gap that needs an HTML-tag fallback
    // here -- the server-side conversion is always complete on its own.
    // [PATCH — chat bullet dots] BULLET_RE runs BEFORE the bold pass below,
    // not after -- deliberately, verified safe both ways but this order is
    // the more defensive one: converting the leading marker first means the
    // bold pass then only ever sees "**...**" spans on their own, no risk
    // of the bullet pass's own replacement HTML (the <span class="ces-
    // bullet">) accidentally sitting where a "**" scan could reach across
    // it. Up to 8 leading whitespace chars preserved in $1 (captures one
    // level of nested-list indentation without guessing at a nesting
    // scheme this widget doesn't otherwise support). Marker is "*" or "-"
    // followed by one-or-more spaces/tabs, with one remaining guard: (?!\*)
    // so a line starting "**Bold**" is left untouched for the bold pass
    // below (first "*" is followed by a second "*", lookahead fails, no
    // match) instead of being misread as a bulleted line. [FIX] Originally
    // consumed exactly one space -- real reply evidence
    // (ces-reply-2026-08-16T23-16-23.txt) showed the model formatting
    // bulleted definitions as "*   $f_{ctr}$: ..." (three spaces before
    // the variable), so only the first space was consumed and the other
    // two survived as literal leftover whitespace after the rendered dot,
    // widening the visible gap. Widened to [ \t]+ (all of it consumed,
    // exactly one space re-emitted in the replacement) -- same fix shape
    // already applied to ORDINAL_RE below for the same reason. Does not
    // reopen the decimal/negative-number collision this guard exists for:
    // the hyphen branch still requires AT LEAST one space, so "-5" (zero
    // spaces between the hyphen and the digit) never matches regardless of
    // how many are now tolerated on the matching side -- only "- 5" (a
    // hyphen-marked list item) does, exactly as before. Real bullet glyph
    // (U+2022) in the replacement, not the literal "*"/"-" the model
    // typed -- see .ces-bullet in the stylesheet for why (glyph shape, not
    // just color).
    //
    // [FIX — math-fragment truncation] This function is called PER PROSE
    // FRAGMENT by _cesRenderBotHtmlWithMath below, not once on the full
    // line: that caller splits raw text on every unescaped '$'/'$$' and
    // hands _cesRenderBotHtml only the slice BEFORE the next delimiter, so
    // a line like "* $M_{cr}$: ..." arrives here as the two-character
    // fragment "* " -- nothing else, the KaTeX span is rendered separately
    // by the caller and never concatenated back into this string. In this
    // domain almost every list item names a variable immediately after its
    // marker ("* $M_{cr}$: is the cracking moment", "1. $I_g$: ..."), so
    // this isn't an edge case, it's the overwhelmingly common shape of a
    // bulleted/numbered reply here. All three leading-marker patterns
    // below (BULLET_RE, ORDINAL_RE, HEADING_RE) originally required
    // confirming real non-whitespace content immediately after the marker
    // in the SAME regex call -- (?=\S) here, (?=\S) on ORDINAL_RE, (.+)
    // (one-or-more) on HEADING_RE -- as a guard against styling a truly
    // bare, dangling marker. That guard is unfixable within a single
    // fragment: the fragment legitimately ends right after the marker
    // whenever math follows, so "confirm something comes next" can never
    // succeed no matter how the whitespace is written, which is why the
    // earlier spacing-only fix to ORDINAL_RE (below) did not fully resolve
    // this -- it fixed a real, separate, narrower bug (exact-one-space
    // requirement) but not this structural one. Removed here instead:
    // BULLET_RE and ORDINAL_RE no longer require anything after the
    // marker+space; HEADING_RE's capture group changed from (.+) to (.*)
    // so it matches (and still strips the hash run) even when the fragment
    // ends right there, at the cost of the heading text itself only being
    // wrapped in .ces-heading up to wherever the fragment happens to end --
    // acceptable, since headers are already a defense-in-depth case, not
    // an observed one, per HEADING_RE's own comment below. Trade-off
    // accepted for all three: a genuinely bare "* " with nothing anywhere
    // on the full raw line (not just this fragment) now renders as an
    // orphaned styled dot instead of plain text -- rare, cosmetic, and
    // strictly preferable to the marker silently staying unstyled on
    // nearly every math-adjacent list item in the app, which is what
    // shipped instead until this fix.
    // [PATCH — ordinal list numbers] ORDINAL_RE. Same leading-marker-first
    // ordering rationale as BULLET_RE above (runs before the bold pass so
    // "**" scanning never has to reason about this pass's own inserted
    // markup) and the same up-to-8-leading-space indentation allowance.
    // Requires the digit run, then ".", then one or more spaces/tabs.
    // [FIX] Originally required exactly one space -- production evidence
    // (a live reply formatting "1.  المستطيل" with two spaces after the
    // period) showed that assumption was wrong: nothing in chat.js's
    // system prompt constrains ordinal-list spacing the way it does bold
    // markers. Widened to [ \t]+; this alone does NOT reopen the decimal-
    // collision risk the single-space version guarded against -- "3.5"
    // still never matches, because there is no whitespace at all between
    // "." and "5", and [ \t]+ requires at least one. Digit run capped at 3
    // (\d{1,3}) -- chat replies don't produce 4-digit list items, and
    // capping avoids an unbounded match reasoning about "1000. " as a
    // marker. Unlike BULLET_RE, the matched text is kept, not replaced
    // with a synthesized glyph -- the model's own number is real
    // information (list position), so it's wrapped, not discarded (see
    // .ces-num in the stylesheet).
    //
    // [PATCH — ATX headings] HEADING_RE. chat.js's system prompt tells the
    // model not to emit these in live replies (defense-in-depth, not a fix
    // for an observed bug -- see the .ces-heading CSS comment for the full
    // rationale, incl. why saved session history is the real exposure).
    // 1-6 "#" then required whitespace (CommonMark ATX syntax) keeps this
    // from ever firing on the engineering "#8 rebar" convention, which is
    // always written tight against the digit with no space -- verified
    // against that exact case, not assumed. Already used [ \t]+ (one or
    // more), not the single-space mistake ORDINAL_RE above had to be fixed
    // for. Capture is greedy to end of line ("." doesn't match "\n", same
    // non-cross-paragraph safety BULLET_RE's own comment explains for its
    // trailing content) but now (.*) not (.+) -- see the math-fragment fix
    // above for why. Only the hash run is discarded; whatever heading text
    // is present in this fragment is kept and wrapped, same "don't throw
    // away real content" principle as ORDINAL_RE above.
    // [FIX — bold/italic moved out of this function] **bold** and *italic*
    // used to be converted right here, same as the other passes above. Moved
    // to a raw-text pre-pass in _cesRenderBotHtmlWithMath instead: this
    // function only ever sees one $-delimited FRAGMENT of a reply (see the
    // math-fragment comment on BULLET_RE above for why), so a bold/italic
    // pair with math sitting between its open and close delimiter --
    // "**Cracking Moment ($M_{cr}$):**" -- had its open in one fragment and
    // its close in another, and neither fragment alone ever had a complete
    // pair to match. Real reply evidence (ces-reply-2026-08-17T05-29-*.txt)
    // showed exactly this: every bolded step label that named its variable
    // inline left literal, unconverted "**" on both sides. Fixed at the
    // source in _cesRenderBotHtmlWithMath instead of patched here.
    return _cesEscapeHtml(text)
      .replace(/^([ \t]{0,8})[*\-](?!\*)[ \t]+/gm, '$1<span class="ces-bullet">\u2022</span> ')
      .replace(/^([ \t]{0,8})(\d{1,3}\.)[ \t]+/gm, '$1<span class="ces-num">$2</span> ')
      .replace(/^([ \t]{0,3})#{1,6}[ \t]+(.*)$/gm, '$1<strong class="ces-heading">$2</strong>')
      .replace(/(?<![A-Za-z0-9_])([A-Za-z\u03B1\u03B2\u03B3\u03B5\u03BB\u03C1\u03C4\u03C8](?:&#39;|'|\u2019)?)_\{([A-Za-z0-9]{1,8})\}/g, '$1<sub>$2</sub>')
      .replace(/(?<![A-Za-z0-9_])([A-Za-z\u03B1\u03B2\u03B3\u03B5\u03BB\u03C1\u03C4\u03C8](?:&#39;|'|\u2019)?)_([A-Za-z0-9]{1,8})(?![A-Za-z0-9_])/g, '$1<sub>$2</sub>')
      .replace(/((?<![A-Za-z0-9_])\d+|(?<![A-Za-z0-9_])[A-Za-z\u03B1\u03B2\u03B3\u03B5\u03BB\u03C1\u03C4\u03C8]|[)\]])\^\{([A-Za-z0-9+\-=()]{1,8})\}/g, '$1<sup>$2</sup>')
      .replace(/((?<![A-Za-z0-9_])\d+|(?<![A-Za-z0-9_])[A-Za-z\u03B1\u03B2\u03B3\u03B5\u03BB\u03C1\u03C4\u03C8]|[)\]])\^([A-Za-z0-9+\-]{1,3})(?![A-Za-z0-9])/g, '$1<sup>$2</sup>');
  }

  // ── [PATCH — KaTeX] Lazy-loaded math rendering ──────────────────────────
  // Self-hosted (/vendor/katex/), NOT eager-preloaded in <head>: most site
  // visitors never open the chat, and most opened chats never contain math
  // (chat.js's NOTATION rule -- buildSystemPrompt -- is what makes the
  // model emit $...$/$$...$$ at all), so the ~165KB (JS+CSS+fonts,
  // brotli-equivalent) is fetched at most once per session, the first
  // time accumulated bot text actually contains a '$', and cached by the
  // browser for the rest of it (see the repo's _headers file for the
  // matching long-lived cache-control on /vendor/katex/*). Idempotent and
  // safe to call every render pass; after the first call it's a
  // resolved-promise fast path with no new DOM writes.
  var _cesKatexLoadPromise = null;
  function _cesEnsureKatexLoaded() {
    if (_cesKatexLoadPromise) return _cesKatexLoadPromise;
    _cesKatexLoadPromise = new Promise(function (resolve, reject) {
      if (window.katex) { resolve(window.katex); return; }
      // [[path]].js's CSP is nonce + 'strict-dynamic' on script-src, which
      // *should* trust a script inserted by already-nonced running code
      // regardless of whether the new element itself carries a nonce --
      // that's the entire point of strict-dynamic. Stamping it explicitly
      // anyway rather than relying on that alone: document.currentScript
      // is only valid for strictly synchronous execution and this can be
      // reached from an async rAF/promise callback where it's already
      // null, so fall back to any nonced <script> still in the DOM --
      // per spec, nonce-hiding clears the ATTRIBUTE after parse but the
      // element's .nonce IDL PROPERTY keeps returning the real value for
      // exactly this legitimate same-page use; getAttribute('nonce')
      // would silently give '' here instead. style-src 'self' already
      // permits the stylesheet link with no nonce at all, but setting it
      // there too costs nothing if that policy ever tightens later.
      var nonceEl = document.currentScript || document.querySelector('script[nonce]');
      var nonce = nonceEl ? nonceEl.nonce : '';
      var link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = '/vendor/katex/katex.min.css';
      if (nonce) link.setAttribute('nonce', nonce);
      document.head.appendChild(link);
      var script = document.createElement('script');
      script.src = '/vendor/katex/katex.min.js';
      if (nonce) script.nonce = nonce; // IDL property, not setAttribute -- see comment above
      script.onload = function () { resolve(window.katex); };
      script.onerror = function () {
        _cesKatexLoadPromise = null; // allow a retry on a later render pass
        reject(new Error('KaTeX script failed to load'));
      };
      document.head.appendChild(script);
    });
    return _cesKatexLoadPromise;
  }

  // Memoizes rendered HTML by exact LaTeX source (+ display/inline mode).
  // flushStream (below) re-renders the WHOLE accumulated buffer every
  // animation frame -- without this, every equation that finished
  // typesetting several frames ago would be re-run through
  // katex.renderToString on every subsequent frame for the rest of that
  // reply, for no reason (its source text hasn't changed). Capped and
  // FIFO-evicted; generous enough that a normal session never hits the
  // cap, small enough that a pathological one can't grow unbounded.

  var _cesKatexCache = new Map();
  var _CES_KATEX_CACHE_MAX = 500;

export function _cesRenderKatexSpan(tex, displayMode) {
    var key = (displayMode ? 'D:' : 'I:') + tex;
    var cached = _cesKatexCache.get(key);
    if (cached !== undefined) return cached;
    var html;
    try {
      html = window.katex.renderToString(tex, {
        throwOnError: false, // never blank the whole reply over one bad equation
        trust: false,        // explicit, not just relying on the default: never allow
                              // \includegraphics/\href/\htmlData -- CVE-2024-28245 and
                              // CVE-2025-23207 both lived behind trust:true on exactly
                              // those commands, and this renders LLM-originated text
                              // (untrusted input) by construction
        strict: 'warn',
        displayMode: displayMode,
      });
    } catch (e) {
      // Last-resort net for whatever still throws synchronously despite
      // throwOnError:false (trust:false already blocks the two CVE
      // classes above; this is defense-in-depth, not the primary guard).
      html = '<span class="ces-katex-pending">' +
        _cesEscapeHtml(displayMode ? '$$' + tex + '$$' : '$' + tex + '$') + '</span>';
    }
    if (_cesKatexCache.size >= _CES_KATEX_CACHE_MAX) {
      _cesKatexCache.delete(_cesKatexCache.keys().next().value); // evict oldest
    }
    _cesKatexCache.set(key, html);
    return html;
  }

  // Finds the next unescaped occurrence of `delim` in `text` from `from`
  // -- mirrors functions/_lib/notationNormalizer.mjs's findUnescapedDelim
  // exactly (same escaping convention: a single preceding backslash means
  // "literal $, not a delimiter"), so server and client agree on where a
  // math span starts and ends.

export function _cesFindUnescapedDelim(text, delim, from) {
    var i = from;
    for (;;) {
      var idx = text.indexOf(delim, i);
      if (idx === -1) return -1;
      if (text[idx - 1] !== '\\') return idx;
      i = idx + 1;
    }
  }

  // Splits RAW (pre-escape) text on $$...$$ / $...$ boundaries first, then
  // escapes+converts each PROSE segment through the existing
  // _cesRenderBotHtml pipeline unchanged (leading markers, legacy sub/sup
  // marker upgrade for old saved-history text), and renders each MATH
  // segment straight from its raw LaTeX source via KaTeX. Splitting before
  // escaping is required, not stylistic: _cesEscapeHtml would mangle the
  // backslashes/braces that ARE the LaTeX syntax, and running the legacy
  // sub/sup regex passes on real LaTeX would corrupt it the same way it
  // would server-side (see notationNormalizer.mjs's file header for the
  // exact mechanism -- same bug, same fix, both ends of the pipe now agree
  // on where math starts and ends before touching it).
  //
  // '$$' is checked before a lone '$' at every position (matches KaTeX
  // auto-render's own default delimiter order, and notationNormalizer.mjs
  // server-side). A span still open at the end of `text` -- its closing
  // delimiter hasn't streamed in yet -- is shown as an escaped,
  // monospaced placeholder; flushStream's unchanged per-frame full-buffer
  // re-render picks it back up as real typeset math automatically once
  // the close arrives, no separate "upgrade a partial equation in place"
  // path needed here.
  //
  // [FIX — bold/italic across a math boundary] **bold** and *italic* are
  // PAIRED delimiters (open...close), unlike the leading markers above
  // (bullet/ordinal/heading), which only ever need to recognize a single
  // character at a line's start. The loop below fragments raw text at
  // every unescaped '$', then escapes+converts each fragment independently
  // -- so when the model writes "**Cracking Moment ($M_{cr}$):**", the
  // open "**" lands in one fragment and the close "**" lands in a LATER
  // fragment, on the far side of the math span; neither fragment, taken
  // alone, ever contains a complete pair, so the per-fragment bold regex
  // that used to live in _cesRenderBotHtml could never match either half,
  // and both were left as literal, visible asterisks. Confirmed against
  // real replies (ces-reply-2026-08-17T05-29-*.txt): every bolded step
  // label that named its own variable inline hit this.
  //
  // Fixed by finding complete **bold**/*italic* PAIRS on the untouched raw
  // text, before the loop below ever runs, and marking their boundaries
  // with Private Use Area sentinel characters (U+E000-U+E003) instead of
  // the literal asterisks. A sentinel is not '$', '&', '<', '>', '"', or
  // "'", so it passes through the loop's delimiter search, _cesEscapeHtml,
  // and every other regex in _cesRenderBotHtml completely inertly -- to
  // everything downstream it's just an ordinary character riding along
  // inside whatever fragment it ends up in, on either side of an embedded
  // math span. Only once the whole reply is fully assembled (escaped,
  // math-typeset, leading markers converted) do the sentinels get swapped
  // for real <strong>/<em> tags, as the very last step -- at that point
  // they're guaranteed to still be correctly paired and in the right
  // order, since nothing in between ever touched them.
  //
  // Bold is matched first, specifically because ** is two of the same
  // character italic's own single-'*' delimiter uses: consuming every real
  // bold pair into sentinels before the italic regex ever runs means that
  // regex never has to reason about which '*' already belongs to a '**'
  // pair -- by the time it runs, those are gone, replaced by sentinels,
  // not asterisks. The italic regex separately requires the opening '*'
  // NOT be followed by whitespace and the closing '*' NOT be preceded by
  // whitespace -- standard markdown's own disambiguator, and exactly what
  // keeps it from ever mistaking a "* " bullet marker (marker, then a
  // required space) for an italic-open (never a space right after).
  // Both stay non-greedy and both refuse to cross a line break, same
  // "don't eat a whole multi-paragraph reply" reasoning BULLET_RE's own
  // comment gives -- unpaired/malformed markers (a stray trailing "**",
  // "****" with nothing between) still fall through untouched, same as
  // before this fix; that was never the failure mode here.
  // ── [PATCH — tables] Raw-text pre-pass: GFM pipe-table blocks (header row +
  // "|---|---|" delimiter row + >=1 body row) extracted from the FULL raw
  // buffer, same sentinel-placeholder technique the **bold**/*italic* pass
  // two lines below already uses and for the identical reason -- a table
  // spans multiple lines and (per-fragment) $-splitting below would never
  // see a whole table at once. Detection requires the delimiter row to be
  // its own dedicated GFM syntax (only "-", ":", "|", spaces/tabs) with
  // >=2 columns on BOTH the header and delimiter row before anything is
  // touched -- a stray "---" divider or a single "|" in prose (a shell
  // pipe, "A|B" shorthand) never has a second row matching that exact
  // shape immediately after it, so neither is mistaken for a table. Cell
  // HTML is built HERE, immediately, from the raw (unescaped) source --
  // _cesTableCellHtml is the only place table content is ever concatenated
  // into an HTML string, and it always routes through _cesEscapeHtml first
  // (via _cesRenderBotHtml), same as every other bot-text path in this
  // file; nothing here ever trusts a literal "<" or ">" from the model.
  // [SUPERSEDED — see the "[FIX — $...$/$$...$$ inside cells]" comment on
  // _cesTableCellHtml below] This used to say $...$ math support inside
  // cells was deliberately scoped out because "a cell can't itself contain
  // the raw newline the $-split loop's surrounding prose relies on" --
  // that reasoning didn't actually hold up: the loop just scans
  // characters, newlines included, and a cell's content (already
  // newline-free by construction, split from one physical text line
  // before _cesTableCellHtml ever runs) is if anything a cleaner input for
  // it than general prose is. Real screenshot/reply evidence
  // (ces-reply-2026-08-19T09-4*) showed what "degrades to plain escaped
  // text" actually meant in practice was worse than either a clean render
  // or flat text: the old pass-through called _cesRenderBotHtml directly
  // with no $-awareness, so "$q_{all} = \frac{Q_s}{A_{footing}}$" left the
  // '$'/'\frac{}{}' raw while the subscript regex still fired on the
  // q_{all}/Q_s/A_{footing} tokens sitting inside it -- a hybrid neither
  // reading as source nor as a formula.

  var TABLE_DELIM_ROW_RE = /^[ \t]{0,3}\|?[ \t]*:?-{2,}:?[ \t]*(\|[ \t]*:?-{2,}:?[ \t]*)*\|?[ \t]*$/;

export function _cesSplitTableRow(line) {
    var s = line.replace(/^[ \t]{0,3}/, '');
    if (s.charAt(0) === '|') s = s.slice(1);
    if (s.length && s.charAt(s.length - 1) === '|' && s.charAt(s.length - 2) !== '\\') s = s.slice(0, -1);
    var cells = [];
    var cur = '';
    for (var i = 0; i < s.length; i++) {
      if (s[i] === '\\' && s[i + 1] === '|') { cur += '|'; i++; continue; }
      if (s[i] === '|') { cells.push(cur); cur = ''; continue; }
      cur += s[i];
    }
    cells.push(cur);
    return cells.map(function (c) { return c.trim(); });
  }

  // Cell content is resolved to FINAL html right here (own bold/italic pass,
  // own escaping) rather than left as sentinels for the caller's end-of-
  // function swap -- once a table block is extracted it's opaque to the rest
  // of the pipeline (spliced back in as one placeholder token), so it has to
  // be fully self-contained before that happens.
  // [FIX — <br> inside a cell] Real reply evidence (ces-reply-2026-08-17T09-
  // 05-34.txt) showed the model writing a literal "<br>" inside a cell to
  // force a line break in a two-part value ("$$I_e = I_g$$ <br> *(note)*"),
  // despite the system prompt telling it not to (chat.js's TABLES rule was
  // tightened separately to stop this at the source). Belt-and-suspenders:
  // this pass recognizes that ONE specific, fixed, harmless string --
  // never any other tag, never with attributes -- and swaps it for a
  // sentinel BEFORE escaping runs, same mechanism as the bold/italic pass
  // right below it, so it survives to become a real, hardcoded <br> with
  // no model-controlled content ever reaching innerHTML through this path.
  // Without this, the literal text "<br>" (escaped to "&lt;br&gt;") showed
  // up as visible clutter in the middle of the cell instead of a break.
  // [FIX — $...$/$$...$$ inside cells] Mirrors _cesRenderBotHtmlWithMath's
  // own scan loop exactly (same '$'-not-preceded-by-'\' open check, same
  // _cesFindUnescapedDelim close search, same window.katex-not-loaded-yet
  // "pending" fallback), just scoped to one cell's already-isolated string
  // instead of the whole reply buffer -- and reuses _cesRenderKatexSpan
  // rather than a second copy of its cache/trust:false/strict:'warn'
  // settings. An unclosed '$' within a cell falls through to the same
  // "render as an ordinary character" fallback the prose loop uses; that's
  // correct for a genuine stray '$' AND for a row still mid-stream (a row
  // is only ever swept into a table once its own line has fully arrived --
  // see the body-row loop in _cesExtractTables below -- so this is the
  // same streaming-boundary case the prose loop already handles, not a
  // second one).

export function _cesTableCellHtml(raw) {
    var t = String(raw)
      .replace(/<br\s*\/?>/gi, '\uE004')
      .replace(/\*\*([^\n|]+?)\*\*/g, '\uE000$1\uE001')
      .replace(/\*(?!\s)([^\n|*]+?)(?<!\s)\*/g, '\uE002$1\uE003');
    var out = '';
    var i = 0;
    while (i < t.length) {
      if (t[i] === '$' && t[i - 1] !== '\\') {
        var isDisplay = t[i + 1] === '$';
        var delim = isDisplay ? '$$' : '$';
        var close = _cesFindUnescapedDelim(t, delim, i + delim.length);
        if (close !== -1) {
          var tex = t.slice(i + delim.length, close);
          var cls = isDisplay ? 'ces-katex-block' : 'ces-katex-inline';
          out += window.katex
            ? ('<span class="' + cls + ' ces-katex-cell" dir="ltr">' + _cesRenderKatexSpan(tex, isDisplay) + '</span>')
            : ('<span class="ces-katex-pending" dir="ltr">' + _cesEscapeHtml(delim + tex + delim) + '</span>');
          i = close + delim.length;
          continue;
        }
        // No close within this cell -- ordinary character, same as prose.
      }
      var next = t.indexOf('$', i + 1);
      if (next === -1) next = t.length;
      out += _cesRenderBotHtml(t.slice(i, next));
      i = next;
    }
    return out
      .replace(/\uE000/g, '<strong class="ces-hl">').replace(/\uE001/g, '</strong>')
      .replace(/\uE002/g, '<em class="ces-em">').replace(/\uE003/g, '</em>')
      .replace(/\uE004/g, '<br>');
  }


export function _cesExtractTables(text) {
    var lines = text.split('\n');
    var tables = [];
    var i = 0;
    while (i < lines.length) {
      var header = lines[i];
      var delim = lines[i + 1];
      if (header !== undefined && delim !== undefined &&
          header.indexOf('|') !== -1 && TABLE_DELIM_ROW_RE.test(delim)) {
        var headerCells = _cesSplitTableRow(header);
        var delimCells = _cesSplitTableRow(delim);
        if (headerCells.length >= 2 && delimCells.length >= 2) {
          var aligns = delimCells.map(function (c) {
            var left = c.charAt(0) === ':';
            var right = c.charAt(c.length - 1) === ':';
            if (left && right) return 'center';
            if (right) return 'right';
            if (left) return 'left';
            return '';
          });
          var bodyRows = [];
          var j = i + 2;
          while (j < lines.length && lines[j].indexOf('|') !== -1 && lines[j].trim() !== '') {
            bodyRows.push(_cesSplitTableRow(lines[j]));
            j++;
          }
          // [FIX — dir on a pure-digit/symbol cell] dir="auto" resolves a
          // cell’s direction from its own first STRONG character (L/R/AL);
          // digits, "$", commas, spaces, and backslash-commands are all WEAK
          // or NEUTRAL, not strong. A cell like "$12, 16, 20, 25, 32$" (a
          // rebar-diameter list) or "$1200 \text{ kN}$" has no strong
          // character in it at all -- when auto finds none, it falls back to
          // the INHERITED direction, which for an Arabic reply is the
          // ambient dir="rtl" on .ces-bubble, and the comma/space-separated
          // list still visually reorders exactly like the un-fixed case did.
          // Real reply evidence (ces-reply-2026-08-17T09-15-09.txt /
          // ...T09-16-15.txt) showed exactly this: diameter lists and
          // value+unit pairs reversed even with auto in place. Fix: decide
          // direction from content instead of leaning on auto's fallback --
          // isArabic() (defined above, same test the rest of this file
          // already uses for bubble-level dir) on the RAW cell text, before
          // any HTML conversion. Arabic present -> dir="auto" (mixed
          // Arabic+number content resolves correctly on its own, same as
          // before). No Arabic at all -> force dir="ltr" outright, so a
          // pure-technical cell never has a direction to fall back to in
          // the first place.
          var thead = '<tr>' + headerCells.map(function (c, k) {
            var a = aligns[k] ? ' style="text-align:' + aligns[k] + '"' : '';
            var d = isArabic(c) ? 'auto' : 'ltr';
            return '<th dir="' + d + '"' + a + '>' + _cesTableCellHtml(c) + '</th>';
          }).join('') + '</tr>';
          var tbody = bodyRows.map(function (row) {
            return '<tr>' + headerCells.map(function (_unused, k) {
              var a = aligns[k] ? ' style="text-align:' + aligns[k] + '"' : '';
              var cell = k < row.length ? row[k] : '';
              var d = isArabic(cell) ? 'auto' : 'ltr';
              return '<td dir="' + d + '"' + a + '>' + _cesTableCellHtml(cell) + '</td>';
            }).join('') + '</tr>';
          }).join('');
          tables.push(
            '<div class="dynamic-table-container">' +
              '<div class="dynamic-table-toolbar">' +
                '<svg class="dynamic-table-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M3 15h18M9 3v18M15 3v18"/></svg>' +
                '<div class="dynamic-table-actions">' +
                  '<button type="button" class="dynamic-table-btn" data-action="copy" title="Copy table / نسخ الجدول" aria-label="Copy table">' +
                    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="1.5"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>' +
                  '</button>' +
                  '<button type="button" class="dynamic-table-btn" data-action="csv" title="Download CSV / تنزيل CSV" aria-label="Download table as CSV">' +
                    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12m0 0l-4-4m4 4l4-4"/><path d="M5 19h14"/></svg>' +
                  '</button>' +
                '</div>' +
              '</div>' +
              '<div class="dynamic-table-scroll"><table class="dynamic-custom-table">' +
              '<thead>' + thead + '</thead><tbody>' + tbody + '</tbody></table></div>' +
            '</div>'
          );
          lines.splice(i, j - i, '\uE010' + (tables.length - 1) + '\uE011');
          i++;
          continue;
        }
      }
      i++;
    }
    return { text: lines.join('\n'), tables: tables };
  }
