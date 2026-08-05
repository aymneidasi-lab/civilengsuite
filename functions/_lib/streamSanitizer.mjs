// Streaming-safe re-implementation of chat.js's existing sanitizeAiReply()/
// stripSelfGeneratedDevBanner() gates. Both original functions are
// all-or-nothing: they inspect a fully-buffered reply and either pass it
// through unchanged or replace/trim it. Token streaming means the client
// receives bytes before the full reply exists, so a plain port is unsafe —
// this class holds back the minimum amount of trailing text needed to keep
// both gates' original detection guarantees, while still emitting the rest
// live. See the accompanying patch notes for the residual trade-off this
// does NOT eliminate (documented there, not restated here).
//
// Usage per request:
//   const sanitizer = new StreamingSanitizer({ isDeveloperMode, blocklist });
//   for each upstream delta:
//     const { emit, retracted } = sanitizer.push(delta);
//     if (emit) controller.enqueue(...);
//     if (retracted) { abortUpstream(); controller.enqueue(retractEvent); break; }
//   if stream ended without retraction:
//     const { emit, finalText } = sanitizer.finish();
export class StreamingSanitizer {
  // blocklist            -> chat.js's existing AI_DISCLOSURE_BLOCKLIST
  // bannerDevTerms       -> chat.js's existing BANNER_DEVMODE_TERMS
  // bannerConfirmTerms   -> chat.js's existing BANNER_CONFIRM_TERMS
  // Passed in rather than imported so this module has zero coupling to
  // chat.js's internals beyond these three already-existing arrays.
  constructor({ isDeveloperMode, blocklist = [], bannerDevTerms = [], bannerConfirmTerms = [] }) {
    this.isDeveloperMode = isDeveloperMode;
    this.blocklist = blocklist.map((t) => t.toLowerCase());
    this.maxTermLen = this.blocklist.reduce((m, t) => Math.max(m, t.length), 0);
    this.bannerDevTerms = bannerDevTerms.map((t) => t.toLowerCase());
    this.bannerConfirmTerms = bannerConfirmTerms.map((t) => t.toLowerCase());
    this.raw = '';          // everything received so far, unmodified
    this.emittedLen = 0;    // how much of `raw` has already been handed to the caller
    this.retracted = false;
    this.bannerDecided = this.isDeveloperMode ? false : true; // non-dev mode: no banner gate at all
    this.bannerSuppressUpTo = 0; // if the banner gate fires, chars [0, this) are dropped, not emitted
    // [FIX — see audit notes "streamSanitizer quadratic scan"] Bounded
    // scratch buffer used for blocklist scanning only. Always equal to
    // raw.slice(emittedLen) by construction (proven by induction: seeded
    // once from that exact slice, then only ever += a chunk and .slice()s
    // off its own front by the same amount emittedLen advances by) but
    // never re-derived FROM the full-length `raw` on every call, so each
    // push() after the first is O(chunk + holdback) instead of O(current
    // total reply length). null until the banner gate resolves and the
    // first post-gate call seeds it.
    this._tailBuf = null;
  }

  push(chunk) {
    if (this.retracted) return { emit: '', retracted: true };
    this.raw += chunk;

    if (!this.bannerDecided) {
      const decided = this._resolveBannerGate();
      if (!decided) return { emit: '', retracted: false }; // still buffering paragraph 1
    }

    if (this.isDeveloperMode) {
      // Dev mode has no disclosure-blocklist gate (matches the original:
      // sanitizeAiReply() returns immediately for isDeveloperMode).
      const emit = this.raw.slice(Math.max(this.emittedLen, this.bannerSuppressUpTo));
      this.emittedLen = this.raw.length;
      return { emit, retracted: false };
    }

    if (this._tailBuf === null) {
      // First call after the banner gate resolved. One-time catch-up,
      // bounded by the gate's own 220-char cap regardless of total reply
      // length, so this single full slice is cheap even though it isn't
      // "just the new chunk".
      this._tailBuf = this.raw.slice(Math.max(this.emittedLen, this.bannerSuppressUpTo));
    } else {
      this._tailBuf += chunk;
    }
    return this._advanceWithBlocklistHoldback();
  }

  finish() {
    if (this.retracted) return { emit: '', finalText: '' };
    if (!this.bannerDecided) this._resolveBannerGate(true); // force a decision on EOF
    let emit = '';
    if (this.isDeveloperMode) {
      emit = this.raw.slice(Math.max(this.emittedLen, this.bannerSuppressUpTo));
      this.emittedLen = this.raw.length;
    } else {
      // Flush whatever the holdback margin was still withholding — safe now
      // because no more text will ever arrive to complete a split term.
      emit = this.raw.slice(this.emittedLen);
      this.emittedLen = this.raw.length;
    }
    return { emit, finalText: this.raw.slice(this.bannerSuppressUpTo) };
  }

  // Mirrors stripSelfGeneratedDevBanner(): inspect ONLY the first paragraph
  // (text up to the first blank line), bail out unmodified once it exceeds
  // 220 chars with no blank line yet (matches the original's own
  // `firstPara.length > 220` early-return, so the gate window is identical).
  _resolveBannerGate(forced = false) {
    const blankIdx = this.raw.search(/\n\s*\n/);
    const firstPara = blankIdx === -1 ? this.raw : this.raw.slice(0, blankIdx);
    if (blankIdx === -1 && firstPara.length <= 220 && !forced) return false; // keep buffering

    if (firstPara.length > 220) { this.bannerDecided = true; return true; } // original: pass through

    const headLower = firstPara.toLowerCase();
    const hasDevTerm = this.bannerDevTerms.some((t) => headLower.includes(t));
    const hasConfirmTerm = this.bannerConfirmTerms.some((t) => headLower.includes(t));
    if (hasDevTerm && hasConfirmTerm) {
      this.bannerSuppressUpTo = blankIdx === -1 ? this.raw.length : blankIdx;
      this.emittedLen = this.bannerSuppressUpTo;
    }
    this.bannerDecided = true;
    return true;
  }

  _advanceWithBlocklistHoldback() {
    const holdback = this.maxTermLen > 0 ? this.maxTermLen - 1 : 0;
    const scannable = this._tailBuf.toLowerCase();
    for (const term of this.blocklist) {
      if (term && scannable.includes(term)) {
        this.retracted = true;
        return { emit: '', retracted: true };
      }
    }
    const emitLen = Math.max(0, this._tailBuf.length - holdback);
    const emit = this._tailBuf.slice(0, emitLen);
    this._tailBuf = this._tailBuf.slice(emitLen);
    this.emittedLen += emit.length;
    return { emit, retracted: false };
  }
}
