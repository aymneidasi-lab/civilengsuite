// Streaming-safe engineering-notation normalizer.
// Composed AFTER StreamingSanitizer in chat.js's relay() (see streamSanitizer.mjs
// for the confidentiality gate this runs downstream of): the confidentiality gate
// decides what may be sent at all; this only reshapes text already cleared to send.
//
// ── What changed vs the previous revision ──────────────────────────────────
// The old table mapped e.g. 'fcu' -> 'f' + U+1D9C + U+1D58 ("MODIFIER LETTER
// SMALL C/U"). Those codepoints are SUPERSCRIPT-shaped by Unicode's own
// naming (verified via unicodedata: category Lm, name "MODIFIER LETTER
// SMALL *" / "SUPERSCRIPT LATIN SMALL LETTER N" for every single entry in
// the old table) -- the exact fᶜᵘ-instead-of-f_cu defect this module exists
// to prevent was baked into its own answer key, deterministically, for
// every user, every time. Separately: true Unicode SUBSCRIPT letters only
// exist for a e h k l m n o p s t x (Superscripts and Subscripts block,
// U+2090-209C) -- c, u, y, g, r, v, w, d have NO subscript codepoint at
// all, so 'u' alone (Pu, Mu, Vu, qu, wu, fcu -- the single most common
// subscript in ultimate-strength / LRFD notation) could never have been
// rendered as a real subscript by character substitution no matter which
// codepoints were picked. Pure-Unicode substitution cannot be a complete
// fix for this domain; only markup can.
//
// This revision emits a canonical, escaping-safe PLAIN-TEXT marker instead
// -- base + '_{' + sub + '}', e.g. 'f_{cu}' -- and relies on the client
// (_cesRenderBotHtml in pc_suite_v47.html / footing_pro_v47.html) to turn
// that into a real <sub> element, using the exact same escape-then-
// whitelist-one-more-pattern shape already proven there for **bold**. The
// marker is chosen specifically because _, {, } all survive
// _cesEscapeHtml() untouched (that function only escapes & < > " '), so no
// XSS surface is reopened: the AI's raw text is fully escaped first, and
// only a fixed, safe <sub> wrapper is layered onto matched, already-escaped
// substrings afterward -- structurally identical to how **x** already
// becomes <strong> today.
//
// ── Four independent, streaming-safe passes (in this order) ────────────────
//  0. Stray Unicode pseudo-subscript letters the MODEL typed directly
//     (fᶜᵘ) -> canonical marker. Purely defensive: the prompt-level
//     instruction (buildSystemPrompt's NOTATION section) is the primary
//     defense against the model doing this at all; this is the safety net
//     for when it doesn't listen. Not gated on the curated table below --
//     see isKnownSymbol() comment for why that's the correct call here.
//  1. LaTeX-style subscript syntax the model used INSTEAD of the plain
//     form it was asked for -- f_{cu}, f_cu, $f_{cu}$ -- recognized against
//     the SAME curated symbol table as pass 2, so this never fires on
//     arbitrary code-like snake_case text. This is the actual fix for the
//     reported "AI writes LaTeX, old regex can't see fcu inside f_{cu}"
//     bug: no \b/lookaround tuning on a literal "fcu" pattern can ever
//     match that text, because the letters f-c-u are not contiguous in
//     "f_{cu}" for ANY boundary definition -- the underscore/braces have
//     to be parsed, not boundary-tuned around.
//  2. Bare ASCII shorthand (fcu, Pu, qall...) -> canonical marker. Same
//     word/pattern-boundary-guarded approach as the previous revision,
//     'As' still gets its own prose-collision guard (collides with the
//     English word "As"); no other trigger in the table is a standalone
//     English word, so no other trigger needs it.
//  3. Bare LaTeX macros with no braces/arguments (\times, \phi, ...) ->
//     plain Unicode. Unchanged from the previous revision.
// Plus the pre-existing bare '$'/'$$' stripping pass, unchanged in
// behavior and still running after all four replacement passes.
//
// All four passes are FIXED, FINITE-LENGTH-PER-TOKEN operations, so all
// four stay safe to holdback-buffer with a boundary-derived (not fixed-
// offset) cut point -- see findSafeCutIndex below. Anything requiring
// unbounded lookahead (\frac{a}{b} argument extraction, arbitrary nested
// LaTeX) is deliberately NOT attempted here -- the prompt-level instruction
// is the primary defense for those; this is a bounded, low-risk safety net,
// not a LaTeX parser.

export const ENGINEERING_SYMBOLS = {
  // key = base + subscript, concatenated (this IS the bare-ASCII surface
  // form pass 2 matches, and the previous revision's key set, unchanged).
  // base = key[0], subscript = key.slice(1) -- DERIVED below, not
  // hand-duplicated per entry, so there is exactly one place this table
  // can disagree with itself about what a symbol's parts are.
  fcu:  'concrete cube strength',
  fy:   'steel yield strength',
  fc:   'concrete cylinder strength',
  fr:   'modulus of rupture',
  As:   'steel area',
  Ac:   'concrete area',
  Ag:   'gross area',
  Av:   'shear-reinforcement area',
  Ast:  'total steel area',
  Pu:   'factored axial load',
  Pn:   'nominal axial capacity',
  Mu:   'factored moment',
  Mn:   'nominal moment',
  Mcr:  'cracking moment',
  Vu:   'factored shear',
  Vn:   'nominal shear',
  Vc:   'concrete shear capacity',
  Vs:   'stirrup shear capacity',
  bo:   'punching-shear perimeter',
  bw:   'web width',
  qu:   'ultimate bearing pressure',
  qall: 'allowable bearing pressure',
  qnet: 'net bearing pressure',
  wu:   'factored distributed load',
  wd:   'dead load, distributed',
  wl:   'live load, distributed',
  Ec:   'concrete modulus',
  Es:   'steel modulus',
  // 'ld' and 'ln' deliberately omitted: 'ln' collides with the natural-log
  // function name (earthquake-pro damping/decrement calcs use ln(x)); 'ld'
  // is low-frequency enough outside that collision family that the risk of
  // asymmetric treatment isn't worth it. Both remain covered by the
  // PROMPT-level compositional rule for the primary model; only the blind
  // pattern-matching safety net excludes them.
};

const BARE_LATEX_MACROS = {
  '\\times': 'x', '\\cdot': 'x',
  '\\leq': '\u2264', '\\geq': '\u2265', '\\pm': '\u00B1',
  '\\alpha': '\u03B1', '\\beta': '\u03B2', '\\gamma': '\u03B3', '\\delta': '\u03B4',
  '\\phi': '\u03C6', '\\rho': '\u03C1', '\\lambda': '\u03BB', '\\mu': '\u03BC',
  '\\sigma': '\u03C3', '\\tau': '\u03C4', '\\Delta': '\u0394',
};

// base -> Set of valid subscripts for that base. Derived once from
// ENGINEERING_SYMBOLS so passes 1 and 2 can never disagree about which
// symbols are "known."
const SUBS_BY_BASE = new Map();
for (const key of Object.keys(ENGINEERING_SYMBOLS)) {
  const base = key[0];
  const sub = key.slice(1);
  if (!SUBS_BY_BASE.has(base)) SUBS_BY_BASE.set(base, new Set());
  SUBS_BY_BASE.get(base).add(sub);
}

function canonicalMarker(base, sub) {
  return `${base}_{${sub}}`;
}

function isKnownSymbol(base, sub) {
  const subs = SUBS_BY_BASE.get(base);
  return !!subs && subs.has(sub);
}

// ─── Pass 2: bare ASCII shorthand ("fcu", "Pu", ...) ───────────────────────
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const allBareKeys = Object.keys(ENGINEERING_SYMBOLS).slice().sort((a, b) => b.length - a.length);
const bareWordKeys = allBareKeys.filter((k) => k !== 'As');
const bareWordPattern = bareWordKeys.map(escapeRe).join('|');
const BARE_SHORTHAND_RE = new RegExp(
  `\\bAs\\b(?!-)(?!\\s?[a-z])` +
  `|\\b(?:${bareWordPattern})\\b(?!-)`,
  'g',
);

function applyBareShorthand(text) {
  return text.replace(BARE_SHORTHAND_RE, (m) => canonicalMarker(m[0], m.slice(1)));
}

// ─── Pass 1: LaTeX-style subscript syntax (f_{cu}, f_cu) ───────────────────
// Matches ANY single-letter-base + underscore + short alnum run (braced or
// not) and looks the (base, sub) pair up against the curated table -- an
// unrecognized combination (an unrelated "x_test" in some snippet) is
// returned UNCHANGED, never guessed at via prefix-trimming. \b before the
// base keeps this from firing mid-identifier (e.g. the 'l' in
// "Pool_test" -- 'l' is preceded by 'o', a word character, so \b fails
// there and the match never starts).
const LATEX_SUBSCRIPT_RE = /\b([A-Za-z])_(?:\{([A-Za-z0-9]{1,8})\}|([A-Za-z0-9]{1,8})(?![A-Za-z0-9_]))/g;

function applyLatexSubscript(text) {
  return text.replace(LATEX_SUBSCRIPT_RE, (m, base, bracedSub, bareSub) => {
    const sub = bracedSub !== undefined ? bracedSub : bareSub;
    return isKnownSymbol(base, sub) ? canonicalMarker(base, sub) : m;
  });
}

// ─── Pass 0: stray Unicode pseudo-subscript letters typed by the model ─────
// Covers both the wrong (superscript-shaped "MODIFIER LETTER SMALL *") and
// the correct-but-inconsistent (true "LATIN SUBSCRIPT SMALL LETTER *")
// blocks, folding either back to ASCII so everything downstream funnels
// through ONE rendering path (<sub> via the client) instead of a mix of
// raw Unicode glyphs and HTML tags. Unlike passes 1/2, this does NOT gate
// on the curated table: a normal letter immediately followed by one of
// these specific 26 codepoints has essentially no legitimate reading in a
// structural-engineering chat widget other than "the model hand-formatted
// a subscript," so any run of them is folded, listed symbol or not --
// being permissive here is what makes it a safety net for symbols outside
// the curated 27 too (e.g. a model-invented "kᵥ" still gets fixed).
const PSEUDO_SUB_TO_ASCII = {
  '\u1D9C': 'c', '\u1D58': 'u', '\u02B8': 'y', '\u02B3': 'r', '\u02E2': 's',
  '\u1D4D': 'g', '\u1D5B': 'v', '\u1D57': 't', '\u207F': 'n', '\u1D52': 'o',
  '\u02B7': 'w', '\u1D43': 'a', '\u02E1': 'l', '\u1D49': 'e',
  '\u2090': 'a', '\u2091': 'e', '\u2092': 'o', '\u2093': 'x', '\u2094': 'e',
  '\u2095': 'h', '\u2096': 'k', '\u2097': 'l', '\u2098': 'm', '\u2099': 'n',
  '\u209A': 'p', '\u209B': 's', '\u209C': 't',
};
const PSEUDO_SUB_CHARS = Object.keys(PSEUDO_SUB_TO_ASCII).join('');
const PSEUDO_SUB_RUN_RE = new RegExp(`\\b([A-Za-z])([${PSEUDO_SUB_CHARS}]+)`, 'g');

function applyPseudoSubFold(text) {
  return text.replace(PSEUDO_SUB_RUN_RE, (m, base, run) => {
    const sub = [...run].map((ch) => PSEUDO_SUB_TO_ASCII[ch]).join('');
    return canonicalMarker(base, sub);
  });
}

// ─── Pass 3: bare LaTeX macros with no braces/arguments ────────────────────
const macroKeys = Object.keys(BARE_LATEX_MACROS).slice().sort((a, b) => b.length - a.length);
const macroPattern = macroKeys.map(escapeRe).join('|');
const MACRO_RE = new RegExp(`(?:${macroPattern})(?![a-zA-Z])`, 'g');

function applyBareMacros(text) {
  return text.replace(MACRO_RE, (m) => BARE_LATEX_MACROS[m] ?? m);
}

function applyReplacements(text) {
  // Order: fold stray Unicode first so it benefits from the same
  // downstream canonical-marker path; LaTeX-underscore forms next; bare
  // ASCII forms last; macros independent of all three. Each pass keys off
  // a DIFFERENT literal separator (pseudo-sub codepoints, underscore, or
  // a contiguous letter run with no separator at all), so no input text
  // can be matched by more than one pass and pass order carries no risk
  // of double-processing.
  let out = applyPseudoSubFold(text);
  out = applyLatexSubscript(out);
  out = applyBareShorthand(out);
  out = applyBareMacros(out);
  return out;
}

// Bare '$' / '$$' LaTeX delimiter stripping. Zero lookahead needed: a lone
// '$' is stripped unconditionally UNLESS immediately followed by a digit,
// which is the currency pattern this product actually uses in developer-
// mode cost discussions ($5/mo, $0.00 -- see chat.js changelog). No holdback
// margin required since the decision needs only the next character, which
// is already in-buffer by construction (see push() below).
function stripBareDollar(text) {
  return text.replace(/\$(?!\d)/g, '');
}

// A fixed trailing-length margin is NOT sufficient on its own: it can still
// land the cut *inside* a trigger token even within a single push() call
// (e.g. "\phi Mn test" sliced at length-6 splits "Mn" into "M" + "n test",
// and neither half matches \bMn\b). The correct safe-cut point is the last
// position in the buffer that is already KNOWN to terminate any in-progress
// token -- i.e. the last character that cannot itself be part of a trigger.
//
// Extended (vs the previous revision) to also treat '_' and '{' as
// token-forming: an unterminated "f_" or "f_{c" must NOT be cut before the
// closing '}' (braced form) or a genuine non-alnum terminator (bare form)
// arrives, or the split silently defeats pass 1 exactly the way a
// mid-token split already silently defeated the ASCII-only passes before
// this fix. '}' is deliberately NOT added to the token-forming set: it
// unambiguously CLOSES a braced group, so it is a valid, safe cut point
// like any other punctuation. The 26 pseudo-subscript codepoints pass 0
// folds are token-forming for the same reason letters are -- an "fᶜ" +
// "ᵘ" split across two push() calls must not let pass 0 see only the
// first half and silently drop the second.
const STATIC_TOKEN_CHAR_RE = /[A-Za-z\\$_{]/;
const PSEUDO_SUB_CHAR_SET = new Set(Object.keys(PSEUDO_SUB_TO_ASCII));
function isTokenChar(ch) {
  return STATIC_TOKEN_CHAR_RE.test(ch) || PSEUDO_SUB_CHAR_SET.has(ch);
}
const MAX_HOLDBACK = 64; // safety valve: bound worst-case latency if a
                         // pathological chunk has no separator at all

function findSafeCutIndex(buf) {
  for (let i = buf.length - 1; i >= 0; i--) {
    if (!isTokenChar(buf[i])) return i + 1;
  }
  return 0; // buffer is one unbroken run of token-forming chars so far
}

// 'As' needs up to 2 characters of trailing context to resolve its prose
// guard (an optional space plus one letter). findSafeCutIndex alone only
// guarantees the token itself is complete, not that enough *following*
// context is buffered to trust the guard's verdict -- e.g. safePart could
// end in exactly "...As " (a real token boundary right after the space),
// which lets the guard see "nothing follows" and wrongly treat that as
// "safe to convert", when a same-chunk-away letter would have blocked it.
// If the last 'As' in the candidate safePart doesn't yet have 2 characters
// of buffer past its end, pull the cut back to before that 'As' so it
// (and everything after it) waits for the next push. Unaffected by passes
// 0/1 -- this guards ONLY the bare-ASCII 'As' branch, which is unchanged
// from the previous revision.
const AS_RE = /\bAs\b/g;
function adjustCutForAsLookahead(buf, cut) {
  AS_RE.lastIndex = 0;
  let m, lastEnd = -1;
  const scan = buf.slice(0, cut);
  while ((m = AS_RE.exec(scan))) lastEnd = m.index + m[0].length;
  if (lastEnd !== -1 && cut - lastEnd < 2) return lastEnd - 2;
  return cut;
}

export class NotationNormalizer {
  constructor() {
    this._buf = '';
  }

  // Streaming-safe: emits everything up to the last confirmed token
  // boundary and holds back only a genuinely still-forming tail. Mirrors
  // StreamingSanitizer's holdback-margin / detect-and-retract shape, but
  // the cut point is boundary-derived rather than a fixed offset.
  push(deltaText) {
    this._buf += deltaText;
    let cut = findSafeCutIndex(this._buf);
    cut = adjustCutForAsLookahead(this._buf, cut);
    if (cut < 0) cut = 0;
    if (this._buf.length - cut > MAX_HOLDBACK) {
      cut = this._buf.length - MAX_HOLDBACK; // bounded worst case, see above
    }
    if (cut === 0) return { emit: '' };
    const safePart = this._buf.slice(0, cut);
    this._buf = this._buf.slice(cut);
    const emit = stripBareDollar(applyReplacements(safePart));
    return { emit };
  }

  finish() {
    const rest = this._buf;
    this._buf = '';
    const emit = stripBareDollar(applyReplacements(rest));
    return { emit };
  }
}
