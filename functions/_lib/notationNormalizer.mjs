// Streaming-safe engineering-notation normalizer.
// Same holdback-margin / detect-and-retract shape as StreamingSanitizer
// (see streamSanitizer.mjs), composed AFTER it in chat.js's relay():
// the confidentiality gate decides what may be sent at all; this only
// reshapes text that has already been cleared for sending.
//
// FOUR correction passes, all pattern-boundary guarded, in this order:
//  0. LaTeX subscript SYNTAX -> normalized form. Handles Base_{Sub} and
//     bare Base_Sub (single trailing char, real LaTeX grammar) BEFORE the
//     flat-abbreviation pass below, because "fcu" is not a contiguous
//     substring of "f_{cu}" -- no amount of \b vs (?<![A-Za-z]) tuning on
//     a flat "fcu" trigger can ever match text that already contains a
//     literal underscore/brace splitting the letters apart. This pass
//     closes that gap directly by parsing the LaTeX construct itself.
//     Base may be a single Latin letter, a single Greek letter, or one of
//     BARE_LATEX_MACROS' Greek macro spellings (\gamma_c) -- see the block
//     directly above LATEX_SUBSCRIPT_RE for why \b cannot be reused for
//     the Greek case and what replaces it.
//  1. ASCII engineering shorthand -> Unicode subscript (fcu -> f + true
//     subscript c+u where available, plain "f_cu" fallback where not --
//     see SUBSCRIPT_LETTER_MAP: Unicode has NO subscript codepoint for
//     b/c/d/f/g/q/w/y/z, so fcu/fy/Ac/Asc/Ag/Mcr/Vc/bw/wd/Ec can never be
//     rendered as pure-Unicode subscript; superscript "modifier letter"
//     codepoints exist for those letters, which is what the PREVIOUS
//     version of this table used by mistake -- that is the exact fᶜᵘ/fʸ
//     bug this rewrite fixes, not a regex issue).
//  2. Bare LaTeX macros with no braces/arguments -> plain Unicode
//     (\times -> x, \phi -> \u03c6, etc.)
//  3. (folded into pass 0's regex, not a separate scan) Greek macro name
//     directly followed by a subscript (\gamma_c) -- same drift BARE_
//     LATEX_MACROS exists to catch for the no-subscript case, just as
//     likely (arguably more likely, \gamma_c being the canonical LaTeX
//     spelling of a partial-safety-factor symbol) once a subscript is
//     attached, so it gets the same safety net rather than being left as
//     a gap that only happens to close for the bare-macro case.
// All passes are FIXED, FINITE-LENGTH-BOUNDED, so all are safe to
// holdback-buffer with a character-class-derived margin. Anything
// requiring unbounded lookahead (\frac{a}{b} argument extraction,
// nested braces) is deliberately NOT attempted here -- the prompt-level
// instruction (NOTATION_FORMATTING_RULE in chat.js) is the primary
// defense for those; this is a bounded, low-risk safety net, not a
// LaTeX parser.

// Unicode "Superscripts and Subscripts" block (U+2080-209C) plus the
// Phonetic Extensions additions (i/r/u/v) and U+2C7C (j). This is the
// COMPLETE set of Latin lowercase letters with a true Unicode subscript
// codepoint -- 17 of 26. b, c, d, f, g, q, w, y, z have none; do not add
// entries for them here, there is nothing to add.
const SUBSCRIPT_LETTER_MAP = {
  a: '\u2090', e: '\u2091', h: '\u2095', i: '\u1D62', j: '\u2C7C',
  k: '\u2096', l: '\u2097', m: '\u2098', n: '\u2099', o: '\u2092',
  p: '\u209A', r: '\u1D63', s: '\u209B', t: '\u209C', u: '\u1D64',
  v: '\u1D65', x: '\u2093',
};

// Returns the true-Unicode-subscript rendering of `sub`, or null if any
// character in it has no subscript codepoint (caller then falls back to
// a plain underscore -- never to a superscript substitute; superscript
// reads as an exponent/power in an engineering context, which is a
// worse, actively misleading error, not a neutral-looking compromise).
function toSubscriptForm(sub) {
  let out = '';
  for (const ch of sub) {
    const sc = SUBSCRIPT_LETTER_MAP[ch];
    if (!sc) return null;
    out += sc;
  }
  return out;
}

function subscriptOrFallback(base, sub) {
  const sc = toSubscriptForm(sub);
  return sc ? base + sc : `${base}_${sub}`;
}

// [trigger, base, subscript] -- the OUTPUT string is now GENERATED via
// subscriptOrFallback/SUBSCRIPT_LETTER_MAP instead of hand-transcribed
// Unicode escapes. Hand-transcription is exactly how the previous table
// silently drifted into the wrong Unicode block (modifier-letter
// superscripts) for every single entry -- generating it from a 17-letter
// lookup table makes that class of error structurally impossible to
// reintroduce, and keeps this table and the LaTeX-syntax pass below
// (which calls the same two helpers) permanently in agreement.
// 'Asc' added -- present in the ECP 203 column formula (compression
// steel area) and in the bug report's own trigger list, but absent from
// the table entirely in the previous version.
const ENGINEERING_NOTATION_ENTRIES = [
  ['fcu', 'f', 'cu'], ['fy', 'f', 'y'], ['fc', 'f', 'c'], ['fr', 'f', 'r'],
  ['As', 'A', 's'], ['Ac', 'A', 'c'], ['Ag', 'A', 'g'], ['Av', 'A', 'v'],
  ['Ast', 'A', 'st'], ['Asc', 'A', 'sc'],
  ['Pu', 'P', 'u'], ['Pn', 'P', 'n'],
  ['Mu', 'M', 'u'], ['Mn', 'M', 'n'], ['Mcr', 'M', 'cr'],
  ['Vu', 'V', 'u'], ['Vn', 'V', 'n'], ['Vc', 'V', 'c'], ['Vs', 'V', 's'],
  ['bo', 'b', 'o'], ['bw', 'b', 'w'],
  ['qu', 'q', 'u'], ['qall', 'q', 'all'], ['qnet', 'q', 'net'],
  ['wu', 'w', 'u'], ['wd', 'w', 'd'], ['wl', 'w', 'l'],
  ['Ec', 'E', 'c'], ['Es', 'E', 's'],
  // 'ld' and 'ln' deliberately omitted: 'ln' collides with the natural-log
  // function name (earthquake-pro damping/decrement calcs use ln(x)); 'ld'
  // is low-frequency enough outside that collision family that the risk of
  // asymmetric treatment isn't worth it. Both remain covered by the
  // PROMPT-level compositional rule for the primary model; only the blind
  // pattern-matching safety net excludes them.
];

export const ENGINEERING_NOTATION_MAP = Object.fromEntries(
  ENGINEERING_NOTATION_ENTRIES.map(([trigger, base, sub]) => [trigger, subscriptOrFallback(base, sub)]),
);

const BARE_LATEX_MACROS = {
  '\\times': 'x', '\\cdot': 'x',
  '\\leq': '\u2264', '\\geq': '\u2265', '\\pm': '\u00B1',
  '\\alpha': '\u03B1', '\\beta': '\u03B2', '\\gamma': '\u03B3', '\\delta': '\u03B4',
  '\\phi': '\u03C6', '\\rho': '\u03C1', '\\lambda': '\u03BB', '\\mu': '\u03BC',
  '\\sigma': '\u03C3', '\\tau': '\u03C4', '\\Delta': '\u0394',
};

// Escapes a string for literal use as a regex ALTERNATION branch (outside
// any character class -- backslash, braces, etc. all need escaping here).
// Moved above LATEX_SUBSCRIPT_RE -- previously declared only where
// COMBINED_RE needed it, further down -- because the Greek-macro
// alternative below now needs the identical escaping at construction
// time, and a second, differently-scoped copy is exactly the kind of
// hand-duplication this file's own ENGINEERING_NOTATION_MAP comment above
// already warns is how tables drift out of agreement.
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Separate, narrower escape for use INSIDE a character class ([...]),
// where the only characters requiring escaping are ']', '\', '^' (if
// first) and '-' (if not first/last) -- escapeRe's broader set is
// unnecessary here and would double-escape safe characters like '.' or
// '(' if reused as-is.
const escapeClassChars = (s) => s.replace(/[\]\\^-]/g, '\\$&');

// Greek base letters this product's engineering vocabulary actually uses
// (partial safety factors gamma_c/gamma_s, capacity-reduction phi, etc.)
// -- derived from BARE_LATEX_MACROS' own values rather than hand-
// duplicated, so any Greek macro added to that table above becomes a
// valid subscript Base here automatically. Filtered to the Greek/Coptic
// Unicode block (U+0370-03FF) specifically so the table's non-letter
// values ('x' for \times/\cdot, \leq/\geq/\pm's operator glyphs) are
// excluded -- those were never candidates for a subscript Base.
const GREEK_RANGE_RE = /[\u0370-\u03FF]/;
const GREEK_BASE_CHARS = [...new Set(Object.values(BARE_LATEX_MACROS))]
  .filter((ch) => GREEK_RANGE_RE.test(ch))
  .join('');
// The OTHER form the same LaTeX-habit drift takes: the macro spelling
// with a subscript glued directly on (\gamma_c) instead of the literal
// character (\gamma_c only differs from plain "\gamma" -- which
// BARE_LATEX_MACROS/Pass 2 already catches -- by having "_c" attached).
// Longest-first alternation for the same reason sortedTriggers below is:
// no macro name here is currently a prefix of another, but sorting makes
// that a structural guarantee instead of an accident of table order if
// the table grows.
const GREEK_MACRO_NAMES = Object.keys(BARE_LATEX_MACROS)
  .filter((k) => GREEK_RANGE_RE.test(BARE_LATEX_MACROS[k]))
  .sort((a, b) => b.length - a.length);
const GREEK_MACRO_PATTERN = GREEK_MACRO_NAMES.map(escapeRe).join('|');

// ── Pass 0: LaTeX subscript SYNTAX ──────────────────────────────────────
// Base_{Sub} (braced, up to 8 subscript letters) or bare Base_Sub (1-3
// trailing letters, capped -- NOT real LaTeX grammar, which only ever binds
// a single bare token; widened deliberately, see below). Base is restricted
// to a single Latin or Greek letter (or one Greek macro spelling, see
// GREEK_MACRO_PATTERN above) -- matching every base symbol actually used in
// this domain (f, A, P, M, V, b, q, w, E, plus gamma/phi/etc.) -- this is
// also what keeps the pattern from firing inside multi-letter identifiers
// like DEVELOPER_PASSWORD or RACE_CONCURRENCY.
//
// \b is NOT used for the single-letter alternative (this is the fix for
// the Greek-base bug): \b is defined against ASCII \w ([A-Za-z0-9_]) only
// -- a Greek letter is neither in \w nor does adjacency to one produce a
// \B-vs-\b transition, so "\b" followed by a Greek letter can never match
// at start-of-string, after a space, or after punctuation/markdown --
// i.e. never, in any realistic position a Greek base actually occurs.
// Widening only the character class while leaving \b in place (the fix as
// first proposed) verifiably changes nothing; \b is the actual failure,
// not the class. The negative lookbehind below replaces it with a
// Unicode-correct equivalent: reject any position preceded by a Latin
// letter, digit, underscore, OR Greek letter, independent of \w's
// ASCII-only notion of "word character". This preserves the exact same
// protection against mid-identifier firing (DEVELOPER_PASSWORD, Greek
// run "\u03b1\u03b3_c") that \b gave the Latin-only case, and extends it
// to Greek on both sides of the comparison.
//
// The Greek-macro alternative needs no left-guard of its own, for the
// same reason COMBINED_RE's macroPattern branch further below needs none
// on its left: a backslash is never itself a valid identifier character,
// so there is no "mid-identifier" case for it to be adjacent to. Its
// right-guard, (?![A-Za-z]), is the same maximal-munch guard COMBINED_RE
// already uses for macro names generally (stops "\gamma" claiming a match
// inside an unrelated, longer macro-like word such as "\gammaX").
//
// Bare-form cap is 1-3, NOT 1: the prompt-level instruction (chat.js's
// NOTATION rule) explicitly teaches the model bare "q_all" / "f_cu" as the
// SIMPLEST, preferred form -- multi-letter subscripts with no braces --
// which real LaTeX's own single-token bare-subscript grammar would not
// actually support (real LaTeX "q_all" only subscripts the "a"). This
// module intentionally does not implement real LaTeX grammar; it implements
// THIS product's plain-underscore convention. 3 is the exact longest
// subscript any table entry below uses ('all', 'net') -- capping there
// (not leaving it unbounded) is what keeps "n_items" from being misread as
// n + subscript("ite") + "ms": (?![A-Za-z]) rejects every length from 3
// down to 1 in turn (a letter follows each candidate cut), so the whole
// bare alternative fails to match at all, same outcome as before widening.
// Braced form stays capped separately at 8: '{' immediately after '_' is
// essentially never a real identifier, so it can safely stay more
// permissive than the ambiguous bare form.
const GREEK_CLASS = escapeClassChars(GREEK_BASE_CHARS);
const NOT_PRECEDING_BASE_RE = `[A-Za-z0-9_${GREEK_CLASS}]`;
const LATEX_SUBSCRIPT_RE = new RegExp(
  `(?:(?<!${NOT_PRECEDING_BASE_RE})([A-Za-z${GREEK_CLASS}])` +
    (GREEK_MACRO_PATTERN ? `|(${GREEK_MACRO_PATTERN})(?![A-Za-z])` : '') +
  `)_(?:\\{([A-Za-z]{1,8})\\}|([A-Za-z]{1,3})(?![A-Za-z]))`,
  'g',
);

function convertLatexSubscripts(text) {
  return text.replace(LATEX_SUBSCRIPT_RE, (_m, charBase, macroBase, braced, bare) => {
    const base = charBase || BARE_LATEX_MACROS[macroBase];
    const sub = braced || bare;
    return subscriptOrFallback(base, sub);
  });
}

const ALL_TRIGGERS = [...Object.keys(ENGINEERING_NOTATION_MAP), ...Object.keys(BARE_LATEX_MACROS)];
const MAX_TRIGGER_LEN = Math.max(...ALL_TRIGGERS.map(t => t.length)); // holdback margin (see NOT_TOKEN_CHAR_RE for the real cut logic)

// One combined regex, longest-trigger-first so e.g. 'qall' wins over 'q'-prefix
// ambiguity (there is no bare 'q' entry, but longest-first is the correct
// general policy). Word-boundary-guarded for the plain-word entries; the
// backslash macros need no \b on their left (backslash is already a
// non-word char, giving an implicit boundary) but do need one conceptually
// on the right, via a negative lookahead for more letters.
//
// 'As' gets its OWN branch with an extra prose guard: it is the one trigger
// in this table that collides with an ordinary standalone English word
// ("As mentioned", "As shown", "As-built"). Applying that same
// space+lowercase-letter guard to every trigger was tried first and was
// wrong -- it silently blocked completely ordinary conversions like
// "qu versus", "fcu value", "bo below" any time a ​trigger was simply
// followed by another lowercase word, which is the common case in running
// text. No other trigger in this table is a standalone English word, so no
// other trigger needs it.
const sortedTriggers = ALL_TRIGGERS.slice().sort((a, b) => b.length - a.length);
const wordTriggers = sortedTriggers.filter((t) => !t.startsWith('\\') && t !== 'As');
const macroTriggers = sortedTriggers.filter((t) => t.startsWith('\\'));

const wordPattern = wordTriggers.map(escapeRe).join('|');
const macroPattern = macroTriggers.map(escapeRe).join('|');
const COMBINED_RE = new RegExp(
  `\\bAs\\b(?!-)(?!\\s?[a-z])` +
  `|\\b(?:${wordPattern})\\b(?!-)` +
  (macroPattern ? `|(?:${macroPattern})(?![a-zA-Z])` : ''),
  'g',
);

function applyReplacements(text) {
  return text.replace(COMBINED_RE, (m) => ENGINEERING_NOTATION_MAP[m] ?? BARE_LATEX_MACROS[m] ?? m);
}

// Bare '$' / '$$' LaTeX delimiter stripping. Zero lookahead needed: a lone
// '$' is stripped unconditionally UNLESS immediately followed by a digit,
// which is the currency pattern this product actually uses in developer-
// mode cost discussions ($5/mo, $0.00 -- see chat.js changelog). No holdback
// margin required beyond what NOT_TOKEN_CHAR_RE already provides for '$'
// itself, since the decision needs only the next character, which is
// already in-buffer by construction (see push() below) once '$' has been
// released from holdback at all.
function stripBareDollar(text) {
  return text.replace(/\$(?!\d)/g, '');
}

// A fixed trailing-length margin is NOT sufficient on its own: it can still
// land the cut *inside* a trigger token even within a single push() call
// (e.g. "\phi Mn test" sliced at length-6 splits "Mn" into "M" + "n test",
// and neither half matches \bMn\b). The correct safe-cut point is the last
// position in the buffer that is already KNOWN to terminate any in-progress
// token -- i.e. the last character that cannot itself be part of a trigger
// OR of an in-progress LaTeX subscript construct.
//
// '_' and '{' are now included in the protected set (previous version only
// protected letters/backslash/$): a trailing "...f_" or "...A_{sc" with the
// underscore/open-brace treated as a safe cut point would emit "f_" now and
// receive "{cu}" as an unrelated-looking delta next push() -- the exact
// "stream tears mid-token" failure mode this holdback buffer exists to
// prevent, just relocated to the new LaTeX-syntax pass instead of fixed.
// '}' is deliberately left OUT of the protected set: a closing brace fully
// terminates a Base_{Sub} construct, so cutting right after it is safe and
// avoids adding latency the construct's own grammar doesn't require.
//
// Greek letters (GREEK_BASE_CHARS) are now in the protected set too, for
// the identical reason Latin letters already were: a chunk ending in a
// bare "\u03b3" is exactly as capable of being a still-forming "\u03b3_c"
// as a chunk ending in bare "f" is of being a still-forming "f_cu" --
// without this, the Greek fix above is real but streaming-inert: push()
// would emit the "\u03b3" alone on one call (nothing yet to disqualify it
// as a safe cut) and receive "_c" alone on the next, and the two would
// never occupy the same safePart for LATEX_SUBSCRIPT_RE to see together.
// finish() does not depend on this at all (it flushes the whole remaining
// buffer in one shot with no holdback decision), which is why this class
// of bug is invisible in a non-streaming/whole-string test and only shows
// up against push()-by-push() chunking -- see verification below.
const NOT_TOKEN_CHAR_RE = new RegExp(`[^A-Za-z\\\\$_{${GREEK_CLASS}]`);
const MAX_HOLDBACK = 64; // safety valve: bound worst-case latency if a
                         // pathological chunk has no separator at all
                         // (MAX_TRIGGER_LEN=4; longest LaTeX construct is
                         // now the longest Greek macro name, not a single
                         // base letter -- '\lambda_{twelveletter}' caps at
                         // 7(\lambda)+1(_)+1({)+8+1(}) = 18 chars -- 64 is
                         // still comfortable headroom, not a tight fit).

function findSafeCutIndex(buf) {
  for (let i = buf.length - 1; i >= 0; i--) {
    if (NOT_TOKEN_CHAR_RE.test(buf[i])) return i + 1;
  }
  return 0; // buffer is one unbroken run of letters/backslash/$/_/{  so far
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
// (and everything after it) waits for the next push.
//
// The bare-form LaTeX subscript (Base_X, one trailing letter) needs an
// analogous 1-character lookahead to resolve its own (?![A-Za-z]) guard,
// but does NOT need a matching adjust function: that guard's target
// character (X, the subscript letter itself) is a letter, which
// findSafeCutIndex already refuses to cut immediately after on its own --
// the cut point never lands mid-letter-run regardless of which pass added
// the letter to the protected set, so the buffer already can't expose
// "Base_X" as a safePart until at least one more (non-letter) character
// has arrived to either confirm or refute the guard. Only 'As' needs the
// dedicated function because its guard's own boundary (\b, i.e. between
// the trigger's last letter and whatever follows) is satisfied by ANY
// non-word character -- including one that a same-chunk-away letter would
// still invalidate the *prose* guard on, which is a strictly later check
// than plain token-completeness.
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
    const emit = stripBareDollar(applyReplacements(convertLatexSubscripts(safePart)));
    return { emit };
  }

  finish() {
    const rest = this._buf;
    this._buf = '';
    const emit = stripBareDollar(applyReplacements(convertLatexSubscripts(rest)));
    return { emit };
  }
}
