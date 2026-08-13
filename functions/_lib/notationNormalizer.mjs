// Streaming-safe engineering-notation normalizer.
// Same holdback-margin / detect-and-retract shape as StreamingSanitizer
// (see streamSanitizer.mjs), composed AFTER it in chat.js's relay():
// the confidentiality gate decides what may be sent at all; this only
// reshapes text that has already been cleared for sending.
//
// SIX correction passes, all pattern-boundary guarded, in this order:
// -2. \sqrt{...} -> \sqrt(...). Braces swapped for parens (bounded,
//     ≤32 chars, no nested braces) so a model reaching for real LaTeX's
//     braced \sqrt{x} out of habit still lands on the same bare-macro
//     path as Pass 2 below, instead of stranding literal "{"/"}".
// -1. Bare Greek base macro -> literal glyph, for bases that can carry a
//     subscript (γ, λ, ψ, ρ, β, τ, ε, α -- see GREEK_SUBSCRIPT_BASES).
//     Runs before Pass 0 so "\gamma_c" and a directly-typed "γ_c"
//     converge onto the exact same Pass 0 code path instead of needing a
//     second, macro-aware subscript grammar.
//  0. LaTeX subscript SYNTAX -> normalized form. Handles Base_{Sub} and
//     bare Base_Sub (single trailing char, real LaTeX grammar) BEFORE the
//     flat-abbreviation pass below, because "fcu" is not a contiguous
//     substring of "f_{cu}" -- no amount of \b vs (?<![A-Za-z]) tuning on
//     a flat "fcu" trigger can ever match text that already contains a
//     literal underscore/brace splitting the letters apart. This pass
//     closes that gap directly by parsing the LaTeX construct itself.
//     Base may be a single ASCII letter or a Greek base glyph already
//     expanded by Pass -1, optionally followed by a prime mark (f'_c).
//  0.5. LaTeX SUPERSCRIPT syntax -> normalized form. Same shape as Pass 0,
//     mirrored for base^exp; base may also be a bare closing bracket
//     (see LATEX_SUPERSCRIPT_RE) so a parenthesized ratio raised to a
//     power, e.g. (M_cr / M_a)^3, converts as a whole.
//  1. ASCII engineering shorthand -> Unicode subscript (fcu -> f + true
//     subscript c+u where available, plain "f_cu" fallback where not --
//     see SUBSCRIPT_LETTER_MAP: Unicode has NO subscript codepoint for
//     b/c/d/f/g/q/w/y/z, so fcu/fy/Ac/Asc/Ag/Mcr/Vc/bw/wd/Ec (and γc, for
//     the same reason -- no subscript 'c') can never be rendered as
//     pure-Unicode subscript; superscript "modifier letter" codepoints
//     exist for those letters, which is what the PREVIOUS version of
//     this table used by mistake -- that is the exact fᶜᵘ/fʸ bug this
//     rewrite fixes, not a regex issue. Do not reintroduce it for Greek
//     bases either (i.e. never emit γᶜ using U+1D9C) -- same bug, same
//     reason it's wrong, one Unicode block over.
//  2. Bare LaTeX macros with no braces/arguments -> plain Unicode
//     (\times -> x, \phi -> \u03c6, \sqrt -> √, etc.)
// All six are FIXED, FINITE-LENGTH-BOUNDED, so all are safe to
// holdback-buffer with a character-class-derived margin. Anything
// requiring unbounded lookahead (\frac{a}{b} argument extraction, real
// nested-brace matching) is deliberately NOT attempted here -- the
// prompt-level instruction (the NOTATION rule in chat.js) is the primary
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

// Superscript counterpart. Deliberately covers ONLY digits + the five
// bracket/operator codepoints from the U+2070-209F block (plus the three
// legacy Latin-1 spillovers 00B2/00B3/00B9) -- the single oldest, most
// universally-fonted Unicode range in this entire feature area. No
// superscript LETTERS are included even though Unicode has them for all
// 26 lowercase and most uppercase letters: those codepoints are scattered
// across Spacing Modifier Letters (1996), Phonetic Extensions (2005),
// Latin Extended-C/D (2008-2020), and -- for 'q' specifically -- a 2021
// supplementary-plane addition (U+107A5) that needs a UTF-16 surrogate
// pair and has negligible real-world font coverage. Letters always go
// through the <sup> HTML path in _cesRenderBotHtml instead: same
// no-font-risk, same reasoning as why subscript falls back to underscore
// for b/c/d/f/g/q/w/y/z above, just applied preemptively to the whole
// letter set rather than per-gap.
const SUPERSCRIPT_CHAR_MAP = {
  0: '\u2070', 1: '\u00B9', 2: '\u00B2', 3: '\u00B3', 4: '\u2074',
  5: '\u2075', 6: '\u2076', 7: '\u2077', 8: '\u2078', 9: '\u2079',
  '+': '\u207A', '-': '\u207B', '=': '\u207C', '(': '\u207D', ')': '\u207E',
};

function toSuperscriptForm(sup) {
  let out = '';
  for (const ch of sup) {
    const sc = SUPERSCRIPT_CHAR_MAP[ch];
    if (!sc) return null;
    out += sc;
  }
  return out;
}

function superscriptOrFallback(base, sup) {
  const sc = toSuperscriptForm(sup);
  return sc ? base + sc : `${base}^${sup}`;
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
  '\\psi': '\u03C8', '\\epsilon': '\u03B5', '\\varepsilon': '\u03B5',
  // [PATCH — square root] '\sqrt' -> '\u221A' (√). Deliberately a bare,
  // zero-argument substitution exactly like '\times'/'\phi' above, NOT an
  // argument-extracting macro -- this table has never done argument
  // extraction and this entry doesn't start now (see the file header's
  // note on why that's out of scope). The model supplies its own
  // parentheses after it (chat.js's prompt now teaches \sqrt(...), not
  // \sqrt{...}); '\sqrt(f\'_c)' becomes '√(f\'_c)' the same way
  // '\times' becomes '×' -- one macro token swapped for one glyph,
  // nothing else in the string touched. A model that reaches for real
  // LaTeX's braced '\sqrt{...}' out of training habit anyway is still
  // covered -- see convertSqrtBraces/SQRT_BRACE_RE below, which rewrites
  // that form down to this same bare form before this table ever runs.
  '\\sqrt': '\u221A',
};

// Greek bases that can carry an engineering subscript in this domain (γ_c,
// ψ_t -- ECP 203 partial safety factors, ACI 318 development-length
// modification factors). Was gamma-only, pending evidence another base
// needed it; ces-reply-2026-08-09T08-42-05.txt (a real captured reply) is
// that evidence -- it uses λ, ψ, ρ, γ, β, τ, ε as bases across its ACI
// 318 / ECP 203 formulas. ψ_t/ψ_e/ψ_s specifically go from literal
// underscore to a true lowered subscript with this change (t/e/s are all
// covered letters); γ_c/ρ_b/β_c/τ_bd stay on the underscore fallback
// either way (c/b/d are uncovered) but now correctly reach the frontend's
// <sub>-tag upgrade pass instead of stopping here as dead literal text --
// see the matching change in _cesRenderBotHtml (footing_pro/pc_suite).
// [PATCH — alpha_s] \alpha added on the SAME evidence basis as the other
// seven, from a second captured production reply: ACI 318's two-way
// (punching) shear equation uses alpha_s as the column-location factor
// (interior/edge/corner), and until this line \alpha was in
// BARE_LATEX_MACROS (so a bare "\alpha" on its own already rendered as α)
// but absent from THIS table -- meaning "\alpha_s" fell through Pass -1
// untouched, then failed Pass 0's base-lookbehind (the trailing "a" of
// "alpha" is preceded by "h", an alnum, so the lookbehind correctly
// refuses to treat it as a standalone base), then only got picked up by
// Pass 2 matching literal "\alpha" and leaving a bare "_s" sitting after
// it -- same failure shape as every other omitted-base case above, closed
// the same way: add the key here, nothing else needs to change.
// Add more keys here if another base shows up in a future reply; nothing
// else below needs to change to support it, this table is the single
// source the rest of Pass -1/Pass 0 read from.
const GREEK_SUBSCRIPT_BASES = {
  '\\gamma': '\u03B3', '\\lambda': '\u03BB', '\\psi': '\u03C8',
  '\\rho': '\u03C1', '\\beta': '\u03B2', '\\tau': '\u03C4', '\\epsilon': '\u03B5',
  '\\alpha': '\u03B1',
};
const GREEK_BASE_GLYPHS = Object.values(GREEK_SUBSCRIPT_BASES).join('');

// ── Pass -2: \sqrt{...} -> \sqrt(...) ───────────────────────────────────
// [PATCH — square root] Runs before EVERYTHING else, including Pass -1,
// because it only ever swaps the outer delimiters -- whatever ends up
// between the new parentheses (very often an apostrophe/subscript
// construct, e.g. \sqrt{f'_c}) still needs to go through every later pass
// normally, exactly as if the model had typed the parens itself.
// Deliberately the ONLY braced-argument macro this file handles, added
// specifically because \sqrt is the one macro here where a model trained
// on real LaTeX overwhelmingly reaches for the braced form out of habit
// -- \phi/\times/etc. never take an argument at all in real LaTeX either,
// so there's no competing habit to guard against for those. Left
// unhandled, this would either strand literal "{"/"}" in the reply (bare
// '\sqrt' -> '√' still fires on '\sqrt{f\'_c}' since '{' satisfies its
// own (?![a-zA-Z]) guard, but the braces themselves are never consumed by
// anything) or never convert at all if the model doesn't reliably emit
// the bare form the prompt asks for.
// Bounded exactly like every other braced construct in this file: content
// capped at 32 chars (more headroom than the subscript/exponent 8-char
// cap since a radicand is often a short arithmetic expression, not a
// single symbol -- "0.05 * (f'_c - 28)" is 19 chars) with NO nested
// '{'/'}' permitted, so this is a fixed-max-length match, never
// unbounded/real brace-balancing (see the file header's note on why
// that's out of scope generally).
const SQRT_BRACE_RE = /\\sqrt\{([^{}]{1,32})\}/g;
function convertSqrtBraces(text) {
  return text.replace(SQRT_BRACE_RE, (_m, inner) => `\\sqrt(${inner})`);
}

// ── Pass -1: bare Greek macro -> literal glyph, for bases only ─────────
// Runs BEFORE Pass 0 so "\gamma_c" and "γ_c" hit the exact same code path
// below instead of needing a second, parallel LaTeX-macro-aware subscript
// regex. Guarded the same way the Pass 2 macro replacement guards itself
// (no trailing letter -- (?![a-zA-Z])) so this can never fire on a longer,
// unrelated macro name. This does NOT touch \phi/\rho/etc.; those still
// go through Pass 2 only, unchanged, until/unless they're added to
// GREEK_SUBSCRIPT_BASES above.
const GREEK_MACRO_RE = new RegExp(
  Object.keys(GREEK_SUBSCRIPT_BASES).map((m) => m.replace(/\\/g, '\\\\')).join('|') + '(?![a-zA-Z])',
  'g',
);
function expandGreekSubscriptBases(text) {
  return text.replace(GREEK_MACRO_RE, (m) => GREEK_SUBSCRIPT_BASES[m]);
}

// ── Pass 0: LaTeX subscript SYNTAX ──────────────────────────────────────
// Base_{Sub} (braced, up to 8 subscript letters) or bare Base_Sub (1-3
// trailing letters, capped -- NOT real LaTeX grammar, which only ever binds
// a single bare token; widened deliberately, see below). Base is a single
// ASCII letter OR a literal Greek base glyph from GREEK_SUBSCRIPT_BASES
// (already expanded from its macro form by Pass -1 above by the time this
// runs). Restricting to single-character bases is what keeps the pattern
// from firing inside multi-letter identifiers like DEVELOPER_PASSWORD or
// RACE_CONCURRENCY.
//
// Left boundary is an explicit negative lookbehind, NOT \b: JS's \b is
// defined purely against the ASCII \w class ([A-Za-z0-9_]). γ is \W under
// that definition, so \b can NEVER match immediately before it -- not
// after a space, not after another Greek letter, not even at the very
// start of the string (verified: \b requires a \w on at least one side of
// the transition; string-start-then-\W is not a transition). A plain
// `\bγ_c` pattern would therefore match nothing, ever, silently -- this
// was checked by direct execution, not inferred. The lookbehind form
// below works identically for ASCII and Greek bases and has no such gap.
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
//
// [PATCH — f'_c prime notation] Base group now allows an optional trailing
// prime mark, ['\u2019]?, between the base letter and the underscore.
// This is the ACI 318 f'_c convention (concrete compressive strength,
// f-prime-c) captured directly from a production reply -- the prime sits
// BETWEEN the base and the subscript marker, and the base group used to
// require the underscore immediately after the base letter with nothing
// in between, so "f'_c" (base "f", then "'", then "_c") could never match
// at all: the character directly before "_" is "'", not a letter, and
// neither alternative in the old group could ever equal "'". Both
// straight (U+0027) and typographic (U+2019) primes are accepted since
// which one a model reaches for isn't predictable and telling them apart
// isn't the point -- either reads as the same mathematical prime mark.
// The prime is INSIDE the capture group, not matched separately, so
// subscriptOrFallback's `base` argument naturally becomes "f'" (or "f")
// and the prime is preserved exactly where it was typed either way --
// this pass only ever decides what happens to the underscore-marked
// subscript AFTER the base, never touches anything before it.
const LATEX_SUBSCRIPT_RE = new RegExp(
  `(?<![A-Za-z0-9_])([A-Za-z${GREEK_BASE_GLYPHS}]['\u2019]?)_(?:\\{([A-Za-z]{1,8})\\}|([A-Za-z]{1,3})(?![A-Za-z]))`,
  'g',
);

function convertLatexSubscripts(text) {
  return text.replace(LATEX_SUBSCRIPT_RE, (_m, base, braced, bare) => {
    const sub = braced || bare;
    return subscriptOrFallback(base, sub);
  });
}

// Exponent content may be digits and/or the four safe operator glyphs;
// bare form stays capped at 3 (matches subscript's own bare cap), braced
// at 8. '=' and the parens are only meaningful/common inside braces
// (nobody writes a bare "x^=2"), so the bare-form charset omits them --
// mirrors why subscript's own bare form is letters-only with no operators
// at all.
//
// [PATCH — bracketed-base exponent] Base alternation now has a THIRD
// branch, `[)\]]`, alongside the original digit-run and single-letter
// branches -- a bare, un-guarded ')' or ']'. This is the actual bug
// behind the Branson's-equation report: real engineering formulas
// exponentiate a whole PARENTHESIZED RATIO, not a single variable --
// (M_cr / M_a)^3 is the exact motivating case, and ECP 203/ACI 318 are
// full of the same shape ((k*L/r)^2 slenderness, (f'c)^0.5, etc). The
// char immediately before '^' there is ')', which neither original
// branch could ever match (')' is not a digit and not in [A-Za-z...]),
// so the whole exponent silently fell through every pass and reached
// the client as literal "^3" -- confirmed by direct execution against
// the captured reply text, not inferred.
// The bracket branch deliberately has NO `(?<![A-Za-z0-9_])` lookbehind
// -- unlike the digit/letter branches, which need it to avoid grabbing
// the trailing letter of a longer identifier as a false single-char
// base ("logbase^2" should not read as base "e"). A closing bracket
// carries no such ambiguity: whatever precedes it is INSIDE the group,
// not the base itself, so the character before ')' is irrelevant to
// whether ')' is a valid base -- in fact a lookbehind here would
// actively break the common case, since ')' is virtually always
// preceded by a letter or digit (the last character of whatever the
// parens wrapped).
// Deliberately still bounded, not a LaTeX parser: this does not attempt
// to locate the matching '(' or validate bracket nesting (see the file
// header's note on why unbounded lookahead/argument-extraction is out
// of scope here) -- it only needs the ONE character immediately before
// '^' to decide whether to emit `base + superscript(exp)`, and a lone
// ')' or ']' answers that in O(1) with no backward scan required.
const LATEX_SUPERSCRIPT_RE = new RegExp(
  `((?<![A-Za-z0-9_])\\d+|(?<![A-Za-z0-9_])[A-Za-z${GREEK_BASE_GLYPHS}]|[)\\]])\\^(?:\\{([A-Za-z0-9+\\-=()]{1,8})\\}|([A-Za-z0-9+\\-]{1,3})(?![A-Za-z0-9]))`,
  'g',
);

function convertLatexSuperscripts(text) {
  return text.replace(LATEX_SUPERSCRIPT_RE, (_m, base, braced, bare) => {
    const sup = braced || bare;
    return superscriptOrFallback(base, sup);
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
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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
const NOT_TOKEN_CHAR_RE = new RegExp(`[^A-Za-z${GREEK_BASE_GLYPHS}\\\\$_{^]`);
const MAX_HOLDBACK = 64; // safety valve: bound worst-case latency if a
                         // pathological chunk has no separator at all.
                         // MAX_TRIGGER_LEN is 11 (\varepsilon); the
                         // largest bounded LaTeX construct is now
                         // \sqrt{...} at up to 39 chars ("\sqrt{" + 32
                         // capped content chars + "}") -- see
                         // SQRT_BRACE_RE below, now the longest one here,
                         // ahead of "\epsilon_{xxxxxxxx}" at 19. 64 is
                         // still ample headroom above 39, not a tight fit.

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

// '^' itself is protected above, so a *bare* trailing caret already can't
// be cut. But digits and +-=() are NOT in the protected set -- adding them
// there unconditionally would hold back every plain number and every
// hyphen in ordinary prose (dates, code names like "ECP 203", "ACI
// 318-19") for no reason, since the overwhelming majority of digits/
// hyphens in this product's replies have nothing to do with an exponent.
// So this stays a targeted, construct-scoped guard instead: if the
// candidate safePart's tail is a base + '^' + zero-or-more still-valid
// exponent characters with nothing after it yet (no confirmed
// terminator), the whole run -- base included -- waits for the next
// push. A tail that already closed with '}' is NOT matched here (mirrors
// why '}' is deliberately left out of NOT_TOKEN_CHAR_RE for subscript:
// the closing brace fully terminates the construct, so it's already safe).
// [PATCH — bracketed-base exponent] Base alternation widened to match
// LATEX_SUPERSCRIPT_RE above (adds ')'/']'): once that regex accepts a
// bracket as a base, THIS regex has to recognize an in-progress
// "...)^12" tail too, or the still-forming exponent gets flushed early
// as if "^12" were already complete -- next push()'s "3" would then
// arrive as an unrelated bare character with no way to rejoin the
// exponent it was actually part of. Exactly the "stream tears
// mid-token" failure this holdback buffer exists to prevent, just for
// the new base shape instead of the original one.
const SUPERSCRIPT_TAIL_RE = new RegExp(
  `(?:\\d+|[A-Za-z${GREEK_BASE_GLYPHS}]|[)\\]])\\^\\{?[A-Za-z0-9+\\-=()]*$`,
);
function adjustCutForSuperscriptLookahead(buf, cut) {
  const scan = buf.slice(0, cut);
  const m = SUPERSCRIPT_TAIL_RE.exec(scan);
  return m ? m.index : cut;
}

// [PATCH — bracketed-base exponent] Companion guard for the OTHER half of
// the same gap: SUPERSCRIPT_TAIL_RE above only fires once '^' has already
// arrived in the buffer. But a bracket base can just as easily be the
// LAST character of a push() with '^' not arrived yet at all -- e.g. a
// chunk boundary landing right after "(M_cr / M_a)". Without this guard,
// findSafeCutIndex would flush that ')' immediately (it's not in
// NOT_TOKEN_CHAR_RE's protected set -- deliberately not, see that const's
// own comment: blanket-protecting every ')' would hold back the huge
// majority that have nothing to do with an exponent, e.g. "(see ACI
// 318-19)"). Once flushed, the bracket is gone from `this._buf` by the
// time '^3' shows up in a later push(), so LATEX_SUPERSCRIPT_RE has
// nothing adjacent to match against no matter how correct its own
// pattern is. So: hold back a bare trailing ')'/']' for exactly one more
// push, same shape as adjustCutForAsLookahead's lookahead above, just a
// 1-character resolution window instead of 2. `while`, not a single
// pullback, because a run of several closing brackets can legitimately
// precede a caret (a bracketed sum of parenthesized terms).
function adjustCutForSuperscriptBaseLookahead(buf, cut) {
  while (cut > 0 && (buf[cut - 1] === ')' || buf[cut - 1] === ']')) cut--;
  return cut;
}

// [PATCH — f'_c prime notation] Companion guard for the SAME shape of gap,
// this time on the subscript side: LATEX_SUBSCRIPT_RE's base group now
// accepts a trailing prime ("f'"), but the prime character itself is not
// in NOT_TOKEN_CHAR_RE's protected set (correctly not -- the overwhelming
// majority of apostrophes in ordinary prose, "it's", "engineer's", have
// nothing to do with a subscript base, same reasoning as every other
// targeted-not-blanket guard in this file). Without this, a chunk
// boundary landing right after "f'" flushes it immediately, and by the
// time "_c" arrives in a later push() the base is already gone from
// `this._buf`. Only 2 characters of lookback (base letter + prime), not a
// `while` loop like the bracket guard above: a base can only ever carry
// ONE prime mark in this notation, there's no equivalent of "several
// closing brackets in a row" to account for here.
function adjustCutForSubscriptBaseLookahead(buf, cut) {
  if (cut >= 2 && (buf[cut - 1] === '\'' || buf[cut - 1] === '\u2019') && /[A-Za-z]/.test(buf[cut - 2])) {
    return cut - 2;
  }
  return cut;
}

// [PATCH — square root] A trailing, not-yet-closed "\sqrt{...content so
// far..." must not be flushed before its closing '}' arrives, for the
// same reason SUPERSCRIPT_TAIL_RE exists above: '\\' and '{' are
// themselves protected already (see NOT_TOKEN_CHAR_RE), but the radicand
// content in between is NOT (it can be digits, spaces, apostrophes,
// operators -- none of those are in the protected set either, same
// reasoning as everywhere else in this file). Left unguarded, e.g.
// "\sqrt{f'" flushes the instant the buffer ends right after that
// apostrophe (an unprotected character on its own), stranding "\sqrt{f'"
// as literal emitted text with "_c}" arriving disconnected from it next
// push() -- the exact "stream tears mid-token" failure this holdback
// buffer exists to prevent, just for the new construct instead of the
// original ones.
const SQRT_BRACE_TAIL_RE = /\\sqrt\{[^{}]*$/;
function adjustCutForSqrtBraceLookahead(buf, cut) {
  const scan = buf.slice(0, cut);
  const m = SQRT_BRACE_TAIL_RE.exec(scan);
  return m ? m.index : cut;
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
    cut = adjustCutForSuperscriptLookahead(this._buf, cut);
    cut = adjustCutForSuperscriptBaseLookahead(this._buf, cut);
    cut = adjustCutForSubscriptBaseLookahead(this._buf, cut);
    cut = adjustCutForSqrtBraceLookahead(this._buf, cut);
    if (cut < 0) cut = 0;
    if (this._buf.length - cut > MAX_HOLDBACK) {
      cut = this._buf.length - MAX_HOLDBACK; // bounded worst case, see above
    }
    if (cut === 0) return { emit: '' };
    const safePart = this._buf.slice(0, cut);
    this._buf = this._buf.slice(cut);
    const emit = stripBareDollar(applyReplacements(convertLatexSuperscripts(convertLatexSubscripts(expandGreekSubscriptBases(convertSqrtBraces(safePart))))));
    return { emit };
  }

  finish() {
    const rest = this._buf;
    this._buf = '';
    const emit = stripBareDollar(applyReplacements(convertLatexSuperscripts(convertLatexSubscripts(expandGreekSubscriptBases(convertSqrtBraces(rest))))));
    return { emit };
  }
}
