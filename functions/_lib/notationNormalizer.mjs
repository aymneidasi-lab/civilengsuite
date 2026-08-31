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
//     second, macro-aware subscript grammar. A companion rule in this
//     same stage, expandBarePsiSubscriptBase(), does the equivalent
//     expansion for BARE "psi_x" specifically (no backslash) -- psi
//     can't get blanket bare-word support the way Pass 2's other Greek
//     letters do (see BARE_GREEK_WORD_MACROS below), so this is scoped
//     narrowly to only the unambiguous "immediately followed by an
//     underscore" shape.
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
//     (\times -> x, \phi -> \u03c6, \sqrt -> √, etc.), PLUS the same set
//     of conversions again without the leading backslash (lambda -> λ,
//     sqrt -> √) for a model that writes the plain word instead -- see
//     BARE_GREEK_WORD_MACROS below for why that's now a first-class,
//     independent path rather than a typo to correct. psi is the one
//     exception still requiring \psi; it collides with the pressure unit
//     abbreviation "psi" (pounds per square inch), routine in this domain.
// All six are FIXED, FINITE-LENGTH-BOUNDED, so all are safe to
// holdback-buffer with a character-class-derived margin. Anything
// requiring unbounded lookahead (\frac{a}{b} argument extraction, real
// nested-brace matching) is deliberately NOT attempted here -- the
// prompt-level instruction (the NOTATION rule in chat.js) is the primary
// defense for those; this is a bounded, low-risk safety net, not a
// LaTeX parser.
//
// [PATCH — KaTeX rendering] The six passes above now run ONLY on text
// outside resolved $ / $$ LaTeX spans -- see the math-span-aware layer at
// the bottom of this file (walkMathSpans / findOpenMathDelimiter /
// findLastResolvedMathEnd / NotationNormalizer._render) for the mechanics
// and the full rationale. Short version: the client renders real LaTeX
// via KaTeX now (see chat.js's NOTATION prompt block), so text the model
// correctly wrapped in $ is real LaTeX grammar these six passes don't
// understand and must not touch -- left ungated, Pass 0 alone turns a
// perfectly correct "$f_{cu}$" into "$f_cu$" (c has no true Unicode
// subscript codepoint, so it falls back to a literal underscore), then
// stripBareDollar strips both now-bare '$'s since neither is followed by
// a digit -- the delimiters vanish and "f_cu" reaches the client as
// plain text, never as math. Verified by tracing the pipeline, not
// inferred. The six passes themselves are otherwise UNCHANGED below --
// they remain exactly what they always were, a bounded safety net for a
// reply (or portion of one) that reverts to old bare notation with no $
// at all.

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

// [PATCH — bare Greek/root words] Two captured production replies
// (ces-reply-2026-08-13T23-59-21.txt, ces-reply-2026-08-13T23-59-35.txt,
// a FRESH chat, no prior-turn history to blame) show the model
// consistently choosing the bare English word over the backslash form
// above -- "lambda", "phi", "sqrt(f_cu)" -- and, more tellingly, stating
// an explicit written rule for itself that gets this exactly backwards:
// "إياك تستخدم علامة \ ... اكتبه بالاسم بتاعه (lambda, phi)" (never use
// the backslash mark, write it by its plain name) -- the opposite of
// what chat.js's prompt actually says. That is not a model skimming a
// long prompt and missing a line; every other nearby rule in the same
// reply (subscript underscores, caret exponents) came out right. The
// specific and consistent thing it gets backwards is exactly the one
// rule that fights a strong, generic prior every LLM picks up from
// training: a raw backslash-escape sequence in a plain, non-LaTeX chat
// surface usually DOES show up as broken literal text, so avoiding it
// is normally the correct instinct. This prompt's claim that THIS one
// app is the exception is, evidently, not winning that argument
// reliably even with direct, explicit, repeated instruction to the
// contrary across three separate patches now.
// So: stop arguing it, and make the code correct for what the model
// already reliably writes instead. Every key here is a BARE word,
// independent of and in addition to the backslash form above (which
// keeps working -- some replies do use it, nothing here removes that
// path, and the two forms can be freely mixed in the same reply).
// 'psi' is deliberately excluded: unlike every other entry here, "psi"
// collides with a live, routine, in-domain abbreviation -- pounds per
// square inch, e.g. "qall = 2500 psi" -- not a hypothetical. \psi
// (backslash form) remains the only accepted path for that one symbol;
// see the matching carve-out in chat.js's prompt.
const BARE_GREEK_WORD_MACROS = {
  lambda: '\u03BB', phi: '\u03C6', mu: '\u03BC', alpha: '\u03B1', beta: '\u03B2',
  gamma: '\u03B3', delta: '\u03B4', Delta: '\u0394', sigma: '\u03C3', tau: '\u03C4',
  epsilon: '\u03B5', rho: '\u03C1', sqrt: '\u221A',
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
// [PATCH — bare Greek/root words] Leading backslash made OPTIONAL
// (`\\?`) -- captured evidence (see BARE_GREEK_WORD_MACROS below) shows
// the model reliably dropping the backslash even when it otherwise
// reaches for LaTeX-style braces, so "sqrt{f'_c}" (no backslash, still
// braced) needs the exact same rescue "\sqrt{f'_c}" already got. Left-
// side lookbehind added for the same reason every bare word in this file
// gets one: without a backslash to act as an unambiguous left boundary
// on its own, "sqrt{" needs its own guard against matching mid-word.
// Output always re-adds the backslash regardless of whether the input
// had one, so Pass 2's existing '\sqrt' macro branch is the only place
// that ever decides the final glyph -- one source of truth either way.
// [PATCH — double-backslash fix] Restructured from a single shared
// `(?<![A-Za-z0-9_])\?sqrt` into two explicit alternatives sharing one
// non-capturing wrapper. The lookbehind now only ever gates the BARE
// alternative, where it belongs -- the backslash-prefixed alternative
// matches unconditionally, whatever precedes the backslash (a backslash
// can never be silently absorbed into a longer bare identifier the way a
// letter can, so no lookbehind is needed there at all). Previously, with
// one shared `(?<!...)\?sqrt`, a backslash immediately preceded by a
// digit or letter (e.g. "0.85\sqrt{...}") made the greedy
// backslash-inclusive match attempt fail its own lookbehind (checked
// BEFORE the backslash, against "5"), forcing a backtrack to the bare
// alternative (lookbehind now checked against the backslash itself,
// which passes) -- so the match became "sqrt{...}" WITHOUT the
// already-present backslash, and the replacement then prepended a SECOND
// one on top of the untouched original. Confirmed by direct execution
// against \lambda\sqrt{f_c} (this exact Ld formula, both here and in
// LEFT_RE/RIGHT_RE/FRAC_RE below, all four sharing the identical bug
// shape), not inferred.
const SQRT_BRACE_RE = /(?:\\sqrt|(?<![A-Za-z0-9_])sqrt)\{([^{}]{1,32})\}/g;
function convertSqrtBraces(text) {
  return text.replace(SQRT_BRACE_RE, (_m, inner) => `\\sqrt(${inner})`);
}

// [PATCH — bare \frac / \left / \right] Same rescue as SQRT_BRACE_RE above,
// same evidence class: the model drops the leading backslash on these two
// STRUCTURAL commands as reliably as it does on \sqrt/\lambda/\phi (see
// BARE_GREEK_WORD_MACROS's header comment for the captured-reply evidence
// this is the same behavior, not a new one) -- except \frac and \left/
// \right have no bare-word rescue available the way "lambda"->λ does,
// because there is no single glyph a fraction or a scaled delimiter can
// fall back to. A bare "frac{Mcr}{Ma}" or "left(...right)" therefore
// didn't degrade to a readable Unicode approximation like a dropped
// "\lambda" did -- it degraded to literal, broken "frac{Mcr}{Ma}" text,
// which is what the production screenshot this patch responds to shows.
// Bounded exactly like SQRT_BRACE_RE: both frac arguments capped at 32
// chars, no nested braces -- a fixed-max-length match, not real
// brace-balancing (see file header). left/right require the bracket
// character immediately adjacent with zero space, which is what makes
// this safe against ordinary prose ("the left side", "right edge") --
// nobody writes "left(" or "right)" with no space as plain English.
// [PATCH — double-backslash fix] Same restructuring, same reason, see
// SQRT_BRACE_RE above -- e.g. "3\frac{1}{2}" immediately after a digit
// (a coefficient right before a fraction, entirely normal in a real
// formula) had the identical failure shape.
const FRAC_RE = /(?:\\frac|(?<![A-Za-z0-9_])frac)\{([^{}]{1,32})\}\{([^{}]{1,32})\}/g;
function convertBareFrac(text) {
  return text.replace(FRAC_RE, (_m, num, den) => `\\frac{${num}}{${den}}`);
}
// [PATCH — double-backslash fix] Same restructuring, same reason, see
// SQRT_BRACE_RE above. This is the pair that actually broke in
// production: "(M_cr/M_a)^3\right]" -- a closing exponent digit directly
// against an already-correct "\right" is completely routine LaTeX, not
// an edge case, which is exactly why this shipped and was hit
// immediately on the very first real Branson's-equation reply.
const LEFT_RE = /(?:\\left|(?<![A-Za-z0-9_])left)(?=[([{])/g;
const RIGHT_RE = /(?:\\right|(?<![A-Za-z0-9_])right)(?=[)\]}])/g;
function convertBareLeftRight(text) {
  return text.replace(LEFT_RE, '\\left').replace(RIGHT_RE, '\\right');
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

// [PATCH — psi subscript exception] Live evidence (development-length Ld
// formula, a fresh-chat reply) confirms the model reaches for bare
// "psi_t"/"psi_e"/"psi_s" here too, exactly like every other Greek letter
// in BARE_GREEK_WORD_MACROS below -- except psi can't just join that
// table (see its own comment: "psi" collides with the pressure unit,
// pounds per square inch, a routine value in this exact domain). Because
// "psi" was excluded there entirely, NOTHING in the pipeline ever
// recognized it as a subscript base -- not just "psi doesn't become ψ"
// (intended) but "_t doesn't become a subscript either" (not intended,
// and not even something the pressure-unit case would want protected:
// nobody writes a bearing value as "2500psi_something", the unit always
// stands alone right after a number). So: a SEPARATE, narrowly-scoped
// rule, not a table entry -- expand bare "psi" ONLY when it's
// immediately followed by "_" and a letter (or brace, for the rarer
// braced-subscript form). That shape is unambiguous in a way standalone
// "psi" never is, so this closes the gap without reopening the
// collision BARE_GREEK_WORD_MACROS's exclusion exists to prevent.
// Runs in the same stage as Pass -1 above (before Pass 0) so "psi_t"
// becomes "ψ_t" -- a single-glyph base -- before the subscript pass ever
// looks at it, same reason Pass -1 itself runs where it does.
// `(?<!\\)` matters, not just `\b`: `\` is a non-word character, so a
// bare `\b` alone is satisfied immediately after it too -- without this,
// "\psi_t" would have its "psi" consumed by THIS rule first (this pass
// runs before Pass -1), stripping the letters out from under Pass -1's
// own "\psi" macro match before it ever runs and leaving a stranded,
// unconverted leading backslash in the output.
const BARE_PSI_SUBSCRIPT_RE = /(?<!\\)\bpsi(?=_[A-Za-z{])/g;
function expandBarePsiSubscriptBase(text) {
  return text.replace(BARE_PSI_SUBSCRIPT_RE, '\u03C8');
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

const ALL_TRIGGERS = [...Object.keys(ENGINEERING_NOTATION_MAP), ...Object.keys(BARE_LATEX_MACROS), ...Object.keys(BARE_GREEK_WORD_MACROS)];
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
//
// [PATCH — bare Greek/root words] BARE_GREEK_WORD_MACROS gets a FOURTH
// branch, not folded into wordTriggers above, because it needs different
// boundary rules on the two sides:
//   - LEFT: same strict "(?<![A-Za-z0-9_])" used by LATEX_SUBSCRIPT_RE's
//     base group elsewhere in this file -- not preceded by a letter,
//     digit, or underscore. Stricter than \b needs to be, but there's no
//     legitimate case (unlike the right side, next point) for one of
//     these words to immediately follow an underscore.
//   - RIGHT: "(?![a-zA-Z])" instead of \b, matching how the macroTriggers
//     branch already treats its own right side just below. This is the
//     one place \b would be actively wrong for this table: \b treats '_'
//     as a word character, so a plain \b(?:alpha)\b would silently NEVER
//     match "alpha_s" (no boundary exists between the "a" and the "_").
//     Real evidence (ces-reply-2026-08-13T23-59-35.txt) is bare
//     "alpha_s" written with no backslash at all, so this has to work.
//     subscript conversion (Pass 0) already ran before this pass and
//     correctly declined to touch "alpha_s" itself (its own lookbehind
//     correctly refuses to read the trailing "a" of "alpha" as a
//     standalone base) -- this pass only ever converts the "alpha" part;
//     the leftover "_s" reaches the client's own <sub>-upgrade pass the
//     same way γ_c/β_c's underscore fallback already does (α is in that
//     pass's base class too, see _cesRenderBotHtml in footing_pro/pc_suite).
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const sortedTriggers = ALL_TRIGGERS.slice().sort((a, b) => b.length - a.length);
const wordTriggers = sortedTriggers.filter((t) => !t.startsWith('\\') && t !== 'As' && !(t in BARE_GREEK_WORD_MACROS));
const macroTriggers = sortedTriggers.filter((t) => t.startsWith('\\'));
const bareGreekTriggers = sortedTriggers.filter((t) => t in BARE_GREEK_WORD_MACROS);

const wordPattern = wordTriggers.map(escapeRe).join('|');
const macroPattern = macroTriggers.map(escapeRe).join('|');
const bareGreekPattern = bareGreekTriggers.map(escapeRe).join('|');
const COMBINED_RE = new RegExp(
  `\\bAs\\b(?!-)(?!\\s?[a-z])` +
  `|\\b(?:${wordPattern})\\b(?!-)` +
  (macroPattern ? `|(?:${macroPattern})(?![a-zA-Z])` : '') +
  (bareGreekPattern ? `|(?<![A-Za-z0-9_])(?:${bareGreekPattern})(?![a-zA-Z])` : ''),
  'g',
);

function applyReplacements(text) {
  return text.replace(
    COMBINED_RE,
    (m) => ENGINEERING_NOTATION_MAP[m] ?? BARE_LATEX_MACROS[m] ?? BARE_GREEK_WORD_MACROS[m] ?? m,
  );
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
// [PATCH — bare Greek/root words] Backslash made optional here too,
// matching the identical change to SQRT_BRACE_RE above -- "sqrt{" (no
// backslash) is just as capable of being mid-construct at a chunk
// boundary as "\sqrt{" is; the letters of "sqrt" and the "{" are already
// individually protected either way, but that alone doesn't protect the
// CONTENT after "{" (digits/spaces/apostrophes/operators, none of which
// are in NOT_TOKEN_CHAR_RE's protected set), which is what this guard is
// actually for.
const SQRT_BRACE_TAIL_RE = /\\?sqrt\{[^{}]*$/;
function adjustCutForSqrtBraceLookahead(buf, cut) {
  const scan = buf.slice(0, cut);
  const m = SQRT_BRACE_TAIL_RE.exec(scan);
  return m ? m.index : cut;
}

// ── Math-span-aware layer ───────────────────────────────────────────────
// Streaming shape mirrors the rest of this file: holdback-margin /
// detect-and-retract, just with a different notion of "safe cut point".
// A resolved span (open delimiter with a matching, already-arrived close)
// is safe to emit in full the moment both ends are in the buffer, same as
// any other confirmed token. An OPEN span with no close yet is the
// opposite of safe -- unlike every bounded construct in the six passes
// above, a LaTeX span has no fixed max length (a $$...$$ block can be an
// entire multi-\frac equation), so nothing after the '$' that opened it
// can be classified -- inline vs. display, prose vs. math -- until the
// close arrives to confirm the span's actual extent.

// Finds the next occurrence of the literal delimiter string `delim`
// ('$' or '$$') in `buf` at or after `from`, skipping any that are
// escaped (immediately preceded by '\', e.g. the "\$500" a model writes
// for a literal dollar sign inside an equation). Same one-character
// lookback convention as every other escape check in this file (compare
// GREEK_MACRO_RE's own guard) -- not a general escaped-backslash parser
// (a literal "\\$" is not specially handled), matching this file's
// established bounded-not-a-parser scope.
function findUnescapedDelim(buf, delim, from) {
  let idx = buf.indexOf(delim, from);
  while (idx !== -1 && buf[idx - 1] === '\\') {
    idx = buf.indexOf(delim, idx + 1);
  }
  return idx;
}

// Shared walk over buf's top-level $ / $$ delimiters: jumps from one
// resolved span to the next, calling onResolvedEnd(i) with the buffer
// index immediately after each span it closes. Returns the index of the
// first '$' that OPENS a span with no matching close anywhere later in
// buf, or -1 if every '$' in buf resolves (including "no '$' at all").
// findOpenMathDelimiter and findLastResolvedMathEnd are both thin
// wrappers over this one walk so the two can never independently drift
// out of agreement -- see findLastResolvedMathEnd's own comment for why
// that agreement specifically matters here.
function walkMathSpans(buf, onResolvedEnd) {
  let i = 0;
  while (i < buf.length) {
    if (buf[i] === '$' && buf[i - 1] !== '\\') {
      const isDisplay = buf[i + 1] === '$';
      const delim = isDisplay ? '$$' : '$';
      const close = findUnescapedDelim(buf, delim, i + delim.length);
      if (close === -1) return i;
      i = close + delim.length;
      onResolvedEnd(i);
      continue;
    }
    i++;
  }
  return -1;
}

function findOpenMathDelimiter(buf) {
  return walkMathSpans(buf, () => {});
}

// Returns the buffer index immediately after the LAST fully resolved math
// span in buf, or 0 if none. Only meaningful -- and only ever called --
// when findOpenMathDelimiter(buf) has already returned -1 (every '$'
// resolves), so the walk below never actually hits its own `close === -1`
// branch in practice; it's there so this function still returns a safe,
// non-advancing boundary instead of a bogus one if that invariant is ever
// violated by a future caller.
//
// This can't be derived from findOpenMathDelimiter's -1 return alone: -1
// only proves the walk reached buf.length without hitting an unresolved
// open, it doesn't say WHERE the last resolved span actually ended,
// because the walk keeps advancing character-by-character (the plain
// `i++` branch) straight through any trailing $-free prose after that
// span, all the way to buf.length. Treating "-1 means the whole buffer is
// safe" as license to hand push()'s tail-cut logic a `tail` starting at 0
// would re-run the six legacy passes over span content that's already
// resolved and must stay untouched -- this bookmarks the position at each
// onResolvedEnd() call, and only that, so the boundary this function
// returns is always a true post-span boundary, never mid-span.
function findLastResolvedMathEnd(buf) {
  let lastEnd = 0;
  walkMathSpans(buf, (end) => { lastEnd = end; });
  return lastEnd;
}

// Bound on how long an OPEN (unclosed-so-far) math span may sit in the
// holdback buffer before this module gives up waiting for its close and
// flushes it as plain text instead. Deliberately much larger than
// MAX_HOLDBACK (64): that constant bounds the six FIXED, FINITE-LENGTH
// legacy constructs (longest is \sqrt{...} at 39 chars); a $$...$$
// display block has no such fixed bound -- a real multi-\frac ACI 318 /
// ECP 203 derivation can legitimately run several hundred characters. 2000
// is a deliberately generous, still-bounded ceiling, not derived from a
// hard spec: if a span hasn't closed within 2000 characters, either the
// model failed to close it at all (a generation-side bug this file can
// only contain, not fix) or it's producing something long enough that
// holding the ENTIRE stream hostage to it would be the worse failure
// mode. Flushing at that point routes the abandoned '$' and everything
// since through _render's fallback segment, where stripBareDollar strips
// it like any other stray '$' -- degraded (unrendered math) but bounded
// and non-blocking, not a frozen stream.
const MATH_MAX_HOLDBACK = 2000;

// ---- Fence-span protection (mirrors the $/$$ math-span protection above) ----
// A ```...``` fenced block (any language tag, including a future mermaid
// renderer) is DSL/code, not prose and not LaTeX -- the six passes below
// must never touch its interior, same reasoning as resolved $ spans.
// No escaping semantics for backticks (unlike \$), so this is simpler
// than the math scanner: plain left-to-right ``` ... ``` pairing.

function findResolvedFenceSpans(text) {
  const spans = [];
  let i = 0;
  while (true) {
    const openIdx = text.indexOf('```', i);
    if (openIdx === -1) break;
    const closeIdx = text.indexOf('```', openIdx + 3);
    if (closeIdx === -1) break; // unresolved trailing fence -- not this function's job, see findOpenFenceDelimiter
    spans.push([openIdx, closeIdx + 3]);
    i = closeIdx + 3;
  }
  return spans;
}

// Mirrors findOpenMathDelimiter's contract: -1 if every ``` in text is
// part of a complete pair; else the start index of the first unresolved
// (never-closed) opening fence -- used by push() to withhold a fence
// opened mid-stream until its close arrives, same as an open $.
function findOpenFenceDelimiter(text) {
  let i = 0;
  while (true) {
    const openIdx = text.indexOf('```', i);
    if (openIdx === -1) return -1;
    const closeIdx = text.indexOf('```', openIdx + 3);
    if (closeIdx === -1) return openIdx;
    i = closeIdx + 3;
  }
}

// Same-length blanking of every COMPLETE fence span's interior, so the
// EXISTING (unmodified) findOpenMathDelimiter/walkMathSpans can be called
// on the result without ever seeing a '$' that lives inside a code fence
// (a stray unpaired '$' inside a fence -- e.g. a cost label -- must never
// be treated as an opening math delimiter, or push() would withhold the
// whole fence until MATH_MAX_HOLDBACK's safety valve force-flushes it).
// Positions are preserved exactly (NUL can never itself look like '$' or
// resolve/open a span), so this is only ever used for the boolean
// "is anything open" check in push(), never for the actual rendered text.
function maskCompleteFences(text) {
  const spans = findResolvedFenceSpans(text);
  if (spans.length === 0) return text;
  let out = text;
  for (const [start, end] of spans) {
    out = out.slice(0, start) + '\u0000'.repeat(end - start) + out.slice(end);
  }
  return out;
}

export class NotationNormalizer {
  constructor() {
    this._buf = '';
  }

  // Streaming-safe, same holdback-margin / detect-and-retract shape as
  // every other pass in this file, decided in two tiers:
  //
  // 1. If the whole buffer's '$'s all resolve (findOpenMathDelimiter
  //    returns -1), everything through the end of the LAST resolved span
  //    is unconditionally safe -- it's a complete, alternating sequence
  //    of plain text and closed math spans, nothing left ambiguous. The
  //    trailing plain-text remainder (`tail`, guaranteed $-free -- see
  //    findLastResolvedMathEnd) still needs the ORIGINAL legacy holdback
  //    treatment, because IT can still end mid-token for any of the six
  //    bounded constructs above -- math-span resolution says nothing
  //    about whether "...the value fc" is done or about to become
  //    "...fcu" on the next push(). All five lookahead adjusters run
  //    here, not just the most common ones -- omitting any would reopen
  //    exactly the "stream tears mid-token" bugs their own comments above
  //    document fixing, just for the fallback-prose case this tier now
  //    exclusively handles.
  //
  // 2. If there's an unresolved open '$' (findOpenMathDelimiter !== -1),
  //    everything before it is safe for the same reason as tier 1 (same
  //    alternating shape, just with no trailing tail -- the cut lands
  //    precisely on a span/token boundary, never mid-word), and nothing
  //    from the open '$' onward is safe until its close arrives -- see
  //    MATH_MAX_HOLDBACK for the bounded exception.
  push(deltaText) {
    this._buf += deltaText;
    const fenceOpenAt = findOpenFenceDelimiter(this._buf);
    const mathOpenAt = findOpenMathDelimiter(maskCompleteFences(this._buf));
    const openAt =
      fenceOpenAt === -1 ? mathOpenAt :
      mathOpenAt === -1 ? fenceOpenAt :
      Math.min(fenceOpenAt, mathOpenAt);
    let cut;
    if (openAt === -1) {
      const spanEnd = findLastResolvedMathEnd(this._buf);
      const tail = this._buf.slice(spanEnd);
      let tailCut = findSafeCutIndex(tail);
      tailCut = adjustCutForAsLookahead(tail, tailCut);
      tailCut = adjustCutForSuperscriptLookahead(tail, tailCut);
      tailCut = adjustCutForSuperscriptBaseLookahead(tail, tailCut);
      tailCut = adjustCutForSubscriptBaseLookahead(tail, tailCut);
      tailCut = adjustCutForSqrtBraceLookahead(tail, tailCut);
      if (tail.length - tailCut > MAX_HOLDBACK) tailCut = tail.length - MAX_HOLDBACK;
      cut = spanEnd + tailCut;
    } else {
      cut = openAt;
      if (this._buf.length - openAt > MATH_MAX_HOLDBACK) cut = this._buf.length; // safety valve, see MATH_MAX_HOLDBACK
    }
    if (cut <= 0) return { emit: '' };
    const safePart = this._buf.slice(0, cut);
    this._buf = this._buf.slice(cut);
    return { emit: this._render(safePart) };
  }

  finish() {
    const rest = this._buf;
    this._buf = '';
    return { emit: this._render(rest) };
  }

  // Walks `text` left to right. A '$'/'$$' span with its matching close
  // ALSO inside `text` -- guaranteed for every '$' push() ever hands this
  // method, by construction of the two cut branches above -- is copied
  // through byte-for-byte with NONE of the six legacy passes applied:
  // that text is real LaTeX now, KaTeX's job, not this file's. Everything
  // else -- plain prose between/around spans, or (only reachable via
  // finish()'s end-of-stream flush, or push()'s MATH_MAX_HOLDBACK safety
  // valve) a '$' that never found a close at all -- runs through the full
  // six-pass pipeline in the same order the old single-pass push()/
  // finish() always used: Pass -2 (sqrt braces), Pass -1 (bare-psi, then
  // Greek macros), Pass 0/0.5 (subscript/superscript syntax), Pass 1/2
  // (applyReplacements' combined table), then stripBareDollar last --
  // which is exactly what strips an abandoned/never-closed '$' down to
  // nothing (unless a digit follows it, preserving genuine "$5/mo"-style
  // currency) instead of leaking a literal '$' into a reply where '$' now
  // means "LaTeX begins here" to the client.
  // [PATCH — fence protection] Unchanged from before this patch, EXCEPT
  // renamed: this is the original single-pass body, now called only on
  // text guaranteed (by _render below) to contain no fence at all. Every
  // line inside is byte-identical to the pre-patch _render.
  _renderNoFences(text) {
    let out = '', i = 0;
    while (i < text.length) {
      if (text[i] === '$' && text[i - 1] !== '\\') {
        const isDisplay = text[i + 1] === '$';
        const delim = isDisplay ? '$$' : '$';
        const close = findUnescapedDelim(text, delim, i + delim.length);
        if (close !== -1) {
          // [PATCH — bare \frac/\left/\right inside $...$] Everything else
          // in a resolved math span is still real LaTeX passed through
          // byte-for-byte -- KaTeX's job, not this file's -- but frac/
          // left/right get the SAME bare-command rescue as the fallback
          // path below runs outside $, because the model drops the
          // backslash on these two just as reliably whether or not it
          // correctly wrapped the equation in $ first (independent
          // failures -- fixing $-wrapping doesn't fix this, and vice
          // versa; both are patched here from the same captured evidence).
          const inner = text.slice(i + delim.length, close);
          const fixed = convertBareLeftRight(convertBareFrac(inner));
          out += delim + fixed + delim;
          i = close + delim.length;
          continue;
        }
      }
      let next = text.indexOf('$', i + 1);
      if (next === -1) next = text.length;
      const segment = text.slice(i, next);
      out += stripBareDollar(applyReplacements(convertLatexSuperscripts(convertLatexSubscripts(
        expandGreekSubscriptBases(expandBarePsiSubscriptBase(convertBareLeftRight(convertBareFrac(convertSqrtBraces(segment)))))))));
      i = next;
    }
    return out;
  }

  // [PATCH — fence protection] New outer layer. `text` is guaranteed (by
  // push()'s fenceOpenAt-aware cut, mirroring its existing $-openness
  // guarantee) to contain only COMPLETE ``` spans, never a dangling open
  // one. Fence interiors -- Mermaid or any other fenced code -- are
  // copied through with NONE of the six passes and NONE of the $-math
  // logic applied: that text is a diagram/code DSL, not prose or LaTeX.
  _render(text) {
    const spans = findResolvedFenceSpans(text);
    if (spans.length === 0) return this._renderNoFences(text);
    let out = '', cursor = 0;
    for (const [start, end] of spans) {
      if (start > cursor) out += this._renderNoFences(text.slice(cursor, start));
      out += text.slice(start, end); // fence, delimiters included, byte-for-byte
      cursor = end;
    }
    if (cursor < text.length) out += this._renderNoFences(text.slice(cursor));
    return out;
  }
}
