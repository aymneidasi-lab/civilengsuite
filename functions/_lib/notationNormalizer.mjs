// Streaming-safe engineering-notation normalizer.
// Same holdback-margin / detect-and-retract shape as StreamingSanitizer
// (see streamSanitizer.mjs), composed AFTER it in chat.js's relay():
// the confidentiality gate decides what may be sent at all; this only
// reshapes text that has already been cleared for sending.
//
// Two independent correction passes, both word/pattern-boundary guarded:
//  1. ASCII engineering shorthand -> Unicode subscript-substitute form
//     (fcu -> f + MODIFIER LETTER SMALL C/U, etc.)
//  2. Bare LaTeX macros with no braces/arguments -> plain Unicode
//     (\times -> x, \phi -> \u03c6, etc.)
// Both are FIXED, FINITE-LENGTH strings, so both are safe to holdback-buffer
// with a fixed margin. Anything requiring unbounded lookahead ($...$ content,
// \frac{a}{b} argument extraction) is deliberately NOT attempted here -- the
// prompt-level instruction is the primary defense for those; this is a
// bounded, low-risk safety net, not a LaTeX parser.

export const ENGINEERING_NOTATION_MAP = {
  'fcu': 'f\u1D9C\u1D58',  // f + modifier-c + modifier-u  (concrete cube strength)
  'fy':  'f\u02B8',        // f + modifier-y                (steel yield strength)
  'fc':  'f\u1D9C',        // f + modifier-c                (concrete cylinder strength)
  'fr':  'f\u02B3',        // f + modifier-r                (modulus of rupture)
  'As':  'A\u02E2',        // A + modifier-s                (steel area)
  'Ac':  'A\u1D9C',        // A + modifier-c                (concrete area)
  'Ag':  'A\u1D4D',        // A + modifier-g                (gross area)
  'Av':  'A\u1D5B',        // A + modifier-v                (shear-reinf. area)
  'Ast': 'A\u02E2\u1D57',  // A + modifier-s + modifier-t   (total steel area)
  'Pu':  'P\u1D58',        // P + modifier-u                (factored axial load)
  'Pn':  'P\u207F',        // P + modifier-n                (nominal axial capacity)
  'Mu':  'M\u1D58',        // M + modifier-u                (factored moment)
  'Mn':  'M\u207F',        // M + modifier-n                (nominal moment)
  'Mcr': 'M\u1D9C\u02B3',  // M + modifier-c + modifier-r   (cracking moment)
  'Vu':  'V\u1D58',        // V + modifier-u                (factored shear)
  'Vn':  'V\u207F',        // V + modifier-n                (nominal shear)
  'Vc':  'V\u1D9C',        // V + modifier-c                (concrete shear capacity)
  'Vs':  'V\u02E2',        // V + modifier-s                (stirrup shear capacity)
  'bo':  'b\u1D52',        // b + modifier-o                (punching-shear perimeter)
  'bw':  'b\u02B7',        // b + modifier-w                (web width)
  'qu':  'q\u1D58',        // q + modifier-u                (ultimate bearing pressure)
  'qall':'q\u1D43\u02E1\u02E1', // q + a+l+l               (allowable bearing pressure)
  'qnet':'q\u207F\u1D49\u1D57', // q + n+e+t                (net bearing pressure)
  'wu':  'w\u1D58',        // w + modifier-u                (factored distributed load)
  'wd':  'w\u1D48',        // w + modifier-d                (dead load, distributed)
  'wl':  'w\u02E1',        // w + modifier-l                (live load, distributed)
  'Ec':  'E\u1D9C',        // E + modifier-c                (concrete modulus)
  'Es':  'E\u02E2',        // E + modifier-s                (steel modulus)
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

const ALL_TRIGGERS = [...Object.keys(ENGINEERING_NOTATION_MAP), ...Object.keys(BARE_LATEX_MACROS)];
const MAX_TRIGGER_LEN = Math.max(...ALL_TRIGGERS.map(t => t.length)); // holdback margin

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
// token -- i.e. the last character that cannot itself be part of a trigger
// (not [A-Za-z], not '\', not '$'). Everything up to and including that
// character is final and safe to process; everything after it might still
// be extended by the next chunk and must stay buffered.
const NOT_TOKEN_CHAR_RE = /[^A-Za-z\\$]/;
const MAX_HOLDBACK = 64; // safety valve: bound worst-case latency if a
                         // pathological chunk has no separator at all

function findSafeCutIndex(buf) {
  for (let i = buf.length - 1; i >= 0; i--) {
    if (NOT_TOKEN_CHAR_RE.test(buf[i])) return i + 1;
  }
  return 0; // buffer is one unbroken run of letters/backslash/$ so far
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
