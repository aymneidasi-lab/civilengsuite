// functions/_lib/structuralDrawingKit.mjs
//
// Shared, zero-dependency SVG drawing kernel for every deterministic
// (non-AI) structural diagram this app renders. Extracted from
// footingDiagram.mjs — that file is the only *live* diagram module (see
// its own header; chat.js imports exclusively from it, not from
// computedFootingDiagram.mjs, which is unreferenced dead code as of this
// writing and should be deleted rather than used as a template). The
// extraction pulls out exactly the parts footingDiagram.mjs already
// proved out (esc/dimensionLine/hatchDefs/wrapText/font-stack split) so
// beamDiagram.mjs and any future columnDiagram.mjs/workshopDiagram.mjs
// reuse one tested implementation instead of a third hand-copy — the
// same copy-paste that already produced two divergent DiagramError
// classes (footingDiagram.mjs and the dead computedFootingDiagram.mjs
// each declare their own) which would silently break `instanceof`
// checks the moment code from one module ever caught an error thrown by
// the other. Every element-type module in this app should import
// DiagramError from HERE and re-export it, not redeclare it.
//
// Zero imports, no Workers-runtime-only globals (no env, no KV, no
// fetch) — pure ES2022 JS, so this runs identically in a Cloudflare
// Worker, in Node for local testing, or in any bundler. Nothing in this
// file allocates a timer, opens a connection, or holds a handle past its
// own return — see each module's own "Resource Lifecycle" note for why
// that matters on a request-scoped Worker isolate.

// ============================================================================
// Step 17 — internal documentation (see the four points this covers below)
// ============================================================================
// Safety limits (MAX_*): this file defines none itself — it only draws what
// it is given. Every MAX_* cap (MAX_BAR_GROUPS, MAX_DOWELS, MAX_LAP_ZONES,
// MAX_WORKSHOP_SECTIONS, etc.) lives in the geometry-computing module that
// owns the schema field it bounds (footingDiagram.mjs, beamDiagram.mjs,
// columnDiagram.mjs), because the safe ceiling for "how many bar groups" is
// a property of what that element type's compute function does with the
// input, not of how a dot or a tick gets drawn here. All caps ultimately
// exist for the same reason: a Cloudflare Worker request has a hard CPU
// budget (isolate killed past ~10ms of actual CPU time), and SVG string
// concatenation over an attacker- or typo-supplied unbounded array is the
// most direct way to blow that budget or return a multi-MB response body.
//
// "Drawn extent" vs. "actual cut length": this file has no opinion on the
// distinction — it draws whatever coordinates and labels a caller supplies.
// The distinction itself (relevant wherever beamDiagram.mjs/columnDiagram
// .mjs label a bar's length) is: the drawn extent is the geometric span
// between two caller-supplied X-coordinates — pure subtraction, computable
// here with zero domain knowledge. The actual cut length (cuttingLengthMM)
// is a fabrication-ready number that depends on which design code governs
// the project (hooks, bends, lap-splice class, development length by fy/
// fcu/bar condition...) — this kit, and every module built on it, never
// computes that value; it only ever displays a cuttingLengthMM the caller
// already computed and passed in. Displaying a computed span as if it were
// a fabrication length would be a silent safety defect, not a cosmetic one
// — which is why every module that shows both keeps them as visually
// distinct labels (see beamDiagram.mjs's extent-suffix handling).
//
// Fully deterministic: no `env.AI`, no model call, no network fetch, no
// randomness anywhere in this file or the three modules built on it. Every
// SVG byte this file emits is a pure function of the numbers and strings a
// caller passes in. The "confirmed against cairosvg" comments scattered
// through this codebase (see structuralLabels.mjs, footingDiagram.mjs,
// columnDiagram.mjs) refer to an external, offline check the developer ran
// in earlier sessions to verify actual rendered pixel geometry — font
// metrics, glyph coverage, overlap margins — against the arithmetic below;
// that tool is not a runtime or test-suite dependency of this codebase.
// ============================================================================

// ============================================================================
// Step 18 — future-expansion readiness (Slabs / Shear Walls / Stairs)
// ============================================================================
// This step is an ASSESSMENT, not a build: per the plan text governing this
// step, no slabDiagram.mjs/shearWallDiagram.mjs/stairDiagram.mjs is written
// here, and nothing in this file's compute/render behavior changed — every
// edit under this heading is documentation only, verified by re-running the
// full 255-check suite (134+56+65) unchanged after this file was edited and
// after syncing the edit to functions/_lib.
//
// Slabs (mesh + small extra bars): both needs are already covered by
// EXISTING exports, combined by the future slabDiagram.mjs itself, not by a
// new kit function. A 2D mesh is two calls to distributeTicks() — one per
// axis — feeding a nested loop of barDot() calls at each (x,y) pair; that is
// exactly distributeTicks()'s documented purpose (representative, evenly-
// spaced positions across a zone, capped rather than one dot per real bar),
// just applied on two axes instead of one. "Small extra bar" annotations
// (e.g. additional top steel over a support) are literally what barDot()
// already draws — diameter + scale in, a legible dot out, with MIN_BAR_PX_R
// keeping it visible at any zoom, and no assumption baked in about which
// element type is calling it.
//
// Shear Walls (vertical+horizontal mesh + boundary elements): the mesh half
// is the same distributeTicks()+barDot() combination as slabs, oriented
// along the wall's height and length instead of a footing/slab's two plan
// axes. Boundary-element ties (concentrated confinement reinforcement at a
// wall end) reuse stirrupTick() (vertical leg) and tieTickH() (horizontal
// band) unchanged — both already take plain pixel coordinates with no beam-
// or column-specific coupling; columnDiagram.mjs's own use of tieTickH() for
// a column tie is already proof this primitive generalizes across element
// types, not just a beam/column pair. A boundary zone's own outline needs no
// new kit function either: it is a plain <rect class="concrete-outline"/>
// written directly by the caller, the same way footingDiagram.mjs's own
// generic (no-numbers) path already draws shapes the kit doesn't wrap (see
// that file's gPanelFrame). barDot()'s `face` parameter only ships CSS for
// 'top'/'bottom' in kitStyleBlock() today, but this is an already-proven,
// already-used extension point, not a gap: columnDiagram.mjs appends its
// own `.bar-dot-column` rule after kitStyleBlock() and calls
// barDot(..., 'column') — a future shearWallDiagram.mjs introducing e.g. a
// 'boundary' face does the same, locally, with zero kit changes.
//
// Stairs (steps + landing + rebar): the flight profile (the zigzag step
// outline) and the bent bar line following it are genuinely element-
// specific geometry — exactly as beamDiagram.mjs's own longitudinal bar
// paths and footingDiagram.mjs's own plan/section layouts are computed in
// those files, not handed a "drawStairProfile" function by this kit. What
// IS this kit's job, it already does: hatchDefs() for the concrete hatch
// under the flight/landing, dimensionLine() for rise/run/landing
// dimensions, barDot() for bent-bar cross-section points in a stair section
// cut, esc()/wrapText()/renderCaptionAt() for labels, the .bar-top/
// .bar-bottom/.concrete-outline classes in kitStyleBlock() for styling a raw
// <path>/<polyline> stair profile and its rebar line, and scheduleTable()
// for a stair rebar schedule. A landing is a plain <rect
// class="concrete-outline"/>, same as a boundary element above — no new
// function needed.
//
// Net conclusion, verified by reading this file's actual exports against
// the three element types above (not assumed): NO new structuralDrawingKit
// .mjs function is required to unblock any of the three. Every future
// element file follows the same, already-three-times-proven pattern
// (footingDiagram.mjs, beamDiagram.mjs, columnDiagram.mjs): import the
// generic primitives that fit, write element-specific geometry + raw SVG
// locally for whatever the kit doesn't wrap, append local CSS classes after
// kitStyleBlock() for any new face/element name. This file's compute/render
// exports are therefore UNCHANGED by this step.
//
// One real, non-blocking risk flagged for whichever future step actually
// builds slabDiagram.mjs/shearWallDiagram.mjs: distributeTicks() hard-caps
// at 24 positions per axis (`Math.max(2, Math.min(maxCount, 24))`). A 2D
// mesh calls it once per axis, so a naive rows×cols loop over two maxed-out
// axes emits up to 24×24=576 barDot() calls (a <circle> plus, if labeled, a
// <text> each) for ONE mesh — call that twice for a slab's top+bottom mats,
// or add a wall's own boundary-element bars on top, and the per-request SVG
// size / CPU cost is materially different from any existing footing/beam/
// column request this app has actually load-tested (see
// خطة_المرحلة_التالية_13-18.md's Step 13 section for that methodology).
// This is NOT a kit defect — per this file's own Step 17 documentation
// above, a MAX_* ceiling belongs to the geometry-computing module that owns
// the field it bounds, and a mesh row/column count is exactly such a field.
// It just means whichever future step actually writes slabDiagram.mjs/
// shearWallDiagram.mjs must define its own MAX_MESH_ROWS/MAX_MESH_COLS (or
// an equivalent combined dot-count cap) and re-run the same real Workers
// CPU test Step 13 ran for beams, per Rule 4 ("no raising limits without
// CPU testing") — not assume 24×24 per axis is automatically safe combined.
//
// DONE (Step 19): slabDiagram.mjs built \u2014 uses this file's exports via the
// same pipeline anticipated above (distributeTicks()+barDot() for the mesh,
// no new kit function). See slabDiagram.mjs.
// DONE (Step 19): shearWallDiagram.mjs built \u2014 same pipeline (mesh via
// distributeTicks()+barDot(), boundary-element ties via tieTickH()), no new
// kit function. See shearWallDiagram.mjs.
// Step 19 also built stairDiagram.mjs, exactly as this file's own Step 18
// assessment predicted: element-specific flight-profile/waist-offset
// geometry computed locally in that file, drawn with this kit's existing
// hatchDefs()/dimensionLine()/barDot()/esc() primitives \u2014 no kit change
// needed there either. All three new modules import DiagramError from here
// and re-export it (never redeclare it), matching footingDiagram.mjs/
// beamDiagram.mjs/columnDiagram.mjs's own convention. This file's own
// compute/render exports are UNCHANGED by Step 19 \u2014 every one of the three
// new modules' MAX_MESH_ROWS/MAX_MESH_COLS caps (14, not 24) was defined
// and CPU-timed independently in its own file, per the risk this file's
// Step 18 note flagged, not assumed safe from this file's 24/axis cap alone.
// ============================================================================

export class DiagramError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DiagramError';
    this.code = code;
  }
}

// ── Units ──────────────────────────────────────────────────────────────
// All geometry in this app is stored internally in millimetres — this
// table is the single conversion factor source so a display-unit choice
// never has to touch compute code, only the fmt() call at output time.
export const MM_PER_UNIT = { mm: 1, cm: 10, m: 1000 };

// Input: a numeric value already in `unit`, and that unit's name.
// Formula: value * MM_PER_UNIT[unit].
// Output: the equivalent value in millimetres (throws DiagramError on an
// unrecognized unit rather than silently returning NaN downstream).
export function toMm(value, unit) {
  const factor = MM_PER_UNIT[unit];
  if (!factor) {
    throw new DiagramError('BAD_UNIT', `Unknown unit "${unit}" — expected one of: ${Object.keys(MM_PER_UNIT).join(', ')}.`);
  }
  return value * factor;
}

// Input: a millimetre value and a target unit. Formula: mm / MM_PER_UNIT
// [unit] (the inverse of toMm). Output: the value expressed in `unit`,
// unrounded.
export function fromMm(mm, unit) {
  return mm / MM_PER_UNIT[unit];
}

// Input: a millimetre value, a display unit, and a decimal precision.
// Formula: fromMm() then toFixed(decimals). Output: a ready-to-render
// label string with the unit suffix attached, e.g. fmt(1250, 'm', 2) ->
// "1.25m".
export function fmt(mmValue, unit, decimals = 0) {
  return `${fromMm(mmValue, unit).toFixed(decimals)}${unit}`;
}

// ── Validation ─────────────────────────────────────────────────────────
// The four guards below are this app's only line of defense between raw
// chat/API input and geometry math — every one throws DiagramError(
// 'BAD_PARAM', ...) with the offending field name and value in the message
// rather than letting a bad number propagate into NaN/Infinity SVG output,
// so callers can render the error directly instead of debugging a blank or
// malformed drawing.

// Rejects non-numbers, NaN, Infinity, and values <= 0.
export function assertFinitePositive(name, value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new DiagramError('BAD_PARAM', `"${name}" must be a positive finite number, got ${JSON.stringify(value)}.`);
  }
}

// Same as assertFinitePositive but allows exactly 0 (e.g. a zero-width
// gap, or a dowel projection of 0mm meaning "flush").
export function assertFiniteNonNegative(name, value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new DiagramError('BAD_PARAM', `"${name}" must be a non-negative finite number, got ${JSON.stringify(value)}.`);
  }
}

// Rejects non-integers and, when min/max are supplied, out-of-range
// integers — this is how every MAX_* cap in the other four modules is
// actually enforced at the input boundary (assertInt('count', n, {min:1,
// max:MAX_BAR_GROUPS})), so a schema's stated ceiling and its runtime
// enforcement can't silently drift apart into two different numbers.
export function assertInt(name, value, { min = -Infinity, max = Infinity } = {}) {
  if (!Number.isInteger(value) || value < min || value > max) {
    const range = `${min === -Infinity ? '' : `>= ${min}`}${max === Infinity ? '' : ` and <= ${max}`}`.trim();
    throw new DiagramError('BAD_PARAM', `"${name}" must be an integer${range ? ` (${range})` : ''}, got ${JSON.stringify(value)}.`);
  }
}

// Rejects any value not present in the `allowed` list — used for closed-set
// fields like face ('top'/'bottom') or shape ('closed'/'open') so a typo
// fails loudly at the boundary instead of falling through to a rendering
// branch that silently treats an unrecognized string as some default.
export function assertOneOf(name, value, allowed) {
  if (!allowed.includes(value)) {
    throw new DiagramError('BAD_PARAM', `"${name}" must be one of: ${allowed.join(', ')} — got ${JSON.stringify(value)}.`);
  }
}

// Rejects overlapping [startMM,endMM) intervals in an already-sorted-by-
// caller-order array. Used for stirrup zones (a beam has exactly one
// spacing at any given point along its length) and for any other
// "zones must tile without overlap" case. Sorts a shallow copy by start
// so caller order doesn't matter; original array/order is untouched.
export function assertNoIntervalOverlap(items, { startKey = 'startMM', endKey = 'endMM', label = 'zone' } = {}) {
  const sorted = [...items].sort((a, b) => a[startKey] - b[startKey]);
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i][startKey] < sorted[i - 1][endKey]) {
      throw new DiagramError(
        'ZONES_OVERLAP',
        `${label} overlap: [${sorted[i - 1][startKey]}, ${sorted[i - 1][endKey]}] and [${sorted[i][startKey]}, ${sorted[i][endKey]}].`,
      );
    }
  }
}

// ── Text / XML ─────────────────────────────────────────────────────────
// Escapes &, <, > only — deliberately not " — nothing in this kit places
// a label string inside a quoted attribute, only inside <text> element
// content, so that gap doesn't apply (same reasoning footingDiagram.mjs
// documents for its own copy of this function).
export function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Character-count word wrap — no real font metrics available at SVG
// generation time (this runs server-side, no DOM/canvas to measure
// against), so this is deliberately generous rather than pixel-exact:
// it will wrap one line earlier than necessary before it will ever
// overflow the intended width.
export function wrapText(text, maxCharsPerLine) {
  const words = String(text).split(' ');
  const lines = [];
  let current = '';
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length > maxCharsPerLine && current) {
      lines.push(current);
      current = word;
    } else {
      current = candidate;
    }
  }
  if (current) lines.push(current);
  return lines;
}

export function captionLineCount(caption, maxCharsPerLine = 100) {
  return wrapText(caption, maxCharsPerLine).length;
}

// Renders a (possibly multi-line) caption anchored at an EXPLICIT
// (x, startY) — unlike footingDiagram.mjs's renderCaption(), which
// closes over a module-scope fixed CANVAS and always bottom-anchors.
// Beam/column sheets have variable height (schedule table row count
// varies per element), so the caller must position this itself; call
// captionLineCount() first if you need to reserve vertical space before
// the final canvas height is known.
export function renderCaptionAt(caption, opts = {}) {
  const {
    x, startY, lang = 'en', maxCharsPerLine = 100, lineHeight = 16, className = 'sheet-caption',
  } = opts;
  const lines = wrapText(caption, maxCharsPerLine);
  const rtl = lang === 'ar';
  const anchor = rtl ? 'end' : 'start';
  return lines
    .map((line, i) => `<text x="${x}" y="${startY + i * lineHeight}" text-anchor="${anchor}" dir="${rtl ? 'rtl' : 'ltr'}" class="${className}">${esc(line)}</text>`)
    .join('\n  ');
}

// ── Fonts ──────────────────────────────────────────────────────────────
// Per-element-class font split, not a blanket global change — see the
// live bug this fixes, documented in footingDiagram.mjs/
// computedFootingDiagram.mjs's headers: putting an Arabic-first stack on
// the WHOLE drawing breaks the Latin engineering notation (B=, dia,
// mm, Ø — Latin+digits by international drafting convention regardless
// of `lang`) because the Arabic-first font doesn't carry a full Latin
// alphabet and nothing falls back for the missing glyphs. Engineering
// notation always uses defaultFontStack; product-identity / label
// strings (sheet title, view titles, bar-mark tags, captions) use
// scriptFontStack, which only actually changes when lang==='ar'.
export function fontStacks(lang) {
  const defaultFontStack = `Arial, Tahoma, 'Noto Sans Arabic', 'Noto Naskh Arabic', sans-serif`;
  const scriptFontStack = lang === 'ar'
    ? `'Noto Naskh Arabic', 'Noto Sans Arabic', Tahoma, Arial, sans-serif`
    : defaultFontStack;
  return { defaultFontStack, scriptFontStack };
}

// Shared <style> block every drawing module includes verbatim, then
// concatenates its own element-specific classes after. Keeping this
// centralized means a house-style tweak (e.g. dimension-line color)
// changes once, not once per element type.
export function kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) {
  const rtlSpacing = lang === 'ar' ? 'normal' : '0.5px';
  return `
    text { font-family: ${defaultFontStack}; }
    .dim-line        { stroke:#333; stroke-width:1; }
    .dim-tick        { stroke:#333; stroke-width:1; }
    .dim-label       { font-size:14px; fill:#111; }
    .cut-line        { stroke:#1a1a1a; stroke-width:1.4; stroke-dasharray:6,3; }
    .cut-label       { font-size:14px; font-weight:bold; fill:#111; }
    .view-title      { font-size:16px; font-weight:bold; fill:#111; letter-spacing:${rtlSpacing}; font-family: ${scriptFontStack}; }
    .sheet-title     { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .sheet-caption   { font-size:12px; fill:#444; font-family: ${scriptFontStack}; }
    .bar-bottom      { stroke:#c0392b; stroke-width:2.2; fill:none; }
    .bar-top         { stroke:#1f5aa6; stroke-width:2.2; fill:none; }
    .bar-dot-bottom  { fill:#c0392b; stroke:#7a2015; stroke-width:0.6; }
    .bar-dot-top     { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }
    .stirrup-tick    { stroke:#2f7a3d; stroke-width:1.3; }
    .stirrup-outline { fill:none; stroke:#2f7a3d; stroke-width:1.4; }
    .mark-tag-circle { fill:#ffffff; stroke:#111; stroke-width:1; }
    .mark-tag-text   { font-size:10.5px; font-weight:bold; fill:#111; }
    .leader-line     { stroke:#666; stroke-width:0.8; stroke-dasharray:2,2; }
    .concrete-outline{ fill:#f4f4f4; stroke:#1a1a1a; stroke-width:1.7; }
    .support-outline { fill:#e2e2e2; stroke:#1a1a1a; stroke-width:1.7; }
    .table-header-bg { fill:#eef1f4; }
    .table-border    { stroke:#888; stroke-width:1; fill:none; }
    .table-text      { font-size:12px; fill:#111; font-family: ${defaultFontStack}; }
    .table-text-script { font-size:12px; fill:#111; font-family: ${scriptFontStack}; }
    .table-header-txt{ font-size:12px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
  `;
}

// ── Hatching ───────────────────────────────────────────────────────────
export function hatchDefs() {
  return `
    <pattern id="soilHatch" width="10" height="10" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <line x1="0" y1="0" x2="0" y2="10" stroke="#8a7350" stroke-width="1.4"/>
    </pattern>
    <pattern id="concreteHatch" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <line x1="0" y1="0" x2="0" y2="8" stroke="#9aa0a6" stroke-width="1"/>
    </pattern>`;
}

// ── Dimension lines ────────────────────────────────────────────────────
export function dimensionLine(x1, y1, x2, y2, label, opts = {}) {
  const orientation = opts.orientation || (Math.abs(x1 - x2) >= Math.abs(y1 - y2) ? 'h' : 'v');
  const tick = opts.tick ?? 6;
  const midX = (x1 + x2) / 2, midY = (y1 + y2) / 2;
  const labelDx = orientation === 'h' ? 0 : -10;
  const labelDy = orientation === 'h' ? -6 : 4;
  const anchor = orientation === 'h' ? 'middle' : 'end';
  return `
    <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="dim-line"/>
    <line x1="${x1}" y1="${y1 - tick}" x2="${x1}" y2="${y1 + tick}" class="dim-tick"/>
    <line x1="${x2}" y1="${y2 - tick}" x2="${x2}" y2="${y2 + tick}" class="dim-tick"/>
    <text x="${midX + labelDx}" y="${midY + labelDy}" text-anchor="${anchor}" class="dim-label">${esc(label)}</text>`;
}

// ── Reinforcement primitives ───────────────────────────────────────────
export const MIN_BAR_PX_R = 3.2; // bars stay legible even when geometry scales tiny
export const MIN_STROKE_PX = 1.2;

// Cross-section bar dot. `face` selects the bar-dot-{face} class (top/
// bottom); pass any other string and it falls back to a neutral class
// name of your own construction (kitStyleBlock only defines top/bottom,
// so a caller introducing a third face must extend the style block).
export function barDot(cxPx, cyPx, diaMM, scale, face, opts = {}) {
  const r = Math.max(MIN_BAR_PX_R, (diaMM * scale) / 2);
  const cls = `bar-dot-${face}`;
  const label = opts.label != null
    ? `<text x="${cxPx}" y="${cyPx - r - 3}" text-anchor="middle" class="mark-tag-text">${esc(opts.label)}</text>`
    : '';
  return `<circle cx="${cxPx}" cy="${cyPx}" r="${r.toFixed(2)}" class="${cls}"/>${label}`;
}

// One representative stirrup leg tick in an ELEVATION view — a short
// vertical stroke from the top steel line to the bottom steel line, with
// small end caps so it reads as a closed stirrup leg rather than a bare
// dimension tick. This draws ONE tick; callers space multiple ticks
// across a zone themselves (see distributeTicks below) — capped, because
// a real zone can call for a stirrup every 100mm across several meters
// and drawing every single one both clutters the sheet and costs
// needless SVG bytes/CPU for zero added legibility over a
// representative-tick + spacing-callout convention (the same convention
// real shop drawings use).
export function stirrupTick(xPx, yTopPx, yBottomPx) {
  const cap = 4;
  return `
    <line x1="${xPx}" y1="${yTopPx}" x2="${xPx}" y2="${yBottomPx}" class="stirrup-tick"/>
    <line x1="${xPx - cap}" y1="${yTopPx}" x2="${xPx + cap}" y2="${yTopPx}" class="stirrup-tick"/>
    <line x1="${xPx - cap}" y1="${yBottomPx}" x2="${xPx + cap}" y2="${yBottomPx}" class="stirrup-tick"/>`;
}

// Horizontal counterpart of stirrupTick — added for columnDiagram.mjs's
// elevation view, where the member runs VERTICALLY (height along the
// y-axis) so tie bands cross the member horizontally, the opposite
// orientation of a beam's stirrup legs. Not a signature change to
// stirrupTick (that would silently break every existing beamDiagram.mjs
// call site, all positional) — a new, additive export instead, same
// cap-line visual convention so a tie and a stirrup read as the same
// kind of mark on any sheet that shows both.
export function tieTickH(xLeftPx, xRightPx, yPx) {
  const cap = 4;
  return `
    <line x1="${xLeftPx}" y1="${yPx}" x2="${xRightPx}" y2="${yPx}" class="stirrup-tick"/>
    <line x1="${xLeftPx}" y1="${yPx - cap}" x2="${xLeftPx}" y2="${yPx + cap}" class="stirrup-tick"/>
    <line x1="${xRightPx}" y1="${yPx - cap}" x2="${xRightPx}" y2="${yPx + cap}" class="stirrup-tick"/>`;
}

// Evenly-spaced representative tick x-positions (px) across [startPx,
// endPx], capped at maxCount — always includes both ends when count>1,
// so the drawn ticks visually bound the zone even when the real spacing
// would imply far more of them.
export function distributeTicks(startPx, endPx, maxCount) {
  const n = Math.max(2, Math.min(maxCount, 24));
  if (endPx <= startPx) return [startPx];
  const step = (endPx - startPx) / (n - 1);
  return Array.from({ length: n }, (_, i) => startPx + i * step);
}

// Small numbered bubble identifying a bar mark, with an optional dashed
// leader to the geometry it labels. `side` only affects text-anchor so
// the bubble doesn't visually collide with a line running toward it.
export function barMarkTag(xPx, yPx, markId, opts = {}) {
  const r = opts.r ?? 9;
  const leader = opts.leaderTo
    ? `<line x1="${xPx}" y1="${yPx}" x2="${opts.leaderTo.x}" y2="${opts.leaderTo.y}" class="leader-line"/>`
    : '';
  return `${leader}
    <circle cx="${xPx}" cy="${yPx}" r="${r}" class="mark-tag-circle"/>
    <text x="${xPx}" y="${yPx + 3.5}" text-anchor="middle" class="mark-tag-text">${esc(String(markId))}</text>`;
}

// ── Scale fitting ──────────────────────────────────────────────────────
// Generalizes footingDiagram.mjs's inline `Math.min(planFit, sectionFit)
// * 0.85` into a reusable helper: given N (content-size, box-size) pairs
// that must all share ONE scale (so a beam's elevation and its cross
// sections are drawn at scales that stay visually consistent with each
// other), returns the largest scale that fits every pair, times a
// margin so nothing touches its box edge.
export function fitScale(pairs, margin = 0.85) {
  let s = Infinity;
  for (const p of pairs) {
    if (p.contentW > 0) s = Math.min(s, p.boxW / p.contentW);
    if (p.contentH > 0) s = Math.min(s, p.boxH / p.contentH);
  }
  if (!Number.isFinite(s) || s <= 0) s = 1;
  return s * margin;
}

// ── Schedule table (bar-bending-schedule style) ───────────────────────
// SVG has no native <table> — this lays out header + rows manually from
// an explicit column-width spec, so callers get pixel-exact wrapping
// instead of guessing. Returns {svg, height} because callers with a
// dynamic-height canvas (beam/column sheets — row count varies per
// element, unlike footing's fixed layout) need the table's actual
// footprint to place anything below it or to size the canvas.
export function scheduleTable(x, y, colDefs, rows, opts = {}) {
  const rowH = opts.rowHeight ?? 22;
  const headH = opts.headerHeight ?? 24;
  const rtl = opts.lang === 'ar';
  const totalW = colDefs.reduce((s, c) => s + c.width, 0);
  const totalH = headH + rows.length * rowH;

  let svg = `<g class="schedule-table">`;
  svg += `<rect x="${x}" y="${y}" width="${totalW}" height="${headH}" class="table-header-bg"/>`;
  let cx = x;
  for (const col of colDefs) {
    svg += `<text x="${cx + col.width / 2}" y="${y + headH / 2 + 4}" text-anchor="middle" dir="${rtl ? 'rtl' : 'ltr'}" class="table-header-txt">${esc(col.label)}</text>`;
    cx += col.width;
  }
  rows.forEach((row, i) => {
    const ry = y + headH + i * rowH;
    if (i % 2 === 1) svg += `<rect x="${x}" y="${ry}" width="${totalW}" height="${rowH}" fill="#f8f9fa"/>`;
    let ccx = x;
    for (const col of colDefs) {
      const val = row[col.key] ?? '';
      const cls = col.script ? 'table-text-script' : 'table-text';
      svg += `<text x="${ccx + col.width / 2}" y="${ry + rowH / 2 + 4}" text-anchor="middle" dir="${rtl ? 'rtl' : 'ltr'}" class="${cls}">${esc(val)}</text>`;
      ccx += col.width;
    }
    svg += `<line x1="${x}" y1="${ry + rowH}" x2="${x + totalW}" y2="${ry + rowH}" class="table-border" stroke-width="0.5" stroke="#ccc"/>`;
  });
  cx = x;
  for (const col of colDefs) {
    svg += `<line x1="${cx}" y1="${y}" x2="${cx}" y2="${y + totalH}" class="table-border" stroke-width="0.5" stroke="#ccc"/>`;
    cx += col.width;
  }
  svg += `<line x1="${x + totalW}" y1="${y}" x2="${x + totalW}" y2="${y + totalH}" class="table-border" stroke-width="0.5" stroke="#ccc"/>`;
  svg += `<rect x="${x}" y="${y}" width="${totalW}" height="${totalH}" class="table-border"/>`;
  svg += `</g>`;
  return { svg, height: totalH, width: totalW };
}

// ── Data URI ───────────────────────────────────────────────────────────
// Single shared implementation — footingDiagram.mjs and
// computedFootingDiagram.mjs each currently declare their own byte-
// identical copy of this one-liner; every new module should import it
// from here instead of adding a fourth copy.
export function svgToDataUri(svgString) {
  return 'data:image/svg+xml,' + encodeURIComponent(svgString);
}
