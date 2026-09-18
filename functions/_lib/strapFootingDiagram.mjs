// functions/_lib/strapFootingDiagram.mjs
//
// Deterministic, zero-AI SVG generator for a strap (cantilever) combined-
// footing system: two independent, physically SEPARATE rectangular pads
// — one exterior/eccentric (its column sits near a property-line edge,
// so a normal isolated footing would either overhang the line or bear
// unevenly), one interior (column centered on its own pad) — tied
// together by a rigid STRAP BEAM spanning the clear gap between them.
// The strap transfers moment from the eccentric footing into the
// interior one so both end up with (approximately) uniform soil
// pressure, without a slab of concrete filling the gap the way
// footingDiagram.mjs's 'combined' type draws.
//
// New-element track, Part 2 candidate 3. Closes the third and last
// documented gap trapezoidalFootingDiagram.mjs's own header named:
// footing_pro's product copy lists Rectangular / Trapezoidal / Strap as
// three independent standalone combined-footing options; footingDiagram
// .mjs's 'combined' only ever draws the rectangular one,
// trapezoidalFootingDiagram.mjs added the second, this module is the
// third and closes the set.
//
// Same philosophy as every other element module in this app: every
// dimension, bar position, and count in the output is arithmetic on the
// KB data supplied, never a model's guess, never a computed soil-bearing
// solve. This module owns compute+render only.
//
// FIDELITY REVISION (this pass): checked directly against the Egyptian
// Code (ECP 203) detail guide's own Fig. 6-16 ("تفاصيل تسليح قاعدة جار
// باستخدام كمرة رابطة" — reinforcement detail of a boundary/neighbor
// footing using a strap beam) at the caller's request. Two elements that
// figure labels explicitly were entirely absent from every view this
// module drew: column dowels/starter bars ("أشاير العمود") continuing
// through the strap depth into the column, and shrinkage/skin bars
// around the strap's own perimeter ("اسياخ انكماش ... على المحيط"). Both
// are now REQUIRED inputs (see footing1/footing2.dowels and
// strap.shrinkageBarDiaMM/shrinkageBarCount below) — a breaking contract
// change, deliberately: this file's own "never draw a defaulted design
// value" rule means there is no honest silent default for "how many
// dowels", so every existing caller must start supplying real numbers
// for these two elements rather than the drawing quietly continuing to
// omit them. A new SECTION_1_1 view (renderSection11) was added
// specifically to show both together with the strap's own top/bottom
// steel, matching that same reference figure's own top-of-page section.
// The strap's top/bottom bars, previously drawn stopping dead at the
// clear-gap edge, now extend to each column's own centerline (a pure
// geometry fix using data already in the contract, spanMM/colCenterMM —
// no new field) with a schematic anchorage hook, because Fig. 6-16 shows
// this reinforcement continuing into and anchoring within the column
// cage, not terminating in open air. The EXACT bar-by-bar arrangement
// within that cage (which strap bar nests between which column bar) is
// NOT reproduced — that is a shop-drawing-level sequencing detail
// ("ترتيب دخول تسليح الكمرة الرابطة داخل تسليح العمود" in the same
// figure) this parametric schematic has no column-bar-layout input to
// derive it from; the caption says so explicitly rather than silently
// under-drawing it. Two further elements the same figure appears to show
// — a plain-concrete footing step wider than the reinforced pad
// ("القاعده العاديه" vs "...المسلحه"), and a primary/secondary bottom-
// mesh split with an anchorage-length proviso — are exposed as OPTIONAL,
// caller-supplied fields (plainProjectionMM, secondaryReinforcementNote)
// rather than hardcoded: the source photo's own small print does not
// give this module's author enough confidence in the exact percentage or
// ECP clause number to bake either as a default without risking a wrong
// number reaching a construction set. See each field's own comment below.
//
// VISUAL-FIDELITY REVISION (this pass): caller asked for a drawing engine
// that produces execution-grade output with real color differentiation
// between reinforcement element families AND real thickness
// differentiation between bar sizes ("بتمييز لوني بين عناصر التسليح
// المختلفة وبتخانات مختلفه") — supplied 4 reference images, one of which
// (the labeled Section A-A leader-line legend) this module's own
// renderStrapCrossSection already tracked closely. Two concrete gaps,
// both verified against this module's own previously-generated output,
// not assumed: (1) EVERY bar-cross-section dot rendered at the identical
// r="3.20" regardless of its real mm diameter (a 12mm shrinkage dot, a
// 16mm top-bar dot, a 20mm bottom-bar dot all measured the same), and
// several existing stroke-width="N" attempts at line-weight variation
// (mesh-line, the plan-view bar-top/bar-bottom, the stirrup ticks, the
// long-section shrinkage line) were SILENTLY NO-OPS in any spec-correct
// SVG renderer — a bare presentation attribute has lower CSS specificity
// than the very class= on the same element that also sets stroke-width,
// verified by rendering both forms through librsvg and diffing the
// rasterized pixel output, not asserted from memory; (2) the footing's
// own bottom mesh (F1/F2) and the strap's own bottom bars (SB1) — two
// different schedule marks — rendered in the identical red, the one
// place this sheet asked to differentiate elements that did not.
// Fixed: a new diameter-to-pixel weight mapping (barLineWidthPx/
// barDotRadiusPx, bounded/legible, NOT literal diaMM*scale — see that
// block's own header for why literal-to-scale is wrong at this sheet's
// typical scale) now drives every bar line/dot in every view, always via
// `style="stroke-width:...px"` (never a bare attribute, for the cascade
// reason above); mesh gets its own color (violet, #7d3c98) and its own
// .bar-dot-mesh/.mesh-line treatment, no longer borrowing bar-bottom's
// red; a new sheet-wide, scale-independent REINFORCEMENT KEY legend row
// (renderLegendRow) sits under the title, covering all six families the
// schedule's eight marks reduce to. A per-row schedule color swatch was
// considered and deliberately NOT added: scheduleTable()'s own row
// layout (height, striping) lives in the shared kit this file doesn't
// have; hand-replicating its pixel geometry from observed output alone
// would silently drift out of sync if that kit's own layout ever
// changes, with no error to catch it — flagged as a kit-level follow-up
// (a rowAccentColor field on scheduleTable's own row shape) rather than
// hacked around here. See strapFootingDiagram_dxf.mjs's own header for
// the parallel DXF-side pass (LWPolyline-based real line width, a new
// REBAR-MESH-LINE layer) and for why DXF lineweight itself (group 370)
// could not be touched from either file.
//
// SCOPE (v1, as revised):
//   - exactly TWO footings, one exterior (eccentric, column offset from
//     its pad by a caller-supplied edge distance) and one interior
//     (column always centered on its own pad — the real, near-universal
//     convention for the far end of a strap system; an eccentric
//     INTERIOR footing is a different, rarer detail this module doesn't
//     model).
//   - both footings sit on the SAME centerline as the strap beam (no
//     offset across the perpendicular/breadth axis) — same "single
//     shared axis" simplification trapezoidalFootingDiagram.mjs makes
//     for its own two columns.
//   - one representative bottom mesh layer per footing pad (isotropic:
//     one diameter+spacing pair, applied in both plan directions — same
//     scope limit footingDiagram.mjs's own isolated type documents for
//     its dia field, simplified further here to one spacing instead of
//     separate long/short spacings), plus that pad's own column dowels
//     (perimeter-distributed by count — not a full column bar schedule
//     with individually marked corner/face bars) and, optionally, a
//     wider plain-concrete step beneath it.
//   - the strap beam itself: constant width/depth, one top bar group,
//     one bottom bar group, one shrinkage/skin bar group, one stirrup
//     spacing — a typical-section schematic, exactly the scope note
//     every beam-like member in this app already carries (see
//     beamDiagram.mjs's own basic mode), now three bar groups instead of
//     two, still a fixed, finite, named set rather than an arbitrary
//     caller-defined list.
// NOT modeled, on purpose (same explicit-scope-boundary convention every
// sibling module's header already uses):
//   - more than two footings, or a footing offset across the breadth
//     axis from the strap centerline.
//   - an eccentric INTERIOR footing, a sloped strap, a strap that also
//     bears on soil (this module always treats the strap as spanning a
//     clear, non-bearing gap — see NOT_A_STRAP below, which redirects a
//     near-zero gap to footingDiagram.mjs's own 'combined' type instead
//     of silently drawing a degenerate strap).
//   - pedestals, a second (top) mesh mat within a footing pad itself
//     (distinct from the strap's own top bars, which ARE modeled), the
//     column's own full bar-mark schedule (corner vs. face bar
//     distinction), or more than one bar group/stirrup zone per family
//     on the strap — same "schematic, not shop drawing" scope every
//     footing/beam module in this app already states, now drawn around
//     three strap bar families and two footings' worth of dowels instead
//     of the smaller set this header previously described.
//   - a computed soil-bearing check or a solver that derives pad sizes
//     from column loads to equalize pressure (the real-world REASON a
//     strap footing is chosen) — this module draws whatever dimensions
//     the caller supplies; verifying they actually equalize bearing
//     pressure is the KB/design layer's job, exactly like
//     trapezoidalFootingDiagram.mjs never decides B1/B2 itself.
//   - a computed dowel/bar development or lap-splice LENGTH (concrete
//     grade, bar type, and code-table dependent) — schedule rows for
//     dowels show an em-dash in the length column rather than a
//     fabricated number, same "never compute cuttingLengthMM" contract
//     structuralDrawingKit.mjs's own header states generally.
//
// ── INPUT CONTRACT (what the KB layer should hand this module) ─────────
// {
//   unit?: 'mm'|'cm'|'m',                 // default 'mm'
//   strapId: string,                      // e.g. "STF-1"
//   spanMM: number,                       // column-CENTER to column-
//                                         // CENTER distance along the
//                                         // strap axis
//   footing1: {                           // exterior / eccentric pad
//     widthMM,                            // plan dimension ALONG the
//                                         // strap axis
//     breadthMM,                          // plan dimension
//                                         // PERPENDICULAR to the strap
//                                         // axis
//     thicknessMM, coverMM,
//     colWidthMM,                        // column dimension
//                                         // PERPENDICULAR to the strap
//                                         // axis
//     colDepthMM,                        // column dimension ALONG the
//                                         // strap axis
//     edgeMM,                            // clear distance from
//                                         // column1's OUTER face (the
//                                         // face away from footing2,
//                                         // i.e. toward the property
//                                         // line) to the pad's own
//                                         // outer edge — the smaller
//                                         // this is, the more eccentric
//                                         // the footing; 0 means the
//                                         // column face sits flush with
//                                         // the pad's outer edge
//     mesh: { diameterMM, spacingMM },   // one bottom-mesh spec, both
//                                         // plan directions
//     dowels: { diameterMM, count },     // REQUIRED — column starter
//                                         // bars, perimeter-distributed
//                                         // around colWidthMM x
//                                         // colDepthMM (count>=4, corners
//                                         // always included)
//     plainProjectionMM?: number,        // OPTIONAL, default 0 — plain-
//                                         // concrete step beyond the
//                                         // reinforced pad edge, every
//                                         // side
//     secondaryReinforcementNote?: string, // OPTIONAL — verbatim
//                                         // caller-supplied anchorage/
//                                         // code-clause note rendered
//                                         // under this pad's mesh dims;
//                                         // never generated internally
//   },
//   footing2: {                          // interior pad, column CENTERED
//     widthMM, breadthMM, thicknessMM, coverMM,
//     colWidthMM, colDepthMM,
//     mesh: { diameterMM, spacingMM },
//     dowels: { diameterMM, count },     // REQUIRED, same shape as footing1's
//     plainProjectionMM?: number,        // OPTIONAL, same as footing1's
//     secondaryReinforcementNote?: string, // OPTIONAL, same as footing1's
//   },
//   strap: {                             // the connecting beam
//     widthMM,                           // plan width (perpendicular
//                                         // to the strap axis)
//     depthMM,                           // total beam depth (vertical)
//     coverMM,
//     topBarDiaMM, topBarCount,
//     bottomBarDiaMM, bottomBarCount,
//     shrinkageBarDiaMM, shrinkageBarCount, // REQUIRED — perimeter/skin
//                                         // bars; count must be even
//                                         // (split in pairs across the
//                                         // two side faces)
//     stirrupDiaMM, stirrupSpacingMM,
//   },
//   sectionThrough?: 1 | 2,              // default 1 — which footing's
//                                         // transverse section AND new
//                                         // SECTION 1-1 (column+strap)
//                                         // are shown (mirrors
//                                         // footingDiagram.mjs/
//                                         // trapezoidalFootingDiagram.mjs's
//                                         // own sectionThrough field)
// }
//
// ── Coordinate convention ───────────────────────────────────────────────
// One shared global X axis along the strap direction: x=0 is column1's
// CENTER, x=spanMM is column2's CENTER (identical convention to
// trapezoidalFootingDiagram.mjs's own col1.offsetMM/col2.offsetMM — this
// module reuses it directly rather than inventing a third). Footing1's
// pad is positioned from column1's OUTER face (x = -colDepthMM1/2) minus
// edgeMM1; footing2's pad is always centered on column2 (x = spanMM).
//
// ── /diagram and /rebar wiring ──────────────────────────────────────────
// Wired the same way every prior new-element step in this app was:
// parseDiagramCommand below (leading token "strap") + diagramCommandRouter
// .mjs (import + PARSERS[] + ALL_SUPPORTED_TYPES[]) + chat.js's three
// existing dispatch tables (DIAGRAM_TYPE_RENDERERS,
// DIAGRAM_TYPE_ERROR_MESSAGE, REBAR_ELEMENT_DISPATCH) + a new
// strapFootingDiagramErrorMessage() AR wrapper inside chat.js, matching
// every sibling wrapper's exact shape. Per this app's own New-element-
// track convention, all four link points are one non-optional unit of
// work — see this file's own CHANGELOG.md entry for the actual wiring
// commit, not a separate "link it later" step.
//
// Resource lifecycle: pure/synchronous, zero imports beyond the shared
// kit, no timers/fetch/KV/handles — same as every sibling module.
// Fully deterministic: no env.AI, no model call, no randomness anywhere
// in this file.

import {
  DiagramError, toMm, assertFinitePositive, assertFiniteNonNegative, assertInt,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, fitScale, scheduleTable, stirrupTick,
  distributeTicks, svgToDataUri, wrapText,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ──────────────────────────────────────────────────────
// Same role as every sibling module's MAX_*/MIN_*: bound worst-case loop
// counts and input ranges so one request can't build an oversized SVG,
// blow a Worker CPU-time budget, or describe a shape that cannot be
// drawn sanely. None of these encode a design rule — they are drawing-
// safety bounds only, same disclaimer every sibling module's own caps
// section carries.
const MIN_SPAN_MM = 1500, MAX_SPAN_MM = 12000;
const MIN_PAD_DIM_MM = 500, MAX_PAD_DIM_MM = 4000; // width & breadth, per pad
const MIN_THICKNESS_MM = 300, MAX_THICKNESS_MM = 1200;
const MIN_EDGE_MM = 0, MAX_EDGE_MM = 1000;
const MIN_COL_SIDE_MM = 150, MAX_COL_SIDE_MM = 1200;
const MIN_MESH_SPACING_MM = 75, MAX_MESH_SPACING_MM = 400; // matches slabDiagram.mjs's own bound
const MAX_MESH_LINES = 12; // per direction, per pad
// Below this clear gap between the two pads, this is functionally a
// rectangular combined footing wearing a strap-footing label, not a real
// strap system (no meaningful non-bearing span for the beam to span) —
// see NOT_A_STRAP below. Same role as trapezoidalFootingDiagram.mjs's
// own MIN_TAPER_MM guarding against a "trapezoid" that is really a
// rectangle.
const MIN_CLEAR_STRAP_MM = 200;
const MIN_STRAP_WIDTH_MM = 200, MAX_STRAP_WIDTH_MM = 1000;
const MIN_STRAP_DEPTH_MM = 300, MAX_STRAP_DEPTH_MM = 1500;
const MIN_BAR_DIA_MM = 10, MAX_BAR_DIA_MM = 32;
const MIN_BAR_COUNT = 2, MAX_BAR_COUNT = 8;
const MIN_STIRRUP_DIA_MM = 6, MAX_STIRRUP_DIA_MM = 16;
const MIN_STIRRUP_SPACING_MM = 50, MAX_STIRRUP_SPACING_MM = 300;
// Dowels (column starter bars, footing1 AND footing2 — ECP 203 detail
// guide Fig. 6-16 shows these at the column/strap junction; see this
// file's header for the citation). Same physical bar-size range as the
// strap's own top/bottom bars — reused, not duplicated.
const MIN_DOWEL_DIA_MM = MIN_BAR_DIA_MM, MAX_DOWEL_DIA_MM = MAX_BAR_DIA_MM;
const MIN_DOWEL_COUNT = 4, MAX_DOWEL_COUNT = 16; // 4 = one per corner, the minimum for any rectangular column
// Shrinkage/skin bars around the strap's perimeter (Fig. 6-16's own
// "اسياخ انكماش ... على المحيط"). Must be even: split in pairs across the
// strap's two side faces, one per depth level (enforced below).
const MIN_SHRINK_COUNT = 2, MAX_SHRINK_COUNT = 8;
// Optional plain-concrete step beyond the reinforced pad edge (Fig.
// 6-16's own "طول/عرض القاعده العاديه" vs "...المسلحه" pair) — drawing-
// safety bound only, same role MAX_EDGE_MM already plays; 0 (the
// default) means "no step", identical to every caller before this field
// existed.
const MAX_PLAIN_PROJECTION_MM = 300;

// ── Compute ──────────────────────────────────────────────────────────

// Places `count` points evenly (by arc length) around a rectangle's
// perimeter, corners ALWAYS included first (the near-universal real
// convention: a rectangular column's dowels/verticals always include one
// bar per corner; any count beyond 4 is extra bars distributed along the
// four faces, largest-remainder-allocated by face length so a
// deep-but-narrow column doesn't get its extras clumped on the short
// faces). Pure arithmetic on (halfX, halfY, count) — no design decision,
// same "arithmetic on supplied data" contract every other geometry
// helper in this file already follows. Local coordinate frame: origin at
// the rectangle's own center, x = the column's DEPTH axis (ALONG the
// strap axis, matching colDepthMM's own documented meaning), y = the
// column's WIDTH axis (PERPENDICULAR to the strap axis, matching
// colWidthMM's own documented meaning) — same (x=depth,y=width) pairing
// every other per-column field in this file already uses, so a caller
// never has to remember a second, dowel-specific axis convention.
function rectPerimeterPoints(halfX, halfY, count) {
  const corners = [
    { xLocalMM: -halfX, yLocalMM: -halfY },
    { xLocalMM: halfX, yLocalMM: -halfY },
    { xLocalMM: halfX, yLocalMM: halfY },
    { xLocalMM: -halfX, yLocalMM: halfY },
  ];
  if (count <= 4) return corners.slice(0, count);

  const edgeLenX = 2 * halfX; // bottom/top edges run along x
  const edgeLenY = 2 * halfY; // right/left edges run along y
  const edges = [
    { from: corners[0], to: corners[1], len: edgeLenX },
    { from: corners[1], to: corners[2], len: edgeLenY },
    { from: corners[2], to: corners[3], len: edgeLenX },
    { from: corners[3], to: corners[0], len: edgeLenY },
  ];
  const totalLen = 2 * (edgeLenX + edgeLenY);
  const extra = count - 4;

  // Largest-remainder allocation so per-edge extra counts sum to exactly
  // `extra` regardless of rounding (same reason dimensionLine-style
  // proportional splits elsewhere in this app avoid a naive Math.round
  // per bucket).
  const raw = edges.map((e) => (extra * e.len) / totalLen);
  const base = raw.map(Math.floor);
  let assigned = base.reduce((a, b) => a + b, 0);
  const remainders = raw
    .map((r, i) => [r - base[i], i])
    .sort((a, b) => b[0] - a[0]);
  for (let i = 0; assigned < extra; i++, assigned++) base[remainders[i][1]] += 1;

  const points = [...corners];
  edges.forEach((edge, i) => {
    const n = base[i];
    for (let k = 1; k <= n; k++) {
      const t = k / (n + 1);
      points.push({
        xLocalMM: edge.from.xLocalMM + (edge.to.xLocalMM - edge.from.xLocalMM) * t,
        yLocalMM: edge.from.yLocalMM + (edge.to.yLocalMM - edge.from.yLocalMM) * t,
      });
    }
  });
  return points;
}

// Shared footing-pad field validation (both footing1 and footing2 use
// this for the fields they have in common); positioning along the strap
// axis (the one genuine difference between the eccentric and the
// centered pad) is handled separately in computeStrapFootingGeometry,
// right after this returns.
function readFootingBase(tag, raw, unit) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', `"${tag}" is required: an object with widthMM, breadthMM, thicknessMM, coverMM, colWidthMM, colDepthMM, mesh.`);
  }
  const widthMM = toMm(raw.widthMM, unit);
  const breadthMM = toMm(raw.breadthMM, unit);
  const thicknessMM = toMm(raw.thicknessMM, unit);
  const coverMM = toMm(raw.coverMM, unit);
  const colWidthMM = toMm(raw.colWidthMM, unit);
  const colDepthMM = toMm(raw.colDepthMM, unit);
  for (const [name, v] of Object.entries({
    widthMM, breadthMM, thicknessMM, coverMM, colWidthMM, colDepthMM,
  })) {
    assertFinitePositive(`${tag}.${name}`, v);
  }
  if (widthMM < MIN_PAD_DIM_MM || widthMM > MAX_PAD_DIM_MM) {
    throw new DiagramError('BAD_PARAM', `"${tag}.widthMM" must be between ${MIN_PAD_DIM_MM}mm and ${MAX_PAD_DIM_MM}mm, got ${widthMM}mm.`);
  }
  if (breadthMM < MIN_PAD_DIM_MM || breadthMM > MAX_PAD_DIM_MM) {
    throw new DiagramError('BAD_PARAM', `"${tag}.breadthMM" must be between ${MIN_PAD_DIM_MM}mm and ${MAX_PAD_DIM_MM}mm, got ${breadthMM}mm.`);
  }
  if (thicknessMM < MIN_THICKNESS_MM || thicknessMM > MAX_THICKNESS_MM) {
    throw new DiagramError('BAD_PARAM', `"${tag}.thicknessMM" must be between ${MIN_THICKNESS_MM}mm and ${MAX_THICKNESS_MM}mm, got ${thicknessMM}mm.`);
  }
  if (colWidthMM < MIN_COL_SIDE_MM || colWidthMM > MAX_COL_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"${tag}.colWidthMM" must be between ${MIN_COL_SIDE_MM}mm and ${MAX_COL_SIDE_MM}mm, got ${colWidthMM}mm.`);
  }
  if (colDepthMM < MIN_COL_SIDE_MM || colDepthMM > MAX_COL_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"${tag}.colDepthMM" must be between ${MIN_COL_SIDE_MM}mm and ${MAX_COL_SIDE_MM}mm, got ${colDepthMM}mm.`);
  }
  // Column must physically fit within its own pad's cross-section
  // (perpendicular axis) — same check, same code, as footingDiagram
  // .mjs's own isolated-footing colB>=B guard.
  if (colWidthMM >= breadthMM) {
    throw new DiagramError('COLUMN_TOO_WIDE', `"${tag}.colWidthMM" (${colWidthMM}mm) must be smaller than "${tag}.breadthMM" (${breadthMM}mm).`);
  }

  if (!raw.mesh || typeof raw.mesh !== 'object') {
    throw new DiagramError('BAD_PARAM', `"${tag}.mesh" is required: { diameterMM, spacingMM }.`);
  }
  const meshDiaMM = toMm(raw.mesh.diameterMM, unit);
  const meshSpacingMM = toMm(raw.mesh.spacingMM, unit);
  assertFinitePositive(`${tag}.mesh.diameterMM`, meshDiaMM);
  assertFinitePositive(`${tag}.mesh.spacingMM`, meshSpacingMM);
  if (meshSpacingMM < MIN_MESH_SPACING_MM || meshSpacingMM > MAX_MESH_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"${tag}.mesh.spacingMM" must be between ${MIN_MESH_SPACING_MM}mm and ${MAX_MESH_SPACING_MM}mm, got ${meshSpacingMM}mm.`);
  }

  // Two-way mesh room check, both plan directions — same "cover + dia
  // leaves no room" shape every sibling module's own NO_ROOM_FOR_BARS
  // check uses.
  const firstW = coverMM + meshDiaMM / 2, lastW = widthMM - coverMM - meshDiaMM / 2;
  if (lastW <= firstW) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) and mesh bar diameter (${meshDiaMM}mm) leave no room for reinforcement across "${tag}"'s ${widthMM}mm width.`);
  }
  const firstB = coverMM + meshDiaMM / 2, lastB = breadthMM - coverMM - meshDiaMM / 2;
  if (lastB <= firstB) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) and mesh bar diameter (${meshDiaMM}mm) leave no room for reinforcement across "${tag}"'s ${breadthMM}mm breadth.`);
  }

  // Bars running ALONG the breadth axis (drawn as vertical lines in
  // local pad space), spaced along the width; and bars running ALONG
  // the width axis (horizontal lines), spaced along the breadth — the
  // classic two-way footing mesh, both directions constant-length since
  // (unlike trapezoidalFootingDiagram.mjs's own shape) a strap pad is a
  // plain rectangle.
  const alongBreadthCount = Math.max(2, Math.min(Math.floor((lastW - firstW) / meshSpacingMM) + 1, MAX_MESH_LINES));
  const alongBreadthStep = alongBreadthCount > 1 ? (lastW - firstW) / (alongBreadthCount - 1) : 0;
  const alongBreadthLines = Array.from({ length: alongBreadthCount }, (_, i) => ({
    xLocalMM: firstW + i * alongBreadthStep, drawnLengthMM: lastB - firstB,
  }));
  const alongWidthCount = Math.max(2, Math.min(Math.floor((lastB - firstB) / meshSpacingMM) + 1, MAX_MESH_LINES));
  const alongWidthStep = alongWidthCount > 1 ? (lastB - firstB) / (alongWidthCount - 1) : 0;
  const alongWidthLines = Array.from({ length: alongWidthCount }, (_, i) => ({
    yLocalMM: firstB + i * alongWidthStep, drawnLengthMM: lastW - firstW,
  }));

  // ── Column dowels / starter bars (أشاير العمود) ───────────────────────
  // Required, not optional: Fig. 6-16 shows these at every column/strap
  // junction it details, so a footing drawn without them is drawing an
  // incomplete joint, the same category of omission mesh-less footing
  // would already be rejected for above. Perimeter placement only
  // (rectPerimeterPoints) — this module still does not model a full
  // column bar SCHEDULE (face vs. corner bar marks, individual cover
  // ties) any more than it modeled one before; it now shows where the
  // bars ARE, not a column shop drawing.
  if (!raw.dowels || typeof raw.dowels !== 'object') {
    throw new DiagramError('BAD_PARAM', `"${tag}.dowels" is required: { diameterMM, count } — column starter bars through the strap/column junction (ECP 203 detail guide Fig. 6-16).`);
  }
  const dowelDiaMM = toMm(raw.dowels.diameterMM, unit);
  assertFinitePositive(`${tag}.dowels.diameterMM`, dowelDiaMM);
  if (dowelDiaMM < MIN_DOWEL_DIA_MM || dowelDiaMM > MAX_DOWEL_DIA_MM) {
    throw new DiagramError('BAD_PARAM', `"${tag}.dowels.diameterMM" must be between ${MIN_DOWEL_DIA_MM}mm and ${MAX_DOWEL_DIA_MM}mm, got ${dowelDiaMM}mm.`);
  }
  const dowelCount = Math.round(Number(raw.dowels.count));
  assertInt(`${tag}.dowels.count`, dowelCount, { min: MIN_DOWEL_COUNT, max: MAX_DOWEL_COUNT });
  // Dowels must fit within the column's own cross-section the same way
  // mesh bars must fit within the pad's — reusing the identical
  // cover-less "does the bar physically fit the member" shape (dowels
  // sit at the column PERIMETER, not inset by the pad's own coverMM,
  // since a column cage has its own, separate cover the KB/design layer
  // owns — this only guards against a diameter too large for the
  // column's own smallest side to physically contain).
  if (dowelDiaMM >= Math.min(colWidthMM, colDepthMM)) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `"${tag}.dowels.diameterMM" (${dowelDiaMM}mm) leaves no room within the column's own ${Math.min(colWidthMM, colDepthMM)}mm smaller side.`);
  }
  const dowelPoints = rectPerimeterPoints(colDepthMM / 2, colWidthMM / 2, dowelCount);

  // ── Optional plain-concrete step (القاعده العاديه vs القاعده المسلحه) ──
  // Off (0) by default — identical drawn result to every caller written
  // before this field existed. When > 0, the plain pad is this many mm
  // WIDER than the reinforced pad on every side, matching Fig. 6-16's own
  // two-dimension-pair convention (separate "طول/عرض القاعده العاديه" and
  // "...المسلحه" labels bracketing the same footing).
  const plainProjectionMM = raw.plainProjectionMM != null ? toMm(raw.plainProjectionMM, unit) : 0;
  assertFiniteNonNegative(`${tag}.plainProjectionMM`, plainProjectionMM);
  if (plainProjectionMM > MAX_PLAIN_PROJECTION_MM) {
    throw new DiagramError('BAD_PARAM', `"${tag}.plainProjectionMM" must be at most ${MAX_PLAIN_PROJECTION_MM}mm, got ${plainProjectionMM}mm.`);
  }
  const plain = plainProjectionMM > 0
    ? { widthMM: widthMM + 2 * plainProjectionMM, breadthMM: breadthMM + 2 * plainProjectionMM, projectionMM: plainProjectionMM }
    : null;

  // ── Optional secondary-reinforcement anchorage note ───────────────────
  // Fig. 6-16 asterisks a specific ECP-clause anchorage proviso next to
  // its primary/secondary bottom-mesh split (see this file's header for
  // why the exact percentage/clause number is NOT hardcoded here). Pure
  // passthrough string — never generated, never defaulted; omitted
  // entirely unless the caller supplies it, so no unverified numeric
  // code citation can appear on a drawing this module produced.
  let secondaryReinforcementNote = null;
  if (raw.secondaryReinforcementNote != null) {
    if (typeof raw.secondaryReinforcementNote !== 'string' || !raw.secondaryReinforcementNote.trim()) {
      throw new DiagramError('BAD_PARAM', `"${tag}.secondaryReinforcementNote" must be a non-empty string when supplied.`);
    }
    secondaryReinforcementNote = raw.secondaryReinforcementNote.trim();
  }

  return {
    widthMM, breadthMM, thicknessMM, coverMM, colWidthMM, colDepthMM,
    mesh: {
      dia: meshDiaMM, spacing: meshSpacingMM, alongBreadthLines, alongWidthLines,
    },
    dowels: { dia: dowelDiaMM, count: dowelCount, points: dowelPoints },
    plain,
    secondaryReinforcementNote,
  };
}

export function computeStrapFootingGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Strap footing input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.strapId != null ? String(raw.strapId) : 'STF';

  const spanMM = toMm(raw.spanMM, unit);
  assertFinitePositive('spanMM', spanMM);
  if (spanMM < MIN_SPAN_MM || spanMM > MAX_SPAN_MM) {
    throw new DiagramError('BAD_PARAM', `"spanMM" must be between ${MIN_SPAN_MM}mm and ${MAX_SPAN_MM}mm, got ${spanMM}mm.`);
  }

  const f1 = readFootingBase('footing1', raw.footing1, unit);
  const f2 = readFootingBase('footing2', raw.footing2, unit);

  const edgeMM = toMm(raw.footing1 && raw.footing1.edgeMM, unit);
  assertFiniteNonNegative('footing1.edgeMM', edgeMM);
  if (edgeMM > MAX_EDGE_MM) {
    throw new DiagramError('BAD_PARAM', `"footing1.edgeMM" must be at most ${MAX_EDGE_MM}mm, got ${edgeMM}mm.`);
  }

  // Footing1 (eccentric): positioned from column1's OUTER face (x =
  // -colDepthMM/2) minus the caller-supplied edge distance.
  const f1StartMM = -f1.colDepthMM / 2 - edgeMM;
  const f1EndMM = f1StartMM + f1.widthMM;
  // The column's INNER face (toward footing2) must not stick out past
  // the pad's own inner edge — the one genuine position-dependent
  // bounds check this module needs (footing2 can't have the equivalent
  // problem: it is always centered on its own pad by construction).
  if (f1.colDepthMM / 2 > f1EndMM) {
    throw new DiagramError(
      'COLUMN_OUT_OF_BOUNDS',
      `"footing1" (edgeMM=${edgeMM}mm, colDepthMM=${f1.colDepthMM}mm) needs at least ${(f1.colDepthMM / 2 + edgeMM).toFixed(1)}mm of widthMM on the column's inner side, but widthMM is only ${f1.widthMM}mm.`,
    );
  }

  // Footing2 (interior): always centered on column2, i.e. on x=spanMM.
  const f2StartMM = spanMM - f2.widthMM / 2;
  const f2EndMM = spanMM + f2.widthMM / 2;

  if (f1EndMM > f2StartMM) {
    throw new DiagramError('FOOTINGS_OVERLAP', `footing1 and footing2 overlap along the strap's span given their widths, edge distance, and spanMM.`);
  }
  const clearStrapMM = f2StartMM - f1EndMM;
  if (clearStrapMM < MIN_CLEAR_STRAP_MM) {
    throw new DiagramError(
      'NOT_A_STRAP',
      `The clear gap between footing1 and footing2 (${clearStrapMM.toFixed(1)}mm) is below the ${MIN_CLEAR_STRAP_MM}mm minimum for a real strap span — this is effectively a rectangular combined footing; use footingDiagram.mjs's own "combined" type instead.`,
    );
  }

  // ── Strap beam ─────────────────────────────────────────────────────
  const rawStrap = raw.strap;
  if (!rawStrap || typeof rawStrap !== 'object') {
    throw new DiagramError('BAD_PARAM', '"strap" is required: an object with widthMM, depthMM, coverMM, topBarDiaMM, topBarCount, bottomBarDiaMM, bottomBarCount, stirrupDiaMM, stirrupSpacingMM.');
  }
  const strapWidthMM = toMm(rawStrap.widthMM, unit);
  const strapDepthMM = toMm(rawStrap.depthMM, unit);
  const strapCoverMM = toMm(rawStrap.coverMM, unit);
  const topBarDiaMM = toMm(rawStrap.topBarDiaMM, unit);
  const bottomBarDiaMM = toMm(rawStrap.bottomBarDiaMM, unit);
  const stirrupDiaMM = toMm(rawStrap.stirrupDiaMM, unit);
  const stirrupSpacingMM = toMm(rawStrap.stirrupSpacingMM, unit);
  for (const [name, v] of Object.entries({
    widthMM: strapWidthMM, depthMM: strapDepthMM, coverMM: strapCoverMM,
    topBarDiaMM, bottomBarDiaMM, stirrupDiaMM, stirrupSpacingMM,
  })) {
    assertFinitePositive(`strap.${name}`, v);
  }
  const topBarCount = Math.round(Number(rawStrap.topBarCount));
  const bottomBarCount = Math.round(Number(rawStrap.bottomBarCount));
  assertInt('strap.topBarCount', topBarCount, { min: MIN_BAR_COUNT, max: MAX_BAR_COUNT });
  assertInt('strap.bottomBarCount', bottomBarCount, { min: MIN_BAR_COUNT, max: MAX_BAR_COUNT });

  if (strapWidthMM < MIN_STRAP_WIDTH_MM || strapWidthMM > MAX_STRAP_WIDTH_MM) {
    throw new DiagramError('BAD_PARAM', `"strap.widthMM" must be between ${MIN_STRAP_WIDTH_MM}mm and ${MAX_STRAP_WIDTH_MM}mm, got ${strapWidthMM}mm.`);
  }
  if (strapDepthMM < MIN_STRAP_DEPTH_MM || strapDepthMM > MAX_STRAP_DEPTH_MM) {
    throw new DiagramError('BAD_PARAM', `"strap.depthMM" must be between ${MIN_STRAP_DEPTH_MM}mm and ${MAX_STRAP_DEPTH_MM}mm, got ${strapDepthMM}mm.`);
  }
  // Caller rule, refined: "عرض الشداد دائما أكبر من او يساوي أكبر بعد
  // يمر به من العمودين ... بحيث ان عرض الشداد دائما يحتوي العموديين" —
  // not just colWidthMM: this model never ties either column's
  // colWidthMM specifically to the strap's own cross-direction (a
  // column can face the strap with EITHER of its two plan dimensions),
  // so the strap must contain whichever of EACH column's own two
  // dimensions — colWidthMM or colDepthMM — is larger, for BOTH
  // columns, or a column turned 90° from what colWidthMM alone assumed
  // would still poke outside the strap's own cage.
  const maxColSpanMM = Math.max(f1.colWidthMM, f1.colDepthMM, f2.colWidthMM, f2.colDepthMM);
  if (strapWidthMM < maxColSpanMM) {
    throw new DiagramError(
      'STRAP_NARROWER_THAN_COLUMN',
      `"strap.widthMM" (${strapWidthMM}mm) must be >= the largest column dimension it must contain (${maxColSpanMM}mm, across both columns' own width and depth) — a strap narrower than either column cannot be built.`,
    );
  }
  // Caller rule: "ارتفاع [الشداد] أكبر من او يساوي أصغر ارتفاع من
  // القاعدين" — the strap must reach at least as deep as the SHALLOWER
  // of the two footings, or it would not be embedded in that footing's
  // own thickness at all.
  const minFootingThicknessMM = Math.min(f1.thicknessMM, f2.thicknessMM);
  if (strapDepthMM < minFootingThicknessMM) {
    throw new DiagramError(
      'STRAP_SHALLOWER_THAN_FOOTING',
      `"strap.depthMM" (${strapDepthMM}mm) must be >= the shallower footing's thickness (${minFootingThicknessMM}mm) — otherwise the strap is not embedded in that footing at all.`,
    );
  }
  for (const [name, v] of Object.entries({ topBarDiaMM, bottomBarDiaMM })) {
    if (v < MIN_BAR_DIA_MM || v > MAX_BAR_DIA_MM) {
      throw new DiagramError('BAD_PARAM', `"strap.${name}" must be between ${MIN_BAR_DIA_MM}mm and ${MAX_BAR_DIA_MM}mm, got ${v}mm.`);
    }
  }
  if (stirrupDiaMM < MIN_STIRRUP_DIA_MM || stirrupDiaMM > MAX_STIRRUP_DIA_MM) {
    throw new DiagramError('BAD_PARAM', `"strap.stirrupDiaMM" must be between ${MIN_STIRRUP_DIA_MM}mm and ${MAX_STIRRUP_DIA_MM}mm, got ${stirrupDiaMM}mm.`);
  }
  if (stirrupSpacingMM < MIN_STIRRUP_SPACING_MM || stirrupSpacingMM > MAX_STIRRUP_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"strap.stirrupSpacingMM" must be between ${MIN_STIRRUP_SPACING_MM}mm and ${MAX_STIRRUP_SPACING_MM}mm, got ${stirrupSpacingMM}mm.`);
  }

  // Top/bottom bar room across the strap's own width (same shape as a
  // beam cross-section's own bar-layout room check).
  for (const [label, dia, count] of [['top', topBarDiaMM, topBarCount], ['bottom', bottomBarDiaMM, bottomBarCount]]) {
    const first = strapCoverMM + stirrupDiaMM + dia / 2;
    const last = strapWidthMM - strapCoverMM - stirrupDiaMM - dia / 2;
    if (last <= first) {
      throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${strapCoverMM}mm), stirrup diameter (${stirrupDiaMM}mm), and ${label} bar diameter (${dia}mm) leave no room across the strap's ${strapWidthMM}mm width.`);
    }
    void count; // count only affects distribution below, not the room check itself
  }
  // Stirrup + top/bottom bar room within the strap's own depth.
  const depthNeeded = 2 * strapCoverMM + 2 * stirrupDiaMM + (topBarDiaMM + bottomBarDiaMM) / 2;
  if (depthNeeded >= strapDepthMM) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${strapCoverMM}mm), stirrup diameter (${stirrupDiaMM}mm), and top/bottom bar diameters leave no room within the strap's ${strapDepthMM}mm depth.`);
  }

  const topBarFirst = strapCoverMM + stirrupDiaMM + topBarDiaMM / 2;
  const topBarLast = strapWidthMM - strapCoverMM - stirrupDiaMM - topBarDiaMM / 2;
  const topBarStep = topBarCount > 1 ? (topBarLast - topBarFirst) / (topBarCount - 1) : 0;
  const topBars = Array.from({ length: topBarCount }, (_, i) => topBarFirst + i * topBarStep);

  const bottomBarFirst = strapCoverMM + stirrupDiaMM + bottomBarDiaMM / 2;
  const bottomBarLast = strapWidthMM - strapCoverMM - stirrupDiaMM - bottomBarDiaMM / 2;
  const bottomBarStep = bottomBarCount > 1 ? (bottomBarLast - bottomBarFirst) / (bottomBarCount - 1) : 0;
  const bottomBars = Array.from({ length: bottomBarCount }, (_, i) => bottomBarFirst + i * bottomBarStep);

  const stirrupCount = Math.max(2, Math.min(Math.floor(clearStrapMM / stirrupSpacingMM) + 1, MAX_MESH_LINES * 2));

  // ── Shrinkage / skin bars around the strap's perimeter (اسياخ انكماش) ──
  // Required, same reasoning as footing1/footing2.dowels above: Fig.
  // 6-16 labels these explicitly on the one strap-beam section it shows,
  // so a strap drawn without them is missing a labeled element of that
  // reference detail, not a cosmetic omission. Placed in PAIRS — one per
  // side face, per depth level — between the top-bar and bottom-bar
  // rows, matching the reference figure's own "between the flexural
  // layers" position and the general skin-reinforcement convention it
  // illustrates.
  if (rawStrap.shrinkageBarDiaMM == null || rawStrap.shrinkageBarCount == null) {
    throw new DiagramError('BAD_PARAM', '"strap.shrinkageBarDiaMM" and "strap.shrinkageBarCount" are required — perimeter/skin reinforcement (ECP 203 detail guide Fig. 6-16\'s "اسياخ انكماش ... على المحيط").');
  }
  const shrinkageBarDiaMM = toMm(rawStrap.shrinkageBarDiaMM, unit);
  assertFinitePositive('strap.shrinkageBarDiaMM', shrinkageBarDiaMM);
  if (shrinkageBarDiaMM < MIN_BAR_DIA_MM || shrinkageBarDiaMM > MAX_BAR_DIA_MM) {
    throw new DiagramError('BAD_PARAM', `"strap.shrinkageBarDiaMM" must be between ${MIN_BAR_DIA_MM}mm and ${MAX_BAR_DIA_MM}mm, got ${shrinkageBarDiaMM}mm.`);
  }
  const shrinkageBarCount = Math.round(Number(rawStrap.shrinkageBarCount));
  assertInt('strap.shrinkageBarCount', shrinkageBarCount, { min: MIN_SHRINK_COUNT, max: MAX_SHRINK_COUNT });
  if (shrinkageBarCount % 2 !== 0) {
    throw new DiagramError('BAD_PARAM', `"strap.shrinkageBarCount" must be even (split across the strap's two side faces), got ${shrinkageBarCount}.`);
  }

  // Depth positions, measured from the strap's OWN bottom fiber (the
  // baseline every render function already anchors to) — computed once,
  // here, so renderLongSection/renderSection11/the DXF path all read the
  // same numbers instead of re-deriving the cover+stirrup+dia/2 formula
  // three times.
  const bottomBarDepthMM = strapCoverMM + stirrupDiaMM + bottomBarDiaMM / 2;
  const topBarDepthMM = strapDepthMM - strapCoverMM - stirrupDiaMM - topBarDiaMM / 2;
  const shrinkageLevels = shrinkageBarCount / 2;
  const shrinkGapNeeded = (shrinkageLevels + 1) * shrinkageBarDiaMM;
  if (topBarDepthMM - bottomBarDepthMM < shrinkGapNeeded) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `"strap.shrinkageBarCount" (${shrinkageBarCount}) needs at least ${shrinkGapNeeded.toFixed(1)}mm of clear depth between the top and bottom bar rows, but only ${(topBarDepthMM - bottomBarDepthMM).toFixed(1)}mm is available — reduce the count or increase strap.depthMM.`);
  }
  const shrinkageLevelsMM = Array.from(
    { length: shrinkageLevels },
    (_, i) => bottomBarDepthMM + (topBarDepthMM - bottomBarDepthMM) * ((i + 1) / (shrinkageLevels + 1)),
  );
  const shrinkageFaceYMM = strapWidthMM / 2 - strapCoverMM - stirrupDiaMM - shrinkageBarDiaMM / 2;
  if (shrinkageFaceYMM <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${strapCoverMM}mm), stirrup diameter (${stirrupDiaMM}mm), and shrinkage bar diameter (${shrinkageBarDiaMM}mm) leave no room across the strap's ${strapWidthMM}mm width.`);
  }
  const shrinkagePoints = shrinkageLevelsMM.flatMap((depthMM) => [
    { yLocalMM: -shrinkageFaceYMM, depthMM },
    { yLocalMM: shrinkageFaceYMM, depthMM },
  ]);

  const sectionThrough = raw.sectionThrough === 2 ? 2 : 1;

  return {
    type: 'strap', unit, id, spanMM, sectionThrough,
    footing1: {
      ...f1, startMM: f1StartMM, endMM: f1EndMM, edgeMM, colCenterMM: 0,
    },
    footing2: {
      ...f2, startMM: f2StartMM, endMM: f2EndMM, colCenterMM: spanMM,
    },
    clearStrapMM,
    strap: {
      widthMM: strapWidthMM, depthMM: strapDepthMM, coverMM: strapCoverMM,
      topBarDia: topBarDiaMM, topBarCount, topBars, topBarDepthMM,
      bottomBarDia: bottomBarDiaMM, bottomBarCount, bottomBars, bottomBarDepthMM,
      stirrupDia: stirrupDiaMM, stirrupSpacing: stirrupSpacingMM, stirrupCount,
      shrinkageBarDia: shrinkageBarDiaMM, shrinkageBarCount, shrinkageLevelsMM, shrinkagePoints,
    },
  };
}

// ── Labels ───────────────────────────────────────────────────────────
// Local L={en:{...},ar:{...}} dictionary — same decision every sibling
// module's header already documents (structuralLabels.mjs scopes itself
// to footingDiagram.mjs only). Arabic values written parenthesis- and
// em/en-dash-free per structuralLabels.mjs's documented Noto Naskh
// Arabic glyph-gap note; engineering notation (Ø, mm, numbers) and
// translated labels are rendered as two separate <text> nodes below,
// same convention every sibling module already uses.
const L = {
  en: {
    title: (id) => `STRAP FOOTING ${id} \u2014 REINFORCEMENT DETAIL`,
    plan: 'PLAN', longSection: 'LONGITUDINAL SECTION', transSection: 'TRANSVERSE SECTION',
    section11: 'SECTION 1-1 (through column \u0026 strap)',
    sectionAA: 'SECTION A-A: STRAP BEAM CROSS-SECTION',
    footing1: 'FOOTING 1 (exterior)', footing2: 'FOOTING 2 (interior)', strapLabel: 'STRAP BEAM',
    mesh: 'Mesh', topBars: 'Top bars', bottomBars: 'Bottom bars', stirrups: 'Stirrups',
    dowels: 'Column dowels', shrinkageBars: 'Shrinkage bars', column: 'Column',
    legendTitle: 'REINFORCEMENT KEY',
    reinforcedFooting: 'Reinforced footing', plainFooting: 'Plain concrete footing',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design before issuing for construction. Each footing shows one representative bottom mesh layer and its own column dowels, perimeter-distributed \u2014 not a full column bar schedule. The strap shows one representative top/bottom bar group, stirrup spacing, and shrinkage/skin bar group. Strap top and bottom bars are drawn extending to each column\u2019s centerline for anchorage; the exact bar arrangement within the column\u2019s own reinforcement cage is a shop-drawing detail this schematic does not re-derive \u2014 confirm it against the column\u2019s own layout (reference arrangement: ECP 203 detail guide Fig. 6-16). The gap between the two footings is drawn as a non-bearing strap span, not a poured slab.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد القاعدة ذات الرابطة ${id}`,
    plan: 'مسقط', longSection: 'قطاع طولي', transSection: 'قطاع عرضي',
    section11: 'قطاع 1-1 يمر بالعمود وكمرة الرابطة',
    sectionAA: 'قطاع أ-أ: قطاع الكمرة الرابطة العرضي',
    footing1: 'القاعدة 1 الخارجية', footing2: 'القاعدة 2 الداخلية', strapLabel: 'كمرة الرابطة',
    mesh: 'شبكة', topBars: 'حديد علوي', bottomBars: 'حديد سفلي', stirrups: 'كانات',
    dowels: 'أشاير العمود', shrinkageBars: 'اسياخ انكماش', column: 'عمود',
    legendTitle: 'مفتاح رموز التسليح',
    reinforcedFooting: 'القاعدة المسلحة', plainFooting: 'القاعدة العادية',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. يوضح الرسم لكل قاعدة طبقة تسليح سفلية تمثيلية واحدة وأشاير عمودها موزعة على محيط العمود، لا مخططاً كاملاً لتسليح العمود. يوضح لكمرة الرابطة مجموعة تمثيلية واحدة من الحديد العلوي والسفلي والكانات وأسياخ الانكماش. يمتد حديد الكمرة العلوي والسفلي حتى محور كل عمود لتحقيق الرباط، وترتيب دخوله داخل تسليح العمود نفسه تفصيل تنفيذي يُراجع وفق تسليح العمود الفعلي، انظر دليل التفاصيل الانشائية شكل 6-16 للترتيب المرجعي. تمثل الفجوة بين القاعدتين امتداد الرابطة غير الحامل على التربة، وليست بلاطة مصبوبة.',
    dirAttr: 'rtl',
  },
};

// ── Render ───────────────────────────────────────────────────────────
// View stack order matches ECP 203 detail guide Fig. 6-16's own page
// order top-to-bottom: the column/strap section first, plan below it,
// then this module's own pre-existing longitudinal/transverse sections.
const CANVAS_W = 950;
const STRAP_SECTION_BOX = { x: 80, y: 110, w: 300, h: 300 };
const SECTION_1_1_BOX = { x: 80, y: STRAP_SECTION_BOX.y + STRAP_SECTION_BOX.h + 50, w: 790, h: 310 };
const PLAN_BOX = { x: 80, y: SECTION_1_1_BOX.y + SECTION_1_1_BOX.h + 60, w: 790, h: 300 };
const LONG_SECTION_BOX = { x: 80, y: PLAN_BOX.y + PLAN_BOX.h + 110, w: 790, h: 260 };
// Cosmetic-only column-stub height for the longitudinal section and
// Section 1-1 (both draw the column as a short stub "continuing off the
// detail", exactly as Fig. 6-16 itself does — not a real story height).
// Named and isolated here, same transparency convention this file's own
// sanity-cap block already uses for every value that draws something but
// encodes no design rule.
const COLUMN_STUB_HEIGHT_FRACTION = 0.6;
// Fixed drafting default for the unreinforced blinding/plain-concrete
// layer every reinforced footing sits on in practice — this module has
// no dedicated input field for it, so every footing-section view draws
// it unconditionally at this nominal thickness (matching this file's own
// long-established f1plainprojection=75 example value, a plausible
// same-order-of-magnitude default for a real blinding course).
const PLAIN_CONCRETE_THICKNESS_MM = 75;

export function renderStrapFootingDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  // Caller: "احذف هذه الرسمه ... فهي بلا معني" — Transverse Section
  // duplicated what Section 1-1 already shows (same footing, same
  // bottom-only mesh, same blinding layer, once Section 1-1 got its own
  // full-reinforcement fix) with strictly less context (no strap/column
  // at all) once the two were made visually consistent. Removed outright
  // (not left as dead code): renderTransSection/renderTransSectionDXF
  // were both module-private, never exported, so nothing outside either
  // file could have depended on them.
  const tableY = LONG_SECTION_BOX.y + LONG_SECTION_BOX.h + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .footing-title   { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .footing-outline { fill:#f4f4f4; stroke:#1a1a1a; stroke-width:1.7; }
    .strap-outline   { fill:#eef2f7; stroke:#1a1a1a; stroke-width:1.7; stroke-dasharray:4,3; }
    .column-outline  { fill:#e2e2e2; stroke:#1a1a1a; stroke-width:1.7; }
    .plain-outline   { fill:none; stroke:#555; stroke-width:1.2; stroke-dasharray:2,2; }
    .mesh-line       { stroke:#7d3c98; stroke-width:1.2; }
    .pad-tag         { font-size:12px; fill:#333; font-family: ${scriptFontStack}; }
    .rebar-note      { font-size:11px; fill:#333; font-family: ${defaultFontStack}; }
    .bar-dot-dowel     { fill:#0e7c7b; stroke:#0a4f4e; stroke-width:0.6; }
    .bar-dot-shrinkage { fill:#d68910; stroke:#8a5a09; stroke-width:0.6; }
    .bar-dot-mesh      { fill:#7d3c98; stroke:#4a235a; stroke-width:0.6; }
    .bar-line-shrinkage{ stroke:#8a5a09; fill:none; }
    .dowel-line        { stroke:#0e7c7b; stroke-width:1.6; }
    .anchor-hook       { stroke:#1a1a1a; stroke-width:1.4; }
    .legend-title      { font-size:11px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .legend-text       { font-size:10.5px; fill:#222; font-family: ${scriptFontStack}; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="footing-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderLegendRow(60, 72, CANVAS_W - 120, l)}
  ${renderStrapCrossSection(geometry, STRAP_SECTION_BOX, l)}
  ${renderSection11(geometry, SECTION_1_1_BOX, l)}
  ${renderPlanView(geometry, PLAN_BOX, l)}
  ${renderLongSection(geometry, LONG_SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// Everything drawn on one FIXED horizontal midline (box.y + box.h/2) —
// same anchoring discipline trapezoidalFootingDiagram.mjs's own plan
// view documents (never derive the shared centerline from either pad's
// own half-breadth, which would silently drift the two pads apart from
// the shared strap axis they are actually both centered on).
// Small helper local to this file: word-wraps `text` at
// `maxCharsPerLine` (reusing the kit's own wrapText) and stacks the
// resulting lines as separate centered <text> nodes starting at
// (x,startY).
function renderWrapped(text, x, startY, maxCharsPerLine, lineHeight, dir, cls, bold) {
  const lines = wrapText(text, maxCharsPerLine);
  return lines.map((line, i) => `<text x="${x}" y="${startY + i * lineHeight}" text-anchor="middle" class="${cls}" dir="${dir}"${bold ? ' font-weight="bold"' : ''}>${esc(line)}</text>`).join('');
}

// ── Visual weight: diameter-driven color + line/dot thickness ──────────
// Prior to this revision every bar-cross-section dot in this file's
// output rendered at the SAME fixed radius (r="3.20") and every bar LINE
// at a family-fixed stroke-width, regardless of that specific bar's own
// real mm diameter (verified directly against this module's own
// previously-generated SVG: a 12mm shrinkage dot, a 16mm top-bar dot, and
// a 20mm bottom-bar dot all measured r=3.20 in the shipped output) — so
// "how thick is this bar" was not actually readable from the drawing,
// only "which family is it" (via color). This section fixes that: every
// call site below now derives its stroke-width/radius from the SAME bar
// diameter already carried on `geometry` (strap.topBarDia, .bottomBarDia,
// .stirrupDia, .shrinkageBarDia, footingN.mesh.dia, footingN.dowels.dia)
// through one shared, bounded mapping, so a 25mm bar always reads
// visibly heavier than a 10mm bar, consistently, in every one of this
// sheet's five views.
//
// The mapping target is a fixed, legible PIXEL range, NOT diaMM*scale
// directly: at this module's own typical plan/section scale (well under
// 1 px/mm — a multi-metre footing system fit into an ~800px box), a bare
// diaMM*scale for a 10-25mm bar is often sub-2px and unreadable once
// rasterized or printed. Real rebar-detailing practice draws bar symbols
// schematically oversized for legibility while preserving RELATIVE
// weight between diameters, not literal to-scale thickness — this
// mirrors that convention rather than inventing a new one. Domain is
// this module's own already-validated diameter sanity caps (so the
// mapping is never asked to place a value outside what
// computeStrapFootingGeometry already accepted).
//
// CASCADE WARNING — verified by rendering both forms through a
// standards-compliant SVG engine (librsvg) and diffing the rasterized
// pixel output: a bare `stroke-width="X"` attribute on an element that
// ALSO carries a `class="..."` whose stylesheet rule sets stroke-width
// (e.g. .bar-top/.bar-bottom/.stirrup-outline from the shared kit, or
// this file's own .mesh-line/.dowel-line) is SILENTLY OVERRIDDEN by that
// class's own value in any spec-correct renderer — an SVG presentation
// attribute carries the lowest possible CSS specificity, below even a
// plain class selector, so the stylesheet always wins the conflict. This
// was a real, pre-existing, invisible bug in this file's prior revision
// (.mesh-line's stroke-width="2" override, the plan-view bar-bottom/
// bar-top's stroke-width="1.4"/"1.2", the stirrup-outline tick's
// stroke-width="1", and the long-section shrinkage line's
// stroke-width="1.6" were ALL silently ignored, rendering at each class's
// own flat default instead) — fixed at every site below by emitting
// `style="stroke-width:...px"` (an inline STYLE declaration, which DOES
// win the cascade) instead of a bare attribute. Never reintroduce a bare
// stroke-width= alongside a stroke-width-setting class in this file.
const BAR_DIA_DOMAIN_MM = [MIN_STIRRUP_DIA_MM, Math.max(MAX_BAR_DIA_MM, MAX_DOWEL_DIA_MM)]; // [6,32]
const BAR_LINE_PX_RANGE = [1.0, 3.4]; // stroke-width range for bar/mesh/dowel LINES
const BAR_DOT_PX_RANGE = [1.8, 4.4]; // radius range for bar cross-section DOTS

function barWeightT(diaMM) {
  const [lo, hi] = BAR_DIA_DOMAIN_MM;
  const d = Math.min(hi, Math.max(lo, diaMM));
  return (d - lo) / (hi - lo);
}
function barLineWidthPx(diaMM) {
  const [lo, hi] = BAR_LINE_PX_RANGE;
  return +(lo + barWeightT(diaMM) * (hi - lo)).toFixed(2);
}
function barDotRadiusPx(diaMM) {
  const [lo, hi] = BAR_DOT_PX_RANGE;
  return +(lo + barWeightT(diaMM) * (hi - lo)).toFixed(2);
}
// Local replacement for the kit's own barDot(): identical OUTPUT shape
// (one <circle>, class="bar-dot-{kind}", same class-driven fill/stroke
// this file already relies on) so every existing call site only needed
// its name changed, not its surrounding code — but radius now comes from
// barDotRadiusPx(diaMM) above instead of a flat, diameter-blind constant.
// `r` is a plain geometry attribute here (not a CSS property any class
// in this sheet touches), so — unlike stroke-width above — a bare
// attribute is safe and correct for it; no cascade risk.
function weightedBarDot(x, y, diaMM, kind) {
  return `<circle cx="${x}" cy="${y}" r="${barDotRadiusPx(diaMM)}" class="bar-dot-${kind}"/>`;
}

// Single source of truth for the LEGEND's own swatch colors. Drawn as
// plain inline-colored <line>/<circle> elements with no class="" at all
// (see renderLegendRow below), so these never fight the cascade the way
// a class-based swatch could — but they must still be kept in sync BY
// HAND with the <style> block's own .bar-top/.bar-bottom/.mesh-line/
// .stirrup-outline/.bar-line-shrinkage/.dowel-line colors above/in the
// kit, since nothing here reads the stylesheet back out. Bottom bars use
// the kit's own bar-bottom red; every other entry mirrors this file's
// own local class colors one-for-one.
const REBAR_COLORS = {
  top: '#1f5aa6', bottom: '#c0392b', mesh: '#7d3c98',
  stirrup: '#2f7a3d', shrinkage: '#8a5a09', dowel: '#0e7c7b',
};

// One horizontal color/weight key for the whole sheet — the explicit
// "تمييز لوني بين عناصر التسليح المختلفة" ask: SECTION A-A already
// leader-labels four of these six families with a straight line to one
// representative bar (see renderStrapCrossSection below), but that
// leader is only readable at THAT view's own scale, and mesh/dowels
// never get one at all. This row is scale-independent, always visible
// once, near the sheet title, and covers all six families the schedule
// table's own eight marks reduce to (F1/F2->mesh, ST1->top, SB1->bottom,
// SS1->stirrup, SK1->shrinkage, DW1/DW2->dowel). Placed in the existing
// gap between the sheet title (y=32) and STRAP_SECTION_BOX (y=110) — a
// fixed span already comfortably empty in every prior revision's own
// layout math, so this needed no other box/offset in this file to move.
function renderLegendRow(x, y, width, l) {
  const items = [
    ['top', l.topBars], ['bottom', l.bottomBars], ['mesh', l.mesh],
    ['stirrup', l.stirrups], ['shrinkage', l.shrinkageBars], ['dowel', l.dowels],
  ];
  const cellW = width / items.length;
  let svg = `<g class="legend-row">`;
  svg += `<text x="${x}" y="${y - 13}" text-anchor="start" class="legend-title" dir="${l.dirAttr}">${esc(l.legendTitle)}</text>`;
  items.forEach(([kind, label], i) => {
    // RTL sheets fill the row right-to-left, same "first item nearest the
    // sheet's own reading start" convention already used above.
    const cellX = l.dirAttr === 'rtl' ? (x + width) - (i + 1) * cellW : x + i * cellW;
    const x1 = cellX, x2 = cellX + 22;
    const color = REBAR_COLORS[kind];
    svg += `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="${color}" style="stroke-width:3px"/>`;
    svg += `<circle cx="${(x1 + x2) / 2}" cy="${y}" r="2.6" fill="${color}"/>`;
    svg += `<text x="${x2 + 6}" y="${y + 3.5}" text-anchor="start" class="legend-text" dir="${l.dirAttr}">${esc(label)}</text>`;
  });
  svg += `</g>`;
  return svg;
}

// Standalone strap cross-section, matching the reviewer's own reference
// image exactly: just the beam's own section (no footing/column
// context — that relationship is Section 1-1's job below), with a
// rounded stirrup outline and a real leader line from each label to a
// representative bar of its own group, rather than a plain nearby
// caption. Built entirely from data Section 1-1 already computes
// (strap.topBars/bottomBars/shrinkagePoints, strap.topBarDepthMM/
// bottomBarDepthMM) — no new geometry.
function renderStrapCrossSection(geometry, box, l) {
  const { strap } = geometry;
  const scale = fitScale([{ contentW: strap.widthMM, contentH: strap.depthMM, boxW: box.w - 140, boxH: box.h - 100 }]);
  const cx = box.x + box.w / 2;
  const groundY = box.y + box.h - 70;
  const topY = groundY - strap.depthMM * scale;
  const sw = strap.widthMM * scale;
  const sx = cx - sw / 2;

  let svg = `<g class="strap-section-view">`;
  let labels = '';

  // Cutting-plane "A" arrows, top and bottom of the beam, matching the
  // reference's own convention.
  const cutX = sx - 34;
  labels += `<text x="${cutX}" y="${topY - 6}" text-anchor="end" class="pad-tag" dir="${l.dirAttr}">A</text>`;
  svg += `<line x1="${cutX + 4}" y1="${topY - 4}" x2="${cutX + 20}" y2="${topY + 10}" stroke="#1a1a1a" stroke-width="1.3"/>`;
  labels += `<text x="${cutX}" y="${groundY + 14}" text-anchor="end" class="pad-tag" dir="${l.dirAttr}">A</text>`;
  svg += `<line x1="${cutX + 4}" y1="${groundY + 12}" x2="${cutX + 20}" y2="${groundY - 2}" stroke="#1a1a1a" stroke-width="1.3"/>`;

  svg += `<rect x="${sx}" y="${topY}" width="${sw}" height="${groundY - topY}" class="strap-outline"/>`;
  const inset = strap.coverMM * scale;
  svg += `<rect x="${sx + inset}" y="${topY + inset}" width="${sw - 2 * inset}" height="${(groundY - topY) - 2 * inset}" rx="${inset * 0.6}" class="stirrup-outline" style="stroke-width:${barLineWidthPx(strap.stirrupDia)}px"/>`;

  const topBarY = groundY - strap.topBarDepthMM * scale;
  const topDotXs = strap.topBars.map((off) => sx + off * scale);
  for (const x of topDotXs) svg += weightedBarDot(x, topBarY, strap.topBarDia, 'top');

  const botBarY = groundY - strap.bottomBarDepthMM * scale;
  const botDotXs = strap.bottomBars.map((off) => sx + off * scale);
  for (const x of botDotXs) svg += weightedBarDot(x, botBarY, strap.bottomBarDia, 'bottom');

  const shrinkPts = strap.shrinkagePoints.map((pt) => ({ x: cx + pt.yLocalMM * scale, y: groundY - pt.depthMM * scale }));
  for (const p of shrinkPts) svg += weightedBarDot(p.x, p.y, strap.shrinkageBarDia, 'shrinkage');

  // Leader lines: one per group, label outside the rectangle, straight
  // line to a representative bar of that group — the reference's own
  // "text with an arrow to the element" convention, not a caption
  // merely placed nearby.
  const leader = (labelX, labelY, anchor, tx, ty, text, color) => {
    svg += `<line x1="${labelX}" y1="${labelY}" x2="${tx}" y2="${ty}" stroke="${color || '#333'}" stroke-width="1"/>`;
    labels += `<text x="${labelX}" y="${labelY}" text-anchor="${anchor}" dy="-4" class="rebar-note" dir="${l.dirAttr}">${esc(text)}</text>`;
  };
  leader(sx + sw + 40, topBarY - 14, 'start', topDotXs[topDotXs.length - 1], topBarY, l.topBars, '#1f5aa6');
  leader(sx - 40, topY + inset + 14, 'end', sx + inset, topY + inset, l.stirrups, '#2f7a3d');
  leader(sx + sw + 40, groundY - inset - 14, 'start', botDotXs[botDotXs.length - 1], botBarY, l.shrinkageBars, '#8a5a09');
  leader(sx - 40, botBarY + 14, 'end', botDotXs[0], botBarY, l.bottomBars, '#c0392b');

  labels += renderWrapped(l.sectionAA, cx, box.y + box.h - 10, 34, 14, l.dirAttr, 'pad-tag', true);

  svg += labels;
  svg += `</g>`;
  return svg;
}

function renderPlanView(geometry, box, l) {
  const {
    footing1: f1, footing2: f2, strap, spanMM,
  } = geometry;
  const drawMinX = f1.startMM, drawMaxX = f2.endMM;
  const totalMM = drawMaxX - drawMinX;
  const maxBreadth = Math.max(f1.breadthMM, f2.breadthMM, strap.widthMM);
  const scale = fitScale([{ contentW: totalMM, contentH: maxBreadth, boxW: box.w - 100, boxH: box.h - 70 }]);
  const originX = box.x + (box.w - totalMM * scale) / 2 - drawMinX * scale;
  const midY = box.y + box.h / 2;
  const xPx = (xMM) => originX + xMM * scale;

  let svg = `<g class="plan-view">`;
  let labels = ''; // every <text> in this view collects here and is appended LAST (see below).

  for (const [pad, tag] of [[f1, l.footing1], [f2, l.footing2]]) {
    const x1 = xPx(pad.startMM), x2 = xPx(pad.endMM);
    const halfPx = (pad.breadthMM * scale) / 2;

    // Optional plain-concrete step: drawn BEHIND the reinforced outline,
    // dashed, so it reads as "the wider pour beneath" rather than a
    // second reinforced pad (Fig. 6-16's own القاعده العاديه/المسلحه pair).
    if (pad.plain) {
      const plainHalfPx = (pad.plain.breadthMM * scale) / 2;
      const plainX1 = x1 - pad.plain.projectionMM * scale, plainX2 = x2 + pad.plain.projectionMM * scale;
      svg += `<rect x="${plainX1}" y="${midY - plainHalfPx}" width="${plainX2 - plainX1}" height="${plainHalfPx * 2}" class="plain-outline"/>`;
    }

    svg += `<rect x="${x1}" y="${midY - halfPx}" width="${x2 - x1}" height="${halfPx * 2}" class="footing-outline"/>`;

    for (const line of pad.mesh.alongBreadthLines) {
      const x = xPx(pad.startMM + line.xLocalMM);
      const h = (line.drawnLengthMM * scale) / 2;
      svg += `<line x1="${x}" y1="${midY - h}" x2="${x}" y2="${midY + h}" class="mesh-line" style="stroke-width:${barLineWidthPx(pad.mesh.dia)}px"/>`;
    }
    for (const line of pad.mesh.alongWidthLines) {
      const y = midY - (pad.breadthMM * scale) / 2 + line.yLocalMM * scale;
      const xa = xPx(pad.startMM + (pad.widthMM - line.drawnLengthMM) / 2);
      const xb = xPx(pad.startMM + (pad.widthMM + line.drawnLengthMM) / 2);
      svg += `<line x1="${xa}" y1="${y}" x2="${xb}" y2="${y}" class="mesh-line" style="stroke-width:${barLineWidthPx(pad.mesh.dia)}px"/>`;
    }

    labels += `<text x="${(x1 + x2) / 2}" y="${midY - halfPx - 10}" text-anchor="middle" dir="${l.dirAttr}" class="pad-tag">${esc(tag)}</text>`;
    if (pad.secondaryReinforcementNote) {
      // Anchored to maxBreadth (the same reference the width/clear
      // dimension lines below already use), not this pad's own —
      // possibly smaller — breadth: anchoring to the pad's own breadth
      // previously let a note under the narrower pad collide with a
      // dimension line sized for the wider one.
      labels += `<text x="${(x1 + x2) / 2}" y="${midY + (maxBreadth * scale) / 2 + 92}" text-anchor="middle" dir="${l.dirAttr}" class="rebar-note">${esc(pad.secondaryReinforcementNote)}</text>`;
    }
  }

  // Strap beam plan outline: spans footing1's own OUTER edge to
  // footing2's own OUTER edge — caller rule "الشداد مستمر من بداية
  // القاعده الخارجيه لنهاية القاعده الداخليه" (continuous from the
  // external footing's own START to the internal footing's own END),
  // repeated and clarified as "مد الشداد للنهايه" (extend the strap to
  // the [footing's own] end) after an earlier revision only reached
  // column-to-column (xPx(0) to xPx(spanMM)) — column-to-column covers
  // the clear span but stops well short of each footing's own far edge,
  // which is what was still visibly wrong. Drawn AFTER the footings, on
  // top, so its dashed line stays visible even where it passes through
  // each footing's own solid fill: that portion is a reference/hidden
  // line (the strap is physically embedded in/merged with the footing's
  // own concrete there, not a separate visible edge), exactly how Fig.
  // 6-16's own plan view shows the strap's dashed outline continuing
  // inside each footing, not stopping at the footing's inner face.
  // Its own reinforcement is drawn WITHIN this outline (bottom bars,
  // top bars, stirrup ticks) rather than left blank, the same way the
  // footing's own mesh is already shown here — revealing the bar layout
  // "as if a horizontal section," per the reference clarification.
  {
    const x1 = xPx(f1.startMM), x2 = xPx(f2.endMM);
    const halfPx = (strap.widthMM * scale) / 2;
    svg += `<rect x="${x1}" y="${midY - halfPx}" width="${x2 - x1}" height="${halfPx * 2}" class="strap-outline"/>`;

    for (const off of strap.bottomBars) {
      const y = midY - halfPx + off * scale;
      svg += `<line x1="${x1 + 2}" y1="${y}" x2="${x2 - 2}" y2="${y}" class="bar-bottom" style="stroke-width:${barLineWidthPx(strap.bottomBarDia)}px"/>`;
    }
    for (const off of strap.topBars) {
      const y = midY - halfPx + off * scale;
      svg += `<line x1="${x1 + 2}" y1="${y}" x2="${x2 - 2}" y2="${y}" class="bar-top" style="stroke-width:${barLineWidthPx(strap.topBarDia)}px" stroke-dasharray="5,3"/>`;
    }
    for (const tickX of distributeTicks(x1 + 6, x2 - 6, Math.min(strap.stirrupCount, 24))) {
      svg += `<line x1="${tickX}" y1="${midY - halfPx}" x2="${tickX}" y2="${midY + halfPx}" class="stirrup-outline" style="stroke-width:${barLineWidthPx(strap.stirrupDia)}px"/>`;
    }

    const gx1 = xPx(f1.endMM), gx2 = xPx(f2.startMM);
    labels += `<text x="${(gx1 + gx2) / 2}" y="${midY + halfPx + 16}" text-anchor="middle" dir="${l.dirAttr}" class="pad-tag">${esc(l.strapLabel)}</text>`;
  }

  // Columns, at x=0 (footing1) and x=spanMM (footing2) — same
  // depth-as-x-extent/width-as-y-extent convention
  // trapezoidalFootingDiagram.mjs's own plan view uses. Drawn last (on
  // top of the strap's own outline) so the column reads cleanly at the
  // junction. Dowels drawn on top of the column outline, at each
  // dowel's own perimeter position.
  for (const [pad, xMM] of [[f1, 0], [f2, spanMM]]) {
    const cx = xPx(xMM);
    const cw = pad.colDepthMM * scale, ch = pad.colWidthMM * scale;
    svg += `<rect x="${cx - cw / 2}" y="${midY - ch / 2}" width="${cw}" height="${ch}" class="column-outline"/>`;
    for (const pt of pad.dowels.points) {
      svg += weightedBarDot(cx + pt.xLocalMM * scale, midY + pt.yLocalMM * scale, pad.dowels.dia, 'dowel');
    }
  }

  svg += dimensionLine(xPx(0), midY - (maxBreadth * scale) / 2 - 34, xPx(spanMM), midY - (maxBreadth * scale) / 2 - 34, `span=${Math.round(spanMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(xPx(f1.startMM), midY + (maxBreadth * scale) / 2 + 26, xPx(f1.endMM), midY + (maxBreadth * scale) / 2 + 26, `${Math.round(f1.widthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(xPx(f2.startMM), midY + (maxBreadth * scale) / 2 + 26, xPx(f2.endMM), midY + (maxBreadth * scale) / 2 + 26, `${Math.round(f2.widthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(xPx(f1.endMM), midY + (maxBreadth * scale) / 2 + 48, xPx(f2.startMM), midY + (maxBreadth * scale) / 2 + 48, `clear=${Math.round(geometry.clearStrapMM)}mm`, { orientation: 'h', tick: 5 });
  // Footing1's own eccentricity, labeled with a real number (its
  // column's outer face to the pad's own outer edge) rather than left
  // to read only as a visual impression at whatever scale this
  // particular drawing happens to render at.
  svg += dimensionLine(xPx(f1.startMM), midY + (maxBreadth * scale) / 2 + 70, xPx(-f1.colDepthMM / 2), midY + (maxBreadth * scale) / 2 + 70, `edge=${Math.round(f1.edgeMM)}mm`, { orientation: 'h', tick: 5 });

  labels += `<text x="${originX + ((drawMinX + drawMaxX) / 2) * scale}" y="${midY + (maxBreadth * scale) / 2 + 114}" text-anchor="middle" dir="${l.dirAttr}" class="view-title">${esc(l.plan)}</text>`;
  // Every label appended last: no shape drawn above (footing rects,
  // dimension lines) can ever paint over a text node, regardless of how
  // narrow the strap's own clear-gap span is at the current scale (see
  // this file's header for the pre-existing bug this ordering fixes).
  svg += labels;
  svg += `</g>`;
  return svg;
}

// Elevation along the strap axis: both footings and the strap rise
// from ONE shared bottom (groundY, established inside
// renderLongSection below) since they are cast integrally — the strap
// is the taller of the two, so it continues up out of each footing's
// own top rather than sitting on top of it. See renderLongSection's own
// header for the full citation against Fig. 6-16.
// Quarter-circle hook from a straight bar segment into a perpendicular
// tail — the standard schematic for a 90\u00b0 rebar hook. (x,y): where the
// straight run ends and the curve begins. dx: -1 bends the curve toward
// -x, +1 toward +x. dy: -1 the tail then runs toward -y (up), +1 toward
// +y (down). Sweep-flag empirically verified against all 4 (dx,dy)
// combinations before use (see this file's own development notes) —
// not derived from memory, since SVG arc sweep-flags are an easy source
// of silent mirror-image bugs.
function hookPath(x, y, r, tail, dx, dy) {
  const sweep = dx * dy < 0 ? 1 : 0;
  const midX = x + dx * r, midY = y + dy * r;
  return `M ${x} ${y} A ${r} ${r} 0 0 ${sweep} ${midX} ${midY} L ${midX} ${midY + dy * tail}`;
}

function renderLongSection(geometry, box, l) {
  const {
    footing1: f1, footing2: f2, strap, clearStrapMM, spanMM,
  } = geometry;
  const drawMinX = f1.startMM, drawMaxX = f2.endMM;
  const totalMM = drawMaxX - drawMinX;
  const maxThickness = Math.max(f1.thicknessMM, f2.thicknessMM);
  const stubHeightMM = strap.depthMM * COLUMN_STUB_HEIGHT_FRACTION;
  // Footing and strap now share ONE bottom reference (groundY below), so
  // the footing's own thickness no longer stacks ON TOP of the strap's
  // depth when sizing this view — only whichever of the two is taller
  // (almost always the strap, by design; Math.max keeps this safe if a
  // caller ever supplies the reverse) drives the content height.
  const contentH = Math.max(strap.depthMM, maxThickness) + stubHeightMM;
  const scale = fitScale([{ contentW: totalMM, contentH, boxW: box.w - 100, boxH: box.h - 90 }]);
  const originX = box.x + (box.w - totalMM * scale) / 2 - drawMinX * scale;
  const xPx = (xMM) => originX + xMM * scale;
  // groundY: the ONE shared bottom for BOTH footings and the strap —
  // NOT "footing top = strap bottom" as an earlier revision of this
  // function drew it. That earlier version left the strap's own concrete
  // floating above the footings with nothing physically connecting them
  // across the clear span, and put every bar's absolute position at the
  // wrong level everywhere except directly at a column. Flagged directly
  // against Fig. 6-16's own قطاع ١-١, which shows the strap's OWN bottom
  // steel positioned within the footing's own body (near its bottom),
  // not hovering at the footing's top surface. Both members now rise
  // from this one line; the footing is simply the shorter of the two, so
  // the strap reads as continuing up out of the wider footing rather
  // than as a beam resting on top of one.
  const groundY = box.y + 30 + stubHeightMM * scale + Math.max(strap.depthMM, maxThickness) * scale;
  const strapTopY = groundY - strap.depthMM * scale;
  const stubTopY = strapTopY - stubHeightMM * scale;
  // Caller rule (repeated: "مد الشداد للنهايه" — extend the strap to
  // the [footing's own] end): column-to-column (xPx(0) to xPx(spanMM))
  // still stopped short of each footing's own far edge — see the plan
  // view's own matching header note for the full citation.
  const barX1 = xPx(f1.startMM), barX2 = xPx(f2.endMM);

  let svg = `<g class="long-section-view">`;
  let labels = `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.longSection)}</text>`;

  // Strap concrete: ONE continuous rectangle spanning column-to-column
  // (barX1..barX2), drawn FIRST — same span the bar lines below already
  // use, so the concrete envelope and its own reinforcement are
  // consistent with each other. Each footing's own (shorter) rectangle
  // is drawn AFTER, directly below/overlapping — it visually masks the
  // strap's lower, wider-footprint portion over its own span, leaving
  // only the strap's narrower "neck" showing above that footing's own
  // top, and the strap's full depth showing (nothing to mask it) across
  // the true clear gap. This is the same z-order trick the plan view
  // below already uses at the footing/strap seam — no polygon math
  // needed, just paint order: draw the taller/narrower shape first, the
  // shorter/wider shape after.
  svg += `<rect x="${barX1}" y="${strapTopY}" width="${barX2 - barX1}" height="${groundY - strapTopY}" class="strap-outline"/>`;

  // Column stubs (schematic — COLUMN_STUB_HEIGHT_FRACTION only, the
  // column itself continues off-detail), on top of the strap rect so
  // their own outline reads cleanly at the strap/column junction.
  for (const [pad, colCenterMM] of [[f1, 0], [f2, spanMM]]) {
    const cx = xPx(colCenterMM);
    const cw = pad.colDepthMM * scale;
    svg += `<rect x="${cx - cw / 2}" y="${stubTopY}" width="${cw}" height="${strapTopY - stubTopY}" class="column-outline"/>`;
  }

  for (const pad of [f1, f2]) {
    const x1 = xPx(pad.startMM), x2 = xPx(pad.endMM);
    const h = pad.thicknessMM * scale;
    // Caller rule: "لا يوجد تهشير بالقاعده الخرسانيه [المسلحه]" (no
    // hatch on the REINFORCED concrete — show only its reinforcement)
    // vs "أسفل القاعده الخرسانيه المسلحه يوجد قاعده خرسانه عاديه
    // بتهشير خرسانه عاديه" (below it, a PLAIN/blinding concrete layer,
    // WITH hatch — there is nothing to obscure there, so hatch is how
    // it reads as concrete rather than soil). PLAIN_CONCRETE_THICKNESS_MM
    // is a fixed drafting default (this module has no dedicated
    // blinding-thickness input field): every reinforced footing sits on
    // one in practice, so it is drawn unconditionally, not gated behind
    // the optional pad.plain (which only ever supplied a WIDER footprint,
    // not a thickness) — pad.plain's own breadthMM still widens it when
    // supplied, otherwise it matches the reinforced footing's own width.
    const plainH = PLAIN_CONCRETE_THICKNESS_MM * scale;
    const plainW = pad.plain ? pad.plain.breadthMM * scale : (x2 - x1);
    const plainMidX = (x1 + x2) / 2;
    const plainX1 = plainMidX - plainW / 2, plainX2 = plainMidX + plainW / 2;
    const plainBottomY = groundY + plainH;
    svg += `<rect x="${plainX1 - 16}" y="${plainBottomY}" width="${plainX2 - plainX1 + 32}" height="20" fill="url(#soilHatch)" opacity="0.5"/>`;
    svg += `<rect x="${plainX1}" y="${groundY}" width="${plainX2 - plainX1}" height="${plainH}" class="footing-outline" style="fill:url(#concreteHatch)"/>`;
    svg += `<rect x="${x1}" y="${groundY - h}" width="${x2 - x1}" height="${h}" class="footing-outline"/>`;
    const barY = groundY - pad.coverMM * scale - pad.mesh.dia * scale / 2;
    svg += `<line x1="${x1 + 4}" y1="${barY}" x2="${x2 - 4}" y2="${barY}" class="mesh-line" style="stroke-width:${barLineWidthPx(pad.mesh.dia)}px"/>`;
  }

  // Column dowels: one vertical line per DISTINCT depth-axis (xLocal)
  // position among that column's own perimeter points (positions sharing
  // an xLocal, differing only across colWidthMM, collapse to one line in
  // this elevation — same width-collapsing simplification this view
  // already applies to the strap's own top/bottom bars and to each pad's
  // own mesh, both below). Drawn from near the footing's own bottom
  // mesh (near groundY, the shared bottom — no longer the old
  // footing-top-relative offset), straight up through the strap depth,
  // into the column stub.
  for (const [pad, colCenterMM] of [[f1, 0], [f2, spanMM]]) {
    const cx = xPx(colCenterMM);
    const dowelBottomY = groundY - pad.coverMM * scale;
    const seen = new Set();
    for (const pt of pad.dowels.points) {
      const key = Math.round(pt.xLocalMM);
      if (seen.has(key)) continue;
      seen.add(key);
      const x = cx + pt.xLocalMM * scale;
      svg += `<line x1="${x}" y1="${dowelBottomY}" x2="${x}" y2="${stubTopY + 6}" class="dowel-line" style="stroke-width:${barLineWidthPx(pad.dowels.dia)}px"/>`;
    }
  }

  // Strap bars, column-to-column extent (unchanged from before, see
  // this function's own prior header note) but now measured from
  // groundY, the strap's real bottom, instead of the old (wrong)
  // footing-top baseline — and terminated with a proper curved hook
  // (hookPath, defined above this function) instead of a straight tick,
  // matching standard rebar-detailing convention.
  {
    const sx1 = xPx(f1.endMM), sx2 = xPx(f2.startMM);
    const topY = groundY - strap.topBarDepthMM * scale;
    const botY = groundY - strap.bottomBarDepthMM * scale;
    const hookR = 9, hookTail = 16;
    const topW = barLineWidthPx(strap.topBarDia), botW = barLineWidthPx(strap.bottomBarDia);
    svg += `<line x1="${barX1 + hookR}" y1="${topY}" x2="${barX2 - hookR}" y2="${topY}" class="bar-top" style="stroke-width:${topW}px"/>`;
    svg += `<path d="${hookPath(barX1 + hookR, topY, hookR, hookTail, -1, 1)}" class="bar-top" fill="none" style="stroke-width:${topW}px"/>`;
    svg += `<path d="${hookPath(barX2 - hookR, topY, hookR, hookTail, 1, 1)}" class="bar-top" fill="none" style="stroke-width:${topW}px"/>`;
    svg += `<line x1="${barX1 + hookR}" y1="${botY}" x2="${barX2 - hookR}" y2="${botY}" class="bar-bottom" style="stroke-width:${botW}px"/>`;
    svg += `<path d="${hookPath(barX1 + hookR, botY, hookR, hookTail, -1, -1)}" class="bar-bottom" fill="none" style="stroke-width:${botW}px"/>`;
    svg += `<path d="${hookPath(barX2 - hookR, botY, hookR, hookTail, 1, -1)}" class="bar-bottom" fill="none" style="stroke-width:${botW}px"/>`;

    for (const levelMM of strap.shrinkageLevelsMM) {
      const y = groundY - levelMM * scale;
      svg += `<line x1="${sx1 + 4}" y1="${y}" x2="${sx2 - 4}" y2="${y}" class="bar-line-shrinkage" style="stroke-width:${barLineWidthPx(strap.shrinkageBarDia)}px"/>`;
    }

    for (const tickX of distributeTicks(sx1 + 6, sx2 - 6, Math.min(strap.stirrupCount, 14))) {
      svg += stirrupTick(tickX, topY, botY);
    }
    labels += `<text x="${(sx1 + sx2) / 2}" y="${strapTopY - 10}" text-anchor="middle" dir="${l.dirAttr}" class="pad-tag">${esc(l.strapLabel)}</text>`;

    svg += dimensionLine(sx1, strapTopY - 26, sx2, strapTopY - 26, `${Math.round(clearStrapMM)}mm`, { orientation: 'h', tick: 5 });
  }

  svg += labels;
  svg += `</g>`;
  return svg;
}

// True cross-section, cut perpendicular to the strap axis at the CHOSEN
// column (sectionThrough — one input field, reused nowhere else now that
// renderTransSection is gone). Three rectangles stacked on one shared
// vertical centerline — footing (widest), strap
// (mid), column stub (narrowest) — matching Fig. 6-16's own قطاع ١-١
// exactly: every bar family that runs LENGTHWISE along the strap/column
// (dowels, strap top/bottom/shrinkage bars) is cut END-ON here and drawn
// as barDot() circles — the opposite simplification from
// renderLongSection above, which collapses those same families to lines
// because IT cuts them in-plane. The footing's own two-way mesh is not
// repeated here (already fully shown in the pre-existing renderTransSection,
// a few hundred mm away along the strap axis on the same sheet) — this
// view's own job is the column/strap junction specifically.
function renderSection11(geometry, box, l) {
  const chosen = geometry.sectionThrough === 2 ? geometry.footing2 : geometry.footing1;
  const { strap } = geometry;
  const stubHeightMM = strap.depthMM * COLUMN_STUB_HEIGHT_FRACTION;
  const contentW = Math.max(chosen.breadthMM, chosen.plain?.breadthMM ?? 0, strap.widthMM, chosen.colWidthMM);
  // Footing and strap share ONE bottom (groundY below) — see
  // renderLongSection's own header for the full reasoning — so content
  // height is whichever of the two is taller, plus the stub, not both
  // stacked.
  const contentH = Math.max(strap.depthMM, chosen.thicknessMM) + stubHeightMM;
  const scale = fitScale([{ contentW, contentH, boxW: box.w - 120, boxH: box.h - 90 }]);
  const cx = box.x + box.w / 2;
  // groundY: the shared bottom BOTH the footing and the strap rise from
  // (screen-Y, largest value = lowest on screen) — not "footing top" as
  // an earlier revision measured every bar position from; see
  // renderLongSection's own header for the citation against Fig. 6-16.
  const groundY = box.y + 30 + contentH * scale;
  const strapTopY = groundY - strap.depthMM * scale;
  const footingTopY = groundY - chosen.thicknessMM * scale;
  const stubTopY = strapTopY - stubHeightMM * scale;
  // Footing's own mesh bottom row, in advance of drawing either the
  // footing or the strap — needed by both (the footing block below, and
  // the strap's own bottom-bar clamp further down) and cheap to compute
  // from numbers already known at this point.
  const meshInsetPx = chosen.coverMM * scale;
  const meshBottomRowY = footingTopY + chosen.thicknessMM * scale - meshInsetPx;

  let svg = `<g class="section11-view">`;
  let labels = `<text x="${cx}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.section11)}</text>`;

  // Column stub (drawn first — light fill, dowels/strap bars painted on
  // top stay visible).
  {
    const cw = chosen.colWidthMM * scale;
    svg += `<rect x="${cx - cw / 2}" y="${stubTopY}" width="${cw}" height="${strapTopY - stubTopY}" class="column-outline"/>`;
    labels += `<text x="${cx}" y="${stubTopY - 8}" text-anchor="middle" dir="${l.dirAttr}" class="pad-tag">${esc(l.column)}</text>`;
  }

  // Footing block: outline + soil hatch, drawn BEFORE the strap (fixed
  // z-order — an earlier revision drew the strap's full cage first and
  // the footing's own OPAQUE concrete fill second, which silently
  // painted over every strap bar that fell within the footing's own
  // depth: only the thin neck above the footing's own top ever stayed
  // visible, which is exactly the "isolated small box, no bottom bars
  // visible anywhere inside the footing" screenshot this revision was
  // reported against — the bars were never missing, they were painted
  // over).
  {
    const fw = chosen.breadthMM * scale;
    // Blinding/plain-concrete layer, drawn BELOW the reinforced footing
    // (not flanking it at the same level, as an earlier revision drew
    // pad.plain) — caller's own two-part rule: the REINFORCED footing
    // below carries NO hatch ("لا يوجد تهشير بالقاعده الخرسانيه
    // المسلحه ... نبين فقط التسليح" — show only its reinforcement), the
    // PLAIN layer here KEEPS it ("أسفل القاعده الخرسانيه المسلحه يوجد
    // قاعده خرسانه عاديه بتهشير خرسانه عاديه" — nothing reinforced sits
    // there to obscure, so hatch is the only cue it reads as concrete
    // and not soil). See PLAIN_CONCRETE_THICKNESS_MM's own note for why
    // this layer is unconditional; pad.plain's own breadthMM still
    // widens it when supplied, otherwise it matches the footing above.
    const plainH = PLAIN_CONCRETE_THICKNESS_MM * scale;
    const plainW = chosen.plain ? chosen.plain.breadthMM * scale : fw;
    const plainX1 = cx - plainW / 2, plainX2 = cx + plainW / 2;
    const plainBottomY = groundY + plainH;
    svg += `<rect x="${plainX1 - 16}" y="${plainBottomY}" width="${plainX2 - plainX1 + 32}" height="20" fill="url(#soilHatch)" opacity="0.5"/>`;
    svg += `<rect x="${plainX1}" y="${groundY}" width="${plainX2 - plainX1}" height="${plainH}" class="footing-outline" style="fill:url(#concreteHatch)"/>`;
    if (chosen.plain) {
      labels += `<text x="${plainX1 - 10}" y="${groundY + plainH - 6}" text-anchor="end" dir="${l.dirAttr}" class="rebar-note">${esc(l.plainFooting)}</text>`;
      svg += dimensionLine(plainX1, plainBottomY + 20, plainX2, plainBottomY + 20, `${Math.round(chosen.plain.breadthMM)}mm`, { orientation: 'h', tick: 5 });
    }

    svg += `<rect x="${cx - fw / 2}" y="${footingTopY}" width="${fw}" height="${chosen.thicknessMM * scale}" class="footing-outline"/>`;

    // Footing's own bottom mesh: bar dots ONLY, one row, no enclosing
    // zone rectangle and no row near the top. Caller rule: "الاسياخ
    // العلويه في القاعده احذفها. لا يوجد أي أسياخ علويه لا طوليه ولا
    // عرضيه" — a real bottom-only mat has no bars anywhere near the
    // footing's own top face; the earlier revision's rectangle with
    // dots at both its top and bottom edges read as a top layer AND a
    // bottom layer, which this footing never has. meshInsetPx/
    // meshBottomRowY were already computed above (shared with the
    // strap's own bottom-bar clamp further below).
    {
      const meshX1 = cx - fw / 2 + meshInsetPx, meshX2 = cx + fw / 2 - meshInsetPx;
      svg += `<line x1="${meshX1}" y1="${meshBottomRowY}" x2="${meshX2}" y2="${meshBottomRowY}" class="mesh-line" style="stroke-width:${barLineWidthPx(chosen.mesh.dia)}px"/>`;
      const dotSpanPx = meshX2 - meshX1;
      const dotStep = Math.max(28, dotSpanPx / 10);
      for (let dx = 6; dx <= dotSpanPx - 6; dx += dotStep) {
        svg += weightedBarDot(meshX1 + dx, meshBottomRowY, chosen.mesh.dia, 'mesh');
      }
    }

    labels += `<text x="${cx + fw / 2 + 10}" y="${groundY - 6}" text-anchor="start" dir="${l.dirAttr}" class="rebar-note">${esc(l.reinforcedFooting)}</text>`;
    svg += dimensionLine(cx - fw / 2, groundY + 28, cx + fw / 2, groundY + 28, `${Math.round(chosen.breadthMM)}mm`, { orientation: 'h', tick: 5 });
  }

  // Strap cross-section, drawn AFTER the footing (see this function's
  // own header above for why) so every one of its bars — including the
  // ones that fall inside the footing's own depth — stays visible on
  // top of both concrete fills. Full-depth rectangle (groundY up to
  // strapTopY) plus its own stirrup outline and every lengthwise bar
  // family cut end-on (top/bottom/shrinkage): caller rule "قطاع الشداد
  // يرسم داخل القاعده بالكانه والتسليح كامل" — the strap's section is
  // drawn INSIDE the footing with its own stirrup AND full
  // reinforcement, because this cut passes through the strap, the
  // footing, AND the column neck together, not any one of them alone.
  {
    const sw = strap.widthMM * scale;
    const sx = cx - sw / 2;
    svg += `<rect x="${sx}" y="${strapTopY}" width="${sw}" height="${groundY - strapTopY}" class="strap-outline"/>`;

    const stirrupInset = strap.coverMM * scale;
    svg += `<rect x="${sx + stirrupInset}" y="${strapTopY + stirrupInset}" width="${sw - 2 * stirrupInset}" height="${(groundY - strapTopY) - 2 * stirrupInset}" class="stirrup-outline" style="stroke-width:${barLineWidthPx(strap.stirrupDia)}px"/>`;

    const topY = groundY - strap.topBarDepthMM * scale;
    for (const off of strap.topBars) svg += weightedBarDot(sx + off * scale, topY, strap.topBarDia, 'top');

    // Bottom bars: caller rule "أسياخ الحديد المقطوع الدائرية لابد أن
    // تزاح لأعلى فهي الان متقاطعة مع سنتر لاين الحديد" — at their own
    // natural depth (cover+stirrup+half-dia up from groundY) these can
    // land within a dot's-width of the footing's own mesh bottom row
    // (meshBottomRowY above — both measure up from the same shared
    // groundY, with cover values close enough in practice to nearly
    // coincide), reading as one merged smear instead of two distinct
    // bars. Clamped to sit at least both dots' own radii + a hair above
    // that mesh row, never lower than its own natural depth.
    const botYNatural = groundY - strap.bottomBarDepthMM * scale;
    const botClearancePx = barDotRadiusPx(strap.bottomBarDia) + barDotRadiusPx(chosen.mesh.dia) + 1.5;
    const botY = Math.min(botYNatural, meshBottomRowY - botClearancePx);
    for (const off of strap.bottomBars) svg += weightedBarDot(sx + off * scale, botY, strap.bottomBarDia, 'bottom');

    for (const pt of strap.shrinkagePoints) {
      const y = groundY - pt.depthMM * scale;
      svg += weightedBarDot(cx + pt.yLocalMM * scale, y, strap.shrinkageBarDia, 'shrinkage');
    }
    labels += `<text x="${sx - 10}" y="${(strapTopY + groundY) / 2}" text-anchor="end" dir="${l.dirAttr}" class="rebar-note">${esc(l.shrinkageBars)}</text>`;
  }

  // Column dowels, projected onto this section from their own real plan
  // positions (every dowel shown, regardless of how far along the
  // column's OWN depth axis it actually sits — the standard structural-
  // drawing convention for a column bar layout shown in a typical
  // section; see this file's header for the citation). Vertically
  // centered in the stub — stubTopY < strapTopY always, by construction.
  const dowelY = stubTopY + (strapTopY - stubTopY) / 2;
  for (const pt of chosen.dowels.points) {
    svg += weightedBarDot(cx + pt.yLocalMM * scale, dowelY, chosen.dowels.dia, 'dowel');
  }

  // Strap width is not re-dimensioned here: the column stub sits flush
  // on top of the strap with no gap (see this function's own header), so
  // any horizontal dimension line "above the strap" would land inside
  // the column instead — and the width is already dimensioned in both
  // the plan view and the pre-existing transverse section. The strap's
  // own dimension line now spans its FULL depth (strapTopY to groundY),
  // not just the neck above the footing — matching strap.depthMM's own
  // meaning as the beam's total depth, not the visible-above-footing
  // portion alone.
  svg += dimensionLine(cx + (chosen.breadthMM * scale) / 2 + 46, footingTopY, cx + (chosen.breadthMM * scale) / 2 + 46, groundY, `${Math.round(chosen.thicknessMM)}mm`, { orientation: 'v', tick: 5 });
  svg += dimensionLine(cx + (strap.widthMM * scale) / 2 + 46, strapTopY, cx + (strap.widthMM * scale) / 2 + 46, groundY, `${Math.round(strap.depthMM)}mm`, { orientation: 'v', tick: 5 });

  const sectionSep = l.dirAttr === 'rtl' ? '  ' : ' \u2014 ';
  labels += `<text x="${cx}" y="${groundY + (chosen.plain ? 74 : 44)}" text-anchor="middle" dir="${l.dirAttr}" class="rebar-note">${esc(l.dowels)}: ${chosen.dowels.count}\u00d8${Math.round(chosen.dowels.dia)}${sectionSep}${esc(l.topBars)}: ${strap.topBarCount}\u00d8${Math.round(strap.topBarDia)}${sectionSep}${esc(l.bottomBars)}: ${strap.bottomBarCount}\u00d8${Math.round(strap.bottomBarDia)}</text>`;

  svg += labels;
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const { footing1: f1, footing2: f2, strap } = geometry;
  // "element" column renders via table-text-script (Noto Naskh Arabic
  // PRIMARY font) — an em-dash there is the exact same glyph-gap risk
  // this file's header already documents for footing1/footing2, and for
  // the transTitle fix in renderTransSection above. EN keeps the em-dash
  // (no glyph issue in a Latin font); AR uses a plain space instead —
  // same "compose with a plain space" convention used everywhere else in
  // this file for exactly this situation. Fixes F1/F2's own pre-existing
  // use of this pattern too, not just the new rows below.
  const sep = l.dirAttr === 'rtl' ? ' ' : ' \u2014 ';
  return [
    {
      mark: 'F1', element: `${l.mesh}${sep}${l.footing1}`,
      dia: String(Math.round(f1.mesh.dia)),
      count: `@${Math.round(f1.mesh.spacing)}`,
      length: `${Math.round(f1.widthMM)}x${Math.round(f1.breadthMM)}`,
    },
    {
      mark: 'F2', element: `${l.mesh}${sep}${l.footing2}`,
      dia: String(Math.round(f2.mesh.dia)),
      count: `@${Math.round(f2.mesh.spacing)}`,
      length: `${Math.round(f2.widthMM)}x${Math.round(f2.breadthMM)}`,
    },
    {
      // Length reflects the strap's own drawn extent: footing1's outer
      // edge to footing2's outer edge (see renderPlanView/
      // renderLongSection's own header for why this is no longer
      // column-centerline-to-column-centerline, which itself was a
      // correction of an even earlier clear-gap-only extent).
      mark: 'ST1', element: l.topBars,
      dia: String(Math.round(strap.topBarDia)),
      count: String(strap.topBarCount),
      length: String(Math.round(f2.endMM - f1.startMM)),
    },
    {
      mark: 'SB1', element: l.bottomBars,
      dia: String(Math.round(strap.bottomBarDia)),
      count: String(strap.bottomBarCount),
      length: String(Math.round(f2.endMM - f1.startMM)),
    },
    {
      mark: 'SS1', element: l.stirrups,
      dia: String(Math.round(strap.stirrupDia)),
      count: `@${Math.round(strap.stirrupSpacing)} (${strap.stirrupCount})`,
      length: String(Math.round(geometry.clearStrapMM)),
    },
    {
      mark: 'SK1', element: `${l.shrinkageBars}${sep}${l.strapLabel}`,
      dia: String(Math.round(strap.shrinkageBarDia)),
      count: String(strap.shrinkageBarCount),
      length: String(Math.round(geometry.clearStrapMM)),
    },
    {
      // Dowel LENGTH (footing embedment + lap/projection into the
      // column) is a development-length value that depends on concrete
      // grade, bar type, and the governing code's own tables — never
      // fabricated here, same "never compute a fabrication length"
      // contract structuralDrawingKit.mjs's own header states for
      // cuttingLengthMM generally. Shown as —, not a guessed number.
      mark: 'DW1', element: `${l.dowels}${sep}${l.footing1}`,
      dia: String(Math.round(f1.dowels.dia)),
      count: String(f1.dowels.count),
      length: '-', // plain ASCII hyphen, not an em-dash — this cell renders via the schedule table's script-font (Noto Naskh Arabic-primary) column, which is exactly the glyph this file's header already documents as missing
    },
    {
      mark: 'DW2', element: `${l.dowels}${sep}${l.footing2}`,
      dia: String(Math.round(f2.dowels.dia)),
      count: String(f2.dowels.count),
      length: '-', // plain ASCII hyphen, not an em-dash — this cell renders via the schedule table's script-font (Noto Naskh Arabic-primary) column, which is exactly the glyph this file's header already documents as missing
    },
  ];
}

// ── Chat-facing entry point ────────────────────────────────────────────
// Mirrors parseTrapezoidalFootingRebarPayload's error-shape contract
// exactly.
export function parseStrapFootingRebarPayload(raw) {
  try {
    const geometry = computeStrapFootingGeometry(raw);
    return { ok: true, type: 'strap', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Same leading-token + "key=value key=value ..." syntax, same
// BAD_SYNTAX/UNSUPPORTED_TYPE reservation, same never-throws contract,
// error results also carry `.type`, exactly like
// trapezoidalFootingDiagram.mjs's own parseDiagramCommand (this file's
// approved template).
//
// Syntax:
//   /diagram strap id=STF1 span=4000
//     f1width=1800 f1breadth=1800 f1thickness=500 f1cover=50
//     f1colwidth=400 f1coldepth=400 f1edge=100 f1meshdia=16 f1meshspacing=150
//     f1doweldia=16 f1dowelcount=6 [f1plainprojection=75]
//     f2width=2200 f2breadth=2200 f2thickness=500 f2cover=50
//     f2colwidth=450 f2coldepth=450 f2meshdia=16 f2meshspacing=150
//     f2doweldia=16 f2dowelcount=6 [f2plainprojection=75]
//     strapwidth=450 strapdepth=600 strapcover=40
//     straptopdia=16 straptopcount=4 strapbottomdia=20 strapbottomcount=4
//     strapshrinkdia=12 strapshrinkcount=4
//     stirrupdia=10 stirrupspacing=150 [sectionthrough=1] [unit=mm]
//
// f1/f2 dowel*/strap shrink* are REQUIRED as of this revision (breaking
// change — see this file's header for why: an ECP 203 Fig. 6-16 strap
// joint without dowels or shrinkage bars is missing labeled elements of
// that reference detail, not carrying a cosmetic default). Every caller
// built against the pre-dowel/pre-shrinkage contract needs these six new
// keys added. plainprojection stays optional (default: no plain-concrete
// step drawn, byte-identical to every pre-existing caller's own output
// for that part of the drawing). secondaryReinforcementNote has NO flat-
// text key: free text containing spaces does not fit this space-
// delimited key=value grammar — supply it via the object-payload entry
// point (parseStrapFootingRebarPayload) instead.
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: strap key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'strap') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use strap.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const geometry = computeStrapFootingGeometry({
      strapId: kv.id, spanMM: num('span'),
      footing1: {
        widthMM: num('f1width'), breadthMM: num('f1breadth'), thicknessMM: num('f1thickness'), coverMM: num('f1cover'),
        colWidthMM: num('f1colwidth'), colDepthMM: num('f1coldepth'), edgeMM: num('f1edge'),
        mesh: { diameterMM: num('f1meshdia'), spacingMM: num('f1meshspacing') },
        dowels: { diameterMM: num('f1doweldia'), count: num('f1dowelcount') },
        plainProjectionMM: num('f1plainprojection'),
      },
      footing2: {
        widthMM: num('f2width'), breadthMM: num('f2breadth'), thicknessMM: num('f2thickness'), coverMM: num('f2cover'),
        colWidthMM: num('f2colwidth'), colDepthMM: num('f2coldepth'),
        mesh: { diameterMM: num('f2meshdia'), spacingMM: num('f2meshspacing') },
        dowels: { diameterMM: num('f2doweldia'), count: num('f2dowelcount') },
        plainProjectionMM: num('f2plainprojection'),
      },
      strap: {
        widthMM: num('strapwidth'), depthMM: num('strapdepth'), coverMM: num('strapcover'),
        topBarDiaMM: num('straptopdia'), topBarCount: num('straptopcount'),
        bottomBarDiaMM: num('strapbottomdia'), bottomBarCount: num('strapbottomcount'),
        shrinkageBarDiaMM: num('strapshrinkdia'), shrinkageBarCount: num('strapshrinkcount'),
        stirrupDiaMM: num('stirrupdia'), stirrupSpacingMM: num('stirrupspacing'),
      },
      sectionThrough: num('sectionthrough'),
      unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
