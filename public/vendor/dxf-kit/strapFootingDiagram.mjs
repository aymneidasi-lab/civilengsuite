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
// SCOPE (v1):
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
//     separate long/short spacings).
//   - the strap beam itself: constant width/depth, one top bar group,
//     one bottom bar group, one stirrup spacing — a typical-section
//     schematic, exactly the scope note every beam-like member in this
//     app already carries (see beamDiagram.mjs's own basic mode).
// NOT modeled, on purpose (same explicit-scope-boundary convention every
// sibling module's header already uses):
//   - more than two footings, or a footing offset across the breadth
//     axis from the strap centerline.
//   - an eccentric INTERIOR footing, a sloped strap, a strap that also
//     bears on soil (this module always treats the strap as spanning a
//     clear, non-bearing gap — see NOT_A_STRAP below, which redirects a
//     near-zero gap to footingDiagram.mjs's own 'combined' type instead
//     of silently drawing a degenerate strap).
//   - pedestals, dowels, top steel on the footings, or more than one
//     bar group/stirrup zone on the strap — same "schematic, not shop
//     drawing" scope every footing/beam module in this app already
//     states.
//   - a computed soil-bearing check or a solver that derives pad sizes
//     from column loads to equalize pressure (the real-world REASON a
//     strap footing is chosen) — this module draws whatever dimensions
//     the caller supplies; verifying they actually equalize bearing
//     pressure is the KB/design layer's job, exactly like
//     trapezoidalFootingDiagram.mjs never decides B1/B2 itself.
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
//   },
//   footing2: {                          // interior pad, column CENTERED
//     widthMM, breadthMM, thicknessMM, coverMM,
//     colWidthMM, colDepthMM,
//     mesh: { diameterMM, spacingMM },
//   },
//   strap: {                             // the connecting beam
//     widthMM,                           // plan width (perpendicular
//                                         // to the strap axis)
//     depthMM,                           // total beam depth (vertical)
//     coverMM,
//     topBarDiaMM, topBarCount,
//     bottomBarDiaMM, bottomBarCount,
//     stirrupDiaMM, stirrupSpacingMM,
//   },
//   sectionThrough?: 1 | 2,              // default 1 — which footing's
//                                         // transverse section is shown
//                                         // (mirrors footingDiagram.mjs/
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
  distributeTicks, svgToDataUri,
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

// ── Compute ──────────────────────────────────────────────────────────

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

  return {
    widthMM, breadthMM, thicknessMM, coverMM, colWidthMM, colDepthMM,
    mesh: {
      dia: meshDiaMM, spacing: meshSpacingMM, alongBreadthLines, alongWidthLines,
    },
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
      topBarDia: topBarDiaMM, topBarCount, topBars,
      bottomBarDia: bottomBarDiaMM, bottomBarCount, bottomBars,
      stirrupDia: stirrupDiaMM, stirrupSpacing: stirrupSpacingMM, stirrupCount,
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
    footing1: 'FOOTING 1 (exterior)', footing2: 'FOOTING 2 (interior)', strapLabel: 'STRAP BEAM',
    mesh: 'Mesh', topBars: 'Top bars', bottomBars: 'Bottom bars', stirrups: 'Stirrups',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design before issuing for construction. This drawing shows one representative bottom mesh layer per footing and one representative strap-beam section only: no top steel or dowels on the footings, no additional bar groups or stirrup zones on the strap. The gap between the two footings is drawn as a non-bearing strap span, not a poured slab.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد القاعدة ذات الرابطة ${id}`,
    plan: 'مسقط', longSection: 'قطاع طولي', transSection: 'قطاع عرضي',
    footing1: 'القاعدة 1 (خارجية)', footing2: 'القاعدة 2 (داخلية)', strapLabel: 'كمرة الرابطة',
    mesh: 'شبكة', topBars: 'حديد علوي', bottomBars: 'حديد سفلي', stirrups: 'كانات',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. يوضح الرسم طبقة تسليح سفلية تمثيلية واحدة لكل قاعدة وقطاعاً تمثيلياً واحداً لكمرة الرابطة فقط، بلا حديد علوي أو برمة على القواعد، وبلا مجموعات أسياخ أو مناطق كانات إضافية بالكمرة. الفجوة بين القاعدتين تمثل امتداد الرابطة غير الحامل على التربة، وليست بلاطة مصبوبة.',
    dirAttr: 'rtl',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 950;
const PLAN_BOX = { x: 80, y: 110, w: 790, h: 220 };
const LONG_SECTION_BOX = { x: 80, y: PLAN_BOX.y + PLAN_BOX.h + 60, w: 790, h: 240 };
const TRANS_SECTION_BOX = { x: 80, y: LONG_SECTION_BOX.y + LONG_SECTION_BOX.h + 60, w: 790, h: 200 };

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
  const tableY = TRANS_SECTION_BOX.y + TRANS_SECTION_BOX.h + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .footing-title   { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .footing-outline { fill:#f4f4f4; stroke:#1a1a1a; stroke-width:1.7; }
    .strap-outline   { fill:#eef2f7; stroke:#1a1a1a; stroke-width:1.7; stroke-dasharray:4,3; }
    .column-outline  { fill:#e2e2e2; stroke:#1a1a1a; stroke-width:1.7; }
    .mesh-line       { stroke:#c0392b; stroke-width:1.2; }
    .pad-tag         { font-size:12px; fill:#333; font-family: ${scriptFontStack}; }
    .rebar-note      { font-size:11px; fill:#333; font-family: ${defaultFontStack}; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="footing-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderPlanView(geometry, PLAN_BOX, l)}
  ${renderLongSection(geometry, LONG_SECTION_BOX, l)}
  ${renderTransSection(geometry, TRANS_SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// Everything drawn on one FIXED horizontal midline (box.y + box.h/2) —
// same anchoring discipline trapezoidalFootingDiagram.mjs's own plan
// view documents (never derive the shared centerline from either pad's
// own half-breadth, which would silently drift the two pads apart from
// the shared strap axis they are actually both centered on).
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

  // Strap beam (drawn first, so the two pads' outlines sit visually on
  // top of it at the seam).
  {
    const x1 = xPx(f1.endMM), x2 = xPx(f2.startMM);
    const halfPx = (strap.widthMM * scale) / 2;
    svg += `<rect x="${x1}" y="${midY - halfPx}" width="${x2 - x1}" height="${halfPx * 2}" class="strap-outline"/>`;
    svg += `<text x="${(x1 + x2) / 2}" y="${midY + halfPx + 16}" text-anchor="middle" dir="${l.dirAttr}" class="pad-tag">${esc(l.strapLabel)}</text>`;
  }

  for (const [pad, tag] of [[f1, l.footing1], [f2, l.footing2]]) {
    const x1 = xPx(pad.startMM), x2 = xPx(pad.endMM);
    const halfPx = (pad.breadthMM * scale) / 2;
    svg += `<rect x="${x1}" y="${midY - halfPx}" width="${x2 - x1}" height="${halfPx * 2}" class="footing-outline"/>`;

    for (const line of pad.mesh.alongBreadthLines) {
      const x = xPx(pad.startMM + line.xLocalMM);
      const h = (line.drawnLengthMM * scale) / 2;
      svg += `<line x1="${x}" y1="${midY - h}" x2="${x}" y2="${midY + h}" class="mesh-line"/>`;
    }
    for (const line of pad.mesh.alongWidthLines) {
      const y = midY - (pad.breadthMM * scale) / 2 + line.yLocalMM * scale;
      const xa = xPx(pad.startMM + (pad.widthMM - line.drawnLengthMM) / 2);
      const xb = xPx(pad.startMM + (pad.widthMM + line.drawnLengthMM) / 2);
      svg += `<line x1="${xa}" y1="${y}" x2="${xb}" y2="${y}" class="mesh-line"/>`;
    }

    svg += `<text x="${(x1 + x2) / 2}" y="${midY - halfPx - 10}" text-anchor="middle" dir="${l.dirAttr}" class="pad-tag">${esc(tag)}</text>`;
  }

  // Columns, at x=0 (footing1) and x=spanMM (footing2) — same
  // depth-as-x-extent/width-as-y-extent convention
  // trapezoidalFootingDiagram.mjs's own plan view uses.
  for (const [pad, xMM] of [[f1, 0], [f2, spanMM]]) {
    const cx = xPx(xMM);
    const cw = pad.colDepthMM * scale, ch = pad.colWidthMM * scale;
    svg += `<rect x="${cx - cw / 2}" y="${midY - ch / 2}" width="${cw}" height="${ch}" class="column-outline"/>`;
  }

  svg += dimensionLine(xPx(0), midY - (maxBreadth * scale) / 2 - 34, xPx(spanMM), midY - (maxBreadth * scale) / 2 - 34, `span=${Math.round(spanMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(xPx(f1.startMM), midY + (maxBreadth * scale) / 2 + 26, xPx(f1.endMM), midY + (maxBreadth * scale) / 2 + 26, `${Math.round(f1.widthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(xPx(f2.startMM), midY + (maxBreadth * scale) / 2 + 26, xPx(f2.endMM), midY + (maxBreadth * scale) / 2 + 26, `${Math.round(f2.widthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(xPx(f1.endMM), midY + (maxBreadth * scale) / 2 + 48, xPx(f2.startMM), midY + (maxBreadth * scale) / 2 + 48, `clear=${Math.round(geometry.clearStrapMM)}mm`, { orientation: 'h', tick: 5 });

  svg += `<text x="${originX + ((drawMinX + drawMaxX) / 2) * scale}" y="${midY + (maxBreadth * scale) / 2 + 68}" text-anchor="middle" dir="${l.dirAttr}" class="view-title">${esc(l.plan)}</text>`;
  svg += `</g>`;
  return svg;
}

// Elevation along the strap axis: both footing profiles (drawn
// DOWNWARD from a shared "top of footing" baseline, matching how they
// actually sit in the ground) with the strap beam (drawn UPWARD from
// that same baseline, since it is cast integrally with the footing
// tops) spanning the clear gap between them, its own top/bottom bars
// and a representative spread of stirrup ticks.
function renderLongSection(geometry, box, l) {
  const {
    footing1: f1, footing2: f2, strap, clearStrapMM,
  } = geometry;
  const drawMinX = f1.startMM, drawMaxX = f2.endMM;
  const totalMM = drawMaxX - drawMinX;
  const maxThickness = Math.max(f1.thicknessMM, f2.thicknessMM);
  const contentH = maxThickness + strap.depthMM;
  const scale = fitScale([{ contentW: totalMM, contentH, boxW: box.w - 100, boxH: box.h - 90 }]);
  const originX = box.x + (box.w - totalMM * scale) / 2 - drawMinX * scale;
  const xPx = (xMM) => originX + xMM * scale;
  const baseline = box.y + 30 + strap.depthMM * scale;

  let svg = `<g class="long-section-view">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.longSection)}</text>`;

  for (const pad of [f1, f2]) {
    const x1 = xPx(pad.startMM), x2 = xPx(pad.endMM);
    const h = pad.thicknessMM * scale;
    svg += `<rect x="${x1 - 16}" y="${baseline + h}" width="${x2 - x1 + 32}" height="20" fill="url(#soilHatch)" opacity="0.5"/>`;
    svg += `<rect x="${x1}" y="${baseline}" width="${x2 - x1}" height="${h}" class="footing-outline" fill="url(#concreteHatch)"/>`;
    const barY = baseline + h - pad.coverMM * scale - pad.mesh.dia * scale / 2;
    svg += `<line x1="${x1 + 4}" y1="${barY}" x2="${x2 - 4}" y2="${barY}" class="mesh-line" stroke-width="2"/>`;
  }

  // Strap beam, spanning the clear gap, drawn upward from the baseline.
  {
    const sx1 = xPx(f1.endMM), sx2 = xPx(f2.startMM);
    const sh = strap.depthMM * scale;
    svg += `<rect x="${sx1}" y="${baseline - sh}" width="${sx2 - sx1}" height="${sh}" class="strap-outline"/>`;

    const topY = baseline - sh + strap.coverMM * scale + strap.stirrupDia * scale + strap.topBarDia * scale / 2;
    const botY = baseline - strap.coverMM * scale - strap.stirrupDia * scale - strap.bottomBarDia * scale / 2;
    svg += `<line x1="${sx1 + 4}" y1="${topY}" x2="${sx2 - 4}" y2="${topY}" class="bar-top"/>`;
    svg += `<line x1="${sx1 + 4}" y1="${botY}" x2="${sx2 - 4}" y2="${botY}" class="bar-bottom"/>`;
    for (const tickX of distributeTicks(sx1 + 6, sx2 - 6, Math.min(strap.stirrupCount, 14))) {
      svg += stirrupTick(tickX, topY, botY);
    }
    svg += `<text x="${(sx1 + sx2) / 2}" y="${baseline - sh - 10}" text-anchor="middle" dir="${l.dirAttr}" class="pad-tag">${esc(l.strapLabel)}</text>`;
  }

  svg += dimensionLine(xPx(f1.endMM), baseline - strap.depthMM * scale - 26, xPx(f2.startMM), baseline - strap.depthMM * scale - 26, `${Math.round(clearStrapMM)}mm`, { orientation: 'h', tick: 5 });
  svg += `</g>`;
  return svg;
}

function renderTransSection(geometry, box, l) {
  const chosen = geometry.sectionThrough === 2 ? geometry.footing2 : geometry.footing1;
  const scale = fitScale([{ contentW: chosen.breadthMM, contentH: chosen.thicknessMM, boxW: box.w - 100, boxH: box.h - 80 }]);
  const w = chosen.breadthMM * scale, h = chosen.thicknessMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + 30;

  let svg = `<g class="trans-section-view">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.transSection)} (${geometry.sectionThrough === 2 ? l.footing2 : l.footing1})</text>`;
  svg += `<rect x="${sx - 20}" y="${sy + h}" width="${w + 40}" height="26" fill="url(#soilHatch)" opacity="0.5"/>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" class="footing-outline" fill="url(#concreteHatch)"/>`;

  const barY = sy + h - chosen.coverMM * scale - chosen.mesh.dia * scale / 2;
  svg += `<line x1="${sx + 6}" y1="${barY}" x2="${sx + w - 6}" y2="${barY}" class="mesh-line" stroke-width="2"/>`;

  svg += dimensionLine(sx, sy + h + 20, sx + w, sy + h + 20, `${Math.round(chosen.breadthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 24, sy, sx - 24, sy + h, `${Math.round(chosen.thicknessMM)}mm`, { orientation: 'v', tick: 5 });
  svg += `<text x="${sx + w / 2}" y="${sy + h + 40}" text-anchor="middle" class="rebar-note">${Math.round(chosen.mesh.dia)}\u00d8@${Math.round(chosen.mesh.spacing)}</text>`;
  svg += `<text x="${sx + w / 2}" y="${sy + h + 54}" text-anchor="middle" dir="${l.dirAttr}" class="rebar-note">${esc(l.mesh)}</text>`;
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const { footing1: f1, footing2: f2, strap } = geometry;
  return [
    {
      mark: 'F1', element: `${l.mesh} \u2014 ${l.footing1}`,
      dia: String(Math.round(f1.mesh.dia)),
      count: `@${Math.round(f1.mesh.spacing)}`,
      length: `${Math.round(f1.widthMM)}x${Math.round(f1.breadthMM)}`,
    },
    {
      mark: 'F2', element: `${l.mesh} \u2014 ${l.footing2}`,
      dia: String(Math.round(f2.mesh.dia)),
      count: `@${Math.round(f2.mesh.spacing)}`,
      length: `${Math.round(f2.widthMM)}x${Math.round(f2.breadthMM)}`,
    },
    {
      mark: 'ST1', element: l.topBars,
      dia: String(Math.round(strap.topBarDia)),
      count: String(strap.topBarCount),
      length: String(Math.round(geometry.clearStrapMM)),
    },
    {
      mark: 'SB1', element: l.bottomBars,
      dia: String(Math.round(strap.bottomBarDia)),
      count: String(strap.bottomBarCount),
      length: String(Math.round(geometry.clearStrapMM)),
    },
    {
      mark: 'SS1', element: l.stirrups,
      dia: String(Math.round(strap.stirrupDia)),
      count: `@${Math.round(strap.stirrupSpacing)} (${strap.stirrupCount})`,
      length: String(Math.round(geometry.clearStrapMM)),
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
//     f2width=2200 f2breadth=2200 f2thickness=500 f2cover=50
//     f2colwidth=450 f2coldepth=450 f2meshdia=16 f2meshspacing=150
//     strapwidth=350 strapdepth=600 strapcover=40
//     straptopdia=16 straptopcount=4 strapbottomdia=20 strapbottomcount=4
//     stirrupdia=10 stirrupspacing=150 [sectionthrough=1] [unit=mm]
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
      },
      footing2: {
        widthMM: num('f2width'), breadthMM: num('f2breadth'), thicknessMM: num('f2thickness'), coverMM: num('f2cover'),
        colWidthMM: num('f2colwidth'), colDepthMM: num('f2coldepth'),
        mesh: { diameterMM: num('f2meshdia'), spacingMM: num('f2meshspacing') },
      },
      strap: {
        widthMM: num('strapwidth'), depthMM: num('strapdepth'), coverMM: num('strapcover'),
        topBarDiaMM: num('straptopdia'), topBarCount: num('straptopcount'),
        bottomBarDiaMM: num('strapbottomdia'), bottomBarCount: num('strapbottomcount'),
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
