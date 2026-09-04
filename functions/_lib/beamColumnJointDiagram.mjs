// functions/_lib/beamColumnJointDiagram.mjs
//
// Deterministic, zero-AI SVG generator for a beam-column joint's own
// reinforcement detail (joint elevation + joint-core cross-section +
// bar-bending schedule) — ACI 318 Chapter 18 (special moment frames,
// seismic design): transverse reinforcement WITHIN the joint core,
// beam-bar development/anchorage length into the joint, and the
// no-lap-splice plastic-hinge zone (\u2113o) immediately adjacent to each
// joint face. Same philosophy as footingDiagram.mjs/beamDiagram.mjs/
// columnDiagram.mjs: every dimension, bar position, and count in the
// output is arithmetic on the KB data supplied, never a model's guess.
// This module owns compute+render only; it does not decide bar counts,
// diameters, tie spacing, development length, or joint shear capacity
// \u2014 that is the KB/design layer's job (see INPUT CONTRACT below).
//
// SCOPE (v1): a single rectangular column, continuous straight through
// the joint (no splice drawn at any point through the joint core), with
// exactly ONE beam framing into ONE side of the column at the joint
// (an exterior 2D joint, schematically) \u2014 same "single prismatic
// member, single bar group" simplicity columnDiagram.mjs's own v1 scope
// uses. NOT modeled, on purpose (each needs a parametrization this
// module hasn't been given yet):
//   - beams framing into more than one side of the column (interior /
//     corner joints, or a true 3D joint) \u2014 this schema has no field
//     for a second or third beam; ACI 318 \u00a718.8.3.1's reduced-hoop
//     allowance for joints confined on all four sides by beams is
//     therefore never applied here \u2014 jointTies is always drawn at the
//     spacing the caller supplies, full stop.
//   - joint shear capacity/demand check (Vu vs \u03c6Vn, ACI 318 \u00a718.8.4) \u2014
//     this module draws geometry and supplied reinforcement only, the
//     same "never compute a fabrication-ready or capacity-ready value"
//     boundary structuralDrawingKit.mjs's own header documents for
//     cuttingLengthMM, extended here to joint shear.
//   - development-length CALCULATION (ldh per ACI 318 \u00a718.8.5, or
//     straight ld per Chapter 25) \u2014 developmentLengthMM is an optional
//     caller-supplied override, exactly like columnDiagram.mjs's own
//     cuttingLengthMM; omitting it draws the bar straight through to the
//     column's far face, honestly suffixed, never a fabricated number.
//   - hook bend geometry (90\u00b0 standard hook, hook length lhb, tail
//     extension) for the beam bar's own anchorage \u2014 developmentLengthMM
//     is drawn as one straight dimension only, never bent to look like a
//     hook this module hasn't been given the geometry to defend.
//   - beam bar layout ACROSS beamWidthMM (multiple bars per layer side
//     by side) \u2014 each of beamTopBars/beamBottomBars is drawn as ONE
//     representative line + a count\u00d7dia mark tag, the same
//     "representative pair, not one-per-real-bar" convention
//     columnDiagram.mjs's own elevation uses for its vertical bars.
//     beamWidthMM is still a required, validated field (room check
//     only \u2014 see NO_ROOM_FOR_BEAM_BARS below), just never laid out
//     bar-by-bar or drawn as its own cross-section view.
//   - eccentric beam-to-column offset or a skewed beam axis \u2014 the beam
//     is always centered on the joint core's own vertical span
//     (beamDepthMM sets that span directly) and always perpendicular to
//     the column, on one side.
//   - ordinary column ties OUTSIDE the two hinge zones this module
//     draws \u2014 that stretch of the column is columnDiagram.mjs's own
//     job; this module draws a plain, unreinforced-looking outline
//     stub there (CONTEXT_STUB_MM, a fixed schematic buffer, NOT a
//     real length \u2014 see the render-constants section) purely so the
//     column doesn't appear to end abruptly at the hinge-zone boundary.
//
// \u2500\u2500 INPUT CONTRACT (what the KB layer should hand this module) \u2500\u2500\u2500\u2500\u2500
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   jointId: string,                   // joint mark, e.g. "J-201"
//   columnWidthMM: number,             // column dimension drawn HORIZONTAL
//                                      // in the elevation \u2014 also the
//                                      // direction beam bars are embedded
//                                      // into (same "width = horizontal in
//                                      // elevation" convention
//                                      // columnDiagram.mjs's own elevation
//                                      // uses for its widthMM)
//   columnDepthMM: number,             // column's other in-plan dimension,
//                                      // shown only in the joint-core
//                                      // cross-section (same convention as
//                                      // columnDiagram.mjs's own depthMM)
//   beamWidthMM: number,               // beam's out-of-plane dimension \u2014
//                                      // validated for bar room only, not
//                                      // drawn as its own view (see SCOPE)
//   beamDepthMM: number,               // beam depth \u2014 also SETS the joint
//                                      // core's own vertical extent
//   beamSpanShownMM: number,           // schematic stub length the beam is
//                                      // drawn framing into the joint \u2014
//                                      // NOT a real span (see SCOPE)
//   coverMM: number,                   // shared cover, column and beam alike
//   columnBars: {                      // single group, continuous straight
//                                      // through the joint (see SCOPE)
//     diameterMM: number, count: number,   // count must be EVEN \u2014 same
//                                           // perimeter-symmetry rule
//                                           // columnDiagram.mjs's own
//                                           // ODD_BAR_COUNT check uses
//     cuttingLengthMM?: number,            // full bar length if the KB
//                                          // layer already computed it;
//                                          // omit to show the drawn column
//                                          // height labeled "(extent)"
//   },
//   jointTies: {                       // transverse reinforcement WITHIN
//                                      // the joint core only (ACI 318
//                                      // \u00a718.8.3) \u2014 ordinary column ties
//                                      // outside the two hinge zones are
//                                      // out of scope, see SCOPE above
//     diameterMM: number, spacingMM: number,
//     cuttingLengthMM?: number,          // full tie cutting length incl.
//                                        // hooks, if already computed;
//                                        // omit to show the tie's own bend
//                                        // perimeter, honestly labeled
//                                        // "hooks not included"
//   },
//   hingeZoneMM: number,                // REQUIRED \u2014 \u2113o, the plastic-hinge
//                                       // zone length measured from EACH
//                                       // joint face along the column (ACI
//                                       // 318 \u00a718.7.5.1), where lap splices
//                                       // are prohibited; drawn both above
//                                       // AND below the joint core
//   hingeZoneTieSpacingMM?: number,     // optional tighter tie spacing
//                                       // shown within each hinge zone;
//                                       // omit to leave the zone marked
//                                       // "no splice" only, WITHOUT
//                                       // implying this module computed a
//                                       // specific special spacing itself
//   beamTopBars: {
//     diameterMM: number, count: number,
//     developmentLengthMM?: number,     // anchorage length into the joint,
//                                       // if the KB layer already computed
//                                       // it (see SCOPE \u2014 never computed
//                                       // here); omit to draw the bar
//                                       // straight through to the column's
//                                       // far face, labeled "(extent to
//                                       // far face)"; when supplied, must
//                                       // not exceed columnWidthMM \u2014 see
//                                       // DEV_LENGTH_EXCEEDS_COLUMN below
//   },
//   beamBottomBars: { diameterMM: number, count: number, developmentLengthMM?: number },  // same shape as beamTopBars
// }
//
// \u2500\u2500 Column-bar perimeter layout (computeJointBarPositions) \u2500\u2500\u2500\u2500\u2500\u2500\u2500
// Byte-for-byte the SAME algorithm columnDiagram.mjs's own (private,
// unexported) computeColumnBarPositions uses \u2014 4 corner bars, remaining
// bars split into a top/bottom pair and a left/right pair proportional to
// each pair's own edge length \u2014 duplicated locally rather than imported,
// because that function is module-private in columnDiagram.mjs. Kept
// deliberately identical so a column's own joint-core section and this
// module's joint-core section read as the SAME layout convention to
// anyone comparing the two sheets, not a coincidentally-similar one.
//
// \u2500\u2500 /diagram wiring \u2014 NOT done in this pass, by explicit request \u2500\u2500\u2500
// parseDiagramCommand below exists (schema \u2192 validate \u2192 compute \u2192 render
// \u2192 parseDiagramCommand is this module's own build scope, per the plan
// text governing this session), but diagramCommandRouter.mjs and
// chat.js's three dispatch tables (DIAGRAM_TYPE_RENDERERS /
// DIAGRAM_TYPE_ERROR_MESSAGE / REBAR_ELEMENT_DISPATCH) are UNTOUCHED —
// this element is not reachable from /diagram or /rebar yet. Wiring is a
// separate, later, explicitly-requested integration pass covering every
// unconnected element accumulated by then, not this module alone \u2014 see
// this session's own handoff prompt for the reasoning.
//
// Resource lifecycle: this module is pure/synchronous \u2014 no timers, no
// fetch, no KV, no external handles of any kind. The caps below exist to
// bound Worker CPU time and output size on a request-scoped isolate, not
// to manage a leakable resource.
//
// Fully deterministic: no `env.AI`, no model call, no network fetch, no
// randomness anywhere in this file. Every SVG byte is arithmetic on
// computeBeamColumnJointDiagramGeometry's own output. "Drawn extent" vs
// "actual cut/development length": see cuttingLengthMM/
// developmentLengthMM in the INPUT CONTRACT above and
// structuralDrawingKit.mjs's header for the general rule this file
// follows (buildScheduleRows below falls back to the drawn extent,
// suffixed, only when the caller-supplied length is absent).
//
// PARENTHESES/EM-DASH WARNING: same constraint columnDiagram.mjs's own
// header documents \u2014 Noto Naskh Arabic (the font scriptFontStack selects
// for lang==='ar') has no glyph for "(", ")", or an em/en-dash. Every
// Arabic value below is written parenthesis- and dash-free.

import {
  DiagramError, toMm, assertFinitePositive, assertInt,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, tieTickH, distributeTicks, barMarkTag,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// \u2500\u2500 Sanity caps \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
// Same role as columnDiagram.mjs's own caps: this is a chat-driven
// schematic tool, not a CAD system \u2014 bound worst-case loop counts and
// input ranges so one request can't build an oversized SVG, blow a CPU-
// time budget, or describe a joint that cannot be drawn sanely.
const MIN_SIDE_MM = 150;   // reused for column width/depth AND beam width/
const MAX_SIDE_MM = 3000;  // depth \u2014 all four are schematic section sides
const MIN_BEAM_SPAN_SHOWN_MM = 300;
const MAX_BEAM_SPAN_SHOWN_MM = 4000; // schematic stub only \u2014 not a real span, see SCOPE
const MIN_COL_BAR_COUNT = 4; // a rectangular perimeter needs at least its 4 corners held
const MAX_COL_BAR_COUNT = 40;
const MIN_BEAM_BAR_COUNT = 1;
const MAX_BEAM_BAR_COUNT = 12;
const MIN_TIE_SPACING_MM = 30;
const MAX_TIE_SPACING_MM = 600;
const MIN_HINGE_ZONE_MM = 150;
const MAX_HINGE_ZONE_MM = 3000;
const MAX_DRAWN_TIES_PER_ZONE = 12;   // joint core is much shorter than a full column \u2014 columnDiagram.mjs's own 24 would be excessive here
const MAX_DRAWN_HINGE_TIES = 8;       // each hinge zone, drawn separately

// Fixed schematic visual buffer above/below the two hinge zones so the
// drawn column doesn't appear to end abruptly at the hinge-zone boundary
// \u2014 NOT a real length, NOT a schema field, purely a render constant (see
// SCOPE's last bullet). Total drawn column height is therefore always
// DERIVED (2\u00d7stub + 2\u00d7hingeZoneMM + beamDepthMM), never a separate input,
// so there is no "column too short for its own hinge zones" input class
// to validate against \u2014 it is correct by construction.
const CONTEXT_STUB_MM = 400;

// \u2500\u2500 Compute \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
export function computeBeamColumnJointDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Beam-column joint diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.jointId != null ? String(raw.jointId).slice(0, 40) : 'JOINT';

  const columnWidthMM = toMm(raw.columnWidthMM, unit);
  const columnDepthMM = toMm(raw.columnDepthMM, unit);
  assertFinitePositive('columnWidthMM', columnWidthMM);
  assertFinitePositive('columnDepthMM', columnDepthMM);
  if (columnWidthMM < MIN_SIDE_MM || columnWidthMM > MAX_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"columnWidthMM" must be between ${MIN_SIDE_MM}mm and ${MAX_SIDE_MM}mm for this schematic, got ${columnWidthMM}mm.`);
  }
  if (columnDepthMM < MIN_SIDE_MM || columnDepthMM > MAX_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"columnDepthMM" must be between ${MIN_SIDE_MM}mm and ${MAX_SIDE_MM}mm for this schematic, got ${columnDepthMM}mm.`);
  }

  const beamWidthMM = toMm(raw.beamWidthMM, unit);
  const beamDepthMM = toMm(raw.beamDepthMM, unit);
  assertFinitePositive('beamWidthMM', beamWidthMM);
  assertFinitePositive('beamDepthMM', beamDepthMM);
  if (beamWidthMM < MIN_SIDE_MM || beamWidthMM > MAX_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"beamWidthMM" must be between ${MIN_SIDE_MM}mm and ${MAX_SIDE_MM}mm for this schematic, got ${beamWidthMM}mm.`);
  }
  if (beamDepthMM < MIN_SIDE_MM || beamDepthMM > MAX_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"beamDepthMM" must be between ${MIN_SIDE_MM}mm and ${MAX_SIDE_MM}mm for this schematic, got ${beamDepthMM}mm.`);
  }

  const beamSpanShownMM = toMm(raw.beamSpanShownMM, unit);
  assertFinitePositive('beamSpanShownMM', beamSpanShownMM);
  if (beamSpanShownMM < MIN_BEAM_SPAN_SHOWN_MM || beamSpanShownMM > MAX_BEAM_SPAN_SHOWN_MM) {
    throw new DiagramError('BAD_PARAM', `"beamSpanShownMM" must be between ${MIN_BEAM_SPAN_SHOWN_MM}mm and ${MAX_BEAM_SPAN_SHOWN_MM}mm \u2014 this is a schematic stub length only, not a real beam span (see module SCOPE), got ${beamSpanShownMM}mm.`);
  }

  const coverMM = toMm(raw.coverMM, unit);
  assertFinitePositive('coverMM', coverMM);

  if (!raw.columnBars || typeof raw.columnBars !== 'object') {
    throw new DiagramError('BAD_PARAM', '"columnBars" is required: { diameterMM, count, cuttingLengthMM? }.');
  }
  const colBarDia = toMm(raw.columnBars.diameterMM, unit);
  assertFinitePositive('columnBars.diameterMM', colBarDia);
  assertInt('columnBars.count', raw.columnBars.count, { min: MIN_COL_BAR_COUNT, max: MAX_COL_BAR_COUNT });
  if (raw.columnBars.count % 2 !== 0) {
    throw new DiagramError(
      'ODD_COLUMN_BAR_COUNT',
      `columnBars.count must be even \u2014 this module distributes column bars symmetrically around the section perimeter (same rule columnDiagram.mjs uses) and will not invent an asymmetric layout, got ${raw.columnBars.count}.`,
    );
  }
  const colCuttingLengthMM = raw.columnBars.cuttingLengthMM != null ? toMm(raw.columnBars.cuttingLengthMM, unit) : null;
  if (colCuttingLengthMM != null) assertFinitePositive('columnBars.cuttingLengthMM', colCuttingLengthMM);

  if (!raw.jointTies || typeof raw.jointTies !== 'object') {
    throw new DiagramError('BAD_PARAM', '"jointTies" is required: { diameterMM, spacingMM, cuttingLengthMM? }.');
  }
  const jointTieDia = toMm(raw.jointTies.diameterMM, unit);
  assertFinitePositive('jointTies.diameterMM', jointTieDia);
  const jointTieSpacing = toMm(raw.jointTies.spacingMM, unit);
  assertFinitePositive('jointTies.spacingMM', jointTieSpacing);
  if (jointTieSpacing < MIN_TIE_SPACING_MM || jointTieSpacing > MAX_TIE_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"jointTies.spacingMM" must be between ${MIN_TIE_SPACING_MM}mm and ${MAX_TIE_SPACING_MM}mm, got ${jointTieSpacing}mm.`);
  }
  const jointTieCuttingLengthMM = raw.jointTies.cuttingLengthMM != null ? toMm(raw.jointTies.cuttingLengthMM, unit) : null;
  if (jointTieCuttingLengthMM != null) assertFinitePositive('jointTies.cuttingLengthMM', jointTieCuttingLengthMM);

  const hingeZoneMM = toMm(raw.hingeZoneMM, unit);
  assertFinitePositive('hingeZoneMM', hingeZoneMM);
  if (hingeZoneMM < MIN_HINGE_ZONE_MM || hingeZoneMM > MAX_HINGE_ZONE_MM) {
    throw new DiagramError('BAD_PARAM', `"hingeZoneMM" must be between ${MIN_HINGE_ZONE_MM}mm and ${MAX_HINGE_ZONE_MM}mm, got ${hingeZoneMM}mm.`);
  }
  const hingeZoneTieSpacingMM = raw.hingeZoneTieSpacingMM != null ? toMm(raw.hingeZoneTieSpacingMM, unit) : null;
  if (hingeZoneTieSpacingMM != null) {
    assertFinitePositive('hingeZoneTieSpacingMM', hingeZoneTieSpacingMM);
    if (hingeZoneTieSpacingMM < MIN_TIE_SPACING_MM || hingeZoneTieSpacingMM > MAX_TIE_SPACING_MM) {
      throw new DiagramError('BAD_PARAM', `"hingeZoneTieSpacingMM" must be between ${MIN_TIE_SPACING_MM}mm and ${MAX_TIE_SPACING_MM}mm, got ${hingeZoneTieSpacingMM}mm.`);
    }
  }

  // Beam bar groups \u2014 parsed after columnWidthMM (needed for the
  // DEV_LENGTH_EXCEEDS_COLUMN check below) but before the room check
  // that follows, which needs both groups' own diameters.
  const beamTopBars = parseBeamBarGroup(raw.beamTopBars, unit, 'beamTopBars', columnWidthMM);
  const beamBottomBars = parseBeamBarGroup(raw.beamBottomBars, unit, 'beamBottomBars', columnWidthMM);

  const maxBeamBarDia = Math.max(beamTopBars.dia, beamBottomBars.dia);
  if (beamWidthMM <= 2 * coverMM + maxBeamBarDia) {
    throw new DiagramError('NO_ROOM_FOR_BEAM_BARS', `Cover (${coverMM}mm) and bar diameter (${maxBeamBarDia}mm) leave no room for beam bars inside a ${beamWidthMM}mm-wide beam.`);
  }

  // Column-bar envelope: inset from the column face by cover + joint-tie
  // diameter (the tie loop sits just inside the cover) + half the
  // column bar's own diameter \u2014 the same cover-to-center logic
  // columnDiagram.mjs's own compute uses, applied here against the
  // joint-core cross-section instead of an ordinary column section.
  const insetX = coverMM + jointTieDia + colBarDia / 2;
  const insetY = insetX;
  const innerW = columnWidthMM - 2 * insetX;
  const innerH = columnDepthMM - 2 * insetY;
  if (innerW <= 0 || innerH <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm), joint tie diameter (${jointTieDia}mm), and column bar diameter (${colBarDia}mm) leave no room for column bars inside a ${columnWidthMM}x${columnDepthMM}mm section.`);
  }
  const columnBarPositions = computeJointBarPositions({ innerW, innerH, count: raw.columnBars.count })
    .map((p) => ({ xMM: insetX + p.xMM, yMM: insetY + p.yMM }));

  // Joint-tie outer rectangle sits at `coverMM` from the column face on
  // all four sides, exactly like columnDiagram.mjs's own tie outer rect.
  const jointTieOuter = { x: coverMM, y: coverMM, w: columnWidthMM - 2 * coverMM, h: columnDepthMM - 2 * coverMM };
  if (jointTieOuter.w <= 0 || jointTieOuter.h <= 0) {
    throw new DiagramError('NO_ROOM_FOR_JOINT_TIE', `Cover (${coverMM}mm) leaves no room for a joint tie inside a ${columnWidthMM}x${columnDepthMM}mm section.`);
  }

  // Real (undrawn-cap-free) tie counts \u2014 computed ONCE here, not
  // re-derived independently in both the elevation renderer and the
  // schedule table, so the two can never silently drift apart (the same
  // discipline columnDiagram.mjs's own tieCount computation documents).
  const jointTieCount = Math.max(2, Math.round(beamDepthMM / jointTieSpacing) + 1);
  const hingeTieCountEachZone = hingeZoneTieSpacingMM != null
    ? Math.max(2, Math.round(hingeZoneMM / hingeZoneTieSpacingMM) + 1)
    : null;

  // Total drawn column height and zone boundaries (all in mm, measured
  // from the top of the drawn column) \u2014 derived, not a schema field
  // (see CONTEXT_STUB_MM above).
  const totalColumnHeightMM = 2 * CONTEXT_STUB_MM + 2 * hingeZoneMM + beamDepthMM;
  const zones = {
    hinge1: [CONTEXT_STUB_MM, CONTEXT_STUB_MM + hingeZoneMM],
    core: [CONTEXT_STUB_MM + hingeZoneMM, CONTEXT_STUB_MM + hingeZoneMM + beamDepthMM],
    hinge2: [
      CONTEXT_STUB_MM + hingeZoneMM + beamDepthMM,
      CONTEXT_STUB_MM + 2 * hingeZoneMM + beamDepthMM,
    ],
  };

  return {
    type: 'beamColumnJoint', unit, id,
    columnWidthMM, columnDepthMM, beamWidthMM, beamDepthMM, beamSpanShownMM, coverMM,
    columnBars: { dia: colBarDia, count: raw.columnBars.count, cuttingLengthMM: colCuttingLengthMM, positions: columnBarPositions },
    jointTies: { dia: jointTieDia, spacing: jointTieSpacing, cuttingLengthMM: jointTieCuttingLengthMM, outer: jointTieOuter, count: jointTieCount },
    hingeZoneMM, hingeZoneTieSpacingMM, hingeTieCountEachZone,
    beamTopBars, beamBottomBars,
    totalColumnHeightMM, zones,
  };
}

// See INPUT CONTRACT's beamTopBars/beamBottomBars entry above.
function parseBeamBarGroup(raw, unit, tag, columnWidthMM) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', `"${tag}" is required: { diameterMM, count, developmentLengthMM? }.`);
  }
  const dia = toMm(raw.diameterMM, unit);
  assertFinitePositive(`${tag}.diameterMM`, dia);
  assertInt(`${tag}.count`, raw.count, { min: MIN_BEAM_BAR_COUNT, max: MAX_BEAM_BAR_COUNT });
  const developmentLengthMM = raw.developmentLengthMM != null ? toMm(raw.developmentLengthMM, unit) : null;
  if (developmentLengthMM != null) {
    assertFinitePositive(`${tag}.developmentLengthMM`, developmentLengthMM);
    if (developmentLengthMM > columnWidthMM) {
      throw new DiagramError(
        'DEV_LENGTH_EXCEEDS_COLUMN',
        `"${tag}.developmentLengthMM" (${developmentLengthMM}mm) cannot exceed "columnWidthMM" (${columnWidthMM}mm) \u2014 this module draws a straight embedment only, no hook return (see SCOPE), so a longer bar would run past the column's far face.`,
      );
    }
  }
  return { dia, count: raw.count, developmentLengthMM };
}

// See "Column-bar perimeter layout" note at the top of this file \u2014
// byte-for-byte the same algorithm as columnDiagram.mjs's own (private)
// computeColumnBarPositions. innerW/innerH are the bar-CENTER envelope
// dimensions (already inset from the column face by the caller);
// returned points are relative to that envelope's own top-left corner.
function computeJointBarPositions({ innerW, innerH, count }) {
  const remaining = count - 4; // always even \u2014 enforced by ODD_COLUMN_BAR_COUNT in the caller
  const halfRemaining = remaining / 2;
  const topCount = Math.round((halfRemaining * innerW) / (innerW + innerH));
  const leftCount = halfRemaining - topCount;

  const points = [
    { xMM: 0, yMM: 0 }, { xMM: innerW, yMM: 0 },
    { xMM: innerW, yMM: innerH }, { xMM: 0, yMM: innerH },
  ];
  for (let i = 1; i <= topCount; i++) {
    const x = (innerW * i) / (topCount + 1);
    points.push({ xMM: x, yMM: 0 });
    points.push({ xMM: x, yMM: innerH });
  }
  for (let i = 1; i <= leftCount; i++) {
    const y = (innerH * i) / (leftCount + 1);
    points.push({ xMM: 0, yMM: y });
    points.push({ xMM: innerW, yMM: y });
  }
  return points;
}

// \u2500\u2500 Labels \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
// Local `L = {en:{...}, ar:{...}}` dictionary in THIS file, following
// beamDiagram.mjs's and columnDiagram.mjs's own precedent \u2014 NOT an
// extension of structuralLabels.mjs, which explicitly scopes itself to
// footingDiagram.mjs only (see that file's own header). columnDiagram
// .mjs's header documents the same "least possible change" reasoning at
// greater length; this file follows it without re-arguing it.
const L = {
  en: {
    title: (id) => `BEAM-COLUMN JOINT ${id} \u2014 REINFORCEMENT DETAIL`,
    elevation: 'JOINT ELEVATION', jointCoreSection: 'JOINT CORE SECTION',
    columnVertical: 'Column Vertical', jointTie: 'Joint Tie', hingeTie: 'Hinge-Zone Tie',
    beamTop: 'Beam Top', beamBottom: 'Beam Bottom', hingeZoneNote: 'Hinge Zone',
    jointCoreLabel: 'JOINT CORE', noSpliceShort: 'NO SPLICE', devLenNote: 'development length into joint',
    extentSuffix: ' (extent)', extentToFarFaceSuffix: ' (extent to far face)',
    perimeterSuffix: ' (bend perimeter, hooks not included)',
    tieHookNote: 'add standard hook length per code \u2014 not shown',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design (ACI 318 Chapter 18) before issuing for construction. This drawing does not check joint shear capacity, does not compute development or anchorage length, and does not model hook bend geometry \u2014 supply developmentLengthMM if you want an anchorage length shown; omitting it draws the bar straight through to the column\u2019s far face instead. Lengths marked "(extent)" are the drawn member length only. The joint tie length shown is its bend perimeter only \u2014 add hook and lap length per your design code before fabrication.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد وصلة عمود كمرة ${id}`,
    elevation: 'منظور الوصلة', jointCoreSection: 'قطاع منطقة الوصلة',
    columnVertical: 'رأسي العمود', jointTie: 'كانة منطقة الوصلة', hingeTie: 'كانة منطقة المفصل اللدن',
    beamTop: 'علوي الكمرة', beamBottom: 'سفلي الكمرة', hingeZoneNote: 'منطقة المفصل اللدن',
    jointCoreLabel: 'منطقة الوصلة', noSpliceShort: 'ممنوع التراكب', devLenNote: 'طول الرسو داخل الوصلة',
    extentSuffix: ' امتداد', extentToFarFaceSuffix: ' امتداد حتى الوجه البعيد',
    perimeterSuffix: ' محيط الكانة بدون الكلبتين',
    tieHookNote: 'أضف طول الكلبتين حسب الكود، غير موضح بالرسم',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص ووفق ACI 318 الفصل 18 قبل الاعتماد للتنفيذ. هذا الرسم لا يتحقق من سعة قص الوصلة، ولا يحسب طول الرسو، ولا يوضح هندسة انحناء الكلبة. أدخل طول الرسو إن رغبت بإظهاره؛ بدونه يُرسم السيخ ممتداً حتى الوجه البعيد للعمود. الأطوال المُعلَّمة امتداد هي طول الامتداد فقط. طول كانة الوصلة المذكور هو محيط الانحناء فقط بدون الكلبتين؛ أضف طول التداخل والكلبتين حسب الكود المستخدم.',
    dirAttr: 'rtl',
  },
};

// \u2500\u2500 Render \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
const CANVAS_W = 980;
const JOINT_BOX = { x: 60, y: 110, w: 260, h: 320 };
const ELEV_BOX = { x: 360, y: 110, w: 560, h: 460 };

export function renderBeamColumnJointDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const jointScale = fitScale([{ contentW: geometry.columnWidthMM, contentH: geometry.columnDepthMM, boxW: JOINT_BOX.w - 64, boxH: JOINT_BOX.h - 96 }]);
  const elevScale = fitScale([{ contentW: geometry.columnWidthMM + geometry.beamSpanShownMM, contentH: geometry.totalColumnHeightMM, boxW: ELEV_BOX.w - 90, boxH: ELEV_BOX.h - 40 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = Math.max(JOINT_BOX.y + JOINT_BOX.h, ELEV_BOX.y + ELEV_BOX.h) + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 108);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .joint-title      { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .bar-dot-jointcol { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }
    .joint-core-zone  { fill:#dbe9ff; fill-opacity:0.55; stroke:#1f5aa6; stroke-width:1.4; stroke-dasharray:4,2; }
    .hinge-zone       { fill:#ffe3e3; fill-opacity:0.6; stroke:#b23b3b; stroke-width:1.2; stroke-dasharray:5,3; }
    .zone-caption     { font-size:10.5px; fill:#333; font-family: ${scriptFontStack}; }
    .hinge-caption    { font-size:10.5px; font-weight:bold; fill:#8a2020; font-family: ${scriptFontStack}; }
  `;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="joint-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderJointCoreSection(geometry, jointScale, JOINT_BOX, l)}
  ${renderJointElevation(geometry, elevScale, ELEV_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 108, lineHeight: 15 })}
</svg>`;
}

function renderJointCoreSection(geometry, scale, box, l) {
  const { columnWidthMM, columnDepthMM, columnBars, jointTies } = geometry;
  const w = columnWidthMM * scale, h = columnDepthMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + 30 + (box.h - 100 - h) / 2;
  let svg = `<g class="joint-core-section">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.jointCoreSection)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" class="concrete-outline"/>`;
  const tx = sx + jointTies.outer.x * scale, ty = sy + jointTies.outer.y * scale;
  svg += `<rect x="${tx}" y="${ty}" width="${jointTies.outer.w * scale}" height="${jointTies.outer.h * scale}" class="stirrup-outline"/>`;
  for (const p of columnBars.positions) {
    svg += barDot(sx + p.xMM * scale, sy + p.yMM * scale, columnBars.dia, scale, 'jointcol');
  }
  svg += barMarkTag(sx + w + 24, sy + h / 2, `${columnBars.count}\u00d8${Math.round(columnBars.dia)}`, { r: 13 });
  svg += dimensionLine(sx, sy + h + 20, sx + w, sy + h + 20, `${Math.round(columnWidthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 20, sy, sx - 20, sy + h, `${Math.round(columnDepthMM)}mm`, { orientation: 'v', tick: 5 });
  // Fixed-anchored footer, from the BOX'S OWN bottom edge, not from
  // `sy + h` (the rect's variable bottom) \u2014 same "variable-height
  // element's trailing content must not be positioned relative to its
  // own variable end" discipline columnDiagram.mjs's own renderTieDetail
  // documents and this file re-verified by actual cairosvg rendering
  // (see this session's own verification pass) rather than assumed.
  svg += `<text x="${box.x + box.w / 2}" y="${box.y + box.h - 32}" text-anchor="middle" class="dim-label">\u00d8${Math.round(jointTies.dia)}mm@${Math.round(jointTies.spacing)}mm</text>`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y + box.h - 16}" text-anchor="middle" class="sheet-caption" dir="${l.dirAttr}">${esc(l.tieHookNote)}</text>`;
  svg += `</g>`;
  return svg;
}

function renderJointElevation(geometry, scale, box, l) {
  const {
    columnWidthMM, beamSpanShownMM, totalColumnHeightMM, zones,
    columnBars, jointTies, hingeZoneTieSpacingMM, hingeTieCountEachZone,
    beamTopBars, beamBottomBars,
  } = geometry;

  const colW = columnWidthMM * scale;
  const sx = box.x + 70;
  const topY = box.y + 26;
  const botY = topY + totalColumnHeightMM * scale;
  const yAt = (zMM) => topY + zMM * scale;

  const hinge1Top = yAt(zones.hinge1[0]), hinge1Bot = yAt(zones.hinge1[1]);
  const hinge2Top = yAt(zones.hinge2[0]), hinge2Bot = yAt(zones.hinge2[1]);
  const coreTop = yAt(zones.core[0]), coreBot = yAt(zones.core[1]);

  let svg = `<g class="joint-elevation">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 4}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.elevation)}</text>`;

  svg += `<rect x="${sx}" y="${topY}" width="${colW}" height="${botY - topY}" class="concrete-outline"/>`;
  svg += `<rect x="${sx}" y="${hinge1Top}" width="${colW}" height="${hinge1Bot - hinge1Top}" class="hinge-zone"/>`;
  svg += `<rect x="${sx}" y="${hinge2Top}" width="${colW}" height="${hinge2Bot - hinge2Top}" class="hinge-zone"/>`;
  svg += `<rect x="${sx}" y="${coreTop}" width="${colW}" height="${coreBot - coreTop}" class="joint-core-zone"/>`;

  // Zone captions on the LEFT of the column, opposite the beam (which
  // occupies the right side) \u2014 keeps these labels off the beam stub
  // entirely rather than relying on z-order/opacity to stay legible.
  svg += `<text x="${sx - 10}" y="${(coreTop + coreBot) / 2 - 4}" text-anchor="end" class="zone-caption" dir="${l.dirAttr}">${esc(l.jointCoreLabel)}</text>`;
  svg += `<text x="${sx - 10}" y="${(hinge1Top + hinge1Bot) / 2}" text-anchor="end" class="hinge-caption" dir="${l.dirAttr}">${esc(l.noSpliceShort)}</text>`;
  svg += `<text x="${sx - 10}" y="${(hinge2Top + hinge2Bot) / 2}" text-anchor="end" class="hinge-caption" dir="${l.dirAttr}">${esc(l.noSpliceShort)}</text>`;

  // Beam stub, aligned with the joint core's own vertical span.
  const beamX = sx + colW;
  const beamW = beamSpanShownMM * scale;
  svg += `<rect x="${beamX}" y="${coreTop}" width="${beamW}" height="${coreBot - coreTop}" class="concrete-outline"/>`;

  // Column longitudinal bars \u2014 two representative outer lines, drawn
  // CONTINUOUSLY through the joint core (no break/splice symbol at any
  // point) \u2014 the drawing's own way of showing "continuous through the
  // joint", matching the SCOPE note's "no splice modeled here" choice.
  svg += `<line x1="${sx + 4}" y1="${topY}" x2="${sx + 4}" y2="${botY}" class="bar-bottom"/>`;
  svg += `<line x1="${sx + colW - 4}" y1="${topY}" x2="${sx + colW - 4}" y2="${botY}" class="bar-bottom"/>`;
  svg += barMarkTag(sx - 10, topY + 14, `${columnBars.count}\u00d8${Math.round(columnBars.dia)}`, { r: 12 });

  // Joint ties \u2014 within the joint core's own vertical span only (this
  // module's SCOPE \u2014 ordinary column ties above/below the hinge zones
  // are columnDiagram.mjs's job, not redrawn here).
  const drawnJointTies = Math.min(jointTies.count, MAX_DRAWN_TIES_PER_ZONE);
  for (const ty of distributeTicks(coreTop, coreBot, drawnJointTies)) {
    svg += tieTickH(sx, sx + colW, ty);
  }

  // Hinge-zone ties, only if the caller supplied a tighter spacing \u2014
  // see SCOPE: this module never invents a "special" spacing on its own.
  if (hingeZoneTieSpacingMM != null) {
    const drawnHinge = Math.min(hingeTieCountEachZone, MAX_DRAWN_HINGE_TIES);
    for (const ty of distributeTicks(hinge1Top, hinge1Bot, drawnHinge)) svg += tieTickH(sx, sx + colW, ty);
    for (const ty of distributeTicks(hinge2Top, hinge2Bot, drawnHinge)) svg += tieTickH(sx, sx + colW, ty);
  }

  // Beam bars \u2014 one representative top line + one representative bottom
  // line (same "representative, not one-per-real-bar" convention
  // columnDiagram.mjs's own elevation uses for its vertical bars), each
  // embedded into the column by its own developmentLengthMM, or drawn to
  // the column's far face \u2014 honestly suffixed \u2014 when that value is
  // omitted (see INPUT CONTRACT).
  const topBarY = coreTop + (coreBot - coreTop) * 0.28;
  const botBarY = coreTop + (coreBot - coreTop) * 0.82;
  const beamOuterX = beamX + beamW;

  const topEmbedMM = beamTopBars.developmentLengthMM ?? columnWidthMM;
  const botEmbedMM = beamBottomBars.developmentLengthMM ?? columnWidthMM;
  const topEmbedX = (sx + colW) - topEmbedMM * scale;
  const botEmbedX = (sx + colW) - botEmbedMM * scale;

  svg += `<line x1="${beamOuterX}" y1="${topBarY}" x2="${topEmbedX}" y2="${topBarY}" class="bar-top"/>`;
  svg += `<line x1="${beamOuterX}" y1="${botBarY}" x2="${botEmbedX}" y2="${botBarY}" class="bar-bottom"/>`;
  svg += barMarkTag(beamOuterX + 22, topBarY, `${beamTopBars.count}\u00d8${Math.round(beamTopBars.dia)}`, { r: 12 });
  svg += barMarkTag(beamOuterX + 22, botBarY, `${beamBottomBars.count}\u00d8${Math.round(beamBottomBars.dia)}`, { r: 12 });

  // Development-length dimension \u2014 measured from the joint's near face
  // (column's right face) into the column, for the TOP bar group only
  // (the bottom group's own value is in the schedule table instead, to
  // avoid two overlapping dimension lines this close together on one
  // sheet \u2014 same "one view answers WHERE, the table answers HOW MANY/
  // HOW LONG" split columnDiagram.mjs's own elevation+schedule use).
  svg += dimensionLine(sx + colW, topBarY - 16, topEmbedX, topBarY - 16, `${Math.round(topEmbedMM)}mm`, { orientation: 'h', tick: 5 });
  svg += `<text x="${(sx + colW + topEmbedX) / 2}" y="${topBarY - 26}" text-anchor="middle" class="zone-caption" dir="${l.dirAttr}">${esc(l.devLenNote)}</text>`;

  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  const cb = geometry.columnBars;
  rows.push({
    mark: 'C1', element: l.columnVertical,
    dia: String(Math.round(cb.dia)), count: String(cb.count),
    length: cb.cuttingLengthMM != null ? String(Math.round(cb.cuttingLengthMM)) : `${Math.round(geometry.totalColumnHeightMM)}${l.extentSuffix}`,
  });

  const jt = geometry.jointTies;
  const jtPerimeterMM = 2 * (jt.outer.w + jt.outer.h);
  rows.push({
    mark: 'JT', element: l.jointTie,
    dia: String(Math.round(jt.dia)), count: `@${Math.round(jt.spacing)} (${jt.count})`,
    length: jt.cuttingLengthMM != null ? String(Math.round(jt.cuttingLengthMM)) : `${Math.round(jtPerimeterMM)}${l.perimeterSuffix}`,
  });

  if (geometry.hingeZoneTieSpacingMM != null) {
    rows.push({
      mark: 'HT', element: l.hingeTie,
      dia: String(Math.round(jt.dia)),
      count: `@${Math.round(geometry.hingeZoneTieSpacingMM)} (${geometry.hingeTieCountEachZone}\u00d72)`,
      length: `${Math.round(jtPerimeterMM)}${l.perimeterSuffix}`,
    });
  }

  const bt = geometry.beamTopBars;
  rows.push({
    mark: 'BT', element: l.beamTop,
    dia: String(Math.round(bt.dia)), count: String(bt.count),
    length: bt.developmentLengthMM != null ? String(Math.round(bt.developmentLengthMM)) : `${Math.round(geometry.columnWidthMM)}${l.extentToFarFaceSuffix}`,
  });

  const bb = geometry.beamBottomBars;
  rows.push({
    mark: 'BB', element: l.beamBottom,
    dia: String(Math.round(bb.dia)), count: String(bb.count),
    length: bb.developmentLengthMM != null ? String(Math.round(bb.developmentLengthMM)) : `${Math.round(geometry.columnWidthMM)}${l.extentToFarFaceSuffix}`,
  });

  rows.push({
    mark: '\u2014', element: l.hingeZoneNote,
    dia: '\u2014', count: '\u2014',
    length: String(Math.round(geometry.hingeZoneMM)),
  });

  return rows;
}

// \u2500\u2500 Chat-facing entry point \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
// Mirrors columnDiagram.mjs's parseColumnRebarPayload() error-shape
// contract exactly ({ok:true,...} / {ok:false,code,message}). Never
// throws a DiagramError out; anything else (a genuine programmer error)
// is rethrown, same as every sibling module.
export function parseBeamColumnJointRebarPayload(raw) {
  try {
    const geometry = computeBeamColumnJointDiagramGeometry(raw);
    return { ok: true, type: 'beamColumnJoint', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// \u2500\u2500 Flat-text /diagram command parser \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
// Written now as part of this module's own build (schema \u2192 validate \u2192
// compute \u2192 render \u2192 parseDiagramCommand, per this session's own scope
// for a single new element) \u2014 NOT wired into diagramCommandRouter.mjs or
// chat.js yet; see the "/diagram wiring" note at the top of this file.
// Mirrors columnDiagram.mjs's parseDiagramCommand exactly: same leading-
// token + "key=value key=value ..." syntax, same BAD_SYNTAX/
// UNSUPPORTED_TYPE reservation, same never-throws contract, error
// results also carry `.type`.
//
// Syntax:
//   /diagram beamcolumnjoint id=J1 colwidth=400 coldepth=400
//     beamwidth=300 beamdepth=500 beamspan=800 cover=40
//     colbardia=20 colbarcount=8 jointtiedia=10 jointtiespacing=100
//     hingezone=600 topbardia=20 topbarcount=4 botbardia=18 botbarcount=3
//     [hingetiespacing=75] [unit=mm]
// No key for either bar group's own developmentLengthMM \u2014 override-only
// field with no flat-command key, same precedent columnDiagram.mjs's own
// parseDiagramCommand sets for verticalBars[0].cuttingLengthMM/
// ties.cuttingLengthMM (JSON-payload-only fields).
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: beamcolumnjoint key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'beamcolumnjoint') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use beamcolumnjoint.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const geometry = computeBeamColumnJointDiagramGeometry({
      jointId: kv.id,
      columnWidthMM: num('colwidth'), columnDepthMM: num('coldepth'),
      beamWidthMM: num('beamwidth'), beamDepthMM: num('beamdepth'),
      beamSpanShownMM: num('beamspan'), coverMM: num('cover'),
      columnBars: { diameterMM: num('colbardia'), count: num('colbarcount') },
      jointTies: { diameterMM: num('jointtiedia'), spacingMM: num('jointtiespacing') },
      hingeZoneMM: num('hingezone'), hingeZoneTieSpacingMM: num('hingetiespacing'),
      beamTopBars: { diameterMM: num('topbardia'), count: num('topbarcount') },
      beamBottomBars: { diameterMM: num('botbardia'), count: num('botbarcount') },
      unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
