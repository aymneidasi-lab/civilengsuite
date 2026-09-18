// corbelDiagram.dxf.mjs
// DXF render path for the corbel/bracket reinforcement diagram — parallel
// to, and entirely separate from, renderCorbelDiagramSVG() in
// corbelDiagram.mjs. Separate file per the project's session-3 decision:
// keeps @tarikjabiri/dxf out of any ordinary /diagram or /rebar (SVG-only)
// module graph.
//
// computeCorbelDiagramGeometry() is consumed exactly as returned, imported
// from corbelDiagram.mjs with zero modification to that file. This module
// only renders; it never validates or computes. Verified directly against
// that file's own compute() return shape before writing this:
//   { type:'corbel', unit, id,
//     geo: { colB, projection, av, h, h1, cover, tieBarDia, tieBarCount,
//            stirrupDia, stirrupCount, bearingPlateWidth, d },
//     tieLayer: { diaMM, count, barCentersMM }, meta: {...} }
//
// v1 scope exclusions carried over unchanged from the prompt: no schedule
// table (DXF TABLE), no long caption paragraph, no Arabic labels (English
// only, hardcoded — not opts.lang-driven, matching every other
// <element>.dxf.mjs in this project). Short per-entity text labels (e.g.
// "Bearing Plate") are NOT "caption text" under that exclusion and were
// already present before this revision.
//
// REVISION (guide-fidelity pass, same request/scope as corbelDiagram.mjs's
// own header note — read that file's header for the full rationale; not
// repeated verbatim here to keep the two files' comments from drifting out
// of sync with each other over time): the bearing-plate edge-distance fix
// needs NO change here (computeCorbelDiagramGeometry() owns that check;
// this file only renders whatever geometry object it's handed). Render-
// side changes, each the DXF-real-mm counterpart of the SVG-pixel fix of
// the same name in corbelDiagram.mjs's own header:
//   - exact-count Ah tie positions (distributeTicks() -> local
//     distributeExact(), same reasoning as the SVG file)
//   - a real 90-degree end hook on the main tie bar (was a bare straight
//     "hookDrop"), arc+line, standard-hook proportions off tieBarDia
//   - column ties immediately above the corbel (tieTickHDXF() — already
//     exported, wasn't being called from this file)
//   - bar-mark tags (barMarkTagDXF() — already exported, wasn't being
//     called from this file) on the main bar, Ah ties, and column ties
//   - a new third view, PLAN AT MAIN-STEEL LEVEL, same hairpin-anchorage
//     geometry as the SVG file's renderPlanAnchorage(), independently
//     re-derived in DXF's own y-up, real-mm arc-angle terms (verified by
//     the same isolated-render-then-inspect method used for the SVG path
//     — see the chat transcript's own geometry proof before this was
//     written into the file; not assumed by analogy with the SVG
//     derivation, since SVG path-arc sweep-flags and DXF start/end angles
//     are different conventions that do not transliterate 1:1).
//
// REVISION 2 (correction pass, mirrors corbelDiagram.mjs's own REVISION 2
// header — read that file for the full corner-by-corner derivation, not
// repeated verbatim here): two errors, both confirmed against a fresh
// high-resolution re-trace of the reference figure, not a guess:
//   - the taper was backwards. TOP is flat (As runs level, no slope) and
//     it is the BOTTOM that slopes — full depth h at the column face,
//     shallower h1 at the tip. renderElevationViewDXF rewritten around a
//     constant topY and a sloped bottomYAt(x).
//   - the PLAN AT MAIN STEEL view's 180-degree hairpin never appeared in
//     the reference. Replaced with what the figure actually shows: main
//     bars run straight through the column, and only the outer bars (by
//     width position) deflect at a shallow ANGLE toward their own
//     nearest column corner; the closed tie is what closes with a
//     rounded hook, at the LOADED end, not the column end. Also added:
//     the four column-corner tie dots, and the bearing-plate footprint
//     at shear span av (this view previously showed no load position at
//     all). renderPlanAnchorageViewDXF rewritten around this reading.
//
// ── AXIS NOTE ──────────────────────────────────────────────────────────
// Unlike stairDiagram.mjs (whose LOCAL profile coordinates are authored
// y-down and need an explicit flip), corbelDiagram.mjs's own renderElevation
// computes every SVG y-pixel directly as "baselineY - realHeightMM*scale"
// — i.e. it already expresses every vertical position as a real mm height
// ABOVE a baseline, just packaged as a screen-space subtraction. That
// real-mm-above-baseline value is already exactly what a y-UP DXF world
// needs, unchanged — no flip arithmetic required here (verified by
// tracing the source's own topYAt()/tieStartY/tieEndY formulas before
// writing this, not assumed by analogy with stairDiagram's different
// case). World origin (0,0) below is the baseline/column-face corner:
// x=0 at the column face (projection direction is +x), y=0 at the
// baseline (the corbel's flat bottom face and the column stub's own
// datum), matching corbelDiagram.mjs's own faceX/baselineY reference
// point one-for-one. The new PLAN view (below) is a SEPARATE local frame
// with its own origin, unrelated to this one — noted at its own function.

import {
  DxfWriter,
  point3d,
  Units,
  LAYERS,
  defineDxfLayers,
  dxfText,
  closedRectDXF,
  closedPolylineDXF,
  barDotDXF,
  stirrupTickVDXF,
  tieTickHDXF,
  barMarkTagDXF,
  dimensionLineDXF,
  minPairwiseDistanceMM,
  DiagramError,
} from '../shared/structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from '../shared/tarikjabiri-dxf.esm.js';

// ── Layout conventions ──────────────────────────────────────────────
// None of these come from geometry or from the prompt; each is a chosen
// default for real-mm placement that the SVG path never needed (it drew
// everything inside a fixed px canvas instead). All overridable via opts,
// all named so they're auditable, per the session's "no magic number" rule.

// Column-stub proportions — direct real-mm translation of corbelDiagram.mjs's
// own renderElevation proportions (colStubW = h*scale*0.55, colTopY =
// baselineY - h*scale*1.5, colBottomY = baselineY + h*scale*0.4): the
// SAME three ratios, applied to real h directly instead of h*scale px, so
// the stub's schematic proportions to the corbel's own principal
// dimension are preserved exactly, just unit-converted.
const COL_STUB_WIDTH_FACTOR = 0.55; // x h — also reused by the new PLAN view's own schematic column "depth", same as corbelDiagram.mjs's COL_STUB_DEPTH_FACTOR
const COL_STUB_ABOVE_FACTOR = 1.5; // x h, height of stub above baseline
const COL_STUB_BELOW_FACTOR = 0.4; // x h, depth of stub below baseline

const TIE_EMBEDMENT_MM = 30; // min embedment length of the main tie bar into the column stub, past the face — mirrors the SVG source's own bare "30" (there, an unconverted px constant with no fixed mm meaning; given a named real-mm value here), still capped by 0.4x the stub width exactly as that source caps it
const STIRRUP_ZONE_START_MIN_MM = 6; // min inset from the column face to the first closed-tie position — mirrors the SVG source's own bare "6"

const PLATE_THICKNESS_MM = 20; // schematic bearing-plate thickness drawn above the corbel's sloped top surface — this geometry has no real plate-thickness input, so this is a representative visual convention, not a design value (same "schematic only" status the file header already assigns the bearing plate itself)
const MARGIN_MM = 300; // gutter around the elevation view for dimension lines/labels
const VIEW_GAP_MM = 600; // real-mm gap between views, model space
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view titles (ELEVATION/SECTION), dimension/plate labels
const DIM_TEXT_HEIGHT_MM = 150;
const NOTE_TEXT_HEIGHT_MM = 110;

function fmt0(mm) {
  return String(Math.round(mm));
}

// ── Standard hook / bend geometry (ACI 318-19 Table 25.3.1) ───────────
// Identical formulas to corbelDiagram.mjs's own (duplicated, not
// imported — the two render paths stay decoupled at the module level per
// this project's own established convention; see that file's header for
// the citation and the "schematic, not a BBS" caveat, not repeated here).
function standardHookBendDiaMM(barDiaMM) {
  if (barDiaMM <= 25) return 6 * barDiaMM;
  if (barDiaMM <= 32) return 8 * barDiaMM;
  return 10 * barDiaMM;
}
function standardHookBendRadiusMM(barDiaMM) {
  return standardHookBendDiaMM(barDiaMM) / 2 + barDiaMM / 2;
}
function standardHook90ExtensionMM(barDiaMM) {
  return 12 * barDiaMM;
}
function standardHook180ExtensionMM(barDiaMM) {
  return Math.max(4 * barDiaMM, 65);
}

// Exact-count position distribution — see corbelDiagram.mjs's own
// distributeExact() header comment for why distributeTicks() (still used
// elsewhere in this file's sibling modules) is the wrong tool for a
// corbel's own Ah count specifically.
function distributeExact(startMM, endMM, count) {
  const n = Math.max(1, Math.round(count));
  if (n === 1) return [(startMM + endMM) / 2];
  const step = (endMM - startMM) / (n - 1);
  return Array.from({ length: n }, (_, i) => startMM + i * step);
}

// One 90-degree hook, DXF world (y-up): the incoming straight run ends at
// (x,y) heading +x; this adds the quarter-circle bend plus a straight
// tail, landing the bar heading -y (down toward the baseline). Center and
// angle span derived and verified (see file header) so the arc's tangent
// is horizontal at (x,y) and vertical at the hand-off point — NOT a
// transliteration of the SVG path's sweep-flag, which has no DXF
// equivalent. Returns the hand-off point so the caller can draw the tail.
function addHookDown90(dxf, x, y, radiusMM, tailMM, layerName) {
  const center = point3d(x, y - radiusMM);
  dxf.addArc(center, radiusMM, 0, 90, { layerName });
  const exX = x + radiusMM;
  const exY = y - radiusMM;
  dxf.addLine(point3d(exX, exY), point3d(exX, exY - tailMM), { layerName });
  return { x: exX, y: exY - tailMM };
}

// One 180-degree hairpin turn, in the PLAN view's own local frame: the
// incoming run ends at (x,y) heading -x (into the column); this adds the
// semicircular bend, landing the bar heading +x (back out), offset by one
// bend diameter in y (dir=+1 toward +y, dir=-1 toward -y) — bulging
// further in the ORIGINAL direction of travel (-x) either way, i.e. away
// from the corbel, which is what makes it a U-turn rather than a hook
// (both straight legs stay in this one plan plane). See file header for
// the derivation. Returns the hand-off point for the return leg.
function addHairpin180(dxf, x, y, radiusMM, dir, layerName) {
  const center = point3d(x, y + dir * radiusMM);
  dxf.addArc(center, radiusMM, 90, 270, { layerName });
  return { x, y: y + dir * 2 * radiusMM };
}

function renderElevationViewDXF(dxf, geometry, origin) {
  const { colB, projection, av, h, h1, cover, tieBarDia, stirrupDia, stirrupCount, bearingPlateWidth, d } = geometry.geo;
  const { x: ox, y: oy } = origin; // (ox,oy) maps to the column-face / FLAT-TOP corner

  // GEOMETRY CORRECTION: TOP is flat -- As runs level at oy across the
  // whole span, no slope -- and the BOTTOM is what slopes: h below the
  // top at the column face, the shallower h1 below the top at the tip.
  const bottomAtFaceY = oy - h;
  const bottomAtTipY = oy - h1;
  const bottomYAt = (xMM) => bottomAtFaceY + (xMM / projection) * (bottomAtTipY - bottomAtFaceY);
  const xAtBottomY = (yMM) => {
    if (yMM >= bottomAtTipY) return projection;
    if (yMM <= bottomAtFaceY) return 0;
    return projection * (yMM - bottomAtFaceY) / (bottomAtTipY - bottomAtFaceY);
  };

  // Column stub (context only -- colB is the only real column dimension
  // this module tracks; see file header's proportions).
  const colStubWidth = h * COL_STUB_WIDTH_FACTOR;
  const colStubTop = oy + h * COL_STUB_ABOVE_FACTOR;
  const colStubBottom = bottomAtFaceY - h * COL_STUB_BELOW_FACTOR;
  closedRectDXF(dxf, ox - colStubWidth, colStubBottom, colStubWidth, colStubTop - colStubBottom, LAYERS.CONCRETE_OUTLINE.name);

  // The column's own longitudinal bars -- context only (no real column
  // reinforcement input; see file header).
  const colBarInset = Math.max(15, colStubWidth * 0.12);
  const colBarXs = [ox - colStubWidth + colBarInset, ox - colBarInset];
  for (const x of colBarXs) {
    dxf.addLine(point3d(x, colStubBottom + 6), point3d(x, colStubTop - 6), { layerName: LAYERS.REBAR_TOP.name });
  }

  // Column ties immediately above the corbel -- GEOMETRY CORRECTION (per
  // direct user review against the reference): a tie wraps the column's
  // own LONGITUDINAL BARS, not the bare concrete width -- previously
  // spanned the full stub width, past both bars into the cover.
  const colTieBandTop = oy + (colStubTop - oy) * 0.82;
  const colTieBandBottom = oy + (colStubTop - oy) * 0.18;
  const colTieYs = distributeExact(colTieBandBottom, colTieBandTop, 2);
  for (const y of colTieYs) tieTickHDXF(dxf, colBarXs[0], colBarXs[1], y, LAYERS.REBAR_BOTTOM.name);

  // Corbel outline: flat top (face to tip) -> down the tip's own short
  // face -> sloped bottom back to the face -> up the face.
  closedPolylineDXF(dxf, [
    { x: ox, y: oy },
    { x: ox + projection, y: oy },
    { x: ox + projection, y: bottomAtTipY },
    { x: ox, y: bottomAtFaceY },
  ], LAYERS.CONCRETE_OUTLINE.name);

  // Main tie bar + 90-degree end hook at the loaded face.
  const tieOffset = cover + tieBarDia / 2;
  const tieY = oy - tieOffset; // level throughout -- no slope on this face
  const tieStartX = ox - Math.min(TIE_EMBEDMENT_MM, colStubWidth * 0.4);
  const hookRadiusMM = Math.min(
    standardHookBendRadiusMM(tieBarDia),
    Math.max(4, (projection - cover) - (TIE_EMBEDMENT_MM + 10)),
  );
  const tieEndX = ox + projection - cover - hookRadiusMM;
  dxf.addLine(point3d(tieStartX, tieY), point3d(tieEndX, tieY), { layerName: LAYERS.REBAR_TOP.name });
  dxfText(dxf, tieStartX + 300, tieY - 60, SUBTITLE_HEIGHT_MM * 0.8, 'As', {
    layerName: LAYERS.REBAR_TOP.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Top,
  });
  const hookBottomAtX = bottomYAt(Math.min(projection, (tieEndX + hookRadiusMM) - ox));
  const maxHookTailMM = Math.max(6, (tieY - hookRadiusMM) - (hookBottomAtX + cover * 0.6));
  const hookTailMM = Math.min(standardHook90ExtensionMM(tieBarDia), maxHookTailMM);
  addHookDown90(dxf, tieEndX, tieY, hookRadiusMM, hookTailMM, LAYERS.REBAR_TOP.name);

  // GEOMETRY CORRECTION (per the same review): Ah is NOT a vertical
  // tick. The reference draws it exactly like As -- a HORIZONTAL bar,
  // level, one per stirrupCount, stacked within (2/3)d of the column
  // face (measured from As down toward the compression face at the
  // column -- "d", not "h"). Each bar is cut off by the real sloped
  // boundary via xAtBottomY(), matching the reference's own bars, which
  // visibly get shorter the further down they sit.
  const zoneBottomY = tieY - (2 / 3) * d;
  const ahColorLayers = [LAYERS.REBAR_EXTRA.name, LAYERS.ZONE_LABEL.name, LAYERS.STIRRUP_TIE.name, LAYERS.REBAR_HORIZONTAL.name];
  const ahYs = distributeExact(tieY - cover * 1.4, Math.max(zoneBottomY, bottomAtFaceY + cover * 0.6), stirrupCount);
  ahYs.forEach((y, i) => {
    const xEndRel = Math.min(xAtBottomY(y) - cover * 0.4, projection - cover * 0.4);
    dxf.addLine(point3d(ox - Math.min(20, colStubWidth * 0.3), y), point3d(ox + Math.max(10, xEndRel), y), { layerName: ahColorLayers[i % ahColorLayers.length] });
  });

  // GEOMETRY ADDITION: the reference also draws secondary horizontal
  // bars BELOW (2/3)d, in the remaining third of d toward the column's
  // compression face -- outside the code-mandated Ah zone (ACI 318
  // 16.5.5.2 / the same ECP clause caps Ah's OWN distribution at 2/3 d,
  // no further), so these are not part of the Ah count either. Fixed at
  // 2, same "placement only, no input for the count" status as the
  // vertical legs and the strut-parallel bar below.
  const extraZoneTop = Math.max(zoneBottomY, bottomAtFaceY + cover * 0.6) - cover * 1.2;
  const extraZoneBottom = bottomAtFaceY + cover * 1.4;
  const extraYs = extraZoneTop > extraZoneBottom ? distributeExact(extraZoneTop, extraZoneBottom, 2) : [];
  for (const y of extraYs) {
    const xEndRel = Math.min(xAtBottomY(y) - cover * 0.4, projection - cover * 0.4);
    dxf.addLine(point3d(ox - Math.min(20, colStubWidth * 0.3), y), point3d(ox + Math.max(10, xEndRel), y), { layerName: LAYERS.REBAR_BOTTOM.name });
  }

  // GEOMETRY ADDITION (per the same review -- vertical ties, named by
  // the reference's own callout, were entirely absent before this):
  // closed ties are RECTANGULAR loops, so the "parallel to As"
  // horizontal legs above need a vertical leg to close them. A fixed,
  // schematic 3 length-positions (no input for how many -- same status
  // as the 2 column ties: placement is real, count is a drawing
  // convention). Each leg runs from As down to the REAL sloped boundary
  // at that x. Colored to match the reference's own choice (same family
  // as the column ties, not the Ah bars).
  const legZoneStartX = ox + Math.max(10, colStubWidth * 0.15);
  const legZoneEndX = ox + projection * 0.68;
  const legXs = distributeExact(legZoneStartX, legZoneEndX, 3);
  for (const x of legXs) {
    dxf.addLine(point3d(x, tieY), point3d(x, bottomYAt(Math.min(x - ox, projection)) + cover * 0.5), { layerName: LAYERS.REBAR_BOTTOM.name });
  }

  // GEOMETRY ADDITION: steel running the length of (parallel and
  // adjacent to) the compression strut line, not just crossing it --
  // drawn as its own offset line alongside the strut, spanning nearly
  // the full sloped face.
  const stirrupOffsetMM = Math.max(10, stirrupDia * 1.5);
  const strutX1 = ox + projection - cover * 1.5;
  const strutY1 = bottomYAt(strutX1 - ox) + cover * 0.5;
  const strutX2 = ox;
  const strutY2 = bottomAtFaceY;
  const strutLen = Math.hypot(strutX2 - strutX1, strutY2 - strutY1) || 1;
  const strutNx = -(strutY2 - strutY1) / strutLen;
  const strutNy = (strutX2 - strutX1) / strutLen;
  dxf.addLine(
    point3d(strutX1 + strutNx * stirrupOffsetMM, strutY1 + strutNy * stirrupOffsetMM),
    point3d(strutX2 + strutNx * stirrupOffsetMM, strutY2 + strutNy * stirrupOffsetMM),
    { layerName: LAYERS.REBAR_BOTTOM.name },
  );
  dxfText(dxf, strutX2 + 40, (strutY1 + strutY2) / 2 - 150, NOTE_TEXT_HEIGHT_MM, 'Ah >= 0.5(As-An)', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Top,
  });

  // Mark 1 -- a short bar near the loaded face, same color/family as the
  // column ties in the reference -- distinct from As (mark 2 there) and
  // drawn just above the bearing plate.
  const mark1Len = Math.max(80, bearingPlateWidth * 0.6);
  const mark1Y = oy + PLATE_THICKNESS_MM + 90;
  dxf.addLine(point3d(ox + av - mark1Len / 2, mark1Y), point3d(ox + av + mark1Len / 2, mark1Y), { layerName: LAYERS.REBAR_BOTTOM.name });

  // Bearing plate -- sits directly on the flat top, no slope to project
  // it onto.
  closedRectDXF(dxf, ox + av - bearingPlateWidth / 2, oy, bearingPlateWidth, PLATE_THICKNESS_MM, LAYERS.BEARING_PLATE.name);
  dxfText(dxf, ox + av, oy + PLATE_THICKNESS_MM + SUBTITLE_HEIGHT_MM * 0.4, SUBTITLE_HEIGHT_MM, 'Bearing Plate', {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });
  dimensionLineDXF(dxf, ox + av + bearingPlateWidth / 2, oy + MARGIN_MM * 0.75, ox + projection, oy + MARGIN_MM * 0.75, `edge >= max(dia,cover)=${fmt0(Math.max(tieBarDia, cover))}mm`, { orientation: 'h', textHeightMM: NOTE_TEXT_HEIGHT_MM });

  // Dimensions -- av, total projection (a) below everything; h (at
  // face), h1 (at tip), d and (2/3)d (from As toward the column-face
  // compression fiber) all measured DOWN from the flat top. d/(2/3)d
  // are a GEOMETRY ADDITION: this zone was computed and used to place
  // ties, but never actually drawn/labeled on the sheet before.
  dimensionLineDXF(dxf, ox, colStubBottom - MARGIN_MM * 0.4, ox + av, colStubBottom - MARGIN_MM * 0.4, `av=${fmt0(av)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox, colStubBottom - MARGIN_MM * 0.8, ox + projection, colStubBottom - MARGIN_MM * 0.8, `a=${fmt0(projection)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.5, oy, ox - MARGIN_MM * 0.5, bottomAtFaceY, `h=${fmt0(h)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 1.1, tieY, ox - MARGIN_MM * 1.1, bottomAtFaceY, `d=${fmt0(d)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 1.6, tieY, ox - MARGIN_MM * 1.6, zoneBottomY, '(2/3)d', { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox + projection + MARGIN_MM * 0.5, oy, ox + projection + MARGIN_MM * 0.5, bottomAtTipY, `h1=${fmt0(h1)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // Bar-mark tags -- mark 1 (main tie), 2 (closed ties), 3 (column
  // ties), matching this element's own SVG path (same three marks).
  barMarkTagDXF(dxf, tieStartX - 200, tieY, '1', LAYERS.MARK_TAGS.name, { leaderTo: { x: tieStartX, y: tieY } });
  if (ahYs.length) {
    barMarkTagDXF(dxf, ox + 150, bottomAtFaceY + 200, '2', LAYERS.MARK_TAGS.name, { leaderTo: { x: legXs[0], y: ahYs[0] } });
  }
  barMarkTagDXF(dxf, ox - colStubWidth - 200, colTieYs[0], '3', LAYERS.MARK_TAGS.name, { leaderTo: { x: colBarXs[0], y: colTieYs[0] } });
  dxfText(dxf, ox - colStubWidth - 200, colTieYs[0] - 250, NOTE_TEXT_HEIGHT_MM, 'Column ties: by column design, not scheduled here', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Top,
  });

  dxfText(dxf, ox + projection / 2, colStubTop + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'ELEVATION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: projection, height: colStubTop - colStubBottom, topY: colStubTop, bottomY: colStubBottom };
}

function renderSectionViewDXF(dxf, geometry, origin) {
  const { colB, h, cover, tieBarDia } = geometry.geo;
  const { tieLayer } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, colB, h, LAYERS.CONCRETE_OUTLINE.name);

  const stirrupInset = cover;
  closedRectDXF(dxf, ox + stirrupInset, oy + stirrupInset, colB - 2 * stirrupInset, h - 2 * stirrupInset, LAYERS.STIRRUP_TIE.name);

  const tieY = oy + h - (cover + tieBarDia / 2); // near the TOP face (tension tie steel), mirrors source's own tieY = sy + (cover+dia/2)*scale measured from the top of its y-down section box
  const centers = tieLayer.barCentersMM.map((c) => ({ x: ox + c, y: tieY }));
  // Real on-drawing pitch for this specific bar layer (evenly spaced
  // across colB by computeBarLayerAcrossWidth(), but the true minimum
  // spacing is still measured live, per the units decision's bar-dot-
  // radius rule — never the schema's static spacing floor).
  const tiePitchMM = minPairwiseDistanceMM(centers);
  for (const c of centers) {
    barDotDXF(dxf, c.x, c.y, tieBarDia, tiePitchMM, LAYERS.REBAR_TOP.name);
  }

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.4, ox + colB, oy - MARGIN_MM * 0.4, `colB=${fmt0(colB)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + colB / 2, oy + h + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: colB, height: h, topY: oy + h };
}

// PLAN AT MAIN-STEEL LEVEL — the reference guide's own "A-A" horizontal
// section: each main bar turns through a 180-degree hairpin around the
// column's far side, the small-diameter (<16mm) anchorage convention the
// guide documents (see corbelDiagram.mjs header for the full citation).
// OWN LOCAL FRAME, unrelated to the elevation's: local x=0 at the
// column/corbel face, +x toward the corbel/tip, -x into the column;
// local y = position across colB (arbitrary sense, consistent within
// this view only). Column "depth" here is the SAME schematic proportion
// of h the elevation's own stub already uses (COL_STUB_WIDTH_FACTOR) —
// not a new real dimension; this module still has no real column-depth
// input (see file header).
function renderPlanAnchorageViewDXF(dxf, geometry, origin) {
  const { colB, h, projection, av, tieBarDia, cover, bearingPlateWidth } = geometry.geo;
  const { tieLayer } = geometry;
  const { x: ox, y: oy } = origin; // maps to the local (0,0): column/corbel face, y=0 edge of colB

  const colDepth = h * COL_STUB_WIDTH_FACTOR;
  const colFarX = ox - colDepth;
  const colTopY = oy + colB;
  const corbelStubDepth = Math.max(150, Math.min(600, projection * 0.6));
  const corbelFarX = ox + corbelStubDepth;

  closedRectDXF(dxf, colFarX, oy, colDepth, colB, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, ox, oy, corbelStubDepth, colB, LAYERS.CONCRETE_OUTLINE.name);
  dxf.addLine(point3d(ox, oy), point3d(ox, colTopY), { layerName: LAYERS.CONCRETE_OUTLINE.name, lineType: 'DASHED' });

  // Bearing-plate footprint at shear span av — addresses "where does the
  // load actually sit", which this view previously showed nowhere.
  const plateFootprintX = ox + av;
  const plateFootprintW = Math.max(10, bearingPlateWidth);
  const rect = [
    { x: plateFootprintX - plateFootprintW / 2, y: oy - 15 },
    { x: plateFootprintX + plateFootprintW / 2, y: oy - 15 },
    { x: plateFootprintX + plateFootprintW / 2, y: colTopY + 15 },
    { x: plateFootprintX - plateFootprintW / 2, y: colTopY + 15 },
  ];
  for (let i = 0; i < 4; i++) {
    dxf.addLine(point3d(rect[i].x, rect[i].y), point3d(rect[(i + 1) % 4].x, rect[(i + 1) % 4].y), { layerName: LAYERS.DIMENSIONS.name, lineType: 'DASHED' });
  }
  dxfText(dxf, plateFootprintX, colTopY + 40, NOTE_TEXT_HEIGHT_MM, 'Bearing Plate', {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  // Main bars: straight through the column; only the bars nearest an
  // edge deflect, at a shallow ANGLE — not a curve — toward that edge's
  // own nearest column corner (REVISION 2: replaces a 180-degree hairpin
  // that does not appear in the reference — see file header).
  const cornerMarginMM = Math.max(9, cover * 1.1);
  const bendZoneStartX = colFarX + Math.max(24, colDepth * 0.3);
  const topEdgeMM = colB / 3;
  const bottomEdgeMM = (colB * 2) / 3;
  const entryX = corbelFarX - Math.max(16, corbelStubDepth * 0.12);

  for (const c of tieLayer.barCentersMM) {
    const y = oy + c;
    let targetY = y;
    if (c < topEdgeMM) targetY = oy + cornerMarginMM;
    else if (c > bottomEdgeMM) targetY = colTopY - cornerMarginMM;
    dxf.addLine(point3d(entryX, y), point3d(bendZoneStartX, y), { layerName: LAYERS.REBAR_TOP.name });
    dxf.addLine(point3d(bendZoneStartX, y), point3d(colFarX + cornerMarginMM, targetY), { layerName: LAYERS.REBAR_TOP.name });
  }

  // Column tie (mark 3) — a closed rectangular loop just inside the
  // column footprint, matching the reference's own drawn shape
  // (previously just 4 unconnected corner dots, no loop between them).
  const tieInsetMM = Math.max(20, cornerMarginMM * 0.7);
  closedRectDXF(dxf, colFarX + tieInsetMM, oy + tieInsetMM, colDepth - 2 * tieInsetMM, colB - 2 * tieInsetMM, LAYERS.REBAR_BOTTOM.name);

  // Column corner dots — at the same corners the loop above passes
  // through, matching the reference's own corner markers (previously
  // absent from this view).
  const corners = [
    { x: colFarX, y: oy }, { x: ox, y: oy },
    { x: colFarX, y: colTopY }, { x: ox, y: colTopY },
  ];
  const cornerPitchMM = minPairwiseDistanceMM(corners);
  for (const { x, y } of corners) barDotDXF(dxf, x, y, tieBarDia, cornerPitchMM, LAYERS.REBAR_BOTTOM.name);

  // Closed tie (Ah), one representative run, closing with a rounded hook
  // at the LOADED end (REVISION 2 — was closing at the column end via
  // the same wrong hairpin; see file header). Positioned in the gap
  // between the first two main bars so it never merges visually with
  // either; falls back to mid-width with a single bar.
  const centers = tieLayer.barCentersMM;
  const tieCMM = centers.length >= 2 ? (centers[0] + centers[1]) / 2 : colB / 2;
  const tieY = oy + tieCMM;
  const tieRadiusMM = Math.max(15, Math.min(60, corbelStubDepth * 0.18));
  const tieBendX = corbelFarX - Math.max(20, tieRadiusMM * 0.7);
  const tieStartX = colFarX + cornerMarginMM + 10;
  dxf.addLine(point3d(tieStartX, tieY), point3d(tieBendX, tieY), { layerName: LAYERS.STIRRUP_TIE.name });
  const handoff = addHairpin180(dxf, tieBendX, tieY, tieRadiusMM, 1, LAYERS.STIRRUP_TIE.name);
  dxf.addLine(point3d(tieBendX, handoff.y), point3d(tieStartX, handoff.y), { layerName: LAYERS.STIRRUP_TIE.name });
  dxfText(dxf, tieStartX + 20, tieY + 30, SUBTITLE_HEIGHT_MM * 0.7, 'Ah', {
    layerName: LAYERS.STIRRUP_TIE.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Bottom,
  });

  // Bar-mark tags — mark 1 (main tie), 2 (closed tie), 3 (column ties).
  barMarkTagDXF(dxf, entryX - 20, colTopY + 200, '1', LAYERS.MARK_TAGS.name, { leaderTo: { x: entryX - 20, y: oy + centers[0] } });
  barMarkTagDXF(dxf, tieStartX + 40, tieY - 200, '2', LAYERS.MARK_TAGS.name, { leaderTo: { x: tieStartX + 40, y: tieY } });
  barMarkTagDXF(dxf, colFarX - 200, oy - 200, '3', LAYERS.MARK_TAGS.name, { leaderTo: { x: colFarX, y: oy } });

  dimensionLineDXF(dxf, colFarX, oy - MARGIN_MM * 0.4, ox, oy - MARGIN_MM * 0.4, 'Column', { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dxfText(dxf, (colFarX + ox) / 2, colTopY + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'PLAN AT MAIN STEEL - ANCHORAGE', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: colDepth + corbelStubDepth, height: colB, topY: colTopY + 60 };
}

export function renderCorbelDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'corbel') {
    throw new DiagramError('BAD_PARAM', 'renderCorbelDiagramDXF expects a geometry object from computeCorbelDiagramGeometry() (type "corbel").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const elevOrigin = { x: 0, y: 0 };
  const elevation = renderElevationViewDXF(dxf, geometry, elevOrigin);

  const gap = opts.viewGapMM ?? VIEW_GAP_MM;
  const sectionOriginX = geometry.geo.projection + gap;
  const section = renderSectionViewDXF(dxf, geometry, { x: sectionOriginX, y: 0 });

  const planOriginX = sectionOriginX + section.width + gap + geometry.geo.h * COL_STUB_WIDTH_FACTOR;
  renderPlanAnchorageViewDXF(dxf, geometry, { x: planOriginX, y: 0 });

  dxfText(dxf, elevOrigin.x + elevation.width / 2, elevation.topY + MARGIN_MM * 0.6, TITLE_HEIGHT_MM, `CORBEL ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
