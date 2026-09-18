// corbelDiagram.dxf.mjs
// DXF render path for the corbel/bracket reinforcement diagram — parallel
// to, and entirely separate from, renderCorbelDiagramSVG() in
// corbelDiagram.mjs. Separate file per the project's session-3 decision:
// keeps @tarikjabiri/dxf out of any ordinary /diagram or /rebar (SVG-only)
// module graph.
//
// computeCorbelDiagramGeometry() is consumed exactly as returned, imported
// from corbelDiagram.mjs with zero modification to that file. This module
// only renders; it never validates or computes.
//
// v1 scope exclusions carried over unchanged from the prompt: no schedule
// table (DXF TABLE), no long caption paragraph, no Arabic labels (English
// only, hardcoded — not opts.lang-driven, matching every other
// <element>.dxf.mjs in this project). Short per-entity text labels (e.g.
// "Bearing Plate") are NOT "caption text" under that exclusion.
//
// REVISION 3. Same scope as corbelDiagram.mjs's REVISION 4. No compute-side
// change: computeCorbelDiagramGeometry()'s input contract and return shape
// are byte-identical to the previous revision. Render-side changes only:
//   D1. addHairpin180() renamed to addLoadedEndClosure180() and its doc
//       comment corrected. The old name and its "bulging further in the
//       ORIGINAL direction of travel (-x), i.e. away from the corbel"
//       comment described the discarded main-bar hairpin around the
//       column's far side (removed in REVISION 2), not the shape this
//       function actually draws. The math was already right — a U-turn
//       at the LOADED end of the closed tie — only the name/comment were
//       stale, and a future maintainer trusting them could re-introduce
//       the removed shape.
//   D2. The plan-view tie-closure radius was bounded only by an
//       arbitrary 0.18 * corbelStubDepth. At small colB that could push
//       the return leg past colTopY. Now bounded by the same frame
//       constraint the SVG path uses — (colTopY - tieY - margin)/2 — so
//       the return leg always lands inside the section frame.
//   D3. Plan-view mark 1's leader previously crossed the bearing-plate
//       footprint (a vertical leader at x = entryX - 20, and entryX-20
//       fell inside [plateX ± W/2] for typical CB1 inputs). Mark 1 tag
//       moved to the clear upper-right gutter and its leader shortened
//       so it enters the bar from outside the plate footprint, matching
//       the SVG fix of the same name.
//   D4. The Ah ≥ 0.5(As−An) callout was floating in the column stub at
//       a y no reader associates with the Ah zone. In DXF there is no
//       white-mask primitive equivalent to the SVG path's mask rect, and
//       no placement inside the elevation's own Ah zone is leg-free at
//       the DXF text height (110mm) the rest of the sheet uses. Moved to
//       the margin to the right of the corbel at mid-height, and the
//       file header notes this as an explicit DXF-vs-SVG deviation.
//
// The three RC-render corrections from REVISION 2 (flat top / sloped
// bottom / vertical tip; loaded-end tie closure; corner deflections on
// outer main bars only) are unchanged and untouched by this pass.
//
// REVISION 4 (this pass — integration-fix). Two execution-verified bugs
// found by tracing the module against the kit's own documented contracts,
// neither a logic-rewrite — one wrong arc angle pair, one missing kit
// call:
//   F1. addLoadedEndClosure180() drew its semicircle in the WRONG
//       half-plane. DXF ARC always sweeps CCW from startAngle to
//       endAngle, so the original (90, 270) passed through 180° (left
//       of center) and bulged the closure -x, away from the tip —
//       the exact opposite of the SVG loadedEndClosure180PathD(sweep=1)
//       it is meant to mirror, and the opposite of this file's own
//       D1 comment ("bulges in the direction of travel"). Fixed to
//       (270, 90), which passes through 0° (right of center) and
//       reproduces the SVG shape exactly for BOTH dir values (dir=-1
//       draws the same curve, traversed from far end to near end —
//       visually identical, handoff point unchanged).
//   F2. renderPlanAnchorageViewDXF called dxf.addLine with
//       lineType: 'DASHED' — a bare string — but nothing in this module
//       ever registered a DASHED LTYPE. structuralDrawingDxfKit.mjs's
//       own comment on defineDashedLType() states this exactly: an
//       entity's lineType is written verbatim with no fallback, so an
//       unregistered name dangles (renders continuous in some readers,
//       errors in others, no fixed behavior). Fixed by importing
//       defineDashedLType and DASHED_LTYPE_NAME from the kit, calling
//       defineDashedLType(dxf) once in renderCorbelDiagramDXF right
//       after defineDxfLayers(dxf), and replacing the literal 'DASHED'
//       with the shared constant so the two names cannot drift.
//
// ── AXIS NOTE ──────────────────────────────────────────────────────────
// corbelDiagram.mjs's own renderElevation computes every SVG y-pixel as
// "baselineY - realHeightMM*scale" — i.e. it already expresses every
// vertical position as a real mm height ABOVE a baseline, just packaged
// as a screen-space subtraction. That real-mm-above-baseline value is
// already exactly what a y-UP DXF world needs, unchanged. World origin
// (0,0) below is the baseline/column-face corner: x=0 at the column
// face (projection direction is +x), y=0 at the baseline. The plan view
// is a SEPARATE local frame with its own origin — noted at its own
// function.

import {
  DxfWriter,
  point3d,
  Units,
  LAYERS,
  defineDxfLayers,
  defineDashedLType,
  DASHED_LTYPE_NAME,
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
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// ── Layout conventions ──────────────────────────────────────────────
const COL_STUB_WIDTH_FACTOR = 0.55; // x h — also reused by the plan view's own schematic column "depth"
const COL_STUB_ABOVE_FACTOR = 1.5;  // x h, height of stub above baseline
const COL_STUB_BELOW_FACTOR = 0.4;  // x h, depth of stub below baseline

const TIE_EMBEDMENT_MM = 30;
const STIRRUP_ZONE_START_MIN_MM = 6;

const PLATE_THICKNESS_MM = 20;
const MARGIN_MM = 300;
const VIEW_GAP_MM = 600;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 150;
const NOTE_TEXT_HEIGHT_MM = 110;

// D2 (this revision): minimum y-gap the plan view's Ah return leg keeps
// from the column frame's own top edge. Named so the frame constraint is
// auditable, not a bare constant.
const PLAN_RETURN_LEG_MARGIN_MM = 20;

function fmt0(mm) {
  return String(Math.round(mm));
}

// ── Standard hook / bend geometry (ACI 318-19 Table 25.3.1) ───────────
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

function distributeExact(startMM, endMM, count) {
  const n = Math.max(1, Math.round(count));
  if (n === 1) return [(startMM + endMM) / 2];
  const step = (endMM - startMM) / (n - 1);
  return Array.from({ length: n }, (_, i) => startMM + i * step);
}

// One 90-degree hook, DXF world (y-up): the incoming straight run ends at
// (x,y) heading +x; this adds the quarter-circle bend plus a straight
// tail, landing the bar heading -y. Center and angle span derived and
// verified so the arc's tangent is horizontal at (x,y) and vertical at
// the hand-off point. Returns the hand-off point.
function addHookDown90(dxf, x, y, radiusMM, tailMM, layerName) {
  const center = point3d(x, y - radiusMM);
  dxf.addArc(center, radiusMM, 0, 90, { layerName });
  const exX = x + radiusMM;
  const exY = y - radiusMM;
  dxf.addLine(point3d(exX, exY), point3d(exX, exY - tailMM), { layerName });
  return { x: exX, y: exY - tailMM };
}

// D1: renamed from addHairpin180. This draws the closed tie (Ah)'s own
// 180-degree closure at the LOADED (tip) end of the corbel — NOT the
// main-bar anchorage around the column's far side, which does not appear
// in the reference and was removed in REVISION 2. Both straight legs stay
// in this one plan plane (unlike a hook, which leaves the plane), and the
// semicircle bulges in the direction of travel so the return leg sits one
// bend diameter behind the incoming leg.
//
// F1 (REVISION 4): DXF ARC always sweeps CCW from startAngle to endAngle
// in the entity's own coordinate system, so a chord-vertical semicircle
// with center at (x, y+dir*r) is only correct as (270, 90) — that span
// passes through 0° (right of center), producing a +x bulge that matches
// SVG's loadedEndClosure180PathD(sweep=1) exactly. The original (90, 270)
// passed through 180° and bulged -x, producing the mirror image of the
// SVG shape and contradicting this function's own comment above. Because
// the entity is a curve (direction-agnostic for rendering), the same
// (270, 90) span is correct for dir=-1 as well: it draws the same
// semicircle from far end to near end, and the handoff point returned
// below is unchanged. Returns the hand-off point for the return leg.
function addLoadedEndClosure180(dxf, x, y, radiusMM, dir, layerName) {
  const center = point3d(x, y + dir * radiusMM);
  dxf.addArc(center, radiusMM, 270, 90, { layerName });
  return { x, y: y + dir * 2 * radiusMM };
}

function renderElevationViewDXF(dxf, geometry, origin) {
  const { colB, projection, av, h, h1, cover, tieBarDia, stirrupDia, stirrupCount, bearingPlateWidth, d } = geometry.geo;
  const { x: ox, y: oy } = origin;

  // Flat top; sloped bottom (h at face, h1 at tip); vertical tip face.
  const bottomAtFaceY = oy - h;
  const bottomAtTipY = oy - h1;
  const bottomYAt = (xMM) => bottomAtFaceY + (xMM / projection) * (bottomAtTipY - bottomAtFaceY);
  const xAtBottomY = (yMM) => {
    if (yMM >= bottomAtTipY) return projection;
    if (yMM <= bottomAtFaceY) return 0;
    return projection * (yMM - bottomAtFaceY) / (bottomAtTipY - bottomAtFaceY);
  };

  // Column stub (context).
  const colStubWidth = h * COL_STUB_WIDTH_FACTOR;
  const colStubTop = oy + h * COL_STUB_ABOVE_FACTOR;
  const colStubBottom = bottomAtFaceY - h * COL_STUB_BELOW_FACTOR;
  closedRectDXF(dxf, ox - colStubWidth, colStubBottom, colStubWidth, colStubTop - colStubBottom, LAYERS.CONCRETE_OUTLINE.name);

  // Column longitudinal bars (context).
  const colBarInset = Math.max(15, colStubWidth * 0.12);
  const colBarXs = [ox - colStubWidth + colBarInset, ox - colBarInset];
  for (const x of colBarXs) {
    dxf.addLine(point3d(x, colStubBottom + 6), point3d(x, colStubTop - 6), { layerName: LAYERS.REBAR_TOP.name });
  }

  // Column ties immediately above the corbel, wrapping the column's own
  // longitudinal bars (not the bare concrete width).
  const colTieBandTop = oy + (colStubTop - oy) * 0.82;
  const colTieBandBottom = oy + (colStubTop - oy) * 0.18;
  const colTieYs = distributeExact(colTieBandBottom, colTieBandTop, 2);
  for (const y of colTieYs) tieTickHDXF(dxf, colBarXs[0], colBarXs[1], y, LAYERS.REBAR_BOTTOM.name);

  // Corbel outline.
  closedPolylineDXF(dxf, [
    { x: ox, y: oy },
    { x: ox + projection, y: oy },
    { x: ox + projection, y: bottomAtTipY },
    { x: ox, y: bottomAtFaceY },
  ], LAYERS.CONCRETE_OUTLINE.name);

  // Main tie bar + 90-degree end hook.
  const tieOffset = cover + tieBarDia / 2;
  const tieY = oy - tieOffset;
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

  // Ah bars — horizontal, level, cut by the real sloped boundary.
  const zoneBottomY = tieY - (2 / 3) * d;
  const ahColorLayers = [LAYERS.REBAR_EXTRA.name, LAYERS.ZONE_LABEL.name, LAYERS.STIRRUP_TIE.name, LAYERS.REBAR_HORIZONTAL.name];
  const ahYs = distributeExact(tieY - cover * 1.4, Math.max(zoneBottomY, bottomAtFaceY + cover * 0.6), stirrupCount);
  ahYs.forEach((y, i) => {
    const xEndRel = Math.min(xAtBottomY(y) - cover * 0.4, projection - cover * 0.4);
    dxf.addLine(point3d(ox - Math.min(20, colStubWidth * 0.3), y), point3d(ox + Math.max(10, xEndRel), y), { layerName: ahColorLayers[i % ahColorLayers.length] });
  });

  // Extra horizontal bars below (2/3)d, outside the Ah zone.
  const extraZoneTop = Math.max(zoneBottomY, bottomAtFaceY + cover * 0.6) - cover * 1.2;
  const extraZoneBottom = bottomAtFaceY + cover * 1.4;
  const extraYs = extraZoneTop > extraZoneBottom ? distributeExact(extraZoneTop, extraZoneBottom, 2) : [];
  for (const y of extraYs) {
    const xEndRel = Math.min(xAtBottomY(y) - cover * 0.4, projection - cover * 0.4);
    dxf.addLine(point3d(ox - Math.min(20, colStubWidth * 0.3), y), point3d(ox + Math.max(10, xEndRel), y), { layerName: LAYERS.REBAR_BOTTOM.name });
  }

  // Vertical tie legs — three schematic positions, each down to the real
  // sloped boundary at its own x.
  const legZoneStartX = ox + Math.max(10, colStubWidth * 0.15);
  const legZoneEndX = ox + projection * 0.68;
  const legXs = distributeExact(legZoneStartX, legZoneEndX, 3);
  for (const x of legXs) {
    dxf.addLine(point3d(x, tieY), point3d(x, bottomYAt(Math.min(x - ox, projection)) + cover * 0.5), { layerName: LAYERS.REBAR_BOTTOM.name });
  }

  // Strut-parallel bar, offset alongside the compression strut.
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

  // D4: Ah ≥ 0.5(As−An) callout moved OUT of the column stub (its previous
  // position was floating in the column concrete, at a y the reader does
  // not associate with the Ah zone) and OUT of the elevation body entirely
  // — no placement inside the corbel outline is leg-free at the 110mm DXF
  // text height the rest of the sheet uses, and DXF has no white-mask
  // primitive equivalent to the SVG path's mask rect. Placed in the
  // right-hand margin, clearly associated with the corbel by proximity and
  // by the reader's own knowledge that this is the only corbel on the
  // sheet. This is an explicit DXF-vs-SVG deviation — documented here
  // rather than hidden.
  dxfText(dxf, ox + projection + MARGIN_MM * 0.35, oy - h / 2, NOTE_TEXT_HEIGHT_MM, 'Ah >= 0.5(As-An)', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Middle,
  });

  // Short loaded-face bar (schematic; placement only).
  const mark1Len = Math.max(80, bearingPlateWidth * 0.6);
  const mark1Y = oy + PLATE_THICKNESS_MM + 90;
  dxf.addLine(point3d(ox + av - mark1Len / 2, mark1Y), point3d(ox + av + mark1Len / 2, mark1Y), { layerName: LAYERS.REBAR_BOTTOM.name });

  // Bearing plate.
  closedRectDXF(dxf, ox + av - bearingPlateWidth / 2, oy, bearingPlateWidth, PLATE_THICKNESS_MM, LAYERS.BEARING_PLATE.name);
  dxfText(dxf, ox + av, oy + PLATE_THICKNESS_MM + SUBTITLE_HEIGHT_MM * 0.4, SUBTITLE_HEIGHT_MM, 'Bearing Plate', {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });
  dimensionLineDXF(dxf, ox + av + bearingPlateWidth / 2, oy + MARGIN_MM * 0.75, ox + projection, oy + MARGIN_MM * 0.75, `edge >= max(dia,cover)=${fmt0(Math.max(tieBarDia, cover))}mm`, { orientation: 'h', textHeightMM: NOTE_TEXT_HEIGHT_MM });

  // Dimensions.
  dimensionLineDXF(dxf, ox, colStubBottom - MARGIN_MM * 0.4, ox + av, colStubBottom - MARGIN_MM * 0.4, `av=${fmt0(av)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox, colStubBottom - MARGIN_MM * 0.8, ox + projection, colStubBottom - MARGIN_MM * 0.8, `a=${fmt0(projection)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.5, oy, ox - MARGIN_MM * 0.5, bottomAtFaceY, `h=${fmt0(h)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 1.1, tieY, ox - MARGIN_MM * 1.1, bottomAtFaceY, `d=${fmt0(d)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 1.6, tieY, ox - MARGIN_MM * 1.6, zoneBottomY, '(2/3)d', { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox + projection + MARGIN_MM * 0.5, oy, ox + projection + MARGIN_MM * 0.5, bottomAtTipY, `h1=${fmt0(h1)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // Bar-mark tags.
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

  const tieY = oy + h - (cover + tieBarDia / 2);
  const centers = tieLayer.barCentersMM.map((c) => ({ x: ox + c, y: tieY }));
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
// section. Main bars run straight through the column; only the outer bars
// (nearest the top/bottom edge) deflect at a shallow angle toward their
// own nearest column corner. The closed tie (Ah) closes with a rounded
// U-turn at the LOADED end of the corbel. OWN LOCAL FRAME: local x=0 at
// the column/corbel face, +x toward the corbel/tip, -x into the column;
// local y = position across colB. Column "depth" here is the SAME
// schematic proportion of h the elevation's own stub uses
// (COL_STUB_WIDTH_FACTOR) — not a new real dimension.
function renderPlanAnchorageViewDXF(dxf, geometry, origin) {
  const { colB, h, projection, av, tieBarDia, cover, bearingPlateWidth } = geometry.geo;
  const { tieLayer } = geometry;
  const { x: ox, y: oy } = origin;

  const colDepth = h * COL_STUB_WIDTH_FACTOR;
  const colFarX = ox - colDepth;
  const colTopY = oy + colB;
  const corbelStubDepth = Math.max(150, Math.min(600, projection * 0.6));
  const corbelFarX = ox + corbelStubDepth;

  closedRectDXF(dxf, colFarX, oy, colDepth, colB, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, ox, oy, corbelStubDepth, colB, LAYERS.CONCRETE_OUTLINE.name);
  // F2 (REVISION 4): lineType must reference a registered LTYPE name.
  // DASHED_LTYPE_NAME is the kit's own constant; defineDashedLType(dxf)
  // is called once in renderCorbelDiagramDXF before any entity is added.
  dxf.addLine(point3d(ox, oy), point3d(ox, colTopY), { layerName: LAYERS.CONCRETE_OUTLINE.name, lineType: DASHED_LTYPE_NAME });

  // Bearing-plate footprint at shear span av, clipped to the section
  // frame — the SVG fix of the same name; previously extended 15mm past
  // both colB edges.
  const plateFootprintX = ox + av;
  const plateFootprintW = Math.max(10, bearingPlateWidth);
  closedRectDXF(dxf, plateFootprintX - plateFootprintW / 2, oy, plateFootprintW, colB, LAYERS.BEARING_PLATE.name);
  dxfText(dxf, plateFootprintX, colTopY + 40, NOTE_TEXT_HEIGHT_MM, 'Bearing Plate', {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  // Main bars: straight through the column; outer bars deflect toward
  // their own nearest column corner.
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

  // Column tie (mark 3) — closed rectangular loop just inside the column
  // footprint.
  const tieInsetMM = Math.max(20, cornerMarginMM * 0.7);
  closedRectDXF(dxf, colFarX + tieInsetMM, oy + tieInsetMM, colDepth - 2 * tieInsetMM, colB - 2 * tieInsetMM, LAYERS.REBAR_BOTTOM.name);

  // Column corner dots — at the same corners the loop above passes
  // through.
  const corners = [
    { x: colFarX, y: oy }, { x: ox, y: oy },
    { x: colFarX, y: colTopY }, { x: ox, y: colTopY },
  ];
  const cornerPitchMM = minPairwiseDistanceMM(corners);
  for (const { x, y } of corners) barDotDXF(dxf, x, y, tieBarDia, cornerPitchMM, LAYERS.REBAR_BOTTOM.name);

  // Closed tie (Ah) — one representative run, closing with a rounded
  // U-turn at the LOADED end.
  const centers = tieLayer.barCentersMM;
  const tieCMM = centers.length >= 2 ? (centers[0] + centers[1]) / 2 : colB / 2;
  const tieY = oy + tieCMM;
  // D2 (this revision): radius bounded by the frame constraint the SVG
  // path uses — (colTopY - tieY - margin)/2 — so the return leg never
  // leaves the section frame at small colB. The old 0.18*stubDepth bound
  // alone could push it past colTopY.
  const remainingToTopMM = colTopY - tieY;
  const maxRadiusFromFrameMM = Math.max(8, (remainingToTopMM - PLAN_RETURN_LEG_MARGIN_MM) / 2);
  const tieRadiusMM = Math.max(8, Math.min(60, corbelStubDepth * 0.18, maxRadiusFromFrameMM));
  const tieBendX = corbelFarX - Math.max(20, tieRadiusMM * 0.7);
  const tieStartX = colFarX + cornerMarginMM + 10;
  dxf.addLine(point3d(tieStartX, tieY), point3d(tieBendX, tieY), { layerName: LAYERS.STIRRUP_TIE.name });
  const handoff = addLoadedEndClosure180(dxf, tieBendX, tieY, tieRadiusMM, 1, LAYERS.STIRRUP_TIE.name);
  dxf.addLine(point3d(tieBendX, handoff.y), point3d(tieStartX, handoff.y), { layerName: LAYERS.STIRRUP_TIE.name });
  dxfText(dxf, tieStartX + 20, tieY + 30, SUBTITLE_HEIGHT_MM * 0.7, 'Ah', {
    layerName: LAYERS.STIRRUP_TIE.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Bottom,
  });

  // D3 (this revision): mark 1 tag moved out of the plate footprint's
  // own x-range, and its leader shortened to a short diagonal entering
  // the bar from OUTSIDE the plate footprint. Previously the tag sat at
  // entryX - 20 with a vertical leader straight down through
  // [plateFootprintX ± W/2] for typical CB1 inputs. Mark 2, mark 3
  // positions unchanged — no collision was found for either.
  const mark1TagX = corbelFarX + 40;
  const mark1TagY = colTopY + 200;
  barMarkTagDXF(dxf, mark1TagX, mark1TagY, '1', LAYERS.MARK_TAGS.name, {
    leaderTo: { x: entryX, y: oy + centers[0] },
  });
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
  // F2 (REVISION 4): register the DASHED linetype before any entity
  // references it. DXF LTYPE must be defined in the document before a
  // LINE/LWPOLYLINE can name it — the tarikjabiri-dxf writer does not
  // fall back to Continuous for a dangling entity-level lineType (that
  // fallback only exists for a LAYER's own default linetype). Called
  // once here, at the same point as defineDxfLayers, so the ordering
  // guarantee is auditable in one place.
  defineDashedLType(dxf);

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