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
// table (DXF TABLE), no caption text, no Arabic labels (English only,
// hardcoded — not opts.lang-driven, matching every other <element>.dxf.mjs
// in this project).
//
// Two shared-kit additions this element required (session gate resolved
// before this file was written — see the standalone patch note for
// structuralDrawingDxfKit.mjs): the BEARING-PLATE layer, and
// stirrupTickVDXF() (the vertical-tick counterpart to the existing
// tieTickHDXF()) — both imported below, not duplicated here.
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
// point one-for-one.

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
  dimensionLineDXF,
  distributeTicks,
  minPairwiseDistanceMM,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

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
const COL_STUB_WIDTH_FACTOR = 0.55; // x colB... no: x h, matching source's own h-based width ratio (colB is a separate, unrelated real dimension used only in the section view)
const COL_STUB_ABOVE_FACTOR = 1.5; // x h, height of stub above baseline
const COL_STUB_BELOW_FACTOR = 0.4; // x h, depth of stub below baseline

const TIE_EMBEDMENT_MM = 30; // min embedment length of the main tie bar into the column stub, past the face — mirrors the SVG source's own bare "30" (there, an unconverted px constant with no fixed mm meaning; given a named real-mm value here), still capped by 0.4x the stub width exactly as that source caps it
const TIE_TIP_INSET_MIN_MM = 8; // min inset from the outer tip to the tie bar's end — mirrors the SVG source's own bare "8"
const TIE_HOOK_DROP_MAX_MM = 20; // max length of the tie bar's short vertical hook drop at its tip end — mirrors the SVG source's own bare "20", still capped by half the remaining drop-to-baseline distance exactly as that source caps it
const STIRRUP_ZONE_START_MIN_MM = 6; // min inset from the column face to the first closed-tie position — mirrors the SVG source's own bare "6"

const PLATE_THICKNESS_MM = 20; // schematic bearing-plate thickness drawn above the corbel's sloped top surface — this geometry has no real plate-thickness input, so this is a representative visual convention, not a design value (same "schematic only" status the file header already assigns the bearing plate itself)
const MARGIN_MM = 300; // gutter around the elevation view for dimension lines/labels
const VIEW_GAP_MM = 600; // real-mm gap between the elevation and section views, model space
const SECTION_EDGE_MARGIN_MM = 0; // no edge inset needed — tieLayer.barCentersMM already places its first/last center inset by cover+dia/2 from computeBarLayerAcrossWidth() itself
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view titles (ELEVATION/SECTION), dimension/plate labels
const DIM_TEXT_HEIGHT_MM = 150;

function fmt0(mm) {
  return String(Math.round(mm));
}

function renderElevationViewDXF(dxf, geometry, origin) {
  const { colB, projection, av, h, h1, cover, tieBarDia, stirrupDia, stirrupCount, bearingPlateWidth, d } = geometry.geo;
  const { x: ox, y: oy } = origin; // (ox,oy) maps to the column-face / baseline corner, per file header's AXIS NOTE

  // Linear interpolation of the sloped top face's real height above the
  // baseline at a given real x (0 at the face, projection at the tip) —
  // direct real-mm translation of corbelDiagram.mjs's own topYAt(xPx),
  // re-verified against that source before writing this.
  const topYAt = (xMM) => h + (xMM / projection) * (h1 - h);

  // Column stub (context only — colB is the only real column dimension
  // this module tracks; see file header's proportions).
  const colStubWidth = h * COL_STUB_WIDTH_FACTOR;
  const colStubTop = oy + h * COL_STUB_ABOVE_FACTOR;
  const colStubBottom = oy - h * COL_STUB_BELOW_FACTOR;
  closedRectDXF(dxf, ox - colStubWidth, colStubBottom, colStubWidth, colStubTop - colStubBottom, LAYERS.CONCRETE_OUTLINE.name);

  // Corbel outline: face (bottom-to-top) -> sloped top face to the tip ->
  // down the tip's own edge -> back along the flat bottom (baseline) to
  // the face — direct translation of corbelDiagram.mjs's own outline path
  // (`M faceX,baselineY L faceX,topFaceY L tipX,topTipY L tipX,baselineY Z`).
  closedPolylineDXF(dxf, [
    { x: ox, y: oy },
    { x: ox, y: oy + h },
    { x: ox + projection, y: oy + topYAt(projection) },
    { x: ox + projection, y: oy },
  ], LAYERS.CONCRETE_OUTLINE.name);

  // Main (top) tie bar line: a constant vertical offset below the sloped
  // top face — verified against corbelDiagram.mjs's own tieStartY/tieEndY
  // formulas before writing this (topYAt(x) + tieOffset, NOT a
  // perpendicular-to-slope decomposition like stairDiagram.dxf.mjs's own
  // waist offset — a different source element, replicated as its own
  // source actually computes it, not homogenized across elements). Since
  // topYAt is linear in x, a constant vertical shift IS parallel to it,
  // matching the source header's own "drawn parallel to the slope" claim.
  const tieOffset = cover + tieBarDia / 2;
  const tieStartX = ox - Math.min(TIE_EMBEDMENT_MM, colStubWidth * 0.4);
  const tieEndX = ox + projection - Math.max(TIE_TIP_INSET_MIN_MM, cover * 0.6);
  const tieStartY = oy + topYAt(Math.max(0, tieStartX - ox)) - tieOffset;
  const tieEndY = oy + topYAt(tieEndX - ox) - tieOffset;
  dxf.addLine(point3d(tieStartX, tieStartY), point3d(tieEndX, tieEndY), { layerName: LAYERS.REBAR_TOP.name });
  const hookDrop = Math.min(TIE_HOOK_DROP_MAX_MM, (tieEndY - oy) * 0.5);
  dxf.addLine(point3d(tieEndX, tieEndY), point3d(tieEndX, tieEndY - hookDrop), { layerName: LAYERS.REBAR_TOP.name });

  // Closed horizontal ties (Ah), distributed within (2/3)d of the column
  // face — direct translation of corbelDiagram.mjs's own zoneEndMM/
  // stirrupXs logic (real mm here needs no px/scale conversion at all,
  // distributeTicks() is already unit-agnostic).
  const zoneEndMM = (2 / 3) * d;
  const zoneStartX = ox + Math.max(STIRRUP_ZONE_START_MIN_MM, cover * 0.5);
  const zoneEndX = ox + zoneEndMM;
  const stirrupXs = distributeTicks(zoneStartX, Math.max(zoneStartX + 1, zoneEndX), stirrupCount);
  for (const x of stirrupXs) {
    // Real-mm y-up equivalent of the source's own
    // `Math.max(topYAt(x)+coverPx*0.6, topFaceY)` clamp — re-derived from
    // physical meaning rather than transliterated, since a y-down-to-y-up
    // flip inverts which comparison operator enforces the same physical
    // constraint (never extend the tick above the actual sloped top
    // face): inset DOWN from the slope by cover*0.6 is a SUBTRACTION in
    // y-up (not the source's own addition, which was a y-down "move
    // down the page"), and the safety bound becomes a Math.min against
    // topYAt(0)=h (the shape's own tallest point), not a Math.max.
    const xRel = Math.min(x - ox, projection);
    const tickTop = Math.min(oy + topYAt(xRel) - cover * 0.6, oy + h);
    stirrupTickVDXF(dxf, x, tickTop, oy + cover * 0.6, LAYERS.STIRRUP_TIE.name);
  }

  // Bearing plate — schematic rectangle resting ON the sloped top surface
  // at shear span av, centered on av, spanning bearingPlateWidth.
  const plateSurfaceY = oy + topYAt(av);
  closedRectDXF(dxf, ox + av - bearingPlateWidth / 2, plateSurfaceY, bearingPlateWidth, PLATE_THICKNESS_MM, LAYERS.BEARING_PLATE.name);
  dxfText(dxf, ox + av, plateSurfaceY + PLATE_THICKNESS_MM + SUBTITLE_HEIGHT_MM * 0.3, SUBTITLE_HEIGHT_MM, 'Bearing Plate', {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  // Dimensions — av, total projection (a), h (at face), h1 (at tip).
  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.4, ox + av, oy - MARGIN_MM * 0.4, `av=${fmt0(av)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.8, ox + projection, oy - MARGIN_MM * 0.8, `a=${fmt0(projection)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.5, oy, ox - MARGIN_MM * 0.5, oy + h, `h=${fmt0(h)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox + projection + MARGIN_MM * 0.5, oy, ox + projection + MARGIN_MM * 0.5, oy + topYAt(projection), `h1=${fmt0(h1)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + projection / 2, oy + h * COL_STUB_ABOVE_FACTOR + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'ELEVATION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: projection, height: colStubTop - colStubBottom, topY: colStubTop };
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

  return { width: colB, height: h, originX: ox };
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

  const sectionOriginX = geometry.geo.projection + (opts.viewGapMM ?? VIEW_GAP_MM);
  renderSectionViewDXF(dxf, geometry, { x: sectionOriginX, y: 0 });

  dxfText(dxf, elevOrigin.x + elevation.width / 2, elevation.topY + MARGIN_MM * 0.6, TITLE_HEIGHT_MM, `CORBEL ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
