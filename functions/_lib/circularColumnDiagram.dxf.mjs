// circularColumnDiagram.dxf.mjs
// DXF render path for the circular-column reinforcement diagram — parallel
// to, and entirely separate from, renderCircularColumnDiagramSVG() in
// circularColumnDiagram.mjs. Same placement rationale as every other
// sibling *.dxf.mjs in this kit (see shearWallDiagram.dxf.mjs's own header):
// a separate file keeps @tarikjabiri/dxf out of the module graph for an
// ordinary /diagram or /rebar SVG request.
//
// computeCircularColumnDiagramGeometry() is consumed exactly as-is,
// imported from circularColumnDiagram.mjs with zero modification to that
// file. This module only renders; it never validates or computes.
//
// v1 scope exclusions carried over unchanged from every reference
// *.dxf.mjs (shearWallDiagram/columnDiagram): no Arabic labels (English
// only, hardcoded), no schedule table, no multi-line caption/disclaimer
// paragraph. Short view-level annotations with no caption/schedule role
// (spiral Ø@pitch note, clear-spacing note) ARE kept — same treatment
// columnDiagram.dxf.mjs already gives its own analogous tie Ø@spacing note.
//
// GEOMETRY MAPPING (verified directly against circularColumnDiagram.mjs's
// own render functions before writing this, not assumed from the module
// header's prose):
//   cross section  -> concrete circle (R) + spiral outer-bend circle
//                      (spiral.outerRadius) + bar dots at
//                      verticalBars.positions (already box-local, {xMM,yMM}
//                      relative to a (0,0)-origin R,R-center box, same
//                      "positions relative to the view's own box origin"
//                      convention columnDiagram.dxf.mjs's cross-section
//                      already uses for its rectangular positions).
//   spiral detail  -> 3 stacked circles at the spiral's own true radius
//                      (spiral.dia/2), pitchMM apart center-to-center, plus
//                      a dashed centerline. True radius is provably safe
//                      here with NO barDotRadiusMM enlargement/cap needed:
//                      compute's own SPIRAL_OVERLAP guard already rejects
//                      any input where clearSpacingMM = pitchMM - spiralDia
//                      <= 0, so edge-to-edge margin between consecutive
//                      turn-dots is always clearSpacingMM > 0 by
//                      construction — a stronger, already-enforced
//                      guarantee than the generic legibility-cap formula
//                      barDotDXF/barDotRadiusMM apply elsewhere in this kit
//                      for grid/perimeter bar layouts that carry no such
//                      built-in geometric guard.
//   elevation      -> concrete rectangle (diameterMM x heightMM) + a
//                      continuous open zigzag polyline standing in for the
//                      helix (SVG source's own documented convention —
//                      "standard drafting convention for showing a coil in
//                      a flat elevation view", read directly from that
//                      file's renderElevationView comment) + 2 representative
//                      near-edge bar lines + optional lap-splice zone,
//                      exact structural analogue of columnDiagram.dxf.mjs's
//                      own elevation view.
//
// NEW LAYER/FUNCTION FLAGGED FOR CONFIRMATION (session-protocol step 4):
// NO new LAYERS entry needed — every CSS class this element's SVG source
// uses maps onto an already-existing kit layer by exact hex match, verified
// against circularColumnDiagram.mjs's own <style> block and the shared
// kitStyleBlock() in structuralDrawingKit.mjs directly, not guessed:
//   .bar-dot-circular  #1f5aa6 -> REBAR-TOP   (exact match; also the
//                                  already-automatic bar-dot-* rule the
//                                  v2 prompt itself states applies without
//                                  re-raising the question)
//   .stirrup-outline   #2f7a3d -> STIRRUP-TIE (shared kitStyleBlock() class,
//                                  same class + color columnDiagram.dxf.mjs
//                                  already maps to STIRRUP-TIE for its own
//                                  tie-outline rect)
//   .spiral-coil       #2f7a3d -> STIRRUP-TIE (exact match, local override
//                                  of the same color — same confinement role)
//   .spiral-turn-dot   #2f7a3d -> STIRRUP-TIE (exact match)
//   .zone-label        #8a6d00 -> ZONE-LABEL  (exact match, already
//                                  table-confirmed)
// ONE new shared kit FUNCTION was needed: openPolylineDXF(dxf, points,
// layerName) — see its own header comment in structuralDrawingDxfKit.mjs
// for why this crossed the "promote to shared" threshold this session.

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
  barDotDXF,
  barMarkTagDXF,
  dimensionLineDXF,
  distributeTicks,
  minPairwiseDistanceMM,
  openPolylineDXF,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Duplicated from circularColumnDiagram.mjs — that file does not export
// this (an unexported module-level const used only inside its own
// renderElevationView), and this file must not be edited to add an export
// (zero modification to the existing file, per session scope). Flagged
// here explicitly, mirroring columnDiagram.dxf.mjs's own MAX_DRAWN_TIES_
// PER_COLUMN precedent: circularColumnDiagram.mjs line 148 at time of
// writing ("const MAX_DRAWN_TURNS_PER_COLUMN = 24; // matches
// distributeTicks' own hard cap").
const MAX_DRAWN_TURNS_PER_COLUMN = 24;

// Layout conventions — none of these come from geometry or from the SVG
// source; each is a chosen default for real-mm placement the SVG path
// never needed (it drew everything inside a fixed pixel canvas instead).
// MARGIN_MM/VIEW_GAP_MM/TITLE_HEIGHT_MM/SUBTITLE_HEIGHT_MM/DIM_TEXT_HEIGHT_MM
// reuse columnDiagram.dxf.mjs's own values verbatim — same nominal plot
// scale, same role, no reason found to diverge for this sibling element.
const MARGIN_MM = 300; // gutter around each view for dimension lines/labels
const VIEW_GAP_MM = 1000; // real-mm gap between adjacent views (section -> spiral detail -> elevation), model space
const TITLE_HEIGHT_MM = 220; // sheet title text height
const SUBTITLE_HEIGHT_MM = 150; // view titles, zone labels, mark tags, spiral/spacing annotations
const DIM_TEXT_HEIGHT_MM = 150; // dimension line label text height

// The SVG source's own renderElevationView keeps its zigzag swing and its
// two representative bar lines just inside the concrete face with small,
// near-identical fixed pixel offsets (sx+3 for the zigzag, sx+4 for the
// bar lines — read directly from that file, not assumed) whose only job is
// staying visibly clear of the outline, not representing a real bar/spiral
// x-position. One named real-mm constant replaces both: same
// "clearly-visible offset from the true edge" role TICK_CAP_MM already
// plays elsewhere in this kit, reused here rather than inventing a second,
// functionally identical constant.
const ELEV_EDGE_INSET_MM = 40;

function fmt0(mm) {
  return String(Math.round(mm));
}

function renderCrossSectionDXF(dxf, geometry, origin) {
  const { diameterMM, verticalBars, spiral } = geometry;
  const { x: ox, y: oy } = origin;
  const R = diameterMM / 2;
  const cx = ox + R, cy = oy + R;

  dxf.addCircle(point3d(cx, cy), R, { layerName: LAYERS.CONCRETE_OUTLINE.name });
  dxf.addCircle(point3d(cx, cy), spiral.outerRadius, { layerName: LAYERS.STIRRUP_TIE.name });

  // verticalBars.positions are already box-local ({xMM,yMM} relative to
  // this view's own (0,0) origin — see computeCircularBarPositions' own
  // header comment in circularColumnDiagram.mjs, verified directly before
  // writing this) — direct ox+/oy+ offset, same convention
  // columnDiagram.dxf.mjs's cross-section already uses for its own
  // (differently-shaped) positions array.
  const barPts = verticalBars.positions.map((p) => ({ x: ox + p.xMM, y: oy + p.yMM }));
  const pitch = minPairwiseDistanceMM(barPts);
  for (const p of barPts) {
    barDotDXF(dxf, p.x, p.y, verticalBars.dia, pitch, LAYERS.REBAR_TOP.name);
  }

  barMarkTagDXF(dxf, ox + diameterMM + MARGIN_MM * 0.8, cy, `${verticalBars.count}\u00d8${fmt0(verticalBars.dia)}`, LAYERS.MARK_TAGS.name);

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + diameterMM, oy - MARGIN_MM * 0.6, `\u00d8${fmt0(diameterMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, cx, oy + diameterMM + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'CROSS SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: diameterMM, height: diameterMM };
}

// See file header's GEOMETRY MAPPING note for why true radius (no
// barDotDXF/barDotRadiusMM enlargement-and-cap) is correct here: compute's
// own SPIRAL_OVERLAP guard already guarantees clearSpacingMM > 0, a
// stronger guarantee than the generic legibility cap provides elsewhere.
function renderSpiralDetailDXF(dxf, geometry, origin) {
  const { spiral } = geometry;
  const { x: ox, y: oy } = origin;
  const r = spiral.dia / 2;
  const cx = ox + r + MARGIN_MM * 0.5;
  const cy0 = oy, cy1 = oy + spiral.pitch, cy2 = oy + 2 * spiral.pitch;

  for (const cy of [cy0, cy1, cy2]) {
    dxf.addCircle(point3d(cx, cy), r, { layerName: LAYERS.STIRRUP_TIE.name });
  }
  // Dashed centerline through the 3 turn-dots — direct analogue of the SVG
  // source's own single `stroke-dasharray="1,3"` <line> element (verified
  // directly: renderSpiralDetail draws exactly one line here, not a
  // polyline), using the kit's established DASHED_LTYPE_NAME mechanism —
  // same pattern trapezoidalFootingDiagram.dxf.mjs's own section-cut
  // marker already uses.
  dxf.addLine(point3d(cx, cy0), point3d(cx, cy2), { layerName: LAYERS.STIRRUP_TIE.name, lineType: DASHED_LTYPE_NAME });

  dimensionLineDXF(dxf, cx + MARGIN_MM * 0.6, cy0, cx + MARGIN_MM * 0.6, cy1, `${fmt0(spiral.pitch)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, cx, cy2 + SUBTITLE_HEIGHT_MM * 0.9, DIM_TEXT_HEIGHT_MM, `\u00d8${fmt0(spiral.dia)}mm  clear ${fmt0(spiral.clearSpacingMM)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  dxfText(dxf, cx, oy - SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SPIRAL PITCH DETAIL', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: r * 2 + MARGIN_MM * 1.5, height: 2 * spiral.pitch + r * 2 + SUBTITLE_HEIGHT_MM };
}

function renderElevationDXF(dxf, geometry, origin) {
  const { diameterMM, heightMM, spiral, lapSpliceMM, verticalBars } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, diameterMM, heightMM, LAYERS.CONCRETE_OUTLINE.name);

  // Continuous open zigzag standing in for the helix — see file header's
  // GEOMETRY MAPPING note. drawTurns caps at MAX_DRAWN_TURNS_PER_COLUMN,
  // same "representative-not-literal" convention distributeTicks() itself
  // documents and columnDiagram.dxf.mjs's own tie-tick loop already
  // follows for its (different) confinement mark.
  const drawTurns = Math.min(spiral.turns, MAX_DRAWN_TURNS_PER_COLUMN);
  const ys = distributeTicks(oy, oy + heightMM, drawTurns);
  const zigzagPts = ys.map((y, i) => ({ x: i % 2 === 0 ? ox + ELEV_EDGE_INSET_MM : ox + diameterMM - ELEV_EDGE_INSET_MM, y }));
  openPolylineDXF(dxf, zigzagPts, LAYERS.STIRRUP_TIE.name);

  // Two representative outermost vertical bar lines, full height — same
  // 'bar-bottom' class (REBAR-BOTTOM layer) columnDiagram.mjs's own SVG
  // source uses for the identical role (verified directly against
  // circularColumnDiagram.mjs's renderElevationView before writing this:
  // both its <line> elements carry class="bar-bottom"), even though this
  // view's own cross-section bar dots are 'bar-dot-circular' (REBAR-TOP) —
  // the same source-file asymmetry columnDiagram.dxf.mjs's own comment
  // already documents and does not "fix".
  dxf.addLine(point3d(ox + ELEV_EDGE_INSET_MM, oy), point3d(ox + ELEV_EDGE_INSET_MM, oy + heightMM), { layerName: LAYERS.REBAR_BOTTOM.name });
  dxf.addLine(point3d(ox + diameterMM - ELEV_EDGE_INSET_MM, oy), point3d(ox + diameterMM - ELEV_EDGE_INSET_MM, oy + heightMM), { layerName: LAYERS.REBAR_BOTTOM.name });

  barMarkTagDXF(dxf, ox + diameterMM + MARGIN_MM * 0.8, oy + heightMM - MARGIN_MM * 0.5, `${verticalBars.count}\u00d8${fmt0(verticalBars.dia)}`, LAYERS.MARK_TAGS.name);

  // Lap-splice zone placement: same base-anchored convention
  // columnDiagram.dxf.mjs's own elevation uses (see that file's header for
  // the backwards-placement bug class this guards against) — oy is the
  // column BASE here too (verified directly: circularColumnDiagram.mjs's
  // own renderElevationView computes `lapY = botY - lapH`, i.e. against
  // its own botY/base, same convention).
  if (lapSpliceMM != null) {
    const lapBottomMM = oy;
    const lapTopMM = oy + lapSpliceMM;
    closedRectDXF(dxf, ox, lapBottomMM, diameterMM, lapSpliceMM, LAYERS.LAP_ZONE.name);
    dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, lapBottomMM, ox - MARGIN_MM * 0.6, lapTopMM, `${fmt0(lapSpliceMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
    dxfText(dxf, ox + diameterMM + MARGIN_MM * 0.8, (lapBottomMM + lapTopMM) / 2, SUBTITLE_HEIGHT_MM, 'LAP SPLICE ZONE', {
      layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Middle,
    });
  }

  dimensionLineDXF(dxf, ox + diameterMM + MARGIN_MM * 2.2, oy, ox + diameterMM + MARGIN_MM * 2.2, oy + heightMM, `H = ${(heightMM / 1000).toFixed(2)}m`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + diameterMM / 2, oy - MARGIN_MM * 0.6, SUBTITLE_HEIGHT_MM, `\u00d8${fmt0(spiral.dia)}@${fmt0(spiral.pitch)}`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  dxfText(dxf, ox + diameterMM / 2, oy + heightMM + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'ELEVATION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: diameterMM, height: heightMM };
}

export function renderCircularColumnDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'circularColumn') {
    throw new DiagramError('BAD_PARAM', 'renderCircularColumnDiagramDXF expects a geometry object from computeCircularColumnDiagramGeometry() (type "circularColumn").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);
  defineDashedLType(dxf);

  const gap = opts.viewGapMM ?? VIEW_GAP_MM;

  const sectionOrigin = { x: 0, y: 0 };
  const section = renderCrossSectionDXF(dxf, geometry, sectionOrigin);

  const detailOriginX = sectionOrigin.x + section.width + gap;
  const detail = renderSpiralDetailDXF(dxf, geometry, { x: detailOriginX, y: 0 });

  const elevOriginX = detailOriginX + detail.width + gap;
  const elev = renderElevationDXF(dxf, geometry, { x: elevOriginX, y: 0 });

  // Shared y=0 baseline across all three views, same "no physical
  // requirement for the other two, simplest consistent choice" reasoning
  // columnDiagram.dxf.mjs's own comment documents for its analogous stack.
  const overallHeight = Math.max(section.height, detail.height, elev.height);
  const overallWidth = elevOriginX + elev.width + MARGIN_MM * 3 - sectionOrigin.x;
  dxfText(dxf, sectionOrigin.x + overallWidth / 2, overallHeight + MARGIN_MM * 2.2, TITLE_HEIGHT_MM, `CIRCULAR COLUMN ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
