// couplingBeamDiagram.dxf.mjs
// DXF render path for the diagonally-reinforced coupling-beam diagram —
// separate from renderCouplingBeamDiagramSVG() in couplingBeamDiagram.mjs.
// v1 exclusions carried over: no schedule table, no caption, English only.
//
// Diagonal geometry is real mm throughout (DXF is unit-native, so
// totalLengthMM/depthMM/insetY/angleDeg from computeCouplingBeamDiagramGeometry()
// are used directly — no px/scale conversion, unlike the SVG path). Anchor
// points below are derived the same way the SVG's own renderElevation derives
// g1x1/g1y1 etc., just re-expressed for a y-up frame (DXF standard) instead of
// the SVG's y-down canvas — verified by direct substitution, not assumed.
//
// bundle.positions (bundle-detail view) are left as-is, no y-flip: for every
// row r the complementary row (layers-1-r) is also present with the SAME full
// set of columns (verified by reading computeCouplingBeamDiagramGeometry's own
// bar-grid loop), so the point set is already invariant under y -> innerH-y.
//
// bar-dot-diag1 (#1f5aa6, confirmed by reading this file directly, per this
// kit's own "unconfirmed, check when built" flag) is identical to REBAR_TOP's
// hex and sits squarely in that layer's own established "bar-dot-*" family
// (unlike DIAGONAL_BAR/wallOpeningDiagram's ".diagonal-bar" class, a genuinely
// different naming pattern that earned an independent layer) — mapped directly
// onto REBAR_TOP, no new layer. bar-dot-diag2 is declared in the SVG's own
// style block but never actually drawn by any barDot() call (grepped directly)
// — dead styling, nothing to translate.

import {
  DxfWriter, point3d, Units, LAYERS, defineDxfLayers, dxfText,
  closedRectDXF, barDotDXF, barMarkTagDXF, dimensionLineDXF,
  distributeTicks, DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TICK_CAP_MM } from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

const MARGIN_MM = 300;
const VIEW_GAP_MM = 1000;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 150;
const MARK_GAP_MM = 220;
const TICK_HALF_LEN_MM = TICK_CAP_MM; // reuse the kit's own tick-length convention

// Duplicated from couplingBeamDiagram.mjs (private, unexported) — line 174 at
// time of writing, same flagging convention every sibling .dxf.mjs uses.
const MAX_DRAWN_TIES_PER_GROUP = 20;

function fmt0(mm) {
  return String(Math.round(mm));
}

// Diagonal counterpart of the kit's own tieTickHDXF (axis-aligned only, so it
// doesn't fit an angled bundle line — element-specific geometry drawn locally
// with the kit's generic addLine, per couplingBeamDiagram.mjs's own header
// note sanctioning this pattern).
function diagonalTicksDXF(dxf, x1, y1, x2, y2, count, halfLenMM, layerName) {
  const dx = x2 - x1, dy = y2 - y1;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len, uy = dy / len;
  const px = -uy, py = ux;
  for (const t of distributeTicks(0, 1, count)) {
    const cx = x1 + dx * t, cy = y1 + dy * t;
    dxf.addLine(point3d(cx + px * halfLenMM, cy + py * halfLenMM), point3d(cx - px * halfLenMM, cy - py * halfLenMM), { layerName });
  }
}

function renderElevationDXF(dxf, geometry, origin) {
  const { totalLengthMM, spanClearMM, depthMM, embedMM, insetY, confinementTies, diagonalBars, angleDeg } = geometry;
  const { x: ox, y: oy } = origin;
  const beamX = ox + embedMM;
  const rightPierX = beamX + spanClearMM;
  const drawCount = Math.min(confinementTies.count, MAX_DRAWN_TIES_PER_GROUP);

  closedRectDXF(dxf, ox, oy, embedMM, depthMM, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, rightPierX, oy, embedMM, depthMM, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, beamX, oy, spanClearMM, depthMM, LAYERS.CONCRETE_OUTLINE.name);

  // Group 1: bottom-left anchor -> top-right anchor (y-up frame).
  const g1x1 = ox, g1y1 = oy + insetY, g1x2 = ox + totalLengthMM, g1y2 = oy + depthMM - insetY;
  dxf.addLine(point3d(g1x1, g1y1), point3d(g1x2, g1y2), { layerName: LAYERS.REBAR_TOP.name });
  diagonalTicksDXF(dxf, g1x1, g1y1, g1x2, g1y2, drawCount, TICK_HALF_LEN_MM, LAYERS.STIRRUP_TIE.name);

  // Group 2: top-left anchor -> bottom-right anchor (mirrored).
  const g2x1 = ox, g2y1 = oy + depthMM - insetY, g2x2 = ox + totalLengthMM, g2y2 = oy + insetY;
  dxf.addLine(point3d(g2x1, g2y1), point3d(g2x2, g2y2), { layerName: LAYERS.REBAR_BOTTOM.name });
  diagonalTicksDXF(dxf, g2x1, g2y1, g2x2, g2y2, drawCount, TICK_HALF_LEN_MM, LAYERS.STIRRUP_TIE.name);

  barMarkTagDXF(dxf, (g1x1 + g1x2) / 2, (g1y1 + g1y2) / 2 + MARK_GAP_MM * 0.7, `2\u00d7${diagonalBars.countPerGroup}\u00d8${fmt0(diagonalBars.dia)}`, LAYERS.MARK_TAGS.name);
  dxfText(dxf, beamX + 60, oy - MARGIN_MM * 0.5, SUBTITLE_HEIGHT_MM, `alpha ~= ${angleDeg.toFixed(1)} deg`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, beamX + 60, oy - MARGIN_MM * 0.9, SUBTITLE_HEIGHT_MM * 0.75, 'as drawn', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Top,
  });

  dimensionLineDXF(dxf, beamX, oy + depthMM + MARGIN_MM * 0.6, beamX + spanClearMM, oy + depthMM + MARGIN_MM * 0.6, `ln = ${fmt0(spanClearMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox + totalLengthMM + MARGIN_MM, oy, ox + totalLengthMM + MARGIN_MM, oy + depthMM, `h = ${fmt0(depthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + embedMM / 2, oy - MARGIN_MM * 0.5, SUBTITLE_HEIGHT_MM, `${fmt0(embedMM)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, rightPierX + embedMM / 2, oy - MARGIN_MM * 0.5, SUBTITLE_HEIGHT_MM, `${fmt0(embedMM)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, ox + embedMM / 2, oy - MARGIN_MM * 0.9, SUBTITLE_HEIGHT_MM * 0.85, 'Wall Pier', {
    layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, rightPierX + embedMM / 2, oy - MARGIN_MM * 0.9, SUBTITLE_HEIGHT_MM * 0.85, 'Wall Pier', {
    layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, ox + totalLengthMM / 2, oy + depthMM + MARGIN_MM * 1.5, SUBTITLE_HEIGHT_MM, 'ELEVATION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: totalLengthMM, height: depthMM };
}

function renderBundleDetailDXF(dxf, geometry, origin) {
  const { bundle, diagonalBars, confinementTies } = geometry;
  const { x: ox, y: oy } = origin;
  const { w, h } = bundle.outer;

  closedRectDXF(dxf, ox, oy, w, h, LAYERS.STIRRUP_TIE.name); // rx=3 rounding dropped — no native rounded LWPolyline, arcs excluded from v1 scope
  for (const p of bundle.positions) {
    barDotDXF(dxf, ox + p.xMM, oy + p.yMM, diagonalBars.dia, confinementBundlePitchMM(bundle), LAYERS.REBAR_TOP.name);
  }
  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + w, oy - MARGIN_MM * 0.6, `${fmt0(w)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + h, `${fmt0(h)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dxfText(dxf, ox + w / 2, oy + h + MARGIN_MM * 0.5, SUBTITLE_HEIGHT_MM, `\u00d8${fmt0(confinementTies.dia)}mm@${fmt0(confinementTies.spacing)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });
  dxfText(dxf, ox + w / 2, oy - MARGIN_MM * 1.1, SUBTITLE_HEIGHT_MM * 0.85, `Diagonal Group ${diagonalBars.layers}x${diagonalBars.barsPerLayer}`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, ox + w / 2, oy + h + MARGIN_MM * 1.1, SUBTITLE_HEIGHT_MM, 'DIAGONAL BUNDLE DETAIL', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: w, height: h };
}

// Real minimum pairwise distance across the bar grid, computed once per
// bundle (not per dot) — same role minPairwiseDistanceMM plays elsewhere,
// specialized here for a rectangular row/column grid where the true nearest
// neighbor is always the adjacent row or column pitch.
function confinementBundlePitchMM(bundle) {
  const pts = bundle.positions;
  let min = Infinity;
  for (let i = 0; i < pts.length; i++) {
    for (let j = i + 1; j < pts.length; j++) {
      const d = Math.hypot(pts[i].xMM - pts[j].xMM, pts[i].yMM - pts[j].yMM);
      if (d > 0 && d < min) min = d;
    }
  }
  return min;
}

function renderMidspanSectionDXF(dxf, geometry, origin) {
  const { widthMM, depthMM } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, widthMM, depthMM, LAYERS.CONCRETE_OUTLINE.name);
  // Schematic X only — both groups cross near midspan (see SVG source's own
  // note); a symmetric X reads identically under a y-flip, so no conversion
  // is needed beyond using the same fractions directly.
  dxf.addLine(point3d(ox + widthMM * 0.15, oy + depthMM * 0.15), point3d(ox + widthMM * 0.85, oy + depthMM * 0.85), { layerName: LAYERS.REBAR_TOP.name });
  dxf.addLine(point3d(ox + widthMM * 0.15, oy + depthMM * 0.85), point3d(ox + widthMM * 0.85, oy + depthMM * 0.15), { layerName: LAYERS.REBAR_BOTTOM.name });
  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + widthMM, oy - MARGIN_MM * 0.6, `${fmt0(widthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + depthMM, `${fmt0(depthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dxfText(dxf, ox + widthMM / 2, oy + depthMM + MARGIN_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION AT MIDSPAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: widthMM, height: depthMM };
}

export function renderCouplingBeamDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'couplingBeam') {
    throw new DiagramError('BAD_PARAM', 'renderCouplingBeamDiagramDXF expects a geometry object from computeCouplingBeamDiagramGeometry() (type "couplingBeam").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const gap = opts.viewGapMM ?? VIEW_GAP_MM;
  const bundleOrigin = { x: 0, y: 0 };
  const bundle = renderBundleDetailDXF(dxf, geometry, bundleOrigin);

  const sectionOrigin = { x: bundle.width + gap, y: 0 };
  const section = renderMidspanSectionDXF(dxf, geometry, sectionOrigin);

  const row1Height = Math.max(bundle.height, section.height);
  const elevOrigin = { x: 0, y: row1Height + gap * 1.6 };
  const elev = renderElevationDXF(dxf, geometry, elevOrigin);

  const overallWidth = Math.max(sectionOrigin.x + section.width, elevOrigin.x + elev.width);
  const overallTop = elevOrigin.y + elev.height;
  dxfText(dxf, overallWidth / 2, overallTop + MARGIN_MM * 2.6, TITLE_HEIGHT_MM, `COUPLING BEAM ${geometry.id} - DIAGONAL REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
