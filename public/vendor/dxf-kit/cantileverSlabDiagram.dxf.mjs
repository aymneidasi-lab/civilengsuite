// cantileverSlabDiagram.dxf.mjs
// DXF render path for computeCantileverSlabDiagramGeometry()
// (cantileverSlabDiagram.mjs), parallel to renderCantileverSlabDiagramSVG().
// Zero modification to that file. English only, no schedule table, no
// caption — same v1 exclusion every sibling .dxf.mjs carries.
//
// Layer choice, all pre-existing: support + slab -> CONCRETE_OUTLINE;
// top main bars -> REBAR_TOP; top "extra" curtailed bars AND the free-
// edge U-bar both -> REBAR_EXTRA (same generic "supplementary bar"
// role that layer already holds for basementWallDiagram.dxf.mjs — two
// different supplementary bars on one sheet is exactly the kind of
// case that layer already exists to cover, no new layer needed); bottom
// nominal bars -> REBAR_BOTTOM; plan bar-spacing tick lines ->
// REBAR_MESH_LINE (same representative-spacing-line role raftPileDiagram
// .dxf.mjs's own mesh already establishes).

import {
  DxfWriter, point3d, Units, LAYERS, defineDxfLayers, dxfText,
  closedRectDXF, dimensionLineDXF, DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

const MARGIN_MM = 300;
const VIEW_GAP_MM = 1200;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 150;
const SUPPORT_OVERHANG_MM = 200;

function fmt0(mm) { return String(Math.round(mm)); }

function renderSectionDXF(dxf, geometry, origin) {
  const {
    projectionMM, thicknessMM, coverMM, supportWidthMM, devLengthMM, tipXMM,
    topMainBars, topExtraBars, bottomBars, edgeUBar,
  } = geometry;
  const { x: ox, y: oy } = origin; // oy = slab underside (bottom)

  closedRectDXF(dxf, ox - supportWidthMM, oy - SUPPORT_OVERHANG_MM, supportWidthMM, thicknessMM + 2 * SUPPORT_OVERHANG_MM, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, ox, oy, projectionMM, thicknessMM, LAYERS.CONCRETE_OUTLINE.name);

  const topY = oy + thicknessMM - coverMM - topMainBars.dia / 2;
  dxf.addLine(point3d(ox - devLengthMM, topY), point3d(ox + tipXMM, topY), { layerName: LAYERS.REBAR_TOP.name });

  if (topExtraBars) {
    const extraY = topY - (topMainBars.dia / 2 + 15 + topExtraBars.dia / 2);
    dxf.addLine(point3d(ox - devLengthMM, extraY), point3d(ox + topExtraBars.extraLengthMM, extraY), { layerName: LAYERS.REBAR_EXTRA.name });
  }

  const botY = oy + coverMM + bottomBars.dia / 2;
  dxf.addLine(point3d(ox - devLengthMM, botY), point3d(ox + tipXMM, botY), { layerName: LAYERS.REBAR_BOTTOM.name });

  if (edgeUBar) {
    const tipX = ox + tipXMM;
    dxf.addLine(point3d(tipX, botY), point3d(tipX + edgeUBar.dia * 2, botY), { layerName: LAYERS.REBAR_EXTRA.name });
    dxf.addLine(point3d(tipX + edgeUBar.dia * 2, botY), point3d(tipX + edgeUBar.dia * 2, topY), { layerName: LAYERS.REBAR_EXTRA.name });
    dxf.addLine(point3d(tipX + edgeUBar.dia * 2, topY), point3d(tipX, topY), { layerName: LAYERS.REBAR_EXTRA.name });
  }

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.9, ox + projectionMM, oy - MARGIN_MM * 0.9, `projection = ${fmt0(projectionMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox + projectionMM + MARGIN_MM * 0.6, oy, ox + projectionMM + MARGIN_MM * 0.6, oy + thicknessMM, `t = ${fmt0(thicknessMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + projectionMM / 2, oy + thicknessMM + SUPPORT_OVERHANG_MM + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: supportWidthMM + projectionMM, bottomY: oy - MARGIN_MM * 1.8, topY: oy + thicknessMM + SUPPORT_OVERHANG_MM };
}

function renderPlanDXF(dxf, geometry, origin) {
  const { projectionMM, widthMM, topMainBars, edgeUBar } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, projectionMM, widthMM, LAYERS.CONCRETE_OUTLINE.name);
  for (const p of topMainBars.ticks.positions) {
    dxf.addLine(point3d(ox, oy + p), point3d(ox + projectionMM, oy + p), { layerName: LAYERS.REBAR_MESH_LINE.name });
  }
  if (edgeUBar) {
    for (const p of edgeUBar.ticks.positions) {
      dxf.addLine(point3d(ox + projectionMM - 15, oy + p - 20), point3d(ox + projectionMM - 15, oy + p + 20), { layerName: LAYERS.REBAR_EXTRA.name });
    }
  }

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + projectionMM, oy - MARGIN_MM * 0.6, `w = ${fmt0(widthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dxfText(dxf, ox + projectionMM / 2, oy + widthMM + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: projectionMM, height: widthMM };
}

export function renderCantileverSlabDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'cantileverSlab') {
    throw new DiagramError('BAD_PARAM', 'renderCantileverSlabDiagramDXF expects a geometry object from computeCantileverSlabDiagramGeometry() (type "cantileverSlab").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const sectionOrigin = { x: 0, y: 0 };
  const section = renderSectionDXF(dxf, geometry, sectionOrigin);

  const gap = opts.viewGapMM ?? VIEW_GAP_MM;
  const planOrigin = { x: 0, y: section.bottomY - gap - geometry.widthMM };
  const plan = renderPlanDXF(dxf, geometry, planOrigin);

  const overallWidth = Math.max(section.width, plan.width);
  dxfText(dxf, overallWidth / 2, section.topY + SUBTITLE_HEIGHT_MM + MARGIN_MM * 1.6, TITLE_HEIGHT_MM, `CANTILEVER SLAB ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
