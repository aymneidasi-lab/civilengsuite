// elevatorPitDiagram.dxf.mjs
// DXF render path for computeElevatorPitDiagramGeometry() (elevatorPitDiagram.mjs),
// parallel to renderElevatorPitDiagramSVG(). Zero modification to that
// file. English only, no schedule table, no caption — same v1 exclusion
// every sibling .dxf.mjs carries.
//
// Layer choice, all pre-existing: wall ring + base slab -> CONCRETE_OUTLINE;
// base-slab mesh -> REBAR_MESH_LINE (raftPileDiagram.dxf.mjs's own
// convention); exterior vertical curtain -> REBAR_BOTTOM, interior
// vertical curtain -> REBAR_TOP, horizontal bars -> REBAR_HORIZONTAL —
// all three verified directly against basementWallDiagram.dxf.mjs's own
// layer assignments before writing this, same physical condition (a
// below-grade wall restrained top+bottom) as that file documents for its
// own double-curtain choice. Sump void -> CONCRETE_OUTLINE with DASHED
// linetype (a formed recess, not a solid material edge — same
// solid-vs-dashed distinction trapezoidalFootingDiagram.dxf.mjs's own
// section-cut marker already establishes).

import {
  DxfWriter, point3d, Units, LAYERS, defineDxfLayers, dxfText,
  closedRectDXF, barDotDXF, dimensionLineDXF, DiagramError,
  defineDashedLType, DASHED_LTYPE_NAME,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

const MARGIN_MM = 300;
const VIEW_GAP_MM = 1200;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 150;

function fmt0(mm) { return String(Math.round(mm)); }

function renderPlanDXF(dxf, geometry, origin) {
  const { outerLengthMM, outerWidthMM, innerLengthMM, innerWidthMM, wallThicknessMM, baseSlabMesh, sump } = geometry;
  const { x: ox, y: oy } = origin;

  for (const mm of baseSlabMesh.meshXs) {
    dxf.addLine(point3d(ox + mm, oy), point3d(ox + mm, oy + outerWidthMM), { layerName: LAYERS.REBAR_MESH_LINE.name });
  }
  for (const mm of baseSlabMesh.meshYs) {
    dxf.addLine(point3d(ox, oy + mm), point3d(ox + outerLengthMM, oy + mm), { layerName: LAYERS.REBAR_MESH_LINE.name });
  }

  closedRectDXF(dxf, ox, oy, outerLengthMM, outerWidthMM, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, ox + wallThicknessMM, oy + wallThicknessMM, innerLengthMM, innerWidthMM, LAYERS.CONCRETE_OUTLINE.name);

  if (sump) {
    const sx0 = ox + wallThicknessMM + sump.offsetXMM, sy0 = oy + wallThicknessMM + sump.offsetYMM;
    closedRectDXF(dxf, sx0, sy0, sump.lengthMM, sump.widthMM, LAYERS.CONCRETE_OUTLINE.name, { lineType: DASHED_LTYPE_NAME });
    dxfText(dxf, sx0 + sump.lengthMM / 2, sy0 + sump.widthMM / 2, SUBTITLE_HEIGHT_MM * 0.6, 'SUMP', {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Middle,
    });
  }

  dimensionLineDXF(dxf, ox + wallThicknessMM, oy - MARGIN_MM * 0.6, ox + wallThicknessMM + innerLengthMM, oy - MARGIN_MM * 0.6, `${fmt0(innerLengthMM)} x ${fmt0(innerWidthMM)} (interior)`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + outerLengthMM / 2, oy + outerWidthMM + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: outerLengthMM, height: outerWidthMM };
}

function renderSectionDXF(dxf, geometry, origin) {
  const {
    wallThicknessMM, pitDepthMM, baseSlabThicknessMM, coverMM,
    exteriorVerticalBars, interiorVerticalBars, horizontal,
  } = geometry;
  const { x: ox, y: oy } = origin; // oy = base-slab underside (bottom)
  const slabWidthMM = wallThicknessMM * 4.5;
  const slabTopY = oy + baseSlabThicknessMM;
  const wallTopY = slabTopY + pitDepthMM;
  const wallX0 = ox + wallThicknessMM * 1.75;

  closedRectDXF(dxf, ox, oy, slabWidthMM, baseSlabThicknessMM, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, wallX0, slabTopY, wallThicknessMM, pitDepthMM, LAYERS.CONCRETE_OUTLINE.name);

  const extX = wallX0 + coverMM + exteriorVerticalBars.dia / 2;
  const intX = wallX0 + wallThicknessMM - coverMM - interiorVerticalBars.dia / 2;
  const barBotY = oy + coverMM, barTopY = wallTopY;
  dxf.addLine(point3d(extX, barBotY), point3d(extX, barTopY), { layerName: LAYERS.REBAR_BOTTOM.name });
  dxf.addLine(point3d(intX, barBotY), point3d(intX, barTopY), { layerName: LAYERS.REBAR_TOP.name });

  for (const rowYFromWallTop of horizontal.rowYs) {
    const y = wallTopY - rowYFromWallTop;
    barDotDXF(dxf, extX, y, horizontal.dia, horizontal.dia * 6, LAYERS.REBAR_HORIZONTAL.name);
    barDotDXF(dxf, intX, y, horizontal.dia, horizontal.dia * 6, LAYERS.REBAR_HORIZONTAL.name);
  }

  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, slabTopY, ox - MARGIN_MM * 0.6, wallTopY, `pit depth = ${fmt0(pitDepthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, slabTopY, `slab = ${fmt0(baseSlabThicknessMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + slabWidthMM / 2, wallTopY + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION A-A', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: slabWidthMM, topY: wallTopY, bottomY: oy };
}

export function renderElevatorPitDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'elevatorPit') {
    throw new DiagramError('BAD_PARAM', 'renderElevatorPitDiagramDXF expects a geometry object from computeElevatorPitDiagramGeometry() (type "elevatorPit").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);
  defineDashedLType(dxf);

  const planOrigin = { x: 0, y: 0 };
  const plan = renderPlanDXF(dxf, geometry, planOrigin);

  const gap = opts.viewGapMM ?? VIEW_GAP_MM;
  const sectionOrigin = { x: plan.width + gap, y: 0 };
  const section = renderSectionDXF(dxf, geometry, sectionOrigin);

  const overallTopY = Math.max(plan.height, section.topY);
  const titleX = (plan.width + (sectionOrigin.x + section.width)) / 2;
  dxfText(dxf, titleX, overallTopY + MARGIN_MM * 1.6, TITLE_HEIGHT_MM, `ELEVATOR PIT ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
