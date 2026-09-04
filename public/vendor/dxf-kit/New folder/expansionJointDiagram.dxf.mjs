// expansionJointDiagram.dxf.mjs
// DXF render path for computeExpansionJointDiagramGeometry()
// (expansionJointDiagram.mjs), parallel to renderExpansionJointDiagramSVG().
// Zero modification to that file. English only, no schedule table, no
// caption — same v1 exclusion every sibling .dxf.mjs carries.
//
// Layer choice: dashed joint-line (plan) and dowel sleeve segment
// (section) both use CONCRETE_OUTLINE / DOWEL_BAR respectively with
// DASHED linetype — same solid-vs-dashed distinction
// trapezoidalFootingDiagram.dxf.mjs's own section-cut marker and
// elevatorPitDiagram.dxf.mjs's own sump void already establish. Dowel
// bonded segments use the new DOWEL_BAR layer (added to
// structuralDrawingDxfKit.mjs this session — see that file's own
// provenance comment on the addition).

import {
  DxfWriter, point3d, Units, LAYERS, defineDxfLayers, dxfText,
  closedRectDXF, dimensionLineDXF, DiagramError,
  defineDashedLType, DASHED_LTYPE_NAME,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

const MARGIN_MM = 300;
const VIEW_GAP_MM = 1200;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 150;
const PANEL_HALF_DEPTH_MM = 1000; // matches expansionJointDiagram.mjs's own fixed schematic plan-depth constant exactly

function fmt0(mm) { return String(Math.round(mm)); }

function renderPlanDXF(dxf, geometry, origin) {
  const { runLengthMM, dowels } = geometry;
  const { x: ox, y: oy } = origin;
  const panelDepth = 2 * PANEL_HALF_DEPTH_MM;

  closedRectDXF(dxf, ox, oy, runLengthMM, panelDepth, LAYERS.CONCRETE_OUTLINE.name);
  dxf.addLine(point3d(ox + runLengthMM / 2, oy), point3d(ox + runLengthMM / 2, oy + panelDepth), {
    layerName: LAYERS.CONCRETE_OUTLINE.name, lineType: DASHED_LTYPE_NAME,
  });

  const midY = oy + PANEL_HALF_DEPTH_MM;
  if (dowels) {
    for (const px of dowels.positionsX) {
      dxf.addCircle(point3d(ox + px, midY), 25, { layerName: LAYERS.DOWEL_BAR.name });
    }
  } else {
    dxfText(dxf, ox + runLengthMM / 2, oy + panelDepth + SUBTITLE_HEIGHT_MM * 0.3, SUBTITLE_HEIGHT_MM * 0.8, 'NO DOWELS - FREE MOVEMENT JOINT', {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
    });
  }

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + runLengthMM, oy - MARGIN_MM * 0.6, `run = ${fmt0(runLengthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dxfText(dxf, ox + runLengthMM / 2, oy + panelDepth + SUBTITLE_HEIGHT_MM * (dowels ? 0.5 : 1.6), SUBTITLE_HEIGHT_MM, 'PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: runLengthMM, height: panelDepth };
}

function renderSectionDXF(dxf, geometry, origin) {
  const { gapWidthMM, memberDepthMM, dowels } = geometry;
  const { x: ox, y: oy } = origin;
  const memberWidthMM = Math.max(gapWidthMM * 6, memberDepthMM * 1.5, 400);

  closedRectDXF(dxf, ox, oy, memberWidthMM, memberDepthMM, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, ox + memberWidthMM + gapWidthMM, oy, memberWidthMM, memberDepthMM, LAYERS.CONCRETE_OUTLINE.name);

  if (dowels) {
    const midY = oy + memberDepthMM / 2;
    const leftEmbedEnd = ox + memberWidthMM - dowels.embedEachSideMM;
    const rightEmbedEnd = ox + memberWidthMM + gapWidthMM + dowels.embedEachSideMM;
    const gapLo = ox + memberWidthMM, gapHi = ox + memberWidthMM + gapWidthMM;
    const sleeveOnLeft = dowels.sleeveSide === 'left';
    const sleeveLo = sleeveOnLeft ? leftEmbedEnd : gapHi;
    const sleeveHi = sleeveOnLeft ? gapLo : gapHi + dowels.sleeveLengthMM;

    dxf.addLine(point3d(leftEmbedEnd, midY), point3d(sleeveOnLeft ? sleeveLo : gapLo, midY), { layerName: LAYERS.DOWEL_BAR.name });
    dxf.addLine(point3d(sleeveLo, midY), point3d(sleeveHi, midY), { layerName: LAYERS.DOWEL_BAR.name, lineType: DASHED_LTYPE_NAME });
    dxf.addLine(point3d(sleeveOnLeft ? gapHi : sleeveHi, midY), point3d(rightEmbedEnd, midY), { layerName: LAYERS.DOWEL_BAR.name });

    dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 1.2, ox + memberWidthMM, oy - MARGIN_MM * 1.2, `\u00d8${fmt0(dowels.dia)}@${fmt0(dowels.spacing)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  }

  dimensionLineDXF(dxf, ox + memberWidthMM, oy + memberDepthMM + MARGIN_MM * 0.4, ox + memberWidthMM + gapWidthMM, oy + memberDepthMM + MARGIN_MM * 0.4, `gap=${fmt0(gapWidthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + memberDepthMM, `d=${fmt0(memberDepthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + memberWidthMM + gapWidthMM / 2, oy - MARGIN_MM * 1.9, SUBTITLE_HEIGHT_MM, 'SECTION (typ. dowel)', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: 2 * memberWidthMM + gapWidthMM, bottomY: oy - MARGIN_MM * 2.2 };
}

export function renderExpansionJointDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'expansionJoint') {
    throw new DiagramError('BAD_PARAM', 'renderExpansionJointDiagramDXF expects a geometry object from computeExpansionJointDiagramGeometry() (type "expansionJoint").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);
  defineDashedLType(dxf);

  const planOrigin = { x: 0, y: 0 };
  const plan = renderPlanDXF(dxf, geometry, planOrigin);

  const gap = opts.viewGapMM ?? VIEW_GAP_MM;
  const sectionOrigin = { x: 0, y: -(gap + geometry.memberDepthMM) };
  const section = renderSectionDXF(dxf, geometry, sectionOrigin);

  const overallWidth = Math.max(plan.width, section.width);
  dxfText(dxf, overallWidth / 2, plan.height + MARGIN_MM * 2.4, TITLE_HEIGHT_MM, `EXPANSION JOINT ${geometry.id} - DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
