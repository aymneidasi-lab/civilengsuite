// beamColumnJointDiagram.dxf.mjs
// DXF render path for the beam-column joint reinforcement diagram —
// separate from renderBeamColumnJointDiagramSVG() in beamColumnJointDiagram.mjs
// (same "own .dxf.mjs file, kit import only" rule every element here follows).
// v1 exclusions carried over: no schedule table, no caption paragraph, English
// labels only, hardcoded.
//
// Layout decision beyond the SVG (session-explicit, applied directly per this
// session's own instruction): the elevation draws TWO development-length
// dimension lines (top AND bottom bar groups), not one — the SVG only dimensions
// the top group and leaves the bottom group's value to the schedule table, which
// this DXF v1 does not draw, so the bottom value would otherwise be lost.
//
// Coordinate convention: y-up (DXF standard), unlike the SVG's own y-down canvas.
// geometry.zones.* are measured from the COLUMN'S TOP per beamColumnJointDiagram
// .mjs's own comment ("measured from the top of the drawn column") — converted
// here via yUp = totalColumnHeightMM - zFromTop.
//
// columnBars.positions (joint-core section) are left as-is, no y-flip applied:
// computeJointBarPositions() always pushes top/bottom-edge points and left/
// right-edge points in mirrored pairs (verified by reading that function
// directly), so the point SET is already invariant under y -> innerH-y — a flip
// would produce a visually identical drawing.

import {
  DxfWriter, point3d, Units, LAYERS, defineDxfLayers, dxfText,
  closedRectDXF, barDotDXF, tieTickHDXF, barMarkTagDXF, dimensionLineDXF,
  distributeTicks, minPairwiseDistanceMM, defineDashedLType, DASHED_LTYPE_NAME,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Duplicated from beamColumnJointDiagram.mjs (private, unexported consts) —
// same flagging convention shearWallDiagram.dxf.mjs uses for MAX_MESH_COLS etc.
// Lines 202-203 at time of writing.
const MAX_DRAWN_TIES_PER_ZONE = 12;
const MAX_DRAWN_HINGE_TIES = 8;

const MARGIN_MM = 300;
const VIEW_GAP_MM = 1000; // real-mm gap between joint-core section and elevation
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 150;
const MARK_GAP_MM = 220; // gap from a shape's edge to its mark-tag bubble
const ZONE_LABEL_GAP_MM = 100; // gap from column left face to a zone caption
const DIM_OFFSET_MM = 100; // offset from a bar line to its development-length dimension line
// Schematic inset for the two representative column-bar lines drawn in
// elevation (SVG's own "4px" has no mm meaning to carry over — same reasoning
// shearWallDiagram.dxf.mjs's TICK_CAP_INSET_MM already documents).
function repLineInsetMM(columnWidthMM) {
  return Math.min(60, columnWidthMM * 0.08);
}

function fmt0(mm) {
  return String(Math.round(mm));
}

function renderJointCoreSectionDXF(dxf, geometry, origin) {
  const { columnWidthMM, columnDepthMM, columnBars, jointTies } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, columnWidthMM, columnDepthMM, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, ox + jointTies.outer.x, oy + jointTies.outer.y, jointTies.outer.w, jointTies.outer.h, LAYERS.STIRRUP_TIE.name);

  const pitch = minPairwiseDistanceMM(columnBars.positions.map((p) => ({ x: p.xMM, y: p.yMM })));
  for (const p of columnBars.positions) {
    barDotDXF(dxf, ox + p.xMM, oy + p.yMM, columnBars.dia, pitch, LAYERS.REBAR_TOP.name);
  }

  barMarkTagDXF(dxf, ox + columnWidthMM + MARK_GAP_MM, oy + columnDepthMM / 2, `${columnBars.count}\u00d8${fmt0(columnBars.dia)}`, LAYERS.MARK_TAGS.name);
  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + columnWidthMM, oy - MARGIN_MM * 0.6, `${fmt0(columnWidthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + columnDepthMM, `${fmt0(columnDepthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + columnWidthMM / 2, oy - MARGIN_MM * 1.4, SUBTITLE_HEIGHT_MM, `\u00d8${fmt0(jointTies.dia)}mm@${fmt0(jointTies.spacing)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, ox + columnWidthMM / 2, oy - MARGIN_MM * 1.9, SUBTITLE_HEIGHT_MM * 0.85, 'add standard hook length per code - not shown', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, ox + columnWidthMM / 2, oy + columnDepthMM + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'JOINT CORE SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: columnWidthMM, height: columnDepthMM };
}

function renderJointElevationDXF(dxf, geometry, origin) {
  const {
    columnWidthMM, beamSpanShownMM, totalColumnHeightMM, zones,
    columnBars, jointTies, hingeZoneTieSpacingMM, hingeTieCountEachZone,
    beamTopBars, beamBottomBars,
  } = geometry;
  const { x: ox, y: oy } = origin;
  const yUp = (zFromTop) => oy + (totalColumnHeightMM - zFromTop);

  const hinge1Top = yUp(zones.hinge1[0]), hinge1Bot = yUp(zones.hinge1[1]);
  const hinge2Top = yUp(zones.hinge2[0]), hinge2Bot = yUp(zones.hinge2[1]);
  const coreTop = yUp(zones.core[0]), coreBot = yUp(zones.core[1]);
  const colTopY = oy + totalColumnHeightMM;

  closedRectDXF(dxf, ox, oy, columnWidthMM, totalColumnHeightMM, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, ox, hinge1Bot, columnWidthMM, hinge1Top - hinge1Bot, LAYERS.HINGE_ZONE.name, { lineType: DASHED_LTYPE_NAME });
  closedRectDXF(dxf, ox, hinge2Bot, columnWidthMM, hinge2Top - hinge2Bot, LAYERS.HINGE_ZONE.name, { lineType: DASHED_LTYPE_NAME });
  closedRectDXF(dxf, ox, coreBot, columnWidthMM, coreTop - coreBot, LAYERS.JOINT_CORE_ZONE.name, { lineType: DASHED_LTYPE_NAME });

  dxfText(dxf, ox - ZONE_LABEL_GAP_MM, (coreTop + coreBot) / 2, SUBTITLE_HEIGHT_MM, 'JOINT CORE', {
    layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Right, vAlign: TextVerticalAlignment.Middle,
  });
  dxfText(dxf, ox - ZONE_LABEL_GAP_MM, (hinge1Top + hinge1Bot) / 2, SUBTITLE_HEIGHT_MM, 'NO SPLICE', {
    layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Right, vAlign: TextVerticalAlignment.Middle,
  });
  dxfText(dxf, ox - ZONE_LABEL_GAP_MM, (hinge2Top + hinge2Bot) / 2, SUBTITLE_HEIGHT_MM, 'NO SPLICE', {
    layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Right, vAlign: TextVerticalAlignment.Middle,
  });

  const beamX = ox + columnWidthMM;
  const beamOuterX = beamX + beamSpanShownMM;
  closedRectDXF(dxf, beamX, coreBot, beamSpanShownMM, coreTop - coreBot, LAYERS.CONCRETE_OUTLINE.name);

  // Column longitudinal bars — two representative outer lines, continuous
  // through the joint (no splice), per SVG source class="bar-bottom" ->
  // REBAR_BOTTOM (matched verbatim, not "corrected" to REBAR_TOP).
  const inset = repLineInsetMM(columnWidthMM);
  dxf.addLine(point3d(ox + inset, oy), point3d(ox + inset, colTopY), { layerName: LAYERS.REBAR_BOTTOM.name });
  dxf.addLine(point3d(ox + columnWidthMM - inset, oy), point3d(ox + columnWidthMM - inset, colTopY), { layerName: LAYERS.REBAR_BOTTOM.name });
  barMarkTagDXF(dxf, ox - MARK_GAP_MM * 0.5, colTopY - MARK_GAP_MM * 0.5, `${columnBars.count}\u00d8${fmt0(columnBars.dia)}`, LAYERS.MARK_TAGS.name);

  // Joint ties, within the joint core's own span only.
  const drawnJointTies = Math.min(jointTies.count, MAX_DRAWN_TIES_PER_ZONE);
  for (const ty of distributeTicks(coreBot, coreTop, drawnJointTies)) {
    tieTickHDXF(dxf, ox, ox + columnWidthMM, ty, LAYERS.STIRRUP_TIE.name);
  }
  if (hingeZoneTieSpacingMM != null) {
    const drawnHinge = Math.min(hingeTieCountEachZone, MAX_DRAWN_HINGE_TIES);
    for (const ty of distributeTicks(hinge1Bot, hinge1Top, drawnHinge)) tieTickHDXF(dxf, ox, ox + columnWidthMM, ty, LAYERS.STIRRUP_TIE.name);
    for (const ty of distributeTicks(hinge2Bot, hinge2Top, drawnHinge)) tieTickHDXF(dxf, ox, ox + columnWidthMM, ty, LAYERS.STIRRUP_TIE.name);
  }

  // Beam bars — one representative line each, embedded by developmentLengthMM
  // or drawn to the column's far face when omitted (INPUT CONTRACT).
  const coreZ0 = zones.core[0], coreZ1 = zones.core[1];
  const topBarY = oy + (totalColumnHeightMM - (coreZ0 + 0.28 * (coreZ1 - coreZ0)));
  const botBarY = oy + (totalColumnHeightMM - (coreZ0 + 0.82 * (coreZ1 - coreZ0)));
  const topEmbedMM = beamTopBars.developmentLengthMM ?? geometry.columnWidthMM;
  const botEmbedMM = beamBottomBars.developmentLengthMM ?? geometry.columnWidthMM;
  const topEmbedX = beamX - topEmbedMM;
  const botEmbedX = beamX - botEmbedMM;

  dxf.addLine(point3d(beamOuterX, topBarY), point3d(topEmbedX, topBarY), { layerName: LAYERS.REBAR_TOP.name });
  dxf.addLine(point3d(beamOuterX, botBarY), point3d(botEmbedX, botBarY), { layerName: LAYERS.REBAR_BOTTOM.name });
  barMarkTagDXF(dxf, beamOuterX + MARK_GAP_MM, topBarY, `${beamTopBars.count}\u00d8${fmt0(beamTopBars.dia)}`, LAYERS.MARK_TAGS.name);
  barMarkTagDXF(dxf, beamOuterX + MARK_GAP_MM, botBarY, `${beamBottomBars.count}\u00d8${fmt0(beamBottomBars.dia)}`, LAYERS.MARK_TAGS.name);

  // Two development-length dimensions (top AND bottom) — see file header.
  dimensionLineDXF(dxf, beamX, topBarY + DIM_OFFSET_MM, topEmbedX, topBarY + DIM_OFFSET_MM, `${fmt0(topEmbedMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dxfText(dxf, (beamX + topEmbedX) / 2, topBarY + DIM_OFFSET_MM * 1.9, SUBTITLE_HEIGHT_MM * 0.85, 'development length into joint - top', {
    layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });
  dimensionLineDXF(dxf, beamX, botBarY - DIM_OFFSET_MM, botEmbedX, botBarY - DIM_OFFSET_MM, `${fmt0(botEmbedMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dxfText(dxf, (beamX + botEmbedX) / 2, botBarY - DIM_OFFSET_MM * 1.9, SUBTITLE_HEIGHT_MM * 0.85, 'development length into joint - bottom', {
    layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  dxfText(dxf, ox + columnWidthMM / 2, colTopY + SUBTITLE_HEIGHT_MM * 1.8, SUBTITLE_HEIGHT_MM, 'JOINT ELEVATION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: columnWidthMM + beamSpanShownMM, height: totalColumnHeightMM };
}

export function renderBeamColumnJointDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'beamColumnJoint') {
    throw new DiagramError('BAD_PARAM', 'renderBeamColumnJointDiagramDXF expects a geometry object from computeBeamColumnJointDiagramGeometry() (type "beamColumnJoint").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);
  defineDashedLType(dxf);

  const sectionOrigin = { x: 0, y: 0 };
  const section = renderJointCoreSectionDXF(dxf, geometry, sectionOrigin);

  const elevOriginX = section.width + (opts.viewGapMM ?? VIEW_GAP_MM);
  const elevOrigin = { x: elevOriginX, y: 0 };
  const elev = renderJointElevationDXF(dxf, geometry, elevOrigin);

  const overallWidth = (elevOriginX + elev.width) - sectionOrigin.x;
  const overallHeight = Math.max(section.height, elev.height);
  dxfText(dxf, sectionOrigin.x + overallWidth / 2, overallHeight + MARGIN_MM * 2.6, TITLE_HEIGHT_MM, `BEAM-COLUMN JOINT ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
