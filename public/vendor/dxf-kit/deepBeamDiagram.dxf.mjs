// deepBeamDiagram.dxf.mjs
// DXF render path for computeDeepBeamDiagramGeometry() (deepBeamDiagram.mjs),
// parallel to renderDeepBeamDiagramSVG(). Zero modification to that file;
// geometry consumed as-is. English only, no schedule table, no caption —
// same v1 exclusion every sibling .dxf.mjs carries (verified against
// beamDiagram.dxf.mjs and couplingBeamDiagram.dxf.mjs before writing this).
//
// Layer choice, all pre-existing, none new: main bars -> REBAR_TOP /
// REBAR_BOTTOM (same as beamDiagram.dxf.mjs's own longitudinal bars);
// horizontal web bars (Avh) -> REBAR_MESH_LINE, drawn as full-span lines
// exactly like raftPileDiagram.dxf.mjs's own mesh (same distributed-
// reinforcement role); vertical web bars (Av) -> STIRRUP_TIE via
// stirrupTickVDXF, exactly like beamDiagram.dxf.mjs's own stirrup ticks
// (same representative-tick + spacing-callout convention); beam +
// supports -> CONCRETE_OUTLINE, same reuse beamDiagram.dxf.mjs's own
// support rects already establish.

import {
  DxfWriter, point3d, Units, LAYERS, defineDxfLayers, dxfText,
  closedRectDXF, barDotDXF, barMarkTagDXF, stirrupTickVDXF, dimensionLineDXF,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

const MARGIN_MM = 300;
const VIEW_GAP_MM = 1200;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 150;
const SUPPORT_OVERHANG_MM = 200;

function fmt0(mm) { return String(Math.round(mm)); }

function renderElevationDXF(dxf, geometry, origin) {
  const {
    totalLengthMM, depthMM, coverMM, supports, mainBars, webReinforcement,
  } = geometry;
  const { x: ox, y: oy } = origin; // oy = beam soffit (bottom edge)
  const topY = oy + depthMM;

  const supportTopY = topY + SUPPORT_OVERHANG_MM;
  const supportBotY = oy - SUPPORT_OVERHANG_MM;
  supports.forEach((s) => {
    const lo = ox + s.x - s.width / 2, hi = ox + s.x + s.width / 2;
    closedRectDXF(dxf, lo, supportBotY, hi - lo, supportTopY - supportBotY, LAYERS.CONCRETE_OUTLINE.name);
    dxfText(dxf, (lo + hi) / 2, supportBotY - MARGIN_MM * 0.3, SUBTITLE_HEIGHT_MM * 0.7, s.label, {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
    });
  });

  closedRectDXF(dxf, ox, oy, totalLengthMM, depthMM, LAYERS.CONCRETE_OUTLINE.name);

  for (const yFromTopMM of webReinforcement.horizontal.rowYsFromTopMM) {
    const y = topY - yFromTopMM;
    dxf.addLine(point3d(ox, y), point3d(ox + totalLengthMM, y), { layerName: LAYERS.REBAR_MESH_LINE.name });
  }
  const tieTopY = topY - coverMM * 0.5, tieBotY = oy + coverMM * 0.5;
  for (const xMM of webReinforcement.vertical.colXs) {
    stirrupTickVDXF(dxf, ox + xMM, tieTopY, tieBotY, LAYERS.STIRRUP_TIE.name);
  }

  for (const g of mainBars) {
    const y = topY - g.yFromTopMM;
    const layerName = g.face === 'top' ? LAYERS.REBAR_TOP.name : LAYERS.REBAR_BOTTOM.name;
    dxf.addLine(point3d(ox + g.startX, y), point3d(ox + g.endX, y), { layerName });
    const tagY = g.face === 'top' ? y + SUBTITLE_HEIGHT_MM : y - SUBTITLE_HEIGHT_MM;
    barMarkTagDXF(dxf, ox + (g.startX + g.endX) / 2, tagY, `${g.markId} \u00d8${fmt0(g.dia)}-${g.count}`, LAYERS.MARK_TAGS.name);
  }

  dimensionLineDXF(dxf, ox, supportBotY - MARGIN_MM * 0.8, ox + totalLengthMM, supportBotY - MARGIN_MM * 0.8, `L = ${fmt0(totalLengthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + totalLengthMM / 2, supportTopY + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'ELEVATION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { totalLengthMM, bottomY: supportBotY - MARGIN_MM * 1.6, topY: supportTopY };
}

function renderSectionDXF(dxf, geometry, origin) {
  const { section, sections } = geometry;
  const sec = sections[0];
  const { x: ox, y: oy } = origin; // oy = section bottom edge
  const topY = oy + section.h;

  closedRectDXF(dxf, ox, oy, section.b, section.h, LAYERS.CONCRETE_OUTLINE.name);

  for (const bar of sec.webBars) {
    barDotDXF(dxf, ox + bar.xMM, topY - bar.yFromTopMM, bar.dia, bar.dia * 6, LAYERS.REBAR_MESH_LINE.name);
  }
  for (const bar of sec.mainBars) {
    const layerName = bar.face === 'top' ? LAYERS.REBAR_TOP.name : LAYERS.REBAR_BOTTOM.name;
    barDotDXF(dxf, ox + bar.xMM, topY - bar.yFromTopMM, bar.dia, bar.dia * 6, layerName);
  }

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + section.b, oy - MARGIN_MM * 0.6, `b = ${fmt0(section.b)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, topY, `h = ${fmt0(section.h)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + section.b / 2, topY + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION A-A', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: section.b, height: section.h };
}

export function renderDeepBeamDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'deepBeam') {
    throw new DiagramError('BAD_PARAM', 'renderDeepBeamDiagramDXF expects a geometry object from computeDeepBeamDiagramGeometry() (type "deepBeam").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const elevOrigin = { x: 0, y: 0 };
  const elev = renderElevationDXF(dxf, geometry, elevOrigin);

  const gap = opts.viewGapMM ?? VIEW_GAP_MM;
  const sectionOrigin = { x: 0, y: elev.bottomY - gap - geometry.section.h };
  renderSectionDXF(dxf, geometry, sectionOrigin);

  dxfText(dxf, elev.totalLengthMM / 2, elev.topY + MARGIN_MM * 1.6, TITLE_HEIGHT_MM, `DEEP BEAM ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
