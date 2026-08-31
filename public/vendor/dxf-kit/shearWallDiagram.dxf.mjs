// shearWallDiagram.dxf.mjs
// DXF render path for the shear-wall reinforcement diagram — parallel to,
// and entirely separate from, renderShearWallDiagramSVG() in
// shearWallDiagram.mjs. Placement decided by explicit session
// confirmation (separate file, not a function added to shearWallDiagram.mjs)
// specifically so an ordinary /diagram or /rebar SVG request never pulls
// @tarikjabiri/dxf into the Worker's module graph — only whatever future
// entry point actually asks for a DXF export does.
//
// computeShearWallDiagramGeometry() is consumed exactly as-is, imported
// from shearWallDiagram.mjs with zero modification to that file. This
// module only renders; it never validates or computes.
//
// v1 scope exclusions carried over unchanged from the prompt: no Arabic
// labels (English only, hardcoded — not opts.lang-driven, unlike the SVG
// version), no schedule table, no multi-line caption. Both omissions are
// deliberate, not oversights — see برومبت_مسار_تحويل_DXF_v4.md's "نطاق
// هذه الجلسة" section.

import {
  DxfWriter,
  point3d,
  Units,
  LAYERS,
  defineDxfLayers,
  dxfText,
  closedRectDXF,
  barDotDXF,
  tieTickHDXF,
  barMarkTagDXF,
  dimensionLineDXF,
  distributeTicks,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Duplicated from shearWallDiagram.mjs — that file does not export these
// (they are unexported module-level consts used only inside its own
// render functions), and this file must not be edited to add an export
// (zero modification to the existing file, per session scope). Flagged
// here explicitly so a future change to the source values does not
// silently desync: shearWallDiagram.mjs lines 78-79 and 85 at time of
// writing (session26; verified byte-identical to session25).
const MAX_MESH_COLS = 14;
const MAX_MESH_ROWS = 14;
const MAX_DRAWN_TIES = 24;

// Layout conventions — none of these come from geometry or from the
// prompt; each is a chosen default for real-mm placement that the SVG
// path never needed (it drew everything inside a fixed pixel canvas
// instead). All overridable via opts, all named so they're auditable.
const MARGIN_MM = 300; // gutter around the elevation view for dimension lines/labels
const VIEW_GAP_MM = 1000; // real-mm gap between elevation and section views, model space
const SECTION_EDGE_MARGIN_MM = 60; // inset from the section strip's ends to its first/last bar dot
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view titles (ELEVATION/SECTION), zone labels, mark tags, support-label
const DIM_TEXT_HEIGHT_MM = 150;

function fmt0(mm) {
  return String(Math.round(mm));
}

function renderElevationViewDXF(dxf, geometry, origin, opts) {
  const { lengthMM, heightMM, mesh, boundaryElement } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, lengthMM, heightMM, LAYERS.CONCRETE_OUTLINE.name);

  const drawCols = Math.min(mesh.vertical.count, MAX_MESH_COLS);
  const drawRows = Math.min(mesh.horizontal.count, MAX_MESH_ROWS);
  const xs = distributeTicks(ox, ox + lengthMM, drawCols);
  const ys = distributeTicks(oy, oy + heightMM, drawRows);
  const pitchX = xs.length > 1 ? xs[1] - xs[0] : Infinity;
  const pitchY = ys.length > 1 ? ys[1] - ys[0] : Infinity;
  const meshPitch = Math.min(pitchX, pitchY);
  for (const y of ys) {
    for (const x of xs) {
      barDotDXF(dxf, x, y, mesh.vertical.dia, meshPitch, LAYERS.REBAR_TOP.name);
    }
  }

  if (boundaryElement) {
    const bw = boundaryElement.widthMM;
    closedRectDXF(dxf, ox, oy, bw, heightMM, LAYERS.STIRRUP_TIE.name);
    closedRectDXF(dxf, ox + lengthMM - bw, oy, bw, heightMM, LAYERS.STIRRUP_TIE.name);

    const drawTies = Math.min(boundaryElement.ties.count, MAX_DRAWN_TIES);
    const tieInset = Math.min(TICK_CAP_INSET_MM(bw), bw / 2 - 1);
    for (const ty of distributeTicks(oy, oy + heightMM, drawTies)) {
      tieTickHDXF(dxf, ox + tieInset, ox + bw - tieInset, ty, LAYERS.STIRRUP_TIE.name);
      tieTickHDXF(dxf, ox + lengthMM - bw + tieInset, ox + lengthMM - tieInset, ty, LAYERS.STIRRUP_TIE.name);
    }

    // NOTE on vertical direction: the SVG source uses a downward-y screen
    // convention (sy = top of wall, sy+h = bottom), so its zone-label at
    // "sy-4" sits ABOVE the wall's top edge. This file uses an upward-y
    // convention (oy = bottom, oy+heightMM = top), so the equivalent
    // "above the top edge" position is oy+heightMM+gap, NOT oy-gap — an
    // earlier draft got this backwards (placed it below instead of above)
    // and was corrected before this file was finalized.
    const zoneLabel = `BOUNDARY ELEMENT ${boundaryElement.verticalBars.count}x\u00d8${fmt0(boundaryElement.verticalBars.dia)}`;
    dxfText(dxf, ox + bw / 2, oy + heightMM + SUBTITLE_HEIGHT_MM * 0.3, SUBTITLE_HEIGHT_MM, zoneLabel, {
      layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
    });
    dxfText(dxf, ox + lengthMM - bw / 2, oy + heightMM + SUBTITLE_HEIGHT_MM * 0.3, SUBTITLE_HEIGHT_MM, zoneLabel, {
      layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
    });
  }

  barMarkTagDXF(dxf, ox + lengthMM + MARGIN_MM * 0.8, oy + heightMM - MARGIN_MM * 0.5, `\u00d8${fmt0(mesh.vertical.dia)}@${fmt0(mesh.vertical.spacing)}`, LAYERS.MARK_TAGS.name);

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + lengthMM, oy - MARGIN_MM * 0.6, `${fmt0(lengthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + heightMM, `${fmt0(heightMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + lengthMM / 2, oy - MARGIN_MM * 1.3, SUBTITLE_HEIGHT_MM, `\u00d8${fmt0(mesh.horizontal.dia)}@${fmt0(mesh.horizontal.spacing)}`, {
    // "support-label" in the SVG source has no confirmed CSS rule (verified: none found in either
    // structuralDrawingKit.mjs or shearWallDiagram.mjs) — placed on ANNOTATION as a flagged default,
    // not a table-confirmed layer assignment.
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  // Above everything else stacked above the wall's top edge (zone labels
  // included, when present) so the view title never overlaps them.
  const titleGap = boundaryElement ? SUBTITLE_HEIGHT_MM * 1.8 : SUBTITLE_HEIGHT_MM * 0.5;
  dxfText(dxf, ox + lengthMM / 2, oy + heightMM + titleGap, SUBTITLE_HEIGHT_MM, 'ELEVATION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: lengthMM, height: heightMM };
}

function TICK_CAP_INSET_MM(boundaryWidthMM) {
  return Math.min(40, boundaryWidthMM * 0.1);
}

function renderSectionViewDXF(dxf, geometry, origin, opts) {
  const { thicknessMM, coverMM, mesh } = geometry;
  const { x: ox, y: oy } = origin;
  const edgeMargin = SECTION_EDGE_MARGIN_MM;
  const stripLenMM = 3 * mesh.vertical.spacing + 2 * edgeMargin; // 4 representative dots -> 3 true-pitch intervals, same count as the SVG version's fixed distributeTicks(...,4)

  closedRectDXF(dxf, ox, oy, stripLenMM, thicknessMM, LAYERS.CONCRETE_OUTLINE.name);

  const nearY = oy + coverMM;
  const farY = oy + thicknessMM - coverMM;
  const lineInset = Math.min(edgeMargin * 0.5, stripLenMM / 2 - 1);
  dxf.addLine(point3d(ox + lineInset, nearY), point3d(ox + stripLenMM - lineInset, nearY), { layerName: LAYERS.REBAR_TOP.name });
  dxf.addLine(point3d(ox + lineInset, farY), point3d(ox + stripLenMM - lineInset, farY), { layerName: LAYERS.REBAR_BOTTOM.name });

  const xs = distributeTicks(ox + edgeMargin, ox + stripLenMM - edgeMargin, 4);
  const horizPitch = xs.length > 1 ? xs[1] - xs[0] : Infinity;
  const nearFarGap = farY - nearY; // the other axis these dots could collide across, at small thicknessMM/large coverMM combinations
  const pitch = Math.min(horizPitch, nearFarGap);
  for (const x of xs) {
    barDotDXF(dxf, x, nearY, mesh.vertical.dia, pitch, LAYERS.REBAR_TOP.name);
    barDotDXF(dxf, x, farY, mesh.vertical.dia, pitch, LAYERS.REBAR_TOP.name); // both near and far dots use the same 'shearwall' face class in the SVG source -> same layer, verified, not a fidelity slip
  }

  dimensionLineDXF(dxf, ox + stripLenMM + MARGIN_MM * 0.5, oy, ox + stripLenMM + MARGIN_MM * 0.5, oy + thicknessMM, `${fmt0(thicknessMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, nearY, `${fmt0(coverMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + stripLenMM / 2, oy + thicknessMM + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: stripLenMM, height: thicknessMM, originX: ox };
}

export function renderShearWallDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'shearWall') {
    throw new DiagramError('BAD_PARAM', 'renderShearWallDiagramDXF expects a geometry object from computeShearWallDiagramGeometry() (type "shearWall").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const elevOrigin = { x: 0, y: 0 };
  renderElevationViewDXF(dxf, geometry, elevOrigin, opts);

  const sectionOriginX = geometry.lengthMM + (opts.viewGapMM ?? VIEW_GAP_MM);
  const section = renderSectionViewDXF(dxf, geometry, { x: sectionOriginX, y: 0 }, opts);

  const overallWidth = (sectionOriginX + section.width) - elevOrigin.x;
  dxfText(dxf, elevOrigin.x + overallWidth / 2, geometry.heightMM + MARGIN_MM * 2.2, TITLE_HEIGHT_MM, `SHEAR WALL ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
