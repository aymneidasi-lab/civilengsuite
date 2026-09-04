// wallOpeningDiagram.dxf.mjs
// DXF render path for the wall-opening trim reinforcement diagram —
// parallel to, and entirely separate from, renderWallOpeningDiagramSVG()
// in wallOpeningDiagram.mjs. Separate file per this project's standing
// session-3 decision: keeps @tarikjabiri/dxf out of any ordinary
// /diagram or /rebar (SVG-only) module graph.
//
// computeWallOpeningDiagramGeometry() is consumed exactly as returned,
// imported from wallOpeningDiagram.mjs with zero modification to that
// file. This module only renders; it never validates or computes.
// Verified directly by executing that function before writing this:
//   { type:'wallOpening', unit, id, lengthMM, heightMM, thicknessMM, coverMM,
//     opening: { widthMM, heightMM, xMM, sillMM, topFromWallTopMM },
//     trimBars: { dia, count, spacing, faceOffsetMM, extensionMM,
//                 cuttingLengthMM, faceReachMM, envelopeMM },
//     diagonalBars: { dia, count, legMM, cuttingLengthMM,
//                     corners:[{cx,cy,ex,ey}x4] } | null }
//
// v1 scope exclusions carried over unchanged from the prompt: no
// schedule table (DXF TABLE), no caption text, no Arabic labels (English
// only, hardcoded — not opts.lang-driven, matching every other
// <element>.dxf.mjs in this project). No bar-dot circles anywhere in
// this element — every rebar mark here is a straight LINE (trim bars,
// diagonal bars), so there is no bar-dot collision concern to guard.
//
// ── AXIS NOTE (verified against wallOpeningDiagram.mjs's own compute()
// return shape by executing it before writing this, not assumed) ──
// geometry.opening.sillMM is ALREADY a real height-above-the-wall-BASE
// value (door/window sill height, as specified on a real drawing) — the
// exact y-up quantity a DXF world needs, unchanged. World origin (0,0)
// below is the wall's own bottom-left corner: x=0 at the wall's left
// edge (opening.xMM measured the same way, no flip), y=0 at the wall's
// base (opening.sillMM measured the same way, no flip). Only
// geometry.opening.topFromWallTopMM and diagonalBars.corners[].cy/ey are
// in the OTHER, SVG-only frame (y-DOWN from the wall's TOP, per that
// file's own DIRECTION CONVENTION note) — those alone need the flip:
// worldY = heightMM - localY. Confirmed by tracing the source's own
// corner-generation code (oTop=topFromWallTopMM, corners built from
// oTop/oBot) before writing toWorldY() below, not assumed by analogy
// with any other element's axis case.
function toWorldY(localYFromTopMM, heightMM) {
  return heightMM - localYFromTopMM;
}

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
  dimensionLineDXF,
  barMarkTagDXF,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// ── Layout conventions ──────────────────────────────────────────────
// None of these come from geometry or from the prompt; each is a chosen
// default for real-mm placement that the SVG path never needed (it drew
// everything inside a fixed px canvas instead). All overridable via
// opts, all named so they're auditable.
const MARGIN_MM = 300; // gutter around the elevation view for dimension lines/labels
const VIEW_GAP_MM = 1200; // real-mm gap between the elevation and detail views, model space
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view titles, zone label, mark tags
const DIM_TEXT_HEIGHT_MM = 150;

function fmt0(mm) {
  return String(Math.round(mm));
}

function renderElevationViewDXF(dxf, geometry, origin) {
  const { lengthMM, heightMM, opening, trimBars } = geometry;
  const { x: ox, y: oy } = origin; // (ox,oy) maps to the wall's own bottom-left corner

  closedRectDXF(dxf, ox, oy, lengthMM, heightMM, LAYERS.CONCRETE_OUTLINE.name);

  const opX = ox + opening.xMM;
  const opY = oy + opening.sillMM; // real height-above-base, no flip — see AXIS NOTE
  const opW = opening.widthMM;
  const opH = opening.heightMM;
  const env = trimBars.envelopeMM;

  // Trim-bar envelope — SVG's own `.stirrup-outline` rect around the
  // opening, direct translation: fill:none unfilled rect either way.
  closedRectDXF(dxf, opX - env, opY - env, opW + 2 * env, opH + 2 * env, LAYERS.STIRRUP_TIE.name);

  // Opening cut boundary — SVG's own `.cut-line` (dashed) class, reused
  // here on CONCRETE_OUTLINE + DASHED, same "real edge solid / cut or
  // void boundary dashed" convention footingDiagram.dxf.mjs's own
  // pedestal rect already establishes for this kit.
  closedRectDXF(dxf, opX, opY, opW, opH, LAYERS.CONCRETE_OUTLINE.name, { lineType: DASHED_LTYPE_NAME });
  dxfText(dxf, opX + opW / 2, opY + opH / 2, SUBTITLE_HEIGHT_MM * 0.75, 'OPENING', {
    layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Middle,
  });

  dimensionLineDXF(dxf, ox, oy + heightMM + MARGIN_MM * 0.6, ox + lengthMM, oy + heightMM + MARGIN_MM * 0.6, `${fmt0(lengthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + heightMM, `${fmt0(heightMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, opX, oy - MARGIN_MM * 0.6, `${fmt0(opening.xMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox + lengthMM + MARGIN_MM * 0.6, oy, ox + lengthMM + MARGIN_MM * 0.6, opY, `${fmt0(opening.sillMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  barMarkTagDXF(dxf, opX + opW + env + MARGIN_MM * 0.5, opY + opH + env, `${trimBars.count}x\u00d8${fmt0(trimBars.dia)}`, LAYERS.MARK_TAGS.name);

  dxfText(dxf, ox + lengthMM / 2, oy + heightMM + MARGIN_MM * 1.4, SUBTITLE_HEIGHT_MM, 'ELEVATION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: lengthMM, height: heightMM };
}

function renderDetailViewDXF(dxf, geometry, origin) {
  const { opening, trimBars, diagonalBars, heightMM } = geometry;
  const { x: ox, y: oy } = origin; // (ox,oy) maps to the opening's own bottom-left corner
  const ow = opening.widthMM, oh = opening.heightMM;

  closedRectDXF(dxf, ox, oy, ow, oh, LAYERS.CONCRETE_OUTLINE.name, { lineType: DASHED_LTYPE_NAME });

  const ext = trimBars.extensionMM;
  const xLo = ox - ext, xHi = ox + ow + ext;
  const yLo = oy - ext, yHi = oy + oh + ext;
  // Direct translation of the SVG source's own per-side loop: horizontal
  // lines (top & bottom trim) on REBAR_BOTTOM, vertical lines (left &
  // right trim) on REBAR_TOP — the source's own class assignment
  // (bar-bottom for horizontal, bar-top for vertical), replicated
  // exactly, not "corrected".
  for (let i = 0; i < trimBars.count; i++) {
    const off = trimBars.faceOffsetMM + i * trimBars.spacing;
    dxf.addLine(point3d(xLo, oy + oh + off), point3d(xHi, oy + oh + off), { layerName: LAYERS.REBAR_BOTTOM.name }); // top trim (world-up from opening top)
    dxf.addLine(point3d(xLo, oy - off), point3d(xHi, oy - off), { layerName: LAYERS.REBAR_BOTTOM.name }); // bottom trim
    dxf.addLine(point3d(ox - off, yLo), point3d(ox - off, yHi), { layerName: LAYERS.REBAR_TOP.name }); // left trim
    dxf.addLine(point3d(ox + ow + off, yLo), point3d(ox + ow + off, yHi), { layerName: LAYERS.REBAR_TOP.name }); // right trim
  }

  if (diagonalBars) {
    // corners[].cx/cy/ex/ey are in the SVG-only y-down-from-wall-top
    // frame (see AXIS NOTE) — flipped here via toWorldY(), then
    // re-based onto this view's own local (opening-corner) origin using
    // the SAME opening.xMM/opening's-top-in-that-frame offset the
    // source itself subtracts (opening.xMM horizontally,
    // opening.topFromWallTopMM vertically, pre-flip).
    for (const c of diagonalBars.corners) {
      const x1 = ox + (c.cx - opening.xMM);
      const y1 = oy + (toWorldY(c.cy, heightMM) - toWorldY(opening.topFromWallTopMM + opening.heightMM, heightMM));
      const x2 = ox + (c.ex - opening.xMM);
      const y2 = oy + (toWorldY(c.ey, heightMM) - toWorldY(opening.topFromWallTopMM + opening.heightMM, heightMM));
      dxf.addLine(point3d(x1, y1), point3d(x2, y2), { layerName: LAYERS.DIAGONAL_BAR.name });
    }
  }

  barMarkTagDXF(dxf, ox - ext - MARGIN_MM * 0.6, oy + oh + ext + MARGIN_MM * 0.6, `${trimBars.count}x\u00d8${fmt0(trimBars.dia)}`, LAYERS.MARK_TAGS.name);
  if (diagonalBars) {
    barMarkTagDXF(dxf, ox + ow + ext + MARGIN_MM * 0.6, oy + oh + ext + MARGIN_MM * 0.6, `${diagonalBars.count}x\u00d8${fmt0(diagonalBars.dia)}`, LAYERS.MARK_TAGS.name);
  }

  dimensionLineDXF(dxf, ox, oy - ext - MARGIN_MM * 0.6, ox + ow, oy - ext - MARGIN_MM * 0.6, `${fmt0(ow)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - ext - MARGIN_MM * 0.6, oy, ox - ext - MARGIN_MM * 0.6, oy + oh, `${fmt0(oh)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + ow / 2, oy + oh + ext + MARGIN_MM * 1.3, SUBTITLE_HEIGHT_MM, 'OPENING DETAIL', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: ow + 2 * ext, height: oh + 2 * ext, originX: ox - ext };
}

export function renderWallOpeningDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'wallOpening') {
    throw new DiagramError('BAD_PARAM', 'renderWallOpeningDiagramDXF expects a geometry object from computeWallOpeningDiagramGeometry() (type "wallOpening").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);
  defineDashedLType(dxf);

  const elevOrigin = { x: 0, y: 0 };
  const elevation = renderElevationViewDXF(dxf, geometry, elevOrigin);

  const detailOriginX = geometry.lengthMM + (opts.viewGapMM ?? VIEW_GAP_MM);
  const detailOrigin = { x: detailOriginX, y: geometry.opening.sillMM };
  const detail = renderDetailViewDXF(dxf, geometry, detailOrigin);

  const overallWidth = (detail.originX + detail.width) - elevOrigin.x;
  dxfText(dxf, elevOrigin.x + overallWidth / 2, elevation.height + MARGIN_MM * 2.4, TITLE_HEIGHT_MM, `WALL OPENING ${geometry.id} - TRIM REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
