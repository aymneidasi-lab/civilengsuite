// hordiSlabDiagram.dxf.mjs
// DXF render path for the one-way ribbed (Hordi) slab schematic —
// parallel to, and entirely separate from, renderHordiSlabDiagramSVG()
// in hordiSlabDiagram.mjs. Same placement rationale as every sibling
// *.dxf.mjs: an ordinary /diagram or /rebar SVG request must never pull
// @tarikjabiri/dxf into the Worker's module graph — only a real
// DXF-export request does.
//
// computeHordiSlabDiagramGeometry() is consumed exactly as returned —
// zero modification to hordiSlabDiagram.mjs, zero re-derivation of any
// value it already provides (mainBars.positions/topBars.positions are
// already-computed real x-local-to-rib mm, read directly).
//
// \u26a0 NON-DELETABLE WARNING, carried forward unchanged: this module's
// caller-supplied ribWidthMM/blockWidthMM/toppingMM are checked here
// only against the SAME generic drawability caps
// computeHordiSlabDiagramGeometry() already enforces — NOT against ECP
// 203's own numeric limits (max clear rib spacing, min topping
// thickness), which this project's own source notes were taken from
// secondary lecture material, not the official code text. Per that
// source file's own instruction ("repeated in the on-drawing caption ...
// so it travels with the artifact, not just this source file"), this
// warning is carried into CAPTION_EN below — this is a second artifact
// path (DXF, not just SVG) and the instruction applies to it too.
//
// SCOPE DECISION — mesh detail is TEXT-ONLY, not a drawn icon grid: the
// SVG source's own renderMeshDetail draws a fixed NxN dot grid in a
// fixed-size box explicitly UNRELATED to the real spacingMM value (see
// that function's own comment: a dimensionLine was deliberately NOT used
// there because it would visually imply the drawn gap is to-scale, which
// it is not — "NTS" in the label is the SVG's own honesty marker). DXF
// is a measured CAD format, not a raster preview — a CAD user routinely
// snaps to and measures drawn geometry, so carrying that same
// deliberately-fake-spaced dot grid into DXF risks exactly the
// "wrong-but-plausible-looking" scale claim the SVG source's own
// comment says it was written specifically to avoid. This file omits
// the icon grid entirely and keeps only the real dia@spacing value as a
// plain ANNOTATION text note (same information the SVG's own text
// caption already carries alongside its icon) — never a drawn geometry
// a CAD user could mistake for real bar positions.
//
// v1 scope exclusions carried over unchanged from the master prompt: no
// Arabic labels (English only, hardcoded, not opts.lang-driven), no
// HATCH (v1-excluded everywhere — the hollow-block symbol and topping
// fill are both outline-only here), no scheduleTable-as-DXF-TABLE (every
// row that table would have shown is still real, individually placed
// geometry/dimension callouts on the two views themselves, or stated in
// the caption for the per-rib-vs-panel-total distinction, which has no
// on-sheet geometry to carry it otherwise).
//
// New-for-this-element decisions, disclosed per the master prompt's own
// protocol:
//   - BLOCK layer added to the shared kit (see that file's own diff
//     comment) — this element's own `block-outline` is its only user.
//   - `.rib-outline` (stroke:#1a1a1a, verified) is CONCRETE-OUTLINE's
//     exact hex — placed there directly, no new layer.
//   - `.support-tri` and `.topping-outline` are BOTH already explicit
//     entries under the master table's own CONCRETE-OUTLINE row
//     ("support-tri", "topping-outline") — used as-is.
//   - `.break-line` (stroke:#555, dashed) and `.box-note` (fill:#555)
//     have no exact-hex match anywhere in the shared table, but the
//     table's own ANNOTATION row is explicitly documented as "varies"
//     (\u0645\u062a\u0641\u0627\u0648\u062a, default #111111 — i.e. per-element variation is
//     already the expected norm for this layer, not a gap needing a new
//     one). `.break-line` also plays the identical semantic role the
//     table's own already-placed "cut-line"/"cut-label" pair plays
//     (a schematic truncation/repeat marker, dashed, not real material
//     edge) — placed on ANNOTATION on that basis, not color alone.
//   - Bar-dot family check: `renderMeshDetail`'s own (now-omitted, see
//     above) dots used face='top' literally in the SVG source — had the
//     icon grid been kept, it would have mapped to REBAR-TOP, not a new
//     layer. Noted for completeness even though this file never draws
//     it.

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
  closedPolylineDXF,
  barDotDXF,
  barMarkTagDXF,
  dimensionLineDXF,
  minPairwiseDistanceMM,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Layout conventions — none of these come from geometry or from the SVG
// source (which drew everything inside a fixed pixel canvas instead);
// each is a chosen default for real-mm placement, named so it's
// auditable, matching every sibling *.dxf.mjs's own convention.
const MARGIN_MM = 300;
const VIEW_GAP_MM = 1000;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 150;
const CAPTION_HEIGHT_MM = 115;
const BREAK_OVERHANG_MM = 80; // how far a break-line extends past the topping/rib zone's own top and bottom edges — real-mm analogue of the SVG source's own 8px overhang
const SUPPORT_TRI_HALF_WIDTH_MM = 80; // half-width of a rib-elevation support-triangle symbol — schematic size, not a real bearing dimension this module was given
const SUPPORT_TRI_HEIGHT_MM = 140;

const CAPTION_EN = 'Schematic drawing generated from the supplied data, for verification only \u2014 check every bar mark, count, spacing, and length against your own design before construction. Lengths marked (extent) are drawn spans only, not computed development lengths. Bar/mesh quantities shown are PER RIB SHOWN, not a real panel-wide total, unless totalSlabWidthMM was supplied (see the computed rib count noted below when present). Mesh spacing is stated as text only, not drawn to scale. \u26a0 ribWidthMM/blockWidthMM/toppingMM are checked here only against generic drawing limits, NOT against ECP 203\u2019s own numeric limits (rib clear spacing, minimum topping thickness) \u2014 those specific figures were sourced from secondary lecture material, not the official code text, at the time this module was written; verify them independently before treating this drawing as code-compliant.';

function fmt0(mm) {
  return String(Math.round(mm));
}

// Draws the typical cross-section (perpendicular to the ribs): a
// continuous topping slab over `ribsShown` ribs and (ribsShown-1)
// hollow-block bays between them, break lines at both ends (honest
// "typical, repeats" convention — never implies only ribsShown ribs
// exist on the real panel), one representative bottom-bar-group dot set
// per rib (every rib identical, per this element's own single-symmetric-
// group scope), and the mesh spec as a text note (see this file's own
// header for why no icon grid is drawn). origin.y is the rib's own
// bottom (soffit) face — topping sits ABOVE it by ribDepthMM, matching
// the real physical stacking (rib depth below the topping, per this
// element's own INPUT CONTRACT: "ribDepthMM ... web depth only; total
// slab depth = toppingMM + ribDepthMM").
function renderCrossSectionDXF(dxf, geometry, origin, opts) {
  const {
    ribsShown, ribWidthMM, blockWidthMM, toppingMM, ribDepthMM, totalShownWidthMM, mainBars, toppingMesh,
  } = geometry;
  const { x: ox, y: ribBaseY } = origin;
  const toppingBaseY = ribBaseY + ribDepthMM;
  const moduleMM = ribWidthMM + blockWidthMM;

  closedRectDXF(dxf, ox, toppingBaseY, totalShownWidthMM, toppingMM, LAYERS.CONCRETE_OUTLINE.name);

  const dots = [];
  for (let i = 0; i < ribsShown; i++) {
    const ribX = ox + i * moduleMM;
    closedRectDXF(dxf, ribX, ribBaseY, ribWidthMM, ribDepthMM, LAYERS.CONCRETE_OUTLINE.name);
    for (const bx of mainBars.positions) {
      dots.push({ x: ribX + bx, y: ribBaseY + geometry.coverMM + mainBars.dia / 2, diaMM: mainBars.dia });
    }
    if (i < ribsShown - 1) {
      closedRectDXF(dxf, ribX + ribWidthMM, ribBaseY, blockWidthMM, ribDepthMM, LAYERS.BLOCK.name);
    }
  }
  const pitch = minPairwiseDistanceMM(dots);
  for (const d of dots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_BOTTOM.name);

  const topZoneY0 = ribBaseY - BREAK_OVERHANG_MM;
  const topZoneY1 = toppingBaseY + toppingMM + BREAK_OVERHANG_MM;
  dxf.addLine(point3d(ox, topZoneY0), point3d(ox, topZoneY1), { layerName: LAYERS.ANNOTATION.name, lineType: DASHED_LTYPE_NAME });
  dxf.addLine(point3d(ox + totalShownWidthMM, topZoneY0), point3d(ox + totalShownWidthMM, topZoneY1), { layerName: LAYERS.ANNOTATION.name, lineType: DASHED_LTYPE_NAME });
  dxfText(dxf, ox, topZoneY0 - MARGIN_MM * 0.2, SUBTITLE_HEIGHT_MM * 0.8, 'typical, repeats', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, ox + totalShownWidthMM, topZoneY0 - MARGIN_MM * 0.2, SUBTITLE_HEIGHT_MM * 0.8, 'typical, repeats', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  const dimRowY = topZoneY0 - MARGIN_MM * 1.2;
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, toppingBaseY, ox - MARGIN_MM * 0.6, toppingBaseY + toppingMM, `${fmt0(toppingMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, ribBaseY, ox - MARGIN_MM * 0.6, toppingBaseY, `${fmt0(ribDepthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox, dimRowY, ox + ribWidthMM, dimRowY, `${fmt0(ribWidthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  let dimRow2Y = dimRowY;
  if (ribsShown > 1) {
    dimRow2Y = dimRowY - MARGIN_MM * 1.4;
    dimensionLineDXF(dxf, ox + ribWidthMM, dimRow2Y, ox + ribWidthMM + blockWidthMM, dimRow2Y, `${fmt0(blockWidthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  }

  const tagX = ox + totalShownWidthMM + MARGIN_MM * 0.8;
  const tagY = ribBaseY + ribDepthMM / 2;
  barMarkTagDXF(dxf, tagX, tagY, `${mainBars.count}\u00d8${fmt0(mainBars.dia)}`, LAYERS.MARK_TAGS.name);

  dxfText(dxf, tagX, tagY - MARGIN_MM * 0.6, DIM_TEXT_HEIGHT_MM, `\u00d8${fmt0(toppingMesh.dia)}mm @ ${fmt0(toppingMesh.spacing)}mm b.w.`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, tagX, tagY - MARGIN_MM * 0.6 - SUBTITLE_HEIGHT_MM, DIM_TEXT_HEIGHT_MM * 0.8, 'topping shrinkage mesh (schematic, not to scale)', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Top,
  });

  const titleY = toppingBaseY + toppingMM + MARGIN_MM * 0.8;
  dxfText(dxf, ox + totalShownWidthMM / 2, titleY, SUBTITLE_HEIGHT_MM, 'TYPICAL CROSS-SECTION (perpendicular to ribs)', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return {
    width: totalShownWidthMM,
    top: titleY + SUBTITLE_HEIGHT_MM,
    bottom: Math.min(dimRow2Y, dimRowY) - MARGIN_MM * 0.6,
  };
}

// Draws a single rib in longitudinal section: the rib outline over its
// FULL drawn span (clear span + end extensions), support-triangle
// symbols at each clear-span end, the bottom bar line (full drawn
// span), and — if supplied — the top (support/negative-moment) bar
// lines, each extentMM long from its own end. origin.y is the rib's own
// bottom (soffit) face, origin.x is the drawn span's own left edge
// (x=0 local to this view, matching computeHordiSlabDiagramGeometry's
// own spanMM/extraLengthAtEachEndMM coordinate convention directly).
function renderRibElevationDXF(dxf, geometry, origin, opts) {
  const { spanMM, ribDepthMM, mainBars, topBars, coverMM } = geometry;
  const { x: ox, y: baseY } = origin;
  const drawSpanMM = spanMM + 2 * mainBars.extraLengthAtEachEndMM;
  const spanX0 = ox + mainBars.extraLengthAtEachEndMM;
  const spanX1 = spanX0 + spanMM;
  const topY = baseY + ribDepthMM;

  closedRectDXF(dxf, ox, baseY, drawSpanMM, ribDepthMM, LAYERS.CONCRETE_OUTLINE.name);

  for (const sx of [spanX0, spanX1]) {
    closedPolylineDXF(dxf, [
      { x: sx, y: baseY },
      { x: sx - SUPPORT_TRI_HALF_WIDTH_MM, y: baseY - SUPPORT_TRI_HEIGHT_MM },
      { x: sx + SUPPORT_TRI_HALF_WIDTH_MM, y: baseY - SUPPORT_TRI_HEIGHT_MM },
    ], LAYERS.CONCRETE_OUTLINE.name);
  }

  const barY = baseY + coverMM + mainBars.dia / 2;
  dxf.addLine(point3d(ox, barY), point3d(ox + drawSpanMM, barY), { layerName: LAYERS.REBAR_BOTTOM.name });
  barMarkTagDXF(dxf, ox - MARGIN_MM * 0.6, barY, `${mainBars.count}\u00d8${fmt0(mainBars.dia)}`, LAYERS.MARK_TAGS.name);

  if (topBars) {
    const topBarY = topY - coverMM - topBars.dia / 2;
    dxf.addLine(point3d(spanX0, topBarY), point3d(spanX0 + topBars.extentMM, topBarY), { layerName: LAYERS.REBAR_TOP.name });
    dxf.addLine(point3d(spanX1 - topBars.extentMM, topBarY), point3d(spanX1, topBarY), { layerName: LAYERS.REBAR_TOP.name });
    barMarkTagDXF(dxf, ox + drawSpanMM + MARGIN_MM * 0.6, topBarY, `${topBars.count}\u00d8${fmt0(topBars.dia)}`, LAYERS.MARK_TAGS.name);
  }

  const spanDimY = baseY - SUPPORT_TRI_HEIGHT_MM - MARGIN_MM * 0.8;
  dimensionLineDXF(dxf, spanX0, spanDimY, spanX1, spanDimY, `${fmt0(spanMM)}mm (clear span)`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  let extraDimY = topY + MARGIN_MM * 0.5;
  if (mainBars.extraLengthAtEachEndMM > 0) {
    dimensionLineDXF(dxf, ox, extraDimY, spanX0, extraDimY, `${fmt0(mainBars.extraLengthAtEachEndMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
    dimensionLineDXF(dxf, spanX1, extraDimY, ox + drawSpanMM, extraDimY, `${fmt0(mainBars.extraLengthAtEachEndMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  } else {
    extraDimY = topY;
  }

  const titleY = extraDimY + MARGIN_MM;
  dxfText(dxf, ox + drawSpanMM / 2, titleY, SUBTITLE_HEIGHT_MM, 'SINGLE RIB \u2014 LONGITUDINAL SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: drawSpanMM, top: titleY + SUBTITLE_HEIGHT_MM, bottom: spanDimY - MARGIN_MM * 0.5 };
}

export function renderHordiSlabDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'hordiSlab') {
    throw new DiagramError('BAD_PARAM', 'renderHordiSlabDiagramDXF expects a geometry object from computeHordiSlabDiagramGeometry() (type "hordiSlab").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  // MUST precede defineDxfLayers()/any entity referencing
  // DASHED_LTYPE_NAME — see structuralDrawingDxfKit.mjs's own header on
  // DxfLayerTable.addLayer()'s silent-Continuous-fallback behavior for an
  // unregistered linetype name.
  defineDashedLType(dxf);
  defineDxfLayers(dxf);

  // Stacked bottom-to-top in DXF model space: RIB ELEVATION lowest,
  // CROSS-SECTION above it — reproducing the SVG source's own
  // top-to-bottom reading order (CROSS_BOX/MESH_BOX drawn first/highest
  // on the sheet, ELEV_BOX below both) as a two-view stack, same
  // "first-drawn-in-SVG reads first/highest" convention every other
  // stacked-view sibling *.dxf.mjs already uses.
  const elevation = renderRibElevationDXF(dxf, geometry, { x: 0, y: 0 }, opts);

  const crossBaseY = elevation.top + (opts.viewGapMM ?? VIEW_GAP_MM);
  const cross = renderCrossSectionDXF(dxf, geometry, { x: 0, y: crossBaseY }, opts);

  const overallWidth = Math.max(elevation.width, cross.width);
  const titleY = cross.top + MARGIN_MM * 2.2;
  dxfText(dxf, overallWidth / 2, titleY, TITLE_HEIGHT_MM, `HORDI (RIBBED) SLAB - TYPICAL SECTION: ${geometry.id}`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  let captionText = CAPTION_EN;
  if (geometry.totalRibCount != null) {
    captionText += ` Computed total ribs in panel (from totalSlabWidthMM): ${geometry.totalRibCount}.`;
  }
  const captionY = elevation.bottom - MARGIN_MM * 1.3;
  dxfText(dxf, overallWidth / 2, captionY, CAPTION_HEIGHT_MM, captionText, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return dxf.stringify();
}
