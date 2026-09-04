// slabOpeningDiagram.dxf.mjs
// DXF render path for the flat-slab opening reinforcement diagram —
// parallel to, and entirely separate from, renderSlabOpeningDiagramSVG() in
// slabOpeningDiagram.mjs. Same placement rationale as
// shearWallDiagram.dxf.mjs (separate file, not a function added to
// slabOpeningDiagram.mjs): an ordinary /diagram or /rebar SVG request must
// never pull @tarikjabiri/dxf into the Worker's module graph.
//
// computeSlabOpeningDiagramGeometry() is consumed exactly as-is, imported
// from slabOpeningDiagram.mjs with zero modification to that file. This
// module only renders; it never validates or computes.
//
// v1 scope exclusions carried over unchanged from the prompt (same as
// shearWallDiagram.dxf.mjs): no Arabic labels (English only, hardcoded, not
// opts.lang-driven), no schedule table, no legend swatches — the legend row
// in the SVG source is schedule-adjacent decorative content (one of its
// three swatches exists only to letter the opening's own span, because a
// fixed-scale SVG raster cannot be measured; a real-mm DXF drawing can be
// measured directly, so that role is dropped, not translated). The essential
// per-bar-group information the legend and schedule table otherwise carried
// (diameter, spacing/count) is preserved instead as minimal MARK-TAGS/
// ZONE-LABEL callouts, the same role shearWallDiagram.dxf.mjs's own
// barMarkTagDXF + "support-label" text already serve there — dot radius is a
// legibility indication, not literal diameter (see structuralDrawingDxfKit.mjs's
// own header), so it cannot carry that information on its own.
//
// Opening void outline: the SVG source draws this with a dashed
// stroke-dasharray specifically to read as "void" against a HATCH-filled
// concrete background. HATCH is out of v1 scope entirely (no fill anywhere
// in this kit), so there is no hatch for the dashed line to contrast
// against — the absence of mesh dots / the gap between the two concrete
// segments already reads as a void unambiguously. A DASHED linetype is not
// added: @tarikjabiri/dxf@2.8.9 does export a LineTypes table, but using it
// correctly requires a verified LTYPE definition this session did not check
// against a real reference — inventing one would violate this project's own
// "no unverified DXF property" rule. Drawn as a plain closedRectDXF outline
// on ANNOTATION (cut-line, per the layer table) instead.

import {
  DxfWriter,
  point3d,
  Units,
  LAYERS,
  defineDxfLayers,
  dxfText,
  closedRectDXF,
  barDotDXF,
  barMarkTagDXF,
  dimensionLineDXF,
  distributeTicks,
  minPairwiseDistanceMM,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Duplicated from slabOpeningDiagram.mjs — that file does not export these
// (unexported module-level consts used only inside its own compute
// function), and this file must not be edited to add an export (zero
// modification to the existing file, per session scope). Flagged here
// explicitly so a future change to the source values does not silently
// desync: slabOpeningDiagram.mjs lines 148-149 at time of writing, verified
// against the actual uploaded file content, not memory.
const MAX_MESH_ROWS = 14;
const MAX_MESH_COLS = 14;

// Layout conventions — none of these come from geometry or from the prompt;
// each is a chosen default for real-mm placement the SVG path never needed
// (fixed pixel canvas instead). All overridable via opts, all named so
// they're auditable. MARGIN_MM/VIEW_GAP_MM/TITLE_HEIGHT_MM/SUBTITLE_HEIGHT_MM/
// DIM_TEXT_HEIGHT_MM reuse shearWallDiagram.dxf.mjs's own values — same
// "gutter for a dimension line + label at typical structural-schematic plot
// scale" reasoning applies unchanged to a different element; independently
// named here (not imported) since the two .dxf.mjs files are separate.
const MARGIN_MM = 300;
const VIEW_GAP_MM = 1000;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view titles, zone labels, mark tags, support-label
const DIM_TEXT_HEIGHT_MM = 150;

// New for this element:
const TRIM_EDGE_INSET_MM = 30; // keeps the first/last trim dot off the opening's own corner vertex, where it would sit exactly on the outline's corner point and closest to the perpendicular trim group's own nearest dot — order-of-magnitude match to the kit's own TICK_CAP_MM (40mm), independently named/justified since it serves a different purpose (dot placement, not a tick cap). Real safety against corner-group collision comes from minPairwiseDistanceMM below, not from this inset — verified in test_slabOpeningDiagramDXF.mjs's tight-edge-case fixture, not just asserted here.
const SECTION_BAR_EDGE_INSET_MM = 30; // same role as TRIM_EDGE_INSET_MM, applied to the section view's bottom-bar line/dots pulling back from the void boundary. The SVG source used an asymmetric 12px/20px split between the left and right segment's own end margin; not preserved (no real-mm meaning survives that asymmetry — see file header) in favor of one symmetric, named constant.
const MIN_SEGMENT_FOR_BAR_LINE_MM = 60; // below this, an intact concrete segment is too short to hold a legible bottom-bar line + end margins — same "legibility floor" convention as the SVG source's own ">24px" guard it replaces. computeSlabOpeningDiagramGeometry()'s own MIN_OPENING_EDGE_MARGIN_MM=150mm (verified by reading that function's edge-margin validation directly) guarantees every real segment clears this by a wide margin; kept as a defensive floor for parity with the source, not a live edge case.
const SECTION_VOID_OVERSHOOT_MM = 40; // real-mm analogue of the SVG section view's 6px overshoot above/below the strip on the void outline, so the void's outline reads clearly past the two concrete segments' own top/bottom edges rather than exactly meeting them.

function fmt0(mm) {
  return String(Math.round(mm));
}

function renderPlanViewDXF(dxf, geometry, origin, opts) {
  const { lengthMM, widthMM, mesh, opening, trimBars } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, lengthMM, widthMM, LAYERS.CONCRETE_OUTLINE.name);

  // Bottom mesh grid, skipping cells inside the opening — same
  // distributeTicks()+pitch convention as shearWallDiagram.dxf.mjs's own
  // elevation mesh loop, extended with the opening skip the SVG source's
  // own drawMeshGridSkippingOpening() performs. Skipping only ever REMOVES
  // points from a regular grid; every remaining pair is still at a multiple
  // of the base pitch (never closer), so this shared meshPitch value stays
  // a valid, un-optimistic radius-safety bound after skipping too.
  const drawCols = Math.min(mesh.bottom.countX, MAX_MESH_COLS);
  const drawRows = Math.min(mesh.bottom.countY, MAX_MESH_ROWS);
  const xs = distributeTicks(ox, ox + lengthMM, drawCols);
  const ys = distributeTicks(oy, oy + widthMM, drawRows);
  const pitchX = xs.length > 1 ? xs[1] - xs[0] : Infinity;
  const pitchY = ys.length > 1 ? ys[1] - ys[0] : Infinity;
  const meshPitch = Math.min(pitchX, pitchY);

  const openX0 = ox + opening.offX, openX1 = ox + opening.offX + opening.spanX;
  const openY0 = oy + opening.offY, openY1 = oy + opening.offY + opening.spanY;

  for (const y of ys) {
    for (const x of xs) {
      if (x >= openX0 && x <= openX1 && y >= openY0 && y <= openY1) continue; // inside the opening — interrupted mesh, replaced by trim bars below
      barDotDXF(dxf, x, y, mesh.bottom.dia, meshPitch, LAYERS.REBAR_BOTTOM.name);
    }
  }

  // Opening void outline — plain outline, ANNOTATION layer (cut-line per
  // the layer table); see file header for why no dashed linetype.
  closedRectDXF(dxf, openX0, openY0, opening.spanX, opening.spanY, LAYERS.ANNOTATION.name);

  // Trim bars: build the full same-layer point set for THIS view first —
  // four groups meet at the opening's four corners, so a parallelToX dot's
  // true nearest neighbor there can be a parallelToY dot, not one of its
  // own group (see minPairwiseDistanceMM's own header in the kit). Each
  // point keeps its own group's diameter for drawing, but every dot in this
  // view shares the one true minimum pitch for the radius-safety cap.
  const inset = TRIM_EDGE_INSET_MM;
  const yTicks = distributeTicks(openY0 + inset, openY1 - inset, trimBars.parallelToY.countPerSide);
  const xTicks = distributeTicks(openX0 + inset, openX1 - inset, trimBars.parallelToX.countPerSide);
  const trimPoints = [];
  for (const y of yTicks) {
    trimPoints.push({ x: openX0, y, dia: trimBars.parallelToY.dia });
    trimPoints.push({ x: openX1, y, dia: trimBars.parallelToY.dia });
  }
  for (const x of xTicks) {
    trimPoints.push({ x, y: openY0, dia: trimBars.parallelToX.dia });
    trimPoints.push({ x, y: openY1, dia: trimBars.parallelToX.dia });
  }
  const trimPitch = minPairwiseDistanceMM(trimPoints);
  for (const p of trimPoints) {
    barDotDXF(dxf, p.x, p.y, p.dia, trimPitch, LAYERS.OPENING_TRIM.name);
  }

  // Dimension lines — length/width/offX/offY only, matching exactly what
  // the SVG source itself dimensions (see file header on why opening
  // spanX/spanY get no extra dimension line here: real-mm DXF geometry is
  // directly measurable, unlike the source's fixed-scale raster).
  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + lengthMM, oy - MARGIN_MM * 0.6, `${fmt0(lengthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + widthMM, `${fmt0(widthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox, oy + widthMM + MARGIN_MM * 0.6, openX0, oy + widthMM + MARGIN_MM * 0.6, `${fmt0(opening.offX)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 1.6, oy, ox - MARGIN_MM * 1.6, openY0, `${fmt0(opening.offY)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // Bottom-mesh spacing/diameter callouts — same two-annotation pattern as
  // shearWallDiagram.dxf.mjs's own mesh.vertical/mesh.horizontal pair (one
  // MARK-TAGS bubble, one plain ANNOTATION support-label), applied to this
  // element's own spacingX/spacingY (bars ||Y measured along X, bars ||X
  // measured along Y — matches slabOpeningDiagram.mjs's own bottomDirX/
  // bottomDirY label pairing).
  barMarkTagDXF(dxf, ox + lengthMM + MARGIN_MM * 0.8, oy + widthMM - MARGIN_MM * 0.5, `\u00d8${fmt0(mesh.bottom.dia)}@${fmt0(mesh.bottom.spacingX)}`, LAYERS.MARK_TAGS.name);
  dxfText(dxf, ox + lengthMM / 2, oy - MARGIN_MM * 1.6, SUBTITLE_HEIGHT_MM, `\u00d8${fmt0(mesh.bottom.dia)}@${fmt0(mesh.bottom.spacingY)}`, {
    // "support-label" in the SVG source has no confirmed CSS rule (same gap
    // shearWallDiagram.dxf.mjs already flagged for its own analogous label)
    // — placed on ANNOTATION as a flagged default, not a table-confirmed
    // layer assignment.
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  // Trim-bar-group callouts — ZONE-LABEL (#8a6d00, "every occurrence in
  // every element" per the layer table), same "N x diameter" text
  // convention as shearWallDiagram.dxf.mjs's own boundary-element zone
  // label, applied here to a repeated-bar zone along the opening's edges
  // instead of a wall's boundary element.
  dxfText(dxf, ox + lengthMM / 2, oy + widthMM + MARGIN_MM * 1.6, SUBTITLE_HEIGHT_MM, `TRIM BARS || X: ${trimBars.parallelToX.countPerSide}x\u00d8${fmt0(trimBars.parallelToX.dia)}`, {
    layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });
  dxfText(dxf, ox - MARGIN_MM * 2.6, oy + widthMM / 2, SUBTITLE_HEIGHT_MM, `TRIM BARS || Y: ${trimBars.parallelToY.countPerSide}x\u00d8${fmt0(trimBars.parallelToY.dia)}`, {
    layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Right, vAlign: TextVerticalAlignment.Middle,
  });

  dxfText(dxf, ox + lengthMM / 2, oy + widthMM + MARGIN_MM * 2.8, SUBTITLE_HEIGHT_MM, 'OPENING PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: lengthMM, height: widthMM, titleTopY: oy + widthMM + MARGIN_MM * 2.8 };
}

function renderSectionViewDXF(dxf, geometry, origin, opts) {
  const { lengthMM, thicknessMM, coverMM, mesh, opening, trimBars } = geometry;
  const { x: ox, y: oy } = origin;
  const stripW = lengthMM; // full panel length — unlike shearWallDiagram's own representative repeated-pitch strip, this section cuts the FULL panel (see file header's "Section cut" note in slabOpeningDiagram.mjs itself: one real cut through the opening's true Y-center, not a repeated-pattern close-up)
  const stripH = thicknessMM;

  const openX0 = ox + opening.offX, openX1 = ox + opening.offX + opening.spanX;

  // Two intact concrete segments either side of the void — never one rect
  // spanning the opening. HATCH fill dropped per v1 scope (outline only,
  // same as shearWallDiagram.dxf.mjs's own section strip).
  closedRectDXF(dxf, ox, oy, openX0 - ox, stripH, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, openX1, oy, ox + stripW - openX1, stripH, LAYERS.CONCRETE_OUTLINE.name);

  const bottomY = oy + coverMM; // near/bottom face — same "oy + coverMM" upward-Y convention as shearWallDiagram.dxf.mjs's own nearY (oy = bottom face here too); single face only, this module carries no mesh.top (see slabOpeningDiagram.mjs's own SCOPE header), so there is no analogous farY.
  const leftSegLenMM = openX0 - ox; // == opening.offX
  const rightSegLenMM = ox + stripW - openX1; // == lengthMM - offX - spanX

  // Both segments are guaranteed >= MIN_OPENING_EDGE_MARGIN_MM (150mm,
  // enforced by computeSlabOpeningDiagramGeometry()'s own offX/offY/edge
  // validation, verified by reading that function's return path directly)
  // — this check can never actually be false for any geometry object this
  // function receives; kept for defensive parity with the SVG source's own
  // guard, not because either branch is reachable-false here.
  const inset = SECTION_BAR_EDGE_INSET_MM;
  if (leftSegLenMM > MIN_SEGMENT_FOR_BAR_LINE_MM) {
    dxf.addLine(point3d(ox + inset / 2, bottomY), point3d(openX0 - inset / 2, bottomY), { layerName: LAYERS.REBAR_BOTTOM.name });
    const segXs = distributeTicks(ox + inset, openX0 - inset, Math.min(mesh.bottom.countX, 4));
    const segPitch = segXs.length > 1 ? segXs[1] - segXs[0] : Infinity;
    for (const x of segXs) barDotDXF(dxf, x, bottomY, mesh.bottom.dia, segPitch, LAYERS.REBAR_BOTTOM.name);
  }
  if (rightSegLenMM > MIN_SEGMENT_FOR_BAR_LINE_MM) {
    dxf.addLine(point3d(openX1 + inset / 2, bottomY), point3d(ox + stripW - inset / 2, bottomY), { layerName: LAYERS.REBAR_BOTTOM.name });
    const segXs = distributeTicks(openX1 + inset, ox + stripW - inset, Math.min(mesh.bottom.countX, 4));
    const segPitch = segXs.length > 1 ? segXs[1] - segXs[0] : Infinity;
    for (const x of segXs) barDotDXF(dxf, x, bottomY, mesh.bottom.dia, segPitch, LAYERS.REBAR_BOTTOM.name);
  }

  // Opening void — full section height plus a small overshoot; plain
  // outline (see file header), ANNOTATION layer.
  closedRectDXF(dxf, openX0, oy - SECTION_VOID_OVERSHOOT_MM, opening.spanX, stripH + 2 * SECTION_VOID_OVERSHOOT_MM, LAYERS.ANNOTATION.name);

  // Trim bars parallel to Y sit exactly at this cut (the cut runs through
  // the opening's own true Y-center) — two dots at the void's two
  // boundaries, at the bottom steel line. Only 2 same-layer dots exist in
  // this view; their one real neighbor is each other, at the true
  // opening.spanX separation — no dual-axis or multi-group check needed
  // here (unlike the plan view above), since both sit at the same y and
  // this module carries only one mesh face (see bottomY's own comment).
  barDotDXF(dxf, openX0, bottomY, trimBars.parallelToY.dia, opening.spanX, LAYERS.OPENING_TRIM.name);
  barDotDXF(dxf, openX1, bottomY, trimBars.parallelToY.dia, opening.spanX, LAYERS.OPENING_TRIM.name);

  dimensionLineDXF(dxf, ox + stripW + MARGIN_MM * 0.5, oy, ox + stripW + MARGIN_MM * 0.5, oy + stripH, `${fmt0(thicknessMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, openX0, oy - MARGIN_MM * 0.6, openX1, oy - MARGIN_MM * 0.6, `${fmt0(opening.spanX)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + stripW / 2, oy + stripH + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION THROUGH OPENING', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: stripW, height: stripH };
}

export function renderSlabOpeningDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'slabOpening') {
    throw new DiagramError('BAD_PARAM', 'renderSlabOpeningDiagramDXF expects a geometry object from computeSlabOpeningDiagramGeometry() (type "slabOpening").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const planOrigin = { x: 0, y: 0 };
  const plan = renderPlanViewDXF(dxf, geometry, planOrigin, opts);

  const sectionOriginX = geometry.lengthMM + (opts.viewGapMM ?? VIEW_GAP_MM);
  const section = renderSectionViewDXF(dxf, geometry, { x: sectionOriginX, y: 0 }, opts);

  const overallWidth = (sectionOriginX + section.width) - planOrigin.x;
  dxfText(dxf, planOrigin.x + overallWidth / 2, plan.titleTopY + MARGIN_MM * 1.2, TITLE_HEIGHT_MM, `SLAB ${geometry.id} - OPENING REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
