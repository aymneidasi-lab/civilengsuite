// trapezoidalFootingDiagram.dxf.mjs
// DXF render path for the trapezoidal combined-footing schematic —
// parallel to, and entirely separate from,
// renderTrapezoidalFootingDiagramSVG() in trapezoidalFootingDiagram.mjs.
// Same placement rationale as every sibling *.dxf.mjs: an ordinary
// /diagram or /rebar SVG request must never pull @tarikjabiri/dxf into
// the Worker's module graph — only a real DXF-export request does.
//
// computeTrapezoidalFootingGeometry() is consumed exactly as returned —
// zero modification to trapezoidalFootingDiagram.mjs, zero re-derivation
// of any value it already provides (b1MM/b2MM, chosenLocalWidthMM, each
// mesh row's own drawnLengthMM, each longitudinal bar's own
// offsetFromCenterMM — all read directly, never recomputed via the
// local, unexported computeLocalWidthMM() helper that file keeps
// private).
//
// v1 scope exclusions (same category every sibling *.dxf.mjs already
// carries): no Arabic labels (English only, hardcoded, not opts.lang-
// driven), no HATCH (soil band omitted entirely — the SVG source's own
// soil rect carries no assigned layer in the master prompt's layer
// table either, same "don't invent an unlisted layer" precedent
// footingDiagram.dxf.mjs's own header already documents), no
// scheduleTable-as-DXF-TABLE (the SVG source's own T1/L1 schedule rows
// have no on-sheet text equivalent here — the bars themselves are still
// drawn at their real, collision-checked positions).
//
// New-for-this-element decisions, disclosed per the master prompt's own
// protocol (none contradict its already-decided layer table — every
// layer used below is an already-listed, already-color-assigned entry;
// no new LAYERS entry was needed):
//   - REBAR-BOTTOM carries every rebar element this file draws
//     (transverse rows + longitudinal bars in plan, the transverse
//     representative line + longitudinal bar-cross-section dots in
//     section) — verified against trapezoidalFootingDiagram.mjs's own
//     CSS, not assumed: its single `.mesh-line { stroke:#c0392b; ... }`
//     rule covers both bar families with one class, and #c0392b is
//     REBAR-BOTTOM's own hex. This element has no REBAR-TOP usage
//     anywhere, matching footingDiagram.dxf.mjs's own identical finding
//     for its sibling footing types.
//   - view-title (PLAN/SECTION), col-tag (COLUMN 1/COLUMN 2), cut-line/
//     cut-label, rebar-note -> ANNOTATION. Every one of these class names
//     is already an ANNOTATION-layer precedent set by footingDiagram
//     .dxf.mjs for the identical role in a sibling footing type; not a
//     fresh assignment.
//   - Section-view longitudinal-bar dots: the SVG source's own
//     renderSectionView draws only ONE line for the transverse bar
//     family and never visualizes mesh.longitudinal.bars at all (a
//     schematic simplification, not a scope exclusion — the compute
//     function already returns each longitudinal bar's real
//     offsetFromCenterMM). This file draws them as real, collision-
//     checked barDotDXF circles alongside the representative transverse
//     line, at the same barY the transverse line uses (this element's
//     compute output has no second, separately-derived height for a
//     "longitudinal mat" — inventing one would be adding a number
//     geometry never gave; co-locating both families on the one real
//     height the SVG source computes is the enrichment precedent
//     footingDiagram.dxf.mjs's own section view already set: draw every
//     family geometry actually positions, using barDotDXF for genuine
//     per-bar collision safety, rather than mirroring the SVG's single
//     representative line literally). Matches the master prompt's own
//     rule 6 (test must include a real geometric no-overlap check, not a
//     visual-only one) — this is the only place in this element with any
//     circle to check; the plan view draws every bar family as lines
//     only, matching footingDiagram.dxf.mjs's own identical plan-view
//     convention (crossing lines, no dots, for a mesh grid).
//   - Dashed section-cut marker (plan view): the SVG source's shared
//     kitStyleBlock() genuinely styles `.cut-line` with
//     stroke-dasharray:6,3 (verified directly in
//     structuralDrawingKit.mjs, not assumed) — DASHED_LTYPE_NAME /
//     defineDashedLType(), added to structuralDrawingDxfKit.mjs this
//     session (see that file's own header comment on the addition), is
//     used here. Everything else in this file is a solid LINE/
//     LWPOLYLINE/CIRCLE, per the kit's own stated hard constraint.
//
// Real-mm view-local axes (neither is a literal carry-over of any
// sibling's own convention, chosen fresh for this element's own shape):
//   Plan view: origin (px,py) = the plan bounding box's own bottom-left
//   corner; centerY = py + maxB/2 is the footing's actual longitudinal
//   centerline (a FIXED line derived from the box, not from either end's
//   own half-width) — same anti-pattern avoidance
//   trapezoidalFootingDiagram.mjs's own render header already documents
//   for its SVG version ("centered on a FIXED horizontal midline ...
//   anchoring from the box's own fixed center sidesteps [the Y-anchoring
//   bug class] entirely"), carried over here for the identical reason.
//   Section view: origin (sox,soy) = the section rectangle's own
//   bottom-left corner, soy+thicknessMM = top — same "soy = the physical
//   bottom face" convention footingDiagram.dxf.mjs's own header already
//   establishes for this footing family.

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
  dimensionLineDXF,
  minPairwiseDistanceMM,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Layout conventions — none of these come from geometry; each is a
// chosen default for real-mm placement the SVG path never needed (fixed
// pixel canvas instead). All named so they're auditable, matching every
// sibling *.dxf.mjs's own convention. Values reused verbatim from
// footingDiagram.dxf.mjs wherever this element's layout role is
// identical to that file's own — noted per constant below — rather than
// re-deriving a fresh number for no reason.
const MARGIN_MM = 300; // same role/value as every sibling file's own MARGIN_MM
const VIEW_GAP_MM = 1000; // same role/value as footingDiagram.dxf.mjs's own (section below, plan above — see module header)
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view titles, column tags, cut labels
const DIM_TEXT_HEIGHT_MM = 150;
const CAPTION_HEIGHT_MM = 115;
const LABEL_STACK_GAP_MM = 130; // vertical gap between the stacked cover/bar-spec text lines in the section view — same value/role footingDiagram.dxf.mjs already established for its own identical two-line stack
const COLUMN_TAG_GAP_MM = 60; // gap from a column's own centerline-facing edge to its tag label — same value/role footingDiagram.dxf.mjs already established for its own column tags
const CUT_LINE_OVERHANG_MM = 150; // how far the section-cut marker extends past the plan bounding box's top/bottom — same value footingDiagram.dxf.mjs already established
const CUT_LABEL_GAP_MM = 70; // gap from the cut-line's overhung end to its lettered label — same value footingDiagram.dxf.mjs already established
const B_DIM_OVERHANG_MM = 60; // B1/B2 vertical dimension lines extend this far past the trapezoid's own edge at each end — real-mm analogue of the SVG source's own fixed 22px overhang (dimensionLine(..., yAt(0,-1)-22, ..., yAt(0,1)+22, ...))

const CAPTION_EN = 'Schematic for reference only, not a construction/shop drawing. Shows one representative bottom mesh layer only \u2014 no top steel, no dowels, no pedestal. Transverse bar lengths vary along the footing; see the plan view for each row\u2019s actual drawn length.';

function fmt0(mm) {
  return String(Math.round(mm));
}

function columnTagEN(n) {
  return `COLUMN ${n}`; // this element only ever has exactly two columns (col1/col2 in the input contract) — no lettered/numbered-by-count branching a footingDiagram-style multi-column type needs
}

// Draws the top-down view: the trapezoid outline (a genuine 4-vertex
// polygon, not a rectangle — closedPolylineDXF, not closedRectDXF),
// every transverse row + every longitudinal bar as real-length lines
// (each length/position taken directly from geometry, zero render-time
// inset math — the compute function already applies the cover+half-dia
// envelope to every value used here), both columns, a lettered
// section-cut marker through the chosen column, and the B1/B2/L overall
// dimension lines. origin = (px, py) is the plan bounding box's own
// bottom-left corner (see module header for the centerY convention).
function renderPlanViewDXF(dxf, geometry, origin, opts) {
  const {
    b1MM, b2MM, lengthMM, col1, col2, mesh, sectionThrough,
  } = geometry;
  const { x: px, y: py } = origin;
  const maxB = Math.max(b1MM, b2MM);
  const centerY = py + maxB / 2;

  const points = [
    { x: px, y: centerY - b1MM / 2 },
    { x: px, y: centerY + b1MM / 2 },
    { x: px + lengthMM, y: centerY + b2MM / 2 },
    { x: px + lengthMM, y: centerY - b2MM / 2 },
  ];
  closedPolylineDXF(dxf, points, LAYERS.CONCRETE_OUTLINE.name);

  for (const row of mesh.transverse.rows) {
    const x = px + row.xMM;
    const half = row.drawnLengthMM / 2;
    dxf.addLine(point3d(x, centerY - half), point3d(x, centerY + half), { layerName: LAYERS.REBAR_BOTTOM.name });
  }
  for (const bar of mesh.longitudinal.bars) {
    const y = centerY + bar.offsetFromCenterMM;
    dxf.addLine(point3d(px + mesh.longitudinal.startMM, y), point3d(px + mesh.longitudinal.endMM, y), { layerName: LAYERS.REBAR_BOTTOM.name });
  }

  [[col1, 1], [col2, 2]].forEach(([col, n]) => {
    const cx = px + col.offsetMM;
    const cw = col.depthMM, ch = col.widthMM;
    closedRectDXF(dxf, cx - cw / 2, centerY - ch / 2, cw, ch, LAYERS.CONCRETE_OUTLINE.name);
    dxfText(dxf, cx, centerY - ch / 2 - COLUMN_TAG_GAP_MM, SUBTITLE_HEIGHT_MM, columnTagEN(n), {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
    });
  });

  {
    const chosenCol = sectionThrough === 2 ? col2 : col1;
    const cx = px + chosenCol.offsetMM;
    const yLo = centerY - maxB / 2 - CUT_LINE_OVERHANG_MM;
    const yHi = centerY + maxB / 2 + CUT_LINE_OVERHANG_MM;
    dxf.addLine(point3d(cx, yLo), point3d(cx, yHi), { layerName: LAYERS.ANNOTATION.name, lineType: DASHED_LTYPE_NAME });
    dxfText(dxf, cx, yLo - CUT_LABEL_GAP_MM, SUBTITLE_HEIGHT_MM, 'A', { layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top });
    dxfText(dxf, cx, yHi + CUT_LABEL_GAP_MM, SUBTITLE_HEIGHT_MM, 'A', { layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom });
  }

  dimensionLineDXF(dxf, px, centerY - b1MM / 2 - B_DIM_OVERHANG_MM, px, centerY + b1MM / 2 + B_DIM_OVERHANG_MM, `B1=${fmt0(b1MM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, px + lengthMM, centerY - b2MM / 2 - B_DIM_OVERHANG_MM, px + lengthMM, centerY + b2MM / 2 + B_DIM_OVERHANG_MM, `B2=${fmt0(b2MM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, px, centerY + maxB / 2 + MARGIN_MM * 0.7, px + lengthMM, centerY + maxB / 2 + MARGIN_MM * 0.7, `L=${fmt0(lengthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  const titleY = centerY - maxB / 2 - CUT_LINE_OVERHANG_MM - CUT_LABEL_GAP_MM - SUBTITLE_HEIGHT_MM * 1.2; // below the cut-line's own lowest label, so PLAN never overlaps it
  dxfText(dxf, px + lengthMM / 2, titleY, SUBTITLE_HEIGHT_MM, 'PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return { width: lengthMM, height: maxB, top: centerY + maxB / 2, bottom: titleY };
}

// Draws the vertical cut through the chosen column: the local footing
// cross-section (width = chosenLocalWidthMM, thickness = thicknessMM),
// one representative line for the transverse bar family (matching the
// SVG source's own single-line convention exactly), and — new in this
// file, see module header — one collision-checked barDotDXF circle per
// longitudinal bar at its own real offsetFromCenterMM, sharing the same
// barY the representative line uses. origin = (sox, soy) is the section
// rectangle's own BOTTOM-LEFT corner (soy = the footing's physical
// bottom/soil-facing face, soy+thicknessMM = top — see module header).
function renderSectionViewDXF(dxf, geometry, origin, opts) {
  const { thicknessMM, chosenLocalWidthMM, coverMM, mesh } = geometry;
  const { x: sox, y: soy } = origin;
  const w = chosenLocalWidthMM;

  closedRectDXF(dxf, sox, soy, w, thicknessMM, LAYERS.CONCRETE_OUTLINE.name);

  // barY per the SVG source's own formula (renderSectionView: `sy + h -
  // coverMM*scale - mesh.transverse.dia*scale/2`, i.e. the bar center
  // sits (cover + half the transverse bar's own diameter) above the
  // footing's physical bottom face) — translated directly to this file's
  // soy-is-the-bottom-face convention, not re-derived.
  const barY = soy + coverMM + mesh.transverse.dia / 2;
  const midX = sox + w / 2;

  dxf.addLine(point3d(sox, barY), point3d(sox + w, barY), { layerName: LAYERS.REBAR_BOTTOM.name });

  const longDots = mesh.longitudinal.bars.map((bar) => ({ x: midX + bar.offsetFromCenterMM, y: barY, diaMM: mesh.longitudinal.dia }));
  const pitch = minPairwiseDistanceMM(longDots);
  for (const d of longDots) {
    barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_BOTTOM.name);
  }

  dimensionLineDXF(dxf, sox + w + MARGIN_MM * 0.5, soy, sox + w + MARGIN_MM * 0.5, soy + thicknessMM, `${fmt0(thicknessMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, sox, soy - MARGIN_MM * 0.6, sox + w, soy - MARGIN_MM * 0.6, `${fmt0(w)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, midX, barY + LABEL_STACK_GAP_MM, DIM_TEXT_HEIGHT_MM, `cover = ${fmt0(coverMM)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });
  dxfText(dxf, midX, barY + LABEL_STACK_GAP_MM * 2, DIM_TEXT_HEIGHT_MM, `T:\u00d8${fmt0(mesh.transverse.dia)}@${fmt0(mesh.transverse.spacing)}  L:\u00d8${fmt0(mesh.longitudinal.dia)}@${fmt0(mesh.longitudinal.spacing)}`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  dxfText(dxf, midX, soy - MARGIN_MM * 1.3, SUBTITLE_HEIGHT_MM, 'SECTION A-A', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return { width: w, height: thicknessMM };
}

export function renderTrapezoidalFootingDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'trapezoidal') {
    throw new DiagramError('BAD_PARAM', 'renderTrapezoidalFootingDiagramDXF expects a geometry object from computeTrapezoidalFootingGeometry() (type "trapezoidal").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  // MUST precede defineDxfLayers()/any entity referencing
  // DASHED_LTYPE_NAME — see structuralDrawingDxfKit.mjs's own header on
  // DxfLayerTable.addLayer()'s silent-Continuous-fallback behavior for
  // an unregistered linetype name (entities themselves have no such
  // fallback, but the table entry must still exist for the reference to
  // resolve to a real linetype rather than a dangling name).
  defineDashedLType(dxf);
  defineDxfLayers(dxf);

  // Section at the origin, plan stacked above it — same stacking choice
  // and same rationale footingDiagram.dxf.mjs already made for this
  // footing family (a trapezoidal plan can run to several meters along
  // its length while the section's own local width is typically much
  // smaller; stacking avoids one view's large horizontal extent
  // competing for column alignment with the other's).
  const sectionOrigin = { x: 0, y: 0 };
  const section = renderSectionViewDXF(dxf, geometry, sectionOrigin, opts);

  const planOrigin = { x: 0, y: sectionOrigin.y + section.height + (opts.viewGapMM ?? VIEW_GAP_MM) };
  const plan = renderPlanViewDXF(dxf, geometry, planOrigin, opts);

  const overallWidth = Math.max(plan.width, section.width);
  const titleY = plan.top + MARGIN_MM * 2.2;
  dxfText(dxf, overallWidth / 2, titleY, TITLE_HEIGHT_MM, `TRAPEZOIDAL FOOTING ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  const captionY = sectionOrigin.y - MARGIN_MM * 2.4;
  dxfText(dxf, overallWidth / 2, captionY, CAPTION_HEIGHT_MM, CAPTION_EN, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return dxf.stringify();
}
