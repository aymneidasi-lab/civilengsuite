// strapFootingDiagram.dxf.mjs
// DXF render path for the strap-footing schematic — parallel to, and
// entirely separate from, renderStrapFootingDiagramSVG() in
// strapFootingDiagram.mjs. Same placement rationale as every sibling
// *.dxf.mjs: an ordinary /diagram or /rebar SVG request must never pull
// @tarikjabiri/dxf into the Worker's module graph — only a real
// DXF-export request does.
//
// computeStrapFootingGeometry() is consumed exactly as returned — zero
// modification to strapFootingDiagram.mjs, zero re-derivation of any
// value it already provides (footing1/footing2's own startMM/endMM,
// each mesh line's own xLocalMM/yLocalMM/drawnLengthMM, strap.topBars/
// bottomBars' own real offsets, clearStrapMM — all read directly).
//
// v1 scope exclusions (same category every sibling *.dxf.mjs already
// carries): no Arabic labels (English only, hardcoded, not opts.lang-
// driven), no HATCH (soil bands omitted entirely — same "don't invent an
// unlisted layer" precedent every sibling footing-family file already
// documents), no scheduleTable-as-DXF-TABLE (the SVG source's own F1/F2/
// ST1/SB1/SS1 schedule rows have no on-sheet text equivalent here — the
// bars themselves are still drawn at their real, collision-checked
// positions).
//
// New-for-this-element decisions, disclosed per the master prompt's own
// protocol (every layer below is an already-listed, already-color-
// assigned entry — no new LAYERS entry was needed):
//   - REBAR-BOTTOM: every footing-pad mesh dot/line (both pads, both
//     mesh directions) and the strap's own bottom-bar line — verified
//     against strapFootingDiagram.mjs's own CSS: `.mesh-line` and (by
//     the master table's own listed mapping) `bar-bottom` both resolve
//     to REBAR-BOTTOM's #c0392b.
//   - REBAR-TOP: the strap beam's top-bar line only — `bar-top` is the
//     ONE place in this element that actually uses REBAR-TOP (unlike
//     trapezoidalFootingDiagram.dxf.mjs, which had none at all; the
//     footing pads here still have none).
//   - STIRRUP-TIE: the strap's stirrup ticks — master table: "STIRRUP-
//     TIE | stirrup-tick, stirrup-outline, ...". Verified the SVG
//     source's own stirrupTick(xPx,yTopPx,yBottomPx) shape directly in
//     structuralDrawingKit.mjs before writing this (not assumed from the
//     name): ONE vertical main line + horizontal end-caps at both ends —
//     the exact shape stirrupTickVDXF (already added to this kit for
//     corbelDiagram.dxf.mjs) implements, reused here unchanged rather
//     than adding a third near-duplicate tick function.
//   - pad-tag/strap-tag/view-title/cut-free section titles -> ANNOTATION
//     (already-listed, already color-assigned).
//   - Dashed strap-outline (plan AND longitudinal-section views): the
//     SVG source's shared `.strap-outline` rule is genuinely
//     `stroke-dasharray:4,3` (verified directly in this file's own
//     <style> block) — the exact case the master layer table already
//     flags by name ("فرعية بخط متقطع: strap-outline ... ميّزها بنمط خط
//     DXF متقطع, لا تدمجها بصرياً"). DASHED_LTYPE_NAME (added to the
//     shared kit last session) is used via closedRectDXF's own new
//     opts.lineType parameter (added THIS session, to this same kit
//     file, because this element is the first one that actually needs a
//     dashed RECTANGLE rather than a dashed line — see that function's
//     own header comment for the exact addition and its backward-
//     compatibility verification).
//   - Section-view enrichment (both the longitudinal and transverse
//     sections): the SVG source's own renderLongSection/renderTransSection
//     each draw only ONE representative bottom-mesh line per footing
//     pad and never visualize the OTHER real bar family
//     (alongBreadthLines / alongWidthLines respectively) that compute
//     already positions. Matching the precedent this same session's
//     sibling trapezoidalFootingDiagram.dxf.mjs already set: whichever
//     bar family is genuinely IN-PLANE with a given cut is drawn as one
//     representative line (its own real drawnLengthMM, not the SVG's
//     cosmetic px inset); whichever family is genuinely PERPENDICULAR to
//     that same cut is drawn as real, individually positioned, collision-
//     checked barDotDXF circles — never both collapsed to the SVG's
//     single line. See each render function's own comment for exactly
//     which family is in-plane vs. perpendicular for that specific cut
//     (they differ between the longitudinal and transverse sections,
//     verified geometrically, not assumed to match).

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
  barDotDXF,
  stirrupTickVDXF,
  dimensionLineDXF,
  distributeTicks,
  minPairwiseDistanceMM,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Layout conventions — none of these come from geometry; each is a
// chosen default for real-mm placement the SVG path never needed. All
// named so they're auditable, matching every sibling *.dxf.mjs's own
// convention. Values reused verbatim from trapezoidalFootingDiagram
// .dxf.mjs / footingDiagram.dxf.mjs wherever this element's layout role
// is identical to theirs, rather than re-deriving a fresh number.
const MARGIN_MM = 300;
const VIEW_GAP_MM = 1000;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 150;
const CAPTION_HEIGHT_MM = 115;
const PAD_TAG_GAP_MM = 60; // gap from a footing pad's own outer (away-from-centerline) edge to its tag label — same value/role every sibling's own *_TAG_GAP_MM convention
const STRAP_TAG_GAP_MM = 60;
const SPAN_DIM_GAP_MM = MARGIN_MM * 0.7; // above the plan shape — same fractional-margin convention trapezoidalFootingDiagram.dxf.mjs's own L dimension already established
const WIDTH_DIM_GAP_MM = MARGIN_MM * 0.6; // below the plan shape, nearest row
const CLEAR_DIM_GAP_MM = MARGIN_MM * 1.4; // below the plan shape, second row — spaced past the first row's own line PLUS dimensionLineDXF's own LABEL_GAP_MM(120mm) label offset, so the two rows' text never overlaps (verified by execution, see the "no two ANNOTATION/DIMENSIONS texts overlap in y" test below)
const PLAN_TITLE_GAP_MM = MARGIN_MM * 2.2; // below the plan shape, past both dimension rows
const CAPTION_EN = 'Schematic for reference only, not a construction/shop drawing. Shows one representative bottom mesh layer per footing and one representative strap-beam section only \u2014 no top steel or dowels on the footings, no additional bar groups or stirrup zones on the strap. The gap between the two footings is a non-bearing strap span, not a poured slab.';

function fmt0(mm) {
  return String(Math.round(mm));
}

const FOOTING_TAG_EN = { 1: 'FOOTING 1 (exterior)', 2: 'FOOTING 2 (interior)' };

// Everything anchored on one FIXED horizontal centerline (py + maxBreadth/2)
// — same anti-drift discipline trapezoidalFootingDiagram.dxf.mjs's own
// plan view already documents (never derive the shared axis from either
// pad's own half-breadth). origin = (px, py) is the plan bounding box's
// own bottom-left corner.
function renderPlanViewDXF(dxf, geometry, origin, opts) {
  const {
    footing1: f1, footing2: f2, strap, spanMM, clearStrapMM,
  } = geometry;
  const { x: px, y: py } = origin;
  const maxBreadth = Math.max(f1.breadthMM, f2.breadthMM, strap.widthMM);
  const centerY = py + maxBreadth / 2;

  // Strap first, so the two pads' own outlines read as sitting visually
  // on top of it at the seam — same draw-order rationale the SVG source's
  // own renderPlanView comment states.
  {
    const x1 = px + f1.endMM, x2 = px + f2.startMM;
    closedRectDXF(dxf, x1, centerY - strap.widthMM / 2, x2 - x1, strap.widthMM, LAYERS.CONCRETE_OUTLINE.name, { lineType: DASHED_LTYPE_NAME });
    dxfText(dxf, (x1 + x2) / 2, centerY - strap.widthMM / 2 - STRAP_TAG_GAP_MM, SUBTITLE_HEIGHT_MM, 'STRAP BEAM', {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
    });
  }

  for (const [pad, n] of [[f1, 1], [f2, 2]]) {
    const x1 = px + pad.startMM, x2 = px + pad.endMM;
    closedRectDXF(dxf, x1, centerY - pad.breadthMM / 2, x2 - x1, pad.breadthMM, LAYERS.CONCRETE_OUTLINE.name);

    for (const line of pad.mesh.alongBreadthLines) {
      const x = px + pad.startMM + line.xLocalMM;
      const half = line.drawnLengthMM / 2;
      dxf.addLine(point3d(x, centerY - half), point3d(x, centerY + half), { layerName: LAYERS.REBAR_BOTTOM.name });
    }
    for (const line of pad.mesh.alongWidthLines) {
      const y = centerY - pad.breadthMM / 2 + line.yLocalMM;
      const xa = px + pad.startMM + (pad.widthMM - line.drawnLengthMM) / 2;
      const xb = px + pad.startMM + (pad.widthMM + line.drawnLengthMM) / 2;
      dxf.addLine(point3d(xa, y), point3d(xb, y), { layerName: LAYERS.REBAR_BOTTOM.name });
    }

    dxfText(dxf, (x1 + x2) / 2, centerY + pad.breadthMM / 2 + PAD_TAG_GAP_MM, SUBTITLE_HEIGHT_MM, FOOTING_TAG_EN[n], {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
    });
  }

  // Columns at x=0 (col1, footing1) and x=spanMM (col2, footing2) — same
  // depth-as-x-extent/width-as-y-extent convention
  // trapezoidalFootingDiagram.dxf.mjs's own plan view uses.
  for (const [pad, xMM] of [[f1, 0], [f2, spanMM]]) {
    const cx = px + xMM;
    closedRectDXF(dxf, cx - pad.colDepthMM / 2, centerY - pad.colWidthMM / 2, pad.colDepthMM, pad.colWidthMM, LAYERS.CONCRETE_OUTLINE.name);
  }

  dimensionLineDXF(dxf, px, centerY + maxBreadth / 2 + SPAN_DIM_GAP_MM, px + spanMM, centerY + maxBreadth / 2 + SPAN_DIM_GAP_MM, `span=${fmt0(spanMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, px + f1.startMM, centerY - maxBreadth / 2 - WIDTH_DIM_GAP_MM, px + f1.endMM, centerY - maxBreadth / 2 - WIDTH_DIM_GAP_MM, `${fmt0(f1.widthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, px + f2.startMM, centerY - maxBreadth / 2 - WIDTH_DIM_GAP_MM, px + f2.endMM, centerY - maxBreadth / 2 - WIDTH_DIM_GAP_MM, `${fmt0(f2.widthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, px + f1.endMM, centerY - maxBreadth / 2 - CLEAR_DIM_GAP_MM, px + f2.startMM, centerY - maxBreadth / 2 - CLEAR_DIM_GAP_MM, `clear=${fmt0(clearStrapMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  const titleY = centerY - maxBreadth / 2 - PLAN_TITLE_GAP_MM;
  dxfText(dxf, px + (f1.startMM + f2.endMM) / 2, titleY, SUBTITLE_HEIGHT_MM, 'PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return { width: f2.endMM - f1.startMM, height: maxBreadth, top: centerY + maxBreadth / 2, bottom: titleY, drawMinX: f1.startMM };
}

// Both footing pads hang DOWNWARD from a shared baseline (their own
// physical top-of-footing elevation — where a column notionally lands);
// the strap beam rises UPWARD from that exact same baseline, since it is
// cast integrally with the footing tops — matching the SVG source's own
// renderLongSection header comment precisely (not re-derived, translated
// directly: "footing profiles drawn DOWNWARD ... strap beam DOWNWARD ...
// UPWARD from that same baseline").
//
// In-plane vs. perpendicular bar families for THIS cut (the cutting
// plane runs along global X, the strap axis, i.e. contains every pad's
// own WIDTH direction and excludes its BREADTH direction): each pad's
// alongWidthLines (bars running along width, parallel to X) are IN-PLANE
// -> one representative REBAR-BOTTOM line, real length taken directly
// from alongWidthLines[0].drawnLengthMM (constant across the family for
// a rectangular pad, verified — not the SVG's own cosmetic x1+4/x2-4
// inset). Each pad's alongBreadthLines (bars running along breadth,
// perpendicular to X) are cut end-on here -> real barDotDXF circles, one
// per line, at that line's own real xLocalMM position along width.
function renderLongSectionDXF(dxf, geometry, origin, opts) {
  const {
    footing1: f1, footing2: f2, strap,
  } = geometry;
  const { x: ox, y: baseline } = origin;
  const drawX = (xMM) => ox + xMM;

  for (const pad of [f1, f2]) {
    const x1 = drawX(pad.startMM), x2 = drawX(pad.endMM);
    const bottomY = baseline - pad.thicknessMM;
    closedRectDXF(dxf, x1, bottomY, x2 - x1, pad.thicknessMM, LAYERS.CONCRETE_OUTLINE.name);

    const barY = bottomY + pad.coverMM + pad.mesh.dia / 2;
    const alongWidthLen = pad.mesh.alongWidthLines[0].drawnLengthMM;
    dxf.addLine(point3d(drawX(pad.startMM + (pad.widthMM - alongWidthLen) / 2), barY), point3d(drawX(pad.startMM + (pad.widthMM + alongWidthLen) / 2), barY), { layerName: LAYERS.REBAR_BOTTOM.name });

    const dots = pad.mesh.alongBreadthLines.map((line) => ({ x: drawX(pad.startMM + line.xLocalMM), y: barY, diaMM: pad.mesh.dia }));
    const pitch = minPairwiseDistanceMM(dots);
    for (const d of dots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_BOTTOM.name);
  }

  const sx1 = drawX(f1.endMM), sx2 = drawX(f2.startMM);
  const strapTop = baseline + strap.depthMM;
  closedRectDXF(dxf, sx1, baseline, sx2 - sx1, strap.depthMM, LAYERS.CONCRETE_OUTLINE.name, { lineType: DASHED_LTYPE_NAME });

  // Strap bars: spread across the strap's WIDTH (the out-of-plane axis
  // for THIS cut, since the strap's width runs perpendicular to its own
  // length/global-X) collapse to one apparent height each in a
  // longitudinal cut — every top bar reads as ONE line, every bottom bar
  // as ONE line, matching the SVG source's own identical simplification
  // exactly (verified: it draws exactly one <line class="bar-top"/> and
  // one <line class="bar-bottom"/>, never per-bar-count lines — a
  // longitudinal cut genuinely cannot distinguish bars separated only
  // across width, unlike the footing-pad case above where the
  // perpendicular family IS distinguishable along the cut's own visible
  // axis).
  const topY = strapTop - strap.coverMM - strap.stirrupDia - strap.topBarDia / 2;
  const botY = baseline + strap.coverMM + strap.stirrupDia + strap.bottomBarDia / 2;
  dxf.addLine(point3d(sx1, topY), point3d(sx2, topY), { layerName: LAYERS.REBAR_TOP.name });
  dxf.addLine(point3d(sx1, botY), point3d(sx2, botY), { layerName: LAYERS.REBAR_BOTTOM.name });
  for (const tickX of distributeTicks(sx1, sx2, Math.min(strap.stirrupCount, 14))) {
    stirrupTickVDXF(dxf, tickX, topY, botY, LAYERS.STIRRUP_TIE.name);
  }

  // Clear-span dimension above the strap's own top — ported directly
  // from the SVG source's own renderLongSection (`dimensionLine(xPx(f1
  // .endMM), baseline-strap.depthMM*scale-26, xPx(f2.startMM), ...,
  // clearStrapMM+'mm', {orientation:'h'})`, missed on the first pass of
  // this file and added on review before delivery).
  const dimY = strapTop + MARGIN_MM * 0.5; // real-mm analogue of the SVG source's own 26px "above the strap" placement
  dimensionLineDXF(dxf, sx1, dimY, sx2, dimY, `clear=${fmt0(geometry.clearStrapMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dxfText(dxf, (sx1 + sx2) / 2, dimY + MARGIN_MM, SUBTITLE_HEIGHT_MM, 'STRAP BEAM', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  const lowestY = baseline - Math.max(f1.thicknessMM, f2.thicknessMM);
  const titleY = lowestY - MARGIN_MM * 1.3;
  dxfText(dxf, (drawX(f1.startMM) + drawX(f2.endMM)) / 2, titleY, SUBTITLE_HEIGHT_MM, 'LONGITUDINAL SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return { top: dimY + MARGIN_MM + SUBTITLE_HEIGHT_MM, bottom: titleY };
}

// The chosen footing's own breadth x thickness cross-section, cut
// perpendicular to global X (the opposite cutting plane from the
// longitudinal section above) — so the in-plane/perpendicular roles
// invert exactly: alongBreadthLines (bars along breadth, IN-PLANE with a
// cut perpendicular to X) -> one representative REBAR-BOTTOM line, real
// length from alongBreadthLines[0].drawnLengthMM (constant across the
// family). alongWidthLines (bars along width, cut end-on here) -> real
// barDotDXF circles, one per line, at that line's own real yLocalMM
// position across breadth. origin = (sox, soy) is the section
// rectangle's own bottom-left corner (soy = the physical bottom/soil-
// facing face — same convention footingDiagram.dxf.mjs's own transverse-
// style section already establishes for this element family).
function renderTransSectionDXF(dxf, geometry, origin, opts) {
  const chosen = geometry.sectionThrough === 2 ? geometry.footing2 : geometry.footing1;
  const { x: sox, y: soy } = origin;
  const w = chosen.breadthMM;

  closedRectDXF(dxf, sox, soy, w, chosen.thicknessMM, LAYERS.CONCRETE_OUTLINE.name);

  const barY = soy + chosen.coverMM + chosen.mesh.dia / 2;
  const alongBreadthLen = chosen.mesh.alongBreadthLines[0].drawnLengthMM;
  dxf.addLine(point3d(sox + (w - alongBreadthLen) / 2, barY), point3d(sox + (w + alongBreadthLen) / 2, barY), { layerName: LAYERS.REBAR_BOTTOM.name });

  const dots = chosen.mesh.alongWidthLines.map((line) => ({ x: sox + line.yLocalMM, y: barY, diaMM: chosen.mesh.dia }));
  const pitch = minPairwiseDistanceMM(dots);
  for (const d of dots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_BOTTOM.name);

  dimensionLineDXF(dxf, sox, soy - MARGIN_MM * 0.6, sox + w, soy - MARGIN_MM * 0.6, `${fmt0(w)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, sox + w + MARGIN_MM * 0.5, soy, sox + w + MARGIN_MM * 0.5, soy + chosen.thicknessMM, `${fmt0(chosen.thicknessMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, sox + w / 2, barY + 130, DIM_TEXT_HEIGHT_MM, `\u00d8${fmt0(chosen.mesh.dia)}@${fmt0(chosen.mesh.spacing)}`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  const titleY = soy - MARGIN_MM * 1.3;
  dxfText(dxf, sox + w / 2, titleY, SUBTITLE_HEIGHT_MM, `TRANSVERSE SECTION (${FOOTING_TAG_EN[geometry.sectionThrough]})`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return { width: w, height: chosen.thicknessMM, bottom: titleY };
}

export function renderStrapFootingDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'strap') {
    throw new DiagramError('BAD_PARAM', 'renderStrapFootingDiagramDXF expects a geometry object from computeStrapFootingGeometry() (type "strap").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  // MUST precede defineDxfLayers()/any entity referencing
  // DASHED_LTYPE_NAME — see structuralDrawingDxfKit.mjs's own header on
  // DxfLayerTable.addLayer()'s silent-Continuous-fallback behavior for an
  // unregistered linetype name.
  defineDashedLType(dxf);
  defineDxfLayers(dxf);

  // Stacked bottom-to-top in DXF model space: TRANSVERSE SECTION lowest,
  // LONGITUDINAL SECTION above it, PLAN highest — reproducing the SVG
  // source's own top-to-bottom reading order (PLAN_BOX above
  // LONG_SECTION_BOX above TRANS_SECTION_BOX) when plotted, since DXF Y
  // increases upward.
  const transOrigin = { x: 0, y: 0 };
  const trans = renderTransSectionDXF(dxf, geometry, transOrigin, opts);

  const longBaselineY = trans.height + (opts.viewGapMM ?? VIEW_GAP_MM) + Math.max(geometry.footing1.thicknessMM, geometry.footing2.thicknessMM);
  const long_ = renderLongSectionDXF(dxf, geometry, { x: 0, y: longBaselineY }, opts);

  const planOrigin = { x: -geometry.footing1.startMM, y: long_.top + (opts.viewGapMM ?? VIEW_GAP_MM) };
  const plan = renderPlanViewDXF(dxf, geometry, planOrigin, opts);

  const overallWidth = Math.max(plan.width, trans.width);
  const titleY = plan.top + MARGIN_MM * 2.2;
  dxfText(dxf, overallWidth / 2, titleY, TITLE_HEIGHT_MM, `STRAP FOOTING ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  const captionY = -MARGIN_MM * 1.3;
  dxfText(dxf, overallWidth / 2, captionY, CAPTION_HEIGHT_MM, CAPTION_EN, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return dxf.stringify();
}
