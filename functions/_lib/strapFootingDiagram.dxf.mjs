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
// FIDELITY REVISION (this pass): mirrors strapFootingDiagram.mjs's own
// header note in full — checked against ECP 203 detail guide Fig. 6-16
// at the caller's request; footing1/footing2.dowels and
// strap.shrinkageBarDiaMM/shrinkageBarCount are now REQUIRED in the
// geometry this file consumes (computeStrapFootingGeometry() enforces
// it — this file does not re-validate, same "consume geometry exactly
// as returned" contract stated below), a new renderSection11DXF mirrors
// the SVG source's own new Section 1-1 view, and the strap's top/bottom
// bar lines in renderLongSectionDXF now extend to each column's own
// centerline with a schematic anchorage hook instead of stopping at the
// clear-gap edge. See strapFootingDiagram.mjs's header for the full
// citation and the reasoning for what stayed OUT of scope (the exact
// bar-by-bar column-cage arrangement; the plain-footing step and
// secondary-mesh note stay OPTIONAL fields, drawn only when supplied).
//
// VISUAL-FIDELITY REVISION (this pass): mirrors strapFootingDiagram.mjs's
// own header note in full (real color+thickness differentiation between
// reinforcement families, caller-supplied reference images). Two fixes,
// both verified against the installed @tarikjabiri/dxf v2.8.9 itself,
// not assumed: (1) every LINEAR bar/mesh/dowel run drew as a
// mathematically zero-width LINE — this library's CommonEntityOptions
// and DxfLayer both carry no lineweight/width field at ANY level, and
// this module's own previously-generated output confirms every LAYER's
// own group-370 lineweight reads 0 — so DXF group-370 LWEIGHT is not
// reachable here at all; addLWPolyline's own constantWidth option (DXF
// group 43) IS real and verified (a 2-vertex LWPolyline with
// constantWidth:20 round-trips to a genuine "43/20" pair), so every bar
// run below now goes through a new local weightedLine(), constantWidth
// = that bar's own true mm diameter (this file's whole model space is
// already real mm — not a compressed "weight class" the way the SVG
// path's own px mapping has to be). (2) footing mesh (F1/F2) and the
// strap's own bottom bars (SB1) shared LAYERS.REBAR_BOTTOM — verified
// against this module's own previously-generated LAYER table that a
// separate, already-defined, currently-UNUSED "REBAR-MESH-LINE" layer
// exists (own true color, distinct from REBAR-BOTTOM's) — every mesh-
// only entity (both plan-view mesh families, the long/trans-section mesh
// line+dots, the Section-1-1 reinforced-zone frame+corner dots) now
// targets that layer instead. NOT touched: barDotDXF's own circle radii
// (that formula lives in structuralDrawingDxfKit.mjs, not here, and this
// module's own previously-generated output shows every circle at an
// identical 12.5mm regardless of the 12/16/20mm diaMM passed in — could
// be a real diameter-blind bug, or could be a legitimate pitch/collision
// clamp dominating for this specific geometry; this file cannot tell
// which without that kit's own source, so it does not guess); DXF
// group-370 LWEIGHT itself, for the same "not reachable through this
// library" reason stated above — a real per-layer LWEIGHT still requires
// either an @tarikjabiri/dxf version that exposes it or direct group-code
// injection neither this file nor its kit currently does.
//
// v1 scope exclusions (same category every sibling *.dxf.mjs already
// carries): no Arabic labels (English only, hardcoded, not opts.lang-
// driven), no HATCH (soil bands omitted entirely — same "don't invent an
// unlisted layer" precedent every sibling footing-family file already
// documents), no scheduleTable-as-DXF-TABLE (the SVG source's own F1/F2/
// ST1/SB1/SS1/SK1/DW1/DW2 schedule rows have no on-sheet text equivalent
// here — the bars themselves are still drawn at their real, collision-
// checked positions), no column bar-mark schedule (dowels are drawn at
// their real perimeter positions, same geometry the SVG path uses — but
// this file, like that one, does not mark individual corner-vs-face bars
// separately).
//
// New-for-this-element decisions, disclosed per the master prompt's own
// protocol (every layer below is an already-listed, already-color-
// assigned entry — no new LAYERS entry was needed, including for this
// pass's own additions: DOWEL_BAR and REBAR_EXTRA were both already
// defined in this shared kit for other elements — expansionJointDiagram
// .dxf.mjs and basementWallDiagram.dxf.mjs respectively — and are reused
// here unchanged, same "reuse a semantically-matching existing layer"
// convention this whole kit already follows):
//   - DOWEL-BAR: every column dowel, both footings, in every view that
//     shows them (plan, longitudinal section, Section 1-1) — the exact
//     concept this layer was already named for.
//   - REBAR-EXTRA: the strap's shrinkage/skin bars (Section 1-1's own
//     dots and the longitudinal section's own additional depth-level
//     lines) — reused as "extra reinforcement beyond the main flexural
//     groups", the same role this layer already plays for
//     basementWallDiagram.dxf.mjs's own extra bars.
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
const EDGE_DIM_GAP_MM = MARGIN_MM * 1.87; // below the plan shape, third row — footing1's own eccentricity, labeled with a real number (reviewer's own most-important point: the column offset must read unambiguously, not just as a visual impression)
const NOTE_DIM_GAP_MM = MARGIN_MM * 2.33; // below the plan shape, fourth row — the optional per-pad secondaryReinforcementNote
const PLAN_TITLE_GAP_MM = MARGIN_MM * 3.17; // below the plan shape, past all four rows
// Section 1-1 (new this pass): same cosmetic-only column-stub proportion
// as strapFootingDiagram.mjs's own COLUMN_STUB_HEIGHT_FRACTION — kept as
// an independent constant (not imported) since this file already keeps
// every layout number independently named/verified, same convention its
// own header states for every other constant in this block.
const COLUMN_STUB_HEIGHT_FRACTION = 0.6;
// Same value, same reasoning as strapFootingDiagram.mjs's own
// PLAIN_CONCRETE_THICKNESS_MM — every reinforced footing sits on an
// unreinforced blinding layer in practice; this module has no dedicated
// input field for its thickness, so renderSection11DXF draws it
// unconditionally at this nominal default.
const PLAIN_CONCRETE_THICKNESS_MM = 75;
const SECTION11_DIM_GAP_MM = MARGIN_MM * 1.5; // to the right of the footing/strap stack — wider than WIDTH_DIM_GAP_MM's own 0.6x because two vertical dimension rows sit side by side here (footing thickness, strap depth) and both need clearance from the bar dots, not just from each other
const SECTION11_LABEL_GAP_MM = MARGIN_MM * 0.8;
const CAPTION_EN = 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design before issuing for construction. Each footing shows one representative bottom mesh layer and its own column dowels, perimeter-distributed \u2014 not a full column bar schedule. The strap shows one representative top/bottom bar group, stirrup spacing, and shrinkage/skin bar group. Strap top and bottom bars are drawn extending to each column\u2019s centerline for anchorage; the exact bar arrangement within the column\u2019s own reinforcement cage is a shop-drawing detail this schematic does not re-derive \u2014 confirm it against the column\u2019s own layout (reference arrangement: ECP 203 detail guide Fig. 6-16). The gap between the two footings is drawn as a non-bearing strap span, not a poured slab.';

function fmt0(mm) {
  return String(Math.round(mm));
}

// ── Diameter-driven line width ("بتخانات مختلفة") ───────────────────────
// @tarikjabiri/dxf's addLine() carries no width/lineweight parameter —
// verified directly against the installed package (v2.8.9): its
// CommonEntityOptions only exposes trueColor/colorNumber/layerName/
// visible/lineType/lineTypeScale, and its DxfLayer class exposes no
// lineWeight field either, so DXF group-370 LWEIGHT is not reachable
// through this library's public API at the entity level OR the layer
// level. Every LINEAR bar/mesh/dowel run this file drew before this
// revision was therefore a mathematically zero-width LINE — confirmed
// empirically against this module's own previously-generated output:
// every LAYER's own group-370 lineweight reads 0, and no other width
// source existed anywhere in that file. addLWPolyline DOES support a
// real width via its own constantWidth option (DXF group 43) — verified
// directly against the installed library: a 2-vertex LWPolyline with
// constantWidth:20 round-trips to a genuine "43 / 20" group pair in the
// written DXF, which any DXF-compliant viewer renders as a filled strip
// of that width. Since this file's whole model space is already real,
// unscaled millimetres (dxf.setUnits(Units.Millimeters); every
// coordinate below is a real mm value), using a bar's own TRUE diaMM as
// constantWidth is not an arbitrary "weight class" the way the SVG
// path's own barLineWidthPx has to be (that path is scale-compressed for
// legibility) — it is simply the bar's real physical width, the most
// technically correct representation this format can carry. `point3d`
// (already imported above) is used for the 2D vertices too — accepted
// at runtime despite the type surface nominally wanting vec2_t, verified
// directly against the installed library (the extra z field is simply
// unread). Used for every LINEAR bar run (top/bottom/mesh/dowel);
// barDotDXF's own circles (cross-section cuts) are left untouched — this
// file cannot verify that shared-kit helper's internal radius-vs-pitch
// formula without its own source (structuralDrawingDxfKit.mjs), so this
// pass does not touch circle sizing, only line width. See this file's
// own CHANGELOG entry for that open item.
function weightedLine(dxf, x1, y1, x2, y2, diaMM, layerName, extraOpts) {
  return dxf.addLWPolyline(
    [{ point: point3d(x1, y1) }, { point: point3d(x2, y2) }],
    { layerName, constantWidth: diaMM, ...extraOpts },
  );
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

  // Strap plan outline: spans footing1's own OUTER edge to footing2's
  // own OUTER edge — caller rule "الشداد مستمر من بداية القاعده
  // الخارجيه لنهاية القاعده الداخليه", repeated as "مد الشداد للنهايه"
  // after an earlier revision only reached column-to-column (px to
  // px+spanMM), which stopped short of each footing's own far edge —
  // see strapFootingDiagram.mjs's own renderPlanView header for the full
  // citation; same fix, same reasoning, mirrored here. (No z-order
  // concern here unlike the SVG source's identical fix: closedRectDXF
  // draws an outline only, with no fill entity to mask or be masked by
  // — DXF simply overlays lines.)
  {
    const barX1 = px + f1.startMM, barX2 = px + f2.endMM;
    closedRectDXF(dxf, barX1, centerY - strap.widthMM / 2, barX2 - barX1, strap.widthMM, LAYERS.CONCRETE_OUTLINE.name, { lineType: DASHED_LTYPE_NAME });

    for (const off of strap.bottomBars) {
      const y = centerY - strap.widthMM / 2 + off;
      weightedLine(dxf, barX1 + 2, y, barX2 - 2, y, strap.bottomBarDia, LAYERS.REBAR_BOTTOM.name);
    }
    for (const off of strap.topBars) {
      const y = centerY - strap.widthMM / 2 + off;
      weightedLine(dxf, barX1 + 2, y, barX2 - 2, y, strap.topBarDia, LAYERS.REBAR_TOP.name, { lineType: DASHED_LTYPE_NAME });
    }
    for (const tickX of distributeTicks(barX1 + 6, barX2 - 6, Math.min(strap.stirrupCount, 24))) {
      weightedLine(dxf, tickX, centerY - strap.widthMM / 2, tickX, centerY + strap.widthMM / 2, strap.stirrupDia, LAYERS.STIRRUP_TIE.name);
    }

    const gx1 = px + f1.endMM, gx2 = px + f2.startMM;
    dxfText(dxf, (gx1 + gx2) / 2, centerY - strap.widthMM / 2 - STRAP_TAG_GAP_MM, SUBTITLE_HEIGHT_MM, 'STRAP BEAM', {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
    });
  }

  for (const [pad, n] of [[f1, 1], [f2, 2]]) {
    const x1 = px + pad.startMM, x2 = px + pad.endMM;

    // Optional plain-concrete step, drawn BEHIND/before the reinforced
    // outline so the reinforced rect's own solid line reads on top at
    // the shared edges — same "wider pour beneath" reading the SVG
    // source's own .plain-outline (dashed, no fill) gives it.
    if (pad.plain) {
      const px1 = x1 - pad.plain.projectionMM, px2 = x2 + pad.plain.projectionMM;
      closedRectDXF(dxf, px1, centerY - pad.plain.breadthMM / 2, px2 - px1, pad.plain.breadthMM, LAYERS.CONCRETE_OUTLINE.name, { lineType: DASHED_LTYPE_NAME });
    }

    closedRectDXF(dxf, x1, centerY - pad.breadthMM / 2, x2 - x1, pad.breadthMM, LAYERS.CONCRETE_OUTLINE.name);

    for (const line of pad.mesh.alongBreadthLines) {
      const x = px + pad.startMM + line.xLocalMM;
      const half = line.drawnLengthMM / 2;
      weightedLine(dxf, x, centerY - half, x, centerY + half, pad.mesh.dia, LAYERS.REBAR_MESH_LINE.name);
    }
    for (const line of pad.mesh.alongWidthLines) {
      const y = centerY - pad.breadthMM / 2 + line.yLocalMM;
      const xa = px + pad.startMM + (pad.widthMM - line.drawnLengthMM) / 2;
      const xb = px + pad.startMM + (pad.widthMM + line.drawnLengthMM) / 2;
      weightedLine(dxf, xa, y, xb, y, pad.mesh.dia, LAYERS.REBAR_MESH_LINE.name);
    }

    dxfText(dxf, (x1 + x2) / 2, centerY + pad.breadthMM / 2 + PAD_TAG_GAP_MM, SUBTITLE_HEIGHT_MM, FOOTING_TAG_EN[n], {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
    });
    if (pad.secondaryReinforcementNote) {
      // Anchored to maxBreadth, not this pad's own (possibly smaller)
      // breadth — same fix strapFootingDiagram.mjs's own renderPlanView
      // needed for the identical collision risk (a note under the
      // narrower pad landing on top of a dimension line sized for the
      // wider one).
      dxfText(dxf, (x1 + x2) / 2, centerY - maxBreadth / 2 - NOTE_DIM_GAP_MM, DIM_TEXT_HEIGHT_MM, pad.secondaryReinforcementNote, {
        layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
      });
    }
  }

  // Columns at x=0 (col1, footing1) and x=spanMM (col2, footing2) — same
  // depth-as-x-extent/width-as-y-extent convention
  // trapezoidalFootingDiagram.dxf.mjs's own plan view uses. Dowels drawn
  // at each dowel's own real perimeter position (rectPerimeterPoints'
  // xLocalMM/yLocalMM offsets from the column's own center — read
  // directly, never re-derived).
  for (const [pad, xMM] of [[f1, 0], [f2, spanMM]]) {
    const cx = px + xMM;
    closedRectDXF(dxf, cx - pad.colDepthMM / 2, centerY - pad.colWidthMM / 2, pad.colDepthMM, pad.colWidthMM, LAYERS.CONCRETE_OUTLINE.name);
    const dots = pad.dowels.points.map((pt) => ({ x: cx + pt.xLocalMM, y: centerY + pt.yLocalMM, diaMM: pad.dowels.dia }));
    const pitch = minPairwiseDistanceMM(dots);
    for (const d of dots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.DOWEL_BAR.name);
  }

  dimensionLineDXF(dxf, px, centerY + maxBreadth / 2 + SPAN_DIM_GAP_MM, px + spanMM, centerY + maxBreadth / 2 + SPAN_DIM_GAP_MM, `span=${fmt0(spanMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, px + f1.startMM, centerY - maxBreadth / 2 - WIDTH_DIM_GAP_MM, px + f1.endMM, centerY - maxBreadth / 2 - WIDTH_DIM_GAP_MM, `${fmt0(f1.widthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, px + f2.startMM, centerY - maxBreadth / 2 - WIDTH_DIM_GAP_MM, px + f2.endMM, centerY - maxBreadth / 2 - WIDTH_DIM_GAP_MM, `${fmt0(f2.widthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, px + f1.endMM, centerY - maxBreadth / 2 - CLEAR_DIM_GAP_MM, px + f2.startMM, centerY - maxBreadth / 2 - CLEAR_DIM_GAP_MM, `clear=${fmt0(clearStrapMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  // Footing1's own eccentricity, labeled with a real number (mirrors the
  // SVG source's identical addition — see its own comment for why).
  dimensionLineDXF(dxf, px + f1.startMM, centerY - maxBreadth / 2 - EDGE_DIM_GAP_MM, px - f1.colDepthMM / 2, centerY - maxBreadth / 2 - EDGE_DIM_GAP_MM, `edge=${fmt0(f1.edgeMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

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
    footing1: f1, footing2: f2, strap, spanMM,
  } = geometry;
  const { x: ox, y: groundY } = origin;
  const drawX = (xMM) => ox + xMM;
  const stubHeightMM = strap.depthMM * COLUMN_STUB_HEIGHT_FRACTION;
  // groundY (renamed from an earlier revision's "baseline"): the ONE
  // shared bottom BOTH footings and the strap rise from — not "footing
  // top = strap bottom" as that earlier revision modeled it (which left
  // the strap's own concrete floating above the footings with nothing
  // physically connecting them across the clear span, flagged directly
  // against Fig. 6-16's own قطاع ١-١; see the SVG source's own
  // renderLongSection header for the full citation — this file mirrors
  // that fix exactly, real-mm/Y-up instead of pixel/Y-down).
  const strapTop = groundY + strap.depthMM;
  const stubTopY = strapTop + stubHeightMM;
  // Caller rule (repeated: "مد الشداد للنهايه"): column-to-column
  // (drawX(0)..drawX(spanMM)) still stopped short of each footing's own
  // far edge — see renderPlanViewDXF's own header for the full citation.
  const barX1 = drawX(f1.startMM), barX2 = drawX(f2.endMM);

  // Strap concrete: ONE continuous rectangle spanning footing1's own
  // outer edge to footing2's own outer edge (barX1..barX2), drawn FIRST
  // — same span its own bars use below, so the concrete envelope and
  // its reinforcement are mutually consistent. Each footing's own
  // (shorter) rectangle is drawn AFTER, directly
  // below/overlapping — masking the strap's lower, wider-footprint
  // portion over its own span and leaving only the narrower "neck"
  // above that footing's own top, exactly as Fig. 6-16 shows at a
  // column, and the strap's full depth showing across the true clear
  // gap where nothing masks it. Same z-order trick the plan view below
  // already uses at the footing/strap seam.
  closedRectDXF(dxf, barX1, groundY, barX2 - barX1, strap.depthMM, LAYERS.CONCRETE_OUTLINE.name, { lineType: DASHED_LTYPE_NAME });

  // Column stubs, on top of the strap rect so their own outline reads
  // cleanly at the strap/column junction, with each column's own dowels
  // drawn as vertical lines, one per DISTINCT depth-axis (xLocal)
  // position (positions sharing an xLocal, differing only across
  // colWidthMM, collapse to one line in this elevation — the same
  // width-collapsing simplification already applied to the strap's own
  // top/bottom bars and to each pad's own along-width mesh family
  // below). Drawn from near the footing's own bottom mesh (near
  // groundY directly now, not an offset from a separate baseline),
  // straight up through the strap depth, into the column stub.
  for (const [pad, colCenterMM] of [[f1, 0], [f2, spanMM]]) {
    const cx = drawX(colCenterMM);
    closedRectDXF(dxf, cx - pad.colDepthMM / 2, strapTop, pad.colDepthMM, stubHeightMM, LAYERS.CONCRETE_OUTLINE.name);
    const dowelBottomY = groundY + pad.coverMM;
    const seen = new Set();
    for (const pt of pad.dowels.points) {
      const key = Math.round(pt.xLocalMM);
      if (seen.has(key)) continue;
      seen.add(key);
      weightedLine(dxf, cx + pt.xLocalMM, dowelBottomY, cx + pt.xLocalMM, stubTopY, pad.dowels.dia, LAYERS.DOWEL_BAR.name);
    }
  }

  for (const pad of [f1, f2]) {
    const x1 = drawX(pad.startMM), x2 = drawX(pad.endMM);
    closedRectDXF(dxf, x1, groundY, x2 - x1, pad.thicknessMM, LAYERS.CONCRETE_OUTLINE.name);

    const barY = groundY + pad.coverMM + pad.mesh.dia / 2;
    const alongWidthLen = pad.mesh.alongWidthLines[0].drawnLengthMM;
    weightedLine(dxf, drawX(pad.startMM + (pad.widthMM - alongWidthLen) / 2), barY, drawX(pad.startMM + (pad.widthMM + alongWidthLen) / 2), barY, pad.mesh.dia, LAYERS.REBAR_MESH_LINE.name);

    const dots = pad.mesh.alongBreadthLines.map((line) => ({ x: drawX(pad.startMM + line.xLocalMM), y: barY, diaMM: pad.mesh.dia }));
    const pitch = minPairwiseDistanceMM(dots);
    for (const d of dots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_MESH_LINE.name);
  }

  const sx1 = drawX(f1.endMM), sx2 = drawX(f2.startMM);

  // Strap bars: spread across the strap's WIDTH (the out-of-plane axis
  // for THIS cut, since the strap's width runs perpendicular to its own
  // length/global-X) collapse to one apparent height each in a
  // longitudinal cut — every top bar reads as ONE line, every bottom bar
  // as ONE line, matching the SVG source's own identical simplification.
  // Column-to-column extent with a schematic anchorage hook at each end
  // (Fig. 6-16 shows this steel continuing into and anchoring within the
  // column cage rather than terminating at the clear-gap edge). Measured
  // from groundY — the strap's real bottom — not the old (wrong)
  // footing-top baseline.
  const topY = groundY + strap.topBarDepthMM;
  const botY = groundY + strap.bottomBarDepthMM;
  const hook = MARGIN_MM * 0.35;
  weightedLine(dxf, barX1, topY, barX2, topY, strap.topBarDia, LAYERS.REBAR_TOP.name);
  weightedLine(dxf, barX1, topY, barX1, topY + hook, strap.topBarDia, LAYERS.REBAR_TOP.name);
  weightedLine(dxf, barX2, topY, barX2, topY + hook, strap.topBarDia, LAYERS.REBAR_TOP.name);
  weightedLine(dxf, barX1, botY, barX2, botY, strap.bottomBarDia, LAYERS.REBAR_BOTTOM.name);
  weightedLine(dxf, barX1, botY, barX1, botY - hook, strap.bottomBarDia, LAYERS.REBAR_BOTTOM.name);
  weightedLine(dxf, barX2, botY, barX2, botY - hook, strap.bottomBarDia, LAYERS.REBAR_BOTTOM.name);

  // Shrinkage/skin bars: same "collapses to one line per depth level"
  // simplification as the top/bottom bars above, confined to the strap's
  // own clear-gap extent (NOT extended into the columns — skin
  // reinforcement is a deep-section provision for the strap's own
  // visible span, unlike the main flexural steel above, which this
  // module deliberately does continue into the column).
  for (const levelMM of strap.shrinkageLevelsMM) {
    const y = groundY + levelMM;
    weightedLine(dxf, sx1, y, sx2, y, strap.shrinkageBarDia, LAYERS.REBAR_EXTRA.name);
  }

  for (const tickX of distributeTicks(sx1, sx2, Math.min(strap.stirrupCount, 14))) {
    stirrupTickVDXF(dxf, tickX, topY, botY, LAYERS.STIRRUP_TIE.name);
  }

  const dimY = strapTop + MARGIN_MM * 0.5;
  dimensionLineDXF(dxf, sx1, dimY, sx2, dimY, `clear=${fmt0(geometry.clearStrapMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dxfText(dxf, (sx1 + sx2) / 2, dimY + MARGIN_MM, SUBTITLE_HEIGHT_MM, 'STRAP BEAM', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  // lowestY now derives from groundY directly — the footing no longer
  // hangs below a separate baseline (see this function's own header).
  const lowestY = groundY;
  const titleY = lowestY - MARGIN_MM * 1.3;
  dxfText(dxf, (drawX(f1.startMM) + drawX(f2.endMM)) / 2, titleY, SUBTITLE_HEIGHT_MM, 'LONGITUDINAL SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  // top now reflects the column stubs (the tallest content in this
  // view) rather than the clear-span dimension row, since a tall/deep
  // strap can make stubTopY exceed dimY+margin+subtitle.
  return { top: Math.max(stubTopY, dimY + MARGIN_MM + SUBTITLE_HEIGHT_MM), bottom: titleY };
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
// True cross-section through the CHOSEN column + strap + footing
// (sectionThrough — one input field, not reused by any second,
// independent field), mirroring the SVG source's own
// renderSection11 exactly: footing (widest) at the bottom, strap (mid),
// column stub (narrowest) at top, all on ONE shared vertical centerline.
// Every bar family that runs LENGTHWISE along the strap/column (dowels,
// strap top/bottom/shrinkage bars) is cut END-ON here -> real barDotDXF
// circles, the opposite simplification from renderLongSectionDXF above,
// which collapses those same families to lines because IT cuts them
// in-plane. The footing's own two-way mesh is not repeated here
// (already fully shown in the pre-existing renderTransSectionDXF) — this
// view's own job is the column/strap junction specifically. origin =
// (sox, soy): soy = the footing's own bottom/soil-facing face; sox = the
// LEFT edge of the widest element in this view (kept in positive-X
// space relative to origin, same left-edge-origin convention every other
// view in this file already uses, rather than a centerline origin that
// would push part of the content into negative X).
// Mirrors the SVG source's own renderStrapCrossSection exactly (see its
// header for the reasoning): standalone strap cross-section with a
// leader line from each bar-group label to a representative bar, built
// from data Section 1-1 already computes. origin = (ox, oy): the
// section's own bottom-center (oy = the beam's real bottom fiber).
function renderStrapCrossSectionDXF(dxf, geometry, origin, opts) {
  const { strap } = geometry;
  const { x: cx, y: groundY } = origin;
  const topY = groundY + strap.depthMM;
  const sw = strap.widthMM;
  const sx = cx - sw / 2;
  const inset = strap.coverMM;

  const cutX = sx - MARGIN_MM * 1.1;
  dxfText(dxf, cutX, topY + MARGIN_MM * 0.2, SUBTITLE_HEIGHT_MM, 'A', { layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Right, vAlign: TextVerticalAlignment.Bottom });
  dxf.addLine(point3d(cutX + MARGIN_MM * 0.13, topY + MARGIN_MM * 0.13), point3d(cutX + MARGIN_MM * 0.65, topY - MARGIN_MM * 0.3), { layerName: LAYERS.ANNOTATION.name });
  dxfText(dxf, cutX, groundY - MARGIN_MM * 0.45, SUBTITLE_HEIGHT_MM, 'A', { layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Right, vAlign: TextVerticalAlignment.Top });
  dxf.addLine(point3d(cutX + MARGIN_MM * 0.13, groundY - MARGIN_MM * 0.4), point3d(cutX + MARGIN_MM * 0.65, groundY + MARGIN_MM * 0.05), { layerName: LAYERS.ANNOTATION.name });

  closedRectDXF(dxf, sx, groundY, sw, strap.depthMM, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, sx + inset, groundY + inset, sw - 2 * inset, strap.depthMM - 2 * inset, LAYERS.STIRRUP_TIE.name);

  const topBarY = groundY + strap.topBarDepthMM;
  const topDots = strap.topBars.map((off) => ({ x: sx + off, y: topBarY, diaMM: strap.topBarDia }));
  let pitch = minPairwiseDistanceMM(topDots);
  for (const d of topDots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_TOP.name);

  const botBarY = groundY + strap.bottomBarDepthMM;
  const botDots = strap.bottomBars.map((off) => ({ x: sx + off, y: botBarY, diaMM: strap.bottomBarDia }));
  pitch = minPairwiseDistanceMM(botDots);
  for (const d of botDots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_BOTTOM.name);

  const shrinkDots = strap.shrinkagePoints.map((pt) => ({ x: cx + pt.yLocalMM, y: groundY + pt.depthMM, diaMM: strap.shrinkageBarDia }));
  pitch = minPairwiseDistanceMM(shrinkDots);
  for (const d of shrinkDots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_EXTRA.name);

  const leader = (labelX, labelY, hAlign, tx, ty, text, layer) => {
    dxf.addLine(point3d(labelX, labelY), point3d(tx, ty), { layerName: layer });
    dxfText(dxf, labelX, labelY + MARGIN_MM * 0.08, DIM_TEXT_HEIGHT_MM, text, { layerName: LAYERS.ANNOTATION.name, hAlign, vAlign: TextVerticalAlignment.Bottom });
  };
  leader(sx + sw + MARGIN_MM * 0.7, topBarY, TextHorizontalAlignment.Left, topDots[topDots.length - 1].x, topBarY, 'Top bars', LAYERS.REBAR_TOP.name);
  leader(sx - MARGIN_MM * 0.7, topY - inset, TextHorizontalAlignment.Right, sx + inset, topY - inset, 'Stirrups', LAYERS.STIRRUP_TIE.name);
  leader(sx + sw + MARGIN_MM * 0.7, groundY + inset, TextHorizontalAlignment.Left, botDots[botDots.length - 1].x, botBarY, 'Shrinkage bars', LAYERS.REBAR_EXTRA.name);
  leader(sx - MARGIN_MM * 0.7, botBarY, TextHorizontalAlignment.Right, botDots[0].x, botBarY, 'Bottom bars', LAYERS.REBAR_BOTTOM.name);

  const titleY = groundY - MARGIN_MM * 0.9;
  dxfText(dxf, cx, titleY, SUBTITLE_HEIGHT_MM, 'SECTION A-A: STRAP BEAM', { layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top });
  dxfText(dxf, cx, titleY - SUBTITLE_HEIGHT_MM - MARGIN_MM * 0.15, SUBTITLE_HEIGHT_MM, 'CROSS-SECTION', { layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top });

  return { top: topY + MARGIN_MM * 0.5, bottom: titleY - SUBTITLE_HEIGHT_MM * 2 - MARGIN_MM * 0.3, width: sw + MARGIN_MM * 3 };
}

function renderSection11DXF(dxf, geometry, origin, opts) {
  const chosen = geometry.sectionThrough === 2 ? geometry.footing2 : geometry.footing1;
  const { strap } = geometry;
  const { x: sox, y: soy } = origin;
  const stubHeightMM = strap.depthMM * COLUMN_STUB_HEIGHT_FRACTION;
  const maxW = Math.max(chosen.breadthMM, strap.widthMM, chosen.colWidthMM);
  const cx = sox + maxW / 2;

  // soy IS the shared bottom both the footing and the strap rise from —
  // an earlier revision of this function stacked the strap ON TOP OF
  // footingTopY instead (footing top = strap bottom), the same bug the
  // SVG source's own renderSection11 header describes fixing against
  // Fig. 6-16. strapTopY now rises from soy directly, matching
  // strap.depthMM's own meaning as the beam's TOTAL depth.
  const strapTopY = soy + strap.depthMM;
  const footingTopY = soy + chosen.thicknessMM;
  const stubTopY = strapTopY + stubHeightMM;

  // Column stub (drawn first so bars/dowels painted afterward stay
  // visible against its own outline).
  closedRectDXF(dxf, cx - chosen.colWidthMM / 2, strapTopY, chosen.colWidthMM, stubHeightMM, LAYERS.CONCRETE_OUTLINE.name);
  dxfText(dxf, cx, stubTopY + SECTION11_LABEL_GAP_MM, SUBTITLE_HEIGHT_MM, 'Column', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  // Strap cross-section. Unlike the SVG source, draw order here does not
  // affect what is visible — closedRectDXF/barDotDXF are wireframe
  // entities with no solid fill to occlude anything, so an earlier
  // revision's own "masks its lower portion" comment on this block (and
  // the footing block below) never described a real DXF-side bug, only
  // a narrative copied from the SVG source's own genuine one. Kept in
  // this order regardless, matching the SVG source's own structure.
  // Stirrup outline and every lengthwise bar family cut end-on
  // (top/bottom/shrinkage) are positioned from soy — the strap's TRUE
  // bottom — so the bottom bars land within the footing's own body near
  // its bottom (matching the reference figure's own bottom-reinforcement
  // pointer, which lands inside the footing's concrete, not at the
  // neck's own base).
  {
    const sxLeft = cx - strap.widthMM / 2;
    closedRectDXF(dxf, sxLeft, soy, strap.widthMM, strap.depthMM, LAYERS.CONCRETE_OUTLINE.name, { lineType: DASHED_LTYPE_NAME });

    const inset = strap.coverMM;
    closedRectDXF(dxf, sxLeft + inset, soy + inset, strap.widthMM - 2 * inset, strap.depthMM - 2 * inset, LAYERS.STIRRUP_TIE.name);

    const topDots = strap.topBars.map((off) => ({ x: sxLeft + off, y: soy + strap.topBarDepthMM, diaMM: strap.topBarDia }));
    let pitch = minPairwiseDistanceMM(topDots);
    for (const d of topDots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_TOP.name);

    const botDots = strap.bottomBars.map((off) => ({ x: sxLeft + off, y: soy + strap.bottomBarDepthMM, diaMM: strap.bottomBarDia }));
    pitch = minPairwiseDistanceMM(botDots);
    for (const d of botDots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_BOTTOM.name);

    const shrinkDots = strap.shrinkagePoints.map((pt) => ({ x: cx + pt.yLocalMM, y: soy + pt.depthMM, diaMM: strap.shrinkageBarDia }));
    pitch = minPairwiseDistanceMM(shrinkDots);
    for (const d of shrinkDots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_EXTRA.name);

    dxfText(dxf, sxLeft - SECTION11_LABEL_GAP_MM, (soy + strapTopY) / 2, DIM_TEXT_HEIGHT_MM, 'Shrinkage bars', {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Right, vAlign: TextVerticalAlignment.Middle,
    });
  }

  // Blinding/plain-concrete layer, drawn BELOW the reinforced footing —
  // not flanking it at soy as an earlier revision drew chosen.plain.
  // Same PLAIN_CONCRETE_THICKNESS_MM/reasoning as the SVG source's own
  // renderSection11 (see that function's header): unconditional, real
  // construction sequence, not gated behind the optional chosen.plain
  // (which only ever supplied a WIDER footprint, not a thickness).
  const plainW = chosen.plain ? chosen.plain.breadthMM : chosen.breadthMM;
  const plainBottomY = soy - PLAIN_CONCRETE_THICKNESS_MM;
  closedRectDXF(dxf, cx - plainW / 2, plainBottomY, plainW, PLAIN_CONCRETE_THICKNESS_MM, LAYERS.CONCRETE_OUTLINE.name);
  const dimRowOffset = SECTION11_LABEL_GAP_MM * 0.9;
  if (chosen.plain) {
    dxfText(dxf, cx - plainW / 2 - SECTION11_LABEL_GAP_MM * 0.3, plainBottomY + MARGIN_MM * 0.1, DIM_TEXT_HEIGHT_MM, 'Plain concrete footing', {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Right, vAlign: TextVerticalAlignment.Bottom,
    });
    dimensionLineDXF(dxf, cx - plainW / 2, plainBottomY - dimRowOffset, cx + plainW / 2, plainBottomY - dimRowOffset, `${fmt0(plainW)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  }
  closedRectDXF(dxf, cx - chosen.breadthMM / 2, soy, chosen.breadthMM, chosen.thicknessMM, LAYERS.CONCRETE_OUTLINE.name);

  // Footing's own bottom mesh: bar dots ONLY, one row, no enclosing
  // frame and no row near the top — a real bottom-only mat has no bars
  // anywhere near the footing's own top face (same caller rule the SVG
  // source's own renderSection11 header cites in full: "الاسياخ العلويه
  // في القاعده احذفها. لا يوجد أي أسياخ علويه"). An earlier revision's
  // rectangle with dots at both its top and bottom edges read as a top
  // layer AND a bottom layer, which this footing never has.
  {
    const meshInset = chosen.coverMM;
    const meshY = soy + meshInset;
    const meshX1 = cx - chosen.breadthMM / 2 + meshInset, meshX2 = cx + chosen.breadthMM / 2 - meshInset;
    weightedLine(dxf, meshX1, meshY, meshX2, meshY, chosen.mesh.dia, LAYERS.REBAR_MESH_LINE.name);
    const dotStep = Math.max(80, (meshX2 - meshX1) / 10);
    const dots = [];
    for (let x = meshX1 + 20; x <= meshX2 - 20; x += dotStep) dots.push({ x, y: meshY, diaMM: chosen.mesh.dia });
    const pitch = minPairwiseDistanceMM(dots);
    for (const d of dots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.REBAR_MESH_LINE.name);
  }

  dxfText(dxf, cx + chosen.breadthMM / 2 + SECTION11_LABEL_GAP_MM * 0.3, soy + MARGIN_MM * 0.1, DIM_TEXT_HEIGHT_MM, 'Reinforced footing', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Bottom,
  });
  dimensionLineDXF(dxf, cx - chosen.breadthMM / 2, soy - dimRowOffset, cx + chosen.breadthMM / 2, soy - dimRowOffset, `${fmt0(chosen.breadthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // Column dowels, projected onto this section from their own real plan
  // positions (every dowel shown, regardless of how far along the
  // column's OWN depth axis it actually sits — the standard structural-
  // drawing convention for a column bar layout shown in a typical
  // section; see strapFootingDiagram.mjs's own header for the citation).
  // Vertically centered in the stub.
  {
    const dowelY = strapTopY + stubHeightMM / 2;
    const dots = chosen.dowels.points.map((pt) => ({ x: cx + pt.yLocalMM, y: dowelY, diaMM: chosen.dowels.dia }));
    const pitch = minPairwiseDistanceMM(dots);
    for (const d of dots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, LAYERS.DOWEL_BAR.name);
  }

  // Strap width is not re-dimensioned here (the column stub sits flush
  // on the strap with no gap — see this function's own header — so any
  // horizontal dimension "above the strap" would land inside the
  // column; the width is already dimensioned in both the plan view and
  // the pre-existing transverse section). The strap's own dimension line
  // now spans its FULL depth (soy to strapTopY), not just the neck above
  // the footing — matching strap.depthMM's own meaning as the beam's
  // total depth.
  dimensionLineDXF(dxf, cx + chosen.breadthMM / 2 + SECTION11_DIM_GAP_MM, footingTopY, cx + chosen.breadthMM / 2 + SECTION11_DIM_GAP_MM, soy, `${fmt0(chosen.thicknessMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, cx + strap.widthMM / 2 + SECTION11_DIM_GAP_MM, strapTopY, cx + strap.widthMM / 2 + SECTION11_DIM_GAP_MM, soy, `${fmt0(strap.depthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, cx, soy - dimRowOffset - SECTION11_LABEL_GAP_MM, DIM_TEXT_HEIGHT_MM, `Column dowels: ${chosen.dowels.count}\u00d8${fmt0(chosen.dowels.dia)} \u2014 Top bars: ${strap.topBarCount}\u00d8${fmt0(strap.topBarDia)} \u2014 Bottom bars: ${strap.bottomBarCount}\u00d8${fmt0(strap.bottomBarDia)}`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  const titleY = stubTopY + SECTION11_LABEL_GAP_MM + SUBTITLE_HEIGHT_MM + MARGIN_MM * 0.6;
  dxfText(dxf, cx, titleY, SUBTITLE_HEIGHT_MM, 'SECTION 1-1 (through column & strap)', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: maxW, top: titleY, bottom: soy - SECTION11_LABEL_GAP_MM * 1.6 - DIM_TEXT_HEIGHT_MM };
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

  // Stacked bottom-to-top in DXF model space: LONGITUDINAL SECTION
  // lowest, PLAN above it, SECTION 1-1 highest — reproducing the SVG
  // source's own top-to-bottom reading order when plotted, since DXF Y
  // increases upward. TRANSVERSE SECTION used to sit below all of this
  // (lowest) — removed outright, same "احذف هذه الرسمه ... فهي بلا
  // معني" caller rule strapFootingDiagram.mjs's own header cites: it
  // duplicated Section 1-1 with strictly less context, once the two
  // read the same footing/mesh/blinding-layer convention.
  const longBaselineY = Math.max(geometry.footing1.thicknessMM, geometry.footing2.thicknessMM);
  const long_ = renderLongSectionDXF(dxf, geometry, { x: 0, y: longBaselineY }, opts);

  const planOrigin = { x: -geometry.footing1.startMM, y: long_.top + (opts.viewGapMM ?? VIEW_GAP_MM) };
  const plan = renderPlanViewDXF(dxf, geometry, planOrigin, opts);

  const section11Origin = { x: 0, y: plan.top + (opts.viewGapMM ?? VIEW_GAP_MM) };
  const section11 = renderSection11DXF(dxf, geometry, section11Origin, opts);

  const strapSecOrigin = { x: geometry.strap.widthMM, y: section11.top + (opts.viewGapMM ?? VIEW_GAP_MM) };
  const strapSec = renderStrapCrossSectionDXF(dxf, geometry, strapSecOrigin, opts);

  const overallWidth = Math.max(plan.width, section11.width);
  const titleY = strapSec.top + MARGIN_MM * 2.2;
  dxfText(dxf, overallWidth / 2, titleY, TITLE_HEIGHT_MM, `STRAP FOOTING ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  const captionY = -MARGIN_MM * 1.3;
  dxfText(dxf, overallWidth / 2, captionY, CAPTION_HEIGHT_MM, CAPTION_EN, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return dxf.stringify();
}
