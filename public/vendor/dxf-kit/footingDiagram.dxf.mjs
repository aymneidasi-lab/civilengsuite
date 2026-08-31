// footingDiagram.dxf.mjs
// DXF render path for the footing schematic — parallel to, and entirely
// separate from, renderFootingDiagramSVG() in footingDiagram.mjs. Same
// placement rationale as shearWallDiagram.dxf.mjs: an ordinary /diagram
// or /rebar SVG request must never pull @tarikjabiri/dxf into the
// Worker's module graph — only a real DXF-export request does.
//
// One render function covers all four footing types (isolated/combined/
// strip/raft) — computeIsolatedFootingGeometry()/
// computeCombinedFootingGeometry()/computeStripFootingGeometry()/
// computeRaftFootingGeometry() are consumed exactly as returned, zero
// modification to footingDiagram.mjs. This mirrors the SVG source's own
// architecture: renderPlanView()/renderSectionView() in footingDiagram.mjs
// are ALREADY generic across all four types (every type-specific
// difference already lives in geometry.plan/.section) — the two
// functions below keep that same one-render-path-per-view shape rather
// than branching per type.
//
// v1 scope exclusions (same category as shearWallDiagram.dxf.mjs's own):
// no Arabic labels (English only, hardcoded, not opts.lang-driven), no
// HATCH (soil band and concrete/column fill patterns omitted — outline
// only, matching CONCRETE-OUTLINE's own documented "fill has no meaning
// without HATCH" v1 position), no scheduleTable-as-DXF-TABLE (the
// pedestal/dowel/mesh workshop summary row is v1-excluded — dowel count/
// dia/projection and mesh dia/spacing therefore have no on-sheet text
// label here, exactly mirroring how the SVG source itself only shows
// that data inside the now-excluded table; the dots themselves are still
// drawn at their real, collision-checked positions).
//
// New-for-this-element decisions, disclosed per the master prompt's own
// protocol (none contradict its already-decided layer table):
//   - REBAR-BOTTOM carries every rebar element this file draws (main
//     bottom bars, plan-view mesh grid, the optional "top mesh" second
//     layer, and dowels) — verified against footingDiagram.mjs's actual
//     CSS, not assumed: .mesh-line/.bar-dot/.bar-dot-dowel all share the
//     identical #c0392b hex (REBAR-BOTTOM's own color), and the file's
//     own Step-14.3 comment states the top-mesh layer is "distinguished
//     from the bottom layer by POSITION ... not by color" — so this
//     element has no REBAR-TOP usage anywhere, unlike shearWallDiagram.
//   - cut-line / cut-label -> ANNOTATION (already listed by name in the
//     master prompt's shared layer table).
//   - col-tag -> ANNOTATION, flagged default (unlisted in the master
//     table; same treatment shearWallDiagram.dxf.mjs already gave its
//     own unlisted "support-label").
//   - New kit primitive: dashed linetype (structuralDrawingDxfKit.mjs's
//     closedRectDXF opts.lineType + defineDashedLType()/
//     DASHED_PATTERN_MM), used for the pedestal-outline overlay in plan
//     and the section-cut marker line — both drawn dashed in the SVG
//     source (stroke-dasharray) where solid-vs-dashed carries real
//     meaning (overlay/marker vs. an actual material edge) that a solid
//     line would flatten away. See the kit function's own header for the
//     verified @tarikjabiri/dxf@2.8.9 mechanics and the ordering
//     constraint it depends on.
//   - Soil band (SVG's soilHatch rect): omitted entirely, not even as an
//     outline — a HATCH-only visual with no assigned layer anywhere in
//     the master's table, carrying no structural/dimensional
//     information (same "don't invent an unlisted layer" principle the
//     master prompt states explicitly for CONCRETE-OUTLINE's own fill).
//
// Collision-safety note (Decision 1's per-view, per-axis real-pitch
// mandate): unlike shearWallDiagram's single homogeneous mesh grid, one
// section view here can draw THREE independent REBAR-BOTTOM dot families
// at once (bottom bars, optional dowels at the footing-top interface,
// optional top mesh inset exactly one cover below that same interface)
// whose closest real neighbor is not always same-family — see
// renderSectionViewDXF's own inline note. pitchMM is therefore computed
// per-dot as the true nearest-neighbor distance across every dot actually
// drawn on REBAR-BOTTOM in that view, not one shared family-level pitch.

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
  dimensionLineDXF,
  distributeTicks,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

const FOOTING_TYPES = ['isolated', 'combined', 'strip', 'raft'];
// Mirrors footingDiagram.mjs's own module-level NUMBERED_COLUMN_TYPES
// (verified byte-identical in behavior at time of writing: isolated has
// exactly one, unlabeled column and is deliberately excluded — there is
// nothing to disambiguate).
const NUMBERED_COLUMN_TYPES = new Set(['combined', 'strip', 'raft']);

// Layout conventions — none of these come from geometry; each is a
// chosen default for real-mm placement the SVG path never needed (fixed
// pixel canvas instead). All named so they're auditable, matching
// shearWallDiagram.dxf.mjs's own convention.
const MARGIN_MM = 300; // gutter for dimension lines/labels — same value shearWallDiagram used for the identical role
const VIEW_GAP_MM = 1000; // real-mm gap between section (below) and plan (above) — same order of magnitude as shearWallDiagram's own view gap
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view titles, column tags, cut labels
const DIM_TEXT_HEIGHT_MM = 150;
const CAPTION_HEIGHT_MM = 115; // slightly below SUBTITLE_HEIGHT_MM — a footnote, not a heading
const MESH_LINE_INSET_MM = 40; // inset off the footing edges for plan-view mesh grid lines, real-mm analogue of the SVG source's fixed 2px inset
const BAR_LINE_INSET_MM = 60; // inset for the section view's representative bar-family lines, real-mm analogue of the SVG source's fixed 8px inset
const COLUMN_TAG_GAP_MM = 60; // gap from a column's edge to its tag label, real-mm analogue of the SVG source's fixed 16px gap
const CUT_LINE_OVERHANG_MM = 150; // how far the section-cut marker extends past the plan view's short-axis edges, real-mm analogue of the SVG source's fixed 14px overhang
const CUT_LABEL_GAP_MM = 70; // gap from the cut-line's overhung end to its lettered label
const SECTION_STUB_NO_PEDESTAL_MM = 600; // fixed "column continues" decorative stub above the footing top when no pedestal is given — real-mm analogue of the SVG source's fixed 90px stub (neither version is ever given a real column height to draw to scale)
const PEDESTAL_STUB_MM = 200; // shorter decorative stub above a real-scale pedestal, real-mm analogue of the SVG source's fixed 40px secondary stub
const LABEL_STACK_GAP_MM = 130; // vertical gap between the stacked cover/bar-spec text lines in the section view

function fmt0(mm) {
  return String(Math.round(mm));
}

// English-only hardcoded equivalents of structuralLabels.mjs's
// columnTag()/sectionTitle()/footingTitle() — same v1 decision
// shearWallDiagram.dxf.mjs already made (no Arabic, not opts.lang-
// driven). Values confirmed against test_footingDiagram.mjs's own
// assertions for the English strings (columnTag('combined',0,'en') ===
// 'COLUMN A', columnTag('raft',11,'en') === 'COLUMN 12',
// sectionTitle('isolated',null,'en') === 'SECTION A-A',
// sectionTitle('combined',0,'en') === 'SECTION A-A (through COLUMN A)').
function columnTagEN(type, i) {
  if (type === 'combined') return `COLUMN ${String.fromCharCode(65 + i)}`; // A, B — combined only ever has 2 columns
  return `COLUMN ${i + 1}`; // strip/raft: numbered from 1
}

function sectionTitleEN(type, throughIdx) {
  if (throughIdx == null) return 'SECTION A-A'; // isolated: one unlabeled column, nothing to disambiguate
  return `SECTION A-A (through ${columnTagEN(type, throughIdx)})`;
}

// footingTitle()'s exact translated English strings live in
// structuralLabels.mjs, which is not read by this DXF path (v1 decision,
// see header) — these are fresh, standard structural-engineering terms
// directly matching this file's own type-by-type documentation
// (footingDiagram.mjs's header: "'isolated' — single-column spread
// footing", "'combined' — two-column rectangular footing", "'strip' —
// continuous rectangular footing", "'raft' — single-thickness mat slab").
const FOOTING_TITLE_EN = {
  isolated: 'ISOLATED FOOTING',
  combined: 'COMBINED FOOTING',
  strip: 'STRIP FOOTING',
  raft: 'RAFT FOUNDATION',
};

// Fixed disclaimer, deliberately generic so it stays true whether or not
// pedestal/dowels/mesh were supplied — same reason footingDiagram.mjs's
// own captionComputed was rewritten at Step 14 to stay accurate in both
// cases (see that file's header). An over-specific claim like "no dowels
// shown" would be wrong exactly when geometry.dowels is present.
const CAPTION_EN = 'Schematic for reference only, not a construction/shop drawing. Reinforcement shown is representative, not exhaustive.';

// Draws the vertical cut: footing body, the column/pedestal stack rising
// from the footing top (real-scale pedestal when supplied, else a fixed
// decorative stub — see SECTION_STUB_NO_PEDESTAL_MM/PEDESTAL_STUB_MM),
// dowel circles at the footing-top interface when supplied, the bottom
// reinforcement layer (real count/spacing from computeSectionGeometry),
// the optional top mesh layer, and the depth/width/cover/bar-spec
// dimension callouts. origin = (sox, soy) is the footing body's own
// BOTTOM-LEFT corner (soy = soil interface, soy+depthMM = footing top) —
// this file's own real-mm y-up convention, chosen fresh for this
// element (see module header on why this is not a literal carry-over of
// shearWallDiagram's own origin convention).
function renderSectionViewDXF(dxf, geometry, origin, opts) {
  const { section } = geometry;
  const { x: sox, y: soy } = origin;
  const wPx = section.widthMM;

  closedRectDXF(dxf, sox, soy, wPx, section.depthMM, LAYERS.CONCRETE_OUTLINE.name);

  const footingTopY = soy + section.depthMM;
  const colW = section.colWidthMM;
  const colX = sox + wPx / 2 - colW / 2;
  let colTop, dowelHostX;
  if (geometry.pedestal) {
    const pedW = geometry.pedestal.widthMM, pedH = geometry.pedestal.heightMM;
    const pedX = sox + wPx / 2 - pedW / 2;
    // Solid, not dashed — only the PLAN-view pedestal footprint is
    // dashed in the SVG source; the section view's pedestal uses the
    // same solid column-outline treatment as the column itself.
    closedRectDXF(dxf, pedX, footingTopY, pedW, pedH, LAYERS.CONCRETE_OUTLINE.name);
    closedRectDXF(dxf, colX, footingTopY + pedH, colW, PEDESTAL_STUB_MM, LAYERS.CONCRETE_OUTLINE.name);
    colTop = footingTopY + pedH + PEDESTAL_STUB_MM;
    dowelHostX = pedX;
  } else {
    closedRectDXF(dxf, colX, footingTopY, colW, SECTION_STUB_NO_PEDESTAL_MM, LAYERS.CONCRETE_OUTLINE.name);
    colTop = footingTopY + SECTION_STUB_NO_PEDESTAL_MM;
    dowelHostX = colX;
  }

  // Collect every REBAR-BOTTOM dot this view will draw BEFORE drawing
  // any of them, so each dot's pitchMM (passed to barDotDXF) is the true
  // nearest-neighbor distance across every family actually present —
  // dowels sit exactly at footingTopY; the optional mesh layer sits
  // exactly one cover below that same Y (see meshY below) — a real
  // cross-family collision axis a single shared per-family pitch would
  // miss. Positions match footingDiagram.mjs's renderSectionView exactly:
  // dowels.centersMM / mesh.barCentersMM are relative to their own host
  // envelope (dowelHostX / sox respectively — mesh always spans the full
  // section width, dowels only their host's, per computeFootingExtras's
  // own documented split).
  const dots = [];
  const barY = soy + section.coverMM;
  for (const cMM of section.barCentersMM) dots.push({ x: sox + cMM, y: barY, diaMM: section.diaMM });
  if (geometry.dowels) {
    for (const cMM of geometry.dowels.centersMM) dots.push({ x: dowelHostX + cMM, y: footingTopY, diaMM: geometry.dowels.diaMM });
  }
  let meshY = null;
  if (geometry.mesh) {
    meshY = footingTopY - section.coverMM;
    for (const cMM of geometry.mesh.barCentersMM) dots.push({ x: sox + cMM, y: meshY, diaMM: geometry.mesh.diaMM });
  }
  function nearestNeighborMM(index) {
    const p = dots[index];
    let min = Infinity;
    for (let i = 0; i < dots.length; i++) {
      if (i === index) continue;
      const d = Math.hypot(p.x - dots[i].x, p.y - dots[i].y);
      if (d > 0 && d < min) min = d;
    }
    return min;
  }

  // Representative lines (bottom layer always; top mesh only if
  // present) — dowels have no representative line in the SVG source
  // either, individual dots only.
  dxf.addLine(point3d(sox + BAR_LINE_INSET_MM, barY), point3d(sox + wPx - BAR_LINE_INSET_MM, barY), { layerName: LAYERS.REBAR_BOTTOM.name });
  if (geometry.mesh) {
    dxf.addLine(point3d(sox + BAR_LINE_INSET_MM, meshY), point3d(sox + wPx - BAR_LINE_INSET_MM, meshY), { layerName: LAYERS.REBAR_BOTTOM.name });
  }
  dots.forEach((d, i) => {
    barDotDXF(dxf, d.x, d.y, d.diaMM, nearestNeighborMM(i), LAYERS.REBAR_BOTTOM.name);
  });

  // Dimensions: depth (right), width (below), cover + bar-spec (stacked,
  // centered above the bottom bar row — matches the SVG source's own
  // "stacked on two centered lines, not left/right on one line" fix).
  dimensionLineDXF(dxf, sox + wPx + MARGIN_MM * 0.5, soy, sox + wPx + MARGIN_MM * 0.5, footingTopY, `D = ${fmt0(section.depthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  const widthLabel = section.widthMM === geometry.meta.B ? 'B' : geometry.plan.shortLabel;
  dimensionLineDXF(dxf, sox, soy - MARGIN_MM * 0.6, sox + wPx, soy - MARGIN_MM * 0.6, `${widthLabel} = ${fmt0(section.widthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  const midX = sox + wPx / 2;
  dxfText(dxf, midX, barY + LABEL_STACK_GAP_MM, DIM_TEXT_HEIGHT_MM, `cover = ${fmt0(section.coverMM)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });
  dxfText(dxf, midX, barY + LABEL_STACK_GAP_MM * 2, DIM_TEXT_HEIGHT_MM, `${section.barCount} \u00d8${fmt0(section.diaMM)} @ ${fmt0(section.actualSpacingMM)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  const throughIdx = NUMBERED_COLUMN_TYPES.has(geometry.type) ? geometry.sectionThrough - 1 : null;
  dxfText(dxf, midX, soy - MARGIN_MM * 1.3, SUBTITLE_HEIGHT_MM, sectionTitleEN(geometry.type, throughIdx), {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return { width: wPx, height: colTop - soy };
}

// Draws the top-down view: footing outline, a reinforcement mesh drawn
// as crossing lines (long-way lines at geometry.section.barCentersMM —
// the same set the section view draws as circles, one source of truth
// for that direction, verified geometry.section.widthMM ===
// geometry.plan.shortMM for all four footing types; short-way lines
// independently derived inline, matching the SVG source's own inline
// derivation since that count is plan-only), every column (+ pedestal
// footprint overlay, dashed, when supplied), a lettered section-cut
// marker on multi-column types, and the two overall dimension lines.
// origin = (ox, oy) is the footing outline's own BOTTOM-LEFT corner.
function renderPlanViewDXF(dxf, geometry, origin, opts) {
  const { plan } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, plan.longMM, plan.shortMM, LAYERS.CONCRETE_OUTLINE.name);

  for (const cMM of geometry.section.barCentersMM) {
    const y = oy + cMM;
    dxf.addLine(point3d(ox + MESH_LINE_INSET_MM, y), point3d(ox + plan.longMM - MESH_LINE_INSET_MM, y), { layerName: LAYERS.REBAR_BOTTOM.name });
  }
  {
    const env = plan.longMM - 2 * geometry.meta.cover - geometry.meta.dia;
    const spacingLong = geometry.meta.spacingLong ?? geometry.meta.spacing;
    const count = Math.max(2, Math.floor(env / spacingLong) + 1);
    const first = geometry.meta.cover + geometry.meta.dia / 2;
    const last = plan.longMM - geometry.meta.cover - geometry.meta.dia / 2;
    const xs = distributeTicks(ox + first, ox + last, count);
    for (const x of xs) {
      dxf.addLine(point3d(x, oy + MESH_LINE_INSET_MM), point3d(x, oy + plan.shortMM - MESH_LINE_INSET_MM), { layerName: LAYERS.REBAR_BOTTOM.name });
    }
  }

  plan.columns.forEach((col, i) => {
    const cx = ox + col.centerLongMM;
    // raft columns carry their own centerShortMM (2-D plan position);
    // every other type omits it, keeping them on the plan's short-axis
    // midline exactly as the SVG source's own identical fallback does.
    const cy = col.centerShortMM != null ? oy + col.centerShortMM : oy + plan.shortMM / 2;
    const cw = col.alongLongMM, ch = col.alongShortMM;

    if (geometry.pedestal) {
      const pedSide = geometry.pedestal.widthMM;
      closedRectDXF(dxf, cx - pedSide / 2, cy - pedSide / 2, pedSide, pedSide, LAYERS.CONCRETE_OUTLINE.name, { lineType: DASHED_LTYPE_NAME });
    }
    closedRectDXF(dxf, cx - cw / 2, cy - ch / 2, cw, ch, LAYERS.CONCRETE_OUTLINE.name);

    if (NUMBERED_COLUMN_TYPES.has(geometry.type)) {
      dxfText(dxf, cx, cy - ch / 2 - COLUMN_TAG_GAP_MM, SUBTITLE_HEIGHT_MM, columnTagEN(geometry.type, i), {
        layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
      });
    }
  });

  if (NUMBERED_COLUMN_TYPES.has(geometry.type)) {
    const chosen = plan.columns[geometry.sectionThrough - 1];
    const cx = ox + chosen.centerLongMM;
    const yLo = oy - CUT_LINE_OVERHANG_MM, yHi = oy + plan.shortMM + CUT_LINE_OVERHANG_MM;
    dxf.addLine(point3d(cx, yLo), point3d(cx, yHi), { layerName: LAYERS.ANNOTATION.name, lineType: DASHED_LTYPE_NAME });
    dxfText(dxf, cx, yLo - CUT_LABEL_GAP_MM, SUBTITLE_HEIGHT_MM, 'A', { layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top });
    dxfText(dxf, cx, yHi + CUT_LABEL_GAP_MM, SUBTITLE_HEIGHT_MM, 'A', { layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom });
  }

  dimensionLineDXF(dxf, ox, oy + plan.shortMM + MARGIN_MM * 0.6, ox + plan.longMM, oy + plan.shortMM + MARGIN_MM * 0.6, `${plan.longLabel} = ${fmt0(plan.longMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + plan.shortMM, `${plan.shortLabel} = ${fmt0(plan.shortMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + plan.longMM / 2, oy - SUBTITLE_HEIGHT_MM * 1.2, SUBTITLE_HEIGHT_MM, 'PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return { width: plan.longMM, height: plan.shortMM };
}

export function renderFootingDiagramDXF(geometry, opts = {}) {
  if (!geometry || !FOOTING_TYPES.includes(geometry.type)) {
    throw new DiagramError('BAD_PARAM', `renderFootingDiagramDXF expects a geometry object from computeIsolatedFootingGeometry()/computeCombinedFootingGeometry()/computeStripFootingGeometry()/computeRaftFootingGeometry() (type one of ${FOOTING_TYPES.join(', ')}).`);
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  // MUST precede defineDxfLayers()/any entity referencing
  // DASHED_LTYPE_NAME — see structuralDrawingDxfKit.mjs's own header on
  // DxfLayerTable.addLayer()'s silent-Continuous-fallback behavior for
  // an unregistered linetype name.
  defineDashedLType(dxf);
  defineDxfLayers(dxf);

  // Section at the origin, plan stacked above it — the SVG source's own
  // arrangement (PLAN_BOX above SECTION_BOX), kept rather than
  // shearWallDiagram's side-by-side convention because footing plans can
  // run to several meters along the long axis while the section's own
  // width (B) is typically much smaller; stacking avoids one view's
  // large horizontal extent competing for column alignment with the
  // other's, exactly the layout problem the SVG source's own box choice
  // already solved for this element.
  const sectionOrigin = { x: 0, y: 0 };
  const section = renderSectionViewDXF(dxf, geometry, sectionOrigin, opts);

  const planOrigin = { x: 0, y: sectionOrigin.y + section.height + (opts.viewGapMM ?? VIEW_GAP_MM) };
  const plan = renderPlanViewDXF(dxf, geometry, planOrigin, opts);

  const overallWidth = Math.max(plan.width, section.width);
  const titleY = planOrigin.y + plan.height + MARGIN_MM * 2.2;
  dxfText(dxf, overallWidth / 2, titleY, TITLE_HEIGHT_MM, FOOTING_TITLE_EN[geometry.type], {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  const captionY = sectionOrigin.y - MARGIN_MM * 2.4; // below the section view's own title/dimensions, the sheet's lowest element — mirrors the SVG source's own bottom-of-sheet caption placement
  dxfText(dxf, overallWidth / 2, captionY, CAPTION_HEIGHT_MM, CAPTION_EN, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return dxf.stringify();
}
