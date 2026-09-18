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
  // [Step 20] tieTickHDXF: already built in the kit for columnDiagram's
  // own vertical-member elevation ties — same geometry this file's own
  // column-stub-above-the-footing needs, so no new kit primitive, only
  // a new call site here (see renderSectionViewDXF's own ties block).
  tieTickHDXF,
} from '../shared/structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from '../shared/tarikjabiri-dxf.esm.js';

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

// [Step 21] Mirrors footingDiagram.mjs's own DUAL_SECTION_TYPES exactly —
// see that file's comment for why isolated/raft are excluded.
const DUAL_SECTION_TYPES = new Set(['combined', 'strip']);
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
  let colTop, dowelHostX, colSegBottom;
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
    colSegBottom = footingTopY + pedH; // [Step 20] top of the pedestal = bottom of the drawn COLUMN segment
  } else {
    closedRectDXF(dxf, colX, footingTopY, colW, SECTION_STUB_NO_PEDESTAL_MM, LAYERS.CONCRETE_OUTLINE.name);
    colTop = footingTopY + SECTION_STUB_NO_PEDESTAL_MM;
    dowelHostX = colX;
    colSegBottom = footingTopY; // [Step 20] no pedestal — the column segment runs straight down to the footing top
  }

  // [Step 20] Column ties — same column-segment-only scope as the SVG
  // renderer's own ties block (never the pedestal segment; see that
  // file's comment on why). distributeTicks, not footingDiagram.mjs's
  // own local distributeCenters (not exported, and this is a different
  // file): already imported here and already this file's own established
  // way to spread an exact count across a real-mm range (see the plan
  // mesh's short-way block above this function). geometry.ties.count is
  // already clamped to [2, MAX_TIES=12] at compute time, comfortably
  // inside distributeTicks' own internal [2,24] clamp.
  if (geometry.ties) {
    const tieInsetMM = 40; // real-mm analogue of the SVG renderer's 8px inset, scaled for typical dowel/tie diagram sizes in this file's other real-mm insets (see MARGIN_MM/BAR_LINE_INSET_MM below)
    // [Bug found via entity-count verification, not the earlier "does it
    // throw" pass] This file's Y axis runs UP (colTop > colSegBottom
    // numerically — colTop is further from the footing, not closer to
    // it, unlike the SVG renderer's Y-DOWN px convention this line was
    // first adapted from). distributeTicks treats its first argument as
    // the smaller bound and silently collapses to one point whenever
    // start >= end — passing the larger value first made every call
    // degenerate to a single tick regardless of geometry.ties.count.
    // colSegBottom is the smaller Y here, so it goes first.
    const ys = distributeTicks(colSegBottom + tieInsetMM, colTop - tieInsetMM, geometry.ties.count);
    for (const y of ys) {
      tieTickHDXF(dxf, colX, colX + colW, y, LAYERS.STIRRUP_TIE.name);
    }
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
  // [Bug fix, mirrors renderSectionView's SVG-side fix] barY/meshY (used
  // for the LINE below) are the TRANSVERSE bars' true-cover reference
  // position; the LONGITUDINAL bars these dots represent are a different
  // bar crossing at that point, not the same bar drawn twice, so they
  // cannot sit on the line itself. Shifted one radius toward mid-depth —
  // DXF's Y axis runs up, so that is +radius from the bottom face and
  // -radius from the top face.
  const dots = [];
  const barY = soy + section.coverMM;
  const barRadiusMM = section.diaMM / 2;
  const barDotY = barY + barRadiusMM;
  for (const cMM of section.barCentersMM) dots.push({ x: sox + cMM, y: barDotY, diaMM: section.diaMM, layer: LAYERS.REBAR_BOTTOM.name });
  if (geometry.dowels) {
    for (const cMM of geometry.dowels.centersMM) dots.push({ x: dowelHostX + cMM, y: footingTopY, diaMM: geometry.dowels.diaMM, layer: LAYERS.REBAR_BOTTOM.name });
  }
  let meshY = null;
  let meshDotY = null;
  if (geometry.mesh) {
    meshY = footingTopY - section.coverMM;
    meshDotY = meshY - geometry.mesh.diaMM / 2;
    // [Step 20] REBAR_TOP, not REBAR_BOTTOM — this layer now also gets a
    // plan-view presence (renderPlanViewDXF below), where, unlike this
    // section view, there is no position cue distinguishing top from
    // bottom (a plan is a projection — top and bottom bars land on the
    // same plane), so the two families need their own layer/color to
    // stay visually distinguishable in EVERY view they now both appear
    // in, not only here where inset-from-the-top-face already did that
    // job on its own. Matches every other element in this shared kit,
    // which already puts top and bottom steel on separate layers — this
    // file was the one exception, only while the top layer stayed
    // section-only.
    for (const cMM of geometry.mesh.barCentersMM) dots.push({ x: sox + cMM, y: meshDotY, diaMM: geometry.mesh.diaMM, layer: LAYERS.REBAR_TOP.name });
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
    dxf.addLine(point3d(sox + BAR_LINE_INSET_MM, meshY), point3d(sox + wPx - BAR_LINE_INSET_MM, meshY), { layerName: LAYERS.REBAR_TOP.name });
  }
  dots.forEach((d, i) => {
    barDotDXF(dxf, d.x, d.y, d.diaMM, nearestNeighborMM(i), d.layer);
  });

  // Dimensions: depth (right, vertical), width (below, horizontal).
  dimensionLineDXF(dxf, sox + wPx + MARGIN_MM * 0.5, soy, sox + wPx + MARGIN_MM * 0.5, footingTopY, `D = ${fmt0(section.depthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  const widthLabel = section.widthMM === geometry.meta.B ? 'B' : geometry.plan.shortLabel;
  // [Bug fix — root cause confirmed by reading dimensionLineDXF's actual
  // source, not further guessing: for horizontal orientation it places
  // text at (midY + LABEL_GAP_MM(=120)), Bottom-aligned. The previous
  // MARGIN*0.6 line position put that text only 60mm below the footing —
  // with 150mm-tall Bottom-aligned text extending UPWARD from its
  // anchor, 90mm of it landed inside the footing, overlapping the bottom
  // bar row (and, in the rendered image, everything stacked below it in
  // turn). MARGIN*1.3 clears the footing with 120mm to spare, verified
  // by this arithmetic, not re-guessed from the next rendered image.
  dimensionLineDXF(dxf, sox, soy - MARGIN_MM * 1.3, sox + wPx, soy - MARGIN_MM * 1.3, `${widthLabel} = ${fmt0(section.widthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // Cover/bar-spec/title: each independently Top-aligned (this file
  // controls their exact span directly, unlike the dimension line's
  // text), each with a verified real gap to the row above — 150-180mm of
  // actual clearance, not a value that merely avoided the one case that
  // got rendered last.
  const midX = sox + wPx / 2;
  dxfText(dxf, midX, soy - MARGIN_MM * 1.9, DIM_TEXT_HEIGHT_MM, `cover = ${fmt0(section.coverMM)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, midX, soy - MARGIN_MM * 2.7, DIM_TEXT_HEIGHT_MM, `${section.barCount} \u00d8${fmt0(section.diaMM)} @ ${fmt0(section.actualSpacingMM)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  const throughIdx = NUMBERED_COLUMN_TYPES.has(geometry.type) ? geometry.sectionThrough - 1 : null;
  // [Step 21] opts.secondary: this function now serves two roles, same
  // as its SVG-source sibling — the sole section for isolated/raft
  // (unchanged), and the secondary "side" view for combined/strip, which
  // gets a short, distinct title instead of the SVG version's overflow
  // problem (fixed there by shortening rather than combining strings;
  // DXF text has no fixed-box width to overflow, but the shorter title
  // is kept for the same reason it reads more clearly either way).
  const titleTextDXF = opts.secondary ? 'TRANSVERSE SECTION' : sectionTitleEN(geometry.type, throughIdx);
  const titleY = soy - MARGIN_MM * 3.5;
  dxfText(dxf, midX, titleY, SUBTITLE_HEIGHT_MM, titleTextDXF, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  // [Bug fix — mirrors the SVG source's own Step 14.3 dynamic
  // captionBottomY fix] bottomTextY reports how far down this view's OWN
  // text reaches, so the caller can position the sheet caption safely
  // below it instead of a fixed offset a tall text stack can defeat
  // again — exactly the class of bug the row redesign above was fixing
  // in the first place, now closed at its source instead of re-opened
  // one level up.
  const bottomTextY = titleY - SUBTITLE_HEIGHT_MM;
  return { width: wPx, height: colTop - soy, bottomTextY };
}

// ── Step 21: primary longitudinal section (combined/strip only) ────────
// DXF mirror of footingDiagram.mjs's renderLongSectionView. Same bar-role
// swap as that function's own header documents (this cut is perpendicular
// to B, so transverse bars are the circles and longitudinal bars are the
// line — opposite of renderSectionViewDXF above), same stacking-offset
// fix, same "every column gets the one global pedestal/tie/dowel spec"
// simplification, same no-curtailment scope decision.
// origin = (ox, oy) is the footing outline's own bottom-left corner, same
// convention renderPlanViewDXF/renderSectionViewDXF already use.
function renderLongSectionViewDXF(dxf, geometry, origin, opts) {
  const { plan, meta } = geometry;
  const { x: ox, y: oy } = origin;
  const wPx = plan.longMM;

  closedRectDXF(dxf, ox, oy, wPx, meta.D, LAYERS.CONCRETE_OUTLINE.name);
  const footingTopY = oy + meta.D;

  let maxColTop = footingTopY;
  plan.columns.forEach((col, i) => {
    const colW = col.alongLongMM;
    const cx = ox + col.centerLongMM;
    const colX = cx - colW / 2;
    let colTop, dowelHostX, colSegBottom;
    if (geometry.pedestal) {
      const pedW = geometry.pedestal.widthMM, pedH = geometry.pedestal.heightMM;
      const pedX = cx - pedW / 2;
      closedRectDXF(dxf, pedX, footingTopY, pedW, pedH, LAYERS.CONCRETE_OUTLINE.name);
      closedRectDXF(dxf, colX, footingTopY + pedH, colW, PEDESTAL_STUB_MM, LAYERS.CONCRETE_OUTLINE.name);
      colTop = footingTopY + pedH + PEDESTAL_STUB_MM;
      dowelHostX = pedX;
      colSegBottom = footingTopY + pedH;
    } else {
      closedRectDXF(dxf, colX, footingTopY, colW, SECTION_STUB_NO_PEDESTAL_MM, LAYERS.CONCRETE_OUTLINE.name);
      colTop = footingTopY + SECTION_STUB_NO_PEDESTAL_MM;
      dowelHostX = colX;
      colSegBottom = footingTopY;
    }
    maxColTop = Math.max(maxColTop, colTop);
    if (geometry.ties) {
      const tieInsetMM = 40;
      const ys = distributeTicks(colSegBottom + tieInsetMM, colTop - tieInsetMM, geometry.ties.count);
      for (const y of ys) tieTickHDXF(dxf, colX, colX + colW, y, LAYERS.STIRRUP_TIE.name);
    }
    if (geometry.dowels) {
      for (const cMM of geometry.dowels.centersMM) {
        barDotDXF(dxf, dowelHostX + cMM, footingTopY, geometry.dowels.diaMM, Infinity, LAYERS.REBAR_BOTTOM.name);
      }
    }
    if (col.tag) {
      dxfText(dxf, cx, colTop + COLUMN_TAG_GAP_MM, SUBTITLE_HEIGHT_MM, columnTagEN(geometry.type, i), {
        layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
      });
    }
  });

  // Bottom layer: transverse bars (circles, true cover) + longitudinal
  // bar (line, shifted toward mid-depth) — see this function's own
  // header on the role swap versus renderSectionViewDXF.
  const transYBottom = oy + meta.cover;
  const barRadiusMM = meta.dia / 2;
  const longYBottom = transYBottom + barRadiusMM;
  dxf.addLine(point3d(ox + BAR_LINE_INSET_MM, longYBottom), point3d(ox + wPx - BAR_LINE_INSET_MM, longYBottom), { layerName: LAYERS.REBAR_BOTTOM.name });
  const transXsBottom = computeTransverseXPositionsMMDXF(plan.longMM, meta.cover, meta.dia, meta.spacingLong ?? meta.spacing);
  for (const posMM of transXsBottom) {
    barDotDXF(dxf, ox + posMM, transYBottom, meta.dia, meta.spacingLong ?? meta.spacing, LAYERS.REBAR_BOTTOM.name);
  }
  if (geometry.band) {
    for (const zone of geometry.band.zones) {
      for (const cMM of zone.barCentersMM) {
        barDotDXF(dxf, ox + cMM, transYBottom, geometry.band.diaMM, geometry.band.spacingMM, LAYERS.REBAR_BOTTOM.name);
      }
    }
  }

  if (geometry.mesh) {
    const transYTop = footingTopY - meta.cover;
    const longYTop = transYTop - geometry.mesh.diaMM / 2;
    dxf.addLine(point3d(ox + BAR_LINE_INSET_MM, longYTop), point3d(ox + wPx - BAR_LINE_INSET_MM, longYTop), { layerName: LAYERS.REBAR_TOP.name });
    const transXsTop = computeTransverseXPositionsMMDXF(plan.longMM, meta.cover, geometry.mesh.diaMM, geometry.mesh.spacingMM);
    for (const posMM of transXsTop) {
      barDotDXF(dxf, ox + posMM, transYTop, geometry.mesh.diaMM, geometry.mesh.spacingMM, LAYERS.REBAR_TOP.name);
    }
  }

  // [Bug fix — same root cause as renderSectionViewDXF's own fix above:
  // MARGIN*0.6 put this line's text only 60mm below the footing, and its
  // 150mm Bottom-aligned height put 90mm of it inside the footing,
  // overlapping the bottom bar row.
  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 1.3, ox + wPx, oy - MARGIN_MM * 1.3, `${plan.longLabel} = ${fmt0(plan.longMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox + wPx + MARGIN_MM * 0.5, oy, ox + wPx + MARGIN_MM * 0.5, footingTopY, `D = ${fmt0(meta.D)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  // [Bug fix — confirmed via exact coordinates: D='s text is Middle-
  // aligned at the footing's own vertical MIDPOINT (oy+footingTopY)/2,
  // which for a typical D is close to transYBottom+LABEL_STACK_GAP_MM —
  // this was landing in the same Y range as D's text, not just visually
  // near it. Moved out of the footing entirely, into its own row below
  // it, same as cover already is in renderSectionViewDXF above — one
  // convention for "where does the cover callout go" across both
  // section functions, not two.
  dxfText(dxf, ox + wPx / 2, oy - MARGIN_MM * 1.9, DIM_TEXT_HEIGHT_MM, `cover = ${fmt0(meta.cover)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });
  const longTitleY = oy - MARGIN_MM * 2.7;
  dxfText(dxf, ox + wPx / 2, longTitleY, SUBTITLE_HEIGHT_MM, 'LONGITUDINAL SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  const bottomTextY = longTitleY - SUBTITLE_HEIGHT_MM;
  return { width: wPx, height: maxColTop - oy, bottomTextY };
}

// Local copy of footingDiagram.mjs's computeTransverseXPositionsMM —
// duplicated, not imported: this file and footingDiagram.mjs are
// independent sibling renderers of the same geometry object, neither
// importing from the other anywhere else in this codebase (each imports
// only its own kit), and renderPlanViewDXF below already independently
// re-derives this exact formula inline for the same reason. Suffixed
// DXF only to avoid any accidental name collision; the math is identical.
function computeTransverseXPositionsMMDXF(longMM, coverMM, diaMM, spacingMM) {
  const env = longMM - 2 * coverMM - diaMM;
  const count = Math.max(2, Math.floor(env / spacingMM) + 1);
  const first = coverMM + diaMM / 2;
  const last = longMM - coverMM - diaMM / 2;
  const step = count > 1 ? (last - first) / (count - 1) : 0;
  return Array.from({ length: count }, (_, i) => (count === 1 ? longMM / 2 : first + i * step));
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

  // [Step 20] Top mesh, both directions — REBAR_TOP layer carries the
  // top/bottom distinction here (DXF has no dash-weight convention the
  // way the SVG renderer's stroke-dasharray does; a CAD viewer toggling
  // REBAR-TOP's layer visibility gets the same practical separation).
  if (geometry.mesh) {
    for (const cMM of geometry.mesh.barCentersMM) {
      const y = oy + cMM;
      dxf.addLine(point3d(ox + MESH_LINE_INSET_MM, y), point3d(ox + plan.longMM - MESH_LINE_INSET_MM, y), { layerName: LAYERS.REBAR_TOP.name });
    }
    const env = plan.longMM - 2 * geometry.meta.cover - geometry.mesh.diaMM;
    const count = Math.max(2, Math.floor(env / geometry.mesh.spacingMM) + 1);
    const first = geometry.meta.cover + geometry.mesh.diaMM / 2;
    const last = plan.longMM - geometry.meta.cover - geometry.mesh.diaMM / 2;
    const xs = distributeTicks(ox + first, ox + last, count);
    for (const x of xs) {
      dxf.addLine(point3d(x, oy + MESH_LINE_INSET_MM), point3d(x, oy + plan.shortMM - MESH_LINE_INSET_MM), { layerName: LAYERS.REBAR_TOP.name });
    }
  }

  // [Step 20] Concentration band(s) — dashed REBAR_BOTTOM outline per
  // zone (closedRectDXF already has a DASHED_LTYPE_NAME path, used above
  // for the pedestal footprint outline) plus the zone's own extra
  // transverse bars, additive to the field mesh drawn above it — see
  // computeBandGeometry's own header (footingDiagram.mjs) for why
  // additive, never a replacement.
  if (geometry.band) {
    for (const zone of geometry.band.zones) {
      closedRectDXF(dxf, ox + zone.startMM, oy, zone.endMM - zone.startMM, plan.shortMM, LAYERS.REBAR_BOTTOM.name, { lineType: DASHED_LTYPE_NAME });
      for (const cMM of zone.barCentersMM) {
        const x = ox + cMM;
        dxf.addLine(point3d(x, oy + MESH_LINE_INSET_MM), point3d(x, oy + plan.shortMM - MESH_LINE_INSET_MM), { layerName: LAYERS.REBAR_BOTTOM.name });
      }
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
  // [Step 21] Second marker for the new PRIMARY longitudinal section —
  // horizontal, through the column centerline (B/2) — mirrors
  // renderPlanView's own SVG-side addition; see that comment for why a
  // numeral ('1') rather than a translated/lettered label.
  if (DUAL_SECTION_TYPES.has(geometry.type)) {
    const cy = oy + plan.shortMM / 2;
    const xLo = ox - CUT_LINE_OVERHANG_MM, xHi = ox + plan.longMM + CUT_LINE_OVERHANG_MM;
    dxf.addLine(point3d(xLo, cy), point3d(xHi, cy), { layerName: LAYERS.ANNOTATION.name, lineType: DASHED_LTYPE_NAME });
    dxfText(dxf, xLo - CUT_LABEL_GAP_MM, cy, SUBTITLE_HEIGHT_MM, '1', { layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Right, vAlign: TextVerticalAlignment.Middle });
    dxfText(dxf, xHi + CUT_LABEL_GAP_MM, cy, SUBTITLE_HEIGHT_MM, '1', { layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Middle });
  }

  dimensionLineDXF(dxf, ox, oy + plan.shortMM + MARGIN_MM * 0.6, ox + plan.longMM, oy + plan.shortMM + MARGIN_MM * 0.6, `${plan.longLabel} = ${fmt0(plan.longMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 1.0, oy, ox - MARGIN_MM * 1.0, oy + plan.shortMM, `${plan.shortLabel} = ${fmt0(plan.shortMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

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
  // [Step 21] combined/strip: primary longitudinal section at the
  // origin, secondary transverse section placed beside it (the SVG
  // source's own side-by-side arrangement, per direct request — see
  // that file's DUAL_SECTION_TYPES comment), plan stacked above
  // whichever of the two is taller. isolated/raft: unchanged single
  // section call, exactly as before Step 21.
  const isDual = DUAL_SECTION_TYPES.has(geometry.type);
  const sectionOrigin = { x: 0, y: 0 };
  let sectionsHeight, sectionsWidth, lowestTextY;
  if (isDual) {
    const longSec = renderLongSectionViewDXF(dxf, geometry, sectionOrigin, opts);
    const transOrigin = { x: sectionOrigin.x + longSec.width + (opts.viewGapMM ?? VIEW_GAP_MM) * 0.5, y: sectionOrigin.y };
    const transSec = renderSectionViewDXF(dxf, geometry, transOrigin, { ...opts, secondary: true });
    sectionsWidth = (transOrigin.x - sectionOrigin.x) + transSec.width;
    sectionsHeight = Math.max(longSec.height, transSec.height);
    lowestTextY = Math.min(longSec.bottomTextY, transSec.bottomTextY);
  } else {
    const section = renderSectionViewDXF(dxf, geometry, sectionOrigin, opts);
    sectionsWidth = section.width;
    sectionsHeight = section.height;
    lowestTextY = section.bottomTextY;
  }

  const planOrigin = { x: 0, y: sectionOrigin.y + sectionsHeight + (opts.viewGapMM ?? VIEW_GAP_MM) };
  const plan = renderPlanViewDXF(dxf, geometry, planOrigin, opts);

  const overallWidth = Math.max(plan.width, sectionsWidth);
  const titleY = planOrigin.y + plan.height + MARGIN_MM * 2.2;
  dxfText(dxf, overallWidth / 2, titleY, TITLE_HEIGHT_MM, FOOTING_TITLE_EN[geometry.type], {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  // [Bug fix — mirrors the SVG source's own Step 14.3 dynamic
  // captionBottomY fix] Was a fixed sectionOrigin.y - MARGIN*2.4,
  // independent of how far the section view(s)' own title/dimension text
  // actually reached — collided with that text whenever the stack below
  // the footing was taller than whoever picked that fixed offset
  // anticipated (a long bar-spec string; two side-by-side sections each
  // with their own title). Anchored to the actual lowest text edge
  // instead, so a taller stack pushes the caption down with it rather
  // than being overlapped by it.
  const captionY = lowestTextY - MARGIN_MM * 0.7;
  dxfText(dxf, overallWidth / 2, captionY, CAPTION_HEIGHT_MM, CAPTION_EN, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return dxf.stringify();
}
