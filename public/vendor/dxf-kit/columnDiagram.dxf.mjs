// columnDiagram.dxf.mjs
// DXF render path for the column reinforcement diagram — parallel to,
// and entirely separate from, renderColumnDiagramSVG() in
// columnDiagram.mjs. Same placement rationale as shearWallDiagram.dxf.mjs
// (see that file's own header): a separate file keeps @tarikjabiri/dxf
// out of the module graph for ordinary /diagram or /rebar SVG requests.
//
// computeColumnDiagramGeometry() is consumed exactly as-is, imported from
// columnDiagram.mjs with zero modification to that file. This module only
// renders; it never validates or computes.
//
// v1 scope exclusions carried over unchanged from the prompt (same as
// shearWallDiagram.dxf.mjs): no Arabic labels (English only, hardcoded),
// no schedule table, no multi-line caption. The short view-level
// annotations columnDiagram.mjs draws with NO caption/schedule role (tie
// hook note, tie Ø@spacing note) ARE kept — same treatment
// shearWallDiagram.dxf.mjs already gave its own analogous "support-label"
// text; only the big disclaimer paragraph and the BBS table are dropped.
//
// NEW LAYER FLAGGED FOR CONFIRMATION (session-protocol step 4): this
// element's lap-splice zone (renderElevationView's inline-styled
// <rect fill="#fff3cd" fill-opacity="0.55" stroke="#b8860b" .../>, no CSS
// class) is not in the v1 prompt's pre-scanned layer table. Added as
// LAP-ZONE (hex #b8860b, taken directly from that literal stroke
// attribute) to structuralDrawingDxfKit.mjs's shared LAYERS object — same
// table PILE/CRITICAL-PERIMETER/etc. already live in for other elements —
// rather than defined locally here, so defineDxfLayers() stays the single
// place that creates every layer used anywhere. Purely additive: one new
// LAYERS key, no existing key touched, so shearWallDiagram.dxf.mjs's own
// defineDxfLayers()-driven layer set is unaffected (see that file's own
// test — its per-key layer-existence loop iterates whatever LAYERS
// currently contains, so a new key cannot break an existing assertion
// there; verified by inspection of defineDxfLayers's implementation, not
// re-run in this session since shearWallDiagram.mjs's SVG source was not
// provided here). Fill/opacity/dash are dropped, same v1 HATCH-exclusion
// policy already applied to CONCRETE-OUTLINE and to shearWallDiagram's
// own boundary-element rects — outline only.

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

// Duplicated from columnDiagram.mjs — that file does not export this (an
// unexported module-level const used only inside its own render
// function), and this file must not be edited to add an export (zero
// modification to the existing file, per session scope). Flagged here
// explicitly, mirroring shearWallDiagram.dxf.mjs's own MAX_MESH_COLS/
// MAX_DRAWN_TIES precedent, so a future change to the source value does
// not silently desync: columnDiagram.mjs line 148 at time of writing
// ("const MAX_DRAWN_TIES_PER_COLUMN = 24; // matches distributeTicks' own
// hard cap").
const MAX_DRAWN_TIES_PER_COLUMN = 24;

// Layout conventions — none of these come from geometry or from the
// prompt; each is a chosen default for real-mm placement the SVG path
// never needed (it drew everything inside a fixed pixel canvas instead).
// All overridable via opts, all named so they're auditable. MARGIN_MM/
// VIEW_GAP_MM/TITLE_HEIGHT_MM/SUBTITLE_HEIGHT_MM/DIM_TEXT_HEIGHT_MM reuse
// shearWallDiagram.dxf.mjs's own values verbatim — same nominal plot
// scale, same role, no reason found to diverge for this element.
const MARGIN_MM = 300; // gutter around each view for dimension lines/labels
const VIEW_GAP_MM = 1000; // real-mm gap between adjacent views (section -> tie detail -> elevation), model space
const TITLE_HEIGHT_MM = 220; // sheet title text height
const SUBTITLE_HEIGHT_MM = 150; // view titles, zone labels, mark tags, tie/spacing annotations
const DIM_TEXT_HEIGHT_MM = 150; // dimension line label text height

function fmt0(mm) {
  return String(Math.round(mm));
}

// Pairwise-minimum bar-dot spacing (see the units-decision note at the
// top of structuralDrawingDxfKit.mjs). shearWallDiagram's regular mesh
// grid could take its safe pitch straight from distributeTicks' own
// output; computeColumnBarPositions (columnDiagram.mjs) instead
// distributes bars around a RECTANGULAR PERIMETER with a proportional
// top/bottom vs left/right split (verified by reading that function's
// source directly — see its own header comment), so the horizontal-edge
// and vertical-edge pitches are generally DIFFERENT and there is no
// single closed-form "pitch" to reuse. The real, verifiable safe value is
// the actual minimum center-to-center distance over every pair of drawn
// bar positions — O(n^2), n<=MAX_BAR_COUNT=40 (columnDiagram.mjs) so
// <=780 pairs, trivial cost. This is exactly the definition
// test_columnDiagramDXF.mjs's own assertNoCircleOverlap uses to VERIFY
// the render output, so derivation and verification share one definition
// of "spacing" by construction — kept local to this file (not promoted
// to the shared kit) per the prompt's own "no automatic expansion beyond
// the element this session is scoped to" rule; promote it if/when a
// future non-grid element needs the same pattern.
function minPairwiseDistanceMM(positions) {
  let min = Infinity;
  for (let i = 0; i < positions.length; i++) {
    for (let j = i + 1; j < positions.length; j++) {
      const d = Math.hypot(positions[i].xMM - positions[j].xMM, positions[i].yMM - positions[j].yMM);
      if (d > 0 && d < min) min = d;
    }
  }
  return min;
}

function renderCrossSectionDXF(dxf, geometry, origin, opts) {
  const { widthMM, depthMM, verticalBars, ties } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, widthMM, depthMM, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, ox + ties.outer.x, oy + ties.outer.y, ties.outer.w, ties.outer.h, LAYERS.STIRRUP_TIE.name);

  const pitch = minPairwiseDistanceMM(verticalBars.positions);
  for (const p of verticalBars.positions) {
    barDotDXF(dxf, ox + p.xMM, oy + p.yMM, verticalBars.dia, pitch, LAYERS.REBAR_TOP.name);
  }

  barMarkTagDXF(dxf, ox + widthMM + MARGIN_MM * 0.8, oy + depthMM / 2, `${verticalBars.count}\u00d8${fmt0(verticalBars.dia)}`, LAYERS.MARK_TAGS.name);

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + widthMM, oy - MARGIN_MM * 0.6, `${fmt0(widthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + depthMM, `${fmt0(depthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + widthMM / 2, oy + depthMM + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'CROSS SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: widthMM, height: depthMM };
}

function renderTieDetailDXF(dxf, geometry, origin, opts) {
  const { ties } = geometry;
  const { x: ox, y: oy } = origin;
  const w = ties.outer.w, h = ties.outer.h;

  // Plain sharp-corner outline — the SVG source's rx="3" corner rounding
  // has no real structural meaning (a 3px cosmetic nudge) and would need
  // an ARC/bulge segment this v1 kit does not implement (no ARC anywhere
  // in this file, matching the units-decision note's own "simplest
  // available geometric composition" scope for this pass).
  closedRectDXF(dxf, ox, oy, w, h, LAYERS.STIRRUP_TIE.name);

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + w, oy - MARGIN_MM * 0.6, `${fmt0(w)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + h, `${fmt0(h)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // ties.dia label + hook note: two SEPARATE standalone TEXT entities in
  // the SVG source (class="dim-label" and class="sheet-caption"
  // respectively — NOT part of a dimensionLine() call), placed below the
  // rect in that same top-to-bottom order. Layers follow those classes'
  // table-confirmed mapping (DIMENSIONS, ANNOTATION) directly — no new
  // assignment needed for either.
  const dimLineY = oy - MARGIN_MM * 0.6;
  const diaLabelY = dimLineY - SUBTITLE_HEIGHT_MM * 1.2; // clear of the dim line's own LABEL_GAP_MM-offset label sitting above dimLineY
  const hookNoteY = diaLabelY - SUBTITLE_HEIGHT_MM * 1.2;
  dxfText(dxf, ox + w / 2, diaLabelY, DIM_TEXT_HEIGHT_MM, `\u00d8${fmt0(ties.dia)}mm`, {
    layerName: LAYERS.DIMENSIONS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });
  dxfText(dxf, ox + w / 2, hookNoteY, SUBTITLE_HEIGHT_MM * 0.8, 'add standard hook length per code - not shown', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  dxfText(dxf, ox + w / 2, oy + h + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'TIE DETAIL', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: w, height: h };
}

function renderElevationViewDXF(dxf, geometry, origin, opts) {
  const { widthMM, heightMM, ties, lapSpliceMM, verticalBars } = geometry;
  const { x: ox, y: oy } = origin;
  // Vertical convention (matches shearWallDiagram.dxf.mjs's own elevation
  // note): oy = column BASE, oy+heightMM = column TOP. The SVG source
  // uses a downward-y screen convention where botY (= topY+h) is the
  // base — verified directly (lapY = botY - lapH sits the lap-splice
  // rect against botY, i.e. against the base, matching real column
  // practice of lapping just above a floor/foundation level, not at
  // mid-height or top). This file's upward-y equivalent of "against the
  // base" is therefore the rect spanning [oy, oy+lapSpliceMM] — NOT
  // [oy+heightMM-lapSpliceMM, oy+heightMM], which would silently place it
  // at the top instead (the exact backwards-placement bug class
  // shearWallDiagram.dxf.mjs's own zone-label comment already flags and
  // corrects for its own case) — checked explicitly in this file's test.

  closedRectDXF(dxf, ox, oy, widthMM, heightMM, LAYERS.CONCRETE_OUTLINE.name);

  const drawTies = Math.min(ties.count, MAX_DRAWN_TIES_PER_COLUMN);
  for (const ty of distributeTicks(oy, oy + heightMM, drawTies)) {
    tieTickHDXF(dxf, ox, ox + widthMM, ty, LAYERS.STIRRUP_TIE.name);
  }

  // Two representative outermost vertical bar lines, full height — same
  // 'bar-bottom' class (REBAR-BOTTOM layer) the SVG source uses (verified
  // directly: renderElevationView's two <line class="bar-bottom"/>
  // elements) even though the cross-section's own bar dots are
  // 'bar-dot-column' (REBAR-TOP) — this asymmetry is the SVG source's own
  // existing convention, not something to "fix" here. Inset is the FIRST
  // corner bar's real xMM offset from the column face
  // (verticalBars.positions[0] is always a corner by construction — see
  // computeColumnBarPositions' point-push order in columnDiagram.mjs, and
  // insetX===insetY there), not the SVG's arbitrary 4px cosmetic nudge,
  // which has no real-mm equivalent to port.
  const barLineInsetMM = verticalBars.positions[0].xMM;
  dxf.addLine(point3d(ox + barLineInsetMM, oy), point3d(ox + barLineInsetMM, oy + heightMM), { layerName: LAYERS.REBAR_BOTTOM.name });
  dxf.addLine(point3d(ox + widthMM - barLineInsetMM, oy), point3d(ox + widthMM - barLineInsetMM, oy + heightMM), { layerName: LAYERS.REBAR_BOTTOM.name });

  barMarkTagDXF(dxf, ox + widthMM + MARGIN_MM * 0.8, oy + heightMM - MARGIN_MM * 0.5, `${verticalBars.count}\u00d8${fmt0(verticalBars.dia)}`, LAYERS.MARK_TAGS.name);

  if (lapSpliceMM != null) {
    const lapBottomMM = oy;
    const lapTopMM = oy + lapSpliceMM;
    closedRectDXF(dxf, ox, lapBottomMM, widthMM, lapSpliceMM, LAYERS.LAP_ZONE.name);
    dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, lapBottomMM, ox - MARGIN_MM * 0.6, lapTopMM, `${fmt0(lapSpliceMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
    dxfText(dxf, ox + widthMM + MARGIN_MM * 0.8, (lapBottomMM + lapTopMM) / 2, SUBTITLE_HEIGHT_MM, 'LAP SPLICE ZONE', {
      layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Middle,
    });
  }

  dimensionLineDXF(dxf, ox + widthMM + MARGIN_MM * 2.2, oy, ox + widthMM + MARGIN_MM * 2.2, oy + heightMM, `H = ${(heightMM / 1000).toFixed(2)}m`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // "support-label" in the SVG source (columnDiagram.mjs's tie Ø@spacing
  // note below the elevation) has no confirmed CSS rule, same as
  // shearWallDiagram.dxf.mjs's own identically-named case — placed on
  // ANNOTATION as the same already-established flagged default, not a
  // new decision.
  dxfText(dxf, ox + widthMM / 2, oy - MARGIN_MM * 0.6, SUBTITLE_HEIGHT_MM, `\u00d8${fmt0(ties.dia)}@${fmt0(ties.spacing)}`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  dxfText(dxf, ox + widthMM / 2, oy + heightMM + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'ELEVATION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: widthMM, height: heightMM };
}

export function renderColumnDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'column') {
    throw new DiagramError('BAD_PARAM', 'renderColumnDiagramDXF expects a geometry object from computeColumnDiagramGeometry() (type "column").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const gap = opts.viewGapMM ?? VIEW_GAP_MM;

  const sectionOrigin = { x: 0, y: 0 };
  const section = renderCrossSectionDXF(dxf, geometry, sectionOrigin, opts);

  const tieOriginX = sectionOrigin.x + section.width + gap;
  const tie = renderTieDetailDXF(dxf, geometry, { x: tieOriginX, y: 0 }, opts);

  const elevOriginX = tieOriginX + tie.width + gap;
  const elev = renderElevationViewDXF(dxf, geometry, { x: elevOriginX, y: 0 }, opts);

  // All three views share y=0 as their own bottom/origin (elevation's
  // y=0 is physically the column base, load-bearing on the vertical
  // convention noted above; cross section/tie detail have no "up"
  // semantic of their own, so sharing the same reference is the simplest
  // consistent choice, not a physical requirement for those two). Because
  // heightMM (up to 12000mm) can vastly exceed widthMM/depthMM (up to
  // 3000mm), the sheet title below can end up floating well above the
  // two shorter views at typical inputs — a real-mm CAD viewer pans/zooms
  // to it same as everything else here, per this whole file's own
  // units-decision philosophy; not a defect.
  const overallHeight = Math.max(section.height, tie.height, elev.height);
  const overallWidth = elevOriginX + elev.width + MARGIN_MM * 3 - sectionOrigin.x; // +3xMARGIN clears the height dim line/mark tag to the right of elevation; approximate, cosmetic only (title centering), same tolerance shearWallDiagram.dxf.mjs's own overallWidth already accepts
  dxfText(dxf, sectionOrigin.x + overallWidth / 2, overallHeight + MARGIN_MM * 2.2, TITLE_HEIGHT_MM, `COLUMN ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
