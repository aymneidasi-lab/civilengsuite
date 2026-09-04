// retainingWallDiagram.dxf.mjs
// DXF render path for the cantilever retaining-wall typical-section
// reinforcement diagram — parallel to, and entirely separate from,
// renderRetainingWallDiagramSVG() in retainingWallDiagram.mjs. Separate
// file per the same session-confirmed rule shearWallDiagram.dxf.mjs
// follows: an ordinary /diagram or /rebar SVG request must never pull
// @tarikjabiri/dxf into the Worker's module graph.
//
// computeRetainingWallDiagramGeometry() is consumed exactly as-is,
// imported from retainingWallDiagram.mjs with zero modification to that
// file. This module only renders; it never validates or computes.
//
// v1 scope exclusions (English-only hardcoded title, no schedule table,
// no multi-line caption) carried over unchanged from the shearWallDiagram
// session. One additional exclusion specific to this element: the SVG
// source's retained-backfill block (url(#soilHatch) rect over the heel)
// is NOT drawn here. That block is HATCH-only in purpose (its own input-
// contract comment calls it "illustrative only"; no dimension line or
// bar position anywhere in computeRetainingWallDiagramGeometry depends
// on soilHeightMM), and HATCH fill is already excluded from v1 scope by
// the general prompt. An unfilled outline in its place would misrepresent
// a fill-only element as a real boundary, so it is omitted entirely
// rather than half-drawn.
//
// Layer-sharing note (verified from source, not assumed): every barDot()
// call in retainingWallDiagram.mjs's renderSectionView passes the SAME
// class token 'wall' (-> bar-dot-wall, i.e. LAYERS.REBAR_BOTTOM, per the
// v1-prompt's shared layer table), regardless of which of the four bar
// groups (stemMainBars/stemDistBars/baseBottomBars/baseTopBars) the dot
// belongs to. Only the connecting LINEs differentiate REBAR_BOTTOM
// ('bar-bottom': stem-main line, base-bottom line) from REBAR_TOP
// ('bar-top': base-top line only) — the four bar groups' DOTS never do.
// This is a genuinely different situation from shearWallDiagram, where
// every same-layer circle came from ONE bar group (mesh.vertical) drawn
// twice (near/far face). Here, four INDEPENDENTLY-parameterized groups
// (different dia/spacing each) land on one shared layer, so the
// dual-axis "measure the real spacing, take the smaller" rule the v1
// prompt requires is generalized below to a full nearest-neighbor scan
// across every dot destined for REBAR_BOTTOM, computed from actual
// plotted coordinates before any circle is drawn — not a per-group
// along-spacing formula, which (verified by hand for the joint region,
// where the stem-main bottom dot and the stem-distribution bars' bottom
// dot both land at the same y) is not guaranteed to catch the closest
// pair when independently-sized groups meet at a shared point like the
// stem/base joint.

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
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Duplicated from retainingWallDiagram.mjs — that file does not export
// this (an unexported module-level const used only inside its own
// renderSectionView), and this file must not be edited to add an export
// (zero modification to the existing file, per session scope). Flagged
// here explicitly so a future change to the source value does not
// silently desync: retainingWallDiagram.mjs line 156 at time of writing.
const MAX_DRAWN_DIST_BARS = 14;

// Layout conventions — none of these come from geometry; each is a
// chosen default for real-mm placement the SVG path never needed (fixed
// pixel canvas instead). All overridable via opts, all named so they're
// auditable, matching shearWallDiagram.dxf.mjs's own convention.
const DIM_CHAIN_GAP_MM = 250; // gap from the base's bottom edge to the inner (toe|stem|heel) dimension row
const DIM_OVERALL_GAP_MM = 600; // gap from the base's bottom edge to the outer overall-length row (clears the inner row's own tick + label)
const COVER_NOTE_GAP_MM = 200; // extra gap below the outer dimension row for the cover note text
const LEFT_DIM_OFFSET_MM = 300; // horizontal offset left of x=0 for the stem-height dimension line
const RIGHT_DIM_OFFSET_MM = 300; // horizontal offset right of the base's right edge for the base-thickness dimension line
const TAG_LABEL_COL_MM = 900; // horizontal offset right of the base's right edge, to the mark-tag group-name label column
const TAG_BUBBLE_COL_MM = 1500; // horizontal offset right of the base's right edge, to the mark-tag bubble column (clears "BASE BOTTOM", the longest label, at SUBTITLE_HEIGHT_MM — convention, not measured)
const TAG_ROW_GAP_MM = 500; // vertical spacing between stacked mark-tag rows
const SECTION_TITLE_GAP_MM = 200; // gap from the stem's top edge to the "SECTION" view-title baseline
const SHEET_TITLE_GAP_MM = 550; // gap from the stem's top edge to the sheet-title baseline (clears the view title's own line)
const TITLE_HEIGHT_MM = 220; // sheet title text height (matches shearWallDiagram.dxf.mjs)
const SUBTITLE_HEIGHT_MM = 150; // view title / tag group-name label text height (matches shearWallDiagram.dxf.mjs)
const DIM_TEXT_HEIGHT_MM = 150; // dimension label text height (matches shearWallDiagram.dxf.mjs)
const NOTE_TEXT_HEIGHT_MM = 120; // cover note text height — smaller than a dimension label, it is a note, not a measurement

function fmt0(mm) {
  return String(Math.round(mm));
}

// Real (not schema-floor) nearest-neighbor distance for every point in a
// shared point cloud, computed from actual plotted coordinates. This is
// the per-element "measure the real spacing on THIS drawing" check the
// v1 prompt's units-decision requires, generalized from shearWallDiagram's
// two-axis (along-line / near-far) formula to an n-way scan, because here
// up to four independently-parameterized bar groups can land arbitrarily
// close to one another at the stem/base joint, not just two faces of one
// group. d===0 pairs (exact coincident centers) are skipped, same as
// test_shearWallDiagramDXF.mjs's own overlap check — a coincident point
// is not a spacing case.
function nearestNeighborPitchesMM(points) {
  return points.map((p, i) => {
    let min = Infinity;
    for (let j = 0; j < points.length; j++) {
      if (j === i) continue;
      const d = Math.hypot(p.x - points[j].x, p.y - points[j].y);
      if (d > 0 && d < min) min = d;
    }
    return min;
  });
}

function renderSectionViewDXF(dxf, geometry, origin, opts) {
  const {
    stem, base, coverMM,
    stemMainBars, stemDistBars, baseBottomBars, baseTopBars,
  } = geometry;
  const { x: ox, y: oy } = origin;
  const hasHeel = base.heelLengthMM > 0;
  const hasToe = base.toeLengthMM > 0;

  const stemX = ox + base.toeLengthMM;
  const jointY = oy + base.thicknessMM; // top of base = bottom of stem, single shared reference level
  const stemTopY = jointY + stem.heightMM;
  const baseRightX = ox + base.lengthMM;

  // ── Concrete outline: base slab + stem, as two independent closed
  // rectangles (matches the SVG source's own independent <rect> pair —
  // no stem-to-base fillet/haunch is modeled there either). ──────────
  closedRectDXF(dxf, ox, oy, base.lengthMM, base.thicknessMM, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, stemX, jointY, stem.thicknessMM, stem.heightMM, LAYERS.CONCRETE_OUTLINE.name);

  // ── Stem main bars (vertical, soil-side/back face) ──────────────────
  const mainX = stemX + stem.thicknessMM - coverMM - stemMainBars.dia / 2;
  const mainBotY = jointY;
  const mainTopY = jointY + stem.heightMM - coverMM - stemMainBars.dia / 2;

  // ── Stem distribution bars (front face, one dot per level up the
  // stem — the one group in this element with a genuine in-plane count,
  // capped the same way the SVG source caps its own drawn dot count). ──
  const distX = stemX + coverMM + stemDistBars.dia / 2;
  const distBotY = jointY;
  const distTopY = jointY + stem.heightMM - coverMM - stemDistBars.dia / 2;
  const drawDistCount = Math.min(stemDistBars.count, MAX_DRAWN_DIST_BARS);
  const distYs = distributeTicks(distBotY, distTopY, drawDistCount);

  // ── Base bottom bars (toe region) ───────────────────────────────────
  const bBotY = oy + coverMM + baseBottomBars.dia / 2;
  const bBotFromX = ox + coverMM;
  const bBotToX = stemX + stem.thicknessMM;

  // ── Base top bars (heel region), only when a heel exists ───────────
  const bTopY = jointY - coverMM - baseTopBars.dia / 2;
  const bTopFromX = stemX;
  const bTopToX = baseRightX - coverMM;

  // ── Lines (these DO differentiate REBAR_BOTTOM vs REBAR_TOP; only
  // the dots below share one layer regardless of group — see file
  // header) ────────────────────────────────────────────────────────────
  dxf.addLine(point3d(mainX, mainBotY), point3d(mainX, mainTopY), { layerName: LAYERS.REBAR_BOTTOM.name });
  dxf.addLine(point3d(bBotFromX, bBotY), point3d(bBotToX, bBotY), { layerName: LAYERS.REBAR_BOTTOM.name });
  if (hasHeel) {
    dxf.addLine(point3d(bTopFromX, bTopY), point3d(bTopToX, bTopY), { layerName: LAYERS.REBAR_TOP.name });
  }

  // ── Dots: gather every REBAR_BOTTOM-bound center FIRST, across all
  // four bar groups, then derive each one's drawn radius from its own
  // real nearest-neighbor distance in that shared set (see file header
  // and nearestNeighborPitchesMM's own docstring). ───────────────────
  const dots = [
    { x: mainX, y: mainBotY, dia: stemMainBars.dia },
    { x: mainX, y: mainTopY, dia: stemMainBars.dia },
    ...distYs.map((y) => ({ x: distX, y, dia: stemDistBars.dia })),
    { x: bBotFromX, y: bBotY, dia: baseBottomBars.dia },
    { x: bBotToX, y: bBotY, dia: baseBottomBars.dia },
  ];
  if (hasHeel) {
    dots.push({ x: bTopFromX, y: bTopY, dia: baseTopBars.dia });
    dots.push({ x: bTopToX, y: bTopY, dia: baseTopBars.dia });
  }
  const pitches = nearestNeighborPitchesMM(dots);
  dots.forEach((d, i) => barDotDXF(dxf, d.x, d.y, d.dia, pitches[i], LAYERS.REBAR_BOTTOM.name));

  // ── Dimension chain: toe | stem-width | heel (inner row), overall
  // base length (outer row), stem height (left), base thickness
  // (right). All six values come straight from geometry; none are
  // re-derived or guessed. ────────────────────────────────────────────
  const chainY = oy - DIM_CHAIN_GAP_MM;
  if (hasToe) {
    dimensionLineDXF(dxf, ox, chainY, stemX, chainY, `${fmt0(base.toeLengthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  }
  dimensionLineDXF(dxf, stemX, chainY, stemX + stem.thicknessMM, chainY, `${fmt0(stem.thicknessMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  if (hasHeel) {
    dimensionLineDXF(dxf, stemX + stem.thicknessMM, chainY, baseRightX, chainY, `${fmt0(base.heelLengthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  }
  const overallY = oy - DIM_OVERALL_GAP_MM;
  dimensionLineDXF(dxf, ox, overallY, baseRightX, overallY, `${fmt0(base.lengthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dimensionLineDXF(dxf, ox - LEFT_DIM_OFFSET_MM, jointY, ox - LEFT_DIM_OFFSET_MM, stemTopY, `${fmt0(stem.heightMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, baseRightX + RIGHT_DIM_OFFSET_MM, oy, baseRightX + RIGHT_DIM_OFFSET_MM, jointY, `${fmt0(base.thicknessMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // Cover applies uniformly to all four bar groups (both stem faces,
  // both base faces) — a single location-agnostic note reads more
  // correctly than a dimension line anchored at one arbitrary spot.
  dxfText(dxf, ox, overallY - COVER_NOTE_GAP_MM, NOTE_TEXT_HEIGHT_MM, `COVER = ${fmt0(coverMM)}mm (TYP.)`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Top,
  });

  // ── Mark-tag callouts: one per bar group, self-contained (dia@spacing
  // directly in the bubble text, same convention shearWallDiagram.dxf.mjs
  // established) since the schedule table that would otherwise carry
  // this is v1-excluded. Stacked to the right; floating, no leader line
  // — matching shearWallDiagram.dxf.mjs's own tag, which also omits
  // opts.leaderTo. Stack anchored so its lowest row never drops below
  // the joint even for a minimum-height stem. ────────────────────────
  const tagRows = [
    { label: 'STEM MAIN', dia: stemMainBars.dia, spacing: stemMainBars.spacing },
    { label: 'STEM DIST', dia: stemDistBars.dia, spacing: stemDistBars.spacing },
    { label: 'BASE BOTTOM', dia: baseBottomBars.dia, spacing: baseBottomBars.spacing },
  ];
  if (hasHeel) tagRows.push({ label: 'BASE TOP', dia: baseTopBars.dia, spacing: baseTopBars.spacing });

  const tagTopY = Math.max(stemTopY, jointY + tagRows.length * TAG_ROW_GAP_MM);
  tagRows.forEach((row, i) => {
    const y = tagTopY - i * TAG_ROW_GAP_MM;
    dxfText(dxf, baseRightX + TAG_LABEL_COL_MM, y, SUBTITLE_HEIGHT_MM, row.label, {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Middle,
    });
    barMarkTagDXF(dxf, baseRightX + TAG_BUBBLE_COL_MM, y, `\u00d8${fmt0(row.dia)}@${fmt0(row.spacing)}`, LAYERS.MARK_TAGS.name);
  });

  dxfText(dxf, ox + base.lengthMM / 2, stemTopY + SECTION_TITLE_GAP_MM, SUBTITLE_HEIGHT_MM, 'SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return {
    width: base.lengthMM, height: (stem.heightMM + base.thicknessMM),
    baseRightX, stemTopY, jointY,
  };
}

export function renderRetainingWallDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'retainingWall') {
    throw new DiagramError('BAD_PARAM', 'renderRetainingWallDiagramDXF expects a geometry object from computeRetainingWallDiagramGeometry() (type "retainingWall").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const origin = { x: 0, y: 0 };
  const section = renderSectionViewDXF(dxf, geometry, origin, opts);

  dxfText(dxf, origin.x + section.width / 2, section.stemTopY + SHEET_TITLE_GAP_MM, TITLE_HEIGHT_MM, `RETAINING WALL ${geometry.id} - TYPICAL SECTION`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
