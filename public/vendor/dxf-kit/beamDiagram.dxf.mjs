// beamDiagram.dxf.mjs
// DXF render path for the beam reinforcement schematic — parallel to,
// and entirely separate from, renderBeamDiagramSVG() in beamDiagram.mjs.
// Same placement rationale as every sibling *.dxf.mjs: an ordinary
// /diagram or /rebar SVG request must never pull @tarikjabiri/dxf into
// the Worker's module graph — only a real DXF-export request does.
//
// computeBeamDiagramGeometry() is consumed exactly as returned — zero
// modification to beamDiagram.mjs, zero re-derivation of any value it
// already provides (each longitudinal group's own yFromTopMM, each
// section's own bars[].xMM/yFromTopMM — already positioned by
// layoutSectionBars — all read directly).
//
// SCOPE DECISION (verified against the source before writing this, not
// assumed): beamDiagram.mjs exports TWO independent render paths —
// renderBeamDiagramSVG's default 'rebarDiagram' mode (elevation +
// cross-section row + schedule) and a wholly separate 'beamWorkshop'
// mode (renderBeamWorkshopSVG, built on computeBeamWorkshopExtras() —
// install-sequence numbering, shape-letter cross-references, lap-splice
// zones, extra bar-count-change section cuts). computeBeamWorkshopExtras
// is never called by, and geometry.lapZones is never read by,
// renderElevation/renderSections/buildScheduleRows (grep-verified: every
// lapZones reference in the source lives inside
// computeBeamWorkshopExtras/computeWorkshopSections/renderWorkshopElevation/
// buildWorkshopScheduleRows only). This file therefore covers ONLY the
// 'rebarDiagram' mode — same "typical-section schematic, not every mode"
// scope boundary every sibling *.dxf.mjs already documents (e.g.
// strapFootingDiagram.dxf.mjs's own footing-pedestal/dowel exclusions).
// beamWorkshop-mode DXF export is out of v1 scope for this element,
// stated on the sheet's own caption below, not silently dropped.
//
// v1 scope exclusions carried over unchanged from the master prompt: no
// Arabic labels (English only, hardcoded, not opts.lang-driven), no
// HATCH (support hatching omitted — same "outline only" treatment every
// sibling gives a concreteHatch/soilHatch-filled SVG rect), no
// scheduleTable-as-DXF-TABLE (the SVG source's own bar-bending-schedule
// rows have no on-sheet text equivalent here — every bar/zone this
// module draws is still real, individually positioned geometry, and
// each longitudinal-bar/stirrup-zone mark tag still carries its own
// dia/count/spacing callout on the elevation itself).
//
// New-for-this-element decisions, disclosed per the master prompt's own
// protocol:
//   - "support-label" (the S1/W1/etc. tag drawn under each support) has
//     an ALREADY-established project-wide placement: every prior element
//     that draws a class named "support-label" (columnDiagram,
//     circularColumnDiagram, shearWallDiagram, pileCapDiagram,
//     slabOpeningDiagram, stairDiagram, basementWallDiagram) places it on
//     ANNOTATION, each flagged in its own session as "no confirmed CSS
//     rule". beamDiagram.mjs is the FIRST element where that class name
//     genuinely DOES carry a real CSS rule (`fill:#333`, i.e. exactly
//     `#333333` — verified directly in this file's own <style> block,
//     line ~691) AND is used for a semantically different thing (the
//     support's own ID tag, not a Ø@spacing callout like every other
//     element's usage of the same class name). #333333 happens to equal
//     DIMENSIONS' own hex exactly, which would be an equally defensible
//     placement by color-match precedent — but kept on ANNOTATION
//     instead, for consistency with the established multi-element
//     decision for this exact class name (a support ID tag is an
//     annotation/label, not a measured dimension value; fragmenting one
//     class name across two layers by per-element coincidence would
//     undermine the whole point of a shared class-to-layer table).
//   - Caption text: the three most recently built elements
//     (footingDiagram, trapezoidalFootingDiagram, strapFootingDiagram)
//     established including a single-line ANNOTATION caption; the
//     earlier eight did not. Followed here as the current-direction
//     precedent. Text is NOT a verbatim port of beamDiagram.mjs's own
//     L.en.caption — that string references the schedule table's
//     "(extent)" suffix convention, which has no on-sheet equivalent
//     here (schedule-as-DXF-TABLE is v1-excluded) — rewritten below
//     (CAPTION_EN) to describe what THIS sheet actually shows, plus an
//     explicit note that beamWorkshop-mode content is not included here.
//   - No other CSS class this render path actually uses is new: bar-top/
//     bar-bottom/bar-dot-top/bar-dot-bottom/stirrup-tick/concrete-outline/
//     support-outline/mark-tag-circle/mark-tag-text/view-title/dim-line/
//     dim-tick/dim-label/beam-title (sheet title, same role as every
//     sibling's own "sheet-title"->ANNOTATION mapping) are all
//     already-listed, already-color-assigned entries in the master
//     table. `.zone-label` is defined in beamDiagram.mjs's own <style>
//     block but never actually applied to any element inside
//     renderElevation/renderSections (grep-verified) — dead CSS in
//     rebarDiagram mode, so it needs no layer decision here.
//   - No new LAYERS entry and no new shared kit function were needed for
//     this element — every primitive below (closedRectDXF, barDotDXF,
//     barMarkTagDXF, stirrupTickVDXF, dimensionLineDXF, dxfText,
//     distributeTicks, minPairwiseDistanceMM) already exists in
//     structuralDrawingDxfKit.mjs and is used as-is.
//   - stirrupTickVDXF (added for corbelDiagram) is reused here rather
//     than a new tick primitive: verified beamDiagram.mjs's own
//     stirrupTick(xPx,yTopPx,yBottomPx) (imported from
//     structuralDrawingKit.mjs, the SAME shared function corbelDiagram's
//     SVG source uses) draws one vertical main line + horizontal end-cap
//     hashes at both ends — the exact shape stirrupTickVDXF already
//     implements, correct for a beam's stirrup legs (a horizontally-
//     running member, ties/legs crossing its vertical depth).

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
  MARK_TAG_RADIUS_MM,
  stirrupTickVDXF,
  dimensionLineDXF,
  distributeTicks,
  minPairwiseDistanceMM,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Duplicated from beamDiagram.mjs — that file does not export this (an
// unexported module-level const used only inside its own renderElevation),
// and this file must not be edited to add an export (zero modification to
// the existing file, per session scope). Flagged here explicitly so a
// future change to the source value does not silently desync:
// beamDiagram.mjs's own line 129 at time of writing.
const MAX_DRAWN_TIES_PER_ZONE = 20;

// Layout conventions — none of these come from geometry or from the SVG
// source (which drew everything inside a fixed pixel canvas instead);
// each is a chosen default for real-mm placement, named so it's
// auditable, matching every sibling *.dxf.mjs's own convention.
const MARGIN_MM = 300; // gutter around a view for its own dimension lines/labels — same value every sibling uses
const VIEW_GAP_MM = 1000; // real-mm gap between the elevation view and the section-cuts row, model space — same value every sibling's own inter-view gap uses
const SECTION_GAP_MM = 500; // real-mm gap between adjacent section-cut boxes within the bottom row — smaller than VIEW_GAP_MM since these boxes read as one row, not two independent views
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view titles (ELEVATION/SECTION), mark tags, support tags
const DIM_TEXT_HEIGHT_MM = 150;
const CAPTION_HEIGHT_MM = 115;
const SUPPORT_OVERHANG_MM = 200; // how far a support block is drawn past the beam's own top/bottom face on each side — the SVG source's own analogous overhang (34px) has no fixed physical meaning to convert; chosen as a fixed schematic real-mm value, same "named convention default" pattern as this kit's own TICK_CAP_MM
const SUPPORT_TAG_CLEAR_MM = 180; // horizontal clearance a longitudinal-bar mark tag is shifted by when its default midpoint would otherwise land inside a support's own real x-range — real-mm analogue of the SVG source's own 18px shift constant
const MARK_TAG_OFFSET_MM = MARK_TAG_RADIUS_MM + 70; // vertical offset from a bar line to its mark-tag CENTER — the tag's own radius plus a small clear gap so the tag circle never touches the line it labels

const CAPTION_EN = 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design (ECP 203 / ACI 318) before issuing for construction. Longitudinal bar lengths shown are drawn span extents only, unless the supplied data included an explicit cutting length; add development / hook / lap length per your design code before fabrication. This sheet covers rebarDiagram-mode content only \u2014 beamWorkshop-mode content (install sequence, shape-letter cross-references, lap-splice zones) is not included here.';

function fmt0(mm) {
  return String(Math.round(mm));
}

// Draws the beam's side view: supports (outline only, no hatch fill —
// v1 excludes HATCH), the concrete outline, one line per longitudinal-
// bar GROUP at its own computed depth (never one line per individual
// bar — a group's count is conveyed by its mark tag, "markId Ødia-count",
// matching the SVG source's own identical simplification, verified: it
// draws exactly one <line> per group), representative stirrup ticks per
// zone (capped at MAX_DRAWN_TIES_PER_ZONE, not one per real stirrup —
// same representative-tick + spacing-callout convention every sibling
// elevation view already uses), and the overall length dimension.
// origin.y is the beam's own BOTTOM (soffit) edge in DXF model space —
// note the source's own yFromTopMM is measured from the TOP face
// regardless of which face a bar is on, so every real-y conversion below
// is `topY - g.yFromTopMM`, the exact inverse of the SVG source's own
// screen-down `beamY + g.yFromTopMM*scale`.
function renderElevationDXF(dxf, geometry, baseY, opts) {
  const {
    totalLength, supports, longitudinalBars, stirrupZones, cover,
  } = geometry;
  const { h } = geometry.section;
  const topY = baseY + h;

  // Supports drawn first, so the beam outline + bars read as sitting
  // visually on top of them — same draw-order rationale every sibling
  // element's own plan/elevation view comment states.
  const supportRanges = supports.map((s) => ({ lo: s.x - s.width / 2, hi: s.x + s.width / 2 }));
  const supportTopY = topY + SUPPORT_OVERHANG_MM;
  const supportBotY = baseY - SUPPORT_OVERHANG_MM;
  supports.forEach((s, i) => {
    const { lo, hi } = supportRanges[i];
    closedRectDXF(dxf, lo, supportBotY, hi - lo, supportTopY - supportBotY, LAYERS.CONCRETE_OUTLINE.name);
    const label = s.label || (s.type === 'wall' ? 'W' : 'S') + (i + 1);
    dxfText(dxf, (lo + hi) / 2, supportBotY - MARGIN_MM * 0.3, SUBTITLE_HEIGHT_MM, label, {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
    });
  });

  closedRectDXF(dxf, 0, baseY, totalLength, h, LAYERS.CONCRETE_OUTLINE.name);

  // Longitudinal bar lines + mark tags. A group whose midpoint falls on
  // an interior support is the ORDINARY case for negative-moment top
  // steel (typically centered exactly on the support it resists moment
  // over), not an edge case — shift the tag clear of that support's own
  // outline instead of letting it render on top of it, same collision
  // logic the SVG source's own renderElevation applies (ported to real
  // support x-ranges here instead of px ranges).
  for (const g of longitudinalBars) {
    const y = topY - g.yFromTopMM;
    const layerName = g.face === 'top' ? LAYERS.REBAR_TOP.name : LAYERS.REBAR_BOTTOM.name;
    dxf.addLine(point3d(g.startX, y), point3d(g.endX, y), { layerName });

    let tagX = (g.startX + g.endX) / 2;
    const collided = supportRanges.find((r) => tagX >= r.lo && tagX <= r.hi);
    if (collided) {
      const shiftRight = collided.hi + SUPPORT_TAG_CLEAR_MM;
      const shiftLeft = collided.lo - SUPPORT_TAG_CLEAR_MM;
      tagX = shiftRight <= g.endX ? shiftRight : (shiftLeft >= g.startX ? shiftLeft : tagX);
    }
    const tagY = g.face === 'top' ? y + MARK_TAG_OFFSET_MM : y - MARK_TAG_OFFSET_MM;
    barMarkTagDXF(dxf, tagX, tagY, `${g.markId} \u00d8${fmt0(g.dia)}-${g.count}`, LAYERS.MARK_TAGS.name);
  }

  // Stirrup zones — representative ticks + spacing callout, one
  // dimension-line row shared by every zone (safe: stirrupZones are
  // already guaranteed non-overlapping in X by computeBeamDiagramGeometry's
  // own assertNoIntervalOverlap, so their labels can never collide
  // horizontally on one shared row).
  const tieTopY = topY - cover * 0.4;
  const tieBotY = baseY + cover * 0.4;
  const supportLabelY = supportBotY - MARGIN_MM * 0.3;
  const zoneRowY = supportLabelY - MARGIN_MM * 1.5;
  const lengthRowY = zoneRowY - MARGIN_MM * 1.8;
  stirrupZones.forEach((z) => {
    const x1 = z.startX, x2 = z.endX;
    const realCount = Math.max(2, Math.round((z.endX - z.startX) / z.spacing) + 1);
    const drawCount = Math.min(realCount, MAX_DRAWN_TIES_PER_ZONE);
    for (const tx of distributeTicks(x1, x2, drawCount)) {
      stirrupTickVDXF(dxf, tx, tieTopY, tieBotY, LAYERS.STIRRUP_TIE.name);
    }
    dimensionLineDXF(dxf, x1, zoneRowY, x2, zoneRowY, `${z.markId} \u00d8${fmt0(z.dia)}-${z.legs}L@${fmt0(z.spacing)}`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  });

  dimensionLineDXF(dxf, 0, lengthRowY, totalLength, lengthRowY, `L = ${(totalLength / 1000).toFixed(2)}m`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // View title well clear of the highest a top-face bar's own mark tag
  // can reach (tag center at up to topY + MARK_TAG_OFFSET_MM, tag TEXT
  // extending a further ~MARK_TAG_RADIUS_MM*0.6 above that per
  // barMarkTagDXF's own text-height default) — MARGIN_MM*2 clears that
  // with real margin to spare for any realistic cover/dia combination.
  const titleY = topY + MARGIN_MM * 2;
  dxfText(dxf, totalLength / 2, titleY, SUBTITLE_HEIGHT_MM, 'ELEVATION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: totalLength, top: titleY + SUBTITLE_HEIGHT_MM };
}

// Draws the row of cross-section cuts geometry.sections lists (default:
// one near the first support face + one at midspan — see
// computeBeamDiagramGeometry). Every box shares the SAME b x h (this
// element's own single-prismatic-section scope, verified: geometry.section
// is one constant object for the whole beam, not per-section), so unlike
// a footing-family element's own varying-size views, this row is a
// uniform tiling — box width is exactly b, not a separately-fitted box
// size. Each box's bars are already positioned (xMM across the section
// width, yFromTopMM at the same global per-(face,layer) depth the
// elevation view uses) by beamDiagram.mjs's own layoutSectionBars — read
// directly, never re-derived.
function renderSectionsRowDXF(dxf, geometry, opts) {
  const { b, h } = geometry.section;
  let x = 0;
  geometry.sections.forEach((sec) => {
    const sox = x;
    closedRectDXF(dxf, sox, 0, b, h, LAYERS.CONCRETE_OUTLINE.name);

    for (const face of ['top', 'bottom']) {
      const dots = sec.bars
        .filter((bar) => bar.face === face)
        .map((bar) => ({ x: sox + bar.xMM, y: h - bar.yFromTopMM, diaMM: bar.dia }));
      if (dots.length === 0) continue;
      const pitch = minPairwiseDistanceMM(dots);
      const layerName = face === 'top' ? LAYERS.REBAR_TOP.name : LAYERS.REBAR_BOTTOM.name;
      for (const d of dots) barDotDXF(dxf, d.x, d.y, d.diaMM, pitch, layerName);
    }

    dimensionLineDXF(dxf, sox, -MARGIN_MM * 0.6, sox + b, -MARGIN_MM * 0.6, `b=${fmt0(b)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
    dimensionLineDXF(dxf, sox - MARGIN_MM * 0.6, 0, sox - MARGIN_MM * 0.6, h, `h=${fmt0(h)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

    dxfText(dxf, sox + b / 2, h + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, `SECTION ${sec.label}`, {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
    });

    x = sox + b + SECTION_GAP_MM;
  });
  const rowWidth = geometry.sections.length > 0 ? x - SECTION_GAP_MM : 0;
  return { width: rowWidth, height: h, top: h + SUBTITLE_HEIGHT_MM * 0.5 + SUBTITLE_HEIGHT_MM };
}

export function renderBeamDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'beam') {
    throw new DiagramError('BAD_PARAM', 'renderBeamDiagramDXF expects a geometry object from computeBeamDiagramGeometry() (type "beam").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  // Stacked bottom-to-top in DXF model space: SECTION-CUTS row lowest,
  // ELEVATION above it — reproducing the SVG source's own top-to-bottom
  // reading order (elevation drawn first/highest on the sheet, the
  // section-cuts row below it) when plotted, since DXF Y increases
  // upward.
  const sections = renderSectionsRowDXF(dxf, geometry, opts);

  const elevBaseY = sections.top + (opts.viewGapMM ?? VIEW_GAP_MM);
  const elevation = renderElevationDXF(dxf, geometry, elevBaseY, opts);

  const overallWidth = Math.max(sections.width, elevation.width);
  const titleY = elevation.top + MARGIN_MM * 2.2;
  dxfText(dxf, overallWidth / 2, titleY, TITLE_HEIGHT_MM, `BEAM ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  const captionY = -MARGIN_MM * 1.3;
  dxfText(dxf, overallWidth / 2, captionY, CAPTION_HEIGHT_MM, CAPTION_EN, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return dxf.stringify();
}
