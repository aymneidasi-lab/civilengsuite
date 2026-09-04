// gradeBeamDiagram.dxf.mjs
// DXF render path for the grade-beam / tie-beam reinforcement diagram —
// parallel to, and entirely separate from, renderGradeBeamDiagramSVG() in
// gradeBeamDiagram.mjs. Same placement rationale as
// shearWallDiagram.dxf.mjs (see that file's own header): kept as its own
// file so an ordinary /diagram or /rebar SVG request never pulls
// @tarikjabiri/dxf into the Worker's module graph — only a future DXF
// entry point that actually asks for one does.
//
// computeGradeBeamDiagramGeometry() is consumed exactly as-is, imported
// from gradeBeamDiagram.mjs with zero modification to that file. This
// module only renders; it never validates or computes.
//
// v1 scope exclusions carried over unchanged from the prompt (same as
// shearWallDiagram.dxf.mjs): no Arabic labels (English only, hardcoded —
// not opts.lang-driven), no schedule table, no multi-line caption. The
// soil-bearing strip is drawn as an outline rectangle only — HATCH is
// v1-excluded, same "stroke real, fill meaningless without HATCH"
// treatment CONCRETE-OUTLINE already gets in the shared kit.
//
// NEW layers/functions this element needed, not covered by the shared
// kit at the start of this session (flagged per the general prompt's
// session-protocol step 4, added to structuralDrawingDxfKit.mjs, not
// duplicated here):
//   - LAYERS.NODE_MARKER / LAYERS.BEARING_LABEL — the master layer table
//     already names both as "gradeBeamDiagram only" with color "—"
//     (unconfirmed). Hex values now set on those two LAYERS entries are
//     copied from gradeBeamDiagram.mjs's own SVG CSS (.node-marker /
//     .bearing strip stroke), not invented — see the kit's own comment
//     on each entry. Flagged as pending confirmation, trivial to change
//     (one hex literal each) if the real convention differs.
//   - closedPolylineDXF() — DXF has no native filled-triangle entity;
//     the node marker is drawn as an unfilled 3-vertex closed LWPolyline
//     (added as a generic N-point function, not triangle-specific, per
//     the kit's own stated growth pattern).
//
// UNVERIFIED ASSUMPTION (flagged, not silently guessed): gradeBeamDiagram
// .mjs's SVG path calls stirrupTick(tx, tieTopY, tieBotY) from
// structuralDrawingKit.mjs — a DIFFERENT, differently-named function from
// shearWallDiagram.mjs's tieTickH(...) (whose real 3-segment composition
// the general prompt's own "confirmed technical discoveries" section
// documents as a past silent-bug source: name suggested one line, the
// code was three). structuralDrawingKit.mjs was NOT supplied this
// session, so stirrupTick()'s real SVG composition could not be read and
// verified the same way. Rendered below as a single vertical LINE from
// (tx,tieTopY) to (tx,tieBotY) — inferred from the 3-argument call shape
// (position + top + bottom, no cap-length argument, unlike tieTickH's),
// and from the universal drafting convention for a beam elevation's own
// stirrup-spacing tick (a plain vertical hash mark, not a compound
// wrap-around-tie glyph — that visual belongs to tieTickH's specific
// boundary-element use case, which does not apply to a beam elevation).
// If stirrupTick() is actually compound, only stirrupTickLineDXF() below
// needs to change — isolated to one function for exactly this reason.

import {
  DxfWriter, point3d, Units, LAYERS, defineDxfLayers, dxfText, closedRectDXF,
  closedPolylineDXF, barDotDXF, barMarkTagDXF, dimensionLineDXF,
  distributeTicks, DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Layout conventions — none of these come from geometry; each is a chosen
// default for real-mm placement the SVG path never needed (fixed pixel
// canvas instead). Derived fresh from reading renderGradeBeamDiagramSVG /
// renderElevation / renderSections in full: same views, same relative
// stacking order the SVG source actually draws (title above elevation;
// node markers above the beam; soil band + bearing label + stirrup-zone
// dims + overall-length dim below the beam, in that order; sections row
// further below) — new real-mm values throughout, not shearWallDiagram
// .dxf.mjs's own box carried over. All named so they're auditable.
const MARGIN_MM = 300; // generic safety gutter (clears a dimension line's own end-ticks/labels before the next view starts) — same value shearWallDiagram.dxf.mjs uses, kept as one convention across the DXF kit's sibling files
const VIEW_GAP_MM = 1200; // real-mm vertical gap between the elevation's lowest content and the section-views row's own title line above it — larger than shearWallDiagram.dxf.mjs's 1000mm horizontal VIEW_GAP_MM because this is a vertical stack that must also clear the row's SECTION-title text, not just abut a bare strip
const SECTION_GAP_MM = 500; // real-mm horizontal gap between adjacent section boxes in the row (SVG: SECTION_GAP=40px fixed, no physical meaning to carry over)
const TITLE_HEIGHT_MM = 220; // overall sheet title — same value as shearWallDiagram.dxf.mjs's own TITLE_HEIGHT_MM
const SUBTITLE_HEIGHT_MM = 150; // view titles (ELEVATION / SECTION n-n) — same value as shearWallDiagram.dxf.mjs's own SUBTITLE_HEIGHT_MM
const DIM_TEXT_HEIGHT_MM = 150; // dimension-line label text height — same value as shearWallDiagram.dxf.mjs's own DIM_TEXT_HEIGHT_MM
const NODE_STANDOFF_MM = 100; // gap from the beam's top edge up to the node-marker triangle's apex (SVG: triBotY=beamY-4, a small standoff so the apex nearly touches the top edge)
const NODE_MARKER_HALF_WIDTH_MM = 130; // triangle half base-width — convention (SVG: fixed 7px half-width, no physical meaning to carry over)
const NODE_MARKER_HEIGHT_MM = 220; // triangle apex-to-base height (SVG: 22px fixed, triTopY to triBotY)
const NODE_LABEL_GAP_MM = 150; // gap from the triangle's base up to the node label text baseline
const NODE_LABEL_TEXT_HEIGHT_MM = 110; // node label text height
const BAR_TAG_OFFSET_MM = 180; // vertical float distance from a longitudinal bar's own line to its mark-tag bubble center — sized to clear the kit's own MARK_TAG_RADIUS_MM=150mm bubble plus a small buffer (SVG: fixed 13px, no physical meaning to carry over)
// Fixed gap from the beam's top edge up to the ELEVATION view title's
// baseline, regardless of whether nodes are present — same simplification
// the SVG source itself uses (its own view-title y is a fixed beamY-56
// offset, not conditional on node presence). Sized to clear whichever is
// taller: the node-marker zone (standoff+height+label gap+label text =~
// 100+220+150+110 = 580mm) or a top-face bar's mark tag float
// (offset+radius =~ 180+150 = 330mm); the node zone is taller, so it
// governs, plus a clearance buffer.
const ELEV_TITLE_GAP_MM = NODE_STANDOFF_MM + NODE_MARKER_HEIGHT_MM + NODE_LABEL_GAP_MM + NODE_LABEL_TEXT_HEIGHT_MM + 150;
const SOIL_BAND_HEIGHT_MM = 400; // continuous soil-bearing strip's drawn depth below the beam soffit — a SCHEMATIC symbol depth, not a real soil layer thickness (SVG: SOIL_BAND_H=26px fixed, same non-physical convention, same caveat its own SVG name implies)
const BEARING_LABEL_GAP_MM = 200; // gap from the soil strip's bottom edge down to the "Continuous soil bearing..." label text baseline
const ZONE_DIM_GAP_MM = 350; // gap from the bearing label down to the stirrup-zone dimension-line row
const OVERALL_DIM_GAP_MM = 350; // gap from the stirrup-zone dimension row down to the overall-length dimension line
const SECTION_TITLE_GAP_MM = 250; // gap from a section box's top edge up to its own "SECTION n-n" title
const SECTION_B_DIM_GAP_MM = 300; // gap from a section box's bottom edge down to its b= dimension line
const SECTION_H_DIM_GAP_MM = 300; // gap from a section box's left edge left to its h= dimension line
// Mirrors gradeBeamDiagram.mjs's own MAX_DRAWN_TIES_PER_ZONE=20 (line 130
// at time of writing) — module-local const there, not exported, so it
// cannot be imported; duplicated as a literal here and flagged, same
// precedent shearWallDiagram.dxf.mjs's own MAX_MESH_COLS/MAX_MESH_ROWS/
// MAX_DRAWN_TIES comment sets for the identical situation.
const MAX_DRAWN_TIES_PER_ZONE = 20;

function fmt0(mm) {
  return String(Math.round(mm));
}

// Per-dot nearest-neighbor pitch: generalizes the general prompt's units-
// decision rule ("measure the horizontal AND vertical distance between
// the near and far rebar line, take the smaller") from
// shearWallDiagram.dxf.mjs's own single global horizontal/vertical pitch
// (valid there because its mesh is a uniform grid) to gradeBeamDiagram's
// section view, where bar count varies per face/layer, so no single
// global spacing value is correct for every dot. For each dot, the real
// nearest-neighbor distance to ANY other dot in the same section (any
// face/layer, i.e. both axes at once) is measured directly — same
// "actual on-drawing distance, not a schema constant" rule, applied
// per-dot instead of per-view.
function nearestNeighborPitchMM(dots, i) {
  let min = Infinity;
  for (let j = 0; j < dots.length; j++) {
    if (j === i) continue;
    const d = Math.hypot(dots[i].xMM - dots[j].xMM, dots[i].yMM - dots[j].yMM);
    if (d > 0 && d < min) min = d; // d===0 excluded: a coincident duplicate is not a spacing case
  }
  return min;
}

// origin.y = the beam's SOFFIT (bottom edge); the beam's top edge is at
// origin.y + section.h. Returns the view's vertical extent so the caller
// can place the sections row below it with a real gap.
function renderElevationViewDXF(dxf, geometry, origin) {
  const { totalLength, nodes, longitudinalBars, stirrupZones, cover, section } = geometry;
  const { h } = section;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, totalLength, h, LAYERS.CONCRETE_OUTLINE.name);

  // Continuous soil-bearing strip — one rect spanning the FULL beam
  // length below the soffit (contrast beamDiagram.mjs's own per-support
  // hatch rects — gradeBeamDiagram.mjs's header documents this as the
  // schema difference this element exists for). HATCH excluded (v1
  // scope) — outline only.
  const soilBotY = oy - SOIL_BAND_HEIGHT_MM;
  closedRectDXF(dxf, ox, soilBotY, totalLength, SOIL_BAND_HEIGHT_MM, LAYERS.BEARING_LABEL.name);
  dxfText(dxf, ox + totalLength / 2, soilBotY - BEARING_LABEL_GAP_MM, SUBTITLE_HEIGHT_MM * 0.75, 'Continuous soil bearing along full length', {
    layerName: LAYERS.BEARING_LABEL.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  // Node markers — small unfilled triangle, apex nearly touching the
  // beam's top edge (conventional "reaction point" symbol), label above.
  // Annotation only, drawn straight from `nodes` — nothing below this
  // block reads it again (same scope the SVG source itself uses).
  nodes.forEach((n) => {
    const cx = ox + n.x;
    const apexY = oy + h + NODE_STANDOFF_MM;
    const baseY = apexY + NODE_MARKER_HEIGHT_MM;
    closedPolylineDXF(dxf, [
      { x: cx - NODE_MARKER_HALF_WIDTH_MM, y: baseY },
      { x: cx + NODE_MARKER_HALF_WIDTH_MM, y: baseY },
      { x: cx, y: apexY },
    ], LAYERS.NODE_MARKER.name);
    dxfText(dxf, cx, baseY + NODE_LABEL_GAP_MM, NODE_LABEL_TEXT_HEIGHT_MM, n.label, {
      layerName: LAYERS.NODE_MARKER.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
    });
  });

  // Longitudinal bar lines + mark tags — identical algorithm to
  // beamDiagram.mjs's own (gradeBeamDiagram.mjs's header: "this IS
  // beamDiagram.mjs's own bar-group machinery, reused algorithm-for-
  // algorithm"). g.yFromTopMM measures distance DOWN from the beam's top
  // face; this view's origin is the SOFFIT (oy=bottom), so DXF y is
  // oy + h - g.yFromTopMM.
  for (const g of longitudinalBars) {
    const x1 = ox + g.startX;
    const x2 = ox + g.endX;
    const y = oy + h - g.yFromTopMM;
    const layerName = g.face === 'top' ? LAYERS.REBAR_TOP.name : LAYERS.REBAR_BOTTOM.name;
    dxf.addLine(point3d(x1, y), point3d(x2, y), { layerName });
    const tagX = (x1 + x2) / 2;
    const tagY = g.face === 'top' ? y + BAR_TAG_OFFSET_MM : y - BAR_TAG_OFFSET_MM;
    barMarkTagDXF(dxf, tagX, tagY, `${g.markId} \u00d8${fmt0(g.dia)}-${g.count}`, LAYERS.MARK_TAGS.name);
  }

  // Stirrup zones — vertical tick per drawn position (crossing the beam
  // depth, inset by 0.4xcover from top/bottom face, same real-mm formula
  // the SVG source uses verbatim: tieTopY=beamY+cover*0.4*scale,
  // tieBotY=beamY+beamH-cover*0.4*scale — see the header's flagged
  // stirrupTick() composition note) + a labeled dimension line below the
  // soil band.
  const tickBotY = oy + cover * 0.4;
  const tickTopY = oy + h - cover * 0.4;
  const zoneDimRowY = soilBotY - BEARING_LABEL_GAP_MM - ZONE_DIM_GAP_MM;
  stirrupZones.forEach((z) => {
    const x1 = ox + z.startX;
    const x2 = ox + z.endX;
    const realCount = Math.max(2, Math.round((z.endX - z.startX) / z.spacing) + 1);
    const drawCount = Math.min(realCount, MAX_DRAWN_TIES_PER_ZONE);
    for (const tx of distributeTicks(x1, x2, drawCount)) {
      dxf.addLine(point3d(tx, tickBotY), point3d(tx, tickTopY), { layerName: LAYERS.STIRRUP_TIE.name });
    }
    dimensionLineDXF(dxf, x1, zoneDimRowY, x2, zoneDimRowY, `${z.markId} \u00d8${fmt0(z.dia)}-${z.legs}L@${fmt0(z.spacing)}`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  });

  const overallDimY = zoneDimRowY - OVERALL_DIM_GAP_MM;
  dimensionLineDXF(dxf, ox, overallDimY, ox + totalLength, overallDimY, `L = ${(totalLength / 1000).toFixed(2)}m`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // View title — above everything stacked above the beam's top edge
  // (node markers included, whether or not any are present).
  dxfText(dxf, ox + totalLength / 2, oy + h + ELEV_TITLE_GAP_MM, SUBTITLE_HEIGHT_MM, 'ELEVATION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return {
    width: totalLength,
    lowestY: overallDimY - MARGIN_MM, // clears the overall-length dimension line's own end-ticks before the next view starts
    highestY: oy + h + ELEV_TITLE_GAP_MM + SUBTITLE_HEIGHT_MM,
  };
}

// origin.y = the shared box-bottom baseline for every section in the row;
// each box spans [origin.y, origin.y + section.h]. Every section shares
// the SAME real b x h (geometry.section is a single top-level object —
// verified by reading computeGradeBeamDiagramGeometry()'s own return:
// sections only vary by which bars are ACTIVE at that x, never by a
// different b/h), so no per-section box scaling is needed the way the
// SVG's fixed-pixel SECTION_SIZE box did.
function renderSectionsRowDXF(dxf, geometry, origin) {
  const { b, h } = geometry.section;
  const { x: ox, y: oy } = origin;

  geometry.sections.forEach((sec, i) => {
    const boxX = ox + i * (b + SECTION_GAP_MM);

    closedRectDXF(dxf, boxX, oy, b, h, LAYERS.CONCRETE_OUTLINE.name);
    dxfText(dxf, boxX + b / 2, oy + h + SECTION_TITLE_GAP_MM, SUBTITLE_HEIGHT_MM, `SECTION ${sec.label}`, {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
    });

    // Bar dots — real xMM/yFromTopMM straight from layoutSectionBars(),
    // no fitScale. Per-dot nearest-neighbor pitch (see
    // nearestNeighborPitchMM's own comment above).
    const dots = sec.bars.map((bar) => ({
      xMM: boxX + bar.xMM, yMM: oy + h - bar.yFromTopMM, dia: bar.dia, face: bar.face,
    }));
    dots.forEach((dot, di) => {
      const pitch = nearestNeighborPitchMM(dots, di);
      const layerName = dot.face === 'top' ? LAYERS.REBAR_TOP.name : LAYERS.REBAR_BOTTOM.name;
      barDotDXF(dxf, dot.xMM, dot.yMM, dot.dia, pitch, layerName);
    });

    dimensionLineDXF(dxf, boxX, oy - SECTION_B_DIM_GAP_MM, boxX + b, oy - SECTION_B_DIM_GAP_MM, `b=${fmt0(b)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
    dimensionLineDXF(dxf, boxX - SECTION_H_DIM_GAP_MM, oy, boxX - SECTION_H_DIM_GAP_MM, oy + h, `h=${fmt0(h)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  });

  const rowWidth = geometry.sections.length * b + (geometry.sections.length - 1) * SECTION_GAP_MM;
  return { width: rowWidth };
}

export function renderGradeBeamDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'gradeBeam') {
    throw new DiagramError('BAD_PARAM', 'renderGradeBeamDiagramDXF expects a geometry object from computeGradeBeamDiagramGeometry() (type "gradeBeam").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const elevOrigin = { x: 0, y: 0 };
  const elev = renderElevationViewDXF(dxf, geometry, elevOrigin);

  const viewGapMM = opts.viewGapMM ?? VIEW_GAP_MM;
  const sectionsOriginY = elev.lowestY - viewGapMM - SECTION_TITLE_GAP_MM - SUBTITLE_HEIGHT_MM - geometry.section.h;
  const sections = renderSectionsRowDXF(dxf, geometry, { x: elevOrigin.x, y: sectionsOriginY });

  const overallWidth = Math.max(elev.width, sections.width);
  dxfText(dxf, elevOrigin.x + overallWidth / 2, elev.highestY + TITLE_HEIGHT_MM * 0.6, TITLE_HEIGHT_MM, `GRADE / TIE BEAM ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
