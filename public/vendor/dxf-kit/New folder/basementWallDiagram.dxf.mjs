// basementWallDiagram.dxf.mjs
// DXF render path for the basement-wall typical-section reinforcement
// diagram — parallel to, and entirely separate from,
// renderBasementWallDiagramSVG() in basementWallDiagram.mjs. Same
// placement rationale as shearWallDiagram.dxf.mjs: an ordinary /diagram
// or /rebar SVG request must never pull @tarikjabiri/dxf into the
// Worker's module graph.
//
// computeBasementWallDiagramGeometry() is consumed exactly as-is, imported
// from basementWallDiagram.mjs with zero modification to that file. This
// module only renders; it never validates or computes.
//
// v1 scope exclusions carried over unchanged from برومبت_تحويل_DXF_عام_v1.md:
// no HATCH (soil backfill and both restraint stubs draw as outlines only,
// same fill-less treatment CONCRETE-OUTLINE already has), no schedule
// table as a DXF TABLE entity (V-EXT/V-INT/H1/T1/B1 bar-spec information
// is instead given as plain stacked TEXT callouts — same role
// shearWallDiagram.dxf.mjs's own inline spec callouts played, just for a
// 5-line list instead of a 1-2 line one), no Arabic labels (English only,
// hardcoded, matching shearWallDiagram.dxf.mjs's own choice).
//
// ── Y-AXIS CONVENTION (read before touching any coordinate below) ──────
// The SVG source (renderSectionView in basementWallDiagram.mjs) uses a
// downward-y SCREEN frame: local y=0 is the TOP of the wall (the slab/
// top-restraint interface) and y=heightMM is the BOTTOM (the footing/
// bottom-restraint interface) — verified directly against that function's
// own px() helper and its "sy = top of wall" comment. This file uses an
// upward-y frame instead (oy=0 at the wall/footing interface, oy+heightMM
// at the wall/slab interface), matching shearWallDiagram.dxf.mjs's own
// documented convention choice and AutoCAD's native upward-y display.
// Net transform: any SVG quantity expressed as "distance down from the
// slab" (dTop) becomes this file's DXF y-coordinate via flipY(dTop) =
// heightMM - dTop. One quantity needs NO flip: soilHeightMM is already
// defined (in basementWallDiagram.mjs's own input contract) as measured
// UP FROM THE FOOTING — exactly this file's own y=0 reference — so the
// soil block's real-mm height is used directly, unlike every other
// quantity below.

import {
  DxfWriter,
  point3d,
  Units,
  LAYERS,
  defineDxfLayers,
  dxfText,
  closedRectDXF,
  barDotDXF,
  dimensionLineDXF,
  distributeTicks,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Duplicated from basementWallDiagram.mjs — that file does not export
// these (unexported module-level consts used only inside its own render
// function), and this file must not be edited to add an export (zero
// modification to the existing file, per session scope). Flagged here
// explicitly so a future change to the source values does not silently
// desync: basementWallDiagram.mjs lines 147 and 155 at time of writing.
const MAX_EXTRA_BAR_COUNT = 12;
const MAX_DRAWN_HORIZ_BARS = 14;

// ── Layout conventions ──────────────────────────────────────────────
// Shared plot-scale conventions reused unchanged from shearWallDiagram.dxf.mjs
// (no element-specific reason to differ):
const MARGIN_MM = 300;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view title / restraint labels / bar-spec callout text height
const DIM_TEXT_HEIGHT_MM = 150;
// New, element-specific (this element has restraint stubs + a soil block;
// shearWallDiagram has neither, so it defined no equivalents):
const STUB_HEIGHT_MM = 200; // schematic slab/footing stub thickness — illustrative only, NOT the real slab/footing thickness (that is slabDiagram.mjs's/footingDiagram.mjs's own scope per this element's own header comment); chosen for legibility at typical structural-section plot scale, same "convention" status as the SVG source's own STUB_H=26px
const STUB_OVERHANG_MM = 300; // schematic slab/footing projection beyond each wall face; ALSO reused as-is for the soil block's own width, matching the SVG source's own reuse of its STUB_OVERHANG constant for both purposes
const DIM_CLEARANCE_MM = 150; // extra gap between the outermost schematic content (stub/soil block edges) and a dimension line placed further out, so the dimension line never crosses drawn geometry
const CALLOUT_GAP_MM = 220; // vertical spacing between stacked bar-spec callout lines in the right-side margin list
const HACHURE_RUN_MM = 90; // real-mm equivalent of the SVG restraintHachure()'s 9px horizontal run (angle preserved: 90:120 = 9:12 exactly)
const HACHURE_DROP_MM = 120; // real-mm equivalent of the SVG restraintHachure()'s 12px vertical drop

function fmt0(mm) {
  return String(Math.round(mm));
}

// Direct DXF translation of the SVG source's own local restraintHachure()
// helper (basementWallDiagram.mjs lines 294-303) — n=8 short diagonal
// ticks, the standard drafting "fixed support" callout. That function is
// itself local/unexported in the SVG file with an explicit "no shared kit
// function wraps this... written locally" note, so this DXF equivalent is
// kept local here too, not added to the shared kit.
function restraintHachureDXF(dxf, x1, x2, y, layerName) {
  const n = 8;
  const step = (x2 - x1) / n;
  for (let i = 0; i <= n; i++) {
    const x = x1 + i * step;
    dxf.addLine(point3d(x, y), point3d(x - HACHURE_RUN_MM, y - HACHURE_DROP_MM), { layerName });
  }
}

export function renderBasementWallDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'basementWall') {
    throw new DiagramError('BAD_PARAM', 'renderBasementWallDiagramDXF expects a geometry object from computeBasementWallDiagramGeometry() (type "basementWall").');
  }
  const {
    id, heightMM, thicknessMM, coverMM, soilHeightMM,
    exteriorVerticalBars, interiorVerticalBars, horizontalBars,
    topExtraBars, bottomExtraBars,
  } = geometry;

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  // ox=0 at the exterior (soil) face, thicknessMM at the interior (room)
  // face — same x-sense as the SVG source, x is not affected by the
  // y-convention mismatch described above. oy=0 at the wall/footing
  // interface, oy+heightMM at the wall/slab interface.
  const ox = 0, oy = 0;
  const flipY = (distFromSlabMM) => oy + (heightMM - distFromSlabMM);

  // ── Wall panel + restraint stubs (schematic only, see module header) ──
  closedRectDXF(dxf, ox, oy, thicknessMM, heightMM, LAYERS.CONCRETE_OUTLINE.name);
  // Top restraint stub (floor slab) — extends upward from the wall's top edge.
  closedRectDXF(dxf, ox - STUB_OVERHANG_MM, oy + heightMM, thicknessMM + 2 * STUB_OVERHANG_MM, STUB_HEIGHT_MM, LAYERS.CONCRETE_OUTLINE.name);
  // Bottom restraint stub (footing top) — extends downward from the wall's bottom edge.
  closedRectDXF(dxf, ox - STUB_OVERHANG_MM, oy - STUB_HEIGHT_MM, thicknessMM + 2 * STUB_OVERHANG_MM, STUB_HEIGHT_MM, LAYERS.CONCRETE_OUTLINE.name);

  // Restraint hachure ticks — .restraint-hachure's #1a1a1a is CONCRETE-OUTLINE's
  // exact color (verified against basementWallDiagram.mjs's own style block).
  restraintHachureDXF(dxf, ox - STUB_OVERHANG_MM, ox + thicknessMM + STUB_OVERHANG_MM, oy + heightMM, LAYERS.CONCRETE_OUTLINE.name);
  restraintHachureDXF(dxf, ox - STUB_OVERHANG_MM, ox + thicknessMM + STUB_OVERHANG_MM, oy - STUB_HEIGHT_MM, LAYERS.CONCRETE_OUTLINE.name);

  // Restraint labels — English only (v1 scope). ANNOTATION as a flagged
  // default: .restraint-label's #555 matches nothing in
  // برومبت_تحويل_DXF_عام_v1.md's table — same "flagged, not table-confirmed"
  // treatment shearWallDiagram.dxf.mjs already gave its own unmapped
  // "support-label".
  dxfText(dxf, ox + thicknessMM + STUB_OVERHANG_MM + DIM_CLEARANCE_MM * 0.4, oy + heightMM + STUB_HEIGHT_MM / 2, SUBTITLE_HEIGHT_MM * 0.75, 'FLOOR SLAB (TOP RESTRAINT)', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Middle,
  });
  dxfText(dxf, ox + thicknessMM + STUB_OVERHANG_MM + DIM_CLEARANCE_MM * 0.4, oy - STUB_HEIGHT_MM / 2, SUBTITLE_HEIGHT_MM * 0.75, 'FOOTING (BOTTOM RESTRAINT)', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Middle,
  });

  // Soil backfill — outline only (no HATCH, v1-excluded, same rationale as
  // CONCRETE-OUTLINE's own unfilled boundary). soilHeightMM is already
  // measured up from the footing (see module header) — this frame's own
  // y=0 reference — so no flipY() needed for this one quantity.
  closedRectDXF(dxf, ox - STUB_OVERHANG_MM, oy, STUB_OVERHANG_MM, soilHeightMM, LAYERS.SOIL.name);

  // ── Vertical bars (single representative line + 2 end dots each) ────
  // Exterior (soil-face) — REBAR-BOTTOM: SVG source's own `bar-bottom`
  // line class AND `bar-dot-ext` fill #c0392b both confirmed exact matches.
  const extX = ox + coverMM + exteriorVerticalBars.dia / 2;
  const extNearSlabY = flipY(coverMM + exteriorVerticalBars.dia / 2);
  const extNearFootingY = flipY(heightMM - coverMM - exteriorVerticalBars.dia / 2);
  dxf.addLine(point3d(extX, extNearFootingY), point3d(extX, extNearSlabY), { layerName: LAYERS.REBAR_BOTTOM.name });
  const extEndPitch = Math.abs(extNearSlabY - extNearFootingY); // only other same-layer dot is its own opposite end
  barDotDXF(dxf, extX, extNearSlabY, exteriorVerticalBars.dia, extEndPitch, LAYERS.REBAR_BOTTOM.name);
  barDotDXF(dxf, extX, extNearFootingY, exteriorVerticalBars.dia, extEndPitch, LAYERS.REBAR_BOTTOM.name);

  // Interior (room-face) — REBAR-TOP: `bar-top` line class AND
  // `bar-dot-int` fill #1f5aa6 both confirmed exact matches.
  const intX = ox + thicknessMM - coverMM - interiorVerticalBars.dia / 2;
  const intNearSlabY = flipY(coverMM + interiorVerticalBars.dia / 2);
  const intNearFootingY = flipY(heightMM - coverMM - interiorVerticalBars.dia / 2);
  dxf.addLine(point3d(intX, intNearFootingY), point3d(intX, intNearSlabY), { layerName: LAYERS.REBAR_TOP.name });
  const intEndPitch = Math.abs(intNearSlabY - intNearFootingY);
  barDotDXF(dxf, intX, intNearSlabY, interiorVerticalBars.dia, intEndPitch, LAYERS.REBAR_TOP.name);
  barDotDXF(dxf, intX, intNearFootingY, interiorVerticalBars.dia, intEndPitch, LAYERS.REBAR_TOP.name);

  // ── Horizontal bars (both faces) — REBAR-HORIZONTAL ──────────────────
  // Dual-axis pitch check per برومبت_تحويل_DXF_عام_v1.md Decision #1: measure
  // BOTH the real row-to-row (vertical) spacing AND the real face-to-face
  // (horizontal) spacing between the ext/int columns at the same row, take
  // the smaller, for every dot's barDotRadiusMM() safety cap.
  const drawHorizCount = Math.min(horizontalBars.count, MAX_DRAWN_HORIZ_BARS);
  const horizNearSlabDTop = coverMM + horizontalBars.dia / 2;
  const horizNearFootingDTop = heightMM - coverMM - horizontalBars.dia / 2;
  const ys = distributeTicks(flipY(horizNearFootingDTop), flipY(horizNearSlabDTop), drawHorizCount);
  const vertPitch = ys.length > 1 ? Math.abs(ys[1] - ys[0]) : Infinity;
  const facePitch = Math.abs(intX - extX); // the other axis these dots could collide across (ext vs int column, same row)
  const horizPitch = Math.min(vertPitch, facePitch);
  for (const y of ys) {
    barDotDXF(dxf, extX, y, horizontalBars.dia, horizPitch, LAYERS.REBAR_HORIZONTAL.name);
    barDotDXF(dxf, intX, y, horizontalBars.dia, horizPitch, LAYERS.REBAR_HORIZONTAL.name);
  }

  // ── Optional extra bars at each restraint zone — interior face, REBAR-EXTRA ──
  if (topExtraBars) {
    const drawCount = Math.min(topExtraBars.count, MAX_EXTRA_BAR_COUNT);
    const yTop = distributeTicks(flipY(topExtraBars.projectionMM), flipY(coverMM), drawCount);
    const pitch = yTop.length > 1 ? Math.abs(yTop[1] - yTop[0]) : Infinity;
    for (const y of yTop) barDotDXF(dxf, intX, y, topExtraBars.dia, pitch, LAYERS.REBAR_EXTRA.name);
  }
  if (bottomExtraBars) {
    const drawCount = Math.min(bottomExtraBars.count, MAX_EXTRA_BAR_COUNT);
    const yBot = distributeTicks(flipY(heightMM - coverMM), flipY(heightMM - bottomExtraBars.projectionMM), drawCount);
    const pitch = yBot.length > 1 ? Math.abs(yBot[1] - yBot[0]) : Infinity;
    for (const y of yBot) barDotDXF(dxf, intX, y, bottomExtraBars.dia, pitch, LAYERS.REBAR_EXTRA.name);
  }

  // ── Dimensions (overall height, thickness — the only 2 the SVG source dimensions) ──
  dimensionLineDXF(dxf, ox - STUB_OVERHANG_MM - DIM_CLEARANCE_MM, oy, ox - STUB_OVERHANG_MM - DIM_CLEARANCE_MM, oy + heightMM, `${fmt0(heightMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox, oy - STUB_HEIGHT_MM - DIM_CLEARANCE_MM, ox + thicknessMM, oy - STUB_HEIGHT_MM - DIM_CLEARANCE_MM, `${fmt0(thicknessMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // ── Bar-spec callouts ────────────────────────────────────────────────
  // scheduleTable-as-DXF-TABLE is v1-excluded (برومبت_تحويل_DXF_عام_v1.md);
  // this substitutes plain stacked TEXT for the same underlying
  // information (mark code + dia/spacing or count/projection), same role
  // shearWallDiagram.dxf.mjs's own inline spec callouts played for its one
  // mesh spec. MARK-TAGS layer: these are mark/schedule callout text, same
  // semantic bucket as that layer's own "mark-tag-text" entry, even
  // without a circle+leader (a leader per item would clutter this single,
  // tight section view given 5 possible callouts vs. shearWallDiagram's 1).
  const calloutX = ox + thicknessMM + STUB_OVERHANG_MM + MARGIN_MM * 0.5;
  let calloutY = oy + heightMM - SUBTITLE_HEIGHT_MM;
  const callout = (text) => {
    dxfText(dxf, calloutX, calloutY, SUBTITLE_HEIGHT_MM * 0.8, text, { layerName: LAYERS.MARK_TAGS.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Middle });
    calloutY -= CALLOUT_GAP_MM;
  };
  callout(`V-EXT: \u00d8${fmt0(exteriorVerticalBars.dia)}@${fmt0(exteriorVerticalBars.spacing)}`);
  callout(`V-INT: \u00d8${fmt0(interiorVerticalBars.dia)}@${fmt0(interiorVerticalBars.spacing)}`);
  callout(`H1: \u00d8${fmt0(horizontalBars.dia)}@${fmt0(horizontalBars.spacing)}`);
  if (topExtraBars) callout(`T1: ${topExtraBars.count}-\u00d8${fmt0(topExtraBars.dia)} (proj ${fmt0(topExtraBars.projectionMM)}mm)`);
  if (bottomExtraBars) callout(`B1: ${bottomExtraBars.count}-\u00d8${fmt0(bottomExtraBars.dia)} (proj ${fmt0(bottomExtraBars.projectionMM)}mm)`);

  // ── Titles ────────────────────────────────────────────────────────────
  dxfText(dxf, ox + thicknessMM / 2, oy + heightMM + STUB_HEIGHT_MM + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });
  dxfText(dxf, ox + thicknessMM / 2, oy + heightMM + STUB_HEIGHT_MM + SUBTITLE_HEIGHT_MM * 2.2, TITLE_HEIGHT_MM, `BASEMENT WALL ${id} - TYPICAL SECTION`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
