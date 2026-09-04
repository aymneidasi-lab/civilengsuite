// punchingShearDiagram.dxf.mjs
// DXF render path for the punching-shear stud-rail diagram — parallel to,
// and entirely separate from, renderPunchingShearDiagramSVG() in
// punchingShearDiagram.mjs. Separate file per برومبت_تحويل_DXF_عام_v1.md's
// organizational decision (§"التنظيم"): keeps @tarikjabiri/dxf out of any
// ordinary /diagram (SVG-only) module-graph path.
//
// computePunchingShearDiagramGeometry() is consumed exactly as-is, imported
// from punchingShearDiagram.mjs with zero modification to that file. This
// module only renders; it never validates or computes.
//
// v1 scope exclusions carried over unchanged from shearWallDiagram.dxf.mjs
// (same project-wide DXF v1 boundary, not re-decided per element): English
// labels only (hardcoded, not opts.lang-driven), no schedule table, no
// multi-line caption. The SVG source's caption text (punching-shear-demand
// disclaimer, stirrup-vs-stud scope note) is therefore NOT reproduced here
// — same "out of v1 scope" treatment the reference file already applies to
// its own SVG source's caption.
//
// Two new layers this element needs (SHEAR-STUDS, RAIL-LINE) were added to
// structuralDrawingDxfKit.mjs's shared LAYERS/ACI_FALLBACK tables per the
// project's own master layer table (both already named there; RAIL-LINE's
// previously-unconfirmed hex verified directly against
// punchingShearDiagram.mjs's own `.rail-line` style rule before use) —
// not invented here, not a local/private layer.
//
// Section-cut scope note (unchanged from the SVG source, carried over
// verbatim): the section shows the slab profile, effective depth d as a
// dimension from the top fiber, a column stub, and the two d/2
// critical-perimeter reference lines — it does NOT show individual studs
// in elevation. Studs are drawn only in plan, at their real computed (x,y).

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
  barMarkTagDXF,
  dimensionLineDXF,
  minPairwiseDistanceMM,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// ── Layout conventions — real-mm placement the SVG path never needed ──
// (it drew everything inside a fixed pixel canvas instead). All named,
// all overridable via opts, same convention shearWallDiagram.dxf.mjs
// already establishes for its own layout constants.
const MARGIN_MM = 300; // gutter around each view for dimension lines/labels — same value/role as shearWallDiagram.dxf.mjs's own MARGIN_MM
const VIEW_GAP_MM = 1000; // real-mm gap between plan and section views, model space — same value/role as shearWallDiagram.dxf.mjs's own VIEW_GAP_MM
const TITLE_HEIGHT_MM = 220; // same value/role as shearWallDiagram.dxf.mjs's own TITLE_HEIGHT_MM
const SUBTITLE_HEIGHT_MM = 150; // view titles (PLAN/SECTION), crit-label, mark tags — same value/role as shearWallDiagram.dxf.mjs's own SUBTITLE_HEIGHT_MM
const DIM_TEXT_HEIGHT_MM = 150; // same value/role as shearWallDiagram.dxf.mjs's own DIM_TEXT_HEIGHT_MM
const CRIT_LABEL_GAP_MM = 80; // new — gap from the critical-perimeter rectangle's own corner to its label text, chosen for clear separation without crowding the plan view at typical plot scale
const MARK_TAG_GAP_MM = 250; // new — how far beyond a rail's farthest stud its mark-tag bubble sits (with a leader line back to that stud), enough clearance that the bubble never overlaps the last stud's own dot at any stud diameter this element accepts (MAX_STUD_DIA_MM=25mm, so even doubled that leaves a comfortable margin)
const COLUMN_STUB_HEIGHT_MM = 500; // new — section-view column stub length above the slab's top fiber. Schematic only (the real column continues upward through/above the slab; this drawing does not model or dimension that extent) — same non-dimensioned "member continues, cut off here" convention other elements' cut-off elevations already use. NOT derived from colB: the SVG source's own `Math.min(50, colB*scale*0.5)` was itself only a canvas-fitting convenience for a fixed-size px viewBox, not a real measured length — real-mm space has no such constraint, so a plain named constant is used instead of carrying that px-derived formula forward.

function fmt0(mm) {
  return String(Math.round(mm));
}

// n/s/e/w -> outward unit vector, in the SAME (x grows along L, y grows
// along B) local frame computePunchingShearDiagramGeometry() itself uses
// internally. Re-derived here from `dir` alone because the returned rail
// object does not carry ux/uy (verified against that function's own
// `return { tag, dir, offsetAlongFace, studCount, firstStudOffsetMM,
// studSpacingMM, baseX, baseY, studs }` — no ux/uy field) — this mapping
// is copied verbatim from computePunchingShearDiagramGeometry()'s own
// n/s/w/e branch (punchingShearDiagram.mjs, the `if (dir==='n') {...}`
// block) so the mark-tag placement below stays consistent with where the
// real studs were actually placed, not re-derived independently.
function dirVector(dir) {
  if (dir === 'n') return { ux: 0, uy: -1 };
  if (dir === 's') return { ux: 0, uy: 1 };
  if (dir === 'w') return { ux: -1, uy: 0 };
  return { ux: 1, uy: 0 }; // 'e'
}

function renderPlanDXF(dxf, geometry, origin) {
  const { B, L: patchL, colX0, colX1, colY0, colY1, critX0, critX1, critY0, critY1, rails, studDia } = geometry.plan;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, patchL, B, LAYERS.CONCRETE_OUTLINE.name);

  closedRectDXF(
    dxf, ox + critX0, oy + critY0, critX1 - critX0, critY1 - critY0,
    LAYERS.CRITICAL_PERIMETER.name, { lineType: DASHED_LTYPE_NAME },
  );
  dxfText(
    dxf, ox + critX1 + CRIT_LABEL_GAP_MM, oy + critY1, SUBTITLE_HEIGHT_MM * 0.7,
    'CRITICAL PERIMETER, d/2 FROM COLUMN FACE (REF)',
    { layerName: LAYERS.CRITICAL_PERIMETER.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Bottom },
  );

  // Every stud across every rail, on one flat array: the true nearest
  // same-layer neighbor for a stud on one rail can be a stud on a
  // DIFFERENT, closely-offset rail (same face) or even a rail on an
  // adjacent face near the column corner — a single within-rail
  // studSpacingMM pitch only checks neighbors inside one rail, exactly
  // the cross-group case minPairwiseDistanceMM() was built for (see its
  // own header in structuralDrawingDxfKit.mjs). One global minimum pitch
  // is computed once and reused for every dot's safety cap, consistent
  // with slabOpeningDiagram.dxf.mjs's own established use of this function.
  const allStuds = rails.flatMap((r) => r.studs);
  const studPitch = minPairwiseDistanceMM(allStuds.map((s) => ({ x: ox + s.x, y: oy + s.y })));

  rails.forEach((r, i) => {
    const last = r.studs[r.studs.length - 1];
    dxf.addLine(point3d(ox + r.baseX, oy + r.baseY), point3d(ox + last.x, oy + last.y), { layerName: LAYERS.RAIL_LINE.name });

    for (const s of r.studs) {
      barDotDXF(dxf, ox + s.x, oy + s.y, studDia, studPitch, LAYERS.SHEAR_STUDS.name);
    }

    const { ux, uy } = dirVector(r.dir);
    const tagX = ox + last.x + ux * MARK_TAG_GAP_MM;
    const tagY = oy + last.y + uy * MARK_TAG_GAP_MM;
    barMarkTagDXF(dxf, tagX, tagY, String(i + 2), LAYERS.MARK_TAGS.name, {
      leaderTo: { x: ox + last.x, y: oy + last.y },
    });
  });

  closedRectDXF(dxf, ox + colX0, oy + colY0, colX1 - colX0, colY1 - colY0, LAYERS.CONCRETE_OUTLINE.name);
  barMarkTagDXF(dxf, ox + (colX0 + colX1) / 2, oy + (colY0 + colY1) / 2, '1', LAYERS.MARK_TAGS.name);

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + patchL, oy - MARGIN_MM * 0.6, `L = ${fmt0(patchL)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + B, `B = ${fmt0(B)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + patchL / 2, oy + B + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: patchL, height: B };
}

function renderSectionDXF(dxf, geometry, origin) {
  const { L: patchL, D, d, colX0, colX1, critX0, critX1 } = geometry.plan;
  const { x: sx, y: sy } = origin;

  closedRectDXF(dxf, sx, sy, patchL, D, LAYERS.CONCRETE_OUTLINE.name);

  const topFiber = sy + D;
  const colW = colX1 - colX0;
  closedRectDXF(dxf, sx + colX0, topFiber, colW, COLUMN_STUB_HEIGHT_MM, LAYERS.CONCRETE_OUTLINE.name);

  dxf.addLine(point3d(sx + critX0, sy), point3d(sx + critX0, sy + D), { layerName: LAYERS.CRITICAL_PERIMETER.name, lineType: DASHED_LTYPE_NAME });
  dxf.addLine(point3d(sx + critX1, sy), point3d(sx + critX1, sy + D), { layerName: LAYERS.CRITICAL_PERIMETER.name, lineType: DASHED_LTYPE_NAME });

  dimensionLineDXF(dxf, sx - MARGIN_MM * 0.6, topFiber, sx - MARGIN_MM * 0.6, topFiber - d, `d = ${fmt0(d)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, sx + patchL + MARGIN_MM * 0.6, sy, sx + patchL + MARGIN_MM * 0.6, sy + D, `D = ${fmt0(D)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, sx + patchL / 2, sy - SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION (THROUGH COLUMN, ALONG L)', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return { width: patchL, height: D + COLUMN_STUB_HEIGHT_MM, top: topFiber + COLUMN_STUB_HEIGHT_MM };
}

export function renderPunchingShearDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'punchingshear') {
    throw new DiagramError('BAD_PARAM', 'renderPunchingShearDiagramDXF expects a geometry object from computePunchingShearDiagramGeometry() (type "punchingshear").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);
  defineDashedLType(dxf);

  const planOrigin = { x: 0, y: 0 };
  const plan = renderPlanDXF(dxf, geometry, planOrigin);

  const sectionOriginX = plan.width + (opts.viewGapMM ?? VIEW_GAP_MM);
  const section = renderSectionDXF(dxf, geometry, { x: sectionOriginX, y: 0 });

  const overallWidth = (sectionOriginX + section.width) - planOrigin.x;
  const overallTop = Math.max(plan.height, section.top);
  dxfText(dxf, planOrigin.x + overallWidth / 2, overallTop + MARGIN_MM * 2.2, TITLE_HEIGHT_MM, `PUNCHING SHEAR ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
