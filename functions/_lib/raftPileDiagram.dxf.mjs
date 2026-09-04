// raftPileDiagram.dxf.mjs
// DXF render path for computeRaftPileDiagramGeometry() (raftPileDiagram.mjs),
// parallel to renderRaftPileDiagramSVG(). Zero modification to that file;
// geometry consumed as-is. English only, no schedule table, no caption —
// same v1 exclusions every sibling .dxf.mjs carries.
//
// Layer choice: raft slab, column footprints, section slab and column
// stubs are all CONCRETE_OUTLINE — the kit's own established generic
// member-outline layer (used this way by every prior element; a new
// layer is only spun off for a functionally distinct sub-feature, not
// for another member's own outline). PILE and REBAR_MESH_LINE were
// already added to the kit anticipating this file — both used as-is.
// No kit change was required for this element.
//
// Two views, stacked vertically (plan above, section below), not
// side-by-side like shearWallDiagram — both views share the same L
// extent, so vertical alignment is the more legible drafting choice.

import {
  DxfWriter, point3d, Units, LAYERS, defineDxfLayers, dxfText,
  closedRectDXF, dimensionLineDXF, DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

const MARGIN_MM = 300;
const VIEW_GAP_MM = 1000;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 150;
const MARK_TEXT_CAP_MM = 120;      // ceiling on mark-number text height regardless of pile/column size
const MIN_LABEL_HALF_MM = 80;      // column half-dimension floor to bother drawing its mark number
const STUB_HEIGHT_CAP_MM = 400;    // section column-stub visual height ceiling
const STUB_HEIGHT_FRACTION = 0.6;  // stub height as a fraction of col.b, below the cap

function fmt0(mm) {
  return String(Math.round(mm));
}

function renderPlanDXF(dxf, geometry, origin) {
  const { B, L: raftL, columns, piles, pileDia } = geometry.plan;
  const { mesh } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, raftL, B, LAYERS.CONCRETE_OUTLINE.name);

  for (const c of mesh.long.barCentersMM) {
    dxf.addLine(point3d(ox + c, oy), point3d(ox + c, oy + B), { layerName: LAYERS.REBAR_MESH_LINE.name });
  }
  for (const c of mesh.short.barCentersMM) {
    dxf.addLine(point3d(ox, oy + c), point3d(ox + raftL, oy + c), { layerName: LAYERS.REBAR_MESH_LINE.name });
  }

  piles.forEach((p, i) => {
    const cx = ox + p.offx, cy = oy + p.offy, r = pileDia / 2;
    dxf.addCircle(point3d(cx, cy), r, { layerName: LAYERS.PILE.name });
    dxfText(dxf, cx, cy, Math.min(r * 0.6, MARK_TEXT_CAP_MM), String(columns.length + i + 1), {
      layerName: LAYERS.MARK_TAGS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Middle,
    });
  });

  columns.forEach((c, i) => {
    const x = ox + c.offx - c.l / 2, y = oy + c.offy - c.b / 2;
    closedRectDXF(dxf, x, y, c.l, c.b, LAYERS.CONCRETE_OUTLINE.name);
    if (c.l / 2 >= MIN_LABEL_HALF_MM && c.b / 2 >= MIN_LABEL_HALF_MM) {
      dxfText(dxf, ox + c.offx, oy + c.offy, Math.min(Math.min(c.b, c.l) * 0.25, MARK_TEXT_CAP_MM), String(i + 1), {
        layerName: LAYERS.MARK_TAGS.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Middle,
      });
    }
  });

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + raftL, oy - MARGIN_MM * 0.6, `L = ${fmt0(raftL)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + B, `B = ${fmt0(B)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + raftL / 2, oy + B + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: raftL, height: B };
}

// origin.y is the raft's own underside (section box spans oy..oy+D);
// column stubs extend upward from oy+D, pile embedment stubs occupy the
// bottom pileEmbedMM of the D box, both matching the SVG source's own
// "embedded up from the underside" convention verbatim.
function renderSectionDXF(dxf, geometry, origin) {
  const { L: raftL, D, columns, piles, pileDia, pileEmbed } = geometry.plan;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, raftL, D, LAYERS.CONCRETE_OUTLINE.name);

  for (const p of piles) {
    const w = pileDia, h = Math.min(pileEmbed, D);
    closedRectDXF(dxf, ox + p.offx - w / 2, oy, w, h, LAYERS.PILE.name);
  }

  let maxStubHeight = 0;
  for (const c of columns) {
    const stubH = Math.min(STUB_HEIGHT_CAP_MM, c.b * STUB_HEIGHT_FRACTION);
    maxStubHeight = Math.max(maxStubHeight, stubH);
    closedRectDXF(dxf, ox + c.offx - c.l / 2, oy + D, c.l, stubH, LAYERS.CONCRETE_OUTLINE.name);
  }

  dimensionLineDXF(dxf, ox + raftL + MARGIN_MM * 0.6, oy, ox + raftL + MARGIN_MM * 0.6, oy + D, `D = ${fmt0(D)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // Title sits BELOW the section box (not above, unlike every sibling
  // view title) because column stubs occupy the space directly above it.
  dxfText(dxf, ox + raftL / 2, oy - SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION (representative, along L)', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return { width: raftL, height: D, maxStubHeight };
}

export function renderRaftPileDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'raftpile') {
    throw new DiagramError('BAD_PARAM', 'renderRaftPileDiagramDXF expects a geometry object from computeRaftPileDiagramGeometry() (type "raftpile").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const planOrigin = { x: 0, y: 0 };
  const plan = renderPlanDXF(dxf, geometry, planOrigin);

  const { D, columns } = geometry.plan;
  const maxStubHeight = columns.reduce((m, c) => Math.max(m, Math.min(STUB_HEIGHT_CAP_MM, c.b * STUB_HEIGHT_FRACTION)), 0);
  const gap = opts.viewGapMM ?? VIEW_GAP_MM;
  // top-of-stub always lands at exactly y = -gap regardless of D/columns —
  // see the arithmetic: -(gap+D+maxStubHeight) + D + maxStubHeight = -gap.
  const sectionOrigin = { x: 0, y: -(gap + D + maxStubHeight) };
  const section = renderSectionDXF(dxf, geometry, sectionOrigin);

  const overallWidth = Math.max(plan.width, section.width);
  dxfText(dxf, overallWidth / 2, plan.height + MARGIN_MM * 2.2, TITLE_HEIGHT_MM, `RAFT OVER PILE ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
