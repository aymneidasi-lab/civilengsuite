// slabDiagram.dxf.mjs
// DXF render path for the two-way slab reinforcement diagram — parallel to,
// and entirely separate from, renderSlabDiagramSVG() in slabDiagram.mjs.
// Placement decided by the same explicit session rule shearWallDiagram
// used (separate file, not a function added to slabDiagram.mjs)
// specifically so an ordinary /diagram or /rebar SVG request never pulls
// @tarikjabiri/dxf into the Worker's module graph — only whatever future
// entry point actually asks for a DXF export does.
//
// computeSlabDiagramGeometry() is consumed exactly as-is, imported from
// slabDiagram.mjs with zero modification to that file. This module only
// renders; it never validates or computes.
//
// v1 scope exclusions carried over unchanged from برومبت_تحويل_DXF_عام_v1.md:
// no Arabic labels (English only, hardcoded — not opts.lang-driven, unlike
// the SVG version), no schedule table, no multi-line caption, and — new
// for this element specifically — no plan-view "bottom mesh / top mesh"
// legend (the SVG source's small dot+text key is schedule/caption-adjacent
// cosmetic annotation, not structural geometry; layer color alone already
// distinguishes REBAR-TOP from REBAR-BOTTOM in any DXF viewer). All
// omissions are deliberate, not oversights.
//
// TOP/BOTTOM MESH PLAN-VIEW POSITION — deliberate divergence from the SVG
// source, not a fidelity gap: slabDiagram.mjs's renderPlanView() offsets
// the top-mesh dot grid by a fixed 5px purely so the two dot layers stay
// visually distinguishable on screen, and says so explicitly in its own
// comment ("this offset is a drafting convenience only, never a claimed
// position" — real top/bottom bars occupy the SAME plan (x,y) footprint
// at different depths). Per this session's unit decision (real DXF
// coordinates only, no rescaled/cosmetic offsets), this file draws top
// and bottom mesh dots at their true, identical plan (x,y): REBAR-TOP and
// REBAR-BOTTOM are already distinct layers/colors, which gives the same
// visual separation the SVG offset existed for, without misstating
// geometry that has no real x/y difference.

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
  MARK_TAG_RADIUS_MM,
  distributeTicks,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Duplicated from slabDiagram.mjs — that file does not export these (they
// are unexported module-level consts used only inside its own render
// functions), and this file must not be edited to add an export (zero
// modification to the existing file, per session scope). Flagged here
// explicitly so a future change to the source values does not silently
// desync: verified byte-identical against slabDiagram.mjs lines 86-87 at
// time of writing.
const MAX_MESH_ROWS = 14;
const MAX_MESH_COLS = 14;

// ── Layout conventions ──────────────────────────────────────────────
// None of these come from geometry or from the prompt; each is a chosen
// default for real-mm placement that the SVG path never needed (it drew
// everything inside a fixed pixel canvas instead). All overridable via
// opts, all named so they're auditable. Reused unchanged from
// shearWallDiagram.dxf.mjs where the same generic role applies (margin,
// view gap, text heights); slab-specific values (representative dot
// count, edge-tag offsets) are derived fresh below with their own
// reasoning, per this session's own real-mm layout for this element.
const MARGIN_MM = 300; // gutter around the plan view for dimension lines/labels/mark tags
const VIEW_GAP_MM = 1000; // real-mm gap between plan and section views, model space
const SECTION_EDGE_MARGIN_MM = 60; // inset from the section strip's ends to its first/last bar dot
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view titles (MESH PLAN/SECTION), mark tags
const DIM_TEXT_HEIGHT_MM = 150;

// Representative dot count for the section strip — mirrors
// slabDiagram.mjs's own renderSectionView(), which draws
// Math.min(mesh.X.countX, 6) dots across the strip (inline literal, not a
// module constant, so there is nothing to import — this is a fresh named
// constant chosen to match that same visual density, not a duplicated
// source value).
const SECTION_REPRESENTATIVE_DOTS = 6;

// Edge-tag placement for extraTopBars[] callouts (plan view). 600mm
// clears every interaction checked for this layout:
//  - vs. the length/width dimension lines' own tick extent (±TICK_CAP_MM
//    default 40mm around a line offset by MARGIN_MM*0.6=180mm from the
//    panel edge -> reaches 220mm out at most): 600-150(tag radius)=450mm
//    clearance, well clear of 220mm.
//  - vs. the bottom/top mesh-spec mark tags stacked at
//    lengthMM+MARGIN_MM*0.8=240mm on the right margin: a 'right'-edge
//    extra-bar tag at 600mm is 360mm away in X alone (>=2*
//    MARK_TAG_RADIUS_MM=300mm), which guarantees no overlap regardless of
//    Y — verified empirically below (MARK-TAGS overlap test).
const EXTRA_BAR_TAG_OFFSET_MM = 600;

// Vertical shift applied to 'left'/'right' edge-tag positions only, off
// the panel's exact vertical middle. Without this, a 'left' or 'right'
// extraTopBars tag sits at the exact same Y as the width dimension
// line's label (dimensionLineDXF always centers a 'v' label on the
// line's midpoint) — 600mm clears the label's own vertical text extent
// (~half of DIM_TEXT_HEIGHT_MM) with margin to spare.
const LEFT_RIGHT_TAG_Y_SHIFT_MM = 600;

// Vertical step between the stacked bottom-mesh and top-mesh spec mark
// tags on the plan view's right margin. Must clear 2x
// MARK_TAG_RADIUS_MM=300mm between tag centers; 500mm leaves a visible
// gap.
const MARK_TAG_STACK_STEP_MM = 500;

function fmt0(mm) {
  return String(Math.round(mm));
}

function meshPitchXY(xs, ys) {
  // Dual-axis pitch check per this session's unit decision #1: measure
  // both the horizontal and vertical distance between neighboring dots
  // on THIS mesh's own drawn grid, take the smaller, so barDotRadiusMM's
  // enlargement can never make two dots on the same grid touch on either
  // axis.
  const pitchX = xs.length > 1 ? xs[1] - xs[0] : Infinity;
  const pitchY = ys.length > 1 ? ys[1] - ys[0] : Infinity;
  return Math.min(pitchX, pitchY);
}

function drawMeshGridDXF(dxf, ox, oy, lengthMM, widthMM, meshGeom, layerName) {
  const xs = distributeTicks(ox, ox + lengthMM, Math.min(meshGeom.countX, MAX_MESH_COLS));
  const ys = distributeTicks(oy, oy + widthMM, Math.min(meshGeom.countY, MAX_MESH_ROWS));
  const pitch = meshPitchXY(xs, ys);
  for (const y of ys) {
    for (const x of xs) {
      barDotDXF(dxf, x, y, meshGeom.dia, pitch, layerName);
    }
  }
}

function renderPlanViewDXF(dxf, geometry, origin, opts) {
  const { lengthMM, widthMM, mesh, extraTopBars } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, lengthMM, widthMM, LAYERS.CONCRETE_OUTLINE.name);

  // Bottom mesh (required) — see file header for why top/bottom share the
  // true (x,y) grid instead of the SVG source's cosmetic offset.
  drawMeshGridDXF(dxf, ox, oy, lengthMM, widthMM, mesh.bottom, LAYERS.REBAR_BOTTOM.name);
  if (mesh.top) {
    drawMeshGridDXF(dxf, ox, oy, lengthMM, widthMM, mesh.top, LAYERS.REBAR_TOP.name);
  }

  // extraTopBars edge callouts — direct translation of the SVG source's
  // edgeMarkPositions, Y-flipped for this file's upward-y convention (see
  // shearWallDiagram.dxf.mjs's own note on the same SVG-down vs DXF-up
  // mismatch: SVG "top" = smaller sy = visually above; this file's "top"
  // = larger y = oy+widthMM+offset). Known, unchanged limitation carried
  // over from the SVG source: multiple zones sharing the same edge are
  // positioned identically (edgeMarkPositions is keyed by edge, not by
  // zone) and will visually coincide — the source has this same behavior
  // (renderPlanView's own extraTopBars.forEach uses the same
  // per-edge-only lookup), not something introduced by this conversion,
  // and fixing it is out of this session's scope (no compute/render
  // contract change beyond a faithful real-mm translation).
  const hasTopEdgeExtra = extraTopBars.some((z) => z.edge === 'top');
  const edgePos = {
    top: { x: ox + lengthMM / 2, y: oy + widthMM + EXTRA_BAR_TAG_OFFSET_MM },
    bottom: { x: ox + lengthMM / 2, y: oy - EXTRA_BAR_TAG_OFFSET_MM },
    left: { x: ox - EXTRA_BAR_TAG_OFFSET_MM, y: oy + widthMM / 2 + LEFT_RIGHT_TAG_Y_SHIFT_MM },
    right: { x: ox + lengthMM + EXTRA_BAR_TAG_OFFSET_MM, y: oy + widthMM / 2 + LEFT_RIGHT_TAG_Y_SHIFT_MM },
  };
  for (const z of extraTopBars) {
    const p = edgePos[z.edge];
    barMarkTagDXF(dxf, p.x, p.y, `${z.count}\u00d8${fmt0(z.dia)}`, LAYERS.MARK_TAGS.name);
  }

  // Mesh spec mark tags — bottom always; top (if present) stacked one
  // step further out so the two bubbles never touch.
  const tagX = ox + lengthMM + MARGIN_MM * 0.8;
  const bottomTagY = oy + widthMM - MARGIN_MM * 0.5;
  barMarkTagDXF(
    dxf, tagX, bottomTagY,
    `\u00d8${fmt0(mesh.bottom.dia)}@${fmt0(mesh.bottom.spacingX)}/${fmt0(mesh.bottom.spacingY)}`,
    LAYERS.MARK_TAGS.name,
  );
  if (mesh.top) {
    barMarkTagDXF(
      dxf, tagX, bottomTagY - MARK_TAG_STACK_STEP_MM,
      `\u00d8${fmt0(mesh.top.dia)}@${fmt0(mesh.top.spacingX)}/${fmt0(mesh.top.spacingY)}`,
      LAYERS.MARK_TAGS.name,
    );
  }

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + lengthMM, oy - MARGIN_MM * 0.6, `${fmt0(lengthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + widthMM, `${fmt0(widthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // View title stacks just outside the top-edge extra-bar tag's own
  // extent when one is present (same clearance convention
  // shearWallDiagram.dxf.mjs uses for its boundary-element zone-label ->
  // view-title gap), else a small default gap.
  const titleGap = hasTopEdgeExtra
    ? EXTRA_BAR_TAG_OFFSET_MM + MARK_TAG_RADIUS_MM + SUBTITLE_HEIGHT_MM * 0.3
    : SUBTITLE_HEIGHT_MM * 0.5;
  dxfText(dxf, ox + lengthMM / 2, oy + widthMM + titleGap, SUBTITLE_HEIGHT_MM, 'MESH PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: lengthMM, height: widthMM, topGap: titleGap };
}

function renderSectionViewDXF(dxf, geometry, origin, opts) {
  const { thicknessMM, coverMM, mesh } = geometry;
  const { x: ox, y: oy } = origin;
  const edgeMargin = SECTION_EDGE_MARGIN_MM;

  const drawBottom = Math.min(mesh.bottom.countX, SECTION_REPRESENTATIVE_DOTS);
  const drawTop = mesh.top ? Math.min(mesh.top.countX, SECTION_REPRESENTATIVE_DOTS) : 0;
  const neededBottom = (drawBottom - 1) * mesh.bottom.spacingX;
  const neededTop = mesh.top ? (drawTop - 1) * mesh.top.spacingX : 0;
  const stripLenMM = Math.max(neededBottom, neededTop) + 2 * edgeMargin;

  closedRectDXF(dxf, ox, oy, stripLenMM, thicknessMM, LAYERS.CONCRETE_OUTLINE.name);

  const nearY = oy + coverMM; // bottom-face reinforcement, near the bottom cover
  const farY = oy + thicknessMM - coverMM; // top-face reinforcement, near the top cover
  const nearFarGap = farY - nearY; // the other axis these dots could collide across (dual-axis check)
  const lineInset = Math.min(edgeMargin * 0.5, stripLenMM / 2 - 1);

  dxf.addLine(point3d(ox + lineInset, nearY), point3d(ox + stripLenMM - lineInset, nearY), { layerName: LAYERS.REBAR_BOTTOM.name });
  const bottomPitch = Math.min(drawBottom > 1 ? mesh.bottom.spacingX : Infinity, nearFarGap);
  for (let i = 0; i < drawBottom; i++) {
    barDotDXF(dxf, ox + edgeMargin + i * mesh.bottom.spacingX, nearY, mesh.bottom.dia, bottomPitch, LAYERS.REBAR_BOTTOM.name);
  }

  if (mesh.top) {
    dxf.addLine(point3d(ox + lineInset, farY), point3d(ox + stripLenMM - lineInset, farY), { layerName: LAYERS.REBAR_TOP.name });
    const topPitch = Math.min(drawTop > 1 ? mesh.top.spacingX : Infinity, nearFarGap);
    for (let i = 0; i < drawTop; i++) {
      barDotDXF(dxf, ox + edgeMargin + i * mesh.top.spacingX, farY, mesh.top.dia, topPitch, LAYERS.REBAR_TOP.name);
    }
  }

  dimensionLineDXF(dxf, ox + stripLenMM + MARGIN_MM * 0.5, oy, ox + stripLenMM + MARGIN_MM * 0.5, oy + thicknessMM, `${fmt0(thicknessMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, nearY, `${fmt0(coverMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + stripLenMM / 2, oy + thicknessMM + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: stripLenMM, height: thicknessMM };
}

export function renderSlabDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'slab') {
    throw new DiagramError('BAD_PARAM', 'renderSlabDiagramDXF expects a geometry object from computeSlabDiagramGeometry() (type "slab").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const planOrigin = { x: 0, y: 0 };
  const plan = renderPlanViewDXF(dxf, geometry, planOrigin, opts);

  const sectionOriginX = geometry.lengthMM + (opts.viewGapMM ?? VIEW_GAP_MM);
  const section = renderSectionViewDXF(dxf, geometry, { x: sectionOriginX, y: 0 }, opts);

  const overallWidth = (sectionOriginX + section.width) - planOrigin.x;
  // Stacks just outside the "MESH PLAN" view-title's own text extent
  // (SUBTITLE_HEIGHT_MM tall), adaptively covering the has-extraTopBars-
  // on-top case — unlike shearWallDiagram.dxf.mjs's fixed MARGIN_MM*2.2
  // offset (safe there only because that file's own max stack height,
  // with a boundary element, is much shorter than slab's optional
  // extra-bar-tag stack can be).
  const sheetTitleY = plan.height + plan.topGap + SUBTITLE_HEIGHT_MM * 1.5;
  dxfText(dxf, planOrigin.x + overallWidth / 2, sheetTitleY, TITLE_HEIGHT_MM, `SLAB ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
