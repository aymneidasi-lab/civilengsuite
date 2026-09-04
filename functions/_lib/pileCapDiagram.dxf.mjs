// pileCapDiagram.dxf.mjs
// DXF render path for the pile-cap reinforcement/embedment diagram —
// parallel to, and entirely separate from, renderPileCapDiagramSVG() in
// pileCapDiagram.mjs. Same placement rationale as
// shearWallDiagram.dxf.mjs: an ordinary /diagram or /rebar SVG request
// must never pull @tarikjabiri/dxf into the Worker's module graph; only
// a future DXF-export entry point does.
//
// computePileCapDiagramGeometry() is consumed exactly as-is, imported
// from pileCapDiagram.mjs with zero modification to that file. This
// module only renders; it never validates or computes.
//
// v1 scope exclusions carried over unchanged from the prompt: no Arabic
// labels (English only, hardcoded — not opts.lang-driven), no schedule
// table, no caption. For this element specifically that also means no
// mesh-diameter/spacing callout anywhere on the drawing: verified
// against the actual SVG source (renderPlan/renderSection) that, unlike
// shearWallDiagram's SVG, pileCapDiagram's SVG conveys dia/spacing/
// pileEmbed ONLY through the (DXF-excluded) schedule table, never
// through a drawn label or dimension line in the plan/section views
// themselves. This file carries that same absence forward — it is the
// source's own scope, not an oversight introduced here.
//
// ── Decisions specific to this element (verified against this file's
// own compute/render source; NOT assumed from shearWallDiagram) ──
//
// 1. Two-way bottom mesh is drawn as LINES, not bar-dots. Verified by
//    direct read of pileCapDiagram.mjs's renderPlan(): mesh.long/
//    short.barCentersMM each drive one full-span grid LINE (inline
//    stroke="#9ab3cf", no CSS class) — there is no per-intersection
//    <circle>, and the ".bar-dot-mesh" class defined in that file's
//    <style> block is dead code (grepped: zero elements reference it).
//    The master layer table's "REBAR-TOP ... bar-dot-mesh (pileCap and
//    raftPile)" entry names a class that isn't actually instantiated
//    here, but its LAYER INTENT (this element's one reinforcement mesh
//    -> REBAR-TOP) is honored: the grid lines below are drawn on
//    REBAR-TOP using the kit's own canonical hex (#1f5aa6), not the
//    SVG's own display-only #9ab3cf — same "shared layer keeps the
//    kit's curated color, not the literal SVG RGB" precedent
//    CONCRETE_OUTLINE already set (kit #1a1a1a vs. this file's own
//    inline "#333" stroke).
//
// 2. Pile circles are drawn at TRUE radius (pileDia/2), NOT through
//    barDotRadiusMM(). That kit function exists for the one exception
//    the units-decision carved out: rebar diameters (8-32mm) too small
//    to read at real-mm plot scale. Piles (250-1500mm here) are
//    themselves a real structural/geotechnical dimension at a scale
//    comparable to the column and cap outline; enlarging them the way a
//    rebar indication-dot is enlarged would misrepresent an actual
//    physical quantity. The SVG's own `Math.max(3, (pileDia/2)*scale)`
//    is a degenerate-px floor for on-screen visibility at small zoom,
//    not a legibility-enlargement rule — it has no real-mm analogue and
//    is dropped here, the same treatment shearWallDiagram.dxf.mjs gave
//    every other px-only SVG constant.
//
// 3. Pile-to-pile clear spacing is already enforced by
//    computePileCapDiagramGeometry() (PILES_OVERLAP, MIN_CLEAR_FACTOR)
//    — true center distance is always >= pileDia*1.25 for any geometry
//    this function successfully returns, i.e. always strictly greater
//    than 2x true radius. The render-time circle-overlap test in this
//    element's own DXF suite therefore verifies the render path doesn't
//    introduce its own scaling/offset bug — not that piles can collide
//    (that guard is compute's job, untouched).
//
// 4. No real "column height" exists in this element's own contract
//    (only colB/colL cross-section + plan position). The section
//    view's column stub above the cap is, same as the SVG's own
//    `Math.min(60, colB*scale*0.6)`, a representative visual
//    continuation, not a dimensioned height. COLUMN_STUB_FACTOR below
//    keeps the SVG's proportional intent (0.6 x colB — the SVG uses
//    colB, not colL, for this factor; matched exactly here even though
//    colL is the column's visible in-section width) and drops only the
//    arbitrary 60px screen-space ceiling, which has no real-mm
//    equivalent.
//
// 5. Pile-tag text (the bare "pile1"/"pile2".. label drawn inside each
//    plan-view circle) has no confirmed layer/CSS-class entry in the
//    master table. Placed on ANNOTATION as a flagged default — the
//    same treatment shearWallDiagram.dxf.mjs gave its own
//    "support-label" for the identical reason (no confirmed rule found
//    in either source file).
//
// 6. offx/offy in this element's own contract are already
//    orientation-neutral displacements "from the cap's own offx=0/
//    offy=0 edge" (pileCapDiagram.mjs's own header). Unlike
//    shearWallDiagram's SVG-to-DXF port, there is no SVG-down-to-DXF-up
//    flip to correct here: this file defines its own plan origin as
//    the (offx=0, offy=0) corner and maps offx/offy straight onto DXF
//    x/y with no sign inversion. The section view's pile-embedment
//    stubs ARE bottom-anchored at the cap's own underside (see note in
//    renderSectionViewDXF below) — the correct y-up translation of the
//    SVG's y-down `topY = sy + capH - embedH` anchor.
//
// 7. computeMeshLayer() (pileCapDiagram.mjs's own local helper) enforces
//    no minimum spacing floor on spacingLong/spacingShort (only
//    assertFinitePositive) — unlike shearWallDiagram's own schema. A
//    pathologically small spacing therefore produces an unbounded
//    barCentersMM array in BOTH the existing SVG path and this DXF
//    path; this file does not add a cap that the SVG source itself
//    doesn't have (adding one here that isn't in the source would be
//    exactly the kind of unrequested, unverified expansion the session
//    protocol rules out). Flagged, not silently patched — fixing it
//    would mean touching computeMeshLayer()/computePileCapDiagramGeometry(),
//    out of scope for this file.

import {
  DxfWriter,
  point3d,
  Units,
  LAYERS,
  defineDxfLayers,
  dxfText,
  closedRectDXF,
  dimensionLineDXF,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Layout conventions — chosen real-mm defaults for placement the SVG
// path never needed (it drew everything inside a fixed pixel canvas
// instead). All overridable via opts, all named so they're auditable.
// Same role as shearWallDiagram.dxf.mjs's own MARGIN_MM/VIEW_GAP_MM
// block; values re-chosen for this element, not imported from that file.
const MARGIN_MM = 300; // gutter around each view for dimension lines/labels
const VIEW_GAP_MM = 1000; // real-mm gap between plan and section views, model space — same convention value shearWallDiagram.dxf.mjs uses between its own two views, proportionate at this element's own size range (600-8000mm cap side)
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view titles (PLAN/SECTION), pile-tag text
const DIM_TEXT_HEIGHT_MM = 150;
const COLUMN_STUB_FACTOR = 0.6; // section-view column stub height above the cap = colB x this factor — mirrors the SVG's own proportional intent (Math.min(60, colB*scale*0.6)) without the arbitrary 60px screen-space ceiling, which has no real-mm equivalent (see header note 4)

function fmt0(mm) {
  return String(Math.round(mm));
}

function renderPlanViewDXF(dxf, geometry, origin, opts) {
  const { B, L: capL, column, piles, pileDia } = geometry.plan;
  const { mesh } = geometry;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, capL, B, LAYERS.CONCRETE_OUTLINE.name);

  // Two-way mesh grid — see header note 1. mesh.long.barCentersMM are
  // positions along L -> vertical lines spanning the full B height;
  // mesh.short.barCentersMM are positions along B -> horizontal lines
  // spanning the full L width. Direct translation of renderPlan()'s own
  // two loops (which draw the identical pair of full-span line sets).
  for (const c of mesh.long.barCentersMM) {
    dxf.addLine(point3d(ox + c, oy), point3d(ox + c, oy + B), { layerName: LAYERS.REBAR_TOP.name });
  }
  for (const c of mesh.short.barCentersMM) {
    dxf.addLine(point3d(ox, oy + c), point3d(ox + capL, oy + c), { layerName: LAYERS.REBAR_TOP.name });
  }

  const colW = column.colL, colH = column.colB;
  closedRectDXF(dxf, ox + column.centerLongMM - colW / 2, oy + column.centerShortMM - colH / 2, colW, colH, LAYERS.CONCRETE_OUTLINE.name);

  const pileR = pileDia / 2; // true radius, see header note 2
  for (const p of piles) {
    const cx = ox + p.offx, cy = oy + p.offy;
    dxf.addCircle(point3d(cx, cy), pileR, { layerName: LAYERS.PILE.name });
    dxfText(dxf, cx, cy, SUBTITLE_HEIGHT_MM * 0.5, p.tag, {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Middle,
    }); // flagged default placement, see header note 5
  }

  dimensionLineDXF(dxf, ox, oy - MARGIN_MM * 0.6, ox + capL, oy - MARGIN_MM * 0.6, `${fmt0(capL)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, ox - MARGIN_MM * 0.6, oy, ox - MARGIN_MM * 0.6, oy + B, `${fmt0(B)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  dxfText(dxf, ox + capL / 2, oy + B + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: capL, height: B, topY: B };
}

function renderSectionViewDXF(dxf, geometry, origin, opts) {
  const { L: capL, D, column, piles, pileDia, pileEmbed } = geometry.plan;
  const { x: ox, y: oy } = origin;

  closedRectDXF(dxf, ox, oy, capL, D, LAYERS.CONCRETE_OUTLINE.name);

  // Pile embedment stubs — bottom-anchored at the cap's own underside
  // (oy), extending up into the cap by pileEmbedMM. Correct y-up
  // translation of the SVG's y-down `topY = sy + capH - embedH` (which
  // anchors the stub to the cap's BOTTOM edge in screen space) — see
  // header note 6.
  const pileW = pileDia; // true diameter, same true-scale reasoning as the plan-view circles (header note 2)
  for (const p of piles) {
    const cx = ox + p.offx;
    closedRectDXF(dxf, cx - pileW / 2, oy, pileW, pileEmbed, LAYERS.PILE.name);
  }

  // Column stub, top-anchored at the cap's own top edge (oy+D),
  // extending further up — see header note 4.
  const stubH = column.colB * COLUMN_STUB_FACTOR;
  const colX = ox + column.centerLongMM - column.colL / 2;
  closedRectDXF(dxf, colX, oy + D, column.colL, stubH, LAYERS.CONCRETE_OUTLINE.name);

  dimensionLineDXF(dxf, ox + capL + MARGIN_MM * 0.5, oy, ox + capL + MARGIN_MM * 0.5, oy + D, `${fmt0(D)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  const topY = D + stubH;
  dxfText(dxf, ox + capL / 2, oy + topY + SUBTITLE_HEIGHT_MM * 0.5, SUBTITLE_HEIGHT_MM, 'SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: capL, height: D, topY };
}

export function renderPileCapDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'pilecap') {
    throw new DiagramError('BAD_PARAM', 'renderPileCapDiagramDXF expects a geometry object from computePileCapDiagramGeometry() (type "pilecap").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const planOrigin = { x: 0, y: 0 };
  const plan = renderPlanViewDXF(dxf, geometry, planOrigin, opts);

  const sectionOriginX = geometry.plan.L + (opts.viewGapMM ?? VIEW_GAP_MM);
  const section = renderSectionViewDXF(dxf, geometry, { x: sectionOriginX, y: 0 }, opts);

  const overallWidth = (sectionOriginX + section.width) - planOrigin.x;
  // Neither view is guaranteed taller than the other for this element —
  // B (600-8000mm) and D (400-2500mm)+stub have no cross-constraint in
  // computePileCapDiagramGeometry(), unlike shearWallDiagram where
  // heightMM always dominates thicknessMM in practice. Computed, not
  // assumed.
  const highestViewTop = Math.max(plan.topY, section.topY);
  dxfText(dxf, planOrigin.x + overallWidth / 2, highestViewTop + MARGIN_MM * 2.2, TITLE_HEIGHT_MM, `PILE CAP ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
