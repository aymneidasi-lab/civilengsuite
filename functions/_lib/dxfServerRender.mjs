// functions/_lib/dxfServerRender.mjs
//
// Server-side replacement for the old client-side dynamic-import mechanism.
// The DXF-kit modules (this file's sibling *.dxf.mjs files, plus
// structuralDrawingDxfKit.mjs and tarikjabiri-dxf.esm.js) now live only in
// functions/_lib, which the browser cannot reach over HTTP. Since chat.js
// runs in the same process as this file, generation moved server-side
// instead: chat.js calls renderDxfServerSide() with the exact same geometry
// object it already computed for the SVG, gets back finished DXF text (or a
// structured failure), and forwards the text — never a file path, never a
// module reference — to the client as part of the normal JSON response.
//
// Static imports only (no dynamic import() by computed path): this runs on
// Cloudflare Pages Functions (Workers runtime, confirmed by chat.js's own
// `export async function onRequestPost` / `onRequestOptions` signatures),
// which bundles each function via esbuild ahead of time. A dynamic
// import(`./${file}`) keyed off a runtime string is the same class of
// "resolve a path at the wrong time" bug this module exists to eliminate —
// every renderer below is a plain top-of-file import, exactly like chat.js
// already does for the SVG-side siblings of these same files.
//
// DXF_RENDERERS is the single source of truth for "which element types have
// a working DXF export." chat.js should derive its own DXF_READY_TYPES from
// Object.keys(DXF_RENDERERS) instead of maintaining a second, hand-written
// list — the entire multi-session bug history in chat.js's own comments
// (wallopening/couplingbeam/punchingshear/circularcolumn/deepbeam/
// elevatorpit/expansionjoint all drifting in or out of sync with the
// front-end's DXF_MODULE_MAP at one point or another) was exactly this
// class of two-lists-that-must-agree bug. One list, imported, ends it.

import { renderFootingDiagramDXF } from './footingDiagram.dxf.mjs';
import { renderSlabDiagramDXF } from './slabDiagram.dxf.mjs';
import { renderShearWallDiagramDXF } from './shearWallDiagram.dxf.mjs';
import { renderStairDiagramDXF } from './stairDiagram.dxf.mjs';
import { renderColumnDiagramDXF } from './columnDiagram.dxf.mjs';
import { renderBeamDiagramDXF } from './beamDiagram.dxf.mjs';
import { renderRetainingWallDiagramDXF } from './retainingWallDiagram.dxf.mjs';
import { renderTrapezoidalFootingDiagramDXF } from './trapezoidalFootingDiagram.dxf.mjs';
import { renderStrapFootingDiagramDXF } from './strapFootingDiagram.dxf.mjs';
import { renderGradeBeamDiagramDXF } from './gradeBeamDiagram.dxf.mjs';
import { renderPileCapDiagramDXF } from './pileCapDiagram.dxf.mjs';
import { renderSlabOpeningDiagramDXF } from './slabOpeningDiagram.dxf.mjs';
import { renderBasementWallDiagramDXF } from './basementWallDiagram.dxf.mjs';
import { renderCorbelDiagramDXF } from './corbelDiagram.dxf.mjs';
import { renderFlatSlabDropPanelDiagramDXF } from './flatSlabDropPanelDiagram.dxf.mjs';
import { renderHordiSlabDiagramDXF } from './hordiSlabDiagram.dxf.mjs';
import { renderExpansionJointDiagramDXF } from './expansionJointDiagram.dxf.mjs';
import { renderWallOpeningDiagramDXF } from './wallOpeningDiagram.dxf.mjs';
import { renderCouplingBeamDiagramDXF } from './couplingBeamDiagram.dxf.mjs';
import { renderPunchingShearDiagramDXF } from './punchingShearDiagram.dxf.mjs';
import { renderCircularColumnDiagramDXF } from './circularColumnDiagram.dxf.mjs';
import { renderDeepBeamDiagramDXF } from './deepBeamDiagram.dxf.mjs';
import { renderElevatorPitDiagramDXF } from './elevatorPitDiagram.dxf.mjs';
import { renderBeamColumnJointDiagramDXF } from './beamColumnJointDiagram.dxf.mjs';
import { renderCantileverSlabDiagramDXF } from './cantileverSlabDiagram.dxf.mjs';
import { renderRaftPileDiagramDXF } from './raftPileDiagram.dxf.mjs';


// elementType -> render function. Keys mirror chat.js's own
// DIAGRAM_TYPE_RENDERERS / REBAR_ELEMENT_DISPATCH vocabulary exactly
// (isolated/combined/strip/raft all share one footing renderer, corbel/
// bracket share one corbel renderer, gradebeam/tiebeam share one grade-beam
// renderer — same aliasing the old client-side DXF_MODULE_MAP used).
// raftpile / cantileverslab are deliberately absent: per footing_pro's own
// [REVERTED] note, those two .dxf.mjs files were verified in Node but never
// actually deployed, so a row here would just swap "wrong path" for "right
// path, wrong file" — same guaranteed failure, harder to diagnose. Add them
// once the actual files exist in this directory.
export const DXF_RENDERERS = {
  isolated: renderFootingDiagramDXF,
  combined: renderFootingDiagramDXF,
  strip: renderFootingDiagramDXF,
  raft: renderFootingDiagramDXF,
  slab: renderSlabDiagramDXF,
  shearwall: renderShearWallDiagramDXF,
  stair: renderStairDiagramDXF,
  column: renderColumnDiagramDXF,
  beam: renderBeamDiagramDXF,
  retainingwall: renderRetainingWallDiagramDXF,
  trapezoidal: renderTrapezoidalFootingDiagramDXF,
  strap: renderStrapFootingDiagramDXF,
  gradebeam: renderGradeBeamDiagramDXF,
  tiebeam: renderGradeBeamDiagramDXF,
  pilecap: renderPileCapDiagramDXF,
  slabopening: renderSlabOpeningDiagramDXF,
  basementwall: renderBasementWallDiagramDXF,
  corbel: renderCorbelDiagramDXF,
  bracket: renderCorbelDiagramDXF,
  dropcapital: renderFlatSlabDropPanelDiagramDXF,
  hordi: renderHordiSlabDiagramDXF,
  expansionjoint: renderExpansionJointDiagramDXF,
  wallopening: renderWallOpeningDiagramDXF,
  couplingbeam: renderCouplingBeamDiagramDXF,
  punchingshear: renderPunchingShearDiagramDXF,
  circularcolumn: renderCircularColumnDiagramDXF,
  deepbeam: renderDeepBeamDiagramDXF,
  elevatorpit: renderElevatorPitDiagramDXF,
  beamcolumnjoint: renderBeamColumnJointDiagramDXF,
  cantileverslab: renderCantileverSlabDiagramDXF,
  raftpile: renderRaftPileDiagramDXF,
};

export function isDxfReady(elementType) {
  return Object.prototype.hasOwnProperty.call(DXF_RENDERERS, elementType);
}

// Never throws. Always resolves to either { ok:true, dxfText } or
// { ok:false, code, message? } — chat.js can call this unconditionally and
// only needs to check `.ok` before deciding whether to attach dxfText to
// the response; a render failure here must never take down the SVG
// response that already succeeded.
export function renderDxfServerSide(elementType, geometry) {
  const renderFn = DXF_RENDERERS[elementType];
  if (typeof renderFn !== 'function') {
    return { ok: false, code: 'NOT_SUPPORTED' };
  }
  let dxfText;
  try {
    dxfText = renderFn(geometry);
  } catch (err) {
    return {
      ok: false,
      code: 'RENDER_EXCEPTION',
      message: err && err.message ? err.message : String(err),
    };
  }
  if (typeof dxfText !== 'string' || dxfText.length === 0) {
    return { ok: false, code: 'EMPTY_OUTPUT' };
  }
  return { ok: true, dxfText };
}
