// functions/_lib/hordiSlabDiagram.mjs
//
// New-element track, Part 2 — pool 3 candidate ("ECP 203 coverage gaps"),
// per برومبت_استكمال_العمل_v17.md's gate: One-Way Ribbed / Hollow-Block
// "Hordi" Slab. Deterministic, zero-AI SVG generator for a typical
// cross-section + single-rib longitudinal section + bar-bending schedule
// of a one-way ribbed (block-and-rib) slab — the standard Egyptian-
// practice floor system with no direct ACI equivalent. Same philosophy as
// every other module in this app: every dimension, bar position, and
// count in the output is arithmetic on the KB data supplied, never a
// model's guess. This module owns compute+render only; it does not decide
// bar counts, diameters, spacing, or rib/block sizing — that is the
// KB/design layer's job (see INPUT CONTRACT below).
//
// ── \u26a0 NON-DELETABLE WARNING (per this session's own gate note) \u2500\u2500\u2500\u2500\u2500\u2500
// This module's schema accepts ribWidthMM/blockWidthMM/toppingMM as raw
// numbers from the caller and validates them ONLY against generic
// drawability sanity caps (MIN_*/MAX_* below) \u2014 NOT against ECP 203's own
// specific numeric limits (commonly cited: max clear rib spacing \u2248700mm,
// min topping thickness \u224850mm or span/10 whichever governs). Those two
// figures, as sourced for this project's own candidate note, come from
// secondary university lecture material citing ECP 203, not from a direct
// reading of the official code text at the time this file was written.
// Do NOT treat this module's acceptance of a given blockWidthMM/toppingMM
// as confirmation of ECP 203 compliance \u2014 verify the real limits against
// the official code text independently before using this module's output
// for construction. This warning must not be removed by a future edit
// without that verification actually happening first; it is repeated in
// the on-drawing caption (see L.en/L.ar.caption below) for the same
// reason \u2014 so it travels with the artifact, not just this source file.
//
// ── SCOPE (v1) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
// A single simply-supported one-way ribbed panel: ONE clear span, constant
// rectangular ribs (no taper) at a constant clear spacing (the hollow
// block width), a constant topping thickness, ONE bottom bar group per
// rib (identical in every rib \u2014 same "single symmetric group" convention
// columnDiagram.mjs's ties / wallOpeningDiagram.mjs's trim-bar group use),
// and an OPTIONAL single support top-bar group per rib (also identical in
// every rib). A representative topping shrinkage/temperature mesh
// (single diameter/spacing, both directions) is drawn schematically, not
// tied to a real plan area (see MESH_GRID_N below).
// NOT modeled, on purpose (each needs a parametrization this module
// hasn't been given yet, same "explicit scope boundary" convention every
// sibling module's header uses):
//   - tapered ribs (narrower at the bottom, wider under the block) \u2014 v1
//     draws a constant-width rectangular rib only.
//   - stirrups within the ribs \u2014 common Hordi practice omits them for
//     narrow ribs; a project that needs them is not representable here
//     without its own stirrup-zone schema (see beamDiagram.mjs's
//     stirrupZones for the shape such a field would need).
//   - continuous multi-span ribs, the real negative-moment envelope, or
//     any code-based cutoff-point rule for support top steel \u2014 topBars,
//     if supplied, is drawn as ONE symmetric extent at each support end
//     (extentMM is a caller-supplied DRAWN length, exactly the
//     "extensionMM" honesty convention corbelDiagram.mjs/
//     raftPileDiagram.mjs already use), never a computed development
//     length or moment-based cutoff.
//   - transverse/distribution ("kammar") secondary ribs some ECP designs
//     add across the main ribs at intervals \u2014 a materially different
//     plan-layout element this file has no field for.
//   - the hollow block's own real internal geometry (cavities/webs) \u2014
//     drawn as a single hatched rectangle standing in for the block,
//     schematic only, never a real block-catalog shape.
//   - validating ribWidthMM/blockWidthMM/toppingMM against ECP 203's own
//     numeric limits \u2014 see the NON-DELETABLE WARNING above; only generic
//     drawability sanity caps are enforced here.
//   - computing the real total rib count from a supplied panel width
//     unless the caller explicitly supplies totalSlabWidthMM \u2014 omit it
//     and the schedule reports per-rib quantities only, never a guessed
//     total.
//
// ── INPUT CONTRACT (what the KB layer should hand this module) \u2500\u2500\u2500\u2500\u2500\u2500\u2500
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   slabId?: string,                   // panel mark, e.g. "RS-1"
//   spanMM: number,                    // clear span of the ribs (one direction, simple span)
//   toppingMM: number,                 // topping (flange) thickness above the blocks
//   ribDepthMM: number,                // rib depth BELOW the topping (web depth only;
//                                      // total slab depth = toppingMM + ribDepthMM)
//   ribWidthMM: number,                // rib (web) width, constant, rectangular
//   blockWidthMM: number,              // hollow-block width = clear spacing between adjacent rib webs
//   ribsShown?: number,                // how many ribs to DRAW in the typical cross-section
//                                      // (a schematic choice, default 3, 2..6) \u2014 unrelated to
//                                      // the real total rib count; see totalSlabWidthMM below
//   totalSlabWidthMM?: number,         // OPTIONAL: full panel width perpendicular to the ribs.
//                                      // Supplied -> schedule computes the real total rib count
//                                      // (fence-post arithmetic on ribWidthMM/blockWidthMM, see
//                                      // computeTotalRibCount). Omitted -> schedule reports
//                                      // per-rib-shown quantities only, no invented total.
//   coverMM: number,                   // concrete cover to the bottom bar face, per rib
//   mainBars: {                        // ONE bottom bar group, identical in every rib
//     diameterMM: number, count: number,       // count = bars WITHIN a single rib (usually 1-2)
//     extraLengthAtEachEndMM?: number,         // default 0 \u2014 drawn extension beyond the clear
//                                              // span at each end; NOT a computed development length
//     cuttingLengthMM?: number,                // full bar length if the KB layer already computed
//                                              // it; omit to show (spanMM + 2*extraLength) labeled "(extent)"
//   },
//   topBars?: {                        // OPTIONAL support/negative-moment steel, identical in every rib
//     diameterMM: number, count: number,
//     extentMM: number,                        // drawn length from EACH support inward \u2014 caller-
//                                              // supplied, never a computed moment-based cutoff
//     cuttingLengthMM?: number,                // full bar length if already computed; omit to show
//                                              // extentMM labeled "(extent)"
//   },
//   toppingMesh: { diameterMM: number, spacingMM: number }, // shrinkage/temperature mesh in the
//                                      // topping, single value both directions, drawn as a
//                                      // representative schematic grid (see MESH_GRID_N)
// }
//
// ── Resource lifecycle \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
// Pure/synchronous, same as every sibling module \u2014 no timers, no fetch,
// no KV, no external handles of any kind, no `env.AI`, no randomness. The
// MIN_*/MAX_* caps below exist to bound Worker CPU time and output size on
// a request-scoped isolate, not to manage a leakable resource.
//
// ── Wiring status \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
// [Build-only, per این session's Phase A / Phase B split] This file is
// deliberately NOT wired into diagramCommandRouter.mjs, chat.js's three
// dispatch tables, or either footing_pro/pc_suite HTML front end \u2014 that
// wiring is this project's own documented definition of "done" for a new
// element (see برومبت_استكمال_العمل_v17.md's Part 2, Phase B), and is
// skipped here only because Phase B is a separate, later, explicitly-
// requested batch step \u2014 not an architectural blocker. Whoever performs
// that wiring later should follow columnDiagram.mjs's own router/chat.js
// entries as the direct template (this file's parseDiagramCommand below
// already matches that module's leading-token + key=value convention,
// token 'hordi', already lowercase \u2014 see the shearWall/shearwall lesson
// this project's own notes warn against repeating).

import {
  DiagramError, toMm, assertFinitePositive, assertFiniteNonNegative, assertInt,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, distributeTicks, barMarkTag,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps (drawability only \u2014 see NON-DELETABLE WARNING above; these
// are NOT ECP 203 compliance limits) ────────────────────────────────────
const MIN_SPAN_MM = 1000;
const MAX_SPAN_MM = 8000;
const MIN_TOPPING_MM = 30;
const MAX_TOPPING_MM = 150;
const MIN_RIB_DEPTH_MM = 100;
const MAX_RIB_DEPTH_MM = 500;
const MIN_RIB_WIDTH_MM = 80;
const MAX_RIB_WIDTH_MM = 400;
const MIN_BLOCK_WIDTH_MM = 150;
const MAX_BLOCK_WIDTH_MM = 700;
const MIN_RIBS_SHOWN = 2;
const MAX_RIBS_SHOWN = 6;
const MIN_BAR_COUNT_PER_RIB = 1;
const MAX_BAR_COUNT_PER_RIB = 4;
const MIN_MESH_SPACING_MM = 100;
const MAX_MESH_SPACING_MM = 300;
const MESH_GRID_N = 4; // fixed representative NxN grid \u2014 see renderMeshDetail; not tied to a real plan area

// ── Compute ──────────────────────────────────────────────────────────
export function computeHordiSlabDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Hordi slab diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.slabId != null ? String(raw.slabId).slice(0, 40) : 'RS';

  const spanMM = toMm(raw.spanMM, unit);
  assertFinitePositive('spanMM', spanMM);
  if (spanMM < MIN_SPAN_MM || spanMM > MAX_SPAN_MM) {
    throw new DiagramError('BAD_PARAM', `"spanMM" must be between ${MIN_SPAN_MM}mm and ${MAX_SPAN_MM}mm for this schematic, got ${spanMM}mm.`);
  }

  const toppingMM = toMm(raw.toppingMM, unit);
  assertFinitePositive('toppingMM', toppingMM);
  if (toppingMM < MIN_TOPPING_MM || toppingMM > MAX_TOPPING_MM) {
    throw new DiagramError('BAD_PARAM', `"toppingMM" must be between ${MIN_TOPPING_MM}mm and ${MAX_TOPPING_MM}mm for this schematic, got ${toppingMM}mm.`);
  }

  const ribDepthMM = toMm(raw.ribDepthMM, unit);
  assertFinitePositive('ribDepthMM', ribDepthMM);
  if (ribDepthMM < MIN_RIB_DEPTH_MM || ribDepthMM > MAX_RIB_DEPTH_MM) {
    throw new DiagramError('BAD_PARAM', `"ribDepthMM" must be between ${MIN_RIB_DEPTH_MM}mm and ${MAX_RIB_DEPTH_MM}mm for this schematic, got ${ribDepthMM}mm.`);
  }

  const ribWidthMM = toMm(raw.ribWidthMM, unit);
  assertFinitePositive('ribWidthMM', ribWidthMM);
  if (ribWidthMM < MIN_RIB_WIDTH_MM || ribWidthMM > MAX_RIB_WIDTH_MM) {
    throw new DiagramError('BAD_PARAM', `"ribWidthMM" must be between ${MIN_RIB_WIDTH_MM}mm and ${MAX_RIB_WIDTH_MM}mm for this schematic, got ${ribWidthMM}mm.`);
  }

  const blockWidthMM = toMm(raw.blockWidthMM, unit);
  assertFinitePositive('blockWidthMM', blockWidthMM);
  if (blockWidthMM < MIN_BLOCK_WIDTH_MM || blockWidthMM > MAX_BLOCK_WIDTH_MM) {
    throw new DiagramError('BAD_PARAM', `"blockWidthMM" must be between ${MIN_BLOCK_WIDTH_MM}mm and ${MAX_BLOCK_WIDTH_MM}mm for this schematic, got ${blockWidthMM}mm — this is a drawability cap only, NOT an ECP 203 compliance check (see file header).`);
  }

  const ribsShown = raw.ribsShown != null ? raw.ribsShown : 3;
  assertInt('ribsShown', ribsShown, { min: MIN_RIBS_SHOWN, max: MAX_RIBS_SHOWN });

  const coverMM = toMm(raw.coverMM, unit);
  assertFinitePositive('coverMM', coverMM);

  if (!raw.mainBars || typeof raw.mainBars !== 'object') {
    throw new DiagramError('BAD_PARAM', '"mainBars" is required: { diameterMM, count, extraLengthAtEachEndMM?, cuttingLengthMM? }.');
  }
  const mainDia = toMm(raw.mainBars.diameterMM, unit);
  assertFinitePositive('mainBars.diameterMM', mainDia);
  assertInt('mainBars.count', raw.mainBars.count, { min: MIN_BAR_COUNT_PER_RIB, max: MAX_BAR_COUNT_PER_RIB });
  const mainExtra = raw.mainBars.extraLengthAtEachEndMM != null ? toMm(raw.mainBars.extraLengthAtEachEndMM, unit) : 0;
  assertFiniteNonNegative('mainBars.extraLengthAtEachEndMM', mainExtra);
  const mainCuttingLengthMM = raw.mainBars.cuttingLengthMM != null ? toMm(raw.mainBars.cuttingLengthMM, unit) : null;
  if (mainCuttingLengthMM != null) assertFinitePositive('mainBars.cuttingLengthMM', mainCuttingLengthMM);

  const mainBarPositions = ribBarXPositions(raw.mainBars.count, ribWidthMM, coverMM, mainDia, 'mainBars');

  let topBars = null;
  if (raw.topBars != null) {
    if (typeof raw.topBars !== 'object') throw new DiagramError('BAD_PARAM', '"topBars" must be an object: { diameterMM, count, extentMM, cuttingLengthMM? }.');
    const topDia = toMm(raw.topBars.diameterMM, unit);
    assertFinitePositive('topBars.diameterMM', topDia);
    assertInt('topBars.count', raw.topBars.count, { min: MIN_BAR_COUNT_PER_RIB, max: MAX_BAR_COUNT_PER_RIB });
    const extentMM = toMm(raw.topBars.extentMM, unit);
    assertFinitePositive('topBars.extentMM', extentMM);
    if (2 * extentMM >= spanMM) {
      throw new DiagramError('TOP_BAR_EXTENT_TOO_LONG', `"topBars.extentMM" (${extentMM}mm) at each end must together be less than "spanMM" (${spanMM}mm), got 2\u00d7${extentMM}=${2 * extentMM}mm.`);
    }
    const topCuttingLengthMM = raw.topBars.cuttingLengthMM != null ? toMm(raw.topBars.cuttingLengthMM, unit) : null;
    if (topCuttingLengthMM != null) assertFinitePositive('topBars.cuttingLengthMM', topCuttingLengthMM);
    const topBarPositions = ribBarXPositions(raw.topBars.count, ribWidthMM, coverMM, topDia, 'topBars');
    topBars = { dia: topDia, count: raw.topBars.count, extentMM, cuttingLengthMM: topCuttingLengthMM, positions: topBarPositions };
  }

  if (!raw.toppingMesh || typeof raw.toppingMesh !== 'object') {
    throw new DiagramError('BAD_PARAM', '"toppingMesh" is required: { diameterMM, spacingMM }.');
  }
  const meshDia = toMm(raw.toppingMesh.diameterMM, unit);
  assertFinitePositive('toppingMesh.diameterMM', meshDia);
  const meshSpacing = toMm(raw.toppingMesh.spacingMM, unit);
  assertFinitePositive('toppingMesh.spacingMM', meshSpacing);
  if (meshSpacing < MIN_MESH_SPACING_MM || meshSpacing > MAX_MESH_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"toppingMesh.spacingMM" must be between ${MIN_MESH_SPACING_MM}mm and ${MAX_MESH_SPACING_MM}mm, got ${meshSpacing}mm.`);
  }

  let totalSlabWidthMM = null;
  let totalRibCount = null;
  if (raw.totalSlabWidthMM != null) {
    totalSlabWidthMM = toMm(raw.totalSlabWidthMM, unit);
    assertFinitePositive('totalSlabWidthMM', totalSlabWidthMM);
    if (totalSlabWidthMM < ribWidthMM) {
      throw new DiagramError('TOTAL_WIDTH_TOO_NARROW', `"totalSlabWidthMM" (${totalSlabWidthMM}mm) must be at least one rib width (${ribWidthMM}mm).`);
    }
    totalRibCount = computeTotalRibCount(totalSlabWidthMM, ribWidthMM, blockWidthMM);
  }

  const totalDepthMM = toppingMM + ribDepthMM;
  const totalShownWidthMM = ribsShown * ribWidthMM + (ribsShown - 1) * blockWidthMM;

  return {
    type: 'hordiSlab', unit, id, spanMM, toppingMM, ribDepthMM, ribWidthMM, blockWidthMM,
    totalDepthMM, ribsShown, totalShownWidthMM, coverMM,
    mainBars: { dia: mainDia, count: raw.mainBars.count, extraLengthAtEachEndMM: mainExtra, cuttingLengthMM: mainCuttingLengthMM, positions: mainBarPositions },
    topBars,
    toppingMesh: { dia: meshDia, spacing: meshSpacing },
    totalSlabWidthMM, totalRibCount,
  };
}

// Evenly distributes `count` bar centers across a rib's own width, inset
// from each face by (coverMM + dia/2) \u2014 same cover-to-center convention
// columnDiagram.mjs's computeColumnBarPositions uses along one axis.
// count===1 centers the single bar; count>1 spaces the rest evenly across
// the inset span. Throws NO_ROOM_FOR_BARS if the inset leaves negative
// usable width, exactly the failure this module refuses to silently draw
// past (bars overlapping or off the rib face).
function ribBarXPositions(count, ribWidthMM, coverMM, dia, fieldLabel) {
  const inset = coverMM + dia / 2;
  const usable = ribWidthMM - 2 * inset;
  if (usable < 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) and bar diameter (${dia}mm) leave no room for ${fieldLabel} inside a ${ribWidthMM}mm-wide rib.`);
  }
  if (count === 1) return [ribWidthMM / 2];
  const positions = [];
  for (let i = 0; i < count; i++) positions.push(inset + (usable * i) / (count - 1));
  return positions;
}

// Fence-post arithmetic: a strip of total width W built from repeating
// (rib + block) modules, starting AND ending on a rib (so the panel edges
// are always solid concrete, never a block flush with the panel edge) has
// ribCount ribs and (ribCount-1) full blocks between them, plus whatever
// partial width is left over is NOT itself counted as another rib (this
// module never invents a partial rib). Pure arithmetic on the two
// caller-supplied widths \u2014 no code rule, no design judgement.
function computeTotalRibCount(totalWidthMM, ribWidthMM, blockWidthMM) {
  const moduleMM = ribWidthMM + blockWidthMM;
  return Math.max(1, Math.floor((totalWidthMM - ribWidthMM) / moduleMM) + 1);
}

// ── Labels (EN/AR) \u2014 local dict, per this app's documented convention
// (structuralLabels.mjs backs footingDiagram.mjs only; every other element
// module carries its own local L = {en:{...}, ar:{...}}, see
// columnDiagram.mjs's own header for why unifying now would leave a worse
// three-way inconsistency, not a better one). ───────────────────────────
const L = {
  en: {
    title: (id) => `Hordi (Ribbed) Slab \u2014 Typical Section: ${id}`,
    crossSection: 'Typical Cross-Section (perpendicular to ribs)',
    ribElevation: 'Single Rib \u2014 Longitudinal Section',
    meshDetail: 'Topping Mesh (schematic, representative)',
    typicalRepeats: 'typical, repeats',
    block: 'Block',
    topping: 'Topping',
    rib: 'Rib',
    mainBar: 'Rib bottom bar', topBar: 'Support top bar (each end)', mesh: 'Topping shrinkage mesh',
    totalRibsRow: 'Total ribs in panel (computed)',
    extentSuffix: ' (extent)',
    meshLenNote: '\u2014 (mesh, no single length)',
    perRibNote: 'per rib',
    perRibHint: 'Counts above are PER RIB SHOWN. Supply totalSlabWidthMM for a real panel-wide total (see the computed row below when present).',
    meshRepresentativeNote: 'representative grid \u2014 real coverage per project layout',
    colMark: 'Mark', colElement: 'Element', colDia: 'Dia (mm)', colCount: 'Count / spacing', colLength: 'Length (mm)',
    caption: 'Schematic drawing generated from the supplied data, for verification only. Check every bar mark, count, spacing, and length against your own design before construction. Lengths marked (extent) are drawn spans only, not computed development lengths. \u26a0 ribWidthMM/blockWidthMM/toppingMM are checked here only against generic drawing limits, NOT against ECP 203\'s own numeric limits (rib clear spacing, minimum topping thickness) \u2014 those specific figures were sourced from secondary lecture material, not the official code text, at the time this module was written; verify them independently before treating this drawing as code-compliant.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `\u0628\u0644\u0627\u0637\u0629 \u0647\u0648\u0631\u062f\u064a \u2014 \u0642\u0637\u0627\u0639 \u0646\u0645\u0648\u0630\u062c\u064a: ${id}`,
    crossSection: '\u0642\u0637\u0627\u0639 \u0646\u0645\u0648\u0630\u062c\u064a \u0639\u0631\u0636\u064a (\u0639\u0645\u0648\u062f\u064a \u0639\u0644\u0649 \u0627\u0644\u0643\u0645\u0631\u0627\u062a)',
    ribElevation: '\u0643\u0645\u0631\u0629 \u0645\u0646\u0641\u0631\u062f\u0629 \u2014 \u0642\u0637\u0627\u0639 \u0637\u0648\u0644\u064a',
    meshDetail: '\u0634\u0628\u0643\u0629 \u0627\u0644\u0637\u0628\u0642\u0629 \u0627\u0644\u0639\u0644\u0648\u064a\u0629 (\u062a\u0648\u0636\u064a\u062d\u064a\u0629)',
    typicalRepeats: '\u0646\u0645\u0648\u0630\u062c\u064a\u060c \u064a\u062a\u0643\u0631\u0631',
    block: '\u0637\u0648\u0628\u0629',
    topping: '\u0637\u0628\u0642\u0629 \u0639\u0644\u0648\u064a\u0629',
    rib: '\u0643\u0645\u0631\u0629',
    mainBar: '\u0633\u064a\u062e \u0633\u0641\u0644\u064a \u0628\u0627\u0644\u0643\u0645\u0631\u0629', topBar: '\u0633\u064a\u062e \u0639\u0644\u0648\u064a \u0641\u0648\u0642 \u0627\u0644\u0643\u0645\u0631\u0629 (\u0637\u0631\u0641\u064a\u0647\u0627)', mesh: '\u0634\u0628\u0643\u0629 \u0627\u0644\u0627\u0646\u0643\u0645\u0627\u0634',
    totalRibsRow: '\u0625\u062c\u0645\u0627\u0644\u064a \u0639\u062f\u062f \u0627\u0644\u0643\u0645\u0631\u0627\u062a \u0628\u0627\u0644\u0628\u0644\u0627\u0637\u0629 (\u0645\u062d\u0633\u0648\u0628)',
    extentSuffix: ' (\u0627\u0645\u062a\u062f\u0627\u062f)',
    meshLenNote: '\u2014 (\u0634\u0628\u0643\u0629\u060c \u0628\u0644\u0627 \u0637\u0648\u0644 \u0645\u0646\u0641\u0631\u062f)',
    perRibNote: '\u0644\u0643\u0644 \u0643\u0645\u0631\u0629',
    perRibHint: '\u0627\u0644\u0623\u0639\u062f\u0627\u062f \u0623\u0639\u0644\u0627\u0647 \u0644\u0643\u0644 \u0643\u0645\u0631\u0629 \u0645\u0631\u0633\u0648\u0645\u0629 \u0641\u0642\u0637. \u0623\u0636\u0641 totalSlabWidthMM \u0644\u0644\u062d\u0635\u0648\u0644 \u0639\u0644\u0649 \u0625\u062c\u0645\u0627\u0644\u064a \u062d\u0642\u064a\u0642\u064a \u0644\u0644\u0628\u0644\u0627\u0637\u0629 \u0643\u0627\u0645\u0644\u0629 (\u0627\u0646\u0638\u0631 \u0627\u0644\u0635\u0641 \u0627\u0644\u0645\u062d\u0633\u0648\u0628 \u0623\u062f\u0646\u0627\u0647 \u0625\u0646 \u0648\u064f\u062c\u062f).',
    meshRepresentativeNote: '\u0634\u0628\u0643\u0629 \u062a\u0648\u0636\u064a\u062d\u064a\u0629 \u2014 \u0627\u0644\u062a\u063a\u0637\u064a\u0629 \u0627\u0644\u0641\u0639\u0644\u064a\u0629 \u062d\u0633\u0628 \u0645\u062e\u0637\u0637 \u0627\u0644\u0645\u0634\u0631\u0648\u0639',
    colMark: '\u0627\u0644\u0639\u0644\u0627\u0645\u0629', colElement: '\u0627\u0644\u0646\u0648\u0639', colDia: '\u0627\u0644\u0642\u0637\u0631 \u0645\u0645', colCount: '\u0627\u0644\u0639\u062f\u062f \u0623\u0648 \u0627\u0644\u062a\u0628\u0627\u0639\u062f', colLength: '\u0627\u0644\u0637\u0648\u0644 \u0645\u0645',
    caption: '\u0631\u0633\u0645 \u062a\u0641\u0635\u064a\u0644\u064a \u062a\u0648\u0636\u064a\u062d\u064a \u0623\u064f\u0646\u0634\u0626 \u0645\u0646 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0645\u064f\u062f\u062e\u0644\u0629\u060c \u0644\u0644\u062a\u062d\u0642\u0642 \u0641\u0642\u0637. \u0631\u0627\u062c\u0639 \u0643\u0644 \u0639\u0644\u0627\u0645\u0629 \u0633\u064a\u062e \u0648\u0639\u062f\u062f\u0647\u0627 \u0648\u062a\u0628\u0627\u0639\u062f\u0647\u0627 \u0648\u0637\u0648\u0644\u0647\u0627 \u0648\u0641\u0642 \u062a\u0635\u0645\u064a\u0645\u0643 \u0627\u0644\u062e\u0627\u0635 \u0642\u0628\u0644 \u0627\u0644\u062a\u0646\u0641\u064a\u0630. \u0627\u0644\u0623\u0637\u0648\u0627\u0644 \u0627\u0644\u0645\u064f\u0639\u0644\u0645\u0629 (\u0627\u0645\u062a\u062f\u0627\u062f) \u0647\u064a \u0637\u0648\u0644 \u0627\u0645\u062a\u062f\u0627\u062f \u0627\u0644\u0631\u0633\u0645 \u0641\u0642\u0637\u060c \u0644\u0627 \u0637\u0648\u0644 \u0631\u0628\u0637 \u0645\u062d\u0633\u0648\u0628. \u26a0 \u0623\u0628\u0639\u0627\u062f ribWidthMM/blockWidthMM/toppingMM \u062a\u064f\u0641\u062d\u0635 \u0647\u0646\u0627 \u0641\u0642\u0637 \u0645\u0642\u0627\u0628\u0644 \u062d\u062f\u0648\u062f \u0631\u0633\u0645 \u0639\u0627\u0645\u0629\u060c \u0644\u0627 \u0645\u0642\u0627\u0628\u0644 \u0627\u0644\u062d\u062f\u0648\u062f \u0627\u0644\u0631\u0642\u0645\u064a\u0629 \u0627\u0644\u0641\u0639\u0644\u064a\u0629 \u0644\u0640 ECP 203 (\u062a\u0628\u0627\u0639\u062f \u0627\u0644\u0643\u0645\u0631\u0627\u062a\u060c \u0627\u0644\u062d\u062f \u0627\u0644\u0623\u062f\u0646\u0649 \u0644\u0633\u0645\u0643 \u0627\u0644\u0628\u0644\u0627\u0637\u0629 \u0627\u0644\u0639\u0644\u0648\u064a\u0629) \u2014 \u0647\u0630\u0647 \u0627\u0644\u0623\u0631\u0642\u0627\u0645 \u0645\u0635\u062f\u0631\u0647\u0627 \u0645\u062d\u0627\u0636\u0631\u0627\u062a \u062c\u0627\u0645\u0639\u064a\u0629 \u062b\u0627\u0646\u0648\u064a\u0629\u060c \u0644\u0627 \u0646\u0635 \u0627\u0644\u0643\u0648\u062f \u0627\u0644\u0631\u0633\u0645\u064a \u0645\u0628\u0627\u0634\u0631\u0629\u060c \u0648\u0642\u062a \u0643\u062a\u0627\u0628\u0629 \u0647\u0630\u0627 \u0627\u0644\u0645\u0644\u0641 \u2014 \u062a\u062d\u0642\u0642 \u0645\u0646\u0647\u0627 \u0628\u0634\u0643\u0644 \u0645\u0633\u062a\u0642\u0644 \u0642\u0628\u0644 \u0627\u0639\u062a\u0628\u0627\u0631 \u0647\u0630\u0627 \u0627\u0644\u0631\u0633\u0645 \u0645\u0637\u0627\u0628\u0642\u0627\u064b \u0644\u0644\u0643\u0648\u062f.',
    dirAttr: 'rtl',
  },
};

// ── Local hatch (block symbol) \u2014 added HERE, not to structuralDrawingKit
// .mjs, per that file's own Step 18 documented convention: a new visual
// symbol specific to one element type is a local <pattern> in that
// module's own render function, not a shared-kit change (columnDiagram
// .mjs's own local .bar-dot-column CSS class after kitStyleBlock() is the
// same pattern, just for a CSS class instead of an SVG <pattern>). ──────
function localHatchDefs() {
  return `
    <pattern id="hordiBlockHatch" width="9" height="9" patternTransform="rotate(-45)" patternUnits="userSpaceOnUse">
      <rect width="9" height="9" fill="#e8e2d5"/>
      <line x1="0" y1="0" x2="0" y2="9" stroke="#b8ab8a" stroke-width="1.2"/>
    </pattern>`;
}

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 1000;
const CROSS_BOX = { x: 60, y: 110, w: 460, h: 260 };
const MESH_BOX = { x: 560, y: 110, w: 200, h: 220 };
const ELEV_BOX = { x: 60, y: CROSS_BOX.y + CROSS_BOX.h + 80, w: 880, h: 190 };

export function renderHordiSlabDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const crossScale = fitScale([{ contentW: geometry.totalShownWidthMM, contentH: geometry.totalDepthMM, boxW: CROSS_BOX.w - 60, boxH: CROSS_BOX.h - 70 }]);
  const elevScale = fitScale([{ contentW: geometry.spanMM + 2 * geometry.mainBars.extraLengthAtEachEndMM, contentH: geometry.ribDepthMM * 3.2, boxW: ELEV_BOX.w - 40, boxH: ELEV_BOX.h - 40 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW, script: true },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = ELEV_BOX.y + ELEV_BOX.h + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const showHint = geometry.totalRibCount == null;
  const hintY = tableY + table.height + 20;
  const captionY = hintY + (showHint ? 18 : 0) + 16;
  const captionLines = captionLineCount(l.caption, 105);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .hordi-title   { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .block-outline { fill:url(#hordiBlockHatch); stroke:#8a7a52; stroke-width:1.2; }
    .rib-outline   { fill:url(#concreteHatch); stroke:#1a1a1a; stroke-width:1.5; }
    .topping-outline { fill:#f4f4f4; stroke:#1a1a1a; stroke-width:1.5; }
    .break-line    { stroke:#555; stroke-width:1; stroke-dasharray:5,3; }
    .support-tri   { fill:#e2e2e2; stroke:#1a1a1a; stroke-width:1.3; }
    .box-note      { font-size:10px; fill:#555; font-family: ${scriptFontStack}; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}${localHatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="hordi-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderCrossSection(geometry, crossScale, CROSS_BOX, l)}
  ${renderMeshDetail(geometry, MESH_BOX, l)}
  ${renderRibElevation(geometry, elevScale, ELEV_BOX, l)}
  ${table.svg}
  ${showHint ? renderCaptionAt(l.perRibHint, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: hintY, lang, maxCharsPerLine: 105, lineHeight: 15, className: 'box-note' }) : ''}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 105, lineHeight: 15 })}
</svg>`;
}

function renderCrossSection(geometry, scale, box, l) {
  const {
    ribsShown, ribWidthMM, blockWidthMM, toppingMM, ribDepthMM, totalShownWidthMM, mainBars,
  } = geometry;
  const w = totalShownWidthMM * scale;
  const toppingH = toppingMM * scale, ribH = ribDepthMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + (box.h - (toppingH + ribH)) / 2;

  let svg = `<g class="cross-section">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.crossSection)}</text>`;

  // Topping \u2014 one continuous rectangle spanning every rib+block shown.
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${toppingH}" class="topping-outline"/>`;

  // Ribs + blocks, alternating, ribsShown ribs and (ribsShown-1) blocks
  // between them \u2014 see file header for why the panel edges are always a
  // rib, never a block flush with the drawn edge.
  const moduleMM = ribWidthMM + blockWidthMM;
  for (let i = 0; i < ribsShown; i++) {
    const ribXmm = i * moduleMM;
    const ribX = sx + ribXmm * scale;
    svg += `<rect x="${ribX}" y="${sy + toppingH}" width="${ribWidthMM * scale}" height="${ribH}" class="rib-outline"/>`;
    for (const bx of mainBars.positions) {
      svg += barDot(ribX + bx * scale, sy + toppingH + ribH - geometry.coverMM * scale - mainBars.dia * scale / 2, mainBars.dia, scale, 'bottom');
    }
    if (i < ribsShown - 1) {
      const blockX = ribX + ribWidthMM * scale;
      svg += `<rect x="${blockX}" y="${sy + toppingH}" width="${blockWidthMM * scale}" height="${ribH}" class="block-outline"/>`;
    }
  }

  // Break lines at both ends \u2014 honest "typical, repeats" convention
  // instead of implying only `ribsShown` ribs exist on the real panel.
  svg += `<line x1="${sx}" y1="${sy - 8}" x2="${sx}" y2="${sy + toppingH + ribH + 8}" class="break-line"/>`;
  svg += `<line x1="${sx + w}" y1="${sy - 8}" x2="${sx + w}" y2="${sy + toppingH + ribH + 8}" class="break-line"/>`;
  svg += `<text x="${sx}" y="${sy + toppingH + ribH + 16}" text-anchor="middle" class="box-note" dir="${l.dirAttr}">${esc(l.typicalRepeats)}</text>`;
  svg += `<text x="${sx + w}" y="${sy + toppingH + ribH + 16}" text-anchor="middle" class="box-note" dir="${l.dirAttr}">${esc(l.typicalRepeats)}</text>`;

  // Dimensions. Rib/block width dimension pushed to +54 (was +34) so it
  // clears the break-line note above it — an earlier version had both
  // within 6px and they overlapped for narrow ribs, caught only by
  // rendering to PNG and inspecting actual pixels (this session's
  // verification pass), not by any text-content check.
  svg += dimensionLine(sx - 24, sy, sx - 24, sy + toppingH, `${Math.round(toppingMM)}mm`, { orientation: 'v', tick: 4 });
  svg += dimensionLine(sx - 24, sy + toppingH, sx - 24, sy + toppingH + ribH, `${Math.round(ribDepthMM)}mm`, { orientation: 'v', tick: 4 });
  // ribWidth and blockWidth labels sit on TWO separate vertical tiers
  // (+54 / +72), not the same line: when the shown content is wide (many
  // ribs, wide rib+block) the scale shrinks enough that each span's own
  // pixel width is narrower than its own label text, and two same-line
  // adjacent labels collide regardless of only drawing each dimension
  // once — found by rendering the max-scale test case (6 ribs, 400mm rib,
  // 700mm block) to PNG, not visible in the smaller cases tested first.
  svg += dimensionLine(sx, sy + toppingH + ribH + 54, sx + ribWidthMM * scale, sy + toppingH + ribH + 54, `${Math.round(ribWidthMM)}mm`, { orientation: 'h', tick: 4 });
  if (ribsShown > 1) {
    const blk0X = sx + ribWidthMM * scale;
    svg += dimensionLine(blk0X, sy + toppingH + ribH + 72, blk0X + blockWidthMM * scale, sy + toppingH + ribH + 72, `${Math.round(blockWidthMM)}mm`, { orientation: 'h', tick: 4 });
  }

  // Bar mark tag only \u2014 the "(per rib)" qualifier lives in the schedule
  // table's count column (buildScheduleRows), not repeated here: an
  // earlier version put a full explanatory sentence next to this tag and
  // it overflowed into the mesh-detail box to its right at every scale
  // tested, again only caught by rendering to PNG.
  svg += barMarkTag(sx + w + 24, sy + toppingH + ribH / 2, `${mainBars.count}\u00d8${Math.round(mainBars.dia)}`, { r: 12 });

  svg += `</g>`;
  return svg;
}

function renderMeshDetail(geometry, box, l) {
  const { toppingMesh } = geometry;
  const gridW = box.w - 60, gridH = 90;
  const sx = box.x + 30, sy = box.y + 34;
  let svg = `<g class="mesh-detail">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 10}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.meshDetail)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${gridW}" height="${gridH}" fill="none" stroke="#1a1a1a" stroke-width="1"/>`;
  const xs = distributeTicks(sx + 10, sx + gridW - 10, MESH_GRID_N);
  const ys = distributeTicks(sy + 10, sy + gridH - 10, MESH_GRID_N);
  for (const y of ys) {
    for (const x of xs) svg += barDot(x, y, toppingMesh.dia, 1.6, 'top');
  }
  // Plain text, not a dimensionLine \u2014 the grid dots are spaced evenly
  // across a FIXED box regardless of the real spacingMM value (see
  // MESH_GRID_N above), so a tick-and-line construct here would visually
  // imply the drawn gap is to-scale, which it is not. An earlier version
  // used dimensionLine() and, while not a pixel collision, was flagged in
  // this session's own verification pass as a "wrong-but-plausible-
  // looking" scale claim this app's house rule exists to prevent \u2014
  // fixed to a plain labeled value instead.
  svg += `<text x="${box.x + box.w / 2}" y="${sy + gridH + 22}" text-anchor="middle" class="box-note" dir="${l.dirAttr}">\u00d8${Math.round(toppingMesh.dia)}mm @ ${Math.round(toppingMesh.spacing)}mm b.w. (NTS)</text>`;
  svg += `<text x="${box.x + box.w / 2}" y="${sy + gridH + 38}" text-anchor="middle" class="box-note" dir="${l.dirAttr}">${esc(l.meshRepresentativeNote)}</text>`;
  svg += `</g>`;
  return svg;
}

function renderRibElevation(geometry, scale, box, l) {
  const { spanMM, ribDepthMM, mainBars, topBars } = geometry;
  const drawSpanMM = spanMM + 2 * mainBars.extraLengthAtEachEndMM;
  const w = drawSpanMM * scale, h = ribDepthMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + 20;
  const spanX0 = sx + mainBars.extraLengthAtEachEndMM * scale;
  const spanX1 = spanX0 + spanMM * scale;

  let svg = `<g class="rib-elevation">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 6}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.ribElevation)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" class="rib-outline"/>`;

  // Supports (triangles) at each clear-span end.
  svg += `<path d="M ${spanX0},${sy + h} l -9,16 l 18,0 Z" class="support-tri"/>`;
  svg += `<path d="M ${spanX1},${sy + h} l -9,16 l 18,0 Z" class="support-tri"/>`;

  // Bottom bar line, full drawn span including end extensions.
  const barY = sy + h - Math.max(4, (geometry.coverMM + mainBars.dia / 2) * scale);
  svg += `<line x1="${sx}" y1="${barY}" x2="${sx + w}" y2="${barY}" class="bar-bottom"/>`;
  svg += barMarkTag(sx - 22, barY, `${mainBars.count}\u00d8${Math.round(mainBars.dia)}`, { r: 12 });

  if (topBars) {
    const topY = sy + Math.max(4, (geometry.coverMM + topBars.dia / 2) * scale);
    svg += `<line x1="${spanX0}" y1="${topY}" x2="${spanX0 + topBars.extentMM * scale}" y2="${topY}" class="bar-top"/>`;
    svg += `<line x1="${spanX1 - topBars.extentMM * scale}" y1="${topY}" x2="${spanX1}" y2="${topY}" class="bar-top"/>`;
    svg += barMarkTag(sx + w + 22, topY, `${topBars.count}\u00d8${Math.round(topBars.dia)}`, { r: 12 });
  }

  svg += dimensionLine(spanX0, sy + h + 34, spanX1, sy + h + 34, `${Math.round(spanMM)}mm (clear span)`, { orientation: 'h', tick: 5 });
  if (mainBars.extraLengthAtEachEndMM > 0) {
    svg += dimensionLine(sx, sy - 12, spanX0, sy - 12, `${Math.round(mainBars.extraLengthAtEachEndMM)}mm`, { orientation: 'h', tick: 4 });
    svg += dimensionLine(spanX1, sy - 12, sx + w, sy - 12, `${Math.round(mainBars.extraLengthAtEachEndMM)}mm`, { orientation: 'h', tick: 4 });
  }

  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  const mb = geometry.mainBars;
  const mainLen = mb.cuttingLengthMM != null ? Math.round(mb.cuttingLengthMM) : Math.round(geometry.spanMM + 2 * mb.extraLengthAtEachEndMM);
  const mainLenLabel = mb.cuttingLengthMM != null ? String(mainLen) : `${mainLen}${l.extentSuffix}`;
  const mainCountLabel = geometry.totalRibCount != null
    ? `${mb.count}/rib \u00d7 ${geometry.totalRibCount} = ${mb.count * geometry.totalRibCount}`
    : `${mb.count} (${l.perRibNote})`;
  rows.push({ mark: 'B1', element: l.mainBar, dia: String(Math.round(mb.dia)), count: mainCountLabel, length: mainLenLabel });

  if (geometry.topBars) {
    const tb = geometry.topBars;
    const topLen = tb.cuttingLengthMM != null ? Math.round(tb.cuttingLengthMM) : Math.round(tb.extentMM);
    const topLenLabel = tb.cuttingLengthMM != null ? String(topLen) : `${topLen}${l.extentSuffix}`;
    const topCountLabel = geometry.totalRibCount != null
      ? `${tb.count}\u00d72 ends/rib \u00d7 ${geometry.totalRibCount} = ${tb.count * 2 * geometry.totalRibCount}`
      : `${tb.count}\u00d72 ends (${l.perRibNote})`;
    rows.push({ mark: 'T1', element: l.topBar, dia: String(Math.round(tb.dia)), count: topCountLabel, length: topLenLabel });
  }

  rows.push({
    mark: 'M1', element: l.mesh, dia: String(Math.round(geometry.toppingMesh.dia)),
    count: `@${Math.round(geometry.toppingMesh.spacing)}mm b.w.`, length: l.meshLenNote,
  });

  if (geometry.totalRibCount != null) {
    rows.push({ mark: '\u2014', element: l.totalRibsRow, dia: '\u2014', count: String(geometry.totalRibCount), length: '\u2014' });
  }
  return rows;
}

// ── Chat-facing entry point ────────────────────────────────────────────
// Mirrors columnDiagram.mjs's parseColumnRebarPayload() error-shape
// contract exactly ({ok:true,...} / {ok:false,code,message}).
export function parseHordiSlabRebarPayload(raw) {
  try {
    const geometry = computeHordiSlabDiagramGeometry(raw);
    return { ok: true, type: 'hordiSlab', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Mirrors columnDiagram.mjs's parseDiagramCommand exactly: same leading-
// token + "key=value key=value ..." syntax, same BAD_SYNTAX/
// UNSUPPORTED_TYPE reservation, never throws, error results carry `.type`.
// Token 'hordi' is a single word \u2014 already lowercase, so it sidesteps the
// shearWall/shearwall camelCase-token lesson this project's own notes warn
// against repeating.
//
// Syntax:
//   /diagram hordi id=RS-1 span=4000 topping=50 ribdepth=200 ribwidth=120
//     block=400 [ribsshown=3] cover=25 bardia=12 barcount=2
//     [extraend=100] [topdia=10] [topcount=1] [topextent=800]
//     meshdia=6 meshspacing=200 [totalwidth=6000] [unit=mm]
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: hordi key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'hordi') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use hordi.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const geometry = computeHordiSlabDiagramGeometry({
      slabId: kv.id, spanMM: num('span'), toppingMM: num('topping'),
      ribDepthMM: num('ribdepth'), ribWidthMM: num('ribwidth'), blockWidthMM: num('block'),
      ribsShown: kv.ribsshown != null ? num('ribsshown') : undefined,
      coverMM: num('cover'),
      mainBars: { diameterMM: num('bardia'), count: num('barcount'), extraLengthAtEachEndMM: kv.extraend != null ? num('extraend') : undefined },
      topBars: (kv.topdia != null || kv.topcount != null || kv.topextent != null)
        ? { diameterMM: num('topdia'), count: num('topcount'), extentMM: num('topextent') }
        : undefined,
      toppingMesh: { diameterMM: num('meshdia'), spacingMM: num('meshspacing') },
      totalSlabWidthMM: kv.totalwidth != null ? num('totalwidth') : undefined,
      unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
