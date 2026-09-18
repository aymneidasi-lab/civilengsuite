// functions/_lib/footingDiagram.mjs
//
// Deterministic, zero-AI, zero-neuron-cost SVG generator for footing
// schematics. This is the complement to imageGen.mjs's /image path, not
// a replacement for it: /image produces a loose artistic illustration
// from a diffusion model and is explicitly NOT to scale (see that file's
// header). This module produces a drawing computed directly from the
// numbers the user supplies — every dimension, bar count, and bar
// position in the output is arithmetic on the input, not a model's guess
// — so it is the correct tool whenever the user needs the picture to
// actually match specific numbers, and the wrong tool whenever they want
// a quick conceptual/artistic image (it will not draw anything for
// which it wasn't given explicit numeric parameters).
//
// SCOPE: four footing types share one compute*Geometry ->
// renderFootingDiagramSVG pipeline, built around computeSectionGeometry
// as the common section-view engine:
//   'isolated' — single-column spread footing.
//   'combined' — two-column rectangular footing (col1/col2).
//   'strip'    — continuous rectangular footing under a row of 2..
//                MAX_COLUMNS columns (combined generalized to N
//                columns, still constant-width, still every column on
//                the B midline). NOT a wall strip footing: a footing
//                with no columns at all, continuous under a bearing
//                wall, is a distinct sub-case and is not modeled —
//                calling with fewer than 2 columns is a BAD_PARAM, not a
//                wall footing.
//   'raft'     — single-thickness mat slab under 2..MAX_COLUMNS columns
//                positioned anywhere in plan (2-D offx/offy), not just
//                along one centerline. The section cut is a straight cut
//                through one chosen column only — a representative
//                section, not a claim about every other column's depth
//                along that same cut line.
// Calling with an unknown type throws DiagramError('UNSUPPORTED_TYPE',
// ...) rather than silently drawing the wrong thing.
//
// STILL NOT MODELED, on purpose, because drawing them correctly needs a
// parametrization this module has never been given (guessing one would
// be exactly the "confident but wrong" failure imageGen.mjs's own header
// documents fixing — see PROMPT ITERATION 2 there): trapezoidal-plan or
// strap-beam-connected combined footings (footing_pro's own product copy
// lists Rectangular / Trapezoidal / Strap as its three live combined
// footing types — this module's 'combined' only ever draws the
// rectangular one), pile caps, and top/shear reinforcement of any kind.
//
// This is a schematic, not a shop/construction drawing. Reinforcement is
// shown as one representative bottom-mesh layer only — no top steel, no
// full development-length extensions. renderFootingDiagramSVG() always
// appends a fixed caption saying so; treat that caption as load-bearing
// UX, not decoration — see appendBotDiagramBubble() in the footing_pro/
// pc_suite integration notes for why it must never be stripped out by a
// caller.
//
// [Step 14] The paragraph above describes the DEFAULT drawing. pedestal/
// dowels/mesh are optional inputs (see computeFootingExtras()) that ARE
// drawn when the caller explicitly supplies them — captionComputed in
// structuralLabels.mjs was reworded at the same step to stay accurate in
// both cases rather than describing only the no-extras default.
//
// [This session — ECP 203 detailing-guide parity] Two more optional
// groups joined pedestal/dowels/mesh in computeFootingExtras(), closing
// the specific gap a direct comparison against the Egyptian code's own
// "دليل التفاصيل الانشائية" isolated-footing figure (شكل ٢-١٦) surfaced:
//   - blinding — the plain/lean concrete (سمك الخرسانة العادية) layer
//     under the structural footing, its own wider plan projection drawn
//     as a second, outer outline in both views (طول/عرض القاعدة العادية
//     vs طول/عرض القاعدة المسلحة in the guide's own labels).
//   - ties — column confinement ties (كانات العمود) drawn as tick marks
//     at the footing/column interface, reusing the same tieTickH-style
//     3-segment mark structuralDrawingKit.mjs already exports for other
//     elements (see renderSectionView's own comment on why THIS file's
//     copy is local rather than an import — the kit file itself was not
//     available to verify the real signature against when this change
//     was made; flagged as technical debt alongside the file's existing
//     local dimensionLine/hatchDefs/esc duplicates).
// The existing dowels group also gained a real drawn vertical leg (from
// the footing-top interface up into the column, length = the caller's
// own dowels.projection, dimensioned on-drawing as "Dowel Lap Length")
// and a hooked foot at the bottom bar layer — previously
// dowels.projectionMM was computed and reported in the Step 14.3 summary
// table but never actually drawn as geometry; the dowel was a bare row
// of circles with no visible bar. Both additions follow the file's
// existing all-or-nothing-per-group gate and its "never draw a number
// the caller didn't give us" rule: the hook FOOT length is a fixed,
// unlabeled illustrative convention (see DOWEL_HOOK_FOOT_FACTOR below),
// never presented as a computed or code-mandated value, for the same
// reason MAX_* constants are documented as tool limits, not engineering
// limits.
//
// NOT carried over from the guide figure in this pass, deliberately: the
// guide's plan-view note tying a concentrated reinforcement band (a
// percentage of steel within a band width at the column) to a specific
// bond/anchorage-length clause. The exact fraction and band-width rule
// is a real ECP 203 provision, not read with enough confidence off a
// photographed page to hardcode as this tool's own default without
// risking exactly the "confident but wrong" number this file's header
// already commits never to produce — see PROMPT ITERATION 2 in
// imageGen.mjs, cited elsewhere in this header. Left for a follow-up
// session where the clause can be confirmed against the code text
// itself, not an image of it.
//
// ── Step 17 addendum ────────────────────────────────────────────────────
// Fully deterministic: no `env.AI`, no model call, no network fetch, no
// randomness anywhere in this file (computed path or generic path) — see
// "zero-neuron-cost" in this file's own first line above, stated here
// again in these exact terms per Step 17's checklist.
//
// MAX_* rationale: MAX_COLUMNS and MAX_DOWELS (below) both exist for the
// same reason every other module's caps do — this is a chat-driven
// schematic tool, not a CAD system, and a Cloudflare Worker isolate is
// killed past ~10ms of actual CPU time, so any loop whose count comes
// from user input must be bounded or a long/malicious command can blow
// that budget or return a multi-MB SVG. Each constant's own comment below
// explains what it specifically bounds.
//
// "Drawn extent" vs "actual cut length": this file has no cuttingLengthMM
// field anywhere in its schema — a footing schematic shows bar COUNT/
// SPACING/DIAMETER (computeSectionGeometry, computeMeshLayer), never a
// fabrication cutting length, so the distinction structuralDrawingKit.mjs's
// header documents does not arise here the way it does in beamDiagram.mjs
// /columnDiagram.mjs. The same underlying honesty rule appears in a
// different shape instead: every bar count/spacing number shown is
// arithmetic on real input (cover, dia, spacing, envelope width) — see
// computeSectionGeometry's own header below — never a guessed or
// hardcoded figure. The generic (no-numbers) path at the bottom of this
// file is the other side of that same rule: where there are no real
// numbers to be honest with, every dimension label is a SYMBOL (L, B, D),
// never a fabricated digit — see that section's own header for the full
// reasoning.
//
// Known, undocumented-elsewhere-until-now technical debt (recorded here
// AND in CHANGELOG.md): structuralDrawingKit.mjs's header states its
// primitives were "extracted from footingDiagram.mjs", but this file was
// never retrofitted to import them back. Only DiagramError/assertInt/
// barDot/scheduleTable are actually imported from the kit (see the import
// statement below); MM_PER_UNIT/toMm/fromMm/assertFinitePositive/fmt/esc/
// dimensionLine/hatchDefs below are this file's own local copies,
// verified byte-for-byte functionally identical to the kit's exported
// versions as of this session. Not a bug — both copies are independently
// tested and correct — but a missed consolidation the kit's own
// extraction was meant to eventually complete.

// [Step 1 — error unification] DiagramError used to be declared inline
// here AND separately in the now-deleted computedFootingDiagram.mjs —
// two classes with the same name meant an `instanceof DiagramError`
// check written against one module's export silently failed on an error
// thrown by the other. structuralDrawingKit.mjs is now the single
// source; beamDiagram.mjs already imports it the same way. Re-exported
// below so any existing caller importing DiagramError from this file's
// path keeps working unchanged.
// [Step 14.3] barDot/scheduleTable added to the existing DiagramError/
// assertInt import — both are reused verbatim from the shared kit
// (barDot for the new dowel face, scheduleTable for the new workshop
// table row) rather than hand-rolled a second time in this file. See
// خطة_تجزئة_الخطوة_14.md's decision NOT to switch this file's whole
// <style> block over to kitStyleBlock() — only the specific classes
// these two functions need (.bar-dot-dowel, .table-*) are added to the
// local block below, verbatim-copied from kitStyleBlock's own values.
import {
  DiagramError, assertInt, scheduleTable,
  toMm, fromMm, fmt, assertFinitePositive, assertFiniteNonNegative, tieTickH,
} from './structuralDrawingKit.mjs';
export { DiagramError };
// [Step 4 — translation] footingTitle/columnTag/sectionTitle replace
// this file's old module-scope TITLES table and the raw col.tag /
// hardcoded "PLAN"/"SECTION A-A" strings renderPlanView/renderSectionView
// used to emit regardless of `lang` — see structuralLabels.mjs's own
// header for the full rationale and the tofu-avoidance constraint on
// any Arabic value added there.
import { translate, footingTitle, columnTag, sectionTitle as translatedSectionTitle } from './structuralLabels.mjs';

// [Integration merge — this pass] toMm/fromMm/fmt/assertFinitePositive/
// assertFiniteNonNegative/MM_PER_UNIT were local duplicates of the
// shared kit's exports of the same name. This file's own Step 17
// addendum deferred migrating onto the kit's versions because the kit
// file was not co-located with this one at the time, and an unverified
// same-session behavioral migration was judged riskier than a known,
// flagged duplicate — see footing/_extended_src/footingDiagram-2.mjs
// (an untouched snapshot, kept alongside this file) for the prior local
// copies. Both files now live in one
// project; the five functions were confirmed byte-identical to the
// kit's exports by direct diff before this file switched to importing
// them, and test/regression-footing-extended.mjs further confirms this
// file's own rendered SVG output is unchanged for a representative
// input battery after the switch. MM_PER_UNIT is not re-declared:
// nothing else in this file referenced it once toMm/fromMm moved here.

// Sanity cap on the multi-column types (strip/raft) — this is a quick
// schematic tool driven by a single ASCII command string with a 2000-
// char server-side limit (see chat.js's `body.mode === 'image'` handler,
// which tries parseDiagramCommand on the prompt text itself — there is
// no separate mode:'diagram' route; see Step 2's client patch for the
// command-prefix framing this comment used to imply incorrectly), not a
// CAD system; a raft or strip with more columns than this needs a real
// drafting tool, not this one. isolated/combined are unaffected (fixed
// at 1 and 2 columns respectively, unchanged).
const MAX_COLUMNS = 12;

// [Step 14.1] Same philosophy as MAX_COLUMNS: a schematic-tool cap, not
// a structural-engineering limit. Bounds dowels.count for the same
// reason MAX_COLUMNS bounds strip/raft — this is a single ASCII command
// string, not a CAD system.
const MAX_DOWELS = 20;

// [This session] Same cap philosophy as MAX_DOWELS, applied to
// ties.count — a column showing 30 confinement ties in a single
// schematic section is already well past what this tool's fixed-height
// column stub can lay out legibly; a real tie schedule needs a real
// drafting tool, not this one.
const MAX_TIES = 30;

// [This session] The dowel's hooked FOOT at the bottom bar layer is
// drawn at a fixed length proportional to bar diameter — a common
// schematic convention for "this bar is hooked here", NOT a computed
// standard-hook length per any specific ECP 203 / ACI 318 hook-geometry
// table (those tables key off hook angle, bar grade, and cover in ways
// this tool is never given). Never labeled with a number on the drawing
// for exactly that reason — see this file's header, "NOT carried over"
// note, for the same never-assert-an-unverified-figure rule applied to
// the reinforcement band the guide figure also shows. Only the VERTICAL
// leg (real input: dowels.projectionMM) gets a dimensioned label.
const DOWEL_HOOK_FOOT_FACTOR = 6; // foot length = 6 x dowel dia, purely illustrative

// [This session — column main bars / break symbol] Fixed pixel gap
// between the break symbol and the column stub's own top edge — same
// "schematic mark, not a to-scale anything" convention as
// DOWEL_HOOK_FOOT_FACTOR just above (a break symbol has no real-world
// length to be proportional to; it is a drafting convention meaning
// "this bar continues, not drawn to its real height"), so a fixed
// pixel constant is honest here in a way a computed one would not be.
// [This session — column main bars] Deliberately SMALLER than
// STUB_MARGIN_PX (15, inline below in renderSectionView) — this is the
// gap between colTop and the break symbol, and keeping it under
// STUB_MARGIN_PX guarantees the break always sits ABOVE the dowel bend
// point with room to spare WITHOUT columnBars ever having to grow the
// stub itself (see the deliberate absence of any columnBars term in
// stubH's own Math.max() calls, and that block's comment, for why: an
// earlier version of this feature added a dedicated
// MIN_COLUMN_BAR_VISIBLE_PX term to stubH so the visible bar run could
// be longer, but for a realistic large dowel.projectionMM — 600mm, a
// plausible ECP 203 tension lap length for a 16mm bar, not an
// adversarial input — that extra growth pushed colTop up far enough to
// visually collide with the plan-view title above SECTION_BOX, found by
// rendering exactly that case to PNG. Reusing the dowel's own existing
// headroom instead of asking for more keeps colTop provably unchanged
// from the dowels-only case (byte-identical stubH), at the cost of a
// shorter, but always positive and always collision-free, visible bar
// run above the bend.
const BREAK_SYMBOL_MARGIN_PX = 8;

// toMm/fromMm/assertFinitePositive/assertFiniteNonNegative/fmt: now
// imported from the shared kit (see the import block above) — local
// definitions removed in this pass. assertFiniteNonNegative still
// permits exactly 0 (blinding.projection legitimately can be 0mm — a
// footing poured flush with no blinding projection), matching this
// file's prior local copy and the kit's own export, confirmed identical
// by diff before the switch.

// ── Shared section-view geometry ────────────────────────────────────────
// Used identically by all four footing types — isolated (its only
// column), and combined/strip/raft (through whichever column
// sectionThrough selects). widthMM is the in-plan dimension visible in
// this cut (the short axis for isolated; B for combined/strip/raft,
// since all three assume constant width B along their length/footprint —
// documented in each compute*Geometry function).
//
// Bar centers are distributed evenly across the cover-to-cover envelope
// rather than laid out at exactly the nominal input spacing starting
// from one edge — standard even-distribution simplification for a
// schematic. actualSpacingMM (the spacing this distribution actually
// produced) is returned alongside nominalSpacingMM specifically so the
// rendered label never claims a spacing value that doesn't match what
// is actually drawn — every number on this drawing must be independently
// verifiable against the geometry, unlike the AI-illustration path.
// [Step 14.1] Pure geometric distribution — no cover/dia/envelope logic
// of its own, just "N points evenly spaced between two ends, closed
// interval, both ends included when count>1". Extracted from what used
// to be inline in computeSectionGeometry (below) so computeDowelGeometry
// and computeMeshLayer can reuse the identical placement rule instead of
// re-deriving it. count===1 centers the single point on the envelope's
// midpoint — this branch was previously unreachable inside
// computeSectionGeometry (barCount there is always Math.max(2, ...)) but
// IS reachable now via dowels.count, which has no such floor.
function distributeCenters(envelopeStartMM, envelopeEndMM, count) {
  if (count <= 1) {
    return { centersMM: [(envelopeStartMM + envelopeEndMM) / 2], actualSpacingMM: 0 };
  }
  const actualSpacingMM = (envelopeEndMM - envelopeStartMM) / (count - 1);
  const centersMM = Array.from({ length: count }, (_, i) => envelopeStartMM + i * actualSpacingMM);
  return { centersMM, actualSpacingMM };
}

// Input: widthMM/depthMM (the section cut's own plan width and footing
// depth), colWidthMM (the column this cut passes, for the containment
// check), coverMM/diaMM/nominalSpacingMM (the reinforcement spec).
// Formula: rawCount = floor((width - 2*cover - dia) / nominalSpacing) + 1,
// floored at 2 (a "mesh" of one bar is not a mesh), then centers are
// re-distributed EVENLY across the cover-to-cover envelope (see
// distributeCenters) rather than placed at exactly nominalSpacingMM from
// one edge — actualSpacingMM (what that even distribution actually
// produced) is returned alongside nominalSpacingMM so the rendered label
// never claims a spacing value the drawing doesn't actually show.
// Output: a geometry fragment ({widthMM, depthMM, barCount,
// barCentersMM, actualSpacingMM, ...}) consumed by renderSectionView and,
// for the long-axis count, recomputed inline by renderPlanView (see that
// function's own comment on why the long axis isn't threaded through
// here).
function computeSectionGeometry({ widthMM, depthMM, colWidthMM, coverMM, diaMM, nominalSpacingMM }) {
  assertFinitePositive('width', widthMM);
  assertFinitePositive('depth', depthMM);
  assertFinitePositive('column width', colWidthMM);
  assertFinitePositive('cover', coverMM);
  assertFinitePositive('bar diameter', diaMM);
  assertFinitePositive('bar spacing', nominalSpacingMM);

  if (colWidthMM >= widthMM) {
    throw new DiagramError('COLUMN_TOO_WIDE', `Column width (${colWidthMM}mm) must be smaller than the footing width it sits on (${widthMM}mm).`);
  }
  const envelope = widthMM - 2 * coverMM - diaMM;
  if (envelope <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) and bar diameter (${diaMM}mm) leave no room for reinforcement across a ${widthMM}mm width.`);
  }
  const rawCount = Math.floor(envelope / nominalSpacingMM) + 1;
  const barCount = Math.max(2, rawCount); // a "mesh" with 1 bar isn't a mesh; floor at 2
  const firstCenterMM = coverMM + diaMM / 2;
  const lastCenterMM = widthMM - coverMM - diaMM / 2;
  const { centersMM: barCentersMM, actualSpacingMM } = distributeCenters(firstCenterMM, lastCenterMM, barCount);

  return {
    widthMM, depthMM, colWidthMM, coverMM, diaMM,
    nominalSpacingMM, actualSpacingMM, barCount, barCentersMM,
  };
}

// ── Step 14.1: pedestal / dowels / mesh — pure compute, no drawing ─────
// computeDowelGeometry: dowel centers distributed across ONE host width
// (the pedestal's width if a pedestal was given, else the column's own
// width — resolved by the caller, computeFootingExtras below), inset by
// the same footing cover used for the main reinforcement. Mirrors
// computeSectionGeometry's own cover-to-cover envelope logic exactly,
// generalized to an explicit `count` instead of deriving one from
// spacing (dowel counts come from the user directly — spacing is not an
// input dowels are specified by).
function computeDowelGeometry({ hostWidthMM, cover, diaMM, count }) {
  assertFinitePositive('dowels host width', hostWidthMM);
  assertFinitePositive('dowels cover', cover);
  assertFinitePositive('dowels.dia', diaMM);
  assertInt('dowels.count', count, { min: 1, max: MAX_DOWELS });

  const envelope = hostWidthMM - 2 * cover - diaMM;
  if (envelope <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${cover}mm) and dowel diameter (${diaMM}mm) leave no room for dowels across a ${hostWidthMM}mm width.`);
  }
  const firstCenterMM = cover + diaMM / 2;
  const lastCenterMM = hostWidthMM - cover - diaMM / 2;
  const { centersMM, actualSpacingMM } = distributeCenters(firstCenterMM, lastCenterMM, count);
  return { centersMM, actualSpacingMM };
}

// computeMeshLayer: same barCount-from-spacing derivation
// computeSectionGeometry uses for the primary reinforcement, applied to
// an independent second layer's own dia/spacing across the SAME host
// width the section's primary mesh already spans (not the dowels' host
// width — mesh is a footing-wide layer, dowels are one-column-wide).
function computeMeshLayer({ hostWidthMM, cover, diaMM, spacingMM }) {
  assertFinitePositive('mesh host width', hostWidthMM);
  assertFinitePositive('mesh cover', cover);
  assertFinitePositive('meshDia', diaMM);
  assertFinitePositive('meshSpacing', spacingMM);

  const envelope = hostWidthMM - 2 * cover - diaMM;
  if (envelope <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${cover}mm) and mesh bar diameter (${diaMM}mm) leave no room for mesh reinforcement across a ${hostWidthMM}mm width.`);
  }
  const rawCount = Math.floor(envelope / spacingMM) + 1;
  const barCount = Math.max(2, rawCount);
  const firstCenterMM = cover + diaMM / 2;
  const lastCenterMM = hostWidthMM - cover - diaMM / 2;
  const { centersMM: barCentersMM, actualSpacingMM } = distributeCenters(firstCenterMM, lastCenterMM, barCount);
  return { diaMM, spacingMM, actualSpacingMM, barCount, barCentersMM };
}

// computeTieGeometry: N ties, evenly spaced at the caller's own spacing,
// starting AT the footing/column interface (offset 0) and marching UP
// into the column — mirrors the guide figure's own callout, which shows
// the confinement ties beginning right at "منسوب ظهر القاعدة المسلحة"
// (the reinforced footing's own top level) and continuing upward. Unlike
// computeDowelGeometry (an X-axis envelope distribution), this is a 1-D
// arithmetic sequence — no cover/host-width envelope applies to a
// vertical position along the column.
function computeTieGeometry({ spacingMM, count }) {
  assertFinitePositive('ties.spacing', spacingMM);
  assertInt('ties.count', count, { min: 1, max: MAX_TIES });
  const offsetsMM = Array.from({ length: count }, (_, i) => i * spacingMM);
  return { offsetsMM };
}

// computeFootingExtras: shared "all sub-fields of a group or none"
// gate + unit conversion + compute dispatch for all three optional
// groups, called identically by all four compute*FootingGeometry
// functions below. hostWidthMM/coverMM are already-converted mm values
// from the caller (the same column width already chosen for that
// type's section cut — colShortMM for isolated, chosen.b for
// combined/strip/raft; see each call site).
//
// [Step 14.1 decision, resolving خطة_تجزئة_الخطوة_14.md's "سؤال مفتوح"]
// meshSpacing/meshDia = interpretation (A): an independent SECOND mesh
// layer, separate from the section's existing single bottom-mesh layer
// (dia/spacing). Not interpretation (B) ("make the existing layer's own
// spacing/dia independently settable") — the plan text describes this
// field as partially cancelling the single-bottom-layer simplification,
// and a "one layer" simplification has nothing to partially cancel
// except by adding a real second layer.
// [Step 14.3 bug fix] Original 14.1 signature took a single hostWidthMM
// and fed it to BOTH dowels (correctly — a column-width envelope) AND
// mesh (incorrectly — computeMeshLayer's own header always documented
// mesh as spanning "the SAME host width the section's primary mesh
// already spans", i.e. the FOOTING's full width, not the column's).
// Passing the column width into computeMeshLayer silently produced a
// too-narrow, too-few-bars second layer (e.g. 2-3 bars across a 400mm
// column instead of the correct count across an 1800mm footing) — wrong
// per this project's own "no number you can't defend" rule, caught only
// now while wiring the Step 14.3 render layer against real numbers, not
// by reading the compute code alone. Fixed by taking the footing's full
// section width as its own explicit parameter instead of overloading
// the column-width one.
function computeFootingExtras(rawParams, unit, colWidthMM, footingWidthMM, coverMM) {
  const extras = {};

  if (rawParams.pedestal != null) {
    const { width, height } = rawParams.pedestal;
    if (width == null || height == null) {
      throw new DiagramError('BAD_PARAM', `"pedestal" requires both "width" and "height" together, got ${JSON.stringify(rawParams.pedestal)}.`);
    }
    const widthMM = toMm(width, unit);
    const heightMM = toMm(height, unit);
    assertFinitePositive('pedestal.width', widthMM);
    assertFinitePositive('pedestal.height', heightMM);
    // Pedestal assumed SQUARE in plan (one dimension only) — a
    // documented simplification, not an invented number; see design
    // note in خطة_تجزئة_الخطوة_14.md ("البرمة تُفترض مربعة الشكل").
    extras.pedestal = { widthMM, heightMM };
  }

  if (rawParams.dowels != null) {
    const { count, dia, projection } = rawParams.dowels;
    if (count == null || dia == null || projection == null) {
      throw new DiagramError('BAD_PARAM', `"dowels" requires "count", "dia", and "projection" together, got ${JSON.stringify(rawParams.dowels)}.`);
    }
    const diaMM = toMm(dia, unit);
    const projectionMM = toMm(projection, unit);
    assertFinitePositive('dowels.projection', projectionMM);
    // Dowels belong to ONE column only — the same column the section
    // cut already shows (see design note: "dowels تُحسب لعمود واحد
    // فقط"). If a pedestal was also given, dowels sit within the
    // pedestal's footprint (the narrower of the two, always — pedestal
    // is drawn centered on the column); otherwise within the column
    // itself.
    const dowelHostWidthMM = extras.pedestal ? extras.pedestal.widthMM : colWidthMM;
    const { centersMM, actualSpacingMM } = computeDowelGeometry({
      hostWidthMM: dowelHostWidthMM, cover: coverMM, diaMM, count,
    });
    extras.dowels = { count, diaMM, projectionMM, centersMM, actualSpacingMM };
  }

  const hasMeshSpacing = rawParams.meshSpacing != null;
  const hasMeshDia = rawParams.meshDia != null;
  if (hasMeshSpacing !== hasMeshDia) {
    throw new DiagramError('BAD_PARAM', `"meshSpacing" and "meshDia" must be given together, got meshSpacing=${JSON.stringify(rawParams.meshSpacing)} meshDia=${JSON.stringify(rawParams.meshDia)}.`);
  }
  if (hasMeshSpacing && hasMeshDia) {
    const meshDiaMM = toMm(rawParams.meshDia, unit);
    const meshSpacingMM = toMm(rawParams.meshSpacing, unit);
    // footingWidthMM, not colWidthMM — see function header fix note.
    extras.mesh = computeMeshLayer({ hostWidthMM: footingWidthMM, cover: coverMM, diaMM: meshDiaMM, spacingMM: meshSpacingMM });
  }

  // [This session] blinding — plain/lean concrete under the footing.
  // "thickness" and "projection" required together, same shape as
  // pedestal's width+height: a thickness with no stated projection (or
  // vice versa) is an ambiguous drawing request, not a defaultable one.
  if (rawParams.blinding != null) {
    const { thickness, projection } = rawParams.blinding;
    if (thickness == null || projection == null) {
      throw new DiagramError('BAD_PARAM', `"blinding" requires both "thickness" and "projection" together, got ${JSON.stringify(rawParams.blinding)}.`);
    }
    const thicknessMM = toMm(thickness, unit);
    const projectionMM = toMm(projection, unit);
    assertFinitePositive('blinding.thickness', thicknessMM);
    assertFiniteNonNegative('blinding.projection', projectionMM); // 0 = flush with the footing edge, a valid design choice
    extras.blinding = { thicknessMM, projectionMM };
  }

  // [This session] ties — column confinement ties at the footing/column
  // interface. "dia", "spacing", and "count" required together, same
  // shape as dowels' count+dia+projection: a spacing with no count (or
  // vice versa) cannot be drawn without inventing the missing number.
  if (rawParams.ties != null) {
    const { dia, spacing, count } = rawParams.ties;
    if (dia == null || spacing == null || count == null) {
      throw new DiagramError('BAD_PARAM', `"ties" requires "dia", "spacing", and "count" together, got ${JSON.stringify(rawParams.ties)}.`);
    }
    const diaMM = toMm(dia, unit);
    const spacingMM = toMm(spacing, unit);
    assertFinitePositive('ties.dia', diaMM);
    const { offsetsMM } = computeTieGeometry({ spacingMM, count });
    extras.ties = { diaMM, spacingMM, count, offsetsMM };
  }

  // [This session — column main bars / break symbol] columnBars — the
  // column's OWN continuing longitudinal reinforcement (the guide
  // figure's "١٦Φ" callout at the very top of the column, cut off by a
  // break symbol since this schematic is never given a real column
  // height), distinct from "أشاير العمود"/dowels just below it (the
  // short starter/lap bars computed above). Deliberately reuses
  // dowels.centersMM/count rather than taking its own count or an
  // independent position input: in standard detailing the main bars and
  // their own starter dowels occupy the SAME positions (that is what a
  // lap splice means — one bar continuing where the other leaves off),
  // so asking the caller for a second, independently-specified count/
  // position here would let the two groups disagree in a way real
  // construction never does, and this tool's own "never draw a number
  // you can't defend" rule extends to positions, not just diameters.
  // Only "dia" is a real new input; requiring dowels to already exist is
  // enforced explicitly below rather than left as a silent no-op when
  // dowels is absent, matching this function's existing style of
  // throwing a named BAD_PARAM rather than degrading quietly.
  if (rawParams.columnBars != null) {
    if (!extras.dowels) {
      throw new DiagramError('BAD_PARAM', '"columnBars" requires "dowels" to also be supplied — column bars are drawn continuing upward from the same dowel positions.');
    }
    const { dia } = rawParams.columnBars;
    if (dia == null) {
      throw new DiagramError('BAD_PARAM', `"columnBars" requires "dia", got ${JSON.stringify(rawParams.columnBars)}.`);
    }
    const diaMM = toMm(dia, unit);
    assertFinitePositive('columnBars.dia', diaMM);
    extras.columnBars = { diaMM };
  }

  return extras;
}

// ── Isolated (single-column spread) footing ─────────────────────────────
// rawParams (all lengths in `unit`, default 'mm'):
//   B, L, D            footing plan width, plan length, depth
//   colB, colL         column cross-section (plan)
//   cover              concrete cover to reinforcement
//   dia                bar diameter
//   spacing            nominal bar spacing, both directions (isotropic
//                      default — pass spacingLong/spacingShort to override
//                      either direction independently)
//   unit               'mm' | 'cm' | 'm', default 'mm'
export function computeIsolatedFootingGeometry(rawParams) {
  const unit = rawParams.unit || 'mm';
  const B = toMm(rawParams.B, unit);
  const L = toMm(rawParams.L, unit);
  const D = toMm(rawParams.D, unit);
  const colB = toMm(rawParams.colB, unit);
  const colL = toMm(rawParams.colL, unit);
  const cover = toMm(rawParams.cover, unit);
  const dia = toMm(rawParams.dia, unit);
  const spacingLong = toMm(rawParams.spacingLong ?? rawParams.spacing, unit);
  const spacingShort = toMm(rawParams.spacingShort ?? rawParams.spacing, unit);

  for (const [name, v] of Object.entries({ B, L, D, colB, colL, cover, dia, spacingLong, spacingShort })) {
    assertFinitePositive(name, v);
  }
  if (colB >= B) throw new DiagramError('COLUMN_TOO_WIDE', `colB (${colB}mm) must be smaller than B (${B}mm).`);
  if (colL >= L) throw new DiagramError('COLUMN_TOO_WIDE', `colL (${colL}mm) must be smaller than L (${L}mm).`);

  // Draw the LONGER plan dimension horizontally regardless of whether the
  // caller called it B or L — makes near-square footings render sensibly
  // and elongated ones render legibly instead of tall-and-narrow. Track
  // the original name so dimension labels stay attached to the value the
  // user actually gave.
  const bIsShort = B <= L;
  const shortLabel = bIsShort ? 'B' : 'L';
  const longLabel = bIsShort ? 'L' : 'B';
  const shortMM = bIsShort ? B : L;
  const longMM = bIsShort ? L : B;
  const colShortMM = bIsShort ? colB : colL;
  const colLongMM = bIsShort ? colL : colB;

  const section = computeSectionGeometry({
    widthMM: shortMM, depthMM: D, colWidthMM: colShortMM,
    coverMM: cover, diaMM: dia, nominalSpacingMM: spacingShort,
  });
  // [Step 14.1] isolated has exactly one column — that column is the
  // dowels/pedestal host width, unambiguously. shortMM (the footing's
  // own short-axis width) is passed separately for mesh — see Step
  // 14.3's fix note on computeFootingExtras.
  const extras = computeFootingExtras(rawParams, unit, colShortMM, shortMM, cover);

  return {
    type: 'isolated',
    unit,
    plan: {
      longLabel, shortLabel, longMM, shortMM,
      columns: [{ alongLongMM: colLongMM, alongShortMM: colShortMM, centerLongMM: longMM / 2 }],
    },
    section,
    meta: { B, L, D, colB, colL, cover, dia, spacingLong, spacingShort },
    ...extras,
  };
}

// ── Combined (two-column) footing ───────────────────────────────────────
// rawParams (all lengths in `unit`, default 'mm'):
//   B, L, D            footing width (constant along its length — see
//                      note below), overall length spanning both
//                      columns, depth
//   col1{b,l,off}, col2{b,l,off}   each column's plan cross-section and
//                      its centerline distance from the L=0 edge. Both
//                      columns are assumed centered on the B midline —
//                      a footing housing two columns offset from each
//                      other across B as well as along L is a real but
//                      much rarer case, not modeled here.
//   cover, dia, spacing, unit      as isolated
//   sectionThrough     1 | 2, default 1 — which column the section cut
//                      passes through
export function computeCombinedFootingGeometry(rawParams) {
  const unit = rawParams.unit || 'mm';
  const B = toMm(rawParams.B, unit);
  const L = toMm(rawParams.L, unit);
  const D = toMm(rawParams.D, unit);
  const cover = toMm(rawParams.cover, unit);
  const dia = toMm(rawParams.dia, unit);
  const spacing = toMm(rawParams.spacing, unit);
  const sectionThrough = rawParams.sectionThrough === 2 ? 2 : 1;

  const col1 = {
    b: toMm(rawParams.col1.b, unit), l: toMm(rawParams.col1.l, unit), off: toMm(rawParams.col1.off, unit),
  };
  const col2 = {
    b: toMm(rawParams.col2.b, unit), l: toMm(rawParams.col2.l, unit), off: toMm(rawParams.col2.off, unit),
  };

  for (const [name, v] of Object.entries({ B, L, D, cover, dia, spacing })) assertFinitePositive(name, v);
  for (const [tag, col] of [['col1', col1], ['col2', col2]]) {
    assertFinitePositive(`${tag}.b`, col.b);
    assertFinitePositive(`${tag}.l`, col.l);
    if (!Number.isFinite(col.off) || col.off <= 0) {
      throw new DiagramError('BAD_PARAM', `"${tag}.off" must be a positive finite number, got ${JSON.stringify(col.off)}.`);
    }
    if (col.b >= B) throw new DiagramError('COLUMN_TOO_WIDE', `${tag}.b (${col.b}mm) must be smaller than B (${B}mm).`);
    const lo = col.off - col.l / 2, hi = col.off + col.l / 2;
    if (lo < 0 || hi > L) {
      throw new DiagramError('COLUMN_OUT_OF_BOUNDS', `${tag} (offset ${col.off}mm, length ${col.l}mm) extends outside the footing's L=${L}mm extent.`);
    }
  }
  // Non-overlap check between the two columns along L.
  const [first, second] = col1.off <= col2.off ? [col1, col2] : [col2, col1];
  if (first.off + first.l / 2 > second.off - second.l / 2) {
    throw new DiagramError('COLUMNS_OVERLAP', `col1 and col2 overlap along L given their offsets and lengths.`);
  }

  const chosen = sectionThrough === 2 ? col2 : col1;
  const section = computeSectionGeometry({
    widthMM: B, depthMM: D, colWidthMM: chosen.b,
    coverMM: cover, diaMM: dia, nominalSpacingMM: spacing,
  });
  // [Step 14.1] dowels/pedestal belong to `chosen` — the same column the
  // section cut already shows — not both columns. B (footing width) is
  // passed separately for mesh — see Step 14.3's fix note.
  const extras = computeFootingExtras(rawParams, unit, chosen.b, B, cover);

  return {
    type: 'combined',
    unit,
    sectionThrough,
    plan: {
      longLabel: 'L', shortLabel: 'B', longMM: L, shortMM: B,
      columns: [
        { alongLongMM: col1.l, alongShortMM: col1.b, centerLongMM: col1.off, tag: 'col1' },
        { alongLongMM: col2.l, alongShortMM: col2.b, centerLongMM: col2.off, tag: 'col2' },
      ],
    },
    section,
    meta: { B, L, D, cover, dia, spacing, col1, col2 },
    ...extras,
  };
}

// ── Multi-column overlap helpers (shared by strip and raft) ─────────────
// Combined's own overlap check (above) is hand-written for exactly two
// columns and is left untouched — these generalize the same idea to
// 2..MAX_COLUMNS columns for strip (1-D, along L only — every strip
// column sits on the B midline, same assumption combined makes) and raft
// (2-D, along both L and B, since raft columns can sit anywhere in
// plan). assertNoOverlap1D sorts a COPY of the array to check only
// adjacent pairs after sorting (sufficient and O(n log n) for 1-D
// interval overlap); tags in any thrown message still refer to the
// caller's original col1/col2/... labels, not sorted position.
function assertNoOverlap1D(columns) {
  const sorted = columns.slice().sort((a, b) => a.off - b.off);
  for (let i = 0; i < sorted.length - 1; i++) {
    const a = sorted[i], b = sorted[i + 1];
    if (a.off + a.l / 2 > b.off - b.l / 2) {
      throw new DiagramError('COLUMNS_OVERLAP', `${a.tag} and ${b.tag} overlap along L given their offsets and lengths.`);
    }
  }
}

function assertNoOverlap2D(columns) {
  for (let i = 0; i < columns.length; i++) {
    for (let j = i + 1; j < columns.length; j++) {
      const a = columns[i], b = columns[j];
      const sepX = Math.abs(a.offx - b.offx) >= (a.l + b.l) / 2;
      const sepY = Math.abs(a.offy - b.offy) >= (a.b + b.b) / 2;
      if (!sepX && !sepY) {
        throw new DiagramError('COLUMNS_OVERLAP', `${a.tag} and ${b.tag} overlap given their positions and dimensions.`);
      }
    }
  }
}

// ── Strip (continuous multi-column) footing ─────────────────────────────
// rawParams (all lengths in `unit`, default 'mm'):
//   B, L, D                footing width (constant along its length —
//                           same constant-width assumption combined
//                           makes), overall length spanning every
//                           column, depth
//   columns                array of { b, l, off }, length 2..MAX_COLUMNS
//                           — each column's plan cross-section and its
//                           centerline distance from the L=0 edge, same
//                           convention as combined's col1/col2. All
//                           columns are centered on the B midline (same
//                           assumption combined makes) — a strip with
//                           columns offset across B as well as along L
//                           is not modeled here. Tags (col1, col2, ...)
//                           are assigned by array order, not by sorted
//                           position along L — matches how combined's
//                           col1/col2 are caller-chosen labels, not
//                           positions.
//   cover, dia, spacing, unit     as combined
//   sectionThrough          1..columns.length, default 1 — which column
//                           (by array order) the section cut passes
//                           through
//
// This is combined's two-column case generalized to 2..MAX_COLUMNS — a
// continuous footing under a row of columns. It is NOT a wall strip
// footing: a continuous footing with zero columns, under a bearing wall
// rather than discrete columns, is a distinct sub-case and is not
// modeled — `columns` must have at least 2 entries.
export function computeStripFootingGeometry(rawParams) {
  const unit = rawParams.unit || 'mm';
  const B = toMm(rawParams.B, unit);
  const L = toMm(rawParams.L, unit);
  const D = toMm(rawParams.D, unit);
  const cover = toMm(rawParams.cover, unit);
  const dia = toMm(rawParams.dia, unit);
  const spacing = toMm(rawParams.spacing, unit);
  const sectionThrough = Number.isInteger(rawParams.sectionThrough) && rawParams.sectionThrough >= 1
    ? rawParams.sectionThrough : 1;

  for (const [name, v] of Object.entries({ B, L, D, cover, dia, spacing })) assertFinitePositive(name, v);

  const rawColumns = rawParams.columns;
  if (!Array.isArray(rawColumns) || rawColumns.length < 2) {
    throw new DiagramError('BAD_PARAM', `"columns" must list at least 2 columns for a strip footing, got ${Array.isArray(rawColumns) ? rawColumns.length : JSON.stringify(rawColumns)}.`);
  }
  if (rawColumns.length > MAX_COLUMNS) {
    throw new DiagramError('TOO_MANY_COLUMNS', `Strip footing supports at most ${MAX_COLUMNS} columns in this schematic, got ${rawColumns.length}.`);
  }

  const columns = rawColumns.map((c, i) => {
    const tag = `col${i + 1}`;
    const b = toMm(c.b, unit), l = toMm(c.l, unit), off = toMm(c.off, unit);
    assertFinitePositive(`${tag}.b`, b);
    assertFinitePositive(`${tag}.l`, l);
    if (!Number.isFinite(off) || off <= 0) {
      throw new DiagramError('BAD_PARAM', `"${tag}.off" must be a positive finite number, got ${JSON.stringify(c.off)}.`);
    }
    if (b >= B) throw new DiagramError('COLUMN_TOO_WIDE', `${tag}.b (${b}mm) must be smaller than B (${B}mm).`);
    const lo = off - l / 2, hi = off + l / 2;
    if (lo < 0 || hi > L) {
      throw new DiagramError('COLUMN_OUT_OF_BOUNDS', `${tag} (offset ${off}mm, length ${l}mm) extends outside the footing's L=${L}mm extent.`);
    }
    return { tag, b, l, off };
  });

  assertNoOverlap1D(columns);

  if (sectionThrough > columns.length) {
    throw new DiagramError('BAD_PARAM', `"sectionThrough" (${sectionThrough}) exceeds the column count (${columns.length}).`);
  }
  const chosen = columns[sectionThrough - 1];
  const section = computeSectionGeometry({
    widthMM: B, depthMM: D, colWidthMM: chosen.b,
    coverMM: cover, diaMM: dia, nominalSpacingMM: spacing,
  });
  // [Step 14.1] dowels/pedestal belong to `chosen` only, same as combined.
  // B (footing width) is passed separately for mesh — see Step 14.3's
  // fix note.
  const extras = computeFootingExtras(rawParams, unit, chosen.b, B, cover);

  return {
    type: 'strip',
    unit,
    sectionThrough,
    plan: {
      longLabel: 'L', shortLabel: 'B', longMM: L, shortMM: B,
      columns: columns.map((c) => ({ alongLongMM: c.l, alongShortMM: c.b, centerLongMM: c.off, tag: c.tag })),
    },
    section,
    meta: { B, L, D, cover, dia, spacing, columns },
    ...extras,
  };
}

// ── Raft (mat) foundation ────────────────────────────────────────────────
// rawParams (all lengths in `unit`, default 'mm'):
//   B, L, D                raft plan width (short/vertical axis in the
//                           drawing) and length (long/horizontal axis),
//                           uniform thickness. Unlike isolated, axes are
//                           never auto-swapped to "longer axis
//                           horizontal": col offx/offy are given
//                           relative to a fixed L/B convention, and
//                           swapping which axis is called which would
//                           silently invalidate every position the
//                           caller supplied — same reasoning combined
//                           already follows, for the same reason.
//   columns                array of { b, l, offx, offy }, length
//                           2..MAX_COLUMNS — b/l are the column's plan
//                           cross-section (b along B, l along L, same
//                           convention as colB/colL elsewhere in this
//                           file); offx is the column centerline's
//                           distance from the L=0 edge, offy from the
//                           B=0 edge. Tags assigned by array order.
//   cover, dia, spacing, unit     as combined — spacing applies to both
//                           plan directions (isotropic mesh, same
//                           simplification combined already makes)
//   sectionThrough          1..columns.length, default 1 — which column
//                           the section cut passes through. The cut is a
//                           straight vertical line at that column's
//                           offx, spanning the full B — a representative
//                           section, not a claim about any other
//                           column's actual depth along that same cut
//                           line.
export function computeRaftFootingGeometry(rawParams) {
  const unit = rawParams.unit || 'mm';
  const B = toMm(rawParams.B, unit);
  const L = toMm(rawParams.L, unit);
  const D = toMm(rawParams.D, unit);
  const cover = toMm(rawParams.cover, unit);
  const dia = toMm(rawParams.dia, unit);
  const spacing = toMm(rawParams.spacing, unit);
  const sectionThrough = Number.isInteger(rawParams.sectionThrough) && rawParams.sectionThrough >= 1
    ? rawParams.sectionThrough : 1;

  for (const [name, v] of Object.entries({ B, L, D, cover, dia, spacing })) assertFinitePositive(name, v);

  const rawColumns = rawParams.columns;
  if (!Array.isArray(rawColumns) || rawColumns.length < 2) {
    throw new DiagramError('BAD_PARAM', `"columns" must list at least 2 columns for a raft foundation, got ${Array.isArray(rawColumns) ? rawColumns.length : JSON.stringify(rawColumns)}.`);
  }
  if (rawColumns.length > MAX_COLUMNS) {
    throw new DiagramError('TOO_MANY_COLUMNS', `Raft foundation supports at most ${MAX_COLUMNS} columns in this schematic, got ${rawColumns.length}.`);
  }

  const columns = rawColumns.map((c, i) => {
    const tag = `col${i + 1}`;
    const b = toMm(c.b, unit), l = toMm(c.l, unit);
    const offx = toMm(c.offx, unit), offy = toMm(c.offy, unit);
    assertFinitePositive(`${tag}.b`, b);
    assertFinitePositive(`${tag}.l`, l);
    if (!Number.isFinite(offx) || offx <= 0) {
      throw new DiagramError('BAD_PARAM', `"${tag}.offx" must be a positive finite number, got ${JSON.stringify(c.offx)}.`);
    }
    if (!Number.isFinite(offy) || offy <= 0) {
      throw new DiagramError('BAD_PARAM', `"${tag}.offy" must be a positive finite number, got ${JSON.stringify(c.offy)}.`);
    }
    if (b >= B) throw new DiagramError('COLUMN_TOO_WIDE', `${tag}.b (${b}mm) must be smaller than B (${B}mm).`);
    if (l >= L) throw new DiagramError('COLUMN_TOO_WIDE', `${tag}.l (${l}mm) must be smaller than L (${L}mm).`);
    const loX = offx - l / 2, hiX = offx + l / 2;
    const loY = offy - b / 2, hiY = offy + b / 2;
    if (loX < 0 || hiX > L || loY < 0 || hiY > B) {
      throw new DiagramError('COLUMN_OUT_OF_BOUNDS', `${tag} (offx ${offx}mm, offy ${offy}mm, ${l}x${b}mm) extends outside the raft's ${L}x${B}mm footprint.`);
    }
    return { tag, b, l, offx, offy };
  });

  assertNoOverlap2D(columns);

  if (sectionThrough > columns.length) {
    throw new DiagramError('BAD_PARAM', `"sectionThrough" (${sectionThrough}) exceeds the column count (${columns.length}).`);
  }
  const chosen = columns[sectionThrough - 1];
  const section = computeSectionGeometry({
    widthMM: B, depthMM: D, colWidthMM: chosen.b,
    coverMM: cover, diaMM: dia, nominalSpacingMM: spacing,
  });
  // [Step 14.1] dowels/pedestal belong to `chosen` only, same as combined/strip.
  // B (footing width) is passed separately for mesh — see Step 14.3's
  // fix note.
  const extras = computeFootingExtras(rawParams, unit, chosen.b, B, cover);

  return {
    type: 'raft',
    unit,
    sectionThrough,
    plan: {
      longLabel: 'L', shortLabel: 'B', longMM: L, shortMM: B,
      columns: columns.map((c) => ({
        alongLongMM: c.l, alongShortMM: c.b, centerLongMM: c.offx, centerShortMM: c.offy, tag: c.tag,
      })),
    },
    section,
    meta: { B, L, D, cover, dia, spacing, columns },
    ...extras,
  };
}

// ── SVG rendering ─────────────────────────────────────────────────────
const CANVAS = { w: 960, h: 760 };
const PLAN_BOX = { x: 80, y: 60, w: 800, h: 280 };
const SECTION_BOX = { x: 80, y: 420, w: 800, h: 240 };
const MIN_BAR_PX_R = 3.2;      // bars stay legible even when geometry scales tiny
const MIN_STROKE_PX = 1.2;

// [Bugfix, this session — reviewer feedback] The bottom bar row's clear
// cover from the footing's own underside (barY = baseY - cover*scale,
// just below) had no pixel floor, unlike every other real-but-small
// dimension in this file (MIN_BAR_PX_R/MIN_STROKE_PX just above,
// MIN_COLUMN_BAR_VISIBLE_PX's own former role). At typical scale a
// 50mm cover renders as a ~6-7px gap, and the bar dot's own radius
// (MIN_BAR_PX_R=3.2px floor) eats most of that — the bars visually read
// as sitting almost exactly on the bottom face, i.e. no cover at all,
// which is wrong at ANY scale (cover is never zero on a real footing).
// Flagged directly against a rendered PNG, not inferred from the
// coordinate math. 12px keeps the gap unambiguous at this file's usual
// render sizes without being so large it reads as a second dimension
// needing its own callout.
const MIN_COVER_GAP_PX = 12;

// [Bugfix, this session round 8 — reviewer feedback, supersedes round 7's
// fixed-tick version] "رجل الحديد هي عبارة عن ارتفاع القاعدة مطروح منه
// الكفر العلوي والسفلي" — round 7's PLAN_HOOK_TICK_PX (a fixed 14px
// in-plane bend, same idea as DOWEL_HOOK_FOOT_FACTOR/BREAK_SYMBOL_MARGIN_PX)
// was wrong in KIND, not degree: this leg is not an illustrative mark at
// all, it is the SAME real, already-correctly-computed quantity
// renderSectionView's own bottom-bar hook uses (barY to legTopY spans
// exactly depthMM - 2*coverMM — see that block's own comment) — bar-
// bending-schedule convention draws an out-of-plane leg true-length,
// "unfolded" into the plane of the page, not foreshortened to a token
// tick. renderPlanView now computes this directly from geometry.section
// (depthMM, coverMM) rather than using this constant as the value; the
// constant below is kept only as a floor for the degenerate case
// (cover so large relative to depth that depthMM - 2*coverMM is small or
// negative), the same role MIN_BAR_PX_R/MIN_COVER_GAP_PX already play for
// other real-but-occasionally-tiny quantities in this file, not a
// default.
const MIN_PLAN_HOOK_PX = 8;

// [This session — visual-style pass] Palette matched against a color
// scan of the ECP 203 detailing guide's own figure (شكل ٢-١٦), not
// invented: background cream, main reinforcement (bottom bars, dowels)
// a dark maroon, secondary reinforcement (ties, transverse callouts) a
// mustard gold, plain concrete flat light gray, reinforced concrete a
// stippled mid gray. One named constant per role rather than the hex
// literal repeated at each use site, so a future correction is a
// one-line change instead of a find-and-replace across the file.
const CANVAS_BG = '#F9F8F3';
const REBAR_MAIN = '#800000';
const REBAR_MAIN_STROKE = '#5c0000';
const REBAR_SECONDARY = '#D4A017';
const PC_FILL = '#E5E5E5';
const RC_FILL_BG = '#d3d3d3';
const RC_FILL_DOT = '#9a9fa5';
const LEVEL_MARKER = '#87CEEB';
const LEVEL_MARKER_STROKE = '#4a90a4';
const CENTERLINE_COLOR = '#7fa8c9';

// Types whose plan view carries more than one tagged column, and whose
// section view is therefore "through col<N>" rather than an unlabeled
// single cut. isolated has exactly one, unlabeled column and is
// deliberately excluded — there is nothing to disambiguate.
const NUMBERED_COLUMN_TYPES = new Set(['combined', 'strip', 'raft']);

// Local duplicates of structuralDrawingKit.mjs's esc/dimensionLine/
// hatchDefs — see this file's Step 17 header addendum for why. All three
// verified functionally identical to the kit's exported versions.
// [Bugfix, this session] No real font metrics are available at SVG-
// generation time — same limitation wrapText's own header already
// documents for this file, applied here to a second problem. Used only
// to size the RIGHT-side dimension-label gutter in renderSectionView
// (see rightGutterPx there) against the two CENTERED labels
// (cover=.../N Ø.. @ ..) that can otherwise reach into it on a small or
// near-square footing — never to lay out real glyphs. 0.62 x font-size
// per character is a generous average advance width for the Latin+
// digit engineering strings this is ever called on (B=/D=/cover=/Ø/mm/
// @only — never an Arabic phrase, which this file's own scriptPrefix
// convention keeps on separate <text> lines specifically so a case like
// this one never has to estimate Arabic glyph widths); slightly
// over-wide is the safe direction for a gutter-clearance calculation,
// under-wide is what caused the bug this exists to fix.
function estimateTextWidthPx(str, fontSizePx = 15) {
  return String(str).length * fontSizePx * 0.62;
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// [This session] opts.script: set true ONLY when `label` carries a
// translated phrase (dowel lap length, blinding thickness) rather than
// pure engineering notation (B=/D=/cover=/mm/Ø, always Latin+digits by
// convention regardless of lang — see this file's own header on that
// point). Every pre-existing call site omits opts.script and keeps
// rendering through .dim-label/defaultFontStack exactly as before —
// this is a strictly additive branch, not a behavior change to any
// existing caller. Needed because defaultFontStack puts Arial first:
// this file's own renderFootingDiagramSVG comment documents that at
// least one real SVG renderer (cairosvg) resolves a font-family list by
// matching only the FIRST token and never falls back for a missing
// glyph — an Arabic phrase under .dim-label would render as tofu there,
// the identical bug Step 4 fixed for view-title/col-tag/cut-label/
// sheet-title/sheet-caption. Those all use scriptFontStack; a label
// this function draws should follow the same rule when it is one of
// them, which opts.script now lets a caller declare.
// [This session] opts.labelT: where along the line (0=start, 1=end,
// default 0.5=exact center) the label sits. Every pre-existing call site
// omits it, so midX/midY below reduce to the exact original (x1+x2)/2,
// (y1+y2)/2 formula — mathematically identical, not just visually.
// Needed for one specific new case: the blinding-footprint plan
// dimension and the pre-existing footing plan dimension are concentric
// rectangles, so their default-centered labels land on the IDENTICAL
// midpoint regardless of how long either string is — found by actually
// rendering the extras case to PNG and looking at it, not from the
// coordinate math alone (see renderPlanView's own call for the fix).
// [This session, revised] opts.script alone (previous paragraph) turned
// out insufficient: rendering this file's own output to PNG (cairosvg +
// real Noto Naskh Arabic, not assumed) showed that font is missing far
// more than parentheses/dashes — it has no Latin LETTERS and no "="/":"
// either. A single class on a string mixing "طول ربط أسياخ الانتظار"
// with "= 600mm" tofus the ENTIRE thing under a non-fallback renderer,
// not just the punctuation. opts.scriptPrefix is the actual fix: the
// Arabic phrase and the Latin "= value" become two separate <tspan>s,
// each with its OWN explicit class/font — correct regardless of whether
// the renderer falls back through a font-family list at all, rather
// than depending on it. opts.script (no prefix, one class on the whole
// string) is left in place as a fallback path — nothing currently calls
// it that way after this revision, but removing it serves no purpose
// and widens the diff for no benefit.
// [This session, revised again] The tspan-concatenation approach above
// (opts.scriptPrefix as two <tspan> children of one <text>) turned out
// to have the SAME class of problem one level down: rendering to PNG
// showed the phrase and value tspans landing on TOP of each other
// rather than flowing in sequence, even though each had its own correct
// class/font. Root cause, confirmed by elimination (repositioning every
// SURROUNDING element did nothing — the bug travels with the text
// element itself): cairosvg/Pango does not implement multi-tspan flow
// under text-anchor="end" + dir="rtl" the way the SVG spec describes:
// un-positioned sibling tspans should continue inline from where the
// previous one ended, but here both anchor independently at the same
// point. Fix: two fully independent <text> elements (phrase above,
// value below), each with its own x/y/anchor, no flow relationship for
// a renderer to get wrong. Costs a second line of vertical space, which
// every call site below now accounts for.
function dimensionLine(x1, y1, x2, y2, label, opts = {}) {
  const orientation = opts.orientation || (Math.abs(x1 - x2) >= Math.abs(y1 - y2) ? 'h' : 'v');
  const tick = 6;
  const t = opts.labelT != null ? opts.labelT : 0.5;
  const midX = x1 + (x2 - x1) * t, midY = y1 + (y2 - y1) * t;
  const labelDx = orientation === 'h' ? 0 : -10;
  const labelDy = orientation === 'h' ? -6 : 4;
  const anchor = orientation === 'h' ? 'middle' : 'end';
  const lines = `
    <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="dim-line"/>
    <line x1="${x1}" y1="${y1 - tick}" x2="${x1}" y2="${y1 + tick}" class="dim-tick"/>
    <line x1="${x2}" y1="${y2 - tick}" x2="${x2}" y2="${y2 + tick}" class="dim-tick"/>`;
  if (opts.scriptPrefix) {
    const px = midX + labelDx, py = midY + labelDy;
    return `${lines}
    <text x="${px}" y="${py - 9}" text-anchor="${anchor}" dir="rtl" class="dim-label-script">${esc(opts.scriptPrefix)}</text>
    <text x="${px}" y="${py + 9}" text-anchor="${anchor}" class="dim-label">${esc(label)}</text>`;
  }
  const textClass = opts.script ? 'dim-label-script' : 'dim-label';
  const dirAttr = opts.script ? ' dir="rtl"' : '';
  return `${lines}
    <text x="${midX + labelDx}" y="${midY + labelDy}" text-anchor="${anchor}"${dirAttr} class="${textClass}">${esc(label)}</text>`;
}

// [This session] Level marker (منسوب) — inverted triangle sitting on a
// short horizontal line, matching the guide figure's own symbol for
// calling out an elevation (used there for founding level and the
// reinforced footing's own top face). `side` is about DRAWING position
// (label extends further left or right of the marker), independent of
// `lang` (RTL Arabic still reads naturally growing away from the
// marker in either direction — only text-anchor changes, not the
// underlying geometry).
function levelMarker(x, y, label, lang, side) {
  const halfLine = 15, triW = 9, triH = 13;
  const labelClass = lang === 'ar' ? 'dim-label-script' : 'dim-label';
  const dirAttr = lang === 'ar' ? ' dir="rtl"' : '';
  const anchor = side === 'left' ? 'end' : 'start';
  const labelX = side === 'left' ? x - halfLine - 6 : x + halfLine + 6;
  return `
    <line x1="${x - halfLine}" y1="${y}" x2="${x + halfLine}" y2="${y}" class="level-line"/>
    <path d="M${x - triW / 2},${(y - triH).toFixed(2)} L${x + triW / 2},${(y - triH).toFixed(2)} L${x},${y} Z" class="level-marker"/>
    <text x="${labelX}" y="${y - 4}" text-anchor="${anchor}"${dirAttr} class="${labelClass}">${esc(label)}</text>`;
}

// [Integration merge — this pass] Column/confinement tie mark. Was a
// local duplicate of structuralDrawingKit.mjs's tieTickH(), kept local
// because — per this comment's own prior wording — "the kit file itself
// was not available in this session to confirm tieTickH()'s actual
// parameter order/signature against". The kit is now co-located and its
// tieTickH() confirmed by direct read: same 3-segment shape (one main
// line + two end-cap hashes), same parameter order (xLeftPx, xRightPx,
// yPx). It hardcoded a 4px cap and the 'stirrup-tick' class, so it has
// been given a fourth opts argument ({capPx, cssClass}) rather than
// duplicated again — the call site below now reads
// tieTickH(tieLeftX, tieRightX, y, { capPx: 5, cssClass: 'tie-tick' })
// to keep this file's own capped-at-5px, tie-tick-colored tie marks
// visually unchanged (verified byte-identical against this function's
// pre-merge output — see test/regression-footing-extended.mjs).

// [This session — column main bars] A standard drafting "break" mark
// (two opposed zigzags) meaning "this element continues past this
// point, not drawn to its real extent" — the SAME convention the
// generic (no-numbers) path's own gBreakSymbol() already draws for the
// identical reason, ported here as a section-view-local twin using this
// path's own stroke class (column-outline's stroke color) rather than
// gBreakSymbol's hardcoded '#1c2b3a', since the computed and generic
// paths keep independent styling throughout this file (see this file's
// header on tieTick being a local copy for the same kind of reason).
function breakSymbol(cx, y, halfW) {
  const x1 = cx - halfW - 4, x2 = cx + halfW + 4;
  return `
    <path d="M${x1},${y} L${x1 + 6},${y - 7} L${x1 + 14},${y + 7} L${x1 + 22},${y - 7} L${x1 + 30},${y}
      M${x2 - 30},${y} L${x2 - 22},${y - 7} L${x2 - 14},${y + 7} L${x2 - 6},${y - 7} L${x2},${y}"
      fill="none" stroke="#1a1a1a" stroke-width="1.4"/>`;
}

// [This session — visual-style pass] Recolored/reshaped to match the
// ECP 203 detailing-guide figure's own actual rendering (شكل ٢-١٦),
// confirmed against a color scan, not the black-and-white one used
// earlier: RC gets a stipple/dot fill (the guide draws reinforced
// concrete as dots-on-gray, not diagonal hatch lines).
// [Bugfix, this session round 5 — reviewer feedback, supersedes the PC
// claim above] "هل لديك القدرة على وضع تهشير للخرسانة العادية؟ تهشير
// الخرسانة العادية مختلف تماماً عن تهشير الخرسانة المسلحة" — PC
// (plainConcreteHatch) was flat solid PC_FILL with no line texture at
// all, on the theory above that the guide figure draws it that way.
// Explicit, current, on-the-actual-render feedback overrides that
// undocumented color-scan claim from a prior session this file has no
// way to re-verify. PC now keeps the same light PC_FILL background
// (still visually "concrete-family", not a different material) but
// gains sparse diagonal line hatching — and at rotate(135), the
// OPPOSITE diagonal from soilHatch's rotate(45) just above, not merely
// a different color, since blinding sits directly adjacent to soil in
// this drawing and an opposite angle keeps the two unmistakable at a
// glance even before reading either one's color.
// [Second half of the same bug] Defining the pattern correctly was not
// sufficient on its own: `fill="url(#plainConcreteHatch)"` was already
// present on both `<rect class="blinding-outline">` elements (plan
// projection ring, section band) BEFORE this fix, but .blinding-outline
// in the <style> block below carried `fill:none` — an SVG presentation
// attribute is lower specificity than a CSS class rule from a <style>
// element, so that stylesheet rule was silently winning and suppressing
// whatever the rect's own fill attribute said, pattern or otherwise.
// Fixed by dropping fill:none from .blinding-outline itself (see that
// rule, further down) — the attribute alone was never going to work
// while the class kept overriding it, regardless of what the pattern
// contained.
// [Bugfix, this session round 6 — reviewer feedback, supersedes round 5's
// diagonal-line version above] "هذا التهشير يستخدم للخرسانة المسلحة
// وليس العادية. تهشير الخرسانة العادية مختلف. انظر للرسم" — round 5's
// rotate(135) diagonal lines were themselves wrong, not just the earlier
// flat fill: per the newly-supplied reference figure, plain/blinding
// concrete is a dense irregular AGGREGATE SPECKLE texture (small dark
// dots scattered at non-grid-aligned positions), and diagonal line
// hatching reads as the REINFORCED-concrete convention instead in that
// same reference. plainConcreteHatch below is redesigned to that
// speckle look: 8 small circles at deliberately uneven (not evenly
// spaced/grid-aligned) positions within one 8x8 tile, two close-but-
// distinct dark grays (#333/#444) for a bit of visual noise rather than
// one flat dot color — the same repeating-tile-with-irregular-placement
// technique standard CAD hatch libraries use for a "concrete aggregate"
// swatch, since a true non-repeating random texture is not something an
// SVG <pattern> (inherently one tile, tiled identically) can produce.
// Left deliberately denser/smaller (8x8, r 0.4-0.55) than concreteHatch's
// own 9x9/r-0.85 two-dot tile just above, so the two stay visually
// distinct at a glance and not just "the same dot idea, different
// count" — concreteHatch's own regular two-dot repeat is UNCHANGED by
// this fix; nothing in this round's feedback was about how reinforced
// concrete looks, only about plain concrete needing to look different
// from it, which it already did before this round in a different way
// (flat vs diagonal-hatched) and does again now (regular two-dot repeat
// vs irregular eight-speck repeat).
function hatchDefs() {
  return `
    <pattern id="soilHatch" width="10" height="10" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <line x1="0" y1="0" x2="0" y2="10" stroke="#8a7350" stroke-width="1.4"/>
    </pattern>
    <pattern id="concreteHatch" width="9" height="9" patternUnits="userSpaceOnUse">
      <rect width="9" height="9" fill="${RC_FILL_BG}"/>
      <circle cx="2.25" cy="2.25" r="0.85" fill="${RC_FILL_DOT}"/>
      <circle cx="6.75" cy="6.75" r="0.85" fill="${RC_FILL_DOT}"/>
    </pattern>
    <pattern id="plainConcreteHatch" width="8" height="8" patternUnits="userSpaceOnUse">
      <rect width="8" height="8" fill="${PC_FILL}"/>
      <circle cx="1.2" cy="1.5" r="0.5" fill="#333"/>
      <circle cx="4.5" cy="0.8" r="0.4" fill="#444"/>
      <circle cx="6.8" cy="2.3" r="0.55" fill="#333"/>
      <circle cx="2.7" cy="3.8" r="0.45" fill="#444"/>
      <circle cx="6" cy="5" r="0.5" fill="#333"/>
      <circle cx="0.8" cy="6.2" r="0.4" fill="#444"/>
      <circle cx="3.8" cy="6.8" r="0.55" fill="#333"/>
      <circle cx="7" cy="7.2" r="0.4" fill="#444"/>
    </pattern>`;
}

// Draws the top-down view: footing outline, a reinforcement MESH drawn as
// crossing lines (long-way lines at geometry.section.barCentersMM — the
// same set the section view draws as circles, one source of truth for
// that direction; short-way lines recomputed inline just below since
// that count is plan-only and no other view needs it), every column
// (plus its pedestal outline, dashed, when supplied), a lettered
// section-cut marker on multi-column types, and the two overall
// dimension lines. Schematic, not to-scale-of-real-bar-diameter: bar
// lines are drawn at a fixed thin stroke width regardless of `dia`,
// consistent with this file's "representative, not photographic" scope.
function renderPlanView(geometry, scale, lang) {
  const { plan } = geometry;
  const originX = PLAN_BOX.x + (PLAN_BOX.w - plan.longMM * scale) / 2;
  const originY = PLAN_BOX.y + (PLAN_BOX.h - plan.shortMM * scale) / 2;
  const wPx = plan.longMM * scale, hPx = plan.shortMM * scale;

  let svg = `<g class="plan-view">`;

  // [This session] Blinding (plain concrete) footprint — drawn BEHIND the
  // reinforced-footing outline below, offset outward by the caller's own
  // blinding.projectionMM on all four sides. Matches the guide figure's
  // own plan view, which dimensions the plain-concrete footprint
  // (طول/عرض القاعدة العادية) as a distinct, wider outline around the
  // reinforced footing's own footprint (طول/عرض القاعدة المسلحة) — not a
  // single outline, the way this drawing's plan view was before this
  // group existed.
  if (geometry.blinding) {
    const projPx = geometry.blinding.projectionMM * scale;
    const bx = originX - projPx, by = originY - projPx;
    const bw = wPx + 2 * projPx, bh = hPx + 2 * projPx;
    svg += `<rect x="${bx}" y="${by}" width="${bw}" height="${bh}" class="blinding-outline" fill="url(#plainConcreteHatch)"/>`;
    // [This session] NOT a second stacked dimensionLine, unlike the B
    // (vertical) case just below: PLAN_BOX leaves roughly 45px between
    // the plan view's own top edge and the sheet title, which the ONE
    // pre-existing L-dimension already uses nearly all of — a second
    // stacked horizontal dimension line has no headroom left at any
    // offset and collides with the title regardless (found by rendering
    // to PNG). A left-anchored corner label needs no extra vertical band
    // of its own, so it sidesteps the headroom limit instead of fighting
    // it.
    // [This session] L folded into the SAME vertical-dimension label as
    // B, not a separate stacked horizontal line of its own: PLAN_BOX
    // leaves too little room between the plan view's own top edge and
    // the sheet title for a second horizontal dimension line at ANY
    // offset (found by rendering to PNG — labelT only shifts a label
    // ALONG its own line, which does nothing for a collision on the
    // cross-axis). The vertical B-dimension had genuine room once
    // de-centered (labelT: 0.68, below), so both values ride on it.
    // [This session] Projection alone, not a combined "L=..., B=..."
    // string: that longer form, with an internal comma, broke tspan
    // positioning under cairosvg (found by rendering to PNG — both
    // tspans landed stacked at the same X instead of flowing in
    // sequence), even though the identical scriptPrefix/label split
    // works correctly for the shorter labels just below. Projection is
    // the one new fact this outline doesn't already show on its own;
    // the outer L/B are visible from its drawn proportions.
    svg += dimensionLine(
      bx - 46, by, bx - 46, by + bh,
      lang === 'ar' ? `= ${fmt(geometry.blinding.projectionMM, geometry.unit, 0)}` : `${translate('blindingProjection', lang)} = ${fmt(geometry.blinding.projectionMM, geometry.unit, 0)}`,
      { orientation: 'v', scriptPrefix: lang === 'ar' ? translate('blindingProjection', lang) : undefined, labelT: 0.68 },
    );
  }

  svg += `<rect x="${originX}" y="${originY}" width="${wPx}" height="${hPx}" class="footing-outline" fill="url(#concreteHatch)"/>`;

  // [Bugfix, this session round 7 — reviewer feedback] "حديد الشبكة في
  // المسقط الأفقي، قم بإزالته، واكتفِ فقط برسم الحديد المرسوم بالمسقط
  // الأفقي الموضح [بالمرجع]" — this used to loop every barCentersMM
  // position in BOTH directions, drawing a full literal N x M grid (for
  // this file's own 12 Ø16 @ 153mm running example, a dense 12-line by
  // several-line mesh). The reference figure's own plan view is
  // schematic, not literal: only the OUTERMOST bar in each direction is
  // drawn, each with its own hooked ends bent 90 deg IN-PLANE toward the
  // interior — the reference's rounded-corner "frame" look is two
  // straight bars' hook returns landing close together at each corner,
  // not one continuous loop or a real mesh. Interior bars are not drawn
  // individually at all: the section view's own "N Ø D @ S" callout and
  // the summary table already carry the real count/spacing, so
  // redrawing every one of them here a second time was pure duplication,
  // not information the plan view uniquely provided.
  // [Bugfix, this session round 9 — reviewer feedback, extends round 8]
  // "ما مشكلتك في أن تصنع مثل هذا تماماً" — a closer crop of the same
  // reference shows the outer hooked bar is NOT alone at each edge: a
  // second, PLAIN (unhooked) bar runs immediately alongside it, and a
  // bar-spec label ("تسليح طولي * <spacing>") sits next to that pair —
  // round 7/8 only ever drew the single outer hooked bar per direction.
  // innerLongYs/innerTransXs below are the REAL second-bar-from-each-edge
  // positions already present in barCentersMM/the transverse count this
  // block computes anyway — not a second invented offset — so the inner
  // line lands exactly where that actual bar sits, not at an arbitrary
  // schematic gap from the outer one. Guarded (length > 2 / count > 2)
  // so a footing with too few bars to HAVE a distinct second position
  // does not draw the same line twice on top of itself.
  const planHookLegPx = Math.max(MIN_PLAN_HOOK_PX, (geometry.section.depthMM - 2 * geometry.section.coverMM) * scale);
  {
    const centers = geometry.section.barCentersMM;
    const outerYs = [centers[0], centers[centers.length - 1]].map((cMM) => originY + cMM * scale);
    for (const y of outerYs) {
      const x1 = originX + 2, x2 = originX + wPx - 2;
      const tickDir = y < originY + hPx / 2 ? 1 : -1; // bend toward the interior
      const yTick = (y + tickDir * planHookLegPx).toFixed(2);
      svg += `<path d="M${x1},${yTick} L${x1},${y.toFixed(2)} L${x2},${y.toFixed(2)} L${x2},${yTick}" fill="none" class="mesh-line"/>`;
    }
    if (centers.length > 2) {
      const innerYs = [centers[1], centers[centers.length - 2]].map((cMM) => originY + cMM * scale);
      for (const y of innerYs) {
        svg += `<line x1="${originX + 2}" y1="${y.toFixed(2)}" x2="${originX + wPx - 2}" y2="${y.toFixed(2)}" class="mesh-line"/>`;
      }
      const labelStr = `${centers.length} \u00d8${fmt(geometry.section.diaMM, geometry.unit, 0)} @ ${fmt(geometry.section.actualSpacingMM, geometry.unit, 0)}`;
      svg += `<text x="${originX + wPx / 2}" y="${(innerYs[1] + 16).toFixed(2)}" text-anchor="middle" class="dim-label">${esc(labelStr)}</text>`;
    }
  }
  {
    const env = plan.longMM - 2 * geometry.meta.cover - geometry.meta.dia;
    const spacingLong = geometry.meta.spacingLong ?? geometry.meta.spacing;
    const count = Math.max(2, Math.floor(env / spacingLong) + 1);
    const first = geometry.meta.cover + geometry.meta.dia / 2;
    const last = plan.longMM - geometry.meta.cover - geometry.meta.dia / 2;
    const step = count > 1 ? (last - first) / (count - 1) : 0;
    const outerMM = count > 1 ? [first, last] : [plan.longMM / 2];
    for (const posMM of outerMM) {
      const x = originX + posMM * scale;
      const y1 = originY + 2, y2 = originY + hPx - 2;
      const tickDir = x < originX + wPx / 2 ? 1 : -1; // bend toward the interior
      const xTick = (x + tickDir * planHookLegPx).toFixed(2);
      svg += `<path d="M${xTick},${y1} L${x.toFixed(2)},${y1} L${x.toFixed(2)},${y2} L${xTick},${y2}" fill="none" class="mesh-line"/>`;
    }
    if (count > 2) {
      const innerMM = [first + step, last - step];
      const innerXs = innerMM.map((posMM) => originX + posMM * scale);
      for (const x of innerXs) {
        svg += `<line x1="${x.toFixed(2)}" y1="${originY + 2}" x2="${x.toFixed(2)}" y2="${originY + hPx - 2}" class="mesh-line"/>`;
      }
      // BUGFIX [PLAN-LONGAXIS-LABEL-SPACING]: was `fmt(spacingLong, ...)`,
      // the raw nominal/target spacing straight from the input -- not what
      // distributeCenters' even-distribution actually produced (`step`,
      // the exact long-axis analogue of the short axis's own
      // actualSpacingMM, used correctly in labelStr just above). For a
      // square footing (longMM === shortMM) both axes run the identical
      // formula on identical inputs, so they must produce identical actual
      // spacing -- yet this label showed the untouched nominal value
      // (e.g. "150mm") while the short-axis label a few lines up showed
      // the real distributed value (e.g. "153mm") for the SAME footing,
      // visibly contradicting a drawing that is actually symmetric.
      // Violates this file's own "no number you can't defend" rule (see
      // the computeFootingExtras header comment on the same principle):
      // `step` is what the bars above are actually drawn at; `spacingLong`
      // is only ever the pre-distribution target.
      const labelStr2 = `${count} \u00d8${fmt(geometry.meta.dia, geometry.unit, 0)} @ ${fmt(step, geometry.unit, 0)}`;
      svg += `<text x="${(innerXs[1] - 12).toFixed(2)}" y="${originY + hPx / 2}" text-anchor="middle" class="dim-label" transform="rotate(-90 ${(innerXs[1] - 12).toFixed(2)} ${originY + hPx / 2})">${esc(labelStr2)}</text>`;
    }
  }

  // [This session] Grid centerlines (محاور) — dash-dot, extending past
  // the outermost drawn footprint (blinding's, if present, else the
  // reinforced footing's) on all four sides, matching the guide
  // figure's own plan-view convention exactly: the horizontal axis gets
  // an open (unfilled) circle at BOTH ends; the vertical axis gets one
  // ONLY at the bottom end, not the top (confirmed against the source
  // description, not guessed for symmetry). Drawn through each column's
  // own center — for isolated (exactly one column) this reduces to the
  // single cross through the middle the figure shows; combined/strip/
  // raft draw one per column, which overlap into a shared line wherever
  // those columns share an axis (harmless, not deduplicated — a lower
  // priority than getting isolated right, out of scope for this pass).
  {
    const clMargin = 40;
    const projPx = geometry.blinding ? geometry.blinding.projectionMM * scale : 0;
    const oLeft = originX - projPx - clMargin, oRight = originX + wPx + projPx + clMargin;
    const oTop = originY - projPx - clMargin, oBottom = originY + hPx + projPx + clMargin;
    plan.columns.forEach((col) => {
      const cx = originX + col.centerLongMM * scale;
      const cy = col.centerShortMM != null ? originY + col.centerShortMM * scale : originY + hPx / 2;
      svg += `<line x1="${oLeft}" y1="${cy}" x2="${oRight}" y2="${cy}" class="centerline"/>`;
      svg += `<line x1="${cx}" y1="${oTop}" x2="${cx}" y2="${oBottom}" class="centerline"/>`;
      svg += `<circle cx="${oLeft}" cy="${cy}" r="8" class="centerline-dot"/>`;
      svg += `<circle cx="${oRight}" cy="${cy}" r="8" class="centerline-dot"/>`;
      svg += `<circle cx="${cx}" cy="${oBottom}" r="8" class="centerline-dot"/>`;
    });
  }

  // Columns
  plan.columns.forEach((col, i) => {
    const cx = originX + col.centerLongMM * scale;
    // raft columns carry their own centerShortMM (2-D position in
    // plan); every other type omits it, which keeps them on the
    // vertical center of the plan box exactly as before this field
    // existed — isolated/combined/strip are unaffected.
    const cy = col.centerShortMM != null ? originY + col.centerShortMM * scale : originY + hPx / 2;
    const cw = col.alongLongMM * scale, ch = col.alongShortMM * scale;
    // [Step 14.3] Pedestal outline drawn UNDER every column in plan —
    // the plan already shows every column, so it shows every pedestal
    // too (unlike dowels, which are section-only: see design note
    // "برمة تُرسم في كل مواضع الأعمدة في المسقط، لكن برمة واحدة فقط في
    // القطاع"). Dashed, not filled — a pedestal sits AT the footing top,
    // not literally in the footing plan, so it is drawn as an outline
    // overlay rather than a solid shape competing with the column fill
    // above it. Drawn before the column rect so the solid column sits
    // visually on top of it.
    if (geometry.pedestal) {
      const pedSidePx = geometry.pedestal.widthMM * scale;
      svg += `<rect x="${cx - pedSidePx / 2}" y="${cy - pedSidePx / 2}" width="${pedSidePx}" height="${pedSidePx}" fill="none" stroke="#1a1a1a" stroke-width="1" stroke-dasharray="4,3"/>`;
    }
    svg += `<rect x="${cx - cw / 2}" y="${cy - ch / 2}" width="${cw}" height="${ch}" class="column-outline"/>`;
    if (col.tag) {
      // [Step 4] translated ("COLUMN A"/"عمود أ", "COLUMN 3"/"عمود 3"),
      // not the raw internal col.tag ("col1") this used to print
      // straight to the drawing regardless of lang.
      const label = columnTag(geometry.type, i, lang);
      svg += `<text x="${cx}" y="${cy + ch / 2 + 16}" text-anchor="middle" dir="${lang === 'ar' ? 'rtl' : 'ltr'}" class="col-tag">${esc(label)}</text>`;
    }
  });

  // Section cut marker, so the section view below is traceable back to a
  // specific column instead of floating unlabeled. Applies to every type
  // with more than one numbered column (combined/strip/raft) — isolated
  // has exactly one, unlabeled column, so there is nothing to
  // disambiguate and no cut marker is drawn for it.
  if (NUMBERED_COLUMN_TYPES.has(geometry.type)) {
    const chosen = plan.columns[geometry.sectionThrough - 1];
    const cx = originX + chosen.centerLongMM * scale;
    const cutLetter = esc(translate('cutLetter', lang)); // 'A' (en) / 'أ' (ar) — must match renderSectionView's title below
    svg += `<line x1="${cx}" y1="${originY - 14}" x2="${cx}" y2="${originY + hPx + 14}" class="cut-line"/>`;
    svg += `<text x="${cx}" y="${originY - 18}" text-anchor="middle" class="cut-label">${cutLetter}</text>`;
    svg += `<text x="${cx}" y="${originY + hPx + 28}" text-anchor="middle" class="cut-label">${cutLetter}</text>`;
  }

  // Overall dimensions
  svg += dimensionLine(originX, originY - 26, originX + wPx, originY - 26, `${plan.longLabel} = ${fmt(plan.longMM, geometry.unit, 2)}`, { orientation: 'h' });
  svg += dimensionLine(originX - 26, originY, originX - 26, originY + hPx, `${plan.shortLabel} = ${fmt(plan.shortMM, geometry.unit, 2)}`, { orientation: 'v' });

  svg += `<text x="${originX + wPx / 2}" y="${originY + hPx + 46}" text-anchor="middle" dir="${lang === 'ar' ? 'rtl' : 'ltr'}" class="view-title">${esc(translate('plan', lang))}</text>`;
  svg += `</g>`;
  return svg;
}

// Draws the vertical cut: blinding (when supplied) + soil hatch, footing
// body, the column/pedestal stack rising from the footing top (real-
// scale pedestal when supplied, else a fixed decorative stub — see the
// Step 14.3 comment inline below for why that split exists, now sized
// to also clear any real dowel-leg/tie extent — see this session's own
// comment on stubH), column ties at the footing/column interface when
// supplied, a bent dowel leg + hooked foot per dowel when supplied (not
// just a row of circles — see this session's own comment inline), the
// bottom reinforcement layer (real count/spacing from
// computeSectionGeometry), the optional top mesh layer, and the depth/
// width/cover/bar-spec/blinding-thickness/dowel-lap-length dimension
// callouts. Same schematic-not-photographic scope as renderPlanView
// above.
function renderSectionView(geometry, scale, lang) {
  const { section } = geometry;
  const originX = SECTION_BOX.x + (SECTION_BOX.w - section.widthMM * scale) / 2;
  const baseY = SECTION_BOX.y + SECTION_BOX.h - 60; // leave room for soil hatch + labels below — footing's own bottom face
  const topY = baseY - section.depthMM * scale;
  const wPx = section.widthMM * scale;
  // [This session] Hoisted to the top of the function: barY (the bottom
  // reinforcement layer's Y) used to sit right before the block that
  // draws that layer; the new dowel foot below also anchors to it, so it
  // is computed once, early, rather than duplicated.
  // [Bugfix, this session — reviewer feedback round 2] coverPx factored
  // out to a named constant (was inline in barY's own expression only):
  // the bottom-bar hook legs now need the SAME cover-in-pixels value to
  // compute where they stop at the TOP face (topY + coverPx — see that
  // block below), and reusing this one value keeps "cover" meaning the
  // same visual quantity everywhere it is drawn, rather than risking a
  // second, differently-floored copy of the same concept.
  const coverPx = Math.max(MIN_COVER_GAP_PX, section.coverMM * scale);
  const barY = baseY - coverPx;
  const sectionMidX = originX + wPx / 2;

  let svg = `<g class="section-view">`;

  // [This session] Blinding (plain/lean concrete, سمك الخرسانة العادية)
  // — a second material layer BELOW the structural footing, projecting
  // outward by blinding.projectionMM on each side, distinct hatch
  // (plainConcreteHatch) from the structural concreteHatch above it.
  // Pushes the soil band down by the blinding's own thickness so the
  // stacking order matches the guide figure's own (reinforced concrete,
  // then plain concrete, then منسوب التأسيس/founding level at the soil
  // interface) instead of soil sitting directly under the structural
  // footing as it did before this group existed. blindPx is 0 (and
  // soilTopY reduces to exactly baseY) whenever blinding is absent, so
  // every position computed FROM soilTopY below is byte-identical to the
  // pre-existing baseY-based expression in that case.
  const blindPx = geometry.blinding ? geometry.blinding.thicknessMM * scale : 0;
  const soilTopY = baseY + blindPx;
  if (geometry.blinding) {
    const projPx = geometry.blinding.projectionMM * scale;
    svg += `<rect x="${originX - projPx}" y="${baseY}" width="${wPx + 2 * projPx}" height="${blindPx}" class="blinding-outline" fill="url(#plainConcreteHatch)"/>`;
  }
  // Soil band under everything
  // [Bugfix, this session — reviewer feedback] "هذا يوحي بوجود خرسانه
  // أسفل العاديه" — was `fill="url(#soilHatch)" stroke="#8a7350"
  // stroke-width="1"`. A full 4-sided stroked rectangle reads as a
  // defined material block regardless of which hatch pattern fills it —
  // visually the same "bordered rectangle" language this file uses for
  // every real concrete layer (.footing-outline/.blinding-outline both
  // stroke+fill). Below the blinding is undifferentiated soil, not
  // another engineered layer with a real thickness, so it should not
  // share that visual language. Dropping the stroke keeps the hatch
  // texture (there IS soil there, worth showing) without the enclosing
  // border that implied a second concrete course — the less destructive
  // of the two fixes suggested, keeping information the fully-removed
  // option would lose.
  svg += `<rect x="${originX - 20}" y="${soilTopY}" width="${wPx + 40}" height="26" fill="url(#soilHatch)"/>`;
  // Footing body
  svg += `<rect x="${originX}" y="${topY}" width="${wPx}" height="${section.depthMM * scale}" class="footing-outline" fill="url(#concreteHatch)"/>`;

  // [This session] Level markers — see the guide figure's own placement:
  // top-of-footing on the LEFT at the footing's own top face; founding
  // level on the RIGHT at the founding surface (soilTopY — bottom of
  // blinding when supplied, else the footing's own bottom; this already
  // reduces correctly with or without geometry.blinding since soilTopY
  // itself does).
  svg += levelMarker(originX - 20, topY, translate('topFootingLevel', lang), lang, 'left');
  // [Bugfix, this session round 3] foundingLevel's marker used to sit at
  // a fixed originX+wPx+95 regardless of what the D/blinding-thickness
  // gutter (rightGutterX, computed later in this function — see that
  // block) actually needed. In English specifically, "Blinding
  // Thickness = 100mm" is a much wider combined string than Arabic's
  // short "= 100mm" value-only line (dimensionLine's scriptPrefix
  // branch is Arabic-only — see that option's own header), so
  // rightGutterX grows well past +95px whenever both an English render
  // AND blinding are present, and the blinding label's own text (which
  // extends LEFTWARD from rightGutterX by its own width) swept directly
  // into "Founding Level" — confirmed by rendering the English
  // full-extras case to PNG specifically (this had only ever been
  // checked in Arabic before, where the short value-only line never
  // reached far enough to collide). The call is DEFERRED to just after
  // rightGutterX is computed (same visual result — SVG paint order does
  // not affect two non-overlapping-by-position elements like this one
  // and the column/dowel/tie group drawn in between) rather than moving
  // rightGutterX's whole computation block earlier, to keep this a
  // small, isolated relocation instead of restructuring an
  // already-verified block.

  // [Step 14.3] Column/pedestal stack rising from the footing top.
  // Default (no pedestal): a single decorative stub, exactly as before
  // Step 14 in the common case — it was never drawn to scale (this
  // module is never given a real column height), just a "the column
  // continues here" cue. When a pedestal IS supplied, its width/height
  // are real user inputs and ARE drawn to this section's real `scale`,
  // with a short decorative stub above it so the stack still reads as
  // "column continues out of the pedestal" — see خطة_تجزئة_الخطوة_14.md
  // ("دمج البرمة مع رسم العمود المستمر"). Known, documented limitation:
  // PLAN_BOX/SECTION_BOX are fixed screen regions, not re-fitted around
  // pedestal height, so a pedestal tall relative to `scale` can visually
  // approach the plan view above — the same "representative, not a
  // layout solver" limitation this file already accepted for the fixed
  // stub, now reachable by a much wider range of real inputs.
  //
  // [This session] stubH additionally clears whichever of the dowel
  // leg's real height (dowels.projectionMM, measured from topY — a
  // dowel pierces the pedestal on its way from footing to column, so
  // its own reference point never moves) or the tie stack's real extent
  // (ties.offsetsMM's last entry, measured from tieRefY — ties confine
  // the COLUMN, so their reference point is pedTop, not topY, when a
  // pedestal exists) is tallest, so neither is ever silently clipped by
  // the old fixed-stub assumption. STUB_MARGIN_PX keeps a leg/tie ending
  // exactly at the stub's own top edge from reading as truncated.
  const dowelLegPx = geometry.dowels ? geometry.dowels.projectionMM * scale : 0;
  const tieExtentPx = geometry.ties ? geometry.ties.offsetsMM[geometry.ties.offsetsMM.length - 1] * scale : 0;
  const STUB_MARGIN_PX = 15;
  // [This session] columnBars deliberately contributes NO term of its
  // own to either stubH Math.max() below — see BREAK_SYMBOL_MARGIN_PX's
  // own comment above for why growing the stub specifically for
  // columnBars turned out to risk crowding the plan view on a realistic
  // input. columnBars is drawn entirely within the headroom the dowel
  // term already reserves (dowelLegPx + STUB_MARGIN_PX), which is
  // always present whenever columnBars is (computeFootingExtras
  // requires dowels alongside it).

  const colW = section.colWidthMM * scale;
  const colX = originX + wPx / 2 - colW / 2;
  let colTop, dowelHostXPx, tieRefY;
  if (geometry.pedestal) {
    const pedWPx = geometry.pedestal.widthMM * scale;
    const pedHPx = geometry.pedestal.heightMM * scale;
    const pedX = originX + wPx / 2 - pedWPx / 2;
    const pedTop = topY - pedHPx;
    svg += `<rect x="${pedX}" y="${pedTop}" width="${pedWPx}" height="${pedHPx}" class="column-outline" fill="url(#concreteHatch)"/>`;
    const stubH = Math.max(40, dowelLegPx - pedHPx + STUB_MARGIN_PX, tieExtentPx + STUB_MARGIN_PX);
    colTop = pedTop - stubH;
    svg += `<rect x="${colX}" y="${colTop}" width="${colW}" height="${pedTop - colTop}" class="column-outline" fill="url(#concreteHatch)"/>`;
    dowelHostXPx = pedX;
    tieRefY = pedTop;
  } else {
    const stubH = Math.max(90, dowelLegPx + STUB_MARGIN_PX, tieExtentPx + STUB_MARGIN_PX);
    colTop = topY - stubH;
    svg += `<rect x="${colX}" y="${colTop}" width="${colW}" height="${topY - colTop}" class="column-outline" fill="url(#concreteHatch)"/>`;
    dowelHostXPx = colX;
    tieRefY = topY;
  }

  // [This session] Column ties (كانات العمود) — one 3-segment tick per
  // offset in geometry.ties.offsetsMM, spanning the COLUMN's own width
  // (not the pedestal's — the guide figure itself draws the pedestal as
  // the enlarged, separately-detailed base, distinct from the column's
  // own confinement steel), starting at tieRefY and marching up into the
  // column. Drawn via the shared kit's tieTickH() (opts shape) as of
  // this pass's integration merge — see that function's own comment
  // above this block's former local copy for the verification trail.
  // [Bugfix, this session — reviewer feedback] Was tieTick(colX, colX +
  // colW, y) — the tie drawn from the OUTER CONCRETE FACE on one side to
  // the outer concrete face on the other. A real tie wraps the column's
  // own longitudinal bars, not the concrete surface — it sits just
  // outside the bar cage, itself covered by concrete, so its legs must
  // stop at the bars' own X positions, not run all the way to the
  // column face. Uses the SAME centersMM/dowelHostXPx geometry.dowels
  // already provides (the column's outermost longitudinal bars are, by
  // construction here, the outermost dowels — see computeFootingExtras'
  // own columnBars comment on why the two positions are never allowed
  // to disagree). computeFootingExtras validates ties independently of
  // dowels, so a ties-without-dowels combination is possible even though
  // it is not the common case this file's own guide-figure reference
  // uses; the cover-based inset below is the fallback for exactly that
  // combination — the best available proxy for "just inside the main
  // bars" without a bar-position input to reference, not a fabricated
  // constant.
  let tieLeftX, tieRightX;
  if (geometry.dowels && geometry.dowels.centersMM.length >= 2) {
    const xs = geometry.dowels.centersMM.map((cMM) => dowelHostXPx + cMM * scale);
    tieLeftX = Math.min(...xs);
    tieRightX = Math.max(...xs);
  } else {
    const insetPx = section.coverMM * scale;
    tieLeftX = colX + insetPx;
    tieRightX = colX + colW - insetPx;
  }
  if (geometry.ties) {
    for (const offMM of geometry.ties.offsetsMM) {
      const y = tieRefY - offMM * scale;
      svg += tieTickH(tieLeftX, tieRightX, y, { capPx: 5, cssClass: 'tie-tick' });
    }
  }

  // [Step 14.3, extended this session] Dowels: a representative row of
  // circles at the footing-top interface (topY), as before — PLUS (new)
  // an actual bent-bar leg per dowel: a vertical run from the bottom bar
  // layer (barY) up to topY - dowels.projectionMM (the real lap zone
  // inside the column/pedestal), with a short hooked foot at the bottom
  // bending away from the section's own centerline — same hook-direction
  // convention genSectionIsolated's own gDowels() already uses on the
  // generic (no-numbers) path below, reused here so the two paths read
  // as the same family of drawing. Previously dowels.projectionMM was
  // computed and reported in the Step 14.3 summary table but never
  // actually drawn as geometry — a bare row of circles with no visible
  // bar above or below them. dowels.centersMM are relative to the DOWEL
  // HOST's own width envelope (computeDowelGeometry), so they map onto
  // dowelHostXPx here — NOT onto originX/wPx, the full footing width,
  // which would misplace every bar when a pedestal narrower than the
  // footing exists (unchanged reasoning from before this session). The
  // hook foot's length is a fixed illustrative convention
  // (DOWEL_HOOK_FOOT_FACTOR), never labeled with a number — see that
  // constant's own header comment.
  // [Bugfix, this session round 4 — reviewer feedback] "ازل هذه الاسياخ
  // الدائري... فلا معنى لها" — this loop used to also draw
  // barDot(cx, topY, ..., 'dowel') for each dowel: a filled circle at
  // the footing/column interface. Every dowel is ALREADY drawn as one
  // continuous path (hook foot -> barY -> dowelLegTopY, immediately
  // below) that passes straight through topY on its way up — topY is
  // not where the bar starts, ends, or changes anything, just a point
  // partway along a line already fully drawn. Unlike the bottom bar-dot
  // row (a real cross-section: those bars run PERPENDICULAR to this
  // cut, so a circle there depicts an actual cut face), a dowel runs
  // PARALLEL to this cut — we see it in elevation, not cross-section —
  // so a circle on top of its own already-visible line adds no
  // information. Removed outright, not repositioned: there is no
  // Y-coordinate where this mark WOULD mean something.
  if (geometry.dowels) {
    const dowelLegTopY = topY - geometry.dowels.projectionMM * scale;
    const hookFootPx = DOWEL_HOOK_FOOT_FACTOR * geometry.dowels.diaMM * scale;
    for (const cMM of geometry.dowels.centersMM) {
      const cx = dowelHostXPx + cMM * scale;
      const hookDir = cx < sectionMidX ? -1 : 1;
      svg += `<path d="M${(cx + hookDir * hookFootPx).toFixed(2)},${barY.toFixed(2)} L${cx.toFixed(2)},${barY.toFixed(2)} L${cx.toFixed(2)},${dowelLegTopY.toFixed(2)}" class="dowel-bar"/>`;
    }
    // One shared lap-length callout for the whole group (every dowel in
    // it shares the same projectionMM) — anchored just left of the
    // column, clear of the D=/B=/cover= callouts already on this view.
    // This is the drawn, dimensioned counterpart of the Step 14.3
    // summary table's existing dowelProjection column — same number,
    // now also shown directly on the geometry it describes.
    svg += dimensionLine(
      colX - 24, topY, colX - 24, dowelLegTopY,
      lang === 'ar' ? `= ${fmt(geometry.dowels.projectionMM, geometry.unit, 0)}` : `${translate('dowelLapLength', lang)} = ${fmt(geometry.dowels.projectionMM, geometry.unit, 0)}`,
      { orientation: 'v', scriptPrefix: lang === 'ar' ? translate('dowelLapLength', lang) : undefined },
    );

    // [This session — column main bars / break symbol] The guide
    // figure's own "١٦Φ" callout: the column's CONTINUING main
    // longitudinal bars, straight (no hook — a hook belongs to the
    // dowel's own bottom anchorage, already drawn above, not to a bar
    // that keeps running), rising from the SAME dowel bend point
    // (dowelLegTopY) up to a break symbol near the stub's own top edge.
    // computeFootingExtras already guarantees geometry.dowels exists
    // whenever geometry.columnBars does, so reusing dowels.centersMM/
    // dowelHostXPx here (rather than recomputing an independent
    // position set) is always safe, not an unchecked assumption.
    if (geometry.columnBars) {
      const breakY = colTop + BREAK_SYMBOL_MARGIN_PX;
      for (const cMM of geometry.dowels.centersMM) {
        const cx = dowelHostXPx + cMM * scale;
        svg += `<line x1="${cx.toFixed(2)}" y1="${dowelLegTopY.toFixed(2)}" x2="${cx.toFixed(2)}" y2="${breakY.toFixed(2)}" class="dowel-bar"/>`;
      }
      svg += breakSymbol(sectionMidX, breakY, colW * 0.3);
      svg += `<text x="${sectionMidX}" y="${(breakY - 10).toFixed(2)}" text-anchor="middle" class="dim-label">${geometry.dowels.count} \u00d8${fmt(geometry.columnBars.diaMM, geometry.unit, 0)}</text>`;
    }
  }

  // Bottom reinforcement layer: representative Family-B line + Family-A
  // bar circles at their true spacing/positions. (barY is now computed
  // at this function's own top — see that declaration's comment.)
  const rPx = Math.max(MIN_BAR_PX_R, (section.diaMM / 2) * scale);
  // [Round 10, reverted this session] A single continuous line with a
  // hook at both ends was briefly split into two separate L-shaped runs
  // meeting near center — that was a misapplied fix: the feedback it was
  // based on described PLAN-VIEW bar distribution (renderPlanView, see
  // that function's own round 7-9 comments), not this section-view line.
  // Restored to the original single run, byte-for-byte the same as
  // before round 10 (originX+8 to originX+wPx-8, no gap, no split).
  svg += `<line x1="${originX + 8}" y1="${barY}" x2="${originX + wPx - 8}" y2="${barY}" class="mesh-line"/>`;
  // [Bugfix, this session — reviewer feedback round 2, replaces round 1's
  // illustrative hook] "الأرجل تمتد لأعلى حتى منسوب الخرسانة المسلحة
  // العلوي مطروح منه الكفر الخرساني" — round 1 drew a short, fixed-length
  // illustrative tick (DOWEL_HOOK_FOOT_FACTOR x dia, the same convention
  // used for the UNRELATED dowel hook). That was wrong in kind, not just
  // degree: this leg's height is not illustrative at all — it is a real,
  // fully-determined quantity, the clear run between the bottom bar level
  // and the top face minus its own cover, same idea as barY's own offset
  // from the BOTTOM face, mirrored at the top. legTopY replaces the old
  // capped bottomHookLegPx entirely. Math.min guards only the pathological
  // case (D too shallow for cover top AND bottom to both fit) from
  // inverting the line — not a stylistic cap, a last-resort guard.
  const legTopY = Math.min(topY + coverPx, barY - 4);
  // [Bugfix, this session — reviewer feedback round 2] "دوائر التسليح
  // العرضي مازالت مرسومة على سنترلاين الخط، والمفروض ترحل بقيمة القطر
  // على 2 لأعلى وللجوانب للداخل" — the circles (bars running PERPENDICULAR
  // to this cut, i.e. cut cross-section) and the two L-shaped runs above
  // (the bar running PARALLEL to this cut) are two DIFFERENT physical
  // bars that cross and stack, not one bar drawn twice. The line's layer
  // sits first (lower, at barY, touching the chairs); the circles' layer
  // sits on top of it, so its centers belong one (rendered) radius higher
  // — dotY, not barY. The two EDGE circles additionally shift inward by
  // that same radius: their unshifted X exactly coincides with the
  // line-layer's own hook-leg X (both come from the same barCentersMM
  // entry), and since the two are now different bars stacked rather than
  // one bar drawn once, they should not sit exactly on top of one
  // another at the edge either. Interior circles keep their X — only the
  // vertical (all circles) and the edge horizontal (first/last only)
  // shifts are asked for.
  const dotY = barY - rPx;
  const lastBarIdx = section.barCentersMM.length - 1;
  const edgeIndices = new Set([0, lastBarIdx]);
  section.barCentersMM.forEach((cMM, i) => {
    const lineX = originX + cMM * scale; // the longitudinal/line layer's own X — unshifted
    if (edgeIndices.has(i)) {
      svg += `<line x1="${lineX.toFixed(2)}" y1="${barY.toFixed(2)}" x2="${lineX.toFixed(2)}" y2="${legTopY.toFixed(2)}" class="mesh-line"/>`;
    }
    let dotX = lineX;
    if (i === 0) dotX += rPx;
    else if (i === lastBarIdx) dotX -= rPx;
    svg += `<circle cx="${dotX.toFixed(2)}" cy="${dotY.toFixed(2)}" r="${rPx}" class="bar-dot"/>`;
  });

  // [Step 14.3] Independent top mesh layer (interpretation A resolved in
  // خطة_تجزئة_الخطوة_14.md's "سؤال مفتوح" — see computeMeshLayer's own
  // header). Reuses the existing bottom layer's .mesh-line/.bar-dot
  // classes rather than inventing a second color convention this file
  // has never needed before; distinguished from the bottom layer by
  // POSITION (inset from the footing's TOP face by the same cover) not
  // by color.
  if (geometry.mesh) {
    const meshY = topY + section.coverMM * scale;
    svg += `<line x1="${originX + 8}" y1="${meshY}" x2="${originX + wPx - 8}" y2="${meshY}" class="mesh-line"/>`;
    const rPxMesh = Math.max(MIN_BAR_PX_R, (geometry.mesh.diaMM / 2) * scale);
    for (const cMM of geometry.mesh.barCentersMM) {
      svg += `<circle cx="${originX + cMM * scale}" cy="${meshY}" r="${rPxMesh}" class="bar-dot"/>`;
    }
  }

  // Dimensions: depth, [blinding thickness], width, cover, bar spec.
  // The depth (D) and blinding-thickness dimension lines share one
  // vertical offset (wPx+40) and chain end-to-end at baseY — standard
  // stacked-dimension drafting convention, and exactly how this pair
  // degenerates to just "D" alone (unchanged from before this session)
  // when geometry.blinding is absent.
  // [Bugfix, this session] Root cause (found by rendering several real
  // combinations to PNG, not by reading the coordinate math alone): the
  // D/blinding-thickness dimension labels sit at a FIXED x1=originX+wPx+40
  // gutter with text-anchor="end" (dimensionLine's own default for a 'v'
  // line grows the label LEFTWARD from x1, back toward the section), while
  // the cover/N-Ø-@-spacing labels just below sit CENTERED at midX. On a
  // small or near-square footing (small wPx at this render's scale) the
  // horizontal gap between midX and that gutter shrinks to less than
  // either label's own rendered width, so the two independently-positioned
  // groups draw on top of each other regardless of which Y each picks —
  // no labelT value fixes a collision whose real cause is horizontal, not
  // vertical. rightGutterPx below is the actual fix: it grows the gutter
  // offset (beyond the pre-existing, now-baseline 40) whenever the
  // centered labels' own estimated half-width would otherwise reach past
  // it, using estimateTextWidthPx's character-count estimate (this file's
  // established no-real-font-metrics convention, see that function's own
  // header) — byte-identical to the old fixed 40px offset whenever the
  // footing is wide enough that the two groups were never going to
  // collide in the first place.
  // [Bugfix, this session, corrected] The first version of this fix
  // (see the version-control history for this file) sized rightGutterPx
  // only against how far the CENTERED cover/bar-spec text reaches
  // rightward — and missed that the gutter label itself (text-anchor
  // "end" at rightGutterX-10) then reads back LEFTWARD by its own full
  // width, which can be ~120px for "D = 500.00mm" alone. That version
  // still collided (confirmed by re-rendering, not assumed) whenever the
  // gutter label's own width exceeded the small margin the first
  // version left. dLabelStr/blindingLabelStr below are the ACTUAL
  // strings that will be drawn at that gutter (not a separately-guessed
  // constant), so gutterLabelFullWidthPx tracks whatever they really
  // say — including the longer English combined "Blinding Thickness = ...mm"
  // form, not just Arabic's shorter "= ...mm" value-only line.
  const coverStr = `cover = ${fmt(section.coverMM, geometry.unit, 0)}`;
  const barSpecStr = `${section.barCount} \u00d8${fmt(section.diaMM, geometry.unit, 0)} @ ${fmt(section.actualSpacingMM, geometry.unit, 0)}`;
  const centeredHalfWidthPx = Math.max(estimateTextWidthPx(coverStr), estimateTextWidthPx(barSpecStr)) / 2;
  const dLabelStr = `D = ${fmt(section.depthMM, geometry.unit, 2)}`;
  const blindingLabelStr = geometry.blinding
    ? (lang === 'ar' ? `= ${fmt(geometry.blinding.thicknessMM, geometry.unit, 0)}` : `${translate('blindingThickness', lang)} = ${fmt(geometry.blinding.thicknessMM, geometry.unit, 0)}`)
    : '';
  const gutterLabelFullWidthPx = Math.max(estimateTextWidthPx(dLabelStr), estimateTextWidthPx(blindingLabelStr));
  const GUTTER_CLEARANCE_PX = 15;
  // Solves for the gutter offset that keeps [gutter label's own left
  // edge] >= [centered text's own right edge] + margin — see this
  // block's own comment above for the inequality this reduces from.
  // BUGFIX [SECTION-GUTTER-FOOTING-CLEARANCE]: this formula's clearance
  // reference was centeredHalfWidthPx alone -- the cover/bar-spec labels'
  // own half-width, NOT the footing rectangle's own half-width (wPx/2).
  // Whenever the footing is wider than those labels (centeredHalfWidthPx
  // < wPx/2 -- true for this file's own 1800mm running example: cover/
  // bar-spec text half-width ~79px vs a ~119px half-width footing), the
  // old `centeredHalfWidthPx + ... - wPx/2` arithmetic went NEGATIVE on
  // that term, silently discounting clearance the FOOTING OUTLINE itself
  // still needs regardless of how narrow the centered text is. Invisible
  // in English only because gutterLabelFullWidthPx (sized off the long
  // "Blinding Thickness = 100mm" form) happens to overshoot the resulting
  // gap anyway; exposed in Arabic, where the translated blinding label
  // ("= 100mm" -- value only, see blindingLabelStr's own lang branch
  // above) is short enough that it no longer papers over the deficit, so
  // the D-label's own left edge lands inside the footing outline (found
  // by rendering isolatedFooting_demo_ar.svg to PNG and comparing against
  // the English render side by side, not by reading the coordinate math
  // alone -- see this function's own established convention for how
  // every OTHER fix in this block was found). Math.max(wPx / 2, ...)
  // makes the footing's own half-width a hard floor the formula can no
  // longer discount below, independent of centeredHalfWidthPx.
  const rightGutterPx = Math.max(40, Math.max(wPx / 2, centeredHalfWidthPx) + gutterLabelFullWidthPx + GUTTER_CLEARANCE_PX + 10 - wPx / 2);
  const rightGutterX = originX + wPx + rightGutterPx;
  // foundingLevelX must clear the blinding/D label's own right edge
  // (rightGutterX - 10, per dimensionLine's labelDx=-10 for a 'v' line)
  // by at least the level marker's own tick-to-label gap (halfLine+6=21,
  // inlined in levelMarker above) plus a small safety margin — 20px
  // here is deliberately more than the bare minimum, not a tight fit.
  const foundingLevelX = Math.max(originX + wPx + 95, rightGutterX + 20);
  svg += levelMarker(foundingLevelX, soilTopY, translate('foundingLevel', lang), lang, 'right');

  svg += dimensionLine(rightGutterX, topY, rightGutterX, baseY, dLabelStr, { orientation: 'v' });
  if (geometry.blinding) {
    svg += dimensionLine(
      rightGutterX, baseY, rightGutterX, soilTopY, blindingLabelStr,
      { orientation: 'v', scriptPrefix: lang === 'ar' ? translate('blindingThickness', lang) : undefined, labelT: 0.5 },
    );
  }
  svg += dimensionLine(originX, soilTopY + 46, originX + wPx, soilTopY + 46, `${section.widthMM === geometry.meta.B ? 'B' : geometry.plan.shortLabel} = ${fmt(section.widthMM, geometry.unit, 2)}`, { orientation: 'h' });
  // Stacked on two centered lines, not left/right on one line — at
  // narrow widths (e.g. B=1200mm) same-line opposite-anchored labels
  // collide in the middle; found by rendering Case 2 in the test suite
  // and inspecting the PNG, not by inspection of the code alone.
  // [Bugfix, this session] -34/-16 (was -26/-10) — a small additional
  // margin above barY so this block's lower line keeps clear of the
  // blinding-thickness label now centered in its own band just below
  // baseY (labelT: 0.5 above) instead of pinned against it. coverStr/
  // barSpecStr are the SAME variables rightGutterPx was already sized
  // against above, not independently re-typed strings that could drift
  // out of sync with what that clearance calculation actually measured.
  const midX = originX + wPx / 2;
  svg += `<text x="${midX}" y="${barY - 34}" text-anchor="middle" class="dim-label">${esc(coverStr)}</text>`;
  svg += `<text x="${midX}" y="${barY - 16}" text-anchor="middle" class="dim-label">${esc(barSpecStr)}</text>`;

  const titleText = translatedSectionTitle(
    geometry.type,
    NUMBERED_COLUMN_TYPES.has(geometry.type) ? geometry.sectionThrough - 1 : null,
    lang,
  );
  svg += `<text x="${originX + wPx / 2}" y="${soilTopY + 70}" text-anchor="middle" dir="${lang === 'ar' ? 'rtl' : 'ltr'}" class="view-title">${esc(titleText)}</text>`;
  svg += `</g>`;
  return svg;
}

// opts.lang: 'ar' | 'en', default 'ar'
// Top-level assembly for the COMPUTED (real-numbers) path: picks one
// shared scale that fits both the plan and section boxes simultaneously
// (so the two views read as one consistent drawing, not two independently
// scaled ones), builds the optional Step-14.3 pedestal/dowel/mesh summary
// table + caption when any of those three were supplied, and concatenates
// title + plan + section + table + caption into one <svg>. The hasExtras
// branch is written so the no-extras path reduces to exactly the pre-
// Step-14 output byte-for-byte — see its own inline comment for why that
// mattered more than a cleaner unconditional code path would have.
export function renderFootingDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'en' ? 'en' : 'ar';
  // Some renderers resolve a CSS font-family list by matching only the
  // first token and never fall back to later entries for missing glyphs
  // (confirmed against cairosvg while testing this module). That cuts
  // both ways: an Arial-first stack drew Arabic title text as tofu; a
  // naive fix — putting 'Noto Naskh Arabic' first for the WHOLE drawing
  // — would break the Latin dimension labels (B=, cover=, mm, Ø, bar
  // counts) instead, because that font doesn't carry a full Latin
  // alphabet and nothing falls back for the missing glyphs. The fix is
  // per-element, not global: pure engineering notation (B=, L=, D=,
  // cover=, mm, ⌀, bar counts) is Latin+digits by international
  // drafting convention regardless of `lang` and always uses
  // defaultFontStack. Product-identity / label strings — sheet title,
  // caption, PLAN/SECTION view titles, column tags, cut-line letters —
  // come from structuralLabels.mjs and DO localize as of Step 4
  // (previously only .sheet-title/.sheet-caption did; view-title/
  // col-tag/cut-label leaked raw English/internal identifiers under
  // Arabic — see structuralLabels.mjs's own header and Step 0's
  // findings). Those classes get scriptFontStack, and only when this
  // render is actually Arabic — never the blanket global change that
  // caused the original tofu bug.
  const defaultFontStack = `Arial, Tahoma, 'Noto Sans Arabic', 'Noto Naskh Arabic', sans-serif`;
  const scriptFontStack = lang === 'ar'
    ? `'Noto Naskh Arabic', 'Noto Sans Arabic', Tahoma, Arial, sans-serif`
    : defaultFontStack;
  const scale = Math.min(
    PLAN_BOX.w / geometry.plan.longMM,
    PLAN_BOX.h / geometry.plan.shortMM,
    SECTION_BOX.w / geometry.section.widthMM,
    (SECTION_BOX.h - 60) / geometry.section.depthMM,
  ) * 0.85;

  const caption = translate('captionComputed', lang);
  const title = footingTitle(geometry.type, lang);

  // [Step 14.3] Workshop table + dynamic canvas height, ONLY when the
  // caller supplied at least one of pedestal/dowels/mesh. With none of
  // the three, canvasH/tableSvg/captionBottomY below reduce to exactly
  // CANVAS.h / '' / CANVAS.h-20 — the pre-Step-14 output, unchanged
  // pixel-for-pixel. This conditional-only-when-needed approach is the
  // backward-compatibility strategy خطة_تجزئة_الخطوة_14.md's point 5
  // calls for (no existing test pins an exact viewBox number, so this
  // is safe, but keeping the no-extras path byte-identical removes any
  // risk of an untested silent visual regression on the common case).
  // [This session] blinding joins pedestal in the OR-chain despite
  // neither having its own dedicated table column below (blinding's
  // thickness/projection are already dimensioned twice on-drawing — once
  // in each view — so a third, textual repetition in the table would be
  // pure redundancy; pedestal already set this exact precedent pre-this-
  // session). ties DOES get dedicated columns just below: unlike
  // blinding, a tie tick mark carries no on-drawing number at all, so
  // without a table entry its dia/spacing/count would not appear as text
  // anywhere on the sheet.
  const hasExtras = !!(geometry.pedestal || geometry.dowels || geometry.mesh || geometry.blinding || geometry.ties);
  let canvasH = CANVAS.h;
  let canvasWidth = CANVAS.w;
  let tableSvg = '';
  let captionBottomY = CANVAS.h - 20;

  if (hasExtras) {
    const unit = geometry.unit;
    const volumeM3 = (geometry.meta.B / 1000) * (geometry.meta.L / 1000) * (geometry.meta.D / 1000);
    // [Step 14.2 decision — see structuralLabels.mjs's own header] ONE
    // summary row, one dedicated column per optional field, blank cell
    // ('—') when that field's group is absent — not a multi-row
    // schedule like beamDiagram.mjs's bar list. Decided during 14.2
    // specifically so this session would not have to re-litigate table
    // shape.
    const cols = [
      { key: 'dowelCount', label: translate('dowelCount', lang), width: 120 },
      { key: 'dowelDia', label: translate('dowelDia', lang), width: 110 },
      { key: 'dowelProjection', label: translate('dowelProjection', lang), width: 150 },
      { key: 'meshDia', label: translate('meshDia', lang), width: 110 },
      { key: 'meshSpacing', label: translate('meshSpacing', lang), width: 140 },
      // [This session] Same one-column-per-field convention, extended to
      // ties. Placed after mesh/before concreteVolume — concreteVolume
      // stays last since it is always populated (unconditional), same
      // position it already held.
      { key: 'tieCount', label: translate('tieCount', lang), width: 100 },
      { key: 'tieDia', label: translate('tieDia', lang), width: 90 },
      { key: 'tieSpacing', label: translate('tieSpacing', lang), width: 120 },
      { key: 'concreteVolume', label: translate('concreteVolume', lang), width: 250 },
    ];
    // Engineering notation (Ø, mm-derived numbers, m³) is Latin+digits
    // by convention regardless of `lang` (same rule this file already
    // applies to B=/D=/cover=) — no column here sets script:true, so
    // scheduleTable() renders every data cell with .table-text
    // (defaultFontStack), only the translated HEADER labels get
    // .table-header-txt (scriptFontStack).
    const row = {
      dowelCount: geometry.dowels ? String(geometry.dowels.count) : '\u2014',
      dowelDia: geometry.dowels ? `\u00d8${fmt(geometry.dowels.diaMM, unit, 0)}` : '\u2014',
      dowelProjection: geometry.dowels ? fmt(geometry.dowels.projectionMM, unit, 0) : '\u2014',
      meshDia: geometry.mesh ? `\u00d8${fmt(geometry.mesh.diaMM, unit, 0)}` : '\u2014',
      meshSpacing: geometry.mesh ? fmt(geometry.mesh.actualSpacingMM, unit, 0) : '\u2014',
      tieCount: geometry.ties ? String(geometry.ties.count) : '\u2014',
      tieDia: geometry.ties ? `\u00d8${fmt(geometry.ties.diaMM, unit, 0)}` : '\u2014',
      tieSpacing: geometry.ties ? fmt(geometry.ties.spacingMM, unit, 0) : '\u2014',
      concreteVolume: `${volumeM3.toFixed(2)} m\u00b3`,
    };
    const totalW = cols.reduce((s, c) => s + c.width, 0);
    // [This session] The pre-existing 6-column table (totalW=880) was
    // already sized to fit CANVAS.w=960 with an 80px margin exactly —
    // Math.max below reduces to precisely 960 in that case (0 change).
    // The 3 new tie columns can push totalW past 960; when they do, the
    // CANVAS.w CONSTANT is left untouched (PLAN_BOX/SECTION_BOX still
    // reference it, unaffected) but this render's own local canvasWidth
    // grows to keep the table centered and unclipped. Known cosmetic
    // consequence, not fixed here: the two views stay anchored at their
    // existing fixed x/w, so a wide-canvas render leaves visible margin
    // to their right rather than re-centering them too — the same class
    // of "fixed screen regions, not a layout solver" limitation this
    // file already accepts for a tall pedestal (see renderSectionView's
    // own comment on that).
    canvasWidth = Math.max(CANVAS.w, totalW + 80);
    const tableX = (canvasWidth - totalW) / 2;
    const tableY = SECTION_BOX.y + SECTION_BOX.h + 40;
    const table = scheduleTable(tableX, tableY, cols, [row], { lang });
    tableSvg = `
  <line x1="${PLAN_BOX.x}" y1="${tableY - 20}" x2="${PLAN_BOX.x + PLAN_BOX.w}" y2="${tableY - 20}" stroke="#ccc" stroke-width="1"/>
  ${table.svg}`;
    // [Step 14.3 bug fix — found by rendering the actual SVG and
    // measuring pixel positions, not by the test suite: every check was
    // green while this still overlapped] The FIRST caption line's Y must
    // be pinned a fixed margin below the table's bottom edge, the same
    // for every language. Anchoring the LAST line at a numLines-
    // independent Y (the original approach here) lets a longer caption
    // (English wraps to more lines than Arabic for this text) push its
    // FIRST line upward past that anchor and into the table — exactly
    // what happened: en wrapped to 4 lines vs ar's 3, and the 4-line
    // case collided with the table by 8px even though every existing
    // check stayed green (nothing here checks pixel-level visual
    // overlap). Computing the bottom anchor FROM numLines instead keeps
    // the first line's Y constant regardless of line count.
    {
      const tableBottom = tableY + table.height;
      const capMarginPx = 24;
      const numLines = wrapText(caption, 100).length;
      captionBottomY = tableBottom + capMarginPx + (numLines - 1) * 16;
    }
    canvasH = captionBottomY + 20;
  }

  // [Step 14.3] .bar-dot-dowel / .table-* below are copied verbatim from
  // structuralDrawingKit.mjs's kitStyleBlock() — this file's own <style>
  // stays local rather than switching to kitStyleBlock wholesale (see
  // خطة_تجزئة_الخطوة_14.md point 4: .view-title's letter-spacing differs
  // between the two, and 99 existing checks regex the literal style
  // block), but these six classes did not exist locally before
  // barDot()/scheduleTable() needed them and are harmless to always
  // emit (unused when hasExtras is false, since nothing references
  // them).
  // [This session] Four more classes join the six documented above, same
  // "harmless to always emit, unused when the corresponding group is
  // absent" reasoning: .blinding-outline / .tie-tick / .dowel-bar are new
  // geometry, and .dim-label-script is the scriptFontStack twin of
  // .dim-label (see dimensionLine's own opts.script comment for why a
  // second class rather than a conditional font-family on the existing
  // one — every pre-existing .dim-label caller must keep resolving to
  // defaultFontStack unconditionally).
  return `<svg viewBox="0 0 ${canvasWidth} ${canvasH}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>
    text { font-family: ${defaultFontStack}; }
    .footing-outline { fill:${PC_FILL}; stroke:#1a1a1a; stroke-width:${MIN_STROKE_PX * 1.4}; }
    .column-outline  { fill:${PC_FILL}; stroke:#1a1a1a; stroke-width:${MIN_STROKE_PX * 1.4}; }
    .mesh-line       { stroke:${REBAR_MAIN}; stroke-width:${MIN_STROKE_PX * 1.6}; stroke-linecap:round; }
    .bar-dot         { fill:${REBAR_SECONDARY}; stroke:${REBAR_MAIN_STROKE}; stroke-width:0.6; }
    .dim-line        { stroke:#333; stroke-width:1; }
    .dim-tick        { stroke:#333; stroke-width:1; }
    .dim-label       { font-size:15px; fill:#111; }
    .dim-label-script{ font-size:15px; fill:#111; font-family: ${scriptFontStack}; }
    .view-title      { font-size:16px; font-weight:bold; fill:#111; letter-spacing:${lang === 'ar' ? 'normal' : '1px'}; font-family: ${scriptFontStack}; }
    .cut-line        { stroke:#1a1a1a; stroke-width:1.4; stroke-dasharray:6,3; }
    .cut-label       { font-size:14px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .col-tag         { font-size:12px; fill:#333; font-family: ${scriptFontStack}; }
    .sheet-title     { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .sheet-caption   { font-size:12.5px; fill:#444; font-family: ${scriptFontStack}; }
    .bar-dot-dowel    { fill:${REBAR_MAIN}; stroke:${REBAR_MAIN_STROKE}; stroke-width:0.6; }
    .dowel-bar        { fill:none; stroke:${REBAR_MAIN}; stroke-width:${MIN_STROKE_PX * 1.6}; stroke-linecap:round; stroke-linejoin:round; }
    .tie-tick         { stroke:${REBAR_SECONDARY}; stroke-width:${MIN_STROKE_PX * 1.4}; }
    .blinding-outline { stroke:#6b6f73; stroke-width:${MIN_STROKE_PX}; stroke-dasharray:3,2; }
    .level-marker     { fill:${LEVEL_MARKER}; stroke:${LEVEL_MARKER_STROKE}; stroke-width:0.8; }
    .level-line       { stroke:#1a1a1a; stroke-width:1; }
    .centerline       { stroke:${CENTERLINE_COLOR}; stroke-width:1; stroke-dasharray:10,4,2,4; }
    .centerline-dot   { fill:${CANVAS_BG}; stroke:${CENTERLINE_COLOR}; stroke-width:1.2; }
    .table-header-bg  { fill:#eef1f4; }
    .table-border     { stroke:#888; stroke-width:1; fill:none; }
    .table-text       { font-size:12px; fill:#111; font-family: ${defaultFontStack}; }
    .table-text-script{ font-size:12px; fill:#111; font-family: ${scriptFontStack}; }
    .table-header-txt { font-size:12px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
  </style>
  <rect x="0" y="0" width="${canvasWidth}" height="${canvasH}" fill="${CANVAS_BG}"/>
  <text x="${canvasWidth / 2}" y="30" text-anchor="middle" class="sheet-title" dir="${lang === 'ar' ? 'rtl' : 'ltr'}">${esc(title)}</text>
  ${renderPlanView(geometry, scale, lang)}
  ${renderSectionView(geometry, scale, lang)}
  <line x1="${PLAN_BOX.x}" y1="${SECTION_BOX.y - 30}" x2="${PLAN_BOX.x + PLAN_BOX.w}" y2="${SECTION_BOX.y - 30}" stroke="#ccc" stroke-width="1"/>${tableSvg}
  ${renderCaption(caption, lang, captionBottomY, canvasWidth)}
</svg>`;
}

// Plain <text> lines, not foreignObject — foreignObject is silently
// dropped by at least one real SVG renderer this module was verified
// against (cairosvg), which would silently drop this caption. <text> is
// universally supported. Wrapping is a simple character-count estimate
// (no real font metrics available at generation time), generous enough
// at this font size/canvas width that it will not truncate, only
// possibly wrap one line earlier than a pixel-exact wrap would.
function wrapText(text, maxCharsPerLine) {
  const words = text.split(' ');
  const lines = [];
  let current = '';
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length > maxCharsPerLine && current) {
      lines.push(current);
      current = word;
    } else {
      current = candidate;
    }
  }
  if (current) lines.push(current);
  return lines;
}

// [Step 14.3] bottomAnchorY made an explicit parameter (defaulting to
// the exact old hardcoded value) so renderFootingDiagramSVG can push the
// caption below the new workshop table when one is drawn, without
// touching the no-extras call path's output at all.
// [This session] canvasWidth is the same idea applied to the RTL x-
// anchor: defaults to the CANVAS.w constant (byte-identical whenever the
// table doesn't need a wider canvas), but lets the caller pass its own
// local canvasWidth when it does.
function renderCaption(caption, lang, bottomAnchorY = CANVAS.h - 20, canvasWidth = CANVAS.w) {
  const lines = wrapText(caption, 100);
  const rtl = lang === 'ar';
  const x = rtl ? canvasWidth - 40 : 40;
  const anchor = rtl ? 'end' : 'start';
  const startY = bottomAnchorY - (lines.length - 1) * 16;
  return lines
    .map((line, i) => `<text x="${x}" y="${startY + i * 16}" text-anchor="${anchor}" dir="${rtl ? 'rtl' : 'ltr'}" class="sheet-caption">${esc(line)}</text>`)
    .join('\n  ');
}

// ── Chat command parser ──────────────────────────────────────────────
// Syntax (ASCII key=value pairs — deliberately not natural-language, so
// there is no NLP ambiguity on the numbers that matter):
//   /diagram isolated B=1800 L=1800 D=500 colB=400 colL=400 cover=50 dia=16 spacing=150 [unit=mm]
//   /diagram combined B=1200 L=4200 D=600 col1b=400 col1l=400 col1off=700 col2b=400 col2l=400 col2off=3500 cover=50 dia=16 spacing=150 [unit=mm]
//   /diagram strip B=900 L=7500 D=450 cols=3 col1b=350 col1l=350 col1off=750 col2b=350 col2l=350 col2off=3750 col3b=350 col3l=350 col3off=6750 cover=50 dia=14 spacing=150 [unit=mm] [sectionthrough=2]
//   /diagram raft B=6000 L=9000 D=500 cols=4 col1b=400 col1l=400 col1offx=1000 col1offy=1000 col2b=400 col2l=400 col2offx=1000 col2offy=5000 col3b=400 col3l=400 col3offx=5000 col3offy=1000 col4b=400 col4l=400 col4offx=5000 col4offy=5000 cover=75 dia=16 spacing=200 [unit=mm] [sectionthrough=1]
// strip/raft additionally require cols=N (2..MAX_COLUMNS) up front, then
// col1.. through colN.. of the fields shown above — colNoff for strip
// (1-D, distance along L), colNoffx/colNoffy for raft (2-D, distance
// along L / along B respectively).
// [This session] Optional, all four types: pedestalwidth=/pedestalheight=,
// dowelcount=/doweldia=/dowelprojection=, meshspacing=/meshdia=,
// blindingthickness=/blindingprojection=, tiedia=/tiespacing=/tiecount=,
// columnbarsdia= (requires dowelcount=/doweldia=/dowelprojection= also
// given — see computeFootingExtras' own BAD_PARAM gate).
// Returns { ok:true, type, geometry } or { ok:false, code, message }.
// Never throws — every DiagramError from the compute*Geometry functions
// is caught and converted to the same { ok:false } shape validateImagePrompt()
// uses elsewhere in this app, so callers have one error shape to handle.
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  // Capture ANY leading token as the candidate type — deliberately not
  // anchored to just isolated|combined|strip|raft — so an unimplemented-
  // but-real type (e.g. "trapezoidal") reaches the UNSUPPORTED_TYPE
  // branch below with a useful message instead of being misreported as
  // unparseable syntax. BAD_SYNTAX is reserved for input with no
  // leading-token/params shape at all.
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    // No leading-token+rest shape at all, OR a rest with no "key=value"
    // structure in it (e.g. free text) — this is not the command syntax,
    // full stop, as opposed to a recognized syntax with an unsupported
    // type keyword. Keeps "not a valid command" from being reported back
    // as if "not" were a real-but-unimplemented diagram type.
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: isolated|combined|strip|raft key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  // [Step 14.1] Builds a {a,b,...} group object from flat kv keys, but
  // returns undefined (the key is OMITTED from rawParams entirely, not
  // set to an object of undefineds) when none of the group's keys were
  // present in the command at all. This is required for backward
  // compatibility: computeFootingExtras() gates each group on
  // `rawParams.pedestal != null` — passing `{width: undefined, height:
  // undefined}` for every old command lacking these keys would make
  // that check true unconditionally and BAD_PARAM every existing
  // /diagram command. Passing SOME-but-not-all keys still correctly
  // reaches computeFootingExtras' own all-or-nothing BAD_PARAM check.
  function optionalGroup(propToFlatKey) {
    const obj = {};
    let any = false;
    for (const [prop, flatKey] of Object.entries(propToFlatKey)) {
      obj[prop] = num(flatKey);
      if (obj[prop] !== undefined) any = true;
    }
    return any ? obj : undefined;
  }

  // Shared by strip/raft: scan col1.., col2.., ... up to kv.cols and
  // assemble the per-column param objects computeStripFootingGeometry/
  // computeRaftFootingGeometry expect as a `columns` array — the flat-kv-
  // to-nested-object step combined's branch already does by hand for
  // exactly col1/col2, generalized here to an arbitrary field list and
  // column count. Throws BAD_PARAM/TOO_MANY_COLUMNS directly; caught by
  // this function's own try/catch below, same as every DiagramError
  // thrown deeper inside the compute*Geometry functions.
  function collectColumns(fields) {
    const n = num('cols');
    if (!Number.isFinite(n) || !Number.isInteger(n) || n < 2) {
      throw new DiagramError('BAD_PARAM', `"cols" must be an integer of at least 2, got ${JSON.stringify(kv.cols)}.`);
    }
    if (n > MAX_COLUMNS) {
      throw new DiagramError('TOO_MANY_COLUMNS', `At most ${MAX_COLUMNS} columns are supported in this schematic, got ${n}.`);
    }
    const columns = [];
    for (let i = 1; i <= n; i++) {
      const col = {};
      for (const f of fields) col[f] = num(`col${i}${f}`);
      columns.push(col);
    }
    return columns;
  }

  // [Step 14.1] Shared across all four types — same flat-key convention
  // (pedestalwidth=, pedestalheight=, dowelcount=, doweldia=,
  // dowelprojection=, meshspacing=, meshdia=) regardless of footing
  // type, same as cover=/dia=/spacing= already are.
  const pedestal = optionalGroup({ width: 'pedestalwidth', height: 'pedestalheight' });
  const dowels = optionalGroup({ count: 'dowelcount', dia: 'doweldia', projection: 'dowelprojection' });
  const meshSpacing = num('meshspacing');
  const meshDia = num('meshdia');
  // [This session] Same flat-key convention, extended to blinding/ties.
  const blinding = optionalGroup({ thickness: 'blindingthickness', projection: 'blindingprojection' });
  const ties = optionalGroup({ dia: 'tiedia', spacing: 'tiespacing', count: 'tiecount' });
  // [This session] Single-field group — optionalGroup() still applies
  // (same "return undefined, not {dia: undefined}, when the one key is
  // absent" behavior computeFootingExtras' `!= null` gate depends on),
  // it is just degenerate with only one entry in propToFlatKey. Shares
  // dowels' own MAX_DOWELS-bounded count/positions (see
  // computeFootingExtras' BAD_PARAM gate requiring dowels alongside
  // this), so there is no columnbarscount flat key to parse here —
  // only the diameter is a genuinely independent input.
  const columnBars = optionalGroup({ dia: 'columnbarsdia' });

  try {
    let geometry;
    if (type === 'isolated') {
      geometry = computeIsolatedFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        colB: num('colb'), colL: num('coll'),
        cover: num('cover'), dia: num('dia'),
        spacing: num('spacing'), spacingLong: num('spacinglong'), spacingShort: num('spacingshort'),
        unit: kv.unit || 'mm',
        pedestal, dowels, meshSpacing, meshDia, blinding, ties, columnBars,
      });
    } else if (type === 'combined') {
      geometry = computeCombinedFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        col1: { b: num('col1b'), l: num('col1l'), off: num('col1off') },
        col2: { b: num('col2b'), l: num('col2l'), off: num('col2off') },
        cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
        sectionThrough: num('sectionthrough') === 2 ? 2 : 1,
        unit: kv.unit || 'mm',
        pedestal, dowels, meshSpacing, meshDia, blinding, ties, columnBars,
      });
    } else if (type === 'strip') {
      const st = num('sectionthrough');
      geometry = computeStripFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        columns: collectColumns(['b', 'l', 'off']),
        cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
        sectionThrough: Number.isFinite(st) ? st : 1,
        unit: kv.unit || 'mm',
        pedestal, dowels, meshSpacing, meshDia, blinding, ties, columnBars,
      });
    } else if (type === 'raft') {
      const st = num('sectionthrough');
      geometry = computeRaftFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        columns: collectColumns(['b', 'l', 'offx', 'offy']),
        cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
        sectionThrough: Number.isFinite(st) ? st : 1,
        unit: kv.unit || 'mm',
        pedestal, dowels, meshSpacing, meshDia, blinding, ties, columnBars,
      });
    } else {
      return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported. Use isolated, combined, strip, or raft.` };
    }
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) {
      return { ok: false, code: err.code, message: err.message };
    }
    throw err; // programmer error (e.g. bad code path) — do not swallow silently
  }
}

// ════════════════════════════════════════════════════════════════════════
// GENERIC (NO-NUMBERS) SCHEMATICS — natural-language /image short-circuit
// ════════════════════════════════════════════════════════════════════════
//
// classifyFootingDiagram / buildFootingDiagramSvg / svgToDataUri —
// referenced by name in this file's own header ("footingDiagram.mjs's
// classifyFootingDiagram() reaches the same call — see its own header
// comment") and in imageGen.mjs's ARABIC_ENGINEERING_GLOSSARY comments,
// and imported by chat.js's mode:'image' handler — but not actually
// defined anywhere in this file before this section. Restored here.
//
// Covers the closed set of structural elements this product's chat
// surface can meaningfully draw WITHOUT numbers: isolated,
// rectangular-combined, trapezoidal-combined, strap — each has one fixed
// topology regardless of the specific project (a combined footing is
// always exactly 2 columns on one centerline), so a generic drawing is
// honestly representative. strip and raft are deliberately NOT drawn
// generically — see the classifyFootingDiagram()/chat.js call site
// comment below for why (column count/layout varies too much between
// real projects for a fixed picture to be honest) — they're still
// classified, just routed to a "use /diagram" response instead of a
// guessed picture.
//
// Every dimension is a SYMBOL (L, B, D — a letter, never a digit) for the
// same reason renderFootingDiagramSVG() above never fabricates a number
// it wasn't given: this path has no real numbers to be honest WITH. A
// silently-defaulted "B = 1200mm" here would be the same failure
// imageGen.mjs's PROMPT ITERATION 2 comment describes for the diffusion
// path (a confident-looking fabricated number), just relocated from a
// diffusion model's pixels to this module's arithmetic.
//
// esc() is reused from above as-is: it doesn't escape `"`, but nothing
// below places a fixed label string inside a quoted SVG attribute value,
// only inside <text> element content, so the gap doesn't apply here.

const GENERIC_FONT = "font-family:'Segoe UI',Arial,sans-serif;";

const GENERIC_L = {
  en: {
    plan: 'PLAN VIEW', section: 'SECTION A\u2013A',
    colA: 'COLUMN A', colB: 'COLUMN B', col: 'COLUMN',
    footRect: 'RECTANGULAR COMBINED FOOTING', footTrap: 'TRAPEZOIDAL COMBINED FOOTING',
    footStrap: 'STRAP FOOTING', footIso: 'ISOLATED FOOTING',
    strapBeam: 'STRAP BEAM', edgeFooting: 'EDGE FOOTING', interiorFooting: 'INTERIOR FOOTING',
    ground: 'GROUND LINE', rebarNote: 'REINFORCEMENT MAT (SCHEMATIC)',
    caption: 'Generic reference schematic \u2014 not project-specific. For an exact, to-scale drawing use /diagram with your own dimensions. Verify every dimension against your own ECP 203 / ACI 318 design.',
    dirAttr: 'ltr',
  },
  ar: {
    plan: 'مسقط أفقي', section: 'قطاع أ-أ',
    colA: 'عمود أ', colB: 'عمود ب', col: 'عمود',
    footRect: 'قاعدة مشتركة مستطيلة', footTrap: 'قاعدة مشتركة شبه منحرفة',
    footStrap: 'القاعدة الشريطية', footIso: 'قاعدة منفردة',
    strapBeam: 'كمرة الربط', edgeFooting: 'القاعدة الطرفية', interiorFooting: 'القاعدة الداخلية',
    ground: 'منسوب سطح الأرض', rebarNote: 'شبكة تسليح (توضيحية)',
    caption: 'مخطط توضيحي عام وليس خاصاً بمشروع معين — لرسم دقيق بأبعادك الفعلية استخدم أمر /diagram. راجع جميع الأبعاد مع تصميمك الخاص وفق ECP 203 / ACI 318.',
    dirAttr: 'rtl',
  },
};

// ── Generic-path primitives ─────────────────────────────────────────────
// Self-contained low-level SVG builders for the GENERIC (no-numbers) path
// only — deliberately not shared with the computed path's own esc/
// dimensionLine/hatchDefs above, or with structuralDrawingKit.mjs: this
// code pre-dates both, was never migrated, and (unlike the computed
// path's local duplicates noted in this file's Step 17 header addendum)
// isn't even functionally equivalent to the kit's primitives — gDimH/
// gDimV draw arrow-terminated dimension lines with a fixed 14px bold
// label, a different visual convention from the kit's tick-terminated
// dimensionLine(). One-line purpose per function:
//   genericDefs      — the <pattern>/<marker> defs (concrete hatch, soil
//                       hatch, arrowheads) every generic drawing needs.
//   gText            — a single styled <text> node; every other primitive
//                       here composes its own labels through this one.
//   gDimH / gDimV     — horizontal/vertical arrow-terminated dimension
//                       lines with a bold symbolic label (L, B, D — never
//                       a number; see this section's own header below).
//   gRebarMeshPlan    — a crossing-line grid inside a rect, standing in
//                       for "there is a reinforcement mat here" in plan.
//   gRebarDotsRow     — an evenly-spaced row of filled dots, standing in
//                       for bar cross-sections in a section-view cut.
//   gDowels           — a fixed small count of hooked dowel bars rising
//                       from a footing into a column, purely illustrative
//                       (count defaults to 4 regardless of real design).
//   gBreakSymbol      — the conventional zig-zag "member continues off-
//                       drawing" break mark, used above every column stub.
//   gPanelFrame       — the thin frame + caption around each plan/section
//                       panel buildFootingDiagramSvg lays the generator
//                       output inside.
function genericDefs() {
  return `<defs>
    <pattern id="gConcreteHatch" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <rect width="8" height="8" fill="#ffffff"/>
      <line x1="0" y1="0" x2="0" y2="8" stroke="#5b6b7a" stroke-width="1.1"/>
    </pattern>
    <pattern id="gSoilHatch" width="14" height="10" patternUnits="userSpaceOnUse">
      <rect width="14" height="10" fill="#f4f1ea"/>
      <line x1="0" y1="10" x2="7" y2="0" stroke="#9a8f78" stroke-width="1"/>
      <line x1="7" y1="10" x2="14" y2="0" stroke="#9a8f78" stroke-width="1"/>
    </pattern>
    <marker id="gArrowStart" markerWidth="8" markerHeight="8" refX="1" refY="4" orient="auto">
      <path d="M7,1 L1,4 L7,7 Z" fill="#1c2b3a"/>
    </marker>
    <marker id="gArrowEnd" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M1,1 L7,4 L1,7 Z" fill="#1c2b3a"/>
    </marker>
  </defs>`;
}

function gText(x, y, str, { size = 13, weight = 'normal', anchor = 'middle', color = '#1c2b3a', dir = 'ltr' } = {}) {
  return `<text x="${x}" y="${y}" text-anchor="${anchor}" dir="${dir}" style="${GENERIC_FONT}font-size:${size}px;font-weight:${weight};fill:${color};">${esc(str)}</text>`;
}

function gDimH(x1, x2, y, label, dir) {
  return `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="#1c2b3a" stroke-width="1" marker-start="url(#gArrowStart)" marker-end="url(#gArrowEnd)"/>
    <line x1="${x1}" y1="${y - 6}" x2="${x1}" y2="${y + 6}" stroke="#1c2b3a" stroke-width="1"/>
    <line x1="${x2}" y1="${y - 6}" x2="${x2}" y2="${y + 6}" stroke="#1c2b3a" stroke-width="1"/>
    ${gText((x1 + x2) / 2, y - 8, label, { size: 14, weight: '700', dir })}`;
}

function gDimV(y1, y2, x, label, dir, side = 'left') {
  const lx = side === 'left' ? x - 12 : x + 12;
  const anchor = side === 'left' ? 'end' : 'start';
  return `<line x1="${x}" y1="${y1}" x2="${x}" y2="${y2}" stroke="#1c2b3a" stroke-width="1" marker-start="url(#gArrowStart)" marker-end="url(#gArrowEnd)"/>
    <line x1="${x - 6}" y1="${y1}" x2="${x + 6}" y2="${y1}" stroke="#1c2b3a" stroke-width="1"/>
    <line x1="${x - 6}" y1="${y2}" x2="${x + 6}" y2="${y2}" stroke="#1c2b3a" stroke-width="1"/>
    ${gText(lx, (y1 + y2) / 2 + 4, label, { size: 14, weight: '700', anchor, dir })}`;
}

function gRebarMeshPlan(x, y, w, h, step = 26) {
  let out = '';
  for (let gx = x; gx <= x + w + 0.01; gx += step) out += `<line x1="${gx}" y1="${y}" x2="${gx}" y2="${y + h}" stroke="#8fa3b8" stroke-width="0.75"/>`;
  for (let gy = y; gy <= y + h + 0.01; gy += step) out += `<line x1="${x}" y1="${gy}" x2="${x + w}" y2="${gy}" stroke="#8fa3b8" stroke-width="0.75"/>`;
  return `<g opacity="0.85">${out}</g>`;
}

function gRebarDotsRow(x1, x2, y, count = 7, r = 3.2) {
  let out = '';
  for (let i = 0; i < count; i++) {
    const x = x1 + ((x2 - x1) * i) / (count - 1);
    out += `<circle cx="${x}" cy="${y}" r="${r}" fill="#1c2b3a"/>`;
  }
  return out;
}

function gDowels(cx, colHalfW, topY, hookY, count = 4) {
  let out = '';
  const inset = colHalfW * 0.5;
  for (let i = 0; i < count; i++) {
    const x = cx - inset + (i * (2 * inset)) / (count - 1);
    const hookDir = x < cx ? -1 : 1;
    out += `<path d="M${x},${topY} L${x},${hookY} L${x + hookDir * 10},${hookY}" fill="none" stroke="#1c2b3a" stroke-width="1.3"/>`;
  }
  return out;
}

function gBreakSymbol(cx, y, halfW) {
  const x1 = cx - halfW - 4, x2 = cx + halfW + 4;
  return `<path d="M${x1},${y} L${x1 + 6},${y - 7} L${x1 + 14},${y + 7} L${x1 + 22},${y - 7} L${x1 + 30},${y}
    M${x2 - 30},${y} L${x2 - 22},${y - 7} L${x2 - 14},${y + 7} L${x2 - 6},${y - 7} L${x2},${y}"
    fill="none" stroke="#1c2b3a" stroke-width="1.2"/>`;
}

function gPanelFrame(x, y, w, h, caption, dir) {
  return `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="none" stroke="#c7d2dc" stroke-width="1"/>
    ${gText(x + w / 2, y + h + 22, caption, { size: 15, weight: '700', dir })}`;
}

// ── Per-type generators ─────────────────────────────────────────────────
// Four pairs below (isolated, rectangular, trapezoidal, strap), one plan+
// section pair per GENERIC_BUILDERS entry. Every function takes
// (px, py, pw, ph, l) — the panel box gPanelFrame already outlined — and
// returns SVG fragments positioned as hand-tuned FRACTIONS of that box
// (0.56, 0.28, 0.34, ...): these proportions are visual-legibility
// choices, not derived from any real dimension, which is legitimate ONLY
// because this is the generic (no-numbers) path — GENERIC_L.caption tells
// the reader outright that this is a non-project-specific reference
// image, unlike the computed path above where every proportion in
// computeSectionGeometry/renderSectionView traces back to real input.
// Every dimension callout drawn here is a SYMBOL (L, B, D, B1, B2), never
// a digit, for that same reason — see this section's own module header
// above ("Every dimension is a SYMBOL").
//
// ── Isolated (single column) ────────────────────────────────────────────
function genPlanIsolated(px, py, pw, ph, l) {
  const fw = pw * 0.56, fh = ph * 0.62;
  const fx = px + (pw - fw) / 2, fy = py + (ph - fh) / 2;
  const cw = Math.min(fw, fh) * 0.34;
  const cx = fx + fw / 2, cy = fy + fh / 2;
  const cutX1 = cx, cutY1 = fy - 18, cutY2 = fy + fh + 18;
  return `
    ${gRebarMeshPlan(fx + 8, fy + 8, fw - 16, fh - 16)}
    <rect x="${fx}" y="${fy}" width="${fw}" height="${fh}" fill="none" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${cx - cw / 2}" y="${cy - cw / 2}" width="${cw}" height="${cw}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${gText(cx + cw / 2 + 10, cy + 4, l.col, { size: 12, weight: '700', anchor: 'start', dir: l.dirAttr })}
    <line x1="${cutX1}" y1="${cutY1}" x2="${cutX1}" y2="${cutY2}" stroke="#8a2b2b" stroke-width="1.4" stroke-dasharray="10,4,2,4"/>
    ${gText(cutX1, cutY1 - 8, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'middle' })}
    ${gText(cutX1 + 14, cutY2 + 5, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'start' })}
    ${gDimH(fx, fx + fw, fy + fh + 26, 'L', l.dirAttr)}
    ${gDimV(fy, fy + fh, fx - 26, 'B', l.dirAttr, 'left')}
  `;
}

// Section cut through the column: ground line + soil hatch, footing body
// with a representative dot row, the column rising through a break
// symbol, and a hooked-dowel row at the interface — see gDowels' own
// one-line summary above.
function genSectionIsolated(px, py, pw, ph, l) {
  const gy = py + ph * 0.42;
  const fx = px + pw * 0.14, fw = pw * 0.72, fh = ph * 0.15, fy = gy;
  const cw = fh * 0.85;
  const cx = fx + fw / 2;
  const colTop = py + ph * 0.06;
  return `
    <rect x="${px}" y="${gy}" width="${pw}" height="${py + ph - gy}" fill="url(#gSoilHatch)"/>
    <line x1="${px}" y1="${gy}" x2="${px + pw}" y2="${gy}" stroke="#5b4a2f" stroke-width="1.5"/>
    ${gText(px + pw - 4, gy - 6, l.ground, { size: 10, color: '#5b4a2f', anchor: 'end' })}
    <rect x="${fx}" y="${fy}" width="${fw}" height="${fh}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2.5"/>
    ${gRebarDotsRow(fx + 14, fx + fw - 14, fy + fh - 12)}
    <rect x="${cx - cw / 2}" y="${colTop}" width="${cw}" height="${fy - colTop}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${gBreakSymbol(cx, colTop + 6, cw / 2)}
    ${gDowels(cx, cw / 2, colTop + 14, fy + fh - 10)}
    ${gText(cx, colTop - 8, l.col, { size: 12, weight: '700', dir: l.dirAttr })}
    ${gDimH(fx, fx + fw, fy + fh + 26, 'B', l.dirAttr)}
    ${gDimV(fy, fy + fh, fx - 26, 'D', l.dirAttr, 'left')}
  `;
}

// ── Rectangular combined ────────────────────────────────────────────────
// Plan: one rectangular footing, two columns (A/B) at fixed 20%/80%
// positions along its length, one section-cut line through both.
function genPlanRectangular(px, py, pw, ph, l) {
  const fx = px + pw * 0.10, fy = py + ph * 0.28, fw = pw * 0.80, fh = ph * 0.34;
  const cw = fh * 0.42;
  const cAx = fx + fw * 0.20, cBx = fx + fw * 0.80, cy = fy + fh / 2;
  const cutY = cy, cutX1 = fx - 18, cutX2 = fx + fw + 18;
  return `
    ${gRebarMeshPlan(fx + 10, fy + 10, fw - 20, fh - 20)}
    <rect x="${fx}" y="${fy}" width="${fw}" height="${fh}" fill="none" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${cAx - cw / 2}" y="${cy - cw / 2}" width="${cw}" height="${cw}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    <rect x="${cBx - cw / 2}" y="${cy - cw / 2}" width="${cw}" height="${cw}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${gText(cAx, fy - 10, l.colA, { size: 12, weight: '700', dir: l.dirAttr })}
    ${gText(cBx, fy - 10, l.colB, { size: 12, weight: '700', dir: l.dirAttr })}
    <line x1="${cutX1}" y1="${cutY}" x2="${cutX2}" y2="${cutY}" stroke="#8a2b2b" stroke-width="1.4" stroke-dasharray="10,4,2,4"/>
    ${gText(cutX1, cutY - 10, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'middle' })}
    ${gText(cutX2, cutY - 10, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'middle' })}
    ${gDimH(fx, fx + fw, fy + fh + 26, 'L', l.dirAttr)}
    ${gDimV(fy, fy + fh, fx - 26, 'B', l.dirAttr, 'left')}
  `;
}

// Section through both columns. Takes an optional `extraNote` (two text
// lines shown between the columns) — genSectionTrapezoidal below calls
// this function directly rather than duplicating it, passing its own
// note text, since a trapezoidal footing's SECTION cut looks the same as
// a rectangular one at this schematic's level of detail (only the PLAN
// view actually differs, hence trapezoidal has its own genPlanTrapezoidal
// but no separate section-drawing code).
function genSectionRectangular(px, py, pw, ph, l, extraNote) {
  const gy = py + ph * 0.42;
  const fx = px + pw * 0.10, fw = pw * 0.80, fh = ph * 0.15, fy = gy;
  const cw = fh * 0.85;
  const cAx = fx + fw * 0.20, cBx = fx + fw * 0.80;
  const colTop = py + ph * 0.06;
  const gapX = cAx + cw / 2 + 6, gapW = (cBx - cw / 2) - (cAx + cw / 2) - 12;
  const noteTop = colTop + (fy - colTop) * 0.18;
  const note = extraNote ? `
    <rect x="${gapX}" y="${noteTop}" width="${gapW}" height="34" fill="#ffffff" opacity="0.9"/>
    ${gText((cAx + cBx) / 2, noteTop + 14, extraNote[0], { size: 9.5, color: '#5b6b7a', dir: l.dirAttr })}
    ${gText((cAx + cBx) / 2, noteTop + 27, extraNote[1], { size: 9.5, color: '#5b6b7a', dir: l.dirAttr })}
  ` : '';
  return `
    <rect x="${px}" y="${gy}" width="${pw}" height="${py + ph - gy}" fill="url(#gSoilHatch)"/>
    <line x1="${px}" y1="${gy}" x2="${px + pw}" y2="${gy}" stroke="#5b4a2f" stroke-width="1.5"/>
    ${gText(px + pw - 4, gy - 6, l.ground, { size: 10, color: '#5b4a2f', anchor: 'end' })}
    <rect x="${fx}" y="${fy}" width="${fw}" height="${fh}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2.5"/>
    ${gRebarDotsRow(fx + 14, fx + fw - 14, fy + fh - 12)}
    <rect x="${cAx - cw / 2}" y="${colTop}" width="${cw}" height="${fy - colTop}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    <rect x="${cBx - cw / 2}" y="${colTop}" width="${cw}" height="${fy - colTop}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${gBreakSymbol(cAx, colTop + 6, cw / 2)}
    ${gBreakSymbol(cBx, colTop + 6, cw / 2)}
    ${gDowels(cAx, cw / 2, colTop + 14, fy + fh - 10)}
    ${gDowels(cBx, cw / 2, colTop + 14, fy + fh - 10)}
    ${gText(cAx, colTop - 8, l.colA, { size: 12, weight: '700', dir: l.dirAttr })}
    ${gText(cBx, colTop - 8, l.colB, { size: 12, weight: '700', dir: l.dirAttr })}
    ${gDimH(fx, fx + fw, fy + fh + 26, 'L', l.dirAttr)}
    ${gDimV(fy, fy + fh, fx - 26, 'D', l.dirAttr, 'left')}
    ${note}
  `;
}

// ── Trapezoidal combined ────────────────────────────────────────────────
// Plan: a trapezoid (clipped mesh fill via gTrapClip) with two differently
// -sized columns (the narrower/wider footing ends), dimensioned B1/B2 (two
// distinct end widths) instead of rectangular's single B — the one real
// visual distinction this footing type has over the rectangular case.
function genPlanTrapezoidal(px, py, pw, ph, l) {
  const fx = px + pw * 0.10, fy = py + ph * 0.24, fw = pw * 0.80, fh1 = ph * 0.44, fh2 = ph * 0.22;
  const topL = fy + (fh1 - fh2) / 2, botL = topL + fh2;
  const topR = fy, botR = fy + fh1;
  const cw = fh2 * 0.7;
  const cAx = fx + fw * 0.16, cAy = (topL + botL) / 2;
  const cBx = fx + fw * 0.82, cBy = (topR + botR) / 2;
  const clipTop = Math.min(topL, topR), clipBot = Math.max(botL, botR);
  return `
    <clipPath id="gTrapClip"><polygon points="${fx},${topL} ${fx + fw},${topR} ${fx + fw},${botR} ${fx},${botL}"/></clipPath>
    <g clip-path="url(#gTrapClip)">${gRebarMeshPlan(fx, clipTop, fw, clipBot - clipTop)}</g>
    <polygon points="${fx},${topL} ${fx + fw},${topR} ${fx + fw},${botR} ${fx},${botL}" fill="none" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${cAx - cw / 2}" y="${cAy - cw / 2}" width="${cw}" height="${cw}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    <rect x="${cBx - cw * 1.15 / 2}" y="${cBy - cw * 1.15 / 2}" width="${cw * 1.15}" height="${cw * 1.15}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${gText(cAx, topL - 12, l.colA, { size: 12, weight: '700', dir: l.dirAttr })}
    ${gText(cBx, topR - 12, l.colB, { size: 12, weight: '700', dir: l.dirAttr })}
    <line x1="${fx - 18}" y1="${cAy}" x2="${fx + fw + 18}" y2="${cBy}" stroke="#8a2b2b" stroke-width="1.4" stroke-dasharray="10,4,2,4"/>
    ${gText(fx - 18, cAy - 10, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'middle' })}
    ${gText(fx + fw + 18, cBy - 10, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'middle' })}
    ${gDimH(fx, fx + fw, botR + 30, 'L', l.dirAttr)}
    ${gDimV(topL, botL, fx - 26, 'B1', l.dirAttr, 'left')}
    ${gDimV(topR, botR, fx + fw + 26, 'B2', l.dirAttr, 'right')}
  `;
}

function genSectionTrapezoidal(px, py, pw, ph, l) {
  const noteLines = l.dirAttr === 'rtl'
    ? ['العرض يتغيّر مع الطول', 'انظر المسقط الأفقي']
    : ['width tapers along length', '\u2014 see plan'];
  return genSectionRectangular(px, py, pw, ph, l, noteLines);
}

// ── Strap (two separate pads + connecting beam) ─────────────────────────
// Plan: two independent footing pads (edge + interior, deliberately NOT
// touching) linked by a dashed strap-beam outline — the visual signature
// that distinguishes this type from rectangular-combined's one continuous
// footing.
function genPlanStrap(px, py, pw, ph, l) {
  const midY = py + ph * 0.5;
  const edgeW = pw * 0.20, edgeH = ph * 0.30;
  const intW = pw * 0.30, intH = ph * 0.42;
  const edgeX = px + pw * 0.08, edgeY = midY - edgeH / 2;
  const intX = px + pw * 0.72, intY = midY - intH / 2;
  const strapX1 = edgeX + edgeW, strapX2 = intX, strapH = ph * 0.10;
  const cw = Math.min(edgeH, intH) * 0.5;
  return `
    <rect x="${edgeX}" y="${edgeY}" width="${edgeW}" height="${edgeH}" fill="none" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${intX}" y="${intY}" width="${intW}" height="${intH}" fill="none" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${strapX1}" y="${midY - strapH / 2}" width="${strapX2 - strapX1}" height="${strapH}" fill="none" stroke="#1c2b3a" stroke-width="2" stroke-dasharray="6,3"/>
    <rect x="${edgeX + edgeW * 0.30 - cw / 2}" y="${midY - cw / 2}" width="${cw}" height="${cw}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    <rect x="${intX + intW * 0.5 - cw * 1.1 / 2}" y="${midY - cw * 1.1 / 2}" width="${cw * 1.1}" height="${cw * 1.1}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${gText(edgeX + edgeW / 2, edgeY - 10, l.edgeFooting, { size: 11, weight: '700', dir: l.dirAttr })}
    ${gText(intX + intW / 2, intY - 10, l.interiorFooting, { size: 11, weight: '700', dir: l.dirAttr })}
    ${gText((strapX1 + strapX2) / 2, midY - strapH / 2 - 8, l.strapBeam, { size: 10, weight: '700', dir: l.dirAttr })}
    <line x1="${edgeX - 16}" y1="${midY}" x2="${intX + intW + 16}" y2="${midY}" stroke="#8a2b2b" stroke-width="1.4" stroke-dasharray="10,4,2,4"/>
    ${gText(edgeX - 24, midY + 4, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'end' })}
    ${gText(intX + intW + 24, midY + 4, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'start' })}
    ${gDimH(edgeX, intX + intW, Math.max(edgeY + edgeH, intY + intH) + 28, 'L', l.dirAttr)}
  `;
}

// Section: both pads' independent depths plus the strap beam drawn as a
// raised connecting member above the soil line between them — the two
// pads deliberately do not share one section depth/width the way
// rectangular-combined's two columns do, matching the plan view's
// "two independent footings" reading.
function genSectionStrap(px, py, pw, ph, l) {
  const gy = py + ph * 0.50;
  const edgeW = pw * 0.16, edgeFh = ph * 0.10;
  const intW = pw * 0.22, intFh = ph * 0.14;
  const edgeX = px + pw * 0.10, edgeFy = gy - edgeFh * 0.3;
  const intX = px + pw * 0.70, intFy = gy;
  const gap = ph * 0.07;
  const strapY = Math.min(edgeFy, intFy) - gap - ph * 0.06;
  const strapH = ph * 0.06;
  const colTop = py + ph * 0.04;
  const cwE = edgeFh * 1.4, cwI = intFh * 1.1;
  const edgeCx = edgeX + edgeW / 2, intCx = intX + intW / 2;
  return `
    <rect x="${px}" y="${gy}" width="${pw}" height="${py + ph - gy}" fill="url(#gSoilHatch)"/>
    <line x1="${px}" y1="${gy}" x2="${px + pw}" y2="${gy}" stroke="#5b4a2f" stroke-width="1.5"/>
    ${gText(px + pw - 4, gy - 6, l.ground, { size: 10, color: '#5b4a2f', anchor: 'end' })}
    <rect x="${edgeX}" y="${edgeFy}" width="${edgeW}" height="${py + ph * 0.62 - edgeFy}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${intX}" y="${intFy}" width="${intW}" height="${py + ph * 0.68 - intFy}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${edgeX + edgeW - 6}" y="${strapY}" width="${intX - (edgeX + edgeW - 6) + 6}" height="${strapH}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${gText((edgeX + edgeW + intX) / 2, strapY - 8, l.strapBeam, { size: 10, weight: '700', dir: l.dirAttr })}
    <rect x="${edgeCx - cwE / 2}" y="${colTop}" width="${cwE}" height="${strapY - colTop}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    <rect x="${intCx - cwI / 2}" y="${colTop}" width="${cwI}" height="${strapY - colTop}" fill="url(#gConcreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${gBreakSymbol(edgeCx, colTop + 6, cwE / 2)}
    ${gBreakSymbol(intCx, colTop + 6, cwI / 2)}
    ${gRebarDotsRow(edgeX + 6, edgeX + edgeW - 6, py + ph * 0.62 - 8, 3, 2.6)}
    ${gRebarDotsRow(intX + 6, intX + intW - 6, py + ph * 0.68 - 8, 4, 2.8)}
    ${gText(edgeCx, colTop - 8, l.colA, { size: 11, weight: '700', dir: l.dirAttr })}
    ${gText(intCx, colTop - 8, l.colB, { size: 11, weight: '700', dir: l.dirAttr })}
  `;
}

const GENERIC_BUILDERS = {
  isolated:    { title: 'footIso',   plan: genPlanIsolated,     section: genSectionIsolated },
  rectangular: { title: 'footRect',  plan: genPlanRectangular,  section: genSectionRectangular },
  trapezoidal: { title: 'footTrap',  plan: genPlanTrapezoidal,  section: genSectionTrapezoidal },
  strap:       { title: 'footStrap', plan: genPlanStrap,        section: genSectionStrap },
};

// strip and raft are NOT in GENERIC_BUILDERS on purpose (see section
// header) — classifyFootingDiagram() below still returns those two type
// strings so chat.js can route them to a "use /diagram" response instead
// of either drawing a possibly-wrong layout or silently falling through
// to the diffusion model for a term the glossary already disambiguates.
// Top-level assembly for the GENERIC (no-numbers) path — the counterpart
// to renderFootingDiagramSVG above, called from chat.js when
// classifyFootingDiagram() below recognizes a type but the user gave no
// numeric parameters. Fixed 1000x640 canvas, two fixed side-by-side
// panels (plan left, section right) regardless of footing type — unlike
// the computed path, there is no per-drawing scale-fitting because there
// are no real dimensions to fit; every generator above already sizes
// itself as a fraction of the fixed panel box it's handed. Returns null
// for a type with no GENERIC_BUILDERS entry (strip/raft) so the caller
// can fall back to a "use /diagram" response — see the section header
// above for why those two are excluded on purpose.
export function buildFootingDiagramSvg(type, lang) {
  const l = GENERIC_L[lang === 'ar' ? 'ar' : 'en'];
  const b = GENERIC_BUILDERS[type];
  if (!b) return null;

  const W = 1000, H = 640;
  const PX0 = 50, PY0 = 118, PW = 400, PH = 380;
  const SX0 = 560, SY0 = 118, SW = 400, SH = 380;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${esc(l[b.title])}">
    <rect width="${W}" height="${H}" fill="#ffffff"/>
    ${genericDefs()}
    ${gText(W / 2, 42, l[b.title], { size: 22, weight: '700', dir: l.dirAttr })}
    ${gText(W / 2, 64, l.rebarNote, { size: 11, color: '#5b6b7a', dir: l.dirAttr })}
    ${gPanelFrame(PX0, PY0, PW, PH, l.plan, l.dirAttr)}
    ${gPanelFrame(SX0, SY0, SW, SH, l.section, l.dirAttr)}
    <g>${b.plan(PX0, PY0, PW, PH, l)}</g>
    <g>${b.section(SX0, SY0, SW, SH, l)}</g>
    <line x1="30" y1="${H - 34}" x2="${W - 30}" y2="${H - 34}" stroke="#e2e8ee" stroke-width="1"/>
    ${gText(W / 2, H - 14, l.caption, { size: 10.5, color: '#7a8a9a', dir: l.dirAttr })}
  </svg>`;
}

// Strips a leading Arabic definite article ("ال") from the front of every
// whitespace-separated word in the input, once, before pattern matching.
// This product's own copy is routinely written definite — "القاعدة
// الشريطية", "القاعدة المشتركة المستطيلة" (both straight from
// footing_pro's own meta/FAQ text) — and a plain pattern like
// /قاعدة\s*شريطية/ does not match inside "القاعدة الشريطية": "قاعدة"
// matches as a substring of "القاعدة", but the very next characters are
// " ال" (space + the second word's own definite article), not the start
// of "شريطية", so the two halves of the pattern never line up. Confirmed
// by testing the exact live phrase, not assumed from reading the regex.
//
// imageGen.mjs's translateKnownTerms() hit the identical root cause and
// fixed it differently — a per-phrase regex with an optional (?:ال)?
// before every word (buildArabicMatcher there) — because that function
// has to return the matched TEXT for substitution, so it cannot destroy
// the original string up front. This function only returns a yes/no
// classification, never the input text itself, so normalizing the INPUT
// once up front is simpler and equally correct for this narrower job;
// see that file's own comment cross-referencing this one.
function stripAl(text) {
  return String(text)
    .split(/(\s+)/)
    .map((tok) => (/^\s+$/.test(tok) ? tok : tok.replace(/^ال/, '')))
    .join('');
}

// Ordered so the classifier checks the most specific terms first —
// "trapezoidal" must win over a bare "footing"/"combined" match, "strip"
// (with its wall-qualifier) must win before "strap" would otherwise catch
// "قاعدة شريطية" as a substring, and "isolated"/"raft" are checked before
// the bare "قاعدة" pattern could otherwise swallow them.
//
// 'قاعدة شريطية' alone (no wall-qualifier) maps to STRAP, not the
// textbook-generic "strip/continuous" reading — matching this product's
// own usage (footing_pro's FAQ literally glosses "القاعدة الشريطية" as
// "Strap" in English, inline, in its own Arabic copy) and matching
// imageGen.mjs's ARABIC_ENGINEERING_GLOSSARY, which had to make the
// identical call on the identical evidence — this is the second of two
// places that decision had to be made consistently, not a one-off (see
// that file's own comment on this same point).
// [Bugfix, this session] The three (?!\s+\w+=) / \b additions below
// (trapezoidal, raft, strap) close two gaps in the same family Step 2
// only partly closed:
//   1. trapezoidal/strap had NO (?!\s+\w+=) guard at all — a full,
//      valid "/diagram trapezoidal B=6000 L=9000 D=500 col1off=1000 ..."
//      or "/diagram strap B=... col1off=..." command matched this
//      loose-text pattern and (pre this session's chat.js dispatch-order
//      fix) got misrouted to the "generic template" response before
//      trapezoidalFootingDiagram.mjs's / strapFootingDiagram.mjs's own
//      parseDiagramCommand ever ran. Same root cause Step 2 fixed for
//      raft, never carried over to these two.
//   2. raft's existing Step 2 guard stops at the first whitespace, so it
//      only ever excluded "raft" followed by a SPACE then a param
//      ("raft B=..."). It does nothing against a DIFFERENT command
//      token that happens to start with the same four letters and no
//      space in between — "raftpile ...". Adding \b right after the
//      literal "raft" (before the lookahead) makes the match stop
//      dead at "raftpile"'s embedded "raft" (no word boundary between
//      "t" and "p"), while every previously-passing case (bare "raft",
//      "raft foundation", "raft B=...") is unaffected — verified
//      against both sets in test_classify_fix.mjs, not assumed from
//      reading the regex.
// This closes the same class of bug diagramCommandRouter.mjs's own
// UNSUPPORTED_TYPE-fallthrough design already prevents for the STRICT
// command path — routeDiagramCommand always gets first refusal on a
// real command now (see chat.js's own dispatch-order fix note) — but
// classifyFootingDiagram is fixed at its own source too, since other
// call sites may invoke it directly without that ordering guarantee.
const GENERIC_PATTERNS = [
  { type: 'trapezoidal', re: /\b(?:trapezoidal|trapezoid)\b(?!\s+\w+=)/i },
  { type: 'trapezoidal', re: /شبه\s*منحرف/ },
  { type: 'strip', re: /strip\s*footing/i },
  { type: 'strip', re: /قاعدة\s*شريطية\s*تحت\s*حائط/ },
  { type: 'raft', re: /raft\b(?!\s+\w+=)\s*(foundation|footing)?|mat\s*foundation/i },
  { type: 'raft', re: /قاعدة\s*(لبشة|حصيرة)/ },
  { type: 'strap', re: /\bstrap(?!\s+\w+=)\s*(footing|beam)?\b/i },
  { type: 'strap', re: /قاعدة\s*رباط|قاعدة\s*شريطية|كمرة\s*رباط/ },
  { type: 'isolated', re: /isolated\s*(column)?\s*footing|spread\s*footing/i },
  { type: 'isolated', re: /قاعدة\s*(منفردة|منفصلة)/ },
  { type: 'rectangular', re: /rectangular\s*(combined)?\s*footing/i },
  { type: 'rectangular', re: /combined\s*footing/i },
  { type: 'rectangular', re: /قاعدة\s*(مشتركة|مستطيلة)/ },
];

export function classifyFootingDiagram(rawPrompt) {
  const p = stripAl(String(rawPrompt || ''));
  for (const { type, re } of GENERIC_PATTERNS) {
    if (re.test(p)) return type;
  }
  return null;
}

export function svgToDataUri(svgString) {
  return 'data:image/svg+xml,' + encodeURIComponent(svgString);
}
