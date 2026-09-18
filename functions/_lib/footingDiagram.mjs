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
// hooks, no dowels, no development-length extensions, no stirrups/ties.
// Column-to-footing dowelling is not shown. renderFootingDiagramSVG()
// always appends a fixed caption saying so; treat that caption as load-
// bearing UX, not decoration — see appendBotDiagramBubble() in the
// footing_pro/pc_suite integration notes for why it must never be
// stripped out by a caller.
//
// [Step 14] The paragraph above describes the DEFAULT drawing. pedestal/
// dowels/mesh are now optional inputs (see computeFootingExtras()) that
// ARE drawn when the caller explicitly supplies them — captionComputed
// in structuralLabels.mjs was reworded at the same step to stay accurate
// in both cases rather than describing only the no-extras default.
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
// [Step 20] tieTickH/assertNoIntervalOverlap added to the existing
// DiagramError/assertInt/barDot/scheduleTable import — both reused
// verbatim from the shared kit rather than hand-rolled a second time.
// tieTickH already exists there for columnDiagram.mjs's elevation view
// ("the member runs VERTICALLY... tie bands cross the member
// horizontally" — that function's own header) — exactly this file's own
// column-stub-above-the-footing geometry, so no new kit primitive is
// needed for column ties, only a new call site here.
import {
  DiagramError, assertInt, barDot, scheduleTable, tieTickH, assertNoIntervalOverlap,
} from './structuralDrawingKit.mjs';
export { DiagramError };
// [Step 4 — translation] footingTitle/columnTag/sectionTitle replace
// this file's old module-scope TITLES table and the raw col.tag /
// hardcoded "PLAN"/"SECTION A-A" strings renderPlanView/renderSectionView
// used to emit regardless of `lang` — see structuralLabels.mjs's own
// header for the full rationale and the tofu-avoidance constraint on
// any Arabic value added there.
import { translate, footingTitle, columnTag, sectionTitle as translatedSectionTitle } from './structuralLabels.mjs';

// Local duplicates of structuralDrawingKit.mjs's MM_PER_UNIT/toMm/fromMm/
// assertFinitePositive/fmt — see this file's Step 17 header addendum
// above for why these were never migrated onto the kit's exported
// versions. Kept here unchanged rather than edited in place, since this
// step is documentation-only and a same-session behavioral migration
// carries risk this step's scope does not call for.
const MM_PER_UNIT = { mm: 1, cm: 10, m: 1000 };

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

// [Step 20] Same philosophy again, applied to ties.count. A column tie
// zone in a real design can call for a confinement tie every 50-75mm —
// drawing every single one would both clutter this schematic's small
// fixed section box and cost needless SVG bytes for zero added
// legibility over a representative-tick + spacing-callout convention,
// same reasoning distributeTicks()'s own cap in structuralDrawingKit.mjs
// already documents for beam stirrups.
const MAX_TIES = 12;

// [Step 20] Bounds the number of EXTRA transverse bars drawn inside one
// column's concentration band (computeBandGeometry below) — a schematic-
// tool cap on the same axis MAX_DOWELS already caps for dowels, not a
// structural limit. A band this dense would be illegible at this
// canvas's fixed scale regardless of how structurally real the count is.
const MAX_BAND_BARS_PER_ZONE = 20;

function toMm(value, unit) {
  const factor = MM_PER_UNIT[unit];
  if (!factor) {
    throw new DiagramError('BAD_UNIT', `Unknown unit "${unit}" — expected one of: ${Object.keys(MM_PER_UNIT).join(', ')}.`);
  }
  return value * factor;
}

function fromMm(mm, unit) {
  return mm / MM_PER_UNIT[unit];
}

function assertFinitePositive(name, value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new DiagramError('BAD_PARAM', `"${name}" must be a positive finite number, got ${JSON.stringify(value)}.`);
  }
}

function fmt(mmValue, unit, decimals = 0) {
  const v = fromMm(mmValue, unit);
  return `${v.toFixed(decimals)}${unit}`;
}

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

// ── Step 20: reinforcement concentration band (شريحة تركيز التسليح) ────
// The Egyptian code's own detailing guide (دليل التفاصيل الانشائية,
// شكل ١٦-٣) shows a combined footing's TRANSVERSE bottom steel as denser
// directly under each column ("شريحة تركيز التسليح") than in the general
// field between/beyond them (labelled there at a flat 0.5% minimum,
// itself the guide's own value, not this tool's invention). This
// function draws that second, ADDITIVE layer — never a replacement for
// the field mesh renderPlanView already draws unconditionally — because
// deciding whether concentrated bars replace or supplement a portion of
// the field mesh is a real design choice this tool has no basis to make
// silently; showing both, clearly distinguished, lets the caller's own
// design govern that bookkeeping instead of this schematic guessing it.
//
// widthMM is a REQUIRED explicit input (rawParams.band.width — see
// computeFootingExtras below), never derived from colWidthMM times some
// unverified multiplier: this file's own house rule ("no number you
// can't defend" — see this file's Step 17 header addendum) applies here
// exactly as it does to every dia/spacing value elsewhere, and no
// version of this codebase has ever had the actual ECP 203 clause text
// in hand to derive a band-width formula from. The caller supplies it.
//
// One zone per column, centered on that column's own centerLongMM,
// clipped against the footing's own L extent and checked against every
// other zone for overlap (assertNoIntervalOverlap, reused from the kit)
// — the same "zones must tile without crossing" guarantee beam stirrup
// zones already rely on elsewhere in this codebase.
function computeBandGeometry({
  columnCentersMM, footingLongMM, widthMM, coverMM, diaMM, spacingMM,
}) {
  assertFinitePositive('band width', widthMM);
  assertFinitePositive('band cover', coverMM);
  assertFinitePositive('band.dia', diaMM);
  assertFinitePositive('band.spacing', spacingMM);

  // De-duplicate identical centers BEFORE building zones. Every caller
  // except raft's already guarantees distinct centers here (combined/
  // strip's own COLUMNS_OVERLAP check rejects two columns sharing one L
  // position outright, since two positive-length footprints centered on
  // the same point always overlap) — but a raft can legitimately place
  // two columns at the same offx (same L) and different offy (different
  // B), which is not a real footing overlap at all, just two columns
  // that happen to sit under the same transverse cut. Found by testing
  // raft's own 2x2 column grid directly, not assumed from reading the
  // 1-D combined/strip case alone: without this dedupe step, those two
  // columns would generate two IDENTICAL zones and fail the overlap
  // check below on a false positive.
  const uniqueCentersMM = [...new Set(columnCentersMM)];

  const rawZones = uniqueCentersMM.map((centerLongMM) => {
    const startMM = centerLongMM - widthMM / 2;
    const endMM = centerLongMM + widthMM / 2;
    if (startMM < 0 || endMM > footingLongMM) {
      throw new DiagramError(
        'BAND_OUT_OF_BOUNDS',
        `Concentration band centered at L=${centerLongMM}mm (width ${widthMM}mm) extends outside the footing's L=${footingLongMM}mm extent.`,
      );
    }
    return {
      centerLongMM, startMM, endMM,
    };
  });
  assertNoIntervalOverlap(rawZones, { startKey: 'startMM', endKey: 'endMM', label: 'concentration band' });

  const zones = rawZones.map(({ centerLongMM, startMM, endMM }) => {
    // Same "no room for even one bar" guard computeSectionGeometry/
    // computeMeshLayer already apply to a footing width, applied here to
    // one zone's own (narrower) width instead.
    const envelope = (endMM - startMM) - diaMM;
    if (envelope <= 0) {
      throw new DiagramError('NO_ROOM_FOR_BARS', `Band width (${(endMM - startMM).toFixed(0)}mm) leaves no room for a ${diaMM}mm bar.`);
    }
    const rawCount = Math.floor(envelope / spacingMM) + 1;
    const barCount = Math.max(1, Math.min(rawCount, MAX_BAND_BARS_PER_ZONE));
    const firstMM = startMM + diaMM / 2;
    const lastMM = endMM - diaMM / 2;
    const { centersMM: barCentersMM, actualSpacingMM } = distributeCenters(firstMM, lastMM, barCount);
    return {
      centerLongMM, startMM, endMM, barCount, barCentersMM, actualSpacingMM,
    };
  });

  return { widthMM, diaMM, spacingMM, zones };
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
// [Step 20] footingLongMM/columnCentersMM added for `band` only — every
// existing caller of this function already has both values in scope at
// its own call site (see each compute*FootingGeometry function's own
// updated call below); ties needs neither (see the `ties` branch's own
// comment on why tie positions are computed later, per-renderer).
function computeFootingExtras(rawParams, unit, colWidthMM, footingWidthMM, coverMM, footingLongMM, columnCentersMM) {
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

  // [Step 20] Ties: dia/spacing/count are LABEL values only — positions
  // are deliberately NOT computed here. The column stub ties are drawn
  // against is a fixed DECORATIVE height (SECTION_STUB_NO_PEDESTAL_MM in
  // this file / its own analogue in footingDiagram.dxf.mjs) — a render-
  // time display constant, never a real user-supplied column height
  // (same reason that stub itself has never been drawn to scale — see
  // this file's Step 14.3 comments) — and it differs between the SVG and
  // DXF renderers. Computing tie Y-positions here against one renderer's
  // stub height would silently be wrong for the other. Each renderer
  // instead distributes `count` representative ticks across whatever
  // height IT actually draws, using this same file's own
  // distributeCenters() helper — one geometric rule, applied twice,
  // rather than two different fixed heights baked into one compute-time
  // answer.
  if (rawParams.ties != null) {
    const { dia, spacing, count } = rawParams.ties;
    if (dia == null || spacing == null || count == null) {
      throw new DiagramError('BAD_PARAM', `"ties" requires "dia", "spacing", and "count" together, got ${JSON.stringify(rawParams.ties)}.`);
    }
    const diaMM = toMm(dia, unit);
    const spacingMM = toMm(spacing, unit);
    assertFinitePositive('ties.dia', diaMM);
    assertFinitePositive('ties.spacing', spacingMM);
    assertInt('ties.count', count, { min: 2, max: MAX_TIES });
    extras.ties = { diaMM, spacingMM, count };
  }

  // [Step 20] Band: widthMM is REQUIRED and always caller-supplied — see
  // computeBandGeometry's own header on why this tool never derives it.
  if (rawParams.band != null) {
    const { width, dia, spacing } = rawParams.band;
    if (width == null || dia == null || spacing == null) {
      throw new DiagramError('BAD_PARAM', `"band" requires "width", "dia", and "spacing" together, got ${JSON.stringify(rawParams.band)}.`);
    }
    const widthMM = toMm(width, unit);
    const diaMM = toMm(dia, unit);
    const spacingMM = toMm(spacing, unit);
    extras.band = computeBandGeometry({
      columnCentersMM, footingLongMM, widthMM, coverMM: coverMM, diaMM, spacingMM,
    });
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
  // [Step 20] longMM/[longMM/2]: isolated's own long axis and its single
  // (centered) column position, for the new `band` extra — a band on a
  // single-column footing is a less common case than combined/strip/raft
  // but not an invalid one, so it is supported uniformly rather than
  // singled out as an exception.
  const extras = computeFootingExtras(rawParams, unit, colShortMM, shortMM, cover, longMM, [longMM / 2]);

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
  // [Step 20] Unlike dowels/pedestal, `band` is drawn at EVERY column in
  // plan, not just `chosen` — both col1.off/col2.off are passed.
  const extras = computeFootingExtras(rawParams, unit, chosen.b, B, cover, L, [col1.off, col2.off]);

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
  // [Step 20] `band` is drawn at EVERY column in plan — every column's
  // own .off, not just `chosen`'s.
  const extras = computeFootingExtras(rawParams, unit, chosen.b, B, cover, L, columns.map((c) => c.off));

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
  // [Step 20] `band` is drawn at EVERY column in plan — every column's
  // own .offx (its L-axis position; a raft band is a strip across the
  // full B at that L position, same shape as combined/strip's own band,
  // not a 2-D patch around the column's .offy too — a raft column can
  // still need a locally concentrated CUT across the full width at its
  // own L position, which is what this draws).
  const extras = computeFootingExtras(rawParams, unit, chosen.b, B, cover, L, columns.map((c) => c.offx));

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
// [Step 21] combined/strip only (see DUAL_SECTION_TYPES below) — SECTION_BOX's
// footprint split into a larger left zone for the new primary longitudinal
// section and a smaller right zone for the pre-Step-21 section, kept as a
// secondary "side" view per direct request rather than dropped. Same total
// span as SECTION_BOX (540+20+240=800, x:80 to x:880) so the two-section
// layout lines up under PLAN_BOX exactly like the single-section layout did.
const LONG_SECTION_BOX = { x: 80, y: 420, w: 540, h: 240 };
const TRANS_SECTION_BOX = { x: 640, y: 420, w: 240, h: 240 };
// isolated: one column, no "span between columns" — a longitudinal section
// is not a distinct view from the transverse one. raft: a 2-D column grid —
// "the longitudinal section" is ambiguous (through which row?). Both keep
// the single pre-Step-21 section, unchanged. combined/strip: columns lie on
// one line, so "through the column line" is unambiguous, matching the
// Egyptian code guide's own قطاع رأس ١-١ (both columns + the span between).
const DUAL_SECTION_TYPES = new Set(['combined', 'strip']);

// [Step 21] Shared by renderPlanView's short-way (transverse) blocks AND
// the new renderLongSectionView's transverse-bar-as-circles blocks below —
// previously duplicated inline in renderPlanView for the bottom layer and
// again for the top-mesh layer; a third and fourth near-identical copy for
// the longitudinal section was the point at which "just copy it again"
// stopped being defensible. Pure function of the values every caller
// already has (plan.longMM, cover, a layer's own dia/spacing) — same
// floor(envelope/spacing)+1 rule computeMeshLayer/computeSectionGeometry
// already use, applied along L instead of across B/colWidth.
function computeTransverseXPositionsMM(longMM, coverMM, diaMM, spacingMM) {
  const env = longMM - 2 * coverMM - diaMM;
  const count = Math.max(2, Math.floor(env / spacingMM) + 1);
  const first = coverMM + diaMM / 2;
  const last = longMM - coverMM - diaMM / 2;
  const step = count > 1 ? (last - first) / (count - 1) : 0;
  return Array.from({ length: count }, (_, i) => (count === 1 ? longMM / 2 : first + i * step));
}
const MIN_BAR_PX_R = 3.2;      // bars stay legible even when geometry scales tiny
const MIN_STROKE_PX = 1.2;

// Types whose plan view carries more than one tagged column, and whose
// section view is therefore "through col<N>" rather than an unlabeled
// single cut. isolated has exactly one, unlabeled column and is
// deliberately excluded — there is nothing to disambiguate.
const NUMBERED_COLUMN_TYPES = new Set(['combined', 'strip', 'raft']);

// Local duplicates of structuralDrawingKit.mjs's esc/dimensionLine/
// hatchDefs — see this file's Step 17 header addendum for why. All three
// verified functionally identical to the kit's exported versions.
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function dimensionLine(x1, y1, x2, y2, label, opts = {}) {
  const orientation = opts.orientation || (Math.abs(x1 - x2) >= Math.abs(y1 - y2) ? 'h' : 'v');
  const tick = 6;
  const midX = (x1 + x2) / 2, midY = (y1 + y2) / 2;
  const labelDx = orientation === 'h' ? 0 : -10;
  const labelDy = orientation === 'h' ? -6 : 4;
  const anchor = orientation === 'h' ? 'middle' : 'end';
  return `
    <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="dim-line"/>
    <line x1="${x1}" y1="${y1 - tick}" x2="${x1}" y2="${y1 + tick}" class="dim-tick"/>
    <line x1="${x2}" y1="${y2 - tick}" x2="${x2}" y2="${y2 + tick}" class="dim-tick"/>
    <text x="${midX + labelDx}" y="${midY + labelDy}" text-anchor="${anchor}" class="dim-label">${esc(label)}</text>`;
}

function hatchDefs() {
  return `
    <pattern id="soilHatch" width="10" height="10" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <line x1="0" y1="0" x2="0" y2="10" stroke="#8a7350" stroke-width="1.4"/>
    </pattern>
    <pattern id="concreteHatch" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <line x1="0" y1="0" x2="0" y2="8" stroke="#9aa0a6" stroke-width="1"/>
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
  svg += `<rect x="${originX}" y="${originY}" width="${wPx}" height="${hPx}" class="footing-outline"/>`;

  // Reinforcement mesh — lines only in plan (real bar count/spacing, not
  // decorative): bars running the long way, spaced across the short
  // axis == geometry.section.barCentersMM (the same set the section view
  // draws as circles — one source of truth for that direction).
  for (const cMM of geometry.section.barCentersMM) {
    const y = originY + cMM * scale;
    svg += `<line x1="${originX + 2}" y1="${y}" x2="${originX + wPx - 2}" y2="${y}" class="mesh-line"/>`;
  }
  // Bars running the short way: spaced across the long axis at the same
  // nominal spacing (independent count derived the same way, but not the
  // section's job to track — computed inline here since it's plan-only).
  {
    const xs = computeTransverseXPositionsMM(plan.longMM, geometry.meta.cover, geometry.meta.dia, geometry.meta.spacingLong ?? geometry.meta.spacing);
    for (const posMM of xs) {
      const x = originX + posMM * scale;
      svg += `<line x1="${x}" y1="${originY + 2}" x2="${x}" y2="${originY + hPx - 2}" class="mesh-line"/>`;
    }
  }

  // [Step 20] Top mesh, both directions — the plan-view counterpart of
  // the section's existing top-mesh layer (Step 14.3). Only drawn when
  // `mesh` was supplied. Dashed + blue (.bar-top/.bar-dot-top, added to
  // this file's own <style> block below) rather than reusing .mesh-line:
  // in SECTION, position alone (inset from the top face) already tells
  // top from bottom apart, which is why Step 14.3 could reuse one color
  // there — but a top-down PLAN view has no position cue at all (top and
  // bottom bars project onto the exact same plane), so color/dash is the
  // only honest way to keep the two layers visually distinguishable here.
  // Long-way (top longitudinal) reuses geometry.mesh.barCentersMM
  // exactly as the bottom layer above reuses geometry.section's — one
  // source of truth per layer. Short-way (top transverse) is derived
  // inline the same way the bottom layer's own short-way block just did,
  // against geometry.mesh's own dia/spacing instead of geometry.meta's.
  if (geometry.mesh) {
    for (const cMM of geometry.mesh.barCentersMM) {
      const y = originY + cMM * scale;
      svg += `<line x1="${originX + 2}" y1="${y}" x2="${originX + wPx - 2}" y2="${y}" class="bar-top" stroke-dasharray="6,3"/>`;
    }
    const xs = computeTransverseXPositionsMM(plan.longMM, geometry.meta.cover, geometry.mesh.diaMM, geometry.mesh.spacingMM);
    for (const posMM of xs) {
      const x = originX + posMM * scale;
      svg += `<line x1="${x}" y1="${originY + 2}" x2="${x}" y2="${originY + hPx - 2}" class="bar-top" stroke-dasharray="6,3"/>`;
    }
  }

  // [Step 20] Concentration band(s) — ADDITIVE transverse bars inside
  // each column's own band zone, plus a dashed boundary marking the zone
  // itself (same visual device the pedestal footprint overlay above
  // already uses for "this outline marks an extent, not a poured edge").
  // Bold red (.band-outline/.mesh-line-band) rather than a new hue: this
  // is still bottom-family transverse steel, just concentrated — a new
  // color would visually suggest an unrelated element the way this kit's
  // other hues each do (green=ties, purple=wall-horizontal, teal=
  // movement-joint dowels — see structuralDrawingDxfKit.mjs's own LAYERS
  // comments), which concentrated bottom steel is not. See
  // computeBandGeometry's own header for why these bars are additive,
  // never a replacement for the field mesh drawn above.
  if (geometry.band) {
    for (const zone of geometry.band.zones) {
      const xStart = originX + zone.startMM * scale;
      const xEnd = originX + zone.endMM * scale;
      svg += `<rect x="${xStart}" y="${originY}" width="${xEnd - xStart}" height="${hPx}" class="band-outline"/>`;
      for (const cMM of zone.barCentersMM) {
        const x = originX + cMM * scale;
        svg += `<line x1="${x}" y1="${originY + 2}" x2="${x}" y2="${originY + hPx - 2}" class="mesh-line-band"/>`;
      }
    }
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
  // [Step 21] Second marker for the new PRIMARY longitudinal section —
  // horizontal, through the column centerline (B/2), spanning past both
  // edges the same way the vertical marker above spans past top/bottom.
  // Numeral '1', not a translated letter: digits are Latin-by-convention
  // regardless of `lang` throughout this file (same rule bar counts/
  // B=/L=/D=/cover= already follow), and a numeral cut label is exactly
  // what the Egyptian code guide's own قطاع رأس ١-١ uses for this type of
  // cut (a plane through a column LINE), as distinct from the lettered
  // A-A this file already uses for a plane through one column.
  if (DUAL_SECTION_TYPES.has(geometry.type)) {
    const cy = originY + hPx / 2;
    svg += `<line x1="${originX - 14}" y1="${cy}" x2="${originX + wPx + 14}" y2="${cy}" class="cut-line"/>`;
    svg += `<text x="${originX - 22}" y="${cy + 5}" text-anchor="middle" class="cut-label">1</text>`;
    svg += `<text x="${originX + wPx + 22}" y="${cy + 5}" text-anchor="middle" class="cut-label">1</text>`;
  }

  // Overall dimensions. [Step 20] A stacked second dimension line here
  // for the cover-inset ("reinforced-extent") measurement was tried and
  // rejected after actually rendering it: at any spacing tight enough to
  // fit this fixed-size plan box, the vertical pair's un-rotated text
  // labels overlapped almost completely, and the horizontal pair crowded
  // the sheet title on tall/narrow inputs. See renderFootingDiagramSVG's
  // caption assembly below for where that same information (طول/عرض
  // القاعدة المسلحة, matching the guide's own paired gross/net callout)
  // is reported instead — as text, using the caption's own wrapText
  // machinery, which already exists to solve exactly this class of
  // collision rather than introducing a second, competing solution here.
  svg += dimensionLine(originX, originY - 26, originX + wPx, originY - 26, `${plan.longLabel} = ${fmt(plan.longMM, geometry.unit, 2)}`, { orientation: 'h' });
  svg += dimensionLine(originX - 26, originY, originX - 26, originY + hPx, `${plan.shortLabel} = ${fmt(plan.shortMM, geometry.unit, 2)}`, { orientation: 'v' });

  svg += `<text x="${originX + wPx / 2}" y="${originY + hPx + 46}" text-anchor="middle" dir="${lang === 'ar' ? 'rtl' : 'ltr'}" class="view-title">${esc(translate('plan', lang))}</text>`;
  svg += `</g>`;
  return svg;
}

// Draws the vertical cut: soil hatch, footing body, the column/pedestal
// stack rising from the footing top (real-scale pedestal when supplied,
// else a fixed 90px decorative stub — see the Step 14.3 comment inline
// below for why that split exists), dowel circles at the footing-top
// interface when supplied, the bottom reinforcement layer (real
// count/spacing from computeSectionGeometry), the optional top mesh
// layer, and the depth/width/cover/bar-spec dimension callouts. Same
// schematic-not-photographic scope as renderPlanView above.
function renderSectionView(geometry, scale, lang, box = SECTION_BOX) {
  const { section } = geometry;
  const originX = box.x + (box.w - section.widthMM * scale) / 2;
  const baseY = box.y + box.h - 60; // leave room for soil hatch + labels below
  const topY = baseY - section.depthMM * scale;
  const wPx = section.widthMM * scale;

  let svg = `<g class="section-view">`;
  // Soil band under the footing
  svg += `<rect x="${originX - 20}" y="${baseY}" width="${wPx + 40}" height="26" fill="url(#soilHatch)" stroke="#8a7350" stroke-width="1"/>`;
  // Footing body
  svg += `<rect x="${originX}" y="${topY}" width="${wPx}" height="${section.depthMM * scale}" class="footing-outline" fill="url(#concreteHatch)"/>`;

  // [Step 14.3] Column/pedestal stack rising from the footing top.
  // Default (no pedestal): a single FIXED 90px decorative stub, exactly
  // as before Step 14 — it was never drawn to scale (this module is
  // never given a real column height), just a "the column continues
  // here" cue. When a pedestal IS supplied, its width/height are real
  // user inputs and ARE drawn to this section's real `scale`, with a
  // short fixed decorative stub above it so the stack still reads as
  // "column continues out of the pedestal" — see خطة_تجزئة_الخطوة_14.md
  // ("دمج البرمة مع رسم العمود المستمر"). Known, documented limitation:
  // PLAN_BOX/SECTION_BOX are fixed screen regions, not re-fitted around
  // pedestal height, so a pedestal tall relative to `scale` can visually
  // approach the plan view above — the same "representative, not a
  // layout solver" limitation this file already accepted for the fixed
  // 90px stub, now reachable by a much wider range of real inputs.
  const colW = section.colWidthMM * scale;
  const colX = originX + wPx / 2 - colW / 2;
  let colTop, dowelHostXPx, colSegBottomPx;
  if (geometry.pedestal) {
    const pedWPx = geometry.pedestal.widthMM * scale;
    const pedHPx = geometry.pedestal.heightMM * scale;
    const pedX = originX + wPx / 2 - pedWPx / 2;
    const pedTop = topY - pedHPx;
    svg += `<rect x="${pedX}" y="${pedTop}" width="${pedWPx}" height="${pedHPx}" class="column-outline" fill="url(#concreteHatch)"/>`;
    const stubH = 40; // fixed decorative "column continues" stub, same role the 90px default plays
    colTop = pedTop - stubH;
    svg += `<rect x="${colX}" y="${colTop}" width="${colW}" height="${pedTop - colTop}" class="column-outline" fill="url(#concreteHatch)"/>`;
    dowelHostXPx = pedX;
    colSegBottomPx = pedTop; // [Step 20] bottom edge of the drawn COLUMN segment (above the pedestal) — see the ties block below
  } else {
    colTop = topY - 90;
    svg += `<rect x="${colX}" y="${colTop}" width="${colW}" height="${topY - colTop}" class="column-outline" fill="url(#concreteHatch)"/>`;
    dowelHostXPx = colX;
    colSegBottomPx = topY; // [Step 20] no pedestal — the column segment runs straight down to the footing top
  }

  // [Step 20] Column ties: representative horizontal tie ticks across
  // the drawn COLUMN segment specifically (colTop..colSegBottomPx) —
  // never the pedestal segment, in either branch above. A pedestal
  // commonly ties differently from the column it carries (or not at
  // all, by design), and this tool has no input telling it which — the
  // column segment is the one member every combined/isolated/strip/raft
  // section always draws unambiguously, pedestal or not, so it is the
  // only one this schematic ties. `count` ticks are spread evenly across
  // whatever height is actually drawn here (real when geometry.pedestal
  // is absent and this is the full decorative stub, short when a
  // pedestal is present — see the file-level Step 14.3 comment on why
  // that stub itself is never to real scale) via this file's own
  // distributeCenters() — reused here for a PIXEL range exactly as it is
  // for MM ranges elsewhere in this file (the function is dimensionless
  // arithmetic; naming its destructured result tieYsPx, not the
  // function's own centersMM, keeps that reuse honest at the call site).
  if (geometry.ties) {
    const tieInsetPx = 8; // keep the outermost ticks off the column's own top/bottom edges
    const { centersMM: tieYsPx } = distributeCenters(colTop + tieInsetPx, colSegBottomPx - tieInsetPx, geometry.ties.count);
    for (const y of tieYsPx) {
      svg += tieTickH(colX, colX + colW, y);
    }
  }

  // [Step 14.3] Dowels: one representative row of circles at the
  // footing-top / column-or-pedestal-bottom interface (topY) — where
  // real dowels start and project upward, per خطة_تجزئة_الخطوة_14.md
  // ("dowels تُرسم كصف دوائر واحد ... عند أعلى القاعدة/أسفل البرمة").
  // dowels.centersMM are already relative to the DOWEL HOST's own width
  // envelope (computeDowelGeometry), so they map onto dowelHostXPx here
  // — NOT onto originX/wPx, which is the full footing width and would
  // misplace every dot when a pedestal narrower than the footing exists.
  if (geometry.dowels) {
    for (const cMM of geometry.dowels.centersMM) {
      const cx = dowelHostXPx + cMM * scale;
      svg += barDot(cx, topY, geometry.dowels.diaMM, scale, 'dowel');
    }
  }

  // Bottom reinforcement layer. The representative line is the TRANSVERSE
  // direction (this section's cut is perpendicular to L, so transverse
  // bars — running parallel to the cut plane — are seen in profile, one
  // representative line; longitudinal bars — pierced by the cut plane —
  // are seen end-on, as circles at their true across-B spacing).
  // [Bug fix, found via review against the reference drawing] The two
  // are two DIFFERENT bars crossing at that point, not one bar drawn
  // twice — they cannot occupy the same point. Convention adopted here
  // (documented, not derivable from these two reference images alone):
  // transverse sits closest to the face (the shorter-span direction,
  // conventionally placed outermost for maximum effective depth in that
  // direction); longitudinal sits one bar-radius further toward
  // mid-depth. The circles, not the line, move.
  const barY = baseY - section.coverMM * scale;
  svg += `<line x1="${originX + 8}" y1="${barY}" x2="${originX + wPx - 8}" y2="${barY}" class="mesh-line"/>`;
  const rPx = Math.max(MIN_BAR_PX_R, (section.diaMM / 2) * scale);
  const barDotY = barY - rPx; // toward mid-depth from the bottom face = smaller SVG y
  for (const cMM of section.barCentersMM) {
    svg += `<circle cx="${originX + cMM * scale}" cy="${barDotY}" r="${rPx}" class="bar-dot"/>`;
  }

  // [Step 14.3, restyled at Step 20] Independent top mesh layer
  // (interpretation A resolved in خطة_تجزئة_الخطوة_14.md's "سؤال مفتوح"
  // — see computeMeshLayer's own header). Originally reused the bottom
  // layer's .mesh-line/.bar-dot classes, distinguished only by POSITION
  // — safe while this layer was section-only, since position alone tells
  // top from bottom apart there. Step 20 gives this same layer a plan-
  // view presence too (renderPlanView above), where position carries NO
  // such information (a top-down view collapses top/bottom onto the same
  // plane) — so this section view is switched onto the SAME .bar-top/
  // .bar-dot-top classes the plan view now uses, for one consistent
  // color per layer across both views on one sheet, not two different
  // conventions for the same physical bars. Gated on geometry.mesh
  // exactly as before, so this is invisible whenever that extra is
  // absent.
  if (geometry.mesh) {
    const meshY = topY + section.coverMM * scale;
    svg += `<line x1="${originX + 8}" y1="${meshY}" x2="${originX + wPx - 8}" y2="${meshY}" class="bar-top"/>`;
    const rPxMesh = Math.max(MIN_BAR_PX_R, (geometry.mesh.diaMM / 2) * scale);
    const meshDotY = meshY + rPxMesh; // toward mid-depth from the top face = larger SVG y
    for (const cMM of geometry.mesh.barCentersMM) {
      svg += `<circle cx="${originX + cMM * scale}" cy="${meshDotY}" r="${rPxMesh}" class="bar-dot-top"/>`;
    }
  }

  // Dimensions: depth, width, cover, bar spec
  svg += dimensionLine(originX + wPx + 40, topY, originX + wPx + 40, baseY, `D = ${fmt(section.depthMM, geometry.unit, 2)}`, { orientation: 'v' });
  svg += dimensionLine(originX, baseY + 46, originX + wPx, baseY + 46, `${section.widthMM === geometry.meta.B ? 'B' : geometry.plan.shortLabel} = ${fmt(section.widthMM, geometry.unit, 2)}`, { orientation: 'h' });
  // Stacked on two centered lines, not left/right on one line — at
  // narrow widths (e.g. B=1200mm) same-line opposite-anchored labels
  // collide in the middle; found by rendering Case 2 in the test suite
  // and inspecting the PNG, not by inspection of the code alone.
  // [Step 21 fix — found by rendering at the new, much narrower
  // secondary-view scale, not visible at this function's original
  // single-large-box use] At TRANS_SECTION_BOX's width, text centered
  // under the footing runs into the D= dimension line's own text
  // (originX+wPx+40, right-anchored, extending leftward) — a collision
  // the primary (large) box never produced, so it is fixed only for the
  // secondary case rather than changing the look of the primary one.
  const isSecondary = box === TRANS_SECTION_BOX;
  const midX = originX + wPx / 2;
  if (isSecondary) {
    svg += `<text x="${originX + 4}" y="${barY - 26}" text-anchor="start" class="dim-label">cover = ${fmt(section.coverMM, geometry.unit, 0)}</text>`;
    svg += `<text x="${originX + 4}" y="${barY - 10}" text-anchor="start" class="dim-label">${section.barCount} \u00d8${fmt(section.diaMM, geometry.unit, 0)} @ ${fmt(section.actualSpacingMM, geometry.unit, 0)}</text>`;
  } else {
    svg += `<text x="${midX}" y="${barY - 26}" text-anchor="middle" class="dim-label">cover = ${fmt(section.coverMM, geometry.unit, 0)}</text>`;
    svg += `<text x="${midX}" y="${barY - 10}" text-anchor="middle" class="dim-label">${section.barCount} \u00d8${fmt(section.diaMM, geometry.unit, 0)} @ ${fmt(section.actualSpacingMM, geometry.unit, 0)}</text>`;
  }

  // [Step 21] Secondary context: the short label alone, not the
  // "through COLUMN X" detail — that combined string overflowed the
  // canvas at this box's width when actually rendered, and the plan's
  // own cut marker already identifies which column this cuts through,
  // so the detail is not lost, only moved to where there is room for it.
  const baseTitle = translatedSectionTitle(
    geometry.type,
    NUMBERED_COLUMN_TYPES.has(geometry.type) ? geometry.sectionThrough - 1 : null,
    lang,
  );
  const titleText = isSecondary ? translate('transverseSectionTitle', lang) : baseTitle;
  svg += `<text x="${originX + wPx / 2}" y="${baseY + 70}" text-anchor="middle" dir="${lang === 'ar' ? 'rtl' : 'ltr'}" class="view-title">${esc(titleText)}</text>`;
  svg += `</g>`;
  return svg;
}

// ── Step 21: primary longitudinal section (combined/strip only) ────────
// Cuts along the column line — through every column and the span between
// them — matching the Egyptian code guide's own قطاع رأس ١-١, which shows
// both columns together rather than one column in isolation. Shows L
// horizontally, D vertically.
//
// Bar roles are the OPPOSITE of renderSectionView's: this cut is
// perpendicular to B, not L, so TRANSVERSE bars (pierced by the cut) are
// the circles here, and LONGITUDINAL bars (running parallel to the cut,
// the length of the visible footing) are the representative line. Same
// physical stacking rule as renderSectionView's own fix (a real crossing
// layer cannot occupy the same point as the layer it crosses; transverse
// is the reference layer at the true cover distance, longitudinal shifts
// one bar-radius toward mid-depth) — only which element is "the circles"
// and which is "the line" has swapped along with which direction the cut
// exposes.
//
// Curtailment (top steel stopping short of mid-span, bottom steel lapped
// at supports — the real moment-diagram-driven detailing a computed
// design would show) is NOT modelled: neither reference image gives this
// tool a defensible length to curtail at, and both show the longitudinal
// bars running the full length uncurtailed — this draws the same. If a
// real design calls for curtailment, that is a design output this
// schematic cannot honestly infer from B/L/D/cover/dia/spacing alone.
//
// Column ties/dowels/pedestal: this tool has ONE global spec for each
// (not per-column), so every column in `plan.columns` gets the SAME
// pedestal/tie/dowel treatment — the same simplification dia/spacing/
// cover already make for the whole footing.
function renderLongSectionView(geometry, scale, lang, box) {
  const { plan, meta } = geometry;
  const wPx = plan.longMM * scale;
  const originX = box.x + (box.w - wPx) / 2;
  const baseY = box.y + box.h - 60;
  const topY = baseY - meta.D * scale;
  const depthPx = meta.D * scale;

  let svg = '<g class="long-section-view">';
  svg += `<rect x="${originX - 20}" y="${baseY}" width="${wPx + 40}" height="26" fill="url(#soilHatch)" stroke="#8a7350" stroke-width="1"/>`;
  svg += `<rect x="${originX}" y="${topY}" width="${wPx}" height="${depthPx}" class="footing-outline" fill="url(#concreteHatch)"/>`;

  // One column stack per geometry.plan.columns entry — see this
  // function's own header on why every column shares one pedestal/tie/
  // dowel spec. colSegBottomPx/dowelHostXPx/colTop mirror
  // renderSectionView's own single-column version exactly, just inside
  // a per-column loop and positioned at each column's own centerLongMM
  // instead of the box's horizontal center.
  plan.columns.forEach((col, i) => {
    const colW = col.alongLongMM * scale;
    const cx = originX + col.centerLongMM * scale;
    const colX = cx - colW / 2;
    let colTop, dowelHostXPx, colSegBottomPx, colTopMostPx;
    if (geometry.pedestal) {
      const pedWPx = geometry.pedestal.widthMM * scale;
      const pedHPx = geometry.pedestal.heightMM * scale;
      const pedX = cx - pedWPx / 2;
      const pedTop = topY - pedHPx;
      svg += `<rect x="${pedX}" y="${pedTop}" width="${pedWPx}" height="${pedHPx}" class="column-outline" fill="url(#concreteHatch)"/>`;
      const stubH = 40;
      colTop = pedTop - stubH;
      svg += `<rect x="${colX}" y="${colTop}" width="${colW}" height="${pedTop - colTop}" class="column-outline" fill="url(#concreteHatch)"/>`;
      dowelHostXPx = pedX;
      colSegBottomPx = pedTop;
      colTopMostPx = colTop;
    } else {
      colTop = topY - 90;
      svg += `<rect x="${colX}" y="${colTop}" width="${colW}" height="${topY - colTop}" class="column-outline" fill="url(#concreteHatch)"/>`;
      dowelHostXPx = colX;
      colSegBottomPx = topY;
      colTopMostPx = colTop;
    }
    if (geometry.ties) {
      const tieInsetPx = 8;
      const { centersMM: tieYsPx } = distributeCenters(colTop + tieInsetPx, colSegBottomPx - tieInsetPx, geometry.ties.count);
      for (const y of tieYsPx) svg += tieTickH(colX, colX + colW, y);
    }
    if (geometry.dowels) {
      for (const cMM of geometry.dowels.centersMM) {
        svg += barDot(dowelHostXPx + cMM * scale, topY, geometry.dowels.diaMM, scale, 'dowel');
      }
    }
    if (col.tag) {
      const label = columnTag(geometry.type, i, lang);
      svg += `<text x="${cx}" y="${colTopMostPx - 8}" text-anchor="middle" dir="${lang === 'ar' ? 'rtl' : 'ltr'}" class="col-tag">${esc(label)}</text>`;
    }
  });

  // Bottom layer: transverse bars (circles) at true cover; longitudinal
  // bar (line) shifted toward mid-depth. Reuses the SAME across-L x
  // positions renderPlanView's own bottom short-way block computes —
  // one source of truth (computeTransverseXPositionsMM) for where a
  // transverse bar sits along L, drawn as a plan-view line there and as
  // a section-view circle here.
  const transYBottom = baseY - meta.cover * scale;
  const rPx = Math.max(MIN_BAR_PX_R, (meta.dia / 2) * scale);
  const longYBottom = transYBottom - rPx;
  svg += `<line x1="${originX + 8}" y1="${longYBottom}" x2="${originX + wPx - 8}" y2="${longYBottom}" class="mesh-line"/>`;
  const transXsBottom = computeTransverseXPositionsMM(plan.longMM, meta.cover, meta.dia, meta.spacingLong ?? meta.spacing);
  for (const posMM of transXsBottom) {
    svg += `<circle cx="${originX + posMM * scale}" cy="${transYBottom}" r="${rPx}" class="bar-dot"/>`;
  }
  // [Step 21] Concentration band — denser transverse circles inside each
  // column's own zone, additive to the field circles just drawn (same
  // additive-not-replacing convention as the plan view's own band
  // overlay; see computeBandGeometry's header). Same Y as the field
  // transverse circles: band bars are still transverse bars, just more
  // of them near the column, not a different layer.
  if (geometry.band) {
    const rBandPx = Math.max(MIN_BAR_PX_R, (geometry.band.diaMM / 2) * scale);
    for (const zone of geometry.band.zones) {
      for (const cMM of zone.barCentersMM) {
        svg += `<circle cx="${originX + cMM * scale}" cy="${transYBottom}" r="${rBandPx}" class="bar-dot-band"/>`;
      }
    }
  }

  // Top layer, mirrored — only when `mesh` was supplied.
  if (geometry.mesh) {
    const transYTop = topY + meta.cover * scale;
    const rPxMesh = Math.max(MIN_BAR_PX_R, (geometry.mesh.diaMM / 2) * scale);
    const longYTop = transYTop + rPxMesh;
    svg += `<line x1="${originX + 8}" y1="${longYTop}" x2="${originX + wPx - 8}" y2="${longYTop}" class="bar-top"/>`;
    const transXsTop = computeTransverseXPositionsMM(plan.longMM, meta.cover, geometry.mesh.diaMM, geometry.mesh.spacingMM);
    for (const posMM of transXsTop) {
      svg += `<circle cx="${originX + posMM * scale}" cy="${transYTop}" r="${rPxMesh}" class="bar-dot-top"/>`;
    }
  }

  svg += dimensionLine(originX, topY - 26, originX + wPx, topY - 26, `${plan.longLabel} = ${fmt(plan.longMM, geometry.unit, 2)}`, { orientation: 'h' });
  svg += dimensionLine(originX + wPx + 40, topY, originX + wPx + 40, baseY, `D = ${fmt(meta.D, geometry.unit, 2)}`, { orientation: 'v' });
  const midX = originX + wPx / 2;
  svg += `<text x="${midX}" y="${transYBottom + rPx + 20}" text-anchor="middle" class="dim-label">cover = ${fmt(meta.cover, geometry.unit, 0)}</text>`;

  const titleText = translate('longitudinalSectionTitle', lang);
  svg += `<text x="${originX + wPx / 2}" y="${baseY + 70}" text-anchor="middle" dir="${lang === 'ar' ? 'rtl' : 'ltr'}" class="view-title">${esc(titleText)}</text>`;
  svg += '</g>';
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
  const isDual = DUAL_SECTION_TYPES.has(geometry.type);
  // [Step 21] combined/strip: the plan and the new PRIMARY longitudinal
  // section both show L, so they share one scale (a reader should be
  // able to see the two views are the same length) computed against
  // LONG_SECTION_BOX instead of the old single SECTION_BOX. The
  // secondary transverse section gets its OWN independent, smaller
  // scale fit to TRANS_SECTION_BOX — a smaller side/detail view is
  // expected to use its own scale, same as a detail callout on a real
  // drawing sheet would. isolated/raft: unchanged, one box, one scale,
  // exactly as before Step 21.
  const scale = Math.min(
    PLAN_BOX.w / geometry.plan.longMM,
    PLAN_BOX.h / geometry.plan.shortMM,
    (isDual ? LONG_SECTION_BOX.w : SECTION_BOX.w) / (isDual ? geometry.plan.longMM : geometry.section.widthMM),
    ((isDual ? LONG_SECTION_BOX.h : SECTION_BOX.h) - 60) / geometry.meta.D,
  ) * 0.85;
  const transScale = isDual
    ? Math.min(
      TRANS_SECTION_BOX.w / geometry.section.widthMM,
      (TRANS_SECTION_BOX.h - 60) / geometry.meta.D,
    ) * 0.85
    : scale;

  const title = footingTitle(geometry.type, lang);

  // [Step 14.3] Workshop table + dynamic canvas height, ONLY when the
  // caller supplied at least one of pedestal/dowels/mesh/ties/band. With
  // none of the five, canvasH/tableSvg/captionBottomY below reduce to
  // exactly CANVAS.h / '' / CANVAS.h-20 — the pre-Step-14 output,
  // unchanged pixel-for-pixel. This conditional-only-when-needed approach
  // is the backward-compatibility strategy خطة_تجزئة_الخطوة_14.md's point
  // 5 calls for (no existing test pins an exact viewBox number, so this
  // is safe, but keeping the no-extras path byte-identical removes any
  // risk of an untested silent visual regression on the common case).
  // [Step 20] ties/band added to the same gate: both are opt-in extras
  // exactly like pedestal/dowels/mesh, so they belong in the identical
  // hasExtras umbrella rather than a second, parallel condition.
  const hasExtras = !!(geometry.pedestal || geometry.dowels || geometry.mesh || geometry.ties || geometry.band);
  // [Step 20] Caption moved below hasExtras (was previously computed
  // before it existed) so the extras legend can be appended here, in one
  // place, rather than the caller having to know to check hasExtras
  // itself before choosing which caption string to use. The gross/net
  // extent note is built here, not as a static structuralLabels.mjs
  // string, because the two numbers are per-diagram (renderPlanView's
  // own plan.longMM/shortMM and geometry.meta.cover) — reinforcedExtentNote
  // supplies only the constant label text around them. Latin digits/
  // "mm"/"=" mixed into this scriptFontStack (.sheet-caption) text node
  // are safe in 'ar' mode: this file's Arabic-safety rule bans only
  // '(', ')', '–', '—' (see structuralLabels.mjs's own header), not
  // digits or "=" — unlike the abandoned drawn-dimension approach, which
  // was rejected for a LAYOUT collision, not a glyph one.
  let caption = translate('captionComputed', lang);
  if (hasExtras) {
    const netLongMM = geometry.plan.longMM - 2 * geometry.meta.cover;
    const netShortMM = geometry.plan.shortMM - 2 * geometry.meta.cover;
    const unit = geometry.unit;
    caption += ` ${translate('captionExtrasLegend', lang)} ${translate('reinforcedExtentNote', lang)}: `
      + `${geometry.plan.longLabel}=${fmt(netLongMM, unit, 0)}, ${geometry.plan.shortLabel}=${fmt(netShortMM, unit, 0)}.`;
  }
  let canvasH = CANVAS.h;
  let tableSvg = '';
  let captionBottomY = CANVAS.h - 20;

  if (hasExtras) {
    const unit = geometry.unit;
    const volumeM3 = (geometry.meta.B / 1000) * (geometry.meta.L / 1000) * (geometry.meta.D / 1000);
    // [Step 14.2 decision — see structuralLabels.mjs's own header] ONE
    // summary row, one dedicated column per optional field, blank cell
    // ('—') when that field's group is absent — not a multi-row
    // schedule like beamDiagram.mjs's bar list. Decided during 14.2
    // [Step 20 revision — found by rendering the actual SVG at 1600px:
    // all twelve original-plus-new columns summed to 1600px against a
    // 960px canvas and ran off the sheet edge, something none of the
    // earlier string-content tests could catch since they never measured
    // pixel width. Split into two stacked one-row tables instead of one
    // wide one: the original six columns unchanged (still 880px, same
    // as every pre-Step-20 render), and a second, new six-column row
    // for ties/band beneath it. Each is independently centered via its
    // own totalW, so neither depends on the other's width.]
    const cols1 = [
      { key: 'dowelCount', label: translate('dowelCount', lang), width: 120 },
      { key: 'dowelDia', label: translate('dowelDia', lang), width: 110 },
      { key: 'dowelProjection', label: translate('dowelProjection', lang), width: 150 },
      { key: 'meshDia', label: translate('meshDia', lang), width: 110 },
      { key: 'meshSpacing', label: translate('meshSpacing', lang), width: 140 },
      { key: 'concreteVolume', label: translate('concreteVolume', lang), width: 250 },
    ];
    // [Step 20] tieCount/tieDia/tieSpacing/bandWidth/bandDia/bandSpacing
    // — band's zones can differ per column (different actualSpacingMM at
    // each, from computeBandGeometry's own per-zone distributeCenters
    // call), so its three cells report the BAND SPEC (widthMM/diaMM/
    // nominal spacingMM, shared by every zone by this function's own
    // one-spec-for-every-column design — see computeBandGeometry's own
    // header), not a per-zone breakdown a one-row table has no room for.
    // Column widths sized generously against this table's own longest
    // header ("Band Bar Spacing"/17 chars), not copied from table 1's
    // shorter headers, after table 1's own widths turned out too tight
    // for that string in the same rendering pass that found the
    // 12-column overflow above.
    const cols2 = [
      { key: 'tieCount', label: translate('tieCount', lang), width: 110 },
      { key: 'tieDia', label: translate('tieDia', lang), width: 100 },
      { key: 'tieSpacing', label: translate('tieSpacing', lang), width: 140 },
      { key: 'bandWidth', label: translate('bandWidth', lang), width: 140 },
      { key: 'bandDia', label: translate('bandDia', lang), width: 130 },
      { key: 'bandSpacing', label: translate('bandSpacing', lang), width: 160 },
    ];
    // Engineering notation (Ø, mm-derived numbers, m³) is Latin+digits
    // by convention regardless of `lang` (same rule this file already
    // applies to B=/D=/cover=) — no column here sets script:true, so
    // scheduleTable() renders every data cell with .table-text
    // (defaultFontStack), only the translated HEADER labels get
    // .table-header-txt (scriptFontStack).
    const row1 = {
      dowelCount: geometry.dowels ? String(geometry.dowels.count) : '\u2014',
      dowelDia: geometry.dowels ? `\u00d8${fmt(geometry.dowels.diaMM, unit, 0)}` : '\u2014',
      dowelProjection: geometry.dowels ? fmt(geometry.dowels.projectionMM, unit, 0) : '\u2014',
      meshDia: geometry.mesh ? `\u00d8${fmt(geometry.mesh.diaMM, unit, 0)}` : '\u2014',
      meshSpacing: geometry.mesh ? fmt(geometry.mesh.actualSpacingMM, unit, 0) : '\u2014',
      concreteVolume: `${volumeM3.toFixed(2)} m\u00b3`,
    };
    const row2 = {
      tieCount: geometry.ties ? String(geometry.ties.count) : '\u2014',
      tieDia: geometry.ties ? `\u00d8${fmt(geometry.ties.diaMM, unit, 0)}` : '\u2014',
      tieSpacing: geometry.ties ? fmt(geometry.ties.spacingMM, unit, 0) : '\u2014',
      bandWidth: geometry.band ? fmt(geometry.band.widthMM, unit, 0) : '\u2014',
      bandDia: geometry.band ? `\u00d8${fmt(geometry.band.diaMM, unit, 0)}` : '\u2014',
      bandSpacing: geometry.band ? fmt(geometry.band.spacingMM, unit, 0) : '\u2014',
    };
    const table1X = (CANVAS.w - cols1.reduce((s, c) => s + c.width, 0)) / 2;
    const tableY = SECTION_BOX.y + SECTION_BOX.h + 40;
    const table1 = scheduleTable(table1X, tableY, cols1, [row1], { lang });
    const table2Y = tableY + table1.height + 14;
    const table2X = (CANVAS.w - cols2.reduce((s, c) => s + c.width, 0)) / 2;
    const table2 = scheduleTable(table2X, table2Y, cols2, [row2], { lang });
    const tableBottomEdge = table2Y + table2.height;
    tableSvg = `
  <line x1="${PLAN_BOX.x}" y1="${tableY - 20}" x2="${PLAN_BOX.x + PLAN_BOX.w}" y2="${tableY - 20}" stroke="#ccc" stroke-width="1"/>
  ${table1.svg}
  ${table2.svg}`;
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
    // [Step 20] tableBottomEdge (this table's own stacked-pair bottom,
    // computed above) replaces the single table's tableY+table.height —
    // same anchor-from-the-bottom-edge strategy, now measured against
    // whichever of the two stacked tables actually ends up lower.
    {
      const capMarginPx = 24;
      const numLines = wrapText(caption, 100).length;
      captionBottomY = tableBottomEdge + capMarginPx + (numLines - 1) * 16;
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
  // [Step 20] .stirrup-tick/.bar-top/.bar-dot-top below are, likewise,
  // copied verbatim from kitStyleBlock() (same #2f7a3d / #1f5aa6 hex
  // values that file already uses for every other element's ties/top-
  // steel) — not new colors invented for this file. .band-outline/
  // .mesh-line-band have no kit precedent (no other element needs a
  // "concentrated sub-layer of an existing layer" style) and are defined
  // fresh here, deliberately kept in the SAME #c0392b red family as
  // .mesh-line/.bar-dot — see renderPlanView's own comment on why a new
  // hue would be the wrong call for this specific case. All five are
  // harmless to always emit, unused whenever their extra is absent.
  return `<svg viewBox="0 0 ${CANVAS.w} ${canvasH}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>
    text { font-family: ${defaultFontStack}; }
    .footing-outline { fill:#f4f4f4; stroke:#1a1a1a; stroke-width:${MIN_STROKE_PX * 1.4}; }
    .column-outline  { fill:#e2e2e2; stroke:#1a1a1a; stroke-width:${MIN_STROKE_PX * 1.4}; }
    .mesh-line       { stroke:#c0392b; stroke-width:${MIN_STROKE_PX}; }
    .bar-dot         { fill:#c0392b; stroke:#7a2015; stroke-width:0.6; }
    .dim-line        { stroke:#333; stroke-width:1; }
    .dim-tick        { stroke:#333; stroke-width:1; }
    .dim-label       { font-size:15px; fill:#111; }
    .view-title      { font-size:16px; font-weight:bold; fill:#111; letter-spacing:${lang === 'ar' ? 'normal' : '1px'}; font-family: ${scriptFontStack}; }
    .cut-line        { stroke:#1a1a1a; stroke-width:1.4; stroke-dasharray:6,3; }
    .cut-label       { font-size:14px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .col-tag         { font-size:12px; fill:#333; font-family: ${scriptFontStack}; }
    .sheet-title     { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .sheet-caption   { font-size:12.5px; fill:#444; font-family: ${scriptFontStack}; }
    .bar-dot-dowel    { fill:#c0392b; stroke:#7a2015; stroke-width:0.6; }
    .stirrup-tick     { stroke:#2f7a3d; stroke-width:1.3; }
    .bar-top          { stroke:#1f5aa6; stroke-width:2.2; fill:none; }
    .bar-dot-top      { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }
    .band-outline     { fill:none; stroke:#c0392b; stroke-width:1; stroke-dasharray:5,3; }
    .mesh-line-band   { stroke:#c0392b; stroke-width:2.4; }
    .bar-dot-band     { fill:#c0392b; stroke:#7a2015; stroke-width:1; }
    .table-header-bg  { fill:#eef1f4; }
    .table-border     { stroke:#888; stroke-width:1; fill:none; }
    .table-text       { font-size:12px; fill:#111; font-family: ${defaultFontStack}; }
    .table-text-script{ font-size:12px; fill:#111; font-family: ${scriptFontStack}; }
    .table-header-txt { font-size:12px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
  </style>
  <rect x="0" y="0" width="${CANVAS.w}" height="${canvasH}" fill="#ffffff"/>
  <text x="${CANVAS.w / 2}" y="30" text-anchor="middle" class="sheet-title" dir="${lang === 'ar' ? 'rtl' : 'ltr'}">${esc(title)}</text>
  ${renderPlanView(geometry, scale, lang)}
  ${isDual ? renderLongSectionView(geometry, scale, lang, LONG_SECTION_BOX) : ''}
  ${isDual ? renderSectionView(geometry, transScale, lang, TRANS_SECTION_BOX) : renderSectionView(geometry, scale, lang)}
  <line x1="${PLAN_BOX.x}" y1="${SECTION_BOX.y - 30}" x2="${PLAN_BOX.x + PLAN_BOX.w}" y2="${SECTION_BOX.y - 30}" stroke="#ccc" stroke-width="1"/>${tableSvg}
  ${renderCaption(caption, lang, captionBottomY)}
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
function renderCaption(caption, lang, bottomAnchorY = CANVAS.h - 20) {
  const lines = wrapText(caption, 100);
  const rtl = lang === 'ar';
  const x = rtl ? CANVAS.w - 40 : 40;
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
//     [Step 20 optional] tiedia=8 tiespacing=150 tiecount=4 — column
//     confinement ties, drawn on whichever column-segment stub the
//     section shows (see computeFootingExtras' own comment on why these
//     three are label-only; positions are distributed at render time).
//     bandwidth=800 banddia=12 bandspacing=100 — reinforcement
//     concentration band(s), one drawn centered on EVERY column in plan
//     (see computeBandGeometry's own header on why width has no default
//     and must always be given explicitly).
//   /diagram strip B=900 L=7500 D=450 cols=3 col1b=350 col1l=350 col1off=750 col2b=350 col2l=350 col2off=3750 col3b=350 col3l=350 col3off=6750 cover=50 dia=14 spacing=150 [unit=mm] [sectionthrough=2]
//   /diagram raft B=6000 L=9000 D=500 cols=4 col1b=400 col1l=400 col1offx=1000 col1offy=1000 col2b=400 col2l=400 col2offx=1000 col2offy=5000 col3b=400 col3l=400 col3offx=5000 col3offy=1000 col4b=400 col4l=400 col4offx=5000 col4offy=5000 cover=75 dia=16 spacing=200 [unit=mm] [sectionthrough=1]
// strip/raft additionally require cols=N (2..MAX_COLUMNS) up front, then
// col1.. through colN.. of the fields shown above — colNoff for strip
// (1-D, distance along L), colNoffx/colNoffy for raft (2-D, distance
// along L / along B respectively).
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
  // [Step 20] Same flat-key convention, two more groups: tiedia=/
  // tiespacing=/tiecount= and bandwidth=/banddia=/bandspacing=.
  const ties = optionalGroup({ dia: 'tiedia', spacing: 'tiespacing', count: 'tiecount' });
  const band = optionalGroup({ width: 'bandwidth', dia: 'banddia', spacing: 'bandspacing' });

  try {
    let geometry;
    if (type === 'isolated') {
      geometry = computeIsolatedFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        colB: num('colb'), colL: num('coll'),
        cover: num('cover'), dia: num('dia'),
        spacing: num('spacing'), spacingLong: num('spacinglong'), spacingShort: num('spacingshort'),
        unit: kv.unit || 'mm',
        pedestal, dowels, meshSpacing, meshDia, ties, band,
      });
    } else if (type === 'combined') {
      geometry = computeCombinedFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        col1: { b: num('col1b'), l: num('col1l'), off: num('col1off') },
        col2: { b: num('col2b'), l: num('col2l'), off: num('col2off') },
        cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
        sectionThrough: num('sectionthrough') === 2 ? 2 : 1,
        unit: kv.unit || 'mm',
        pedestal, dowels, meshSpacing, meshDia, ties, band,
      });
    } else if (type === 'strip') {
      const st = num('sectionthrough');
      geometry = computeStripFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        columns: collectColumns(['b', 'l', 'off']),
        cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
        sectionThrough: Number.isFinite(st) ? st : 1,
        unit: kv.unit || 'mm',
        pedestal, dowels, meshSpacing, meshDia, ties, band,
      });
    } else if (type === 'raft') {
      const st = num('sectionthrough');
      geometry = computeRaftFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        columns: collectColumns(['b', 'l', 'offx', 'offy']),
        cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
        sectionThrough: Number.isFinite(st) ? st : 1,
        unit: kv.unit || 'mm',
        pedestal, dowels, meshSpacing, meshDia, ties, band,
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
