// functions/_lib/beamDiagram.mjs
//
// Deterministic, zero-AI SVG generator for beam reinforcement details
// (elevation + cross-sections + bar-bending schedule) — same philosophy
// as footingDiagram.mjs: every dimension, bar position, and count in the
// output is arithmetic on the KB data supplied, never a model's guess.
// This is the "actual drawing" half of the split the KB-data effort
// implies: this module owns compute+render only; it does not decide bar
// counts, spacing, or curtailment points — that is the KB/design layer's
// job (see the INPUT CONTRACT below, which is exactly the shape the KB
// layer should emit).
//
// SCOPE (v1): a single prismatic span sequence (constant b×h along the
// whole member) with top/bottom longitudinal bar GROUPS (each valid
// across an [startX,endX] extent and stacked by `layer`) and stirrup
// ZONES (each with its own leg count/spacing across an extent). This
// covers the ordinary case — most beams in a schedule ARE prismatic —
// and is the same kind of explicit, named scope boundary
// footingDiagram.mjs's own header uses ("STILL NOT MODELED, on
// purpose"). NOT modeled, on purpose, because each needs a
// parametrization this module hasn't been given yet: haunched/tapered
// depth, bent-up (cranked) bars, splice/lap zone markers, and
// code-specific cutting-length math (development length, hook
// allowance, lap length — all fy/fcu/bar-condition/code-dependent).
// That last one is the important boundary, not an oversight: this
// module reports a bar's drawn EXTENT (endX-startX) as its length,
// clearly labeled "(extent)", UNLESS the caller supplies an explicit
// `cuttingLengthMM` — it never invents a development/hook/lap length
// from a formula this module wasn't given the code/material inputs for.
// That is exactly the "never render a number you can't stand behind"
// rule imageGen.mjs's own header documents fixing for the diffusion
// path, applied here to arithmetic instead of pixels: a wrong cutting
// length on a shop drawing is a fabrication defect, not a cosmetic bug.
//
// ── INPUT CONTRACT (what the KB layer should hand this module) ─────────
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   id: string,                        // beam mark, e.g. "B1"
//   section: { b: number, h: number }, // constant cross-section
//   cover: number,                     // concrete cover to stirrup outer face
//   totalLength: number,
//   supports: [                        // >=1, columns/walls/free ends along the beam
//     { x: number, width: number, type?: 'column'|'wall'|'end', label?: string }
//   ],
//   longitudinalBars: [                // >=1, each a group of identical bars
//     {
//       markId?: string,               // defaults to array index+1
//       face: 'top'|'bottom',
//       dia: number, count: number,    // bar diameter, how many in this group
//       layer?: number,                // 1 = closest to face (default 1)
//       startX: number, endX: number,  // extent along the beam this group covers
//       shapeCode?: string,            // free-text bend/shape note (not drawn as geometry — see scope note)
//       cuttingLengthMM?: number,      // full cutting length INCLUDING hooks/dev/lap,
//                                      // if the KB layer has already computed it —
//                                      // omit to show extent-only, honestly labeled
//     }, ...
//   ],
//   stirrupZones: [                    // >=1, tiling (non-overlapping) zones
//     { markId?: string, dia: number, legs: number, spacing: number, startX: number, endX: number, cuttingLengthMM?: number }, ...
//   ],
//   sections?: [ { x: number, label?: string }, ... ], // which cuts to draw;
//                                      // defaults to one near the first support
//                                      // face (hogging) + one at midspan (sagging)
// }
//
// Resource lifecycle: this module is pure/synchronous — no timers, no
// fetch, no KV, no external handles of any kind. All caps below
// (MAX_SUPPORTS etc.) exist to bound Worker CPU time and output size on
// a request-scoped isolate, not to manage a leakable resource.
//
// Step 17: fully deterministic — no `env.AI`, no model call, no network
// fetch, no randomness anywhere in this file (rebarDiagram mode or
// beamWorkshop mode). Every SVG byte is arithmetic on
// computeBeamDiagramGeometry's output (plus computeBeamWorkshopExtras'
// for beamWorkshop mode); see structuralDrawingKit.mjs's header for the
// general "drawn extent vs. actual cut length" rule this file's
// cuttingLengthMM handling (above) and lapZones handling (below) both
// follow.
//
// Step 23: this module now exports parseDiagramCommand(text), wiring
// beam into the flat-text /diagram command family alongside footing/
// slab/shearWall/stair/column (see diagramCommandRouter.mjs). Steps 21
// and 22 both stated this schema "needs a materially larger flat-text
// grammar than the single-group schemas this pattern was designed for" —
// true, but beamAsciiToPayload.mjs's group-indexed grammar (built in
// Step 22 for the /rebar path) already IS that larger grammar. Step 23
// does not invent a new one: it strips the leading `beam` token this
// family's convention requires, hands the remainder to
// parseBeamAsciiCommand unchanged, then feeds the resulting payload
// through the existing, untouched parseBeamRebarPayload — the exact same
// compute path every JSON /rebar caller already uses. No compute/render
// logic in this file changed for this step.
// Same BAD_SYNTAX/UNSUPPORTED_TYPE split as every sibling
// parseDiagramCommand: BAD_SYNTAX = no leading-token+params shape at all;
// UNSUPPORTED_TYPE = shape present but leading token isn't "beam" — lets
// diagramCommandRouter.mjs try the next module without masking a real
// error. Unlike the /rebar path (which falls back to JSON.parse on a
// BAD_SYNTAX from parseBeamAsciiCommand), /diagram has no JSON fallback —
// once the leading token is confirmed "beam", any ascii-parser failure
// (BAD_SYNTAX or BAD_TOKEN) is a real, terminal error here, reported with
// `type:'beam'` attached, matching slab/shearWall/stairDiagram.mjs's own
// error-shape convention (footingDiagram.mjs's original parseDiagramCommand
// predates that convention and still omits type on error).

import {
  DiagramError, toMm, fromMm, assertFinitePositive, assertFiniteNonNegative,
  assertInt, assertOneOf, assertNoIntervalOverlap, esc, captionLineCount,
  renderCaptionAt, fontStacks, kitStyleBlock, hatchDefs, dimensionLine, barDot,
  stirrupTick, distributeTicks, barMarkTag, fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';
import { parseBeamAsciiCommand } from './beamAsciiToPayload.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ──────────────────────────────────────────────────────
// Same role as footingDiagram.mjs's MAX_COLUMNS: this is a chat-driven
// schematic tool, not a CAD system: bound worst-case loop counts so one
// request can't build an oversized SVG or blow a CPU-time budget — a
// Cloudflare Worker isolate is killed past ~10ms of actual CPU time, and
// every cap below is sized so the corresponding compute+render pass
// stays well under that regardless of what a chat user types (see the
// "Max-load smoke test" in each test_*.mjs file, which asserts an actual
// measured elapsed-ms figure against this, not just a byte-size check).
const MAX_SUPPORTS = 10;
const MAX_BAR_GROUPS = 24;
const MAX_STIRRUP_ZONES = 16;
const MAX_SECTIONS = 6;
const MAX_LAYER = 4;
const MAX_DRAWN_TIES_PER_ZONE = 20;
const MIN_BEAM_LENGTH_MM = 300;
const MAX_BEAM_LENGTH_MM = 60000; // 60m — a schematic past this needs a real drafting tool

// Step 16 (beamWorkshop mode) additions. Same CPU/output-size-bounding
// role as the caps above, not a physical/design limit.
const MAX_LAP_ZONES = 6;
const MAX_WORKSHOP_SECTIONS = 6; // combined base+extra sections DRAWN in beamWorkshop mode — matches MAX_SECTIONS so the section-row layout math (SECTION_SIZE/SECTION_GAP) stays within the same bounded worst case the rebarDiagram path already assumes
const MODES = ['rebarDiagram', 'beamWorkshop'];

const FACES = ['top', 'bottom'];

// ── Compute ──────────────────────────────────────────────────────────
// Input: a raw KB-layer object matching the INPUT CONTRACT above (mixed
// units allowed per-field via `unit`, converted internally to mm).
// Formula: validates every field (throwing DiagramError('BAD_PARAM' /
// a more specific code on the first violation found, never silently
// clamping or defaulting a caller-supplied bad value), converts all
// lengths to mm via toMm(), derives each longitudinal-bar group's drawn
// depth (yFromTopMM) from a global per-(face,layer) map so elevation and
// every cross section agree on where a group sits, and — when the caller
// didn't supply explicit `sections` — picks two representative cut
// locations (near the first support face, and midspan).
// Output: a frozen-shape geometry object ({type:'beam', ...}) that is
// the sole input renderBeamDiagramSVG/renderBeamWorkshopSVG/
// computeBeamWorkshopExtras ever read from — no render function reaches
// back into `raw`.
export function computeBeamDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Beam diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.id != null ? String(raw.id).slice(0, 40) : 'BEAM';

  if (!raw.section || typeof raw.section !== 'object') {
    throw new DiagramError('BAD_PARAM', '"section" is required: { b, h }.');
  }
  const b = toMm(raw.section.b, unit);
  const h = toMm(raw.section.h, unit);
  assertFinitePositive('section.b', b);
  assertFinitePositive('section.h', h);

  const cover = toMm(raw.cover, unit);
  assertFinitePositive('cover', cover);
  if (2 * cover >= Math.min(b, h)) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${cover}mm) leaves no room for reinforcement inside a ${b}x${h}mm section.`);
  }

  const totalLength = toMm(raw.totalLength, unit);
  assertFinitePositive('totalLength', totalLength);
  if (totalLength < MIN_BEAM_LENGTH_MM || totalLength > MAX_BEAM_LENGTH_MM) {
    throw new DiagramError('BAD_PARAM', `"totalLength" must be between ${MIN_BEAM_LENGTH_MM}mm and ${MAX_BEAM_LENGTH_MM}mm for this schematic, got ${totalLength}mm.`);
  }

  if (!Array.isArray(raw.supports) || raw.supports.length < 1) {
    throw new DiagramError('BAD_PARAM', '"supports" must be a non-empty array of { x, width, type? }.');
  }
  if (raw.supports.length > MAX_SUPPORTS) {
    throw new DiagramError('TOO_MANY_SUPPORTS', `At most ${MAX_SUPPORTS} supports are supported in this schematic, got ${raw.supports.length}.`);
  }
  const supports = raw.supports
    .map((s, i) => {
      const x = toMm(s.x, unit);
      const width = toMm(s.width, unit);
      assertFiniteNonNegative(`supports[${i}].x`, x);
      assertFinitePositive(`supports[${i}].width`, width);
      const type = s.type || 'column';
      assertOneOf(`supports[${i}].type`, type, ['column', 'wall', 'end']);
      // Only the CENTERLINE must lie within the beam's length — a
      // support's drawn width is expected to extend past x=0/totalLength
      // at the two end supports (a beam's length is conventionally
      // measured centerline-to-centerline of its end columns, so the
      // column itself straddles that centerline and oversteps the
      // beam's nominal ends). This is the opposite relationship from
      // footingDiagram.mjs's COLUMN_TOO_WIDE check, where the column
      // must sit entirely inside the footing it bears on — copying that
      // containment rule verbatim here would reject the ordinary case.
      if (x < -1e-6 || x > totalLength + 1e-6) {
        throw new DiagramError('SUPPORT_OUT_OF_BOUNDS', `supports[${i}] centerline (x=${fromMm(x, unit)}${unit}) is outside the beam's 0..${fromMm(totalLength, unit)}${unit} length.`);
      }
      return { x, width, type, label: s.label != null ? String(s.label).slice(0, 20) : null };
    })
    .sort((a, c) => a.x - c.x);
  assertNoIntervalOverlap(
    supports.map((s) => ({ startMM: s.x - s.width / 2, endMM: s.x + s.width / 2 })),
    { label: 'supports' },
  );

  if (!Array.isArray(raw.longitudinalBars) || raw.longitudinalBars.length < 1) {
    throw new DiagramError('BAD_PARAM', '"longitudinalBars" must be a non-empty array.');
  }
  if (raw.longitudinalBars.length > MAX_BAR_GROUPS) {
    throw new DiagramError('TOO_MANY_BAR_GROUPS', `At most ${MAX_BAR_GROUPS} longitudinal bar groups are supported, got ${raw.longitudinalBars.length}.`);
  }
  const longitudinalBars = raw.longitudinalBars.map((g, i) => {
    const tag = `longitudinalBars[${i}]`;
    if (!g || typeof g !== 'object') throw new DiagramError('BAD_PARAM', `${tag} must be an object.`);
    assertOneOf(`${tag}.face`, g.face, FACES);
    const dia = toMm(g.dia, unit);
    assertFinitePositive(`${tag}.dia`, dia);
    assertInt(`${tag}.count`, g.count, { min: 1, max: 30 });
    const layer = g.layer ?? 1;
    assertInt(`${tag}.layer`, layer, { min: 1, max: MAX_LAYER });
    const startX = toMm(g.startX, unit);
    const endX = toMm(g.endX, unit);
    assertFiniteNonNegative(`${tag}.startX`, startX);
    assertFinitePositive(`${tag}.endX`, endX);
    if (endX <= startX) throw new DiagramError('BAD_PARAM', `${tag}: endX must be greater than startX.`);
    if (startX < -1e-6 || endX > totalLength + 1e-6) {
      throw new DiagramError('BAR_OUT_OF_BOUNDS', `${tag} [${fromMm(startX, unit)}, ${fromMm(endX, unit)}]${unit} extends outside the beam's 0..${fromMm(totalLength, unit)}${unit} length.`);
    }
    const cuttingLengthMM = g.cuttingLengthMM != null ? toMm(g.cuttingLengthMM, unit) : null;
    if (cuttingLengthMM != null) assertFinitePositive(`${tag}.cuttingLengthMM`, cuttingLengthMM);
    return {
      markId: g.markId != null ? String(g.markId).slice(0, 10) : String(i + 1),
      face: g.face, dia, count: g.count, layer, startX, endX,
      shapeCode: g.shapeCode ? String(g.shapeCode).slice(0, 40) : null,
      cuttingLengthMM,
    };
  });

  if (!Array.isArray(raw.stirrupZones) || raw.stirrupZones.length < 1) {
    throw new DiagramError('BAD_PARAM', '"stirrupZones" must be a non-empty array.');
  }
  if (raw.stirrupZones.length > MAX_STIRRUP_ZONES) {
    throw new DiagramError('TOO_MANY_ZONES', `At most ${MAX_STIRRUP_ZONES} stirrup zones are supported, got ${raw.stirrupZones.length}.`);
  }
  const stirrupZones = raw.stirrupZones.map((z, i) => {
    const tag = `stirrupZones[${i}]`;
    if (!z || typeof z !== 'object') throw new DiagramError('BAD_PARAM', `${tag} must be an object.`);
    const dia = toMm(z.dia, unit);
    assertFinitePositive(`${tag}.dia`, dia);
    assertInt(`${tag}.legs`, z.legs, { min: 2, max: 8 });
    const spacing = toMm(z.spacing, unit);
    assertFinitePositive(`${tag}.spacing`, spacing);
    const startX = toMm(z.startX, unit);
    const endX = toMm(z.endX, unit);
    assertFiniteNonNegative(`${tag}.startX`, startX);
    assertFinitePositive(`${tag}.endX`, endX);
    if (endX <= startX) throw new DiagramError('BAD_PARAM', `${tag}: endX must be greater than startX.`);
    if (startX < -1e-6 || endX > totalLength + 1e-6) {
      throw new DiagramError('ZONE_OUT_OF_BOUNDS', `${tag} [${fromMm(startX, unit)}, ${fromMm(endX, unit)}]${unit} extends outside the beam's 0..${fromMm(totalLength, unit)}${unit} length.`);
    }
    const cuttingLengthMM = z.cuttingLengthMM != null ? toMm(z.cuttingLengthMM, unit) : null;
    if (cuttingLengthMM != null) assertFinitePositive(`${tag}.cuttingLengthMM`, cuttingLengthMM);
    // Additive field (Step 16 / beamWorkshop): open (U-shape, e.g. where
    // top steel must be threaded in after the stirrup is set) vs closed
    // (fully wrapped rectangular) stirrup. Defaults to 'closed', which is
    // exactly what every zone rendered before this field existed, so
    // rebarDiagram-mode output (and every existing test's expectations)
    // is byte-for-byte unaffected — this is display metadata beamWorkshop
    // mode reads, rebarDiagram mode never looks at it.
    const shape = z.shape || 'closed';
    assertOneOf(`${tag}.shape`, shape, ['closed', 'open']);
    return {
      markId: z.markId != null ? String(z.markId).slice(0, 10) : `St${i + 1}`,
      dia, legs: z.legs, spacing, startX, endX, cuttingLengthMM, shape,
    };
  });
  assertNoIntervalOverlap(stirrupZones.map((z) => ({ startMM: z.startX, endMM: z.endX })), { label: 'stirrup zones' });

  // Additive (Step 16 / beamWorkshop): explicit lap-splice zones. Same
  // "never invent a code-dependent length" boundary this file's header
  // already draws around cuttingLengthMM — a lap zone's extent is a
  // development-length/code calculation this module has no fy/fcu/bar-
  // condition inputs for, so it is only ever DRAWN here, never computed;
  // the KB/design layer must supply startX/endX explicitly, same as it
  // must supply cuttingLengthMM if it wants an exact (not "(extent)")
  // length shown. Optional and empty by default — every existing caller
  // that never sends "lapZones" gets geometry.lapZones = [] and no
  // change to rebarDiagram-mode output.
  let lapZones = [];
  if (raw.lapZones != null) {
    if (!Array.isArray(raw.lapZones)) {
      throw new DiagramError('BAD_PARAM', '"lapZones" must be an array when provided.');
    }
    if (raw.lapZones.length > MAX_LAP_ZONES) {
      throw new DiagramError('TOO_MANY_LAP_ZONES', `At most ${MAX_LAP_ZONES} lap zones are supported, got ${raw.lapZones.length}.`);
    }
    lapZones = raw.lapZones
      .map((z, i) => {
        const tag = `lapZones[${i}]`;
        if (!z || typeof z !== 'object') throw new DiagramError('BAD_PARAM', `${tag} must be an object.`);
        const startX = toMm(z.startX, unit);
        const endX = toMm(z.endX, unit);
        assertFiniteNonNegative(`${tag}.startX`, startX);
        assertFinitePositive(`${tag}.endX`, endX);
        if (endX <= startX) throw new DiagramError('BAD_PARAM', `${tag}: endX must be greater than startX.`);
        if (startX < -1e-6 || endX > totalLength + 1e-6) {
          throw new DiagramError('LAP_ZONE_OUT_OF_BOUNDS', `${tag} [${fromMm(startX, unit)}, ${fromMm(endX, unit)}]${unit} extends outside the beam's 0..${fromMm(totalLength, unit)}${unit} length.`);
        }
        return {
          markRef: z.markRef != null ? String(z.markRef).slice(0, 10) : null,
          startX, endX,
          note: z.note ? String(z.note).slice(0, 60) : null,
        };
      })
      .sort((a, c) => a.startX - c.startX);
    // Lap zones are allowed to overlap bar groups and stirrup zones (a
    // lap sits ON a longitudinal bar's own extent, not beside it) — only
    // two lap zones claiming the same stretch of beam is a genuine data
    // contradiction, so only lapZones-vs-lapZones is checked, deliberately
    // NOT unioned with the stirrup-zone overlap check above.
    assertNoIntervalOverlap(lapZones.map((z) => ({ startMM: z.startX, endMM: z.endX })), { label: 'lap zones' });
  }

  // Global per-(face,layer) depth map — computed ONCE across every
  // longitudinal group regardless of its x-extent, so a group's line in
  // the elevation view lines up exactly with its dot in every cross
  // section that includes it, instead of each view independently
  // guessing a depth.
  const layerDepth = new Map();
  for (const face of FACES) {
    const layers = [...new Set(longitudinalBars.filter((g) => g.face === face).map((g) => g.layer))].sort((x, y) => x - y);
    let depthFromFaceMM = cover;
    for (const layer of layers) {
      const groups = longitudinalBars.filter((g) => g.face === face && g.layer === layer);
      const maxDia = Math.max(...groups.map((g) => g.dia));
      const yFromFaceMM = depthFromFaceMM + maxDia / 2;
      const yFromTopMM = face === 'top' ? yFromFaceMM : h - yFromFaceMM;
      layerDepth.set(`${face}:${layer}`, { yFromTopMM, maxDia });
      depthFromFaceMM += maxDia * 2.2; // clear gap to next layer — wide enough that stacked layers sharing an X position (common: outer bars of a smaller and larger group both sit at the envelope edge) stay visually separated at typical schematic scale
    }
  }
  for (const g of longitudinalBars) {
    g.yFromTopMM = layerDepth.get(`${g.face}:${g.layer}`).yFromTopMM;
  }

  let sectionDefs = raw.sections;
  if (!Array.isArray(sectionDefs) || sectionDefs.length === 0) {
    const firstFace = supports[0].x + supports[0].width / 2;
    sectionDefs = [
      { x: fromMm(Math.min(firstFace + Math.min(150, totalLength * 0.05), totalLength * 0.3), unit), label: '1-1' },
      { x: fromMm(totalLength / 2, unit), label: '2-2' },
    ];
  }
  if (sectionDefs.length > MAX_SECTIONS) {
    throw new DiagramError('TOO_MANY_SECTIONS', `At most ${MAX_SECTIONS} cross-sections are supported, got ${sectionDefs.length}.`);
  }
  const sections = sectionDefs.map((s, i) => {
    if (!s || typeof s !== 'object') throw new DiagramError('BAD_PARAM', `sections[${i}] must be an object.`);
    const x = toMm(s.x, unit);
    if (x < -1e-6 || x > totalLength + 1e-6) {
      throw new DiagramError('SECTION_OUT_OF_BOUNDS', `sections[${i}] x=${fromMm(x, unit)}${unit} is outside the beam's 0..${fromMm(totalLength, unit)}${unit} length.`);
    }
    const activeBars = longitudinalBars.filter((g) => g.startX <= x + 1e-6 && g.endX >= x - 1e-6);
    return {
      x, label: s.label ? String(s.label).slice(0, 20) : `${i + 1}-${i + 1}`,
      bars: layoutSectionBars(activeBars, b, cover),
    };
  });

  return { type: 'beam', unit, id, section: { b, h }, cover, totalLength, supports, longitudinalBars, stirrupZones, sections, lapZones };
}

// Distributes the bars ACTIVE at one cut evenly across the section width
// per (face,layer) group — same "distribute evenly, report what was
// drawn" principle as footingDiagram.mjs's computeSectionGeometry, using
// the depth already fixed by the global layerDepth map above (see its
// comment for why depth is global but x-position is per-section).
function layoutSectionBars(activeBars, bMM, coverMM) {
  const placed = [];
  for (const face of FACES) {
    const faceBars = activeBars.filter((g) => g.face === face);
    const layers = [...new Set(faceBars.map((g) => g.layer))];
    for (const layer of layers) {
      const groups = faceBars.filter((g) => g.layer === layer);
      const maxDia = Math.max(...groups.map((g) => g.dia));
      const totalCount = groups.reduce((s, g) => s + g.count, 0);
      const envelope = bMM - 2 * coverMM - maxDia;
      const step = totalCount > 1 ? envelope / (totalCount - 1) : 0;
      let idx = 0;
      for (const g of groups) {
        for (let k = 0; k < g.count; k++) {
          const xMM = totalCount === 1 ? bMM / 2 : coverMM + maxDia / 2 + idx * step;
          placed.push({ face, layer, markId: g.markId, dia: g.dia, xMM, yFromTopMM: g.yFromTopMM });
          idx++;
        }
      }
    }
  }
  return placed;
}

// ── Workshop-mode derived data (Step 16) ────────────────────────────────
// Everything below is DERIVED presentation data for "beamWorkshop" mode
// only. It never changes a single mm/count/length value already computed
// by computeBeamDiagramGeometry above — it only re-orders/re-labels the
// SAME groups for a shop drawing. Two conventions are applied here, both
// documented because they are workshop CONVENTIONS this module chooses to
// apply, not measured facts the caller supplied — same honesty bar as the
// rest of this file, applied to an ordering/labeling choice instead of a
// physical quantity:
//
//   1. INSTALL SEQUENCE: bottom longitudinal groups go in first (they
//      rest on chairs/formwork), ordered along the beam by startX; then
//      stirrup zones, ordered by startX (threaded over the bottom
//      steel); then top longitudinal groups, ordered by startX (dropped
//      in last, through the open stirrups, then stirrups slid to final
//      spacing and tied). This is the ordinary RC beam fixing sequence
//      used on site — it is a documented convention this module applies,
//      not a fact derived from the input, and a real site may reorder it
//      around access/hook/lap constraints this module has no visibility
//      into. The workshop caption says so explicitly (see L.*.workshopCaption).
//   2. SHAPE LETTER: one letter per DISTINCT shape signature, assigned in
//      first-appearance order (bottom bars, top bars, then stirrups —
//      the same enumeration buildWorkshopScheduleRows uses, so the
//      letter column reads top-to-bottom in the same row order as the
//      table). Signature is face+shapeCode for longitudinal groups (two
//      groups sharing an explicit shapeCode share a letter; groups with
//      no shapeCode are all "straight" and share one letter) and
//      open/closed for stirrup zones. This is a CROSS-REFERENCE label
//      only — per this file's SCOPE note this module does not draw bend
//      geometry, so the letter identifies "same shape as row X", not a
//      specific bend pictogram.
export function computeBeamWorkshopExtras(geometry) {
  const { longitudinalBars, stirrupZones, lapZones, totalLength } = geometry;

  const bottomBars = longitudinalBars.filter((g) => g.face === 'bottom').slice().sort((a, b) => a.startX - b.startX);
  const topBars = longitudinalBars.filter((g) => g.face === 'top').slice().sort((a, b) => a.startX - b.startX);
  const stirrupsByX = stirrupZones.slice().sort((a, b) => a.startX - b.startX);

  const installSequence = [];
  let seq = 1;
  for (const g of bottomBars) installSequence.push({ kind: 'bar', ref: g.markId, order: seq++ });
  for (const z of stirrupsByX) installSequence.push({ kind: 'stirrup', ref: z.markId, order: seq++ });
  for (const g of topBars) installSequence.push({ kind: 'bar', ref: g.markId, order: seq++ });
  const barSeq = new Map(installSequence.filter((s) => s.kind === 'bar').map((s) => [s.ref, s.order]));
  const stirrupSeq = new Map(installSequence.filter((s) => s.kind === 'stirrup').map((s) => [s.ref, s.order]));

  const letterOf = new Map(); // signature -> letter
  let nextLetterCode = 65; // 'A'
  function letterFor(signature) {
    if (!letterOf.has(signature)) {
      // 26 distinct shape signatures already exceeds any realistic mix
      // under MAX_BAR_GROUPS+MAX_STIRRUP_ZONES; Z1, Z2... is an honest
      // overflow label rather than silently wrapping back to 'A' and
      // colliding two different shapes onto one letter.
      letterOf.set(signature, nextLetterCode > 90 ? `Z${nextLetterCode - 90}` : String.fromCharCode(nextLetterCode));
      nextLetterCode++;
    }
    return letterOf.get(signature);
  }
  const barShape = new Map(longitudinalBars.map((g) => [g.markId, letterFor(`bar:${g.face}:${g.shapeCode || 'straight'}`)]));
  const stirrupShape = new Map(stirrupZones.map((z) => [z.markId, letterFor(`stirrup:${z.shape}`)]));

  // Extra section-cut candidates: lap-zone boundaries are ALWAYS kept
  // (a lap zone is safety-critical to show regardless of whether bar
  // count happens to change there); bar-count-change candidates are
  // filtered to GENUINE changes only, verified by sampling the active
  // bar count 1mm before and 1mm after each candidate x — a group ending
  // exactly where an identical one begins is NOT a count change and must
  // not generate a redundant cut; only checking "a group edge exists
  // here" (without this sampling step) would over-generate sections.
  // The two candidate kinds are tracked separately and merged AFTER
  // filtering, not filtered together, so the count-change test is never
  // applied to a lap boundary it was never meant to gate.
  const lapCandidates = new Set();
  for (const z of lapZones) {
    if (z.startX > 1e-6 && z.startX < totalLength - 1e-6) lapCandidates.add(Math.round(z.startX));
    if (z.endX > 1e-6 && z.endX < totalLength - 1e-6) lapCandidates.add(Math.round(z.endX));
  }
  const countChangeCandidates = new Set();
  for (const g of longitudinalBars) {
    if (g.startX > 1e-6 && g.startX < totalLength - 1e-6) countChangeCandidates.add(Math.round(g.startX));
    if (g.endX > 1e-6 && g.endX < totalLength - 1e-6) countChangeCandidates.add(Math.round(g.endX));
  }
  const activeCountAt = (x) => longitudinalBars
    .filter((g) => g.startX <= x + 1e-6 && g.endX >= x - 1e-6)
    .reduce((s, g) => s + g.count, 0);
  const dedupe = (xs) => {
    const sorted = [...xs].sort((a, b) => a - b);
    const out = [];
    for (const x of sorted) {
      if (out.length === 0 || x - out[out.length - 1] > 20) out.push(x); // collapse near-duplicates (<20mm apart) into one cut
    }
    return out;
  };
  const lapX = dedupe(lapCandidates);
  const countChangeX = dedupe(countChangeCandidates).filter((x) => activeCountAt(x - 1) !== activeCountAt(x + 1));
  // Final merge: lap points first (priority), then genuine count-change
  // points not already within 20mm of a kept lap point.
  const extraSectionX = [...lapX];
  for (const x of countChangeX) {
    if (!extraSectionX.some((kx) => Math.abs(kx - x) <= 20)) extraSectionX.push(x);
  }
  extraSectionX.sort((a, b) => a - b);

  return { installSequence, barSeq, stirrupSeq, barShape, stirrupShape, extraSectionX };
}

// Combines geometry.sections (the base rebarDiagram cut list) with the
// verified extraSectionX candidates above into the final list of section
// boxes beamWorkshop mode draws, deduplicated (a candidate within 15mm of
// an already-kept x is dropped, not redrawn) and capped at
// MAX_WORKSHOP_SECTIONS total — base sections and lap-zone boundaries are
// kept ahead of plain count-change points in that priority order, since a
// lap zone is the safety-critical one to always show if something has to
// be dropped by the cap.
export function computeWorkshopSections(geometry, extras) {
  const { section, cover, longitudinalBars, lapZones } = geometry;
  const lapX = new Set();
  for (const z of lapZones) { lapX.add(Math.round(z.startX)); lapX.add(Math.round(z.endX)); }

  const kept = geometry.sections.map((s) => ({ x: s.x, label: s.label, kind: 'base', bars: s.bars }));
  const keptX = () => kept.map((s) => s.x);
  const tryAdd = (x, kind) => {
    if (keptX().some((kx) => Math.abs(kx - x) <= 15)) return;
    if (kept.length >= MAX_WORKSHOP_SECTIONS) return;
    const activeBars = longitudinalBars.filter((g) => g.startX <= x + 1e-6 && g.endX >= x - 1e-6);
    kept.push({ x, label: `S${kept.length + 1}`, kind, bars: layoutSectionBars(activeBars, section.b, cover) });
  };
  for (const x of extras.extraSectionX.filter((x) => lapX.has(x))) tryAdd(x, 'lap');
  for (const x of extras.extraSectionX.filter((x) => !lapX.has(x))) tryAdd(x, 'count');

  return kept.sort((a, b) => a.x - b.x);
}

// Single source of truth for how far below the beam's own bottom edge
// (beamY+beamH) renderWorkshopElevation's fixed-offset rows extend —
// zoneRowY itself (+70), then either the overall-length dimension line
// (+34 past zoneRowY) or, when lap zones exist, the lap-zone label row
// instead (+50 past zoneRowY, further down than the length line).
// renderBeamWorkshopSVG calls this BEFORE calling renderWorkshopElevation
// to size sectionsY with guaranteed clearance — extracted here instead
// of duplicating the 70/50/34 literals in both places, which is exactly
// how two independently-computed Y offsets drift out of sync (see the
// zoneRowY clearance fix a few lines below this comment in
// renderWorkshopElevation, and the handoff prompt's own lesson on this
// class of bug).
function workshopElevationExtrasBottomOffset(hasLapZones) {
  const zoneRowOffset = 70;
  const lengthDimOffset = 34;
  const lapLabelOffset = 50;
  return zoneRowOffset + (hasLapZones ? lapLabelOffset : lengthDimOffset);
}

// U-shape (open) stirrup tick — two vertical legs + a bottom cap, no top
// cap, so it visually reads as open where beamDiagram.mjs's existing
// stirrupTick (imported from structuralDrawingKit.mjs, capped top+bottom)
// reads as a closed rectangle. Local to this file rather than exported
// from the kit: this is a beamWorkshop-specific display distinction, not
// a primitive the footing/column modules have any use for.
function stirrupTickOpen(xPx, yTopPx, yBottomPx) {
  const cap = 4;
  return `
    <line x1="${xPx}" y1="${yTopPx}" x2="${xPx}" y2="${yBottomPx}" class="stirrup-tick"/>
    <line x1="${xPx - cap}" y1="${yBottomPx}" x2="${xPx + cap}" y2="${yBottomPx}" class="stirrup-tick"/>`;
}

// ── Labels ───────────────────────────────────────────────────────────
const L = {
  en: {
    title: (id) => `BEAM ${id} \u2014 REINFORCEMENT DETAIL`,
    elevation: 'ELEVATION', sectionWord: 'SECTION',
    top: 'Top', bottom: 'Bottom', stirrupWord: 'Stirrup',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    extentSuffix: ' (extent)',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design (ECP 203 / ACI 318) before issuing for construction. Lengths marked "(extent)" are drawn span length only; add development / hook / lap length per your design code.',
    dirAttr: 'ltr',
    // Step 16 (beamWorkshop mode) additions — additive keys only, nothing
    // above this line is touched.
    workshopTitle: (id) => `BEAM ${id} \u2014 SHOP DRAWING`,
    installSeq: 'Install Seq.', shape: 'Shape', notes: 'Notes',
    stirrupClosed: 'Closed stirrup', stirrupOpen: 'Open (U) stirrup',
    lapZoneWord: 'Lap Splice Zone', lapZoneCol: 'Lap Zone',
    noteBottomBar: 'Place on chairs first',
    noteTopBar: 'Place last, through stirrups',
    noteStirrupClosed: 'Thread over bottom steel before placing top bars',
    noteStirrupOpen: 'Place open, close with top bar/cap per detail',
    noteLapZone: 'Verify lap length against your design code',
    workshopColSeq: 'Seq', workshopColMark: 'Mark', workshopColShape: 'Shape',
    workshopColElement: 'Element', workshopColDia: 'dia (mm)', workshopColCount: 'Count / Spacing',
    workshopColLength: 'Length (mm)', workshopColNotes: 'Install Notes',
    workshopExtentSuffix: ' (extent)',
    workshopCaption: 'Shop/workshop drawing: sequential bar numbers, a fixing-order convention (bottom bars \u2192 stirrups \u2192 top bars), and install notes below are a general RC fixing-practice convention this tool applies for readability \u2014 they are not a project-specific method statement. Verify against your own design and site sequencing before fabrication. The "Shape" column is a cross-reference label only (rows sharing a letter share the same bend pattern); this tool does not draw bend/pictogram geometry.',
    extraSectionLabel: 'extra section',
  },
  ar: {
    title: (id) => `تفريد حديد الكمرة ${id}`,
    elevation: 'منظور جانبي', sectionWord: 'قطاع',
    top: 'علوي', bottom: 'سفلي', stirrupWord: 'كانة',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر (مم)', colCount: 'العدد / التباعد', colLength: 'الطول (مم)',
    extentSuffix: ' (امتداد)',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة — راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص (ECP 203 / ACI 318) قبل الاعتماد للتنفيذ. الأطوال المُعلَّمة "(امتداد)" هي طول الامتداد فقط؛ أضف طول الرباط/الكلبتين/التداخل حسب الكود المستخدم.',
    dirAttr: 'rtl',
    // Step 16 additions. Unlike the pre-existing caption/extentSuffix
    // strings just above (left untouched — out of scope, see the
    // handoff prompt's lesson on not silently repeating this file's
    // known parenthesis/em-dash issue while also not fixing unrelated
    // pre-existing text this session wasn't asked to touch), every NEW
    // Arabic string added below is written parenthesis- and dash-free,
    // following columnDiagram.mjs's verified-safe convention.
    workshopTitle: (id) => `ورشة تفريد حديد الكمرة ${id}`,
    installSeq: 'تسلسل التركيب', shape: 'رمز الشكل', notes: 'ملاحظات',
    stirrupClosed: 'كانة مغلقة', stirrupOpen: 'كانة مفتوحة',
    lapZoneWord: 'منطقة تداخل التسليح', lapZoneCol: 'منطقة تداخل',
    noteBottomBar: 'يوضع على الكراسي أولاً',
    noteTopBar: 'يوضع أخيراً عبر الكانات',
    noteStirrupClosed: 'يُمرَّر فوق الحديد السفلي قبل وضع العلوي',
    noteStirrupOpen: 'يُركَّب مفتوحاً ثم يُغلق بسيخ غطاء حسب التفصيلة',
    noteLapZone: 'تحقق من طول التداخل وفق الكود المستخدم',
    workshopColSeq: 'رقم', workshopColMark: 'العلامة', workshopColShape: 'الشكل',
    workshopColElement: 'النوع', workshopColDia: 'القطر مم', workshopColCount: 'العدد أو التباعد',
    workshopColLength: 'الطول مم', workshopColNotes: 'ملاحظات التركيب',
    // Deliberately NOT reusing the pre-existing "extentSuffix" above
    // (' (امتداد)', parenthesized) for this session's NEW workshop rows —
    // see the parenthesis/em-dash warning at the top of the L.ar block.
    // This is a fresh, safe (no parens/dash) key instead.
    workshopExtentSuffix: ' امتداد',
    workshopCaption: 'رسم ورشة: الأرقام التسلسلية للأسياخ وتسلسل التركيب المقترح من السفلي إلى الكانات إلى العلوي وملاحظات التركيب أدناه هي عرف تنفيذي عام يطبقه هذا الأداة لتسهيل القراءة، وليست بياناً تنفيذياً خاصاً بمشروعك. راجعها وفق تصميمك وترتيب التنفيذ الفعلي في الموقع قبل التصنيع. عمود الشكل مرجع مقارنة فقط، الصفوف التي تشترك في نفس الرمز تشترك في نفس نمط الانحناء، هذه الأداة لا ترسم شكل الانحناء نفسه.',
    extraSectionLabel: 'قطاع إضافي',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 1100;
const ELEV_BOX = { x: 60, y: 130, w: CANVAS_W - 120, h: 130 };
const SECTION_SIZE = 190;
const SECTION_GAP = 40;
const TIE_MAX_SPAN_PX = ELEV_BOX.h; // reserved for readability, not used as a magic number elsewhere

export function renderBeamDiagramSVG(geometry, opts = {}) {
  const mode = opts.mode || 'rebarDiagram';
  assertOneOf('mode', mode, MODES);
  if (mode === 'beamWorkshop') return renderBeamWorkshopSVG(geometry, opts);

  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);
  const { b, h } = geometry.section;

  const scale = fitScale([{ contentW: geometry.totalLength, contentH: h * 2.4, boxW: ELEV_BOX.w, boxH: ELEV_BOX.h }]);
  const beamW = geometry.totalLength * scale;
  const beamH = h * scale;
  const beamX = ELEV_BOX.x + (ELEV_BOX.w - beamW) / 2;
  const beamY = ELEV_BOX.y + (ELEV_BOX.h - beamH) / 2;

  const sectionScale = fitScale([{ contentW: b, contentH: h, boxW: SECTION_SIZE - 50, boxH: SECTION_SIZE - 70 }]);
  const sectionsRowW = geometry.sections.length * SECTION_SIZE + (geometry.sections.length - 1) * SECTION_GAP;
  const sectionsX0 = (CANVAS_W - sectionsRowW) / 2;
  const sectionsY = beamY + beamH + 130;

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = sectionsY + SECTION_SIZE + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .beam-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .zone-label { font-size:10.5px; fill:#2f7a3d; font-family: ${defaultFontStack}; }
    .support-label { font-size:11px; fill:#333; font-family: ${defaultFontStack}; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="beam-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderElevation(geometry, scale, beamX, beamY, beamW, beamH, l)}
  ${renderSections(geometry, sectionScale, sectionsX0, sectionsY, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// Draws the beam's side view (rebarDiagram mode): support hatching, the
// concrete outline, one line per longitudinal-bar GROUP (not one line per
// individual bar — a group's count is conveyed by its mark-tag label, "Ø
// dia-count", not by drawing `count` separate lines) at its computed
// depth, representative stirrup ticks per zone (see distributeTicks —
// capped, not one tick per real stirrup), and the overall length
// dimension. This is a schematic elevation, not a to-scale shop drawing:
// bar diameter/spacing is exaggerated relative to beam length wherever
// the true ratio would make a mark unreadable, by construction of the
// `scale` this function is handed (see fitScale's own header).
function renderElevation(geometry, scale, beamX, beamY, beamW, beamH, l) {
  const { totalLength, supports, longitudinalBars, stirrupZones, cover } = geometry;
  let svg = `<g class="elevation">`;
  svg += `<text x="${beamX + beamW / 2}" y="${beamY - 46}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.elevation)}</text>`;

  // Supports — drawn first so the beam outline + bars sit visually on top
  const supportTopY = beamY - 34, supportBotY = beamY + beamH + 34;
  const supportPxRanges = supports.map((s) => {
    const cx = beamX + s.x * scale;
    const w = Math.max(s.width * scale, 14);
    return { lo: cx - w / 2, hi: cx + w / 2 };
  });
  supports.forEach((s, i) => {
    const { lo, hi } = supportPxRanges[i];
    svg += `<rect x="${lo}" y="${supportTopY}" width="${hi - lo}" height="${supportBotY - supportTopY}" class="support-outline" fill="url(#concreteHatch)"/>`;
    const label = s.label || (s.type === 'wall' ? 'W' : 'S') + (i + 1);
    svg += `<text x="${(lo + hi) / 2}" y="${supportBotY + 14}" text-anchor="middle" class="support-label">${esc(label)}</text>`;
  });

  // Beam concrete outline
  svg += `<rect x="${beamX}" y="${beamY}" width="${beamW}" height="${beamH}" class="concrete-outline"/>`;

  // Longitudinal bar lines + mark tags. A group whose midpoint falls on
  // an interior support is the ORDINARY case for negative-moment top
  // steel (it is typically centered exactly on the support it resists
  // moment over) — not an edge case to ignore. Push the tag clear of
  // that support's hatch instead of letting it render on top of it.
  for (const g of longitudinalBars) {
    const x1 = beamX + g.startX * scale, x2 = beamX + g.endX * scale;
    const y = beamY + g.yFromTopMM * scale;
    svg += `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" class="bar-${g.face}"/>`;
    let tagX = (x1 + x2) / 2;
    const collided = supportPxRanges.find((r) => tagX >= r.lo && tagX <= r.hi);
    if (collided) {
      const shiftRight = collided.hi + 18, shiftLeft = collided.lo - 18;
      tagX = shiftRight <= x2 ? shiftRight : (shiftLeft >= x1 ? shiftLeft : tagX);
    }
    const tagY = g.face === 'top' ? y - 13 : y + 13;
    svg += barMarkTag(tagX, tagY, `${g.markId} \u00d8${g.dia}-${g.count}`, { r: 11 });
  }

  // Stirrup zones — representative ticks + spacing callout + zone extent dimension
  const tieTopY = beamY + (cover * 0.4) * scale;
  const tieBotY = beamY + beamH - (cover * 0.4) * scale;
  const zoneRowY = beamY + beamH + 50;
  stirrupZones.forEach((z) => {
    const x1 = beamX + z.startX * scale, x2 = beamX + z.endX * scale;
    const realCount = Math.max(2, Math.round((z.endX - z.startX) / z.spacing) + 1);
    const drawCount = Math.min(realCount, MAX_DRAWN_TIES_PER_ZONE);
    for (const tx of distributeTicks(x1, x2, drawCount)) {
      svg += stirrupTick(tx, tieTopY, tieBotY);
    }
    svg += dimensionLine(x1, zoneRowY, x2, zoneRowY, `${z.markId} \u00d8${z.dia}-${z.legs}L@${z.spacing}`, { orientation: 'h', tick: 5 });
  });

  // Overall length dimension
  svg += dimensionLine(beamX, zoneRowY + 34, beamX + beamW, zoneRowY + 34, `L = ${(totalLength / 1000).toFixed(2)}m`, { orientation: 'h' });

  svg += `</g>`;
  return svg;
}

// Draws the row of cross-section cuts geometry.sections lists (default:
// one near the first support face + one at midspan — see
// computeBeamDiagramGeometry). Each box is an independent concrete
// outline with the bars ACTIVE at that x (already positioned across the
// section width by layoutSectionBars) drawn as dots — this is why depth
// (yFromTopMM) is computed once globally but x-position is computed
// per-section: the same bar group must land at the same height in every
// cut it appears in, but its horizontal position within the section
// width is a layout-time decision local to that one cut.
function renderSections(geometry, scale, x0, y0, l) {
  const { b, h } = geometry.section;
  const w = b * scale, hh = h * scale;
  let svg = '';
  geometry.sections.forEach((sec, i) => {
    const boxX = x0 + i * (SECTION_SIZE + SECTION_GAP);
    const sx = boxX + (SECTION_SIZE - w) / 2;
    const sy = y0 + 10;
    svg += `<g class="section-${i}">`;
    svg += `<text x="${boxX + SECTION_SIZE / 2}" y="${y0 - 10}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.sectionWord)} ${esc(sec.label)}</text>`;
    svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${hh}" class="concrete-outline"/>`;
    for (const bar of sec.bars) {
      const cx = sx + bar.xMM * scale;
      const cy = sy + bar.yFromTopMM * scale;
      svg += barDot(cx, cy, bar.dia, scale, bar.face);
    }
    svg += dimensionLine(sx, sy + hh + 20, sx + w, sy + hh + 20, `b=${b}mm`, { orientation: 'h', tick: 5 });
    svg += dimensionLine(sx - 20, sy, sx - 20, sy + hh, `h=${h}mm`, { orientation: 'v', tick: 5 });
    svg += `</g>`;
  });
  return svg;
}

// Input: geometry (as returned by computeBeamDiagramGeometry) and the
// active language's label set. Output: one row object per longitudinal-
// bar group, then one per stirrup zone, shaped for structuralDrawingKit
// .mjs's scheduleTable(). The `length` cell is the one place this
// function makes a judgment call: cuttingLengthMM verbatim when the
// caller supplied it, otherwise the drawn extent (endX-startX) suffixed
// "(extent)"/"(امتداد)" so the sheet never implies a fabrication-ready
// number it wasn't given — see this file's header for why that
// distinction is load-bearing, not cosmetic.
function buildScheduleRows(geometry, l) {
  const rows = [];
  for (const g of geometry.longitudinalBars) {
    const extent = Math.round(g.endX - g.startX);
    rows.push({
      mark: g.markId,
      element: g.face === 'top' ? l.top : l.bottom,
      dia: String(Math.round(g.dia)),
      count: String(g.count),
      length: g.cuttingLengthMM != null ? String(Math.round(g.cuttingLengthMM)) : `${extent}${l.extentSuffix}`,
    });
  }
  for (const z of geometry.stirrupZones) {
    rows.push({
      mark: z.markId,
      element: l.stirrupWord,
      dia: String(Math.round(z.dia)),
      count: `${z.legs}L@${Math.round(z.spacing)}`,
      length: z.cuttingLengthMM != null ? String(Math.round(z.cuttingLengthMM)) : '\u2014',
    });
  }
  return rows;
}

// ── beamWorkshop mode (Step 16) ─────────────────────────────────────────
// Separate render path, parallel to renderBeamDiagramSVG's rebarDiagram
// path above rather than a parametrized branch woven through it — same
// choice columnDiagram.mjs made for its own renderElevationView vs
// beamDiagram.mjs's renderElevation (each view stays independently
// readable and independently testable, and this mode's changes can never
// leak into rebarDiagram-mode output by accident).
export function renderBeamWorkshopSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);
  const { b, h } = geometry.section;
  const extras = computeBeamWorkshopExtras(geometry);
  const workshopSections = computeWorkshopSections(geometry, extras);

  const scale = fitScale([{ contentW: geometry.totalLength, contentH: h * 2.4, boxW: ELEV_BOX.w, boxH: ELEV_BOX.h }]);
  const beamW = geometry.totalLength * scale;
  const beamH = h * scale;
  const beamX = ELEV_BOX.x + (ELEV_BOX.w - beamW) / 2;
  const beamY = ELEV_BOX.y + (ELEV_BOX.h - beamH) / 2;

  const sectionScale = fitScale([{ contentW: b, contentH: h, boxW: SECTION_SIZE - 50, boxH: SECTION_SIZE - 70 }]);
  const sectionsRowW = workshopSections.length * SECTION_SIZE + (workshopSections.length - 1) * SECTION_GAP;
  // Canvas width sized to whatever number of section boxes THIS beam
  // actually needs (bounded at MAX_WORKSHOP_SECTIONS) rather than
  // assuming the rebarDiagram path's fixed CANVAS_W is wide enough —
  // that constant was sized for rebarDiagram's own worst case, not this
  // mode's (up to MAX_WORKSHOP_SECTIONS boxes, one more than rebarDiagram
  // ever draws by default).
  const CANVAS_W_WS = Math.max(1100, sectionsRowW + 120);
  const sectionsX0 = (CANVAS_W_WS - sectionsRowW) / 2;
  // Derived from the SAME offsets renderWorkshopElevation actually draws
  // at (see workshopElevationExtrasBottomOffset), plus a 50px clearance
  // margin — measured via direct pixel calculation (not eyeballing) to
  // clear the lowest fixed-offset row down there (lap-label text, when
  // lap zones exist) against this row's own view-title text (16px bold)
  // by a safe margin, matching this project's established >=16px rule
  // with headroom for the taller of the two font sizes involved.
  const sectionsY = beamY + beamH + workshopElevationExtrasBottomOffset(geometry.lapZones.length > 0) + 50;

  const tableRows = buildWorkshopScheduleRows(geometry, extras, l);
  const colW = { seq: 46, mark: 60, shape: 50, dia: 64, count: 96 };
  const fixedW = colW.seq + colW.mark + colW.shape + colW.dia + colW.count;
  const remaining = CANVAS_W_WS - 120 - fixedW;
  const elementW = Math.floor(remaining * 0.24);
  const lengthW = Math.floor(remaining * 0.28);
  const notesW = remaining - elementW - lengthW;
  const tableCols = [
    { key: 'seq', label: l.workshopColSeq, width: colW.seq },
    { key: 'mark', label: l.workshopColMark, width: colW.mark },
    { key: 'shape', label: l.workshopColShape, width: colW.shape },
    { key: 'element', label: l.workshopColElement, width: elementW, script: true },
    { key: 'dia', label: l.workshopColDia, width: colW.dia },
    { key: 'count', label: l.workshopColCount, width: colW.count },
    { key: 'length', label: l.workshopColLength, width: lengthW, script: true },
    { key: 'note', label: l.workshopColNotes, width: notesW, script: true },
  ];
  const tableY = sectionsY + SECTION_SIZE + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.workshopCaption, 130);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .beam-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .zone-label { font-size:10.5px; fill:#2f7a3d; font-family: ${defaultFontStack}; }
    .support-label { font-size:11px; fill:#333; font-family: ${defaultFontStack}; }
    .lap-label { font-size:10.5px; fill:#8a6d00; font-family: ${scriptFontStack}; }
    .shop-note { font-size:10px; fill:#555; font-family: ${scriptFontStack}; }
    .section-cut-label { font-size:10px; fill:#555; font-family: ${defaultFontStack}; }`;

  return `<svg viewBox="0 0 ${CANVAS_W_WS} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W_WS}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W_WS / 2}" y="32" text-anchor="middle" class="beam-title" dir="${l.dirAttr}">${esc(l.workshopTitle(geometry.id))}</text>
  ${renderWorkshopElevation(geometry, extras, workshopSections, scale, beamX, beamY, beamW, beamH, l)}
  ${renderWorkshopSectionsRow(workshopSections, geometry.section, sectionScale, sectionsX0, sectionsY, l)}
  ${table.svg}
  ${renderCaptionAt(l.workshopCaption, { x: lang === 'ar' ? CANVAS_W_WS - 60 : 60, startY: captionY, lang, maxCharsPerLine: 130, lineHeight: 15 })}
</svg>`;
}

// Workshop-mode counterpart of renderElevation above: same basic layout
// (supports, concrete outline, bar lines, stirrup ticks, length
// dimension) plus everything Step 16 added — lap-zone shading behind the
// outline, install-sequence numbers prefixed on every bar/stirrup tag,
// open- vs closed-stirrup tick shape, a shape-word note under each
// stirrup zone, and dashed cut-lines marking every EXTRA section this
// mode draws beyond rebarDiagram's base two. Kept as an entirely separate
// function rather than an `if (workshop)` branch threaded through
// renderElevation — see this file's Step 16 module comment for why (same
// call columnDiagram.mjs made for its own elevation view).
function renderWorkshopElevation(geometry, extras, workshopSections, scale, beamX, beamY, beamW, beamH, l) {
  const { totalLength, supports, longitudinalBars, stirrupZones, lapZones, cover } = geometry;
  let svg = `<g class="elevation">`;
  svg += `<text x="${beamX + beamW / 2}" y="${beamY - 46}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.elevation)}</text>`;

  const supportTopY = beamY - 34, supportBotY = beamY + beamH + 34;
  const supportPxRanges = supports.map((s) => {
    const cx = beamX + s.x * scale;
    const w = Math.max(s.width * scale, 14);
    return { lo: cx - w / 2, hi: cx + w / 2 };
  });
  supports.forEach((s, i) => {
    const { lo, hi } = supportPxRanges[i];
    svg += `<rect x="${lo}" y="${supportTopY}" width="${hi - lo}" height="${supportBotY - supportTopY}" class="support-outline" fill="url(#concreteHatch)"/>`;
    const label = s.label || (s.type === 'wall' ? 'W' : 'S') + (i + 1);
    svg += `<text x="${(lo + hi) / 2}" y="${supportBotY + 14}" text-anchor="middle" class="support-label">${esc(label)}</text>`;
  });

  // Lap zones drawn BEHIND the concrete outline/bars (same layering
  // choice columnDiagram.mjs's own lap-splice rect uses) so the shading
  // reads as a zone ON the member, not a foreground patch hiding the
  // steel it marks.
  for (const z of lapZones) {
    const zx1 = beamX + z.startX * scale, zx2 = beamX + z.endX * scale;
    svg += `<rect x="${zx1}" y="${beamY}" width="${zx2 - zx1}" height="${beamH}" fill="#fff3cd" fill-opacity="0.55" stroke="#b8860b" stroke-width="1" stroke-dasharray="4,2"/>`;
  }

  svg += `<rect x="${beamX}" y="${beamY}" width="${beamW}" height="${beamH}" class="concrete-outline"/>`;

  for (const g of longitudinalBars) {
    const x1 = beamX + g.startX * scale, x2 = beamX + g.endX * scale;
    const y = beamY + g.yFromTopMM * scale;
    svg += `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" class="bar-${g.face}"/>`;
    let tagX = (x1 + x2) / 2;
    const collided = supportPxRanges.find((r) => tagX >= r.lo && tagX <= r.hi);
    if (collided) {
      const shiftRight = collided.hi + 18, shiftLeft = collided.lo - 18;
      tagX = shiftRight <= x2 ? shiftRight : (shiftLeft >= x1 ? shiftLeft : tagX);
    }
    const tagY = g.face === 'top' ? y - 13 : y + 13;
    const seq = extras.barSeq.get(g.markId);
    svg += barMarkTag(tagX, tagY, `${seq}) ${g.markId} \u00d8${g.dia}-${g.count}`, { r: 13 });
  }

  const tieTopY = beamY + (cover * 0.4) * scale;
  const tieBotY = beamY + beamH - (cover * 0.4) * scale;
  // +70, not rebarDiagram's own renderElevation's +50 (untouched, above
  // in this file) — this mode's bottom-face bar tags carry a longer
  // label ("N) mark \u00d8dia-count" vs plain "mark \u00d8dia-count"), and
  // measuring actual pixel positions (not eyeballing) for a small-scale
  // beam showed only ~11px clearance between the bottom-tag circle and
  // this row at +50, under this project's own established 16px-minimum-
  // margin rule. Re-verify by direct calculation, not by re-reading this
  // comment, if tag size/offset here ever changes.
  const zoneRowY = beamY + beamH + 70;
  stirrupZones.forEach((z) => {
    const x1 = beamX + z.startX * scale, x2 = beamX + z.endX * scale;
    const realCount = Math.max(2, Math.round((z.endX - z.startX) / z.spacing) + 1);
    const drawCount = Math.min(realCount, MAX_DRAWN_TIES_PER_ZONE);
    const drawTick = z.shape === 'open' ? stirrupTickOpen : stirrupTick;
    for (const tx of distributeTicks(x1, x2, drawCount)) {
      svg += drawTick(tx, tieTopY, tieBotY);
    }
    const seq = extras.stirrupSeq.get(z.markId);
    const shapeLetter = extras.stirrupShape.get(z.markId);
    const shapeWord = z.shape === 'open' ? l.stirrupOpen : l.stirrupClosed;
    svg += dimensionLine(x1, zoneRowY, x2, zoneRowY, `${seq}) ${z.markId}(${shapeLetter}) \u00d8${z.dia}-${z.legs}L@${z.spacing}`, { orientation: 'h', tick: 5 });
    svg += `<text x="${(x1 + x2) / 2}" y="${zoneRowY + 16}" text-anchor="middle" class="shop-note" dir="${l.dirAttr}">${esc(shapeWord)}</text>`;
  });

  for (const z of lapZones) {
    const zx1 = beamX + z.startX * scale, zx2 = beamX + z.endX * scale;
    svg += `<text x="${(zx1 + zx2) / 2}" y="${zoneRowY + 50}" text-anchor="middle" class="lap-label" dir="${l.dirAttr}">${esc(l.lapZoneWord)}</text>`;
  }

  // Extra-section cut markers — dashed vertical line + numeric-only tag
  // (Latin+digits, defaultFontStack, no translation involved) at each x
  // computeWorkshopSections() added beyond the base rebarDiagram
  // sections, so the reader can see WHERE on the beam each extra
  // cross-section drawn below corresponds to.
  // Known limit, not fixed this session (documented, same spirit as this
  // file's own MAX_DRAWN_TIES_PER_ZONE/barMarkTag-width notes elsewhere):
  // if an extra-section cut point's x coincides closely with a bar tag's
  // own midpoint x, the cut-line label and the tag circle can sit close
  // enough to touch at small beam-height scales. Narrow, cosmetic, and
  // only occurs when those two x's coincide — not addressed here.
  for (const sec of workshopSections.filter((s) => s.kind !== 'base')) {
    const sx = beamX + sec.x * scale;
    svg += `<line x1="${sx}" y1="${beamY - 20}" x2="${sx}" y2="${beamY + beamH + 20}" class="cut-line"/>`;
    svg += `<text x="${sx}" y="${beamY - 24}" text-anchor="middle" class="section-cut-label">${esc(sec.label)}</text>`;
  }

  svg += dimensionLine(beamX, zoneRowY + 34, beamX + beamW, zoneRowY + 34, `L = ${(totalLength / 1000).toFixed(2)}m`, { orientation: 'h' });

  svg += `</g>`;
  return svg;
}

// Workshop-mode counterpart of renderSections above: same per-cut concrete
// outline + bar dots, over workshopSections (base cuts plus computeWork
// shopSections' verified extra cuts) instead of geometry.sections alone.
// Extra-kind boxes get a dashed outline and an "extra section" sub-label
// so a reader can tell at a glance which cuts are the original rebar-
// diagram ones and which were added for this shop drawing specifically.
function renderWorkshopSectionsRow(workshopSections, section, scale, x0, y0, l) {
  const { b, h } = section;
  const w = b * scale, hh = h * scale;
  let svg = '';
  workshopSections.forEach((sec, i) => {
    const boxX = x0 + i * (SECTION_SIZE + SECTION_GAP);
    const sx = boxX + (SECTION_SIZE - w) / 2;
    const sy = y0 + 10; // fixed offset from y0, matches renderSections' own convention — rect is never anchored from the (variable) title/extra-label text above it
    svg += `<g class="section-${i}">`;
    svg += `<text x="${boxX + SECTION_SIZE / 2}" y="${y0 - 24}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.sectionWord)} ${esc(sec.label)}</text>`;
    if (sec.kind !== 'base') {
      svg += `<text x="${boxX + SECTION_SIZE / 2}" y="${y0 - 8}" text-anchor="middle" class="shop-note" dir="${l.dirAttr}">${esc(l.extraSectionLabel)}</text>`;
    }
    svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${hh}" class="concrete-outline"${sec.kind !== 'base' ? ' stroke-dasharray="3,2"' : ''}/>`;
    for (const bar of sec.bars) {
      const cx = sx + bar.xMM * scale;
      const cy = sy + bar.yFromTopMM * scale;
      svg += barDot(cx, cy, bar.dia, scale, bar.face);
    }
    svg += dimensionLine(sx, sy + hh + 20, sx + w, sy + hh + 20, `b=${Math.round(b)}mm`, { orientation: 'h', tick: 5 });
    svg += dimensionLine(sx - 20, sy, sx - 20, sy + hh, `h=${Math.round(h)}mm`, { orientation: 'v', tick: 5 });
    svg += `</g>`;
  });
  return svg;
}

// Workshop-mode counterpart of buildScheduleRows above. Input: geometry,
// the `extras` computeBeamWorkshopExtras returned (install sequence +
// shape letters), and the label set. Output: rows ordered by the install
// sequence itself (bottom bars, then stirrups, then top bars — NOT
// geometry's own array order), each carrying seq/shape/note columns
// buildScheduleRows's rebarDiagram-mode rows don't have, plus one
// trailing row per lap zone (dia/count shown as "—": a lap zone is a
// length+location note, not a bar with its own diameter or count). The
// `length` cell follows the same cuttingLengthMM-vs-extent rule as
// buildScheduleRows, using workshopExtentSuffix (parenthesis-free in
// Arabic) rather than the original extentSuffix — see the L.ar block
// above for why those are two different keys, not one shared one.
function buildWorkshopScheduleRows(geometry, extras, l) {
  const rows = [];
  const barsBottomFirst = geometry.longitudinalBars.slice().sort((a, c) => extras.barSeq.get(a.markId) - extras.barSeq.get(c.markId));
  for (const g of barsBottomFirst) {
    const extent = Math.round(g.endX - g.startX);
    rows.push({
      seq: String(extras.barSeq.get(g.markId)),
      mark: g.markId,
      shape: extras.barShape.get(g.markId),
      element: g.face === 'top' ? l.top : l.bottom,
      dia: String(Math.round(g.dia)),
      count: String(g.count),
      length: g.cuttingLengthMM != null ? String(Math.round(g.cuttingLengthMM)) : `${extent}${l.workshopExtentSuffix}`,
      note: g.face === 'bottom' ? l.noteBottomBar : l.noteTopBar,
    });
  }
  const stirrupsInOrder = geometry.stirrupZones.slice().sort((a, c) => extras.stirrupSeq.get(a.markId) - extras.stirrupSeq.get(c.markId));
  for (const z of stirrupsInOrder) {
    rows.push({
      seq: String(extras.stirrupSeq.get(z.markId)),
      mark: z.markId,
      shape: extras.stirrupShape.get(z.markId),
      element: z.shape === 'open' ? l.stirrupOpen : l.stirrupClosed,
      dia: String(Math.round(z.dia)),
      count: `${z.legs}L@${Math.round(z.spacing)}`,
      length: z.cuttingLengthMM != null ? String(Math.round(z.cuttingLengthMM)) : '\u2014',
      note: z.shape === 'open' ? l.noteStirrupOpen : l.noteStirrupClosed,
    });
  }
  geometry.lapZones.forEach((z, i) => {
    rows.push({
      seq: '\u2014',
      mark: z.markRef || `Lap${i + 1}`,
      shape: '\u2014',
      element: l.lapZoneWord,
      dia: '\u2014',
      count: '\u2014',
      length: `${Math.round(z.endX - z.startX)}${l.workshopExtentSuffix}`,
      note: z.note || l.noteLapZone,
    });
  });
  return rows;
}

// ── Chat-facing entry point ────────────────────────────────────────────
// Mirrors footingDiagram.mjs's parseDiagramCommand() error-shape contract
// ({ok:true,...} / {ok:false,code,message}) but takes an already-parsed
// object instead of an ASCII command string — see the chat.js integration
// note (Variables & Risks) for why flat key=value doesn't scale to this
// data shape. Never throws a DiagramError out; anything else (a genuine
// programmer error) is rethrown, same as footingDiagram.mjs's own
// parseDiagramCommand.
export function parseBeamRebarPayload(raw) {
  try {
    const geometry = computeBeamDiagramGeometry(raw);
    return { ok: true, type: 'beam', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Chat-facing entry point (flat /diagram text) — Step 23 ─────────────
// Follows footingDiagram.mjs's/slabDiagram.mjs's parseDiagramCommand
// convention exactly: leading token + "key=value ..." shape,
// BAD_SYNTAX/UNSUPPORTED_TYPE split, never throws (delegates already
// convert DiagramError to {ok:false,...}; a non-DiagramError throw is a
// programmer error and propagates). The "key=value ..." grammar itself
// is beamAsciiToPayload.mjs's own group-indexed syntax (sup{N}/bar{N}/
// stir{N}/lap{N}/sec{N}) — this function only strips the leading `beam`
// token and hands the rest off unchanged; see this file's Step 23 header
// note above for why no new grammar was needed.
//
// Syntax:
//   /diagram beam id=B1 unit=mm totalLength=6000 b=300 h=600 cover=40
//     sup1x=0 sup1width=300 sup1type=column sup1label=C1
//     sup2x=6000 sup2width=300 sup2type=column sup2label=C2
//     bar1face=bottom bar1dia=20 bar1count=3 bar1startX=0 bar1endX=6000
//     stir1dia=8 stir1legs=2 stir1spacing=150 stir1startX=0 stir1endX=6000
//     [lap1startX=... lap1endX=...] [sec1x=... sec1label=...]
// The `s` flag (not used by column/slab/shearWall/stair's own
// parseDiagramCommand) lets the remainder span multiple lines, matching
// beamAsciiToPayload.mjs's own documented "one line or one field per
// line, either way" acceptance — this grammar has enough fields that a
// single unbroken line is materially less usable than the others'.
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+([\s\S]+)$/);
  if (!m) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: beam key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'beam') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use beam.` };
  }
  const ascii = parseBeamAsciiCommand(m[2]);
  if (!ascii.ok) {
    return { ok: false, type, code: ascii.code, message: ascii.message };
  }
  const result = parseBeamRebarPayload(ascii.payload);
  if (!result.ok) {
    return { ok: false, type, code: result.code, message: result.message };
  }
  return result;
}
