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

export class DiagramError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DiagramError';
    this.code = code;
  }
}

const MM_PER_UNIT = { mm: 1, cm: 10, m: 1000 };

// Sanity cap on the multi-column types (strip/raft) — this is a quick
// schematic tool driven by a single ASCII command string with a 2000-
// char server-side limit (see chat.js's mode:'diagram' handler), not a
// CAD system; a raft or strip with more columns than this needs a real
// drafting tool, not this one. isolated/combined are unaffected (fixed
// at 1 and 2 columns respectively, unchanged).
const MAX_COLUMNS = 12;

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
  const actualSpacingMM = barCount > 1 ? (lastCenterMM - firstCenterMM) / (barCount - 1) : 0;
  const barCentersMM = Array.from({ length: barCount }, (_, i) =>
    barCount === 1 ? widthMM / 2 : firstCenterMM + i * actualSpacingMM
  );

  return {
    widthMM, depthMM, colWidthMM, coverMM, diaMM,
    nominalSpacingMM, actualSpacingMM, barCount, barCentersMM,
  };
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

  return {
    type: 'isolated',
    unit,
    plan: {
      longLabel, shortLabel, longMM, shortMM,
      columns: [{ alongLongMM: colLongMM, alongShortMM: colShortMM, centerLongMM: longMM / 2 }],
    },
    section,
    meta: { B, L, D, colB, colL, cover, dia, spacingLong, spacingShort },
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
  };
}

// ── SVG rendering ─────────────────────────────────────────────────────
const CANVAS = { w: 960, h: 760 };
const PLAN_BOX = { x: 80, y: 60, w: 800, h: 280 };
const SECTION_BOX = { x: 80, y: 420, w: 800, h: 240 };
const MIN_BAR_PX_R = 3.2;      // bars stay legible even when geometry scales tiny
const MIN_STROKE_PX = 1.2;

// Types whose plan view carries more than one tagged column, and whose
// section view is therefore "through col<N>" rather than an unlabeled
// single cut. isolated has exactly one, unlabeled column and is
// deliberately excluded — there is nothing to disambiguate.
const NUMBERED_COLUMN_TYPES = new Set(['combined', 'strip', 'raft']);

const TITLES = {
  isolated: { en: 'Isolated Footing', ar: 'قاعدة منفردة' },
  combined: { en: 'Combined Footing', ar: 'قاعدة مشتركة' },
  strip: { en: 'Strip Footing', ar: 'قاعدة شريطية' },
  raft: { en: 'Raft Foundation', ar: 'قاعدة لبشة' },
};

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

function renderPlanView(geometry, scale) {
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
    const env = plan.longMM - 2 * geometry.meta.cover - geometry.meta.dia;
    const spacingLong = geometry.meta.spacingLong ?? geometry.meta.spacing;
    const count = Math.max(2, Math.floor(env / spacingLong) + 1);
    const first = geometry.meta.cover + geometry.meta.dia / 2;
    const last = plan.longMM - geometry.meta.cover - geometry.meta.dia / 2;
    const step = count > 1 ? (last - first) / (count - 1) : 0;
    for (let i = 0; i < count; i++) {
      const posMM = count === 1 ? plan.longMM / 2 : first + i * step;
      const x = originX + posMM * scale;
      svg += `<line x1="${x}" y1="${originY + 2}" x2="${x}" y2="${originY + hPx - 2}" class="mesh-line"/>`;
    }
  }

  // Columns
  for (const col of plan.columns) {
    const cx = originX + col.centerLongMM * scale;
    // raft columns carry their own centerShortMM (2-D position in
    // plan); every other type omits it, which keeps them on the
    // vertical center of the plan box exactly as before this field
    // existed — isolated/combined/strip are unaffected.
    const cy = col.centerShortMM != null ? originY + col.centerShortMM * scale : originY + hPx / 2;
    const cw = col.alongLongMM * scale, ch = col.alongShortMM * scale;
    svg += `<rect x="${cx - cw / 2}" y="${cy - ch / 2}" width="${cw}" height="${ch}" class="column-outline"/>`;
    if (col.tag) {
      svg += `<text x="${cx}" y="${cy + ch / 2 + 16}" text-anchor="middle" class="col-tag">${esc(col.tag)}</text>`;
    }
  }

  // Section cut marker, so the section view below is traceable back to a
  // specific column instead of floating unlabeled. Applies to every type
  // with more than one numbered column (combined/strip/raft) — isolated
  // has exactly one, unlabeled column, so there is nothing to
  // disambiguate and no cut marker is drawn for it.
  if (NUMBERED_COLUMN_TYPES.has(geometry.type)) {
    const chosen = plan.columns[geometry.sectionThrough - 1];
    const cx = originX + chosen.centerLongMM * scale;
    svg += `<line x1="${cx}" y1="${originY - 14}" x2="${cx}" y2="${originY + hPx + 14}" class="cut-line"/>`;
    svg += `<text x="${cx}" y="${originY - 18}" text-anchor="middle" class="cut-label">A</text>`;
    svg += `<text x="${cx}" y="${originY + hPx + 28}" text-anchor="middle" class="cut-label">A</text>`;
  }

  // Overall dimensions
  svg += dimensionLine(originX, originY - 26, originX + wPx, originY - 26, `${plan.longLabel} = ${fmt(plan.longMM, geometry.unit, 2)}`, { orientation: 'h' });
  svg += dimensionLine(originX - 26, originY, originX - 26, originY + hPx, `${plan.shortLabel} = ${fmt(plan.shortMM, geometry.unit, 2)}`, { orientation: 'v' });

  svg += `<text x="${originX + wPx / 2}" y="${originY + hPx + 46}" text-anchor="middle" class="view-title">PLAN</text>`;
  svg += `</g>`;
  return svg;
}

function renderSectionView(geometry, scale) {
  const { section } = geometry;
  const originX = SECTION_BOX.x + (SECTION_BOX.w - section.widthMM * scale) / 2;
  const baseY = SECTION_BOX.y + SECTION_BOX.h - 60; // leave room for soil hatch + labels below
  const topY = baseY - section.depthMM * scale;
  const wPx = section.widthMM * scale;

  let svg = `<g class="section-view">`;
  // Soil band under the footing
  svg += `<rect x="${originX - 20}" y="${baseY}" width="${wPx + 40}" height="26" fill="url(#soilHatch)" stroke="#8a7350" stroke-width="1"/>`;
  // Footing body
  svg += `<rect x="${originX}" y="${topY}" width="${wPx}" height="${section.depthMM * scale}" class="footing-outline" fill="url(#concreteHatch)"/>`;
  // Column stub rising from the footing top
  const colW = section.colWidthMM * scale;
  const colX = originX + wPx / 2 - colW / 2;
  const colTop = topY - 90;
  svg += `<rect x="${colX}" y="${colTop}" width="${colW}" height="${topY - colTop}" class="column-outline" fill="url(#concreteHatch)"/>`;

  // Bottom reinforcement layer: representative Family-B line + Family-A
  // bar circles at their true spacing/positions.
  const barY = baseY - section.coverMM * scale;
  svg += `<line x1="${originX + 8}" y1="${barY}" x2="${originX + wPx - 8}" y2="${barY}" class="mesh-line"/>`;
  const rPx = Math.max(MIN_BAR_PX_R, (section.diaMM / 2) * scale);
  for (const cMM of section.barCentersMM) {
    svg += `<circle cx="${originX + cMM * scale}" cy="${barY}" r="${rPx}" class="bar-dot"/>`;
  }

  // Dimensions: depth, width, cover, bar spec
  svg += dimensionLine(originX + wPx + 40, topY, originX + wPx + 40, baseY, `D = ${fmt(section.depthMM, geometry.unit, 2)}`, { orientation: 'v' });
  svg += dimensionLine(originX, baseY + 46, originX + wPx, baseY + 46, `${section.widthMM === geometry.meta.B ? 'B' : geometry.plan.shortLabel} = ${fmt(section.widthMM, geometry.unit, 2)}`, { orientation: 'h' });
  // Stacked on two centered lines, not left/right on one line — at
  // narrow widths (e.g. B=1200mm) same-line opposite-anchored labels
  // collide in the middle; found by rendering Case 2 in the test suite
  // and inspecting the PNG, not by inspection of the code alone.
  const midX = originX + wPx / 2;
  svg += `<text x="${midX}" y="${barY - 26}" text-anchor="middle" class="dim-label">cover = ${fmt(section.coverMM, geometry.unit, 0)}</text>`;
  svg += `<text x="${midX}" y="${barY - 10}" text-anchor="middle" class="dim-label">${section.barCount} Ø${fmt(section.diaMM, geometry.unit, 0)} @ ${fmt(section.actualSpacingMM, geometry.unit, 0)}</text>`;

  const sectionTitle = NUMBERED_COLUMN_TYPES.has(geometry.type)
    ? `SECTION A-A (through ${geometry.plan.columns[geometry.sectionThrough - 1].tag})`
    : 'SECTION A-A';
  svg += `<text x="${originX + wPx / 2}" y="${baseY + 70}" text-anchor="middle" class="view-title">${sectionTitle}</text>`;
  svg += `</g>`;
  return svg;
}

// opts.lang: 'ar' | 'en', default 'ar'
export function renderFootingDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'en' ? 'en' : 'ar';
  // Some renderers resolve a CSS font-family list by matching only the
  // first token and never fall back to later entries for missing glyphs
  // (confirmed against cairosvg while testing this module). That cuts
  // both ways: an Arial-first stack drew Arabic title text as tofu; a
  // naive fix — putting 'Noto Naskh Arabic' first for the WHOLE drawing
  // — then broke the Latin dimension labels (B=, PLAN, cover=, mm,
  // col1...) instead, because that font doesn't carry a full Latin
  // alphabet and nothing fell back for the missing glyphs. The actual
  // fix is per-element, not global: every dimension/label string in this
  // drawing (B=, L=, D=, cover=, mm, ⌀, PLAN, SECTION, col1/col2) is
  // Latin+digits by engineering-notation convention regardless of
  // `lang` — only the sheet title and caption ever contain Arabic
  // script. defaultFontStack (Latin-first) is the blanket rule; only
  // .sheet-title/.sheet-caption get scriptFontStack, and only when this
  // render is actually Arabic.
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

  // The Arabic string avoids em-dash and parentheses on purpose — Noto
  // Naskh Arabic (the font this render actually selects for Arabic
  // script; see scriptFontStack above) has no glyph for either, found
  // by isolated-glyph probing during testing, and this app cannot
  // control which font a visitor's system ultimately substitutes.
  // Punctuation actually confirmed present in that font (Arabic comma،
  // period, shadda) is used instead.
  const caption = lang === 'ar'
    ? 'رسم تخطيطي محسوب من القيم المُدخلة، للتحقق فقط. التسليح مبسّط: شبكة سفلية واحدة فقط، بدون كانات أو أطوال ربط. هذا ليس رسم تنفيذي.'
    : 'Schematic computed from the entered values — verify against your own design. Reinforcement is simplified (one bottom mesh layer, no stirrups/laps) — this is not a construction/shop drawing.';

  const title = (TITLES[geometry.type] || TITLES.isolated)[lang];

  return `<svg viewBox="0 0 ${CANVAS.w} ${CANVAS.h}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
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
    .view-title      { font-size:16px; font-weight:bold; fill:#111; letter-spacing:1px; }
    .cut-line        { stroke:#1a1a1a; stroke-width:1.4; stroke-dasharray:6,3; }
    .cut-label       { font-size:14px; font-weight:bold; fill:#111; }
    .col-tag         { font-size:12px; fill:#333; }
    .sheet-title     { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .sheet-caption   { font-size:12.5px; fill:#444; font-family: ${scriptFontStack}; }
  </style>
  <rect x="0" y="0" width="${CANVAS.w}" height="${CANVAS.h}" fill="#ffffff"/>
  <text x="${CANVAS.w / 2}" y="30" text-anchor="middle" class="sheet-title" dir="${lang === 'ar' ? 'rtl' : 'ltr'}">${esc(title)}</text>
  ${renderPlanView(geometry, scale)}
  ${renderSectionView(geometry, scale)}
  <line x1="${PLAN_BOX.x}" y1="${SECTION_BOX.y - 30}" x2="${PLAN_BOX.x + PLAN_BOX.w}" y2="${SECTION_BOX.y - 30}" stroke="#ccc" stroke-width="1"/>
  ${renderCaption(caption, lang)}
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

function renderCaption(caption, lang) {
  const lines = wrapText(caption, 100);
  const rtl = lang === 'ar';
  const x = rtl ? CANVAS.w - 40 : 40;
  const anchor = rtl ? 'end' : 'start';
  const startY = CANVAS.h - 20 - (lines.length - 1) * 16;
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
//   /diagram raft B=6000 L=9000 D=500 cols=4 col1b=400 col1l=400 col1offx=1000 col1offy=1000 col2b=400 col2l=400 col2offx=1000 col2offy=8000 col3b=400 col3l=400 col3offx=5000 col3offy=1000 col4b=400 col4l=400 col4offx=5000 col4offy=8000 cover=75 dia=16 spacing=200 [unit=mm] [sectionthrough=1]
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

  try {
    let geometry;
    if (type === 'isolated') {
      geometry = computeIsolatedFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        colB: num('colb'), colL: num('coll'),
        cover: num('cover'), dia: num('dia'),
        spacing: num('spacing'), spacingLong: num('spacinglong'), spacingShort: num('spacingshort'),
        unit: kv.unit || 'mm',
      });
    } else if (type === 'combined') {
      geometry = computeCombinedFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        col1: { b: num('col1b'), l: num('col1l'), off: num('col1off') },
        col2: { b: num('col2b'), l: num('col2l'), off: num('col2off') },
        cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
        sectionThrough: num('sectionthrough') === 2 ? 2 : 1,
        unit: kv.unit || 'mm',
      });
    } else if (type === 'strip') {
      const st = num('sectionthrough');
      geometry = computeStripFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        columns: collectColumns(['b', 'l', 'off']),
        cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
        sectionThrough: Number.isFinite(st) ? st : 1,
        unit: kv.unit || 'mm',
      });
    } else if (type === 'raft') {
      const st = num('sectionthrough');
      geometry = computeRaftFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        columns: collectColumns(['b', 'l', 'offx', 'offy']),
        cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
        sectionThrough: Number.isFinite(st) ? st : 1,
        unit: kv.unit || 'mm',
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
