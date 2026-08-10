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
const GENERIC_PATTERNS = [
  { type: 'trapezoidal', re: /trapezoidal|trapezoid/i },
  { type: 'trapezoidal', re: /شبه\s*منحرف/ },
  { type: 'strip', re: /strip\s*footing/i },
  { type: 'strip', re: /قاعدة\s*شريطية\s*تحت\s*حائط/ },
  { type: 'raft', re: /raft\s*(foundation|footing)?|mat\s*foundation/i },
  { type: 'raft', re: /قاعدة\s*(لبشة|حصيرة)/ },
  { type: 'strap', re: /\bstrap\s*(footing|beam)?\b/i },
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
