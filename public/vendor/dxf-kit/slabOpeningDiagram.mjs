// functions/_lib/slabOpeningDiagram.mjs
//
// New-element track (session25 gate, candidate 2 of the ACI-318
// gap-analysis pool: "Flat slab opening reinforcement"). Deterministic,
// zero-AI SVG generator for trim/replacement reinforcement around ONE
// rectangular opening cut into an EXISTING flat slab panel — the exact
// geometry slabDiagram.mjs's own header names as NOT modeled ("openings/
// penetrations ... each needs a parametrization this module hasn't been
// given yet"). Same philosophy as every sibling module: every dimension,
// bar position, and count in the output is arithmetic on the KB data
// supplied, never a model's guess, and never a design calculation this
// module performs itself — the caller (KB/design layer) decides how many
// trim bars replace the interrupted mesh; this module only draws what it
// is given. Architecture follows columnDiagram.mjs literally (own file,
// own local `L` dict — see structuralLabels.mjs's own header for why that
// file stays scoped to footingDiagram.mjs — own MIN_*/MAX_* sanity caps,
// compute -> render -> parseDiagramCommand -> parse*RebarPayload,
// DiagramError/kit imports from structuralDrawingKit.mjs) per this
// session's own instruction.
//
// ── SCOPE (v1) ──────────────────────────────────────────────────────────
// Exactly ONE rectangular flat panel (lengthMM x widthMM plan, constant
// thicknessMM) — same plan/section convention as slabDiagram.mjs, this is
// literally the same panel type, just with one opening cut into it — and
// exactly ONE rectangular opening, fully interior to the panel (a margin
// of at least MIN_OPENING_EDGE_MARGIN_MM is required on all four sides —
// an opening touching or crossing a panel edge is a materially different
// drawing problem, not a variant of this one). ONE bottom mesh (required,
// same isotropic-by-default spacingXMM/spacingYMM convention as
// slabDiagram.mjs's own mesh.bottom). Trim/replacement bars are drawn in
// TWO groups — parallelToX (added along the opening's top and bottom
// edges, replacing bottom-mesh bars that ran parallel to X and were cut
// by the opening) and parallelToY (added along the opening's left and
// right edges, replacing bars parallel to Y) — each group ONE diameter/
// count-per-side pair, symmetric both sides of the opening (this module
// will not invent an asymmetric left/right or top/bottom split, same
// "one group, not invented asymmetry" discipline columnDiagram.mjs's own
// header uses for verticalBars).
//
// NOT modeled, on purpose (same "explicit scope boundary" convention
// every sibling module's header uses — naming a gap here, not guessing
// past it):
//   - top mesh interruption/replacement — slabDiagram.mjs's own mesh.top
//     is optional; this module only ever carries mesh.bottom. A panel
//     whose TOP mesh also needs trim bars around the same opening is a
//     real, different input shape this v1 does not accept.
//   - more than one opening on the same panel — a second opening changes
//     which mesh bars are "cut" by which opening and whether their
//     replacement zones overlap; a materially different geometry problem,
//     not a variant of this one.
//   - openings touching or crossing a panel edge, or an opening whose
//     replacement zone would extend past the panel edge — see
//     MIN_OPENING_EDGE_MARGIN_MM below; an edge opening is a different,
//     real detail (often simpler — no bars on the missing side) that this
//     v1 does not draw.
//   - drop panels, column capitals, curtailment, or multi-panel
//     continuous slabs — inherited unchanged from slabDiagram.mjs's own
//     NOT-modeled list; this module adds an opening on top of the same
//     base panel, it does not remove any of that file's own exclusions.
//   - punching-shear reinforcement around a column near the opening —
//     ACI 318 §22.6 punching shear studs/ties are a DIFFERENT reinforcement
//     system (column-driven, not opening-driven) and a distinct,
//     separately-flagged gap in this app's own candidate pool; this
//     module draws no column and computes no punching-shear check of any
//     kind, even when the opening sits near one.
//   - any check that the supplied trim-bar area actually replaces the
//     interrupted mesh area per ACI 318 \u00a78.5.4/24.4.3 (or ECP 203's
//     equivalent) — this module has no bar-area formula in it anywhere;
//     the caller's KB/design layer decides diameterMM/countPerSide, this
//     module only draws the result, same "compute+render only, no design
//     decision" boundary as every sibling module's own header states.
//   - diagonal corner bars at the opening's four corners (a common
//     additional detail for larger openings per some codes/practice) —
//     not modeled; only the two straight trim-bar groups above are drawn.
//   - development/anchorage length for trim bars — same "count/diameter
//     only, no computed cutting length" honesty convention as
//     slabDiagram.mjs's own extraTopBars (see that file's EXTRA-BAR
//     HONESTY NOTE); this module's schedule table shows "\u2014" for every
//     trim-bar row's length, never an invented one.
//
// ── INPUT CONTRACT ───────────────────────────────────────────────────
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   slabId?: string,                   // panel mark, e.g. "S1"
//   lengthMM: number, widthMM: number, // panel plan dims — IDENTICAL
//                                      // meaning to slabDiagram.mjs's own
//                                      // lengthMM/widthMM (length = X
//                                      // extent, width = Y extent)
//   thicknessMM: number,
//   coverMM: number,
//   mesh: {
//     bottom: { diameterMM: number, spacingXMM: number, spacingYMM?: number },
//   },
//   opening: {
//     offXMM: number,                  // opening's near corner, measured
//                                      // from the panel's own X=0 edge
//     offYMM: number,                  // opening's near corner, measured
//                                      // from the panel's own Y=0 edge
//     spanXMM: number,                 // opening extent along X
//     spanYMM: number,                 // opening extent along Y
//   },
//   trimBars: {
//     parallelToX: { diameterMM: number, countPerSide: number }, // top+bottom edges
//     parallelToY: { diameterMM: number, countPerSide: number }, // left+right edges
//   },
// }
//
// offXMM/offYMM/spanXMM/spanYMM are deliberately NOT named
// widthMM/lengthMM inside `opening` — this file's own panel already uses
// those names for the OTHER axis pairing (widthMM = Y extent, lengthMM =
// X extent); reusing them for the opening's own X/spanX, Y/spanY would be
// exactly the "easy to invert by accident" hazard slabDiagram.mjs's own
// SPACING DIRECTION CONVENTION note warns about, just relocated to a
// different field pair. Distinct names side-step it entirely.
//
// ── Section cut ─────────────────────────────────────────────────────
// One straight cut along Y = opening.offYMM + opening.spanYMM/2 — the
// opening's OWN true vertical center, not an arbitrary panel-centerline
// cut. Unlike raft's/pileCap's own representative-elevation cuts (which
// must pick a fixed line because several independent columns/piles never
// share one exact line), this module has exactly ONE opening, so cutting
// through its real center is exact, not representative — every dimension
// the section shows is the true geometry at that line, not a projection.
//
// Resource lifecycle: pure/synchronous, zero state, no timers/fetch/KV/
// handles — same as every sibling module.

import {
  DiagramError, toMm, assertFinitePositive, assertFiniteNonNegative, assertInt,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, distributeTicks, barMarkTag,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ─────────────────────────────────────────────────────
// Panel bounds copied from slabDiagram.mjs's own MIN/MAX_SPAN_MM,
// MIN/MAX_THICKNESS_MM, MIN/MAX_MESH_SPACING_MM, MAX_MESH_ROWS/COLS —
// this is literally the same panel type, so the same schematic-legibility
// ceilings apply for the same reasons (see that file's own comments).
const MIN_SPAN_MM = 1000;
const MAX_SPAN_MM = 12000;
const MIN_THICKNESS_MM = 100;
const MAX_THICKNESS_MM = 500;
const MIN_MESH_SPACING_MM = 75;
const MAX_MESH_SPACING_MM = 400;
const MAX_MESH_ROWS = 14;
const MAX_MESH_COLS = 14;
// Opening-specific caps. MIN_OPENING_SPAN_MM keeps a "opening" from being
// a sliver too thin to draw legibly; MAX_OPENING_SPAN_MM keeps it well
// short of the panel's own MAX_SPAN_MM so the required edge margin below
// always has room to fit even at both maxima simultaneously.
// MIN_OPENING_EDGE_MARGIN_MM exists ONLY so the schematic stays drawable
// and legible (the opening's replacement trim bars need a real strip of
// intact panel to sit on, and the drawing needs room to letter a
// dimension line there) — same explicitly-stated "legibility floor, not a
// design requirement" reasoning pileCapDiagram.mjs's own
// MIN_EDGE_FACTOR/MIN_CLEAR_FACTOR use; it is NOT a substitute for a real
// ACI 318 edge-distance or opening-proximity check and must not be read
// as one.
const MIN_OPENING_SPAN_MM = 150;
const MAX_OPENING_SPAN_MM = 3000;
const MIN_OPENING_EDGE_MARGIN_MM = 150;
const MIN_TRIM_BARS_PER_SIDE = 1;
const MAX_TRIM_BARS_PER_SIDE = 8;

// ── Compute ─────────────────────────────────────────────────────────
function parseMeshSpec(spec, unit, label) {
  if (!spec || typeof spec !== 'object') {
    throw new DiagramError('BAD_PARAM', `"${label}" must be an object: { diameterMM, spacingXMM, spacingYMM? }.`);
  }
  const dia = toMm(spec.diameterMM, unit);
  assertFinitePositive(`${label}.diameterMM`, dia);
  const spacingX = toMm(spec.spacingXMM, unit);
  assertFinitePositive(`${label}.spacingXMM`, spacingX);
  if (spacingX < MIN_MESH_SPACING_MM || spacingX > MAX_MESH_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"${label}.spacingXMM" must be between ${MIN_MESH_SPACING_MM}mm and ${MAX_MESH_SPACING_MM}mm, got ${spacingX}mm.`);
  }
  const spacingY = spec.spacingYMM != null ? toMm(spec.spacingYMM, unit) : spacingX;
  assertFinitePositive(`${label}.spacingYMM`, spacingY);
  if (spacingY < MIN_MESH_SPACING_MM || spacingY > MAX_MESH_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"${label}.spacingYMM" must be between ${MIN_MESH_SPACING_MM}mm and ${MAX_MESH_SPACING_MM}mm, got ${spacingY}mm.`);
  }
  return { dia, spacingX, spacingY };
}

function parseTrimGroup(spec, unit, label) {
  if (!spec || typeof spec !== 'object') {
    throw new DiagramError('BAD_PARAM', `"${label}" must be an object: { diameterMM, countPerSide }.`);
  }
  const dia = toMm(spec.diameterMM, unit);
  assertFinitePositive(`${label}.diameterMM`, dia);
  assertInt(`${label}.countPerSide`, spec.countPerSide, { min: MIN_TRIM_BARS_PER_SIDE, max: MAX_TRIM_BARS_PER_SIDE });
  return { dia, countPerSide: spec.countPerSide };
}

export function computeSlabOpeningDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Slab opening diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.slabId != null ? String(raw.slabId).slice(0, 40) : 'SLAB';

  const lengthMM = toMm(raw.lengthMM, unit);
  const widthMM = toMm(raw.widthMM, unit);
  assertFinitePositive('lengthMM', lengthMM);
  assertFinitePositive('widthMM', widthMM);
  if (lengthMM < MIN_SPAN_MM || lengthMM > MAX_SPAN_MM) {
    throw new DiagramError('BAD_PARAM', `"lengthMM" must be between ${MIN_SPAN_MM}mm and ${MAX_SPAN_MM}mm for this schematic, got ${lengthMM}mm.`);
  }
  if (widthMM < MIN_SPAN_MM || widthMM > MAX_SPAN_MM) {
    throw new DiagramError('BAD_PARAM', `"widthMM" must be between ${MIN_SPAN_MM}mm and ${MAX_SPAN_MM}mm for this schematic, got ${widthMM}mm.`);
  }

  const thicknessMM = toMm(raw.thicknessMM, unit);
  assertFinitePositive('thicknessMM', thicknessMM);
  if (thicknessMM < MIN_THICKNESS_MM || thicknessMM > MAX_THICKNESS_MM) {
    throw new DiagramError('BAD_PARAM', `"thicknessMM" must be between ${MIN_THICKNESS_MM}mm and ${MAX_THICKNESS_MM}mm, got ${thicknessMM}mm.`);
  }

  const coverMM = toMm(raw.coverMM, unit);
  assertFinitePositive('coverMM', coverMM);
  if (coverMM * 2 >= thicknessMM) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) on both faces leaves no room inside a ${thicknessMM}mm-thick slab.`);
  }

  if (!raw.mesh || typeof raw.mesh !== 'object' || !raw.mesh.bottom) {
    throw new DiagramError('BAD_PARAM', '"mesh.bottom" is required: { diameterMM, spacingXMM, spacingYMM? }.');
  }
  const bottomSpec = parseMeshSpec(raw.mesh.bottom, unit, 'mesh.bottom');
  // Real (uncapped) bar counts — same countX/countY-from-spacing formula
  // and the same drawn-vs-real separation slabDiagram.mjs's own
  // toMeshGeometry() uses (drawn/capped count derived later, at render
  // time, from these).
  const bottom = {
    dia: bottomSpec.dia, spacingX: bottomSpec.spacingX, spacingY: bottomSpec.spacingY,
    countX: Math.max(2, Math.round(lengthMM / bottomSpec.spacingX) + 1),
    countY: Math.max(2, Math.round(widthMM / bottomSpec.spacingY) + 1),
  };

  if (!raw.opening || typeof raw.opening !== 'object') {
    throw new DiagramError('BAD_PARAM', '"opening" is required: { offXMM, offYMM, spanXMM, spanYMM }.');
  }
  const offX = toMm(raw.opening.offXMM, unit);
  const offY = toMm(raw.opening.offYMM, unit);
  const spanX = toMm(raw.opening.spanXMM, unit);
  const spanY = toMm(raw.opening.spanYMM, unit);
  assertFiniteNonNegative('opening.offXMM', offX);
  assertFiniteNonNegative('opening.offYMM', offY);
  assertFinitePositive('opening.spanXMM', spanX);
  assertFinitePositive('opening.spanYMM', spanY);
  if (spanX < MIN_OPENING_SPAN_MM || spanX > MAX_OPENING_SPAN_MM) {
    throw new DiagramError('BAD_PARAM', `"opening.spanXMM" must be between ${MIN_OPENING_SPAN_MM}mm and ${MAX_OPENING_SPAN_MM}mm, got ${spanX}mm.`);
  }
  if (spanY < MIN_OPENING_SPAN_MM || spanY > MAX_OPENING_SPAN_MM) {
    throw new DiagramError('BAD_PARAM', `"opening.spanYMM" must be between ${MIN_OPENING_SPAN_MM}mm and ${MAX_OPENING_SPAN_MM}mm, got ${spanY}mm.`);
  }
  if (
    offX < MIN_OPENING_EDGE_MARGIN_MM || offY < MIN_OPENING_EDGE_MARGIN_MM ||
    offX + spanX > lengthMM - MIN_OPENING_EDGE_MARGIN_MM ||
    offY + spanY > widthMM - MIN_OPENING_EDGE_MARGIN_MM
  ) {
    throw new DiagramError(
      'OPENING_TOO_CLOSE_TO_EDGE',
      `Opening [offX ${offX}mm, offY ${offY}mm, ${spanX}x${spanY}mm] must sit at least ${MIN_OPENING_EDGE_MARGIN_MM}mm inside every edge of the ${lengthMM}x${widthMM}mm panel — an opening touching or crossing the panel edge is not modeled by this module (see SCOPE).`,
    );
  }

  if (!raw.trimBars || typeof raw.trimBars !== 'object' || !raw.trimBars.parallelToX || !raw.trimBars.parallelToY) {
    throw new DiagramError('BAD_PARAM', '"trimBars" is required: { parallelToX: {diameterMM,countPerSide}, parallelToY: {diameterMM,countPerSide} }.');
  }
  const trimParallelToX = parseTrimGroup(raw.trimBars.parallelToX, unit, 'trimBars.parallelToX');
  const trimParallelToY = parseTrimGroup(raw.trimBars.parallelToY, unit, 'trimBars.parallelToY');

  return {
    type: 'slabOpening', unit, id, lengthMM, widthMM, thicknessMM, coverMM,
    mesh: { bottom },
    opening: { offX, offY, spanX, spanY },
    trimBars: { parallelToX: trimParallelToX, parallelToY: trimParallelToY },
  };
}

// ── Labels ──────────────────────────────────────────────────────────
// Local dictionary, own file — structuralLabels.mjs stays scoped to
// footingDiagram.mjs only (see columnDiagram.mjs's own "Labels" section
// for the full reasoning, which applies unchanged here). Every Arabic
// string is parenthesis/em-dash free (Noto Naskh Arabic glyph-coverage
// constraint, same as every sibling module).
const L = {
  en: {
    title: (id) => `SLAB ${id} \u2014 OPENING REINFORCEMENT DETAIL`,
    plan: 'OPENING PLAN', section: 'SECTION THROUGH OPENING',
    bottomDirX: 'Bottom mesh, bars || Y', bottomDirY: 'Bottom mesh, bars || X',
    trimRowX: (edge) => `Trim bars || X \u2014 ${edge} edge of opening`,
    trimRowY: (edge) => `Trim bars || Y \u2014 ${edge} edge of opening`,
    extentSuffix: ' (extent)',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    legendBottom: 'bottom mesh', legendTrim: 'trim bar', legendOpening: 'opening',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design (ACI 318 \u00a78.5.4/24.4.3 or ECP 203) before issuing for construction. This drawing does not compute whether the trim-bar area actually replaces the interrupted mesh area, does not check punching shear near any column, and shows no diagonal corner bars \u2014 all are the design engineer\'s own responsibility. Trim-bar rows show count/diameter only, no cutting length is computed for them in this version.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد تسليح فتحة البلاطة ${id}`,
    plan: 'مسقط الفتحة', section: 'قطاع عبر الفتحة',
    bottomDirX: 'شبكة سفلية، أسياخ موازية Y', bottomDirY: 'شبكة سفلية، أسياخ موازية X',
    trimRowX: (edge) => `أسياخ تعويضية موازية X، حافة الفتحة ${edge}`,
    trimRowY: (edge) => `أسياخ تعويضية موازية Y، حافة الفتحة ${edge}`,
    extentSuffix: ' امتداد',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    legendBottom: 'الشبكة السفلية', legendTrim: 'سيخ تعويضي', legendOpening: 'فتحة',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص (ACI 318 القسم 8.5.4 أو 24.4.3 أو ECP 203) قبل الاعتماد للتنفيذ. هذا الرسم لا يحسب إن كانت مساحة الأسياخ التعويضية تعوّض فعلياً مساحة الشبكة المقطوعة، ولا يفحص قص الثقب قرب أي عمود، ولا يُظهر أسياخ الزوايا القطرية — كل ذلك مسؤولية المهندس المصمم. صفوف الأسياخ التعويضية تعرض العدد والقطر فقط، بلا طول قطع محسوب في هذه النسخة.',
    dirAttr: 'rtl',
  },
};

const EDGE_LABEL = {
  en: { top: 'top', bottom: 'bottom', left: 'left', right: 'right' },
  ar: { top: 'علوية', bottom: 'سفلية', left: 'يسرى', right: 'يمنى' },
};

// ── Render ──────────────────────────────────────────────────────────
const CANVAS_W = 950;
const PLAN_BOX = { x: 70, y: 110, w: 480, h: 340 };
const SECTION_BOX = { x: 610, y: 110, w: 270, h: 340 };

// Same distributeTicks()+barDot() mesh-grid convention as slabDiagram.mjs's
// own drawMeshGrid(), extended to skip any representative dot whose pixel
// position falls inside the opening's own pixel rect — an un-skipped dot
// there would draw steel on top of a void, which is not what the input
// describes (the mesh bars in that zone are exactly what the trim bars
// replace).
function drawMeshGridSkippingOpening(sx, sy, w, h, meshGeom, scale, face, openingPx) {
  const drawCols = Math.min(meshGeom.countX, MAX_MESH_COLS);
  const drawRows = Math.min(meshGeom.countY, MAX_MESH_ROWS);
  const xs = distributeTicks(sx, sx + w, drawCols);
  const ys = distributeTicks(sy, sy + h, drawRows);
  let svg = '';
  for (const y of ys) {
    for (const x of xs) {
      if (x >= openingPx.x0 && x <= openingPx.x1 && y >= openingPx.y0 && y <= openingPx.y1) continue;
      svg += barDot(x, y, meshGeom.dia, scale, face);
    }
  }
  return svg;
}

function renderPlanView(geometry, scale, box, l) {
  const { lengthMM, widthMM, mesh, opening, trimBars } = geometry;
  const w = lengthMM * scale, h = widthMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + (box.h - h) / 2;
  const openingPx = {
    x0: sx + opening.offX * scale, x1: sx + (opening.offX + opening.spanX) * scale,
    y0: sy + opening.offY * scale, y1: sy + (opening.offY + opening.spanY) * scale,
  };

  let svg = `<g class="plan-view">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.plan)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" class="concrete-outline"/>`;
  svg += drawMeshGridSkippingOpening(sx, sy, w, h, mesh.bottom, scale, 'slab-bottom', openingPx);

  // Opening void: white fill (not the concrete hatch) + dashed cut-line
  // outline, so it reads as a hole, not as a second material. No text
  // label drawn INSIDE/against the box itself \u2014 a typical opening
  // (hundreds of mm) scales to a box far too small to hold "OPENING" plus
  // two dimension lines without collision (confirmed by an actual
  // cairosvg render during this module's own build, not assumed safe).
  // The "OP" mark + its real size are instead placed in the legend row
  // below, which has guaranteed clear space, connected by a leader line
  // to the opening's own center \u2014 barMarkTag()'s documented leaderTo
  // option, the same primitive slabDiagram.mjs's own extraTopBars zones
  // already use for an analogous "label a zone, not a single bar" case.
  svg += `<rect x="${openingPx.x0}" y="${openingPx.y0}" width="${openingPx.x1 - openingPx.x0}" height="${openingPx.y1 - openingPx.y0}" fill="#ffffff" class="cut-line"/>`;

  // Trim bars parallel to Y — left/right edges of the opening.
  for (const y of distributeTicks(openingPx.y0 + 6, openingPx.y1 - 6, trimBars.parallelToY.countPerSide)) {
    svg += barDot(openingPx.x0, y, trimBars.parallelToY.dia, scale, 'slabopening-trim');
    svg += barDot(openingPx.x1, y, trimBars.parallelToY.dia, scale, 'slabopening-trim');
  }
  // Trim bars parallel to X — top/bottom edges of the opening.
  for (const x of distributeTicks(openingPx.x0 + 6, openingPx.x1 - 6, trimBars.parallelToX.countPerSide)) {
    svg += barDot(x, openingPx.y0, trimBars.parallelToX.dia, scale, 'slabopening-trim');
    svg += barDot(x, openingPx.y1, trimBars.parallelToX.dia, scale, 'slabopening-trim');
  }

  // Legend \u2014 3 swatches, evenly spaced across the box width. The third
  // (opening) spells out its real span here, in guaranteed clear space,
  // since it no longer fits legibly against the box itself (see the
  // comment above the void rect).
  const legendY = box.y + box.h + 34;
  const c1x = box.x + box.w / 2 - 170, c2x = box.x + box.w / 2 - 10, c3x = box.x + box.w / 2 + 150;
  svg += `<circle cx="${c1x}" cy="${legendY}" r="4" class="bar-dot-slab-bottom"/>`;
  svg += `<text x="${c1x + 10}" y="${legendY + 4}" class="sheet-caption" dir="${l.dirAttr}">${esc(l.legendBottom)}</text>`;
  svg += `<circle cx="${c2x}" cy="${legendY}" r="3.4" class="bar-dot-slabopening-trim"/>`;
  svg += `<text x="${c2x + 10}" y="${legendY + 4}" class="sheet-caption" dir="${l.dirAttr}">${esc(l.legendTrim)}</text>`;
  svg += `<rect x="${c3x - 5}" y="${legendY - 5}" width="10" height="10" fill="#ffffff" class="cut-line"/>`;
  svg += `<text x="${c3x + 10}" y="${legendY + 4}" class="sheet-caption" dir="${l.dirAttr}">${esc(l.legendOpening)} \u2014 ${Math.round(opening.spanX)}\u00d7${Math.round(opening.spanY)}mm</text>`;

  // Panel overall dims + the opening's own position (offX/offY) from the
  // panel's own (0,0) corner. The opening's SPAN is not dimensioned again
  // here \u2014 already spelled out in the legend line above, and a second
  // dimension line hugging the box itself is exactly what collided in
  // this module's own build-time render check (see the void-rect comment
  // above).
  svg += dimensionLine(sx, sy + h + 20, sx + w, sy + h + 20, `${Math.round(lengthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 20, sy, sx - 20, sy + h, `${Math.round(widthMM)}mm`, { orientation: 'v', tick: 5 });
  svg += dimensionLine(sx, sy - 34, openingPx.x0, sy - 34, `${Math.round(opening.offX)}mm`, { orientation: 'h', tick: 3 });
  svg += dimensionLine(sx - 44, sy, sx - 44, openingPx.y0, `${Math.round(opening.offY)}mm`, { orientation: 'v', tick: 3 });

  svg += `</g>`;
  return svg;
}

function renderSectionView(geometry, scale, box, l) {
  const { lengthMM, thicknessMM, coverMM, mesh, opening, trimBars } = geometry;
  const stripW = lengthMM * scale;
  const stripH = thicknessMM * scale;
  const sx = box.x + (box.w - stripW) / 2;
  const sy = box.y + (box.h - stripH) / 2;
  const openX0 = sx + opening.offX * scale;
  const openX1 = sx + (opening.offX + opening.spanX) * scale;

  let svg = `<g class="section-view">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.section)}</text>`;

  // Two intact segments either side of the void, drawn as their own
  // concrete-hatched rects (never one rect spanning the opening).
  svg += `<rect x="${sx}" y="${sy}" width="${openX0 - sx}" height="${stripH}" fill="url(#concreteHatch)" class="concrete-outline"/>`;
  svg += `<rect x="${openX1}" y="${sy}" width="${sx + stripW - openX1}" height="${stripH}" fill="url(#concreteHatch)" class="concrete-outline"/>`;

  const bottomY = sy + stripH - coverMM * scale;
  const leftBarSpan = openX0 - sx;
  const rightBarSpan = sx + stripW - openX1;
  if (leftBarSpan > 24) {
    svg += `<line x1="${sx + 6}" y1="${bottomY}" x2="${openX0 - 6}" y2="${bottomY}" class="bar-bottom"/>`;
    for (const x of distributeTicks(sx + 12, openX0 - 12, Math.min(mesh.bottom.countX, 4))) svg += barDot(x, bottomY, mesh.bottom.dia, scale, 'slab-bottom');
  }
  if (rightBarSpan > 24) {
    svg += `<line x1="${openX1 + 6}" y1="${bottomY}" x2="${sx + stripW - 6}" y2="${bottomY}" class="bar-bottom"/>`;
    for (const x of distributeTicks(openX1 + 12, sx + stripW - 20, Math.min(mesh.bottom.countX, 4))) svg += barDot(x, bottomY, mesh.bottom.dia, scale, 'slab-bottom');
  }

  // Opening void — full panel height (plus a small overshoot so the
  // dashed outline reads clearly against the two hatched segments), white
  // fill, dashed cut-line boundary, same convention as the plan view.
  svg += `<rect x="${openX0}" y="${sy - 6}" width="${openX1 - openX0}" height="${stripH + 12}" fill="#ffffff" class="cut-line"/>`;

  // Trim bars parallel to Y sit exactly at this cut (the cut runs through
  // the opening's own Y-center — see this file's own "Section cut" header
  // note) — drawn as bar dots at the two void boundaries, at the bottom
  // steel line.
  svg += barDot(openX0, bottomY, trimBars.parallelToY.dia, scale, 'slabopening-trim');
  svg += barDot(openX1, bottomY, trimBars.parallelToY.dia, scale, 'slabopening-trim');

  svg += dimensionLine(sx + stripW + 50, sy, sx + stripW + 50, sy + stripH, `${Math.round(thicknessMM)}mm`, { orientation: 'v', tick: 5 });
  svg += dimensionLine(openX0, sy + stripH + 20, openX1, sy + stripH + 20, `${Math.round(opening.spanX)}mm`, { orientation: 'h', tick: 4 });
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  const { mesh, trimBars } = geometry;
  rows.push({ mark: 'M1', element: l.bottomDirX, dia: String(Math.round(mesh.bottom.dia)), count: `${mesh.bottom.countX} @ ${Math.round(mesh.bottom.spacingX)}`, length: `${Math.round(geometry.widthMM)}${l.extentSuffix}` });
  rows.push({ mark: 'M2', element: l.bottomDirY, dia: String(Math.round(mesh.bottom.dia)), count: `${mesh.bottom.countY} @ ${Math.round(mesh.bottom.spacingY)}`, length: `${Math.round(geometry.lengthMM)}${l.extentSuffix}` });
  rows.push({ mark: 'OY1', element: l.trimRowY(EDGE_LABEL[geometry._lang || 'en'].left), dia: String(Math.round(trimBars.parallelToY.dia)), count: String(trimBars.parallelToY.countPerSide), length: '\u2014' });
  rows.push({ mark: 'OY2', element: l.trimRowY(EDGE_LABEL[geometry._lang || 'en'].right), dia: String(Math.round(trimBars.parallelToY.dia)), count: String(trimBars.parallelToY.countPerSide), length: '\u2014' });
  rows.push({ mark: 'OX1', element: l.trimRowX(EDGE_LABEL[geometry._lang || 'en'].top), dia: String(Math.round(trimBars.parallelToX.dia)), count: String(trimBars.parallelToX.countPerSide), length: '\u2014' });
  rows.push({ mark: 'OX2', element: l.trimRowX(EDGE_LABEL[geometry._lang || 'en'].bottom), dia: String(Math.round(trimBars.parallelToX.dia)), count: String(trimBars.parallelToX.countPerSide), length: '\u2014' });
  return rows;
}

export function renderSlabOpeningDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const planScale = fitScale([{ contentW: geometry.lengthMM, contentH: geometry.widthMM, boxW: PLAN_BOX.w - 60, boxH: PLAN_BOX.h - 80 }]);
  const sectionScale = fitScale([{ contentW: geometry.lengthMM, contentH: geometry.thicknessMM, boxW: SECTION_BOX.w - 40, boxH: SECTION_BOX.h - 60 }]);

  // buildScheduleRows needs the edge-label language but geometry itself
  // carries no lang field (compute is language-agnostic, same as every
  // sibling module) — pass it through a throwaway own-property rather
  // than adding a `lang` field to the geometry contract every OTHER
  // render call site would then have to know is render-only, not part of
  // the real geometry.
  const tableRows = buildScheduleRows({ ...geometry, _lang: lang }, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = Math.max(PLAN_BOX.y + PLAN_BOX.h, SECTION_BOX.y + SECTION_BOX.h) + 70;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .slabopening-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .bar-dot-slab-bottom       { fill:#c0392b; stroke:#7a2015; stroke-width:0.6; }
    .bar-dot-slabopening-trim  { fill:#e67e22; stroke:#a15c14; stroke-width:0.6; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="slabopening-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderPlanView(geometry, planScale, PLAN_BOX, l)}
  ${renderSectionView(geometry, sectionScale, SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// ── Chat-facing entry point ────────────────────────────────────────────
// Mirrors columnDiagram.mjs's parseColumnRebarPayload() error-shape
// contract exactly ({ok:true,...} / {ok:false,code,message}).
export function parseSlabOpeningRebarPayload(raw) {
  try {
    const geometry = computeSlabOpeningDiagramGeometry(raw);
    return { ok: true, type: 'slabOpening', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Mirrors slabDiagram.mjs's parseDiagramCommand exactly: same leading-
// token+"key=value key=value..." syntax, same BAD_SYNTAX/UNSUPPORTED_TYPE
// reservation (BAD_SYNTAX = no leading-token+params shape at all;
// UNSUPPORTED_TYPE = shape present but leading token isn't "slabopening"
// — lets diagramCommandRouter.mjs try the next module without masking a
// real syntax error), same never-throws contract, error results also
// carry `.type` (the pattern slab/shearWall/stair/column's own catch
// blocks established).
//
// Syntax:
//   /diagram slabopening id=S1 length=6000 width=4000 thickness=180 cover=25
//     botdia=12 botspacingx=150 [botspacingy=150]
//     offx=1200 offy=900 spanx=600 spany=600
//     trimxdia=12 trimxcount=3 trimydia=12 trimycount=3
//     [unit=mm]
// Keys for the opening (offx/offy/spanx/spany) and trim-bar groups
// (trimxdia/trimxcount, trimydia/trimycount) are the flat-command surface
// for `opening` and `trimBars` above — same "one key per scalar field,
// lower-cased" convention as every sibling module's own flat command.
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: slabopening key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'slabopening') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use slabopening.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const geometry = computeSlabOpeningDiagramGeometry({
      slabId: kv.id, lengthMM: num('length'), widthMM: num('width'),
      thicknessMM: num('thickness'), coverMM: num('cover'),
      mesh: { bottom: { diameterMM: num('botdia'), spacingXMM: num('botspacingx'), spacingYMM: num('botspacingy') } },
      opening: { offXMM: num('offx'), offYMM: num('offy'), spanXMM: num('spanx'), spanYMM: num('spany') },
      trimBars: {
        parallelToX: { diameterMM: num('trimxdia'), countPerSide: num('trimxcount') },
        parallelToY: { diameterMM: num('trimydia'), countPerSide: num('trimycount') },
      },
      unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
