// functions/_lib/basementWallDiagram.mjs
//
// Deterministic, zero-AI SVG generator for a basement wall's TYPICAL
// CROSS-SECTION reinforcement detail — new-element candidate, pool 2
// ("ACI 318 coverage gaps"), item #2 of برومبت_استكمال_العمل_v17.md
// ("أعلى أولوية"). Same philosophy as every other element module in this
// app: every dimension, bar position, and spacing in the output is
// arithmetic on the KB data supplied, never a model's guess, and never a
// geotechnical/structural design calculation this module doesn't own.
//
// ── WHY THIS IS NOT retainingWallDiagram.mjs ────────────────────────────
// Per the v17 prompt note that proposed this element: retainingWallDiagram
// models a wall free-cantilevered from the top (fixed at the base only) —
// main flexural steel lives on ONE face only (soil side), because the
// bending moment keeps one sign over the full height. A basement wall is
// RESTRAINED at both ends (top: the ground-floor slab; bottom: the
// footing), so the moment can reverse sign along the height (behaves like
// a continuous or two-way member, not a free cantilever). The structural
// consequence this module's schema exists to represent — WITHOUT
// computing the moment diagram itself, which is the engineer's job, not
// this app's — is that a restrained wall generally needs main vertical
// steel on BOTH faces (a double curtain), not one, plus the option of
// concentrated extra bars near each restrained end where local negative
// moment can exceed the mid-height design. See exteriorVerticalBars/
// interiorVerticalBars/topExtraBars/bottomExtraBars below.
//
// SCOPE (v1): a single prismatic wall panel (constant thicknessMM over
// its full heightMM), drawn as ONE typical section (per running metre of
// wall, the same convention retainingWallDiagram.mjs/real basement-wall
// shop drawings use), not a full elevation along the wall's run. NOT
// modeled, on purpose (same explicit-scope-boundary convention every
// other module here documents):
//   - battered/stepped-thickness wall — thicknessMM is constant over the
//     full heightMM.
//   - the floor slab and footing themselves — only schematic STUB blocks
//     are drawn to represent "restrained here"; the actual slab/footing
//     reinforcement is slabDiagram.mjs's/footingDiagram.mjs's own scope,
//     not duplicated here.
//   - soil pressure, bearing pressure, or any moment/shear design
//     calculation, INCLUDING which face carries which zone's steel — this
//     module draws whatever bar sizes/spacings/faces the caller supplies;
//     topExtraBars/bottomExtraBars are drawn on the interior face as this
//     module's own illustrative convention (a below-grade wall fixed top
//     and bottom commonly needs interior-face steel at both restrained
//     ends), NOT an assertion that this is correct for any given design —
//     verify against your own moment diagram (see caption).
//   - wall RUN LENGTH (along the wall, out of the section plane) or a bar
//     COUNT along that run for exteriorVerticalBars/interiorVerticalBars —
//     a typical section shows one representative bar per group with a
//     spacing callout, exactly like retainingWallDiagram.mjs's
//     stemMainBars. horizontalBars is the one group with a genuine
//     in-plane count (stacked at real heights within this section plane),
//     same split as that file's stemDistBars.
//   - openings (door/window/duct penetrations through the wall).
//   - construction/movement joints, waterproofing or damp-proofing
//     membrane — this is a rebar module, not a waterproofing detail.
//   - hooks/bends on topExtraBars/bottomExtraBars — projectionMM is the
//     drawn extent from the restrained end only (see
//     structuralDrawingKit.mjs's header on "drawn extent" vs. "actual
//     cutting length" for the distinction this follows); add hook/lap
//     length per your design code before fabrication.
//
// ── INPUT CONTRACT ──────────────────────────────────────────────────────
// {
//   unit?: 'mm'|'cm'|'m',                 // default 'mm'
//   wallId: string,                       // wall mark, e.g. "BW-1"
//   heightMM: number,                     // clear height between the top
//                                         // restraint (slab) and bottom
//                                         // restraint (footing top)
//   thicknessMM: number,                  // constant wall thickness
//   coverMM: number,                      // one cover value, both faces
//   soilHeightMM?: number,                // backfill block drawn against
//                                         // the exterior face, measured
//                                         // UP FROM THE BOTTOM (soil is
//                                         // placed from the footing
//                                         // upward during backfilling);
//                                         // default = heightMM (fully
//                                         // backfilled, the normal
//                                         // below-grade case), capped at
//                                         // heightMM
//   exteriorVerticalBars: { diameterMM, spacingMM }, // soil-side face,
//                                         // full height, no in-plane
//                                         // count (see SCOPE)
//   interiorVerticalBars: { diameterMM, spacingMM }, // room-side face,
//                                         // full height, no in-plane
//                                         // count \u2014 the double-curtain
//                                         // group that distinguishes this
//                                         // element from a free-cantilever
//                                         // retaining-wall stem
//   horizontalBars: { diameterMM, spacingMM },       // temperature/
//                                         // shrinkage steel, ONE spec
//                                         // applied to both faces (same
//                                         // simplification
//                                         // shearWallDiagram.mjs's own
//                                         // mesh.horizontal already uses)
//   topExtraBars?: { diameterMM, count, projectionMM },   // OPTIONAL,
//                                         // concentrated extra bars,
//                                         // interior face, at the TOP
//                                         // restraint zone
//   bottomExtraBars?: { diameterMM, count, projectionMM },// OPTIONAL,
//                                         // same, at the BOTTOM restraint
//                                         // zone
// }
//
// ── Chat-facing entry point / wiring ────────────────────────────────────
// parseBasementWallRebarPayload() mirrors parseRetainingWallRebarPayload/
// parseShearWallRebarPayload's error-shape contract exactly
// ({ok:true,...}/{ok:false,code,message}). parseDiagramCommand() below is
// written to the same flat `key=value` convention as every sibling
// module's own copy \u2014 but per this session's explicit instruction,
// NEITHER is wired into diagramCommandRouter.mjs NOR chat.js yet. When
// that wiring happens: `type` must be returned as the LOWER-CASE router
// token ('basementwall'), not the camelCase 'basementWall' geometry.type
// above \u2014 this is the exact casing trap retainingWallDiagram.mjs's own
// header already documents hitting once (a camelCase return there broke
// diagramCommandRouter.mjs's module load entirely, cascading into
// chat.js). parseDiagramCommand already returns the lower-case token
// correctly below; do not "fix" it to camelCase when wiring this in.
//
// Resource lifecycle: pure/synchronous, zero imports beyond the shared
// kit, no timers/fetch/KV/handles. Fully deterministic: no env.AI, no
// model call, no randomness anywhere in this file.

import {
  DiagramError, toMm, assertFinitePositive, assertFiniteNonNegative, assertInt,
  assertNoIntervalOverlap, esc, captionLineCount, renderCaptionAt, fontStacks,
  kitStyleBlock, hatchDefs, dimensionLine, barDot, distributeTicks,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ─────────────────────────────────────────────────────
// Same role as every other module's MAX_*: this is a chat-driven
// schematic tool, not a CAD system.
const MIN_HEIGHT_MM = 2000;
const MAX_HEIGHT_MM = 6000; // one basement story, schematically \u2014 same
// rationale as columnDiagram.mjs's/shearWallDiagram.mjs's own MAX_HEIGHT_MM.
const MIN_THICKNESS_MM = 150;
const MAX_THICKNESS_MM = 600; // matches shearWallDiagram.mjs's thickness range
const MIN_VERT_SPACING_MM = 75;
const MAX_VERT_SPACING_MM = 300;
const MIN_HORIZ_SPACING_MM = 75;
const MAX_HORIZ_SPACING_MM = 400;
const MIN_SOIL_HEIGHT_MM = 100;
const MIN_EXTRA_BAR_COUNT = 2;
const MAX_EXTRA_BAR_COUNT = 12;
const MIN_EXTRA_PROJECTION_MM = 150;
const MAX_EXTRA_PROJECTION_MM = 3000;
// Matches the 14-per-axis cap slabDiagram.mjs/shearWallDiagram.mjs/
// stairDiagram.mjs/retainingWallDiagram.mjs all settled on \u2014 reusing an
// already CPU-timed safe ceiling, not raising past it (see
// structuralDrawingKit.mjs's Step 18 note: that rule gates RAISING a
// limit, not reusing a lower, already-validated one).
const MAX_DRAWN_HORIZ_BARS = 14;

// ── Compute ─────────────────────────────────────────────────────────
function readBarGroup(raw, unit, label, { minSpacing, maxSpacing }) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', `"${label}" is required: { diameterMM, spacingMM }.`);
  }
  const dia = toMm(raw.diameterMM, unit);
  assertFinitePositive(`${label}.diameterMM`, dia);
  const spacing = toMm(raw.spacingMM, unit);
  assertFinitePositive(`${label}.spacingMM`, spacing);
  if (spacing < minSpacing || spacing > maxSpacing) {
    throw new DiagramError('BAD_PARAM', `"${label}.spacingMM" must be between ${minSpacing}mm and ${maxSpacing}mm, got ${spacing}mm.`);
  }
  return { dia, spacing };
}

function readExtraBars(raw, unit, label, heightMM) {
  if (raw == null) return null;
  if (typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', `"${label}" must be an object: { diameterMM, count, projectionMM }.`);
  }
  const dia = toMm(raw.diameterMM, unit);
  assertFinitePositive(`${label}.diameterMM`, dia);
  assertInt(`${label}.count`, raw.count, { min: MIN_EXTRA_BAR_COUNT, max: MAX_EXTRA_BAR_COUNT });
  const projectionMM = toMm(raw.projectionMM, unit);
  assertFinitePositive(`${label}.projectionMM`, projectionMM);
  if (projectionMM < MIN_EXTRA_PROJECTION_MM || projectionMM > MAX_EXTRA_PROJECTION_MM) {
    throw new DiagramError('BAD_PARAM', `"${label}.projectionMM" must be between ${MIN_EXTRA_PROJECTION_MM}mm and ${MAX_EXTRA_PROJECTION_MM}mm, got ${projectionMM}mm.`);
  }
  if (projectionMM >= heightMM) {
    throw new DiagramError('BAD_PARAM', `"${label}.projectionMM" (${projectionMM}mm) must be less than heightMM (${heightMM}mm).`);
  }
  return { dia, count: raw.count, projectionMM };
}

export function computeBasementWallDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Basement wall diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.wallId != null ? String(raw.wallId).slice(0, 40) : 'BW';

  const heightMM = toMm(raw.heightMM, unit);
  assertFinitePositive('heightMM', heightMM);
  if (heightMM < MIN_HEIGHT_MM || heightMM > MAX_HEIGHT_MM) {
    throw new DiagramError('BAD_PARAM', `"heightMM" must be between ${MIN_HEIGHT_MM}mm and ${MAX_HEIGHT_MM}mm for this schematic, got ${heightMM}mm.`);
  }
  const thicknessMM = toMm(raw.thicknessMM, unit);
  assertFinitePositive('thicknessMM', thicknessMM);
  if (thicknessMM < MIN_THICKNESS_MM || thicknessMM > MAX_THICKNESS_MM) {
    throw new DiagramError('BAD_PARAM', `"thicknessMM" must be between ${MIN_THICKNESS_MM}mm and ${MAX_THICKNESS_MM}mm, got ${thicknessMM}mm.`);
  }
  const coverMM = toMm(raw.coverMM, unit);
  assertFinitePositive('coverMM', coverMM);
  if (coverMM * 2 >= thicknessMM) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) on both faces leaves no room inside a ${thicknessMM}mm-thick wall.`);
  }

  const soilHeightMM = raw.soilHeightMM != null ? toMm(raw.soilHeightMM, unit) : heightMM;
  assertFinitePositive('soilHeightMM', soilHeightMM);
  if (soilHeightMM < MIN_SOIL_HEIGHT_MM || soilHeightMM > heightMM) {
    throw new DiagramError('BAD_PARAM', `"soilHeightMM" must be between ${MIN_SOIL_HEIGHT_MM}mm and heightMM (${heightMM}mm), got ${soilHeightMM}mm.`);
  }

  const extVert = readBarGroup(raw.exteriorVerticalBars, unit, 'exteriorVerticalBars', { minSpacing: MIN_VERT_SPACING_MM, maxSpacing: MAX_VERT_SPACING_MM });
  const intVert = readBarGroup(raw.interiorVerticalBars, unit, 'interiorVerticalBars', { minSpacing: MIN_VERT_SPACING_MM, maxSpacing: MAX_VERT_SPACING_MM });
  const horiz = readBarGroup(raw.horizontalBars, unit, 'horizontalBars', { minSpacing: MIN_HORIZ_SPACING_MM, maxSpacing: MAX_HORIZ_SPACING_MM });

  // Real (uncapped) count of horizontal-bar LEVELS up the height \u2014 the
  // one bar group in this module with a genuine in-plane count (see SCOPE
  // above); drawn (capped) positions derived at render time.
  const horizCount = Math.max(2, Math.round(heightMM / horiz.spacing) + 1);

  const topExtraBars = readExtraBars(raw.topExtraBars, unit, 'topExtraBars', heightMM);
  const bottomExtraBars = readExtraBars(raw.bottomExtraBars, unit, 'bottomExtraBars', heightMM);
  if (topExtraBars && bottomExtraBars) {
    // Reuses the kit's own overlap guard (already proved out for beam
    // stirrup zones) rather than a fourth hand-rolled interval check \u2014
    // same "no fourth copy" discipline structuralDrawingKit.mjs's own
    // header documents this app avoiding elsewhere.
    assertNoIntervalOverlap(
      [{ s: 0, e: topExtraBars.projectionMM }, { s: heightMM - bottomExtraBars.projectionMM, e: heightMM }],
      { startKey: 's', endKey: 'e', label: 'top/bottom extra-bar zone' },
    );
  }

  return {
    type: 'basementWall', unit, id, heightMM, thicknessMM, coverMM, soilHeightMM,
    exteriorVerticalBars: extVert, interiorVerticalBars: intVert,
    horizontalBars: { dia: horiz.dia, spacing: horiz.spacing, count: horizCount },
    topExtraBars, bottomExtraBars,
  };
}

// ── Labels ──────────────────────────────────────────────────────────
// PARENTHESES/EM-DASH WARNING (same constraint retainingWallDiagram.mjs/
// structuralLabels.mjs document): Noto Naskh Arabic has no glyph for "(",
// ")", or an em/en-dash. No Arabic value below uses any of the three; the
// notModeled placeholder is only ever used in the 'length' column, so it
// is worded as plain text ("غير محسوب"), not an em-dash.
const L = {
  en: {
    title: (id) => `BASEMENT WALL ${id} \u2014 TYPICAL SECTION`,
    section: 'SECTION',
    extVert: 'Vertical, exterior (soil) face', intVert: 'Vertical, interior (room) face',
    horiz: 'Horizontal, both faces', topExtra: 'Extra, top restraint zone (interior face)',
    bottomExtra: 'Extra, bottom restraint zone (interior face)',
    extentSuffix: ' (extent)', notModeled: 'not modeled (typical section)',
    topRestraint: 'FLOOR SLAB (TOP RESTRAINT)', bottomRestraint: 'FOOTING (BOTTOM RESTRAINT)',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, spacing, and length against your own design (ECP 203 / ACI 318) before issuing for construction. This is a TYPICAL SECTION only: no soil pressure, bearing pressure, or moment/shear design is computed here, and no wall-run bar count is assumed. The floor slab and footing are shown as schematic restraint stubs only \u2014 see slabDiagram.mjs / footingDiagram.mjs for their own reinforcement detail. Which face carries topExtraBars/bottomExtraBars is this module\u2019s illustrative convention, not a design determination \u2014 verify against your own moment diagram. Extra-bar lengths shown are the drawn projection from the restrained end only, not a fabrication cutting length \u2014 add hook/lap length per your design code.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد جدار القبو ${id}`,
    section: 'قطاع نمطي',
    extVert: 'رأسي، الوجه الخارجي عند التربة', intVert: 'رأسي، الوجه الداخلي عند الغرفة',
    horiz: 'أفقي، الوجهان معاً', topExtra: 'حديد إضافي، منطقة القيد العلوي، الوجه الداخلي',
    bottomExtra: 'حديد إضافي، منطقة القيد السفلي، الوجه الداخلي',
    extentSuffix: ' امتداد', notModeled: 'غير محسوب، قطاع نمطي',
    topRestraint: 'بلاطة الأرضية، القيد العلوي', bottomRestraint: 'القاعدة، القيد السفلي',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وتباعدها وطولها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. هذا قطاع نمطي فقط؛ لا يُحسب هنا ضغط التربة ولا إجهاد التربة ولا تصميم العزم أو القص، ولا يُفترض عدد أسياخ على طول الجدار. بلاطة الأرضية والقاعدة مُمثَّلتان كمقطع قيد توضيحي فقط، راجع الرسم التفصيلي الخاص بكل منهما في وحدته المستقلة. اختيار الوجه الحامل للحديد الإضافي العلوي والسفلي هو اصطلاح توضيحي من هذه الوحدة، وليس قراراً تصميمياً؛ تحقق من مخطط العزم الخاص بك. أطوال الحديد الإضافي المذكورة هي طول الامتداد من نهاية القيد فقط، وليست طول قطع للتصنيع؛ أضف طول الكلبة والتداخل حسب الكود المستخدم.',
    dirAttr: 'rtl',
  },
};

// ── Render ──────────────────────────────────────────────────────────
const CANVAS_W = 950;
const SECTION_BOX = { x: 260, y: 110, w: 430, h: 480 };
const STUB_H = 26;
const STUB_OVERHANG = 40;

// Short diagonal hatch ticks along a horizontal edge \u2014 the standard
// drafting "fixed support" callout. No shared kit function wraps this
// (same "a boundary zone's own outline needs no new kit function"
// precedent structuralDrawingKit.mjs's Step 18 note documents for
// shearWallDiagram.mjs's boundary-element rects) \u2014 written locally.
function restraintHachure(x1, x2, y) {
  const n = 8;
  const step = (x2 - x1) / n;
  let svg = '';
  for (let i = 0; i <= n; i++) {
    const x = x1 + i * step;
    svg += `<line x1="${x.toFixed(2)}" y1="${y}" x2="${(x - 9).toFixed(2)}" y2="${y + 12}" class="restraint-hachure"/>`;
  }
  return svg;
}

function renderSectionView(geometry, scale, box, l) {
  const {
    heightMM, thicknessMM, coverMM, soilHeightMM,
    exteriorVerticalBars, interiorVerticalBars, horizontalBars,
    topExtraBars, bottomExtraBars,
  } = geometry;

  // Local mm coords: x runs across the thickness (0 = exterior/soil face,
  // thicknessMM = interior/room face); y runs DOWN the page (0 = top of
  // wall / top restraint level, heightMM = bottom of wall / bottom
  // restraint level) \u2014 a single shared origin, same convention
  // retainingWallDiagram.mjs's px() uses.
  const wallWpx = thicknessMM * scale, wallHpx = heightMM * scale;
  const sx = box.x + (box.w - wallWpx) / 2;
  const sy = box.y + 70; // headroom for the top restraint stub + label
  const px = (xMM, yMM) => ({ x: sx + xMM * scale, y: sy + yMM * scale });

  let svg = `<g class="section-view">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.section)}</text>`;

  // Soil backfill: measured up from the BOTTOM (footing) \u2014 backfilling
  // proceeds from the excavation base upward, so a partial soilHeightMM
  // means "backfilled this far up from the footing", not from the top.
  const soilTopMM = heightMM - soilHeightMM;
  const soilTop = px(0, soilTopMM);
  svg += `<rect x="${(soilTop.x - STUB_OVERHANG).toFixed(2)}" y="${soilTop.y.toFixed(2)}" width="${STUB_OVERHANG}" height="${(soilHeightMM * scale).toFixed(2)}" fill="url(#soilHatch)" stroke="#8a7350" stroke-width="1"/>`;

  // Top restraint stub (floor slab) \u2014 schematic only, see module SCOPE.
  const topStubY = sy - STUB_H;
  svg += `<rect x="${(sx - STUB_OVERHANG).toFixed(2)}" y="${topStubY.toFixed(2)}" width="${(wallWpx + 2 * STUB_OVERHANG).toFixed(2)}" height="${STUB_H}" fill="url(#concreteHatch)" class="concrete-outline"/>`;
  svg += restraintHachure(sx - STUB_OVERHANG, sx + wallWpx + STUB_OVERHANG, topStubY);
  svg += `<text x="${(sx + wallWpx + STUB_OVERHANG + 10).toFixed(2)}" y="${(topStubY + STUB_H / 2 + 4).toFixed(2)}" class="restraint-label" dir="${l.dirAttr}">${esc(l.topRestraint)}</text>`;

  // Wall panel.
  const wallTL = px(0, 0);
  svg += `<rect x="${wallTL.x.toFixed(2)}" y="${wallTL.y.toFixed(2)}" width="${wallWpx.toFixed(2)}" height="${wallHpx.toFixed(2)}" class="concrete-outline"/>`;

  // Bottom restraint stub (footing top) \u2014 schematic only, see SCOPE.
  const botStubY = sy + wallHpx;
  svg += `<rect x="${(sx - STUB_OVERHANG).toFixed(2)}" y="${botStubY.toFixed(2)}" width="${(wallWpx + 2 * STUB_OVERHANG).toFixed(2)}" height="${STUB_H}" fill="url(#concreteHatch)" class="concrete-outline"/>`;
  svg += restraintHachure(sx - STUB_OVERHANG, sx + wallWpx + STUB_OVERHANG, botStubY + STUB_H);
  svg += `<text x="${(sx + wallWpx + STUB_OVERHANG + 10).toFixed(2)}" y="${(botStubY + STUB_H / 2 + 4).toFixed(2)}" class="restraint-label" dir="${l.dirAttr}">${esc(l.bottomRestraint)}</text>`;

  // Exterior (soil-face) vertical bars \u2014 single representative line, red.
  const extX = coverMM + exteriorVerticalBars.dia / 2;
  const extTop = px(extX, coverMM + exteriorVerticalBars.dia / 2);
  const extBot = px(extX, heightMM - coverMM - exteriorVerticalBars.dia / 2);
  svg += `<line x1="${extTop.x.toFixed(2)}" y1="${extTop.y.toFixed(2)}" x2="${extBot.x.toFixed(2)}" y2="${extBot.y.toFixed(2)}" class="bar-bottom"/>`;
  svg += barDot(extTop.x, extTop.y, exteriorVerticalBars.dia, scale, 'ext');
  svg += barDot(extBot.x, extBot.y, exteriorVerticalBars.dia, scale, 'ext');

  // Interior (room-face) vertical bars \u2014 single representative line, blue.
  const intX = thicknessMM - coverMM - interiorVerticalBars.dia / 2;
  const intTop = px(intX, coverMM + interiorVerticalBars.dia / 2);
  const intBot = px(intX, heightMM - coverMM - interiorVerticalBars.dia / 2);
  svg += `<line x1="${intTop.x.toFixed(2)}" y1="${intTop.y.toFixed(2)}" x2="${intBot.x.toFixed(2)}" y2="${intBot.y.toFixed(2)}" class="bar-top"/>`;
  svg += barDot(intTop.x, intTop.y, interiorVerticalBars.dia, scale, 'int');
  svg += barDot(intBot.x, intBot.y, interiorVerticalBars.dia, scale, 'int');

  // Horizontal bars (both faces) \u2014 dots stacked up the height at each
  // vertical bar's own x-position (they sit just inside the vertical
  // curtain on each face), capped at MAX_DRAWN_HORIZ_BARS.
  const drawHorizCount = Math.min(horizontalBars.count, MAX_DRAWN_HORIZ_BARS);
  const horizTopMM = coverMM + horizontalBars.dia / 2;
  const horizBotMM = heightMM - coverMM - horizontalBars.dia / 2;
  const extTicksY = distributeTicks(px(extX, horizTopMM).y, px(extX, horizBotMM).y, drawHorizCount);
  const intTicksY = distributeTicks(px(intX, horizTopMM).y, px(intX, horizBotMM).y, drawHorizCount);
  for (const y of extTicksY) svg += barDot(px(extX, 0).x, y, horizontalBars.dia, scale, 'horiz');
  for (const y of intTicksY) svg += barDot(px(intX, 0).x, y, horizontalBars.dia, scale, 'horiz');

  // Optional extra bars at each restraint zone \u2014 interior face (this
  // module's own illustrative convention, see SCOPE/caption).
  if (topExtraBars) {
    const drawCount = Math.min(topExtraBars.count, MAX_EXTRA_BAR_COUNT);
    const ys = distributeTicks(px(intX, coverMM).y, px(intX, topExtraBars.projectionMM).y, drawCount);
    for (const y of ys) svg += barDot(px(intX, 0).x, y, topExtraBars.dia, scale, 'extra');
  }
  if (bottomExtraBars) {
    const drawCount = Math.min(bottomExtraBars.count, MAX_EXTRA_BAR_COUNT);
    const ys = distributeTicks(px(intX, heightMM - bottomExtraBars.projectionMM).y, px(intX, heightMM - coverMM).y, drawCount);
    for (const y of ys) svg += barDot(px(intX, 0).x, y, bottomExtraBars.dia, scale, 'extra');
  }

  // Dimensions: overall height (left edge), thickness (below bottom stub).
  svg += dimensionLine(sx - STUB_OVERHANG - 26, sy, sx - STUB_OVERHANG - 26, sy + wallHpx, `${Math.round(heightMM)}mm`, { orientation: 'v', tick: 5 });
  svg += dimensionLine(sx, botStubY + STUB_H + 22, sx + wallWpx, botStubY + STUB_H + 22, `${Math.round(thicknessMM)}mm`, { orientation: 'h', tick: 5 });

  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  const { exteriorVerticalBars, interiorVerticalBars, horizontalBars, topExtraBars, bottomExtraBars, heightMM } = geometry;
  rows.push({ mark: 'V-EXT', element: l.extVert, dia: String(Math.round(exteriorVerticalBars.dia)), count: `\u2014 @ ${Math.round(exteriorVerticalBars.spacing)}`, length: `${Math.round(heightMM)}${l.extentSuffix}` });
  rows.push({ mark: 'V-INT', element: l.intVert, dia: String(Math.round(interiorVerticalBars.dia)), count: `\u2014 @ ${Math.round(interiorVerticalBars.spacing)}`, length: `${Math.round(heightMM)}${l.extentSuffix}` });
  rows.push({ mark: 'H1', element: l.horiz, dia: String(Math.round(horizontalBars.dia)), count: `${horizontalBars.count} @ ${Math.round(horizontalBars.spacing)}`, length: l.notModeled });
  if (topExtraBars) {
    rows.push({ mark: 'T1', element: l.topExtra, dia: String(Math.round(topExtraBars.dia)), count: String(topExtraBars.count), length: `${Math.round(topExtraBars.projectionMM)}${l.extentSuffix}` });
  }
  if (bottomExtraBars) {
    rows.push({ mark: 'B1', element: l.bottomExtra, dia: String(Math.round(bottomExtraBars.dia)), count: String(bottomExtraBars.count), length: `${Math.round(bottomExtraBars.projectionMM)}${l.extentSuffix}` });
  }
  return rows;
}

export function renderBasementWallDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const sectionScale = fitScale([{
    contentW: geometry.thicknessMM, contentH: geometry.heightMM,
    boxW: SECTION_BOX.w - 260, boxH: SECTION_BOX.h - 110,
  }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = SECTION_BOX.y + SECTION_BOX.h + 40;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .wall-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .restraint-label { font-size:10.5px; fill:#555; font-family: ${scriptFontStack}; }
    .restraint-hachure { stroke:#1a1a1a; stroke-width:1; }
    .bar-dot-ext   { fill:#c0392b; stroke:#7a2015; stroke-width:0.6; }
    .bar-dot-int   { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }
    .bar-dot-horiz { fill:#2f7a3d; stroke:#1c4d26; stroke-width:0.6; }
    .bar-dot-extra { fill:#d68910; stroke:#8a5a09; stroke-width:0.6; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="wall-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderSectionView(geometry, sectionScale, SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// ── Chat-facing entry point ────────────────────────────────────────────
export function parseBasementWallRebarPayload(raw) {
  try {
    const geometry = computeBasementWallDiagramGeometry(raw);
    return { ok: true, type: 'basementWall', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// NOT wired into diagramCommandRouter.mjs/chat.js this session (deferred
// per instruction) \u2014 written now so wiring later is a pure addition,
// same as every sibling module's own parser.
//
// Syntax:
//   /diagram basementwall id=BW-1 height=3000 thickness=300 cover=40
//     extdia=16 extspacing=150 intdia=16 intspacing=150
//     hdia=12 hspacing=200
//     [soilheight=3000]
//     [topextradia=16 topextracount=4 topextraproj=600]
//     [botextradia=16 botextracount=4 botextraproj=600]
//     [unit=mm]
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: basementwall key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'basementwall') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use basementwall.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    let topExtraBars, bottomExtraBars;
    if (['topextradia', 'topextracount', 'topextraproj'].some((k) => k in kv)) {
      topExtraBars = { diameterMM: num('topextradia'), count: num('topextracount'), projectionMM: num('topextraproj') };
    }
    if (['botextradia', 'botextracount', 'botextraproj'].some((k) => k in kv)) {
      bottomExtraBars = { diameterMM: num('botextradia'), count: num('botextracount'), projectionMM: num('botextraproj') };
    }
    const geometry = computeBasementWallDiagramGeometry({
      wallId: kv.id, heightMM: num('height'), thicknessMM: num('thickness'), coverMM: num('cover'),
      soilHeightMM: 'soilheight' in kv ? num('soilheight') : undefined,
      exteriorVerticalBars: { diameterMM: num('extdia'), spacingMM: num('extspacing') },
      interiorVerticalBars: { diameterMM: num('intdia'), spacingMM: num('intspacing') },
      horizontalBars: { diameterMM: num('hdia'), spacingMM: num('hspacing') },
      topExtraBars, bottomExtraBars, unit: kv.unit || 'mm',
    });
    return { ok: true, type: 'basementwall', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type: 'basementwall', code: err.code, message: err.message };
    throw err;
  }
}
