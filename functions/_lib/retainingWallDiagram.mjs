// functions/_lib/retainingWallDiagram.mjs
//
// Deterministic, zero-AI SVG generator for a cantilever retaining wall's
// TYPICAL CROSS-SECTION reinforcement detail (stem + base slab, one
// section cut perpendicular to the wall's run) — new element track,
// Part 2 candidate 1 (برومبت_استكمال_العمل.md v10). Same philosophy as
// footingDiagram.mjs/beamDiagram.mjs/columnDiagram.mjs/stairDiagram.mjs:
// every dimension, bar position, and spacing in the output is arithmetic
// on the KB data supplied, never a model's guess, and never a
// geotechnical/structural calculation this module doesn't own.
//
// SCOPE (v1): a single prismatic cantilever wall — constant-thickness
// stem (no batter/taper) on a constant-thickness rectangular base slab
// (toe + heel either side of the stem), drawn as ONE typical section —
// the same convention real retaining-wall drawings use (a repeating
// "typical section" with bar-size@spacing callouts), not a full
// elevation along the wall's run. NOT modeled, on purpose (same
// explicit-scope-boundary convention columnDiagram.mjs's own header
// uses):
//   - battered/tapered stem, stepped-thickness stem — thicknessMM is
//     constant over the full stemHeightMM.
//   - shear key beneath the base, counterforts/buttresses — this is a
//     plain cantilever wall, not those wall families.
//   - soil pressure, bearing pressure, sliding/overturning/global
//     stability checks, or any moment/shear calculation — this module
//     draws whatever bar sizes and spacings the caller supplies; it does
//     not perform geotechnical or structural design, exactly like every
//     other module in this app never invents a number it wasn't handed
//     (see structuralDrawingKit.mjs's header on "drawn extent" vs.
//     "actual cut length" for the general rule this follows).
//   - total wall RUN LENGTH (along the wall, out of the section plane)
//     or a bar COUNT along that run — a typical section shows one
//     representative bar per group with a spacing callout, the same way
//     a real retaining-wall drawing does; inventing a wall length just
//     to produce a "count" number would be exactly the kind of
//     defended-by-nothing number this app's philosophy forbids. The one
//     EXCEPTION is stemDistBars, which are genuinely stacked at
//     different HEIGHTS within this section plane (temperature/
//     shrinkage bars, one per level up the stem) — those DO have a real,
//     in-plane count, computed the same way stairDiagram.mjs's
//     distribution-bar count is.
//   - stem-to-base bar continuity (a bent/hooked bar carried from the
//     stem down into the base) — stemMainBars and the two base bar
//     groups are drawn as INDEPENDENT bar marks, not one continuous bent
//     bar, matching footingDiagram.mjs's own dowel-vs-column-bar
//     precedent (a dowel group and a column's own main bars are two
//     separate marks there too, not fused into one guessed shape).
//   - base-slab distribution/transverse steel — only the two MAIN base
//     groups (toe-bottom, heel-top) are modeled; a third/fourth base bar
//     group would need its own zone logic this v1 doesn't have yet.
//   - drainage (weep holes, granular backfill, geotextile) — not shown.
//   - surcharge or backfill above the top of the stem — soilHeightMM is
//     capped at stemHeightMM (see caps below); this is a schematic
//     backfill block on the heel, not a load case.
//
// ── INPUT CONTRACT (what the KB layer should hand this module) ────────
// {
//   unit?: 'mm'|'cm'|'m',                // default 'mm'
//   wallId: string,                      // wall mark, e.g. "RW-1"
//   stem: {
//     heightMM: number,                  // stem height above top of base
//     thicknessMM: number,               // constant stem thickness
//   },
//   base: {
//     toeLengthMM: number,               // projection in FRONT of stem
//                                        // (away from retained soil);
//                                        // may be 0 (no toe)
//     heelLengthMM: number,              // projection BEHIND stem
//                                        // (under retained soil); may
//                                        // be 0 (no heel)
//     thicknessMM: number,               // constant base slab thickness
//   },
//   coverMM: number,                     // one cover value, both stem
//                                        // faces and both base faces
//   soilHeightMM?: number,               // retained-backfill block drawn
//                                        // over the heel, illustrative
//                                        // only; default = stem.heightMM
//                                        // (full-height backfill)
//   stemMainBars: { diameterMM, spacingMM },   // vertical, soil-side
//                                              // (back) face — resists
//                                              // cantilever bending
//   stemDistBars: { diameterMM, spacingMM },   // horizontal, front
//                                              // (exposed) face —
//                                              // temperature/shrinkage;
//                                              // the one group with a
//                                              // real in-plane count
//                                              // (see SCOPE above)
//   baseBottomBars: { diameterMM, spacingMM }, // toe region, bottom face
//   baseTopBars: { diameterMM, spacingMM },    // heel region, top face
// }
//
// ── Chat-facing entry point / wiring ───────────────────────────────────
// parseRetainingWallRebarPayload() below mirrors parseColumnRebarPayload
// /parseStairRebarPayload's error-shape contract exactly.
//
// [Fix, this session] parseDiagramCommand() IS wired (see below) — the
// prior header note ("wiring is a separate, later step") was stale:
// diagramCommandRouter.mjs was already edited to import
// `parseDiagramCommand as parseRetainingWallDiagramCommand` from this
// file (its own header calls this "wired in the same strict-addition
// way"), but the export was never actually added here. That mismatch
// was not cosmetic — `import { parseDiagramCommand } from
// './retainingWallDiagram.mjs'` in a module this file's own name doesn't
// export is a load-time ES-module link failure, not a runtime null:
// diagramCommandRouter.mjs failed to instantiate at all, which broke
// every parser it aggregates (footing/slab/shearwall/stair/column/beam),
// not just retaining wall, and cascaded into chat.js failing to load
// (it imports routeDiagramCommand from that same router). Confirmed by
// running `node --eval "import('./functions/_lib/diagramCommandRouter.mjs')"`
// before this fix: "does not provide an export named 'parseDiagramCommand'".
// `type` below is returned as the lower-case router token
// ('retainingwall'), not the camelCase 'retainingWall' geometry.type
// above or parseRetainingWallRebarPayload's own 'retainingWall' —
// DIAGRAM_TYPE_RENDERERS/DIAGRAM_TYPE_ERROR_MESSAGE in chat.js are keyed
// by the lower-case token; returning camelCase here would silently look
// up `undefined` and throw calling it as a renderer, the exact
// shearWall/shearwall casing trap the project's own prompt already
// documents once (Step 20) and warns not to repeat.
//
// Resource lifecycle: pure/synchronous, zero imports beyond the shared
// kit, no timers/fetch/KV/handles. Fully deterministic: no env.AI, no
// model call, no randomness anywhere in this file.

import {
  DiagramError, toMm, assertFinitePositive, assertFiniteNonNegative, assertInt,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, distributeTicks,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ─────────────────────────────────────────────────────
// Same role as every other module's MAX_*: this is a chat-driven
// schematic tool, not a CAD system — bound worst-case loop counts and
// input ranges so one request can't build an oversized SVG, blow a
// Worker CPU-time budget, or describe a section that cannot be drawn
// sanely.
const MIN_STEM_HEIGHT_MM = 300;
const MAX_STEM_HEIGHT_MM = 8000; // a single schematic stem, not a dam wall
const MIN_STEM_THICKNESS_MM = 150;
const MAX_STEM_THICKNESS_MM = 1000;
const MAX_TOE_MM = 4000; // toe may be 0 — assertFiniteNonNegative allows that
const MAX_HEEL_MM = 6000; // heel may be 0 — assertFiniteNonNegative allows that
const MIN_BASE_THICKNESS_MM = 200;
const MAX_BASE_THICKNESS_MM = 1500;
const MIN_BAR_SPACING_MM = 75;
const MAX_BAR_SPACING_MM = 300;
const MIN_SOIL_HEIGHT_MM = 100;
// Matches the 14-per-axis cap slabDiagram.mjs/shearWallDiagram.mjs/
// stairDiagram.mjs all settled on at Step 19 (not the kit's own generic
// 24/axis distributeTicks ceiling) — reusing an already CPU-timed safe
// ceiling, not raising past it, so no fresh CPU test is owed here (see
// structuralDrawingKit.mjs's own Step 18 note on that rule: it gates
// RAISING a limit, not reusing a lower, already-validated one).
const MAX_DRAWN_DIST_BARS = 14;

// ── Compute ─────────────────────────────────────────────────────────
export function computeRetainingWallDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Retaining wall diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.wallId != null ? String(raw.wallId).slice(0, 40) : 'RW';

  if (!raw.stem || typeof raw.stem !== 'object') {
    throw new DiagramError('BAD_PARAM', '"stem" is required: { heightMM, thicknessMM }.');
  }
  const stemHeightMM = toMm(raw.stem.heightMM, unit);
  assertFinitePositive('stem.heightMM', stemHeightMM);
  if (stemHeightMM < MIN_STEM_HEIGHT_MM || stemHeightMM > MAX_STEM_HEIGHT_MM) {
    throw new DiagramError('BAD_PARAM', `"stem.heightMM" must be between ${MIN_STEM_HEIGHT_MM}mm and ${MAX_STEM_HEIGHT_MM}mm, got ${stemHeightMM}mm.`);
  }
  const stemThicknessMM = toMm(raw.stem.thicknessMM, unit);
  assertFinitePositive('stem.thicknessMM', stemThicknessMM);
  if (stemThicknessMM < MIN_STEM_THICKNESS_MM || stemThicknessMM > MAX_STEM_THICKNESS_MM) {
    throw new DiagramError('BAD_PARAM', `"stem.thicknessMM" must be between ${MIN_STEM_THICKNESS_MM}mm and ${MAX_STEM_THICKNESS_MM}mm, got ${stemThicknessMM}mm.`);
  }

  if (!raw.base || typeof raw.base !== 'object') {
    throw new DiagramError('BAD_PARAM', '"base" is required: { toeLengthMM, heelLengthMM, thicknessMM }.');
  }
  const toeLengthMM = toMm(raw.base.toeLengthMM, unit);
  assertFiniteNonNegative('base.toeLengthMM', toeLengthMM);
  if (toeLengthMM > MAX_TOE_MM) {
    throw new DiagramError('BAD_PARAM', `"base.toeLengthMM" must be <= ${MAX_TOE_MM}mm, got ${toeLengthMM}mm.`);
  }
  const heelLengthMM = toMm(raw.base.heelLengthMM, unit);
  assertFiniteNonNegative('base.heelLengthMM', heelLengthMM);
  if (heelLengthMM > MAX_HEEL_MM) {
    throw new DiagramError('BAD_PARAM', `"base.heelLengthMM" must be <= ${MAX_HEEL_MM}mm, got ${heelLengthMM}mm.`);
  }
  const baseThicknessMM = toMm(raw.base.thicknessMM, unit);
  assertFinitePositive('base.thicknessMM', baseThicknessMM);
  if (baseThicknessMM < MIN_BASE_THICKNESS_MM || baseThicknessMM > MAX_BASE_THICKNESS_MM) {
    throw new DiagramError('BAD_PARAM', `"base.thicknessMM" must be between ${MIN_BASE_THICKNESS_MM}mm and ${MAX_BASE_THICKNESS_MM}mm, got ${baseThicknessMM}mm.`);
  }
  const baseLengthMM = toeLengthMM + stemThicknessMM + heelLengthMM;

  const coverMM = toMm(raw.coverMM, unit);
  assertFinitePositive('coverMM', coverMM);
  if (coverMM * 2 >= stemThicknessMM) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) on both faces leaves no room inside a ${stemThicknessMM}mm stem.`);
  }
  if (coverMM * 2 >= baseThicknessMM) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) on both faces leaves no room inside a ${baseThicknessMM}mm base slab.`);
  }

  const soilHeightMM = raw.soilHeightMM != null ? toMm(raw.soilHeightMM, unit) : stemHeightMM;
  assertFinitePositive('soilHeightMM', soilHeightMM);
  if (soilHeightMM < MIN_SOIL_HEIGHT_MM || soilHeightMM > stemHeightMM) {
    throw new DiagramError('BAD_PARAM', `"soilHeightMM" must be between ${MIN_SOIL_HEIGHT_MM}mm and stem.heightMM (${stemHeightMM}mm), got ${soilHeightMM}mm.`);
  }

  const readBarGroup = (raw2, label) => {
    if (!raw2 || typeof raw2 !== 'object') {
      throw new DiagramError('BAD_PARAM', `"${label}" is required: { diameterMM, spacingMM }.`);
    }
    const dia = toMm(raw2.diameterMM, unit);
    assertFinitePositive(`${label}.diameterMM`, dia);
    const spacing = toMm(raw2.spacingMM, unit);
    assertFinitePositive(`${label}.spacingMM`, spacing);
    if (spacing < MIN_BAR_SPACING_MM || spacing > MAX_BAR_SPACING_MM) {
      throw new DiagramError('BAD_PARAM', `"${label}.spacingMM" must be between ${MIN_BAR_SPACING_MM}mm and ${MAX_BAR_SPACING_MM}mm, got ${spacing}mm.`);
    }
    return { dia, spacing };
  };

  const stemMain = readBarGroup(raw.stemMainBars, 'stemMainBars');
  const stemDist = readBarGroup(raw.stemDistBars, 'stemDistBars');
  const baseBottom = readBarGroup(raw.baseBottomBars, 'baseBottomBars');
  const baseTop = readBarGroup(raw.baseTopBars, 'baseTopBars');

  // Real (uncapped) count of distribution-bar LEVELS up the stem — the
  // one bar group in this module with a genuine in-plane count (see the
  // SCOPE note above); drawn (capped) positions derived at render time,
  // same real-vs-drawn split every other module in this app uses.
  const stemDistCount = Math.max(2, Math.round(stemHeightMM / stemDist.spacing) + 1);

  return {
    type: 'retainingWall', unit, id,
    stem: { heightMM: stemHeightMM, thicknessMM: stemThicknessMM },
    base: { toeLengthMM, heelLengthMM, thicknessMM: baseThicknessMM, lengthMM: baseLengthMM },
    coverMM, soilHeightMM,
    stemMainBars: { dia: stemMain.dia, spacing: stemMain.spacing },
    stemDistBars: { dia: stemDist.dia, spacing: stemDist.spacing, count: stemDistCount },
    baseBottomBars: { dia: baseBottom.dia, spacing: baseBottom.spacing },
    baseTopBars: { dia: baseTop.dia, spacing: baseTop.spacing },
  };
}

// ── Labels ──────────────────────────────────────────────────────────
// PARENTHESES/EM-DASH WARNING (same constraint structuralLabels.mjs/
// columnDiagram.mjs document): Noto Naskh Arabic has no glyph for "(",
// ")", or an em/en-dash. No Arabic value below uses any of the three;
// the "—" (em-dash) placeholder used for N/A schedule cells is only ever
// placed in the 'mark'/'dia'/'count' columns, which render via the
// PLAIN 'table-text' class (defaultFontStack, Latin-safe), never inside
// scriptFontStack text — same convention stairDiagram.mjs's own landing
// row already established.
const L = {
  en: {
    title: (id) => `RETAINING WALL ${id} — TYPICAL SECTION`,
    section: 'SECTION', // sheet title already says "TYPICAL SECTION" — a
    // view title repeating that verbatim directly under it reads as a
    // rendering mistake, not a deliberate label; kept short instead,
    // matching footingDiagram.mjs's own terse "SECTION A-A" convention.
    stemMain: 'Stem main (soil face)', stemDist: 'Stem distribution (front face)',
    baseBottom: 'Base bottom (toe)', baseTop: 'Base top (heel)',
    extentSuffix: ' (extent)', spacingOnlySuffix: ' (typical, spacing shown — no count: see module scope)',
    stemLabel: 'stem', toeLabel: 'toe', heelLabel: 'heel', baseLabel: 'base',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    caption: 'Schematic reinforcement detail generated from the supplied data — verify every bar mark, spacing, and length against your own design (ECP 203 / ACI 318) before issuing for construction. This is a TYPICAL SECTION only: no soil pressure, bearing pressure, sliding/overturning check, or wall-run bar count is computed here. Stem main/base bars are shown as one representative bar per group with a spacing callout, not a bent or continuous bar between stem and base.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد حائط الاستناد ${id}`,
    section: 'قطاع نمطي',
    stemMain: 'حديد الحائط الرئيسي عند وجه الردم', stemDist: 'حديد توزيع الحائط عند الوجه الأمامي',
    baseBottom: 'حديد سفلي للقاعدة عند المقدمة', baseTop: 'حديد علوي للقاعدة عند الكعب',
    extentSuffix: ' امتداد', spacingOnlySuffix: ' تباعد فقط دون عدد',
    stemLabel: 'الحائط', toeLabel: 'المقدمة', heelLabel: 'الكعب', baseLabel: 'القاعدة',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وتباعدها وطولها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. هذا قطاع نمطي فقط؛ لا يُحسب هنا ضغط التربة ولا إجهاد التربة ولا فحص الانزلاق أو الانقلاب ولا عدد الأسياخ على طول الحائط. حديد الحائط الرئيسي وحديد القاعدة تظهر كسيخ نمطي واحد لكل مجموعة مع تباعده فقط، وليست سيخاً واحداً منحنياً متصلاً بين الحائط والقاعدة.',
    dirAttr: 'rtl',
  },
};

// ── Render ──────────────────────────────────────────────────────────
const CANVAS_W = 950;
const SECTION_BOX = { x: 60, y: 110, w: 830, h: 340 };

function renderSectionView(geometry, scale, box, l) {
  const {
    stem, base, coverMM, soilHeightMM,
    stemMainBars, stemDistBars, baseBottomBars, baseTopBars,
  } = geometry;

  // Local mm coords: x runs along the section (0 at the toe's front
  // face, increasing toward the heel), y runs DOWN the page (0 at the
  // top of the base / bottom of the stem — the stem-base joint — so a
  // single shared origin places both without a second offset).
  const baseW = base.lengthMM * scale, baseH = base.thicknessMM * scale;
  const stemH = stem.heightMM * scale;
  const sx = box.x + (box.w - baseW) / 2;
  const sy = box.y + box.h - baseH - 30; // 30px reserved for the bottom dimension line

  const px = (xMM, yMM) => ({ x: sx + xMM * scale, y: sy + yMM * scale });

  let svg = `<g class="section-view">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.section)}</text>`;

  // Base slab.
  const baseTL = px(0, 0);
  svg += `<rect x="${baseTL.x.toFixed(2)}" y="${baseTL.y.toFixed(2)}" width="${baseW.toFixed(2)}" height="${baseH.toFixed(2)}" class="concrete-outline"/>`;

  // Stem, rising from the base between the toe and heel.
  const stemXMM = base.toeLengthMM;
  const stemTL = px(stemXMM, -stem.heightMM);
  const stemWpx = stem.thicknessMM * scale;
  svg += `<rect x="${stemTL.x.toFixed(2)}" y="${stemTL.y.toFixed(2)}" width="${stemWpx.toFixed(2)}" height="${stemH.toFixed(2)}" class="concrete-outline"/>`;

  // Retained backfill: a schematic hatched block sitting on the heel,
  // against the stem's back (soil-side) face, up to soilHeightMM — the
  // same simplified soil-strip convention footingDiagram.mjs already
  // uses (url(#soilHatch), see that file's own renderPlanView).
  if (base.heelLengthMM > 0) {
    const soilXMM = base.toeLengthMM + stem.thicknessMM;
    const soilTL = px(soilXMM, -soilHeightMM);
    const soilWpx = base.heelLengthMM * scale;
    const soilHpx = soilHeightMM * scale;
    svg += `<rect x="${soilTL.x.toFixed(2)}" y="${soilTL.y.toFixed(2)}" width="${soilWpx.toFixed(2)}" height="${soilHpx.toFixed(2)}" fill="url(#soilHatch)" stroke="#8a7350" stroke-width="1"/>`;
  }

  // Stem main bars: single representative vertical line near the back
  // (soil-side, higher-x) face, inset by cover + half its own diameter.
  const mainX = stemXMM + stem.thicknessMM - coverMM - stemMainBars.dia / 2;
  const mainTop = px(mainX, -(stem.heightMM - coverMM - stemMainBars.dia / 2));
  const mainBot = px(mainX, 0);
  svg += `<line x1="${mainTop.x.toFixed(2)}" y1="${mainTop.y.toFixed(2)}" x2="${mainBot.x.toFixed(2)}" y2="${mainBot.y.toFixed(2)}" class="bar-bottom"/>`;
  svg += barDot(mainTop.x, mainTop.y, stemMainBars.dia, scale, 'wall');
  svg += barDot(mainBot.x, mainBot.y, stemMainBars.dia, scale, 'wall');

  // Stem distribution bars: dots stacked up the front (exposed,
  // lower-x) face, one per level, capped at MAX_DRAWN_DIST_BARS.
  const distX = stemXMM + coverMM + stemDistBars.dia / 2;
  const drawDistCount = Math.min(stemDistBars.count, MAX_DRAWN_DIST_BARS);
  const distTopMM = -(stem.heightMM - coverMM - stemDistBars.dia / 2);
  for (const yPx of distributeTicks(px(distX, distTopMM).y, px(distX, 0).y, drawDistCount)) {
    svg += barDot(px(distX, 0).x, yPx, stemDistBars.dia, scale, 'wall');
  }

  // Base bottom bars (toe): representative horizontal line near the
  // bottom face, from just inside the toe's own tip through to the
  // stem's far (heel-side) face — a reasonable drawn extent for "the
  // bar continues through the stem region"; exact development/lap
  // length at the stem is not computed (see module SCOPE).
  const bBotY = base.thicknessMM - coverMM - baseBottomBars.dia / 2;
  const bBotFrom = px(coverMM, bBotY);
  const bBotTo = px(stemXMM + stem.thicknessMM, bBotY);
  svg += `<line x1="${bBotFrom.x.toFixed(2)}" y1="${bBotFrom.y.toFixed(2)}" x2="${bBotTo.x.toFixed(2)}" y2="${bBotTo.y.toFixed(2)}" class="bar-bottom"/>`;
  svg += barDot(bBotFrom.x, bBotFrom.y, baseBottomBars.dia, scale, 'wall');
  svg += barDot(bBotTo.x, bBotTo.y, baseBottomBars.dia, scale, 'wall');

  // Base top bars (heel): representative horizontal line near the top
  // face, from the stem's near (toe-side) face through to just inside
  // the heel's own tip — same "through the stem region" convention.
  if (base.heelLengthMM > 0) {
    const bTopY = coverMM + baseTopBars.dia / 2;
    const bTopFrom = px(stemXMM, bTopY);
    const bTopTo = px(base.lengthMM - coverMM, bTopY);
    svg += `<line x1="${bTopFrom.x.toFixed(2)}" y1="${bTopFrom.y.toFixed(2)}" x2="${bTopTo.x.toFixed(2)}" y2="${bTopTo.y.toFixed(2)}" class="bar-top"/>`;
    svg += barDot(bTopFrom.x, bTopFrom.y, baseTopBars.dia, scale, 'wall');
    svg += barDot(bTopTo.x, bTopTo.y, baseTopBars.dia, scale, 'wall');
  }

  svg += `<text x="${sx}" y="${box.y + 4}" class="sheet-caption" dir="${l.dirAttr}">${esc(l.stemLabel)}=${Math.round(stem.thicknessMM)}mm\u00d7${Math.round(stem.heightMM)}mm, ${esc(l.toeLabel)}=${Math.round(base.toeLengthMM)}mm, ${esc(l.heelLabel)}=${Math.round(base.heelLengthMM)}mm, ${esc(l.baseLabel)}=${Math.round(base.thicknessMM)}mm</text>`;

  // Overall base length, along the very bottom of the box.
  const dimY = sy + baseH + 24;
  svg += dimensionLine(baseTL.x, dimY, baseTL.x + baseW, dimY, `${Math.round(base.lengthMM)}mm`, { orientation: 'h', tick: 5 });
  // Stem height, along the left edge.
  svg += dimensionLine(sx - 24, stemTL.y, sx - 24, sy, `${Math.round(stem.heightMM)}mm`, { orientation: 'v', tick: 5 });

  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  rows.push({
    mark: 'W1', element: l.stemMain, dia: String(Math.round(geometry.stemMainBars.dia)),
    count: `\u2014 @ ${Math.round(geometry.stemMainBars.spacing)}`,
    length: `${Math.round(geometry.stem.heightMM)}${l.extentSuffix}`,
  });
  rows.push({
    mark: 'W2', element: l.stemDist, dia: String(Math.round(geometry.stemDistBars.dia)),
    count: `${geometry.stemDistBars.count} @ ${Math.round(geometry.stemDistBars.spacing)}`,
    length: `${Math.round(geometry.base.lengthMM)}${l.extentSuffix}`,
  });
  rows.push({
    mark: 'B1', element: l.baseBottom, dia: String(Math.round(geometry.baseBottomBars.dia)),
    count: `\u2014 @ ${Math.round(geometry.baseBottomBars.spacing)}`,
    length: `${Math.round(geometry.base.toeLengthMM + geometry.stem.thicknessMM)}${l.extentSuffix}`,
  });
  if (geometry.base.heelLengthMM > 0) {
    rows.push({
      mark: 'B2', element: l.baseTop, dia: String(Math.round(geometry.baseTopBars.dia)),
      count: `\u2014 @ ${Math.round(geometry.baseTopBars.spacing)}`,
      length: `${Math.round(geometry.base.heelLengthMM + geometry.stem.thicknessMM)}${l.extentSuffix}`,
    });
  }
  return rows;
}

export function renderRetainingWallDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const sectionScale = fitScale([{
    contentW: geometry.base.lengthMM,
    contentH: geometry.stem.heightMM + geometry.base.thicknessMM,
    boxW: SECTION_BOX.w - 80,
    boxH: SECTION_BOX.h - 60,
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
  const tableY = SECTION_BOX.y + SECTION_BOX.h + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .wall-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .bar-dot-wall { fill:#c0392b; stroke:#7a2015; stroke-width:0.6; }`;

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
// Mirrors parseColumnRebarPayload/parseStairRebarPayload's error-shape
// contract exactly ({ok:true,...} / {ok:false,code,message}). Never
// throws a DiagramError out; anything else (a genuine programmer error)
// is rethrown, same as every other module.
export function parseRetainingWallRebarPayload(raw) {
  try {
    const geometry = computeRetainingWallDiagramGeometry(raw);
    return { ok: true, type: 'retainingWall', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Same contract/conventions as stairDiagram.mjs's parseDiagramCommand
// (leading-token dispatch, flat `key=value` tokens, DiagramError codes
// surfaced verbatim with `type` attached so chat.js picks the right
// bilingual error wrapper). toe/heel/basetop/basebottom etc. are always
// required tokens (toe=0 / heel=0 to omit a projection) — same
// no-silent-default discipline computeRetainingWallDiagramGeometry
// itself already enforces on base.toeLengthMM/heelLengthMM.
//
// Syntax:
//   /diagram retainingwall id=RW-1 stemheight=3000 stemthickness=300
//     toe=800 heel=1800 basethickness=400 cover=40
//     mainbardia=16 mainbarspacing=150 distbardia=12 distbarspacing=200
//     basebottomdia=16 basebottomspacing=150 basetopdia=12 basetopspacing=150
//     [soilheight=2500] [unit=mm]
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: retainingwall key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'retainingwall') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use retainingwall.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const geometry = computeRetainingWallDiagramGeometry({
      wallId: kv.id,
      stem: { heightMM: num('stemheight'), thicknessMM: num('stemthickness') },
      base: { toeLengthMM: num('toe'), heelLengthMM: num('heel'), thicknessMM: num('basethickness') },
      coverMM: num('cover'),
      soilHeightMM: 'soilheight' in kv ? num('soilheight') : undefined,
      stemMainBars: { diameterMM: num('mainbardia'), spacingMM: num('mainbarspacing') },
      stemDistBars: { diameterMM: num('distbardia'), spacingMM: num('distbarspacing') },
      baseBottomBars: { diameterMM: num('basebottomdia'), spacingMM: num('basebottomspacing') },
      baseTopBars: { diameterMM: num('basetopdia'), spacingMM: num('basetopspacing') },
      unit: kv.unit || 'mm',
    });
    return { ok: true, type: 'retainingwall', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type: 'retainingwall', code: err.code, message: err.message };
    throw err;
  }
}
