// functions/_lib/stairDiagram.mjs
//
// Deterministic, zero-AI SVG generator for a single straight stair
// flight's reinforcement (longitudinal section: step profile + waist
// bar line + optional landing, plus a bar schedule) \u2014 Step 19, built on
// the readiness assessed in structuralDrawingKit.mjs's "Step 18" header,
// which explicitly named this as the one element type needing genuinely
// element-specific geometry (the flight profile and its bent bar line),
// not a new kit function. Same philosophy as the other three modules:
// every dimension, bar position, and count is arithmetic on the KB data
// supplied, never a model's guess.
//
// SCOPE (v1): a single STRAIGHT flight (no winders, no mid-flight turn),
// uniform riser/tread over the whole flight, one main-bar spec following
// the waist slope and one distribution-bar spec, and an OPTIONAL landing
// slab at the TOP of the flight only. NOT modeled, on purpose: quarter/
// half-turn flights, winders, a landing at the bottom, going-line
// (staggered nosing) corrections, and code-specific development/hook
// length at the flight-to-landing junction (this module reports the
// waist bar's drawn EXTENT, labeled "(extent)", exactly like the other
// three modules' honest-length convention \u2014 see
// structuralDrawingKit.mjs's header for the general rule).
//
// ── GEOMETRY NOTE (flight profile \u2192 waist offset) ───────────────────
// The step (nosing) line is the zigzag polyline through each riser/tread
// corner. The waist \u2014 the constant-thickness slab the steps sit on \u2014 is
// that same line offset PERPENDICULAR to the flight's slope by
// waistThicknessMM, not offset vertically by a fixed amount (a vertical-
// only offset would make the waist thicker measured perpendicular to the
// slope than the input actually specifies, a silent geometry defect).
// The offset direction is (sin\u03b8, cos\u03b8) where \u03b8 = atan2(riserMM,
// treadMM) is the flight's rake angle \u2014 computed once in
// computeFlightProfile and reused by both the soffit line and the main-
// bar line (offset a further coverMM inward from the soffit), so the two
// can never silently drift apart the way
// \u0628\u0631\u0648\u0645\u0628\u062a_\u0627\u0633\u062a\u0643\u0645\u0627\u0644_\u0627\u0644\u0639\u0645\u0644.md's lesson 1 warns against for any two
// values that depend on each other.
//
// ── INPUT CONTRACT ───────────────────────────────────────────────────
// {
//   unit?: 'mm'|'cm'|'m',
//   stairId: string,
//   flight: {
//     riserMM: number, treadMM: number, stepsCount: integer,
//     waistThicknessMM: number,   // measured perpendicular to the slope
//   },
//   landing?: { widthMM: number, thicknessMM: number },  // at flight TOP only
//   coverMM: number,
//   mainBars: { diameterMM, spacingMM },         // follow the waist slope
//   distributionBars: { diameterMM, spacingMM }, // perpendicular to main bars
// }
//
// Resource lifecycle: pure/synchronous, zero imports beyond the shared
// kit, no timers/fetch/KV/handles. Fully deterministic: no env.AI, no
// model call, no randomness.

import {
  DiagramError, toMm, assertFinitePositive, assertInt,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, distributeTicks,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ─────────────────────────────────────────────────────
const MIN_RISER_MM = 100;
const MAX_RISER_MM = 220; // typical code-governed comfort range (e.g. ECP 203/IBC), not a code check itself
const MIN_TREAD_MM = 220;
const MAX_TREAD_MM = 400;
const MIN_STEPS = 3;
const MAX_STEPS = 24; // matches distributeTicks' own hard cap, kept consistent across all four modules
const MIN_WAIST_MM = 100;
const MAX_WAIST_MM = 250;
const MIN_LANDING_MM = 800;
const MAX_LANDING_MM = 4000;
const MIN_BAR_SPACING_MM = 75;
const MAX_BAR_SPACING_MM = 300;
const MAX_DRAWN_MAIN_BARS = 14; // representative dots along the waist, not one per real bar \u2014 same convention as distributeTicks' own doc comment

// ── Compute ─────────────────────────────────────────────────────────
export function computeStairDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Stair diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.stairId != null ? String(raw.stairId).slice(0, 40) : 'STAIR';

  if (!raw.flight || typeof raw.flight !== 'object') {
    throw new DiagramError('BAD_PARAM', '"flight" is required: { riserMM, treadMM, stepsCount, waistThicknessMM }.');
  }
  const riserMM = toMm(raw.flight.riserMM, unit);
  assertFinitePositive('flight.riserMM', riserMM);
  if (riserMM < MIN_RISER_MM || riserMM > MAX_RISER_MM) {
    throw new DiagramError('BAD_PARAM', `"flight.riserMM" must be between ${MIN_RISER_MM}mm and ${MAX_RISER_MM}mm, got ${riserMM}mm.`);
  }
  const treadMM = toMm(raw.flight.treadMM, unit);
  assertFinitePositive('flight.treadMM', treadMM);
  if (treadMM < MIN_TREAD_MM || treadMM > MAX_TREAD_MM) {
    throw new DiagramError('BAD_PARAM', `"flight.treadMM" must be between ${MIN_TREAD_MM}mm and ${MAX_TREAD_MM}mm, got ${treadMM}mm.`);
  }
  assertInt('flight.stepsCount', raw.flight.stepsCount, { min: MIN_STEPS, max: MAX_STEPS });
  const stepsCount = raw.flight.stepsCount;
  const waistThicknessMM = toMm(raw.flight.waistThicknessMM, unit);
  assertFinitePositive('flight.waistThicknessMM', waistThicknessMM);
  if (waistThicknessMM < MIN_WAIST_MM || waistThicknessMM > MAX_WAIST_MM) {
    throw new DiagramError('BAD_PARAM', `"flight.waistThicknessMM" must be between ${MIN_WAIST_MM}mm and ${MAX_WAIST_MM}mm, got ${waistThicknessMM}mm.`);
  }

  const coverMM = toMm(raw.coverMM, unit);
  assertFinitePositive('coverMM', coverMM);
  if (coverMM * 2 >= waistThicknessMM) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) on both faces leaves no room inside a ${waistThicknessMM}mm waist.`);
  }

  let landing = null;
  if (raw.landing != null) {
    if (!raw.landing || typeof raw.landing !== 'object') throw new DiagramError('BAD_PARAM', '"landing" must be an object.');
    const widthMM = toMm(raw.landing.widthMM, unit);
    assertFinitePositive('landing.widthMM', widthMM);
    if (widthMM < MIN_LANDING_MM || widthMM > MAX_LANDING_MM) {
      throw new DiagramError('BAD_PARAM', `"landing.widthMM" must be between ${MIN_LANDING_MM}mm and ${MAX_LANDING_MM}mm, got ${widthMM}mm.`);
    }
    const thicknessMM = toMm(raw.landing.thicknessMM, unit);
    assertFinitePositive('landing.thicknessMM', thicknessMM);
    landing = { widthMM, thicknessMM };
  }

  if (!raw.mainBars || typeof raw.mainBars !== 'object') {
    throw new DiagramError('BAD_PARAM', '"mainBars" is required: { diameterMM, spacingMM }.');
  }
  const mainDia = toMm(raw.mainBars.diameterMM, unit);
  assertFinitePositive('mainBars.diameterMM', mainDia);
  const mainSpacing = toMm(raw.mainBars.spacingMM, unit);
  assertFinitePositive('mainBars.spacingMM', mainSpacing);
  if (mainSpacing < MIN_BAR_SPACING_MM || mainSpacing > MAX_BAR_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"mainBars.spacingMM" must be between ${MIN_BAR_SPACING_MM}mm and ${MAX_BAR_SPACING_MM}mm, got ${mainSpacing}mm.`);
  }

  if (!raw.distributionBars || typeof raw.distributionBars !== 'object') {
    throw new DiagramError('BAD_PARAM', '"distributionBars" is required: { diameterMM, spacingMM }.');
  }
  const distDia = toMm(raw.distributionBars.diameterMM, unit);
  assertFinitePositive('distributionBars.diameterMM', distDia);
  const distSpacing = toMm(raw.distributionBars.spacingMM, unit);
  assertFinitePositive('distributionBars.spacingMM', distSpacing);
  if (distSpacing < MIN_BAR_SPACING_MM || distSpacing > MAX_BAR_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"distributionBars.spacingMM" must be between ${MIN_BAR_SPACING_MM}mm and ${MAX_BAR_SPACING_MM}mm, got ${distSpacing}mm.`);
  }

  const flightProfile = computeFlightProfile({ riserMM, treadMM, stepsCount, waistThicknessMM });
  const totalRunMM = stepsCount * treadMM;
  const totalRiseMM = stepsCount * riserMM;
  // Real (uncapped) main-bar count across the flight's sloped (raked)
  // length \u2014 schedule's source of truth; drawn (capped) positions
  // derived at render time from MAX_DRAWN_MAIN_BARS, same split as the
  // other three modules' own real-vs-drawn count pattern.
  const rakedLengthMM = Math.hypot(totalRunMM, totalRiseMM);
  const mainBarCount = Math.max(2, Math.round(rakedLengthMM / mainSpacing) + 1);
  const distBarCount = Math.max(2, Math.round(totalRunMM / distSpacing) + 1);

  return {
    type: 'stair', unit, id, riserMM, treadMM, stepsCount, waistThicknessMM,
    coverMM, landing, totalRunMM, totalRiseMM, rakedLengthMM,
    mainBars: { dia: mainDia, spacing: mainSpacing, count: mainBarCount },
    distributionBars: { dia: distDia, spacing: distSpacing, count: distBarCount },
    profile: flightProfile,
  };
}

// Returns { stepPoints, soffitStart, soffitEnd, angleRad, sinT, cosT } in
// a LOCAL coordinate system: x runs along the horizontal run (0 at the
// bottom riser's face), y runs DOWN the page (0 at the top step's
// nosing, positive y = lower on the page, matching SVG's y-down
// convention so the caller can add a single origin offset and scale
// directly with no axis flip).
function computeFlightProfile({ riserMM, treadMM, stepsCount }) {
  // Corner sequence starting at the bottom riser's foot (x=0,
  // y=stepsCount*riserMM \u2014 the lowest point) and alternating riser
  // (vertical, y decreases) / tread (horizontal, x increases) up to the
  // top step's nosing at (stepsCount*treadMM, 0).
  const stepPoints = [{ x: 0, y: stepsCount * riserMM }];
  for (let i = 0; i < stepsCount; i++) {
    const last = stepPoints[stepPoints.length - 1];
    stepPoints.push({ x: last.x, y: last.y - riserMM });        // riser (vertical)
    stepPoints.push({ x: last.x + treadMM, y: last.y - riserMM }); // tread (horizontal)
  }
  const angleRad = Math.atan2(riserMM, treadMM);
  return { stepPoints, angleRad, sinT: Math.sin(angleRad), cosT: Math.cos(angleRad) };
}

// ── Labels ──────────────────────────────────────────────────────────
const L = {
  en: {
    title: (id) => `STAIR ${id} \u2014 REINFORCEMENT DETAIL`,
    section: 'LONGITUDINAL SECTION',
    mainBar: 'Main bars (waist)', distBar: 'Distribution bars',
    landingRow: 'Landing slab', extentSuffix: ' (extent)',
    riserLabel: 'riser', treadLabel: 'tread', stepsLabel: 'steps',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design (ECP 203 / ACI 318) before issuing for construction. Lengths marked "(extent)" are the drawn member length only, measured along the flight\u2019s own slope where applicable \u2014 development, hook, and lap lengths at the flight-to-landing junction are not computed here.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد الدرج ${id}`,
    section: 'قطاع طولي',
    mainBar: 'الأسياخ الرئيسية للبروة', distBar: 'أسياخ التوزيع',
    landingRow: 'بلاطة البسطة', extentSuffix: ' امتداد',
    riserLabel: 'ارتفاع القائمة', treadLabel: 'عرض النائمة', stepsLabel: 'عدد الدرجات',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. الأطوال المُعلَّمة امتداد هي طول الامتداد فقط، مقاساً على ميل البروة نفسه عند الاقتضاء؛ لا تُحسب هنا أطوال الربط والكلبتين عند وصلة البروة بالبسطة.',
    dirAttr: 'rtl',
  },
};

// ── Render ──────────────────────────────────────────────────────────
const CANVAS_W = 950;
const SECTION_BOX = { x: 60, y: 110, w: 830, h: 320 };

function renderSectionView(geometry, scale, box, l) {
  const { profile, waistThicknessMM, coverMM, landing, totalRunMM, totalRiseMM, mainBars } = geometry;
  const { stepPoints, sinT, cosT } = profile;
  const w = totalRunMM * scale, h = totalRiseMM * scale;
  const sx = box.x + 40;
  const sy = box.y + (box.h - h) / 2;

  // stepPoints are in LOCAL (x-right, y-down-from-top) mm coordinates
  // already; map to px with one origin offset + one scale factor, no
  // further axis flip needed (see computeFlightProfile's own header).
  const px = (p) => ({ x: sx + p.x * scale, y: sy + p.y * scale });
  const stepPx = stepPoints.map(px);

  let svg = `<g class="section-view">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.section)}</text>`;

  // Soffit line: the step profile offset perpendicular-to-slope by
  // waistThicknessMM, in the (sinT, cosT) direction \u2014 see the file
  // header's GEOMETRY NOTE. Only the sloped run needs the offset; the
  // profile's own vertical riser faces stay vertical underneath too, so
  // offsetting every polyline vertex by the same perpendicular vector
  // keeps riser faces vertical and tread faces horizontal in the
  // soffit line as well, which is the physically correct waist shape.
  const waistPx = waistThicknessMM * scale;
  const offsetPts = stepPoints.map((p) => ({ x: p.x + waistThicknessMM * sinT, y: p.y + waistThicknessMM * cosT }));
  const soffitPx = offsetPts.map(px);

  const stepPathD = stepPx.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(' ');
  const soffitPathD = soffitPx.map((p, i) => `${i === 0 ? 'L' : 'L'}${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(' ');
  const soffitLastPx = soffitPx[soffitPx.length - 1];
  // Top end-cap of the flight cross-section: the profile's last vertex
  // (topStep, the nosing) connects to the soffit line's last vertex.
  // The natural connector is a DIAGONAL (soffitLastPx is offset both
  // horizontally and vertically from topStep, since the perpendicular-
  // to-slope offset has both components) \u2014 fine on its own, but when a
  // landing rect is drawn immediately to the right (see below), the
  // landing's own left edge is a plain VERTICAL line starting at the
  // same topStep point. Two different lines leaving one shared point at
  // different angles reads as a thin double-stroke sliver right at the
  // flight/landing junction (confirmed by rendering, not visible from
  // the coordinates alone). When a landing is present, insert one extra
  // vertex directly below topStep at the soffit line's own Y so the cap
  // becomes VERTICAL \u2014 exactly collinear with the landing rect's left
  // edge \u2014 instead of diagonal. No landing: keep the original diagonal
  // cap (nothing else touches that edge, so there is nothing to align
  // it with).
  const topEndCapD = landing ? ` L${stepPx[stepPx.length - 1].x.toFixed(2)},${soffitLastPx.y.toFixed(2)}` : '';
  const closingD = `${stepPathD}${topEndCapD} L${soffitLastPx.x.toFixed(2)},${soffitLastPx.y.toFixed(2)} ${soffitPx.slice().reverse().map((p) => `L${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(' ')} Z`;
  svg += `<path d="${closingD}" class="concrete-outline"/>`;

  // Main-bar line: soffit offset a further coverMM inward (same
  // perpendicular direction), representative dots at drawn spacing.
  const coverPx = coverMM * scale;
  const barPts = stepPoints.map((p) => ({
    x: p.x + (waistThicknessMM - coverMM) * sinT,
    y: p.y + (waistThicknessMM - coverMM) * cosT,
  })).map(px);
  const barPathD = barPts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(' ');
  svg += `<path d="${barPathD}" class="bar-bottom" fill="none"/>`;

  const drawCount = Math.min(mainBars.count, MAX_DRAWN_MAIN_BARS);
  // Sample representative dots along the raked bar path by arc-length
  // fraction (uniform t along the polyline's own vertex sequence is
  // close enough for a schematic representative-dot convention \u2014 same
  // "capped, not exact-per-bar" spirit as distributeTicks itself).
  const segLens = [];
  let totalLen = 0;
  for (let i = 1; i < barPts.length; i++) {
    const d = Math.hypot(barPts[i].x - barPts[i - 1].x, barPts[i].y - barPts[i - 1].y);
    segLens.push(d);
    totalLen += d;
  }
  for (let k = 0; k < drawCount; k++) {
    const target = (totalLen * k) / (drawCount - 1 || 1);
    let acc = 0, seg = 0;
    while (seg < segLens.length - 1 && acc + segLens[seg] < target) { acc += segLens[seg]; seg++; }
    const segFrac = segLens[seg] > 0 ? (target - acc) / segLens[seg] : 0;
    const a = barPts[seg], b = barPts[seg + 1] || barPts[seg];
    const px2 = a.x + (b.x - a.x) * segFrac, py2 = a.y + (b.y - a.y) * segFrac;
    svg += barDot(px2, py2, mainBars.dia, scale, 'stair');
  }

  if (landing) {
    const landW = landing.widthMM * scale;
    const landH = landing.thicknessMM * scale;
    const topStep = stepPx[stepPx.length - 1];
    svg += `<rect x="${topStep.x}" y="${topStep.y}" width="${landW}" height="${landH}" class="concrete-outline"/>`;
    svg += `<line x1="${topStep.x}" y1="${topStep.y + landH - coverPx}" x2="${topStep.x + landW}" y2="${topStep.y + landH - coverPx}" class="bar-bottom"/>`;
  }

  svg += `<text x="${sx}" y="${box.y + 4}" class="sheet-caption" dir="${l.dirAttr}">${esc(l.stepsLabel)}=${geometry.stepsCount}, ${esc(l.riserLabel)}=${Math.round(geometry.riserMM)}mm, ${esc(l.treadLabel)}=${Math.round(geometry.treadMM)}mm</text>`;
  svg += dimensionLine(sx, sy + h + 24, sx + w, sy + h + 24, `${Math.round(totalRunMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 24, sy, sx - 24, sy + h, `${Math.round(geometry.totalRiseMM)}mm`, { orientation: 'v', tick: 5 });
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  rows.push({ mark: 'S1', element: l.mainBar, dia: String(Math.round(geometry.mainBars.dia)), count: `${geometry.mainBars.count} @ ${Math.round(geometry.mainBars.spacing)}`, length: `${Math.round(geometry.rakedLengthMM)}${l.extentSuffix}` });
  rows.push({ mark: 'S2', element: l.distBar, dia: String(Math.round(geometry.distributionBars.dia)), count: `${geometry.distributionBars.count} @ ${Math.round(geometry.distributionBars.spacing)}`, length: `${Math.round(geometry.totalRunMM)}${l.extentSuffix}` });
  if (geometry.landing) {
    rows.push({ mark: '\u2014', element: l.landingRow, dia: '\u2014', count: '\u2014', length: `${Math.round(geometry.landing.widthMM)}${l.extentSuffix}` });
  }
  return rows;
}

export function renderStairDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const landingRunMM = geometry.landing ? geometry.landing.widthMM : 0;
  const sectionScale = fitScale([{ contentW: geometry.totalRunMM + landingRunMM, contentH: geometry.totalRiseMM + geometry.waistThicknessMM * 2, boxW: SECTION_BOX.w - 80, boxH: SECTION_BOX.h - 60 }]);

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
    .stair-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .bar-dot-stair { fill:#c0392b; stroke:#7a2015; stroke-width:0.6; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="stair-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderSectionView(geometry, sectionScale, SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// ── Chat-facing entry point ────────────────────────────────────────────
export function parseStairRebarPayload(raw) {
  try {
    const geometry = computeStairDiagramGeometry(raw);
    return { ok: true, type: 'stair', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Step 20 (this session). Same contract/conventions as
// footingDiagram.mjs's parseDiagramCommand — see slabDiagram.mjs's
// header comment on its own copy for the shared rationale.
//
// Syntax:
//   /diagram stair id=ST1 riser=170 tread=280 steps=18 waist=150 cover=20
//     maindia=12 mainspacing=150 distdia=10 distspacing=200
//     [landingwidth=1200 landingthickness=150]
//     [unit=mm]
// landing is all-or-nothing (either key present builds the group; a
// missing sub-field surfaces as computeStairDiagramGeometry's own
// BAD_PARAM, not a silently-guessed default) — same discipline as
// shearWallDiagram.mjs's boundaryElement and footingDiagram.mjs's
// pedestal/dowels groups.
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: stair key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'stair') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use stair.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    let landing;
    if ('landingwidth' in kv || 'landingthickness' in kv) {
      landing = { widthMM: num('landingwidth'), thicknessMM: num('landingthickness') };
    }
    const geometry = computeStairDiagramGeometry({
      stairId: kv.id,
      flight: { riserMM: num('riser'), treadMM: num('tread'), stepsCount: num('steps'), waistThicknessMM: num('waist') },
      landing, coverMM: num('cover'),
      mainBars: { diameterMM: num('maindia'), spacingMM: num('mainspacing') },
      distributionBars: { diameterMM: num('distdia'), spacingMM: num('distspacing') },
      unit: kv.unit || 'mm',
    });
    return { ok: true, type: 'stair', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type: 'stair', code: err.code, message: err.message };
    throw err;
  }
}
