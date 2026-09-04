// functions/_lib/circularColumnDiagram.mjs
//
// Deterministic, zero-AI SVG generator for CIRCULAR column reinforcement
// details (cross section + spiral-pitch detail + elevation + bar-bending
// schedule). Built this session from the ECP-203-gap candidate pool —
// closes a gap columnDiagram.mjs's own header documents explicitly: that
// module's `ties.type` is validated against `['rectangular']` only and
// throws `UNSUPPORTED_TIE_TYPE` on `'spiral'` because its schema has no
// `diameterMM` field (widthMM/depthMM is rectangular by construction).
// This file does not touch columnDiagram.mjs — it is a new sibling module,
// same relationship trapezoidalFootingDiagram.mjs/strapFootingDiagram.mjs
// have to footingDiagram.mjs. Same philosophy as every element-type module
// in this app: every dimension, bar position, and count in the output is
// arithmetic on the KB data supplied, never a model's guess. This module
// owns compute+render only; it does not decide bar counts, diameters, or
// spiral pitch — that is the KB/design layer's job (see INPUT CONTRACT).
//
// Reference: ACI 318-19 §25.7.3 (spiral reinforcement) and §25.7.4.1
// (minimum 6 longitudinal bars for a spirally reinforced column) — the
// same reference applies under ECP 203 practice for this element, no
// material difference between the two codes here (see this session's own
// candidate-pool note).
//
// SCOPE (v1): a single prismatic circular column (constant diameterMM
// over its full heightMM) with exactly ONE vertical-bar group distributed
// evenly around the section CIRCUMFERENCE at one radius, and ONE
// constant-pitch spiral over the full height. NOT modeled, on purpose
// (same "explicit scope boundary" convention every module in this app
// uses):
//   - multiple bar-diameter groups — verticalBars is a single-group array
//     by construction, same limitation columnDiagram.mjs's rectangular
//     schema has.
//   - circular HOOP ties (a column with a circular section closed by
//     discrete circular ties instead of a continuous spiral) — ACI 318
//     permits this as an alternative to spiral confinement, but it is a
//     materially different fabrication detail (discrete rings, no pitch/
//     helix geometry) this module does not draw; every tie drawn here is
//     part of one continuous spiral.
//   - the volumetric spiral-reinforcement-ratio check, ACI 318-19
//     §25.7.3.3's formula (ρs ≥ 0.45·(Ag/Ach − 1)·f'c/fy) — that needs
//     f'c and fy, a real design computation this module does not perform,
//     same boundary columnDiagram.mjs draws around tie spacing/bar count.
//   - seismic special-confinement zones with a tighter pitch near the
//     member ends — one constant pitch governs the whole height, same
//     limitation columnDiagram.mjs's constant tie spacing has.
//   - a tapered (non-prismatic) circular shaft.
//   - extra anchorage turns at the spiral's top and bottom (ACI 318-19
//     §25.7.3.4 calls for roughly 1.5 extra turns each end) — the
//     computed spiral length below is the pure helix arc length only,
//     the same "drawn extent" vs. "actual cut length" distinction
//     structuralDrawingKit.mjs's header documents; pass
//     spiral.cuttingLengthMM to override with a fabrication-ready total
//     that already includes anchorage turns.
//
// ── INPUT CONTRACT (what the KB layer should hand this module) ─────────
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   columnId: string,                  // column mark, e.g. "C-101"
//   diameterMM: number,                // section diameter
//   heightMM: number,                  // clear/story height drawn in elevation
//   coverMM: number,                   // concrete cover to spiral outer face
//   verticalBars: [                    // exactly ONE group (see SCOPE)
//     {
//       diameterMM: number, count: number,   // count >= 6, see MIN_BAR_COUNT
//       position?: 'circumference',          // only value supported
//       cuttingLengthMM?: number,            // full bar length if the KB
//                                            // layer already computed it;
//                                            // omit to show heightMM
//                                            // labeled "(extent)"/"امتداد"
//     }
//   ],
//   spiral: {
//     diameterMM: number,               // spiral wire/bar diameter
//     pitchMM: number,                  // center-to-center spacing between turns
//     type?: 'spiral',                  // only value supported
//     cuttingLengthMM?: number,         // full fabrication-ready spiral length
//                                       // (incl. anchorage turns) if the KB
//                                       // layer already computed it; omit
//                                       // to show the computed pure helix
//                                       // length, honestly labeled
//   },
//   lapSpliceMM?: number,                // lap-splice zone length at the
//                                        // column base, if the caller
//                                        // wants it marked; omit to draw
//                                        // no lap zone at all
// }
//
// ── Vertical-bar circumference layout (computeCircularBarPositions) ───
// Places `count` bars at equal angular spacing (360/count degrees apart)
// on one circle at the bar-center radius (inset from the column face by
// cover + spiral diameter + half the vertical bar's own diameter — same
// cover-to-center logic columnDiagram.mjs's computeColumnBarPositions
// uses, applied radially instead of on two independent axes because a
// circular section has one degree of freedom, not two). First bar placed
// at 12 o'clock (angle = -90°), proceeding clockwise — no code
// requirement drives this choice, it is purely a stable, readable
// drawing convention, same role columnDiagram.mjs's "4 corners first"
// convention plays for a rectangular layout.
//
// ── /circularcolumn and /image wiring — NOT done this pass ─────────────
// Per this session's own handoff protocol: build (schema → validate →
// compute → render → parseDiagramCommand below) is the default scope for
// a single new element. Wiring into diagramCommandRouter.mjs and
// chat.js's DIAGRAM_TYPE_RENDERERS/DIAGRAM_TYPE_ERROR_MESSAGE/
// REBAR_ELEMENT_DISPATCH tables is a separate, later, explicitly-
// requested batch step (same status raftPileDiagram.mjs/
// punchingShearDiagram.mjs/beamColumnJointDiagram.mjs/
// wallOpeningDiagram.mjs are in as of this session) — this file is not
// imported anywhere yet.
//
// Resource lifecycle: this module is pure/synchronous — no timers, no
// fetch, no KV, no external handles of any kind. The caps below exist to
// bound Worker CPU time and output size on a request-scoped isolate, not
// to manage a leakable resource.
//
// Fully deterministic: no `env.AI`, no model call, no network fetch, no
// randomness anywhere in this file. Every SVG byte is arithmetic on
// computeCircularColumnDiagramGeometry's own output.
//
// PARENTHESES/EM-DASH WARNING (documented in structuralLabels.mjs/
// columnDiagram.mjs, applied here identically): Noto Naskh Arabic — the
// font scriptFontStack selects for lang==='ar' — has no glyph for "(",
// ")", or an em/en-dash. Every Arabic value below is written parenthesis-
// and dash-free.

import {
  DiagramError, toMm, assertFinitePositive, assertInt, assertOneOf,
  esc, wrapText, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, distributeTicks, barMarkTag,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ──────────────────────────────────────────────────────
// Same role as columnDiagram.mjs's MIN_SIDE_MM/MAX_SIDE_MM/etc: bound
// worst-case loop counts and input ranges so one request can't build an
// oversized SVG, blow a CPU-time budget, or describe a section that
// cannot be drawn sanely.
const MIN_DIAMETER_MM = 250;
const MAX_DIAMETER_MM = 3000;
const MIN_HEIGHT_MM = 300;
const MAX_HEIGHT_MM = 12000; // one story's worth, schematically — same ceiling columnDiagram.mjs uses
const MIN_BAR_COUNT = 6; // ACI 318-19 §25.7.4.1 minimum for a spirally reinforced column; below 6 the circumference layout also stops reading as a confined column
const MAX_BAR_COUNT = 40;
const MIN_SPIRAL_PITCH_MM = 25; // schematic drawability floor, not a code minimum — see SPIRAL_OVERLAP below for the real geometric guard
const MAX_SPIRAL_PITCH_MM = 150;
const MAX_DRAWN_TURNS_PER_COLUMN = 24; // matches distributeTicks' own hard cap — see that function's header

// ── Compute ──────────────────────────────────────────────────────────
export function computeCircularColumnDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Circular column diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.columnId != null ? String(raw.columnId).slice(0, 40) : 'COLUMN';

  const diameterMM = toMm(raw.diameterMM, unit);
  assertFinitePositive('diameterMM', diameterMM);
  if (diameterMM < MIN_DIAMETER_MM || diameterMM > MAX_DIAMETER_MM) {
    throw new DiagramError('BAD_PARAM', `"diameterMM" must be between ${MIN_DIAMETER_MM}mm and ${MAX_DIAMETER_MM}mm for this schematic, got ${diameterMM}mm.`);
  }

  const heightMM = toMm(raw.heightMM, unit);
  assertFinitePositive('heightMM', heightMM);
  if (heightMM < MIN_HEIGHT_MM || heightMM > MAX_HEIGHT_MM) {
    throw new DiagramError('BAD_PARAM', `"heightMM" must be between ${MIN_HEIGHT_MM}mm and ${MAX_HEIGHT_MM}mm for this schematic, got ${heightMM}mm.`);
  }

  const coverMM = toMm(raw.coverMM, unit);
  assertFinitePositive('coverMM', coverMM);

  if (!Array.isArray(raw.verticalBars) || raw.verticalBars.length !== 1) {
    throw new DiagramError('BAD_PARAM', '"verticalBars" must be an array with exactly one bar group in this schematic — see module scope note (multiple diameter groups are not modeled).');
  }
  const vRaw = raw.verticalBars[0];
  if (!vRaw || typeof vRaw !== 'object') throw new DiagramError('BAD_PARAM', 'verticalBars[0] must be an object.');
  const barDia = toMm(vRaw.diameterMM, unit);
  assertFinitePositive('verticalBars[0].diameterMM', barDia);
  assertInt('verticalBars[0].count', vRaw.count, { min: MIN_BAR_COUNT, max: MAX_BAR_COUNT });
  const position = vRaw.position || 'circumference';
  assertOneOf('verticalBars[0].position', position, ['circumference']);
  const vCuttingLengthMM = vRaw.cuttingLengthMM != null ? toMm(vRaw.cuttingLengthMM, unit) : null;
  if (vCuttingLengthMM != null) assertFinitePositive('verticalBars[0].cuttingLengthMM', vCuttingLengthMM);

  if (!raw.spiral || typeof raw.spiral !== 'object') {
    throw new DiagramError('BAD_PARAM', '"spiral" is required: { diameterMM, pitchMM, type? }.');
  }
  const spiralDia = toMm(raw.spiral.diameterMM, unit);
  assertFinitePositive('spiral.diameterMM', spiralDia);
  const pitchMM = toMm(raw.spiral.pitchMM, unit);
  assertFinitePositive('spiral.pitchMM', pitchMM);
  if (pitchMM < MIN_SPIRAL_PITCH_MM || pitchMM > MAX_SPIRAL_PITCH_MM) {
    throw new DiagramError('BAD_PARAM', `"spiral.pitchMM" must be between ${MIN_SPIRAL_PITCH_MM}mm and ${MAX_SPIRAL_PITCH_MM}mm, got ${pitchMM}mm.`);
  }
  const spiralType = raw.spiral.type || 'spiral';
  assertOneOf('spiral.type', spiralType, ['spiral']);
  const spiralCuttingLengthMM = raw.spiral.cuttingLengthMM != null ? toMm(raw.spiral.cuttingLengthMM, unit) : null;
  if (spiralCuttingLengthMM != null) assertFinitePositive('spiral.cuttingLengthMM', spiralCuttingLengthMM);

  const lapSpliceMM = raw.lapSpliceMM != null ? toMm(raw.lapSpliceMM, unit) : null;
  if (lapSpliceMM != null) {
    assertFinitePositive('lapSpliceMM', lapSpliceMM);
    if (lapSpliceMM >= heightMM) {
      throw new DiagramError('LAP_EXCEEDS_HEIGHT', `"lapSpliceMM" (${lapSpliceMM}mm) must be less than "heightMM" (${heightMM}mm).`);
    }
  }

  const R = diameterMM / 2;

  // Spiral outer bend circle: cover from the column face, same "outer
  // bend legs, before any hook/anchorage allowance" convention
  // columnDiagram.mjs's tieOuter uses.
  const spiralOuterRadius = R - coverMM;
  if (spiralOuterRadius <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) leaves no room for a spiral inside a \u00d8${diameterMM}mm section.`);
  }

  // Bar-CENTER radius: inset further by the spiral's own diameter (the
  // vertical bars sit just inside the spiral loop) plus half the
  // vertical bar's own diameter — same cover-to-center logic
  // columnDiagram.mjs's insetX/insetY use, applied radially here.
  const barCenterRadius = spiralOuterRadius - spiralDia - barDia / 2;
  if (barCenterRadius <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm), spiral diameter (${spiralDia}mm), and bar diameter (${barDia}mm) leave no room for vertical bars inside a \u00d8${diameterMM}mm section.`);
  }
  const positions = computeCircularBarPositions({ centerX: R, centerY: R, radius: barCenterRadius, count: vRaw.count });

  // Spiral centerline radius: the circle the wire's own centroid traces
  // — needed for the helix-length formula below, distinct from the
  // outer-bend radius the cross section draws (same "outer face" vs.
  // "own centerline" distinction a rectangular tie's bend perimeter
  // draws around its outer rectangle, simplified here because a circle
  // has one radius instead of four sides).
  const spiralCenterlineRadius = spiralOuterRadius - spiralDia / 2;
  if (spiralCenterlineRadius <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Spiral diameter (${spiralDia}mm) leaves no room for its own centerline inside a \u00d8${diameterMM}mm section at ${coverMM}mm cover.`);
  }

  // Clear spacing between consecutive turns (outer face to outer face).
  // A non-positive value means the coil would physically pass through
  // itself — a geometric impossibility this module rejects outright,
  // same class of guard as LAP_EXCEEDS_HEIGHT/NO_ROOM_FOR_BARS above.
  // This is NOT the same check as ACI 318-19 §25.7.3.3's 25mm-75mm
  // code-mandated clear-spacing WINDOW (a design-code opinion the KB/
  // design layer owns, same boundary columnDiagram.mjs draws around tie
  // spacing) — that window is surfaced only as an informational caption
  // note below, never enforced here.
  const clearSpacingMM = pitchMM - spiralDia;
  if (clearSpacingMM <= 0) {
    throw new DiagramError('SPIRAL_OVERLAP', `"spiral.pitchMM" (${pitchMM}mm) must exceed the spiral bar diameter (${spiralDia}mm) — consecutive turns would physically overlap at a clear spacing of ${clearSpacingMM}mm.`);
  }

  // Pure helix arc length per one full turn: sqrt((circumference of the
  // centerline circle)^2 + pitch^2) — the standard result for the path
  // length of one turn of a helix. Arithmetic on caller-supplied
  // numbers only, same "we compute geometry, never a design value"
  // boundary every MAX_*/formula in this app respects.
  const circumferenceMM = 2 * Math.PI * spiralCenterlineRadius;
  const perTurnLengthMM = Math.sqrt(circumferenceMM ** 2 + pitchMM ** 2);

  // Real (undrawn-cap-free) turn count over the full height — computed
  // ONCE here, not re-derived independently in the elevation renderer
  // and the schedule table, so the two can never silently drift apart
  // (same reasoning columnDiagram.mjs's own tieCount comment documents).
  const turns = Math.max(2, Math.round(heightMM / pitchMM) + 1);

  return {
    type: 'circularColumn', unit, id, diameterMM, heightMM, coverMM,
    verticalBars: { dia: barDia, count: vRaw.count, position, cuttingLengthMM: vCuttingLengthMM, positions },
    spiral: {
      dia: spiralDia, pitch: pitchMM, type: spiralType, cuttingLengthMM: spiralCuttingLengthMM,
      outerRadius: spiralOuterRadius, clearSpacingMM, turns, perTurnLengthMM,
    },
    lapSpliceMM,
  };
}

// See "Vertical-bar circumference layout" note at the top of this file.
// Returns points already in section-box coordinates (centerX/centerY is
// the box's own center, typically R,R for a box sized to the column's
// own diameter) — unlike columnDiagram.mjs's computeColumnBarPositions,
// which returns points relative to the envelope's own top-left corner
// and requires the caller to add insetX/insetY; a circle has no
// meaningful "top-left of the envelope" so this returns absolute
// section-box coordinates directly.
function computeCircularBarPositions({ centerX, centerY, radius, count }) {
  const points = [];
  for (let i = 0; i < count; i++) {
    const angle = -Math.PI / 2 + (i * 2 * Math.PI) / count; // start at 12 o'clock, proceed clockwise
    points.push({ xMM: centerX + radius * Math.cos(angle), yMM: centerY + radius * Math.sin(angle) });
  }
  return points;
}

// ── Labels ───────────────────────────────────────────────────────────
// Local L = {en:{...}, ar:{...}} dictionary in THIS file, following
// columnDiagram.mjs's own documented decision (see that file's Labels
// section) — NOT an extension of structuralLabels.mjs, which scopes
// itself to footingDiagram.mjs only.
const L = {
  en: {
    title: (id) => `CIRCULAR COLUMN ${id} \u2014 REINFORCEMENT DETAIL`,
    crossSection: 'CROSS SECTION', elevation: 'ELEVATION', spiralDetail: 'SPIRAL PITCH DETAIL',
    vertical: 'Vertical', spiral: 'Spiral', lapZone: 'Lap Splice Zone',
    extentSuffix: ' (extent)', helixSuffix: ' (helix length, anchorage excluded)',
    spiralNote: 'add anchorage turns per code \u2014 not shown. ACI 318-19 \u00a725.7.3.3 clear spacing window: 25mm\u201375mm.',
    pitchLabel: 'pitch', clearWord: 'clear',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Pitch', colLength: 'Length (mm)',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, pitch, and length against your own design (ECP 203 / ACI 318) before issuing for construction. Lengths marked "(extent)" are the drawn member length only. The spiral length shown is the computed pure helix path only \u2014 add anchorage turns per your design code before fabrication. This module draws continuous spiral confinement only; a circular column tied with discrete circular hoops is a different detail, not shown here.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد العمود الدائري ${id}`,
    crossSection: 'قطاع عرضي', elevation: 'منظور جانبي', spiralDetail: 'تفصيلة تباعد اللولب',
    vertical: 'رأسي', spiral: 'لولب', lapZone: 'منطقة تداخل التسليح',
    extentSuffix: ' امتداد', helixSuffix: ' طول اللولب بدون لفات التثبيت',
    spiralNote: 'أضف لفات التثبيت حسب الكود، غير موضحة بالرسم. حد التباعد الصافي بمرجع ACI 318-19 الفقرة 25.7.3.3 من 25 إلى 75 ملم.',
    pitchLabel: 'تباعد اللولب', clearWord: 'صافي',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. الأطوال المُعلَّمة امتداد هي طول الامتداد فقط. طول اللولب المذكور هو الطول الهندسي المحسوب فقط بدون لفات التثبيت، أضفها حسب الكود المستخدم قبل التصنيع. هذا العنصر يرسم لولباً مستمراً فقط، الكانات الدائرية المنفصلة تفصيلة مختلفة غير موضحة هنا.',
    dirAttr: 'rtl',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 950;
const SECTION_BOX = { x: 70, y: 110, w: 260, h: 260 };
const DETAIL_BOX = { x: 70, y: SECTION_BOX.y + SECTION_BOX.h + 70, w: 260, h: 260 };
const ELEV_BOX = { x: 430, y: 110, w: 220, h: (DETAIL_BOX.y + DETAIL_BOX.h) - 110 };

export function renderCircularColumnDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const sectionScale = fitScale([{ contentW: geometry.diameterMM, contentH: geometry.diameterMM, boxW: SECTION_BOX.w - 60, boxH: SECTION_BOX.h - 60 }]);
  const detailScale = fitScale([{ contentW: geometry.spiral.dia * 3, contentH: geometry.spiral.pitch * 2 + geometry.spiral.dia, boxW: DETAIL_BOX.w - 90, boxH: DETAIL_BOX.h - 86 }]);
  const elevScale = fitScale([{ contentW: geometry.diameterMM * 2.4, contentH: geometry.heightMM, boxW: ELEV_BOX.w, boxH: ELEV_BOX.h - 20 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = Math.max(DETAIL_BOX.y + DETAIL_BOX.h, ELEV_BOX.y + ELEV_BOX.h) + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .column-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .zone-label   { font-size:10.5px; fill:#8a6d00; font-family: ${scriptFontStack}; }
    .bar-dot-circular { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }
    .spiral-coil  { stroke:#2f7a3d; stroke-width:1.6; fill:none; }
    .spiral-turn-dot { fill:#2f7a3d; stroke:#1c5027; stroke-width:0.6; }
    .detail-note  { font-size:9.5px; fill:#555; font-family: ${scriptFontStack}; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="column-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderCrossSection(geometry, sectionScale, SECTION_BOX, l)}
  ${renderSpiralDetail(geometry, detailScale, DETAIL_BOX, l)}
  ${renderElevationView(geometry, elevScale, ELEV_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

function renderCrossSection(geometry, scale, box, l) {
  const { diameterMM, verticalBars, spiral } = geometry;
  const w = diameterMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + (box.h - w) / 2;
  const cx = sx + w / 2, cy = sy + w / 2;
  let svg = `<g class="cross-section">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.crossSection)}</text>`;
  svg += `<circle cx="${cx}" cy="${cy}" r="${w / 2}" class="concrete-outline"/>`;
  svg += `<circle cx="${cx}" cy="${cy}" r="${spiral.outerRadius * scale}" class="stirrup-outline"/>`;
  for (const p of verticalBars.positions) {
    svg += barDot(sx + p.xMM * scale, sy + p.yMM * scale, verticalBars.dia, scale, 'circular');
  }
  svg += barMarkTag(sx + w + 24, cy, `${verticalBars.count}\u00d8${Math.round(verticalBars.dia)}`, { r: 13 });
  svg += dimensionLine(sx, sy + w + 20, sx + w, sy + w + 20, `\u00d8${Math.round(diameterMM)}mm`, { orientation: 'h', tick: 5 });
  svg += `</g>`;
  return svg;
}

// Longitudinal-section view of the spiral: cutting a helix along a plane
// through its axis shows the wire as a series of small circles spaced at
// the pitch — this draws exactly that (3 representative crossings), the
// same convention real shop drawings use to dimension a spiral's pitch,
// distinct from the cross-section view above (which shows the spiral's
// plan-view outer diameter, not its pitch).
function renderSpiralDetail(geometry, scale, box, l) {
  const { spiral } = geometry;
  const r = Math.max(2.2, (spiral.dia * scale) / 2);
  const pitchPx = spiral.pitch * scale;
  // Footer reserves room for THREE fixed lines (dia label + 2-line
  // wrapped note) below the content region, all anchored from the
  // BOX'S OWN bottom edge (fixed offsets), not from the circles' own
  // variable bottom position — same fixed-anchoring convention
  // columnDiagram.mjs's renderTieDetail uses (see that file's own
  // comment for the bug class this avoids: a variable-height block's
  // trailing text positioned relative to that block's own end, only
  // caught by measuring actual rendered pixel Y values).
  const regionTop = box.y + 26, regionBottom = box.y + box.h - 62;
  const contentH = 2 * pitchPx;
  const cx = box.x + box.w / 2;
  const topCy = regionTop + (regionBottom - regionTop - contentH) / 2 + r;
  let svg = `<g class="spiral-detail">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 10}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.spiralDetail)}</text>`;
  const cys = [topCy, topCy + pitchPx, topCy + 2 * pitchPx];
  for (const cy of cys) {
    svg += `<circle cx="${cx}" cy="${cy}" r="${r.toFixed(2)}" class="spiral-turn-dot"/>`;
  }
  svg += `<line x1="${cx}" y1="${cys[0]}" x2="${cx}" y2="${cys[2]}" class="spiral-coil" stroke-dasharray="1,3"/>`;
  svg += dimensionLine(cx + 38, cys[0], cx + 38, cys[1], `${Math.round(spiral.pitch)}mm`, { orientation: 'v', tick: 5 });
  // Two SEPARATE text nodes, not one — mixing a translated Arabic word
  // into the SAME <text> element as "NNmm" (engineering notation, must
  // stay on defaultFontStack) risks tofu for the Arabic glyphs, exactly
  // the font-split rule structuralDrawingKit.mjs documents and
  // columnDiagram.mjs's renderTieDetail already applies in the mirror-
  // image direction (Ø/mm notation kept off scriptFontStack there;
  // here a translated word is kept off the numbers-only dim-label
  // class, which carries no scriptFontStack override).
  const clearMidY = (cys[0] + cys[1]) / 2;
  svg += `<text x="${cx - 38}" y="${clearMidY - 8}" text-anchor="end" class="detail-note" dir="${l.dirAttr}">${esc(l.clearWord)}</text>`;
  svg += `<text x="${cx - 38}" y="${clearMidY + 6}" text-anchor="end" class="dim-label">${Math.round(spiral.clearSpacingMM)}mm</text>`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y + box.h - 44}" text-anchor="middle" class="dim-label">\u00d8${Math.round(spiral.dia)}mm</text>`;
  const noteLines = wrapText(l.spiralNote, 40);
  noteLines.forEach((line, i) => {
    svg += `<text x="${box.x + box.w / 2}" y="${box.y + box.h - 28 + i * 13}" text-anchor="middle" class="detail-note" dir="${l.dirAttr}">${esc(line)}</text>`;
  });
  svg += `</g>`;
  return svg;
}

function renderElevationView(geometry, scale, box, l) {
  const { diameterMM, heightMM, spiral, lapSpliceMM, verticalBars } = geometry;
  const w = diameterMM * scale, h = heightMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const topY = box.y + 10;
  const botY = topY + h;
  let svg = `<g class="elevation">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.elevation)}</text>`;
  svg += `<rect x="${sx}" y="${topY}" width="${w}" height="${h}" class="concrete-outline"/>`;

  // Continuous zigzag representing the spiral's helix, the standard
  // drafting convention for showing a coil in a flat elevation view —
  // distinct from columnDiagram.mjs's discrete tieTickH() ticks, which
  // represent separate, individual rectangular ties, not one continuous
  // wire. Drawn at a capped, representative turn count, same
  // representative-not-literal convention distributeTicks() documents.
  const drawTurns = Math.min(spiral.turns, MAX_DRAWN_TURNS_PER_COLUMN);
  const ys = distributeTicks(topY, botY, drawTurns);
  const pts = ys.map((y, i) => `${i % 2 === 0 ? sx + 3 : sx + w - 3},${y}`);
  svg += `<polyline points="${pts.join(' ')}" class="spiral-coil"/>`;

  // The two extreme (outermost) perimeter bar lines, drawn full height —
  // a representative pair, not all `count` bars individually, same
  // "where, not how many" role columnDiagram.mjs's own elevation plays.
  svg += `<line x1="${sx + 4}" y1="${topY}" x2="${sx + 4}" y2="${botY}" class="bar-bottom"/>`;
  svg += `<line x1="${sx + w - 4}" y1="${topY}" x2="${sx + w - 4}" y2="${botY}" class="bar-bottom"/>`;
  svg += barMarkTag(sx + w + 22, topY + 16, `${verticalBars.count}\u00d8${Math.round(verticalBars.dia)}`, { r: 12 });

  if (lapSpliceMM != null) {
    const lapH = lapSpliceMM * scale;
    const lapY = botY - lapH;
    svg += `<rect x="${sx}" y="${lapY}" width="${w}" height="${lapH}" fill="#fff3cd" fill-opacity="0.55" stroke="#b8860b" stroke-width="1" stroke-dasharray="4,2"/>`;
    svg += dimensionLine(sx - 18, lapY, sx - 18, botY, `${Math.round(lapSpliceMM)}mm`, { orientation: 'v', tick: 5 });
    svg += `<text x="${sx + w + 8}" y="${(lapY + botY) / 2}" class="zone-label" dir="${l.dirAttr}">${esc(l.lapZone)}</text>`;
  }

  svg += dimensionLine(sx + w + 50, topY, sx + w + 50, botY, `H = ${(heightMM / 1000).toFixed(2)}m`, { orientation: 'v' });
  svg += `<text x="${sx + w / 2}" y="${botY + 14}" text-anchor="middle" class="support-label">\u00d8${Math.round(spiral.dia)}@${Math.round(spiral.pitch)}</text>`;
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  const vb = geometry.verticalBars;
  rows.push({
    mark: 'V1',
    element: l.vertical,
    dia: String(Math.round(vb.dia)),
    count: String(vb.count),
    length: vb.cuttingLengthMM != null ? String(Math.round(vb.cuttingLengthMM)) : `${Math.round(geometry.heightMM)}${l.extentSuffix}`,
  });
  rows.push({
    mark: 'SP1',
    element: l.spiral,
    dia: String(Math.round(geometry.spiral.dia)),
    count: `@${Math.round(geometry.spiral.pitch)} (${geometry.spiral.turns})`,
    length: geometry.spiral.cuttingLengthMM != null ? String(Math.round(geometry.spiral.cuttingLengthMM)) : `${Math.round(geometry.spiral.perTurnLengthMM * geometry.spiral.turns)}${l.helixSuffix}`,
  });
  if (geometry.lapSpliceMM != null) {
    rows.push({
      mark: '\u2014',
      element: l.lapZone,
      dia: '\u2014',
      count: '\u2014',
      length: String(Math.round(geometry.lapSpliceMM)),
    });
  }
  return rows;
}

// ── Chat-facing entry point ────────────────────────────────────────────
// Mirrors columnDiagram.mjs's parseColumnRebarPayload() error-shape
// contract exactly ({ok:true,...} / {ok:false,code,message}). Never
// throws a DiagramError out; anything else (a genuine programmer error)
// is rethrown, same as every reference module.
export function parseCircularColumnRebarPayload(raw) {
  try {
    const geometry = computeCircularColumnDiagramGeometry(raw);
    return { ok: true, type: 'circularColumn', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Mirrors columnDiagram.mjs's parseDiagramCommand exactly: same leading-
// token + "key=value key=value ..." syntax, same BAD_SYNTAX/
// UNSUPPORTED_TYPE reservation, same never-throws contract, error results
// also carry `.type`.
//
// Syntax:
//   /diagram circularcolumn id=C1 diameter=500 height=3000 cover=40
//     bardia=20 barcount=8 spiraldia=10 pitch=75
//     [lap=600] [unit=mm]
// No key for vertical-bar position or spiral type: this schema supports
// exactly one value for each ('circumference' bars, 'spiral' ties — see
// the SCOPE note at the top of this file), so there is nothing for a
// flat command to choose between yet; computeCircularColumnDiagramGeometry's
// own defaults apply unchanged when those keys are omitted.
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: circularcolumn key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'circularcolumn') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use circularcolumn.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const geometry = computeCircularColumnDiagramGeometry({
      columnId: kv.id, diameterMM: num('diameter'),
      heightMM: num('height'), coverMM: num('cover'),
      verticalBars: [{ diameterMM: num('bardia'), count: num('barcount') }],
      spiral: { diameterMM: num('spiraldia'), pitchMM: num('pitch') },
      lapSpliceMM: num('lap'), unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
