// functions/_lib/couplingBeamDiagram.mjs
//
// Deterministic, zero-AI SVG generator for a diagonally-reinforced
// coupling-beam detail (elevation + diagonal-bundle cross-section detail
// + midspan section + bar-bending schedule) — candidate from
// برومبت_استكمال_العمل_v17.md's second (ACI 318 gap) collection, medium
// priority: "Coupling Beam — ACI 318 §18.10.7". Same philosophy as
// footingDiagram.mjs/beamDiagram.mjs/columnDiagram.mjs: every dimension,
// bar position, and count in the output is arithmetic on the KB data
// supplied, never a model's guess. This module owns compute+render only;
// it does not decide bar counts, diameters, spacing, or WHETHER diagonal
// detailing is required in the first place — that is the KB/design
// layer's job (see INPUT CONTRACT below).
//
// Web-verified this session (ACI 318-19 §18.10.7.3/.7.4, not carried over
// from any prior undocumented source): a coupling beam with ln/h < 4 and
// Vu >= 4*lambda*sqrt(f'c)*Acw requires two intersecting groups of
// diagonally placed bars, symmetrical about midspan (§18.10.7.2); each
// group needs at least four bars in two or more layers (§18.10.7.3); the
// code offers TWO transverse-reinforcement options at §18.10.7.4 — confine
// EACH diagonal group individually, or confine the ENTIRE beam
// cross-section — plus a nominal perimeter (crack-control) long./transverse
// cage either way. This module draws ONLY the first confinement option.
//
// SCOPE (v1): a single prismatic rectangular coupling beam (constant
// widthMM x depthMM over its clear span spanClearMM) connecting two wall
// piers, with exactly TWO diagonal bar groups — symmetric about midspan,
// one bar diameter/count/layer-count shared by both groups (the code's own
// "symmetrical about the midspan" language) — each individually confined by
// its own rectangular tie at a constant spacing along its length
// (§18.10.7.4's first confinement option).
// NOT modeled, on purpose (each needs a parametrization this module hasn't
// been given yet, same "explicit scope boundary" convention
// beamDiagram.mjs/columnDiagram.mjs's own headers use):
//   - the ln/h < 4 and Vu >= 4*lambda*sqrt(f'c)*Acw GATE that decides
//     whether diagonal detailing applies at all (§18.10.7.1/.2/.3) — a
//     demand/capacity design decision, not a drawing decision; this module
//     assumes the caller already made it, exactly like columnDiagram.mjs
//     never re-derives whether a column needs 4 bars or 40.
//   - the FULL-CROSS-SECTION confinement alternative at §18.10.7.4 — a
//     different tie layout (hoops around the whole beam section along its
//     full length instead of around each diagonal bundle) this module does
//     not attempt; only the "confine each diagonal group individually"
//     variant is drawn.
//   - asymmetric diagonal groups (different diameter/count/layers between
//     the two directions) — diagonalBars is a single spec applied to BOTH
//     groups by construction, matching the code's own symmetry requirement;
//     a genuinely asymmetric pair is not a shape this module will invent.
//   - the nominal perimeter (crack-control) longitudinal + transverse cage
//     §18.10.7.4 also requires around the beam regardless of which
//     confinement option governs — real code requirement, real future
//     work (same top/bottom-bar + stirrup-zone pattern beamDiagram.mjs's
//     own longitudinal/stirrup handling already draws elsewhere in this
//     app), not drawn here in v1.
//   - bar bend/hook geometry at the wall-embedment ends and any
//     code-required development length ld — embedMM is a caller-supplied
//     straight length, this module never computes a development length.
//   - Vn/Vu capacity values (Eq. 18.10.7.4, Vn = 2*Avd*fy*sin(alpha)) —
//     never computed here; this module only draws geometry it is given,
//     same "compute+render only" boundary columnDiagram.mjs documents.
//
// ── INPUT CONTRACT (what the KB layer should hand this module) ─────────
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   beamId: string,                    // coupling-beam mark, e.g. "CB-3F"
//   spanClearMM: number,               // ln — clear span between the two
//                                      // wall-pier faces
//   depthMM: number,                   // h — overall beam depth
//   widthMM: number,                   // bw — beam width (out-of-plane
//                                      // thickness)
//   coverMM: number,                   // clear cover to confinement-tie
//                                      // outer face
//   embedMM: number,                   // straight embedment length of
//                                      // EACH diagonal bar group into ITS
//                                      // own wall pier — same value both
//                                      // ends (symmetric, per §18.10.7.3)
//   diagonalBars: {
//     diameterMM: number,
//     countPerGroup: number,           // bars in ONE group (>=4 — the
//                                       // code's own minimum); both groups
//                                       // identical by construction
//     layers: number,                  // >=2 — "two or more layers";
//                                       // countPerGroup must divide evenly
//                                       // by layers (ODD_BAR_LAYERS below)
//     cuttingLengthMM?: number,        // full fabricated length if the KB
//                                      // layer already computed it; omit
//                                      // to show the drawn straight
//                                      // anchor-to-anchor extent labeled
//                                      // "(extent)"/"امتداد"
//   },
//   confinementTies: {
//     diameterMM: number,
//     spacingMM: number,               // center-to-center ALONG the
//                                      // diagonal bar axis
//     cuttingLengthMM?: number,        // full tie cutting length incl.
//                                      // hooks, if already computed; omit
//                                      // to show the tie's own bend
//                                      // perimeter, honestly labeled
//   },
// }
//
// ── Angle label — an AS-DRAWN value, not a code check ──────────────────
// The angle shown on the elevation is atan2(verticalRiseMM, totalLengthMM)
// where totalLengthMM = spanClearMM + 2*embedMM — i.e. the slope of the
// exact straight line this module draws from anchor to anchor, including
// the embedment run. The literature's own "angle between the diagonal
// bars and the longitudinal axis" (used in Eq. 18.10.7.4, Vn = 2*Avd*fy*
// sin(alpha)) is a DESIGN value the KB layer derives from its own detailing
// convention (which may bend the bar to horizontal inside the wall rather
// than continuing it straight) — this module's label is deliberately
// captioned "as drawn" and must never be read as that design value.
//
// ── Bar layout (computeDiagonalBundleGrid) ──────────────────────────────
// Each group's bars are laid out as a `layers` x `barsPerLayer` GRID inside
// its own confinement-tie envelope (an interior grid, not a hollow
// perimeter — genuinely different geometry from columnDiagram.mjs's
// perimeter layout, because here the code literally requires the bars
// bundled together in rows, not spread around a section edge).
//
// ── /couplingbeam and /image wiring — NOT done here, on purpose ────────
// Per برومبت_استكمال_العمل_v17.md's Phase A/Phase B split: this pass
// builds schema -> validate -> compute -> render -> parseDiagramCommand
// for THIS element only. diagramCommandRouter.mjs, chat.js, and both HTML
// front ends are neither opened nor touched here — that is a separate,
// explicitly-requested, batched integration step (Phase B) covering every
// accumulated unwired element at once, not per-element.
//
// Resource lifecycle: this module is pure/synchronous — no timers, no
// fetch, no KV, no external handles of any kind. The caps below exist to
// bound Worker CPU time and output size on a request-scoped isolate, not
// to manage a leakable resource.
//
// Step 17 convention: fully deterministic — no `env.AI`, no model call, no
// network fetch, no randomness anywhere in this file. Every SVG byte is
// arithmetic on computeCouplingBeamDiagramGeometry's own output. "Drawn
// extent" vs "actual cut length": see cuttingLengthMM in the INPUT
// CONTRACT above and structuralDrawingKit.mjs's header for the general
// rule this file follows (buildScheduleRows below falls back to the drawn
// extent, suffixed, only when cuttingLengthMM is absent) — same convention
// columnDiagram.mjs's own buildScheduleRows uses.

import {
  DiagramError, toMm, assertFinitePositive, assertInt,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, distributeTicks, barMarkTag,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ──────────────────────────────────────────────────────
// Same role as columnDiagram.mjs's MIN/MAX_SIDE_MM etc.: this is a
// chat-driven schematic tool, not a CAD system — bound worst-case loop
// counts and input ranges so one request can't build an oversized SVG,
// blow a CPU-time budget, or describe a beam that cannot be drawn sanely.
const MIN_SPAN_MM = 300;
const MAX_SPAN_MM = 6000;
const MIN_DEPTH_MM = 300;
const MAX_DEPTH_MM = 2000;
const MIN_WIDTH_MM = 150;
const MAX_WIDTH_MM = 1000;
const MIN_EMBED_MM = 150;
const MAX_EMBED_MM = 3000;
const MIN_DIAG_BAR_DIA_MM = 10;
const MAX_DIAG_BAR_DIA_MM = 50;
const MIN_BARS_PER_GROUP = 4; // §18.10.7.3's own stated minimum
const MAX_BARS_PER_GROUP = 24;
const MIN_LAYERS = 2; // §18.10.7.3's own "two or more layers"
const MAX_LAYERS = 6;
const MIN_TIE_DIA_MM = 8;
const MAX_TIE_DIA_MM = 20;
const MIN_TIE_SPACING_MM = 20;
const MAX_TIE_SPACING_MM = 300;
const MAX_DRAWN_TIES_PER_GROUP = 20; // representative-tick cap, matches distributeTicks' own hard cap — see that function's header
const BUNDLE_ROW_PITCH_FACTOR = 2.4; // center-to-center row pitch inside a bundle, as a multiple of bar diameter — generous, non-overlapping schematic spacing, not a code-derived clear-spacing rule

// ── Compute ──────────────────────────────────────────────────────────
export function computeCouplingBeamDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Coupling beam diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.beamId != null ? String(raw.beamId).slice(0, 40) : 'CB';

  const spanClearMM = toMm(raw.spanClearMM, unit);
  assertFinitePositive('spanClearMM', spanClearMM);
  if (spanClearMM < MIN_SPAN_MM || spanClearMM > MAX_SPAN_MM) {
    throw new DiagramError('BAD_PARAM', `"spanClearMM" must be between ${MIN_SPAN_MM}mm and ${MAX_SPAN_MM}mm for this schematic, got ${spanClearMM}mm.`);
  }

  const depthMM = toMm(raw.depthMM, unit);
  assertFinitePositive('depthMM', depthMM);
  if (depthMM < MIN_DEPTH_MM || depthMM > MAX_DEPTH_MM) {
    throw new DiagramError('BAD_PARAM', `"depthMM" must be between ${MIN_DEPTH_MM}mm and ${MAX_DEPTH_MM}mm for this schematic, got ${depthMM}mm.`);
  }

  const widthMM = toMm(raw.widthMM, unit);
  assertFinitePositive('widthMM', widthMM);
  if (widthMM < MIN_WIDTH_MM || widthMM > MAX_WIDTH_MM) {
    throw new DiagramError('BAD_PARAM', `"widthMM" must be between ${MIN_WIDTH_MM}mm and ${MAX_WIDTH_MM}mm for this schematic, got ${widthMM}mm.`);
  }

  const coverMM = toMm(raw.coverMM, unit);
  assertFinitePositive('coverMM', coverMM);

  const embedMM = toMm(raw.embedMM, unit);
  assertFinitePositive('embedMM', embedMM);
  if (embedMM < MIN_EMBED_MM || embedMM > MAX_EMBED_MM) {
    throw new DiagramError('BAD_PARAM', `"embedMM" must be between ${MIN_EMBED_MM}mm and ${MAX_EMBED_MM}mm for this schematic, got ${embedMM}mm.`);
  }

  if (!raw.diagonalBars || typeof raw.diagonalBars !== 'object') {
    throw new DiagramError('BAD_PARAM', '"diagonalBars" is required: { diameterMM, countPerGroup, layers }.');
  }
  const diagDia = toMm(raw.diagonalBars.diameterMM, unit);
  assertFinitePositive('diagonalBars.diameterMM', diagDia);
  if (diagDia < MIN_DIAG_BAR_DIA_MM || diagDia > MAX_DIAG_BAR_DIA_MM) {
    throw new DiagramError('BAD_PARAM', `"diagonalBars.diameterMM" must be between ${MIN_DIAG_BAR_DIA_MM}mm and ${MAX_DIAG_BAR_DIA_MM}mm, got ${diagDia}mm.`);
  }
  assertInt('diagonalBars.countPerGroup', raw.diagonalBars.countPerGroup, { min: MIN_BARS_PER_GROUP, max: MAX_BARS_PER_GROUP });
  assertInt('diagonalBars.layers', raw.diagonalBars.layers, { min: MIN_LAYERS, max: MAX_LAYERS });
  const countPerGroup = raw.diagonalBars.countPerGroup;
  const layers = raw.diagonalBars.layers;
  if (countPerGroup % layers !== 0) {
    throw new DiagramError(
      'UNEVEN_BAR_LAYERS',
      `diagonalBars.countPerGroup (${countPerGroup}) must divide evenly by diagonalBars.layers (${layers}) — this module lays each group out as a rectangular grid of rows and will not invent an uneven row split, got ${countPerGroup}/${layers}.`,
    );
  }
  const barsPerLayer = countPerGroup / layers;
  const diagCuttingLengthMM = raw.diagonalBars.cuttingLengthMM != null ? toMm(raw.diagonalBars.cuttingLengthMM, unit) : null;
  if (diagCuttingLengthMM != null) assertFinitePositive('diagonalBars.cuttingLengthMM', diagCuttingLengthMM);

  if (!raw.confinementTies || typeof raw.confinementTies !== 'object') {
    throw new DiagramError('BAD_PARAM', '"confinementTies" is required: { diameterMM, spacingMM }.');
  }
  const tieDia = toMm(raw.confinementTies.diameterMM, unit);
  assertFinitePositive('confinementTies.diameterMM', tieDia);
  if (tieDia < MIN_TIE_DIA_MM || tieDia > MAX_TIE_DIA_MM) {
    throw new DiagramError('BAD_PARAM', `"confinementTies.diameterMM" must be between ${MIN_TIE_DIA_MM}mm and ${MAX_TIE_DIA_MM}mm, got ${tieDia}mm.`);
  }
  const tieSpacing = toMm(raw.confinementTies.spacingMM, unit);
  assertFinitePositive('confinementTies.spacingMM', tieSpacing);
  if (tieSpacing < MIN_TIE_SPACING_MM || tieSpacing > MAX_TIE_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"confinementTies.spacingMM" must be between ${MIN_TIE_SPACING_MM}mm and ${MAX_TIE_SPACING_MM}mm, got ${tieSpacing}mm.`);
  }
  const tieCuttingLengthMM = raw.confinementTies.cuttingLengthMM != null ? toMm(raw.confinementTies.cuttingLengthMM, unit) : null;
  if (tieCuttingLengthMM != null) assertFinitePositive('confinementTies.cuttingLengthMM', tieCuttingLengthMM);

  // Bar-CENTER inset from the top/bottom beam face by cover + tie diameter
  // (the tie loop sits just inside the cover) + half the diagonal bar's own
  // diameter — same cover-to-center logic columnDiagram.mjs's insetX/insetY
  // use, applied here to the beam's two horizontal faces only (the beam is
  // not confined on its side faces the way a column is on all four).
  const insetY = coverMM + tieDia + diagDia / 2;
  const verticalRiseMM = depthMM - 2 * insetY;
  if (verticalRiseMM <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm), tie diameter (${tieDia}mm), and bar diameter (${diagDia}mm) leave no vertical room for a diagonal bar group inside a ${depthMM}mm-deep beam.`);
  }

  // Full straight anchor-to-anchor length, including both embedment runs —
  // see the header's "Angle label" note for why alpha is measured over
  // THIS length, not spanClearMM alone.
  const totalLengthMM = spanClearMM + 2 * embedMM;
  const angleRad = Math.atan2(verticalRiseMM, totalLengthMM);
  const angleDeg = (angleRad * 180) / Math.PI;
  const drawnDiagLengthMM = Math.hypot(verticalRiseMM, totalLengthMM);

  // Real (undrawn-cap-free) tie count along one group's full drawn length —
  // computed ONCE here, not re-derived independently in both the elevation
  // renderer and the schedule table, so the two can never silently drift
  // apart (same reasoning columnDiagram.mjs's own tieCount comment gives).
  const tieCount = Math.max(2, Math.round(drawnDiagLengthMM / tieSpacing) + 1);

  // Confinement-tie envelope around ONE diagonal bundle (interior grid, not
  // a hollow perimeter — see the header's "Bar layout" note). The envelope
  // spans most of the beam width (inset by coverMM, same as a column's tie
  // sitting `coverMM` inside the concrete face) and just enough depth,
  // measured in the bundle's OWN cross-section plane, to contain `layers`
  // rows at BUNDLE_ROW_PITCH_FACTOR*diagDia center-to-center pitch.
  const bundleRowPitchMM = diagDia * BUNDLE_ROW_PITCH_FACTOR;
  const bundlePlaneMM = layers > 1 ? (layers - 1) * bundleRowPitchMM + diagDia : diagDia;
  const bundleTieOuter = {
    w: widthMM - 2 * coverMM,
    h: bundlePlaneMM + 2 * tieDia,
  };
  if (bundleTieOuter.w <= 0 || bundleTieOuter.h <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BUNDLE', `Cover (${coverMM}mm) and the ${layers}-layer, ${diagDia}mm-diameter bundle leave no room for a confinement tie inside a ${widthMM}mm-wide beam.`);
  }
  const bundleInsetMM = tieDia + diagDia / 2;
  const bundleInnerW = bundleTieOuter.w - 2 * bundleInsetMM;
  const bundleInnerH = bundleTieOuter.h - 2 * bundleInsetMM;
  if (bundleInnerW <= 0 || bundleInnerH <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BUNDLE', `Tie diameter (${tieDia}mm) and bar diameter (${diagDia}mm) leave no room for the bar grid inside the confinement tie.`);
  }
  const bundlePositions = [];
  for (let row = 0; row < layers; row++) {
    const yMM = layers === 1 ? bundleInnerH / 2 : (bundleInnerH * row) / (layers - 1);
    for (let col = 0; col < barsPerLayer; col++) {
      const xMM = barsPerLayer === 1 ? bundleInnerW / 2 : (bundleInnerW * col) / (barsPerLayer - 1);
      bundlePositions.push({ xMM: bundleInsetMM + xMM, yMM: bundleInsetMM + yMM });
    }
  }

  return {
    type: 'couplingBeam', unit, id, spanClearMM, depthMM, widthMM, coverMM, embedMM,
    totalLengthMM, verticalRiseMM, insetY, angleDeg, drawnDiagLengthMM,
    diagonalBars: { dia: diagDia, countPerGroup, layers, barsPerLayer, cuttingLengthMM: diagCuttingLengthMM },
    confinementTies: { dia: tieDia, spacing: tieSpacing, cuttingLengthMM: tieCuttingLengthMM, count: tieCount },
    bundle: { outer: bundleTieOuter, positions: bundlePositions },
  };
}

// ── Labels ───────────────────────────────────────────────────────────
// Local `L = {en:{...}, ar:{...}}` dictionary in THIS file, following
// beamDiagram.mjs/columnDiagram.mjs's own pattern — see columnDiagram.mjs's
// header for why structuralLabels.mjs (scoped to footingDiagram.mjs only,
// per its own header) is not extended here either. PARENTHESES/EM-DASH
// WARNING (verified via cairosvg glyph-probing, per structuralLabels.mjs):
// Noto Naskh Arabic has no glyph for "(", ")", or an em/en-dash — every
// Arabic value below is written parenthesis- and dash-free, following
// footingDiagram.mjs/columnDiagram.mjs's verified-safe convention.
const L = {
  en: {
    title: (id) => `COUPLING BEAM ${id} \u2014 DIAGONAL REINFORCEMENT DETAIL`,
    elevation: 'ELEVATION', bundleDetail: 'DIAGONAL BUNDLE DETAIL', midspanSection: 'SECTION AT MIDSPAN',
    diagonal: 'Diagonal Group', tie: 'Confinement Tie',
    extentSuffix: ' (extent)', perimeterSuffix: ' (bend perimeter, hooks not included)',
    angleNote: 'as drawn',
    wallPier: 'Wall Pier',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    caption: 'Schematic diagonal-reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, angle, and length against your own design (ACI 318-19 \u00a718.10.7) before issuing for construction. This module draws the option that confines EACH diagonal bar group individually (\u00a718.10.7.4) \u2014 the alternative full-cross-section confinement option is not shown. The nominal perimeter crack-control reinforcement \u00a718.10.7.4 also requires is not drawn here. The angle shown is the AS-DRAWN slope of the straight bar line only, not a design value \u2014 do not check it against a code equation directly. Lengths marked "(extent)" are the drawn straight length only; the tie length shown is its bend perimeter only. Add development length, hooks, and lap length per your design code before fabrication.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد كمرة الربط ${id} تسليح قطري`,
    elevation: 'منظور جانبي', bundleDetail: 'تفصيلة الحزمة القطرية', midspanSection: 'قطاع منتصف البحر',
    diagonal: 'مجموعة قطرية', tie: 'كانة تحصير',
    extentSuffix: ' امتداد', perimeterSuffix: ' محيط الكانة بدون الكلبتين',
    angleNote: 'كما يظهر بالرسم',
    wallPier: 'جدار قص',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي للتسليح القطري أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وزاويتها وطولها وفق تصميمك الخاص طبقاً لبند 18.10.7 من الكود الأمريكي قبل الاعتماد للتنفيذ. هذا الرسم يمثل خيار تحصير كل مجموعة قطرية منفردة، لا خيار تحصير المقطع الكامل البديل. التسليح المحيطي الإضافي الذي يتطلبه نفس البند غير موضح بهذا الرسم. الزاوية الظاهرة هي ميل الخط المرسوم فقط، ليست قيمة تصميمية، لا تُقارَن مباشرة بمعادلة الكود. الأطوال المُعلَّمة امتداد هي طول الامتداد المستقيم فقط، وطول الكانة المذكور هو محيط الانحناء فقط بدون الكلبتين. أضف طول التطويل والكلبتين والتداخل حسب الكود المستخدم قبل التصنيع.',
    dirAttr: 'rtl',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 1000;
const ELEV_BOX = { x: 60, y: 110, w: 880, h: 210 };
const BUNDLE_BOX = { x: 60, y: ELEV_BOX.y + ELEV_BOX.h + 70, w: 300, h: 230 };
const SECTION_BOX = { x: 420, y: BUNDLE_BOX.y, w: 220, h: 230 };

export function renderCouplingBeamDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const elevScale = fitScale([{ contentW: geometry.totalLengthMM, contentH: geometry.depthMM, boxW: ELEV_BOX.w - 60, boxH: ELEV_BOX.h - 60 }]);
  const bundleScale = fitScale([{ contentW: geometry.bundle.outer.w, contentH: geometry.bundle.outer.h, boxW: BUNDLE_BOX.w - 70, boxH: BUNDLE_BOX.h - 86 }]);
  const sectionScale = fitScale([{ contentW: geometry.widthMM, contentH: geometry.depthMM, boxW: SECTION_BOX.w - 60, boxH: SECTION_BOX.h - 60 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = Math.max(BUNDLE_BOX.y + BUNDLE_BOX.h, SECTION_BOX.y + SECTION_BOX.h) + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .coupling-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .bar-dot-diag1   { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }
    .bar-dot-diag2   { fill:#c0392b; stroke:#7a2015; stroke-width:0.6; }
    .diag-bar-line   { stroke-width:3; }
    .wall-pier       { fill:url(#concreteHatch); stroke:#1a1a1a; stroke-width:1.4; }
    .angle-label     { font-size:12px; fill:#333; }
    .angle-note-label{ font-size:11px; fill:#333; font-family: ${scriptFontStack}; }
    .zone-label      { font-size:10.5px; fill:#8a6d00; font-family: ${scriptFontStack}; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="coupling-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderElevation(geometry, elevScale, ELEV_BOX, l)}
  ${renderBundleDetail(geometry, bundleScale, BUNDLE_BOX, l)}
  ${renderMidspanSection(geometry, sectionScale, SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// Short tick perpendicular to a line segment, at parametric position t in
// [0,1] between (x1,y1) and (x2,y2) — the diagonal counterpart of the
// kit's own tieTickH()/stirrupTick() (both axis-aligned only, so neither
// fits an angled bundle line; this is the "element-specific geometry
// drawn locally with the kit's generic primitives" pattern
// structuralDrawingKit.mjs's own Step 18 note explicitly sanctions).
// distributeTicks() is reused unchanged for spacing the t values — its
// documented purpose (evenly-spaced representative positions, capped) is
// unit-agnostic, so calling it over the abstract [0,1] range instead of
// pixel coordinates is the same function doing the same job.
function diagonalTicks(x1, y1, x2, y2, count, halfLenPx) {
  const dx = x2 - x1, dy = y2 - y1;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len, uy = dy / len;
  const px = -uy, py = ux;
  let svg = '';
  for (const t of distributeTicks(0, 1, count)) {
    const cx = x1 + dx * t, cy = y1 + dy * t;
    svg += `<line x1="${cx + px * halfLenPx}" y1="${cy + py * halfLenPx}" x2="${cx - px * halfLenPx}" y2="${cy - py * halfLenPx}" class="stirrup-tick"/>`;
  }
  return svg;
}

function renderElevation(geometry, scale, box, l) {
  const { totalLengthMM, spanClearMM, depthMM, embedMM, verticalRiseMM, insetY, confinementTies, diagonalBars, angleDeg } = geometry;
  // `totalPx` sizes the WHOLE drawn assembly (left pier + beam + right
  // pier); the beam's own concrete-outline is only `spanPx` wide — using
  // `totalPx` for the concrete rect itself (an earlier version of this
  // function did exactly that) double-counts the embedment, drawing the
  // beam's own concrete stretching across the wall piers too. Diagonal
  // bar lines legitimately span the FULL assembly (they run from deep in
  // one pier to deep in the other); the concrete outline and the "ln"
  // dimension line must not.
  const totalPx = totalLengthMM * scale, h = depthMM * scale;
  const spanPx = spanClearMM * scale;
  const embedPx = embedMM * scale;
  const sxAll = box.x + (box.w - totalPx) / 2;
  const sy = box.y + (box.h - h) / 2;
  const beamX = sxAll + embedPx;
  const rightPierX = beamX + spanPx;
  const insetPx = insetY * scale;
  const drawCount = Math.min(confinementTies.count, MAX_DRAWN_TIES_PER_GROUP);

  let svg = `<g class="elevation">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.elevation)}</text>`;
  svg += `<rect x="${sxAll}" y="${sy}" width="${embedPx}" height="${h}" class="wall-pier"/>`;
  svg += `<rect x="${rightPierX}" y="${sy}" width="${embedPx}" height="${h}" class="wall-pier"/>`;
  svg += `<rect x="${beamX}" y="${sy}" width="${spanPx}" height="${h}" class="concrete-outline"/>`;

  // Group 1: bottom-left anchor -> top-right anchor, full assembly width
  // (each end anchored deep inside its own wall pier, per embedMM).
  const g1x1 = sxAll, g1y1 = sy + h - insetPx, g1x2 = sxAll + totalPx, g1y2 = sy + insetPx;
  svg += `<line x1="${g1x1}" y1="${g1y1}" x2="${g1x2}" y2="${g1y2}" class="bar-top diag-bar-line"/>`;
  svg += diagonalTicks(g1x1, g1y1, g1x2, g1y2, drawCount, 9);

  // Group 2: top-left anchor -> bottom-right anchor (mirrored).
  const g2x1 = sxAll, g2y1 = sy + insetPx, g2x2 = sxAll + totalPx, g2y2 = sy + h - insetPx;
  svg += `<line x1="${g2x1}" y1="${g2y1}" x2="${g2x2}" y2="${g2y2}" class="bar-bottom diag-bar-line"/>`;
  svg += diagonalTicks(g2x1, g2y1, g2x2, g2y2, drawCount, 9);

  svg += barMarkTag((g1x1 + g1x2) / 2, (g1y1 + g1y2) / 2 - 16, `2\u00d7${diagonalBars.countPerGroup}\u00d8${Math.round(diagonalBars.dia)}`, { r: 13 });
  svg += `<text x="${beamX + 6}" y="${sy + h + 34}" class="angle-label">\u03b1 \u2248 ${angleDeg.toFixed(1)}\u00b0</text>`;
  svg += `<text x="${beamX + 6}" y="${sy + h + 48}" class="angle-note-label" dir="${l.dirAttr}">${esc(l.angleNote)}</text>`;

  svg += dimensionLine(beamX, sy - 20, beamX + spanPx, sy - 20, `ln = ${Math.round(spanClearMM)}mm`, { orientation: 'h', tick: 5 });
  // Depth dimension sits OUTSIDE the full assembly (past the right wall
  // pier), not just past the beam edge — otherwise it lands inside the
  // right pier's own hatch box whenever embedPx exceeds the old 30px
  // offset (caught by the cairosvg render pass, not by inspection).
  svg += dimensionLine(sxAll + totalPx + 30, sy, sxAll + totalPx + 30, sy + h, `h = ${Math.round(depthMM)}mm`, { orientation: 'v', tick: 5 });
  svg += `<text x="${sxAll + embedPx / 2}" y="${sy + h + 16}" text-anchor="middle" class="dim-label">${Math.round(embedMM)}mm</text>`;
  svg += `<text x="${rightPierX + embedPx / 2}" y="${sy + h + 16}" text-anchor="middle" class="dim-label">${Math.round(embedMM)}mm</text>`;
  svg += `<text x="${sxAll + embedPx / 2}" y="${sy + h + 30}" text-anchor="middle" class="zone-label" dir="${l.dirAttr}">${esc(l.wallPier)}</text>`;
  svg += `<text x="${rightPierX + embedPx / 2}" y="${sy + h + 30}" text-anchor="middle" class="zone-label" dir="${l.dirAttr}">${esc(l.wallPier)}</text>`;
  svg += `</g>`;
  return svg;
}

function renderBundleDetail(geometry, scale, box, l) {
  const { bundle, diagonalBars, confinementTies } = geometry;
  const w = bundle.outer.w * scale, h = bundle.outer.h * scale;
  const sx = box.x + (box.w - w) / 2;
  // Same fixed-region convention columnDiagram.mjs's renderTieDetail
  // documents: rect+dimension-line region is [box.y+26, box.y+box.h-46],
  // matching the fitScale boxH budget above; footer text below is
  // anchored from the BOX'S OWN bottom edge, not from `h`.
  const regionTop = box.y + 26, regionBottom = box.y + box.h - 46;
  const sy = regionTop + (regionBottom - regionTop - h) / 2;

  let svg = `<g class="bundle-detail">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 10}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.bundleDetail)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" rx="3" class="stirrup-outline"/>`;
  for (const p of bundle.positions) {
    svg += barDot(sx + p.xMM * scale, sy + p.yMM * scale, diagonalBars.dia, scale, 'diag1');
  }
  svg += dimensionLine(sx, sy + h + 18, sx + w, sy + h + 18, `${Math.round(bundle.outer.w)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 18, sy, sx - 18, sy + h, `${Math.round(bundle.outer.h)}mm`, { orientation: 'v', tick: 5 });
  svg += `<text x="${box.x + box.w / 2}" y="${box.y + box.h - 32}" text-anchor="middle" class="dim-label">\u00d8${Math.round(confinementTies.dia)}mm@${Math.round(confinementTies.spacing)}mm</text>`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y + box.h - 16}" text-anchor="middle" class="sheet-caption" dir="${l.dirAttr}">${esc(l.diagonal)} ${diagonalBars.layers}\u00d7${diagonalBars.barsPerLayer}</text>`;
  svg += `</g>`;
  return svg;
}

function renderMidspanSection(geometry, scale, box, l) {
  const { widthMM, depthMM } = geometry;
  const w = widthMM * scale, h = depthMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + (box.h - h) / 2;
  let svg = `<g class="midspan-section">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.midspanSection)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" class="concrete-outline"/>`;
  // Schematic X only — both groups cross near midspan; the true bar grid
  // is shown once, at full accuracy, in the bundle-detail zoom above; this
  // view is intentionally NOT a claim about exact bar position here.
  svg += `<line x1="${sx + w * 0.15}" y1="${sy + h * 0.85}" x2="${sx + w * 0.85}" y2="${sy + h * 0.15}" class="bar-top diag-bar-line"/>`;
  svg += `<line x1="${sx + w * 0.15}" y1="${sy + h * 0.15}" x2="${sx + w * 0.85}" y2="${sy + h * 0.85}" class="bar-bottom diag-bar-line"/>`;
  svg += dimensionLine(sx, sy + h + 20, sx + w, sy + h + 20, `${Math.round(widthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 20, sy, sx - 20, sy + h, `${Math.round(depthMM)}mm`, { orientation: 'v', tick: 5 });
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  const db = geometry.diagonalBars;
  rows.push({
    mark: 'D1',
    element: l.diagonal,
    dia: String(Math.round(db.dia)),
    count: `2\u00d7${db.countPerGroup}`,
    length: db.cuttingLengthMM != null ? String(Math.round(db.cuttingLengthMM)) : `${Math.round(geometry.drawnDiagLengthMM)}${l.extentSuffix}`,
  });
  const tieOuter = geometry.bundle.outer;
  const tiePerimeterMM = 2 * (tieOuter.w + tieOuter.h);
  rows.push({
    mark: 'T1',
    element: l.tie,
    dia: String(Math.round(geometry.confinementTies.dia)),
    count: `@${Math.round(geometry.confinementTies.spacing)} (2\u00d7${geometry.confinementTies.count})`,
    length: geometry.confinementTies.cuttingLengthMM != null ? String(Math.round(geometry.confinementTies.cuttingLengthMM)) : `${Math.round(tiePerimeterMM)}${l.perimeterSuffix}`,
  });
  return rows;
}

// ── Chat-facing entry point ────────────────────────────────────────────
// Mirrors columnDiagram.mjs's parseColumnRebarPayload() error-shape
// contract exactly ({ok:true,...} / {ok:false,code,message}). Never throws
// a DiagramError out; anything else (a genuine programmer error) is
// rethrown, same as every reference module.
export function parseCouplingBeamRebarPayload(raw) {
  try {
    const geometry = computeCouplingBeamDiagramGeometry(raw);
    return { ok: true, type: 'couplingBeam', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Mirrors columnDiagram.mjs's parseDiagramCommand exactly: same leading-
// token + "key=value key=value ..." syntax, same BAD_SYNTAX/
// UNSUPPORTED_TYPE reservation (BAD_SYNTAX = no leading-token+params shape
// at all; UNSUPPORTED_TYPE = shape present but leading token isn't
// "couplingbeam" — lets diagramCommandRouter.mjs try the next module
// without masking a real syntax error), same never-throws contract, error
// results also carry `.type`. Token is a single lowercase word
// ("couplingbeam") — chosen up front to sidestep the shearWall/shearwall
// lowercase-token mismatch برومبت_استكمال_العمل_v17.md's own item 2 flags
// as a past bug, even though wiring this token into the router's
// distribution table is explicitly Phase B, not done in this pass.
//
// Syntax:
//   /diagram couplingbeam id=CB1 span=1800 depth=900 width=300 cover=40
//     embed=900 diagdia=25 diagcount=8 layers=2 tiedia=10 tiespacing=100
//     [unit=mm]
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: couplingbeam key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'couplingbeam') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use couplingbeam.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const geometry = computeCouplingBeamDiagramGeometry({
      beamId: kv.id, spanClearMM: num('span'), depthMM: num('depth'),
      widthMM: num('width'), coverMM: num('cover'), embedMM: num('embed'),
      diagonalBars: { diameterMM: num('diagdia'), countPerGroup: num('diagcount'), layers: num('layers') },
      confinementTies: { diameterMM: num('tiedia'), spacingMM: num('tiespacing') },
      unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
