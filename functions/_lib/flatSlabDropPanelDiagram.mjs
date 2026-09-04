// functions/_lib/flatSlabDropPanelDiagram.mjs
//
// Deterministic, zero-AI SVG generator for flat-slab drop-panel / column-
// capital details (plan + section) — mjr candidate #4 from the third
// (ECP 203-coverage) pool in برومبت_استكمال_العمل_v17.md: fills the gap
// that module's own header documents at punchingShearDiagram.mjs
// ("NOT MODELED: drop panels or column capitals"). ACI 318-19 §8.2.4
// (drop panels, slab-thickness credit) and §22.6.4.1 (critical section at
// a capital/drop-panel edge) treat both as a geometric alternative to
// shear studs for punching-shear resistance around an interior column —
// this module draws that alternative GEOMETRY; it does not compute or
// verify punching-shear capacity itself (see NOT MODELED below). Same
// philosophy as columnDiagram.mjs: every dimension in the output is
// arithmetic on the KB data supplied, never a model's guess. This module
// owns compute+render only — it does not decide panel/capital size,
// drop depth, or bar counts; that is the KB/design layer's job (see
// INPUT CONTRACT below).
//
// SCOPE (v1): drop panel and column capital are two distinct GEOMETRY
// TYPES on a single RECTANGULAR interior column, discriminated by
// `capitalType: 'dropPanel'|'capital'` — never both on the same call
// (see NOT MODELED). A drop panel is a constant-thickness rectangular
// zone of extra slab depth centered on the column, stepped (not
// tapered) at its edge. A capital is a linear (straight-sided frustum)
// flare from the column's own section up to a wider rectangular
// footprint at the underside of the slab.
// NOT modeled, on purpose (each needs a parametrization this module
// hasn't been given yet, same "explicit scope boundary" convention
// columnDiagram.mjs's own header uses):
//   - circular columns / circular capitals or panels — this module
//     takes columnWidthMM/columnDepthMM (rectangular by construction),
//     matching columnDiagram.mjs's own rectangular-only scope; a
//     circular shape needs a diameterMM field this schema has no room
//     for. Circular columns are a SEPARATE documented candidate
//     ("Circular / Spiral Column") in the same prompt pool, not
//     something this module absorbs.
//   - a drop panel AND a capital stacked on the same column (a stepped
//     capital sitting atop a drop panel) — real but rarer geometry
//     needing a compound schema v1 doesn't have; `capitalType` is a
//     strict either/or.
//   - a sloped/chamfered drop-panel edge (some designs taper the step
//     over some run instead of a sharp vertical face) — drawn as a
//     sharp step only, `computeDropPanel`'s only supported edge.
//   - the ACI §8.2.4 drop-panel-extent-vs-span check (each direction
//     >= 1/6 of that span, center-to-center of supports, for the panel
//     to count toward slab-thickness credit) — this module has no span
//     input at all (only the panel's own plan size), so it cannot and
//     does not validate against that rule; panelWidthMM/panelLengthMM
//     are drawn exactly as supplied, no code-minimum check implied.
//   - punching-shear CAPACITY at the capital/drop-panel-edge critical
//     section (§22.6.4.1's own d/2-from-edge perimeter) — this module
//     draws that perimeter, at the caller-supplied
//     criticalPerimeterOffsetMM, as a plain labeled reference line ONLY
//     when the caller supplies it; it never computes the offset itself
//     (no dMM/Vc arithmetic anywhere in this file) and is not a second
//     source of truth for punchingShearDiagram.mjs's own output — the
//     two are meant to be read side by side for the same column, not
//     merged.
//   - the field slab mesh outside the panel/capital footprint — that is
//     slabDiagram.mjs's job. This module draws only the (optional)
//     extraTopBars count/diameter concentrated INSIDE the panel/capital
//     zone, as a single aggregate mark (see extraTopBars below), not a
//     laid-out bar grid — the schema carries no spacing/direction field
//     for those bars, so no layout is invented for them (mirrors
//     ties.type's "reject rather than guess" convention in
//     columnDiagram.mjs).
//   - no column elevation/height is drawn — this is a panel/capital
//     DETAIL, not a full column sheet; the column shaft below the
//     panel/capital is drawn as a short, explicitly un-dimensioned stub
//     ending in a drafting break line, never a real length this module
//     was not given.
//
// ── INPUT CONTRACT (what the KB layer should hand this module) ─────────
// {
//   unit?: 'mm'|'cm'|'m',               // default 'mm'
//   panelId: string,                    // mark, e.g. "DP-C3" / "CAP-C3"
//   capitalType: 'dropPanel'|'capital', // discriminator — see SCOPE
//   columnWidthMM: number,              // column section, below the panel/capital
//   columnDepthMM: number,
//   slabThicknessMM: number,            // field (away-from-column) slab thickness
//   // capitalType:'dropPanel' only —
//   panelWidthMM?: number,              // plan width of the panel, centered on column
//   panelLengthMM?: number,             // plan length of the panel, centered on column
//   dropDepthMM?: number,               // extra depth below slab soffit at the panel
//   // capitalType:'capital' only —
//   capitalTopWidthMM?: number,         // plan width where the capital meets slab soffit
//   capitalTopDepthMM?: number,
//   capitalHeightMM?: number,           // vertical extent of the flare below slab soffit
//   // shared, optional —
//   extraTopBars?: { diameterMM: number, count: number }, // ONE aggregate group, see SCOPE
//   criticalPerimeterOffsetMM?: number, // reference-only dashed offset line, see SCOPE
// }
//
// ── /diagram wiring — deferred (Phase B), NOT part of this delivery ────
// Per برومبت_استكمال_العمل_v17.md's Phase A/Phase B split: this file is
// build-only. diagramCommandRouter.mjs, chat.js, and both HTML shells are
// untouched by this pass. parseDiagramCommand below exists (same
// never-throws, `.type`-carrying contract as columnDiagram.mjs's own) so
// wiring it in later is a pure table-entry addition, not new parsing
// logic written under time pressure during the batched integration step.
//
// Resource lifecycle: this module is pure/synchronous — no timers, no
// fetch, no KV, no external handles of any kind. The caps below exist to
// bound Worker CPU time and output size on a request-scoped isolate, not
// to manage a leakable resource.
//
// Fully deterministic — no `env.AI`, no model call, no network fetch, no
// randomness anywhere in this file. Every SVG byte is arithmetic on
// computeFlatSlabDropPanelDiagramGeometry's own output.

import {
  DiagramError, toMm, assertFinitePositive, assertInt, assertOneOf,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barMarkTag, fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ──────────────────────────────────────────────────────
// Same role as columnDiagram.mjs's MIN/MAX_SIDE_MM etc.: this is a
// chat-driven schematic tool, not a CAD system — bound worst-case input
// ranges so one request can't describe a shape that cannot be drawn
// sanely. Column-section bounds are copied from columnDiagram.mjs's own
// MIN/MAX_SIDE_MM (this module's columnWidthMM/columnDepthMM is the same
// field, just re-declared locally per structuralDrawingKit.mjs's own
// documented rule: a MAX_* cap lives in the module that owns the field).
const MIN_COL_SIDE_MM = 150;
const MAX_COL_SIDE_MM = 3000;
const MIN_SLAB_THK_MM = 120;
const MAX_SLAB_THK_MM = 600;
const MIN_PANEL_SIDE_MM = 300;
const MAX_PANEL_SIDE_MM = 8000;
const MIN_DROP_DEPTH_MM = 50;
const MAX_DROP_DEPTH_MM = 500;
const MIN_CAP_TOP_SIDE_MM = 300;
const MAX_CAP_TOP_SIDE_MM = 6000;
const MIN_CAP_HEIGHT_MM = 100;
const MAX_CAP_HEIGHT_MM = 2000;
const MIN_BAR_DIA_MM = 6;
const MAX_BAR_DIA_MM = 40;
const MIN_BAR_COUNT = 2;
const MAX_BAR_COUNT = 40;
const MIN_CRIT_OFFSET_MM = 10;
const MAX_CRIT_OFFSET_MM = 3000;

// ── Compute ──────────────────────────────────────────────────────────
export function computeFlatSlabDropPanelDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Drop panel / capital diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const capitalType = raw.capitalType;
  assertOneOf('capitalType', capitalType, ['dropPanel', 'capital']);
  const id = raw.panelId != null
    ? String(raw.panelId).slice(0, 40)
    : (capitalType === 'capital' ? 'CAPITAL' : 'DROP PANEL');

  const columnWidthMM = toMm(raw.columnWidthMM, unit);
  const columnDepthMM = toMm(raw.columnDepthMM, unit);
  assertFinitePositive('columnWidthMM', columnWidthMM);
  assertFinitePositive('columnDepthMM', columnDepthMM);
  if (columnWidthMM < MIN_COL_SIDE_MM || columnWidthMM > MAX_COL_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"columnWidthMM" must be between ${MIN_COL_SIDE_MM}mm and ${MAX_COL_SIDE_MM}mm for this schematic, got ${columnWidthMM}mm.`);
  }
  if (columnDepthMM < MIN_COL_SIDE_MM || columnDepthMM > MAX_COL_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"columnDepthMM" must be between ${MIN_COL_SIDE_MM}mm and ${MAX_COL_SIDE_MM}mm for this schematic, got ${columnDepthMM}mm.`);
  }

  const slabThicknessMM = toMm(raw.slabThicknessMM, unit);
  assertFinitePositive('slabThicknessMM', slabThicknessMM);
  if (slabThicknessMM < MIN_SLAB_THK_MM || slabThicknessMM > MAX_SLAB_THK_MM) {
    throw new DiagramError('BAD_PARAM', `"slabThicknessMM" must be between ${MIN_SLAB_THK_MM}mm and ${MAX_SLAB_THK_MM}mm for this schematic, got ${slabThicknessMM}mm.`);
  }

  let dropPanel = null;
  let capital = null;

  if (capitalType === 'dropPanel') {
    const panelWidthMM = toMm(raw.panelWidthMM, unit);
    const panelLengthMM = toMm(raw.panelLengthMM, unit);
    const dropDepthMM = toMm(raw.dropDepthMM, unit);
    assertFinitePositive('panelWidthMM', panelWidthMM);
    assertFinitePositive('panelLengthMM', panelLengthMM);
    assertFinitePositive('dropDepthMM', dropDepthMM);
    if (panelWidthMM < MIN_PANEL_SIDE_MM || panelWidthMM > MAX_PANEL_SIDE_MM) {
      throw new DiagramError('BAD_PARAM', `"panelWidthMM" must be between ${MIN_PANEL_SIDE_MM}mm and ${MAX_PANEL_SIDE_MM}mm, got ${panelWidthMM}mm.`);
    }
    if (panelLengthMM < MIN_PANEL_SIDE_MM || panelLengthMM > MAX_PANEL_SIDE_MM) {
      throw new DiagramError('BAD_PARAM', `"panelLengthMM" must be between ${MIN_PANEL_SIDE_MM}mm and ${MAX_PANEL_SIDE_MM}mm, got ${panelLengthMM}mm.`);
    }
    if (dropDepthMM < MIN_DROP_DEPTH_MM || dropDepthMM > MAX_DROP_DEPTH_MM) {
      throw new DiagramError('BAD_PARAM', `"dropDepthMM" must be between ${MIN_DROP_DEPTH_MM}mm and ${MAX_DROP_DEPTH_MM}mm, got ${dropDepthMM}mm.`);
    }
    if (panelWidthMM <= columnWidthMM) {
      throw new DiagramError('PANEL_NOT_LARGER_THAN_COLUMN', `"panelWidthMM" (${panelWidthMM}mm) must be greater than "columnWidthMM" (${columnWidthMM}mm) — a drop panel that does not project past the column face is not a drop panel.`);
    }
    if (panelLengthMM <= columnDepthMM) {
      throw new DiagramError('PANEL_NOT_LARGER_THAN_COLUMN', `"panelLengthMM" (${panelLengthMM}mm) must be greater than "columnDepthMM" (${columnDepthMM}mm) — a drop panel that does not project past the column face is not a drop panel.`);
    }
    dropPanel = { panelWidthMM, panelLengthMM, dropDepthMM, totalDepthMM: slabThicknessMM + dropDepthMM };
  } else {
    const capitalTopWidthMM = toMm(raw.capitalTopWidthMM, unit);
    const capitalTopDepthMM = toMm(raw.capitalTopDepthMM, unit);
    const capitalHeightMM = toMm(raw.capitalHeightMM, unit);
    assertFinitePositive('capitalTopWidthMM', capitalTopWidthMM);
    assertFinitePositive('capitalTopDepthMM', capitalTopDepthMM);
    assertFinitePositive('capitalHeightMM', capitalHeightMM);
    if (capitalTopWidthMM < MIN_CAP_TOP_SIDE_MM || capitalTopWidthMM > MAX_CAP_TOP_SIDE_MM) {
      throw new DiagramError('BAD_PARAM', `"capitalTopWidthMM" must be between ${MIN_CAP_TOP_SIDE_MM}mm and ${MAX_CAP_TOP_SIDE_MM}mm, got ${capitalTopWidthMM}mm.`);
    }
    if (capitalTopDepthMM < MIN_CAP_TOP_SIDE_MM || capitalTopDepthMM > MAX_CAP_TOP_SIDE_MM) {
      throw new DiagramError('BAD_PARAM', `"capitalTopDepthMM" must be between ${MIN_CAP_TOP_SIDE_MM}mm and ${MAX_CAP_TOP_SIDE_MM}mm, got ${capitalTopDepthMM}mm.`);
    }
    if (capitalHeightMM < MIN_CAP_HEIGHT_MM || capitalHeightMM > MAX_CAP_HEIGHT_MM) {
      throw new DiagramError('BAD_PARAM', `"capitalHeightMM" must be between ${MIN_CAP_HEIGHT_MM}mm and ${MAX_CAP_HEIGHT_MM}mm, got ${capitalHeightMM}mm.`);
    }
    if (capitalTopWidthMM <= columnWidthMM) {
      throw new DiagramError('CAPITAL_TOP_NOT_LARGER_THAN_COLUMN', `"capitalTopWidthMM" (${capitalTopWidthMM}mm) must be greater than "columnWidthMM" (${columnWidthMM}mm) — a capital that does not flare past the column face is not a capital.`);
    }
    if (capitalTopDepthMM <= columnDepthMM) {
      throw new DiagramError('CAPITAL_TOP_NOT_LARGER_THAN_COLUMN', `"capitalTopDepthMM" (${capitalTopDepthMM}mm) must be greater than "columnDepthMM" (${columnDepthMM}mm) — a capital that does not flare past the column face is not a capital.`);
    }
    capital = { capitalTopWidthMM, capitalTopDepthMM, capitalHeightMM };
  }

  let extraTopBars = null;
  if (raw.extraTopBars != null) {
    if (typeof raw.extraTopBars !== 'object') throw new DiagramError('BAD_PARAM', '"extraTopBars" must be an object: { diameterMM, count }.');
    const dia = toMm(raw.extraTopBars.diameterMM, unit);
    assertFinitePositive('extraTopBars.diameterMM', dia);
    if (dia < MIN_BAR_DIA_MM || dia > MAX_BAR_DIA_MM) {
      throw new DiagramError('BAD_PARAM', `"extraTopBars.diameterMM" must be between ${MIN_BAR_DIA_MM}mm and ${MAX_BAR_DIA_MM}mm, got ${dia}mm.`);
    }
    assertInt('extraTopBars.count', raw.extraTopBars.count, { min: MIN_BAR_COUNT, max: MAX_BAR_COUNT });
    extraTopBars = { dia, count: raw.extraTopBars.count };
  }

  let criticalPerimeterOffsetMM = null;
  if (raw.criticalPerimeterOffsetMM != null) {
    criticalPerimeterOffsetMM = toMm(raw.criticalPerimeterOffsetMM, unit);
    assertFinitePositive('criticalPerimeterOffsetMM', criticalPerimeterOffsetMM);
    if (criticalPerimeterOffsetMM < MIN_CRIT_OFFSET_MM || criticalPerimeterOffsetMM > MAX_CRIT_OFFSET_MM) {
      throw new DiagramError('BAD_PARAM', `"criticalPerimeterOffsetMM" must be between ${MIN_CRIT_OFFSET_MM}mm and ${MAX_CRIT_OFFSET_MM}mm, got ${criticalPerimeterOffsetMM}mm.`);
    }
  }

  return {
    type: 'dropCapital', capitalType, unit, id,
    columnWidthMM, columnDepthMM, slabThicknessMM,
    dropPanel, capital, extraTopBars, criticalPerimeterOffsetMM,
  };
}

// ── Labels ───────────────────────────────────────────────────────────
// Local L = {en:{...}, ar:{...}} dictionary in THIS file, same decision
// columnDiagram.mjs's own header records and the same reasoning: a third
// consumer of structuralLabels.mjs now (that file's own header scopes it
// to footingDiagram.mjs only) would leave the split in a worse,
// inconsistent state rather than resolving it — the real unification
// (migrating footing/beam/column/this module onto one shared label
// source) is separate future work, not this pass's job.
//
// PARENTHESES/EM-DASH WARNING (same as columnDiagram.mjs's own note):
// Noto Naskh Arabic (scriptFontStack for lang==='ar') has no verified
// glyph for "(", ")", or an em/en-dash. Every Arabic string below is
// written parenthesis- and dash-free, following footingDiagram.mjs/
// columnDiagram.mjs's verified-safe convention.
const L = {
  en: {
    title: (id) => `FLAT SLAB DROP PANEL / COLUMN CAPITAL ${id} \u2014 DETAIL`,
    planView: 'PLAN', sectionView: 'SECTION',
    column: 'Column', dropPanelLabel: 'Drop Panel', capitalLabel: 'Column Capital',
    extraTop: 'Extra Top Bars', criticalPerimeter: 'Critical section reference, offset from panel/capital edge',
    fieldSlab: 'Field slab', columnBelow: 'Column continues below',
    vScaleNote: '(vertical scale exaggerated for clarity)',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Plan Size', colLength: 'Depth / Height (mm)',
    caption: 'Schematic drop panel / column capital detail generated from the supplied data \u2014 geometry only, verify every dimension against your own design (ACI 318-19 \u00a78.2.4 drop panel provisions, \u00a722.6.4.1 capital critical-section provisions) before issuing for construction. This drawing does not compute or verify punching-shear capacity, minimum drop-panel extent versus span, or critical-section adequacy \u2014 cross-check against the separate punching-shear diagram for the same column. Extra top bar lengths, where shown, are not computed here.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفصيلة لبادة أو رأس عمود ببلاطة مسطحة ${id}`,
    planView: 'مسقط أفقي', sectionView: 'قطاع رأسي',
    column: 'عمود', dropPanelLabel: 'لبادة', capitalLabel: 'رأس عمود',
    extraTop: 'حديد علوي إضافي', criticalPerimeter: 'خط مرجعي لمحيط القص الحرج، مزاح عن حافة اللبادة أو الرأس',
    fieldSlab: 'البلاطة الأساسية', columnBelow: 'العمود يستمر للأسفل',
    vScaleNote: 'مقياس رأسي مكبر للتوضيح',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو المسقط', colLength: 'العمق أو الارتفاع مم',
    caption: 'رسم تفصيلي توضيحي للبادة أو رأس عمود ببلاطة مسطحة أُنشئ من البيانات المُدخلة، للهندسة فقط. راجع كل بُعد وفق تصميمك الخاص مقابل ACI 318-19 المادة 8.2.4 لأحكام اللبادة والمادة 22.6.4.1 لأحكام محيط القص الحرج عند رأس العمود قبل الاعتماد للتنفيذ. هذا الرسم لا يحسب ولا يتحقق من سعة مقاومة القص الثاقب، ولا امتداد اللبادة الأدنى مقابل البحر، ولا كفاية محيط القص الحرج، راجعها مقابل رسم القص الثاقب المنفصل لنفس العمود. أطوال الحديد العلوي الإضافي، إن وُجدت، غير محسوبة هنا.',
    dirAttr: 'rtl',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 950;
const PLAN_BOX = { x: 60, y: 110, w: 380, h: 380 };
const SECTION_BOX = { x: 500, y: 110, w: 380, h: 380 };
// Un-dimensioned column stub below the panel/capital, ending in a
// drafting break line — see the "no column elevation" NOT MODELED note
// at the top of this file. Pixel length only, never a real column
// height this module was not given.
const STUB_PX = 90;

export function renderFlatSlabDropPanelDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const footprintW = geometry.capitalType === 'dropPanel' ? geometry.dropPanel.panelWidthMM : geometry.capital.capitalTopWidthMM;
  const footprintL = geometry.capitalType === 'dropPanel' ? geometry.dropPanel.panelLengthMM : geometry.capital.capitalTopDepthMM;
  const critOff = geometry.criticalPerimeterOffsetMM || 0;

  const planScale = fitScale([{ contentW: footprintW + 2 * critOff, contentH: footprintL + 2 * critOff, boxW: PLAN_BOX.w - 90, boxH: PLAN_BOX.h - 90 }]);
  // SECTION view uses INDEPENDENT horizontal/vertical scales, not one
  // shared scale — deliberate, not an oversight. A real drop panel/
  // capital is extremely flat in true proportion (e.g. a 150mm step
  // across a 2400mm-wide panel): forcing one scale to fit both axes
  // compresses the vertical dimension to a few px, which measured
  // testing (this session's own cairosvg pass, extreme-aspect capital
  // case) showed collapses every vertical dimension-line label into the
  // shape it's labeling. Real structural drawings of thin members use
  // the same convention (vertically exaggerated section), always
  // labeled as such — see l.vScaleNote below, rendered on every SECTION
  // view, not a silent distortion.
  const sectionSpanMM = footprintW * 1.6;
  const sectionContentH = geometry.slabThicknessMM
    + (geometry.capitalType === 'dropPanel' ? geometry.dropPanel.dropDepthMM : geometry.capital.capitalHeightMM);
  const hScale = fitScale([{ contentW: sectionSpanMM, boxW: SECTION_BOX.w - 90 }]);
  const vScale = fitScale([{ contentH: sectionContentH, boxH: SECTION_BOX.h - 150 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4 },
  ];
  const tableY = PLAN_BOX.y + PLAN_BOX.h + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 108);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .panel-title  { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .zone-label   { font-size:10.5px; fill:#8a6d00; font-family: ${scriptFontStack}; }
    .break-line   { stroke:#1a1a1a; stroke-width:1.4; fill:none; }
    .crit-line    { stroke:#b8860b; stroke-width:1.2; stroke-dasharray:5,3; fill:none; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="panel-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderPlanView(geometry, planScale, PLAN_BOX, l)}
  ${renderSectionView(geometry, { hScale, vScale }, SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 108, lineHeight: 15 })}
</svg>`;
}

function renderPlanView(geometry, scale, box, l) {
  const footprintW = geometry.capitalType === 'dropPanel' ? geometry.dropPanel.panelWidthMM : geometry.capital.capitalTopWidthMM;
  const footprintL = geometry.capitalType === 'dropPanel' ? geometry.dropPanel.panelLengthMM : geometry.capital.capitalTopDepthMM;
  const critOff = geometry.criticalPerimeterOffsetMM;

  const w = footprintW * scale, h = footprintL * scale;
  const cx = box.x + box.w / 2, cy = box.y + box.h / 2;
  const sx = cx - w / 2, sy = cy - h / 2;
  const cw = geometry.columnWidthMM * scale, cd = geometry.columnDepthMM * scale;
  const colX = cx - cw / 2, colY = cy - cd / 2;

  let svg = `<g class="plan-view">`;
  svg += `<text x="${cx}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.planView)}</text>`;

  const co = critOff != null ? critOff * scale : 0;
  if (critOff != null) {
    svg += `<rect x="${sx - co}" y="${sy - co}" width="${w + 2 * co}" height="${h + 2 * co}" class="crit-line"/>`;
    svg += `<text x="${sx - co}" y="${sy - co - 6}" class="zone-label" dir="${l.dirAttr}">${esc(l.criticalPerimeter)}</text>`;
  }

  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" class="concrete-outline"/>`;
  svg += `<rect x="${colX}" y="${colY}" width="${cw}" height="${cd}" class="support-outline"/>`;

  svg += dimensionLine(sx, sy + h + 20, sx + w, sy + h + 20, `${Math.round(footprintW)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 20, sy, sx - 20, sy + h, `${Math.round(footprintL)}mm`, { orientation: 'v', tick: 5 });
  // Column mark placed BELOW the width dimension line AND below the
  // critical-perimeter dashed rect when one is drawn (co) — a fixed
  // +40 offset collided with that dashed rect's own bottom edge once
  // criticalPerimeterOffsetMM pushed it further out, caught by this
  // session's own cairosvg pass (300mm offset case).
  svg += `<text x="${cx}" y="${sy + h + Math.max(40, co + 34)}" text-anchor="middle" class="sheet-caption" dir="${l.dirAttr}">${esc(l.column)} ${Math.round(geometry.columnWidthMM)}\u00d7${Math.round(geometry.columnDepthMM)}</text>`;

  if (geometry.extraTopBars) {
    // r:16, not columnDiagram.mjs's r:13 — this mark's own string can run
    // up to "40\u00d840" (5 chars: two-digit count AND two-digit diameter
    // both allowed by this module's own MAX_BAR_COUNT/MAX_BAR_DIA_MM),
    // wider than any string columnDiagram.mjs's r:13 precedent was sized
    // against; measured by this session's own cairosvg pass (12\u00d820).
    svg += barMarkTag(sx + w + 28, sy + 19, `${geometry.extraTopBars.count}\u00d8${Math.round(geometry.extraTopBars.dia)}`, { r: 19 });
    svg += `<text x="${sx + w + 28}" y="${sy + 50}" text-anchor="middle" class="sheet-caption" dir="${l.dirAttr}">${esc(l.extraTop)}</text>`;
  }
  svg += `</g>`;
  return svg;
}

function renderSectionView(geometry, { hScale, vScale }, box, l) {
  const footprintW = geometry.capitalType === 'dropPanel' ? geometry.dropPanel.panelWidthMM : geometry.capital.capitalTopWidthMM;
  const sectionSpanMM = footprintW * 1.6;
  const w = sectionSpanMM * hScale;
  const sx0 = box.x + (box.w - w) / 2;
  const cx = box.x + box.w / 2;
  // topY leaves room for an ABOVE-slab horizontal dimension line (the
  // capital-top-width case below) between the title and the slab itself
  // — sized generously rather than tuned to one case, so both branches
  // share one topY with margin to spare in the drop-panel case.
  const topY = box.y + 54;

  let svg = `<g class="section-view">`;
  svg += `<text x="${cx}" y="${box.y - 10}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.sectionView)}</text>`;
  svg += `<text x="${cx}" y="${box.y + 8}" text-anchor="middle" class="zone-label" dir="${l.dirAttr}">${esc(l.vScaleNote)}</text>`;

  const slabTop = topY;
  const slabFieldBottom = topY + geometry.slabThicknessMM * vScale;
  // Every dimension line/label OUTSIDE the section's own filled outline
  // is anchored from this single right-hand X, well past the widest
  // filled shape (sx0+w) at any scale — the previous version anchored
  // from panelRight/capHalfTopW instead, which sat INSIDE the filled
  // outline once hScale shrank the panel narrower than the drawn
  // section span, causing the dimension line to cross the fill (caught
  // by this session's own cairosvg pass, not by inspection).
  const RIGHT_DIM_X = sx0 + w + 24;

  if (geometry.capitalType === 'dropPanel') {
    const { panelWidthMM } = geometry.dropPanel;
    const panelHalfW = (panelWidthMM * hScale) / 2;
    const panelLeft = cx - panelHalfW, panelRight = cx + panelHalfW;
    const slabPanelBottom = topY + geometry.dropPanel.totalDepthMM * vScale;

    const path = `M ${sx0} ${slabTop} L ${sx0 + w} ${slabTop} L ${sx0 + w} ${slabFieldBottom} `
      + `L ${panelRight} ${slabFieldBottom} L ${panelRight} ${slabPanelBottom} L ${panelLeft} ${slabPanelBottom} `
      + `L ${panelLeft} ${slabFieldBottom} L ${sx0} ${slabFieldBottom} Z`;
    svg += `<path d="${path}" class="concrete-outline"/>`;

    svg += renderColumnStub(cx, geometry.columnWidthMM * hScale, slabPanelBottom, l);

    svg += dimensionLine(sx0 - 20, slabTop, sx0 - 20, slabFieldBottom, `${Math.round(geometry.slabThicknessMM)}mm`, { orientation: 'v', tick: 5 });
    svg += dimensionLine(RIGHT_DIM_X, slabTop, RIGHT_DIM_X, slabPanelBottom, `${Math.round(geometry.dropPanel.totalDepthMM)}mm`, { orientation: 'v', tick: 5 });
    svg += dimensionLine(panelLeft, slabPanelBottom + 20, panelRight, slabPanelBottom + 20, `${Math.round(panelWidthMM)}mm`, { orientation: 'h', tick: 5 });
  } else {
    const { capitalTopWidthMM, capitalHeightMM } = geometry.capital;
    const capHalfTopW = (capitalTopWidthMM * hScale) / 2;
    const colHalfW = (geometry.columnWidthMM * hScale) / 2;
    const slabSoffitY = slabFieldBottom;
    const columnTopY = slabSoffitY + capitalHeightMM * vScale;

    svg += `<rect x="${sx0}" y="${slabTop}" width="${w}" height="${geometry.slabThicknessMM * vScale}" class="concrete-outline"/>`;
    const path = `M ${cx - colHalfW} ${columnTopY} L ${cx + colHalfW} ${columnTopY} `
      + `L ${cx + capHalfTopW} ${slabSoffitY} L ${cx - capHalfTopW} ${slabSoffitY} Z`;
    svg += `<path d="${path}" class="support-outline"/>`;

    svg += renderColumnStub(cx, geometry.columnWidthMM * hScale, columnTopY, l);

    svg += dimensionLine(sx0 - 20, slabTop, sx0 - 20, slabSoffitY, `${Math.round(geometry.slabThicknessMM)}mm`, { orientation: 'v', tick: 5 });
    svg += dimensionLine(RIGHT_DIM_X, slabSoffitY, RIGHT_DIM_X, columnTopY, `${Math.round(capitalHeightMM)}mm`, { orientation: 'v', tick: 5 });
    // Above the slab, not "-16 into it": at small vScale the slab's own
    // drawn thickness can be only a few px, so an inward offset landed
    // ON TOP of (or above) the slab's own rect in the same cairosvg pass
    // that caught the RIGHT_DIM_X bug above — anchoring from slabTop
    // (fixed, independent of slab thickness) instead of slabSoffitY
    // (variable) removes that dependency entirely.
    svg += dimensionLine(cx - capHalfTopW, slabTop - 20, cx + capHalfTopW, slabTop - 20, `${Math.round(capitalTopWidthMM)}mm`, { orientation: 'h', tick: 5 });
  }

  svg += `</g>`;
  return svg;
}

// Short, explicitly un-dimensioned column shaft ending in a zig-zag
// drafting break line — see the "no column elevation" NOT MODELED note.
// No dimensionLine() call anywhere near this shape, on purpose.
function renderColumnStub(cx, wPx, topYPx, l) {
  const half = wPx / 2;
  const bottomY = topYPx + STUB_PX;
  const breakY = bottomY - 14;
  // Anchor follows dirAttr explicitly (renderCaptionAt's own convention)
  // rather than relying on the SVG default ('start', which for dir=rtl
  // anchors at the text's OWN right edge and can grow the label back
  // toward the stub from an unexpected side) — caught by this session's
  // own cairosvg pass on the Arabic capital case, where the untranslated
  // default pushed the label noticeably further from the stub than the
  // English version's.
  const anchor = l.dirAttr === 'rtl' ? 'end' : 'start';
  let svg = `<g class="column-stub">`;
  svg += `<rect x="${cx - half}" y="${topYPx}" width="${wPx}" height="${STUB_PX - 14}" class="support-outline"/>`;
  svg += `<path d="M ${cx - half} ${breakY} l ${wPx * 0.2} 8 l ${wPx * 0.2} -16 l ${wPx * 0.2} 8 l ${wPx * 0.2} -16 l ${wPx * 0.2} 8" class="break-line"/>`;
  svg += `<text x="${cx + half + 14}" y="${(topYPx + bottomY) / 2}" text-anchor="${anchor}" class="zone-label" dir="${l.dirAttr}">${esc(l.columnBelow)}</text>`;
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  if (geometry.capitalType === 'dropPanel') {
    const { panelWidthMM, panelLengthMM, dropDepthMM } = geometry.dropPanel;
    rows.push({
      mark: 'DP', element: l.dropPanelLabel, dia: '\u2014',
      count: `${Math.round(panelWidthMM)}\u00d7${Math.round(panelLengthMM)}`,
      length: String(Math.round(dropDepthMM)),
    });
  } else {
    const { capitalTopWidthMM, capitalTopDepthMM, capitalHeightMM } = geometry.capital;
    rows.push({
      mark: 'CAP', element: l.capitalLabel, dia: '\u2014',
      count: `${Math.round(capitalTopWidthMM)}\u00d7${Math.round(capitalTopDepthMM)}`,
      length: String(Math.round(capitalHeightMM)),
    });
  }
  if (geometry.extraTopBars) {
    rows.push({
      mark: 'T1', element: l.extraTop,
      dia: String(Math.round(geometry.extraTopBars.dia)),
      count: String(geometry.extraTopBars.count),
      length: '\u2014',
    });
  }
  if (geometry.criticalPerimeterOffsetMM != null) {
    rows.push({
      mark: '\u2014', element: l.criticalPerimeter, dia: '\u2014', count: '\u2014',
      length: String(Math.round(geometry.criticalPerimeterOffsetMM)),
    });
  }
  return rows;
}

// ── Chat-facing entry point ────────────────────────────────────────────
// Mirrors columnDiagram.mjs's parseColumnRebarPayload() error-shape
// contract exactly ({ok:true,...} / {ok:false,code,message}). Never
// throws a DiagramError out; anything else (a genuine programmer error)
// is rethrown, same as every reference module.
export function parseFlatSlabDropPanelRebarPayload(raw) {
  try {
    const geometry = computeFlatSlabDropPanelDiagramGeometry(raw);
    return { ok: true, type: 'dropCapital', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Mirrors columnDiagram.mjs's parseDiagramCommand exactly: same leading-
// token + "key=value key=value ..." syntax, same BAD_SYNTAX/
// UNSUPPORTED_TYPE reservation, same never-throws contract, error
// results also carry `.type`. NOT wired into diagramCommandRouter.mjs in
// this delivery — see the deferred-wiring note at the top of this file.
//
// Syntax:
//   /diagram dropcapital id=DP1 type=dropPanel colwidth=400 coldepth=400
//     slab=200 panelwidth=2000 panellength=2000 dropdepth=150
//     [topdia=16] [topcount=8] [critoffset=300] [unit=mm]
//   /diagram dropcapital id=CAP1 type=capital colwidth=400 coldepth=400
//     slab=200 capwidth=1200 capdepth=1200 capheight=500
//     [topdia=16] [topcount=8] [critoffset=300] [unit=mm]
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: dropcapital key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'dropcapital') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use dropcapital.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const geometry = computeFlatSlabDropPanelDiagramGeometry({
      panelId: kv.id, capitalType: kv.type,
      columnWidthMM: num('colwidth'), columnDepthMM: num('coldepth'),
      slabThicknessMM: num('slab'),
      panelWidthMM: num('panelwidth'), panelLengthMM: num('panellength'), dropDepthMM: num('dropdepth'),
      capitalTopWidthMM: num('capwidth'), capitalTopDepthMM: num('capdepth'), capitalHeightMM: num('capheight'),
      extraTopBars: (kv.topdia != null || kv.topcount != null)
        ? { diameterMM: num('topdia'), count: num('topcount') } : undefined,
      criticalPerimeterOffsetMM: num('critoffset'),
      unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
