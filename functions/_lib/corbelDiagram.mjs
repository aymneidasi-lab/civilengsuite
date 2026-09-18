// functions/_lib/corbelDiagram.mjs
//
// Deterministic, zero-AI SVG generator for a single corbel/bracket
// projecting from one face of a column, per ACI 318-19 §16.5.
//
// REVISION 4 (this pass — layout parity with the reviewed hand-drawn SVG).
// No compute-side change: computeCorbelDiagramGeometry()'s input contract
// and return shape are byte-identical to the previous revision, so
// corbelDiagram_dxf.mjs's "consumed exactly as returned" contract still
// holds. Only renderCorbelDiagramSVG()'s layout constants and two text
// placements change:
//   L1. ELEVATION_BOX enlarged (h: 360 -> 560) and its contentH formula
//       tightened (h*2.2 -> h*1.7), so fitScale() lands near 0.55 instead
//       of the previous 0.245 — the corbel previously rendered at roughly
//       a third the size the sheet had room for.
//   L2. SECTION_BOX / PLAN_BOX pushed down (y: 480 -> 680) to clear the
//       taller elevation box; canvas height grows accordingly.
//   L3. Ah ≥ 0.5(As−An) callout moved from the strut's own midpoint
//       (where the sloped bottom edge and the strut-parallel bar ran
//       through its glyphs) into the clean horizontal band between the
//       last Ah bar and the first extra bar, with a white mask so the
//       middle vertical tie leg doesn't strike through it.
//   L4. Plan-view mark tags: mark 1 moved out to the clear upper-right
//       gutter (was landing on the "Bearing Plate" label); mark 3 moved
//       to the plan box's own upper-left gutter (was landing on the view
//       heading). Mark 2 unchanged.
//   L5. Plan-view "Bearing Plate" label raised 10px so it clears the
//       mark-1 tag's leader line.
//   L6. A standalone "Column ties…" note added below the schedule
//       table — the caption already says this, but the drawing now
//       states it once at the point of use too.
//
// The three RC-render corrections from REVISION 2 (flat top / sloped
// bottom / vertical tip; loaded-end tie closure; corner deflections on
// outer main bars only) are unchanged and untouched by this pass.
//
// Resource lifecycle: pure/synchronous, zero state, no timers/fetch/KV.
// Fully deterministic.

import {
  DiagramError, toMm, fmt, assertFinitePositive, assertInt,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, barMarkTag,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ──────────────────────────────────────────────────────
const MIN_COL_B_MM = 200;
const MAX_COL_B_MM = 1500;
const MIN_H_MM = 200;
const MAX_H_MM = 1200;
const MIN_PROJECTION_MM = 100;
const MAX_PROJECTION_MM = 900;
const MIN_TIE_BAR_COUNT = 2;
const MAX_TIE_BAR_COUNT = 8;
const MIN_STIRRUP_COUNT = 1;
const MAX_STIRRUP_COUNT = 8;
const MIN_H1_FACTOR = 0.5;
const COL_STUB_DEPTH_FACTOR = 0.55; // x h — plan view's schematic column depth

// ── Standard hook / bend geometry (ACI 318-19 Table 25.3.1) ───────────
function standardHookBendDiaMM(barDiaMM) {
  if (barDiaMM <= 25) return 6 * barDiaMM;
  if (barDiaMM <= 32) return 8 * barDiaMM;
  return 10 * barDiaMM;
}
function standardHookBendRadiusMM(barDiaMM) {
  return standardHookBendDiaMM(barDiaMM) / 2 + barDiaMM / 2;
}
function standardHook90ExtensionMM(barDiaMM) {
  return 12 * barDiaMM;
}

// ── Exact-count position distribution (closed ties, Ah) ───────────────
function distributeExact(startPx, endPx, count) {
  const n = Math.max(1, Math.round(count));
  if (n === 1) return [(startPx + endPx) / 2];
  const step = (endPx - startPx) / (n - 1);
  return Array.from({ length: n }, (_, i) => startPx + i * step);
}

// ── Rebar bend paths (SVG path `d`, centerline geometry) ──────────────
function hookDown90PathD(x, y, radiusPx, tailPx) {
  const exX = x + radiusPx;
  const exY = y + radiusPx;
  return `M ${x},${y} A ${radiusPx},${radiusPx} 0 0 1 ${exX},${exY} L ${exX},${exY + tailPx}`;
}
// REVISION 2 naming: the U-turn is at the LOADED end of the closed tie,
// not around the column — see the DXF path's addLoadedEndClosure180()
// for the same rename applied there.
function loadedEndClosure180PathD(x, y, radiusPx, dir) {
  const sweep = dir > 0 ? 1 : 0;
  return `M ${x},${y} A ${radiusPx},${radiusPx} 0 0 ${sweep} ${x},${y + dir * 2 * radiusPx}`;
}

// ── Compute ──────────────────────────────────────────────────────────
export function computeCorbelDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Corbel diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.corbelId != null ? String(raw.corbelId).slice(0, 40) : 'CORBEL';

  const colB = toMm(raw.colB, unit);
  const projection = toMm(raw.projection, unit);
  const av = toMm(raw.av, unit);
  const h = toMm(raw.h, unit);
  const h1 = toMm(raw.h1, unit);
  const cover = toMm(raw.cover, unit);
  const tieBarDia = toMm(raw.tieBarDia, unit);
  const stirrupDia = toMm(raw.stirrupDia, unit);
  const bearingPlateWidth = toMm(raw.bearingPlateWidth, unit);

  for (const [name, v] of Object.entries({
    colB, projection, av, h, h1, cover, tieBarDia, stirrupDia, bearingPlateWidth,
  })) {
    assertFinitePositive(name, v);
  }

  if (colB < MIN_COL_B_MM || colB > MAX_COL_B_MM) {
    throw new DiagramError('BAD_PARAM', `"colB" must be between ${MIN_COL_B_MM}mm and ${MAX_COL_B_MM}mm for this schematic, got ${colB}mm.`);
  }
  if (h < MIN_H_MM || h > MAX_H_MM) {
    throw new DiagramError('BAD_PARAM', `"h" must be between ${MIN_H_MM}mm and ${MAX_H_MM}mm for this schematic, got ${h}mm.`);
  }
  if (projection < MIN_PROJECTION_MM || projection > MAX_PROJECTION_MM) {
    throw new DiagramError('BAD_PARAM', `"projection" must be between ${MIN_PROJECTION_MM}mm and ${MAX_PROJECTION_MM}mm for this schematic, got ${projection}mm.`);
  }
  if (h1 >= h) {
    throw new DiagramError('BAD_PARAM', `"h1" (${h1}mm) must be less than "h" (${h}mm) \u2014 a corbel tapers down from the column face to its outer tip.`);
  }
  if (h1 < MIN_H1_FACTOR * h) {
    throw new DiagramError('TAPER_TOO_STEEP', `"h1" (${h1}mm) is less than ${MIN_H1_FACTOR} x "h" (${h}mm) \u2014 this schematic enforces the common corbel-detailing minimum of half-depth at the outer tip.`);
  }
  if (av > projection) {
    throw new DiagramError('AV_EXCEEDS_PROJECTION',
      `"av" (${av}mm) exceeds "projection" (${projection}mm) \u2014 the load point cannot sit beyond the corbel's own outer tip.`);
  }

  assertInt('tieBarCount', raw.tieBarCount, { min: MIN_TIE_BAR_COUNT, max: MAX_TIE_BAR_COUNT });
  assertInt('stirrupCount', raw.stirrupCount, { min: MIN_STIRRUP_COUNT, max: MAX_STIRRUP_COUNT });
  const tieBarCount = raw.tieBarCount;
  const stirrupCount = raw.stirrupCount;

  const d = h - cover - tieBarDia / 2;
  assertFinitePositive('effective depth (h - cover - tieBarDia/2)', d);

  if (av / d > 1.0) {
    throw new DiagramError('AV_D_RATIO_EXCEEDS_SCOPE',
      `av/d = ${(av / d).toFixed(2)} exceeds 1.0 (av=${fmt(av, 'mm', 0)}, d=${fmt(d, 'mm', 0)}) \u2014 beyond this ratio the member behaves as a short beam, not a corbel (ACI 318 \u00a716.5).`);
  }
  const minPlateEdgeMM = Math.max(tieBarDia, cover);
  if (av + bearingPlateWidth / 2 + minPlateEdgeMM > projection) {
    throw new DiagramError('BEARING_EXCEEDS_PROJECTION',
      `Bearing plate (av=${fmt(av, 'mm', 0)}, half-width=${fmt(bearingPlateWidth / 2, 'mm', 0)}) plus the minimum edge distance (max(tieBarDia, cover) = ${fmt(minPlateEdgeMM, 'mm', 0)}) exceeds the corbel projection (${fmt(projection, 'mm', 0)}).`);
  }

  const tieLayer = computeBarLayerAcrossWidth({
    hostWidthMM: colB, cover, diaMM: tieBarDia, count: tieBarCount,
  });

  return {
    type: 'corbel',
    unit,
    id,
    geo: {
      colB, projection, av, h, h1, cover,
      tieBarDia, tieBarCount, stirrupDia, stirrupCount,
      bearingPlateWidth, d,
    },
    tieLayer,
    meta: {
      colB, projection, av, h, h1, cover,
      tieBarDia, tieBarCount, stirrupDia, stirrupCount, bearingPlateWidth,
    },
  };
}

function computeBarLayerAcrossWidth({ hostWidthMM, cover, diaMM, count }) {
  assertFinitePositive('tie layer host width', hostWidthMM);
  const envelope = hostWidthMM - 2 * cover - diaMM;
  if (envelope <= 0) {
    throw new DiagramError('NO_ROOM_FOR_TIE_BARS', `Cover (${cover}mm) and tie bar diameter (${diaMM}mm) leave no room for reinforcement across a ${hostWidthMM}mm column width.`);
  }
  const firstCenterMM = cover + diaMM / 2;
  const lastCenterMM = hostWidthMM - cover - diaMM / 2;
  const step = count > 1 ? (lastCenterMM - firstCenterMM) / (count - 1) : 0;
  const barCentersMM = Array.from({ length: count }, (_, i) => firstCenterMM + i * step);
  return { diaMM, count, barCentersMM };
}

// ── Labels ───────────────────────────────────────────────────────────
const L = {
  en: {
    title: (id) => `CORBEL ${id} \u2014 REINFORCEMENT DETAIL`,
    elevation: 'ELEVATION', section: 'SECTION', plan: 'PLAN AT MAIN STEEL \u2014 ANCHORAGE',
    column: 'Column', mainTie: 'Main Tie Steel (As)', stirrup: 'Closed Ties (Ah)',
    colTie: 'Column ties (by column design, not scheduled here)',
    colTieNote: 'Column ties shown in the elevation are by column design and are not scheduled in this drawing.',
    plate: 'Bearing Plate', edgeNote: '\u2265 max(dia,cover)', asLabel: 'As', ahLabel: 'Ah', ahMinNote: 'Ah \u2265 0.5(As\u2212An)',
    mark1: '1', mark2: '2', mark3: '3',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'count',
    caption: 'Schematic corbel detail generated from the supplied data \u2014 verify per ACI 318 \u00a716.5 (or the design code governing your project) before issuing for construction. This drawing does not check flexure-plus-tension (Mu, Nu), shear (Vn = Vc), or bearing strength at the plate (\u00a722.8) \u2014 those remain the design engineer\'s responsibility. Inclined bars are not shown \u2014 ACI 318 \u00a716.5 excludes them as ineffective in corbels. Main-bar anchorage follows the small-diameter convention (ECP 203 Fig. 2-11 style): outer bars deflect at a shallow angle toward the column\'s near corner \u2014 not a curve \u2014 plus a 90\u00b0 end hook at the loaded face; the closed tie itself closes with a rounded U-turn at that same loaded end. Hook and bend sizes use ACI 318 Table 25.3.1 proportions and are schematic, not a bar-bending schedule. Ah is drawn level, like As, stacked at exactly stirrupCount positions within (2/3)d of the main steel, matching the input exactly \u2014 each drawn in its own color. Column ties wrap the column\'s own longitudinal bars, not the bare concrete width. Below (2/3)d, two more horizontal bars appear outside the code-mandated Ah zone, so not part of the Ah count. These, the vertical legs closing each tie, the bar running the length of the compression strut, and the short bar at the loaded face, are placement only \u2014 two, three, one, and one respectively, fixed \u2014 this module has no input for any of those four counts. Column-tie size and count are likewise the column\'s own design and are shown only as a placement callout.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفصيلة تسليح الكابولي ${id}`,
    elevation: 'الواجهة', section: 'قطاع رأسي', plan: 'مسقط عند حديد الشد الرئيسي - الرباط',
    column: 'عمود', mainTie: 'حديد الشد الرئيسي', stirrup: 'الكانات الرأسية',
    colTie: 'كانات الأعمدة حسب تسليح العمود، غير مجدولة هنا',
    colTieNote: 'كانات الأعمدة الظاهرة في الواجهة حسب تصميم العمود وليست مجدولة في هذا الرسم.',
    plate: 'لوحة الارتكاز', edgeNote: 'اكبر من قطر السيخ او الغطاء', asLabel: 'As', ahLabel: 'Ah', ahMinNote: 'Ah \u2265 0.5(As\u2212An)',
    mark1: '1', mark2: '2', mark3: '3',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد',
    caption: 'رسم تفصيلي توضيحي للكابولي أُنشئ من البيانات المُدخلة، للتحقق فقط وفق الكود الإنشائي المعتمد في مشروعك مثل ACI 318 قبل الاعتماد للتنفيذ. هذا الرسم لا يتحقق من الانعطاف مع الشد المحوري أو القص أو قدرة تحمل لوحة الارتكاز. لا يُظهر هذا الرسم حديدا مائلا لأنه غير فعال في الكوابيل وفق نفس الكود. تثبيت الحديد الرئيسي مرسوم وفق الطريقة المتبعة للأقطار الصغيرة اقل من 16 مم، حيث ينحرف الحديد الطرفي بزاوية بسيطة نحو الركن القريب من العمود دون تدوير، مع كلابة بزاوية 90 درجة عند وجه التحميل، وتُغلق الكانة الرأسية نفسها بكلابة دائرية عند وجه التحميل أيضا. أبعاد الكلابة والانحناء وفق جدول ACI 318 رقم 25.3.1 وهي أبعاد توضيحية وليست جدول تشكيل حديد نهائي. حديد Ah مرسوم أفقيا مثل As تماما، بعدد يطابق المدخل موزعا خلال ثلثي d من الحديد الرئيسي. كانات الأعمدة تحيط بالحديد الطولي للعمود نفسه وليس عرض الخرسانة كاملا. أسفل ثلثي d يظهر حديدان أفقيان إضافيان خارج نطاق Ah الذي يحدده الكود فلا يُحسبان ضمن عدد Ah. هذه والحديدان والكانات الرأسية والحديد الممتد بطول رباط الضغط والحديد القصير عند وجه التحميل كلها إشارة موضع فقط بأعداد ثابتة.',
    dirAttr: 'rtl',
  },
};

function ahTieTick(xPx, yTopPx, yBottomPx) {
  const cap = 4;
  return `
    <line x1="${xPx}" y1="${yTopPx}" x2="${xPx}" y2="${yBottomPx}" class="bar-ahtie"/>
    <line x1="${xPx - cap}" y1="${yTopPx}" x2="${xPx + cap}" y2="${yTopPx}" class="bar-ahtie"/>
    <line x1="${xPx - cap}" y1="${yBottomPx}" x2="${xPx + cap}" y2="${yBottomPx}" class="bar-ahtie"/>`;
}
function columnTieTick(xLeftPx, xRightPx, yPx) {
  const cap = 4;
  return `
    <line x1="${xLeftPx}" y1="${yPx}" x2="${xRightPx}" y2="${yPx}" class="tie-column"/>
    <line x1="${xLeftPx}" y1="${yPx - cap}" x2="${xLeftPx}" y2="${yPx + cap}" class="tie-column"/>
    <line x1="${xRightPx}" y1="${yPx - cap}" x2="${xRightPx}" y2="${yPx + cap}" class="tie-column"/>`;
}

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 1100;

// L1: elevation box enlarged and content formula tightened so fitScale()
// lands near 0.55 instead of 0.245. L2: section/plan pushed down to clear.
const ELEVATION_BOX = { x: 80, y: 90, w: 900, h: 560 };
const SECTION_BOX = { x: 80, y: 700, w: 320, h: 290 };
const PLAN_BOX = { x: 460, y: 700, w: 500, h: 290 };

export function renderCorbelDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);
  const { geo, tieLayer } = geometry;

  const elevScale = fitScale([{
    contentW: geo.projection * 1.35,
    contentH: geo.h * 1.7,
    boxW: ELEVATION_BOX.w - 100,
    boxH: ELEVATION_BOX.h - 90,
  }]);
  const sectionScale = fitScale([{
    contentW: geo.colB, contentH: geo.h,
    boxW: SECTION_BOX.w - 70, boxH: SECTION_BOX.h - 70,
  }]);
  const planScale = fitScale([{
    contentW: COL_STUB_DEPTH_FACTOR * geo.h + geo.projection * 0.6 + 140,
    contentH: geo.colB + 60,
    boxW: PLAN_BOX.w - 90, boxH: PLAN_BOX.h - 70,
  }]);

  const tableRows = buildScheduleRows(geo, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 4);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: CANVAS_W - 120 - tableColW * 3 },
  ];
  const tableY = Math.max(SECTION_BOX.y + SECTION_BOX.h, PLAN_BOX.y + PLAN_BOX.h) + 30;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  // L6: standalone "column ties" note between table and caption.
  const noteY = tableY + table.height + 24;
  const noteSvg = `<text x="60" y="${noteY}" class="corbel-note">${esc(l.colTieNote)}</text>`;

  const captionY = noteY + 22;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .corbel-title  { font-size:22px; font-weight:bold; fill:#111; font-family:${scriptFontStack}; }
    .box-label     { font-size:14px; font-weight:bold; fill:#333; letter-spacing:0.5px; font-family:${scriptFontStack}; }
    .col-rect      { fill:#cbb393; stroke:#5c4a34; stroke-width:1.7; }
    .corbel-outline{ fill:#d9c4a3; stroke:#5c4a34; stroke-width:1.7; }
    .plate-rect    { fill:#dfe9f5; stroke:#2a5a8c; stroke-width:1.4; }
    .callout-text  { font-size:11px; fill:#555; font-family:${scriptFontStack}; }
    .corbel-note   { font-size:11px; fill:#555; font-family:${scriptFontStack}; }
    .bar-mainsteel { stroke:#1f5aa6; stroke-width:3.2; fill:none; stroke-linecap:round; }
    .bar-ahtie     { stroke:#1f8a5c; stroke-width:2.6; fill:none; stroke-linecap:round; }
    .bar-ahtie-1   { stroke:#c9761f; stroke-width:2.6; fill:none; stroke-linecap:round; }
    .bar-ahtie-2   { stroke:#8a7a1f; stroke-width:2.6; fill:none; stroke-linecap:round; }
    .bar-ahtie-3   { stroke:#1f8a5c; stroke-width:2.6; fill:none; stroke-linecap:round; }
    .bar-ahtie-4   { stroke:#8c2f8a; stroke-width:2.6; fill:none; stroke-linecap:round; }
    .bar-extra     { stroke:#8c2f3a; stroke-width:2.4; fill:none; stroke-linecap:round; }
    .tie-column    { stroke:#8c2f3a; stroke-width:3; fill:none; stroke-linecap:round; }
    .col-bar       { stroke:#1f5aa6; stroke-width:3.4; stroke-linecap:round; }
    .bar-dot-tie   { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }
    .bar-dot-coltie{ fill:#8c2f3a; stroke:#5c1c24; stroke-width:0.6; }
    .plate-footprint{ fill:none; stroke:#2a5a8c; stroke-width:1.2; stroke-dasharray:4,3; }
    .inline-label  { font-size:13px; font-style:italic; fill:#1a1a1a; font-family:${scriptFontStack}; }
    .ah-callout-bg { fill:#ffffff; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="34" text-anchor="middle" class="corbel-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderElevation(geo, elevScale, l)}
  ${renderSection(geo, tieLayer, sectionScale, l)}
  ${renderPlanAnchorage(geo, tieLayer, planScale, l)}
  ${table.svg}
  ${noteSvg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

function renderElevation(geo, scale, l) {
  const { projection, av, h, h1, cover, tieBarDia, stirrupDia, stirrupCount, bearingPlateWidth, d } = geo;

  // Flat top; sloped bottom (h at face, h1 at tip); vertical tip face.
  const topY = ELEVATION_BOX.y + 130;
  const colStubW = Math.max(70, h * scale * COL_STUB_DEPTH_FACTOR);
  const colTopY = topY - h * scale * 0.5;
  const bottomAtFaceY = topY + h * scale;
  const bottomAtTipY = topY + h1 * scale;
  const colBottomY = bottomAtFaceY + h * scale * 0.4;
  const colLeftX = ELEVATION_BOX.x + 95;
  const faceX = colLeftX + colStubW;
  const tipX = faceX + projection * scale;

  const bottomYAt = (xPx) => bottomAtFaceY + ((xPx - faceX) / (tipX - faceX)) * (bottomAtTipY - bottomAtFaceY);
  const xAtBottomY = (yPx) => {
    if (yPx <= bottomAtTipY) return tipX;
    if (yPx >= bottomAtFaceY) return faceX;
    return faceX + (tipX - faceX) * (yPx - bottomAtFaceY) / (bottomAtTipY - bottomAtFaceY);
  };

  const coverPx = cover * scale;
  const tieOffsetPx = (cover + tieBarDia / 2) * scale;
  const tieStartX = faceX - Math.min(30, colStubW * 0.4);
  const tieY = topY + tieOffsetPx;

  const hookRadiusPx = Math.min(
    standardHookBendRadiusMM(tieBarDia) * scale,
    Math.max(4, (tipX - coverPx) - (faceX + 10)),
  );
  const tieEndX = tipX - coverPx - hookRadiusPx;
  const maxHookTailPx = Math.max(6, (bottomYAt(tieEndX) - coverPx * 0.6) - (tieY + hookRadiusPx));
  const hookTailPx = Math.min(standardHook90ExtensionMM(tieBarDia) * scale, maxHookTailPx);
  const hookPathD = hookDown90PathD(tieEndX, tieY, hookRadiusPx, hookTailPx);

  const zoneBottomY = tieY + (2 / 3) * d * scale;
  const ahColorClasses = ['bar-ahtie-1', 'bar-ahtie-2', 'bar-ahtie-3', 'bar-ahtie-4'];
  const ahYs = distributeExact(tieY + coverPx * 1.4, Math.min(zoneBottomY, bottomAtFaceY - coverPx * 0.6), stirrupCount);
  const ahBars = ahYs.map((y, i) => {
    const xEnd = Math.min(xAtBottomY(y) - coverPx * 0.4, tipX - coverPx * 0.4);
    const cls = ahColorClasses[i % ahColorClasses.length];
    return `<line x1="${faceX - Math.min(20, colStubW * 0.3)}" y1="${y}" x2="${Math.max(faceX + 10, xEnd)}" y2="${y}" class="${cls}"/>`;
  }).join('');

  const extraZoneTop = Math.min(zoneBottomY, bottomAtFaceY - coverPx * 0.6) + coverPx * 1.2;
  const extraZoneBottom = bottomAtFaceY - coverPx * 1.4;
  const extraYs = extraZoneBottom > extraZoneTop ? distributeExact(extraZoneTop, extraZoneBottom, 2) : [];
  const extraBars = extraYs.map((y) => {
    const xEnd = Math.min(xAtBottomY(y) - coverPx * 0.4, tipX - coverPx * 0.4);
    return `<line x1="${faceX - Math.min(20, colStubW * 0.3)}" y1="${y}" x2="${Math.max(faceX + 10, xEnd)}" y2="${y}" class="bar-extra"/>`;
  }).join('');

  const legZoneStartX = faceX + Math.max(10, colStubW * 0.15);
  const legZoneEndX = faceX + (tipX - faceX) * 0.68;
  const legXs = distributeExact(legZoneStartX, legZoneEndX, 3);
  const verticalLegs = legXs.map((x) => `<line x1="${x}" y1="${tieY}" x2="${x}" y2="${bottomYAt(Math.min(x, tipX)) - coverPx * 0.5}" class="tie-column"/>`).join('');

  const stirrupOffsetPx = Math.max(10, stirrupDia * scale * 1.5);

  const colTieBandTop = colTopY + (topY - colTopY) * 0.18;
  const colTieBandBottom = topY - (topY - colTopY) * 0.18;
  const colTieYs = distributeExact(colTieBandTop, colTieBandBottom, 2);
  const colBarInsetPx = Math.max(10, colStubW * 0.12);
  const colBarXs = [colLeftX + colBarInsetPx, faceX - colBarInsetPx];
  const colTicks = colTieYs.map((y) => columnTieTick(colBarXs[0], colBarXs[1], y)).join('');

  const plateX = faceX + av * scale;
  const plateW = Math.max(10, bearingPlateWidth * scale);
  const plateThicknessPx = 10;
  const mark1BarLen = Math.max(24, plateW * 0.6);
  const mark1BarY = topY - plateThicknessPx - 22;
  const mark1BarX1 = plateX - mark1BarLen / 2;
  const mark1BarX2 = plateX + mark1BarLen / 2;

  const outline = `M ${faceX},${topY} L ${tipX},${topY} L ${tipX},${bottomAtTipY} L ${faceX},${bottomAtFaceY} Z`;

  const strutX1 = tipX - coverPx * 1.5;
  const strutY1 = bottomYAt(strutX1) - coverPx * 0.5;
  const strutX2 = faceX;
  const strutY2 = bottomAtFaceY;
  const strutLen = Math.hypot(strutX2 - strutX1, strutY2 - strutY1) || 1;
  const strutNx = -(strutY2 - strutY1) / strutLen;
  const strutNy = (strutX2 - strutX1) / strutLen;
  const strutBarLine = `<line x1="${strutX1 + strutNx * stirrupOffsetPx}" y1="${strutY1 + strutNy * stirrupOffsetPx}" x2="${strutX2 + strutNx * stirrupOffsetPx}" y2="${strutY2 + strutNy * stirrupOffsetPx}" class="tie-column"/>`;

  // L3: Ah ≥ 0.5(As−An) callout — moved from the strut's own midpoint
  // into the clean band between the last Ah bar and the first extra bar,
  // with a white mask so the middle vertical tie leg doesn't strike
  // through its glyphs.
  const ahCalloutY = (ahYs.length ? ahYs[ahYs.length - 1] : zoneBottomY) + 22;
  const ahCalloutX = faceX + 40;
  const ahCalloutW = 112;
  const ahCalloutMaskSvg =
    `<rect x="${ahCalloutX - 4}" y="${ahCalloutY - 12}" width="${ahCalloutW}" height="16" class="ah-callout-bg"/>` +
    `<text x="${ahCalloutX}" y="${ahCalloutY}" class="callout-text">${esc(l.ahMinNote)}</text>`;

  const markMainBar = barMarkTag(tieStartX - 16, tieY, l.mark1, { leaderTo: { x: tieStartX, y: tieY } });
  const markStirrup = ahYs.length
    ? barMarkTag(faceX + 10, bottomAtFaceY - 15, l.mark2, { leaderTo: { x: legXs[0], y: ahYs[0] } })
    : '';
  const markColTie = barMarkTag(colLeftX - 16, colTieYs[0], l.mark3, { leaderTo: { x: colBarXs[0], y: colTieYs[0] } });

  const dBracketX = ELEVATION_BOX.x + 60;
  const twoThirdsDBracketX = ELEVATION_BOX.x + 30;

  return `<g>
    <text x="${ELEVATION_BOX.x}" y="${ELEVATION_BOX.y}" class="box-label">${esc(l.elevation)}</text>
    <rect x="${colLeftX}" y="${colTopY}" width="${colStubW}" height="${colBottomY - colTopY}" class="col-rect"/>
    ${colTicks}
    ${colBarXs.map((x) => `<line x1="${x}" y1="${colTopY + 4}" x2="${x}" y2="${colBottomY - 4}" class="col-bar"/>`).join('')}
    <path d="${outline}" class="corbel-outline"/>
    ${ahBars}
    ${extraBars}
    ${verticalLegs}
    ${strutBarLine}
    <line x1="${mark1BarX1}" y1="${mark1BarY}" x2="${mark1BarX2}" y2="${mark1BarY}" class="tie-column"/>
    <line x1="${tieStartX}" y1="${tieY}" x2="${tieEndX}" y2="${tieY}" class="bar-mainsteel"/>
    <path d="${hookPathD}" class="bar-mainsteel"/>
    <text x="${tieStartX + 46}" y="${tieY + 16}" class="inline-label">${esc(l.asLabel)}</text>
    <rect x="${plateX - plateW / 2}" y="${topY - plateThicknessPx}" width="${plateW}" height="${plateThicknessPx}" class="plate-rect"/>
    ${dimensionLine(faceX, colBottomY + 22, plateX, colBottomY + 22, `av = ${fmt(av, 'mm', 0)}`)}
    ${dimensionLine(faceX, colBottomY + 46, tipX, colBottomY + 46, `a = ${fmt(projection, 'mm', 0)}`)}
    ${dimensionLine(faceX - 22, topY, faceX - 22, bottomAtFaceY, `h = ${fmt(h, 'mm', 0)}`, { orientation: 'v' })}
    ${dimensionLine(dBracketX, tieY, dBracketX, bottomAtFaceY, `d = ${fmt(d, 'mm', 0)}`, { orientation: 'v' })}
    ${dimensionLine(twoThirdsDBracketX, tieY, twoThirdsDBracketX, zoneBottomY, `(2/3)d`, { orientation: 'v' })}
    ${dimensionLine(tipX + 55, topY, tipX + 55, bottomAtTipY, `h1 = ${fmt(h1, 'mm', 0)}`, { orientation: 'v' })}
    <text x="${plateX}" y="${topY - plateThicknessPx - 8}" text-anchor="middle" class="dim-label">${esc(l.plate)}</text>
    ${dimensionLine(plateX + plateW / 2, topY - 40, tipX, topY - 40, l.edgeNote)}
    ${ahCalloutMaskSvg}
    ${markMainBar}
    ${markStirrup}
    ${markColTie}
  </g>`;
}

function renderSection(geo, tieLayer, scale, l) {
  const { colB, h, cover, tieBarDia } = geo;
  const sx = SECTION_BOX.x + 40;
  const sy = SECTION_BOX.y + 40;
  const sw = colB * scale;
  const sh = h * scale;

  const tieY = sy + (cover + tieBarDia / 2) * scale;
  const tieDots = tieLayer.barCentersMM.map((c) => barDot(sx + c * scale, tieY, tieBarDia, scale, 'tie')).join('');
  const stirrupInset = cover * scale;

  return `<g>
    <text x="${SECTION_BOX.x}" y="${SECTION_BOX.y}" class="box-label">${esc(l.section)}</text>
    <rect x="${sx}" y="${sy}" width="${sw}" height="${sh}" fill="#f6f6f6" stroke="#333" stroke-width="1.6"/>
    <rect x="${sx + stirrupInset}" y="${sy + stirrupInset}" width="${sw - 2 * stirrupInset}" height="${sh - 2 * stirrupInset}" class="stirrup-outline"/>
    ${tieDots}
    ${dimensionLine(sx, sy + sh + 22, sx + sw, sy + sh + 22, `colB = ${fmt(colB, 'mm', 0)}`)}
  </g>`;
}

function renderPlanAnchorage(geo, tieLayer, scale, l) {
  const { colB, h, projection, av, tieBarDia, cover, bearingPlateWidth } = geo;
  const colDepthPx = COL_STUB_DEPTH_FACTOR * h * scale;

  const colLeftX = PLAN_BOX.x + 60;
  const colTopY = PLAN_BOX.y + 45;
  const colRightX = colLeftX + colDepthPx;
  const colBottomY = colTopY + colB * scale;

  const corbelStubLenPx = Math.min(PLAN_BOX.w - (colRightX - PLAN_BOX.x) - 30, Math.max(160, projection * scale * 0.6));
  const corbelRightX = colRightX + corbelStubLenPx;

  const cornerMarginPx = Math.max(9, cover * scale * 1.1);
  const bendZoneStartX = colLeftX + Math.max(24, colDepthPx * 0.3);
  const topEdgeMM = colB / 3;
  const bottomEdgeMM = (colB * 2) / 3;
  const entryX = corbelRightX - Math.max(16, corbelStubLenPx * 0.12);

  const barLines = tieLayer.barCentersMM.map((c) => {
    const y = colTopY + c * scale;
    let targetY = y;
    if (c < topEdgeMM) targetY = colTopY + cornerMarginPx;
    else if (c > bottomEdgeMM) targetY = colBottomY - cornerMarginPx;
    return `
      <line x1="${entryX}" y1="${y}" x2="${bendZoneStartX}" y2="${y}" class="bar-mainsteel"/>
      <line x1="${bendZoneStartX}" y1="${y}" x2="${colLeftX + cornerMarginPx}" y2="${targetY}" class="bar-mainsteel"/>`;
  }).join('');

  const tieInsetPx = Math.max(6, cornerMarginPx * 0.7);
  const tieRectX = colLeftX + tieInsetPx;
  const tieRectY = colTopY + tieInsetPx;
  const tieRectW = colDepthPx - 2 * tieInsetPx;
  const tieRectH = (colBottomY - colTopY) - 2 * tieInsetPx;
  const colTieLoop = `<rect x="${tieRectX}" y="${tieRectY}" width="${tieRectW}" height="${tieRectH}" rx="8" ry="8" class="tie-column" fill="none"/>`;

  const corners = [
    [colLeftX, colTopY], [colRightX, colTopY],
    [colLeftX, colBottomY], [colRightX, colBottomY],
  ];
  const cornerDots = corners.map(([cx, cy]) => barDot(cx, cy, tieBarDia, scale, 'coltie')).join('');

  const barCenters = tieLayer.barCentersMM;
  const tieYmm = barCenters.length >= 2 ? (barCenters[0] + barCenters[1]) / 2 : colB / 2;
  const tieY = colTopY + tieYmm * scale;
  const remainingRunPx = colBottomY - tieY;
  const RETURN_LEG_MARGIN_PX = 6;
  const maxRadiusFromFramePx = Math.max(4, (remainingRunPx - RETURN_LEG_MARGIN_PX) / 2);
  const tieRadiusPx = Math.max(4, Math.min(20, corbelStubLenPx * 0.16, maxRadiusFromFramePx));
  const tieBendX = corbelRightX - Math.max(18, tieRadiusPx * 0.7);
  const tieReturnY = tieY + 2 * tieRadiusPx;
  const tieStartX = colLeftX + cornerMarginPx + 4;
  const tieGroup = `
    <line x1="${tieStartX}" y1="${tieY}" x2="${tieBendX}" y2="${tieY}" class="bar-ahtie"/>
    <path d="${loadedEndClosure180PathD(tieBendX, tieY, tieRadiusPx, 1)}" class="bar-ahtie"/>
    <line x1="${tieBendX}" y1="${tieReturnY}" x2="${tieStartX}" y2="${tieReturnY}" class="bar-ahtie"/>
    <text x="${tieStartX + 6}" y="${tieY - 8}" class="inline-label">${esc(l.ahLabel)}</text>`;

  const plateFootprintX = colRightX + av * scale;
  const plateFootprintW = Math.max(10, bearingPlateWidth * scale);

  // L4: mark 1 pushed out to the clear upper-right gutter; mark 3 pushed
  // to the plan box's own upper-left gutter. Mark 2 unchanged.
  const markMainBar = barMarkTag(
    corbelRightX + 30, colTopY - 26, l.mark1,
    { leaderTo: { x: entryX, y: colTopY + tieLayer.barCentersMM[0] * scale } },
  );
  const markTie = barMarkTag(tieStartX + 20, tieY + 22, l.mark2, { leaderTo: { x: tieStartX + 20, y: tieY } });
  const markColTie = barMarkTag(colLeftX - 60, colTopY - 8, l.mark3, { leaderTo: { x: colLeftX, y: colTopY } });

  return `<g>
    <text x="${PLAN_BOX.x}" y="${PLAN_BOX.y}" class="box-label">${esc(l.plan)}</text>
    <rect x="${colLeftX}" y="${colTopY}" width="${colDepthPx}" height="${colBottomY - colTopY}" class="col-rect"/>
    <rect x="${colRightX}" y="${colTopY}" width="${corbelRightX - colRightX}" height="${colBottomY - colTopY}" class="corbel-outline"/>
    <line x1="${colRightX}" y1="${colTopY}" x2="${colRightX}" y2="${colBottomY}" stroke="#1a1a1a" stroke-width="1.2" stroke-dasharray="5,3"/>
    <rect x="${plateFootprintX - plateFootprintW / 2}" y="${colTopY}" width="${plateFootprintW}" height="${colBottomY - colTopY}" class="plate-footprint"/>
    ${colTieLoop}
    ${barLines}
    ${tieGroup}
    ${cornerDots}
    <text x="${(colLeftX + colRightX) / 2}" y="${colBottomY + 26}" text-anchor="middle" class="dim-label">${esc(l.column)}</text>
    <text x="${plateFootprintX}" y="${colTopY - 22}" text-anchor="middle" class="callout-text">${esc(l.plate)}</text>
    ${markMainBar}
    ${markTie}
    ${markColTie}
  </g>`;
}

function buildScheduleRows(geo, l) {
  return [
    { mark: l.mark1, element: l.mainTie, dia: String(Math.round(geo.tieBarDia)), count: String(geo.tieBarCount) },
    { mark: l.mark2, element: l.stirrup, dia: String(Math.round(geo.stirrupDia)), count: String(geo.stirrupCount) },
    { mark: l.mark3, element: l.colTie, dia: '\u2014', count: '\u2014' },
  ];
}

// ── Chat-facing entry point (mode:'rebarDiagram' JSON payload) ────────
export function parseCorbelRebarPayload(raw) {
  try {
    const geometry = computeCorbelDiagramGeometry(raw);
    return { ok: true, type: 'corbel', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ─────────────────────────────────
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: corbel key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'corbel' && type !== 'bracket') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use corbel or bracket.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const geometry = computeCorbelDiagramGeometry({
      corbelId: kv.id,
      colB: num('colb'), projection: num('projection'), av: num('av'),
      h: num('h'), h1: num('h1'), cover: num('cover'),
      tieBarDia: num('tiebardia'), tieBarCount: num('tiebarcount'),
      stirrupDia: num('stirrupdia'), stirrupCount: num('stirrupcount'),
      bearingPlateWidth: num('bearingplatewidth'),
      unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}