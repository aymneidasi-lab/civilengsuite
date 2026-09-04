// functions/_lib/slabDiagram.mjs
//
// Deterministic, zero-AI SVG generator for a single rectangular two-way
// slab panel's reinforcement (plan mesh + thickness section + bar
// schedule) — Step 19 ("توسع slabDiagram.mjs/shearWallDiagram.mjs/
// stairDiagram.mjs"), built on the readiness assessed and documented in
// structuralDrawingKit.mjs's own "Step 18" header. Same philosophy as
// footingDiagram.mjs/beamDiagram.mjs/columnDiagram.mjs: every dimension,
// bar position, and count in the output is arithmetic on the KB data
// supplied, never a model's guess. This module owns compute+render only.
//
// SCOPE (v1): a single flat rectangular panel (lengthMM x widthMM plan,
// constant thicknessMM), one bottom mesh (required) and one optional top
// mesh, each isotropic-by-default (spacingYMM defaults to spacingXMM —
// override only for a genuinely anisotropic two-way panel), plus optional
// "extra top bar" edge annotations (count/diameter only, no computed
// cutting length — see EXTRA-BAR HONESTY note below). NOT modeled, on
// purpose (same "explicit scope boundary" convention as the other three
// modules): openings/penetrations, drop panels or column capitals, punching-
// shear reinforcement, curtailment (bars cut short of a full span), and
// multi-panel continuous slabs — each needs a parametrization this module
// hasn't been given yet.
//
// ── SPACING DIRECTION CONVENTION (read before wiring any KB payload) ───
// mesh.bottom.spacingXMM is the spacing BETWEEN bars that run parallel to
// Y (i.e. spaced apart along X) — each such bar's drawn length is
// widthMM. mesh.bottom.spacingYMM is the spacing between bars that run
// parallel to X (spaced apart along Y) — each such bar's drawn length is
// lengthMM. This is standard drafting convention (spacing is always
// measured perpendicular to the bar it separates) but it is easy to
// invert by accident, which would silently swap which schedule row gets
// which length — schema fields are named spacingXMM/spacingYMM (the AXIS
// the spacing is measured ALONG), never "spacing of the X-direction
// bars", specifically to keep this unambiguous at the call site.
//
// ── EXTRA-BAR HONESTY NOTE ──────────────────────────────────────────────
// extraTopBars[] carries diameterMM/count/edge only — no startX/endX
// extent field in v1, so this module has no defendable length to show
// (unlike columnDiagram.mjs's lapSpliceMM, which DOES get a length
// because it is given one). The schedule table shows "\u2014" for these
// rows' length rather than inventing one from a guessed zone width.
//
// ── INPUT CONTRACT ───────────────────────────────────────────────────
// {
//   unit?: 'mm'|'cm'|'m',
//   slabId: string,
//   lengthMM: number, widthMM: number,   // plan dimensions
//   thicknessMM: number,
//   coverMM: number,
//   mesh: {
//     bottom: { diameterMM, spacingXMM, spacingYMM? },   // required
//     top?:   { diameterMM, spacingXMM, spacingYMM? },   // optional
//   },
//   extraTopBars?: [ { diameterMM, count, edge: 'top'|'bottom'|'left'|'right', label? } ],
// }
//
// Resource lifecycle: pure/synchronous, zero imports beyond the shared
// kit, no timers/fetch/KV/handles — same as the other three modules.
// Fully deterministic: no env.AI, no model call, no randomness.

import {
  DiagramError, toMm, assertFinitePositive, assertInt, assertOneOf,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, distributeTicks, barMarkTag,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ─────────────────────────────────────────────────────
// MAX_MESH_ROWS/COLS is the risk structuralDrawingKit.mjs's Step 18 note
// flagged explicitly: distributeTicks() itself hard-caps at 24/axis, so a
// naive 24x24 combined mesh would emit up to 576 barDot() calls per
// layer. 14 is chosen (not 24) so a bottom+top panel together draw at
// most 2 x 14 x 14 = 392 dots — verified below by the Max-load smoke
// test's own timing assertion, the same methodology
// خطة_المرحلة_التالية_13-18.md's Step 13 section used for beams (a real
// Node timing run standing in for the Workers CPU budget check, since
// this sandbox has no Workers runtime to test against directly).
const MIN_SPAN_MM = 1000;
const MAX_SPAN_MM = 12000;
const MIN_THICKNESS_MM = 100;
const MAX_THICKNESS_MM = 500;
const MIN_MESH_SPACING_MM = 75;
const MAX_MESH_SPACING_MM = 400;
const MAX_MESH_ROWS = 14;
const MAX_MESH_COLS = 14;
const MAX_EXTRA_ZONES = 6;
const MAX_EXTRA_BARS_PER_ZONE = 12;

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

export function computeSlabDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Slab diagram input must be an object.');
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
  const topSpec = raw.mesh.top ? parseMeshSpec(raw.mesh.top, unit, 'mesh.top') : null;

  function toMeshGeometry(spec) {
    // Real (uncapped) bar counts — the schedule table's source of truth;
    // drawn (capped) counts are derived later, at render time, from
    // these, the same separation columnDiagram.mjs uses for ties.count
    // vs. MAX_DRAWN_TIES_PER_COLUMN.
    const countX = Math.max(2, Math.round(lengthMM / spec.spacingX) + 1);
    const countY = Math.max(2, Math.round(widthMM / spec.spacingY) + 1);
    return { dia: spec.dia, spacingX: spec.spacingX, spacingY: spec.spacingY, countX, countY };
  }
  const bottom = toMeshGeometry(bottomSpec);
  const top = topSpec ? toMeshGeometry(topSpec) : null;

  let extraTopBars = [];
  if (raw.extraTopBars != null) {
    if (!Array.isArray(raw.extraTopBars) || raw.extraTopBars.length > MAX_EXTRA_ZONES) {
      throw new DiagramError('BAD_PARAM', `"extraTopBars" must be an array of at most ${MAX_EXTRA_ZONES} zones.`);
    }
    extraTopBars = raw.extraTopBars.map((z, i) => {
      if (!z || typeof z !== 'object') throw new DiagramError('BAD_PARAM', `extraTopBars[${i}] must be an object.`);
      const dia = toMm(z.diameterMM, unit);
      assertFinitePositive(`extraTopBars[${i}].diameterMM`, dia);
      assertInt(`extraTopBars[${i}].count`, z.count, { min: 1, max: MAX_EXTRA_BARS_PER_ZONE });
      const edge = z.edge;
      assertOneOf(`extraTopBars[${i}].edge`, edge, ['top', 'bottom', 'left', 'right']);
      const label = z.label != null ? String(z.label).slice(0, 30) : `T${i + 1}`;
      return { dia, count: z.count, edge, label };
    });
  }

  return {
    type: 'slab', unit, id, lengthMM, widthMM, thicknessMM, coverMM,
    mesh: { bottom, top }, extraTopBars,
  };
}

// ── Labels ──────────────────────────────────────────────────────────
// Local dictionary, following beamDiagram.mjs/columnDiagram.mjs's
// pattern (structuralLabels.mjs stays scoped to footingDiagram.mjs — see
// columnDiagram.mjs's own "Labels" section for the full reasoning, which
// applies unchanged here). Every Arabic string is parenthesis/em-dash
// free (Noto Naskh Arabic glyph-coverage constraint, same as the other
// three modules).
const L = {
  en: {
    title: (id) => `SLAB ${id} \u2014 REINFORCEMENT DETAIL`,
    plan: 'MESH PLAN', section: 'SECTION',
    bottomDirX: 'Bottom mesh, bars || Y', bottomDirY: 'Bottom mesh, bars || X',
    topDirX: 'Top mesh, bars || Y', topDirY: 'Top mesh, bars || X',
    extraBarRow: (edge) => `Extra top bar \u2014 ${edge} edge`,
    extentSuffix: ' (extent)',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    legendBottom: 'bottom mesh', legendTop: 'top mesh',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design (ECP 203 / ACI 318) before issuing for construction. Lengths marked "(extent)" are the drawn panel dimension only. Extra top bar rows show count/diameter only \u2014 no cutting length is computed for them in this version.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد البلاطة ${id}`,
    plan: 'مسقط الشبكة', section: 'قطاع',
    bottomDirX: 'شبكة سفلية، أسياخ موازية Y', bottomDirY: 'شبكة سفلية، أسياخ موازية X',
    topDirX: 'شبكة علوية، أسياخ موازية Y', topDirY: 'شبكة علوية، أسياخ موازية X',
    extraBarRow: (edge) => `سيخ علوي إضافي، حافة ${edge}`,
    extentSuffix: ' امتداد',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    legendBottom: 'الشبكة السفلية', legendTop: 'الشبكة العلوية',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. الأطوال المُعلَّمة امتداد هي طول اللوح فقط. صفوف الأسياخ العلوية الإضافية تعرض العدد والقطر فقط، بلا طول قطع محسوب في هذه النسخة.',
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

function drawMeshGrid(sx, sy, w, h, meshGeom, scale, face) {
  if (!meshGeom) return '';
  const drawCols = Math.min(meshGeom.countX, MAX_MESH_COLS);
  const drawRows = Math.min(meshGeom.countY, MAX_MESH_ROWS);
  const xs = distributeTicks(sx, sx + w, drawCols);
  const ys = distributeTicks(sy, sy + h, drawRows);
  let svg = '';
  for (const y of ys) {
    for (const x of xs) {
      svg += barDot(x, y, meshGeom.dia, scale, face);
    }
  }
  return svg;
}

function renderPlanView(geometry, scale, box, l) {
  const { lengthMM, widthMM, mesh, extraTopBars } = geometry;
  const w = lengthMM * scale, h = widthMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + (box.h - h) / 2;
  let svg = `<g class="plan-view">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.plan)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" class="concrete-outline"/>`;
  // Bottom mesh drawn first (larger, drawn under); top mesh (if present)
  // drawn with a small px offset purely so the two dot layers stay
  // visually distinguishable in plan \u2014 real top/bottom bars occupy the
  // SAME plan (x,y) footprint at different depths, so this offset is a
  // drafting convenience only, never a claimed position (documented here
  // so it is never mistaken for real geometry later).
  svg += drawMeshGrid(sx, sy, w, h, mesh.bottom, scale, 'slab-bottom');
  if (mesh.top) svg += drawMeshGrid(sx + 5, sy + 5, w, h, mesh.top, scale, 'slab-top');

  if (mesh.top) {
    const legendY = box.y + box.h + 34;
    const c1x = box.x + box.w / 2 - 110, c2x = box.x + box.w / 2 + 40;
    svg += `<circle cx="${c1x}" cy="${legendY}" r="4" class="bar-dot-slab-bottom"/>`;
    svg += `<text x="${c1x + 10}" y="${legendY + 4}" class="sheet-caption" dir="${l.dirAttr}">${esc(l.legendBottom)}</text>`;
    svg += `<circle cx="${c2x}" cy="${legendY}" r="3.4" class="bar-dot-slab-top"/>`;
    svg += `<text x="${c2x + 10}" y="${legendY + 4}" class="sheet-caption" dir="${l.dirAttr}">${esc(l.legendTop)}</text>`;
  }

  const edgeMarkPositions = { top: { x: sx + w / 2, y: sy - 8 }, bottom: { x: sx + w / 2, y: sy + h + 8 }, left: { x: sx - 8, y: sy + h / 2 }, right: { x: sx + w + 8, y: sy + h / 2 } };
  extraTopBars.forEach((z) => {
    const p = edgeMarkPositions[z.edge];
    svg += barMarkTag(p.x, p.y, `${z.count}\u00d8${Math.round(z.dia)}`, { r: 12 });
  });

  svg += dimensionLine(sx, sy + h + 20, sx + w, sy + h + 20, `${Math.round(lengthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 20, sy, sx - 20, sy + h, `${Math.round(widthMM)}mm`, { orientation: 'v', tick: 5 });
  svg += `</g>`;
  return svg;
}

function renderSectionView(geometry, scale, box, l) {
  const { thicknessMM, coverMM, mesh } = geometry;
  const stripW = box.w - 60;
  const stripH = thicknessMM * scale;
  const sx = box.x + 30;
  const sy = box.y + (box.h - stripH) / 2;
  let svg = `<g class="section-view">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.section)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${stripW}" height="${stripH}" fill="url(#concreteHatch)" class="concrete-outline"/>`;

  const bottomY = sy + stripH - coverMM * scale;
  svg += `<line x1="${sx + 6}" y1="${bottomY}" x2="${sx + stripW - 6}" y2="${bottomY}" class="bar-bottom"/>`;
  for (const x of distributeTicks(sx + 14, sx + stripW - 14, Math.min(mesh.bottom.countX, 6))) {
    svg += barDot(x, bottomY, mesh.bottom.dia, scale, 'slab-bottom');
  }
  if (mesh.top) {
    const topY = sy + coverMM * scale;
    svg += `<line x1="${sx + 6}" y1="${topY}" x2="${sx + stripW - 6}" y2="${topY}" class="bar-top"/>`;
    for (const x of distributeTicks(sx + 14, sx + stripW - 14, Math.min(mesh.top.countX, 6))) {
      svg += barDot(x, topY, mesh.top.dia, scale, 'slab-top');
    }
  }
  svg += dimensionLine(sx + stripW + 22, sy, sx + stripW + 22, sy + stripH, `${Math.round(thicknessMM)}mm`, { orientation: 'v', tick: 5 });
  svg += dimensionLine(sx - 20, bottomY, sx - 20, sy + stripH, `${Math.round(coverMM)}mm`, { orientation: 'v', tick: 4 });
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l, lang) {
  const rows = [];
  const { mesh, extraTopBars } = geometry;
  const edgeL = EDGE_LABEL[lang];
  rows.push({ mark: 'M1', element: l.bottomDirX, dia: String(Math.round(mesh.bottom.dia)), count: `${mesh.bottom.countX} @ ${Math.round(mesh.bottom.spacingX)}`, length: `${Math.round(geometry.widthMM)}${l.extentSuffix}` });
  rows.push({ mark: 'M2', element: l.bottomDirY, dia: String(Math.round(mesh.bottom.dia)), count: `${mesh.bottom.countY} @ ${Math.round(mesh.bottom.spacingY)}`, length: `${Math.round(geometry.lengthMM)}${l.extentSuffix}` });
  if (mesh.top) {
    rows.push({ mark: 'M3', element: l.topDirX, dia: String(Math.round(mesh.top.dia)), count: `${mesh.top.countX} @ ${Math.round(mesh.top.spacingX)}`, length: `${Math.round(geometry.widthMM)}${l.extentSuffix}` });
    rows.push({ mark: 'M4', element: l.topDirY, dia: String(Math.round(mesh.top.dia)), count: `${mesh.top.countY} @ ${Math.round(mesh.top.spacingY)}`, length: `${Math.round(geometry.lengthMM)}${l.extentSuffix}` });
  }
  extraTopBars.forEach((z, i) => {
    rows.push({ mark: `T${i + 1}`, element: l.extraBarRow(edgeL[z.edge]), dia: String(Math.round(z.dia)), count: String(z.count), length: '\u2014' });
  });
  return rows;
}

export function renderSlabDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const planScale = fitScale([{ contentW: geometry.lengthMM, contentH: geometry.widthMM, boxW: PLAN_BOX.w - 60, boxH: PLAN_BOX.h - 80 }]);
  const sectionScale = fitScale([{ contentW: 1, contentH: geometry.thicknessMM, boxW: SECTION_BOX.w - 60, boxH: SECTION_BOX.h - 60 }]);

  const tableRows = buildScheduleRows(geometry, l, lang);
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
    .slab-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .bar-dot-slab-bottom { fill:#c0392b; stroke:#7a2015; stroke-width:0.6; }
    .bar-dot-slab-top    { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="slab-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderPlanView(geometry, planScale, PLAN_BOX, l)}
  ${renderSectionView(geometry, sectionScale, SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// ── Chat-facing entry point ────────────────────────────────────────────
// Mirrors columnDiagram.mjs's parseColumnRebarPayload() error-shape
// contract exactly ({ok:true,...} / {ok:false,code,message}).
export function parseSlabRebarPayload(raw) {
  try {
    const geometry = computeSlabDiagramGeometry(raw);
    return { ok: true, type: 'slab', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Step 20 (this session). Mirrors footingDiagram.mjs's parseDiagramCommand
// exactly: same leading-token+"key=value key=value..." syntax, same
// BAD_SYNTAX/UNSUPPORTED_TYPE reservation (BAD_SYNTAX = no
// leading-token+params shape at all; UNSUPPORTED_TYPE = shape present but
// leading token isn't "slab" — lets diagramCommandRouter.mjs try the next
// module without masking a real syntax error), same never-throws contract
// ({ok:true,type,geometry} / {ok:false,code,message}).
//
// Syntax:
//   /diagram slab id=S1 length=4000 width=3000 thickness=180 cover=25
//     botdia=12 botspacingx=150 [botspacingy=150]
//     [topdia=10 topspacingx=200 [topspacingy=200]]
//     [extras=N extra1dia=12 extra1count=6 extra1edge=top [extra1label=T1] ...]
//     [unit=mm]
// extra{i}edge is the one non-numeric flat value this command accepts;
// lower-cased explicitly below since assertOneOf's allowed set
// ('top'/'bottom'/'left'/'right') is case-sensitive and this tokenizer
// (unlike numeric keys) never normalizes values, only keys.
// extra{i}label cannot contain whitespace — this flat-command syntax has
// no quoting mechanism, same limitation footingDiagram.mjs's command
// syntax already has for every field.
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: slab key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'slab') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use slab.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const mesh = { bottom: { diameterMM: num('botdia'), spacingXMM: num('botspacingx'), spacingYMM: num('botspacingy') } };
    if (kv.topdia !== undefined || kv.topspacingx !== undefined) {
      mesh.top = { diameterMM: num('topdia'), spacingXMM: num('topspacingx'), spacingYMM: num('topspacingy') };
    }
    let extraTopBars;
    const extrasN = num('extras');
    if (Number.isFinite(extrasN) && extrasN > 0) {
      extraTopBars = [];
      for (let i = 1; i <= extrasN; i++) {
        extraTopBars.push({
          diameterMM: num(`extra${i}dia`),
          count: num(`extra${i}count`),
          edge: kv[`extra${i}edge`] != null ? kv[`extra${i}edge`].toLowerCase() : undefined,
          label: kv[`extra${i}label`],
        });
      }
    }
    const geometry = computeSlabDiagramGeometry({
      slabId: kv.id, lengthMM: num('length'), widthMM: num('width'),
      thicknessMM: num('thickness'), coverMM: num('cover'),
      mesh, extraTopBars, unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
