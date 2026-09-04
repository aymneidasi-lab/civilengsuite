// functions/_lib/shearWallDiagram.mjs
//
// Deterministic, zero-AI SVG generator for a single rectangular shear
// wall panel's reinforcement (elevation mesh + thickness section + bar
// schedule) — Step 19, built on the readiness assessed in
// structuralDrawingKit.mjs's "Step 18" header. Same philosophy as the
// other three element modules: every dimension, bar position, and count
// is arithmetic on the KB data supplied, never a model's guess.
//
// SCOPE (v1): a single prismatic rectangular wall panel (constant
// lengthMM x thicknessMM over its full heightMM), one distributed mesh
// (vertical + horizontal bars, each isotropic-by-construction — one
// diameter/spacing pair per direction, both faces assumed identical),
// and an OPTIONAL boundary element of the SAME widthMM/bar-count/tie-spec
// at BOTH ends (symmetric — matches columnDiagram.mjs's single-group
// simplification). NOT modeled, on purpose: openings/coupling beams,
// asymmetric boundary elements (different at each end), staggered mesh
// layers (near-face/far-face at different spacing), out-of-plane
// boundary confinement beyond a single tie spec, and multi-story
// (varying-thickness) walls.
//
// ── DIRECTION CONVENTION ────────────────────────────────────────────
// mesh.vertical describes bars that run VERTICALLY (parallel to
// heightMM, full-height); mesh.vertical.spacingMM is measured
// HORIZONTALLY along the wall's length (how far apart adjacent vertical
// bars sit). mesh.horizontal describes bars that run HORIZONTALLY
// (parallel to lengthMM, full-length); mesh.horizontal.spacingMM is
// measured VERTICALLY up the height. This mirrors slabDiagram.mjs's own
// spacing convention (spacing is always measured perpendicular to the
// bar it separates) for the same reason: an inverted convention would
// silently swap which schedule row gets which drawn length.
//
// ── INPUT CONTRACT ───────────────────────────────────────────────────
// {
//   unit?: 'mm'|'cm'|'m',
//   wallId: string,
//   lengthMM: number,      // plan length, drawn horizontal in elevation
//   heightMM: number,      // story height, drawn vertical in elevation
//   thicknessMM: number,   // out-of-plane thickness, shown in section only
//   coverMM: number,
//   mesh: {
//     vertical:   { diameterMM, spacingMM },
//     horizontal: { diameterMM, spacingMM },
//   },
//   boundaryElement?: {           // omit for a wall with distributed mesh only
//     widthMM: number,            // zone width from EACH end (same both ends)
//     verticalBars: { diameterMM, count },  // full-height bars within the zone
//     ties: { diameterMM, spacingMM },
//   },
// }
//
// Resource lifecycle: pure/synchronous, zero imports beyond the shared
// kit, no timers/fetch/KV/handles. Fully deterministic: no env.AI, no
// model call, no randomness.

import {
  DiagramError, toMm, assertFinitePositive, assertInt,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, tieTickH, distributeTicks,
  barMarkTag, fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ─────────────────────────────────────────────────────
// Same 14/axis reasoning as slabDiagram.mjs's MAX_MESH_ROWS/COLS — kept
// identical here so a wall's elevation mesh never draws more dots than a
// slab's plan mesh does, verified by this file's own Max-load smoke test
// timing assertion.
const MIN_LENGTH_MM = 600;
const MAX_LENGTH_MM = 12000;
const MIN_HEIGHT_MM = 2000;
const MAX_HEIGHT_MM = 6000; // one story, schematically — same rationale as columnDiagram.mjs's MAX_HEIGHT_MM
const MIN_THICKNESS_MM = 150;
const MAX_THICKNESS_MM = 600;
const MIN_MESH_SPACING_MM = 75;
const MAX_MESH_SPACING_MM = 400;
const MAX_MESH_ROWS = 14;
const MAX_MESH_COLS = 14;
const MIN_BOUNDARY_WIDTH_MM = 150;
const MIN_BOUNDARY_BAR_COUNT = 4;
const MAX_BOUNDARY_BAR_COUNT = 16;
const MIN_TIE_SPACING_MM = 30;
const MAX_TIE_SPACING_MM = 300; // boundary elements are more closely tied than a typical column — see ties note below
const MAX_DRAWN_TIES = 24; // matches distributeTicks' own hard cap

// ── Compute ─────────────────────────────────────────────────────────
function parseDirectionalMesh(spec, unit, label) {
  if (!spec || typeof spec !== 'object') {
    throw new DiagramError('BAD_PARAM', `"${label}" must be an object: { diameterMM, spacingMM }.`);
  }
  const dia = toMm(spec.diameterMM, unit);
  assertFinitePositive(`${label}.diameterMM`, dia);
  const spacing = toMm(spec.spacingMM, unit);
  assertFinitePositive(`${label}.spacingMM`, spacing);
  if (spacing < MIN_MESH_SPACING_MM || spacing > MAX_MESH_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"${label}.spacingMM" must be between ${MIN_MESH_SPACING_MM}mm and ${MAX_MESH_SPACING_MM}mm, got ${spacing}mm.`);
  }
  return { dia, spacing };
}

export function computeShearWallDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Shear wall diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.wallId != null ? String(raw.wallId).slice(0, 40) : 'WALL';

  const lengthMM = toMm(raw.lengthMM, unit);
  assertFinitePositive('lengthMM', lengthMM);
  if (lengthMM < MIN_LENGTH_MM || lengthMM > MAX_LENGTH_MM) {
    throw new DiagramError('BAD_PARAM', `"lengthMM" must be between ${MIN_LENGTH_MM}mm and ${MAX_LENGTH_MM}mm for this schematic, got ${lengthMM}mm.`);
  }
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

  if (!raw.mesh || typeof raw.mesh !== 'object') {
    throw new DiagramError('BAD_PARAM', '"mesh" is required: { vertical, horizontal }.');
  }
  const vSpec = parseDirectionalMesh(raw.mesh.vertical, unit, 'mesh.vertical');
  const hSpec = parseDirectionalMesh(raw.mesh.horizontal, unit, 'mesh.horizontal');
  // Real (uncapped) bar counts — schedule's source of truth; drawn
  // (capped) counts derived at render time, same split as
  // columnDiagram.mjs's ties.count vs. MAX_DRAWN_TIES_PER_COLUMN and
  // slabDiagram.mjs's mesh countX/countY vs. MAX_MESH_ROWS/COLS.
  const vertical = { dia: vSpec.dia, spacing: vSpec.spacing, count: Math.max(2, Math.round(lengthMM / vSpec.spacing) + 1) };
  const horizontal = { dia: hSpec.dia, spacing: hSpec.spacing, count: Math.max(2, Math.round(heightMM / hSpec.spacing) + 1) };

  let boundaryElement = null;
  if (raw.boundaryElement != null) {
    const be = raw.boundaryElement;
    if (!be || typeof be !== 'object') throw new DiagramError('BAD_PARAM', '"boundaryElement" must be an object.');
    const widthMM = toMm(be.widthMM, unit);
    assertFinitePositive('boundaryElement.widthMM', widthMM);
    if (widthMM < MIN_BOUNDARY_WIDTH_MM) {
      throw new DiagramError('BAD_PARAM', `"boundaryElement.widthMM" must be at least ${MIN_BOUNDARY_WIDTH_MM}mm, got ${widthMM}mm.`);
    }
    if (widthMM * 2 >= lengthMM) {
      throw new DiagramError('BOUNDARY_EXCEEDS_LENGTH', `Two boundary elements of ${widthMM}mm each do not fit within a ${lengthMM}mm wall length (they would overlap or leave no distributed-mesh zone between them).`);
    }
    if (!be.verticalBars || typeof be.verticalBars !== 'object') {
      throw new DiagramError('BAD_PARAM', '"boundaryElement.verticalBars" is required: { diameterMM, count }.');
    }
    const barDia = toMm(be.verticalBars.diameterMM, unit);
    assertFinitePositive('boundaryElement.verticalBars.diameterMM', barDia);
    assertInt('boundaryElement.verticalBars.count', be.verticalBars.count, { min: MIN_BOUNDARY_BAR_COUNT, max: MAX_BOUNDARY_BAR_COUNT });
    if (!be.ties || typeof be.ties !== 'object') {
      throw new DiagramError('BAD_PARAM', '"boundaryElement.ties" is required: { diameterMM, spacingMM }.');
    }
    const tieDia = toMm(be.ties.diameterMM, unit);
    assertFinitePositive('boundaryElement.ties.diameterMM', tieDia);
    const tieSpacing = toMm(be.ties.spacingMM, unit);
    assertFinitePositive('boundaryElement.ties.spacingMM', tieSpacing);
    if (tieSpacing < MIN_TIE_SPACING_MM || tieSpacing > MAX_TIE_SPACING_MM) {
      throw new DiagramError('BAD_PARAM', `"boundaryElement.ties.spacingMM" must be between ${MIN_TIE_SPACING_MM}mm and ${MAX_TIE_SPACING_MM}mm (boundary-element confinement is closer-spaced than a typical column — see module scope note), got ${tieSpacing}mm.`);
    }
    const tieCount = Math.max(2, Math.round(heightMM / tieSpacing) + 1);
    boundaryElement = { widthMM, verticalBars: { dia: barDia, count: be.verticalBars.count }, ties: { dia: tieDia, spacing: tieSpacing, count: tieCount } };
  }

  return {
    type: 'shearWall', unit, id, lengthMM, heightMM, thicknessMM, coverMM,
    mesh: { vertical, horizontal }, boundaryElement,
  };
}

// ── Labels ──────────────────────────────────────────────────────────
const L = {
  en: {
    title: (id) => `SHEAR WALL ${id} \u2014 REINFORCEMENT DETAIL`,
    elevation: 'ELEVATION', section: 'SECTION',
    meshVertical: 'Mesh, vertical bars', meshHorizontal: 'Mesh, horizontal bars',
    boundaryVertical: 'Boundary element, vertical bars', boundaryTie: 'Boundary element, tie',
    boundaryLabel: 'BOUNDARY ELEMENT', extentSuffix: ' (extent)',
    perimeterSuffix: ' (bend perimeter, hooks not included)',
    tieHookNote: 'add standard hook length per code \u2014 not shown',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design (ECP 203 / ACI 318) before issuing for construction. Lengths marked "(extent)" are the drawn member length only. The boundary-element tie length shown is its bend perimeter only \u2014 add hook/lap length per your design code before fabrication.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد الحائط القص ${id}`,
    elevation: 'منظور جانبي', section: 'قطاع',
    meshVertical: 'شبكة، أسياخ رأسية', meshHorizontal: 'شبكة، أسياخ أفقية',
    boundaryVertical: 'العنصر الحدي، أسياخ رأسية', boundaryTie: 'العنصر الحدي، كانة',
    boundaryLabel: 'عنصر حدي', extentSuffix: ' امتداد',
    perimeterSuffix: ' محيط الكانة بدون الكلبتين',
    tieHookNote: 'أضف طول الكلبتين حسب الكود، غير موضح بالرسم',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. الأطوال المُعلَّمة امتداد هي طول الامتداد فقط. طول كانة العنصر الحدي المذكور هو محيط الانحناء فقط بدون الكلبتين؛ أضف طول التداخل والكلبتين حسب الكود المستخدم.',
    dirAttr: 'rtl',
  },
};

// ── Render ──────────────────────────────────────────────────────────
const CANVAS_W = 950;
const ELEV_BOX = { x: 70, y: 110, w: 520, h: 340 };
const SECTION_BOX = { x: 640, y: 110, w: 240, h: 340 };

function renderElevationView(geometry, scale, box, l) {
  const { lengthMM, heightMM, mesh, boundaryElement } = geometry;
  const w = lengthMM * scale, h = heightMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + (box.h - h) / 2;
  let svg = `<g class="elevation">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.elevation)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" class="concrete-outline"/>`;

  const drawCols = Math.min(mesh.vertical.count, MAX_MESH_COLS);
  const drawRows = Math.min(mesh.horizontal.count, MAX_MESH_ROWS);
  const xs = distributeTicks(sx, sx + w, drawCols);
  const ys = distributeTicks(sy, sy + h, drawRows);
  for (const y of ys) for (const x of xs) svg += barDot(x, y, mesh.vertical.dia, scale, 'shearwall');

  if (boundaryElement) {
    const bw = boundaryElement.widthMM * scale;
    svg += `<rect x="${sx}" y="${sy}" width="${bw}" height="${h}" class="stirrup-outline" fill="none"/>`;
    svg += `<rect x="${sx + w - bw}" y="${sy}" width="${bw}" height="${h}" class="stirrup-outline" fill="none"/>`;
    const drawTies = Math.min(boundaryElement.ties.count, MAX_DRAWN_TIES);
    for (const ty of distributeTicks(sy, sy + h, drawTies)) {
      svg += tieTickH(sx + 4, sx + bw - 4, ty);
      svg += tieTickH(sx + w - bw + 4, sx + w - 4, ty);
    }
    svg += `<text x="${sx + bw / 2}" y="${sy - 4}" text-anchor="middle" class="zone-label" dir="${l.dirAttr}">${esc(l.boundaryLabel)} ${boundaryElement.verticalBars.count}\u00d7\u00d8${Math.round(boundaryElement.verticalBars.dia)}</text>`;
    svg += `<text x="${sx + w - bw / 2}" y="${sy - 4}" text-anchor="middle" class="zone-label" dir="${l.dirAttr}">${esc(l.boundaryLabel)} ${boundaryElement.verticalBars.count}\u00d7\u00d8${Math.round(boundaryElement.verticalBars.dia)}</text>`;
  }

  svg += barMarkTag(sx + w + 24, sy + 16, `\u00d8${Math.round(mesh.vertical.dia)}@${Math.round(mesh.vertical.spacing)}`, { r: 13 });
  svg += dimensionLine(sx, sy + h + 20, sx + w, sy + h + 20, `${Math.round(lengthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 20, sy, sx - 20, sy + h, `${Math.round(heightMM)}mm`, { orientation: 'v', tick: 5 });
  svg += `<text x="${sx + w / 2}" y="${sy + h + 38}" text-anchor="middle" class="support-label">\u00d8${Math.round(mesh.horizontal.dia)}@${Math.round(mesh.horizontal.spacing)}</text>`;
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
  const nearY = sy + coverMM * scale;
  const farY = sy + stripH - coverMM * scale;
  svg += `<line x1="${sx + 6}" y1="${nearY}" x2="${sx + stripW - 6}" y2="${nearY}" class="bar-top"/>`;
  svg += `<line x1="${sx + 6}" y1="${farY}" x2="${sx + stripW - 6}" y2="${farY}" class="bar-bottom"/>`;
  for (const x of distributeTicks(sx + 14, sx + stripW - 14, 4)) {
    svg += barDot(x, nearY, mesh.vertical.dia, scale, 'shearwall');
    svg += barDot(x, farY, mesh.vertical.dia, scale, 'shearwall');
  }
  svg += dimensionLine(sx + stripW + 22, sy, sx + stripW + 22, sy + stripH, `${Math.round(thicknessMM)}mm`, { orientation: 'v', tick: 5 });
  svg += dimensionLine(sx - 20, sy, sx - 20, nearY, `${Math.round(coverMM)}mm`, { orientation: 'v', tick: 4 });
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  const { mesh, boundaryElement } = geometry;
  rows.push({ mark: 'M1', element: l.meshVertical, dia: String(Math.round(mesh.vertical.dia)), count: `${mesh.vertical.count} @ ${Math.round(mesh.vertical.spacing)}`, length: `${Math.round(geometry.heightMM)}${l.extentSuffix}` });
  rows.push({ mark: 'M2', element: l.meshHorizontal, dia: String(Math.round(mesh.horizontal.dia)), count: `${mesh.horizontal.count} @ ${Math.round(mesh.horizontal.spacing)}`, length: `${Math.round(geometry.lengthMM)}${l.extentSuffix}` });
  if (boundaryElement) {
    rows.push({ mark: 'B1', element: l.boundaryVertical, dia: String(Math.round(boundaryElement.verticalBars.dia)), count: String(boundaryElement.verticalBars.count) + ' \u00d7 2', length: `${Math.round(geometry.heightMM)}${l.extentSuffix}` });
    const tiePerimeterMM = 2 * (boundaryElement.widthMM + geometry.thicknessMM);
    rows.push({ mark: 'B2', element: l.boundaryTie, dia: String(Math.round(boundaryElement.ties.dia)), count: `@${Math.round(boundaryElement.ties.spacing)} (${boundaryElement.ties.count} \u00d7 2)`, length: `${Math.round(tiePerimeterMM)}${l.perimeterSuffix}` });
  }
  return rows;
}

export function renderShearWallDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const elevScale = fitScale([{ contentW: geometry.lengthMM, contentH: geometry.heightMM, boxW: ELEV_BOX.w - 70, boxH: ELEV_BOX.h - 80 }]);
  const sectionScale = fitScale([{ contentW: 1, contentH: geometry.thicknessMM, boxW: SECTION_BOX.w - 60, boxH: SECTION_BOX.h - 60 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = Math.max(ELEV_BOX.y + ELEV_BOX.h, SECTION_BOX.y + SECTION_BOX.h) + 70;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .wall-title  { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .zone-label  { font-size:10.5px; fill:#8a6d00; font-family: ${scriptFontStack}; }
    .bar-dot-shearwall { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="wall-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderElevationView(geometry, elevScale, ELEV_BOX, l)}
  ${renderSectionView(geometry, sectionScale, SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// ── Chat-facing entry point ────────────────────────────────────────────
export function parseShearWallRebarPayload(raw) {
  try {
    const geometry = computeShearWallDiagramGeometry(raw);
    return { ok: true, type: 'shearWall', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Step 20 (this session). Same contract/conventions as
// footingDiagram.mjs's parseDiagramCommand / slabDiagram.mjs's own copy
// — see slabDiagram.mjs's header comment on this function for the shared
// rationale (BAD_SYNTAX vs. UNSUPPORTED_TYPE split, no-quoting limit).
//
// Syntax:
//   /diagram shearwall id=W1 length=4000 height=3000 thickness=250 cover=25
//     vdia=16 vspacing=150 hdia=12 hspacing=200
//     [boundarywidth=400 boundarybardia=16 boundarybarcount=8
//      boundarytiedia=10 boundarytiespacing=100]
//     [unit=mm]
// boundaryElement is all-or-nothing, same discipline as
// footingDiagram.mjs's pedestal/dowels optionalGroup: presence of ANY
// boundary* key builds the group object and lets
// computeShearWallDiagramGeometry's own validation enforce completeness,
// rather than this parser silently guessing a default for a missing
// sub-field.
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: shearwall key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'shearwall') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use shearwall.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    let boundaryElement;
    const boundaryKeys = ['boundarywidth', 'boundarybardia', 'boundarybarcount', 'boundarytiedia', 'boundarytiespacing'];
    if (boundaryKeys.some((k) => k in kv)) {
      boundaryElement = {
        widthMM: num('boundarywidth'),
        verticalBars: { diameterMM: num('boundarybardia'), count: num('boundarybarcount') },
        ties: { diameterMM: num('boundarytiedia'), spacingMM: num('boundarytiespacing') },
      };
    }
    const geometry = computeShearWallDiagramGeometry({
      wallId: kv.id, lengthMM: num('length'), heightMM: num('height'),
      thicknessMM: num('thickness'), coverMM: num('cover'),
      mesh: {
        vertical: { diameterMM: num('vdia'), spacingMM: num('vspacing') },
        horizontal: { diameterMM: num('hdia'), spacingMM: num('hspacing') },
      },
      boundaryElement, unit: kv.unit || 'mm',
    });
    return { ok: true, type: 'shearwall', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type: 'shearwall', code: err.code, message: err.message };
    throw err;
  }
}
