// deepBeamDiagram.mjs
// Deep beam / transfer beam reinforcement schematic (ACI 318-19 §9.9 /
// ECP 203 equivalent deep-beam provisions). Distinct from both
// beamDiagram.mjs (ordinary flexural beam: longitudinal + zoned
// stirrups, no distributed web mesh — confirmed by reading its own
// header, which never mentions one) and couplingBeamDiagram.mjs
// (diagonal bar groups, seismic wall-to-wall element, confirmed by
// reading its own header/render code, which anchors into wall piers,
// not columns). Neither models a distributed horizontal+vertical web
// reinforcement mesh, which is the defining reinforcement feature of a
// deep/transfer beam (ACI 318-19 §9.9.4.1: Av and Avh minimum ratios,
// each face, spacing capped at the smaller of d/5 or 300mm). This file
// draws whatever dia/spacing the caller supplies; it does not derive or
// check that ratio itself — same "compute+render, no design" boundary
// every sibling module holds (e.g. couplingBeamDiagram.mjs never checks
// Vn against Vu).
//
// v1 SCOPE (single-span, prismatic, two end supports only):
//   - Main (tie/chord) longitudinal bars: drawn full member length, no
//     curtailment — a deep-beam tie generally needs full anchorage into
//     both supports anyway. Same "not modeled" boundary beamDiagram.mjs
//     itself documents for haunching/cranked bars.
//   - Web reinforcement (Av vertical, Avh horizontal): one uniform
//     dia+spacing pair per direction across the whole member — NOT
//     zoned like beamDiagram's stirrupZones, matching the code intent
//     that this minimum ratio applies throughout a deep beam.
//   - Multi-span continuous transfer girders, web openings, bearing-
//     plate/nodal-zone detailing, and any actual strut-and-tie force or
//     capacity check are explicitly NOT modeled.

import {
  toMm, assertFinitePositive, assertInt, assertOneOf, esc, captionLineCount,
  renderCaptionAt, fontStacks, kitStyleBlock, hatchDefs, dimensionLine,
  barDot, stirrupTick, distributeTicks, barMarkTag, fitScale, scheduleTable,
  DiagramError, svgToDataUri,
} from './structuralDrawingKit.mjs';

const MIN_SPAN_MM = 300, MAX_SPAN_MM = 12000; // deep beams are short-span by definition; capped well below beamDiagram's 60m ordinary-beam ceiling
const MIN_DEPTH_MM = 300, MAX_DEPTH_MM = 6000;
const MIN_WIDTH_MM = 150, MAX_WIDTH_MM = 2000;
const MIN_COVER_MM = 20, MAX_COVER_MM = 100;
const MIN_SUPPORT_WIDTH_MM = 150, MAX_SUPPORT_WIDTH_MM = 3000;
const MAX_MAIN_BAR_GROUPS = 12;
const MIN_MAIN_DIA_MM = 10, MAX_MAIN_DIA_MM = 40;
const MIN_MAIN_COUNT = 1, MAX_MAIN_COUNT = 20;
const MIN_WEB_DIA_MM = 8, MAX_WEB_DIA_MM = 25;
const MIN_WEB_SPACING_MM = 50, MAX_WEB_SPACING_MM = 400;
const BAR_LAYER_GAP_MM = 25; // clear gap assumed between stacked main-bar layers on the same face — fixed schematic convention, same role as this kit's other named fixed constants
const MAX_DRAWN_WEB_ROWS = 20; // representative cap on drawn horizontal web-bar rows — same MAX_DRAWN_TIES_PER_ZONE-style convention beamDiagram.mjs/couplingBeamDiagram.mjs both already use
const MAX_DRAWN_WEB_COLS = 20;

const L = {
  en: {
    title: (id) => `DEEP BEAM ${id} \u2014 REINFORCEMENT DETAIL`,
    elevation: 'ELEVATION', section: 'SECTION A-A',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    mainTag: (markId, dia, count) => `${markId} \u00d8${Math.round(dia)}-${count}`,
    elMain: (face) => (face === 'top' ? 'Top Chord' : 'Bottom Tie'),
    elWebH: 'Web Horiz. (Avh)', elWebV: 'Web Vert. (Av)',
    lenNote: 'full member length (no curtailment, v1)',
    eachFace: 'each face',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design (ECP 203 / ACI 318 \u00a79.9 deep-beam provisions) before issuing for construction. Main-bar lengths shown are full-member-length schematic extents; add development/hook/lap length per your design code before fabrication. Web reinforcement (Av, Avh) is drawn at the single uniform dia/spacing supplied \u2014 this sheet does not derive or check the ACI 318 \u00a79.9.4.1 minimum ratio itself, and does not draw a strut-and-tie model, nodal zones, or bearing plates.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `\u0643\u0645\u0631\u0629 \u0639\u0645\u064a\u0642\u0629 ${id} \u2014 \u062a\u0641\u0635\u064a\u0644\u0629 \u0627\u0644\u062a\u0633\u0644\u064a\u062d`,
    elevation: '\u0648\u0627\u062c\u0647\u0629', section: '\u0642\u0637\u0627\u0639 A-A',
    colMark: '\u0627\u0644\u0639\u0644\u0627\u0645\u0629', colElement: '\u0627\u0644\u0646\u0648\u0639', colDia: '\u0627\u0644\u0642\u0637\u0631 \u0645\u0645', colCount: '\u0627\u0644\u0639\u062f\u062f \u0623\u0648 \u0627\u0644\u062a\u0628\u0627\u0639\u062f', colLength: '\u0627\u0644\u0637\u0648\u0644 \u0645\u0645',
    mainTag: (markId, dia, count) => `${markId} \u00d8${Math.round(dia)}-${count}`,
    elMain: (face) => (face === 'top' ? '\u0631\u0628\u0627\u0637 \u0639\u0644\u0648\u064a' : '\u0631\u0628\u0627\u0637 \u0633\u0641\u0644\u064a'),
    elWebH: '\u062a\u0633\u0644\u064a\u062d \u0623\u0641\u0642\u064a', elWebV: '\u062a\u0633\u0644\u064a\u062d \u0631\u0623\u0633\u064a',
    lenNote: '\u0637\u0648\u0644 \u0627\u0644\u0639\u0646\u0635\u0631 \u0627\u0644\u0643\u0627\u0645\u0644 (\u0628\u062f\u0648\u0646 \u062a\u062f\u0627\u062e\u0644)',
    eachFace: '\u0644\u0643\u0644 \u0648\u062c\u0647',
    caption: '\u062a\u0641\u0635\u064a\u0644\u0629 \u062a\u0633\u0644\u064a\u062d \u062a\u062e\u0637\u064a\u0637\u064a\u0629 \u0645\u0628\u0646\u064a\u0629 \u0639\u0644\u0649 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0645\u062f\u062e\u0644\u0629 \u2014 \u064a\u062c\u0628 \u0645\u0631\u0627\u062c\u0639\u0629 \u0643\u0644 \u0642\u0637\u0631 \u0648\u0639\u062f\u062f \u0648\u062a\u0628\u0627\u0639\u062f \u0648\u0637\u0648\u0644 \u0645\u0642\u0627\u0628\u0644 \u062a\u0635\u0645\u064a\u0645\u0643 \u0642\u0628\u0644 \u0627\u0644\u062a\u0646\u0641\u064a\u0630. \u0647\u0630\u0627 \u0627\u0644\u0631\u0633\u0645 \u0644\u0627 \u064a\u062a\u062d\u0642\u0642 \u0648\u0644\u0627 \u064a\u0631\u0633\u0645 \u0646\u0645\u0648\u0630\u062c \u0627\u0644\u0643\u0627\u0628\u0648\u0644\u064a \u0627\u0644\u0634\u062f\u064a.',
    dirAttr: 'rtl',
  },
};

function fmt0(mm) { return String(Math.round(mm)); }

export function computeDeepBeamDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'computeDeepBeamDiagramGeometry expects an object.');
  }
  const unit = raw.unit || 'mm';
  assertOneOf('unit', unit, ['mm', 'cm', 'm']);
  const id = String(raw.beamId ?? raw.id ?? 'DB1');

  const spanClearMM = toMm(raw.spanClearMM, unit);
  const depthMM = toMm(raw.depthMM, unit);
  const widthMM = toMm(raw.widthMM, unit);
  const coverMM = toMm(raw.coverMM, unit);
  assertFinitePositive('spanClearMM', spanClearMM);
  assertFinitePositive('depthMM', depthMM);
  assertFinitePositive('widthMM', widthMM);
  assertFinitePositive('coverMM', coverMM);
  if (spanClearMM < MIN_SPAN_MM || spanClearMM > MAX_SPAN_MM) {
    throw new DiagramError('OUT_OF_RANGE', `spanClearMM must be between ${MIN_SPAN_MM} and ${MAX_SPAN_MM}, got ${spanClearMM}.`);
  }
  if (depthMM < MIN_DEPTH_MM || depthMM > MAX_DEPTH_MM) {
    throw new DiagramError('OUT_OF_RANGE', `depthMM must be between ${MIN_DEPTH_MM} and ${MAX_DEPTH_MM}, got ${depthMM}.`);
  }
  if (widthMM < MIN_WIDTH_MM || widthMM > MAX_WIDTH_MM) {
    throw new DiagramError('OUT_OF_RANGE', `widthMM must be between ${MIN_WIDTH_MM} and ${MAX_WIDTH_MM}, got ${widthMM}.`);
  }
  if (coverMM < MIN_COVER_MM || coverMM > MAX_COVER_MM) {
    throw new DiagramError('OUT_OF_RANGE', `coverMM must be between ${MIN_COVER_MM} and ${MAX_COVER_MM}, got ${coverMM}.`);
  }

  if (!Array.isArray(raw.supports) || raw.supports.length !== 2) {
    throw new DiagramError('BAD_PARAM', 'supports must be an array of exactly 2 entries (v1 scope: single span, two end supports only).');
  }
  const supportsIn = raw.supports.map((s, i) => {
    const w = toMm(s.widthMM, unit);
    assertFinitePositive(`supports[${i}].widthMM`, w);
    if (w < MIN_SUPPORT_WIDTH_MM || w > MAX_SUPPORT_WIDTH_MM) {
      throw new DiagramError('OUT_OF_RANGE', `supports[${i}].widthMM must be between ${MIN_SUPPORT_WIDTH_MM} and ${MAX_SUPPORT_WIDTH_MM}, got ${w}.`);
    }
    return { widthMM: w, label: s.label ? String(s.label) : `C${i + 1}` };
  });

  const totalLengthMM = supportsIn[0].widthMM + spanClearMM + supportsIn[1].widthMM;
  const supports = [
    { x: supportsIn[0].widthMM / 2, width: supportsIn[0].widthMM, label: supportsIn[0].label },
    { x: totalLengthMM - supportsIn[1].widthMM / 2, width: supportsIn[1].widthMM, label: supportsIn[1].label },
  ];

  if (!Array.isArray(raw.mainBars) || raw.mainBars.length < 1 || raw.mainBars.length > MAX_MAIN_BAR_GROUPS) {
    throw new DiagramError('BAD_PARAM', `mainBars must be an array of 1 to ${MAX_MAIN_BAR_GROUPS} entries.`);
  }
  const layerIndexByFace = { top: 0, bottom: 0 };
  const mainBars = raw.mainBars.map((g, i) => {
    assertOneOf(`mainBars[${i}].face`, g.face, ['top', 'bottom']);
    const dia = toMm(g.diameterMM, unit);
    assertFinitePositive(`mainBars[${i}].diameterMM`, dia);
    if (dia < MIN_MAIN_DIA_MM || dia > MAX_MAIN_DIA_MM) {
      throw new DiagramError('OUT_OF_RANGE', `mainBars[${i}].diameterMM must be between ${MIN_MAIN_DIA_MM} and ${MAX_MAIN_DIA_MM}, got ${dia}.`);
    }
    assertInt(`mainBars[${i}].count`, g.count, { min: MIN_MAIN_COUNT, max: MAX_MAIN_COUNT });
    const count = g.count;
    const cuttingLengthMM = g.cuttingLengthMM != null ? toMm(g.cuttingLengthMM, unit) : null;

    const layer = layerIndexByFace[g.face]++;
    const pitch = dia + BAR_LAYER_GAP_MM;
    const yFromTopMM = g.face === 'bottom'
      ? depthMM - coverMM - dia / 2 - layer * pitch
      : coverMM + dia / 2 + layer * pitch;

    return {
      markId: g.markId ? String(g.markId) : `M${i + 1}`,
      face: g.face, dia, count, layer, yFromTopMM, cuttingLengthMM,
      startX: 0, endX: totalLengthMM,
    };
  });

  for (const face of ['top', 'bottom']) {
    const group = mainBars.filter((g) => g.face === face);
    if (group.length === 0) continue;
    const innermost = group.reduce((a, b) => (a.layer > b.layer ? a : b));
    const edge = innermost.yFromTopMM + (face === 'bottom' ? innermost.dia / 2 : -innermost.dia / 2);
    if (face === 'bottom' && edge < depthMM * 0.15) {
      throw new DiagramError('BAR_ENVELOPE_OVERFLOW', `Stacked bottom main-bar layers (${group.length}) overflow past 85% of depthMM=${depthMM} with the supplied cover/diameters/gap \u2014 reduce layer count or increase depthMM.`);
    }
    if (face === 'top' && edge > depthMM * 0.85) {
      throw new DiagramError('BAR_ENVELOPE_OVERFLOW', `Stacked top main-bar layers (${group.length}) overflow past 85% of depthMM=${depthMM} with the supplied cover/diameters/gap \u2014 reduce layer count or increase depthMM.`);
    }
  }

  const wr = raw.webReinforcement;
  if (!wr || typeof wr !== 'object' || !wr.horizontal || !wr.vertical) {
    throw new DiagramError('BAD_PARAM', 'webReinforcement.horizontal and webReinforcement.vertical are both required.');
  }
  function readWebSpec(spec, name) {
    const dia = toMm(spec.diameterMM, unit);
    assertFinitePositive(`webReinforcement.${name}.diameterMM`, dia);
    if (dia < MIN_WEB_DIA_MM || dia > MAX_WEB_DIA_MM) {
      throw new DiagramError('OUT_OF_RANGE', `webReinforcement.${name}.diameterMM must be between ${MIN_WEB_DIA_MM} and ${MAX_WEB_DIA_MM}, got ${dia}.`);
    }
    const spacing = toMm(spec.spacingMM, unit);
    assertFinitePositive(`webReinforcement.${name}.spacingMM`, spacing);
    if (spacing < MIN_WEB_SPACING_MM || spacing > MAX_WEB_SPACING_MM) {
      throw new DiagramError('OUT_OF_RANGE', `webReinforcement.${name}.spacingMM must be between ${MIN_WEB_SPACING_MM} and ${MAX_WEB_SPACING_MM}, got ${spacing}.`);
    }
    const cuttingLengthMM = spec.cuttingLengthMM != null ? toMm(spec.cuttingLengthMM, unit) : null;
    return { dia, spacing, cuttingLengthMM };
  }
  const horizontalSpec = readWebSpec(wr.horizontal, 'horizontal');
  const verticalSpec = readWebSpec(wr.vertical, 'vertical');

  // Horizontal (Avh) rows fill the clear band between the innermost
  // bottom-face layer and the innermost top-face layer (the region
  // ACI 318 §9.9.4.1 actually requires Avh in — not the full depth).
  const bottomGroup = mainBars.filter((g) => g.face === 'bottom');
  const topGroup = mainBars.filter((g) => g.face === 'top');
  const bottomInnerY = bottomGroup.length
    ? Math.min(...bottomGroup.map((g) => g.yFromTopMM - g.dia / 2 - BAR_LAYER_GAP_MM))
    : depthMM - coverMM;
  const topInnerY = topGroup.length
    ? Math.max(...topGroup.map((g) => g.yFromTopMM + g.dia / 2 + BAR_LAYER_GAP_MM))
    : coverMM;
  if (bottomInnerY <= topInnerY) {
    throw new DiagramError('BAR_ENVELOPE_OVERFLOW', 'No clear band remains between top and bottom main-bar layers for web (Avh) reinforcement \u2014 reduce main-bar layer count or increase depthMM.');
  }
  const webBandHeightMM = bottomInnerY - topInnerY;
  const horizontalRowCount = Math.max(2, Math.round(webBandHeightMM / horizontalSpec.spacing) + 1);
  const rowYsFromTopMM = distributeTicks(topInnerY, bottomInnerY, Math.min(horizontalRowCount, MAX_DRAWN_WEB_ROWS));

  // Vertical (Av) columns fill the clear span between the two support
  // inner faces (the region actually free of support bearing).
  const webSpanLo = supports[0].x + supports[0].width / 2;
  const webSpanHi = supports[1].x - supports[1].width / 2;
  if (webSpanHi <= webSpanLo) {
    throw new DiagramError('BAD_PARAM', 'supports leave no clear span between their inner faces \u2014 reduce support widths or increase spanClearMM.');
  }
  const verticalColCount = Math.max(2, Math.round((webSpanHi - webSpanLo) / verticalSpec.spacing) + 1);
  const colXs = distributeTicks(webSpanLo, webSpanHi, Math.min(verticalColCount, MAX_DRAWN_WEB_COLS));

  const section = { b: widthMM, h: depthMM };
  const sectionMainBars = [];
  for (const g of mainBars) {
    const usable = widthMM - 2 * coverMM - g.dia;
    const xs = g.count === 1 ? [widthMM / 2] : Array.from({ length: g.count }, (_, k) => coverMM + g.dia / 2 + (usable * k) / (g.count - 1));
    for (const xMM of xs) sectionMainBars.push({ face: g.face, xMM, yFromTopMM: g.yFromTopMM, dia: g.dia });
  }
  const sectionWebBars = [];
  const nearX = coverMM + verticalSpec.dia / 2;
  const farX = widthMM - coverMM - verticalSpec.dia / 2;
  for (const yFromTopMM of rowYsFromTopMM) {
    sectionWebBars.push({ side: 'near', xMM: nearX, yFromTopMM, dia: horizontalSpec.dia });
    sectionWebBars.push({ side: 'far', xMM: farX, yFromTopMM, dia: horizontalSpec.dia });
  }

  return {
    type: 'deepBeam', unit: 'mm', id,
    spanClearMM, depthMM, widthMM, coverMM, totalLengthMM,
    supports, mainBars,
    webReinforcement: {
      horizontal: { ...horizontalSpec, realRowCount: horizontalRowCount, rowYsFromTopMM },
      vertical: { ...verticalSpec, realColCount: verticalColCount, colXs },
    },
    section, sections: [{ label: 'A-A', mainBars: sectionMainBars, webBars: sectionWebBars }],
  };
}

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 1100;
const ELEV_BOX = { x: 60, y: 110, w: 760, h: 280 };
const SECTION_BOX = { x: 860, y: 110, w: 190, h: 280 };
const MAX_DRAWN_TIES = MAX_DRAWN_WEB_COLS; // shares the same 20-cap used at compute time

function renderElevation(geometry, scale, box, l) {
  const { totalLengthMM, depthMM, coverMM, supports, mainBars, webReinforcement } = geometry;
  const totalPx = totalLengthMM * scale, h = depthMM * scale;
  const sx = box.x + (box.w - totalPx) / 2;
  const sy = box.y + (box.h - h) / 2;
  const x = (mm) => sx + mm * scale;
  const y = (mm) => sy + mm * scale;
  const overhangPx = depthMM * 0.15 * scale;

  let svg = `<g class="elevation">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.elevation)}</text>`;

  for (const s of supports) {
    const lo = x(s.x - s.width / 2), hi = x(s.x + s.width / 2);
    svg += `<rect x="${lo}" y="${sy - overhangPx}" width="${hi - lo}" height="${h + 2 * overhangPx}" class="support-outline"/>`;
    svg += `<text x="${(lo + hi) / 2}" y="${sy + h + overhangPx + 16}" text-anchor="middle" class="dim-label">${esc(s.label)}</text>`;
  }

  svg += `<rect x="${x(0)}" y="${sy}" width="${totalPx}" height="${h}" class="concrete-outline"/>`;

  for (const yFromTopMM of webReinforcement.horizontal.rowYsFromTopMM) {
    svg += `<line x1="${x(0)}" y1="${y(yFromTopMM)}" x2="${x(totalLengthMM)}" y2="${y(yFromTopMM)}" class="web-mesh-line"/>`;
  }
  const tieTopY = coverMM * 0.5, tieBotY = depthMM - coverMM * 0.5;
  for (const xMM of webReinforcement.vertical.colXs) {
    svg += stirrupTick(x(xMM), y(tieTopY), y(tieBotY));
  }

  for (const g of mainBars) {
    const yy = y(g.yFromTopMM);
    const cls = g.face === 'top' ? 'bar-top' : 'bar-bottom';
    svg += `<line x1="${x(g.startX)}" y1="${yy}" x2="${x(g.endX)}" y2="${yy}" class="${cls}"/>`;
    const tagY = g.face === 'top' ? yy - 16 : yy + 16;
    svg += barMarkTag((x(g.startX) + x(g.endX)) / 2, tagY, l.mainTag(g.markId, g.dia, g.count), { r: 12 });
  }

  svg += dimensionLine(x(0), sy + h + overhangPx + 34, x(totalLengthMM), sy + h + overhangPx + 34, `L = ${fmt0(totalLengthMM)}mm`);
  svg += `</g>`;
  return svg;
}

function renderSection(geometry, scale, box, l) {
  const { b, h } = geometry.section;
  const sec = geometry.sections[0];
  const bPx = b * scale, hPx = h * scale;
  const sx = box.x + (box.w - bPx) / 2;
  const sy = box.y + (box.h - hPx) / 2;
  const x = (mm) => sx + mm * scale;
  const y = (mm) => sy + mm * scale;

  let svg = `<g class="section">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.section)}</text>`;
  svg += `<rect x="${x(0)}" y="${y(0)}" width="${bPx}" height="${hPx}" class="concrete-outline"/>`;
  for (const bar of sec.webBars) svg += barDot(x(bar.xMM), y(bar.yFromTopMM), bar.dia, scale, 'web');
  for (const bar of sec.mainBars) svg += barDot(x(bar.xMM), y(bar.yFromTopMM), bar.dia, scale, bar.face);
  svg += dimensionLine(x(0), y(0) - 20, x(b), y(0) - 20, `b=${fmt0(b)}`);
  svg += dimensionLine(x(0) - 20, y(0), x(0) - 20, y(h), `h=${fmt0(h)}`, { orientation: 'v' });
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  for (const g of geometry.mainBars) {
    rows.push({
      mark: g.markId, element: l.elMain(g.face), dia: fmt0(g.dia), count: String(g.count),
      length: g.cuttingLengthMM != null ? fmt0(g.cuttingLengthMM) : `${fmt0(g.endX - g.startX)} (${l.lenNote})`,
    });
  }
  const wh = geometry.webReinforcement.horizontal;
  rows.push({
    mark: 'Avh', element: l.elWebH, dia: fmt0(wh.dia), count: `@${fmt0(wh.spacing)}mm ${l.eachFace}`,
    length: wh.cuttingLengthMM != null ? fmt0(wh.cuttingLengthMM) : `${fmt0(geometry.totalLengthMM)} (${l.lenNote})`,
  });
  const wv = geometry.webReinforcement.vertical;
  rows.push({
    mark: 'Av', element: l.elWebV, dia: fmt0(wv.dia), count: `@${fmt0(wv.spacing)}mm ${l.eachFace}`,
    length: wv.cuttingLengthMM != null ? fmt0(wv.cuttingLengthMM) : `${fmt0(geometry.depthMM)} (${l.lenNote})`,
  });
  return rows;
}

export function renderDeepBeamDiagramSVG(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'deepBeam') {
    throw new DiagramError('BAD_PARAM', 'renderDeepBeamDiagramSVG expects a geometry object from computeDeepBeamDiagramGeometry() (type "deepBeam").');
  }
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const elevScale = fitScale([{ contentW: geometry.totalLengthMM, contentH: geometry.depthMM * 1.5, boxW: ELEV_BOX.w - 60, boxH: ELEV_BOX.h - 90 }]);
  const sectionScale = fitScale([{ contentW: geometry.section.b, contentH: geometry.section.h, boxW: SECTION_BOX.w - 60, boxH: SECTION_BOX.h - 60 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW, script: true },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = ELEV_BOX.y + ELEV_BOX.h + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .deepbeam-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .web-mesh-line   { stroke:#9ab3cf; stroke-width:1; }
    .bar-dot-web     { fill:#6b7280; stroke:#374151; stroke-width:0.6; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="deepbeam-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderElevation(geometry, elevScale, ELEV_BOX, l)}
  ${renderSection(geometry, sectionScale, SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

export { DiagramError, svgToDataUri };
