// cantileverSlabDiagram.mjs
// Cantilever slab (balcony) reinforcement schematic: SECTION (primary —
// support, top main bars, optional shorter "top-up" bars near the
// support, nominal bottom bars, optional free-edge U-bar) + PLAN (bar
// spacing across the strip width). Distinct from slabDiagram.mjs —
// confirmed by reading its own header before writing this: that file
// is ONE flat panel with uniform top+bottom mesh and explicitly NO
// support-condition concept at all, so it cannot represent a fixed-one-
// edge/free-other-edge member or the top-steel-dominant curtailment
// pattern a cantilever actually needs (tension is at the TOP near the
// support, opposite of an ordinary simply-supported slab).
//
// v1 SCOPE:
//   - ONE straight free edge, constant thickness (no taper/haunch).
//   - Top main bars: full projection length, one uniform dia/spacing.
//   - Top "extra" bars: optional second uniform dia/spacing group,
//     curtailed at a single given length from the support (the common
//     "cut where moment allows" practice) — ONE curtailment point, not
//     a multi-step envelope.
//   - Bottom bars: one uniform nominal dia/spacing, full length.
//   - Free-edge U-bar: optional, one uniform dia/spacing, drawn as a
//     representative tick at the tip (real bend geometry not modeled —
//     same "schematic representative mark, not exact bend geometry"
//     precedent couplingBeamDiagram.mjs's own midspan section already
//     sets for its diagonal bars).
// NOT modeled, on purpose: multi-step bar curtailment envelopes, taper/
// haunch, two-way cantilever corners, drop/thickened edge, punching
// shear at a point-supported cantilever corner.

import {
  toMm, assertFinitePositive, assertOneOf, esc, captionLineCount,
  renderCaptionAt, fontStacks, kitStyleBlock, hatchDefs, dimensionLine,
  barDot, distributeTicks, fitScale, scheduleTable, DiagramError, svgToDataUri,
} from './structuralDrawingKit.mjs';

const MIN_PROJECTION_MM = 400, MAX_PROJECTION_MM = 3000; // typical balcony/cantilever-slab projection range
const MIN_THICKNESS_MM = 120, MAX_THICKNESS_MM = 400;
const MIN_WIDTH_MM = 600, MAX_WIDTH_MM = 8000;
const MIN_COVER_MM = 15, MAX_COVER_MM = 50;
const MIN_SUPPORT_MM = 150, MAX_SUPPORT_MM = 600;
const MIN_BAR_DIA_MM = 8, MAX_BAR_DIA_MM = 20;
const MIN_SPACING_MM = 75, MAX_SPACING_MM = 300;
const MAX_DRAWN_TICKS = 20; // same MAX_DRAWN_TIES_PER_ZONE-style cap every repetitive-spacing element here uses

const L = {
  en: {
    title: (id) => `CANTILEVER SLAB ${id} \u2014 REINFORCEMENT DETAIL`,
    section: 'SECTION', plan: 'PLAN',
    colElement: 'Element', colDia: 'dia (mm)', colSpacing: 'Spacing (mm)', colLength: 'Length (mm)',
    elMain: 'Top Main', elExtra: 'Top Extra (curtailed)', elBottom: 'Bottom (nominal)', elEdge: 'Free-Edge U-Bar',
    fullLenNote: 'full projection + support development',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar diameter, spacing, curtailment length, and cover against your own design before issuing for construction. Top steel is the primary (tension) reinforcement near the support; bottom bars are nominal/shrinkage steel unless your design says otherwise. Free-edge U-bar bend geometry is drawn as a representative mark only, not an exact bend detail \u2014 confirm the actual hook/bend per your own standard.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `\u0628\u0644\u0627\u0637\u0629 \u0643\u0627\u0628\u0648\u0644\u064a\u0629 ${id} \u2014 \u062a\u0641\u0635\u064a\u0644\u0629 \u0627\u0644\u062a\u0633\u0644\u064a\u062d`,
    section: '\u0642\u0637\u0627\u0639', plan: '\u0645\u0633\u0642\u0637',
    colElement: '\u0627\u0644\u0639\u0646\u0635\u0631', colDia: '\u0627\u0644\u0642\u0637\u0631 \u0645\u0645', colSpacing: '\u0627\u0644\u062a\u0628\u0627\u0639\u062f \u0645\u0645', colLength: '\u0627\u0644\u0637\u0648\u0644 \u0645\u0645',
    elMain: '\u0639\u0644\u0648\u064a \u0631\u0626\u064a\u0633\u064a', elExtra: '\u0639\u0644\u0648\u064a \u0625\u0636\u0627\u0641\u064a (\u0645\u0642\u0637\u0648\u0639)', elBottom: '\u0633\u0641\u0644\u064a (\u0627\u0633\u0645\u064a)', elEdge: '\u0648\u062a\u062f U \u0644\u0644\u062d\u0627\u0641\u0629 \u0627\u0644\u062d\u0631',
    fullLenNote: '\u0637\u0648\u0644 \u0627\u0644\u0628\u0644\u0627\u0637\u0629 \u0627\u0644\u0643\u0627\u0645\u0644 + \u0631\u0628\u0627\u0637 \u0628\u0627\u0644\u062d\u0627\u0645\u0644',
    caption: '\u062a\u0641\u0635\u064a\u0644\u0629 \u062a\u0633\u0644\u064a\u062d \u062a\u062e\u0637\u064a\u0637\u064a\u0629 \u0645\u0628\u0646\u064a\u0629 \u0639\u0644\u0649 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0645\u062f\u062e\u0644\u0629 \u2014 \u064a\u062c\u0628 \u0645\u0631\u0627\u062c\u0639\u0629 \u0643\u0644 \u0642\u0637\u0631 \u0648\u062a\u0628\u0627\u0639\u062f \u0648\u0637\u0648\u0644 \u0642\u0637\u0639 \u0648\u063a\u0637\u0627\u0621 \u0642\u0628\u0644 \u0627\u0644\u062a\u0646\u0641\u064a\u0630.',
    dirAttr: 'rtl',
  },
};

function fmt0(mm) { return String(Math.round(mm)); }

export function computeCantileverSlabDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'computeCantileverSlabDiagramGeometry expects an object.');
  }
  const unit = raw.unit || 'mm';
  assertOneOf('unit', unit, ['mm', 'cm', 'm']);
  const id = String(raw.slabId ?? raw.id ?? 'CS1');

  const projectionMM = toMm(raw.projectionMM, unit);
  const thicknessMM = toMm(raw.thicknessMM, unit);
  const widthMM = toMm(raw.widthMM, unit);
  const coverMM = toMm(raw.coverMM, unit);
  const supportWidthMM = toMm(raw.supportWidthMM, unit);
  for (const [name, v, lo, hi] of [
    ['projectionMM', projectionMM, MIN_PROJECTION_MM, MAX_PROJECTION_MM],
    ['thicknessMM', thicknessMM, MIN_THICKNESS_MM, MAX_THICKNESS_MM],
    ['widthMM', widthMM, MIN_WIDTH_MM, MAX_WIDTH_MM],
    ['coverMM', coverMM, MIN_COVER_MM, MAX_COVER_MM],
    ['supportWidthMM', supportWidthMM, MIN_SUPPORT_MM, MAX_SUPPORT_MM],
  ]) {
    assertFinitePositive(name, v);
    if (v < lo || v > hi) throw new DiagramError('OUT_OF_RANGE', `${name} must be between ${lo} and ${hi}, got ${v}.`);
  }

  function readBarSpec(spec, name) {
    if (!spec || typeof spec !== 'object') throw new DiagramError('BAD_PARAM', `${name} is required.`);
    const dia = toMm(spec.diameterMM, unit);
    assertFinitePositive(`${name}.diameterMM`, dia);
    if (dia < MIN_BAR_DIA_MM || dia > MAX_BAR_DIA_MM) {
      throw new DiagramError('OUT_OF_RANGE', `${name}.diameterMM must be between ${MIN_BAR_DIA_MM} and ${MAX_BAR_DIA_MM}, got ${dia}.`);
    }
    const spacing = toMm(spec.spacingMM, unit);
    assertFinitePositive(`${name}.spacingMM`, spacing);
    if (spacing < MIN_SPACING_MM || spacing > MAX_SPACING_MM) {
      throw new DiagramError('OUT_OF_RANGE', `${name}.spacingMM must be between ${MIN_SPACING_MM} and ${MAX_SPACING_MM}, got ${spacing}.`);
    }
    const cuttingLengthMM = spec.cuttingLengthMM != null ? toMm(spec.cuttingLengthMM, unit) : null;
    return { dia, spacing, cuttingLengthMM };
  }
  const topMainBars = readBarSpec(raw.topMainBars, 'topMainBars');
  const bottomBars = readBarSpec(raw.bottomBars, 'bottomBars');

  const devLengthMM = supportWidthMM * 0.8; // schematic embedment into the support — fixed fraction, same "fixed schematic constant" convention every sibling uses somewhere
  const tipXMM = projectionMM - coverMM;

  let topExtraBars = null;
  if (raw.topExtraBars) {
    const spec = readBarSpec(raw.topExtraBars, 'topExtraBars');
    const extraLengthMM = toMm(raw.topExtraBars.extraLengthMM, unit);
    assertFinitePositive('topExtraBars.extraLengthMM', extraLengthMM);
    if (extraLengthMM >= projectionMM) {
      throw new DiagramError('OUT_OF_RANGE', `topExtraBars.extraLengthMM (${extraLengthMM}) must be less than projectionMM (${projectionMM}) \u2014 an "extra" bar that runs the full length isn't a curtailed bar.`);
    }
    topExtraBars = { ...spec, extraLengthMM };
  }

  let edgeUBar = null;
  if (raw.edgeUBar) {
    const dia = toMm(raw.edgeUBar.diameterMM, unit);
    assertFinitePositive('edgeUBar.diameterMM', dia);
    if (dia < MIN_BAR_DIA_MM || dia > MAX_BAR_DIA_MM) {
      throw new DiagramError('OUT_OF_RANGE', `edgeUBar.diameterMM must be between ${MIN_BAR_DIA_MM} and ${MAX_BAR_DIA_MM}, got ${dia}.`);
    }
    const spacing = toMm(raw.edgeUBar.spacingMM, unit);
    assertFinitePositive('edgeUBar.spacingMM', spacing);
    if (spacing < MIN_SPACING_MM || spacing > MAX_SPACING_MM) {
      throw new DiagramError('OUT_OF_RANGE', `edgeUBar.spacingMM must be between ${MIN_SPACING_MM} and ${MAX_SPACING_MM}, got ${spacing}.`);
    }
    edgeUBar = { dia, spacing };
  }

  // Bar tick positions across the strip width — same distributeTicks
  // capped-count convention every repetitive-spacing element here uses.
  function ticksAcrossWidth(spacing) {
    const count = Math.max(2, Math.round((widthMM - 2 * coverMM) / spacing) + 1);
    return { realCount: count, positions: distributeTicks(coverMM, widthMM - coverMM, Math.min(count, MAX_DRAWN_TICKS)) };
  }
  const topMainTicks = ticksAcrossWidth(topMainBars.spacing);
  const edgeTicks = edgeUBar ? ticksAcrossWidth(edgeUBar.spacing) : null;

  return {
    type: 'cantileverSlab', unit: 'mm', id,
    projectionMM, thicknessMM, widthMM, coverMM, supportWidthMM, devLengthMM, tipXMM,
    topMainBars: { ...topMainBars, ticks: topMainTicks },
    topExtraBars, bottomBars,
    edgeUBar: edgeUBar ? { ...edgeUBar, ticks: edgeTicks } : null,
  };
}

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 1100;
const SECTION_BOX = { x: 60, y: 110, w: 980, h: 260 };
const PLAN_BOX = { x: 60, y: 400, w: 980, h: 220 };

function renderSection(geometry, scale, box, l) {
  const {
    projectionMM, thicknessMM, coverMM, supportWidthMM, devLengthMM, tipXMM,
    topMainBars, topExtraBars, bottomBars, edgeUBar,
  } = geometry;
  const totalWMM = supportWidthMM + projectionMM;
  const totalPx = totalWMM * scale, hPx = thicknessMM * scale * 3;
  const sx = box.x + (box.w - totalPx) / 2 + supportWidthMM * scale;
  const sy = box.y + (box.h - hPx) / 2 + hPx * 0.55;
  const x = (mm) => sx + mm * scale;
  const y = (mm) => sy - mm * scale;

  let svg = `<g class="section">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.section)}</text>`;

  const supOverPx = thicknessMM * 1.2 * scale;
  svg += `<rect x="${x(-supportWidthMM)}" y="${y(thicknessMM) - supOverPx}" width="${supportWidthMM * scale}" height="${thicknessMM * scale + 2 * supOverPx}" class="support-outline"/>`;
  svg += `<rect x="${x(0)}" y="${y(thicknessMM)}" width="${projectionMM * scale}" height="${thicknessMM * scale}" class="concrete-outline"/>`;

  const topY = thicknessMM - coverMM - topMainBars.dia / 2;
  svg += `<line x1="${x(-devLengthMM)}" y1="${y(topY)}" x2="${x(tipXMM)}" y2="${y(topY)}" class="bar-top"/>`;
  if (topExtraBars) {
    const extraY = topY - (topMainBars.dia / 2 + 15 + topExtraBars.dia / 2);
    svg += `<line x1="${x(-devLengthMM)}" y1="${y(extraY)}" x2="${x(topExtraBars.extraLengthMM)}" y2="${y(extraY)}" class="bar-top" stroke-dasharray="10,4"/>`;
  }
  const botY = coverMM + bottomBars.dia / 2;
  svg += `<line x1="${x(-devLengthMM)}" y1="${y(botY)}" x2="${x(tipXMM)}" y2="${y(botY)}" class="bar-bottom"/>`;

  if (edgeUBar) {
    svg += `<path d="M ${x(tipXMM - edgeUBar.dia)} ${y(botY)} L ${x(tipXMM)} ${y(botY)} Q ${x(tipXMM + edgeUBar.dia)} ${y((topY + botY) / 2)} ${x(tipXMM)} ${y(topY)} L ${x(tipXMM - edgeUBar.dia)} ${y(topY)}" class="bar-extra"/>`;
  }

  svg += dimensionLine(x(0), y(0) - 30, x(projectionMM), y(0) - 30, `projection = ${fmt0(projectionMM)}mm`);
  svg += dimensionLine(x(tipXMM) + 24, y(0), x(tipXMM) + 24, y(thicknessMM), `t=${fmt0(thicknessMM)}`, { orientation: 'v' });
  svg += `</g>`;
  return svg;
}

function renderPlan(geometry, scale, box, l) {
  const { projectionMM, widthMM, topMainBars, edgeUBar } = geometry;
  const wPx = widthMM * scale, pPx = projectionMM * scale;
  const sx = box.x + (box.w - pPx) / 2;
  const sy = box.y + (box.h - wPx) / 2;
  const x = (mm) => sx + mm * scale;
  const y = (mm) => sy + mm * scale;

  let svg = `<g class="plan">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.plan)}</text>`;
  svg += `<rect x="${x(0)}" y="${y(0)}" width="${pPx}" height="${wPx}" class="concrete-outline"/>`;
  for (const p of topMainBars.ticks.positions) svg += `<line x1="${x(0)}" y1="${y(p)}" x2="${x(projectionMM)}" y2="${y(p)}" class="web-mesh-line"/>`;
  if (edgeUBar) {
    for (const p of edgeUBar.ticks.positions) svg += `<line x1="${x(projectionMM) - 10}" y1="${y(p) - 8}" x2="${x(projectionMM) - 10}" y2="${y(p) + 8}" class="bar-extra"/>`;
  }
  svg += dimensionLine(x(0), y(widthMM) + 24, x(projectionMM), y(widthMM) + 24, `w=${fmt0(widthMM)}`);
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [
    { element: l.elMain, dia: fmt0(geometry.topMainBars.dia), spacing: fmt0(geometry.topMainBars.spacing), length: geometry.topMainBars.cuttingLengthMM != null ? fmt0(geometry.topMainBars.cuttingLengthMM) : `\u2248${fmt0(geometry.devLengthMM + geometry.projectionMM)} (${l.fullLenNote})` },
    { element: l.elBottom, dia: fmt0(geometry.bottomBars.dia), spacing: fmt0(geometry.bottomBars.spacing), length: geometry.bottomBars.cuttingLengthMM != null ? fmt0(geometry.bottomBars.cuttingLengthMM) : `\u2248${fmt0(geometry.devLengthMM + geometry.projectionMM)} (${l.fullLenNote})` },
  ];
  if (geometry.topExtraBars) {
    rows.splice(1, 0, {
      element: l.elExtra, dia: fmt0(geometry.topExtraBars.dia), spacing: fmt0(geometry.topExtraBars.spacing),
      length: geometry.topExtraBars.cuttingLengthMM != null ? fmt0(geometry.topExtraBars.cuttingLengthMM) : `\u2248${fmt0(geometry.devLengthMM + geometry.topExtraBars.extraLengthMM)}`,
    });
  }
  if (geometry.edgeUBar) {
    rows.push({ element: l.elEdge, dia: fmt0(geometry.edgeUBar.dia), spacing: fmt0(geometry.edgeUBar.spacing), length: '\u2014' });
  }
  return rows;
}

export function renderCantileverSlabDiagramSVG(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'cantileverSlab') {
    throw new DiagramError('BAD_PARAM', 'renderCantileverSlabDiagramSVG expects a geometry object from computeCantileverSlabDiagramGeometry() (type "cantileverSlab").');
  }
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const sectionScale = fitScale([{ contentW: geometry.supportWidthMM + geometry.projectionMM, contentH: geometry.thicknessMM * 3, boxW: SECTION_BOX.w - 60, boxH: SECTION_BOX.h - 90 }]);
  const planScale = fitScale([{ contentW: geometry.projectionMM, contentH: geometry.widthMM, boxW: PLAN_BOX.w - 60, boxH: PLAN_BOX.h - 90 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 4);
  const tableCols = [
    { key: 'element', label: l.colElement, width: tableColW * 1.4, script: true },
    { key: 'dia', label: l.colDia, width: tableColW * 0.85 },
    { key: 'spacing', label: l.colSpacing, width: tableColW * 0.85 },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 3.1 },
  ];
  const tableY = PLAN_BOX.y + PLAN_BOX.h + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .cant-title    { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .web-mesh-line { stroke:#9ab3cf; stroke-width:1; }
    .bar-extra     { stroke:#c2760c; stroke-width:2.2; fill:none; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="cant-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderSection(geometry, sectionScale, SECTION_BOX, l)}
  ${renderPlan(geometry, planScale, PLAN_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// ── parseDiagramCommand ──────────────────────────────────────────────
// [RESTORED — new-element integration regression] api/chat.js imports
// `parseDiagramCommand as parseCantileverSlabDiagramCommand` from this
// module (see chat.js's NEW_ELEMENT_PARSERS/tryNewElementDiagramParsers
// header for the full temporary-bypass rationale, pending this module
// joining the shared diagramCommandRouter.mjs). This file had no such
// export at all — a genuine gap, not a rename — which is why the
// Cloudflare Pages build failed with "No matching export ... for
// import parseDiagramCommand" while footingDiagram.mjs (never a source
// of this import name) built fine.
//
// Strict ASCII `cantileverslab key=value key=value ...` syntax, same
// "no NLP ambiguity on the numbers that matter" rationale
// tryNewElementDiagramParsers' own comment gives. Recognized keys map
// straight onto computeCantileverSlabDiagramGeometry's own raw shape;
// this function performs zero range/required-field validation itself
// — it assembles the raw object and relays whatever DiagramError that
// function throws (BAD_PARAM/OUT_OF_RANGE, per this module's own throw
// sites), so there is exactly one source of truth for valid ranges.
//
//   id=<string>                  default CS1
//   unit=mm|cm|m                 default mm
//   projection=<number>          -> projectionMM          (required)
//   thickness=<number>           -> thicknessMM           (required)
//   width=<number>               -> widthMM               (required)
//   cover=<number>               -> coverMM               (required)
//   support=<number>             -> supportWidthMM        (required)
//   topmaindia=<number>          -> topMainBars.diameterMM     (required)
//   topmainspacing=<number>      -> topMainBars.spacingMM      (required)
//   topmaincut=<number>          -> topMainBars.cuttingLengthMM (optional)
//   bottomdia=<number>           -> bottomBars.diameterMM      (required)
//   bottomspacing=<number>       -> bottomBars.spacingMM       (required)
//   bottomcut=<number>           -> bottomBars.cuttingLengthMM (optional)
//   topextradia/topextraspacing/topextracut/topextralen
//                                 -> topExtraBars group (optional;
//                                    attempted only if ANY of these
//                                    four keys is present)
//   edgedia/edgespacing           -> edgeUBar group (optional;
//                                    attempted if EITHER key is present)
//
// e.g. "cantileverslab id=CS1 projection=1500 thickness=200 width=3000
//       cover=25 support=300 topmaindia=12 topmainspacing=150
//       bottomdia=10 bottomspacing=200"
//
// Return shape (matches tryNewElementDiagramParsers' expectations
// exactly — see that function's own header in chat.js):
//   { ok:false, code:'BAD_SYNTAX' }                leading token isn't
//                                                   "cantileverslab" —
//                                                   caller falls through
//                                                   to the next parser.
//   { ok:false, code, type:'cantileverslab', message }
//                                                   leading token
//                                                   matched, compute*
//                                                   Geometry threw.
//   { ok:true, type:'cantileverslab', geometry }    success.
// This function never throws: tryNewElementDiagramParsers calls it
// with no surrounding try/catch (unlike the routeDiagramCommand branch
// beside it in chat.js), so a leaked exception here would 500 the
// whole /diagram request instead of falling through cleanly.
function tokenizeDiagramCommand(text) {
  const tokens = Object.create(null);
  const re = /([A-Za-z][A-Za-z0-9_]*)\s*=\s*("[^"]*"|'[^']*'|[^\s]+)/g;
  let m;
  while ((m = re.exec(text))) {
    let v = m[2];
    if (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
      v = v.slice(1, -1);
    }
    tokens[m[1].toLowerCase()] = v;
  }
  return tokens;
}

export function parseDiagramCommand(promptText) {
  const TYPE = 'cantileverslab';
  if (typeof promptText !== 'string') return { ok: false, code: 'BAD_SYNTAX' };
  const trimmed = promptText.trim();
  const spaceIdx = trimmed.search(/\s/);
  const leading = (spaceIdx === -1 ? trimmed : trimmed.slice(0, spaceIdx)).toLowerCase();
  if (leading !== TYPE) return { ok: false, code: 'BAD_SYNTAX' };

  try {
    const t = tokenizeDiagramCommand(trimmed);
    const num = (k) => (t[k] === undefined ? NaN : Number(t[k]));

    const raw = {
      unit: t.unit ? t.unit.toLowerCase() : undefined,
      slabId: t.id,
      projectionMM: num('projection'),
      thicknessMM: num('thickness'),
      widthMM: num('width'),
      coverMM: num('cover'),
      supportWidthMM: num('support'),
      topMainBars: {
        diameterMM: num('topmaindia'),
        spacingMM: num('topmainspacing'),
        cuttingLengthMM: t.topmaincut !== undefined ? num('topmaincut') : null,
      },
      bottomBars: {
        diameterMM: num('bottomdia'),
        spacingMM: num('bottomspacing'),
        cuttingLengthMM: t.bottomcut !== undefined ? num('bottomcut') : null,
      },
    };

    if (t.topextradia !== undefined || t.topextraspacing !== undefined || t.topextracut !== undefined || t.topextralen !== undefined) {
      raw.topExtraBars = {
        diameterMM: num('topextradia'),
        spacingMM: num('topextraspacing'),
        cuttingLengthMM: t.topextracut !== undefined ? num('topextracut') : null,
        extraLengthMM: num('topextralen'),
      };
    }
    if (t.edgedia !== undefined || t.edgespacing !== undefined) {
      raw.edgeUBar = { diameterMM: num('edgedia'), spacingMM: num('edgespacing') };
    }

    const geometry = computeCantileverSlabDiagramGeometry(raw);
    return { ok: true, type: TYPE, geometry };
  } catch (err) {
    if (err instanceof DiagramError) {
      return { ok: false, code: err.code, type: TYPE, message: err.message };
    }
    // Programmer-error path (malformed token stream, unexpected
    // exception shape) — never surfaced as BAD_SYNTAX (that would
    // incorrectly send a genuine "cantileverslab ..." command down to
    // routeDiagramCommand / the diffusion model instead of reporting
    // the real failure) and never rethrown (see this function's own
    // header on why tryNewElementDiagramParsers has no try/catch
    // around it).
    return { ok: false, code: 'BAD_PARAM', type: TYPE, message: err && err.message ? err.message : 'Could not parse cantileverslab command.' };
  }
}

export { DiagramError, svgToDataUri };
