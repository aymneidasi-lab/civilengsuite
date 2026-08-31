// functions/_lib/corbelDiagram.mjs
//
// New-element track (session25 gate, corrected candidate — supersedes
// the earlier "Isolated footing over pile" pick, which turned out to
// already be built as pileCapDiagram.mjs; see that file's own header).
// Deterministic, zero-AI SVG generator for a single corbel/bracket
// projecting from one face of a column, per ACI 318-19 §16.5's short-
// cantilever ("corbel") member class — the same "compute is arithmetic
// on real input, never a guess" discipline as every sibling module.
// Architecture follows columnDiagram.mjs literally (own file, own local
// `L` dict, own MIN_*/MAX_* sanity caps, compute -> render ->
// parseDiagramCommand -> parse*RebarPayload, DiagramError/kit imports
// from structuralDrawingKit.mjs), matching pileCapDiagram.mjs's own
// restatement of that same instruction.
//
// [Build-only, per explicit user instruction this session] This file
// is deliberately NOT wired into diagramCommandRouter.mjs, chat.js's
// three dispatch tables, or either footing_pro/pc_suite HTML front end.
// That wiring is this project's own documented definition of "done" for
// a new element (see برومبت_استكمال_العمل_v17.md's Part 2), and is
// skipped here only because the user explicitly asked for it to wait
// until a later file update — not because of any architectural
// blocker. Whoever performs that wiring later should follow
// pileCapDiagram.mjs's own router/chat.js entries as the direct
// template (same four-point shape: import, PARSERS[] entry,
// DIAGRAM_TYPE_RENDERERS/DIAGRAM_TYPE_ERROR_MESSAGE/
// REBAR_ELEMENT_DISPATCH entries, quick-reply menu entry in both HTML
// files) — this header flags it explicitly rather than leaving a
// future session to rediscover it silently, per this project's own
// "don't skip a Part-2 item silently" convention.
//
// This app's own chat.js already carries corbel design knowledge (see
// its "CORBELS AND SHORT CANTILEVERS — ACI 318-19 §16.5" block) used
// for conversational Q&A, and states corbel design is roadmap/not yet
// released as a drawing feature — this file is that drawing feature.
// The engineering rules cited in this header (a/d <= 1.0, no inclined
// bars, Ah adjacent to As) are taken directly from that existing block,
// not invented independently, so the two stay consistent.
//
// ── SCOPE (v1) ──────────────────────────────────────────────────────────
// Exactly ONE corbel projecting from ONE vertical face of ONE column,
// full column width (corbel width == colB, flush both side faces — no
// narrower/wider corbel). Corbel depth tapers linearly from `h` at the
// column face to `h1` at the outer tip, top face sloped, bottom face
// flat and level with the column's own bearing line. ONE bearing plate
// (rectangular, schematic only) centered at shear span `av` from the
// column face. ONE layer of main (top) tension tie bars, ONE uniform
// diameter, drawn parallel to the sloped top face at `cover` clear
// distance (see "Rendering note" below for why parallel-to-slope, not
// horizontal). Closed horizontal ties (Ah) distributed within (2/3)d of
// the column face, per this app's own cited ACI 318 §16.5 language,
// same uniform diameter.
//
// STILL NOT MODELED, on purpose (same "explicit scope boundary"
// convention every sibling module's header uses):
//   - any ACI 318 §16.5 STRENGTH check: flexure-plus-horizontal-tension
//     (Mu, Nu combined), shear (Vn = Vc), or bearing strength at the
//     plate (§22.8). This module only enforces the GEOMETRIC scope
//     boundary that defines a corbel as a corbel (av/d <= 1.0) and a
//     handful of schematic-drawability guards (taper minimum, plate-
//     within-projection, bar-room-across-width) — none of these is a
//     substitute for the actual design check, exactly as
//     pileCapDiagram.mjs's own header draws the same line for pile
//     capacity/group interaction.
//   - inclined (diagonal) shear reinforcement — deliberately excluded,
//     per this app's own chat.js text: "shown to be ineffective in
//     corbel tests." Not a gap; a documented exclusion.
//   - hanger bars / U-bar stirrup variants at the bearing plate, framing
//     bars, or any bolted/welded steel bracket connection at the plate
//     itself (only a plain schematic rectangle is drawn for the plate).
//   - the column's own real cross-section, height, or reinforcement —
//     drawn only as a proportioned stub block long enough to show the
//     corbel's anchorage into it. colB is the ONE column dimension this
//     module actually uses (it sets the corbel's own width).
//   - more than one corbel on the same column, or a corbel on more than
//     one face.
//   - non-rectangular (e.g. haunched top, dapped-end interaction) corbel
//     outlines.
//
// ── INPUT CONTRACT ───────────────────────────────────────────────────
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   corbelId?: string,                 // mark, e.g. "C-1"
//   colB: number,                      // column width == corbel width
//   projection: number,                // 'a' — total horizontal length,
//                                      // column face to outer tip
//   av: number,                       // shear span — column face to
//                                      // bearing-plate centerline
//   h: number,                         // corbel depth at column face
//   h1: number,                        // corbel depth at outer tip
//                                      // (must be < h; taper)
//   cover: number,                     // clear cover to main tie bars,
//                                      // measured perpendicular to the
//                                      // sloped top face
//   tieBarDia: number,                 // main (top) tie bar diameter
//   tieBarCount: number,               // integer, 2..8
//   stirrupDia: number,                // closed horizontal tie (Ah) dia
//   stirrupCount: number,              // integer, 1..8
//   bearingPlateWidth: number,         // plate dimension along the
//                                      // projection direction
// }
//
// ── Rendering note — why the tie bar is drawn PARALLEL to the slope ──
// A main tie bar held at a FIXED height above the flat bottom face
// (i.e. horizontal) has shrinking clearance to the sloped top face as
// x moves toward the tip, and can only keep `cover` at every x if h1 is
// implausibly close to h — checked directly by drawing both ways during
// this module's own development and confirmed geometrically, not
// assumed. Offsetting the bar a constant `cover + tieBarDia/2` inward
// from the sloped top face itself (so the bar's own line runs parallel
// to that slope) keeps correct cover at every x with no special case at
// the tip, and matches a detailing practice some corbels genuinely use
// (bar bent to follow the taper). The av/d SCOPE check below still uses
// the FACE-section effective depth d = h - cover - tieBarDia/2, per
// standard corbel notation (d is always evaluated at the column face,
// regardless of how the bar is subsequently drawn along its length).
//
// Resource lifecycle: pure/synchronous, zero state, no timers/fetch/KV/
// handles — same as every sibling module.
//
// Fully deterministic — no `env.AI`, no model call, no network fetch, no
// randomness anywhere in this file, same Step-17 statement every
// sibling module restates in its own header.

import {
  DiagramError, toMm, fmt, assertFinitePositive, assertInt,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, stirrupTick, distributeTicks,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ──────────────────────────────────────────────────────
// Own file, own values — not shared with columnDiagram.mjs/
// pileCapDiagram.mjs's own constants, per this project's per-file
// convention. Bounds worst-case loop counts/input ranges so one request
// can't build an oversized SVG or blow a Worker's CPU-time budget.
const MIN_COL_B_MM = 200;
const MAX_COL_B_MM = 1500;
const MIN_H_MM = 200;
const MAX_H_MM = 1200;
const MIN_PROJECTION_MM = 100;
const MAX_PROJECTION_MM = 900;
const MIN_TIE_BAR_COUNT = 2;   // a single top bar isn't a practical corbel tie layer
const MAX_TIE_BAR_COUNT = 8;
const MIN_STIRRUP_COUNT = 1;
const MAX_STIRRUP_COUNT = 8;
// Schematic-drawability guards ONLY — see SCOPE note above. Not a
// substitute for a real ACI 318 §16.5 design check.
const MIN_H1_FACTOR = 0.5;     // outer-tip depth >= half the face depth
const MIN_PLATE_EDGE_MM = 40;  // min clearance, plate edge to outer tip

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
    throw new DiagramError('TAPER_TOO_STEEP', `"h1" (${h1}mm) is less than ${MIN_H1_FACTOR} x "h" (${h}mm) \u2014 this schematic enforces the common corbel-detailing minimum of half-depth at the outer tip; a steeper taper is not drawable by this module.`);
  }

  assertInt('tieBarCount', raw.tieBarCount, { min: MIN_TIE_BAR_COUNT, max: MAX_TIE_BAR_COUNT });
  assertInt('stirrupCount', raw.stirrupCount, { min: MIN_STIRRUP_COUNT, max: MAX_STIRRUP_COUNT });
  const tieBarCount = raw.tieBarCount;
  const stirrupCount = raw.stirrupCount;

  // Effective depth at the column face — standard corbel notation, used
  // ONLY for this module's own av/d SCOPE boundary check, never as a
  // stand-in for the actual ACI 318 §16.5 strength design (see header).
  const d = h - cover - tieBarDia / 2;
  assertFinitePositive('effective depth (h - cover - tieBarDia/2)', d);

  if (av / d > 1.0) {
    throw new DiagramError(
      'AV_D_RATIO_EXCEEDS_SCOPE',
      `av/d = ${(av / d).toFixed(2)} exceeds 1.0 (av=${fmt(av, 'mm', 0)}, d=${fmt(d, 'mm', 0)}) \u2014 beyond this ratio the member behaves as a short beam, not a corbel (ACI 318 \u00a716.5), and is outside this module's scope.`,
    );
  }
  if (av + bearingPlateWidth / 2 + MIN_PLATE_EDGE_MM > projection) {
    throw new DiagramError(
      'BEARING_EXCEEDS_PROJECTION',
      `Bearing plate (av=${fmt(av, 'mm', 0)}, half-width=${fmt(bearingPlateWidth / 2, 'mm', 0)}) plus the minimum edge distance (${MIN_PLATE_EDGE_MM}mm) exceeds the corbel projection (${fmt(projection, 'mm', 0)}) \u2014 the plate would hang off the outer tip.`,
    );
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

// Own local helper — evenly places `count` bar centers across
// [cover+dia/2, hostWidthMM-cover-dia/2]. Same "first/last center inset
// by cover+dia/2, evenly step between" convention as
// pileCapDiagram.mjs's own local computeMeshLayer, simplified to a
// fixed bar COUNT (a corbel's tie-bar count is caller-specified
// directly, not spacing-derived).
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
// Local `L = {en:{...}, ar:{...}}` dict, per this project's own explicit
// decision (structuralLabels.mjs is footingDiagram.mjs-only; every other
// element carries its own — see columnDiagram.mjs/pileCapDiagram.mjs's
// own headers). Every Arabic value below is written parenthesis- and
// em/en-dash-free, following the same verified-safe convention (Noto
// Naskh Arabic has no glyph for either).
const L = {
  en: {
    title: (id) => `CORBEL ${id} \u2014 REINFORCEMENT DETAIL`,
    elevation: 'ELEVATION', section: 'SECTION',
    column: 'Column', mainTie: 'Main Tie Steel (As)', stirrup: 'Closed Ties (Ah)',
    plate: 'Bearing Plate',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'count',
    caption: 'Schematic corbel detail generated from the supplied data \u2014 verify per ACI 318 \u00a716.5 (or the design code governing your project) before issuing for construction. This drawing does not check flexure-plus-tension (Mu, Nu), shear (Vn = Vc), or bearing strength at the plate (\u00a722.8) \u2014 those remain the design engineer\'s responsibility. Inclined bars are not shown \u2014 ACI 318 \u00a716.5 excludes them as ineffective in corbels. Only the geometry and reinforcement layout supplied are drawn.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفصيلة تسليح الكتيفة ${id}`,
    elevation: 'الواجهة', section: 'قطاع',
    column: 'عمود', mainTie: 'حديد الشد الرئيسي', stirrup: 'الأساور المغلقة',
    plate: 'لوحة الارتكاز',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد',
    caption: 'رسم تفصيلي توضيحي للكتيفة أُنشئ من البيانات المُدخلة، للتحقق فقط وفق الكود الإنشائي المعتمد في مشروعك مثل ACI 318 قبل الاعتماد للتنفيذ. هذا الرسم لا يتحقق من الانعطاف مع الشد المحوري أو القص أو قدرة تحمل لوحة الارتكاز، وتبقى هذه مسؤولية المهندس المصمم. لا يُظهر هذا الرسم حديدا مائلا لأنه غير فعال في الكتيفات وفق نفس الكود. يُعرض هنا فقط الشكل الهندسي وتوزيع حديد التسليح المُدخل.',
    dirAttr: 'rtl',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 960;
const ELEVATION_BOX = { x: 80, y: 70, w: 800, h: 330 };
const SECTION_BOX = { x: 80, y: 440, w: 320, h: 260 };

export function renderCorbelDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);
  const { geo, tieLayer } = geometry;

  const elevScale = fitScale([{ contentW: geo.projection * 1.35, contentH: geo.h * 2.2, boxW: ELEVATION_BOX.w - 100, boxH: ELEVATION_BOX.h - 90 }]);
  const sectionScale = fitScale([{ contentW: geo.colB, contentH: geo.h, boxW: SECTION_BOX.w - 70, boxH: SECTION_BOX.h - 70 }]);

  const tableRows = buildScheduleRows(geo, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 4);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: CANVAS_W - 120 - tableColW * 3 },
  ];
  const tableY = ELEVATION_BOX.y + ELEVATION_BOX.h + SECTION_BOX.h + 30;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .corbel-title  { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .box-label     { font-size:13px; font-weight:bold; fill:#333; font-family: ${scriptFontStack}; }
    .col-rect      { fill:#e2e2e2; stroke:#1a1a1a; stroke-width:1.7; }
    .corbel-outline{ fill:#f4f4f4; stroke:#1a1a1a; stroke-width:1.7; }
    .plate-rect    { fill:#dfe9f5; stroke:#2a5a8c; stroke-width:1.4; }
    .bar-dot-tie   { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="corbel-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderElevation(geo, elevScale, l)}
  ${renderSection(geo, tieLayer, sectionScale, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

function renderElevation(geo, scale, l) {
  const { projection, av, h, h1, cover, tieBarDia, stirrupDia, stirrupCount, bearingPlateWidth, d } = geo;

  const baselineY = ELEVATION_BOX.y + ELEVATION_BOX.h - 70;
  const colStubW = Math.max(70, h * scale * 0.55);
  const colTopY = baselineY - h * scale * 1.5;
  const colBottomY = baselineY + h * scale * 0.4;
  const colLeftX = ELEVATION_BOX.x + 50;
  const faceX = colLeftX + colStubW;

  const tipX = faceX + projection * scale;
  const topFaceY = baselineY - h * scale;
  const topTipY = baselineY - h1 * scale;

  // Linear interpolation of the sloped top face's y at a given x —
  // reused for both the tie-bar offset line and the stirrup tick tops,
  // so both always stay inside the tapered outline (see header's
  // "Rendering note").
  const topYAt = (xPx) => topFaceY + ((xPx - faceX) / (tipX - faceX)) * (topTipY - topFaceY);

  const coverPx = cover * scale;
  const tieOffsetPx = (cover + tieBarDia / 2) * scale;
  const tieStartX = faceX - Math.min(30, colStubW * 0.4); // embedment into column stub
  const tieEndX = tipX - Math.max(8, coverPx * 0.6);
  const tieStartY = topYAt(faceX) + tieOffsetPx;
  const tieEndY = topYAt(tieEndX) + tieOffsetPx;
  const tieHookDropPx = Math.min(20, (baselineY - tieEndY) * 0.5);

  // Closed horizontal ties (Ah), distributed within (2/3)d of the
  // column face — see header's ACI §16.5 citation. Drawn with
  // stirrupTick() (vertical stroke, top-steel-line to bottom-steel-
  // line), the same primitive beamDiagram.mjs uses for its own
  // elevation-view stirrups on a horizontally-running member — a corbel
  // is exactly that orientation, unlike columnDiagram.mjs's vertical
  // member (which is why THAT module uses tieTickH() instead).
  const zoneEndMM = (2 / 3) * d;
  const zoneStartX = faceX + Math.max(6, coverPx * 0.5);
  const zoneEndX = faceX + zoneEndMM * scale;
  const stirrupXs = distributeTicks(zoneStartX, Math.max(zoneStartX + 1, zoneEndX), stirrupCount);
  const stirrupTicks = stirrupXs.map((x) => {
    const topY = Math.max(topYAt(Math.min(x, tipX)) + coverPx * 0.6, topFaceY);
    return stirrupTick(x, topY, baselineY - coverPx * 0.6);
  }).join('');

  const plateX = faceX + av * scale;
  const plateW = Math.max(10, bearingPlateWidth * scale);
  const plateThicknessPx = 10;
  const plateTopSurfaceY = topYAt(plateX);

  const outline = `M ${faceX},${baselineY} L ${faceX},${topFaceY} L ${tipX},${topTipY} L ${tipX},${baselineY} Z`;

  return `<g>
    <text x="${ELEVATION_BOX.x}" y="${ELEVATION_BOX.y}" class="box-label">${esc(l.elevation)}</text>
    <rect x="${colLeftX}" y="${colTopY}" width="${colStubW}" height="${colBottomY - colTopY}" class="col-rect"/>
    <path d="${outline}" class="corbel-outline"/>
    ${stirrupTicks}
    <line x1="${tieStartX}" y1="${tieStartY}" x2="${tieEndX}" y2="${tieEndY}" class="bar-top"/>
    <line x1="${tieEndX}" y1="${tieEndY}" x2="${tieEndX}" y2="${tieEndY + tieHookDropPx}" class="bar-top"/>
    <rect x="${plateX - plateW / 2}" y="${plateTopSurfaceY - plateThicknessPx}" width="${plateW}" height="${plateThicknessPx}" class="plate-rect"/>
    ${dimensionLine(faceX, baselineY + 22, plateX, baselineY + 22, `av = ${fmt(av, 'mm', 0)}`)}
    ${dimensionLine(faceX, baselineY + 46, tipX, baselineY + 46, `a = ${fmt(projection, 'mm', 0)}`)}
    ${dimensionLine(faceX - 22, topFaceY, faceX - 22, baselineY, `h = ${fmt(h, 'mm', 0)}`, { orientation: 'v' })}
    ${dimensionLine(tipX + 22, topTipY, tipX + 22, baselineY, `h1 = ${fmt(h1, 'mm', 0)}`, { orientation: 'v' })}
    <text x="${plateX}" y="${plateTopSurfaceY - plateThicknessPx - 6}" text-anchor="middle" class="dim-label">${esc(l.plate)}</text>
  </g>`;
}

function renderSection(geo, tieLayer, scale, l) {
  const { colB, h, cover, tieBarDia, stirrupDia } = geo;
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

function buildScheduleRows(geo, l) {
  return [
    { mark: '1', element: l.mainTie, dia: String(Math.round(geo.tieBarDia)), count: String(geo.tieBarCount) },
    { mark: '2', element: l.stirrup, dia: String(Math.round(geo.stirrupDia)), count: String(geo.stirrupCount) },
  ];
}

// ── Chat-facing entry point (mode:'rebarDiagram' JSON payload) ────────
// Mirrors pileCapDiagram.mjs's parsePileCapRebarPayload contract exactly.
export function parseCorbelRebarPayload(raw) {
  try {
    const geometry = computeCorbelDiagramGeometry(raw);
    return { ok: true, type: 'corbel', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Syntax:
//   /diagram corbel id=C1 colb=400 projection=350 av=150 h=500 h1=300
//     cover=40 tiebardia=16 tiebarcount=3 stirrupdia=10 stirrupcount=4
//     bearingplatewidth=150 [unit=mm]
// Accepts BOTH leading tokens "corbel" and "bracket" (screenshot's own
// English pairing, "Corbel / Bracket") and echoes back whichever one the
// caller typed — same dual-spelling convention gradeBeamDiagram.mjs uses
// for "gradebeam"/"tiebeam", for the same reason (one schematic product,
// two names in common use). Same BAD_SYNTAX/UNSUPPORTED_TYPE reservation,
// same never-throws contract, same lower-cased leading token as every
// sibling parser.
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
