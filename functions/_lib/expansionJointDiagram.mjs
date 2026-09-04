// expansionJointDiagram.mjs
// Expansion / construction (movement) joint detail: PLAN showing the
// joint line running through a slab/raft/wall run with dowel spacing
// marked, and SECTION cut perpendicular through one representative
// dowel showing the gap and the debonded sleeve on the movable side.
// Distinct from every existing element (confirmed before writing this:
// no sibling module models a gap between two members, a debonded/
// sleeved bar, or a joint-line plan callout) — genuinely new geometry,
// not a variant of beamDiagram/slabDiagram/wallOpeningDiagram.
//
// v1 SCOPE:
//   - ONE straight joint line, constant gap width, constant member
//     depth on both sides (no step/offset across the joint).
//   - Dowels (if present): ONE uniform diameter/spacing/length/sleeve
//     spec for the whole run, ALL on the same side sleeved (v1
//     simplification — alternating sleeve sides is not modeled).
//   - dowels: null models a true expansion joint with NO load transfer
//     (movement-only, common for large thermal-movement joints).
// NOT modeled, on purpose: joint filler/sealant/backer-rod material
// (HATCH-dependent, same v1 exclusion every sibling's fill carries),
// waterstop, cover plate/flashing, stepped or non-straight joint lines,
// alternating dowel sleeve sides.

import {
  toMm, assertFinitePositive, assertOneOf, esc, captionLineCount,
  renderCaptionAt, fontStacks, kitStyleBlock, hatchDefs, dimensionLine,
  distributeTicks, fitScale, scheduleTable, DiagramError, svgToDataUri,
} from './structuralDrawingKit.mjs';

const MIN_RUN_MM = 1000, MAX_RUN_MM = 30000;
const MIN_GAP_MM = 10, MAX_GAP_MM = 100;
const MIN_DEPTH_MM = 150, MAX_DEPTH_MM = 2000;
const MIN_DOWEL_DIA_MM = 12, MAX_DOWEL_DIA_MM = 32;
const MIN_DOWEL_SPACING_MM = 150, MAX_DOWEL_SPACING_MM = 600;
const MIN_DOWEL_LEN_MM = 300, MAX_DOWEL_LEN_MM = 1000;
const MAX_DRAWN_DOWELS = 20; // same MAX_DRAWN_TIES_PER_ZONE-style cap every repetitive-spacing element here uses
const PANEL_HALF_DEPTH_MM = 1000; // fixed schematic plan width shown on each side of the joint line — illustrative only, same "fixed schematic constant" convention BAR_LAYER_GAP_MM (deepBeamDiagram.mjs)/STUB_OVERHANG_MM (basementWallDiagram.mjs) already use

const L = {
  en: {
    title: (id) => `EXPANSION JOINT ${id} \u2014 DETAIL`,
    plan: 'PLAN', section: 'SECTION (typ. dowel)',
    noDowels: 'NO DOWELS \u2014 FREE MOVEMENT JOINT',
    colElement: 'Element', colDia: 'dia (mm)', colSpacing: 'Spacing (mm)', colLength: 'Length (mm)',
    elDowel: 'Dowel Bar', elGap: 'Joint Gap',
    sleeveNote: (side) => `sleeved/debonded ${side} side`,
    caption: 'Schematic joint detail generated from the supplied data \u2014 verify gap width, dowel diameter/spacing/length, and sleeve length against your own design before issuing for construction. Joint filler, sealant, backer rod, and waterstop are not shown \u2014 add per your own detail standard. All dowels are drawn sleeved on the same side (v1 simplification); if sleeve side alternates in your design, adjust accordingly.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `\u0641\u0627\u0635\u0644 \u062a\u0645\u062f\u062f ${id} \u2014 \u062a\u0641\u0635\u064a\u0644\u0629`,
    plan: '\u0645\u0633\u0642\u0637', section: '\u0642\u0637\u0627\u0639 (\u0648\u062a\u062f \u0646\u0645\u0648\u0630\u062c\u064a)',
    noDowels: '\u0628\u062f\u0648\u0646 \u0623\u0648\u062a\u0627\u062f \u2014 \u0641\u0627\u0635\u0644 \u062d\u0631\u0643\u0629 \u062d\u0631',
    colElement: '\u0627\u0644\u0639\u0646\u0635\u0631', colDia: '\u0627\u0644\u0642\u0637\u0631 \u0645\u0645', colSpacing: '\u0627\u0644\u062a\u0628\u0627\u0639\u062f \u0645\u0645', colLength: '\u0627\u0644\u0637\u0648\u0644 \u0645\u0645',
    elDowel: '\u0648\u062a\u062f \u0646\u0642\u0644 \u062d\u0645\u0644', elGap: '\u0641\u062a\u062d\u0629 \u0627\u0644\u0641\u0627\u0635\u0644',
    sleeveNote: (side) => `\u0645\u063a\u0644\u0641/\u063a\u064a\u0631 \u0645\u0644\u062a\u062d\u0645 \u0645\u0646 \u062c\u0647\u0629 ${side}`,
    caption: '\u062a\u0641\u0635\u064a\u0644\u0629 \u0641\u0627\u0635\u0644 \u062a\u062e\u0637\u064a\u0637\u064a\u0629 \u0645\u0628\u0646\u064a\u0629 \u0639\u0644\u0649 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0645\u062f\u062e\u0644\u0629 \u2014 \u064a\u062c\u0628 \u0645\u0631\u0627\u062c\u0639\u0629 \u0639\u0631\u0636 \u0627\u0644\u0641\u062a\u062d\u0629 \u0648\u0642\u0637\u0631/\u062a\u0628\u0627\u0639\u062f/\u0637\u0648\u0644 \u0627\u0644\u0648\u062a\u062f \u0642\u0628\u0644 \u0627\u0644\u062a\u0646\u0641\u064a\u0630.',
    dirAttr: 'rtl',
  },
};

function fmt0(mm) { return String(Math.round(mm)); }

export function computeExpansionJointDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'computeExpansionJointDiagramGeometry expects an object.');
  }
  const unit = raw.unit || 'mm';
  assertOneOf('unit', unit, ['mm', 'cm', 'm']);
  const id = String(raw.jointId ?? raw.id ?? 'EJ1');

  const runLengthMM = toMm(raw.runLengthMM, unit);
  const gapWidthMM = toMm(raw.gapWidthMM, unit);
  const memberDepthMM = toMm(raw.memberDepthMM, unit);
  for (const [name, v, lo, hi] of [
    ['runLengthMM', runLengthMM, MIN_RUN_MM, MAX_RUN_MM],
    ['gapWidthMM', gapWidthMM, MIN_GAP_MM, MAX_GAP_MM],
    ['memberDepthMM', memberDepthMM, MIN_DEPTH_MM, MAX_DEPTH_MM],
  ]) {
    assertFinitePositive(name, v);
    if (v < lo || v > hi) throw new DiagramError('OUT_OF_RANGE', `${name} must be between ${lo} and ${hi}, got ${v}.`);
  }

  let dowels = null;
  if (raw.dowels) {
    const dia = toMm(raw.dowels.diameterMM, unit);
    assertFinitePositive('dowels.diameterMM', dia);
    if (dia < MIN_DOWEL_DIA_MM || dia > MAX_DOWEL_DIA_MM) {
      throw new DiagramError('OUT_OF_RANGE', `dowels.diameterMM must be between ${MIN_DOWEL_DIA_MM} and ${MAX_DOWEL_DIA_MM}, got ${dia}.`);
    }
    const spacing = toMm(raw.dowels.spacingMM, unit);
    assertFinitePositive('dowels.spacingMM', spacing);
    if (spacing < MIN_DOWEL_SPACING_MM || spacing > MAX_DOWEL_SPACING_MM) {
      throw new DiagramError('OUT_OF_RANGE', `dowels.spacingMM must be between ${MIN_DOWEL_SPACING_MM} and ${MAX_DOWEL_SPACING_MM}, got ${spacing}.`);
    }
    const totalLengthMM = toMm(raw.dowels.totalLengthMM, unit);
    assertFinitePositive('dowels.totalLengthMM', totalLengthMM);
    if (totalLengthMM < MIN_DOWEL_LEN_MM || totalLengthMM > MAX_DOWEL_LEN_MM) {
      throw new DiagramError('OUT_OF_RANGE', `dowels.totalLengthMM must be between ${MIN_DOWEL_LEN_MM} and ${MAX_DOWEL_LEN_MM}, got ${totalLengthMM}.`);
    }
    const sleeveLengthMM = toMm(raw.dowels.sleeveLengthMM, unit);
    assertFinitePositive('dowels.sleeveLengthMM', sleeveLengthMM);
    const embedEachSideMM = (totalLengthMM - gapWidthMM) / 2;
    if (embedEachSideMM <= 0) {
      throw new DiagramError('BAD_PARAM', `dowels.totalLengthMM (${totalLengthMM}) must exceed gapWidthMM (${gapWidthMM}) so each side has positive embedment.`);
    }
    if (sleeveLengthMM >= embedEachSideMM) {
      throw new DiagramError('OUT_OF_RANGE', `dowels.sleeveLengthMM (${sleeveLengthMM}) must be less than the per-side embedment (${embedEachSideMM.toFixed(0)}mm = (totalLengthMM-gapWidthMM)/2).`);
    }
    assertOneOf('dowels.sleeveSide', raw.dowels.sleeveSide, ['left', 'right']);

    const dowelCount = Math.max(2, Math.round(runLengthMM / spacing) + 1);
    const positionsX = distributeTicks(0, runLengthMM, Math.min(dowelCount, MAX_DRAWN_DOWELS));
    dowels = { dia, spacing, totalLengthMM, sleeveLengthMM, sleeveSide: raw.dowels.sleeveSide, embedEachSideMM, realCount: dowelCount, positionsX };
  }

  return {
    type: 'expansionJoint', unit: 'mm', id,
    runLengthMM, gapWidthMM, memberDepthMM, dowels,
  };
}

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 1100;
const PLAN_BOX = { x: 60, y: 110, w: 980, h: 220 };
const SECTION_BOX = { x: 60, y: 400, w: 980, h: 260 };

function renderPlan(geometry, scale, box, l) {
  const { runLengthMM, dowels } = geometry;
  const panelDepthPx = 2 * PANEL_HALF_DEPTH_MM * scale, runPx = runLengthMM * scale;
  const sx = box.x + (box.w - runPx) / 2;
  const sy = box.y + (box.h - panelDepthPx) / 2;
  const x = (mm) => sx + mm * scale;
  const y = (mm) => sy + mm * scale;
  const midY = y(PANEL_HALF_DEPTH_MM);

  let svg = `<g class="plan">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.plan)}</text>`;
  svg += `<rect x="${x(0)}" y="${y(0)}" width="${runPx}" height="${panelDepthPx}" class="concrete-outline"/>`;
  svg += `<line x1="${x(runLengthMM / 2)}" y1="${y(0)}" x2="${x(runLengthMM / 2)}" y2="${y(2 * PANEL_HALF_DEPTH_MM)}" class="joint-line"/>`;

  if (dowels) {
    for (const px of dowels.positionsX) svg += `<circle cx="${x(px)}" cy="${midY}" r="4" class="dowel-dot"/>`;
  } else {
    svg += `<text x="${x(runLengthMM / 2)}" y="${y(0) - 10}" text-anchor="middle" class="dim-label">${esc(l.noDowels)}</text>`;
  }

  svg += dimensionLine(x(0), y(2 * PANEL_HALF_DEPTH_MM) + 24, x(runLengthMM), y(2 * PANEL_HALF_DEPTH_MM) + 24, `run = ${fmt0(runLengthMM)}mm`);
  svg += `</g>`;
  return svg;
}

function renderSection(geometry, scale, box, l) {
  const { gapWidthMM, memberDepthMM, dowels } = geometry;
  const memberWidthMM = Math.max(gapWidthMM * 6, memberDepthMM * 1.5, 400);
  const totalWMM = 2 * memberWidthMM + gapWidthMM;
  const totalPx = totalWMM * scale, hPx = memberDepthMM * scale;
  const sx = box.x + (box.w - totalPx) / 2;
  const sy = box.y + (box.h - hPx) / 2;
  const x = (mm) => sx + mm * scale;
  const y = (mm) => sy + mm * scale;

  let svg = `<g class="section">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.section)}</text>`;
  svg += `<rect x="${x(0)}" y="${y(0)}" width="${memberWidthMM * scale}" height="${hPx}" class="concrete-outline"/>`;
  svg += `<rect x="${x(memberWidthMM + gapWidthMM)}" y="${y(0)}" width="${memberWidthMM * scale}" height="${hPx}" class="concrete-outline"/>`;

  if (dowels) {
    const midY = y(memberDepthMM / 2);
    const leftEmbedEnd = memberWidthMM - dowels.embedEachSideMM;
    const rightEmbedEnd = memberWidthMM + gapWidthMM + dowels.embedEachSideMM;
    const sleeveOnLeft = dowels.sleeveSide === 'left';
    const sleeveLo = sleeveOnLeft ? leftEmbedEnd : memberWidthMM + gapWidthMM;
    const sleeveHi = sleeveOnLeft ? memberWidthMM : memberWidthMM + gapWidthMM + dowels.sleeveLengthMM;
    svg += `<line x1="${x(leftEmbedEnd)}" y1="${midY}" x2="${x(sleeveOnLeft ? sleeveLo : memberWidthMM)}" y2="${midY}" class="dowel-bar"/>`;
    svg += `<line x1="${x(sleeveLo)}" y1="${midY}" x2="${x(sleeveHi)}" y2="${midY}" class="dowel-sleeve"/>`;
    svg += `<line x1="${x(sleeveOnLeft ? memberWidthMM + gapWidthMM : sleeveHi)}" y1="${midY}" x2="${x(rightEmbedEnd)}" y2="${midY}" class="dowel-bar"/>`;
    svg += dimensionLine(x(0), y(memberDepthMM) + 24, x(memberWidthMM), y(memberDepthMM) + 24, `\u00d8${fmt0(dowels.dia)}@${fmt0(dowels.spacing)}`);
  }

  svg += dimensionLine(x(memberWidthMM), y(0) - 16, x(memberWidthMM + gapWidthMM), y(0) - 16, `gap=${fmt0(gapWidthMM)}`);
  svg += dimensionLine(x(0) - 20, y(0), x(0) - 20, y(memberDepthMM), `d=${fmt0(memberDepthMM)}`, { orientation: 'v' });
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [{ element: l.elGap, dia: '\u2014', spacing: '\u2014', length: fmt0(geometry.gapWidthMM) }];
  if (geometry.dowels) {
    rows.push({
      element: `${l.elDowel} (${l.sleeveNote(geometry.dowels.sleeveSide)})`,
      dia: fmt0(geometry.dowels.dia), spacing: fmt0(geometry.dowels.spacing), length: fmt0(geometry.dowels.totalLengthMM),
    });
  }
  return rows;
}

export function renderExpansionJointDiagramSVG(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'expansionJoint') {
    throw new DiagramError('BAD_PARAM', 'renderExpansionJointDiagramSVG expects a geometry object from computeExpansionJointDiagramGeometry() (type "expansionJoint").');
  }
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const planScale = fitScale([{ contentW: geometry.runLengthMM, contentH: 2 * PANEL_HALF_DEPTH_MM, boxW: PLAN_BOX.w - 40, boxH: PLAN_BOX.h - 90 }]);
  const memberWidthMM = Math.max(geometry.gapWidthMM * 6, geometry.memberDepthMM * 1.5, 400);
  const sectionScale = fitScale([{ contentW: 2 * memberWidthMM + geometry.gapWidthMM, contentH: geometry.memberDepthMM, boxW: SECTION_BOX.w - 40, boxH: SECTION_BOX.h - 90 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 4);
  const tableCols = [
    { key: 'element', label: l.colElement, width: tableColW * 1.6, script: true },
    { key: 'dia', label: l.colDia, width: tableColW * 0.8 },
    { key: 'spacing', label: l.colSpacing, width: tableColW * 0.8 },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 3.2 },
  ];
  const tableY = SECTION_BOX.y + SECTION_BOX.h + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .joint-title  { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .joint-line   { stroke:#1a1a1a; stroke-width:1.6; stroke-dasharray:8,5; }
    .dowel-dot    { fill:#0e7c7b; stroke:#0b5f5e; stroke-width:0.6; }
    .dowel-bar    { stroke:#0e7c7b; stroke-width:2.4; fill:none; }
    .dowel-sleeve { stroke:#0e7c7b; stroke-width:2.4; fill:none; stroke-dasharray:5,4; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="joint-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderPlan(geometry, planScale, PLAN_BOX, l)}
  ${renderSection(geometry, sectionScale, SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// ── parseDiagramCommand ──────────────────────────────────────────────
// [RESTORED — new-element integration regression] Same gap, same fix,
// as cantileverSlabDiagram.mjs's own parseDiagramCommand header
// comment describes in full — see that file for the build-failure
// root cause and the tryNewElementDiagramParsers contract this
// satisfies.
//
//   id=<string>                  default EJ1
//   unit=mm|cm|m                 default mm
//   run=<number>                  -> runLengthMM     (required)
//   gap=<number>                  -> gapWidthMM      (required)
//   depth=<number>                -> memberDepthMM   (required)
//   dowels=DIA:SPACING:TOTALLEN:SLEEVELEN:SIDE
//     -or- doweldia=<n> dowelspacing=<n> dowellen=<n> sleevelen=<n>
//          sleeveside=left|right      (flat form; footing_pro_v94.html's
//                                      QR_EXPANSIONJOINT_EXAMPLE sends this)
//                                  -> dowels (optional; omit entirely
//                                     for a true movement-only joint
//                                     with no load transfer). SIDE is
//                                     left|right. If both forms are given,
//                                     dowels= wins.
//
// e.g. "expansionjoint id=EJ1 run=6000 gap=25 depth=250
//       dowels=20:300:600:150:left"
//  -or- "expansionjoint id=EJ1 run=6000 gap=25 depth=300 doweldia=16
//       dowelspacing=300 dowellen=500 sleevelen=150 sleeveside=left"
//
// Same three-shape return contract, same "never throws" discipline,
// as cantileverSlabDiagram.mjs's own parseDiagramCommand — see that
// file's header for the full rationale (tryNewElementDiagramParsers
// calls this with no surrounding try/catch).
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

function parseDowelsToken(v) {
  const bits = v.split(':');
  return {
    diameterMM: Number(bits[0]),
    spacingMM: Number(bits[1]),
    totalLengthMM: Number(bits[2]),
    sleeveLengthMM: Number(bits[3]),
    sleeveSide: (bits[4] || '').toLowerCase(),
  };
}

// [BUGFIX] Flat dowel tokens never reached raw.dowels, so every joint
// silently rendered as a free-movement joint. footing_pro_v94.html's
// QR_EXPANSIONJOINT_EXAMPLE/QR_EXPANSIONJOINT_FIELDS document and send
// doweldia=/dowelspacing=/dowellen=/sleevelen=/sleeveside= as five
// separate flat tokens — the same flat-token style id=/unit=/run=/gap=/
// depth= already use — but only the t.dowels branch below (a single
// combined dowels=DIA:SPACING:TOTALLEN:SLEEVELEN:SIDE token no shipped
// caller sends) ever populated raw.dowels. That QR entry shipped marked
// [UNVERIFIED]; confirmed by direct execution in Node that it produced
// geometry.dowels === null for the exact documented example command.
// Maps onto the identical raw.dowels shape computeExpansionJointDiagramGeometry
// already validates (diameterMM/spacingMM/totalLengthMM/sleeveLengthMM/
// sleeveSide) — that function is unmodified. dowels= (compact form)
// still works unchanged for any existing caller already using it;
// dowels= wins if both are present.
function parseFlatDowelTokens(t) {
  return {
    diameterMM: Number(t.doweldia),
    spacingMM: Number(t.dowelspacing),
    totalLengthMM: Number(t.dowellen),
    sleeveLengthMM: Number(t.sleevelen),
    sleeveSide: (t.sleeveside || '').toLowerCase(),
  };
}

export function parseDiagramCommand(promptText) {
  const TYPE = 'expansionjoint';
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
      jointId: t.id,
      runLengthMM: num('run'),
      gapWidthMM: num('gap'),
      memberDepthMM: num('depth'),
    };
    const hasFlatDowelTokens = t.doweldia !== undefined || t.dowelspacing !== undefined ||
      t.dowellen !== undefined || t.sleevelen !== undefined || t.sleeveside !== undefined;
    if (t.dowels !== undefined) {
      raw.dowels = parseDowelsToken(t.dowels);
    } else if (hasFlatDowelTokens) {
      raw.dowels = parseFlatDowelTokens(t);
    }

    const geometry = computeExpansionJointDiagramGeometry(raw);
    return { ok: true, type: TYPE, geometry };
  } catch (err) {
    if (err instanceof DiagramError) {
      return { ok: false, code: err.code, type: TYPE, message: err.message };
    }
    return { ok: false, code: 'BAD_PARAM', type: TYPE, message: err && err.message ? err.message : 'Could not parse expansionjoint command.' };
  }
}

export { DiagramError, svgToDataUri };
