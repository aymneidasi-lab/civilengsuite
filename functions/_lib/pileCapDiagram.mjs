// functions/_lib/pileCapDiagram.mjs
//
// New-element track, Part 2 (session25 gate, "Isolated footing over
// pile" / pile cap-pile group candidate). Deterministic, zero-AI SVG
// generator for a single-column pile cap — same footing family as
// footingDiagram.mjs, same "compute is arithmetic on real input, never a
// guess" discipline, but the ONE geometry footingDiagram.mjs's own
// header explicitly names as NOT modeled: a footing bearing on a
// discrete pile group instead of soil, with piles positioned anywhere
// in plan (not required centered under, or symmetric about, the
// column). Architecture follows columnDiagram.mjs literally (own file,
// own local `L` dict, own MIN_*/MAX_* sanity caps, compute -> render ->
// parseDiagramCommand -> parse*RebarPayload, DiagramError/kit imports
// from structuralDrawingKit.mjs) per this session's own instruction.
//
// ── SCOPE (v1) ──────────────────────────────────────────────────────────
// Exactly ONE rectangular column, centered in plan on a single
// rectangular cap of constant thickness (D). The pile group is 2..
// MAX_PILES piles of ONE uniform diameter, each placed at an explicit
// (offx, offy) plan position supplied by the caller — offx measured
// along L from the cap's own L=0 edge, offy measured along B from the
// cap's own B=0 edge, IDENTICAL to raft's own columns[].offx/offy
// convention in footingDiagram.mjs (see computeRaftFootingGeometry
// there) — so an asymmetric, non-grid pile layout (2 piles, 3 piles in
// an L-shape, etc.) is exactly as representable as a symmetric one; this
// module never invents a grid pattern from a bare pile count. Bottom
// reinforcement is one two-way orthogonal mesh layer (same dia both
// directions, spacingLong/spacingShort independently overridable —
// mirrors computeIsolatedFootingGeometry's own spacingLong/spacingShort
// convention in footingDiagram.mjs exactly).
//
// STILL NOT MODELED, on purpose (same "explicit scope boundary"
// convention columnDiagram.mjs's own header uses — naming a gap here,
// not guessing past it):
//   - more than one column on the cap (a multi-column pile cap is a
//     materially different plan/section problem — combined-footing-
//     over-pile is a distinct future element, not a variant of this one).
//   - pedestal and column-to-cap dowels — footingDiagram.mjs's own
//     computeFootingExtras carries these as optional extras for its four
//     soil-bearing types; this module does not carry them forward in v1.
//   - piles of more than one diameter within the same cap.
//   - pile shaft/toe below the cap, pile axial/lateral capacity, group
//     interaction (block failure), or punching-shear/one-way shear
//     design checks of any kind — every pile is drawn embedded
//     `pileEmbedMM` into the cap and stops there; nothing below the
//     cap's own underside is drawn or computed. The minimum edge-
//     distance and clear-spacing checks below (MIN_EDGE_FACTOR,
//     MIN_CLEAR_FACTOR) exist ONLY so the schematic stays drawable and
//     legible (piles don't overlap each other or hang off the cap
//     edge) — they are NOT a substitute for a real geotechnical/
//     structural pile-cap design check and must not be read as one.
//   - non-rectangular (triangular/polygonal) cap outlines.
//
// ── INPUT CONTRACT ───────────────────────────────────────────────────
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   footingId?: string,                // cap mark, e.g. "PC-1"
//   B: number, L: number, D: number,   // cap plan width(vertical)/
//                                      // length(horizontal)/thickness —
//                                      // same B/L/D convention as every
//                                      // footingDiagram.mjs type
//   colB: number, colL: number,        // column section — centered on
//                                      // the cap at (L/2, B/2)
//   cover: number,                     // concrete cover to bottom mesh
//   dia: number,                       // bottom mesh bar diameter, both
//                                      // directions (see SCOPE)
//   spacing: number,                   // nominal mesh spacing, both
//                                      // directions (isotropic default)
//   spacingLong?, spacingShort?,       // override spacing along L / B
//                                      // independently — same override
//                                      // pair isolated footing exposes
//   pileDiaMM: number,                 // one diameter, every pile
//   pileEmbedMM: number,               // every pile's embedment into
//                                      // the cap, measured up from the
//                                      // cap's own underside
//   piles: [ { offx: number, offy: number }, ... ],  // 2..MAX_PILES
// }
//
// ── Section cut ──────────────────────────────────────────────────────
// One straight cut along B = B/2 (through the column's own centerline,
// which is fixed by construction — see SCOPE). Every pile is projected
// onto that cut at its own TRUE offx — this is a representative
// elevation, not a claim that every pile's offy actually sits on the
// B/2 line, the exact same documented simplification raft's own section
// view uses for every column's depth along its chosen cut line (see
// computeRaftFootingGeometry's own header note above it in
// footingDiagram.mjs).
//
// Resource lifecycle: pure/synchronous, zero state, no timers/fetch/KV/
// handles — same as every sibling module.
//
// Fully deterministic — no `env.AI`, no model call, no network fetch, no
// randomness anywhere in this file, same as footingDiagram.mjs/
// columnDiagram.mjs's own Step 17 statement, restated here in the same
// terms per this project's own documentation convention.

import {
  DiagramError, toMm, fmt, assertFinitePositive,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ──────────────────────────────────────────────────────
// Same role as every sibling module's own MAX_*/MIN_* — bound worst-case
// loop counts and input ranges so one request can't build an oversized
// SVG or blow a Worker's CPU-time budget, and so this module never draws
// a geometry it cannot defend as physically buildable.
const MIN_CAP_SIDE_MM = 600;
const MAX_CAP_SIDE_MM = 8000;
const MIN_CAP_DEPTH_MM = 400;
const MAX_CAP_DEPTH_MM = 2500;
const MIN_PILE_DIA_MM = 250;
const MAX_PILE_DIA_MM = 1500;
const MIN_PILES = 2; // a single pile under a "cap" is just a pile — not this module's shape
const MAX_PILES = 16;
// Schematic-drawability guards ONLY — see SCOPE note above. Not a code
// check substitute.
const MIN_EDGE_FACTOR = 0.5;   // min pile-center-to-cap-edge >= 0.5 x pileDia + cover
const MIN_CLEAR_FACTOR = 0.25; // min pile-to-pile CLEAR spacing >= 0.25 x pileDia

// ── Compute ──────────────────────────────────────────────────────────
export function computePileCapDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Pile cap diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.footingId != null ? String(raw.footingId).slice(0, 40) : 'PILE CAP';

  const B = toMm(raw.B, unit);
  const L = toMm(raw.L, unit);
  const D = toMm(raw.D, unit);
  assertFinitePositive('B', B);
  assertFinitePositive('L', L);
  assertFinitePositive('D', D);
  if (B < MIN_CAP_SIDE_MM || B > MAX_CAP_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"B" must be between ${MIN_CAP_SIDE_MM}mm and ${MAX_CAP_SIDE_MM}mm for this schematic, got ${B}mm.`);
  }
  if (L < MIN_CAP_SIDE_MM || L > MAX_CAP_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"L" must be between ${MIN_CAP_SIDE_MM}mm and ${MAX_CAP_SIDE_MM}mm for this schematic, got ${L}mm.`);
  }
  if (D < MIN_CAP_DEPTH_MM || D > MAX_CAP_DEPTH_MM) {
    throw new DiagramError('BAD_PARAM', `"D" must be between ${MIN_CAP_DEPTH_MM}mm and ${MAX_CAP_DEPTH_MM}mm for this schematic, got ${D}mm.`);
  }

  const colB = toMm(raw.colB, unit);
  const colL = toMm(raw.colL, unit);
  assertFinitePositive('colB', colB);
  assertFinitePositive('colL', colL);
  if (colB >= B) throw new DiagramError('COLUMN_TOO_WIDE', `colB (${colB}mm) must be smaller than B (${B}mm).`);
  if (colL >= L) throw new DiagramError('COLUMN_TOO_WIDE', `colL (${colL}mm) must be smaller than L (${L}mm).`);

  const cover = toMm(raw.cover, unit);
  const dia = toMm(raw.dia, unit);
  const spacingLong = toMm(raw.spacingLong ?? raw.spacing, unit);
  const spacingShort = toMm(raw.spacingShort ?? raw.spacing, unit);
  for (const [name, v] of Object.entries({ cover, dia, spacingLong, spacingShort })) {
    assertFinitePositive(name, v);
  }
  const meshLong = computeMeshLayer({ hostWidthMM: L, cover, diaMM: dia, spacingMM: spacingLong });
  const meshShort = computeMeshLayer({ hostWidthMM: B, cover, diaMM: dia, spacingMM: spacingShort });

  const pileDia = toMm(raw.pileDiaMM, unit);
  assertFinitePositive('pileDiaMM', pileDia);
  if (pileDia < MIN_PILE_DIA_MM || pileDia > MAX_PILE_DIA_MM) {
    throw new DiagramError('BAD_PARAM', `"pileDiaMM" must be between ${MIN_PILE_DIA_MM}mm and ${MAX_PILE_DIA_MM}mm, got ${pileDia}mm.`);
  }
  const pileEmbed = toMm(raw.pileEmbedMM, unit);
  assertFinitePositive('pileEmbedMM', pileEmbed);
  if (pileEmbed >= D) {
    throw new DiagramError('EMBED_EXCEEDS_DEPTH', `"pileEmbedMM" (${pileEmbed}mm) must be less than the cap depth "D" (${D}mm).`);
  }

  const rawPiles = raw.piles;
  if (!Array.isArray(rawPiles) || rawPiles.length < MIN_PILES) {
    throw new DiagramError('TOO_FEW_PILES', `"piles" must list at least ${MIN_PILES} piles, got ${Array.isArray(rawPiles) ? rawPiles.length : JSON.stringify(rawPiles)}.`);
  }
  if (rawPiles.length > MAX_PILES) {
    throw new DiagramError('TOO_MANY_PILES', `Pile cap supports at most ${MAX_PILES} piles in this schematic, got ${rawPiles.length}.`);
  }

  // Edge margin deliberately does NOT include `cover` — cover already
  // governs the independent mesh-layer check above via computeMeshLayer,
  // and mixing the two would make one of them structurally unreachable
  // (a cover large enough to starve mesh room would always trip this
  // pile-edge check first, since pileDia is always >= mesh bar dia in
  // practice) — verified during this module's own compute smoke check.
  const edgeMarginMM = pileDia * MIN_EDGE_FACTOR;
  const piles = rawPiles.map((p, i) => {
    const tag = `pile${i + 1}`;
    const offx = toMm(p.offx, unit);
    const offy = toMm(p.offy, unit);
    if (!Number.isFinite(offx)) throw new DiagramError('BAD_PARAM', `"${tag}.offx" must be a finite number, got ${JSON.stringify(p.offx)}.`);
    if (!Number.isFinite(offy)) throw new DiagramError('BAD_PARAM', `"${tag}.offy" must be a finite number, got ${JSON.stringify(p.offy)}.`);
    if (offx - edgeMarginMM < 0 || offx + edgeMarginMM > L || offy - edgeMarginMM < 0 || offy + edgeMarginMM > B) {
      throw new DiagramError('PILE_OUT_OF_BOUNDS', `${tag} (offx ${offx}mm, offy ${offy}mm) leaves less than the minimum edge margin (${fmt(edgeMarginMM, 'mm', 0)}) inside the ${L}x${B}mm cap.`);
    }
    return { tag, offx, offy };
  });

  const minCenterDist = pileDia * (1 + MIN_CLEAR_FACTOR);
  for (let i = 0; i < piles.length; i++) {
    for (let j = i + 1; j < piles.length; j++) {
      const dx = piles[i].offx - piles[j].offx;
      const dy = piles[i].offy - piles[j].offy;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < minCenterDist) {
        throw new DiagramError('PILES_OVERLAP', `${piles[i].tag} and ${piles[j].tag} are ${fmt(dist, 'mm', 0)} apart, less than the minimum clear-spacing distance (${fmt(minCenterDist, 'mm', 0)}) for a ${pileDia}mm pile diameter.`);
      }
    }
  }

  // [Found during this module's own cairosvg visual verification pass —
  // NOT caught by any text-only check: a pile placed near the cap
  // center visually overlapped the column rectangle in the plan view.
  // Nothing above checks pile-vs-COLUMN clearance, only pile-vs-pile and
  // pile-vs-cap-edge — a real gap, fixed here, not silently left for a
  // future session to rediscover the same way.] Column footprint is
  // colL (along L) x colB (along B), centered at (L/2, B/2) — see SCOPE.
  // Required clearance mirrors the pile-to-pile rule above (same
  // MIN_CLEAR_FACTOR margin) applied to the nearest point of the column
  // rectangle instead of another pile's center.
  const colX0 = L / 2 - colL / 2, colX1 = L / 2 + colL / 2;
  const colY0 = B / 2 - colB / 2, colY1 = B / 2 + colB / 2;
  const minColClearance = (pileDia / 2) * (1 + MIN_CLEAR_FACTOR);
  for (const p of piles) {
    const nearestX = Math.min(Math.max(p.offx, colX0), colX1);
    const nearestY = Math.min(Math.max(p.offy, colY0), colY1);
    const dist = Math.sqrt((p.offx - nearestX) ** 2 + (p.offy - nearestY) ** 2);
    if (dist < minColClearance) {
      throw new DiagramError('COLUMN_PILE_OVERLAP', `${p.tag} (offx ${p.offx}mm, offy ${p.offy}mm) is only ${fmt(dist, 'mm', 0)} clear of the ${colL}x${colB}mm column footprint centered on the cap, less than the minimum clearance (${fmt(minColClearance, 'mm', 0)}) for a ${pileDia}mm pile diameter.`);
    }
  }

  return {
    type: 'pilecap',
    unit,
    id,
    plan: {
      B, L, D,
      column: { colB, colL, centerLongMM: L / 2, centerShortMM: B / 2 },
      piles,
      pileDia, pileEmbed,
    },
    mesh: { long: meshLong, short: meshShort },
    meta: { B, L, D, colB, colL, cover, dia, spacingLong, spacingShort, pileDia, pileEmbed },
  };
}

// Same shape and derivation as footingDiagram.mjs's own computeMeshLayer
// (own local copy, per this file's "no un-exported cross-module
// imports" constraint — footingDiagram.mjs does not export this helper).
function computeMeshLayer({ hostWidthMM, cover, diaMM, spacingMM }) {
  assertFinitePositive('mesh host width', hostWidthMM);
  assertFinitePositive('mesh cover', cover);
  assertFinitePositive('mesh dia', diaMM);
  assertFinitePositive('mesh spacing', spacingMM);
  const envelope = hostWidthMM - 2 * cover - diaMM;
  if (envelope <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${cover}mm) and mesh bar diameter (${diaMM}mm) leave no room for mesh reinforcement across a ${hostWidthMM}mm width.`);
  }
  const rawCount = Math.floor(envelope / spacingMM) + 1;
  const barCount = Math.max(2, rawCount);
  const firstCenterMM = cover + diaMM / 2;
  const lastCenterMM = hostWidthMM - cover - diaMM / 2;
  const step = barCount > 1 ? (lastCenterMM - firstCenterMM) / (barCount - 1) : 0;
  const barCentersMM = Array.from({ length: barCount }, (_, i) => firstCenterMM + i * step);
  return { diaMM, spacingMM, actualSpacingMM: step, barCount, barCentersMM };
}

// ── Labels ───────────────────────────────────────────────────────────
// Local `L = {en:{...}, ar:{...}}` dict, per this project's own explicit
// decision (structuralLabels.mjs is footingDiagram.mjs-only; every other
// element carries its own — see columnDiagram.mjs's header). Every
// Arabic value below is written parenthesis- and em/en-dash-free,
// following footingDiagram.mjs/columnDiagram.mjs's verified-safe
// convention (Noto Naskh Arabic has no glyph for either).
const L = {
  en: {
    title: (id) => `PILE CAP ${id} \u2014 REINFORCEMENT DETAIL`,
    plan: 'PLAN', section: 'SECTION',
    column: 'Column', pile: 'Pile', mesh: 'Bottom Mesh',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colPos: 'offx / offy (mm)',
    caption: 'Schematic pile cap detail generated from the supplied data \u2014 verify pile count, position, embedment, and mesh against your own design before issuing for construction. This drawing does not check pile capacity, group interaction, or punching/one-way shear \u2014 those remain the design engineer\'s responsibility. Only the piles\' embedment into the cap is shown; the pile shaft below the cap is not drawn.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفصيلة تسليح قاعدة الخوازيق ${id}`,
    plan: 'مسقط', section: 'قطاع',
    column: 'عمود', pile: 'خازوق', mesh: 'الشبكة السفلية',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colPos: 'الإزاحة السينية والصادية مم',
    caption: 'رسم تفصيلي توضيحي لقاعدة خوازيق أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع عدد الخوازيق ومواضعها وعمق تغلغلها والشبكة السفلية وفق تصميمك الخاص قبل الاعتماد للتنفيذ. هذا الرسم لا يتحقق من قدرة تحمل الخوازيق أو تفاعل المجموعة أو قص الثقب أو القص من اتجاه واحد، وتبقى هذه مسؤولية المهندس المصمم. يُظهر الرسم فقط تغلغل الخوازيق داخل القاعدة؛ جسم الخازوق أسفل القاعدة غير موضح.',
    dirAttr: 'rtl',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 960;
const PLAN_BOX = { x: 80, y: 70, w: 800, h: 300 };
const SECTION_BOX = { x: 80, y: 430, w: 800, h: 220 };

export function renderPileCapDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);
  const { B, L: capL, D, column, piles, pileDia, pileEmbed } = geometry.plan;

  const planScale = fitScale([{ contentW: capL, contentH: B, boxW: PLAN_BOX.w - 80, boxH: PLAN_BOX.h - 70 }]);
  const sectionScale = fitScale([{ contentW: capL, contentH: D + pileDia, boxW: SECTION_BOX.w - 80, boxH: SECTION_BOX.h - 70 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 4);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'pos', label: l.colPos, width: CANVAS_W - 120 - tableColW * 3 },
  ];
  const tableY = SECTION_BOX.y + SECTION_BOX.h + 50;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .pilecap-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .box-label     { font-size:13px; font-weight:bold; fill:#333; font-family: ${scriptFontStack}; }
    .pile-circle   { fill:#dfe9f5; stroke:#2a5a8c; stroke-width:1.4; }
    .col-rect      { fill:#f2f2f2; stroke:#333; stroke-width:1.6; }
    .bar-dot-mesh  { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="pilecap-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderPlan(geometry, planScale, l)}
  ${renderSection(geometry, sectionScale, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

function renderPlan(geometry, scale, l) {
  const { B, L: capL, column, piles, pileDia } = geometry.plan;
  const { mesh } = geometry;
  const px = PLAN_BOX.x + 40;
  const py = PLAN_BOX.y + 40;
  const pw = capL * scale;
  const ph = B * scale;

  const meshLines = [];
  for (const c of mesh.long.barCentersMM) {
    meshLines.push(`<line x1="${px + c * scale}" y1="${py}" x2="${px + c * scale}" y2="${py + ph}" stroke="#9ab3cf" stroke-width="0.8"/>`);
  }
  for (const c of mesh.short.barCentersMM) {
    meshLines.push(`<line x1="${px}" y1="${py + c * scale}" x2="${px + pw}" y2="${py + c * scale}" stroke="#9ab3cf" stroke-width="0.8"/>`);
  }

  const pileCircles = piles.map((p) => {
    const cx = px + p.offx * scale;
    const cy = py + p.offy * scale;
    const r = Math.max(3, (pileDia / 2) * scale);
    return `<circle cx="${cx}" cy="${cy}" r="${r}" class="pile-circle"/><text x="${cx}" y="${cy + 3}" text-anchor="middle" font-size="9" fill="#123564">${esc(p.tag)}</text>`;
  }).join('');

  const colW = column.colL * scale;
  const colH = column.colB * scale;
  const colX = px + column.centerLongMM * scale - colW / 2;
  const colY = py + column.centerShortMM * scale - colH / 2;

  return `<g>
    <text x="${PLAN_BOX.x}" y="${PLAN_BOX.y}" class="box-label">${esc(l.plan)}</text>
    <rect x="${px}" y="${py}" width="${pw}" height="${ph}" fill="#ffffff" stroke="#333" stroke-width="1.6"/>
    ${meshLines.join('\n    ')}
    ${pileCircles}
    <rect x="${colX}" y="${colY}" width="${colW}" height="${colH}" class="col-rect"/>
    ${dimensionLine(px, py + ph + 22, px + pw, py + ph + 22, `L = ${fmt(capL, 'mm', 0)}`)}
    ${dimensionLine(px - 22, py, px - 22, py + ph, `B = ${fmt(B, 'mm', 0)}`, { orientation: 'v' })}
  </g>`;
}

function renderSection(geometry, scale, l) {
  const { B, L: capL, D, column, piles, pileDia, pileEmbed } = geometry.plan;
  const sx = SECTION_BOX.x + 40;
  const sy = SECTION_BOX.y + 30;
  const sw = capL * scale;
  const capH = D * scale;
  const colTopY = sy - Math.min(60, column.colB * scale * 0.6);
  const colX = sx + column.centerLongMM * scale - (column.colL * scale) / 2;

  const pileStubs = piles.map((p) => {
    const cx = sx + p.offx * scale;
    const w = Math.max(6, pileDia * scale);
    const embedH = pileEmbed * scale;
    const topY = sy + capH - embedH;
    return `<rect x="${cx - w / 2}" y="${topY}" width="${w}" height="${embedH}" fill="#dfe9f5" stroke="#2a5a8c" stroke-width="1.2"/>`;
  }).join('\n    ');

  return `<g>
    <text x="${SECTION_BOX.x}" y="${SECTION_BOX.y}" class="box-label">${esc(l.section)}</text>
    <rect x="${sx}" y="${sy}" width="${sw}" height="${capH}" fill="#f6f6f6" stroke="#333" stroke-width="1.6"/>
    ${pileStubs}
    <rect x="${colX}" y="${colTopY}" width="${column.colL * scale}" height="${sy - colTopY}" class="col-rect"/>
    ${dimensionLine(sx + sw + 22, sy, sx + sw + 22, sy + capH, `D = ${fmt(D, 'mm', 0)}`, { orientation: 'v' })}
  </g>`;
}

function buildScheduleRows(geometry, l) {
  const { column, piles, pileDia } = geometry.plan;
  const rows = [
    {
      mark: '1', element: l.column, dia: '\u2014',
      pos: `${fmt(column.centerLongMM, 'mm', 0)} / ${fmt(column.centerShortMM, 'mm', 0)}`,
    },
  ];
  piles.forEach((p, i) => {
    rows.push({
      // Was `${l.pile} ${p.tag}` — p.tag is always the raw, language-
      // invariant identifier `pile${i+1}` (see readPiles() above and the
      // plan-view circle label, which intentionally keeps that bare tag
      // as a cross-reference ID). Concatenating it after the translated
      // l.pile word duplicated "pile" in English ("Pile pile1") and, in
      // Arabic, mixed an untranslated English word into a translated
      // cell on the same visible line ("خازوق pile1") — found by
      // actually rendering and visually inspecting the AR output, not by
      // a text-content assertion. Fixed to translated-label + plain
      // number, matching every other schedule row in this file (and the
      // sibling modules' own `${l.X} ${i+1}`-style convention) instead of
      // re-embedding the tag string.
      mark: String(i + 2), element: `${l.pile} ${i + 1}`, dia: String(Math.round(pileDia)),
      pos: `${fmt(p.offx, 'mm', 0)} / ${fmt(p.offy, 'mm', 0)}`,
    });
  });
  return rows;
}

// ── Chat-facing entry point (mode:'rebarDiagram' JSON payload) ────────
// Mirrors columnDiagram.mjs's parseColumnRebarPayload contract exactly.
export function parsePileCapRebarPayload(raw) {
  try {
    const geometry = computePileCapDiagramGeometry(raw);
    return { ok: true, type: 'pilecap', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Syntax:
//   /diagram pilecap id=PC1 B=2400 L=2400 D=900 colB=500 colL=500
//     cover=75 dia=20 spacing=150 piledia=600 pileembed=100
//     pile1x=600 pile1y=600 pile2x=1800 pile2y=600
//     pile3x=600 pile3y=1800 pile4x=1800 pile4y=1800 [unit=mm]
// Same BAD_SYNTAX/UNSUPPORTED_TYPE reservation, same never-throws
// contract, same lower-cased leading token as every sibling parser
// (diagramCommandRouter.mjs's own header note on the shearWall/
// shearwall lesson applies here too — "pilecap" one lowercase word).
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: pilecap key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'pilecap') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use pilecap.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  const pileKeys = Object.keys(kv).filter((k) => /^pile\d+x$/.test(k));
  const piles = pileKeys
    .map((k) => Number(k.match(/^pile(\d+)x$/)[1]))
    .sort((a, b) => a - b)
    .map((n) => ({ offx: num(`pile${n}x`), offy: num(`pile${n}y`) }));

  try {
    const geometry = computePileCapDiagramGeometry({
      footingId: kv.id, B: num('b'), L: num('l'), D: num('d'),
      colB: num('colb'), colL: num('coll'),
      cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
      pileDiaMM: num('piledia'), pileEmbedMM: num('pileembed'),
      piles, unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
