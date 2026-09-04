// functions/_lib/raftPileDiagram.mjs
//
// New-element track, candidate "Raft over pile" (لبشة فوق خوازيق) from
// this session's documented candidate pool. Deterministic, zero-AI SVG
// generator for a multi-column raft (mat) foundation bearing on a
// discrete pile field instead of soil. Architecture follows
// columnDiagram.mjs literally (own file, own local `L` dict, own
// MIN_*/MAX_* sanity caps, compute -> render -> parseDiagramCommand ->
// parse*RebarPayload, DiagramError/kit imports from
// structuralDrawingKit.mjs), same discipline pileCapDiagram.mjs's own
// header states for itself.
//
// ── WHY THIS IS A NEW FILE, NOT A VARIANT OF AN EXISTING ONE ──────────
// footingDiagram.mjs's own 'raft' type already supports 2..MAX_COLUMNS
// columns positioned anywhere in plan — but it bears on soil and has no
// pile concept anywhere in its schema (see that file's own SCOPE
// paragraph on 'raft'). pileCapDiagram.mjs already supports an arbitrary
// discrete pile field — but its own header explicitly scopes itself to
// EXACTLY ONE column and names "more than one column on the cap" as
// "a materially different plan/section problem ... not a variant of
// this one" (see that file's STILL NOT MODELED section). Neither
// sibling models "N columns AND a pile field at once" — that gap is
// this file's entire reason to exist, not a refactor of either.
//
// ── SCOPE (v1) ──────────────────────────────────────────────────────────
// 2..MAX_COLUMNS rectangular columns, each positioned anywhere in plan
// (offx/offy, IDENTICAL convention to footingDiagram.mjs's own raft
// columns[].offx/offy — offx from the raft's own L=0 edge, offy from its
// own B=0 edge), on ONE rectangular raft slab of constant thickness (D).
// The pile field is 2..MAX_PILES piles of ONE uniform diameter, each at
// an explicit (offx, offy) plan position — IDENTICAL convention to
// pileCapDiagram.mjs's own piles[].offx/offy: this module never invents
// a grid pattern from a bare pile count, exactly as that file documents
// for its own single-column case. Bottom reinforcement is one two-way
// orthogonal mesh layer (same dia both directions, spacingLong/
// spacingShort independently overridable — copied from
// pileCapDiagram.mjs's own computeMeshLayer convention verbatim, not
// footingDiagram raft's isotropic-only `spacing`, since this module's
// nearer sibling for the "piles" half of its scope is pileCapDiagram.mjs).
//
// STILL NOT MODELED, on purpose (same "explicit scope boundary"
// convention pileCapDiagram.mjs's own header uses — naming a gap here,
// not guessing past it):
//   - pedestal and column-to-raft dowels for any column — neither
//     sibling this module draws from (footingDiagram raft's own
//     computeFootingExtras, pileCapDiagram.mjs) carries these forward
//     into this file; v1 draws bottom mesh only, same as
//     pileCapDiagram.mjs's own v1 decision.
//   - piles of more than one diameter within the same raft.
//   - pile shaft/toe below the raft, pile axial/lateral capacity, group
//     interaction (block failure), or punching-shear/one-way shear
//     design checks of any kind — every pile is drawn embedded
//     `pileEmbedMM` into the raft and stops there, identical to
//     pileCapDiagram.mjs's own documented limit. The minimum edge-
//     distance and clear-spacing checks below (MIN_EDGE_FACTOR,
//     MIN_CLEAR_FACTOR) exist ONLY so the schematic stays drawable and
//     legible — they are NOT a substitute for a real geotechnical/
//     structural design check and must not be read as one.
//   - non-rectangular (triangular/polygonal) raft outlines.
//   - a per-column "sectionThrough" selector (unlike footingDiagram
//     raft's own sectionThrough, which cuts through exactly one chosen
//     column). With an arbitrary pile field spread across the whole
//     footprint, isolating one column's local cut is less informative
//     than showing every column and every pile at once — see the
//     Section-cut note below for the deliberate design this module uses
//     instead.
//
// ── INPUT CONTRACT ───────────────────────────────────────────────────
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   footingId?: string,                // raft mark, e.g. "RP-1"
//   B: number, L: number, D: number,   // raft plan width(vertical)/
//                                      // length(horizontal)/thickness —
//                                      // same B/L/D convention as every
//                                      // footingDiagram.mjs type,
//                                      // including its own 'raft'.
//   columns: [ { b, l, offx, offy }, ... ],  // 2..MAX_COLUMNS — b/l are
//                                      // the column's plan cross-section
//                                      // (b along B, l along L, IDENTICAL
//                                      // to footingDiagram.mjs's own raft
//                                      // columns[] fields); offx/offy are
//                                      // the column centerline's distance
//                                      // from the L=0 / B=0 edges.
//   cover: number,                     // concrete cover to bottom mesh
//   dia: number,                       // bottom mesh bar diameter, both
//                                      // directions (see SCOPE)
//   spacing: number,                   // nominal mesh spacing, both
//                                      // directions (isotropic default)
//   spacingLong?, spacingShort?,       // override spacing along L / B
//                                      // independently — same override
//                                      // pair pileCapDiagram.mjs exposes
//   pileDiaMM: number,                 // one diameter, every pile
//   pileEmbedMM: number,               // every pile's embedment into
//                                      // the raft, measured up from the
//                                      // raft's own underside
//   piles: [ { offx: number, offy: number }, ... ],  // 2..MAX_PILES
// }
//
// ── Section cut ──────────────────────────────────────────────────────
// One straight longitudinal cut sweeping the full L extent. EVERY column
// and EVERY pile is projected onto that cut at its own TRUE offx — a
// representative elevation showing the whole footprint's column and pile
// layout along L, not a claim that any given column or pile's actual
// offy sits on one specific B-line. This is the same documented
// simplification pileCapDiagram.mjs's own section view uses for its
// piles (see that file's own "Section cut" header note), generalized
// here from one column to N.
//
// Resource lifecycle: pure/synchronous, zero state, no timers/fetch/KV/
// handles — same as every sibling module.
//
// Fully deterministic — no `env.AI`, no model call, no network fetch, no
// randomness anywhere in this file, same as every sibling module's own
// Step 17 statement, restated here in the same terms per this project's
// own documentation convention.

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
const MIN_RAFT_DEPTH_MM = 400;
const MAX_RAFT_DEPTH_MM = 3000; // wider than pileCapDiagram.mjs's own
  // MAX_CAP_DEPTH_MM (2500) — a raft spanning many columns legitimately
  // runs thicker than a single-column pile cap; B/L themselves are left
  // unbounded beyond assertFinitePositive, matching footingDiagram.mjs's
  // own 'raft' type exactly (that file imposes no B/L ceiling either —
  // only MAX_COLUMNS below), since fitScale() renders any plan extent at
  // a consistent scale regardless of absolute size.
const MAX_COLUMNS = 12; // identical cap and identical rationale to
  // footingDiagram.mjs's own MAX_COLUMNS — this is a single ASCII
  // command string with a 2000-char server-side limit, not a CAD system.
const MIN_PILE_DIA_MM = 250;
const MAX_PILE_DIA_MM = 1500;
const MIN_PILES = 2; // a single pile is just a pile — not this module's
  // shape, same reasoning pileCapDiagram.mjs states for its own MIN_PILES.
const MAX_PILES = 60; // higher than pileCapDiagram.mjs's own 16 — a raft
  // spans a whole footprint under several columns, not one column's
  // local group, so a materially larger field is the expected case, not
  // an edge case. Worst-case loop cost stays cheap either way: the
  // pairwise pile-overlap check below is O(n^2) = 3600 at the cap, and
  // the column-vs-pile check is O(columns x piles) = 12 x 60 = 720 —
  // both trivial against a Worker's CPU budget.
// Schematic-drawability guards ONLY — see SCOPE note above. Not a code
// check substitute. Values copied verbatim from pileCapDiagram.mjs — same
// physical clearance logic, same reasoning.
const MIN_EDGE_FACTOR = 0.5;   // min pile-center-to-raft-edge >= 0.5 x pileDia + cover
const MIN_CLEAR_FACTOR = 0.25; // min pile-to-pile / pile-to-column CLEAR spacing >= 0.25 x pileDia

// ── Compute ──────────────────────────────────────────────────────────
export function computeRaftPileDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Raft-over-pile diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.footingId != null ? String(raw.footingId).slice(0, 40) : 'RAFT ON PILES';

  const B = toMm(raw.B, unit);
  const L = toMm(raw.L, unit);
  const D = toMm(raw.D, unit);
  assertFinitePositive('B', B);
  assertFinitePositive('L', L);
  assertFinitePositive('D', D);
  if (D < MIN_RAFT_DEPTH_MM || D > MAX_RAFT_DEPTH_MM) {
    throw new DiagramError('BAD_PARAM', `"D" must be between ${MIN_RAFT_DEPTH_MM}mm and ${MAX_RAFT_DEPTH_MM}mm for this schematic, got ${D}mm.`);
  }

  // ── Columns ──────────────────────────────────────────────────────
  // Same shape, same validation order, same error codes as
  // footingDiagram.mjs's own computeRaftFootingGeometry — deliberately
  // NOT imported from there (assertNoOverlap2D and the inline column
  // loop are private/unexported in that file; this module's own
  // "no un-exported cross-module imports" convention, same one
  // pileCapDiagram.mjs's header states for computeMeshLayer, applies
  // identically here).
  const rawColumns = raw.columns;
  if (!Array.isArray(rawColumns) || rawColumns.length < 2) {
    throw new DiagramError('BAD_PARAM', `"columns" must list at least 2 columns for a raft-over-pile foundation, got ${Array.isArray(rawColumns) ? rawColumns.length : JSON.stringify(rawColumns)}.`);
  }
  if (rawColumns.length > MAX_COLUMNS) {
    throw new DiagramError('TOO_MANY_COLUMNS', `Raft-over-pile supports at most ${MAX_COLUMNS} columns in this schematic, got ${rawColumns.length}.`);
  }
  const columns = rawColumns.map((c, i) => {
    const tag = `col${i + 1}`;
    const b = toMm(c.b, unit), l = toMm(c.l, unit);
    const offx = toMm(c.offx, unit), offy = toMm(c.offy, unit);
    assertFinitePositive(`${tag}.b`, b);
    assertFinitePositive(`${tag}.l`, l);
    if (!Number.isFinite(offx)) throw new DiagramError('BAD_PARAM', `"${tag}.offx" must be a finite number, got ${JSON.stringify(c.offx)}.`);
    if (!Number.isFinite(offy)) throw new DiagramError('BAD_PARAM', `"${tag}.offy" must be a finite number, got ${JSON.stringify(c.offy)}.`);
    if (b >= B) throw new DiagramError('COLUMN_TOO_WIDE', `${tag}.b (${b}mm) must be smaller than B (${B}mm).`);
    if (l >= L) throw new DiagramError('COLUMN_TOO_WIDE', `${tag}.l (${l}mm) must be smaller than L (${L}mm).`);
    const loX = offx - l / 2, hiX = offx + l / 2;
    const loY = offy - b / 2, hiY = offy + b / 2;
    if (loX < 0 || hiX > L || loY < 0 || hiY > B) {
      throw new DiagramError('COLUMN_OUT_OF_BOUNDS', `${tag} (offx ${offx}mm, offy ${offy}mm, ${l}x${b}mm) extends outside the raft's ${L}x${B}mm footprint.`);
    }
    return { tag, b, l, offx, offy };
  });
  assertNoColumnOverlap(columns);

  // ── Bottom mesh ──────────────────────────────────────────────────
  const cover = toMm(raw.cover, unit);
  const dia = toMm(raw.dia, unit);
  const spacingLong = toMm(raw.spacingLong ?? raw.spacing, unit);
  const spacingShort = toMm(raw.spacingShort ?? raw.spacing, unit);
  for (const [name, v] of Object.entries({ cover, dia, spacingLong, spacingShort })) {
    assertFinitePositive(name, v);
  }
  const meshLong = computeMeshLayer({ hostWidthMM: L, cover, diaMM: dia, spacingMM: spacingLong });
  const meshShort = computeMeshLayer({ hostWidthMM: B, cover, diaMM: dia, spacingMM: spacingShort });

  // ── Piles ────────────────────────────────────────────────────────
  const pileDia = toMm(raw.pileDiaMM, unit);
  assertFinitePositive('pileDiaMM', pileDia);
  if (pileDia < MIN_PILE_DIA_MM || pileDia > MAX_PILE_DIA_MM) {
    throw new DiagramError('BAD_PARAM', `"pileDiaMM" must be between ${MIN_PILE_DIA_MM}mm and ${MAX_PILE_DIA_MM}mm, got ${pileDia}mm.`);
  }
  const pileEmbed = toMm(raw.pileEmbedMM, unit);
  assertFinitePositive('pileEmbedMM', pileEmbed);
  if (pileEmbed >= D) {
    throw new DiagramError('EMBED_EXCEEDS_DEPTH', `"pileEmbedMM" (${pileEmbed}mm) must be less than the raft depth "D" (${D}mm).`);
  }

  const rawPiles = raw.piles;
  if (!Array.isArray(rawPiles) || rawPiles.length < MIN_PILES) {
    throw new DiagramError('TOO_FEW_PILES', `"piles" must list at least ${MIN_PILES} piles, got ${Array.isArray(rawPiles) ? rawPiles.length : JSON.stringify(rawPiles)}.`);
  }
  if (rawPiles.length > MAX_PILES) {
    throw new DiagramError('TOO_MANY_PILES', `Raft-over-pile supports at most ${MAX_PILES} piles in this schematic, got ${rawPiles.length}.`);
  }

  // Edge margin deliberately does NOT include `cover` — same reasoning
  // pileCapDiagram.mjs's own header gives verbatim: cover already
  // governs the independent mesh-layer check above, and mixing the two
  // would make one of them structurally unreachable.
  const edgeMarginMM = pileDia * MIN_EDGE_FACTOR;
  const piles = rawPiles.map((p, i) => {
    const tag = `pile${i + 1}`;
    const offx = toMm(p.offx, unit);
    const offy = toMm(p.offy, unit);
    if (!Number.isFinite(offx)) throw new DiagramError('BAD_PARAM', `"${tag}.offx" must be a finite number, got ${JSON.stringify(p.offx)}.`);
    if (!Number.isFinite(offy)) throw new DiagramError('BAD_PARAM', `"${tag}.offy" must be a finite number, got ${JSON.stringify(p.offy)}.`);
    if (offx - edgeMarginMM < 0 || offx + edgeMarginMM > L || offy - edgeMarginMM < 0 || offy + edgeMarginMM > B) {
      throw new DiagramError('PILE_OUT_OF_BOUNDS', `${tag} (offx ${offx}mm, offy ${offy}mm) leaves less than the minimum edge margin (${fmt(edgeMarginMM, 'mm', 0)}) inside the ${L}x${B}mm raft.`);
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

  // Same gap pileCapDiagram.mjs's own header documents finding via its
  // cairosvg visual pass, generalized here from one column to every
  // column: nothing above checks pile-vs-COLUMN clearance for any of
  // them, only pile-vs-pile and pile-vs-raft-edge.
  const minColClearance = (pileDia / 2) * (1 + MIN_CLEAR_FACTOR);
  for (const col of columns) {
    const colX0 = col.offx - col.l / 2, colX1 = col.offx + col.l / 2;
    const colY0 = col.offy - col.b / 2, colY1 = col.offy + col.b / 2;
    for (const p of piles) {
      const nearestX = Math.min(Math.max(p.offx, colX0), colX1);
      const nearestY = Math.min(Math.max(p.offy, colY0), colY1);
      const dist = Math.sqrt((p.offx - nearestX) ** 2 + (p.offy - nearestY) ** 2);
      if (dist < minColClearance) {
        throw new DiagramError('COLUMN_PILE_OVERLAP', `${p.tag} (offx ${p.offx}mm, offy ${p.offy}mm) is only ${fmt(dist, 'mm', 0)} clear of ${col.tag}'s ${col.l}x${col.b}mm footprint, less than the minimum clearance (${fmt(minColClearance, 'mm', 0)}) for a ${pileDia}mm pile diameter.`);
      }
    }
  }

  return {
    type: 'raftpile',
    unit,
    id,
    plan: {
      B, L, D,
      columns,
      piles,
      pileDia, pileEmbed,
    },
    mesh: { long: meshLong, short: meshShort },
    meta: { B, L, D, cover, dia, spacingLong, spacingShort, pileDia, pileEmbed, columns },
  };
}

// Column-vs-column overlap — same 2-D separating-axis check as
// footingDiagram.mjs's own private assertNoOverlap2D (raft/strip's
// shared helper), copied here rather than imported because that
// function is not exported — same "own local copy" convention this
// file's header states for computeMeshLayer below.
function assertNoColumnOverlap(columns) {
  for (let i = 0; i < columns.length; i++) {
    for (let j = i + 1; j < columns.length; j++) {
      const a = columns[i], b = columns[j];
      const sepX = Math.abs(a.offx - b.offx) >= (a.l + b.l) / 2;
      const sepY = Math.abs(a.offy - b.offy) >= (a.b + b.b) / 2;
      if (!sepX && !sepY) {
        throw new DiagramError('COLUMNS_OVERLAP', `${a.tag} and ${b.tag} overlap given their positions and dimensions.`);
      }
    }
  }
}

// Same shape and derivation as pileCapDiagram.mjs's own computeMeshLayer
// (own local copy, per this file's "no un-exported cross-module
// imports" constraint — neither footingDiagram.mjs nor
// pileCapDiagram.mjs exports this helper).
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
// following footingDiagram.mjs/columnDiagram.mjs/pileCapDiagram.mjs's
// verified-safe convention (Noto Naskh Arabic has no glyph for either).
const L = {
  en: {
    title: (id) => `RAFT OVER PILE ${id} \u2014 REINFORCEMENT DETAIL`,
    plan: 'PLAN', section: 'SECTION (representative, along L)',
    column: 'Column', pile: 'Pile', mesh: 'Bottom Mesh',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colPos: 'offx / offy (mm)',
    caption: 'Schematic raft-over-pile detail generated from the supplied data \u2014 verify column positions, pile count, position, embedment, and mesh against your own design before issuing for construction. This drawing does not check pile capacity, group interaction, or punching/one-way shear \u2014 those remain the design engineer\'s responsibility. Only the piles\' embedment into the raft is shown; the pile shaft below the raft is not drawn. The section view projects every column and every pile onto one representative longitudinal cut \u2014 it is not a claim that any of them truly share one transverse line.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفصيلة تسليح لبشة فوق خوازيق ${id}`,
    plan: 'مسقط', section: 'قطاع توضيحي على طول L',
    column: 'عمود', pile: 'خازوق', mesh: 'الشبكة السفلية',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colPos: 'الإزاحة السينية والصادية مم',
    caption: 'رسم تفصيلي توضيحي للبشة فوق خوازيق أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع مواضع الأعمدة وعدد الخوازيق ومواضعها وعمق تغلغلها والشبكة السفلية وفق تصميمك الخاص قبل الاعتماد للتنفيذ. هذا الرسم لا يتحقق من قدرة تحمل الخوازيق أو تفاعل المجموعة أو قص الثقب أو القص من اتجاه واحد، وتبقى هذه مسؤولية المهندس المصمم. يُظهر الرسم فقط تغلغل الخوازيق داخل اللبشة؛ جسم الخازوق أسفل اللبشة غير موضح. قطاع الإسقاط يعرض كل عمود وكل خازوق مسقطاً على قطاع طولي واحد توضيحي، وليس تأكيداً على أنها تقع فعلياً على خط عرضي واحد مشترك.',
    dirAttr: 'rtl',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 960;
const PLAN_BOX = { x: 80, y: 70, w: 800, h: 320 };
const SECTION_BOX = { x: 80, y: 450, w: 800, h: 220 };

export function renderRaftPileDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);
  const { B, L: raftL, D, columns, piles, pileDia, pileEmbed } = geometry.plan;

  const planScale = fitScale([{ contentW: raftL, contentH: B, boxW: PLAN_BOX.w - 80, boxH: PLAN_BOX.h - 70 }]);
  const sectionScale = fitScale([{ contentW: raftL, contentH: D + pileDia, boxW: SECTION_BOX.w - 80, boxH: SECTION_BOX.h - 70 }]);

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
    .raftpile-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .box-label      { font-size:13px; font-weight:bold; fill:#333; font-family: ${scriptFontStack}; }
    .pile-circle    { fill:#dfe9f5; stroke:#2a5a8c; stroke-width:1.4; }
    .col-rect       { fill:#f2f2f2; stroke:#333; stroke-width:1.6; }
    .bar-dot-mesh   { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="raftpile-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderPlan(geometry, planScale, l)}
  ${renderSection(geometry, sectionScale, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

function renderPlan(geometry, scale, l) {
  const { B, L: raftL, columns, piles, pileDia } = geometry.plan;
  const { mesh } = geometry;
  const px = PLAN_BOX.x + 40;
  const py = PLAN_BOX.y + 40;
  const pw = raftL * scale;
  const ph = B * scale;

  const meshLines = [];
  for (const c of mesh.long.barCentersMM) {
    meshLines.push(`<line x1="${px + c * scale}" y1="${py}" x2="${px + c * scale}" y2="${py + ph}" stroke="#9ab3cf" stroke-width="0.8"/>`);
  }
  for (const c of mesh.short.barCentersMM) {
    meshLines.push(`<line x1="${px}" y1="${py + c * scale}" x2="${px + pw}" y2="${py + c * scale}" stroke="#9ab3cf" stroke-width="0.8"/>`);
  }

  // Label text is the schedule table's own Mark number (columns 1..M,
  // piles M+1..M+N, identical numbering buildScheduleRows() produces —
  // NOT the longer "pile1"/"col1" tag, and gated on the marker actually
  // having room for it. [Found via this module's own cairosvg visual
  // pass, not a text-only check: a raft's typical plan scale is far
  // smaller than a single pile cap's (a 12m raft vs. pileCapDiagram.mjs's
  // largest 8m cap on the SAME fixed PLAN_BOX), so the full "pile1"-style
  // tag pileCapDiagram.mjs draws safely at its own scale overflowed the
  // marker illegibly here. A short Mark number that's still omitted
  // below the fit threshold, cross-referenced to the schedule table
  // (which every position is in regardless), is honest at any scale —
  // inventing room that isn't there would not be.]
  const pileCircles = piles.map((p, i) => {
    const mark = String(columns.length + i + 1);
    const cx = px + p.offx * scale;
    const cy = py + p.offy * scale;
    const r = Math.max(3, (pileDia / 2) * scale);
    const label = r >= 7 ? `<text x="${cx}" y="${cy + 3}" text-anchor="middle" font-size="9" fill="#123564">${esc(mark)}</text>` : '';
    return `<circle cx="${cx}" cy="${cy}" r="${r}" class="pile-circle"/>${label}`;
  }).join('');

  const colRects = columns.map((c, i) => {
    const mark = String(i + 1);
    const w = c.l * scale, h = c.b * scale;
    const x = px + c.offx * scale - w / 2;
    const y = py + c.offy * scale - h / 2;
    const label = (w / 2 >= 7 && h / 2 >= 7) ? `<text x="${x + w / 2}" y="${y + h / 2 + 3}" text-anchor="middle" font-size="9" fill="#333">${esc(mark)}</text>` : '';
    return `<rect x="${x}" y="${y}" width="${w}" height="${h}" class="col-rect"/>${label}`;
  }).join('');

  return `<g>
    <text x="${PLAN_BOX.x}" y="${PLAN_BOX.y}" class="box-label">${esc(l.plan)}</text>
    <rect x="${px}" y="${py}" width="${pw}" height="${ph}" fill="#ffffff" stroke="#333" stroke-width="1.6"/>
    ${meshLines.join('\n    ')}
    ${pileCircles}
    ${colRects}
    ${dimensionLine(px, py + ph + 22, px + pw, py + ph + 22, `L = ${fmt(raftL, 'mm', 0)}`)}
    ${dimensionLine(px - 22, py, px - 22, py + ph, `B = ${fmt(B, 'mm', 0)}`, { orientation: 'v' })}
  </g>`;
}

// Every column and every pile projected onto one longitudinal cut at its
// own true offx — see this file's own "Section cut" header note. Column
// stub height is a fixed nominal amount above the slab (not a real
// column height, which is outside this schematic's scope, same
// convention pileCapDiagram.mjs's own section uses for its single
// column).
function renderSection(geometry, scale, l) {
  const { B, L: raftL, D, columns, piles, pileDia, pileEmbed } = geometry.plan;
  const sx = SECTION_BOX.x + 40;
  const sy = SECTION_BOX.y + 30;
  const sw = raftL * scale;
  const capH = D * scale;

  const colStubs = columns.map((c) => {
    const w = Math.max(6, c.l * scale);
    const x = sx + c.offx * scale - w / 2;
    const colTopY = sy - Math.min(60, c.b * scale * 0.6);
    return `<rect x="${x}" y="${colTopY}" width="${w}" height="${sy - colTopY}" class="col-rect"/>`;
  }).join('\n    ');

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
    ${colStubs}
    ${dimensionLine(sx + sw + 22, sy, sx + sw + 22, sy + capH, `D = ${fmt(D, 'mm', 0)}`, { orientation: 'v' })}
  </g>`;
}

function buildScheduleRows(geometry, l) {
  const { columns, piles, pileDia } = geometry.plan;
  const rows = columns.map((c, i) => ({
    mark: String(i + 1), element: `${l.column} ${i + 1}`, dia: '\u2014',
    pos: `${fmt(c.offx, 'mm', 0)} / ${fmt(c.offy, 'mm', 0)}`,
  }));
  piles.forEach((p, i) => {
    // Was `${l.pile} ${p.tag}` in an earlier draft of this table — same
    // bug pileCapDiagram.mjs's own header documents finding and fixing
    // (p.tag is the raw, language-invariant `pile${i+1}` cross-reference
    // ID used on the plan-view circle label; concatenating it after the
    // translated l.pile word duplicates "pile" in English and mixes an
    // untranslated word into a translated Arabic cell). Fixed the same
    // way here from the start: translated-label + plain number.
    rows.push({
      mark: String(columns.length + i + 1), element: `${l.pile} ${i + 1}`, dia: String(Math.round(pileDia)),
      pos: `${fmt(p.offx, 'mm', 0)} / ${fmt(p.offy, 'mm', 0)}`,
    });
  });
  return rows;
}

// ── Chat-facing entry point (mode:'rebarDiagram' JSON payload) ────────
// Mirrors pileCapDiagram.mjs's parsePileCapRebarPayload contract exactly.
export function parseRaftPileRebarPayload(raw) {
  try {
    const geometry = computeRaftPileDiagramGeometry(raw);
    return { ok: true, type: 'raftpile', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Syntax:
//   /diagram raftpile id=RP1 B=8000 L=12000 D=800 cols=4
//     col1b=500 col1l=500 col1offx=1500 col1offy=1500
//     col2b=500 col2l=500 col2offx=10500 col2offy=1500
//     col3b=500 col3l=500 col3offx=1500 col3offy=6500
//     col4b=500 col4l=500 col4offx=10500 col4offy=6500
//     cover=75 dia=16 spacing=200 piledia=600 pileembed=150
//     pile1x=1500 pile1y=1500 pile2x=6000 pile2y=1500
//     pile3x=10500 pile3y=1500 pile4x=1500 pile4y=6500
//     pile5x=6000 pile5y=6500 pile6x=10500 pile6y=6500 [unit=mm]
// `cols=N` fixed-count column scan mirrors footingDiagram.mjs's own
// strip/raft `collectColumns` convention exactly (col1.. through
// colN.. of b/l/offx/offy); pile scan mirrors pileCapDiagram.mjs's own
// auto-detect-by-key convention exactly (no `piles=N` — every
// pile<N>x/pile<N>y pair present is collected, sorted by N). Same
// BAD_SYNTAX/UNSUPPORTED_TYPE reservation, same never-throws contract,
// same lower-cased leading token as every sibling parser
// (diagramCommandRouter.mjs's own header note on the shearWall/
// shearwall lesson applies here too — "raftpile" one lowercase word).
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: raftpile key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'raftpile') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use raftpile.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const n = num('cols');
    if (!Number.isFinite(n) || !Number.isInteger(n) || n < 2) {
      throw new DiagramError('BAD_PARAM', `"cols" must be an integer of at least 2, got ${JSON.stringify(kv.cols)}.`);
    }
    if (n > MAX_COLUMNS) {
      throw new DiagramError('TOO_MANY_COLUMNS', `At most ${MAX_COLUMNS} columns are supported in this schematic, got ${n}.`);
    }
    const columns = [];
    for (let i = 1; i <= n; i++) {
      columns.push({
        b: num(`col${i}b`), l: num(`col${i}l`),
        offx: num(`col${i}offx`), offy: num(`col${i}offy`),
      });
    }

    const pileKeys = Object.keys(kv).filter((k) => /^pile\d+x$/.test(k));
    const piles = pileKeys
      .map((k) => Number(k.match(/^pile(\d+)x$/)[1]))
      .sort((a, b) => a - b)
      .map((i) => ({ offx: num(`pile${i}x`), offy: num(`pile${i}y`) }));

    const geometry = computeRaftPileDiagramGeometry({
      footingId: kv.id, B: num('b'), L: num('l'), D: num('d'),
      columns,
      cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
      spacingLong: num('spacinglong'), spacingShort: num('spacingshort'),
      pileDiaMM: num('piledia'), pileEmbedMM: num('pileembed'),
      piles, unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
