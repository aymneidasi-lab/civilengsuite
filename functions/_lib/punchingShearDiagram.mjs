// functions/_lib/punchingShearDiagram.mjs
//
// New-element track, candidate "Punching Shear Reinforcement" (تسليح ثقب
// القص) — ACI 318 §22.6 gap candidate documented alongside this
// session's "Raft over pile"/pile-cap pool: shear studs around a column
// inside a flat slab. Deterministic, zero-AI SVG generator. Architecture
// follows columnDiagram.mjs literally, same discipline
// pileCapDiagram.mjs / raftPileDiagram.mjs state for themselves.
//
// ── WHY THIS IS A NEW FILE ─────────────────────────────────────────────
// slabDiagram.mjs's own header lists "punching-shear reinforcement" by
// name in its own NOT-modeled paragraph ("drop panels or column
// capitals, punching-shear reinforcement, curtailment ... each needs a
// parametrization this module hasn't been given yet") — this file is
// that missing parametrization, not an edit to slabDiagram.mjs, same
// "own file per element" decision as pileCapDiagram.mjs vs
// footingDiagram.mjs's 'raft'.
//
// ── SCOPE (v1) ──────────────────────────────────────────────────────────
// Exactly ONE rectangular column, centered in plan on a local rectangular
// slab patch (B x L) of constant thickness D — same "one column,
// centered on a local patch" decision pileCapDiagram.mjs already made
// for the same reason (a punching-shear check is inherently local to one
// column, not a whole floor plate). Shear reinforcement is SHEAR STUDS
// ON RAILS (ACI 318 §22.6.5's stud-rail system) ONLY — 1..MAX_RAILS
// rails, each projecting outward from one of the column's four faces
// (dir: 'n'|'s'|'e'|'w', at an explicit offset along that face — never
// grid-forced, same "no invented pattern" convention pileCapDiagram.mjs
// states for its own piles[]), each rail carrying studCount studs of ONE
// uniform diameter (studDiaMM) at a caller-supplied firstStudOffsetMM
// from the column face and studSpacingMM thereafter. The effective depth
// `d` is a direct input (not derived from thickness/cover/bar dia — see
// INPUT CONTRACT) used only to draw the ACI 318 critical-perimeter
// reference rectangle at d/2 outside each column face.
//
// STILL NOT MODELED, on purpose (same "explicit scope boundary"
// convention every sibling module states for itself):
//   - closed-tie (stirrup) shear reinforcement, ACI 318 §22.6.4's OTHER
//     system — a materially different detail (bent bars vs. headed
//     studs) than a variant of this file's own stud-rail scope, not a
//     gap in it. The screenshot's own "كانات/studs" names both; this v1
//     draws studs only.
//   - the punching-shear DEMAND/CAPACITY check itself (Vu vs. phi*Vn,
//     ACI 318 §22.6.1-22.6.3) — the critical-perimeter rectangle drawn
//     here is a REFERENCE annotation only (its own location per ACI
//     318 §22.6.4.1, d/2 from the column face), never a claim that the
//     supplied stud layout is adequate for any actual demand. That
//     determination remains the design engineer's responsibility, same
//     disclaimer class every sibling module's caption carries.
//   - round or non-rectangular columns.
//   - stud elevation/embedment depth in the section view — see the
//     Section-cut note below for exactly what the section does and does
//     not show.
//   - off-center columns / edge or corner column-to-slab-edge
//     conditions (where fewer than 4 faces need reinforcement because
//     one or more faces sit at or near a real slab edge) — the local
//     patch here is always a fully interior condition with the column
//     centered; a caller building a genuine edge/corner case may still
//     supply fewer than 4 rails (MIN_RAILS is 1, not 4) but the drawn
//     slab patch itself is never modeled as terminating at a true edge.
//   - the slab's own flexural top/bottom mesh — that is
//     slabDiagram.mjs's job; this file draws the punching-shear stud
//     system as its own independent sheet, not a slabDiagram.mjs overlay.
//
// ── INPUT CONTRACT ───────────────────────────────────────────────────
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   slabId?: string,                   // sheet mark, e.g. "PS-1"
//   B: number, L: number,              // local slab-patch plan extent —
//                                      // column is centered at (L/2, B/2)
//   D: number,                         // slab thickness
//   dMM: number,                       // effective depth, direct input
//                                      // (not derived from cover/bar dia
//                                      // in this file — see SCOPE), must
//                                      // be < D. Used only to place the
//                                      // d/2 critical-perimeter reference
//                                      // rectangle.
//   colB: number, colL: number,        // column section, centered
//   studDiaMM: number,                 // one diameter, every stud
//   rails: [
//     {
//       dir: 'n'|'s'|'e'|'w',          // which column face the rail
//                                      // projects outward from — n/s
//                                      // faces span colL (top/bottom in
//                                      // the drawing), e/w faces span
//                                      // colB (left/right)
//       offsetAlongFace: number,       // signed distance from that
//                                      // face's own center, along the
//                                      // face — |offset| must leave the
//                                      // rail's base ON the face
//       studCount: number,             // 1..MAX_STUDS_PER_RAIL
//       firstStudOffsetMM: number,     // column-face to first stud
//       studSpacingMM: number,         // center-to-center thereafter
//     }, ...
//   ],  // 1..MAX_RAILS
// }
//
// ── Section cut ──────────────────────────────────────────────────────
// One straight cut through the column centerline along L, showing the
// slab profile (thickness D), the effective depth d as a dimension line
// measured down from the top fiber, the column stub, and the d/2
// critical-perimeter location as two dashed vertical reference lines.
// It does NOT show individual studs in elevation (embedment depth,
// head, or shank) — that is a genuinely different, 3-D detail a stud-
// rail shop drawing carries separately, and inventing an elevation
// position for every stud from this file's plan-only geometry would be
// exactly the "confident but wrong" failure imageGen.mjs's own header
// warns against, restated here for a section view instead of an image
// model. Individual studs are shown ONLY in plan, at their real computed
// (x, y) position — never in section.
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
const MIN_PATCH_SIDE_MM = 1000;
const MAX_PATCH_SIDE_MM = 8000; // a punching-shear zone is local by
  // nature (studs rarely extend more than a couple slab thicknesses from
  // the column face) — same order of magnitude as pileCapDiagram.mjs's
  // own MAX_CAP_SIDE_MM (8000), reused for the same reason.
const MIN_SLAB_THICKNESS_MM = 150;
const MAX_SLAB_THICKNESS_MM = 600; // typical flat-plate/flat-slab range;
  // thicker mats are footingDiagram.mjs raft/this project's
  // raftPileDiagram.mjs territory, not a punching-shear-stud sheet's.
const MIN_STUD_DIA_MM = 9;
const MAX_STUD_DIA_MM = 25; // realistic headed-stud shank diameter range
const MIN_RAILS = 1; // a single rail is still a real reinforcement line
  // (unlike pileCapDiagram.mjs's own MIN_PILES=2 reasoning — "a single
  // pile is just a pile, not a cap" does not transfer here: an edge or
  // corner column legitimately needs studs on only 1-2 faces, so forcing
  // a 4-rail minimum would wrongly reject a valid, common configuration).
const MAX_RAILS = 24; // up to 6 rails per face x 4 faces — generous for
  // even a large column; CPU cost stays trivial either way (see the
  // same-face separation check below, O(rails^2) worst case = 576).
const MIN_STUDS_PER_RAIL = 1;
const MAX_STUDS_PER_RAIL = 12;
// Schematic-drawability guards ONLY — same role as every sibling
// module's own MIN_EDGE_FACTOR/MIN_CLEAR_FACTOR. NOT a substitute for
// checking the supplied layout against ACI 318 §22.6's own minimum
// spacing/first-stud-distance provisions — see SCOPE's own note on the
// critical-perimeter rectangle being a reference, not a check.
const RAIL_EDGE_MARGIN_FACTOR = 0.5;  // farthest stud must clear the
  // slab-patch edge by >= 0.5 x studDia
const RAIL_SEPARATION_FACTOR = 1.5;   // two rails on the SAME face must
  // have offsetAlongFace centers >= 1.5 x studDia apart

const DIR_SET = new Set(['n', 's', 'e', 'w']);

// ── Compute ──────────────────────────────────────────────────────────
export function computePunchingShearDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Punching-shear diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.slabId != null ? String(raw.slabId).slice(0, 40) : 'PUNCHING SHEAR';

  const B = toMm(raw.B, unit);
  const L = toMm(raw.L, unit);
  const D = toMm(raw.D, unit);
  assertFinitePositive('B', B);
  assertFinitePositive('L', L);
  assertFinitePositive('D', D);
  if (B < MIN_PATCH_SIDE_MM || B > MAX_PATCH_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"B" must be between ${MIN_PATCH_SIDE_MM}mm and ${MAX_PATCH_SIDE_MM}mm for this schematic, got ${B}mm.`);
  }
  if (L < MIN_PATCH_SIDE_MM || L > MAX_PATCH_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"L" must be between ${MIN_PATCH_SIDE_MM}mm and ${MAX_PATCH_SIDE_MM}mm for this schematic, got ${L}mm.`);
  }
  if (D < MIN_SLAB_THICKNESS_MM || D > MAX_SLAB_THICKNESS_MM) {
    throw new DiagramError('BAD_PARAM', `"D" must be between ${MIN_SLAB_THICKNESS_MM}mm and ${MAX_SLAB_THICKNESS_MM}mm for this schematic, got ${D}mm.`);
  }

  const d = toMm(raw.dMM, unit);
  assertFinitePositive('dMM', d);
  if (d >= D) {
    throw new DiagramError('D_EXCEEDS_THICKNESS', `"dMM" (${d}mm) must be less than the slab thickness "D" (${D}mm).`);
  }

  const colB = toMm(raw.colB, unit);
  const colL = toMm(raw.colL, unit);
  assertFinitePositive('colB', colB);
  assertFinitePositive('colL', colL);
  if (colB >= B) throw new DiagramError('COLUMN_TOO_WIDE', `colB (${colB}mm) must be smaller than B (${B}mm).`);
  if (colL >= L) throw new DiagramError('COLUMN_TOO_WIDE', `colL (${colL}mm) must be smaller than L (${L}mm).`);

  const studDia = toMm(raw.studDiaMM, unit);
  assertFinitePositive('studDiaMM', studDia);
  if (studDia < MIN_STUD_DIA_MM || studDia > MAX_STUD_DIA_MM) {
    throw new DiagramError('BAD_PARAM', `"studDiaMM" must be between ${MIN_STUD_DIA_MM}mm and ${MAX_STUD_DIA_MM}mm, got ${studDia}mm.`);
  }

  const rawRails = raw.rails;
  if (!Array.isArray(rawRails) || rawRails.length < MIN_RAILS) {
    throw new DiagramError('TOO_FEW_RAILS', `"rails" must list at least ${MIN_RAILS} rail, got ${Array.isArray(rawRails) ? rawRails.length : JSON.stringify(rawRails)}.`);
  }
  if (rawRails.length > MAX_RAILS) {
    throw new DiagramError('TOO_MANY_RAILS', `Punching-shear detail supports at most ${MAX_RAILS} rails in this schematic, got ${rawRails.length}.`);
  }

  const colCenterX = L / 2, colCenterY = B / 2;
  const colX0 = colCenterX - colL / 2, colX1 = colCenterX + colL / 2;
  const colY0 = colCenterY - colB / 2, colY1 = colCenterY + colB / 2;
  const edgeMarginMM = studDia * RAIL_EDGE_MARGIN_FACTOR;

  const rails = rawRails.map((r, i) => {
    const tag = `rail${i + 1}`;
    const dir = String(r.dir || '').toLowerCase();
    if (!DIR_SET.has(dir)) {
      throw new DiagramError('BAD_PARAM', `"${tag}.dir" must be one of n, s, e, w, got ${JSON.stringify(r.dir)}.`);
    }
    const offsetAlongFace = toMm(r.offsetAlongFace, unit);
    if (!Number.isFinite(offsetAlongFace)) {
      throw new DiagramError('BAD_PARAM', `"${tag}.offsetAlongFace" must be a finite number, got ${JSON.stringify(r.offsetAlongFace)}.`);
    }
    const studCount = r.studCount;
    if (!Number.isInteger(studCount) || studCount < MIN_STUDS_PER_RAIL || studCount > MAX_STUDS_PER_RAIL) {
      throw new DiagramError('BAD_PARAM', `"${tag}.studCount" must be an integer between ${MIN_STUDS_PER_RAIL} and ${MAX_STUDS_PER_RAIL}, got ${JSON.stringify(studCount)}.`);
    }
    const firstStudOffsetMM = toMm(r.firstStudOffsetMM, unit);
    const studSpacingMM = toMm(r.studSpacingMM, unit);
    assertFinitePositive(`${tag}.firstStudOffsetMM`, firstStudOffsetMM);
    assertFinitePositive(`${tag}.studSpacingMM`, studSpacingMM);

    // Face half-length the rail's base must stay within — n/s faces span
    // colL, e/w faces span colB (see INPUT CONTRACT's own dir note).
    const faceHalfLength = (dir === 'n' || dir === 's') ? colL / 2 : colB / 2;
    if (Math.abs(offsetAlongFace) > faceHalfLength) {
      throw new DiagramError('RAIL_OUT_OF_BOUNDS', `${tag} (dir ${dir}, offset ${offsetAlongFace}mm) starts past the column face's own ${fmt(faceHalfLength * 2, 'mm', 0)} length — it would not sit on the face at all.`);
    }

    const farthest = firstStudOffsetMM + (studCount - 1) * studSpacingMM;
    const availableRadial = (dir === 'n' || dir === 's') ? (B / 2 - colB / 2) : (L / 2 - colL / 2);
    if (farthest + edgeMarginMM > availableRadial) {
      throw new DiagramError('RAIL_OUT_OF_BOUNDS', `${tag} (dir ${dir}) reaches ${fmt(farthest, 'mm', 0)} from the column face, leaving less than the minimum edge margin (${fmt(edgeMarginMM, 'mm', 0)}) inside the ${L}x${B}mm slab patch.`);
    }

    // Base point on the column face, and the outward unit direction —
    // every stud's true (x, y) is computed here once, not re-derived at
    // render time, same "compute produces final coordinates" convention
    // pileCapDiagram.mjs/raftPileDiagram.mjs use for piles/columns.
    let baseX, baseY, ux, uy;
    if (dir === 'n') { baseX = colCenterX + offsetAlongFace; baseY = colY0; ux = 0; uy = -1; }
    else if (dir === 's') { baseX = colCenterX + offsetAlongFace; baseY = colY1; ux = 0; uy = 1; }
    else if (dir === 'w') { baseX = colX0; baseY = colCenterY + offsetAlongFace; ux = -1; uy = 0; }
    else { baseX = colX1; baseY = colCenterY + offsetAlongFace; ux = 1; uy = 0; }

    const studs = Array.from({ length: studCount }, (_, k) => {
      const radial = firstStudOffsetMM + k * studSpacingMM;
      return { x: baseX + ux * radial, y: baseY + uy * radial };
    });

    return { tag, dir, offsetAlongFace, studCount, firstStudOffsetMM, studSpacingMM, baseX, baseY, studs };
  });

  // Same-face minimum separation — schematic-drawability guard only
  // (see this file's own RAIL_SEPARATION_FACTOR comment above), same
  // role as pileCapDiagram.mjs's MIN_CLEAR_FACTOR pile-to-pile check.
  const minSeparation = studDia * RAIL_SEPARATION_FACTOR;
  const byDir = new Map();
  for (const r of rails) {
    if (!byDir.has(r.dir)) byDir.set(r.dir, []);
    byDir.get(r.dir).push(r);
  }
  for (const group of byDir.values()) {
    const sorted = group.slice().sort((a, b) => a.offsetAlongFace - b.offsetAlongFace);
    for (let i = 0; i < sorted.length - 1; i++) {
      const gap = sorted[i + 1].offsetAlongFace - sorted[i].offsetAlongFace;
      if (gap < minSeparation) {
        throw new DiagramError('RAILS_TOO_CLOSE', `${sorted[i].tag} and ${sorted[i + 1].tag} (both dir ${sorted[i].dir}) are ${fmt(gap, 'mm', 0)} apart along the face, less than the minimum separation (${fmt(minSeparation, 'mm', 0)}) for a ${studDia}mm stud diameter.`);
      }
    }
  }

  // ACI 318 §22.6.4.1 critical-perimeter reference rectangle, d/2 outside
  // every column face — REFERENCE ANNOTATION ONLY, see SCOPE's own note.
  const critX0 = colX0 - d / 2, critX1 = colX1 + d / 2;
  const critY0 = colY0 - d / 2, critY1 = colY1 + d / 2;
  if (critX0 < 0 || critX1 > L || critY0 < 0 || critY1 > B) {
    throw new DiagramError('CRITICAL_SECTION_EXCEEDS_SLAB', `The d/2 critical-perimeter rectangle (${fmt(critX1 - critX0, 'mm', 0)} x ${fmt(critY1 - critY0, 'mm', 0)}) extends outside the ${L}x${B}mm slab patch — enlarge B/L or reduce dMM.`);
  }

  return {
    type: 'punchingshear',
    unit,
    id,
    plan: {
      B, L, D, d, colB, colL,
      colX0, colX1, colY0, colY1,
      critX0, critX1, critY0, critY1,
      rails, studDia,
    },
    meta: { B, L, D, d, colB, colL, studDia, rails },
  };
}

// ── Labels ───────────────────────────────────────────────────────────
// Local `L = {en:{...}, ar:{...}}` dict, per this project's own explicit
// decision (structuralLabels.mjs is footingDiagram.mjs-only). Every
// Arabic value below is written parenthesis- and em/en-dash-free,
// following the project's verified-safe convention (Noto Naskh Arabic
// has no glyph for either).
const DIR_LABEL = {
  en: { n: 'Top', s: 'Bottom', w: 'Left', e: 'Right' },
  ar: { n: 'أعلى', s: 'أسفل', w: 'يسار', e: 'يمين' },
};

const L = {
  en: {
    title: (id) => `PUNCHING SHEAR ${id} \u2014 REINFORCEMENT DETAIL`,
    plan: 'PLAN', section: 'SECTION (through column, along L)',
    column: 'Column', rail: 'Rail',
    colMark: 'Mark', colElement: 'Element', colDir: 'Face', colDia: 'dia (mm)', colOff: 'off (mm)', colStuds: 'studs (n@s/first)',
    critLabel: 'Critical perimeter, d/2 from column face (reference only)',
    dLabel: (v) => `d = ${v}`,
    caption: 'Schematic punching-shear stud-rail detail generated from the supplied data \u2014 verify rail count, position, stud count, spacing, and embedment against your own design before issuing for construction. The dashed critical-perimeter rectangle marks the ACI 318 d/2 reference location only \u2014 this drawing does not check punching-shear demand against capacity; that determination remains the design engineer\'s responsibility. Closed-tie (stirrup) shear reinforcement is a distinct system and is not shown here. Studs are shown in plan at their true computed position only; the section view does not show individual stud embedment or elevation.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفصيلة تسليح ثقب القص ${id}`,
    plan: 'مسقط', section: 'قطاع خلال العمود على طول L',
    column: 'عمود', rail: 'صف موصلات',
    colMark: 'العلامة', colElement: 'النوع', colDir: 'الوجه', colDia: 'القطر مم', colOff: 'الإزاحة مم', colStuds: 'الموصلات عدد وتباعد وأول موصل',
    critLabel: 'محيط القص الحرج، على بعد نصف العمق الفعال من وجه العمود، للتوضيح فقط',
    dLabel: (v) => `d = ${v}`,
    caption: 'رسم تفصيلي توضيحي لتسليح ثقب القص بموصلات الرأس أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع عدد صفوف الموصلات ومواضعها وعدد الموصلات في كل صف وتباعدها وتغلغلها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. المستطيل المتقطع يمثل موقع محيط القص الحرج المرجعي فقط على بعد نصف العمق الفعال من وجه العمود، ولا يتحقق هذا الرسم من مقارنة قوة القص المطلوبة بالمقاومة المتاحة، وتبقى هذه مسؤولية المهندس المصمم. التسليح بالكانات المغلقة نظام مختلف تماماً وغير موضح هنا. تظهر الموصلات في المسقط عند مواضعها الفعلية المحسوبة فقط؛ لا يُظهر القطاع تغلغل أو ارتفاع أي موصل بمفرده.',
    dirAttr: 'rtl',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 960;
const PLAN_BOX = { x: 80, y: 70, w: 800, h: 340 };
const SECTION_BOX = { x: 80, y: 460, w: 800, h: 200 };

export function renderPunchingShearDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);
  const { B, L: patchL, D, colB, colL, rails, studDia } = geometry.plan;

  const planScale = fitScale([{ contentW: patchL, contentH: B, boxW: PLAN_BOX.w - 80, boxH: PLAN_BOX.h - 70 }]);
  const sectionScale = fitScale([{ contentW: patchL, contentH: D + Math.max(colB, colL) * 0.4, boxW: SECTION_BOX.w - 80, boxH: SECTION_BOX.h - 70 }]);

  const tableRows = buildScheduleRows(geometry, l);
  // 6 narrower purpose-built columns, not 4 with a free-text "Detail"
  // column. [Found via this module's own cairosvg visual pass, not a
  // text-only check, in two stages: first, the combined "off=.../
  // n=.../first=..." string overflowed a quartered ~210px column
  // illegibly. Second, after splitting those figures into their own
  // columns, the Element cell's own "Rail 1 (Top)" / "Column (500mm x
  // 500mm)" text was still composing ASCII parentheses around a
  // scriptFontStack (Arabic-mode) cell — the same class of risk this
  // file's own header note on parenthesis-free Arabic strings warns
  // about for the fixed label dictionary, just reached here via a
  // dynamically-built string instead of a hardcoded one. Fixed by giving
  // direction and column size their own columns instead of embedding
  // either in Element, in both languages, not just Arabic — one string-
  // building path, not a per-language branch that could silently drift.]
  const markW = 45, dirW = 70, diaW = 60, offW = 80;
  const elementW = 170;
  const studsW = CANVAS_W - 120 - markW - elementW - dirW - diaW - offW;
  const tableCols = [
    { key: 'mark', label: l.colMark, width: markW },
    { key: 'element', label: l.colElement, width: elementW, script: true },
    { key: 'dir', label: l.colDir, width: dirW, script: true },
    { key: 'dia', label: l.colDia, width: diaW },
    { key: 'off', label: l.colOff, width: offW },
    { key: 'studs', label: l.colStuds, width: studsW, script: true },
  ];
  const tableY = SECTION_BOX.y + SECTION_BOX.h + 50;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .punch-title  { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .box-label    { font-size:13px; font-weight:bold; fill:#333; font-family: ${scriptFontStack}; }
    .stud-dot     { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }
    .rail-line    { stroke:#2a5a8c; stroke-width:1.2; }
    .col-rect     { fill:#f2f2f2; stroke:#333; stroke-width:1.6; }
    .crit-rect    { fill:none; stroke:#b23b3b; stroke-width:1.3; stroke-dasharray:7,4; }
    .crit-label   { font-size:11px; fill:#b23b3b; font-family: ${scriptFontStack}; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="punch-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderPlan(geometry, planScale, l)}
  ${renderSection(geometry, sectionScale, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

function renderPlan(geometry, scale, l) {
  const { B, L: patchL, colX0, colX1, colY0, colY1, critX0, critX1, critY0, critY1, rails, studDia } = geometry.plan;
  const px = PLAN_BOX.x + 40;
  const py = PLAN_BOX.y + 40;
  const pw = patchL * scale;
  const ph = B * scale;
  const X = (v) => px + v * scale;
  const Y = (v) => py + v * scale;

  const railLines = rails.map((r) => {
    const last = r.studs[r.studs.length - 1];
    return `<line x1="${X(r.baseX)}" y1="${Y(r.baseY)}" x2="${X(last.x)}" y2="${Y(last.y)}" class="rail-line"/>`;
  }).join('\n    ');

  // Mark-number labels, gated on marker size having room — same
  // legibility-gated convention raftPileDiagram.mjs uses (found via that
  // module's own cairosvg pass; applied here from the start rather than
  // rediscovered).
  const studR = Math.max(2.5, (studDia / 2) * scale);
  const studDots = rails.map((r, i) => {
    const mark = String(i + 2); // mark 1 is the column, see buildScheduleRows
    return r.studs.map((s, k) => {
      const label = (k === 0 && studR >= 7)
        ? `<text x="${X(s.x)}" y="${Y(s.y) - studR - 3}" text-anchor="middle" font-size="9" fill="#123564">${esc(mark)}</text>`
        : '';
      return `<circle cx="${X(s.x)}" cy="${Y(s.y)}" r="${studR}" class="stud-dot"/>${label}`;
    }).join('');
  }).join('');

  return `<g>
    <text x="${PLAN_BOX.x}" y="${PLAN_BOX.y}" class="box-label">${esc(l.plan)}</text>
    <rect x="${px}" y="${py}" width="${pw}" height="${ph}" fill="#ffffff" stroke="#333" stroke-width="1.6"/>
    <rect x="${X(critX0)}" y="${Y(critY0)}" width="${(critX1 - critX0) * scale}" height="${(critY1 - critY0) * scale}" class="crit-rect"/>
    <text x="${X(critX1) + 6}" y="${Y(critY0) + 10}" class="crit-label">${esc(l.critLabel)}</text>
    ${railLines}
    ${studDots}
    <rect x="${X(colX0)}" y="${Y(colY0)}" width="${(colX1 - colX0) * scale}" height="${(colY1 - colY0) * scale}" class="col-rect"/>
    <text x="${X((colX0 + colX1) / 2)}" y="${Y((colY0 + colY1) / 2) + 3}" text-anchor="middle" font-size="9" fill="#333">1</text>
    ${dimensionLine(px, py + ph + 22, px + pw, py + ph + 22, `L = ${fmt(patchL, 'mm', 0)}`)}
    ${dimensionLine(px - 22, py, px - 22, py + ph, `B = ${fmt(B, 'mm', 0)}`, { orientation: 'v' })}
  </g>`;
}

// Slab profile, effective depth d, column stub, and the d/2
// critical-perimeter location as two dashed reference lines — no
// individual studs. See this file's own "Section cut" header note.
function renderSection(geometry, scale, l) {
  const { L: patchL, D, d, colB, colL, colX0, colX1, critX0, critX1 } = geometry.plan;
  const sx = SECTION_BOX.x + 40;
  const sy = SECTION_BOX.y + 30;
  const sw = patchL * scale;
  const slabH = D * scale;
  const dH = d * scale;
  const colW = Math.max(6, colL * scale);
  const colX = sx + (colX0 + colX1) / 2 * scale - colW / 2;
  const colTopY = sy - Math.min(50, colB * scale * 0.5);

  return `<g>
    <text x="${SECTION_BOX.x}" y="${SECTION_BOX.y}" class="box-label">${esc(l.section)}</text>
    <rect x="${sx}" y="${sy}" width="${sw}" height="${slabH}" fill="#f6f6f6" stroke="#333" stroke-width="1.6"/>
    <rect x="${colX}" y="${colTopY}" width="${colW}" height="${sy - colTopY}" class="col-rect"/>
    <line x1="${sx + critX0 * scale}" y1="${sy}" x2="${sx + critX0 * scale}" y2="${sy + slabH}" class="crit-rect"/>
    <line x1="${sx + critX1 * scale}" y1="${sy}" x2="${sx + critX1 * scale}" y2="${sy + slabH}" class="crit-rect"/>
    ${dimensionLine(sx - 22, sy, sx - 22, sy + dH, l.dLabel(fmt(d, 'mm', 0)), { orientation: 'v' })}
    ${dimensionLine(sx + sw + 22, sy, sx + sw + 22, sy + slabH, `D = ${fmt(D, 'mm', 0)}`, { orientation: 'v' })}
  </g>`;
}

function buildScheduleRows(geometry, l) {
  const { rails, studDia } = geometry.plan;
  const dirLabels = DIR_LABEL[l === L.ar ? 'ar' : 'en'];
  // Column size (colB/colL) is not repeated here — same convention every
  // sibling schedule table already follows (pileCapDiagram.mjs's own
  // Column row shows only Mark/Element/dia='—'/position, never a
  // restated size): the input echoes it once, the table doesn't need a
  // second place to hold it.
  const rows = [{ mark: '1', element: l.column, dir: '\u2014', dia: '\u2014', off: '\u2014', studs: '\u2014' }];
  rails.forEach((r, i) => {
    rows.push({
      mark: String(i + 2),
      element: `${l.rail} ${i + 1}`,
      dir: dirLabels[r.dir],
      dia: String(Math.round(studDia)),
      off: fmt(r.offsetAlongFace, 'mm', 0),
      studs: `${r.studCount}@${fmt(r.studSpacingMM, 'mm', 0)}/${fmt(r.firstStudOffsetMM, 'mm', 0)}`,
    });
  });
  return rows;
}

// ── Chat-facing entry point (mode:'rebarDiagram' JSON payload) ────────
// Mirrors pileCapDiagram.mjs's / raftPileDiagram.mjs's parse*RebarPayload
// contract exactly.
export function parsePunchingShearRebarPayload(raw) {
  try {
    const geometry = computePunchingShearDiagramGeometry(raw);
    return { ok: true, type: 'punchingshear', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Syntax:
//   /diagram punchingshear id=PS1 B=3000 L=3000 D=250 deffmm=200
//     colB=500 colL=500 studdia=16 rails=4
//     rail1dir=n rail1off=0 rail1n=4 rail1first=100 rail1spacing=150
//     rail2dir=s rail2off=0 rail2n=4 rail2first=100 rail2spacing=150
//     rail3dir=e rail3off=0 rail3n=4 rail3first=100 rail3spacing=150
//     rail4dir=w rail4off=0 rail4n=4 rail4first=100 rail4spacing=150
//     [unit=mm]
// `rails=N` fixed-count scan mirrors footingDiagram.mjs's own
// strip/raft `collectColumns` convention and raftPileDiagram.mjs's own
// column scan exactly (rail1.. through railN.. of dir/off/n/first/
// spacing). Effective depth is keyed `deffmm=`, NOT `d=` — every flat
// key is lower-cased before lookup (same as every sibling parser), and
// `D=` (slab thickness) already lower-cases to the same `d` key a bare
// `d=` would use; `deffmm` is a deliberately distinct key, not a
// shortening. Same BAD_SYNTAX/UNSUPPORTED_TYPE reservation, same
// never-throws contract, same lower-cased leading token as every
// sibling parser ("punchingshear" one lowercase word).
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: punchingshear key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'punchingshear') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use punchingshear.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const n = num('rails');
    if (!Number.isFinite(n) || !Number.isInteger(n) || n < 1) {
      throw new DiagramError('BAD_PARAM', `"rails" must be an integer of at least 1, got ${JSON.stringify(kv.rails)}.`);
    }
    if (n > MAX_RAILS) {
      throw new DiagramError('TOO_MANY_RAILS', `At most ${MAX_RAILS} rails are supported in this schematic, got ${n}.`);
    }
    const rails = [];
    for (let i = 1; i <= n; i++) {
      rails.push({
        dir: kv[`rail${i}dir`], offsetAlongFace: num(`rail${i}off`),
        studCount: num(`rail${i}n`), firstStudOffsetMM: num(`rail${i}first`),
        studSpacingMM: num(`rail${i}spacing`),
      });
    }

    const geometry = computePunchingShearDiagramGeometry({
      slabId: kv.id, B: num('b'), L: num('l'), D: num('d'), dMM: num('deffmm'),
      colB: num('colb'), colL: num('coll'), studDiaMM: num('studdia'),
      rails, unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
