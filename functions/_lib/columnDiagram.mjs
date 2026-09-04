// functions/_lib/columnDiagram.mjs
//
// Deterministic, zero-AI SVG generator for column reinforcement details
// (cross section + elevation + single-tie detail + bar-bending schedule)
// — Plan Step 15 ("تفريد الأعمدة", numbered Step 14 in the original plan
// text, Step 15 after خطة_المرحلة_التالية_13-18.md's reordering). Same
// philosophy as footingDiagram.mjs and beamDiagram.mjs: every dimension,
// bar position, and count in the output is arithmetic on the KB data
// supplied, never a model's guess. This module owns compute+render only;
// it does not decide bar counts, diameters, or tie spacing — that is the
// KB/design layer's job (see INPUT CONTRACT below).
//
// SCOPE (v1): a single prismatic rectangular column (constant
// widthMM x depthMM over its full heightMM) with exactly ONE vertical-
// bar group distributed around the section PERIMETER, and ONE
// rectangular tie zone at a constant spacing over the full height.
// NOT modeled, on purpose (each needs a parametrization this module
// hasn't been given yet, same "explicit scope boundary" convention
// beamDiagram.mjs's own header uses):
//   - multiple bar-diameter groups (e.g. larger corner bars + smaller
//     intermediate face bars) — verticalBars is a single-group array by
//     construction; a second group would need its own perimeter-sharing
//     layout rule this module doesn't have yet.
//   - circular/spiral columns and ties.type:'spiral' — a spiral tie
//     wraps a CIRCULAR section (diameterMM), which this schema has no
//     field for (widthMM/depthMM is rectangular by construction);
//     bolting a spiral label onto a rectangular tie would be a
//     wrong-but-plausible-looking drawing, exactly the failure mode
//     this app's "never render a shape/number you can't defend" rule
//     exists to prevent. ties.type is validated against ['rectangular']
//     only; 'spiral' throws UNSUPPORTED_TIE_TYPE rather than silently
//     drawing a rectangle.
//   - intermediate/cross-ties for wide sections and seismic special-
//     confinement (closer) zones near the ends — both are real code
//     requirements (ECP 203 / ACI 318) this module does not compute.
//   - varying tie spacing along the height (e.g. tighter near
//     beam-column joints) — one spacing value governs the whole height.
//
// ── INPUT CONTRACT (what the KB layer should hand this module) ─────────
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   columnId: string,                  // column mark, e.g. "C-101"
//   widthMM: number,                   // section width (drawn horizontal in cross section)
//   depthMM: number,                   // section depth
//   heightMM: number,                  // clear/story height drawn in elevation
//   coverMM: number,                   // concrete cover to tie outer face
//   verticalBars: [                    // exactly ONE group (see SCOPE)
//     {
//       diameterMM: number, count: number,   // count must be EVEN — see
//                                             // ODD_BAR_COUNT below for why
//       position?: 'perimeter',              // only value supported
//       cuttingLengthMM?: number,            // full bar length if the KB
//                                            // layer already computed it;
//                                            // omit to show heightMM
//                                            // labeled "(extent)"/"امتداد"
//     }
//   ],
//   ties: {
//     diameterMM: number, spacingMM: number,
//     type?: 'rectangular',              // only value supported (see SCOPE)
//     cuttingLengthMM?: number,          // full tie cutting length incl.
//                                        // hooks, if already computed;
//                                        // omit to show the tie's own
//                                        // bend perimeter, honestly
//                                        // labeled "hooks not included"
//   },
//   lapSpliceMM?: number,                // lap-splice zone length at the
//                                        // column base, if the caller
//                                        // wants it marked; omit to draw
//                                        // no lap zone at all (never
//                                        // guessed from heightMM)
// }
//
// ── Vertical-bar perimeter layout (computeColumnBarPositions) ─────────
// Places 4 bars at the section's inner-rectangle corners, then
// distributes the remaining (count-4) bars across the four edges,
// split into a top/bottom PAIR and a left/right PAIR proportional to
// each pair's edge length, so a long rectangular column naturally gets
// more intermediate bars along its long face than its short one. This
// requires `count` to be EVEN: top/bottom and left/right edges always
// carry the SAME number of intermediate bars as their mirror edge (an
// asymmetric perimeter — three bars on top, one on bottom — is not a
// number this module will invent), so an odd (count-4) — which is
// impossible to split into two even edge-pairs — is rejected up front
// with a clear message rather than silently rounded or made asymmetric.
//
// ── /column and /image wiring — DONE in a follow-up session ────────────
// Wired following exactly the Step 20 pattern slabDiagram.mjs/
// shearWallDiagram.mjs/stairDiagram.mjs established (parseDiagramCommand
// below + diagramCommandRouter.mjs + chat.js's table-driven
// DIAGRAM_TYPE_RENDERERS/DIAGRAM_TYPE_ERROR_MESSAGE/REBAR_ELEMENT_DISPATCH
// — no chat.js dispatch-logic branch needed touching, only three table
// entries, since both dispatch paths were already generic by Step 20).
// The two lessons below (from Step 14's own work, and Step 15's own
// plan-text warning) were applied, not re-discovered the hard way:
//   1. No free-text classifier (classifyColumnDiagram) was added — this
//      module is reached only through the strict `column key=value ...`
//      /diagram syntax (via diagramCommandRouter.mjs) and the structured
//      mode:'rebarDiagram' JSON payload, exactly like slab/shearWall/
//      stair. No regex-based prompt classifier exists for it, so the
//      "raft B=6000..." false-positive-match failure class this note
//      originally warned about does not apply here.
//   2. `parseDiagramCommand`'s ASCII command syntax carries no language
//      signal — chat.js's existing `lang`-from-client convention (already
//      required for slab/shearWall/stair, see chat.js's own comments)
//      covers this module identically, nothing column-specific needed.
// beamDiagram.mjs remains unwired — out of scope for this pass; its
// nested bar-group/stirrup-zone schema needs a materially larger flat-text
// grammar than the single-group schemas (column included) this pattern
// was designed for.
//
// Resource lifecycle: this module is pure/synchronous — no timers, no
// fetch, no KV, no external handles of any kind. The caps below exist to
// bound Worker CPU time and output size on a request-scoped isolate, not
// to manage a leakable resource.
//
// Step 17: fully deterministic — no `env.AI`, no model call, no network
// fetch, no randomness anywhere in this file. Every SVG byte is arithmetic
// on computeColumnDiagramGeometry's own output. "Drawn extent" vs "actual
// cut length": see cuttingLengthMM in the INPUT CONTRACT above and
// structuralDrawingKit.mjs's header for the general rule this file follows
// (buildScheduleRows below shows the length column falling back to the
// drawn extent, suffixed, only when cuttingLengthMM is absent).

import {
  DiagramError, toMm, assertFinitePositive, assertInt, assertOneOf,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barDot, tieTickH, distributeTicks, barMarkTag,
  fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ──────────────────────────────────────────────────────
// Same role as beamDiagram.mjs's MAX_BAR_GROUPS/MAX_STIRRUP_ZONES: this
// is a chat-driven schematic tool, not a CAD system — bound worst-case
// loop counts and input ranges so one request can't build an oversized
// SVG, blow a CPU-time budget, or describe a section that cannot be
// drawn sanely (e.g. a 10mm-wide "column").
const MIN_SIDE_MM = 150;
const MAX_SIDE_MM = 3000;
const MIN_HEIGHT_MM = 300;
const MAX_HEIGHT_MM = 12000; // one story's worth, schematically — a multi-story run needs a real drafting tool
const MIN_BAR_COUNT = 4; // a rectangular tie needs at least its 4 corners held
const MAX_BAR_COUNT = 40;
const MIN_TIE_SPACING_MM = 30;
const MAX_TIE_SPACING_MM = 600;
const MAX_DRAWN_TIES_PER_COLUMN = 24; // matches distributeTicks' own hard cap — see that function's header

// ── Compute ──────────────────────────────────────────────────────────
export function computeColumnDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Column diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.columnId != null ? String(raw.columnId).slice(0, 40) : 'COLUMN';

  const widthMM = toMm(raw.widthMM, unit);
  const depthMM = toMm(raw.depthMM, unit);
  assertFinitePositive('widthMM', widthMM);
  assertFinitePositive('depthMM', depthMM);
  if (widthMM < MIN_SIDE_MM || widthMM > MAX_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"widthMM" must be between ${MIN_SIDE_MM}mm and ${MAX_SIDE_MM}mm for this schematic, got ${widthMM}mm.`);
  }
  if (depthMM < MIN_SIDE_MM || depthMM > MAX_SIDE_MM) {
    throw new DiagramError('BAD_PARAM', `"depthMM" must be between ${MIN_SIDE_MM}mm and ${MAX_SIDE_MM}mm for this schematic, got ${depthMM}mm.`);
  }

  const heightMM = toMm(raw.heightMM, unit);
  assertFinitePositive('heightMM', heightMM);
  if (heightMM < MIN_HEIGHT_MM || heightMM > MAX_HEIGHT_MM) {
    throw new DiagramError('BAD_PARAM', `"heightMM" must be between ${MIN_HEIGHT_MM}mm and ${MAX_HEIGHT_MM}mm for this schematic, got ${heightMM}mm.`);
  }

  const coverMM = toMm(raw.coverMM, unit);
  assertFinitePositive('coverMM', coverMM);

  if (!Array.isArray(raw.verticalBars) || raw.verticalBars.length !== 1) {
    throw new DiagramError('BAD_PARAM', '"verticalBars" must be an array with exactly one bar group in this schematic — see module scope note (multiple diameter groups are not modeled).');
  }
  const vRaw = raw.verticalBars[0];
  if (!vRaw || typeof vRaw !== 'object') throw new DiagramError('BAD_PARAM', 'verticalBars[0] must be an object.');
  const barDia = toMm(vRaw.diameterMM, unit);
  assertFinitePositive('verticalBars[0].diameterMM', barDia);
  assertInt('verticalBars[0].count', vRaw.count, { min: MIN_BAR_COUNT, max: MAX_BAR_COUNT });
  if (vRaw.count % 2 !== 0) {
    throw new DiagramError(
      'ODD_BAR_COUNT',
      `verticalBars[0].count must be even — this module distributes bars symmetrically (top/bottom and left/right edges carry the same intermediate-bar count as their mirror edge) and will not invent an asymmetric layout, got ${vRaw.count}.`,
    );
  }
  const position = vRaw.position || 'perimeter';
  assertOneOf('verticalBars[0].position', position, ['perimeter']);
  const vCuttingLengthMM = vRaw.cuttingLengthMM != null ? toMm(vRaw.cuttingLengthMM, unit) : null;
  if (vCuttingLengthMM != null) assertFinitePositive('verticalBars[0].cuttingLengthMM', vCuttingLengthMM);

  if (!raw.ties || typeof raw.ties !== 'object') {
    throw new DiagramError('BAD_PARAM', '"ties" is required: { diameterMM, spacingMM, type? }.');
  }
  const tieDia = toMm(raw.ties.diameterMM, unit);
  assertFinitePositive('ties.diameterMM', tieDia);
  const tieSpacing = toMm(raw.ties.spacingMM, unit);
  assertFinitePositive('ties.spacingMM', tieSpacing);
  if (tieSpacing < MIN_TIE_SPACING_MM || tieSpacing > MAX_TIE_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"ties.spacingMM" must be between ${MIN_TIE_SPACING_MM}mm and ${MAX_TIE_SPACING_MM}mm, got ${tieSpacing}mm.`);
  }
  const tieType = raw.ties.type || 'rectangular';
  // See the SCOPE note at the top of this file for why 'spiral' is
  // rejected outright rather than drawn as a rectangle.
  assertOneOf('ties.type', tieType, ['rectangular']);
  const tieCuttingLengthMM = raw.ties.cuttingLengthMM != null ? toMm(raw.ties.cuttingLengthMM, unit) : null;
  if (tieCuttingLengthMM != null) assertFinitePositive('ties.cuttingLengthMM', tieCuttingLengthMM);

  const lapSpliceMM = raw.lapSpliceMM != null ? toMm(raw.lapSpliceMM, unit) : null;
  if (lapSpliceMM != null) {
    assertFinitePositive('lapSpliceMM', lapSpliceMM);
    if (lapSpliceMM >= heightMM) {
      throw new DiagramError('LAP_EXCEEDS_HEIGHT', `"lapSpliceMM" (${lapSpliceMM}mm) must be less than "heightMM" (${heightMM}mm).`);
    }
  }

  // Bar-CENTER envelope: inset from the column face by cover + tie
  // diameter (the tie loop sits just inside the cover) + half the
  // vertical bar's own diameter — the same cover-to-center logic
  // footingDiagram.mjs's computeDowelGeometry uses along one axis,
  // applied here on BOTH axes at once because vertical bars sit on a
  // closed rectangular perimeter, not a single line. One coverMM value
  // governs both axes (this schema has no per-axis cover input, unlike
  // e.g. a beam's b/h which are already independent).
  const insetX = coverMM + tieDia + barDia / 2;
  const insetY = insetX;
  const innerW = widthMM - 2 * insetX;
  const innerH = depthMM - 2 * insetY;
  if (innerW <= 0 || innerH <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm), tie diameter (${tieDia}mm), and bar diameter (${barDia}mm) leave no room for vertical bars inside a ${widthMM}x${depthMM}mm section.`);
  }
  const positions = computeColumnBarPositions({ innerW, innerH, count: vRaw.count })
    .map((p) => ({ xMM: insetX + p.xMM, yMM: insetY + p.yMM }));

  // Tie outer rectangle sits at `coverMM` from the column face on all
  // four sides — the tie's own bend legs, before any hook allowance
  // (not computed here — see the schedule row this backs, labeled
  // "bend perimeter, hooks not included" rather than a fabricated total).
  const tieOuter = { x: coverMM, y: coverMM, w: widthMM - 2 * coverMM, h: depthMM - 2 * coverMM };
  if (tieOuter.w <= 0 || tieOuter.h <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) leaves no room for a tie inside a ${widthMM}x${depthMM}mm section.`);
  }

  // Real (undrawn-cap-free) tie count over the full height — computed
  // ONCE here, not re-derived independently in both the elevation
  // renderer and the schedule table, so the two can never silently
  // drift apart (exactly the failure class Step 14.1's mesh/dowel-width
  // mixup came from — see برومبت_استكمال_العمل.md's lesson 1).
  const tieCount = Math.max(2, Math.round(heightMM / tieSpacing) + 1);

  return {
    type: 'column', unit, id, widthMM, depthMM, heightMM, coverMM,
    verticalBars: { dia: barDia, count: vRaw.count, position, cuttingLengthMM: vCuttingLengthMM, positions },
    ties: { dia: tieDia, spacing: tieSpacing, type: tieType, cuttingLengthMM: tieCuttingLengthMM, outer: tieOuter, count: tieCount },
    lapSpliceMM,
  };
}

// See "Vertical-bar perimeter layout" note at the top of this file.
// innerW/innerH are the bar-CENTER envelope dimensions (already inset
// from the column face by the caller); returned points are relative to
// that envelope's own top-left corner at (0,0).
function computeColumnBarPositions({ innerW, innerH, count }) {
  const remaining = count - 4; // always even — enforced by the ODD_BAR_COUNT check in the caller
  const halfRemaining = remaining / 2;
  const topCount = Math.round((halfRemaining * innerW) / (innerW + innerH));
  const leftCount = halfRemaining - topCount;

  const points = [
    { xMM: 0, yMM: 0 }, { xMM: innerW, yMM: 0 },
    { xMM: innerW, yMM: innerH }, { xMM: 0, yMM: innerH },
  ];
  for (let i = 1; i <= topCount; i++) {
    const x = (innerW * i) / (topCount + 1);
    points.push({ xMM: x, yMM: 0 });
    points.push({ xMM: x, yMM: innerH });
  }
  for (let i = 1; i <= leftCount; i++) {
    const y = (innerH * i) / (leftCount + 1);
    points.push({ xMM: 0, yMM: y });
    points.push({ xMM: innerW, yMM: y });
  }
  return points;
}

// ── Labels ───────────────────────────────────────────────────────────
// [Open design question, resolved explicitly per the handoff prompt's
// instruction to decide before writing any render code]
//
// DECISION: local `L = {en:{...}, ar:{...}}` dictionary in THIS file,
// following beamDiagram.mjs's pattern — NOT an extension of
// structuralLabels.mjs. Reasoning:
//   1. structuralLabels.mjs's own header explicitly scopes itself to
//      footingDiagram.mjs only, and explicitly flags migrating
//      beamDiagram.mjs onto it as real-but-untested future work, out of
//      scope for whatever step touches it next. The two live diagram
//      modules (footing, beam) are ALREADY on two different patterns;
//      adding a third consumer to structuralLabels.mjs now would leave
//      that split in a WORSE, inconsistent three-way state (two files
//      still on the local pattern, one file half-migrated) rather than
//      resolving it — the actual unification is "migrate beamDiagram.mjs
//      AND columnDiagram.mjs onto structuralLabels.mjs together", which
//      is Step 18-adjacent future work, not this step's job.
//   2. This matches Step 14's own "least possible change" precedent
//      (خطة_المرحلة_التالية_13-18.md, lesson 4: the pedestal-dimension
//      table-column decision).
// This IS real deferred debt — recorded verbatim so a future session
// doesn't have to re-discover it (see the Step 17 CHANGELOG note this
// project's own plan calls for).
//
// PARENTHESES/EM-DASH WARNING: structuralLabels.mjs documents (and
// verified via cairosvg glyph-probing) that Noto Naskh Arabic — the
// font scriptFontStack actually selects for lang==='ar' — has no glyph
// for "(", ")", or an em/en-dash, and that browsers' per-glyph
// font-family fallback may not save a non-browser SVG renderer from
// tofu here. beamDiagram.mjs's own Arabic caption was NOT written
// against this constraint (it contains both parentheses and an em-dash)
// — that inconsistency is real and unresolved, not something this file
// silently repeats. Every Arabic value below is written parenthesis-
// and dash-free, following footingDiagram.mjs/structuralLabels.mjs's
// verified-safe convention instead.
const L = {
  en: {
    title: (id) => `COLUMN ${id} \u2014 REINFORCEMENT DETAIL`,
    crossSection: 'CROSS SECTION', elevation: 'ELEVATION', tieDetail: 'TIE DETAIL',
    vertical: 'Vertical', tie: 'Tie', lapZone: 'Lap Splice Zone',
    extentSuffix: ' (extent)', perimeterSuffix: ' (bend perimeter, hooks not included)',
    tieHookNote: 'add standard hook length per code \u2014 not shown',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design (ECP 203 / ACI 318) before issuing for construction. Lengths marked "(extent)" are the drawn member length only. The tie length shown is its bend perimeter only \u2014 add development / hook / lap length per your design code before fabrication.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد العمود ${id}`,
    crossSection: 'قطاع عرضي', elevation: 'منظور جانبي', tieDetail: 'تفصيلة الكانة',
    vertical: 'رأسي', tie: 'كانة', lapZone: 'منطقة تداخل التسليح',
    extentSuffix: ' امتداد', perimeterSuffix: ' محيط الكانة بدون الكلبتين',
    tieHookNote: 'أضف طول الكلبتين حسب الكود، غير موضح بالرسم',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. الأطوال المُعلَّمة امتداد هي طول الامتداد فقط. طول الكانة المذكور هو محيط الانحناء فقط بدون الكلبتين؛ أضف طول التداخل والكلبتين حسب الكود المستخدم.',
    dirAttr: 'rtl',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 950;
const SECTION_BOX = { x: 70, y: 110, w: 260, h: 260 };
// h=260: renderTieDetail below draws the tie rect + a dimension line in
// a region sized by fitScale (boxH = TIE_BOX.h-86, guaranteeing an
// 0.85-margin fit — see that call site), THEN two fixed-position text
// lines (dia label + hook note) anchored from THIS BOX'S OWN bottom
// edge, not from the rect's variable height. An earlier version
// computed the text Y from the rect's bottom instead and measured only
// a 3.75px margin before the box edge in the worst case tested (400mm
// square column, 40mm cover, 10mm ties) — the exact bug class
// برومبت_استكمال_العمل.md's lesson 2 documents (a variable-height
// element's trailing content positioned relative to the wrong end, only
// caught by measuring actual rendered pixel Y values, not by any
// text-content test). Fixed-anchoring the footer text removed the
// dependency on `h` entirely; re-measured after the fix across four
// deliberately extreme width/depth/cover/tie-diameter combinations
// (see this session's verification pass) with a clear, positive margin
// in every case.
const TIE_BOX = { x: 70, y: SECTION_BOX.y + SECTION_BOX.h + 70, w: 260, h: 260 };
const ELEV_BOX = { x: 430, y: 110, w: 220, h: (TIE_BOX.y + TIE_BOX.h) - 110 };

export function renderColumnDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const sectionScale = fitScale([{ contentW: geometry.widthMM, contentH: geometry.depthMM, boxW: SECTION_BOX.w - 60, boxH: SECTION_BOX.h - 60 }]);
  // boxH reserves 40px below the title for the dimension line/label AND
  // a further fixed 46px FOOTER strip for the two text lines below that
  // (dia label + hook note) — the footer text is positioned from the
  // BOX'S OWN bottom edge (see renderTieDetail), not from this rect's
  // variable height, precisely to avoid the "Y pinned to the wrong end"
  // bug برومبت_استكمال_العمل.md's lesson 2 documents (a caption's first
  // line computed from the LAST line of a variable-height block above
  // it once floated 8px above that block's own edge — undetected by
  // text-only tests, only found by measuring rendered SVG pixel
  // coordinates directly, exactly what this fitScale budget and the
  // measurement pass in this session's own test run were built to
  // prevent from recurring here).
  const tieScale = fitScale([{ contentW: geometry.ties.outer.w, contentH: geometry.ties.outer.h, boxW: TIE_BOX.w - 70, boxH: TIE_BOX.h - 86 }]);
  const elevScale = fitScale([{ contentW: geometry.widthMM * 2.4, contentH: geometry.heightMM, boxW: ELEV_BOX.w, boxH: ELEV_BOX.h - 20 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = Math.max(TIE_BOX.y + TIE_BOX.h, ELEV_BOX.y + ELEV_BOX.h) + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .column-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .zone-label   { font-size:10.5px; fill:#8a6d00; font-family: ${scriptFontStack}; }
    .bar-dot-column { fill:#1f5aa6; stroke:#123564; stroke-width:0.6; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="column-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderCrossSection(geometry, sectionScale, SECTION_BOX, l)}
  ${renderTieDetail(geometry, tieScale, TIE_BOX, l)}
  ${renderElevationView(geometry, elevScale, ELEV_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

function renderCrossSection(geometry, scale, box, l) {
  const { widthMM, depthMM, verticalBars, ties } = geometry;
  const w = widthMM * scale, h = depthMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + (box.h - h) / 2;
  let svg = `<g class="cross-section">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.crossSection)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" class="concrete-outline"/>`;
  const tx = sx + ties.outer.x * scale, ty = sy + ties.outer.y * scale;
  svg += `<rect x="${tx}" y="${ty}" width="${ties.outer.w * scale}" height="${ties.outer.h * scale}" class="stirrup-outline"/>`;
  for (const p of verticalBars.positions) {
    svg += barDot(sx + p.xMM * scale, sy + p.yMM * scale, verticalBars.dia, scale, 'column');
  }
  svg += barMarkTag(sx + w + 24, sy + h / 2, `${verticalBars.count}\u00d8${Math.round(verticalBars.dia)}`, { r: 13 });
  svg += dimensionLine(sx, sy + h + 20, sx + w, sy + h + 20, `${Math.round(widthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 20, sy, sx - 20, sy + h, `${Math.round(depthMM)}mm`, { orientation: 'v', tick: 5 });
  svg += `</g>`;
  return svg;
}

function renderTieDetail(geometry, scale, box, l) {
  const { ties } = geometry;
  const w = ties.outer.w * scale, h = ties.outer.h * scale;
  const sx = box.x + (box.w - w) / 2;
  // Rect+dimension-line region is [box.y+26, box.y+box.h-46] — matches
  // the fitScale boxH budget above exactly (box.h-86 total minus the
  // dimension-line/label's own ~40px), so `h` is guaranteed (by
  // fitScale's own 0.85 margin) to leave room here without depending on
  // the footer text placed below.
  const regionTop = box.y + 26, regionBottom = box.y + box.h - 46;
  const sy = regionTop + (regionBottom - regionTop - h) / 2;
  let svg = `<g class="tie-detail">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 10}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.tieDetail)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" rx="3" class="stirrup-outline"/>`;
  svg += dimensionLine(sx, sy + h + 18, sx + w, sy + h + 18, `${Math.round(ties.outer.w)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 18, sy, sx - 18, sy + h, `${Math.round(ties.outer.h)}mm`, { orientation: 'v', tick: 5 });
  // Two SEPARATE text nodes, not one — mixing "\u00d8${dia}mm" (engineering
  // notation, must stay on defaultFontStack per structuralDrawingKit.mjs's
  // documented font-split rule) into the SAME <text> element as the
  // translated hook note (needs scriptFontStack) previously put both on
  // scriptFontStack together, which is exactly the tofu risk the
  // Arabic-punctuation warning at the top of this file exists to avoid —
  // caught by test_columnDiagram.mjs's punctuation-regression check, not
  // by inspection. Splitting them is the fix, mirroring how barMarkTag
  // (default font) and view-title (script font) already stay separate
  // elsewhere in this file.
  //
  // Y anchored from the BOX'S OWN bottom edge (fixed offsets), NOT from
  // `sy + h` (the rect's variable bottom) — see the fitScale comment
  // above for why this specific ordering was chosen after measuring the
  // first version overflow past TIE_BOX's edge by a few px.
  svg += `<text x="${box.x + box.w / 2}" y="${box.y + box.h - 32}" text-anchor="middle" class="dim-label">\u00d8${Math.round(ties.dia)}mm</text>`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y + box.h - 16}" text-anchor="middle" class="sheet-caption" dir="${l.dirAttr}">${esc(l.tieHookNote)}</text>`;
  svg += `</g>`;
  return svg;
}

function renderElevationView(geometry, scale, box, l) {
  const { widthMM, heightMM, ties, lapSpliceMM, verticalBars } = geometry;
  const w = widthMM * scale, h = heightMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const topY = box.y + 10;
  const botY = topY + h;
  let svg = `<g class="elevation">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.elevation)}</text>`;
  svg += `<rect x="${sx}" y="${topY}" width="${w}" height="${h}" class="concrete-outline"/>`;

  const drawCount = Math.min(ties.count, MAX_DRAWN_TIES_PER_COLUMN);
  for (const ty of distributeTicks(topY, botY, drawCount)) {
    svg += tieTickH(sx, sx + w, ty);
  }

  // The two extreme (outermost) perimeter bar lines, drawn full height —
  // a representative pair, not all `count` bars individually (the cross
  // section already shows the true count/layout; this view exists for
  // tie spacing + lap-zone context, matching how beamDiagram.mjs's own
  // elevation is the "where", not the "how many", view).
  svg += `<line x1="${sx + 4}" y1="${topY}" x2="${sx + 4}" y2="${botY}" class="bar-bottom"/>`;
  svg += `<line x1="${sx + w - 4}" y1="${topY}" x2="${sx + w - 4}" y2="${botY}" class="bar-bottom"/>`;
  svg += barMarkTag(sx + w + 22, topY + 16, `${verticalBars.count}\u00d8${Math.round(verticalBars.dia)}`, { r: 12 });

  if (lapSpliceMM != null) {
    const lapH = lapSpliceMM * scale;
    const lapY = botY - lapH;
    svg += `<rect x="${sx}" y="${lapY}" width="${w}" height="${lapH}" fill="#fff3cd" fill-opacity="0.55" stroke="#b8860b" stroke-width="1" stroke-dasharray="4,2"/>`;
    svg += dimensionLine(sx - 18, lapY, sx - 18, botY, `${Math.round(lapSpliceMM)}mm`, { orientation: 'v', tick: 5 });
    svg += `<text x="${sx + w + 8}" y="${(lapY + botY) / 2}" class="zone-label" dir="${l.dirAttr}">${esc(l.lapZone)}</text>`;
  }

  svg += dimensionLine(sx + w + 50, topY, sx + w + 50, botY, `H = ${(heightMM / 1000).toFixed(2)}m`, { orientation: 'v' });
  svg += `<text x="${sx + w / 2}" y="${botY + 14}" text-anchor="middle" class="support-label">\u00d8${Math.round(ties.dia)}@${Math.round(ties.spacing)}</text>`;
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const rows = [];
  const vb = geometry.verticalBars;
  rows.push({
    mark: 'V1',
    element: l.vertical,
    dia: String(Math.round(vb.dia)),
    count: String(vb.count),
    length: vb.cuttingLengthMM != null ? String(Math.round(vb.cuttingLengthMM)) : `${Math.round(geometry.heightMM)}${l.extentSuffix}`,
  });
  const tiePerimeterMM = 2 * (geometry.ties.outer.w + geometry.ties.outer.h);
  rows.push({
    mark: 'T1',
    element: l.tie,
    dia: String(Math.round(geometry.ties.dia)),
    count: `@${Math.round(geometry.ties.spacing)} (${geometry.ties.count})`,
    length: geometry.ties.cuttingLengthMM != null ? String(Math.round(geometry.ties.cuttingLengthMM)) : `${Math.round(tiePerimeterMM)}${l.perimeterSuffix}`,
  });
  if (geometry.lapSpliceMM != null) {
    rows.push({
      mark: '\u2014',
      element: l.lapZone,
      dia: '\u2014',
      count: '\u2014',
      length: String(Math.round(geometry.lapSpliceMM)),
    });
  }
  return rows;
}

// ── Chat-facing entry point ────────────────────────────────────────────
// Mirrors beamDiagram.mjs's parseBeamRebarPayload() error-shape contract
// exactly ({ok:true,...} / {ok:false,code,message}). Never throws a
// DiagramError out; anything else (a genuine programmer error) is
// rethrown, same as both reference modules.
export function parseColumnRebarPayload(raw) {
  try {
    const geometry = computeColumnDiagramGeometry(raw);
    return { ok: true, type: 'column', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Added in a follow-up session, extending Step 20's wiring to the one
// module its own CHANGELOG entry flagged as still unwired. Mirrors
// slabDiagram.mjs's parseDiagramCommand exactly: same leading-token +
// "key=value key=value ..." syntax, same BAD_SYNTAX/UNSUPPORTED_TYPE
// reservation (BAD_SYNTAX = no leading-token+params shape at all;
// UNSUPPORTED_TYPE = shape present but leading token isn't "column" —
// lets diagramCommandRouter.mjs try the next module without masking a
// real syntax error), same never-throws contract, error results also
// carry `.type` (the pattern slab/shearWall/stairDiagram.mjs's own catch
// blocks established — footingDiagram.mjs's original parseDiagramCommand
// predates that convention and still omits it on error).
//
// Syntax:
//   /diagram column id=C1 width=400 depth=400 height=3000 cover=40
//     bardia=20 barcount=8 tiedia=10 tiespacing=150
//     [lap=600] [unit=mm]
// No key for tie type or bar position: this schema supports exactly one
// value for each ('rectangular' ties, 'perimeter' bars — see the SCOPE
// note at the top of this file), so there is nothing for a flat command
// to choose between yet; computeColumnDiagramGeometry's own defaults
// apply unchanged when those keys are omitted, same as every other
// optional field this parser doesn't expose (verticalBars[0]
// .cuttingLengthMM, ties.cuttingLengthMM — override-only fields with no
// flat-command key in slabDiagram.mjs's own command syntax either).
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: column key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'column') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use column.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const geometry = computeColumnDiagramGeometry({
      columnId: kv.id, widthMM: num('width'), depthMM: num('depth'),
      heightMM: num('height'), coverMM: num('cover'),
      verticalBars: [{ diameterMM: num('bardia'), count: num('barcount') }],
      ties: { diameterMM: num('tiedia'), spacingMM: num('tiespacing') },
      lapSpliceMM: num('lap'), unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
