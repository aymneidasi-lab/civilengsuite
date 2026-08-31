// functions/_lib/wallOpeningDiagram.mjs
//
// Deterministic, zero-AI SVG generator for trim reinforcement around a
// single rectangular opening (door/duct) cut into a shear or bearing
// wall panel — New-element track, Part 2 candidate ("Wall Opening Trim
// Bars", ACI 318 gap list, high priority). Same philosophy as every
// other module in this app: every dimension, bar position, and count in
// the output is arithmetic on the KB data supplied, never a model's
// guess. This module owns compute+render only.
//
// SCOPE (v1): ONE rectangular opening in a single prismatic rectangular
// wall panel (constant lengthMM x thicknessMM over its full heightMM),
// with ONE symmetric trim-bar group (same diameter/count/spacing on all
// four sides of the opening — top, bottom, left, right) plus an OPTIONAL
// symmetric diagonal corner-bar group (same at all four corners) for
// crack control. Same "single symmetric group" simplification
// columnDiagram.mjs's ties and shearWallDiagram.mjs's boundaryElement
// already use.
// NOT modeled, on purpose:
//   - more than one opening per wall panel — a second opening needs its
//     own overlap/zone-tiling rule this module doesn't have yet (see
//     assertNoIntervalOverlap in structuralDrawingKit.mjs for the kind
//     of rule that would be needed, and footingDiagram.mjs's
//     multi-column handling for the shape such a rule would take).
//   - the wall's own distributed field mesh (vertical+horizontal bars
//     away from the opening) or boundary elements at the wall ends —
//     that is shearWallDiagram.mjs's job; this module draws ONLY the
//     opening and its local trim/diagonal reinforcement.
//   - non-rectangular openings (round duct penetrations, irregular
//     shapes).
//   - computing the REQUIRED trim-bar area to replace interrupted mesh
//     steel per code (ACI 318 §14.3.7 / ECP 203 equivalent) — this
//     module draws whatever diameter/count the caller supplies; it does
//     not size replacement steel, the same "never invent a number you
//     can't defend" boundary columnDiagram.mjs's ties/lapSpliceMM keep.
//   - development length / hook detailing at trim-bar or diagonal-bar
//     ends — `extensionMM` is a drawn dimension the caller supplies, not
//     a computed development length; see cuttingLengthMM handling below
//     for the same "(extent)" honesty convention every sibling module
//     uses.
//
// ── DIRECTION CONVENTION ────────────────────────────────────────────
// opening.xMM is measured from the wall's LEFT edge to the opening's
// LEFT edge (horizontal, plan-length axis). opening.sillMM is measured
// from the wall's BASE (floor) to the opening's BOTTOM edge — matching
// how a door/window sill height is actually specified on a real
// drawing, not from the wall's top. Because every render path in this
// app draws SVG y increasing DOWNWARD from the wall's top (matching
// columnDiagram.mjs's/shearWallDiagram.mjs's own elevation views, where
// the top of the drawing is the wall's top end), computeWallOpeningDiagramGeometry
// converts sillMM into `opening.topFromWallTopMM` ONCE, here, so the
// renderer and the bounds-check below can never independently
// re-derive it and drift apart (the exact failure class this project's
// own lessons file warns against — see columnDiagram.mjs's tieCount
// comment for the same reasoning applied to a different field).
//
// ── INPUT CONTRACT ───────────────────────────────────────────────────
// {
//   unit?: 'mm'|'cm'|'m',
//   wallId: string,
//   lengthMM: number, heightMM: number, thicknessMM: number, coverMM: number,
//   opening: {
//     widthMM: number, heightMM: number,
//     xMM: number,      // wall-left edge -> opening-left edge
//     sillMM: number,   // wall base -> opening-bottom edge
//   },
//   trimBars: {                     // one symmetric group, all 4 sides
//     diameterMM: number, count: number,       // bars per side
//     spacingMM: number,                       // spacing between bars
//                                               // WITHIN one side's group
//                                               // (perpendicular to the
//                                               // opening face); unused
//                                               // visually when count=1
//                                               // but always required —
//                                               // avoids a conditional
//                                               // validation branch.
//     faceOffsetMM: number,          // gap from the opening's cut face
//                                     // to the NEAREST trim bar
//     extensionMM: number,           // how far each trim bar runs past
//                                     // each end of the opening edge it
//                                     // reinforces (anchorage allowance)
//     cuttingLengthMM?: number,      // full bar length if already
//                                     // computed; omit to show the
//                                     // drawn extent, "(extent)"-suffixed
//   },
//   diagonalBars?: {                 // omit for no corner diagonals
//     diameterMM: number, count: number,   // bars per corner (x4 total)
//     legMM: number,                       // straight projection along
//                                           // each axis from the corner;
//                                           // drawn bar length = legMM*root2
//     cuttingLengthMM?: number,
//   },
// }
//
// Resource lifecycle: pure/synchronous — no timers, no fetch, no KV, no
// external handles of any kind, same as every sibling module. The
// MAX_* caps below exist to bound Worker CPU time and output size on a
// request-scoped isolate.
//
// Fully deterministic: no env.AI, no model call, no randomness anywhere
// in this file. Every SVG byte is arithmetic on this file's own compute
// output.
//
// ── Router / chat.js / HTML wiring ──────────────────────────────────
// Intentionally NOT done in this pass — build-only, per this session's
// explicit request to defer the batched integration step (diagramCommandRouter.mjs
// + chat.js + footing_pro/pc_suite HTML) until several new elements have
// accumulated. See برومبت_استكمال_العمل_v16.md's Phase A/Phase B split.
// parseDiagramCommand below is written now (same as every sibling
// module) so Phase B has nothing left to design later, only to wire.

import {
  DiagramError, toMm, assertFinitePositive, assertInt,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, barMarkTag, fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ─────────────────────────────────────────────────────
const MIN_LENGTH_MM = 600;
const MAX_LENGTH_MM = 12000;
const MIN_HEIGHT_MM = 2000;
const MAX_HEIGHT_MM = 6000; // one story, schematically — same rationale as shearWallDiagram.mjs's MAX_HEIGHT_MM
const MIN_THICKNESS_MM = 150;
const MAX_THICKNESS_MM = 600;
const MIN_OPENING_DIM_MM = 200;
const MAX_OPENING_DIM_MM = 3000;
const MIN_TRIM_BAR_COUNT = 1;
const MAX_TRIM_BAR_COUNT = 6;
const MIN_TRIM_SPACING_MM = 30;
const MAX_TRIM_SPACING_MM = 300;
const MIN_FACE_OFFSET_MM = 20;
const MAX_FACE_OFFSET_MM = 150;
const MIN_EXTENSION_MM = 100;
const MAX_EXTENSION_MM = 1500;
const MIN_DIAGONAL_COUNT = 1;
const MAX_DIAGONAL_COUNT = 4;
const MIN_DIAGONAL_LEG_MM = 100;
const MAX_DIAGONAL_LEG_MM = 1000;

// ── Compute ─────────────────────────────────────────────────────────
export function computeWallOpeningDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Wall opening diagram input must be an object.');
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

  if (!raw.opening || typeof raw.opening !== 'object') {
    throw new DiagramError('BAD_PARAM', '"opening" is required: { widthMM, heightMM, xMM, sillMM }.');
  }
  const openW = toMm(raw.opening.widthMM, unit);
  const openH = toMm(raw.opening.heightMM, unit);
  assertFinitePositive('opening.widthMM', openW);
  assertFinitePositive('opening.heightMM', openH);
  if (openW < MIN_OPENING_DIM_MM || openW > MAX_OPENING_DIM_MM) {
    throw new DiagramError('BAD_PARAM', `"opening.widthMM" must be between ${MIN_OPENING_DIM_MM}mm and ${MAX_OPENING_DIM_MM}mm, got ${openW}mm.`);
  }
  if (openH < MIN_OPENING_DIM_MM || openH > MAX_OPENING_DIM_MM) {
    throw new DiagramError('BAD_PARAM', `"opening.heightMM" must be between ${MIN_OPENING_DIM_MM}mm and ${MAX_OPENING_DIM_MM}mm, got ${openH}mm.`);
  }
  const openX = toMm(raw.opening.xMM, unit);
  const sillMM = toMm(raw.opening.sillMM, unit);
  if (typeof openX !== 'number' || !Number.isFinite(openX) || openX < 0) {
    throw new DiagramError('BAD_PARAM', `"opening.xMM" must be a non-negative finite number, got ${JSON.stringify(raw.opening.xMM)}.`);
  }
  if (typeof sillMM !== 'number' || !Number.isFinite(sillMM) || sillMM < 0) {
    throw new DiagramError('BAD_PARAM', `"opening.sillMM" must be a non-negative finite number, got ${JSON.stringify(raw.opening.sillMM)}.`);
  }
  if (openX + openW > lengthMM || sillMM + openH > heightMM) {
    throw new DiagramError(
      'OPENING_OUT_OF_BOUNDS',
      `Opening [x=${openX}..${openX + openW}, sill=${sillMM}..${sillMM + openH}] does not fit within the ${lengthMM}x${heightMM}mm wall panel.`,
    );
  }
  // Converted ONCE here — see the DIRECTION CONVENTION note at the top
  // of this file for why the renderer must never re-derive this itself.
  const topFromWallTopMM = heightMM - sillMM - openH;

  if (!raw.trimBars || typeof raw.trimBars !== 'object') {
    throw new DiagramError('BAD_PARAM', '"trimBars" is required: { diameterMM, count, spacingMM, faceOffsetMM, extensionMM }.');
  }
  const trimDia = toMm(raw.trimBars.diameterMM, unit);
  assertFinitePositive('trimBars.diameterMM', trimDia);
  assertInt('trimBars.count', raw.trimBars.count, { min: MIN_TRIM_BAR_COUNT, max: MAX_TRIM_BAR_COUNT });
  const trimSpacing = toMm(raw.trimBars.spacingMM, unit);
  assertFinitePositive('trimBars.spacingMM', trimSpacing);
  if (trimSpacing < MIN_TRIM_SPACING_MM || trimSpacing > MAX_TRIM_SPACING_MM) {
    throw new DiagramError('BAD_PARAM', `"trimBars.spacingMM" must be between ${MIN_TRIM_SPACING_MM}mm and ${MAX_TRIM_SPACING_MM}mm, got ${trimSpacing}mm.`);
  }
  const faceOffsetMM = toMm(raw.trimBars.faceOffsetMM, unit);
  assertFinitePositive('trimBars.faceOffsetMM', faceOffsetMM);
  if (faceOffsetMM < MIN_FACE_OFFSET_MM || faceOffsetMM > MAX_FACE_OFFSET_MM) {
    throw new DiagramError('BAD_PARAM', `"trimBars.faceOffsetMM" must be between ${MIN_FACE_OFFSET_MM}mm and ${MAX_FACE_OFFSET_MM}mm, got ${faceOffsetMM}mm.`);
  }
  const extensionMM = toMm(raw.trimBars.extensionMM, unit);
  assertFinitePositive('trimBars.extensionMM', extensionMM);
  if (extensionMM < MIN_EXTENSION_MM || extensionMM > MAX_EXTENSION_MM) {
    throw new DiagramError('BAD_PARAM', `"trimBars.extensionMM" must be between ${MIN_EXTENSION_MM}mm and ${MAX_EXTENSION_MM}mm, got ${extensionMM}mm.`);
  }
  const trimCuttingLengthMM = raw.trimBars.cuttingLengthMM != null ? toMm(raw.trimBars.cuttingLengthMM, unit) : null;
  if (trimCuttingLengthMM != null) assertFinitePositive('trimBars.cuttingLengthMM', trimCuttingLengthMM);

  // Perpendicular reach of the farthest trim bar from the opening's cut
  // face — used only to position the drawn bar lines.
  const faceReachMM = faceOffsetMM + (raw.trimBars.count - 1) * trimSpacing;
  // Total bounding margin around the opening the trim group actually
  // occupies, in EITHER direction: a side's own perpendicular reach, or
  // the adjacent sides' bar-length extension past that same corner —
  // whichever is larger. Because the group is symmetric on all four
  // sides, this reduces to one scalar shared by all four margins (see
  // this file's header derivation note kept alongside the CHANGELOG
  // entry for this step, not duplicated here to avoid drift between two
  // copies of the same explanation).
  const envelopeMM = Math.max(extensionMM, faceReachMM);
  if (
    openX - envelopeMM < 0 || openX + openW + envelopeMM > lengthMM ||
    topFromWallTopMM - envelopeMM < 0 || topFromWallTopMM + openH + envelopeMM > heightMM
  ) {
    throw new DiagramError(
      'TRIM_EXCEEDS_WALL',
      `Trim-bar envelope (${Math.round(envelopeMM)}mm beyond the opening on every side) does not fit within the ${lengthMM}x${heightMM}mm wall panel at this opening position.`,
    );
  }

  let diagonalBars = null;
  if (raw.diagonalBars != null) {
    const db = raw.diagonalBars;
    if (!db || typeof db !== 'object') throw new DiagramError('BAD_PARAM', '"diagonalBars" must be an object.');
    const diagDia = toMm(db.diameterMM, unit);
    assertFinitePositive('diagonalBars.diameterMM', diagDia);
    assertInt('diagonalBars.count', db.count, { min: MIN_DIAGONAL_COUNT, max: MAX_DIAGONAL_COUNT });
    const legMM = toMm(db.legMM, unit);
    assertFinitePositive('diagonalBars.legMM', legMM);
    if (legMM < MIN_DIAGONAL_LEG_MM || legMM > MAX_DIAGONAL_LEG_MM) {
      throw new DiagramError('BAD_PARAM', `"diagonalBars.legMM" must be between ${MIN_DIAGONAL_LEG_MM}mm and ${MAX_DIAGONAL_LEG_MM}mm, got ${legMM}mm.`);
    }
    const diagCuttingLengthMM = db.cuttingLengthMM != null ? toMm(db.cuttingLengthMM, unit) : null;
    if (diagCuttingLengthMM != null) assertFinitePositive('diagonalBars.cuttingLengthMM', diagCuttingLengthMM);

    // Four opening corners, each with a diagonal projecting AWAY from
    // the opening (into the solid wall corner region), computed once
    // here — same "compute once, reuse in both render and validation"
    // discipline as topFromWallTopMM above.
    const oTop = topFromWallTopMM, oBot = topFromWallTopMM + openH, oLeft = openX, oRight = openX + openW;
    const corners = [
      { cx: oLeft, cy: oTop, ex: oLeft - legMM, ey: oTop - legMM },     // top-left
      { cx: oRight, cy: oTop, ex: oRight + legMM, ey: oTop - legMM },   // top-right
      { cx: oLeft, cy: oBot, ex: oLeft - legMM, ey: oBot + legMM },     // bottom-left
      { cx: oRight, cy: oBot, ex: oRight + legMM, ey: oBot + legMM },   // bottom-right
    ];
    for (const c of corners) {
      if (c.ex < 0 || c.ex > lengthMM || c.ey < 0 || c.ey > heightMM) {
        throw new DiagramError(
          'DIAGONAL_EXCEEDS_WALL',
          `A diagonal corner bar (leg=${Math.round(legMM)}mm) projects outside the ${lengthMM}x${heightMM}mm wall panel from this opening's corner.`,
        );
      }
    }
    diagonalBars = { dia: diagDia, count: db.count, legMM, cuttingLengthMM: diagCuttingLengthMM, corners };
  }

  return {
    type: 'wallOpening', unit, id, lengthMM, heightMM, thicknessMM, coverMM,
    opening: { widthMM: openW, heightMM: openH, xMM: openX, sillMM, topFromWallTopMM },
    trimBars: {
      dia: trimDia, count: raw.trimBars.count, spacing: trimSpacing,
      faceOffsetMM, extensionMM, cuttingLengthMM: trimCuttingLengthMM,
      faceReachMM, envelopeMM,
    },
    diagonalBars,
  };
}

// ── Labels ──────────────────────────────────────────────────────────
const L = {
  en: {
    title: (id) => `WALL OPENING ${id} \u2014 TRIM REINFORCEMENT DETAIL`,
    elevation: 'ELEVATION', detail: 'OPENING DETAIL', opening: 'OPENING',
    trimHorizontal: 'Trim bars, horizontal (top & bottom)',
    trimVertical: 'Trim bars, vertical (left & right)',
    diagonalCorner: 'Diagonal corner bars',
    extentSuffix: ' (extent)',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design (ECP 203 / ACI 318) before issuing for construction. This module does not calculate the trim-bar area required to replace interrupted wall mesh reinforcement \u2014 that sizing decision belongs to your governing code; supply diameters and counts already sized for it. Lengths marked "(extent)" are the drawn span only, excluding hooks/bends.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تسليح فتحة الجدار ${id} \u2014 تفصيلة الأسياخ المحيطة`,
    elevation: 'منظور جانبي', detail: 'تفصيلة الفتحة', opening: 'فتحة',
    trimHorizontal: 'أسياخ محيطة أفقية (أعلى وأسفل)',
    trimVertical: 'أسياخ محيطة رأسية (يمين ويسار)',
    diagonalCorner: 'أسياخ قطرية بالزوايا',
    extentSuffix: ' امتداد',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. لا يحسب هذا العنصر مساحة الأسياخ المحيطة اللازمة لتعويض حديد الشبكة المقطوع حول الفتحة \u2014 هذا التقدير يخص الكود المستخدم في مشروعك؛ أدخل القطر والعدد بعد تحديدهما وفق ذلك. الأطوال المُعلَّمة امتداد هي طول الامتداد المرسوم فقط بدون الكلبتين أو الانحناءات.',
    dirAttr: 'rtl',
  },
};

// ── Render ──────────────────────────────────────────────────────────
const CANVAS_W = 950;
const ELEV_BOX = { x: 70, y: 110, w: 520, h: 340 };
const DETAIL_BOX = { x: 640, y: 110, w: 240, h: 340 };

function renderElevationView(geometry, scale, box, l) {
  const { lengthMM, heightMM, opening, trimBars } = geometry;
  const w = lengthMM * scale, h = heightMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + (box.h - h) / 2 + 10;
  const botY = sy + h;
  let svg = `<g class="elevation">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.elevation)}</text>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" class="concrete-outline"/>`;

  const opX = sx + opening.xMM * scale;
  const opY = sy + opening.topFromWallTopMM * scale;
  const opW = opening.widthMM * scale;
  const opH = opening.heightMM * scale;
  const env = trimBars.envelopeMM * scale;
  svg += `<rect x="${opX - env}" y="${opY - env}" width="${opW + 2 * env}" height="${opH + 2 * env}" class="stirrup-outline" fill="none"/>`;
  svg += `<rect x="${opX}" y="${opY}" width="${opW}" height="${opH}" fill="#ffffff" class="cut-line"/>`;
  svg += `<text x="${opX + opW / 2}" y="${opY + opH / 2 + 4}" text-anchor="middle" class="zone-label" dir="${l.dirAttr}">${esc(l.opening)}</text>`;

  svg += dimensionLine(sx, botY + 20, sx + w, botY + 20, `${Math.round(lengthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 20, sy, sx - 20, botY, `${Math.round(heightMM)}mm`, { orientation: 'v', tick: 5 });
  svg += dimensionLine(sx, sy - 24, opX, sy - 24, `${Math.round(opening.xMM)}mm`, { orientation: 'h', tick: 4 });
  svg += dimensionLine(sx + w + 40, botY, sx + w + 40, opY + opH, `${Math.round(opening.sillMM)}mm`, { orientation: 'v', tick: 4 });
  svg += barMarkTag(opX + opW + env + 16, opY - env - 4, `${trimBars.count}\u00d7\u00d8${Math.round(trimBars.dia)}`, { r: 13 });
  svg += `</g>`;
  return svg;
}

function renderDetailView(geometry, scale, box, l) {
  const { opening, trimBars, diagonalBars } = geometry;
  const ow = opening.widthMM * scale, oh = opening.heightMM * scale;
  const zoomMarginMM = Math.max(trimBars.envelopeMM, diagonalBars ? diagonalBars.legMM : 0);
  const marginPx = zoomMarginMM * scale;
  const contentW = ow + 2 * marginPx, contentH = oh + 2 * marginPx;
  const boxTop = box.y + 26; // clears the two fixed-position tags below (see those calls for why)
  const availH = box.y + box.h - boxTop;
  const originX = box.x + (box.w - contentW) / 2 + marginPx;
  const originY = boxTop + (availH - contentH) / 2 + marginPx;

  let svg = `<g class="opening-detail">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.detail)}</text>`;
  svg += `<rect x="${originX}" y="${originY}" width="${ow}" height="${oh}" fill="#ffffff" class="cut-line"/>`;

  const ext = trimBars.extensionMM * scale;
  const xLo = originX - ext, xHi = originX + ow + ext;
  const yLo = originY - ext, yHi = originY + oh + ext;
  for (let i = 0; i < trimBars.count; i++) {
    const off = (trimBars.faceOffsetMM + i * trimBars.spacing) * scale;
    svg += `<line x1="${xLo}" y1="${originY - off}" x2="${xHi}" y2="${originY - off}" class="bar-bottom"/>`;
    svg += `<line x1="${xLo}" y1="${originY + oh + off}" x2="${xHi}" y2="${originY + oh + off}" class="bar-bottom"/>`;
    svg += `<line x1="${originX - off}" y1="${yLo}" x2="${originX - off}" y2="${yHi}" class="bar-top"/>`;
    svg += `<line x1="${originX + ow + off}" y1="${yLo}" x2="${originX + ow + off}" y2="${yHi}" class="bar-top"/>`;
  }

  if (diagonalBars) {
    // One representative line per corner, not `count` individually drawn
    // — same convention columnDiagram.mjs's elevation view documents for
    // its own outer perimeter-bar pair (schedule carries the true count).
    for (const c of diagonalBars.corners) {
      const x1 = originX + (c.cx - opening.xMM) * scale;
      const y1 = originY + (c.cy - opening.topFromWallTopMM) * scale;
      const x2 = originX + (c.ex - opening.xMM) * scale;
      const y2 = originY + (c.ey - opening.topFromWallTopMM) * scale;
      svg += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="diagonal-bar"/>`;
    }
  }

  // Two fixed-offset tags anchored from the BOX'S OWN top-left corner,
  // not from any content-derived coordinate (yLo/originY shift with
  // scale/margin per input) — the first version anchored both the trim
  // spec text and the diagonal tag near yLo/originY and the two
  // collided directly (and the long trim-spec text separately ran past
  // the canvas's own right edge) whenever a small opening pushed the
  // drawn content close to the box's top edge. Caught only by actually
  // rendering and looking, not by any text-content check \u2014 same
  // defect class this project's CHANGELOG (Step 19) already documents
  // for other modules. Two short tags at fixed, mutually clear
  // positions replace the one long collision-prone line; the schedule
  // table below already carries the same numbers in full.
  svg += barMarkTag(box.x + 55, box.y + 4, `\u00d8${Math.round(trimBars.dia)}@${Math.round(trimBars.spacing)}`, { r: 11 });
  if (diagonalBars) {
    svg += barMarkTag(box.x + 185, box.y + 4, `${diagonalBars.count}\u00d7\u00d8${Math.round(diagonalBars.dia)}`, { r: 11 });
  }

  svg += dimensionLine(originX, originY + oh + ext + 18, originX + ow, originY + oh + ext + 18, `${Math.round(opening.widthMM)}mm`, { orientation: 'h', tick: 4 });
  svg += dimensionLine(originX - ext - 18, originY, originX - ext - 18, originY + oh, `${Math.round(opening.heightMM)}mm`, { orientation: 'v', tick: 4 });
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const { opening, trimBars, diagonalBars } = geometry;
  const rows = [];
  const hLen = trimBars.cuttingLengthMM != null ? Math.round(trimBars.cuttingLengthMM) : `${Math.round(opening.widthMM + 2 * trimBars.extensionMM)}${l.extentSuffix}`;
  const vLen = trimBars.cuttingLengthMM != null ? Math.round(trimBars.cuttingLengthMM) : `${Math.round(opening.heightMM + 2 * trimBars.extensionMM)}${l.extentSuffix}`;
  rows.push({ mark: 'T1', element: l.trimHorizontal, dia: String(Math.round(trimBars.dia)), count: `${trimBars.count} \u00d7 2`, length: String(hLen) });
  rows.push({ mark: 'T2', element: l.trimVertical, dia: String(Math.round(trimBars.dia)), count: `${trimBars.count} \u00d7 2`, length: String(vLen) });
  if (diagonalBars) {
    const dLen = diagonalBars.cuttingLengthMM != null
      ? Math.round(diagonalBars.cuttingLengthMM)
      : `${Math.round(diagonalBars.legMM * Math.SQRT2)}${l.extentSuffix}`;
    rows.push({ mark: 'D1', element: l.diagonalCorner, dia: String(Math.round(diagonalBars.dia)), count: `${diagonalBars.count} \u00d7 4`, length: String(dLen) });
  }
  return rows;
}

export function renderWallOpeningDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const elevScale = fitScale([{ contentW: geometry.lengthMM, contentH: geometry.heightMM, boxW: ELEV_BOX.w - 70, boxH: ELEV_BOX.h - 80 }]);
  const zoomMarginMM = Math.max(geometry.trimBars.envelopeMM, geometry.diagonalBars ? geometry.diagonalBars.legMM : 0);
  const detailScale = fitScale([{
    contentW: geometry.opening.widthMM + 2 * zoomMarginMM,
    contentH: geometry.opening.heightMM + 2 * zoomMarginMM,
    boxW: DETAIL_BOX.w - 40, boxH: DETAIL_BOX.h - 70,
  }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = Math.max(ELEV_BOX.y + ELEV_BOX.h, DETAIL_BOX.y + DETAIL_BOX.h) + 70;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .wall-title    { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .zone-label    { font-size:10.5px; fill:#8a6d00; font-family: ${scriptFontStack}; }
    .diagonal-bar  { stroke:#c0392b; stroke-width:2; fill:none; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="wall-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderElevationView(geometry, elevScale, ELEV_BOX, l)}
  ${renderDetailView(geometry, detailScale, DETAIL_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// ── Chat-facing entry point ────────────────────────────────────────────
// Mirrors columnDiagram.mjs's parseColumnRebarPayload()/shearWallDiagram
// .mjs's parseShearWallRebarPayload() error-shape contract exactly
// ({ok:true,...} / {ok:false,code,message}).
export function parseWallOpeningRebarPayload(raw) {
  try {
    const geometry = computeWallOpeningDiagramGeometry(raw);
    return { ok: true, type: 'wallOpening', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Same contract/conventions as columnDiagram.mjs's / shearWallDiagram
// .mjs's own copies (BAD_SYNTAX vs. UNSUPPORTED_TYPE split, never
// throws, error results carry `.type`). Written now, not wired into
// diagramCommandRouter.mjs/chat.js yet — see the wiring note at the top
// of this file.
//
// Syntax:
//   /diagram wallopening id=W1 length=4000 height=3000 thickness=200
//     cover=25 openingwidth=900 openingheight=2100 openingx=1500 sill=0
//     trimdia=16 trimcount=2 trimspacing=75 trimoffset=50 extension=400
//     [diagdia=12 diagcount=1 diagleg=300] [unit=mm]
// diagonalBars is all-or-nothing, same discipline as shearWallDiagram
// .mjs's boundaryElement: presence of ANY diag* key builds the group
// object and lets computeWallOpeningDiagramGeometry's own validation
// enforce completeness.
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: wallopening key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'wallopening') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use wallopening.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    let diagonalBars;
    const diagKeys = ['diagdia', 'diagcount', 'diagleg'];
    if (diagKeys.some((k) => k in kv)) {
      diagonalBars = { diameterMM: num('diagdia'), count: num('diagcount'), legMM: num('diagleg') };
    }
    const geometry = computeWallOpeningDiagramGeometry({
      wallId: kv.id, lengthMM: num('length'), heightMM: num('height'),
      thicknessMM: num('thickness'), coverMM: num('cover'),
      opening: {
        widthMM: num('openingwidth'), heightMM: num('openingheight'),
        xMM: num('openingx'), sillMM: num('sill'),
      },
      trimBars: {
        diameterMM: num('trimdia'), count: num('trimcount'), spacingMM: num('trimspacing'),
        faceOffsetMM: num('trimoffset'), extensionMM: num('extension'),
      },
      diagonalBars, unit: kv.unit || 'mm',
    });
    return { ok: true, type: 'wallopening', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type: 'wallopening', code: err.code, message: err.message };
    throw err;
  }
}
