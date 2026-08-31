// functions/_lib/trapezoidalFootingDiagram.mjs
//
// Deterministic, zero-AI SVG generator for a trapezoidal-plan combined
// footing (two columns, a plan shape that flares symmetrically from
// width B1 at one end to width B2 at the other) — New-element track,
// Part 2. Candidate list offered per برومبت_استكمال_العمل_v13.md's own
// documented pool (trapezoidal combined footing, strap footing, isolated
// over pile, raft over pile, flat slab opening reinforcement — verified
// directly against pc_suite_v71-1-2-7.html before being offered, not
// assumed); user chose "Trapezoidal". Directly closes a documented, real
// gap: footingDiagram.mjs's
// own header lists "trapezoidal-plan ... combined footings" under STILL
// NOT MODELED, and notes footing_pro's own product copy already lists
// Rectangular / Trapezoidal / Strap as three live combined-footing
// options while footingDiagram.mjs's 'combined' only ever draws the
// rectangular one. This module is that missing Trapezoidal case — Strap
// (the third option) is a separate, still-open gap, not addressed here.
//
// Same philosophy as every other element module in this app: every
// dimension, bar position, and count in the output is arithmetic on the
// KB data supplied, never a model's guess, never a computed soil-bearing
// pressure or an invented B1/B2 split. This module owns compute+render
// only.
//
// SCOPE (v1): a single constant-thickness trapezoidal footing serving
// exactly TWO columns, one centered at (or near) each parallel end,
// flared SYMMETRICALLY about the longitudinal centerline (an isosceles
// trapezoid — B1 and B2 each straddle the same midline; this module has
// no field for an asymmetric, one-side-only flare). One bottom
// reinforcement mesh: TRANSVERSE bars (the main flexural direction,
// running across the varying width, one row per position along the
// length) plus LONGITUDINAL distribution bars (running the full
// length). NOT modeled, on purpose (each needs a parametrization this
// module hasn't been given, same explicit-scope-boundary convention
// columnDiagram.mjs's own header uses):
//   - the strap-beam combined-footing variant (footing_pro's third
//     product option) — a strap beam is a separate structural element
//     (its own span/depth/reinforcement) connecting two independent
//     footings, not a parametrization of this module's single trapezoid.
//   - more than two columns, or columns not centered on the flare
//     midline (an eccentric column position across the WIDTH axis) —
//     both columns sit on the same centerline this module draws the
//     trapezoid symmetric about.
//   - asymmetric (one-side) taper, sloped or stepped thickness,
//     pedestals, dowels, and top/shear steel — same "schematic, not
//     shop drawing" scope every footing-family module in this app
//     already states; this module shows one representative bottom mesh
//     layer only.
//   - a computed soil-bearing check or a solver that derives B1/B2 from
//     column loads to equalize pressure (the real-world REASON a
//     trapezoidal footing is chosen over a rectangular one) — this
//     module draws whatever B1/B2 the caller supplies; verifying they
//     actually equalize bearing pressure is the KB/design layer's job,
//     exactly like columnDiagram.mjs never decides bar counts.
//
// ── INPUT CONTRACT (what the KB layer should hand this module) ─────────
// {
//   unit?: 'mm'|'cm'|'m',                 // default 'mm'
//   footingId: string,                    // e.g. "TF-1"
//   b1MM: number,                         // plan width at the x=0 end
//   b2MM: number,                         // plan width at the x=lengthMM end
//                                         // — must differ from b1MM by at
//                                         // least MIN_TAPER_MM; equal
//                                         // widths are a rectangle, not a
//                                         // trapezoid — see NOT_TRAPEZOIDAL
//                                         // below, which redirects the
//                                         // caller to footingDiagram.mjs's
//                                         // own 'combined' type instead of
//                                         // silently drawing a degenerate
//                                         // shape.
//   lengthMM: number,                     // plan length between the two
//                                         // parallel width-ends
//   thicknessMM: number,
//   coverMM: number,
//   col1: { widthMM, depthMM, offsetMM }, // widthMM = column dimension
//                                         // across the varying-B axis;
//                                         // depthMM = column dimension
//                                         // along the L axis; offsetMM =
//                                         // column CENTER position along
//                                         // L, measured from the b1MM end
//                                         // (0..lengthMM)
//   col2: { widthMM, depthMM, offsetMM }, // same shape, near the b2MM end
//   sectionThrough?: 1 | 2,               // default 1 — which column the
//                                         // section-view cut passes
//                                         // through (mirrors
//                                         // footingDiagram.mjs's
//                                         // 'combined' sectionThrough
//                                         // field exactly)
//   mesh: {
//     transverse:   { diameterMM, spacingMM },  // main bars, one row per
//                                               // position along L, each
//                                               // row's drawn length is
//                                               // the LOCAL width at that
//                                               // row (varies row to row
//                                               // — the genuinely
//                                               // trapezoid-specific
//                                               // geometry)
//     longitudinal: { diameterMM, spacingMM },  // distribution bars,
//                                               // positioned within the
//                                               // band BOTH ends can
//                                               // accommodate (see
//                                               // "Longitudinal band"
//                                               // note below), each
//                                               // spans the full drawn
//                                               // length (fixed)
//   },
// }
//
// ── Longitudinal band (why every longitudinal bar is guaranteed to fit) ─
// A longitudinal bar runs the full lengthMM at a FIXED perpendicular
// offset from the centerline. Because b1MM/b2MM are linearly
// interpolated (computeLocalWidthMM below), the local width at any x
// between 0 and lengthMM is always >= min(b1MM, b2MM) — the trapezoid
// never narrows past its own narrow end. So constraining every
// longitudinal bar's offset to within half of (min(b1MM,b2MM) - 2*cover
// - dia) of the centerline guarantees it stays inside the concrete
// along the ENTIRE length, not just at the narrow end where the
// constraint is tightest. This is arithmetic on the shape actually
// supplied, not an assumption borrowed from a rectangular footing.
//
// ── /diagram and /rebar wiring ──────────────────────────────────────────
// Wired the same way every prior new-element step in this app was:
// parseDiagramCommand below (leading token "trapezoidal") +
// diagramCommandRouter.mjs (import + PARSERS[] + ALL_SUPPORTED_TYPES[])
// + chat.js's three existing dispatch tables (DIAGRAM_TYPE_RENDERERS,
// DIAGRAM_TYPE_ERROR_MESSAGE, REBAR_ELEMENT_DISPATCH) + a new
// trapezoidalFootingDiagramErrorMessage() AR wrapper inside chat.js,
// matching retainingWallDiagramErrorMessage's exact shape (chat.js
// defines this wrapper locally for every element type — it is not
// exported from any element's own .mjs file, confirmed by reading
// chat.js directly before writing this comment, not assumed). Per this
// prompt's Part 2 rule, all four link points are one non-optional unit
// of work — see this file's own CHANGELOG.md entry for the actual
// wiring commit, not a separate "link it later" step.
//
// Resource lifecycle: pure/synchronous, zero imports beyond the shared
// kit, no timers/fetch/KV/handles — same as every sibling module.
// Fully deterministic: no env.AI, no model call, no randomness anywhere
// in this file.

import {
  DiagramError, toMm, assertFinitePositive, assertFiniteNonNegative,
  esc, captionLineCount, renderCaptionAt, fontStacks, kitStyleBlock,
  hatchDefs, dimensionLine, fitScale, scheduleTable,
  svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ──────────────────────────────────────────────────────
// Same role as every sibling module's MAX_*/MIN_*: bound worst-case loop
// counts and input ranges so one request can't build an oversized SVG,
// blow a Worker CPU-time budget, or describe a shape that cannot be
// drawn sanely.
const MIN_B_MM = 500;
const MAX_B_MM = 6000;
const MIN_TAPER_MM = 100; // |b1-b2| below this is "basically rectangular" — see NOT_TRAPEZOIDAL
const MIN_LENGTH_MM = 1000;
const MAX_LENGTH_MM = 12000;
const MIN_THICKNESS_MM = 300;
const MAX_THICKNESS_MM = 1500;
const MIN_COL_SIDE_MM = 150;
const MAX_COL_SIDE_MM = 1500;
const MIN_MESH_SPACING_MM = 75; // matches slabDiagram.mjs's own bound
const MAX_MESH_SPACING_MM = 400; // matches slabDiagram.mjs's own bound
const MAX_MESH_ROWS = 14; // matches slabDiagram.mjs/shearWallDiagram.mjs's own per-axis cap
const MAX_MESH_COLS = 14;

// Linear interpolation of the plan width between the two parallel ends —
// the single source of truth every column-fit check and every mesh
// row's drawn length below is computed from, so the two can never
// silently drift apart.
function computeLocalWidthMM(xMM, b1MM, b2MM, lengthMM) {
  return b1MM + ((b2MM - b1MM) * xMM) / lengthMM;
}

// ── Compute ──────────────────────────────────────────────────────────
export function computeTrapezoidalFootingGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Trapezoidal footing input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.footingId != null ? String(raw.footingId).slice(0, 40) : 'TF';

  const b1MM = toMm(raw.b1MM, unit);
  const b2MM = toMm(raw.b2MM, unit);
  assertFinitePositive('b1MM', b1MM);
  assertFinitePositive('b2MM', b2MM);
  for (const [name, v] of [['b1MM', b1MM], ['b2MM', b2MM]]) {
    if (v < MIN_B_MM || v > MAX_B_MM) {
      throw new DiagramError('BAD_PARAM', `"${name}" must be between ${MIN_B_MM}mm and ${MAX_B_MM}mm for this schematic, got ${v}mm.`);
    }
  }
  if (Math.abs(b1MM - b2MM) < MIN_TAPER_MM) {
    throw new DiagramError(
      'NOT_TRAPEZOIDAL',
      `b1MM (${b1MM}mm) and b2MM (${b2MM}mm) differ by less than ${MIN_TAPER_MM}mm — this is not a genuine trapezoid. Use footingDiagram.mjs's "combined" (rectangular) type instead of forcing a near-zero taper here.`,
    );
  }

  const lengthMM = toMm(raw.lengthMM, unit);
  assertFinitePositive('lengthMM', lengthMM);
  if (lengthMM < MIN_LENGTH_MM || lengthMM > MAX_LENGTH_MM) {
    throw new DiagramError('BAD_PARAM', `"lengthMM" must be between ${MIN_LENGTH_MM}mm and ${MAX_LENGTH_MM}mm, got ${lengthMM}mm.`);
  }

  const thicknessMM = toMm(raw.thicknessMM, unit);
  assertFinitePositive('thicknessMM', thicknessMM);
  if (thicknessMM < MIN_THICKNESS_MM || thicknessMM > MAX_THICKNESS_MM) {
    throw new DiagramError('BAD_PARAM', `"thicknessMM" must be between ${MIN_THICKNESS_MM}mm and ${MAX_THICKNESS_MM}mm, got ${thicknessMM}mm.`);
  }

  const coverMM = toMm(raw.coverMM, unit);
  assertFinitePositive('coverMM', coverMM);

  // ── Columns ────────────────────────────────────────────────────────
  function readColumn(tag, rawCol) {
    if (!rawCol || typeof rawCol !== 'object') {
      throw new DiagramError('BAD_PARAM', `"${tag}" is required: { widthMM, depthMM, offsetMM }.`);
    }
    const widthMM = toMm(rawCol.widthMM, unit);
    const depthMM = toMm(rawCol.depthMM, unit);
    const offsetMM = toMm(rawCol.offsetMM, unit);
    assertFinitePositive(`${tag}.widthMM`, widthMM);
    assertFinitePositive(`${tag}.depthMM`, depthMM);
    assertFiniteNonNegative(`${tag}.offsetMM`, offsetMM);
    if (widthMM < MIN_COL_SIDE_MM || widthMM > MAX_COL_SIDE_MM) {
      throw new DiagramError('BAD_PARAM', `"${tag}.widthMM" must be between ${MIN_COL_SIDE_MM}mm and ${MAX_COL_SIDE_MM}mm, got ${widthMM}mm.`);
    }
    if (depthMM < MIN_COL_SIDE_MM || depthMM > MAX_COL_SIDE_MM) {
      throw new DiagramError('BAD_PARAM', `"${tag}.depthMM" must be between ${MIN_COL_SIDE_MM}mm and ${MAX_COL_SIDE_MM}mm, got ${depthMM}mm.`);
    }
    const xStartMM = offsetMM - depthMM / 2;
    const xEndMM = offsetMM + depthMM / 2;
    if (xStartMM < 0 || xEndMM > lengthMM) {
      throw new DiagramError(
        'COLUMN_OUT_OF_BOUNDS',
        `"${tag}" (offsetMM=${offsetMM}mm, depthMM=${depthMM}mm) extends from ${xStartMM}mm to ${xEndMM}mm along the footing's length, outside [0, ${lengthMM}]mm.`,
      );
    }
    const localWidthMin = Math.min(
      computeLocalWidthMM(xStartMM, b1MM, b2MM, lengthMM),
      computeLocalWidthMM(xEndMM, b1MM, b2MM, lengthMM),
    );
    if (widthMM >= localWidthMin) {
      throw new DiagramError(
        'COLUMN_TOO_WIDE',
        `"${tag}.widthMM" (${widthMM}mm) must be smaller than the local footing width across its own footprint (${localWidthMin.toFixed(1)}mm), got ${widthMM}mm.`,
      );
    }
    return { widthMM, depthMM, offsetMM, xStartMM, xEndMM };
  }

  const col1 = readColumn('col1', raw.col1);
  const col2 = readColumn('col2', raw.col2);
  const [first, second] = col1.offsetMM <= col2.offsetMM ? [col1, col2] : [col2, col1];
  if (first.xEndMM > second.xStartMM) {
    throw new DiagramError('COLUMNS_OVERLAP', `col1 and col2 overlap along the footing's length given their offsets and depths.`);
  }

  const sectionThrough = raw.sectionThrough === 2 ? 2 : 1;
  const chosenCol = sectionThrough === 2 ? col2 : col1;
  const chosenLocalWidthMM = computeLocalWidthMM(chosenCol.offsetMM, b1MM, b2MM, lengthMM);

  // ── Mesh ───────────────────────────────────────────────────────────
  const minEndWidthMM = Math.min(b1MM, b2MM);

  function readMeshSpec(tag, rawSpec) {
    if (!rawSpec || typeof rawSpec !== 'object') {
      throw new DiagramError('BAD_PARAM', `"mesh.${tag}" is required: { diameterMM, spacingMM }.`);
    }
    const diaMM = toMm(rawSpec.diameterMM, unit);
    const spacingMM = toMm(rawSpec.spacingMM, unit);
    assertFinitePositive(`mesh.${tag}.diameterMM`, diaMM);
    assertFinitePositive(`mesh.${tag}.spacingMM`, spacingMM);
    if (spacingMM < MIN_MESH_SPACING_MM || spacingMM > MAX_MESH_SPACING_MM) {
      throw new DiagramError('BAD_PARAM', `"mesh.${tag}.spacingMM" must be between ${MIN_MESH_SPACING_MM}mm and ${MAX_MESH_SPACING_MM}mm, got ${spacingMM}mm.`);
    }
    return { diaMM, spacingMM };
  }

  const transverseSpec = readMeshSpec('transverse', raw.mesh && raw.mesh.transverse);
  const longSpec = readMeshSpec('longitudinal', raw.mesh && raw.mesh.longitudinal);

  // Transverse rows: evenly spaced along [firstMM, lastMM] (inset by
  // cover + half the bar's own diameter, same first/last convention
  // footingDiagram.mjs's computeMeshLayer uses along one axis). Each
  // row's drawn length is the LOCAL width at that row minus the same
  // cover+half-diameter inset on both of ITS OWN ends — the row nearer
  // the narrow end is always shorter, honestly.
  const rowFirstMM = coverMM + transverseSpec.diaMM / 2;
  const rowLastMM = lengthMM - coverMM - transverseSpec.diaMM / 2;
  if (rowLastMM <= rowFirstMM) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) and transverse bar diameter (${transverseSpec.diaMM}mm) leave no room for a mesh row along a ${lengthMM}mm length.`);
  }
  const narrowDrawnLengthMM = minEndWidthMM - 2 * coverMM - transverseSpec.diaMM;
  if (narrowDrawnLengthMM <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) and transverse bar diameter (${transverseSpec.diaMM}mm) leave no room for a transverse bar at the narrow end (${minEndWidthMM}mm wide).`);
  }
  const rowCount = Math.max(2, Math.min(Math.floor((rowLastMM - rowFirstMM) / transverseSpec.spacingMM) + 1, MAX_MESH_ROWS));
  const rowStep = rowCount > 1 ? (rowLastMM - rowFirstMM) / (rowCount - 1) : 0;
  const transverseRows = Array.from({ length: rowCount }, (_, i) => {
    const xMM = rowCount === 1 ? (rowFirstMM + rowLastMM) / 2 : rowFirstMM + i * rowStep;
    const localWidthMM = computeLocalWidthMM(xMM, b1MM, b2MM, lengthMM);
    return { xMM, drawnLengthMM: localWidthMM - 2 * coverMM - transverseSpec.diaMM };
  });
  const maxTransverseDrawnLengthMM = Math.max(...transverseRows.map((r) => r.drawnLengthMM));

  // Longitudinal band: see the file-header note above for why every
  // position within this band is guaranteed to stay inside the concrete
  // along the full length.
  const halfBandMM = (minEndWidthMM - 2 * coverMM - longSpec.diaMM) / 2;
  if (halfBandMM <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) and longitudinal bar diameter (${longSpec.diaMM}mm) leave no safe band for a longitudinal bar within the narrow end (${minEndWidthMM}mm wide).`);
  }
  const longFirstMM = coverMM + longSpec.diaMM / 2;
  const longLastMM = lengthMM - coverMM - longSpec.diaMM / 2;
  if (longLastMM <= longFirstMM) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) and longitudinal bar diameter (${longSpec.diaMM}mm) leave no room along a ${lengthMM}mm length.`);
  }
  const longDrawnLengthMM = longLastMM - longFirstMM;
  const colCount = Math.max(2, Math.min(Math.floor((2 * halfBandMM) / longSpec.spacingMM) + 1, MAX_MESH_COLS));
  const colStep = colCount > 1 ? (2 * halfBandMM) / (colCount - 1) : 0;
  const longitudinalBars = Array.from({ length: colCount }, (_, i) => ({
    offsetFromCenterMM: colCount === 1 ? 0 : -halfBandMM + i * colStep,
  }));

  return {
    type: 'trapezoidal', unit, id, b1MM, b2MM, lengthMM, thicknessMM, coverMM,
    col1, col2, sectionThrough, chosenLocalWidthMM,
    mesh: {
      transverse: { dia: transverseSpec.diaMM, spacing: transverseSpec.spacingMM, rows: transverseRows, maxDrawnLengthMM: maxTransverseDrawnLengthMM },
      longitudinal: { dia: longSpec.diaMM, spacing: longSpec.spacingMM, bars: longitudinalBars, drawnLengthMM: longDrawnLengthMM, startMM: longFirstMM, endMM: longLastMM },
    },
  };
}

// ── Labels ───────────────────────────────────────────────────────────
// Local L={en:{...},ar:{...}} dictionary, same decision columnDiagram.mjs/
// beamDiagram.mjs/shearWallDiagram.mjs/stairDiagram.mjs/
// retainingWallDiagram.mjs already made and documented (structuralLabels
// .mjs scopes itself to footingDiagram.mjs only — see its own header).
// Every Arabic value below is written parenthesis- and em/en-dash-free,
// per structuralLabels.mjs's documented, cairosvg-verified Noto Naskh
// Arabic glyph gap. Every string that mixes engineering notation (Ø,
// mm, numbers) with a translated label is rendered as TWO separate
// <text> nodes in the render functions below (defaultFontStack for the
// notation, scriptFontStack for the label) — the same convention this
// app's other element modules already use for the identical reason
// (see structuralLabels.mjs's header on the scriptFontStack glyph gap);
// applied here from the start, and confirmed by a direct cairosvg render
// of this module's own output during this session's integration pass,
// not assumed from that convention alone.
const L = {
  en: {
    title: (id) => `TRAPEZOIDAL FOOTING ${id} \u2014 REINFORCEMENT DETAIL`,
    plan: 'PLAN', section: 'SECTION',
    transverse: 'Transverse', longitudinal: 'Longitudinal',
    colTag1: 'COLUMN 1', colTag2: 'COLUMN 2',
    varies: 'varies, max',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar mark, count, spacing, and length against your own design before issuing for construction. This drawing shows one representative bottom mesh layer only: no top steel, no dowels, no pedestal. Transverse bar lengths vary along the footing (narrower toward the B1/B2 end that is smaller); the schedule lists the longest one only \u2014 see the plan view for each row\'s actual drawn length.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `تفريد حديد القاعدة شبه المنحرفة ${id}`,
    plan: 'مسقط', section: 'قطاع',
    transverse: 'عرضي', longitudinal: 'طولي',
    colTag1: 'عمود 1', colTag2: 'عمود 2',
    varies: 'متغير، الحد الأقصى',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة، للتحقق فقط. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص قبل الاعتماد للتنفيذ. يوضح الرسم طبقة تسليح سفلية تمثيلية واحدة فقط، بلا حديد علوي أو برمة أو قاعدة عمود. أطوال الأسياخ العرضية تختلف على طول القاعدة، الأقصر عند طرفها الأضيق؛ الجدول يذكر أطول قيمة فقط، راجع المسقط لطول كل سيخ فعلياً.',
    dirAttr: 'rtl',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 950;
const PLAN_BOX = { x: 80, y: 110, w: 790, h: 260 };
const SECTION_BOX = { x: 80, y: PLAN_BOX.y + PLAN_BOX.h + 70, w: 790, h: 220 };

export function renderTrapezoidalFootingDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = SECTION_BOX.y + SECTION_BOX.h + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .footing-title   { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .footing-outline { fill:#f4f4f4; stroke:#1a1a1a; stroke-width:1.7; }
    .column-outline  { fill:#e2e2e2; stroke:#1a1a1a; stroke-width:1.7; }
    .mesh-line       { stroke:#c0392b; stroke-width:1.2; }
    .col-tag         { font-size:12px; fill:#333; font-family: ${scriptFontStack}; }
    .rebar-note      { font-size:11px; fill:#333; font-family: ${defaultFontStack}; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="footing-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderPlanView(geometry, PLAN_BOX, l)}
  ${renderSectionView(geometry, SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// Plan is centered on a FIXED horizontal midline (box.y + box.h/2), not
// on either end's own half-width — a variable-width shape anchored from
// its own edge is exactly the Y-anchoring bug class this session's Part
// 1 fix (and برومبت_استكمال_العمل.md's lesson 4) warns about; anchoring
// from the box's own fixed center sidesteps it entirely.
function renderPlanView(geometry, box, l) {
  const {
    b1MM, b2MM, lengthMM, col1, col2, mesh, sectionThrough,
  } = geometry;
  const maxB = Math.max(b1MM, b2MM);
  const scale = fitScale([{ contentW: lengthMM, contentH: maxB, boxW: box.w - 100, boxH: box.h - 80 }]);
  const originX = box.x + (box.w - lengthMM * scale) / 2;
  const midY = box.y + box.h / 2;

  const yAt = (xMM, halfWidthSign) => midY + (halfWidthSign * computeLocalWidthMM(xMM, b1MM, b2MM, lengthMM) * scale) / 2;
  const xPx = (xMM) => originX + xMM * scale;

  let svg = `<g class="plan-view">`;
  const points = [
    `${xPx(0)},${yAt(0, -1)}`,
    `${xPx(0)},${yAt(0, 1)}`,
    `${xPx(lengthMM)},${yAt(lengthMM, 1)}`,
    `${xPx(lengthMM)},${yAt(lengthMM, -1)}`,
  ].join(' ');
  svg += `<polygon points="${points}" class="footing-outline"/>`;

  // Transverse rows — vertical segments in screen space (the width axis
  // is drawn vertically here), each row's own drawn length already
  // computed per-row in computeTrapezoidalFootingGeometry.
  for (const row of mesh.transverse.rows) {
    const x = xPx(row.xMM);
    const halfPx = (row.drawnLengthMM * scale) / 2;
    svg += `<line x1="${x}" y1="${midY - halfPx}" x2="${x}" y2="${midY + halfPx}" class="mesh-line"/>`;
  }
  // Longitudinal bars — horizontal segments, fixed drawn length, offset
  // from the centerline per bar.
  for (const bar of mesh.longitudinal.bars) {
    const y = midY + bar.offsetFromCenterMM * scale;
    svg += `<line x1="${xPx(mesh.longitudinal.startMM)}" y1="${y}" x2="${xPx(mesh.longitudinal.endMM)}" y2="${y}" class="mesh-line"/>`;
  }

  // Columns
  for (const [col, tag] of [[col1, l.colTag1], [col2, l.colTag2]]) {
    const cx = xPx(col.offsetMM);
    const cw = col.depthMM * scale, ch = col.widthMM * scale;
    svg += `<rect x="${cx - cw / 2}" y="${midY - ch / 2}" width="${cw}" height="${ch}" class="column-outline"/>`;
    svg += `<text x="${cx}" y="${midY + ch / 2 + 16}" text-anchor="middle" dir="${l.dirAttr}" class="col-tag">${esc(tag)}</text>`;
  }

  // Section-cut marker through the chosen column, same convention as
  // footingDiagram.mjs's own combined/strip/raft cut marker.
  {
    const chosen = sectionThrough === 2 ? col2 : col1;
    const cx = xPx(chosen.offsetMM);
    const cutLetter = l.dirAttr === 'rtl' ? '\u0623' : 'A';
    const topY = yAt(0, -1) === yAt(lengthMM, -1) ? midY - (maxB * scale) / 2 : Math.min(yAt(0, -1), yAt(lengthMM, -1));
    const botY = Math.max(yAt(0, 1), yAt(lengthMM, 1));
    svg += `<line x1="${cx}" y1="${topY - 14}" x2="${cx}" y2="${botY + 14}" class="cut-line"/>`;
    svg += `<text x="${cx}" y="${topY - 18}" text-anchor="middle" class="cut-label">${cutLetter}</text>`;
    svg += `<text x="${cx}" y="${botY + 28}" text-anchor="middle" class="cut-label">${cutLetter}</text>`;
  }

  // Overall dimensions — B1/B2 each anchored from their OWN end's local
  // top/bottom (fixed, not derived from the other end), length spans
  // the full box.
  svg += dimensionLine(xPx(0), yAt(0, -1) - 22, xPx(0), yAt(0, 1) + 22, `B1=${Math.round(b1MM)}mm`, { orientation: 'v', tick: 5 });
  svg += dimensionLine(xPx(lengthMM), yAt(lengthMM, -1) - 22, xPx(lengthMM), yAt(lengthMM, 1) + 22, `B2=${Math.round(b2MM)}mm`, { orientation: 'v', tick: 5 });
  svg += dimensionLine(xPx(0), midY - (maxB * scale) / 2 - 40, xPx(lengthMM), midY - (maxB * scale) / 2 - 40, `L=${Math.round(lengthMM)}mm`, { orientation: 'h', tick: 5 });

  svg += `<text x="${originX + (lengthMM * scale) / 2}" y="${midY + (maxB * scale) / 2 + 48}" text-anchor="middle" dir="${l.dirAttr}" class="view-title">${esc(l.plan)}</text>`;
  svg += `</g>`;
  return svg;
}

function renderSectionView(geometry, box, l) {
  const { thicknessMM, chosenLocalWidthMM, coverMM, mesh } = geometry;
  const scale = fitScale([{ contentW: chosenLocalWidthMM, contentH: thicknessMM, boxW: box.w - 100, boxH: box.h - 80 }]);
  const w = chosenLocalWidthMM * scale, h = thicknessMM * scale;
  const sx = box.x + (box.w - w) / 2;
  const sy = box.y + 30;

  let svg = `<g class="section-view">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.section)}</text>`;
  svg += `<rect x="${sx - 20}" y="${sy + h}" width="${w + 40}" height="26" fill="url(#soilHatch)" opacity="0.5"/>`;
  svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${h}" class="footing-outline" fill="url(#concreteHatch)"/>`;

  const barY = sy + h - coverMM * scale - mesh.transverse.dia * scale / 2;
  svg += `<line x1="${sx + 6}" y1="${barY}" x2="${sx + w - 6}" y2="${barY}" class="mesh-line" stroke-width="2"/>`;

  svg += dimensionLine(sx, sy + h + 20, sx + w, sy + h + 20, `${Math.round(chosenLocalWidthMM)}mm`, { orientation: 'h', tick: 5 });
  svg += dimensionLine(sx - 24, sy, sx - 24, sy + h, `${Math.round(thicknessMM)}mm`, { orientation: 'v', tick: 5 });
  // Two separate <text> nodes (defaultFontStack notation vs scriptFontStack
  // label) — see this file's Labels-section header note.
  svg += `<text x="${sx + w / 2}" y="${sy + h + 40}" text-anchor="middle" class="rebar-note">${Math.round(mesh.transverse.dia)}\u00d8@${Math.round(mesh.transverse.spacing)}</text>`;
  svg += `<text x="${sx + w / 2}" y="${sy + h + 54}" text-anchor="middle" dir="${l.dirAttr}" class="rebar-note">${esc(l.transverse)}</text>`;
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  const { mesh } = geometry;
  return [
    {
      mark: 'T1', element: l.transverse,
      dia: String(Math.round(mesh.transverse.dia)),
      count: `@${Math.round(mesh.transverse.spacing)} (${mesh.transverse.rows.length})`,
      length: `${l.varies} ${Math.round(mesh.transverse.maxDrawnLengthMM)}`,
    },
    {
      mark: 'L1', element: l.longitudinal,
      dia: String(Math.round(mesh.longitudinal.dia)),
      count: `@${Math.round(mesh.longitudinal.spacing)} (${mesh.longitudinal.bars.length})`,
      length: String(Math.round(mesh.longitudinal.drawnLengthMM)),
    },
  ];
}

// ── Chat-facing entry point ────────────────────────────────────────────
// Mirrors parseColumnRebarPayload's error-shape contract exactly.
export function parseTrapezoidalFootingRebarPayload(raw) {
  try {
    const geometry = computeTrapezoidalFootingGeometry(raw);
    return { ok: true, type: 'trapezoidal', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Flat-text /diagram command parser ──────────────────────────────────
// Same leading-token + "key=value key=value ..." syntax, same
// BAD_SYNTAX/UNSUPPORTED_TYPE reservation, same never-throws contract,
// error results also carry `.type`, exactly like columnDiagram.mjs's
// own parseDiagramCommand (this file's approved template).
//
// Syntax:
//   /diagram trapezoidal id=TF1 b1=1800 b2=3000 length=4000 thickness=600
//     cover=50 col1width=400 col1depth=400 col1off=300
//     col2width=500 col2depth=500 col2off=3700
//     transversedia=16 transversespacing=150 longdia=12 longspacing=200
//     [sectionthrough=1] [unit=mm]
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: trapezoidal key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'trapezoidal') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use trapezoidal.` };
  }
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    const geometry = computeTrapezoidalFootingGeometry({
      footingId: kv.id, b1MM: num('b1'), b2MM: num('b2'),
      lengthMM: num('length'), thicknessMM: num('thickness'), coverMM: num('cover'),
      col1: { widthMM: num('col1width'), depthMM: num('col1depth'), offsetMM: num('col1off') },
      col2: { widthMM: num('col2width'), depthMM: num('col2depth'), offsetMM: num('col2off') },
      sectionThrough: num('sectionthrough'),
      mesh: {
        transverse: { diameterMM: num('transversedia'), spacingMM: num('transversespacing') },
        longitudinal: { diameterMM: num('longdia'), spacingMM: num('longspacing') },
      },
      unit: kv.unit || 'mm',
    });
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, type, code: err.code, message: err.message };
    throw err;
  }
}
