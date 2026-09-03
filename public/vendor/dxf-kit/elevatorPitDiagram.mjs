// elevatorPitDiagram.mjs
// Elevator pit reinforcement schematic: a closed rectangular RC wall
// "ring" in plan, sitting on its own base slab, recessed below the
// lowest floor level. Distinct from basementWallDiagram.mjs (confirmed
// by reading its own header before writing this: that file is ONE
// typical wall SECTION only — "not a full elevation along the wall's
// run" — and explicitly excludes drawing the floor slab/footing as
// anything but a schematic stub, so it cannot represent a closed
// 4-wall box in plan or a real base-slab connection). Reuses that
// file's own reinforcement convention directly where the physical
// condition matches (a pit wall is soil/excavation-retained on one
// face and restrained top+bottom, same condition basementWallDiagram.mjs
// documents its own double-curtain choice for) — exterior curtain =
// REBAR_BOTTOM, interior curtain = REBAR_TOP, horizontal = REBAR_HORIZONTAL,
// same layer roles basementWallDiagram.dxf.mjs already assigns, verified
// directly against that file before writing this one. Base-slab mesh
// reuses raftPileDiagram.mjs's own full-span mesh-line convention
// (REBAR_MESH_LINE). Zero new kit layers needed.
//
// v1 SCOPE:
//   - Rectangular interior footprint, 4 walls, constant thickness.
//   - ONE representative wall section (all 4 walls assumed identically
//     reinforced — same "single symmetric group" simplification
//     columnDiagram.mjs's ties and wallOpeningDiagram.mjs's trim bars
//     already use).
//   - Base slab: ONE bottom mesh only (no top mesh, no thickening/
//     haunch at the wall line) — same simplification slabDiagram.mjs's
//     own v1 already carries for an ordinary slab panel.
//   - Optional single rectangular sump recess in one corner, drawn as a
//     void outline only (no sump-specific reinforcement detail).
// NOT modeled, on purpose: buffer-post anchor bolts/dowels, pit ladder,
// waterproofing membrane, kicker/construction-joint waterstop, sloped
// slab-to-sump drainage, more than one sump, non-rectangular plan.

import {
  toMm, assertFinitePositive, assertInt, assertOneOf, esc, captionLineCount,
  renderCaptionAt, fontStacks, kitStyleBlock, hatchDefs, dimensionLine,
  barDot, distributeTicks, fitScale, scheduleTable, DiagramError, svgToDataUri,
} from './structuralDrawingKit.mjs';

const MIN_INNER_MM = 1200, MAX_INNER_MM = 4000; // typical Egyptian-code passenger-lift pit plan range
const MIN_WALL_T_MM = 200, MAX_WALL_T_MM = 500;
const MIN_DEPTH_MM = 1000, MAX_DEPTH_MM = 3000; // pit depth (base slab top to pit-top/ground level)
const MIN_SLAB_T_MM = 200, MAX_SLAB_T_MM = 800;
const MIN_COVER_MM = 30, MAX_COVER_MM = 75;
const MIN_BAR_DIA_MM = 10, MAX_BAR_DIA_MM = 25;
const MIN_SPACING_MM = 100, MAX_SPACING_MM = 300;
const MAX_DRAWN_HORIZ_ROWS = 20; // same MAX_DRAWN_TIES_PER_ZONE-style cap basementWallDiagram.mjs/beamDiagram.mjs both already use
const MAX_DRAWN_MESH_LINES = 20;

const L = {
  en: {
    title: (id) => `ELEVATOR PIT ${id} \u2014 REINFORCEMENT DETAIL`,
    plan: 'PLAN', section: 'SECTION A-A',
    sump: 'SUMP', innerDim: (l, w) => `${l} x ${w} (interior)`,
    colElement: 'Element', colDia: 'dia (mm)', colSpacing: 'Spacing (mm)', colFace: 'Face / Location',
    elExt: 'Exterior Vertical', elInt: 'Interior Vertical', elHoriz: 'Horizontal (both faces)', elMesh: 'Base Slab Mesh (bottom)',
    faceExt: 'excavation face', faceInt: 'pit-interior face', faceBoth: 'both faces', faceBottom: 'bottom, both directions',
    caption: 'Schematic reinforcement detail generated from the supplied data \u2014 verify every bar diameter, spacing, cover, and pit dimension against your own design before issuing for construction. All 4 walls are drawn identically reinforced per the single representative section shown (v1 simplification); if any wall genuinely differs, adjust the schedule accordingly. Buffer-post anchors, waterproofing, sump reinforcement, and pit ladder are not shown \u2014 add per your own detail standard.',
    dirAttr: 'ltr',
  },
  ar: {
    title: (id) => `\u062d\u0641\u0631\u0629 \u0645\u0635\u0639\u062f ${id} \u2014 \u062a\u0641\u0635\u064a\u0644\u0629 \u0627\u0644\u062a\u0633\u0644\u064a\u062d`,
    plan: '\u0645\u0633\u0642\u0637', section: '\u0642\u0637\u0627\u0639 A-A',
    sump: '\u0628\u0626\u0631 \u062a\u062c\u0645\u064a\u0639', innerDim: (l, w) => `${l} x ${w} (\u062f\u0627\u062e\u0644\u064a)`,
    colElement: '\u0627\u0644\u0639\u0646\u0635\u0631', colDia: '\u0627\u0644\u0642\u0637\u0631 \u0645\u0645', colSpacing: '\u0627\u0644\u062a\u0628\u0627\u0639\u062f \u0645\u0645', colFace: '\u0627\u0644\u0648\u062c\u0647 / \u0627\u0644\u0645\u0648\u0642\u0639',
    elExt: '\u0631\u0623\u0633\u064a \u062e\u0627\u0631\u062c\u064a', elInt: '\u0631\u0623\u0633\u064a \u062f\u0627\u062e\u0644\u064a', elHoriz: '\u0623\u0641\u0642\u064a (\u0627\u0644\u0648\u062c\u0647\u064a\u0646)', elMesh: '\u0634\u0628\u0643\u0629 \u0642\u0627\u0639\u062f\u0629 \u0627\u0644\u062d\u0641\u0631\u0629 (\u0633\u0641\u0644\u064a)',
    faceExt: '\u0648\u062c\u0647 \u0627\u0644\u062d\u0641\u0631', faceInt: '\u0648\u062c\u0647 \u062f\u0627\u062e\u0644 \u0627\u0644\u062d\u0641\u0631\u0629', faceBoth: '\u0627\u0644\u0648\u062c\u0647\u064a\u0646', faceBottom: '\u0633\u0641\u0644\u064a\u060c \u0627\u0644\u0627\u062a\u062c\u0627\u0647\u064a\u0646',
    caption: '\u062a\u0641\u0635\u064a\u0644\u0629 \u062a\u0633\u0644\u064a\u062d \u062a\u062e\u0637\u064a\u0637\u064a\u0629 \u0645\u0628\u0646\u064a\u0629 \u0639\u0644\u0649 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0645\u062f\u062e\u0644\u0629 \u2014 \u064a\u062c\u0628 \u0645\u0631\u0627\u062c\u0639\u0629 \u0643\u0644 \u0642\u0637\u0631 \u0648\u062a\u0628\u0627\u0639\u062f \u0648\u063a\u0637\u0627\u0621 \u0642\u0628\u0644 \u0627\u0644\u062a\u0646\u0641\u064a\u0630. \u0627\u0644\u062d\u0648\u0627\u0626\u0637 \u0627\u0644\u0623\u0631\u0628\u0639\u0629 \u0645\u0631\u0633\u0648\u0645\u0629 \u0628\u0646\u0641\u0633 \u0627\u0644\u062a\u0633\u0644\u064a\u062d.',
    dirAttr: 'rtl',
  },
};

function fmt0(mm) { return String(Math.round(mm)); }

export function computeElevatorPitDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'computeElevatorPitDiagramGeometry expects an object.');
  }
  const unit = raw.unit || 'mm';
  assertOneOf('unit', unit, ['mm', 'cm', 'm']);
  const id = String(raw.pitId ?? raw.id ?? 'EP1');

  const innerLengthMM = toMm(raw.innerLengthMM, unit);
  const innerWidthMM = toMm(raw.innerWidthMM, unit);
  const wallThicknessMM = toMm(raw.wallThicknessMM, unit);
  const pitDepthMM = toMm(raw.pitDepthMM, unit);
  const baseSlabThicknessMM = toMm(raw.baseSlabThicknessMM, unit);
  const coverMM = toMm(raw.coverMM, unit);
  for (const [name, v, lo, hi] of [
    ['innerLengthMM', innerLengthMM, MIN_INNER_MM, MAX_INNER_MM],
    ['innerWidthMM', innerWidthMM, MIN_INNER_MM, MAX_INNER_MM],
    ['wallThicknessMM', wallThicknessMM, MIN_WALL_T_MM, MAX_WALL_T_MM],
    ['pitDepthMM', pitDepthMM, MIN_DEPTH_MM, MAX_DEPTH_MM],
    ['baseSlabThicknessMM', baseSlabThicknessMM, MIN_SLAB_T_MM, MAX_SLAB_T_MM],
    ['coverMM', coverMM, MIN_COVER_MM, MAX_COVER_MM],
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
    return { dia, spacing };
  }
  const exteriorVerticalBars = readBarSpec(raw.exteriorVerticalBars, 'exteriorVerticalBars');
  const interiorVerticalBars = readBarSpec(raw.interiorVerticalBars, 'interiorVerticalBars');
  const horizontalBars = readBarSpec(raw.horizontalBars, 'horizontalBars');
  const baseSlabMesh = readBarSpec(raw.baseSlabMesh, 'baseSlabMesh');

  let sump = null;
  if (raw.sump) {
    const lengthMM = toMm(raw.sump.lengthMM, unit);
    const widthMM = toMm(raw.sump.widthMM, unit);
    const depthMM = toMm(raw.sump.depthMM, unit);
    const offsetXMM = toMm(raw.sump.offsetXMM ?? 0, unit);
    const offsetYMM = toMm(raw.sump.offsetYMM ?? 0, unit);
    assertFinitePositive('sump.lengthMM', lengthMM);
    assertFinitePositive('sump.widthMM', widthMM);
    assertFinitePositive('sump.depthMM', depthMM);
    if (offsetXMM < 0 || offsetYMM < 0 || offsetXMM + lengthMM > innerLengthMM || offsetYMM + widthMM > innerWidthMM) {
      throw new DiagramError('OUT_OF_RANGE', 'sump footprint (offset + size) must fit entirely within the pit interior footprint.');
    }
    sump = { lengthMM, widthMM, depthMM, offsetXMM, offsetYMM };
  }

  const outerLengthMM = innerLengthMM + 2 * wallThicknessMM;
  const outerWidthMM = innerWidthMM + 2 * wallThicknessMM;

  // Horizontal-bar rows up the wall height, and base-slab mesh lines
  // across the outer footprint — same distributeTicks capped-count
  // convention every repetitive-reinforcement element in this app uses.
  const horizRowCount = Math.max(2, Math.round((pitDepthMM - 2 * coverMM) / horizontalBars.spacing) + 1);
  const horizRowYs = distributeTicks(coverMM, pitDepthMM - coverMM, Math.min(horizRowCount, MAX_DRAWN_HORIZ_ROWS));

  const meshXCount = Math.max(2, Math.round(outerLengthMM / baseSlabMesh.spacing) + 1);
  const meshYCount = Math.max(2, Math.round(outerWidthMM / baseSlabMesh.spacing) + 1);
  const meshXs = distributeTicks(coverMM, outerLengthMM - coverMM, Math.min(meshXCount, MAX_DRAWN_MESH_LINES));
  const meshYs = distributeTicks(coverMM, outerWidthMM - coverMM, Math.min(meshYCount, MAX_DRAWN_MESH_LINES));

  return {
    type: 'elevatorPit', unit: 'mm', id,
    innerLengthMM, innerWidthMM, outerLengthMM, outerWidthMM,
    wallThicknessMM, pitDepthMM, baseSlabThicknessMM, coverMM,
    exteriorVerticalBars, interiorVerticalBars, horizontalBars,
    horizontal: { ...horizontalBars, realRowCount: horizRowCount, rowYs: horizRowYs },
    baseSlabMesh: { ...baseSlabMesh, realXCount: meshXCount, realYCount: meshYCount, meshXs, meshYs },
    sump,
  };
}

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 1100;
const PLAN_BOX = { x: 60, y: 110, w: 480, h: 420 };
const SECTION_BOX = { x: 600, y: 110, w: 450, h: 420 };

function renderPlan(geometry, scale, box, l) {
  const { outerLengthMM, outerWidthMM, innerLengthMM, innerWidthMM, wallThicknessMM, baseSlabMesh, sump } = geometry;
  const outerPx = outerLengthMM * scale, outerPy = outerWidthMM * scale;
  const sx = box.x + (box.w - outerPx) / 2;
  const sy = box.y + (box.h - outerPy) / 2;
  const x = (mm) => sx + mm * scale;
  const y = (mm) => sy + mm * scale;

  let svg = `<g class="plan">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.plan)}</text>`;

  for (const mm of baseSlabMesh.meshXs) svg += `<line x1="${x(mm)}" y1="${y(0)}" x2="${x(mm)}" y2="${y(outerWidthMM)}" class="web-mesh-line"/>`;
  for (const mm of baseSlabMesh.meshYs) svg += `<line x1="${x(0)}" y1="${y(mm)}" x2="${x(outerLengthMM)}" y2="${y(mm)}" class="web-mesh-line"/>`;

  svg += `<rect x="${x(0)}" y="${y(0)}" width="${outerPx}" height="${outerPy}" class="concrete-outline"/>`;
  svg += `<rect x="${x(wallThicknessMM)}" y="${y(wallThicknessMM)}" width="${innerLengthMM * scale}" height="${innerWidthMM * scale}" class="concrete-outline"/>`;

  if (sump) {
    const sx0 = wallThicknessMM + sump.offsetXMM, sy0 = wallThicknessMM + sump.offsetYMM;
    svg += `<rect x="${x(sx0)}" y="${y(sy0)}" width="${sump.lengthMM * scale}" height="${sump.widthMM * scale}" class="sump-void"/>`;
    svg += `<text x="${x(sx0 + sump.lengthMM / 2)}" y="${y(sy0 + sump.widthMM / 2)}" text-anchor="middle" class="dim-label">${esc(l.sump)}</text>`;
  }

  svg += dimensionLine(x(wallThicknessMM), y(0) - 20, x(wallThicknessMM + innerLengthMM), y(0) - 20, l.innerDim(fmt0(innerLengthMM), fmt0(innerWidthMM)));
  svg += `</g>`;
  return svg;
}

function renderSection(geometry, scale, box, l) {
  const {
    wallThicknessMM, pitDepthMM, baseSlabThicknessMM, coverMM,
    exteriorVerticalBars, interiorVerticalBars, horizontal,
  } = geometry;
  const slabWidthMM = wallThicknessMM * 4.5;
  const totalHMM = pitDepthMM + baseSlabThicknessMM;
  const slabPx = slabWidthMM * scale, totalPy = totalHMM * scale;
  const sx = box.x + (box.w - slabPx) / 2;
  const sy = box.y + (box.h - totalPy) / 2; // sy = top of the tallest content (wall top)
  const x = (mm) => sx + mm * scale;
  const yFromWallTop = (mm) => sy + mm * scale;

  let svg = `<g class="section">`;
  svg += `<text x="${box.x + box.w / 2}" y="${box.y - 14}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.section)}</text>`;

  svg += `<rect x="${x(0)}" y="${yFromWallTop(pitDepthMM)}" width="${slabPx}" height="${baseSlabThicknessMM * scale}" class="concrete-outline"/>`;
  const wallX0 = wallThicknessMM * 1.75;
  svg += `<rect x="${x(wallX0)}" y="${yFromWallTop(0)}" width="${wallThicknessMM * scale}" height="${pitDepthMM * scale}" class="concrete-outline"/>`;

  const extX = wallX0 + coverMM + exteriorVerticalBars.dia / 2;
  const intX = wallX0 + wallThicknessMM - coverMM - interiorVerticalBars.dia / 2;
  const barTopY = 0, barBotY = pitDepthMM + baseSlabThicknessMM - coverMM;
  svg += `<line x1="${x(extX)}" y1="${yFromWallTop(barTopY)}" x2="${x(extX)}" y2="${yFromWallTop(barBotY)}" class="bar-bottom"/>`;
  svg += `<line x1="${x(intX)}" y1="${yFromWallTop(barTopY)}" x2="${x(intX)}" y2="${yFromWallTop(barBotY)}" class="bar-top"/>`;

  for (const rowY of horizontal.rowYs) {
    svg += barDot(x(extX), yFromWallTop(rowY), horizontal.dia, scale, 'bottom');
    svg += barDot(x(intX), yFromWallTop(rowY), horizontal.dia, scale, 'top');
  }

  svg += dimensionLine(x(0) - 20, yFromWallTop(0), x(0) - 20, yFromWallTop(pitDepthMM), `pit depth=${fmt0(pitDepthMM)}`, { orientation: 'v' });
  svg += dimensionLine(x(0) - 20, yFromWallTop(pitDepthMM), x(0) - 20, yFromWallTop(totalHMM), `slab=${fmt0(baseSlabThicknessMM)}`, { orientation: 'v' });
  svg += `</g>`;
  return svg;
}

function buildScheduleRows(geometry, l) {
  return [
    { element: l.elExt, dia: fmt0(geometry.exteriorVerticalBars.dia), spacing: fmt0(geometry.exteriorVerticalBars.spacing), face: l.faceExt },
    { element: l.elInt, dia: fmt0(geometry.interiorVerticalBars.dia), spacing: fmt0(geometry.interiorVerticalBars.spacing), face: l.faceInt },
    { element: l.elHoriz, dia: fmt0(geometry.horizontalBars.dia), spacing: fmt0(geometry.horizontalBars.spacing), face: l.faceBoth },
    { element: l.elMesh, dia: fmt0(geometry.baseSlabMesh.dia), spacing: fmt0(geometry.baseSlabMesh.spacing), face: l.faceBottom },
  ];
}

export function renderElevatorPitDiagramSVG(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'elevatorPit') {
    throw new DiagramError('BAD_PARAM', 'renderElevatorPitDiagramSVG expects a geometry object from computeElevatorPitDiagramGeometry() (type "elevatorPit").');
  }
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);

  const planScale = fitScale([{ contentW: geometry.outerLengthMM, contentH: geometry.outerWidthMM, boxW: PLAN_BOX.w - 60, boxH: PLAN_BOX.h - 90 }]);
  const sectionScale = fitScale([{ contentW: geometry.wallThicknessMM * 4.5, contentH: geometry.pitDepthMM + geometry.baseSlabThicknessMM, boxW: SECTION_BOX.w - 80, boxH: SECTION_BOX.h - 60 }]);

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 4);
  const tableCols = [
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'spacing', label: l.colSpacing, width: tableColW },
    { key: 'face', label: l.colFace, width: CANVAS_W - 120 - tableColW * 3, script: true },
  ];
  const tableY = PLAN_BOX.y + PLAN_BOX.h + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .pit-title      { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .web-mesh-line  { stroke:#9ab3cf; stroke-width:1; }
    .sump-void      { fill:none; stroke:#1a1a1a; stroke-width:1.4; stroke-dasharray:6,4; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="pit-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderPlan(geometry, planScale, PLAN_BOX, l)}
  ${renderSection(geometry, sectionScale, SECTION_BOX, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

export { DiagramError, svgToDataUri };
