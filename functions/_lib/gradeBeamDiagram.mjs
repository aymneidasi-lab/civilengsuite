// functions/_lib/gradeBeamDiagram.mjs
//
// Deterministic, zero-AI SVG generator for a grade beam / tie beam
// reinforcement detail (elevation + cross-sections + bar schedule) — new-
// element track candidate: "Grade beam / tie beam — reuses beamDiagram's
// bar-group machinery but different support convention (soil-bearing
// strip, not point supports); distinct schema from beam's
// SUPPORT_OUT_OF_BOUNDS model." Same philosophy as beamDiagram.mjs/
// footingDiagram.mjs/columnDiagram.mjs: every dimension, bar position,
// and count in the output is arithmetic on the KB data supplied, never a
// model's guess, and never a geotechnical/structural calculation this
// module doesn't own.
//
// WHY A SEPARATE MODULE, NOT A BRANCH INSIDE beamDiagram.mjs:
// beamDiagram.mjs's computeBeamDiagramGeometry requires >=1 discrete
// `supports` entry ({x,width,type}), validates each one's CENTERLINE
// against the beam's 0..totalLength span (SUPPORT_OUT_OF_BOUNDS), and
// checks supports pairwise for overlap — that is the right model for a
// beam bearing on discrete columns/walls at known points. A grade beam
// (bears continuously along a prepared soil/blinding strip) and a tie
// beam (spans between footings, tying them, not itself a soil-bearing
// member in every project's usage of the term — this tool treats the
// two as the SAME schematic product, see the parseDiagramCommand header
// below for why) have no such discrete point-support list at all: the
// bearing IS the full length, by definition, so there is nothing to
// validate an x/width against and no SUPPORT_OUT_OF_BOUNDS-shaped check
// that could even apply. Grafting that model on (e.g. a fake single
// "support" spanning 0..totalLength) would misrepresent the element as
// point-bearing and silently invite the same COLUMN_TOO_WIDE-style
// containment checks that make no physical sense for a continuous strip.
// This is the same "distinct schema, not a reused one bent to fit" call
// footingDiagram.mjs's own header already documents for isolated vs.
// combined vs. strip vs. raft (four distinct compute paths sharing one
// file) and trapezoidalFootingDiagram.mjs/strapFootingDiagram.mjs's own
// headers document for why THEY are separate files from footingDiagram
// .mjs entirely — same reasoning, applied one level further out here
// because unlike those, this element's differentiator is the SUPPORT
// convention itself, not the plan shape.
//
// SCOPE (v1):
//   - a single prismatic span (constant b×h) with soil bearing assumed
//     CONTINUOUS along the full 0..totalLength length — there is no
//     "bearing starts/stops here" concept in this schematic; a grade
//     beam that genuinely only bears over part of its length (e.g. a
//     void former under part of it, common on expansive/heaving soil)
//     is NOT modeled — that is a geotechnical detail this tool has no
//     input contract for and will not silently assume either way.
//   - `nodes`: OPTIONAL, annotation-only markers (0..MAX_NODES) showing
//     where a column/wall/pile actually lands ON the grade beam (e.g.
//     the columns two isolated footings' grade beam ties together).
//     These are drawn as a small marker + label — NOT a structural
//     support the compute step reasons about. Removing every node from
//     the input changes nothing about the beam's own geometry, bar
//     layout, or schedule; they exist purely so the drawing communicates
//     "a column sits here" the way a real grade-beam detail does.
//   - longitudinalBars / stirrupZones: IDENTICAL contract shape and
//     validation rules to beamDiagram.mjs's own (same field names, same
//     caps, same error codes) — this is the literal "reuses beamDiagram's
//     bar-group machinery" the brief asked for. beamDiagram.mjs exports
//     no reusable validator for these (they are private to
//     computeBeamDiagramGeometry), so this module carries its own copy
//     rather than reaching into beamDiagram.mjs's internals — same
//     controlled-duplication call footingDiagram.mjs's own header
//     documents for its local esc/dimensionLine/hatchDefs copies, and
//     the same reasoning trapezoidalFootingDiagram.mjs/
//     strapFootingDiagram.mjs apply for being separate files at all: two
//     independently-tested copies that can never leak a change into each
//     other, at the cost of keeping them in sync by hand if the shared
//     shape ever changes (documented, not hidden).
//   - NOT modeled, on purpose (same explicit-boundary convention every
//     sibling module's header uses): lap-splice zones, beamWorkshop
//     (shop-drawing) mode, bent-up/cranked bars, haunched/tapered depth,
//     code-specific cutting-length math, and any bearing-pressure/
//     settlement/geotechnical calculation. A future session can add
//     lapZones/beamWorkshop the same additive way beamDiagram.mjs's own
//     Step 16 did, once asked for — v1 ships the schema difference the
//     brief actually named.
//
// ── INPUT CONTRACT (what the KB layer should hand this module) ────────
// {
//   unit?: 'mm'|'cm'|'m',              // default 'mm'
//   id: string,                        // grade/tie beam mark, e.g. "GB1"
//   section: { b: number, h: number }, // constant cross-section
//   cover: number,                     // concrete cover to stirrup outer face
//   totalLength: number,
//   nodes?: [                          // 0..MAX_NODES, ANNOTATION ONLY
//     { x: number, label?: string, type?: 'column'|'wall'|'pile' }
//   ],
//   longitudinalBars: [                // >=1, each a group of identical bars
//     {
//       markId?: string, face: 'top'|'bottom', dia: number, count: number,
//       layer?: number, startX: number, endX: number, shapeCode?: string,
//       cuttingLengthMM?: number,
//     }, ...
//   ],
//   stirrupZones: [                    // >=1, tiling (non-overlapping) zones
//     { markId?: string, dia: number, legs: number, spacing: number, startX: number, endX: number, cuttingLengthMM?: number }, ...
//   ],
//   sections?: [ { x: number, label?: string }, ... ], // defaults to one
//     near the first node (if any, else near the 10%-length point) and
//     one at midspan
// }
//
// Resource lifecycle: this module is pure/synchronous — no timers, no
// fetch, no KV, no external handles of any kind, same profile as every
// *Diagram.mjs module in this app.

import {
  DiagramError, toMm, fromMm, assertFinitePositive, assertFiniteNonNegative,
  assertInt, assertOneOf, assertNoIntervalOverlap, esc, captionLineCount,
  renderCaptionAt, fontStacks, kitStyleBlock, hatchDefs, dimensionLine, barDot,
  stirrupTick, distributeTicks, barMarkTag, fitScale, scheduleTable, svgToDataUri,
} from './structuralDrawingKit.mjs';

export { DiagramError, svgToDataUri };

// ── Sanity caps ──────────────────────────────────────────────────────
// Same role, same reasoning, and (where the field is shared with beam)
// the same numeric values as beamDiagram.mjs's own caps — see that
// file's header for the full CPU-time rationale. MAX_NODES mirrors
// beam's MAX_SUPPORTS (10): nodes are cheaper to draw than a real
// support (no overlap check, no hatch rect), so there is no reason to
// cap them tighter, but no reason to allow more than a realistic number
// of columns tying into one grade beam either.
const MAX_NODES = 10;
const MAX_BAR_GROUPS = 24;
const MAX_STIRRUP_ZONES = 16;
const MAX_SECTIONS = 6;
const MAX_LAYER = 4;
const MAX_DRAWN_TIES_PER_ZONE = 20;
const MIN_BEAM_LENGTH_MM = 300;
const MAX_BEAM_LENGTH_MM = 60000; // 60m — a schematic past this needs a real drafting tool

const FACES = ['top', 'bottom'];
const NODE_TYPES = ['column', 'wall', 'pile'];

// ── Compute ──────────────────────────────────────────────────────────
export function computeGradeBeamDiagramGeometry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new DiagramError('BAD_PARAM', 'Grade beam diagram input must be an object.');
  }
  const unit = raw.unit || 'mm';
  const id = raw.id != null ? String(raw.id).slice(0, 40) : 'GB';

  if (!raw.section || typeof raw.section !== 'object') {
    throw new DiagramError('BAD_PARAM', '"section" is required: { b, h }.');
  }
  const b = toMm(raw.section.b, unit);
  const h = toMm(raw.section.h, unit);
  assertFinitePositive('section.b', b);
  assertFinitePositive('section.h', h);

  const cover = toMm(raw.cover, unit);
  assertFinitePositive('cover', cover);
  if (2 * cover >= Math.min(b, h)) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${cover}mm) leaves no room for reinforcement inside a ${b}x${h}mm section.`);
  }

  const totalLength = toMm(raw.totalLength, unit);
  assertFinitePositive('totalLength', totalLength);
  if (totalLength < MIN_BEAM_LENGTH_MM || totalLength > MAX_BEAM_LENGTH_MM) {
    throw new DiagramError('BAD_PARAM', `"totalLength" must be between ${MIN_BEAM_LENGTH_MM}mm and ${MAX_BEAM_LENGTH_MM}mm for this schematic, got ${totalLength}mm.`);
  }

  // ── Nodes: annotation-only column/wall/pile markers. Deliberately NOT
  // the beam-module's SUPPORT_OUT_OF_BOUNDS check reused: a different
  // error code (NODE_OUT_OF_BOUNDS) on purpose, so a caller/log/test can
  // never confuse "a beam support fell outside the span" (a real
  // point-support model's error) with "an annotation marker fell outside
  // the span" (this element has no support model to violate — the
  // marker itself is just misplaced). No overlap check: nodes are
  // zero-width points, not solid objects that could physically collide.
  let nodes = [];
  if (raw.nodes != null) {
    if (!Array.isArray(raw.nodes)) {
      throw new DiagramError('BAD_PARAM', '"nodes" must be an array when provided.');
    }
    if (raw.nodes.length > MAX_NODES) {
      throw new DiagramError('TOO_MANY_NODES', `At most ${MAX_NODES} nodes are supported, got ${raw.nodes.length}.`);
    }
    nodes = raw.nodes.map((n, i) => {
      const tag = `nodes[${i}]`;
      if (!n || typeof n !== 'object') throw new DiagramError('BAD_PARAM', `${tag} must be an object.`);
      const x = toMm(n.x, unit);
      assertFiniteNonNegative(`${tag}.x`, x);
      if (x > totalLength + 1e-6) {
        throw new DiagramError('NODE_OUT_OF_BOUNDS', `${tag} (x=${fromMm(x, unit)}${unit}) is outside the beam's 0..${fromMm(totalLength, unit)}${unit} length.`);
      }
      const type = n.type || 'column';
      assertOneOf(`${tag}.type`, type, NODE_TYPES);
      return {
        x, type,
        label: n.label != null ? String(n.label).slice(0, 20) : `${type[0].toUpperCase()}${i + 1}`,
      };
    }).sort((a, c) => a.x - c.x);
  }

  // ── Longitudinal bars — identical contract/validation to
  // beamDiagram.mjs's own (see this file's header for why this is a
  // controlled duplicate, not a shared import).
  if (!Array.isArray(raw.longitudinalBars) || raw.longitudinalBars.length < 1) {
    throw new DiagramError('BAD_PARAM', '"longitudinalBars" must be a non-empty array.');
  }
  if (raw.longitudinalBars.length > MAX_BAR_GROUPS) {
    throw new DiagramError('TOO_MANY_BAR_GROUPS', `At most ${MAX_BAR_GROUPS} longitudinal bar groups are supported, got ${raw.longitudinalBars.length}.`);
  }
  const longitudinalBars = raw.longitudinalBars.map((g, i) => {
    const tag = `longitudinalBars[${i}]`;
    if (!g || typeof g !== 'object') throw new DiagramError('BAD_PARAM', `${tag} must be an object.`);
    assertOneOf(`${tag}.face`, g.face, FACES);
    const dia = toMm(g.dia, unit);
    assertFinitePositive(`${tag}.dia`, dia);
    assertInt(`${tag}.count`, g.count, { min: 1, max: 30 });
    const layer = g.layer ?? 1;
    assertInt(`${tag}.layer`, layer, { min: 1, max: MAX_LAYER });
    const startX = toMm(g.startX, unit);
    const endX = toMm(g.endX, unit);
    assertFiniteNonNegative(`${tag}.startX`, startX);
    assertFinitePositive(`${tag}.endX`, endX);
    if (endX <= startX) throw new DiagramError('BAD_PARAM', `${tag}: endX must be greater than startX.`);
    if (startX < -1e-6 || endX > totalLength + 1e-6) {
      throw new DiagramError('BAR_OUT_OF_BOUNDS', `${tag} [${fromMm(startX, unit)}, ${fromMm(endX, unit)}]${unit} extends outside the beam's 0..${fromMm(totalLength, unit)}${unit} length.`);
    }
    const cuttingLengthMM = g.cuttingLengthMM != null ? toMm(g.cuttingLengthMM, unit) : null;
    if (cuttingLengthMM != null) assertFinitePositive(`${tag}.cuttingLengthMM`, cuttingLengthMM);
    return {
      markId: g.markId != null ? String(g.markId).slice(0, 10) : String(i + 1),
      face: g.face, dia, count: g.count, layer, startX, endX,
      shapeCode: g.shapeCode ? String(g.shapeCode).slice(0, 40) : null,
      cuttingLengthMM,
    };
  });

  if (!Array.isArray(raw.stirrupZones) || raw.stirrupZones.length < 1) {
    throw new DiagramError('BAD_PARAM', '"stirrupZones" must be a non-empty array.');
  }
  if (raw.stirrupZones.length > MAX_STIRRUP_ZONES) {
    throw new DiagramError('TOO_MANY_ZONES', `At most ${MAX_STIRRUP_ZONES} stirrup zones are supported, got ${raw.stirrupZones.length}.`);
  }
  const stirrupZones = raw.stirrupZones.map((z, i) => {
    const tag = `stirrupZones[${i}]`;
    if (!z || typeof z !== 'object') throw new DiagramError('BAD_PARAM', `${tag} must be an object.`);
    const dia = toMm(z.dia, unit);
    assertFinitePositive(`${tag}.dia`, dia);
    assertInt(`${tag}.legs`, z.legs, { min: 2, max: 8 });
    const spacing = toMm(z.spacing, unit);
    assertFinitePositive(`${tag}.spacing`, spacing);
    const startX = toMm(z.startX, unit);
    const endX = toMm(z.endX, unit);
    assertFiniteNonNegative(`${tag}.startX`, startX);
    assertFinitePositive(`${tag}.endX`, endX);
    if (endX <= startX) throw new DiagramError('BAD_PARAM', `${tag}: endX must be greater than startX.`);
    if (startX < -1e-6 || endX > totalLength + 1e-6) {
      throw new DiagramError('ZONE_OUT_OF_BOUNDS', `${tag} [${fromMm(startX, unit)}, ${fromMm(endX, unit)}]${unit} extends outside the beam's 0..${fromMm(totalLength, unit)}${unit} length.`);
    }
    const cuttingLengthMM = z.cuttingLengthMM != null ? toMm(z.cuttingLengthMM, unit) : null;
    if (cuttingLengthMM != null) assertFinitePositive(`${tag}.cuttingLengthMM`, cuttingLengthMM);
    return {
      markId: z.markId != null ? String(z.markId).slice(0, 10) : `St${i + 1}`,
      dia, legs: z.legs, spacing, startX, endX, cuttingLengthMM,
    };
  });
  assertNoIntervalOverlap(stirrupZones.map((z) => ({ startMM: z.startX, endMM: z.endX })), { label: 'stirrup zones' });

  // Global per-(face,layer) depth map — identical purpose/logic to
  // beamDiagram.mjs's own (see that file's comment): keeps a group's
  // elevation line and every cross-section dot at the same depth.
  const layerDepth = new Map();
  for (const face of FACES) {
    const layers = [...new Set(longitudinalBars.filter((g) => g.face === face).map((g) => g.layer))].sort((x, y) => x - y);
    let depthFromFaceMM = cover;
    for (const layer of layers) {
      const groups = longitudinalBars.filter((g) => g.face === face && g.layer === layer);
      const maxDia = Math.max(...groups.map((g) => g.dia));
      const yFromFaceMM = depthFromFaceMM + maxDia / 2;
      const yFromTopMM = face === 'top' ? yFromFaceMM : h - yFromFaceMM;
      layerDepth.set(`${face}:${layer}`, { yFromTopMM, maxDia });
      depthFromFaceMM += maxDia * 2.2;
    }
  }
  for (const g of longitudinalBars) {
    g.yFromTopMM = layerDepth.get(`${g.face}:${g.layer}`).yFromTopMM;
  }

  // Default section cuts: near the first node (a column/wall bearing
  // point is exactly where a real grade-beam schedule wants a section),
  // else near the 10%-length point when no nodes were given, plus
  // midspan — same "one representative cut near an end, one at midspan"
  // convention beamDiagram.mjs's own default uses, adapted since this
  // element has no support face to anchor the first cut to.
  let sectionDefs = raw.sections;
  if (!Array.isArray(sectionDefs) || sectionDefs.length === 0) {
    const nearX = nodes.length > 0
      ? Math.min(Math.max(nodes[0].x, totalLength * 0.02), totalLength * 0.98)
      : Math.min(totalLength * 0.1, totalLength * 0.3);
    sectionDefs = [
      { x: fromMm(nearX, unit), label: '1-1' },
      { x: fromMm(totalLength / 2, unit), label: '2-2' },
    ];
  }
  if (sectionDefs.length > MAX_SECTIONS) {
    throw new DiagramError('TOO_MANY_SECTIONS', `At most ${MAX_SECTIONS} cross-sections are supported, got ${sectionDefs.length}.`);
  }
  const sections = sectionDefs.map((s, i) => {
    if (!s || typeof s !== 'object') throw new DiagramError('BAD_PARAM', `sections[${i}] must be an object.`);
    const x = toMm(s.x, unit);
    if (x < -1e-6 || x > totalLength + 1e-6) {
      throw new DiagramError('SECTION_OUT_OF_BOUNDS', `sections[${i}] x=${fromMm(x, unit)}${unit} is outside the beam's 0..${fromMm(totalLength, unit)}${unit} length.`);
    }
    const activeBars = longitudinalBars.filter((g) => g.startX <= x + 1e-6 && g.endX >= x - 1e-6);
    return {
      x, label: s.label ? String(s.label).slice(0, 20) : `${i + 1}-${i + 1}`,
      bars: layoutSectionBars(activeBars, b, cover),
    };
  });

  return { type: 'gradeBeam', unit, id, section: { b, h }, cover, totalLength, nodes, longitudinalBars, stirrupZones, sections };
}

// Identical algorithm to beamDiagram.mjs's own layoutSectionBars (see
// that file's comment for the depth-vs-x-position reasoning) — a
// controlled duplicate, not a shared import; see this file's header.
function layoutSectionBars(activeBars, bMM, coverMM) {
  const placed = [];
  for (const face of FACES) {
    const faceBars = activeBars.filter((g) => g.face === face);
    const layers = [...new Set(faceBars.map((g) => g.layer))];
    for (const layer of layers) {
      const groups = faceBars.filter((g) => g.layer === layer);
      const maxDia = Math.max(...groups.map((g) => g.dia));
      const totalCount = groups.reduce((s, g) => s + g.count, 0);
      const envelope = bMM - 2 * coverMM - maxDia;
      const step = totalCount > 1 ? envelope / (totalCount - 1) : 0;
      let idx = 0;
      for (const g of groups) {
        for (let k = 0; k < g.count; k++) {
          const xMM = totalCount === 1 ? bMM / 2 : coverMM + maxDia / 2 + idx * step;
          placed.push({ face, layer, markId: g.markId, dia: g.dia, xMM, yFromTopMM: g.yFromTopMM });
          idx++;
        }
      }
    }
  }
  return placed;
}

// ── Labels ───────────────────────────────────────────────────────────
// top/bottom/stirrupWord/col*/extentSuffix/dirAttr copied verbatim from
// beamDiagram.mjs's own L object — already verified render correctly
// (scheduleTable's `script:true` columns already apply scriptFontStack
// to these). Every OTHER string below is NEW for this module and is
// written parenthesis- and dash-free, following the same discipline
// beamDiagram.mjs's own Step 16 addendum documents (columnDiagram.mjs's
// verified-safe convention) — not because parens/dashes are known-broken
// on an already-scriptFontStack'd class, but because staying consistent
// with the rest of this codebase's newest additions costs nothing and
// keeps one house rule instead of two.
const L = {
  en: {
    title: (id) => `GRADE / TIE BEAM ${id} \u2014 REINFORCEMENT DETAIL`,
    elevation: 'ELEVATION', sectionWord: 'SECTION',
    top: 'Top', bottom: 'Bottom', stirrupWord: 'Stirrup',
    colMark: 'Mark', colElement: 'Element', colDia: 'dia (mm)', colCount: 'Count / Spacing', colLength: 'Length (mm)',
    extentSuffix: ' (extent)',
    dirAttr: 'ltr',
    bearingLabel: 'Continuous soil bearing along full length',
    nodeWord: { column: 'Column', wall: 'Wall', pile: 'Pile' },
    caption: 'Schematic reinforcement detail generated from the supplied data. Bearing is assumed continuous along the full length shown; verify actual bearing extent, soil bearing capacity, and settlement behavior against your own geotechnical report before issuing for construction. Verify every bar mark, count, spacing, and length against your own design (ECP 203 / ACI 318). Lengths marked "(extent)" are drawn span length only; add development / hook / lap length per your design code.',
  },
  ar: {
    title: (id) => `تفريد حديد كمرة الأساس أو الرابط ${id}`,
    elevation: 'منظور جانبي', sectionWord: 'قطاع',
    top: 'علوي', bottom: 'سفلي', stirrupWord: 'كانة',
    colMark: 'العلامة', colElement: 'النوع', colDia: 'القطر مم', colCount: 'العدد أو التباعد', colLength: 'الطول مم',
    extentSuffix: ' امتداد',
    dirAttr: 'rtl',
    bearingLabel: 'تحمل تربة مستمر على كامل الطول',
    nodeWord: { column: 'عمود', wall: 'حائط', pile: 'خازوق' },
    caption: 'رسم تفصيلي توضيحي أُنشئ من البيانات المُدخلة. يُفترض أن التحمل مستمر على كامل الطول الموضح، تحقق من امتداد التحمل الفعلي وقدرة تحمل التربة وسلوك الهبوط وفق تقرير التربة الخاص بمشروعك قبل الاعتماد للتنفيذ. راجع كل علامة سيخ وعددها وتباعدها وطولها وفق تصميمك الخاص ECP 203 أو ACI 318. الأطوال المعلمة امتداد هي طول الامتداد فقط أضف طول الرباط أو الكلبتين أو التداخل حسب الكود المستخدم.',
  },
};

// ── Render ───────────────────────────────────────────────────────────
const CANVAS_W = 1100;
const ELEV_BOX = { x: 60, y: 150, w: CANVAS_W - 120, h: 120 };
const SECTION_SIZE = 190;
const SECTION_GAP = 40;
const SOIL_BAND_H = 26;

export function renderGradeBeamDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const l = L[lang];
  const { defaultFontStack, scriptFontStack } = fontStacks(lang);
  const { b, h } = geometry.section;

  const scale = fitScale([{ contentW: geometry.totalLength, contentH: h * 2.4, boxW: ELEV_BOX.w, boxH: ELEV_BOX.h }]);
  const beamW = geometry.totalLength * scale;
  const beamH = h * scale;
  const beamX = ELEV_BOX.x + (ELEV_BOX.w - beamW) / 2;
  const beamY = ELEV_BOX.y + (ELEV_BOX.h - beamH) / 2;

  const sectionScale = fitScale([{ contentW: b, contentH: h, boxW: SECTION_SIZE - 50, boxH: SECTION_SIZE - 70 }]);
  const sectionsRowW = geometry.sections.length * SECTION_SIZE + (geometry.sections.length - 1) * SECTION_GAP;
  const sectionsX0 = (CANVAS_W - sectionsRowW) / 2;
  const sectionsY = beamY + beamH + SOIL_BAND_H + 150;

  const tableRows = buildScheduleRows(geometry, l);
  const tableColW = Math.floor((CANVAS_W - 120) / 5);
  const tableCols = [
    { key: 'mark', label: l.colMark, width: tableColW },
    { key: 'element', label: l.colElement, width: tableColW, script: true },
    { key: 'dia', label: l.colDia, width: tableColW },
    { key: 'count', label: l.colCount, width: tableColW },
    { key: 'length', label: l.colLength, width: CANVAS_W - 120 - tableColW * 4, script: true },
  ];
  const tableY = sectionsY + SECTION_SIZE + 60;
  const table = scheduleTable(60, tableY, tableCols, tableRows, { lang });

  const captionY = tableY + table.height + 34;
  const captionLines = captionLineCount(l.caption, 110);
  const CANVAS_H = captionY + captionLines * 15 + 24;

  const style = kitStyleBlock({ defaultFontStack, scriptFontStack, lang }) + `
    .gradebeam-title { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .zone-label      { font-size:10.5px; fill:#2f7a3d; font-family: ${defaultFontStack}; }
    .node-label      { font-size:11px; fill:#333; font-family: ${scriptFontStack}; }
    .node-marker     { fill:#333; stroke:#111; stroke-width:0.6; }
    .bearing-label   { font-size:11px; fill:#6b5a3d; font-family: ${scriptFontStack}; }`;

  return `<svg viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>${style}</style>
  <rect x="0" y="0" width="${CANVAS_W}" height="${CANVAS_H}" fill="#ffffff"/>
  <text x="${CANVAS_W / 2}" y="32" text-anchor="middle" class="gradebeam-title" dir="${l.dirAttr}">${esc(l.title(geometry.id))}</text>
  ${renderElevation(geometry, scale, beamX, beamY, beamW, beamH, l)}
  ${renderSections(geometry, sectionScale, sectionsX0, sectionsY, l)}
  ${table.svg}
  ${renderCaptionAt(l.caption, { x: lang === 'ar' ? CANVAS_W - 60 : 60, startY: captionY, lang, maxCharsPerLine: 110, lineHeight: 15 })}
</svg>`;
}

// Draws the elevation: a CONTINUOUS soil-hatch strip beneath the full
// beam length (the schema difference this module exists for — contrast
// with beamDiagram.mjs's renderElevation, which draws one hatched
// support rect per discrete support instead), the concrete outline,
// optional node markers (small filled triangle + label, purely
// annotation — see this file's header), longitudinal bar lines + mark
// tags, and stirrup zone ticks — this part IS beamDiagram.mjs's own bar-
// group machinery, reused algorithm-for-algorithm (not import-for-
// import; see header).
function renderElevation(geometry, scale, beamX, beamY, beamW, beamH, l) {
  const { totalLength, nodes, longitudinalBars, stirrupZones, cover } = geometry;
  let svg = `<g class="elevation">`;
  svg += `<text x="${beamX + beamW / 2}" y="${beamY - 56}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.elevation)}</text>`;

  // Node markers — drawn ABOVE the beam so they never collide with the
  // soil hatch drawn below it. Small downward-pointing triangle sitting
  // on the beam's top edge (the conventional "reaction point" symbol),
  // label above. Annotation only: nothing below this block reads
  // `nodes` again.
  nodes.forEach((n) => {
    const cx = beamX + n.x * scale;
    const triTopY = beamY - 26, triBotY = beamY - 4;
    svg += `<path d="M ${cx - 7} ${triTopY} L ${cx + 7} ${triTopY} L ${cx} ${triBotY} Z" class="node-marker"/>`;
    svg += `<text x="${cx}" y="${triTopY - 4}" text-anchor="middle" class="node-label" dir="${l.dirAttr}">${esc(n.label)}</text>`;
  });

  // Beam concrete outline
  svg += `<rect x="${beamX}" y="${beamY}" width="${beamW}" height="${beamH}" class="concrete-outline"/>`;

  // Continuous soil-bearing strip — one rect spanning the FULL beam
  // length, not one rect per discrete support (contrast beamDiagram.mjs
  // .renderElevation's per-support loop). This single rect IS the
  // "different support convention" the brief asked for, drawn.
  const soilY = beamY + beamH;
  svg += `<rect x="${beamX}" y="${soilY}" width="${beamW}" height="${SOIL_BAND_H}" fill="url(#soilHatch)" stroke="#8a7350" stroke-width="1"/>`;
  svg += `<text x="${beamX + beamW / 2}" y="${soilY + SOIL_BAND_H + 16}" text-anchor="middle" class="bearing-label" dir="${l.dirAttr}">${esc(l.bearingLabel)}</text>`;

  // Longitudinal bar lines + mark tags — identical algorithm to
  // beamDiagram.mjs's own (no support-hatch collision check needed here:
  // there is no discrete support rect to collide with any more).
  for (const g of longitudinalBars) {
    const x1 = beamX + g.startX * scale, x2 = beamX + g.endX * scale;
    const y = beamY + g.yFromTopMM * scale;
    svg += `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" class="bar-${g.face}"/>`;
    const tagX = (x1 + x2) / 2;
    const tagY = g.face === 'top' ? y - 13 : y + 13;
    svg += barMarkTag(tagX, tagY, `${g.markId} \u00d8${g.dia}-${g.count}`, { r: 11 });
  }

  // Stirrup zones — identical algorithm to beamDiagram.mjs's own,
  // positioned below the soil-bearing label row instead of below a bare
  // beam bottom edge.
  const tieTopY = beamY + (cover * 0.4) * scale;
  const tieBotY = beamY + beamH - (cover * 0.4) * scale;
  const zoneRowY = soilY + SOIL_BAND_H + 36;
  stirrupZones.forEach((z) => {
    const x1 = beamX + z.startX * scale, x2 = beamX + z.endX * scale;
    const realCount = Math.max(2, Math.round((z.endX - z.startX) / z.spacing) + 1);
    const drawCount = Math.min(realCount, MAX_DRAWN_TIES_PER_ZONE);
    for (const tx of distributeTicks(x1, x2, drawCount)) {
      svg += stirrupTick(tx, tieTopY, tieBotY);
    }
    svg += dimensionLine(x1, zoneRowY, x2, zoneRowY, `${z.markId} \u00d8${z.dia}-${z.legs}L@${z.spacing}`, { orientation: 'h', tick: 5 });
  });

  // Overall length dimension
  svg += dimensionLine(beamX, zoneRowY + 34, beamX + beamW, zoneRowY + 34, `L = ${(totalLength / 1000).toFixed(2)}m`, { orientation: 'h' });

  svg += `</g>`;
  return svg;
}

// Identical algorithm to beamDiagram.mjs's own renderSections.
function renderSections(geometry, scale, x0, y0, l) {
  const { b, h } = geometry.section;
  const w = b * scale, hh = h * scale;
  let svg = '';
  geometry.sections.forEach((sec, i) => {
    const boxX = x0 + i * (SECTION_SIZE + SECTION_GAP);
    const sx = boxX + (SECTION_SIZE - w) / 2;
    const sy = y0 + 10;
    svg += `<g class="section-${i}">`;
    svg += `<text x="${boxX + SECTION_SIZE / 2}" y="${y0 - 10}" text-anchor="middle" class="view-title" dir="${l.dirAttr}">${esc(l.sectionWord)} ${esc(sec.label)}</text>`;
    svg += `<rect x="${sx}" y="${sy}" width="${w}" height="${hh}" class="concrete-outline"/>`;
    for (const bar of sec.bars) {
      const cx = sx + bar.xMM * scale;
      const cy = sy + bar.yFromTopMM * scale;
      svg += barDot(cx, cy, bar.dia, scale, bar.face);
    }
    svg += dimensionLine(sx, sy + hh + 20, sx + w, sy + hh + 20, `b=${b}mm`, { orientation: 'h', tick: 5 });
    svg += dimensionLine(sx - 20, sy, sx - 20, sy + hh, `h=${h}mm`, { orientation: 'v', tick: 5 });
    svg += `</g>`;
  });
  return svg;
}

// Identical algorithm to beamDiagram.mjs's own buildScheduleRows.
function buildScheduleRows(geometry, l) {
  const rows = [];
  for (const g of geometry.longitudinalBars) {
    const extent = Math.round(g.endX - g.startX);
    rows.push({
      mark: g.markId,
      element: g.face === 'top' ? l.top : l.bottom,
      dia: String(Math.round(g.dia)),
      count: String(g.count),
      length: g.cuttingLengthMM != null ? String(Math.round(g.cuttingLengthMM)) : `${extent}${l.extentSuffix}`,
    });
  }
  for (const z of geometry.stirrupZones) {
    rows.push({
      mark: z.markId,
      element: l.stirrupWord,
      dia: String(Math.round(z.dia)),
      count: `${z.legs}L@${Math.round(z.spacing)}`,
      length: z.cuttingLengthMM != null ? String(Math.round(z.cuttingLengthMM)) : '\u2014',
    });
  }
  return rows;
}

// ── Chat-facing entry point (JSON payload) ──────────────────────────────
// Mirrors beamDiagram.mjs's own parseBeamRebarPayload contract exactly
// ({ok:true,type,geometry} / {ok:false,code,message}).
export function parseGradeBeamRebarPayload(raw) {
  try {
    const geometry = computeGradeBeamDiagramGeometry(raw);
    return { ok: true, type: 'gradeBeam', geometry };
  } catch (err) {
    if (err instanceof DiagramError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
}

// ── Chat-facing entry point (flat /diagram text) ────────────────────────
// Follows beamDiagram.mjs's own Step 23 convention: leading token +
// "key=value ..." shape, BAD_SYNTAX/UNSUPPORTED_TYPE split, never
// throws. Two leading tokens are accepted ("gradebeam" and "tiebeam") —
// this tool treats grade beam and tie beam as the SAME schematic
// product (a beam bearing continuously along its length / tying two
// foundations, drawn with the same bar-group + continuous soil-strip
// model either way), same synonym-acceptance precedent
// footingDiagram.mjs's own raft parser already sets for "raft"/"mat
// foundation" — one compute path, two accepted spellings, not two
// silently-diverging code paths a future session has to keep in sync.
//
// Unlike beamDiagram.mjs (which reuses beamAsciiToPayload.mjs's
// pre-existing group-indexed grammar), this module's ASCII grammar is
// written fresh below: the `sup{N}` group that grammar is built around
// is exactly the point-support concept this element doesn't have.
// `node{N}` replaces it; `bar{N}`/`stir{N}`/`sec{N}` are unchanged in
// shape from beamAsciiToPayload.mjs's own, on purpose, so a caller who
// already knows the beam grammar only has to learn one new prefix.
//
// Syntax:
//   /diagram gradebeam id=GB1 unit=mm totalLength=6000 b=300 h=500 cover=40
//     node1x=0 node1type=column node1label=C1
//     node2x=6000 node2type=column node2label=C2
//     bar1face=bottom bar1dia=16 bar1count=3 bar1startX=0 bar1endX=6000
//     stir1dia=8 stir1legs=2 stir1spacing=200 stir1startX=0 stir1endX=6000
//     [sec1x=... sec1label=...]
const TOP_LEVEL_STRING_FIELDS = new Set(['id', 'unit']);
const TOP_LEVEL_NUMBER_FIELDS = new Set(['b', 'h', 'cover', 'totalLength']);
const GROUP_FIELD_TYPES = {
  node: { x: 'number', label: 'string', type: 'string' },
  bar: {
    face: 'string', dia: 'number', count: 'number', layer: 'number',
    startX: 'number', endX: 'number', shapeCode: 'string',
    cuttingLengthMM: 'number', markId: 'string',
  },
  stir: {
    dia: 'number', legs: 'number', spacing: 'number', startX: 'number',
    endX: 'number', cuttingLengthMM: 'number', markId: 'string',
  },
  sec: { x: 'number', label: 'string' },
};
const GROUP_PREFIXES_BY_LENGTH = Object.keys(GROUP_FIELD_TYPES).sort((a, c) => c.length - a.length);
const TOKEN_RE = /^([a-zA-Z0-9]+)=(.*)$/;

function parseTokenKey(key) {
  if (TOP_LEVEL_STRING_FIELDS.has(key) || TOP_LEVEL_NUMBER_FIELDS.has(key)) {
    return { kind: 'top', field: key };
  }
  for (const prefix of GROUP_PREFIXES_BY_LENGTH) {
    if (key.length > prefix.length && key.startsWith(prefix) && /[0-9]/.test(key[prefix.length])) {
      const rest = key.slice(prefix.length);
      const m = rest.match(/^(\d+)([a-zA-Z]+)$/);
      if (!m) continue;
      const [, idxStr, field] = m;
      const fieldTypes = GROUP_FIELD_TYPES[prefix];
      if (!Object.prototype.hasOwnProperty.call(fieldTypes, field)) continue;
      return { kind: 'group', prefix, index: parseInt(idxStr, 10), field, type: fieldTypes[field] };
    }
  }
  return null;
}

function coerceNumber(rawValue) {
  const n = Number(rawValue);
  return Number.isFinite(n) ? n : null;
}

function parseGradeBeamAsciiCommand(text) {
  const trimmed = text.trim();
  if (trimmed.length === 0) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Empty command.' };
  }
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Looks like JSON, not key=value text.' };
  }

  const tokens = trimmed.split(/\s+/);
  const top = {};
  const groups = { node: new Map(), bar: new Map(), stir: new Map(), sec: new Map() };

  for (const token of tokens) {
    const m = token.match(TOKEN_RE);
    if (!m) {
      return { ok: false, code: 'BAD_SYNTAX', message: `Not a key=value token: "${token}".` };
    }
    const [, rawKey, rawValue] = m;
    if (rawValue === '') {
      return { ok: false, code: 'BAD_TOKEN', message: `"${rawKey}" has no value.` };
    }
    const parsed = parseTokenKey(rawKey);
    if (!parsed) {
      return { ok: false, code: 'BAD_TOKEN', message: `Unrecognized field "${rawKey}" in token "${token}".` };
    }

    if (parsed.kind === 'top') {
      if (TOP_LEVEL_NUMBER_FIELDS.has(parsed.field)) {
        const n = coerceNumber(rawValue);
        if (n === null) return { ok: false, code: 'BAD_TOKEN', message: `"${rawKey}" must be a number, got "${rawValue}".` };
        top[parsed.field] = n;
      } else {
        top[parsed.field] = rawValue;
      }
    } else {
      const { prefix, index, field, type } = parsed;
      if (!Number.isInteger(index) || index < 1) {
        return { ok: false, code: 'BAD_TOKEN', message: `Group index in "${rawKey}" must be >= 1.` };
      }
      let value;
      if (type === 'number') {
        value = coerceNumber(rawValue);
        if (value === null) return { ok: false, code: 'BAD_TOKEN', message: `"${rawKey}" must be a number, got "${rawValue}".` };
      } else {
        value = rawValue;
      }
      const bucket = groups[prefix];
      if (!bucket.has(index)) bucket.set(index, {});
      bucket.get(index)[field] = value;
    }
  }

  function groupArray(prefix) {
    const bucket = groups[prefix];
    return [...bucket.keys()].sort((a, c) => a - c).map((i) => bucket.get(i));
  }

  const payload = { ...top };
  if (top.b !== undefined || top.h !== undefined) {
    payload.section = { b: top.b, h: top.h };
    delete payload.b;
    delete payload.h;
  }
  const nodes = groupArray('node');
  const longitudinalBars = groupArray('bar');
  const stirrupZones = groupArray('stir');
  const sections = groupArray('sec');
  if (nodes.length > 0) payload.nodes = nodes;
  if (longitudinalBars.length > 0) payload.longitudinalBars = longitudinalBars;
  if (stirrupZones.length > 0) payload.stirrupZones = stirrupZones;
  if (sections.length > 0) payload.sections = sections;

  return { ok: true, payload };
}

export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  const m = trimmed.match(/^(\S+)\s+([\s\S]+)$/);
  if (!m) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: gradebeam key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  if (type !== 'gradebeam' && type !== 'tiebeam') {
    return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported here. Use gradebeam or tiebeam.` };
  }
  const ascii = parseGradeBeamAsciiCommand(m[2]);
  if (!ascii.ok) {
    return { ok: false, type, code: ascii.code, message: ascii.message };
  }
  // `type` below is deliberately overridden to the literal lower-cased
  // command token the caller typed ("gradebeam" or "tiebeam"), NOT left
  // as parseGradeBeamRebarPayload's own 'gradeBeam' (camelCase, JSON-
  // payload-entry-point convention — same split retainingWallDiagram.mjs
  // documents between its two entry points). This is what lets
  // DIAGRAM_TYPE_RENDERERS / DIAGRAM_TYPE_ERROR_MESSAGE in chat.js key
  // off the exact token echoed here, same as every sibling module.
  const result = parseGradeBeamRebarPayload(ascii.payload);
  if (!result.ok) {
    return { ok: false, type, code: result.code, message: result.message };
  }
  return { ...result, type };
}
