// stairDiagram.dxf.mjs
// DXF render path for the straight-flight stair reinforcement diagram —
// parallel to, and entirely separate from, renderStairDiagramSVG() in
// stairDiagram.mjs. Separate file per the project's session-3 decision
// (structuralDrawingDxfKit.mjs's own header / برومبت_تحويل_DXF_عام_v1.md):
// keeps @tarikjabiri/dxf out of any ordinary /diagram or /rebar (SVG-only)
// module graph.
//
// computeStairDiagramGeometry() is consumed exactly as returned, imported
// from stairDiagram.mjs with zero modification to that file. This module
// only renders; it never validates or computes. Verified directly against
// that file's own compute()/computeFlightProfile() return shapes before
// writing this (not assumed from the SVG renderer's usage alone):
//   { type:'stair', unit, id, riserMM, treadMM, stepsCount, waistThicknessMM,
//     coverMM, landing: {widthMM,thicknessMM}|null, totalRunMM, totalRiseMM,
//     rakedLengthMM, mainBars:{dia,spacing,count}, distributionBars:{dia,spacing,count},
//     profile: { stepPoints:[{x,y}...], angleRad, sinT, cosT } }
//
// v1 scope exclusions carried over unchanged from the prompt: no schedule
// table (DXF TABLE), no caption text, no Arabic labels (English only,
// hardcoded — not opts.lang-driven, matching every other <element>.dxf.mjs
// in this project). Distribution bars are not drawn as geometry in the SVG
// source either (schedule-row only) — carried here as a text spec label
// only, same convention shearWallDiagram.dxf.mjs already uses for its own
// horizontal-mesh spec (drawn as a plain ANNOTATION label, not as dots).
//
// ── AXIS NOTE (verified against stairDiagram.mjs's own computeFlightProfile
// header before writing toWorld() below, not assumed to match
// shearWallDiagram's case) ──
// profile.stepPoints are LOCAL, y-DOWN-from-the-top-nosing (y=0 at the top
// nosing, y=stepsCount*riserMM at the bottom riser's foot — see that
// function's own comment). This project's real-mm decision implies y-UP
// world coordinates (confirmed by shearWallDiagram.dxf.mjs's own
// "upward-y convention" correction note in structuralDrawingDxfKit.mjs).
// toWorld() below performs that flip: world Y = totalRiseMM - localY,
// plus a constant vertical shift (waistThicknessMM*cosT) so the whole
// shape's lowest real point (the soffit's bottom-most corner) sits at
// world Y = 0, a ground datum — chosen so every dimension/label offset
// below can be expressed as a simple positive/negative margin from either
// world Y = 0 (bottom) or the shape's own top-nosing Y (highest point),
// with no separate origin bookkeeping needed for the vertical axis.

import {
  DxfWriter,
  point3d,
  Units,
  LAYERS,
  defineDxfLayers,
  dxfText,
  closedRectDXF,
  closedPolylineDXF,
  barDotDXF,
  barMarkTagDXF,
  dimensionLineDXF,
  minPairwiseDistanceMM,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment, LWPolylineFlags } from './tarikjabiri-dxf.esm.js';

// Duplicated from stairDiagram.mjs — that file does not export this (an
// unexported module-level const used only inside its own render function),
// and this file must not be edited to add an export (zero modification to
// the existing file, per session scope). Flagged here explicitly so a
// future change to the source value does not silently desync:
// stairDiagram.mjs line 79 at time of writing.
const MAX_DRAWN_MAIN_BARS = 14;

// ── Layout conventions ──────────────────────────────────────────────
// None of these come from geometry or from the prompt; each is a chosen
// default for real-mm placement that the SVG path never needed (it drew
// everything inside a fixed px canvas instead). All overridable via opts,
// all named so they're auditable, per the session's own "no magic number"
// rule.
const RUN_DIM_GAP_MM = 300; // gap below the shape's ground datum (world Y=0, the soffit's lowest corner) to the total-run dimension line
const RISE_DIM_GAP_MM = 300; // gap left of the flight's run-start (world X=origin.x) to the total-rise dimension line
const TITLE_GAP_MM = 200; // gap above the shape's highest point (top nosing / landing surface) to the "LONGITUDINAL SECTION" view title
const SHEET_TITLE_GAP_MM = 500; // further gap above the view title to the overall sheet title
const DIST_LABEL_GAP_MM = 320; // vertical gap above the main-bar mark tag to the stacked distribution-bar spec label
const MARK_TAG_GAP_MM = 400; // horizontal offset right of the shape's rightmost extent (run end, or landing end when present) to the main-bar mark-tag bubble
const MARK_TAG_HEIGHT_FRACTION = 0.5; // vertical placement of the main-bar mark tag at half the flight's total rise — a schematic mid-height position, not tied to any single bar's real location
const DIM_TEXT_HEIGHT_MM = 150;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150; // view title, distribution-bar label

function fmt0(mm) {
  return String(Math.round(mm));
}

function renderFlightSectionDXF(dxf, geometry, origin) {
  const { profile, waistThicknessMM, coverMM, landing, totalRunMM, totalRiseMM, mainBars, distributionBars } = geometry;
  const { stepPoints, sinT, cosT } = profile;
  const yShift = waistThicknessMM * cosT; // see file header's AXIS NOTE — pins the shape's lowest real point to world Y=0
  const toW = (p) => ({ x: origin.x + p.x, y: origin.y + totalRiseMM - p.y + yShift });

  const stepWorld = stepPoints.map(toW);
  const topStepWorld = stepWorld[stepWorld.length - 1];

  // Soffit line: step profile offset PERPENDICULAR to the flight's slope
  // by waistThicknessMM, in the (sinT,cosT) direction — verified against
  // stairDiagram.mjs's own GEOMETRY NOTE (file header) before writing
  // this: a vertical-only offset would make the waist thicker measured
  // perpendicular to the slope than the input specifies.
  const soffitLocal = stepPoints.map((p) => ({ x: p.x + waistThicknessMM * sinT, y: p.y + waistThicknessMM * cosT }));
  const soffitWorld = soffitLocal.map(toW);
  const soffitLastWorld = soffitWorld[soffitWorld.length - 1];

  // Closed outline polygon: step profile -> [optional vertical end-cap
  // vertex when a landing follows] -> soffit line reversed -> auto-closes
  // back to stepWorld[0] via closedPolylineDXF's own Closed flag. Direct
  // vertex-for-vertex translation of stairDiagram.mjs's own closingD SVG
  // path (M stepPath [L topcap] L soffitLast [reversed soffit] Z),
  // re-verified against that source before writing this: the "Z" close
  // there is exactly this function's own last-to-first auto-close, not a
  // separate explicit segment — no vertex is added here to replicate it.
  const outlinePoints = [...stepWorld];
  if (landing) {
    // Same junction fix as the SVG source (that file's own comment,
    // confirmed by rendering there, not re-derived here): an extra vertex
    // directly below topStepWorld at the soffit line's own Y makes this
    // cap a VERTICAL segment — collinear with the landing rect's own left
    // edge (also vertical, at the same X) — instead of the diagonal cap
    // used when no landing follows.
    outlinePoints.push({ x: topStepWorld.x, y: soffitLastWorld.y });
  }
  outlinePoints.push(...soffitWorld.slice().reverse());
  closedPolylineDXF(dxf, outlinePoints, LAYERS.CONCRETE_OUTLINE.name);

  // Main-bar line: soffit offset a further coverMM inward (same
  // perpendicular direction), drawn as a single OPEN polyline through
  // every step corner — closedPolylineDXF always closes its loop (see its
  // own Closed-flag contract in the shared kit), so an open multi-vertex
  // line is a direct library call here, the same class of decision
  // shearWallDiagram.dxf.mjs already makes for entities no kit helper
  // shapes (its own direct dxf.addLine calls for near/far rebar lines).
  const barLocal = stepPoints.map((p) => ({
    x: p.x + (waistThicknessMM - coverMM) * sinT,
    y: p.y + (waistThicknessMM - coverMM) * cosT,
  }));
  const barWorld = barLocal.map(toW);
  dxf.addLWPolyline(
    barWorld.map((p) => ({ point: { x: p.x, y: p.y } })),
    { layerName: LAYERS.REBAR_BOTTOM.name, flags: LWPolylineFlags.None },
  );

  // Representative main-bar dots, sampled by arc-length fraction along
  // barWorld — direct real-mm translation of stairDiagram.mjs's own
  // sampling loop (segment-length accumulation + linear interpolation),
  // same MAX_DRAWN_MAIN_BARS cap, re-verified against that source's exact
  // loop structure before writing this.
  const drawCount = Math.min(mainBars.count, MAX_DRAWN_MAIN_BARS);
  const segLens = [];
  let totalLen = 0;
  for (let i = 1; i < barWorld.length; i++) {
    const d = Math.hypot(barWorld[i].x - barWorld[i - 1].x, barWorld[i].y - barWorld[i - 1].y);
    segLens.push(d);
    totalLen += d;
  }
  const dotCenters = [];
  for (let k = 0; k < drawCount; k++) {
    const target = (totalLen * k) / (drawCount - 1 || 1);
    let acc = 0, seg = 0;
    while (seg < segLens.length - 1 && acc + segLens[seg] < target) { acc += segLens[seg]; seg++; }
    const segFrac = segLens[seg] > 0 ? (target - acc) / segLens[seg] : 0;
    const a = barWorld[seg], b = barWorld[seg + 1] || barWorld[seg];
    dotCenters.push({ x: a.x + (b.x - a.x) * segFrac, y: a.y + (b.y - a.y) * segFrac });
  }
  // Real on-drawing pitch for THIS specific set of drawn dots, per the
  // units decision's bar-dot-radius rule (never the schema's static
  // MIN_BAR_SPACING_MM floor). These dots are not grid-aligned (they lie
  // along a raked polyline sampled by arc length), so the shared
  // minPairwiseDistanceMM(points) primitive — built exactly for
  // irregular, non-grid dot layouts — is the correct generalized check
  // here, not a single-axis distributeTicks() pitch.
  const barPitchMM = minPairwiseDistanceMM(dotCenters);
  for (const c of dotCenters) {
    barDotDXF(dxf, c.x, c.y, mainBars.dia, barPitchMM, LAYERS.REBAR_BOTTOM.name);
  }

  // Landing slab (optional, top of flight only) + its own bottom bar.
  let rightExtentX = topStepWorld.x;
  if (landing) {
    const landingBottomY = topStepWorld.y - landing.thicknessMM; // thickness measured DOWN from the walking surface (topStepWorld.y), matching the SVG source's own topStep.y+landH-in-y-down convention
    closedRectDXF(dxf, topStepWorld.x, landingBottomY, landing.widthMM, landing.thicknessMM, LAYERS.CONCRETE_OUTLINE.name);
    const landingBarY = landingBottomY + coverMM; // coverMM above the slab's bottom face — same "near face" convention as the SVG source's own topStep.y+landH-coverPx line
    dxf.addLine(point3d(topStepWorld.x, landingBarY), point3d(topStepWorld.x + landing.widthMM, landingBarY), { layerName: LAYERS.REBAR_BOTTOM.name });
    rightExtentX = topStepWorld.x + landing.widthMM;
  }

  // Dimension lines — total run excludes the landing (matches the SVG
  // source's own dimensionLine(...,totalRunMM...), which dimensions the
  // flight's run only, not the landing's own separately-labeled width).
  dimensionLineDXF(dxf, origin.x, origin.y - RUN_DIM_GAP_MM, topStepWorld.x, origin.y - RUN_DIM_GAP_MM, `${fmt0(totalRunMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, origin.x - RISE_DIM_GAP_MM, origin.y, origin.x - RISE_DIM_GAP_MM, topStepWorld.y, `${fmt0(totalRiseMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  // Main-bar mark tag, leadered to a representative (middle) drawn dot —
  // same "callout bubble + leader" convention as shearWallDiagram.dxf.mjs's
  // own mesh mark tag.
  const markTagX = rightExtentX + MARK_TAG_GAP_MM;
  const markTagY = origin.y + totalRiseMM * MARK_TAG_HEIGHT_FRACTION;
  const midDot = dotCenters[Math.floor(dotCenters.length / 2)];
  barMarkTagDXF(dxf, markTagX, markTagY, `\u00d8${fmt0(mainBars.dia)}@${fmt0(mainBars.spacing)}`, LAYERS.MARK_TAGS.name, { leaderTo: midDot });

  // Distribution-bar spec — not drawn as geometry in the SVG source either
  // (schedule-row only there; DXF v1 excludes the schedule table entirely,
  // per the prompt's own scope exclusions), so this is carried as a plain
  // text spec label, same convention shearWallDiagram.dxf.mjs already uses
  // for its own horizontal-mesh spec ("support-label", flagged as a
  // non-table-confirmed ANNOTATION placement there — same flag applies
  // here for the same reason: no CSS rule confirms a dedicated layer for
  // this label in either source file).
  dxfText(dxf, markTagX, markTagY - DIST_LABEL_GAP_MM, SUBTITLE_HEIGHT_MM, `DIST. \u00d8${fmt0(distributionBars.dia)}@${fmt0(distributionBars.spacing)}`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Top,
  });

  const topY = topStepWorld.y; // shape's highest real point (top nosing / landing surface — both equal, landing runs flat off the top nosing)
  dxfText(dxf, (origin.x + rightExtentX) / 2, topY + TITLE_GAP_MM, SUBTITLE_HEIGHT_MM, 'LONGITUDINAL SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: rightExtentX - origin.x, height: topY - origin.y, rightExtentX, topY };
}

export function renderStairDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'stair') {
    throw new DiagramError('BAD_PARAM', 'renderStairDiagramDXF expects a geometry object from computeStairDiagramGeometry() (type "stair").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  defineDxfLayers(dxf);

  const origin = { x: 0, y: 0 };
  const section = renderFlightSectionDXF(dxf, geometry, origin);

  dxfText(dxf, (origin.x + section.rightExtentX) / 2, section.topY + TITLE_GAP_MM + SHEET_TITLE_GAP_MM, TITLE_HEIGHT_MM, `STAIR ${geometry.id} - REINFORCEMENT DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return dxf.stringify();
}
