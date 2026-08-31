// flatSlabDropPanelDiagram.dxf.mjs
// DXF render path for the flat-slab drop-panel / column-capital detail —
// parallel to, and entirely separate from,
// renderFlatSlabDropPanelDiagramSVG() in flatSlabDropPanelDiagram.mjs.
// Same placement rationale as every sibling *.dxf.mjs: an ordinary
// /diagram or /rebar SVG request must never pull @tarikjabiri/dxf into
// the Worker's module graph — only a real DXF-export request does.
//
// computeFlatSlabDropPanelDiagramGeometry() is consumed exactly as
// returned — zero modification to flatSlabDropPanelDiagram.mjs, zero
// re-derivation of any value it already provides.
//
// SCOPE DECISION — TRUE SCALE, not the SVG source's own vertical
// exaggeration: renderSectionView (verified directly in the source, its
// own comment block above `sectionSpanMM`/`hScale`/`vScale`) uses
// INDEPENDENT horizontal and vertical px scales on purpose, because a
// real drop panel/capital is extremely flat in true proportion and a
// single shared px scale made every vertical dimension label illegible
// in that SVG's own fixed-canvas cairosvg testing. That reasoning is
// specific to a fixed-pixel raster canvas — it does not apply here.
// Master-prompt decision #1 (final, not reopened per element) already
// settled this globally: DXF model-space geometry is always real,
// un-scaled mm; legibility at a flat/thin true proportion is a
// plot-scale/viewport concern for whoever opens the file in AutoCAD, not
// something this render function should distort the model to solve. The
// SVG source's own `l.vScaleNote` ("vertical scale exaggerated for
// clarity") is therefore NOT ported — stating it here would be false
// (nothing is exaggerated) rather than merely omitted.
//
// v1 scope exclusions carried over unchanged from the master prompt: no
// Arabic labels (English only, hardcoded, not opts.lang-driven), no
// HATCH (v1-excluded everywhere), no scheduleTable-as-DXF-TABLE (every
// row that table would have shown is still real, individually placed
// geometry/dimension callouts on the two views themselves).
//
// New-for-this-element decisions, disclosed per the master prompt's own
// protocol:
//   - CRITICAL-PERIMETER layer added to the shared kit (see that file's
//     own diff comment) — this element's `crit-line` is the first user
//     of it. Hex taken from the master table's own already-"\u0645\u0648\u062d\u0651\u062f"
//     (unified) value (#b23b3b), not this file's own literal
//     `.crit-line{stroke:#b8860b}` — see the kit's own comment for why.
//   - `.break-line` (the column-stub's drafting break zigzag) has no
//     dedicated kit primitive (it is a short, one-off open polyline, not
//     a closed shape closedPolylineDXF covers, and not a reusable
//     structural-drafting symbol on the order of a stirrup/tie tick) —
//     drawn here as a sequence of plain `dxf.addLine` segments, kept
//     local to this file rather than speculatively promoted to the
//     shared kit for a still-single caller. Verified color match: the
//     SVG source's own `.break-line{stroke:#1a1a1a}` is CONCRETE-
//     OUTLINE's exact hex, so it is drawn on that existing layer, not a
//     new one.
//   - `.zone-label` (critical-perimeter caption, "Column continues
//     below" stub label) IS actually used in this element (unlike
//     beamDiagram.mjs, where the same class name was dead CSS) and its
//     own hex (`fill:#8a6d00`, verified directly) is an EXACT match for
//     the already-established ZONE_LABEL layer — used as-is, no new
//     layer.
//   - `sheet-caption` (column-size caption, extra-top-bars caption) and
//     `panel-title` (sheet title) are both already-covered by the master
//     table's own ANNOTATION row ("sheet-title, sheet-caption,
//     view-title, ... every local *-title").
//   - No REBAR-TOP/REBAR-BOTTOM/STIRRUP-TIE entities exist anywhere in
//     this element (verified against the SCOPE note at the top of the
//     source file: extraTopBars is drawn as ONE aggregate mark tag, not
//     a laid-out bar grid — no barDot/stirrupTick call exists anywhere
//     in flatSlabDropPanelDiagram.mjs). This module therefore has no
//     bar-circle collision surface to check — noted explicitly in this
//     file's own test, not silently skipped.

import {
  DxfWriter,
  point3d,
  Units,
  LAYERS,
  defineDxfLayers,
  defineDashedLType,
  DASHED_LTYPE_NAME,
  dxfText,
  closedRectDXF,
  closedPolylineDXF,
  barMarkTagDXF,
  MARK_TAG_RADIUS_MM,
  dimensionLineDXF,
  DiagramError,
} from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

// Layout conventions — none of these come from geometry or from the SVG
// source (which drew everything inside a fixed pixel canvas instead);
// each is a chosen default for real-mm placement, named so it's
// auditable, matching every sibling *.dxf.mjs's own convention.
const MARGIN_MM = 300;
const VIEW_GAP_MM = 1000;
const TITLE_HEIGHT_MM = 220;
const SUBTITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 150;
const CAPTION_HEIGHT_MM = 115;
const STUB_LENGTH_MM = 400; // un-dimensioned column-stub length below the panel/capital, ending in a drafting break line — the SVG source's own analogous STUB_PX(90) has no fixed physical meaning to convert (see this element's own "no column elevation" scope note); chosen as a fixed schematic real-mm value, same "named convention default" pattern as this kit's own TICK_CAP_MM
const BREAK_ZIGZAG_HALF_HEIGHT_MM = 60; // vertical amplitude of the break-line zigzag teeth — real-mm analogue of the SVG source's own 8px zigzag amplitude
const SECTION_FIELD_FACTOR = 1.6; // how far past the panel/capital footprint the section view shows field slab on either side — same real geometric ratio the SVG source's own sectionSpanMM=footprintW*1.6 already chose (a genuine layout ratio, not a px-scale artifact, so kept unchanged)

function fmt0(mm) {
  return String(Math.round(mm));
}

// Short, explicitly un-dimensioned column shaft ending in a zig-zag
// drafting break line — see this element's own "no column elevation"
// scope note. No dimensionLineDXF call anywhere near this shape, on
// purpose (an un-dimensioned stub must never carry an implied length).
function renderColumnStubDXF(dxf, cx, widthMM, topY) {
  const half = widthMM / 2;
  const bottomY = topY - STUB_LENGTH_MM;
  const breakY = bottomY + BREAK_ZIGZAG_HALF_HEIGHT_MM * 0.35; // near the stub's own lower end, same relative position as the SVG source's own breakY = bottomY-14 (14px above a 90px-tall stub)
  closedRectDXF(dxf, cx - half, bottomY, widthMM, topY - bottomY, LAYERS.CONCRETE_OUTLINE.name);

  // Zig-zag: five short diagonal segments across the stub's own width,
  // alternating +/- BREAK_ZIGZAG_HALF_HEIGHT_MM — direct real-mm
  // translation of the SVG source's own
  // `M x y l w*0.2 8 l w*0.2 -16 l w*0.2 8 l w*0.2 -16 l w*0.2 8` path
  // (five relative segments, alternating +8/-16/+8/-16/+8 — net +0,
  // reproduced here as an explicit absolute point sequence instead of a
  // relative path string, since dxf.addLine takes absolute points).
  const step = widthMM * 0.2;
  const amp = BREAK_ZIGZAG_HALF_HEIGHT_MM;
  const xs = [cx - half, cx - half + step, cx - half + 2 * step, cx - half + 3 * step, cx - half + 4 * step, cx - half + 5 * step];
  const ys = [breakY, breakY + amp * 0.5, breakY - amp, breakY + amp * 0.5, breakY - amp, breakY + amp * 0.5];
  for (let i = 0; i < xs.length - 1; i++) {
    dxf.addLine(point3d(xs[i], ys[i]), point3d(xs[i + 1], ys[i + 1]), { layerName: LAYERS.CONCRETE_OUTLINE.name });
  }

  dxfText(dxf, cx + half + MARGIN_MM * 0.3, (topY + bottomY) / 2, SUBTITLE_HEIGHT_MM, 'Column continues below', {
    layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Middle,
  });

  return { bottom: bottomY };
}

// Plan view: footprint (panel or capital-top) and column both centered
// on one shared origin (verified against the SVG source: both are drawn
// centered on the same box center, i.e. the same real-world point) —
// origin.x/origin.y here IS that shared center, unlike this element's
// own section view (which uses a baseline-anchored origin instead, see
// below) since a plan view has no natural "bottom" the way a vertical
// section does.
function renderPlanViewDXF(dxf, geometry, origin, opts) {
  const { x: cx, y: cy } = origin;
  const footprintW = geometry.capitalType === 'dropPanel' ? geometry.dropPanel.panelWidthMM : geometry.capital.capitalTopWidthMM;
  const footprintL = geometry.capitalType === 'dropPanel' ? geometry.dropPanel.panelLengthMM : geometry.capital.capitalTopDepthMM;
  const critOff = geometry.criticalPerimeterOffsetMM;

  const sx = cx - footprintW / 2, sy = cy - footprintL / 2;

  let bottomY = sy;
  if (critOff != null) {
    closedRectDXF(dxf, sx - critOff, sy - critOff, footprintW + 2 * critOff, footprintL + 2 * critOff, LAYERS.CRITICAL_PERIMETER.name, { lineType: DASHED_LTYPE_NAME });
    dxfText(dxf, sx - critOff, sy - critOff - MARGIN_MM * 0.2, SUBTITLE_HEIGHT_MM * 0.8, 'Critical section reference, offset from panel/capital edge', {
      layerName: LAYERS.ZONE_LABEL.name, hAlign: TextHorizontalAlignment.Left, vAlign: TextVerticalAlignment.Bottom,
    });
    bottomY = sy - critOff;
  }

  closedRectDXF(dxf, sx, sy, footprintW, footprintL, LAYERS.CONCRETE_OUTLINE.name);
  closedRectDXF(dxf, cx - geometry.columnWidthMM / 2, cy - geometry.columnDepthMM / 2, geometry.columnWidthMM, geometry.columnDepthMM, LAYERS.CONCRETE_OUTLINE.name);

  dimensionLineDXF(dxf, sx, sy - MARGIN_MM * 0.6, sx + footprintW, sy - MARGIN_MM * 0.6, `${fmt0(footprintW)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });
  dimensionLineDXF(dxf, sx - MARGIN_MM * 0.6, sy, sx - MARGIN_MM * 0.6, sy + footprintL, `${fmt0(footprintL)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });

  const colCaptionY = bottomY - MARGIN_MM * 1.6;
  dxfText(dxf, cx, colCaptionY, SUBTITLE_HEIGHT_MM, `Column ${fmt0(geometry.columnWidthMM)}x${fmt0(geometry.columnDepthMM)}`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  if (geometry.extraTopBars) {
    const tagX = sx + footprintW + MARGIN_MM * 0.9;
    const tagY = sy + footprintL - MARGIN_MM * 0.3;
    const r = MARK_TAG_RADIUS_MM * 1.3; // wider than this kit's own default — this element's own mark string can run up to "40x40" (two-digit count AND two-digit diameter), matching the SVG source's own r:19 vs its usual r:9/11 precedent
    barMarkTagDXF(dxf, tagX, tagY, `${geometry.extraTopBars.count}\u00d8${fmt0(geometry.extraTopBars.dia)}`, LAYERS.MARK_TAGS.name, { r });
    dxfText(dxf, tagX, tagY - r - MARGIN_MM * 0.3, SUBTITLE_HEIGHT_MM, 'Extra Top Bars', {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
    });
  }

  dxfText(dxf, cx, sy + footprintL + MARGIN_MM * 0.5, SUBTITLE_HEIGHT_MM, 'PLAN', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return {
    width: footprintW + (critOff != null ? 2 * critOff : 0),
    top: sy + footprintL + MARGIN_MM * 0.5 + SUBTITLE_HEIGHT_MM,
    bottom: colCaptionY - SUBTITLE_HEIGHT_MM,
  };
}

// Section view, TRUE scale (see this file's own header note). origin.y
// is the FIELD slab's own soffit (the physical elevation shared by both
// the dropPanel and capital branches — the panel projects below it, the
// capital flares up to it) — everything else derived from that one
// baseline, same "one fixed shared reference, never re-derived per
// branch" discipline every sibling section view already applies.
function renderSectionViewDXF(dxf, geometry, origin, opts) {
  const { x: cx, y: fieldSoffitY } = origin;
  const footprintW = geometry.capitalType === 'dropPanel' ? geometry.dropPanel.panelWidthMM : geometry.capital.capitalTopWidthMM;
  const spanMM = footprintW * SECTION_FIELD_FACTOR;
  const x0 = cx - spanMM / 2;
  const slabTopY = fieldSoffitY + geometry.slabThicknessMM;
  const rightDimX = x0 + spanMM + MARGIN_MM * 0.4;

  let stubTop;
  let bottom;
  if (geometry.capitalType === 'dropPanel') {
    const { panelWidthMM, dropDepthMM, totalDepthMM } = geometry.dropPanel;
    const panelLeft = cx - panelWidthMM / 2, panelRight = cx + panelWidthMM / 2;
    const panelBottomY = fieldSoffitY - dropDepthMM;

    closedPolylineDXF(dxf, [
      { x: x0, y: slabTopY },
      { x: x0 + spanMM, y: slabTopY },
      { x: x0 + spanMM, y: fieldSoffitY },
      { x: panelRight, y: fieldSoffitY },
      { x: panelRight, y: panelBottomY },
      { x: panelLeft, y: panelBottomY },
      { x: panelLeft, y: fieldSoffitY },
      { x: x0, y: fieldSoffitY },
    ], LAYERS.CONCRETE_OUTLINE.name);

    dimensionLineDXF(dxf, x0 - MARGIN_MM * 0.6, slabTopY, x0 - MARGIN_MM * 0.6, fieldSoffitY, `${fmt0(geometry.slabThicknessMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
    dimensionLineDXF(dxf, rightDimX, slabTopY, rightDimX, panelBottomY, `${fmt0(totalDepthMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
    dimensionLineDXF(dxf, panelLeft, panelBottomY - MARGIN_MM * 0.6, panelRight, panelBottomY - MARGIN_MM * 0.6, `${fmt0(panelWidthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

    stubTop = panelBottomY;
    bottom = panelBottomY - MARGIN_MM * 1.2;
  } else {
    const { capitalTopWidthMM, capitalHeightMM } = geometry.capital;
    const capLeft = cx - capitalTopWidthMM / 2, capRight = cx + capitalTopWidthMM / 2;
    const colHalf = geometry.columnWidthMM / 2;
    const columnTopY = fieldSoffitY - capitalHeightMM;

    closedRectDXF(dxf, x0, fieldSoffitY, spanMM, geometry.slabThicknessMM, LAYERS.CONCRETE_OUTLINE.name);
    closedPolylineDXF(dxf, [
      { x: cx - colHalf, y: columnTopY },
      { x: cx + colHalf, y: columnTopY },
      { x: capRight, y: fieldSoffitY },
      { x: capLeft, y: fieldSoffitY },
    ], LAYERS.CONCRETE_OUTLINE.name);

    dimensionLineDXF(dxf, x0 - MARGIN_MM * 0.6, slabTopY, x0 - MARGIN_MM * 0.6, fieldSoffitY, `${fmt0(geometry.slabThicknessMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
    dimensionLineDXF(dxf, rightDimX, fieldSoffitY, rightDimX, columnTopY, `${fmt0(capitalHeightMM)}mm`, { orientation: 'v', textHeightMM: DIM_TEXT_HEIGHT_MM });
    dimensionLineDXF(dxf, capLeft, slabTopY + MARGIN_MM * 0.6, capRight, slabTopY + MARGIN_MM * 0.6, `${fmt0(capitalTopWidthMM)}mm`, { orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM });

    stubTop = columnTopY;
    bottom = columnTopY - STUB_LENGTH_MM - MARGIN_MM * 0.6;
  }

  const stub = renderColumnStubDXF(dxf, cx, geometry.columnWidthMM, stubTop);
  bottom = Math.min(bottom, stub.bottom - MARGIN_MM * 0.3);

  const titleY = slabTopY + MARGIN_MM * 0.8;
  dxfText(dxf, cx, titleY, SUBTITLE_HEIGHT_MM, 'SECTION', {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  return { width: spanMM, top: titleY + SUBTITLE_HEIGHT_MM, bottom };
}

export function renderFlatSlabDropPanelDiagramDXF(geometry, opts = {}) {
  if (!geometry || geometry.type !== 'dropCapital') {
    throw new DiagramError('BAD_PARAM', 'renderFlatSlabDropPanelDiagramDXF expects a geometry object from computeFlatSlabDropPanelDiagramGeometry() (type "dropCapital").');
  }

  const dxf = new DxfWriter();
  dxf.setUnits(Units.Millimeters);
  // MUST precede defineDxfLayers()/any entity referencing
  // DASHED_LTYPE_NAME — see structuralDrawingDxfKit.mjs's own header on
  // DxfLayerTable.addLayer()'s silent-Continuous-fallback behavior for an
  // unregistered linetype name.
  defineDashedLType(dxf);
  defineDxfLayers(dxf);

  // Stacked bottom-to-top in DXF model space: SECTION lowest, PLAN
  // above it — reproducing the SVG source's own side-by-side reading
  // order (PLAN left, SECTION right, both at the same visual "row") as
  // a top-to-bottom stack instead, same "first-drawn-in-SVG reads first"
  // convention every other stacked-view sibling *.dxf.mjs already uses,
  // applied here to the SVG's own left-to-right order rather than a
  // top-to-bottom one (this element's SVG source has no natural
  // vertical reading order between its two views to preserve — PLAN_BOX
  // and SECTION_BOX share the same y in that source).
  const section = renderSectionViewDXF(dxf, geometry, { x: 0, y: 0 }, opts);

  const planCenterY = section.top + (opts.viewGapMM ?? VIEW_GAP_MM);
  const plan = renderPlanViewDXF(dxf, geometry, { x: 0, y: planCenterY }, opts);

  const overallWidth = Math.max(plan.width, section.width);
  const titleY = plan.top + MARGIN_MM * 2.2;
  dxfText(dxf, 0, titleY, TITLE_HEIGHT_MM, `FLAT SLAB DROP PANEL / COLUMN CAPITAL ${geometry.id} - DETAIL`, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
  });

  const captionY = section.bottom - MARGIN_MM * 1.3;
  const captionText = 'Schematic drop panel / column capital detail generated from the supplied data \u2014 geometry only, verify every dimension against your own design (ACI 318-19 \u00a78.2.4 drop panel provisions, \u00a722.6.4.1 capital critical-section provisions) before issuing for construction. This drawing does not compute or verify punching-shear capacity, minimum drop-panel extent versus span, or critical-section adequacy \u2014 cross-check against the separate punching-shear diagram for the same column. Extra top bar lengths, where shown, are not computed here. The section view is drawn at true scale (not vertically exaggerated, unlike the reference SVG rendering).';
  dxfText(dxf, 0, captionY, CAPTION_HEIGHT_MM, captionText, {
    layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Top,
  });

  return dxf.stringify();
}
