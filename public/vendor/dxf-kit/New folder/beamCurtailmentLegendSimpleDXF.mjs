// beamCurtailmentLegendSimpleDXF.mjs
//
// DXF counterpart to beamCurtailmentLegendSimple.mjs. That file embeds
// the source PDF's own vector artwork verbatim (glyph curves and all) --
// not attempted here: DXF has no equivalent to SVG's arbitrary <path>
// curve embedding as a single compact primitive, and re-deriving every
// glyph outline as DXF entities would trade "exact replica" for a
// pointless pile of unmaintainable polylines. Curly braces (the source
// figure's own bracket style) also aren't a standard DXF/CAD entity.
//
// Instead: rebuilt as native DXF dimension-line entities -- straight
// lines with tick marks and a text label, using this file's own already-
// imported dimensionLineDXF/dxfText -- because that IS the idiomatic CAD
// convention for "this is the length of this piece", and every other
// length in this same file (bar extents, stirrup zones, overall span) is
// already drawn that way. A literal curly-brace reproduction would be
// LESS consistent with a DXF deliverable, not more faithful to one.
//
// English labels only: beamDiagram.dxf.mjs's own header states its v1
// scope is "no Arabic labels (English only, hardcoded, not
// opts.lang-driven)" -- honored here rather than silently violated by a
// new element pulling Arabic text back in through a side door.
//
// SYMBOLIC, NOT TO SCALE: same as the SVG counterpart -- "a"/"b"/"e" are
// code-table formula names (a = min 0.15Ln, b = max 0.10Ln, e = bigger of
// 12(dia) or 25cm; ECP 2001 p.51), not lengths measured from any real
// beam. The proportions below (each zone as a fraction of a chosen
// illustrative reference width) are a reasonable visual approximation of
// the source figure's own layout, not a pixel-measured reproduction --
// there is nothing to measure, the source itself draws this schematically.
// Scope: simple beam, vertical loads only (see the source figure's own
// caption) -- not universal to every beam this module can draw.

import { dimensionLineDXF, dxfText, LAYERS, DiagramError } from './structuralDrawingDxfKit.mjs';
import { TextHorizontalAlignment, TextVerticalAlignment } from './tarikjabiri-dxf.esm.js';

const REFERENCE_WIDTH_MM = 6000; // illustrative span only, matches this kit's typical beam scale
const ROW_GAP_MM = 350;
const TITLE_HEIGHT_MM = 150;
const DIM_TEXT_HEIGHT_MM = 130;

/**
 * Draws the legend into an existing DxfWriter, anchored at (x, y) with
 * (x, y) as the TOP-LEFT of the block (DXF Y increases upward, so all
 * rows are drawn at y and below).
 * @param {object} dxf - a DxfWriter already created by the caller.
 * @param {{x?: number, y?: number, width?: number}} opts
 * @returns {{width: number, height: number}} the block's own footprint,
 *   so the caller can reserve space / position a title above it.
 */
export function addCurtailmentLegendSimpleDXF(dxf, { x = 0, y = 0, width = REFERENCE_WIDTH_MM } = {}) {
  if (!dxf) throw new DiagramError('BAD_PARAM', 'addCurtailmentLegendSimpleDXF requires an existing DxfWriter.');
  const aW = width * 0.15;
  const rows = [
    { y0: 0, segs: [[0, aW, 'a'], [width - aW, width, 'a']] },
    { y0: -ROW_GAP_MM, segs: [[width * 0.12, width * 0.88, 'Top steel - through piece']] },
    { y0: -ROW_GAP_MM * 2, segs: [[width * 0.08, width * 0.92, 'Bottom steel >= 2/3 As']] },
    { y0: -ROW_GAP_MM * 3, segs: [[width * 0.25, width * 0.75, 'Bottom steel <= 1/3 As']] },
  ];

  dxfText(dxf, x + width / 2, y + ROW_GAP_MM * 0.6, TITLE_HEIGHT_MM,
    'Curtailment convention, simple beam under vertical loads only, ECP 2001 p.51', {
      layerName: LAYERS.ANNOTATION.name, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom,
    });

  for (const row of rows) {
    for (const [sx, ex, label] of row.segs) {
      dimensionLineDXF(dxf, x + sx, y + row.y0, x + ex, y + row.y0, label, {
        orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM,
      });
    }
  }
  // "e" — minimum stagger/lap between the end piece (a) and the through
  // piece, drawn as its own small dimension near the left transition,
  // matching the source figure's own placement.
  const eStart = width * 0.12;
  const eEnd = eStart + width * 0.08;
  dimensionLineDXF(dxf, x + eStart, y - ROW_GAP_MM * 1.5, x + eEnd, y - ROW_GAP_MM * 1.5, 'e', {
    orientation: 'h', textHeightMM: DIM_TEXT_HEIGHT_MM,
  });

  const height = ROW_GAP_MM * 3.6;
  return { width, height };
}
