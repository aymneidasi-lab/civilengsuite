// functions/_lib/computedFootingDiagram.mjs
//
// RENAMED from a draft that carried the header
// "functions/_lib/footingDiagram.mjs" verbatim — the same path
// footingDiagram.mjs itself claims. Two independent modules asserting the
// same canonical path is not a cosmetic mistake: it is why this module was
// never imported into chat.js (an import from '../_lib/footingDiagram.mjs'
// resolves to the OTHER file, the symbolic-only one — see that file's own
// header) and therefore never reachable from a live request despite being
// functionally complete and tested. Fixed by giving this module its own
// real name and its own import path.
//
// Deterministic, zero-AI, zero-neuron-cost SVG generator for footing
// schematics. This is the complement to imageGen.mjs's /image path, not
// a replacement for it: /image produces a loose artistic illustration
// from a diffusion model and is explicitly NOT to scale (see that file's
// header). This module produces a drawing computed directly from the
// numbers the user supplies — every dimension, bar count, and bar
// position in the output is arithmetic on the input, not a model's guess
// — so it is the correct tool whenever the user needs the picture to
// actually match specific numbers, and the wrong tool whenever they want
// a quick conceptual/artistic image (it will not draw anything for
// which it wasn't given explicit numeric parameters).
//
// Column/view/caption product-identity strings come from footingLabels.mjs,
// shared with footingDiagram.mjs — see that file's header for why (it is
// the direct fix for a live "col1"/"col2" label leak: this module used to
// print its own internal column identifiers straight to the drawing
// instead of "COLUMN A"/"COLUMN B" — عمود أ/عمود ب, because it had no
// shared vocabulary with the other renderer to draw from).
//
// SCOPE: 'isolated' (single-column spread footing) and 'combined'
// (two-column footing) types only. Strip and raft footings are
// architecturally supportable by the same
// compute*Geometry -> renderFootingDiagramSVG pipeline (see
// computeSectionGeometry, which both implemented types already share)
// but are not implemented — calling with an unknown type throws
// DiagramError('UNSUPPORTED_TYPE', ...) rather than silently drawing the
// wrong thing.
//
// This is a schematic, not a shop/construction drawing. Reinforcement is
// shown as one representative bottom-mesh layer only — no top steel, no
// hooks, no dowels, no development-length extensions, no stirrups/ties.
// Column-to-footing dowelling is not shown. renderFootingDiagramSVG()
// always appends a fixed caption saying so; treat that caption as load-
// bearing UX, not decoration — see appendBotDiagramBubble() in the
// footing_pro/pc_suite integration notes for why it must never be
// stripped out by a caller.

import { FOOTING_LABELS, sectionThroughLabel } from './footingLabels.mjs';

export class DiagramError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DiagramError';
    this.code = code;
  }
}

const MM_PER_UNIT = { mm: 1, cm: 10, m: 1000 };

function toMm(value, unit) {
  const factor = MM_PER_UNIT[unit];
  if (!factor) {
    throw new DiagramError('BAD_UNIT', `Unknown unit "${unit}" — expected one of: ${Object.keys(MM_PER_UNIT).join(', ')}.`);
  }
  return value * factor;
}

function fromMm(mm, unit) {
  return mm / MM_PER_UNIT[unit];
}

function assertFinitePositive(name, value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new DiagramError('BAD_PARAM', `"${name}" must be a positive finite number, got ${JSON.stringify(value)}.`);
  }
}

function fmt(mmValue, unit, decimals = 0) {
  const v = fromMm(mmValue, unit);
  return `${v.toFixed(decimals)}${unit}`;
}

// ── Shared section-view geometry ────────────────────────────────────────
// Used identically by isolated (its only column) and combined (through
// whichever column sectionThrough selects) — see file header. widthMM is
// the in-plan dimension visible in this cut (the short axis for
// isolated; B for combined, since combined assumes constant width along
// its length — documented in computeCombinedFootingGeometry).
//
// Bar centers are distributed evenly across the cover-to-cover envelope
// rather than laid out at exactly the nominal input spacing starting
// from one edge — standard even-distribution simplification for a
// schematic. actualSpacingMM (the spacing this distribution actually
// produced) is returned alongside nominalSpacingMM specifically so the
// rendered label never claims a spacing value that doesn't match what
// is actually drawn — every number on this drawing must be independently
// verifiable against the geometry, unlike the AI-illustration path.
function computeSectionGeometry({ widthMM, depthMM, colWidthMM, coverMM, diaMM, nominalSpacingMM }) {
  assertFinitePositive('width', widthMM);
  assertFinitePositive('depth', depthMM);
  assertFinitePositive('column width', colWidthMM);
  assertFinitePositive('cover', coverMM);
  assertFinitePositive('bar diameter', diaMM);
  assertFinitePositive('bar spacing', nominalSpacingMM);

  if (colWidthMM >= widthMM) {
    throw new DiagramError('COLUMN_TOO_WIDE', `Column width (${colWidthMM}mm) must be smaller than the footing width it sits on (${widthMM}mm).`);
  }
  const envelope = widthMM - 2 * coverMM - diaMM;
  if (envelope <= 0) {
    throw new DiagramError('NO_ROOM_FOR_BARS', `Cover (${coverMM}mm) and bar diameter (${diaMM}mm) leave no room for reinforcement across a ${widthMM}mm width.`);
  }
  const rawCount = Math.floor(envelope / nominalSpacingMM) + 1;
  const barCount = Math.max(2, rawCount); // a "mesh" with 1 bar isn't a mesh; floor at 2
  const firstCenterMM = coverMM + diaMM / 2;
  const lastCenterMM = widthMM - coverMM - diaMM / 2;
  const actualSpacingMM = barCount > 1 ? (lastCenterMM - firstCenterMM) / (barCount - 1) : 0;
  const barCentersMM = Array.from({ length: barCount }, (_, i) =>
    barCount === 1 ? widthMM / 2 : firstCenterMM + i * actualSpacingMM
  );

  return {
    widthMM, depthMM, colWidthMM, coverMM, diaMM,
    nominalSpacingMM, actualSpacingMM, barCount, barCentersMM,
  };
}

// ── Isolated (single-column spread) footing ─────────────────────────────
// rawParams (all lengths in `unit`, default 'mm'):
//   B, L, D            footing plan width, plan length, depth
//   colB, colL         column cross-section (plan)
//   cover              concrete cover to reinforcement
//   dia                bar diameter
//   spacing            nominal bar spacing, both directions (isotropic
//                      default — pass spacingLong/spacingShort to override
//                      either direction independently)
//   unit               'mm' | 'cm' | 'm', default 'mm'
export function computeIsolatedFootingGeometry(rawParams) {
  const unit = rawParams.unit || 'mm';
  const B = toMm(rawParams.B, unit);
  const L = toMm(rawParams.L, unit);
  const D = toMm(rawParams.D, unit);
  const colB = toMm(rawParams.colB, unit);
  const colL = toMm(rawParams.colL, unit);
  const cover = toMm(rawParams.cover, unit);
  const dia = toMm(rawParams.dia, unit);
  const spacingLong = toMm(rawParams.spacingLong ?? rawParams.spacing, unit);
  const spacingShort = toMm(rawParams.spacingShort ?? rawParams.spacing, unit);

  for (const [name, v] of Object.entries({ B, L, D, colB, colL, cover, dia, spacingLong, spacingShort })) {
    assertFinitePositive(name, v);
  }
  if (colB >= B) throw new DiagramError('COLUMN_TOO_WIDE', `colB (${colB}mm) must be smaller than B (${B}mm).`);
  if (colL >= L) throw new DiagramError('COLUMN_TOO_WIDE', `colL (${colL}mm) must be smaller than L (${L}mm).`);

  // Draw the LONGER plan dimension horizontally regardless of whether the
  // caller called it B or L — makes near-square footings render sensibly
  // and elongated ones render legibly instead of tall-and-narrow. Track
  // the original name so dimension labels stay attached to the value the
  // user actually gave.
  const bIsShort = B <= L;
  const shortLabel = bIsShort ? 'B' : 'L';
  const longLabel = bIsShort ? 'L' : 'B';
  const shortMM = bIsShort ? B : L;
  const longMM = bIsShort ? L : B;
  const colShortMM = bIsShort ? colB : colL;
  const colLongMM = bIsShort ? colL : colB;

  const section = computeSectionGeometry({
    widthMM: shortMM, depthMM: D, colWidthMM: colShortMM,
    coverMM: cover, diaMM: dia, nominalSpacingMM: spacingShort,
  });

  return {
    type: 'isolated',
    unit,
    plan: {
      longLabel, shortLabel, longMM, shortMM,
      columns: [{ alongLongMM: colLongMM, alongShortMM: colShortMM, centerLongMM: longMM / 2 }],
    },
    section,
    meta: { B, L, D, colB, colL, cover, dia, spacingLong, spacingShort },
  };
}

// ── Combined (two-column) footing ───────────────────────────────────────
// rawParams (all lengths in `unit`, default 'mm'):
//   B, L, D            footing width (constant along its length — see
//                      note below), overall length spanning both
//                      columns, depth
//   col1{b,l,off}, col2{b,l,off}   each column's plan cross-section and
//                      its centerline distance from the L=0 edge. Both
//                      columns are assumed centered on the B midline —
//                      a footing housing two columns offset from each
//                      other across B as well as along L is a real but
//                      much rarer case, not modeled here.
//   cover, dia, spacing, unit      as isolated
//   sectionThrough     1 | 2, default 1 — which column the section cut
//                      passes through
export function computeCombinedFootingGeometry(rawParams) {
  const unit = rawParams.unit || 'mm';
  const B = toMm(rawParams.B, unit);
  const L = toMm(rawParams.L, unit);
  const D = toMm(rawParams.D, unit);
  const cover = toMm(rawParams.cover, unit);
  const dia = toMm(rawParams.dia, unit);
  const spacing = toMm(rawParams.spacing, unit);
  const sectionThrough = rawParams.sectionThrough === 2 ? 2 : 1;

  const col1 = {
    b: toMm(rawParams.col1.b, unit), l: toMm(rawParams.col1.l, unit), off: toMm(rawParams.col1.off, unit),
  };
  const col2 = {
    b: toMm(rawParams.col2.b, unit), l: toMm(rawParams.col2.l, unit), off: toMm(rawParams.col2.off, unit),
  };

  for (const [name, v] of Object.entries({ B, L, D, cover, dia, spacing })) assertFinitePositive(name, v);
  for (const [tag, col] of [['col1', col1], ['col2', col2]]) {
    assertFinitePositive(`${tag}.b`, col.b);
    assertFinitePositive(`${tag}.l`, col.l);
    if (!Number.isFinite(col.off) || col.off <= 0) {
      throw new DiagramError('BAD_PARAM', `"${tag}.off" must be a positive finite number, got ${JSON.stringify(col.off)}.`);
    }
    if (col.b >= B) throw new DiagramError('COLUMN_TOO_WIDE', `${tag}.b (${col.b}mm) must be smaller than B (${B}mm).`);
    const lo = col.off - col.l / 2, hi = col.off + col.l / 2;
    if (lo < 0 || hi > L) {
      throw new DiagramError('COLUMN_OUT_OF_BOUNDS', `${tag} (offset ${col.off}mm, length ${col.l}mm) extends outside the footing's L=${L}mm extent.`);
    }
  }
  // Non-overlap check between the two columns along L.
  const [first, second] = col1.off <= col2.off ? [col1, col2] : [col2, col1];
  if (first.off + first.l / 2 > second.off - second.l / 2) {
    throw new DiagramError('COLUMNS_OVERLAP', `col1 and col2 overlap along L given their offsets and lengths.`);
  }

  const chosen = sectionThrough === 2 ? col2 : col1;
  const section = computeSectionGeometry({
    widthMM: B, depthMM: D, colWidthMM: chosen.b,
    coverMM: cover, diaMM: dia, nominalSpacingMM: spacing,
  });

  return {
    type: 'combined',
    unit,
    sectionThrough,
    plan: {
      longLabel: 'L', shortLabel: 'B', longMM: L, shortMM: B,
      columns: [
        { alongLongMM: col1.l, alongShortMM: col1.b, centerLongMM: col1.off, tag: 'col1' },
        { alongLongMM: col2.l, alongShortMM: col2.b, centerLongMM: col2.off, tag: 'col2' },
      ],
    },
    section,
    meta: { B, L, D, cover, dia, spacing, col1, col2 },
  };
}

// ── SVG rendering ─────────────────────────────────────────────────────
const CANVAS = { w: 960, h: 760 };
const PLAN_BOX = { x: 80, y: 60, w: 800, h: 280 };
const SECTION_BOX = { x: 80, y: 420, w: 800, h: 240 };
const MIN_BAR_PX_R = 3.2;      // bars stay legible even when geometry scales tiny
const MIN_STROKE_PX = 1.2;

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function dimensionLine(x1, y1, x2, y2, label, opts = {}) {
  const orientation = opts.orientation || (Math.abs(x1 - x2) >= Math.abs(y1 - y2) ? 'h' : 'v');
  const tick = 6;
  const midX = (x1 + x2) / 2, midY = (y1 + y2) / 2;
  const labelDx = orientation === 'h' ? 0 : -10;
  const labelDy = orientation === 'h' ? -6 : 4;
  const anchor = orientation === 'h' ? 'middle' : 'end';
  return `
    <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="dim-line"/>
    <line x1="${x1}" y1="${y1 - tick}" x2="${x1}" y2="${y1 + tick}" class="dim-tick"/>
    <line x1="${x2}" y1="${y2 - tick}" x2="${x2}" y2="${y2 + tick}" class="dim-tick"/>
    <text x="${midX + labelDx}" y="${midY + labelDy}" text-anchor="${anchor}" class="dim-label">${esc(label)}</text>`;
}

function hatchDefs() {
  return `
    <pattern id="soilHatch" width="10" height="10" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <line x1="0" y1="0" x2="0" y2="10" stroke="#8a7350" stroke-width="1.4"/>
    </pattern>
    <pattern id="concreteHatch" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <line x1="0" y1="0" x2="0" y2="8" stroke="#9aa0a6" stroke-width="1"/>
    </pattern>`;
}

function renderPlanView(geometry, scale, lang) {
  const { plan } = geometry;
  const labels = FOOTING_LABELS[lang === 'ar' ? 'ar' : 'en'];
  const colDisplayLabel = { col1: labels.colA, col2: labels.colB };
  const originX = PLAN_BOX.x + (PLAN_BOX.w - plan.longMM * scale) / 2;
  const originY = PLAN_BOX.y + (PLAN_BOX.h - plan.shortMM * scale) / 2;
  const wPx = plan.longMM * scale, hPx = plan.shortMM * scale;

  let svg = `<g class="plan-view">`;
  svg += `<rect x="${originX}" y="${originY}" width="${wPx}" height="${hPx}" class="footing-outline"/>`;

  // Reinforcement mesh — lines only in plan (real bar count/spacing, not
  // decorative): bars running the long way, spaced across the short
  // axis == geometry.section.barCentersMM (the same set the section view
  // draws as circles — one source of truth for that direction).
  for (const cMM of geometry.section.barCentersMM) {
    const y = originY + cMM * scale;
    svg += `<line x1="${originX + 2}" y1="${y}" x2="${originX + wPx - 2}" y2="${y}" class="mesh-line"/>`;
  }
  // Bars running the short way: spaced across the long axis at the same
  // nominal spacing (independent count derived the same way, but not the
  // section's job to track — computed inline here since it's plan-only).
  {
    const env = plan.longMM - 2 * geometry.meta.cover - geometry.meta.dia;
    const spacingLong = geometry.meta.spacingLong ?? geometry.meta.spacing;
    const count = Math.max(2, Math.floor(env / spacingLong) + 1);
    const first = geometry.meta.cover + geometry.meta.dia / 2;
    const last = plan.longMM - geometry.meta.cover - geometry.meta.dia / 2;
    const step = count > 1 ? (last - first) / (count - 1) : 0;
    for (let i = 0; i < count; i++) {
      const posMM = count === 1 ? plan.longMM / 2 : first + i * step;
      const x = originX + posMM * scale;
      svg += `<line x1="${x}" y1="${originY + 2}" x2="${x}" y2="${originY + hPx - 2}" class="mesh-line"/>`;
    }
  }

  // Columns
  for (const col of plan.columns) {
    const cx = originX + col.centerLongMM * scale;
    const cy = originY + hPx / 2;
    const cw = col.alongLongMM * scale, ch = col.alongShortMM * scale;
    svg += `<rect x="${cx - cw / 2}" y="${cy - ch / 2}" width="${cw}" height="${ch}" class="column-outline"/>`;
    if (col.tag) {
      // col.tag ('col1'/'col2') is an internal geometry identifier, not a
      // display string — see file header. Map through the shared
      // dictionary so this always says "COLUMN A"/"COLUMN B" (or the
      // Arabic equivalent), matching footingDiagram.mjs's proven house
      // style, never the raw tag.
      const label = colDisplayLabel[col.tag] || col.tag;
      svg += `<text x="${cx}" y="${cy + ch / 2 + 16}" text-anchor="middle" class="col-tag" dir="${lang === 'ar' ? 'rtl' : 'ltr'}">${esc(label)}</text>`;
    }
  }

  // Section cut marker for combined footings, so the section view below
  // is traceable back to a specific column instead of floating unlabeled.
  if (geometry.type === 'combined') {
    const chosen = plan.columns[geometry.sectionThrough - 1];
    const cx = originX + chosen.centerLongMM * scale;
    svg += `<line x1="${cx}" y1="${originY - 14}" x2="${cx}" y2="${originY + hPx + 14}" class="cut-line"/>`;
    svg += `<text x="${cx}" y="${originY - 18}" text-anchor="middle" class="cut-label">A</text>`;
    svg += `<text x="${cx}" y="${originY + hPx + 28}" text-anchor="middle" class="cut-label">A</text>`;
  }

  // Overall dimensions
  svg += dimensionLine(originX, originY - 26, originX + wPx, originY - 26, `${plan.longLabel} = ${fmt(plan.longMM, geometry.unit, 2)}`, { orientation: 'h' });
  svg += dimensionLine(originX - 26, originY, originX - 26, originY + hPx, `${plan.shortLabel} = ${fmt(plan.shortMM, geometry.unit, 2)}`, { orientation: 'v' });

  svg += `<text x="${originX + wPx / 2}" y="${originY + hPx + 46}" text-anchor="middle" class="view-title" dir="${lang === 'ar' ? 'rtl' : 'ltr'}">${esc(labels.plan)}</text>`;
  svg += `</g>`;
  return svg;
}

function renderSectionView(geometry, scale, lang) {
  const { section } = geometry;
  const originX = SECTION_BOX.x + (SECTION_BOX.w - section.widthMM * scale) / 2;
  const baseY = SECTION_BOX.y + SECTION_BOX.h - 60; // leave room for soil hatch + labels below
  const topY = baseY - section.depthMM * scale;
  const wPx = section.widthMM * scale;

  let svg = `<g class="section-view">`;
  // Soil band under the footing
  svg += `<rect x="${originX - 20}" y="${baseY}" width="${wPx + 40}" height="26" fill="url(#soilHatch)" stroke="#8a7350" stroke-width="1"/>`;
  // Footing body
  svg += `<rect x="${originX}" y="${topY}" width="${wPx}" height="${section.depthMM * scale}" class="footing-outline" fill="url(#concreteHatch)"/>`;
  // Column stub rising from the footing top
  const colW = section.colWidthMM * scale;
  const colX = originX + wPx / 2 - colW / 2;
  const colTop = topY - 90;
  svg += `<rect x="${colX}" y="${colTop}" width="${colW}" height="${topY - colTop}" class="column-outline" fill="url(#concreteHatch)"/>`;

  // Bottom reinforcement layer: representative Family-B line + Family-A
  // bar circles at their true spacing/positions.
  const barY = baseY - section.coverMM * scale;
  svg += `<line x1="${originX + 8}" y1="${barY}" x2="${originX + wPx - 8}" y2="${barY}" class="mesh-line"/>`;
  const rPx = Math.max(MIN_BAR_PX_R, (section.diaMM / 2) * scale);
  for (const cMM of section.barCentersMM) {
    svg += `<circle cx="${originX + cMM * scale}" cy="${barY}" r="${rPx}" class="bar-dot"/>`;
  }

  // Dimensions: depth, width, cover, bar spec
  svg += dimensionLine(originX + wPx + 40, topY, originX + wPx + 40, baseY, `D = ${fmt(section.depthMM, geometry.unit, 2)}`, { orientation: 'v' });
  svg += dimensionLine(originX, baseY + 46, originX + wPx, baseY + 46, `${section.widthMM === geometry.meta.B ? 'B' : geometry.plan.shortLabel} = ${fmt(section.widthMM, geometry.unit, 2)}`, { orientation: 'h' });
  // Stacked on two centered lines, not left/right on one line — at
  // narrow widths (e.g. B=1200mm) same-line opposite-anchored labels
  // collide in the middle; found by rendering Case 2 in the test suite
  // and inspecting the PNG, not by inspection of the code alone.
  const midX = originX + wPx / 2;
  svg += `<text x="${midX}" y="${barY - 26}" text-anchor="middle" class="dim-label">cover = ${fmt(section.coverMM, geometry.unit, 0)}</text>`;
  svg += `<text x="${midX}" y="${barY - 10}" text-anchor="middle" class="dim-label">${section.barCount} Ø${fmt(section.diaMM, geometry.unit, 0)} @ ${fmt(section.actualSpacingMM, geometry.unit, 0)}</text>`;

  const sectionTitle = geometry.type === 'combined'
    ? sectionThroughLabel(lang, geometry.sectionThrough)
    : FOOTING_LABELS[lang === 'ar' ? 'ar' : 'en'].section;
  svg += `<text x="${originX + wPx / 2}" y="${baseY + 70}" text-anchor="middle" class="view-title" dir="${lang === 'ar' ? 'rtl' : 'ltr'}">${esc(sectionTitle)}</text>`;
  svg += `</g>`;
  return svg;
}

// opts.lang: 'ar' | 'en', default 'ar'
export function renderFootingDiagramSVG(geometry, opts = {}) {
  const lang = opts.lang === 'en' ? 'en' : 'ar';
  // Some renderers resolve a CSS font-family list by matching only the
  // first token and never fall back to later entries for missing glyphs
  // (confirmed against cairosvg while testing this module). That cuts
  // both ways: an Arial-first stack drew Arabic title text as tofu; a
  // naive fix — putting 'Noto Naskh Arabic' first for the WHOLE drawing
  // — would break the Latin dimension labels (B=, cover=, mm, Ø) instead,
  // because that font doesn't carry a full Latin alphabet and nothing
  // falls back for the missing glyphs. The fix is per-element, not
  // global: pure engineering notation (B=, L=, D=, cover=, mm, ⌀, bar
  // counts) is Latin+digits by international drafting convention
  // regardless of `lang` and always uses defaultFontStack. Product-
  // identity strings — sheet title, caption, PLAN/SECTION view titles,
  // COLUMN A/B tags — come from footingLabels.mjs and DO localize,
  // matching footingDiagram.mjs's proven, shipped house style (see the
  // proof_*.png references this fix was checked against); those classes
  // (.sheet-title/.sheet-caption/.view-title/.col-tag) get scriptFontStack,
  // and only when this render is actually Arabic — never the blanket
  // global change that caused the original tofu bug.
  const defaultFontStack = `Arial, Tahoma, 'Noto Sans Arabic', 'Noto Naskh Arabic', sans-serif`;
  const scriptFontStack = lang === 'ar'
    ? `'Noto Naskh Arabic', 'Noto Sans Arabic', Tahoma, Arial, sans-serif`
    : defaultFontStack;
  const scale = Math.min(
    PLAN_BOX.w / geometry.plan.longMM,
    PLAN_BOX.h / geometry.plan.shortMM,
    SECTION_BOX.w / geometry.section.widthMM,
    (SECTION_BOX.h - 60) / geometry.section.depthMM,
  ) * 0.85;

  const labels = FOOTING_LABELS[lang === 'ar' ? 'ar' : 'en'];
  const caption = labels.captionComputed;
  const title = geometry.type === 'combined' ? labels.footCombined : labels.footIsolated;

  return `<svg viewBox="0 0 ${CANVAS.w} ${CANVAS.h}" xmlns="http://www.w3.org/2000/svg" font-family="${defaultFontStack}">
  <defs>${hatchDefs()}</defs>
  <style>
    text { font-family: ${defaultFontStack}; }
    .footing-outline { fill:#f4f4f4; stroke:#1a1a1a; stroke-width:${MIN_STROKE_PX * 1.4}; }
    .column-outline  { fill:#e2e2e2; stroke:#1a1a1a; stroke-width:${MIN_STROKE_PX * 1.4}; }
    .mesh-line       { stroke:#c0392b; stroke-width:${MIN_STROKE_PX}; }
    .bar-dot         { fill:#c0392b; stroke:#7a2015; stroke-width:0.6; }
    .dim-line        { stroke:#333; stroke-width:1; }
    .dim-tick        { stroke:#333; stroke-width:1; }
    .dim-label       { font-size:15px; fill:#111; }
    .view-title      { font-size:16px; font-weight:bold; fill:#111; letter-spacing:${lang === 'ar' ? 'normal' : '1px'}; font-family: ${scriptFontStack}; }
    .cut-line        { stroke:#1a1a1a; stroke-width:1.4; stroke-dasharray:6,3; }
    .cut-label       { font-size:14px; font-weight:bold; fill:#111; }
    .col-tag         { font-size:12px; fill:#333; font-family: ${scriptFontStack}; }
    .sheet-title     { font-size:20px; font-weight:bold; fill:#111; font-family: ${scriptFontStack}; }
    .sheet-caption   { font-size:12.5px; fill:#444; font-family: ${scriptFontStack}; }
  </style>
  <rect x="0" y="0" width="${CANVAS.w}" height="${CANVAS.h}" fill="#ffffff"/>
  <text x="${CANVAS.w / 2}" y="30" text-anchor="middle" class="sheet-title" dir="${lang === 'ar' ? 'rtl' : 'ltr'}">${esc(title)}</text>
  ${renderPlanView(geometry, scale, lang)}
  ${renderSectionView(geometry, scale, lang)}
  <line x1="${PLAN_BOX.x}" y1="${SECTION_BOX.y - 30}" x2="${PLAN_BOX.x + PLAN_BOX.w}" y2="${SECTION_BOX.y - 30}" stroke="#ccc" stroke-width="1"/>
  ${renderCaption(caption, lang)}
</svg>`;
}

// Plain <text> lines, not foreignObject — foreignObject is silently
// dropped by at least one real SVG renderer this module was verified
// against (cairosvg), which would silently drop this caption. <text> is
// universally supported. Wrapping is a simple character-count estimate
// (no real font metrics available at generation time), generous enough
// at this font size/canvas width that it will not truncate, only
// possibly wrap one line earlier than a pixel-exact wrap would.
function wrapText(text, maxCharsPerLine) {
  const words = text.split(' ');
  const lines = [];
  let current = '';
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length > maxCharsPerLine && current) {
      lines.push(current);
      current = word;
    } else {
      current = candidate;
    }
  }
  if (current) lines.push(current);
  return lines;
}

function renderCaption(caption, lang) {
  const lines = wrapText(caption, 100);
  const rtl = lang === 'ar';
  const x = rtl ? CANVAS.w - 40 : 40;
  const anchor = rtl ? 'end' : 'start';
  const startY = CANVAS.h - 20 - (lines.length - 1) * 16;
  return lines
    .map((line, i) => `<text x="${x}" y="${startY + i * 16}" text-anchor="${anchor}" dir="${rtl ? 'rtl' : 'ltr'}" class="sheet-caption">${esc(line)}</text>`)
    .join('\n  ');
}

// ── Chat command parser ──────────────────────────────────────────────
// Syntax (ASCII key=value pairs — deliberately not natural-language, so
// there is no NLP ambiguity on the numbers that matter):
//   /diagram isolated B=1800 L=1800 D=500 colB=400 colL=400 cover=50 dia=16 spacing=150 [unit=mm]
//   /diagram combined B=1200 L=4200 D=600 col1b=400 col1l=400 col1off=700 col2b=400 col2l=400 col2off=3500 cover=50 dia=16 spacing=150 [unit=mm]
// Returns { ok:true, type, geometry } or { ok:false, code, message }.
// Never throws — every DiagramError from the compute*Geometry functions
// is caught and converted to the same { ok:false } shape validateImagePrompt()
// uses elsewhere in this app, so callers have one error shape to handle.
export function parseDiagramCommand(text) {
  const trimmed = (text || '').trim();
  // Capture ANY leading token as the candidate type — deliberately not
  // anchored to just isolated|combined — so an unimplemented-but-real
  // type (e.g. "strip") reaches the UNSUPPORTED_TYPE branch below with a
  // useful message instead of being misreported as unparseable syntax.
  // BAD_SYNTAX is reserved for input with no leading-token/params shape
  // at all.
  const m = trimmed.match(/^(\S+)\s+(.+)$/);
  if (!m || !m[2].includes('=')) {
    // No leading-token+rest shape at all, OR a rest with no "key=value"
    // structure in it (e.g. free text) — this is not the command syntax,
    // full stop, as opposed to a recognized syntax with an unsupported
    // type keyword. Keeps "not a valid command" from being reported back
    // as if "not" were a real-but-unimplemented diagram type.
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected: isolated|combined key=value key=value ...' };
  }
  const type = m[1].toLowerCase();
  const kv = {};
  for (const tok of m[2].split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq === -1) continue;
    kv[tok.slice(0, eq).toLowerCase()] = tok.slice(eq + 1);
  }
  const num = (k) => (k in kv ? Number(kv[k]) : undefined);

  try {
    let geometry;
    if (type === 'isolated') {
      geometry = computeIsolatedFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        colB: num('colb'), colL: num('coll'),
        cover: num('cover'), dia: num('dia'),
        spacing: num('spacing'), spacingLong: num('spacinglong'), spacingShort: num('spacingshort'),
        unit: kv.unit || 'mm',
      });
    } else if (type === 'combined') {
      geometry = computeCombinedFootingGeometry({
        B: num('b'), L: num('l'), D: num('d'),
        col1: { b: num('col1b'), l: num('col1l'), off: num('col1off') },
        col2: { b: num('col2b'), l: num('col2l'), off: num('col2off') },
        cover: num('cover'), dia: num('dia'), spacing: num('spacing'),
        sectionThrough: num('sectionthrough') === 2 ? 2 : 1,
        unit: kv.unit || 'mm',
      });
    } else {
      return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported. Use isolated or combined.` };
    }
    return { ok: true, type, geometry };
  } catch (err) {
    if (err instanceof DiagramError) {
      return { ok: false, code: err.code, message: err.message };
    }
    throw err; // programmer error (e.g. bad code path) — do not swallow silently
  }
}
