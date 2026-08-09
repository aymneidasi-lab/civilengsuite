// functions/_lib/footingDiagram.mjs
//
// Deterministic replacement for the Workers-AI diffusion path (imageGen.mjs)
// for the specific structural elements this product actually specializes in.
//
// WHY THIS FILE EXISTS — root cause, not a prompt tweak:
// imageGen.mjs's own header documents two prior live-traffic patches to
// buildEngineeringPrompt()/NEGATIVE_PROMPT: (1) "combined footing" first
// read as feet/sports and produced a cartoon; (2) requesting dimension
// labels produced confident-looking but fabricated numbers and garbled
// text. Both patches correctly fixed the symptom they targeted. Neither
// could fix the actual constraint: flux-1-schnell and
// stable-diffusion-xl-lightning are general consumer/art diffusion models
// with ~no representation of structural plan/section drawings in their
// training distribution — "combined footing", "trapezoidal combined
// footing", and "strap footing" are specialist CAD content, essentially
// absent from the image-caption corpora these models were trained on. No
// amount of prompt wording adds knowledge the model doesn't have; it only
// steers which *wrong* answer comes out (foot → generic building
// blueprint/interior, per the current live bug report). A 4-step distilled
// model asked for a subject it has no training signal for will always
// regress to its nearest large visual cluster — here, "building interior
// with beams/stairs" — not the specific isolated foundation element asked
// for.
//
// FIX: for the closed set of structural elements this app actually ships
// (Footing Pro v.2026's three "live now" types — see repo's own SEO copy:
// Rectangular Combined Footing, Trapezoidal Combined Footing, Strap
// Footing), skip the diffusion model entirely and render a hand-authored,
// deterministic SVG technical schematic. This is not "a better prompt" —
// it is removing the generative model from the critical path for the exact
// content category it structurally cannot produce. The Workers-AI
// diffusion fallback in imageGen.mjs is untouched and still runs for any
// prompt that does NOT match a known type (e.g. "a golden retriever wearing
// sunglasses" — imageGen.mjs's own doc-comment example) — that is a
// legitimate generic-illustration use case with no correctness expectation,
// unlike a structural element with an established drafting convention.
//
// NUMBERS: every label is symbolic (L, B, D) or a fixed word ("COLUMN A",
// "PLAN VIEW"). No numeric dimension is ever printed. Same reasoning as
// NEGATIVE_PROMPT's text/digit exclusion in imageGen.mjs, applied for a
// different reason: I (the developer) control every glyph here — nothing
// is hallucinated — but this page has no calculator, no column loads, no
// soil bearing capacity (confirmed: footing_pro_v52.html carries the
// product's marketing/FAQ/chat surface, not the ECP203 calculation engine
// itself — the engine ships inside the licensed desktop application only).
// Printing a specific "1.8 m" here would be exactly as fabricated as the
// diffusion model's invented "50mm" was, just from a different source. A
// generic reference schematic with lettered dimensions is the honest
// ceiling for what this endpoint can produce.
//
// ENCODING: data URI built with encodeURIComponent, not base64/btoa.
// btoa() throws on any code point above U+00FF, which Arabic labels hit
// immediately — imageGen.mjs's own arrayBufferToBase64() exists only
// because raw diffusion output is binary, not text; SVG is text, so the
// simpler, Unicode-safe, browser-native `data:image/svg+xml,<uri-encoded>`
// form is used instead (standard technique, no encoding pitfalls, avoids
// depending on btoa/Buffer being available in this exact shape in the
// Workers runtime).

const FONT = "font-family:'Segoe UI',Arial,sans-serif;";

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Label sets (bilingual, static strings only — nothing computed/invented) ──
const L = {
  en: {
    plan: 'PLAN VIEW', section: 'SECTION A\u2013A',
    colA: 'COLUMN A', colB: 'COLUMN B',
    footRect: 'RECTANGULAR COMBINED FOOTING', footTrap: 'TRAPEZOIDAL COMBINED FOOTING', footStrap: 'STRAP FOOTING',
    strapBeam: 'STRAP BEAM', noBearing: 'NO SOIL BEARING UNDER STRAP', edgeFooting: 'EDGE FOOTING', interiorFooting: 'INTERIOR FOOTING',
    ground: 'GROUND LINE', rebarNote: 'REINFORCEMENT MAT (SCHEMATIC)',
    caption: 'Generic reference schematic \u2014 not project-specific. Verify every dimension against your own ECP 203 / ACI 318 design.',
    dirAttr: 'ltr', anchorStart: 'start', anchorEnd: 'end',
  },
  // Written as literal characters, not \u escapes — the first draft of
  // this block hand-computed escapes and two of them were wrong in ways
  // that only showed up on render (بربيط instead of رباط; قاعدة الحرف,
  // "the letter/craft footing", instead of القاعدة الطرفية, "the edge
  // footing"). Escaping a script you can't proofread by eye is exactly
  // the kind of silent-corruption risk imageGen.mjs's own NEGATIVE_PROMPT
  // comment warns about for the diffusion path; the fix here is the same
  // in spirit — verify by rendering, don't trust the encoding by
  // inspection. footStrap deliberately matches this product's own SEO
  // copy (footing_pro_v52.html's meta keywords: "تصميم القاعدة الشريطية"
  // sitting between the rectangular- and trapezoidal-combined-footing
  // entries) rather than a more textbook-generic Arabic rendering, so the
  // chat's own vocabulary doesn't disagree with the site's.
  ar: {
    plan: 'مسقط أفقي', section: 'قطاع أ-أ',
    colA: 'عمود أ', colB: 'عمود ب',
    footRect: 'قاعدة مشتركة مستطيلة', footTrap: 'قاعدة مشتركة شبه منحرفة', footStrap: 'القاعدة الشريطية',
    strapBeam: 'كمرة الربط', noBearing: 'لا يوجد تلامس مع التربة أسفل كمرة الربط', edgeFooting: 'القاعدة الطرفية', interiorFooting: 'القاعدة الداخلية',
    ground: 'منسوب سطح الأرض', rebarNote: 'شبكة تسليح (توضيحية)',
    caption: 'مخطط توضيحي عام وليس خاصاً بمشروع معين — راجع جميع الأبعاد مع تصميمك الخاص وفق ECP 203 / ACI 318.',
    dirAttr: 'rtl', anchorStart: 'end', anchorEnd: 'start',
  },
};

function defs() {
  return `<defs>
    <pattern id="concreteHatch" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <rect width="8" height="8" fill="#ffffff"/>
      <line x1="0" y1="0" x2="0" y2="8" stroke="#5b6b7a" stroke-width="1.1"/>
    </pattern>
    <pattern id="soilHatch" width="14" height="10" patternUnits="userSpaceOnUse">
      <rect width="14" height="10" fill="#f4f1ea"/>
      <line x1="0" y1="10" x2="7" y2="0" stroke="#9a8f78" stroke-width="1"/>
      <line x1="7" y1="10" x2="14" y2="0" stroke="#9a8f78" stroke-width="1"/>
    </pattern>
    <marker id="arrowStart" markerWidth="8" markerHeight="8" refX="1" refY="4" orient="auto">
      <path d="M7,1 L1,4 L7,7 Z" fill="#1c2b3a"/>
    </marker>
    <marker id="arrowEnd" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M1,1 L7,4 L1,7 Z" fill="#1c2b3a"/>
    </marker>
  </defs>`;
}

function text(x, y, str, { size = 13, weight = 'normal', anchor = 'middle', color = '#1c2b3a', dir = 'ltr', letterSpacing = 0 } = {}) {
  const ls = letterSpacing ? ` letter-spacing="${letterSpacing}"` : '';
  return `<text x="${x}" y="${y}" text-anchor="${anchor}" dir="${dir}" ${ls} style="${FONT}font-size:${size}px;font-weight:${weight};fill:${color};">${esc(str)}</text>`;
}

// Horizontal double-headed dimension line with a centered label above it.
function dimH(x1, x2, y, label, dir) {
  return `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="#1c2b3a" stroke-width="1" marker-start="url(#arrowStart)" marker-end="url(#arrowEnd)"/>
    <line x1="${x1}" y1="${y - 6}" x2="${x1}" y2="${y + 6}" stroke="#1c2b3a" stroke-width="1"/>
    <line x1="${x2}" y1="${y - 6}" x2="${x2}" y2="${y + 6}" stroke="#1c2b3a" stroke-width="1"/>
    ${text((x1 + x2) / 2, y - 8, label, { size: 14, weight: '700', dir })}`;
}

// Vertical double-headed dimension line with a label to its side.
function dimV(y1, y2, x, label, dir, side = 'left') {
  const lx = side === 'left' ? x - 12 : x + 12;
  const anchor = side === 'left' ? 'end' : 'start';
  return `<line x1="${x}" y1="${y1}" x2="${x}" y2="${y2}" stroke="#1c2b3a" stroke-width="1" marker-start="url(#arrowStart)" marker-end="url(#arrowEnd)"/>
    <line x1="${x - 6}" y1="${y1}" x2="${x + 6}" y2="${y1}" stroke="#1c2b3a" stroke-width="1"/>
    <line x1="${x - 6}" y1="${y2}" x2="${x + 6}" y2="${y2}" stroke="#1c2b3a" stroke-width="1"/>
    ${text(lx, (y1 + y2) / 2 + 4, label, { size: 14, weight: '700', anchor, dir })}`;
}

// Rebar mesh (plan view): grid of thin lines inside a cover-inset rect —
// a standard schematic way to indicate "a reinforcement mat exists here"
// without claiming a specific bar count or spacing (both unknown at this
// endpoint — see file header).
function rebarMeshPlan(x, y, w, h, step = 26) {
  let out = '';
  for (let gx = x; gx <= x + w + 0.01; gx += step) {
    out += `<line x1="${gx}" y1="${y}" x2="${gx}" y2="${y + h}" stroke="#8fa3b8" stroke-width="0.75"/>`;
  }
  for (let gy = y; gy <= y + h + 0.01; gy += step) {
    out += `<line x1="${x}" y1="${gy}" x2="${x + w}" y2="${gy}" stroke="#8fa3b8" stroke-width="0.75"/>`;
  }
  return `<g opacity="0.85">${out}</g>`;
}

// Rebar cut in section: row of small filled circles = bar cross-sections,
// standard drafting convention for a reinforcement layer seen end-on.
function rebarDotsRow(x1, x2, y, count = 7, r = 3.2) {
  let out = '';
  for (let i = 0; i < count; i++) {
    const x = x1 + ((x2 - x1) * i) / (count - 1);
    out += `<circle cx="${x}" cy="${y}" r="${r}" fill="#1c2b3a"/>`;
  }
  return out;
}

// Column starter/dowel bars: short vertical bars inside a column, each
// ending in a 90-degree hook bent into the footing — standard convention
// for "column reinforcement continues down and anchors into the footing".
function dowels(cx, colHalfW, topY, hookY, count = 4) {
  let out = '';
  const inset = colHalfW * 0.5;
  for (let i = 0; i < count; i++) {
    const x = cx - inset + (i * (2 * inset)) / (count - 1);
    const hookDir = x < cx ? -1 : 1;
    out += `<path d="M${x},${topY} L${x},${hookY} L${x + hookDir * 10},${hookY}" fill="none" stroke="#1c2b3a" stroke-width="1.3"/>`;
  }
  return out;
}

// Break symbol: small zigzag across a column shaft, indicating "column
// continues upward beyond this drawing" (standard drafting break-line).
function breakSymbol(cx, y, halfW) {
  const x1 = cx - halfW - 4, x2 = cx + halfW + 4;
  return `<path d="M${x1},${y} L${x1 + 6},${y - 7} L${x1 + 14},${y + 7} L${x1 + 22},${y - 7} L${x1 + 30},${y}
    M${x2 - 30},${y} L${x2 - 22},${y - 7} L${x2 - 14},${y + 7} L${x2 - 6},${y - 7} L${x2},${y}"
    fill="none" stroke="#1c2b3a" stroke-width="1.2"/>`;
}

function panelFrame(x, y, w, h, caption, dir) {
  return `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="none" stroke="#c7d2dc" stroke-width="1"/>
    ${text(x + w / 2, y + h + 22, caption, { size: 15, weight: '700', dir })}`;
}

// ── Panel builders ──────────────────────────────────────────────────────

function planRectangular(px, py, pw, ph, l) {
  const fx = px + pw * 0.10, fy = py + ph * 0.28, fw = pw * 0.80, fh = ph * 0.34;
  const cw = fh * 0.42;
  const cAx = fx + fw * 0.20, cBx = fx + fw * 0.80, cy = fy + fh / 2;
  const cutY = cy, cutX1 = fx - 18, cutX2 = fx + fw + 18;
  return `
    ${rebarMeshPlan(fx + 10, fy + 10, fw - 20, fh - 20)}
    <rect x="${fx}" y="${fy}" width="${fw}" height="${fh}" fill="none" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${cAx - cw / 2}" y="${cy - cw / 2}" width="${cw}" height="${cw}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    <rect x="${cBx - cw / 2}" y="${cy - cw / 2}" width="${cw}" height="${cw}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${text(cAx, fy - 10, l.colA, { size: 12, weight: '700', dir: l.dirAttr })}
    ${text(cBx, fy - 10, l.colB, { size: 12, weight: '700', dir: l.dirAttr })}
    <line x1="${cutX1}" y1="${cutY}" x2="${cutX2}" y2="${cutY}" stroke="#8a2b2b" stroke-width="1.4" stroke-dasharray="10,4,2,4"/>
    ${text(cutX1, cutY - 10, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'middle' })}
    ${text(cutX2, cutY - 10, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'middle' })}
    ${dimH(fx, fx + fw, fy + fh + 26, 'L', l.dirAttr)}
    ${dimV(fy, fy + fh, fx - 26, 'B', l.dirAttr, 'left')}
  `;
}

function sectionRectangular(px, py, pw, ph, l, extraNote) {
  const gy = py + ph * 0.42;
  const fx = px + pw * 0.10, fw = pw * 0.80, fh = ph * 0.15, fy = gy;
  const cw = fh * 0.85;
  const cAx = fx + fw * 0.20, cBx = fx + fw * 0.80;
  const colTop = py + ph * 0.06;
  // Placed in the real gap between the two column shafts (derived from the
  // same cAx/cBx/cw/colTop this function already computed), not a guessed
  // y-coordinate — the first version of this note used a hand-picked
  // offset that landed on top of the column hatch instead of the gap
  // between the columns (only visible once rendered, see file header on
  // why every variant here gets rasterized and viewed, not just
  // eyeballed as markup).
  // Two short lines, not one long one: Arabic glyphs at the same point
  // size run wider than the English equivalent, and a single-line version
  // of this note overflowed its own backing rect into the column hatch on
  // the Arabic render (caught only by rasterizing and looking — see file
  // header). Splitting removes the dependency on cross-script width
  // parity instead of trying to tune a font size that "happens" to fit
  // both.
  const gapX = cAx + cw / 2 + 6, gapW = (cBx - cw / 2) - (cAx + cw / 2) - 12;
  const noteTop = colTop + (fy - colTop) * 0.18;
  const note = extraNote ? `
    <rect x="${gapX}" y="${noteTop}" width="${gapW}" height="34" fill="#ffffff" opacity="0.9"/>
    ${text((cAx + cBx) / 2, noteTop + 14, extraNote[0], { size: 9.5, color: '#5b6b7a', dir: l.dirAttr })}
    ${text((cAx + cBx) / 2, noteTop + 27, extraNote[1], { size: 9.5, color: '#5b6b7a', dir: l.dirAttr })}
  ` : '';
  return `
    <rect x="${px}" y="${gy}" width="${pw}" height="${py + ph - gy}" fill="url(#soilHatch)"/>
    <line x1="${px}" y1="${gy}" x2="${px + pw}" y2="${gy}" stroke="#5b4a2f" stroke-width="1.5"/>
    ${text(px + pw - 4, gy - 6, l.ground, { size: 10, color: '#5b4a2f', anchor: 'end' })}
    <rect x="${fx}" y="${fy}" width="${fw}" height="${fh}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2.5"/>
    ${rebarDotsRow(fx + 14, fx + fw - 14, fy + fh - 12)}
    <rect x="${cAx - cw / 2}" y="${colTop}" width="${cw}" height="${fy - colTop}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    <rect x="${cBx - cw / 2}" y="${colTop}" width="${cw}" height="${fy - colTop}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${breakSymbol(cAx, colTop + 6, cw / 2)}
    ${breakSymbol(cBx, colTop + 6, cw / 2)}
    ${dowels(cAx, cw / 2, colTop + 14, fy + fh - 10)}
    ${dowels(cBx, cw / 2, colTop + 14, fy + fh - 10)}
    ${text(cAx, colTop - 8, l.colA, { size: 12, weight: '700', dir: l.dirAttr })}
    ${text(cBx, colTop - 8, l.colB, { size: 12, weight: '700', dir: l.dirAttr })}
    ${dimH(fx, fx + fw, fy + fh + 26, 'L', l.dirAttr)}
    ${dimV(fy, fy + fh, fx - 26, 'D', l.dirAttr, 'left')}
    ${note}
  `;
}

function planTrapezoidal(px, py, pw, ph, l) {
  const fx = px + pw * 0.10, fy = py + ph * 0.24, fw = pw * 0.80, fh1 = ph * 0.44, fh2 = ph * 0.22;
  // Wide end (heavier / interior column) on the right, narrow end (lighter /
  // edge column) on the left — the defining trapezoid taper.
  const topL = fy + (fh1 - fh2) / 2, botL = topL + fh2;
  const topR = fy, botR = fy + fh1;
  const cw = fh2 * 0.7;
  const cAx = fx + fw * 0.16, cAy = (topL + botL) / 2;
  const cBx = fx + fw * 0.82, cBy = (topR + botR) / 2;
  const cutY1 = cAy, cutY2 = cBy;
  const clipTop = Math.min(topL, topR), clipBot = Math.max(botL, botR);
  return `
    <clipPath id="trapClip"><polygon points="${fx},${topL} ${fx + fw},${topR} ${fx + fw},${botR} ${fx},${botL}"/></clipPath>
    <g clip-path="url(#trapClip)">${rebarMeshPlan(fx, clipTop, fw, clipBot - clipTop)}</g>
    <polygon points="${fx},${topL} ${fx + fw},${topR} ${fx + fw},${botR} ${fx},${botL}" fill="none" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${cAx - cw / 2}" y="${cAy - cw / 2}" width="${cw}" height="${cw}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    <rect x="${cBx - cw * 1.15 / 2}" y="${cBy - cw * 1.15 / 2}" width="${cw * 1.15}" height="${cw * 1.15}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${text(cAx, topL - 12, l.colA, { size: 12, weight: '700', dir: l.dirAttr })}
    ${text(cBx, topR - 12, l.colB, { size: 12, weight: '700', dir: l.dirAttr })}
    <line x1="${fx - 18}" y1="${cutY1}" x2="${fx + fw + 18}" y2="${cutY2}" stroke="#8a2b2b" stroke-width="1.4" stroke-dasharray="10,4,2,4"/>
    ${text(fx - 18, cutY1 - 10, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'middle' })}
    ${text(fx + fw + 18, cutY2 - 10, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'middle' })}
    ${dimH(fx, fx + fw, botR + 30, 'L', l.dirAttr)}
    ${dimV(topL, botL, fx - 26, 'B1', l.dirAttr, 'left')}
    ${dimV(topR, botR, fx + fw + 26, 'B2', l.dirAttr, 'right')}
  `;
}

function sectionTrapezoidal(px, py, pw, ph, l) {
  // Same longitudinal-cut convention as the rectangular case; the taper is
  // a plan-view-only feature (width perpendicular to this cut), so the
  // section silhouette is drawn the same way, with a note that footing
  // width varies along the length (visible only in plan). Note text is
  // plain ASCII-safe-to-type-correctly Arabic, written literally per the
  // L.ar fix above, not hand-escaped.
  const noteLines = l.dirAttr === 'rtl'
    ? ['العرض يتغيّر مع الطول', 'انظر المسقط الأفقي']
    : ['width tapers along length', '\u2014 see plan'];
  return sectionRectangular(px, py, pw, ph, l, noteLines);
}

function planStrap(px, py, pw, ph, l) {
  const midY = py + ph * 0.5;
  const edgeW = pw * 0.20, edgeH = ph * 0.30;
  const intW = pw * 0.30, intH = ph * 0.42;
  const edgeX = px + pw * 0.08, edgeY = midY - edgeH / 2;
  const intX = px + pw * 0.72, intY = midY - intH / 2;
  const strapX1 = edgeX + edgeW, strapX2 = intX, strapY = midY, strapH = ph * 0.10;
  const cw = Math.min(edgeH, intH) * 0.5;
  return `
    <rect x="${edgeX}" y="${edgeY}" width="${edgeW}" height="${edgeH}" fill="none" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${intX}" y="${intY}" width="${intW}" height="${intH}" fill="none" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${strapX1}" y="${strapY - strapH / 2}" width="${strapX2 - strapX1}" height="${strapH}" fill="none" stroke="#1c2b3a" stroke-width="2" stroke-dasharray="6,3"/>
    <rect x="${edgeX + edgeW * 0.30 - cw / 2}" y="${midY - cw / 2}" width="${cw}" height="${cw}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    <rect x="${intX + intW * 0.5 - cw * 1.1 / 2}" y="${midY - cw * 1.1 / 2}" width="${cw * 1.1}" height="${cw * 1.1}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${text(edgeX + edgeW / 2, edgeY - 10, l.edgeFooting, { size: 11, weight: '700', dir: l.dirAttr })}
    ${text(intX + intW / 2, intY - 10, l.interiorFooting, { size: 11, weight: '700', dir: l.dirAttr })}
    ${text((strapX1 + strapX2) / 2, strapY - strapH / 2 - 8, l.strapBeam, { size: 10, weight: '700', dir: l.dirAttr })}
    <line x1="${edgeX - 16}" y1="${midY}" x2="${intX + intW + 16}" y2="${midY}" stroke="#8a2b2b" stroke-width="1.4" stroke-dasharray="10,4,2,4"/>
    ${text(edgeX - 24, midY + 4, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'end' })}
    ${text(intX + intW + 24, midY + 4, 'A', { size: 13, weight: '700', color: '#8a2b2b', anchor: 'start' })}
    ${dimH(edgeX, intX + intW, Math.max(edgeY + edgeH, intY + intH) + 28, 'L', l.dirAttr)}
  `;
}

function sectionStrap(px, py, pw, ph, l) {
  const gy = py + ph * 0.50;
  const edgeW = pw * 0.16, edgeFh = ph * 0.10;
  const intW = pw * 0.22, intFh = ph * 0.14;
  const edgeX = px + pw * 0.10, edgeFy = gy - edgeFh * 0.3;
  const intX = px + pw * 0.70, intFy = gy;
  const gap = ph * 0.07; // visible daylight gap under the strap — the defining feature vs. a monolithic combined footing
  const strapY = Math.min(edgeFy, intFy) - gap - ph * 0.06;
  const strapH = ph * 0.06;
  const colTop = py + ph * 0.04;
  const cwE = edgeFh * 1.4, cwI = intFh * 1.1;
  const edgeCx = edgeX + edgeW / 2, intCx = intX + intW / 2;
  return `
    <rect x="${px}" y="${gy}" width="${pw}" height="${py + ph - gy}" fill="url(#soilHatch)"/>
    <line x1="${px}" y1="${gy}" x2="${px + pw}" y2="${gy}" stroke="#5b4a2f" stroke-width="1.5"/>
    ${text(px + pw - 4, gy - 6, l.ground, { size: 10, color: '#5b4a2f', anchor: 'end' })}
    <rect x="${edgeX}" y="${edgeFy}" width="${edgeW}" height="${py + ph * 0.62 - edgeFy}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${intX}" y="${intFy}" width="${intW}" height="${py + ph * 0.68 - intFy}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2.5"/>
    <rect x="${edgeX + edgeW - 6}" y="${strapY}" width="${(intX) - (edgeX + edgeW - 6) + 6}" height="${strapH}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${text((edgeX + edgeW + intX) / 2, strapY - 8, l.strapBeam, { size: 10, weight: '700', dir: l.dirAttr })}
    ${text((edgeX + edgeW + intX) / 2, strapY + strapH + (gap * 0.6), l.noBearing, { size: 8.5, color: '#8a2b2b', dir: l.dirAttr })}
    <rect x="${edgeCx - cwE / 2}" y="${colTop}" width="${cwE}" height="${strapY - colTop}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    <rect x="${intCx - cwI / 2}" y="${colTop}" width="${cwI}" height="${strapY - colTop}" fill="url(#concreteHatch)" stroke="#1c2b3a" stroke-width="2"/>
    ${breakSymbol(edgeCx, colTop + 6, cwE / 2)}
    ${breakSymbol(intCx, colTop + 6, cwI / 2)}
    ${rebarDotsRow(edgeX + 6, edgeX + edgeW - 6, py + ph * 0.62 - 8, 3, 2.6)}
    ${rebarDotsRow(intX + 6, intX + intW - 6, py + ph * 0.68 - 8, 4, 2.8)}
    ${text(edgeCx, colTop - 8, l.colA, { size: 11, weight: '700', dir: l.dirAttr })}
    ${text(intCx, colTop - 8, l.colB, { size: 11, weight: '700', dir: l.dirAttr })}
  `;
}

const BUILDERS = {
  rectangular: { title: 'footRect', plan: planRectangular, section: sectionRectangular },
  trapezoidal: { title: 'footTrap', plan: planTrapezoidal, section: sectionTrapezoidal },
  strap: { title: 'footStrap', plan: planStrap, section: sectionStrap },
};

export function buildFootingDiagramSvg(type, lang) {
  const l = L[lang === 'ar' ? 'ar' : 'en'];
  const b = BUILDERS[type];
  if (!b) return null;

  const W = 1000, H = 640;
  const PX0 = 50, PY0 = 118, PW = 400, PH = 380;
  const SX0 = 560, SY0 = 118, SW = 400, SH = 380;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${esc(l[b.title])}">
    <rect width="${W}" height="${H}" fill="#ffffff"/>
    ${defs()}
    ${text(W / 2, 42, l[b.title], { size: 22, weight: '700', dir: l.dirAttr })}
    ${text(W / 2, 64, l.rebarNote, { size: 11, color: '#5b6b7a', dir: l.dirAttr })}
    ${panelFrame(PX0, PY0, PW, PH, l.plan, l.dirAttr)}
    ${panelFrame(SX0, SY0, SW, SH, l.section, l.dirAttr)}
    <g>${b.plan(PX0, PY0, PW, PH, l)}</g>
    <g>${b.section(SX0, SY0, SW, SH, l)}</g>
    <line x1="30" y1="${H - 34}" x2="${W - 30}" y2="${H - 34}" stroke="#e2e8ee" stroke-width="1"/>
    ${text(W / 2, H - 14, l.caption, { size: 10.5, color: '#7a8a9a', dir: l.dirAttr })}
  </svg>`;
}

// Ordered so the classifier checks the most specific terms first — e.g.
// "trapezoidal" must win over a bare "footing"/"combined" match, and
// "strap" must win before it falls through to the generic combined case.
// Bilingual: English keywords plus the Arabic terms already in this
// product's own SEO copy (2_-_REPO_STRUCTURE.txt / footing_pro_v52.html
// meta tags) — "قاعدة مشتركة" (combined footing), "شبه منحرفة"
// (trapezoidal), "قاعدة شريطية"/"قاعدة رباط" (strap).
const PATTERNS = [
  { type: 'trapezoidal', re: /trapezoidal|trapezoid/i },
  { type: 'trapezoidal', re: /شبه\s*منحرف/ },
  { type: 'strap', re: /\bstrap\s*(footing|beam)?\b/i },
  { type: 'strap', re: /قاعدة\s*(ال)?رباط|قاعدة\s*شريطية|كمرة\s*الرباط/ },
  { type: 'rectangular', re: /rectangular\s*(combined)?\s*footing/i },
  { type: 'rectangular', re: /combined\s*footing/i },
  { type: 'rectangular', re: /قاعدة\s*(مشتركة|مستطيلة)/ },
];

export function classifyFootingDiagram(rawPrompt) {
  const p = String(rawPrompt || '');
  for (const { type, re } of PATTERNS) {
    if (re.test(p)) return type;
  }
  return null;
}

export function svgToDataUri(svgString) {
  return 'data:image/svg+xml,' + encodeURIComponent(svgString);
}
