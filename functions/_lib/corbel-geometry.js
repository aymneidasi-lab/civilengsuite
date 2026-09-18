// corbel-geometry-2.js
// Extends corbel-geometry.js. Units: mm, MPa (N/mm^2), N for forces. CommonJS.
// Self-test: `node corbel-geometry-2.js`.
//
// WHY THIS FILE EXISTS: pc_suite_v117-1-1-2-1.html's real CES_CORBEL_FORM_SCHEMA
// (read directly this session, functions/api/chat.js aka chat-9.js confirmed as the
// dispatcher that would receive it) sends THREE geometry fields corbel-geometry.js's
// `computeCorbelGeometry` did not distinguish:
//   - `projection` (100-900mm): "Corbel projection ... from the column face" -- the
//     PHYSICAL outer-tip location.
//   - `av` (>=0): "load point distance (av) from the column face" -- the SHEAR SPAN,
//     i.e. where the bearing/load sits.
//   - `h1` (>=0): "Corbel depth ... at the outer tip" -- the drawn tip height,
//     separate from `d` (effective depth at the column-face critical section).
//
// GEOMETRY SHAPE (this revision): the outline is now the STANDARD corbel shape --
// horizontal top surface (where the bearing plate sits), vertical column face, vertical
// tip face of height h1, and a sloped bottom edge from the tip's bottom back to the
// column face's bottom. The previous revision emitted a sloped TOP and a horizontal
// bottom, which made a horizontal bearing plate impossible to draw (it floated above
// the sloped surface) and put `h1` on the wrong side of the corbel. Both the outline
// array and the self-tests below have been updated accordingly.
//
// checkCorbelACI318 itself, SHEAR_FRICTION_MU, and requiredFlexuralSteelMM2 are
// UNCHANGED from corbel-geometry.js. `av` still flows only into checkCorbelACI318
// (shear span for applicability/Mu/Nuc checks) -- it does not touch the outline.
//
// STILL NOT ADDRESSED HERE: CES_CORBEL_FORM_SCHEMA has no fcMPa/fyMPa/VuN/NucN
// fields, so checkCorbelACI318 cannot run off that schema alone yet -- aciCheck
// stays optional/null-skippable.

'use strict';

const SHEAR_FRICTION_MU = {
  citation: 'ACI 318-19/318-25(unconfirmed) Table 22.9.4.2, via 16.5.4.4. verified:false.',
  monolithic: 1.4,
  hardenedRoughened: 1.0,
  hardenedNotRoughened: 0.6,
  toStructuralSteel: 0.7,
};

function requiredFlexuralSteelMM2({ MuNmm, phi, fcMPa, fyMPa, bMM, dMM }) {
  const Ru = MuNmm / (phi * bMM * dMM * dMM);
  const inner = 1 - (2 * Ru) / (0.85 * fcMPa);
  if (inner < 0) {
    throw new RangeError('Section cannot resist Mu at this b,d (0.85*fc term went negative) -- increase b, d, or fc');
  }
  const rho = (0.85 * fcMPa / fyMPa) * (1 - Math.sqrt(inner));
  return rho * bMM * dMM;
}

// Unchanged from corbel-geometry.js -- `av` here is, and remains, the shear span.
function checkCorbelACI318({ b, h, d, av, fcMPa, fyMPa, VuN, NucN = 0,
                              muCase = 'monolithic', phi = 0.75,
                              ascProvidedMM2, ahProvidedMM2 }) {
  if (!(b > 0 && h > 0 && d > 0 && d < h && av > 0)) throw new RangeError('invalid b/h/d/av');
  if (!(fcMPa > 0 && fyMPa > 0 && VuN > 0)) throw new RangeError('invalid fcMPa/fyMPa/VuN');
  if (!(NucN >= 0)) throw new RangeError('NucN must be >= 0');
  if (!(muCase in SHEAR_FRICTION_MU)) throw new RangeError(`unknown muCase '${muCase}'`);

  const warnings = [];

  const avOverD = av / d;
  const applicable = avOverD <= 1;
  if (!applicable) {
    warnings.push(`av/d = ${avOverD.toFixed(3)} > 1: outside the 16.5 shear-friction/empirical method's ` +
      'applicability range. This module does not implement strut-and-tie (Ch.23) -- ' +
      'do not use this result; the ticket explicitly forbids substituting beam-stirrup logic here.');
  }

  const minDepthOK = h >= 0.5 * d;
  if (!minDepthOK) {
    warnings.push(`h=${h}mm < 0.5*d=${(0.5 * d).toFixed(1)}mm: fails the 16.5.2 minimum edge-depth check.`);
  }

  const NucMinN = 0.2 * VuN;
  const NucUsedN = Math.max(NucN, NucMinN);
  if (NucN < NucMinN) {
    warnings.push(`Nuc provided (${NucN}N) < 0.2*Vu (${NucMinN}N): using ${NucUsedN}N per 16.5.1 minimum.`);
  }

  const mu = SHEAR_FRICTION_MU[muCase];
  const AvfMM2 = VuN / (phi * fyMPa * mu);
  const AvfMinMM2 = 0.04 * (fcMPa / fyMPa) * b * d;
  if (AvfMM2 < AvfMinMM2) {
    warnings.push(`Avf required by strength (${AvfMM2.toFixed(1)}mm^2) < 22.9.4.1 minimum ` +
      `0.04*(fc/fy)*b*d (${AvfMinMM2.toFixed(1)}mm^2) -- the minimum governs.`);
  }

  const MuNmm = VuN * av + NucUsedN * (h - d);
  const AfMM2 = requiredFlexuralSteelMM2({ MuNmm, phi, fcMPa, fyMPa, bMM: b, dMM: d });
  const AnMM2 = NucUsedN / (phi * fyMPa);

  const AscOption1MM2 = AfMM2 + AnMM2;
  const AscOption2MM2 = (2 / 3) * AvfMM2 + AnMM2;
  const AscReqMM2 = Math.max(AscOption1MM2, AscOption2MM2);
  const AscMinMM2 = 0.04 * (fcMPa / fyMPa) * b * d;
  const AscGovMM2 = Math.max(AscReqMM2, AscMinMM2);

  const AhMinMM2 = 0.5 * (AscGovMM2 - AnMM2);

  const Vn1N = 0.2 * fcMPa * b * d;
  const Vn2N = (3.3 + 0.08 * fcMPa) * b * d;
  const Vn3N = 11 * b * d;
  const VnN = Math.min(Vn1N, Vn2N, Vn3N);
  const phiVnN = phi * VnN;
  const vuOK = VuN <= phiVnN;
  if (!vuOK) {
    warnings.push(`Vu (${VuN}N) exceeds phiVn (${phiVnN.toFixed(0)}N): increase b, d, or fc' -- more Avf will not fix this.`);
  }

  if (ascProvidedMM2 != null && ascProvidedMM2 < AscGovMM2) {
    warnings.push(`Asc provided (${ascProvidedMM2}mm^2) < Asc required (${AscGovMM2.toFixed(1)}mm^2).`);
  }
  if (ahProvidedMM2 != null && ahProvidedMM2 < AhMinMM2) {
    warnings.push(`Ah provided (${ahProvidedMM2}mm^2) < Ah minimum (${AhMinMM2.toFixed(1)}mm^2) per 16.5.5.2.`);
  }

  return {
    avOverD, applicable, minDepthOK, NucUsedN,
    AvfMM2, AvfMinMM2, AfMM2, AnMM2, AscReqMM2, AscMinMM2, AscGovMM2, AhMinMM2,
    Vn1N, Vn2N, Vn3N, VnN, phiVnN, vuOK,
    warnings,
    citation: '16.5.1 (applicability, Nuc>=0.2Vu), 16.5.2 (min depth), 16.5.4.4/22.9.4.2 (Avf), ' +
      '22.9.4.1 (Avf minimum), 16.5.5 (Asc, Asc_min=0.04 fc/fy bd), 16.5.5.2 (Ah>=0.5(Asc-An)). ' +
      'Clause numbers per ACI 318-19/318-14; not confirmed against 318-25 renumbering. verified:false.',
  };
}

function computeCorbelGeometry({ b, h, d, av, projection = av, h1 = null, cover = 40,
                                  ascDiameterMM, ascCount,
                                  ahDiameterMM, ahCount,
                                  bearingPlateWidthMM, bearingPlateLengthMM,
                                  x = 0, y = 0,
                                  aciCheck = null }) {
  if (!(b > 0)) throw new RangeError('b must be > 0');
  if (!(h > 0)) throw new RangeError('h must be > 0');
  if (!(d > 0 && d < h)) throw new RangeError('d must be > 0 and < h');
  if (!(av > 0)) throw new RangeError('av must be > 0');
  if (!(projection > 0)) throw new RangeError('projection must be > 0');
  if (!(projection >= av)) {
    throw new RangeError(`projection (${projection}) must be >= av (${av}) -- the load point cannot sit beyond the corbel's outer tip`);
  }
  if (h1 != null && !(h1 > 0)) throw new RangeError('h1 must be > 0 when provided');
  if (h1 != null && h1 > h) {
    throw new RangeError(`h1 (${h1}) must be <= h (${h}) -- the tip cannot be taller than the column-face section`);
  }
  if (!(cover > 0)) throw new RangeError('cover must be > 0');
  if (cover * 2 >= b) {
    throw new RangeError(`cover (${cover}) * 2 >= b (${b}) -- no clear width remains for Asc bars`);
  }
  if (cover >= h - cover) {
    throw new RangeError(`cover (${cover}) leaves no clear depth in a section of height h (${h})`);
  }
  if (!(ascDiameterMM > 0)) throw new RangeError('ascDiameterMM must be > 0');
  if (!Number.isInteger(ascCount) || ascCount < 2) throw new RangeError('ascCount must be an integer >= 2');
  if (!(ahDiameterMM > 0)) throw new RangeError('ahDiameterMM must be > 0');
  if (!Number.isInteger(ahCount) || ahCount < 1) throw new RangeError('ahCount must be an integer >= 1');
  if (!(bearingPlateWidthMM > 0)) throw new RangeError('bearingPlateWidthMM must be > 0');
  if (!(bearingPlateLengthMM > 0)) throw new RangeError('bearingPlateLengthMM must be > 0');

  const tipHeight = h1 != null ? h1 : d; // fallback == old (pre-fix) tip depth exactly

  // GEOMETRY SHAPE: standard corbel -- horizontal top surface (bearing plate sits on it),
  // vertical column face (full height h), vertical tip face of height tipHeight, sloped
  // bottom from the tip's bottom edge back to the column face's bottom edge.
  //   (x, y)                              -- bottom of column face
  //   (x, y+h)                            -- top of column face (start of horizontal top)
  //   (x+projection, y+h)                 -- top of tip (end of horizontal top)
  //   (x+projection, y+h-tipHeight)       -- bottom of tip (start of sloped bottom)
  // closing edge: (x+projection, y+h-tipHeight) -> (x, y) : sloped bottom.
  // `av` does NOT appear here; it flows only into checkCorbelACI318 below.
  const outline = [
    { x: x, y: y },
    { x: x, y: y + h },
    { x: x + projection, y: y + h },
    { x: x + projection, y: y + h - tipHeight },
  ];

  const ascPositions = [];
  const ascSpacing = ascCount > 1 ? (b - 2 * cover) / (ascCount - 1) : 0;
  for (let i = 0; i < ascCount; i++) {
    ascPositions.push({ zAcrossWidth: cover + ascSpacing * i, yFromTop: cover });
  }

  const tieZoneTopY = h - cover;
  const tieZoneHeight = (2 / 3) * d;
  const tieZoneBottomY = Math.max(cover, tieZoneTopY - tieZoneHeight);
  const ahPositions = [];
  const ahSpacing = ahCount > 1 ? (tieZoneTopY - tieZoneBottomY) / (ahCount - 1) : 0;
  for (let i = 0; i < ahCount; i++) {
    ahPositions.push({ yFromBottom: tieZoneBottomY + ahSpacing * i });
  }

  const ascProvidedMM2 = ascCount * Math.PI * (ascDiameterMM / 2) ** 2;
  const ahProvidedMM2 = ahCount * 2 * Math.PI * (ahDiameterMM / 2) ** 2;

  // av (shear span), not projection, per ACI 318 16.5's own definition -- unaffected
  // by whatever the tip is drawn at.
  let aciResult = null;
  if (aciCheck) {
    aciResult = checkCorbelACI318({ ...aciCheck, b, h, d, av, ascProvidedMM2, ahProvidedMM2 });
  }

  return {
    b, h, d, av, projection, h1: tipHeight, cover, outline,
    asc: { diameterMM: ascDiameterMM, count: ascCount, positions: ascPositions, providedMM2: ascProvidedMM2 },
    ah: {
      diameterMM: ahDiameterMM, count: ahCount, positions: ahPositions, spacingMM: ahSpacing,
      zone: { topY: tieZoneTopY, bottomY: tieZoneBottomY, heightMM: tieZoneTopY - tieZoneBottomY },
      providedMM2: ahProvidedMM2,
    },
    bearingPlate: { widthMM: bearingPlateWidthMM, lengthMM: bearingPlateLengthMM },
    aciResult,
  };
}

module.exports = { computeCorbelGeometry, checkCorbelACI318, requiredFlexuralSteelMM2, SHEAR_FRICTION_MU };

if (require.main === module) {
  let checks = 0, failures = 0;
  const checkNumber = (label, actual, expected, tol = 1e-2) => {
    checks++;
    if (Math.abs(actual - expected) > tol) { failures++; console.error(`FAIL ${label}: expected ${expected}, got ${actual}`); }
    else console.log(`OK   ${label}`);
  };
  const checkTrue = (label, actual) => {
    checks++;
    if (actual !== true) { failures++; console.error(`FAIL ${label}: expected true, got ${actual}`); }
    else console.log(`OK   ${label}`);
  };
  const checkThrows = (label, fn) => {
    checks++;
    try { fn(); failures++; console.error(`FAIL ${label}: expected throw, none occurred`); }
    catch (e) { console.log(`OK   ${label} (threw: ${e.message})`); }
  };

  // --- regression: every corbel-geometry.js check, old call signature (no
  // projection/h1 -- must behave as before apart from the corrected shape) ---
  const geo = computeCorbelGeometry({
    b: 300, h: 400, d: 350, av: 150, cover: 40,
    ascDiameterMM: 20, ascCount: 4,
    ahDiameterMM: 10, ahCount: 4,
    bearingPlateWidthMM: 200, bearingPlateLengthMM: 150,
  });
  checkNumber('ah.zone.heightMM == 2d/3', geo.ah.zone.heightMM, (2 / 3) * 350);
  checkTrue('ah zone bottom is above cover (confined, not full-height)', geo.ah.zone.bottomY > 40);
  checkTrue('every ah tie y is within [zone.bottomY, zone.topY]',
    geo.ah.positions.every((p) => p.yFromBottom >= geo.ah.zone.bottomY - 1e-6 && p.yFromBottom <= geo.ah.zone.topY + 1e-6));
  checkNumber('regression: projection defaults to av when omitted', geo.projection, 150);
  checkNumber('regression: h1 defaults to d when omitted', geo.h1, 350);

  // SHAPE CHECKS (this revision): outline[0]=bottom of column face,
  // outline[1]=top of column face, outline[2]=top of tip, outline[3]=bottom of tip.
  checkNumber('shape: outline[0].x == column face (0)', geo.outline[0].x, 0);
  checkNumber('shape: outline[0].y == 0 (bottom of column face)', geo.outline[0].y, 0);
  checkNumber('shape: outline[1].y == h (top of column face)', geo.outline[1].y, 400);
  checkNumber('shape: outline[2].x == projection', geo.outline[2].x, 150);
  checkNumber('shape: outline[2].y == h (top of tip, horizontal top preserved)', geo.outline[2].y, 400);
  checkNumber('shape: outline[3].x == projection (vertical tip face)', geo.outline[3].x, 150);
  checkNumber('shape: outline[3].y == h - tipHeight (bottom of tip)', geo.outline[3].y, 400 - 350);
  checkTrue('shape: top surface is horizontal (outline[1].y == outline[2].y)',
    Math.abs(geo.outline[1].y - geo.outline[2].y) < 1e-6);
  checkTrue('shape: bottom edge is sloped (outline[0].y != outline[3].y)',
    Math.abs(geo.outline[0].y - geo.outline[3].y) > 1e-6);
  checkTrue('shape: column face is vertical (outline[0].x == outline[1].x)',
    Math.abs(geo.outline[0].x - geo.outline[1].x) < 1e-6);
  checkTrue('shape: tip face is vertical (outline[2].x == outline[3].x)',
    Math.abs(geo.outline[2].x - geo.outline[3].x) < 1e-6);

  const b = 300, h = 400, d = 350, av = 150, fc = 28, fy = 420, Vu = 250000, phi = 0.75, mu = 1.4;
  const NucMin = 0.2 * Vu;
  const Mu = Vu * av + NucMin * (h - d);
  const Ru = Mu / (phi * b * d * d);
  const rho = (0.85 * fc / fy) * (1 - Math.sqrt(1 - (2 * Ru) / (0.85 * fc)));
  const AfExp = rho * b * d;
  const AnExp = NucMin / (phi * fy);
  const AvfExp = Vu / (phi * fy * mu);
  const AscExp = Math.max(AfExp + AnExp, (2 / 3) * AvfExp + AnExp);
  const AscMinExp = 0.04 * (fc / fy) * b * d;
  const AscGovExp = Math.max(AscExp, AscMinExp);
  const AhMinExp = 0.5 * (AscGovExp - AnExp);

  const result = checkCorbelACI318({ b, h, d, av, fcMPa: fc, fyMPa: fy, VuN: Vu, NucN: 0, muCase: 'monolithic', phi });
  checkTrue('avOverD <= 1 applicable', result.applicable === true);
  checkTrue('minDepthOK (h=400 >= 0.5*d=175)', result.minDepthOK === true);
  checkNumber('NucUsedN == 0.2*Vu floor applied', result.NucUsedN, NucMin);
  checkNumber('AvfMM2', result.AvfMM2, AvfExp);
  checkNumber('AvfMinMM2 == 0.04*(fc/fy)*b*d', result.AvfMinMM2, 0.04 * (fc / fy) * b * d);
  checkNumber('AfMM2', result.AfMM2, AfExp);
  checkNumber('AnMM2', result.AnMM2, AnExp);
  checkNumber('AscGovMM2', result.AscGovMM2, AscGovExp);
  checkNumber('AhMinMM2', result.AhMinMM2, AhMinExp);
  checkTrue('vuOK (Vu <= phiVn)', result.vuOK === true);
  checkTrue('warning raised for Nuc<0.2Vu default input', result.warnings.some((w) => w.includes('0.2*Vu')));

  const badGeom = checkCorbelACI318({ b, h, d, av: d * 1.5, fcMPa: fc, fyMPa: fy, VuN: Vu });
  checkTrue('av/d > 1 flagged as not applicable', badGeom.applicable === false);
  checkTrue('av/d > 1 produces a warning', badGeom.warnings.some((w) => w.includes('outside the 16.5')));

  const under = checkCorbelACI318({ b, h, d, av, fcMPa: fc, fyMPa: fy, VuN: Vu, ascProvidedMM2: 100 });
  checkTrue('under-provided Asc triggers a warning', under.warnings.some((w) => w.includes('Asc provided')));

  // --- NEW: projection != av (the real pc_suite case -- bearing plate inboard of the tip) ---
  const geoReal = computeCorbelGeometry({
    b: 400, h: 500, d: 442, av: 200, projection: 350, h1: 300, cover: 40,
    ascDiameterMM: 16, ascCount: 3, ahDiameterMM: 10, ahCount: 2,
    bearingPlateWidthMM: 100, bearingPlateLengthMM: 150,
  });
  checkNumber('projection != av: outline[2].x == projection (350), not av (200)', geoReal.outline[2].x, 350);
  checkNumber('projection != av: outline[2].y == h (500) -- top of tip', geoReal.outline[2].y, 500);
  checkNumber('projection != av: outline[3].x == projection (vertical tip face)', geoReal.outline[3].x, 350);
  checkNumber('projection != av: outline[3].y == h - h1 (200) -- bottom of tip', geoReal.outline[3].y, 200);
  checkNumber('projection != av: outline face.x == 0 (column face, unaffected)', geoReal.outline[0].x, 0);
  checkNumber('projection != av: outline face top.y == h (500)', geoReal.outline[1].y, 500);
  checkTrue('projection != av: top edge horizontal (bearing plate can sit on it)',
    Math.abs(geoReal.outline[1].y - geoReal.outline[2].y) < 1e-6);
  checkTrue('projection != av: bottom edge sloped (tip bottom != face bottom)',
    Math.abs(geoReal.outline[3].y - geoReal.outline[0].y) > 1e-6);

  // av must still be the value that reaches checkCorbelACI318 (shear span), not projection.
  const geoRealChecked = computeCorbelGeometry({
    b: 400, h: 500, d: 442, av: 200, projection: 350, h1: 300, cover: 40,
    ascDiameterMM: 16, ascCount: 3, ahDiameterMM: 10, ahCount: 2,
    bearingPlateWidthMM: 100, bearingPlateLengthMM: 150,
    aciCheck: { fcMPa: 28, fyMPa: 420, VuN: 180000 },
  });
  const expectedAvOverD = 200 / 442; // av, not projection (350/442 would be wrong)
  checkNumber('projection != av: aciResult.avOverD uses av (200), not projection (350)',
    geoRealChecked.aciResult.avOverD, expectedAvOverD);

  // --- validation guards ---
  checkThrows('projection < av is rejected', () => computeCorbelGeometry({
    b: 300, h: 400, d: 350, av: 300, projection: 200, cover: 40,
    ascDiameterMM: 16, ascCount: 2, ahDiameterMM: 8, ahCount: 1,
    bearingPlateWidthMM: 100, bearingPlateLengthMM: 100,
  }));
  checkThrows('h1 <= 0 is rejected', () => computeCorbelGeometry({
    b: 300, h: 400, d: 350, av: 150, h1: -10, cover: 40,
    ascDiameterMM: 16, ascCount: 2, ahDiameterMM: 8, ahCount: 1,
    bearingPlateWidthMM: 100, bearingPlateLengthMM: 100,
  }));
  checkThrows('h1 > h is rejected', () => computeCorbelGeometry({
    b: 300, h: 400, d: 350, av: 150, h1: 500, cover: 40,
    ascDiameterMM: 16, ascCount: 2, ahDiameterMM: 8, ahCount: 1,
    bearingPlateWidthMM: 100, bearingPlateLengthMM: 100,
  }));
  checkThrows('cover <= 0 is rejected', () => computeCorbelGeometry({
    b: 300, h: 400, d: 350, av: 150, cover: 0,
    ascDiameterMM: 16, ascCount: 2, ahDiameterMM: 8, ahCount: 1,
    bearingPlateWidthMM: 100, bearingPlateLengthMM: 100,
  }));
  checkThrows('cover*2 >= b is rejected', () => computeCorbelGeometry({
    b: 300, h: 400, d: 350, av: 150, cover: 160,
    ascDiameterMM: 16, ascCount: 2, ahDiameterMM: 8, ahCount: 1,
    bearingPlateWidthMM: 100, bearingPlateLengthMM: 100,
  }));
  checkThrows('bearingPlateWidthMM <= 0 is rejected', () => computeCorbelGeometry({
    b: 300, h: 400, d: 350, av: 150, cover: 40,
    ascDiameterMM: 16, ascCount: 2, ahDiameterMM: 8, ahCount: 1,
    bearingPlateWidthMM: 0, bearingPlateLengthMM: 100,
  }));
  checkThrows('bearingPlateLengthMM <= 0 is rejected', () => computeCorbelGeometry({
    b: 300, h: 400, d: 350, av: 150, cover: 40,
    ascDiameterMM: 16, ascCount: 2, ahDiameterMM: 8, ahCount: 1,
    bearingPlateWidthMM: 100, bearingPlateLengthMM: -5,
  }));

  console.log(`\n${checks - failures} OK / ${failures} FAIL`);
  process.exitCode = failures ? 1 : 0;
}