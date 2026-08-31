// structuralDrawingDxfKit.mjs
// DXF-native counterpart to structuralDrawingKit.mjs, built against
// برومبت_مسار_تحويل_DXF_v4.md, then generalized under
// برومبت_تحويل_DXF_عام_v1.md. ONE canonical copy shared by every element's
// <element>.dxf.mjs — every element imports from this exact file, none
// gets its own copy. Elements built against this kit so far: shearWallDiagram
// (proof-of-pattern), basementWallDiagram, gradeBeamDiagram, columnDiagram,
// pileCapDiagram, retainingWallDiagram, slabDiagram, slabOpeningDiagram.
// Consolidated from independently-delivered per-element kit copies that
// had each accumulated real, non-conflicting additions (new LAYERS entries,
// two new shared functions) — see each addition's own comment below for
// which element introduced it and why. Every element-specific .dxf.mjs
// import list was checked against this file's exports before merging;
// nothing an element actually imports is missing here.
//
// Hard constraint carried from the prompt: every DXF this kit helps produce
// must be self-sufficient — no XREF, no external HATCH pattern file, no
// external BLOCK reference, no font requiring anything beyond a default
// AutoCAD install. Every function here only emits LINE / LWPOLYLINE
// (closed) / CIRCLE / TEXT / LAYER — nothing else.
//
// Pure math/validation helpers (assert*, toMm/fromMm/fmt, distributeTicks,
// DiagramError, MM_PER_UNIT) are unit-agnostic — imported and re-exported
// unchanged from structuralDrawingKit.mjs, zero duplication, per the
// prompt's function-conversion table.
//
// Not ported here (out of v1 scope, per the prompt's explicit exclusions):
//   hatchDefs, scheduleTable, esc (XML-specific), wrapText/captionLineCount/
//   renderCaptionAt, kitStyleBlock/fontStacks, svgToDataUri, fitScale
//   (superseded here by real-mm coordinates + barDotRadiusMM's own
//   pitch-aware sizing — see the units-decision note below).
//
// Units decision (session confirmation, gate resolved): all TRUE structural
// geometry (outlines, dimension-line endpoints, tie/mesh positions) is
// written as real mm, 1 DXF drawing unit = 1mm, header $INSUNITS =
// Millimeters. This is unchanged from the original proposal. What changed
// on user correction: bar-dot circle radius is NOT literally diaMM/2 — the
// user's own words: "قطر الأسياخ مجرد indication وليس قطر فعلي، لكن يجب
// عمله بحذر حتى لا تتداخل الأسياخ" (the bar diameter shown is an
// indication, not the literal true diameter — but done carefully so bars
// never overlap). barDotRadiusMM() below implements that: never smaller
// than true radius (large bars still show true size), enlarged toward a
// legibility floor for small bars, capped by a safe fraction of the ACTUAL
// on-drawing pitch between neighboring dots (computed live from each
// view's own distributeTicks() output, not from the static schema-floor
// constants) so no two dots can ever visually touch, in any valid input.

export {
  DiagramError,
  MM_PER_UNIT,
  toMm,
  fromMm,
  fmt,
  assertFinitePositive,
  assertFiniteNonNegative,
  assertInt,
  assertOneOf,
  assertNoIntervalOverlap,
  distributeTicks,
} from './structuralDrawingKit.mjs';

import {
  DxfWriter as _DxfWriter,
  point3d,
  Units,
  TrueColor,
  LWPolylineFlags,
  TextHorizontalAlignment,
  TextVerticalAlignment,
} from './tarikjabiri-dxf.esm.js';
// DiagramError imported locally (not just re-exported) because a bare
// `export { DiagramError, ... } from './structuralDrawingKit.mjs'` above
// creates NO local binding in this module's own scope — it only forwards
// the name to callers of *this* file. Any `throw new DiagramError(...)`
// written directly inside this file's own function bodies was therefore
// resolving to an undefined identifier at runtime (a silent ReferenceError
// instead of the intended typed error), never caught because no existing
// test exercises a kit-function guard clause with deliberately invalid
// input — every element passes it valid geometry. Found while adding
// openPolylineDXF below (built on the same direct-throw pattern as
// closedPolylineDXF, which already carried this exact latent defect);
// fixed here for both functions in one pass, same file/root cause/fix.
import { DiagramError, assertFinitePositive as assertFinitePositiveMM } from './structuralDrawingKit.mjs';

// Re-export so callers never need a second import from the underlying
// library just to construct a writer / call setUnits.
export { point3d, Units };
export const DxfWriter = _DxfWriter;

// ── Layer table ─────────────────────────────────────────────────────
// Every hex value below is copied verbatim from the v4 prompt's verified
// grep-scan layer table (شعبة "الطبقات عبر كل المكتبة"), restricted to the
// layers shearWallDiagram.mjs actually uses. Colors marked "convention"
// were not in that table (no single fixed color given) — chosen defaults,
// not verified project values; change freely.
export const LAYERS = Object.freeze({
  REBAR_TOP: { name: 'REBAR-TOP', hex: '#1f5aa6' }, // bar-dot-shearwall, bar-top
  REBAR_BOTTOM: { name: 'REBAR-BOTTOM', hex: '#c0392b' }, // bar-bottom
  CONCRETE_OUTLINE: { name: 'CONCRETE-OUTLINE', hex: '#1a1a1a' }, // concrete-outline (stroke color; #f4f4f4 fill has no meaning for an unfilled LWPolyline — HATCH is v1-excluded anyway)
  STIRRUP_TIE: { name: 'STIRRUP-TIE', hex: '#2f7a3d' }, // stirrup-outline, stirrup-tick
  ZONE_LABEL: { name: 'ZONE-LABEL', hex: '#8a6d00' }, // zone-label — already this element's confirmed color pre-unification
  MARK_TAGS: { name: 'MARK-TAGS', hex: '#000000' }, // "white/black neutral" per prompt table — black chosen for visibility on white background
  DIMENSIONS: { name: 'DIMENSIONS', hex: '#333333' }, // dim-line/dim-tick/dim-label
  ANNOTATION: { name: 'ANNOTATION', hex: '#111111' }, // view-title etc. — prompt table says color "varies"; also used for support-label, which has NO confirmed CSS rule in either source file (verified: grep found zero rule for .support-label) — flagged, not a table-confirmed assignment.

  // ── basementWallDiagram additions (برومبت_تحويل_DXF_عام_v1.md's layer table) ──
  REBAR_HORIZONTAL: { name: 'REBAR-HORIZONTAL', hex: '#6c3fa0' }, // bar-dot-horiz (basementWallDiagram). Table: "purple, NEW — not STIRRUP-TIE's green". Verified directly against basementWallDiagram.mjs's own style block: .bar-dot-horiz is ACTUALLY #2f7a3d there (STIRRUP-TIE's exact color) — an SVG/DXF divergence, not a scan error: the shared multi-element DXF layer table keeps basement-wall horizontal steel and stirrup/tie confinement marks separable (toggle one without the other in a combined drawing set), even though the single-element SVG happened to reuse one green for both. Followed as already-decided per that table, not re-litigated here.
  REBAR_EXTRA: { name: 'REBAR-EXTRA', hex: '#d68910' }, // bar-dot-extra (basementWallDiagram). Table lists a fill/stroke pair #d68910/#8a5a09 — fill taken as canonical, same convention already used for REBAR-TOP/REBAR-BOTTOM above (each stores only its SVG source's fill value, never the separate stroke shade).
  SOIL: { name: 'SOIL', hex: '#8a7350' }, // basementWallDiagram's backfill block. NOT in برومبت_تحويل_DXF_عام_v1.md's layer table (new finding, flagged here rather than guessed) — the SVG source's soil <rect> carries no CSS class at all (inline fill="url(#soilHatch)" stroke="#8a7350"), so there is nothing to cross-reference. HATCH fill is v1-excluded (same as CONCRETE-OUTLINE's own fill) — this layer draws the zone as an outline only, colored with the SVG source's own stroke hex.

  // NEW — added for columnDiagram.dxf.mjs. columnDiagram.mjs's
  // renderElevationView draws the lap-splice zone as an inline-styled
  // <rect fill="#fff3cd" fill-opacity="0.55" stroke="#b8860b" ... /> with
  // NO CSS class — not in the v1 prompt's pre-scanned layer table (that
  // scan predates columnDiagram's own DXF session). Not a table-confirmed
  // assignment; flagged per session-protocol step 4 for confirmation.
  // Color is the SVG source's own literal stroke="#b8860b", read directly
  // from columnDiagram.mjs, not guessed. Fill/opacity dropped — same v1
  // HATCH-exclusion policy CONCRETE_OUTLINE's own comment above already
  // documents (outline only; no fill semantics without HATCH, out of v1).
  LAP_ZONE: { name: 'LAP-ZONE', hex: '#b8860b' },

  // ── Added for gradeBeamDiagram ──
  // The master layer table lists "NODE-MARKER / BEARING-LABEL" as
  // gradeBeamDiagram-only with color "—" (unconfirmed) — these two hex
  // values are NOT invented: both are copied verbatim from
  // gradeBeamDiagram.mjs's own SVG <style> block / inline attributes.
  NODE_MARKER: { name: 'NODE-MARKER', hex: '#333333' }, // matches gradeBeamDiagram.mjs's .node-marker{fill:#333} and .node-label{fill:#333} — one DXF layer color for both the marker outline and its label text (.node-marker also has stroke:#111, a separate value SVG can express and DXF's single-color-per-layer model cannot; #333 chosen as the shared value already used by fill AND the label, same "stroke real, fill/duplicate-value collapsed to one layer color" precedent CONCRETE-OUTLINE already sets). FLAGGED — not a table-confirmed hex, pending confirmation like the master table's own "—" marks it.
  BEARING_LABEL: { name: 'BEARING-LABEL', hex: '#8a7350' }, // matches the continuous soil-bearing strip rect's own inline stroke="#8a7350" in gradeBeamDiagram.mjs (the .bearing-label CSS class itself uses a different fill, #6b5a3d, for the caption text only — the strip's real drawn boundary takes precedence for the shared layer color, same reasoning). FLAGGED — not a table-confirmed hex.

  // Added for pileCapDiagram. Master layer table entry:
  // "PILE | #dfe9f5/#2a5a8c | pile-circle (pileCapDiagram, raftPileDiagram)".
  // Same fill/stroke-pair convention as CONCRETE_OUTLINE above: DXF
  // entities here are unfilled LWPOLYLINE/CIRCLE (no HATCH in v1), so the
  // fill half (#dfe9f5) has no renderable meaning — the stroke half
  // (#2a5a8c) is the one carried onto the layer, identical precedent to
  // CONCRETE_OUTLINE taking #1a1a1a (stroke) over #f4f4f4/#e2e2e2 (fill).
  PILE: { name: 'PILE', hex: '#2a5a8c' },

  // Added for corbelDiagram. Master layer table entry:
  // "BEARING-PLATE | نفس PILE بالضبط، اسم مستقل | plate-rect (corbelDiagram)".
  // Independent layer NAME per that table's own explicit instruction
  // ("اسم مستقل") despite the identical hex — kept togglable separately
  // from actual PILE entities in any combined drawing set (a corbel's
  // bearing plate and a pile cap's piles are unrelated members that could
  // both appear on one sheet). Same fill/stroke-pair convention as PILE
  // itself: corbelDiagram.mjs's own .plate-rect is `fill:#dfe9f5;
  // stroke:#2a5a8c` — stroke half taken, identical precedent.
  BEARING_PLATE: { name: 'BEARING-PLATE', hex: '#2a5a8c' },

  // Added for slabOpeningDiagram (element-specific per the prompt's own
  // table: "OPENING-TRIM ... independent of REBAR-EXTRA despite color
  // proximity"). #e67e22 verified directly against slabOpeningDiagram.mjs's
  // own style block: `.bar-dot-slabopening-trim { fill:#e67e22;
  // stroke:#a15c14; ... }` — the FILL value, matching this table's own
  // established convention (REBAR_BOTTOM's #c0392b above is likewise
  // .bar-dot-slab-bottom's fill, not its stroke). Independent layer name per
  // the prompt table's explicit instruction — never merge with REBAR_EXTRA.
  OPENING_TRIM: { name: 'OPENING-TRIM', hex: '#e67e22' }, // bar-dot-slabopening-trim (slabOpeningDiagram only)

  // Added for flatSlabDropPanelDiagram. Master layer table entry:
  // "CRITICAL-PERIMETER | #b23b3b (\u0645\u0648\u062d\u0651\u062f) | crit-rect, crit-label
  // (punchingShearDiagram), crit-line (flatSlabDropPanelDiagram)" — hex
  // taken from the table's own already-decided ("\u0645\u0648\u062d\u0651\u062f" = unified)
  // value, NOT from flatSlabDropPanelDiagram.mjs's own literal CSS
  // (verified directly: that file's `.crit-line` rule is actually
  // `stroke:#b8860b`, an unrelated color, coincidentally identical to
  // this kit's own LAP_ZONE hex). Same precedent as ZONE_LABEL above
  // (also marked "\u0645\u0648\u062d\u0651\u062f" in the table, and already
  // implemented here at the table's own value rather than any one
  // element's individual source color) — a table entry explicitly
  // flagged as unified is the cross-element decision, not a per-element
  // CSS scan result, and takes precedence over a single source file's
  // own literal (and here, evidently pre-unification) styling.
  CRITICAL_PERIMETER: { name: 'CRITICAL-PERIMETER', hex: '#b23b3b' },

  // Added for hordiSlabDiagram.dxf.mjs. That file's own header claims this
  // entry was "added to the shared kit" but the addition was never actually
  // made here — confirmed by executing hordiSlabDiagram.dxf.mjs against the
  // kit as delivered: it throws "Cannot read properties of undefined
  // (reading 'name')" at LAYERS.BLOCK.name, not a logic failure, the same
  // class of described-but-never-merged gap DASHED_LTYPE_NAME's own
  // addition comment above already documents for a different file. Hex is
  // hordiSlabDiagram.mjs's own `.block-outline { fill:url(#hordiBlockHatch);
  // stroke:#8a7a52; ... }` stroke value (fill is a HATCH pattern reference,
  // meaningless without HATCH, v1-excluded — same fill/stroke-pair
  // precedent CONCRETE_OUTLINE/PILE/BEARING_PLATE above already follow).
  BLOCK: { name: 'BLOCK', hex: '#8a7a52' },

  // Added for wallOpeningDiagram. wallOpeningDiagram.mjs's own local
  // .diagonal-bar rule: `stroke:#c0392b; stroke-width:2; fill:none;`
  // (verified directly against that file's <style> block) — identical hex
  // to REBAR_BOTTOM, but a genuinely distinct reinforcement group (corner
  // crack-control diagonals vs. the opening's horizontal/vertical trim
  // bars) that must stay independently toggleable in a combined drawing
  // set — same "same hex, independent name" precedent BEARING_PLATE
  // already established against PILE above.
  DIAGONAL_BAR: { name: 'DIAGONAL-BAR', hex: '#c0392b' },

  // ── Added for beamColumnJointDiagram.dxf.mjs — session-explicit gate
  // resolved (برومبت_تحويل_DXF_عام_v1.md's own "خارج النطاق" list named
  // joint-core-zone/hinge-zone as needing a separate explicit decision;
  // this is that decision, made this session, not carried over from any
  // prior undocumented default). Both are the elevation's two schematic
  // zone RECTANGLES only (.joint-core-zone / .hinge-zone in
  // beamColumnJointDiagram.mjs's own style block) — outline + this kit's
  // existing DASHED_LTYPE_NAME (matching each class's own
  // stroke-dasharray), fill dropped per the same v1 HATCH-exclusion
  // CONCRETE_OUTLINE's own comment above already documents (the SVG's
  // fill-opacity:0.55/0.6 tint has no unfilled-LWPolyline equivalent).
  // Hex copied verbatim from each class's own literal stroke: .joint-core
  // -zone stroke:#1f5aa6 (identical to REBAR_TOP), .hinge-zone
  // stroke:#b23b3b (identical to CRITICAL_PERIMETER) — independent names
  // per the established BEARING_PLATE/PILE and DIAGONAL_BAR/REBAR_BOTTOM
  // precedent above (same hex, but a genuinely distinct marker — a zone
  // boundary, not a bar or a critical-section line — that must stay
  // independently toggleable in a combined drawing set). The zone
  // CAPTION text (.zone-caption/.hinge-caption, a different class from
  // either rect) is NOT this layer — see beamColumnJointDiagram.dxf.mjs's
  // own header for that routing decision (ZONE_LABEL, per this table's
  // already-established "unified regardless of a source file's own
  // literal caption color" convention ZONE_LABEL's own entry above and
  // CRITICAL_PERIMETER's own comment both already document).
  JOINT_CORE_ZONE: { name: 'JOINT-CORE-ZONE', hex: '#1f5aa6' },
  HINGE_ZONE: { name: 'HINGE-ZONE', hex: '#b23b3b' },

  // ── Added for raftPileDiagram.dxf.mjs. raftPileDiagram.mjs's own plan
  // view draws its bottom mesh as CONTINUOUS full-span lines directly
  // (`mesh.long`/`mesh.short` barCentersMM, one <line> per center, inline
  // `stroke="#9ab3cf" stroke-width="0.8"`) — genuinely different from
  // every other element's own bar-DOT mesh (shearWallDiagram, pileCap,
  // etc.), and with no CSS class at all (verified directly against this
  // file's own render function, same "no class, read the inline stroke
  // literally" precedent SOIL's own comment above documents). The file's
  // own DECLARED-but-unused `.bar-dot-mesh{fill:#1f5aa6}` class (matching
  // REBAR_TOP) is dead styling — barDot()/that class is never actually
  // called anywhere in raftPileDiagram.mjs's renderPlan; grepped directly
  // before writing this, not assumed from the master table's own
  // pre-session "bar-dot-mesh (pileCap and raftPile)" listing, which
  // predates this file's actual read and does not hold for THIS file's
  // real drawing method. #9ab3cf does not match any existing layer hex,
  // so a new layer is needed, not a reuse.
  REBAR_MESH_LINE: { name: 'REBAR-MESH-LINE', hex: '#9ab3cf' },

  // Added for punchingShearDiagram.dxf.mjs. That file's own header claims
  // both entries were "added to the shared kit" but neither addition was
  // ever actually made here — confirmed by executing
  // punchingShearDiagram.dxf.mjs against the kit as delivered: it throws
  // "Cannot read properties of undefined (reading 'name')" at
  // LAYERS.RAIL_LINE.name, the same class of described-but-never-merged
  // gap DASHED_LTYPE_NAME's and BLOCK's own addition comments above
  // already document. Hex values are punchingShearDiagram.mjs's own
  // literal style-block rules, read directly: `.stud-dot{fill:#1f5aa6;...}`
  // (fill, same dot-entity convention REBAR_TOP/OPENING_TRIM already
  // follow) and `.rail-line{stroke:#2a5a8c;...}` (stroke, same line-entity
  // convention PILE/BEARING_PLATE already follow — the shared hex with
  // those two is coincidental, not a reuse decision).
  SHEAR_STUDS: { name: 'SHEAR-STUDS', hex: '#1f5aa6' },
  RAIL_LINE: { name: 'RAIL-LINE', hex: '#2a5a8c' },
});

const ACI_FALLBACK = {
  REBAR_TOP: 5, REBAR_BOTTOM: 1, CONCRETE_OUTLINE: 8, STIRRUP_TIE: 3,
  ZONE_LABEL: 2, MARK_TAGS: 7, DIMENSIONS: 8, ANNOTATION: 8,
  REBAR_HORIZONTAL: 6, REBAR_EXTRA: 2, SOIL: 8, LAP_ZONE: 2,
  NODE_MARKER: 8, BEARING_LABEL: 8, PILE: 5, OPENING_TRIM: 2,
  BEARING_PLATE: 5,
  CRITICAL_PERIMETER: 1, // red family, same ACI index as REBAR_BOTTOM — hue-matched to #b23b3b
  BLOCK: 8, // grey/tan family, same ACI index as SOIL — hue-matched to #8a7a52 (SOIL's #8a7350 is the closest existing table entry)
  DIAGONAL_BAR: 1, // red family, same ACI index as REBAR_BOTTOM — hue-matched to #c0392b
  JOINT_CORE_ZONE: 5, // blue family, same ACI index as REBAR_TOP/PILE/BEARING_PLATE — hue-matched to #1f5aa6
  HINGE_ZONE: 1, // red family, same ACI index as REBAR_BOTTOM/CRITICAL_PERIMETER/DIAGONAL_BAR — hue-matched to #b23b3b
  REBAR_MESH_LINE: 5, // blue family, same ACI index as REBAR_TOP/PILE/BEARING_PLATE/JOINT_CORE_ZONE — hue-matched to #9ab3cf
  SHEAR_STUDS: 5, // blue family, same ACI index as REBAR_TOP — hue-matched to #1f5aa6
  RAIL_LINE: 5, // blue family, same ACI index as PILE/BEARING_PLATE — hue-matched to #2a5a8c
};

/** Create every layer this kit uses on the given DxfWriter, with an exact
 * TrueColor match to the hex above and a hue-matched ACI fallback for any
 * pre-2004 DXF reader that ignores true color. Call once per document,
 * before adding entities. */
export function defineDxfLayers(dxf) {
  const created = {};
  for (const key of Object.keys(LAYERS)) {
    const { name, hex } = LAYERS[key];
    const layer = dxf.addLayer(name, ACI_FALLBACK[key] ?? 7, 'Continuous');
    layer.trueColor = TrueColor.fromHex(hex);
    created[key] = layer;
  }
  return created;
}

// ── Dashed linetype (section-cut markers, overlay/marker distinctions) ──
// Added for trapezoidalFootingDiagram.dxf.mjs's plan-view section-cut
// marker line (a real material edge must read as solid; a cut-plane
// marker is conventionally dashed — same distinction the master prompt's
// own layer table calls out for strap-outline: "ميّزها بنمط خط DXF
// متقطع، لا تدمجها بصرياً"). ALSO closes a pre-existing gap: this exact
// name pair (DASHED_LTYPE_NAME/defineDashedLType) was already being
// imported by footingDiagram.dxf.mjs and referenced in
// test_footingDiagramDXF.mjs before this addition, but neither export
// actually existed anywhere in this kit file (confirmed by executing
// test_footingDiagramDXF.mjs against the kit as delivered: it fails at
// import time with "does not provide an export named
// 'DASHED_LTYPE_NAME'", not a logic failure) — that file's own session
// apparently added local kit content that was never merged, the same
// per-session-private-kit-copy problem this master prompt's own rules
// section documents and forbids. This addition supplies the missing
// symbols under their already-established names so that existing,
// already-written import is satisfied without editing
// footingDiagram.dxf.mjs itself (out of this session's scope).
//
// Mechanics verified by executing @tarikjabiri/dxf@2.8.9 directly before
// writing this (not assumed from its .d.ts, whose own comment on
// addLType's `elements` parameter admits uncertainty): DxfWriter.addLType
// (name, descriptive, elements) registers a TABLES/LTYPE record where
// `elements` is literally the dash-pattern array in real drawing units —
// positive = pen-down segment length, negative = pen-up (gap) length,
// matching the standard DXF LTYPE convention; group 40 (total pattern
// length) is computed automatically as the sum of absolute values, no
// caller math needed. A LINE/LWPOLYLINE entity's own `lineType` option
// (group 6) is written verbatim regardless of whether that name is
// registered — entities do NOT get DxfLayerTable.addLayer()'s silent
// fallback-to-Continuous safety net (that fallback only fires for a
// LAYER's own default linetype, a different code path) — so addLType()
// must run before any entity references the name, or the reference
// dangles. Confirmed round-trip: a LINE written with
// lineType:'DASHED' after calling defineDashedLType(dxf) parses back
// via the independent `dxf` package with lineTypeName:'DASHED' intact.
export const DASHED_LTYPE_NAME = 'DASHED';
export const DASHED_PATTERN_MM = [150, -90]; // 150mm dash / 90mm gap, real mm — reads as a clear, unambiguous void at a typical 1:50 structural plot scale (3mm dash / 1.8mm gap on paper), same "named real-mm constant, not a bare px-derived guess" convention every other layout constant in this kit already follows

export function defineDashedLType(dxf) {
  return dxf.addLType(DASHED_LTYPE_NAME, '__ __ __ __', DASHED_PATTERN_MM);
}

// ── Text control-code escaping ─────────────────────────────────────
// DXF TEXT (group 1) predates reliable cross-version Unicode support in
// every AutoCAD-compatible reader; the portable, decades-stable way to
// get a diameter/degree/plus-minus glyph in ANY default AutoCAD install
// is the %%c / %%d / %%p control codes, not a raw Unicode character. `%`
// itself is the control-code lead-in and must be doubled if it occurs
// literally. This is the DXF-format analogue of esc() (which is
// XML-specific and not ported here per the conversion table).
export function escDxfText(s) {
  return String(s)
    .replace(/%/g, '%%%')
    .replace(/\u00d8/g, '%%c')
    .replace(/\u00b0/g, '%%d')
    .replace(/\u00b1/g, '%%p');
}

// ── Centered/justified TEXT helper ─────────────────────────────────
// Verified empirically against @tarikjabiri/dxf@2.8.9's actual output
// (not assumed from its .d.ts): setting horizontalAlignment/
// verticalAlignment WITHOUT also passing secondAlignmentPoint writes DXF
// group codes 72/73 with NO group 11/21/31 at all — an independent parser
// (dxf@5.3.1) round-trips that as an anchor of (0,0,0), i.e. the
// justification silently breaks. Group 11/21/31 (the "second alignment
// point") is where AutoCAD actually reads the anchor from whenever 72 or
// 73 is non-default. This helper always sets it, so every non-left/
// non-baseline label in this kit renders where it's told to.
export function dxfText(dxf, x, y, heightMM, text, opts = {}) {
  assertFinitePositiveMM('heightMM', heightMM);
  const hAlign = opts.hAlign ?? TextHorizontalAlignment.Left;
  const vAlign = opts.vAlign ?? TextVerticalAlignment.BaseLine;
  const needsAnchor = hAlign !== TextHorizontalAlignment.Left || vAlign !== TextVerticalAlignment.BaseLine;
  return dxf.addText(point3d(x, y), heightMM, escDxfText(text), {
    layerName: opts.layerName,
    horizontalAlignment: hAlign,
    verticalAlignment: vAlign,
    ...(needsAnchor ? { secondAlignmentPoint: point3d(x, y) } : {}),
  });
}

// ── Closed rectangle (concrete outline / boundary element / section strip) ──
// DXF equivalent of an SVG <rect>: a 4-vertex closed LWPolyline. There is
// no native DXF "rectangle" primitive; LWPOLYLINE with the Closed flag is
// the standard, universally-supported way to draw one.
export function closedRectDXF(dxf, x, y, w, h, layerName, opts = {}) {
  assertFinitePositiveMM('w', w);
  assertFinitePositiveMM('h', h);
  const options = { layerName, flags: LWPolylineFlags.Closed };
  if (opts.lineType) options.lineType = opts.lineType;
  return dxf.addLWPolyline(
    [
      { point: { x, y } },
      { point: { x: x + w, y } },
      { point: { x: x + w, y: y + h } },
      { point: { x, y: y + h } },
    ],
    options,
  );
}

// ── Bar-dot radius (see units-decision note at top of file) ───────────
export const BAR_DOT_MIN_VISIBLE_MM = 12.5; // legibility floor for small bars — ~0.25mm on paper at a common 1:50 structural-elevation plot scale (convention, overridable)
export const BAR_DOT_MAX_FRACTION_OF_PITCH = 0.35; // radius never exceeds this fraction of the ACTUAL neighbor-to-neighbor spacing on this specific drawing — even at the schema's tightest floor (MIN_MESH_SPACING_MM=75mm) this leaves a >40mm gap between adjacent dot edges

export function barDotRadiusMM(diaMM, pitchMM, opts = {}) {
  assertFinitePositiveMM('diaMM', diaMM);
  const trueR = diaMM / 2;
  if (!Number.isFinite(pitchMM) || pitchMM <= 0) return trueR; // no neighbor-distance known — draw true size, nothing to collide with
  const minVisibleR = opts.minVisibleR ?? BAR_DOT_MIN_VISIBLE_MM;
  const maxSafeR = pitchMM * (opts.maxFractionOfPitch ?? BAR_DOT_MAX_FRACTION_OF_PITCH);
  // BUGFIX (execution-verified during reconciliation): the previous
  // `Math.max(trueR, Math.min(minVisibleR, maxSafeR))` let trueR escape the
  // pitch cap whenever a bar was large enough that trueR > maxSafeR —
  // reachable via e.g. thicknessMM:150/coverMM:74/dia:32 (2mm real gap),
  // reproducing a 30mm circle overlap. Every one of this session's 7 new
  // elements independently re-discovered this same property and chose to
  // route around it with "safe" fixture values rather than fix the shared
  // function — capping trueR itself (not just the legibility floor) makes
  // the bound unconditional without weakening the "large bar draws true
  // size when pitch allows it" guarantee those elements also rely on: this
  // only changes behavior in the specific case where trueR already
  // violated the pitch margin, which is exactly the case that must be
  // capped. Re-verified against all 8 elements' suites below, not just
  // shearWall's.
  return Math.min(Math.max(trueR, minVisibleR), maxSafeR);
}

/** CIRCLE marker for one bar/mesh-intersection point. pitchMM must be the
 * REAL on-drawing distance to this dot's nearest drawn neighbor (the
 * caller derives this from its own distributeTicks() output — see
 * shearWallDiagram.dxf.mjs) — not a schema constant, so the collision
 * guarantee holds for the specific geometry actually being drawn. */
export function barDotDXF(dxf, cx, cy, diaMM, pitchMM, layerName, opts = {}) {
  const r = barDotRadiusMM(diaMM, pitchMM, opts);
  return dxf.addCircle(point3d(cx, cy), r, { layerName });
}

// ── Tie tick (boundary-element confinement mark) ───────────────────
// Verified against the actual tieTickH() source in structuralDrawingKit.mjs
// (re-read directly, not from memory) before writing this: it draws THREE
// segments — one main line from (xLeft,y) to (xRight,y), plus a short
// vertical end-cap hash at xLeft and another at xRight, each spanning
// (y-cap) to (y+cap). All three carry the same class or layer. Direct
// entity-for-entity translation below, real-mm cap length instead of the
// original's 4px (px had no fixed mm meaning to convert).
export const TICK_CAP_MM = 40; // convention — a clearly visible end-cap length at typical structural-elevation plot scale; overridable via opts.capMM

export function tieTickHDXF(dxf, xLeftMM, xRightMM, yMM, layerName, opts = {}) {
  const cap = opts.capMM ?? TICK_CAP_MM;
  return {
    main: dxf.addLine(point3d(xLeftMM, yMM), point3d(xRightMM, yMM), { layerName }),
    capLeft: dxf.addLine(point3d(xLeftMM, yMM - cap), point3d(xLeftMM, yMM + cap), { layerName }),
    capRight: dxf.addLine(point3d(xRightMM, yMM - cap), point3d(xRightMM, yMM + cap), { layerName }),
  };
}

// ── Stirrup tick, vertical orientation (horizontally-running member) ──
// Added for corbelDiagram. Rotated counterpart of tieTickHDXF above: that
// function's main line is HORIZONTAL with vertical end-caps, correct for
// a VERTICAL member (e.g. a column, where ties wrap a horizontal band).
// A corbel is the opposite orientation — a horizontally-running
// cantilever whose closed ties (Ah) cross the member's VERTICAL depth —
// so the tick itself must be a vertical main line with HORIZONTAL
// end-caps. Direct entity-for-entity translation of the existing SVG
// stirrupTick(xPx,yTopPx,yBottomPx) in structuralDrawingKit.mjs (verified
// against that source before writing this, not assumed from the name):
// one vertical line from (x,yTop) to (x,yBottom), plus a short horizontal
// end-cap hash at yTop and another at yBottom, each spanning (x-cap) to
// (x+cap). Reuses this kit's own TICK_CAP_MM (same "clearly visible
// end-cap length" default already established for tieTickHDXF) rather
// than a second cap-length constant — the visual cap size has no reason
// to differ by tick orientation.
export function stirrupTickVDXF(dxf, xMM, yTopMM, yBottomMM, layerName, opts = {}) {
  const cap = opts.capMM ?? TICK_CAP_MM;
  return {
    main: dxf.addLine(point3d(xMM, yTopMM), point3d(xMM, yBottomMM), { layerName }),
    capTop: dxf.addLine(point3d(xMM - cap, yTopMM), point3d(xMM + cap, yTopMM), { layerName }),
    capBottom: dxf.addLine(point3d(xMM - cap, yBottomMM), point3d(xMM + cap, yBottomMM), { layerName }),
  };
}

// ── Bar mark tag (leader bubble + text) ─────────────────────────────
export const MARK_TAG_RADIUS_MM = 150; // convention — legible bubble at typical plot scale (150mm / 50 = 3mm on paper at 1:50); overridable via opts.r

export function barMarkTagDXF(dxf, x, y, markText, layerName, opts = {}) {
  const r = opts.r ?? MARK_TAG_RADIUS_MM;
  const entities = { circle: dxf.addCircle(point3d(x, y), r, { layerName }) };
  entities.text = dxfText(dxf, x, y, opts.textHeightMM ?? r * 0.6, markText, {
    layerName,
    hAlign: TextHorizontalAlignment.Center,
    vAlign: TextVerticalAlignment.Middle,
  });
  if (opts.leaderTo) {
    entities.leader = dxf.addLine(point3d(x, y), point3d(opts.leaderTo.x, opts.leaderTo.y), { layerName });
  }
  return entities;
}

// ── Dimension line (main line + optional end ticks + centered label) ──
// Direct entity-for-entity translation of the SVG dimensionLine()'s own
// hand-drawn composition (a plain line + short end ticks + text) — NOT
// a native DXF DIMENSION entity, which would need its own DIMSTYLE table
// definition (arrow size, extension offsets, text format) the original
// function never had either. Parity with the existing function's actual
// behavior, not a "smarter" replacement.
// Re-verified against the actual dimensionLine() source before writing
// this (caught two mismatches from an earlier, unverified draft — see
// git history if this ever moves to one — so noting the correction here
// explicitly): (1) the two end ticks are ALWAYS vertical segments at
// (x,y-tick)-(x,y+tick), regardless of orientation — there is no
// perpendicular-to-the-line branching in the source; (2) the label's
// position AND alignment differ by orientation — 'h' centers the label
// above the line's midpoint; 'v' right-aligns it to the left of the
// line's midpoint, not centered on it. Both replicated exactly below.
export const LABEL_GAP_MM = 120; // convention — mm-space analogue of the SVG version's small px label offsets (6/10/4px, which had no fixed physical size); overridable via opts.labelGapMM

export function dimensionLineDXF(dxf, x1, y1, x2, y2, label, opts = {}) {
  const layerName = LAYERS.DIMENSIONS.name;
  const orientation = opts.orientation || (Math.abs(x1 - x2) >= Math.abs(y1 - y2) ? 'h' : 'v');
  const tick = opts.tick ?? TICK_CAP_MM; // mm-space default — the original's px default (6) does not carry over as a unit
  const gap = opts.labelGapMM ?? LABEL_GAP_MM;
  const textHeightMM = opts.textHeightMM ?? 150;

  const entities = { main: dxf.addLine(point3d(x1, y1), point3d(x2, y2), { layerName }) };
  if (tick > 0) {
    entities.tick1 = dxf.addLine(point3d(x1, y1 - tick), point3d(x1, y1 + tick), { layerName });
    entities.tick2 = dxf.addLine(point3d(x2, y2 - tick), point3d(x2, y2 + tick), { layerName });
  }

  const midX = (x1 + x2) / 2, midY = (y1 + y2) / 2;
  entities.label = orientation === 'h'
    ? dxfText(dxf, midX, midY + gap, textHeightMM, label, { layerName, hAlign: TextHorizontalAlignment.Center, vAlign: TextVerticalAlignment.Bottom })
    : dxfText(dxf, midX - gap, midY, textHeightMM, label, { layerName, hAlign: TextHorizontalAlignment.Right, vAlign: TextVerticalAlignment.Middle });
  return entities;
}

// ── Closed N-vertex polygon (arbitrary outline shape) ──────────────────
// Added for gradeBeamDiagram's node-marker triangle (DXF has no native
// filled-triangle entity, and HATCH is v1-excluded — same "unfilled
// closed LWPolyline" treatment closedRectDXF already gives the concrete
// outline). Written generically (N points, not triangle-specific) per
// this kit's own stated growth pattern: "عنصر جديد يحتاج دالة غير موجودة
// بالأعلى ... تُضاف كدالة جديدة بهذا الملف المشترك" — a future element
// needing any other non-rectangular outline (e.g. a plate chamfer) reuses
// this instead of a second narrowly-scoped function. closedRectDXF itself
// is left untouched (not refactored to call this) to avoid touching
// already-verified, already-passing code for an unrelated change.
export function closedPolylineDXF(dxf, points, layerName) {
  if (!Array.isArray(points) || points.length < 3) {
    throw new DiagramError('BAD_PARAM', 'closedPolylineDXF requires at least 3 points.');
  }
  return dxf.addLWPolyline(
    points.map((p) => ({ point: { x: p.x, y: p.y } })),
    { layerName, flags: LWPolylineFlags.Closed },
  );
}

// ── Open N-vertex polyline (unclosed multi-vertex line) ────────────────
// Promoted to a shared kit function at explicit user request this session.
// v2 of the master prompt (see stairDiagram/corbelDiagram discoveries)
// deliberately did NOT add this when stairDiagram first needed an open
// polyline — its own text: a single-use composite doesn't justify a kit
// function, "لو تكرر باكثر من عنصر مستقبلاً يستحق حينها دالة كيت
// openPolylineDXF" (worth a kit function once a SECOND element needs it).
// Grepped every .dxf.mjs currently in this vendor delivery (16 element
// files) for direct LWPolylineFlags/addLWPolyline usage before writing
// this: stairDiagram.dxf.mjs is still the only one — no second consuming
// element is present in this session's inputs to name here. This addition
// is therefore NOT independently verified against that recurrence gate;
// it is added because it was explicitly requested, not because a second
// caller was confirmed. If/when a second element's session actually
// consumes this, replace this paragraph with that element's name per the
// convention every other entry in this file follows (BEARING_PLATE,
// stirrupTickVDXF, etc.). stairDiagram.dxf.mjs itself is UNCHANGED — it
// still calls dxf.addLWPolyline() directly rather than this function,
// left untouched to avoid editing an already-tested file outside this
// session's scope.
export function openPolylineDXF(dxf, points, layerName) {
  if (!Array.isArray(points) || points.length < 2) {
    throw new DiagramError('BAD_PARAM', 'openPolylineDXF requires at least 2 points.');
  }
  return dxf.addLWPolyline(
    points.map((p) => ({ point: { x: p.x, y: p.y } })),
    { layerName, flags: LWPolylineFlags.None },
  );
}

// ── True minimum pairwise distance (irregular/multi-group dot layouts) ──
// Needed the first time by slabOpeningDiagram.dxf.mjs: its trim bars are
// FOUR groups arranged around a rectangle's perimeter (opening's
// top/bottom edges = parallelToX, left/right edges = parallelToY), so a
// dot near one corner can have its TRUE nearest same-layer neighbor in
// the PERPENDICULAR group, not its own — a single within-group
// `xs[1]-xs[0]` pitch (shearWallDiagram's own dual-line/dual-face
// pattern) only checks neighbors inside one distributeTicks() call and
// would miss that cross-group corner case. This computes the real
// minimum center-to-center distance across the FULL point set actually
// being drawn on one layer/view, so barDotRadiusMM's safety cap is
// derived from every real neighbor, not just the intended grouping.
// Logic is a direct promotion of test_shearWallDiagramDXF.mjs's own
// minCenterDistance() helper (same exact-zero exclusion: a coincident
// point is a duplicate draw, not a spacing case) from a test-only
// assertion into a shared render-time primitive.
//
// CONSOLIDATION NOTE (kit merge): three other element sessions
// independently wrote local variants of this same idea before this one
// was promoted here. columnDiagram.dxf.mjs has its own local
// minPairwiseDistanceMM — identical logic and signature to this exported
// one, safe to delete in favor of importing this instead, not yet done.
// retainingWallDiagram.dxf.mjs's nearestNeighborPitchesMM(points) and
// gradeBeamDiagram.dxf.mjs's nearestNeighborPitchMM(dots, i) solve the
// same underlying problem but return PER-POINT distances rather than one
// global minimum — a genuinely different, arguably more broadly useful
// shape for a future multi-group element; deliberately left as local
// code in those two files rather than force-fitted into this signature.
// Worth a second kit function for that shape in a future consolidation
// pass, not done here to avoid touching three already-tested files in a
// session that was not scoped to them.
export function minPairwiseDistanceMM(points) {
  let min = Infinity;
  for (let i = 0; i < points.length; i++) {
    for (let j = i + 1; j < points.length; j++) {
      const d = Math.hypot(points[i].x - points[j].x, points[i].y - points[j].y);
      if (d > 0 && d < min) min = d;
    }
  }
  return min; // Infinity for <2 points or all-coincident — barDotRadiusMM's own `pitchMM<=0 || !Number.isFinite(pitchMM)` branch already treats that as "no neighbor known, draw true size", the same fallback distributeTicks-derived Infinity already gets elsewhere in this kit.
}
