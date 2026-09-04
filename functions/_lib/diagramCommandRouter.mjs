// diagramCommandRouter.mjs
//
// Single entry point for this app's /diagram command text. Step 20
// (prior session) wired slabDiagram.mjs's, shearWallDiagram.mjs's, and
// stairDiagram.mjs's new parseDiagramCommand() functions in alongside
// footingDiagram.mjs's pre-existing one. A follow-up session added
// columnDiagram.mjs's own new parseDiagramCommand the same way. None of
// these five modules' own compute/render code, nor footingDiagram.mjs's
// own parseDiagramCommand, has ever been touched by this file.
//
// chat.js: wired in the same follow-up session as Step 20 originally
// (see CHANGELOG.md's Step 20 entry and this file's own history) —
// imports routeDiagramCommand() instead of calling any single module's
// parseDiagramCommand directly. Every existing isolated/combined/strip/
// raft command continues to route to the exact same footingDiagram.mjs
// code path, byte-for-byte — this file changes no existing behavior,
// only adds reachable branches ahead of it.
//
// Step 23: beam is now wired too. beamDiagram.mjs's own new
// parseDiagramCommand does NOT invent a new flat-text grammar — it
// reuses beamAsciiToPayload.mjs's group-indexed syntax (built in Step 22
// for the /rebar path) and only strips the leading `beam` token this
// family's convention requires. See beamDiagram.mjs's own Step 23 header
// note for the full reasoning. This file's own change is a strict
// addition: one more import, one more PARSERS entry, one more
// ALL_SUPPORTED_TYPES string — no existing entry's behavior changed.
//
// New-element track, Part 2 candidate 1 (retaining wall), later step:
// retainingWallDiagram.mjs's own new parseDiagramCommand wired in the
// same strict-addition way. NOTE on step numbering, stated rather than
// silently resolved: this file's own "Step 23" comment above (beam
// wiring) and CHANGELOG.md's own Step 23 entry (HTML quick-reply field
// tables, which explicitly states no .mjs file was touched) are two
// DIFFERENT changes under the same step number — confirmed by reading
// both, not assumed. Not fixed here (renumbering is a documentation
// decision for whoever owns CHANGELOG.md, out of scope for a wiring
// change); flagged so a future session doesn't trust either "Step 23"
// label at face value without checking which change it actually means.
//
// Resource lifecycle: pure/synchronous, zero state held between calls,
// no timers/fetch/KV/handles — same as every module it delegates to.

import { parseDiagramCommand as parseFootingDiagramCommand } from './footingDiagram.mjs';
import { parseDiagramCommand as parseSlabDiagramCommand } from './slabDiagram.mjs';
import { parseDiagramCommand as parseShearWallDiagramCommand } from './shearWallDiagram.mjs';
import { parseDiagramCommand as parseStairDiagramCommand } from './stairDiagram.mjs';
import { parseDiagramCommand as parseColumnDiagramCommand } from './columnDiagram.mjs';
import { parseDiagramCommand as parseBeamDiagramCommand } from './beamDiagram.mjs';
import { parseDiagramCommand as parseRetainingWallDiagramCommand } from './retainingWallDiagram.mjs';
// New-element track, Part 2 candidate 2 (trapezoidal combined footing).
// Own module, own leading token "trapezoidal" — not a branch inside
// footingDiagram.mjs's 'combined', which stays rectangular-only (see
// trapezoidalFootingDiagram.mjs's own header for why this is a separate
// file rather than a fifth type folded into footingDiagram.mjs's switch).
import { parseDiagramCommand as parseTrapezoidalFootingDiagramCommand } from './trapezoidalFootingDiagram.mjs';
// New-element track, Part 2 candidate 3 (strap footing). Own module, own
// leading token "strap" — closes the third and last documented gap
// trapezoidalFootingDiagram.mjs's own header named (see
// strapFootingDiagram.mjs's own header for the full set: Rectangular /
// Trapezoidal / Strap are three independent standalone footing_pro
// products; footingDiagram.mjs's 'combined' only draws the rectangular
// one, trapezoidalFootingDiagram.mjs added the second, this is the third).
import { parseDiagramCommand as parseStrapFootingDiagramCommand } from './strapFootingDiagram.mjs';
// New-element track candidate: grade beam / tie beam. Own module
// (gradeBeamDiagram.mjs), own leading tokens "gradebeam"/"tiebeam" —
// reuses beamDiagram.mjs's bar-group/stirrup-zone algorithms but
// replaces beam's point-support (SUPPORT_OUT_OF_BOUNDS) model with a
// continuous soil-bearing strip + optional annotation-only nodes
// (NODE_OUT_OF_BOUNDS) — see that module's own header for the full
// "why a separate module" reasoning.
import { parseDiagramCommand as parseGradeBeamDiagramCommand } from './gradeBeamDiagram.mjs';
// New-element track (pile cap / "isolated footing over pile"). Own
// module (pileCapDiagram.mjs), own leading token "pilecap" — the one
// geometry footingDiagram.mjs's own header explicitly names as NOT
// modeled (a footing bearing on a discrete, arbitrarily-placed pile
// group instead of soil). See that module's own header for the full
// "why a separate file" reasoning (multi-pile plan geometry, a section
// cut projecting piles from off-cut positions, and its own
// PILE_OUT_OF_BOUNDS/PILES_OVERLAP/COLUMN_PILE_OVERLAP/
// EMBED_EXCEEDS_DEPTH error codes, none of which any other footing-
// family module throws).
import { parseDiagramCommand as parsePileCapDiagramCommand } from './pileCapDiagram.mjs';
// New-element track (session25 gate, ACI-318 gap-pool candidate 2 of 5:
// "Flat slab opening reinforcement"). Own module (slabOpeningDiagram.mjs),
// own leading token "slabopening" \u2014 the geometry slabDiagram.mjs's own
// header explicitly names as NOT modeled (openings/penetrations). See
// that module's own header for the full "why a separate file" reasoning
// (a second, opening-specific mesh/trim-bar schema and its own
// OPENING_TOO_CLOSE_TO_EDGE error code, neither of which slabDiagram.mjs
// itself has any use for).
import { parseDiagramCommand as parseSlabOpeningDiagramCommand } from './slabOpeningDiagram.mjs';
// [New-element track — SVG completeness pass] Ten remaining library
// modules that already had a full compute/render/parse*RebarPayload
// triple (same shape as every module above) but were never wired into
// this router or into chat.js's import list — found by diffing this
// router's own PARSERS array against every *.mjs file in this
// directory. Each import below follows the identical "own module, own
// leading token(s)" convention already established by every sibling
// import above; see each module's own header for why it is a separate
// file rather than a branch inside an existing one.
import { parseDiagramCommand as parseBasementWallDiagramCommand } from './basementWallDiagram.mjs';
import { parseDiagramCommand as parseBeamColumnJointDiagramCommand } from './beamColumnJointDiagram.mjs';
import { parseDiagramCommand as parseCircularColumnDiagramCommand } from './circularColumnDiagram.mjs';
// corbelDiagram.mjs's own parseDiagramCommand accepts TWO leading
// tokens for the same schema ("corbel" or "bracket" — see that
// module's own header), same dual-spelling shape gradeBeamDiagram.mjs
// already established for "gradebeam"/"tiebeam" below.
import { parseDiagramCommand as parseCorbelDiagramCommand } from './corbelDiagram.mjs';
import { parseDiagramCommand as parseCouplingBeamDiagramCommand } from './couplingBeamDiagram.mjs';
// flatSlabDropPanelDiagram.mjs's own leading token is "dropcapital"
// (covers both its capitalType:'dropPanel' and capitalType:'capital'
// variants — see that module's own header), not "flatslabdroppanel".
import { parseDiagramCommand as parseFlatSlabDropPanelDiagramCommand } from './flatSlabDropPanelDiagram.mjs';
// hordiSlabDiagram.mjs's own leading token is "hordi", not "hordislab".
import { parseDiagramCommand as parseHordiSlabDiagramCommand } from './hordiSlabDiagram.mjs';
import { parseDiagramCommand as parsePunchingShearDiagramCommand } from './punchingShearDiagram.mjs';
import { parseDiagramCommand as parseRaftPileDiagramCommand } from './raftPileDiagram.mjs';
import { parseDiagramCommand as parseWallOpeningDiagramCommand } from './wallOpeningDiagram.mjs';

// Order is arbitrary among these twenty-two — each parser claims only its
// own leading token(s) (footing: isolated|combined|strip|raft; slab:
// slab; shearwall: shearwall; stair: stair; column: column; beam: beam;
// retaining wall: retainingwall; trapezoidal footing: trapezoidal; strap
// footing: strap; grade/tie beam: gradebeam|tiebeam; pile cap: pilecap;
// slab opening: slabopening; basement wall: basementwall; beam-column
// joint: beamcolumnjoint; circular column: circularcolumn; corbel:
// corbel|bracket; coupling beam: couplingbeam; flat slab drop
// panel/capital: dropcapital; hordi (rib) slab: hordi; punching shear:
// punchingshear; raft-on-piles: raftpile; wall opening: wallopening),
// so no two ever compete for the same input.
const PARSERS = [
  parseFootingDiagramCommand,
  parseSlabDiagramCommand,
  parseShearWallDiagramCommand,
  parseStairDiagramCommand,
  parseColumnDiagramCommand,
  parseBeamDiagramCommand,
  parseRetainingWallDiagramCommand,
  parseTrapezoidalFootingDiagramCommand,
  parseStrapFootingDiagramCommand,
  parseGradeBeamDiagramCommand,
  parsePileCapDiagramCommand,
  parseSlabOpeningDiagramCommand,
  parseBasementWallDiagramCommand,
  parseBeamColumnJointDiagramCommand,
  parseCircularColumnDiagramCommand,
  parseCorbelDiagramCommand,
  parseCouplingBeamDiagramCommand,
  parseFlatSlabDropPanelDiagramCommand,
  parseHordiSlabDiagramCommand,
  parsePunchingShearDiagramCommand,
  parseRaftPileDiagramCommand,
  parseWallOpeningDiagramCommand,
];

// Types recognized ACROSS all wired parsers — used only to build one
// coherent "not supported" message instead of echoing whichever parser
// happened to run last (its own message would misleadingly say e.g.
// "Use stair" even when slab/shearwall/column/beam/retainingwall/
// isolated/combined/strip/raft/gradebeam/tiebeam/pilecap/slabopening/
// basementwall/beamcolumnjoint/circularcolumn/corbel/bracket/
// couplingbeam/dropcapital/hordi/punchingshear/raftpile/wallopening are
// also valid).
const ALL_SUPPORTED_TYPES = ['isolated', 'combined', 'strip', 'raft', 'slab', 'shearwall', 'stair', 'column', 'beam', 'retainingwall', 'trapezoidal', 'strap', 'gradebeam', 'tiebeam', 'pilecap', 'slabopening', 'basementwall', 'beamcolumnjoint', 'circularcolumn', 'corbel', 'bracket', 'couplingbeam', 'dropcapital', 'hordi', 'punchingshear', 'raftpile', 'wallopening'];

// Tries each wired module's parseDiagramCommand in turn. UNSUPPORTED_TYPE
// is the ONLY code that causes fallthrough to the next parser; any other
// result — ok:true, or a real error (BAD_SYNTAX, BAD_PARAM, etc.) on a
// leading token a parser DID recognize — is returned immediately, so a
// genuine syntax/param error on a matched type is never masked by trying
// the next module. Never throws (each delegate already converts every
// DiagramError to {ok:false,code,message}; a non-DiagramError throw from
// a delegate is a programmer error and propagates, same as every sibling
// module's own convention).
export function routeDiagramCommand(text) {
  let sawUnsupported = false;
  for (const parse of PARSERS) {
    const result = parse(text);
    if (result.code !== 'UNSUPPORTED_TYPE') return result;
    sawUnsupported = true;
  }
  // Every wired parser said UNSUPPORTED_TYPE (or, degenerately, none did
  // and sawUnsupported stayed false only if PARSERS were empty, which it
  // never is) — build one aggregate message naming every type this
  // router actually recognizes.
  void sawUnsupported;
  const m = (text || '').trim().match(/^(\S+)/);
  const type = m ? m[1].toLowerCase() : '';
  return { ok: false, code: 'UNSUPPORTED_TYPE', message: `"${type}" is not supported. Use ${ALL_SUPPORTED_TYPES.join(', ')}.` };
}
