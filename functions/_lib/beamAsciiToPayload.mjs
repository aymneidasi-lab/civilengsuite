// functions/_lib/beamAsciiToPayload.mjs
//
// ASCII "key=value key=value ..." -> beamDiagram.mjs INPUT CONTRACT
// object, for the /rebar beam chat entry point. beamDiagram.mjs exports
// no parseDiagramCommand (ASCII) of its own — REBAR_ELEMENT_DISPATCH.beam
// only accepts a JSON object via parseBeamRebarPayload. This module is a
// syntax-only front end: it builds the exact same object shape
// parseBeamRebarPayload already expects and hands it off unchanged.
// Every business-rule check (bounds, overlaps, positivity, required-
// field enforcement) stays inside beamDiagram.mjs's own
// computeBeamDiagramGeometry, untouched — this module never duplicates
// a validation rule that already exists there. It does not itself
// reject a beam with zero supports/bars/stirrups; an empty or absent
// group reaches computeBeamDiagramGeometry exactly like a JSON caller
// who forgot the field, and gets that function's own BAD_PARAM message,
// not a second, possibly-inconsistent one minted here.
//
// SYNTAX — whitespace-separated key=value tokens. Any mix of spaces,
// tabs, and newlines is accepted identically (a pasted multi-line form
// and one long space-separated line produce the same payload), so users
// can either type one line or fill a template with one field per line.
//
//   Top-level:  id= unit= b= h= cover= totalLength=
//   sup{N}:     x= width= type= label=
//   bar{N}:     face= dia= count= layer= startX= endX= shapeCode=
//               cuttingLengthMM= markId=
//   stir{N}:    dia= legs= spacing= startX= endX= cuttingLengthMM=
//               shape= markId=
//   lap{N}:     startX= endX= markRef= note=
//   sec{N}:     x= label=
//
// {N} is a 1-based group index (sup1, sup2, ... bar1, bar2, ...); each
// prefix (sup/bar/stir/lap/sec) indexes independently. Groups are
// emitted to their array in ascending numeric-index order, not
// first-seen token order, so token order in the input text never
// matters — only the number in the key does. Gaps in numbering (bar1,
// bar3, no bar2) are accepted and simply compact into a 2-element array
// — array position carries no meaning in the target schema beyond
// "one bar group", so this cannot silently misassign a field.
//
// b=/h= (bare) are folded into the required section:{b,h} object
// expected by computeBeamDiagramGeometry; there is no ASCII "section"
// group of its own.
//
// FAILURE MODES (two, deliberately distinguished — same contract shape
// diagramCommandRouter.mjs already uses for its own BAD_SYNTAX):
//   BAD_SYNTAX — the text isn't shaped as key=value tokens at all (a
//     JSON payload, free prose, or empty string). Caller should treat
//     this exactly like "not an attempt at ASCII syntax" and fall back
//     to JSON.parse, preserving every existing JSON /rebar caller
//     unchanged.
//   BAD_TOKEN  — shaped as key=value tokens, but one token's key isn't
//     a recognized field for this element, or a numeric field got a
//     non-numeric value. Almost always a typo. Reported immediately
//     with the exact offending token so it surfaces before the request
//     ever reaches computeBeamDiagramGeometry, rather than silently
//     being dropped or misrouted to the JSON-parse fallback (which
//     would just fail there too, with a much less specific message).
//
// Resource lifecycle: pure/synchronous, no timers, no fetch, no KV, no
// external handles of any kind — same profile as every *Diagram.mjs
// module it feeds.

const TOP_LEVEL_STRING_FIELDS = new Set(['id', 'unit']);
const TOP_LEVEL_NUMBER_FIELDS = new Set(['b', 'h', 'cover', 'totalLength']);

const GROUP_FIELD_TYPES = {
  sup: { x: 'number', width: 'number', type: 'string', label: 'string' },
  bar: {
    face: 'string', dia: 'number', count: 'number', layer: 'number',
    startX: 'number', endX: 'number', shapeCode: 'string',
    cuttingLengthMM: 'number', markId: 'string',
  },
  stir: {
    dia: 'number', legs: 'number', spacing: 'number', startX: 'number',
    endX: 'number', cuttingLengthMM: 'number', shape: 'string', markId: 'string',
  },
  lap: { startX: 'number', endX: 'number', markRef: 'string', note: 'string' },
  sec: { x: 'number', label: 'string' },
};

// Longest-prefix-first so no future shorter prefix could shadow a
// longer one that starts with it (no current collision among sup/bar/
// stir/lap/sec, but this keeps match order well-defined if one is added).
const GROUP_PREFIXES_BY_LENGTH = Object.keys(GROUP_FIELD_TYPES).sort((a, b) => b.length - a.length);

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

export function parseBeamAsciiCommand(text) {
  if (typeof text !== 'string') {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Expected a text command.' };
  }
  const trimmed = text.trim();
  if (trimmed.length === 0) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Empty command.' };
  }
  // Not an attempt at this syntax at all -- e.g. a real JSON payload
  // starting with '{' or '['. Caller falls back to JSON.parse unchanged.
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return { ok: false, code: 'BAD_SYNTAX', message: 'Looks like JSON, not key=value text.' };
  }

  const tokens = trimmed.split(/\s+/);
  const top = {};
  const groups = { sup: new Map(), bar: new Map(), stir: new Map(), lap: new Map(), sec: new Map() };

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
      const isNumber = TOP_LEVEL_NUMBER_FIELDS.has(parsed.field);
      if (isNumber) {
        const n = coerceNumber(rawValue);
        if (n === null) {
          return { ok: false, code: 'BAD_TOKEN', message: `"${rawKey}" must be a number, got "${rawValue}".` };
        }
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
        if (value === null) {
          return { ok: false, code: 'BAD_TOKEN', message: `"${rawKey}" must be a number, got "${rawValue}".` };
        }
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
  const supports = groupArray('sup');
  const longitudinalBars = groupArray('bar');
  const stirrupZones = groupArray('stir');
  const lapZones = groupArray('lap');
  const sections = groupArray('sec');
  if (supports.length > 0) payload.supports = supports;
  if (longitudinalBars.length > 0) payload.longitudinalBars = longitudinalBars;
  if (stirrupZones.length > 0) payload.stirrupZones = stirrupZones;
  if (lapZones.length > 0) payload.lapZones = lapZones;
  if (sections.length > 0) payload.sections = sections;

  return { ok: true, payload };
}
