// factGuard.mjs — deterministic post-generation check for CRITICAL_FACTS
// drift. Pure logic, console.log only — deliberately does NOT write to
// CES_CHAT_KV: that namespace is already near its 1,000-writes/day free-tier
// ceiling from rate limiting alone (see chat.js comment above the dead-key
// cache). Read these lines via `wrangler tail` or the Cloudflare dashboard.
// If persistent/queryable logs are wanted later, use a SEPARATE KV namespace
// — never this one.
//
// [EXT-1] Two new checks added, same philosophy as the original three
// (deterministic, regex/keyword-based, log-only, zero I/O): apology_spiral
// and ungrounded_clause_citation. Evidence: 9 captured replies
// (ces-reply-2026-08-18T15-46-39 through T16-18-25) showing the model, after
// being told it hallucinated a VBA function/line number, spending 9
// consecutive turns apologizing and theorizing about its own internals and
// general AI-hallucination research (RAG, Chain-of-Thought, o1, "Verification-
// Based Training") instead of doing the requested grounded review. That
// theorizing is itself unverifiable — the model has no introspective access
// to why it generated a given token — so it is the same failure class as the
// original hallucination, just aimed at itself. Neither check can block a
// reply (chat.js streams tokens to the client as they're generated; by the
// time finalText exists here, it has already been sent — see chat.js's
// logFactDrift call site, which runs after the last sseWriter.writeDelta).
// Both are therefore log-only like the rest of this file; real-time
// correction is the EPISTEMIC_HONESTY_BLOCK prompt addition in chat.js, not
// this module. See the chat.js patch notes for the one call-site signature
// change this requires (scanForFactDrift now takes an optional second arg).

import { KB_CHUNKS } from './kb-data.js';

export const CANONICAL_FACTS = Object.freeze({
  priceLaunch: 249,
  priceRegular: 499,
  offlineDays: {
    fullOffline: 15, warnStart: 16, warnEnd: 29,
    graceStart: 30, graceEnd: 32, graceWindowDays: 3, blockDay: 33,
  },
  certAlgorithm: 'SHA-256',
  certPublisher: 'Engineering Apps Team',
  contactEmail: 'aymneidasi@gmail.com',
  contactWhatsApp: '+201287232413',
});

// Fails fast if a future hand-edit to CRITICAL_FACTS changes a number here
// without updating this registry — the exact failure class v28 found by hand.
export function assertFactsRegistrySynced(criticalFactsText) {
  const nums = (criticalFactsText.match(/\d+/g) || []).map(Number);
  const required = [
    CANONICAL_FACTS.priceLaunch,
    CANONICAL_FACTS.priceRegular,
    CANONICAL_FACTS.offlineDays.fullOffline,
    CANONICAL_FACTS.offlineDays.warnStart,
    CANONICAL_FACTS.offlineDays.warnEnd,
    CANONICAL_FACTS.offlineDays.graceStart,
    CANONICAL_FACTS.offlineDays.graceEnd,
    CANONICAL_FACTS.offlineDays.graceWindowDays,
    CANONICAL_FACTS.offlineDays.blockDay,
  ];
  const missing = required.filter(n => !nums.includes(n));
  if (missing.length) {
    throw new Error(
      `CRITICAL_FACTS/registry drift: [${missing.join(', ')}] not found verbatim in CRITICAL_FACTS text.`
    );
  }
  return true;
}

const DATE_PATTERN = /\b\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}\b|\b20\d{2}\b/;
const CERT_CONTEXT  = /(certificate|signed|signature|شهادة|موقّع|موقع رقمي|Authenticode)/i;

const PRICE_CONTEXT      = /(EGP|جنيه|price|سعر|تسعير|\/yr|سنوي)/i;
const MULTIYEAR_CONTEXT  = /(years?|سنوات|سنين|×|\*|total|إجمالي)/i;
const KNOWN_PRICE_NUMBERS = new Set([249, 499]);

const TRANSFER_AFFIRM = /(ينقل الترخيص|نقل الترخيص|قابل للنقل|transfer(?:able|red)?\s+(?:the\s+)?licen[cs]e|move.{0,15}licen[cs]e.{0,15}(?:new|another)\s+device)/i;
const NEGATION_NEAR    = /(no |not |never|can'?t|cannot|لا |لأ|مفيش|مش |غير قابل|ماينفعش|not\s+possible)/i;

function findDriftedPrices(text) {
  const hits = [];
  const re = /\b\d{2,4}\b/g;
  let m;
  while ((m = re.exec(text))) {
    const num = Number(m[0]);
    const ctx = text.slice(Math.max(0, m.index - 25), Math.min(text.length, m.index + m[0].length + 25));
    if (!PRICE_CONTEXT.test(ctx)) continue;
    if (MULTIYEAR_CONTEXT.test(ctx)) continue;
    if (KNOWN_PRICE_NUMBERS.has(num)) continue;
    hits.push({ value: num, context: ctx.trim() });
  }
  return hits;
}

function findCertDateLeak(text) {
  const hits = [];
  let idx = text.search(CERT_CONTEXT);
  while (idx !== -1) {
    const ctx = text.slice(Math.max(0, idx - 40), Math.min(text.length, idx + 60));
    if (DATE_PATTERN.test(ctx)) hits.push({ context: ctx.trim() });
    const rest = text.slice(idx + 1);
    const nextRel = rest.search(CERT_CONTEXT);
    idx = nextRel === -1 ? -1 : idx + 1 + nextRel;
  }
  return hits;
}

function findTransferClaim(text) {
  const hits = [];
  const re = new RegExp(TRANSFER_AFFIRM.source, 'gi');
  let m;
  while ((m = re.exec(text))) {
    const ctx = text.slice(Math.max(0, m.index - 20), m.index + m[0].length);
    if (!NEGATION_NEAR.test(ctx)) hits.push({ context: ctx.trim() });
  }
  return hits;
}

// [EXT-1a] APOLOGY-SPIRAL DETECTOR
// Trigger shape observed in all 9 captured incidents: at least one
// self-blame/apology phrase, PLUS EITHER (a) two or more distinct
// AI-hallucination-theory terms (the model explaining RAG/CoT/o1/training
// methodology to justify itself) OR (b) three or more numbered/bulleted
// "from now on I will..." commitment lines — a self-authored "protocol" or
// "constitution" substituting for actually doing the task. Either shape
// alone, paired with an apology, is the pattern; requiring the pairing
// (not apology alone) keeps this from firing on an ordinary one-line "sorry,
// here's the correction" reply, which is desired behavior, not the failure.
const APOLOGY_TERMS = /(حقك عليا|جلا من لا يسهو|بعتذر|أعتذر|اعتذر|غلطت|أنا غلطان|خطأ مني|تقصير مني|غير مهني|مرفوض تماماً|خانني التوفيق|تخريف|تخريب|I apologi[sz]e|my (?:mistake|apologies|bad)|I was wrong|that was unprofessional|I made an error)/i;

const META_AI_TERMS = [
  /هلوسة|hallucinat/i,
  /\bRAG\b|retrieval[- ]augmented/i,
  /chain[- ]of[- ]thought|\bCoT\b/i,
  /\bo1\b/i,
  /verification-based training/i,
  /temperature\s*(control)?|درجة ال(?:ـ)?temperature/i,
  /نماذج احتمالية|probabilistic model/i,
  /pattern matching/i,
  /instruction-following/i,
  /prompt engineering|هندسة البرومبت/i,
  /self-reflect|مراجعة ذاتية/i,
  /zero-shot/i,
  /processing flow/i,
  /contextual hallucination/i,
  /grounding\s*&?\s*self-correction/i,
];

// Matches a numbered/bulleted line opener: "1.", "1)", "١.", "- ", "*  ".
const LIST_ITEM_LINE = /^\s*(?:[0-9]{1,2}|[٠-٩]{1,2})[.\)]\s+\S|^\s*[-*]\s+\S/;

function countMetaAiTerms(text) {
  return META_AI_TERMS.reduce((n, re) => n + (re.test(text) ? 1 : 0), 0);
}

function countListItemLines(text) {
  return text.split(/\r?\n/).filter(line => LIST_ITEM_LINE.test(line)).length;
}

// [EXT-1a, revised after empirical test against the 9 real transcripts —
// see verify.mjs] Original design gated metaHits/listItems behind
// `hasApology` in the SAME message. Empirically wrong: in a real multi-turn
// spiral the apology fires once, early; turns 3+ stop saying "sorry" but
// keep producing unsolicited AI-theory lectures and new numbered
// "protocols" — still the same failure (not doing the grounded task), still
// needs to be caught. Decoupled below: apology is now ONE of three
// independent trigger paths, not a universal gate.
function findApologySpiral(text) {
  const hasApology = APOLOGY_TERMS.test(text);
  const metaHits = countMetaAiTerms(text);
  const listItems = countListItemLines(text);

  const triggered =
    (hasApology && (metaHits >= 2 || listItems >= 3)) || // apology + self-theorizing/new "protocol"
    (metaHits >= 3) ||                                     // unsolicited AI-theory lecture, apology or not
    (listItems >= 4 && metaHits >= 1);                     // heavy "from now on" list touching AI/self-process terms

  if (!triggered) return null;
  return {
    hasApology,
    metaAiTermsMatched: metaHits,
    protocolListLines: listItems,
    lengthChars: text.length,
  };
}

// [EXT-1b] UNGROUNDED ENGINEERING-CITATION DETECTOR
// [REVISED — verified against the real equations-backed kb-data.js (587
// chunks, 68 ACI+ECP equation chunks from build_kb_data.py), not the
// original 519-chunk KB that had zero clause citations of any kind. Three
// things the original regex got wrong once real data existed to check
// against:
//   1. It required "§" as the marker. The actual generated text uses the
//      WORD "Clause" — `Clause: 19.2.2.1` in the body, `(Clause 19.2.2.1)`
//      in the heading (see build_kb_data.py's parse_code_equations). "§"
//      does appear 70 times in the real file, but only in free-text
//      cross-references and a handful of equation_no values — never as the
//      primary clause marker. Fixed: marker now matches §, "Clause"/
//      "Clause:", or "Section"/"Section:", case-insensitive.
//   2. It required dot-separated numbers only. ECP 203 clauses use HYPHENS
//      ("2-2-2", "3-3-1-2") — ACI's convention, not ECP's. A number pattern
//      that only accepted dots silently could never whitelist a single ECP
//      citation. Fixed: separator is now "." OR "-".
//   3. Some clause fields are RANGES ("22.2 – 22.3.2", en-dash). Whitelist
//      building now splits on an en-dash/em-dash (or a hyphen WITH
//      surrounding spaces, which can't collide with ECP's tight
//      no-space hyphenation) and adds both endpoints.
// Extracts every "<CODE> <marker> <number>" citation the REPLY makes, and
// flags any that doesn't appear (same code + same clause number) anywhere
// in the grounding surface actually available to the model for that call:
// KEY_ENGINEERING_REFERENCE + CRITICAL_FACTS (passed in by chat.js — those
// two constants aren't exported, so chat.js supplies the text directly
// rather than this module hand-duplicating it) plus every KB_CHUNKS[].t
// PLUS an authoritative per-chunk `Clause: <value>` line read directly for
// every ACI 318 / ECP 203 chunk (build once at module load — KB_CHUNKS is
// static for the isolate's life). A citation naming a real code but a
// clause number never provided as grounding is a strong, specific
// hallucination signal: a fabricated-but-plausible-looking clause number is
// more dangerous to a structural engineer than a vague answer, because it
// reads as verified. NOT a correctness check on clauses that ARE in the
// whitelist (a whitelisted clause can still be `confidence: unverified` in
// the source .jsonl — that's a caveat for EPISTEMIC_HONESTY_BLOCK to carry
// into the reply, not something this deterministic check can judge); only
// flags citations with NO matching source at all.
const NUM_PART = '[0-9]+(?:[.-][0-9]+){0,4}';
// NOTE: 'بند' (Arabic for "clause/item") is included below as a defensive,
// NOT empirically-verified addition — checked directly: 'بند' and 'مادة'
// appear zero times in footing_pro_knowledge_base.txt / pc_suite_chatbot_kb.txt,
// so the KB source never produces this wording itself. Added anyway because
// a model answering in Arabic may naturally localize "Clause: 2-2-2" as
// "بند 2-2-2" even though the source text says "Clause"; since this check
// only ever logs (chat.js:6368's streaming architecture already sent the
// reply before this runs — see file header), a marker that turns out to
// rarely fire in practice costs nothing. If real traffic shows a different
// term in use, that's the one to add — don't extend this list further on
// guesses alone.
const CLAUSE_MARKER = '(?:§|[Cc]lause\\s*:?|[Ss]ection\\s*:?|بند\\s*:?)';
const CLAUSE_CITATION_RE = new RegExp(
  `\\b(ACI\\s?318(?:-\\d{2})?|ECP\\s?20[0-9])\\s*${CLAUSE_MARKER}\\s*(${NUM_PART})`,
  'gi'
);
// Matches the exact line build_kb_data.py emits: `Clause: <value>`, where
// <value> may be a single number or an en-dash-separated range.
const CLAUSE_LINE_RE = /^Clause:\s*(.+)$/m;

// Strips an edition suffix ("-19", "-14") before comparing: KB_CHUNKS' own
// `s` field is edition-agnostic ("ACI 318", never "ACI 318-19" — the
// edition lives in a separate body line, `Code: ACI 318 318-19`), but a
// reply citing the same real clause will very commonly include the
// edition ("ACI 318-19 §20.6.1"). Verified by direct test: without this
// strip, "ACI 318-19 Clause 19.2.2.1" — a real, grounded citation — was
// flagged as fabricated purely because of the "-19".
function normalizeClauseKey(code, number) {
  const codeNorm = code.replace(/\s+/g, '').replace(/-\d{2}$/, '').toUpperCase();
  return `${codeNorm}§${number.replace(/\s+/g, '')}`;
}

function extractExplicitCitations(text) {
  const out = [];
  const re = new RegExp(CLAUSE_CITATION_RE.source, 'gi');
  let m;
  while ((m = re.exec(text))) out.push({ code: m[1], number: m[2] });
  return out;
}

function buildClauseWhitelist(extraGroundingText) {
  const whitelist = new Set();

  // (a) explicit "<CODE> <marker> <number>" anywhere — grounding text arg
  // plus every chunk's heading+body. Catches free-text cross-references
  // ("ACI 318 §13.2.6" inside an applicability note) as well as headings
  // built from a "§X.X.X"-style equation_no.
  const sources = [extraGroundingText || ''];
  for (const chunk of KB_CHUNKS) sources.push(`${chunk.h || ''}\n${chunk.t || ''}`);
  for (const src of sources) {
    for (const { code, number } of extractExplicitCitations(src)) {
      whitelist.add(normalizeClauseKey(code, number));
    }
  }

  // (b) authoritative per-chunk "Clause: <value>" line for ACI/ECP equation
  // chunks specifically — the exact literal format build_kb_data.py emits,
  // so this is the primary source; (a) above is supplementary. Handles a
  // range ("22.2 – 22.3.2") by whitelisting both endpoints.
  for (const chunk of KB_CHUNKS) {
    if (chunk.s !== 'ACI 318' && chunk.s !== 'ECP 203') continue;
    const m = CLAUSE_LINE_RE.exec(chunk.t || '');
    if (!m) continue;
    const parts = m[1].split(/\s*[–—]\s*|\s+-\s+/).map(s => s.trim()).filter(Boolean);
    for (const p of parts) {
      if (/^[0-9]+(?:[.-][0-9]+)*$/.test(p)) whitelist.add(normalizeClauseKey(chunk.s, p));
    }
  }

  return whitelist;
}

// Built once per isolate lifetime from the static KB — cheap (587 chunks,
// same corpus scoreKbChunks already scans per-request in chat.js) — plus
// re-derived per call ONLY for the caller-supplied grounding text (a few KB
// of CRITICAL_FACTS+KEY_ENGINEERING_REFERENCE, not the full prompt). Caching
// the KB-only half avoids re-scanning 587 chunks on every reply.
const KB_CLAUSE_WHITELIST = buildClauseWhitelist('');

function findUngroundedClauseCitations(text, extraGroundingText) {
  const hits = [];
  const extraWhitelist = extraGroundingText ? buildClauseWhitelist(extraGroundingText) : null;
  for (const { code, number } of extractExplicitCitations(text)) {
    const key = normalizeClauseKey(code, number);
    const grounded = KB_CLAUSE_WHITELIST.has(key) || (extraWhitelist && extraWhitelist.has(key));
    if (!grounded) hits.push({ citation: `${code} ${number}`.trim(), key });
  }
  return hits;
}

// groundingReferenceText: optional. Pass CRITICAL_FACTS + KEY_ENGINEERING_REFERENCE
// (both in scope in chat.js at the call site) so clause citations sourced
// from those constants aren't false-flagged. Defaults to '' — backward
// compatible with any existing call site that doesn't pass it; the check
// then relies on KB_CHUNKS alone, which only widens what gets flagged, never
// narrows it silently.
export function scanForFactDrift(replyText, groundingReferenceText = '') {
  // [FIX — found in verification, pre-existing] every sub-scan below
  // assumes a string (findCertDateLeak's text.search(...) throws on
  // undefined/null with no try/catch anywhere upstream in chat.js's one
  // live call site). finalText is always a string in the current streaming
  // path, so this was latent, not observed in production — but a
  // defensive coercion here is free and turns a would-be 500 into a clean
  // no-violations scan instead, consistent with this file's own log-only,
  // never-throw-into-the-response contract.
  const text = typeof replyText === 'string' ? replyText : '';
  const violations = [];
  const priceHits = findDriftedPrices(text);
  if (priceHits.length) violations.push({ type: 'price', confidence: 'medium', hits: priceHits });
  const certHits = findCertDateLeak(text);
  if (certHits.length) violations.push({ type: 'cert_date_leak', confidence: 'high', hits: certHits });
  const transferHits = findTransferClaim(text);
  if (transferHits.length) violations.push({ type: 'license_transfer_claim', confidence: 'medium', hits: transferHits });
  const apologySpiral = findApologySpiral(text);
  if (apologySpiral) violations.push({ type: 'apology_spiral', confidence: 'high', hits: [apologySpiral] });
  const clauseHits = findUngroundedClauseCitations(text, groundingReferenceText);
  if (clauseHits.length) violations.push({ type: 'ungrounded_clause_citation', confidence: 'medium', hits: clauseHits });
  return { clean: violations.length === 0, violations };
}

// Synchronous, zero I/O cost — console.log only. See file header for why
// this does not touch CES_CHAT_KV.
export function logFactDrift(scanResult, meta) {
  if (scanResult.clean) return;
  console.log('[fact-guard]', JSON.stringify({
    ts: new Date().toISOString(),
    violations: scanResult.violations,
    ...meta,
  }));
}
