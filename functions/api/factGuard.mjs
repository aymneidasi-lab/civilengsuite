// factGuard.mjs — deterministic post-generation check for CRITICAL_FACTS
// drift. Pure logic, console.log only — deliberately does NOT write to
// CES_CHAT_KV: that namespace is already near its 1,000-writes/day free-tier
// ceiling from rate limiting alone (see chat.js comment above the dead-key
// cache). Read these lines via `wrangler tail` or the Cloudflare dashboard.
// If persistent/queryable logs are wanted later, use a SEPARATE KV namespace
// — never this one.

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

export function scanForFactDrift(replyText) {
  const violations = [];
  const priceHits = findDriftedPrices(replyText);
  if (priceHits.length) violations.push({ type: 'price', confidence: 'medium', hits: priceHits });
  const certHits = findCertDateLeak(replyText);
  if (certHits.length) violations.push({ type: 'cert_date_leak', confidence: 'high', hits: certHits });
  const transferHits = findTransferClaim(replyText);
  if (transferHits.length) violations.push({ type: 'license_transfer_claim', confidence: 'medium', hits: transferHits });
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
