import { onRequest as webhookHandler } from './functions/api/payment/webhook.js';

function makeMockKV() {
  const store = new Map();
  const calls = { get: 0, put: 0 };
  return {
    store, calls,
    async get(key, type) {
      calls.get++;
      if (!store.has(key)) return null;
      const val = store.get(key);
      return type === 'json' ? JSON.parse(val) : val;
    },
    async put(key, value) { calls.put++; store.set(key, value); },
  };
}

let failures = 0;
function assert(cond, label) {
  if (!cond) { failures++; console.error('FAIL:', label); }
  else { console.log('ok  -', label); }
}

// ── Real HMAC-SHA512 matching webhook.js's own buildHmacString/field order,
//    so these tests sign payloads the exact way Paymob actually would —
//    not a stub that bypasses signature verification. ──────────────────────
const HMAC_FIELDS = [
  'amount_cents', 'created_at', 'currency', 'error_occured',
  'has_parent_transaction', 'id', 'integration_id', 'is_3d_secure', 'is_auth',
  'is_capture', 'is_refunded', 'is_standalone_payment', 'is_voided',
  'order.id', 'owner', 'pending', 'source_data.pan', 'source_data.sub_type',
  'source_data.type', 'success',
];
function getPath(obj, path) {
  return path.split('.').reduce((acc, key) => (acc != null ? acc[key] : null), obj);
}
function buildHmacString(obj) {
  return HMAC_FIELDS.map((f) => {
    const v = getPath(obj, f);
    return v != null ? String(v) : '';
  }).join('');
}
async function signHmac(secret, obj) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(buildHmacString(obj)));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function makeTxnObj(overrides = {}) {
  return {
    amount_cents: 49900,
    created_at: '2026-08-19T10:00:00Z',
    currency: 'EGP',
    error_occured: false,
    has_parent_transaction: false,
    id: 555111,
    integration_id: 12345,
    is_3d_secure: true,
    is_auth: false,
    is_capture: false,
    is_refunded: false,
    is_standalone_payment: true,
    is_voided: false,
    order: { id: 900001 },
    owner: 1,
    pending: false,
    source_data: { pan: '1234', sub_type: 'MasterCard', type: 'card' },
    success: true,
    billing_data: { email: 'buyer@example.com' },
    ...overrides,
  };
}

async function postWebhook(env, obj, secret) {
  const hmac = await signHmac(secret, obj);
  const req = new Request('https://civilengsuite.is-a.dev/api/payment/webhook?hmac=' + hmac, {
    method: 'POST',
    headers: { 'CF-Connecting-IP': '203.0.113.20', 'Content-Type': 'application/json' },
    body: JSON.stringify({ obj }),
  });
  return webhookHandler({ request: req, env });
}

async function main() {
  const HMAC_SECRET = 'test-paymob-hmac-secret';

  // ── Happy path: pending order (with durationDays, as create-intention.js
  //    now writes) → webhook confirms payment → license issued & stored ────
  {
    const paymentsKv = makeMockKV();
    const licensesKv = makeMockKV();
    const env = { PAYMOB_HMAC_SECRET: HMAC_SECRET, PAYMENTS_KV: paymentsKv, CES_LICENSES: licensesKv };
    await paymentsKv.put('order:900001', JSON.stringify({
      status: 'pending', product_id: 'footing-pro-personal', durationDays: 365,
      currency: 'EGP', amount: 49900, email: 'buyer@example.com', created_at: new Date().toISOString(),
    }));

    const res = await postWebhook(env, makeTxnObj(), HMAC_SECRET);
    assert(res.status === 200, 'confirmed payment returns 200');

    const stored = JSON.parse(paymentsKv.store.get('order:900001'));
    assert(stored.status === 'paid', 'order record transitions to paid');
    assert(typeof stored.licenseKey === 'string' && /^CES-/.test(stored.licenseKey), 'a real licenseKey was written onto the order record: ' + stored.licenseKey);
    assert(typeof stored.licenseExpiresAt === 'string', 'licenseExpiresAt was written');

    const licenseRaw = licensesKv.store.get('license:' + stored.licenseKey);
    assert(!!licenseRaw, 'the license actually exists in CES_LICENSES, not just referenced');
    const licenseRecord = JSON.parse(licenseRaw);
    const days = Math.round((new Date(licenseRecord.expiresAt) - new Date(licenseRecord.createdAt)) / 86400000);
    assert(days === 365, 'license duration matches the pending order\'s durationDays (365), not a hardcoded default: got ' + days);
    assert(licenseRecord.note === 'buyer@example.com', 'license note carries the buyer email through for support/audit');

    // ── Idempotency: Paymob retries the SAME webhook — must NOT mint a
    //    second license ──────────────────────────────────────────────────
    const licenseWritesBefore = licensesKv.calls.put;
    const res2 = await postWebhook(env, makeTxnObj(), HMAC_SECRET);
    assert(res2.status === 200, 'duplicate webhook still returns 200 (so Paymob stops retrying)');
    assert(licensesKv.calls.put === licenseWritesBefore, 'duplicate webhook for an already-paid order issues ZERO additional licenses: writes before=' + licenseWritesBefore + ' after=' + licensesKv.calls.put);
    const storedAfterRetry = JSON.parse(paymentsKv.store.get('order:900001'));
    assert(storedAfterRetry.licenseKey === stored.licenseKey, 'the SAME licenseKey remains on the order record after a duplicate webhook');
  }

  // ── Missing pending record (edge case: PAYMENTS_KV enabled after intent
  //    creation, or 24h pending-TTL elapsed) → falls back to 365 days,
  //    still issues a license rather than silently skipping ──────────────
  {
    const paymentsKv = makeMockKV();
    const licensesKv = makeMockKV();
    const env = { PAYMOB_HMAC_SECRET: HMAC_SECRET, PAYMENTS_KV: paymentsKv, CES_LICENSES: licensesKv };
    const res = await postWebhook(env, makeTxnObj({ order: { id: 900002 }, id: 555222 }), HMAC_SECRET);
    assert(res.status === 200, 'payment with no pre-existing pending record still returns 200');
    const stored = JSON.parse(paymentsKv.store.get('order:900002'));
    assert(typeof stored.licenseKey === 'string', 'a license is still issued via the 365-day fallback when no pending record exists');
  }

  // ── Bad HMAC → rejected, no license, no KV writes at all ────────────────
  {
    const paymentsKv = makeMockKV();
    const licensesKv = makeMockKV();
    const env = { PAYMOB_HMAC_SECRET: HMAC_SECRET, PAYMENTS_KV: paymentsKv, CES_LICENSES: licensesKv };
    const res = await postWebhook(env, makeTxnObj({ order: { id: 900003 } }), 'WRONG-SECRET');
    assert(res.status === 403, 'a webhook signed with the wrong secret is rejected with 403');
    assert(paymentsKv.calls.put === 0, 'a rejected (bad-signature) webhook writes nothing to PAYMENTS_KV');
    assert(licensesKv.calls.put === 0, 'a rejected (bad-signature) webhook issues no license');
  }

  // ── Failed payment → no license, order marked failed ─────────────────────
  {
    const paymentsKv = makeMockKV();
    const licensesKv = makeMockKV();
    const env = { PAYMOB_HMAC_SECRET: HMAC_SECRET, PAYMENTS_KV: paymentsKv, CES_LICENSES: licensesKv };
    const res = await postWebhook(env, makeTxnObj({ order: { id: 900004 }, success: false, pending: false }), HMAC_SECRET);
    assert(res.status === 200, 'a declined payment still returns 200 (ack, not an error)');
    const stored = JSON.parse(paymentsKv.store.get('order:900004'));
    assert(stored.status === 'failed', 'declined payment recorded as failed, not paid');
    assert(licensesKv.calls.put === 0, 'a DECLINED payment issues zero licenses');
  }

  // ── Pending (e.g. Fawry cash) → no license yet ────────────────────────────
  {
    const paymentsKv = makeMockKV();
    const licensesKv = makeMockKV();
    const env = { PAYMOB_HMAC_SECRET: HMAC_SECRET, PAYMENTS_KV: paymentsKv, CES_LICENSES: licensesKv };
    const res = await postWebhook(env, makeTxnObj({ order: { id: 900005 }, success: false, pending: true }), HMAC_SECRET);
    assert(res.status === 200, 'a pending (cash-waiting) notification returns 200');
    const stored = JSON.parse(paymentsKv.store.get('order:900005'));
    assert(stored.status === 'pending_payment', 'recorded as pending_payment, not paid');
    assert(licensesKv.calls.put === 0, 'a PENDING payment issues zero licenses (correctly waits for the real success webhook)');
  }

  console.log('\n' + (failures === 0 ? 'ALL WEBHOOK CHECKS PASSED' : `${failures} CHECK(S) FAILED`));
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => { console.error('CRASHED:', err); process.exit(1); });
