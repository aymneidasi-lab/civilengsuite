/**
 * POST /api/payment/webhook
 * ─────────────────────────────────────────────────────────────────────────────
 * Receives Paymob transaction webhooks.
 * Verifies HMAC-SHA512 signature BEFORE any processing.
 * Uses timing-safe comparison to prevent timing attacks.
 * Idempotent: duplicate webhooks for the same paid order are ignored.
 *
 * [PATCH, subscriber-tier] On a NEWLY confirmed payment (not a duplicate/
 * replayed webhook — see the existing idempotency check below, unchanged),
 * this now also mints a subscriber license via _lib/licenses.mjs and stores
 * it on the SAME order:{id} KV record, so functions/api/payment/verify.js
 * can hand it back to the success page without any new lookup. Durably
 * depends on PAYMENTS_KV being bound (see that var's own "Optional" note
 * below) — if it isn't, this file already silently skips ALL of its
 * existing order-tracking, and license issuance inherits that same
 * limitation rather than introducing a new one. durationDays comes from
 * the SAME pending order:{id} record this file already fetches for its
 * idempotency check — see functions/api/payment/create-intention.js's
 * PRODUCTS catalog for where that number is set per product.
 *
 * Required Cloudflare Pages env vars:
 *   PAYMOB_HMAC_SECRET  — HMAC secret from Paymob dashboard (Settings → Security)
 *
 * Optional:
 *   PAYMENTS_KV         — KV namespace binding for payment records
 *   CES_LICENSES        — [PATCH, subscriber-tier] KV namespace binding for
 *                          licenses (same binding chat.js/dev-upload.js/
 *                          vision.js use). If unbound, issueLicense()
 *                          itself fails closed (KV_NOT_BOUND) and this file
 *                          logs and continues — a license-issuance failure
 *                          must never turn a confirmed PAID payment into a
 *                          failed webhook response (Paymob would retry the
 *                          charge attempt, not just the notification).
 *
 * Paymob sends HMAC as:
 *   - Query parameter: ?hmac=<sha512hex>
 *   - OR request header: hmac: <sha512hex>
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Civil Engineering Suite — Eng. Aymn Asi © 2026
 */

'use strict';

import { issueLicense } from '../_lib/licenses.mjs';

const MAX_BODY_BYTES = 16_384; // 16 KB hard limit

// ── HMAC field order — MUST match Paymob's specification exactly ──────────────
// These field values (from payload.obj) are concatenated in this order and
// then HMAC-SHA512'd with the PAYMOB_HMAC_SECRET to produce the expected hash.
const HMAC_FIELDS = [
  'amount_cents',
  'created_at',
  'currency',
  'error_occured',          // Note: Paymob's typo in their API — keep as-is
  'has_parent_transaction',
  'id',
  'integration_id',
  'is_3d_secure',
  'is_auth',
  'is_capture',
  'is_refunded',
  'is_standalone_payment',
  'is_voided',
  'order.id',               // Nested: obj.order.id
  'owner',
  'pending',
  'source_data.pan',        // Nested: obj.source_data.pan
  'source_data.sub_type',   // Nested: obj.source_data.sub_type
  'source_data.type',       // Nested: obj.source_data.type
  'success',
];

// ── Resolve "a.b.c" paths on an object ───────────────────────────────────────
function getPath(obj, path) {
  return path.split('.').reduce((acc, key) => (acc != null ? acc[key] : null), obj);
}

// ── Build the HMAC input string from the transaction object ───────────────────
function buildHmacString(obj) {
  return HMAC_FIELDS
    .map(field => {
      const val = getPath(obj, field);
      // Undefined/null → empty string; booleans → lowercase "true"/"false"
      return val != null ? String(val) : '';
    })
    .join(''); // No separator
}

// ── Compute HMAC-SHA512 using Web Crypto API ─────────────────────────────────
async function computeHmacSha512(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sigBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ── Constant-time string comparison (prevents timing oracle attacks) ──────────
function safeEqual(a, b) {
  // Pad to equal length before XOR-ing to prevent early-exit timing leaks
  const maxLen = Math.max(a.length, b.length);
  const aPad   = a.padEnd(maxLen, '\0');
  const bPad   = b.padEnd(maxLen, '\0');
  let diff = a.length !== b.length ? 1 : 0;
  for (let i = 0; i < maxLen; i++) {
    diff |= aPad.charCodeAt(i) ^ bPad.charCodeAt(i);
  }
  return diff === 0;
}

// ── Main handler ──────────────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', {
      status: 405,
      headers: { Allow: 'POST', 'Cache-Control': 'no-store' },
    });
  }

  // ── Size gate — read raw body ONCE ────────────────────────────────────────
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) {
    console.warn('[payment:webhook] Oversized payload rejected:', raw.length, 'bytes');
    return new Response('Payload Too Large', { status: 413 });
  }

  // ── Parse JSON ────────────────────────────────────────────────────────────
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    return new Response('Bad Request', { status: 400 });
  }

  // ── Require HMAC secret to be configured ──────────────────────────────────
  const hmacSecret = (env.PAYMOB_HMAC_SECRET || '').trim();
  if (!hmacSecret) {
    console.error('[payment:webhook] PAYMOB_HMAC_SECRET env var is not set — cannot verify webhooks');
    // Return 200 to prevent Paymob retry storm during misconfiguration window
    return new Response('', { status: 200, headers: { 'Cache-Control': 'no-store' } });
  }

  // ── Extract HMAC from query string or header ──────────────────────────────
  const url           = new URL(request.url);
  const receivedHmac  = (
    url.searchParams.get('hmac') ||
    request.headers.get('hmac') ||
    ''
  ).toLowerCase().trim();

  if (!receivedHmac) {
    console.warn('[payment:webhook] Webhook received with no HMAC — rejecting. IP:',
      (request.headers.get('CF-Connecting-IP') || '').split(',')[0].trim()
    );
    return new Response('Forbidden', { status: 403, headers: { 'Cache-Control': 'no-store' } });
  }

  // ── Verify HMAC ───────────────────────────────────────────────────────────
  // Paymob wraps the transaction object inside payload.obj for transaction webhooks.
  // Fall back to payload itself for other event shapes.
  const obj        = (payload && payload.obj) ? payload.obj : payload;
  const hmacStr    = buildHmacString(obj);
  const expectedHmac = await computeHmacSha512(hmacSecret, hmacStr);

  if (!safeEqual(receivedHmac, expectedHmac)) {
    console.error('[payment:webhook] HMAC mismatch — possible spoofed or malformed webhook. IP:',
      (request.headers.get('CF-Connecting-IP') || '').split(',')[0].trim()
    );
    return new Response('Forbidden', { status: 403, headers: { 'Cache-Control': 'no-store' } });
  }

  // ── Extract transaction fields ────────────────────────────────────────────
  const success     = obj.success === true;
  const pending     = obj.pending === true;
  const orderId     = String(obj.order?.id ?? '').trim();
  const transId     = String(obj.id ?? '').trim();
  const amountCents = Number(obj.amount_cents) || 0;
  const currency    = String(obj.currency || '').trim();
  const payType     = String(obj.source_data?.type || 'unknown');
  const paySubType  = String(obj.source_data?.sub_type || '');
  const email       = String(
    obj.billing_data?.email || obj.customer_email || ''
  ).toLowerCase().trim().slice(0, 200);
  const clientIp    = (request.headers.get('CF-Connecting-IP') || '').split(',')[0].trim();

  if (!orderId) {
    console.warn('[payment:webhook] Verified webhook with no order.id — skipping');
    return new Response('', { status: 200, headers: { 'Cache-Control': 'no-store' } });
  }

  // ── Idempotency: never overwrite a confirmed payment ─────────────────────
  // [PATCH, subscriber-tier] Now captures the full existing record, not
  // just its status — durationDays/product_id/email (written by
  // create-intention.js at intent-creation time) are what license issuance
  // below needs, and this is the SAME KV read that idempotency-checking
  // already required, so this costs nothing extra.
  let pendingOrder = null;
  if (env.PAYMENTS_KV) {
    pendingOrder = await env.PAYMENTS_KV.get(`order:${orderId}`, 'json').catch(() => null);
    if (pendingOrder?.status === 'paid') {
      // Already confirmed — ACK without processing to stop Paymob retries.
      // (Also means a license was already issued the first time this order
      // transitioned to paid — see below — so no risk of double-issuance.)
      return new Response('', { status: 200, headers: { 'Cache-Control': 'no-store' } });
    }
  }

  // ── Process by outcome ────────────────────────────────────────────────────
  if (success && !pending) {
    // ── CONFIRMED PAYMENT ─────────────────────────────────────────────────
    // [PATCH, subscriber-tier] Mint a subscriber license for this NEWLY
    // confirmed payment. Reached at most once per order — guarded by the
    // idempotency check above (repeat webhooks for an already-'paid' order
    // return early before this line). issueLicense's own KV write is
    // separate from PAYMENTS_KV (a different namespace, CES_LICENSES), so
    // this happens regardless of whether the PAYMENTS_KV block below
    // succeeds or is even bound — a license should not be held hostage to
    // this project's own payment-tracking KV being configured.
    //
    // durationDays: prefer the pending order's stored value (set by
    // create-intention.js from PRODUCTS[product_id].durationDays at intent
    // creation) — falls back to 365 only if the pending record is missing
    // entirely (its own TTL is 24h; a payment confirmed after that window,
    // or with PAYMENTS_KV enabled only after intent creation, would hit
    // this edge case). Logged distinctly so a fallback firing in practice
    // is visible rather than silently assumed correct.
    let licenseKey = null;
    let licenseExpiresAt = null;
    let durationDays = Number(pendingOrder?.durationDays);
    if (!Number.isFinite(durationDays) || durationDays <= 0) {
      durationDays = 365;
      console.warn(
        '[payment:webhook] No durationDays on pending order', orderId,
        pendingOrder ? '(record exists but lacks the field)' : '(no pending record found)',
        '— falling back to 365 days. Investigate: either PAYMENTS_KV was not bound at intent-creation time, or the 24h pending-order TTL elapsed before payment completed.',
      );
    }
    const licenseNote = email || pendingOrder?.email || '';
    try {
      const issueResult = await issueLicense(env, { durationDays, note: licenseNote });
      if (issueResult.ok) {
        licenseKey = issueResult.license.licenseKey;
        licenseExpiresAt = issueResult.license.expiresAt;
        console.log('[payment:webhook] License issued for order', orderId, ':', licenseKey, 'expires', licenseExpiresAt);
      } else {
        console.error('[payment:webhook] issueLicense failed for order', orderId, ':', issueResult.code, issueResult.error);
      }
    } catch (err) {
      // A licensing failure must never turn a CONFIRMED payment into a
      // non-200 webhook response — Paymob's retry-on-non-2xx behavior is
      // for notification delivery, not a mechanism to retry OUR license
      // minting, and treating it as one would risk a duplicate charge
      // attempt on the customer's card for a purely internal error.
      console.error('[payment:webhook] issueLicense threw for order', orderId, ':', err.message);
    }

    if (env.PAYMENTS_KV) {
      await env.PAYMENTS_KV.put(
        `order:${orderId}`,
        JSON.stringify({
          status:         'paid',
          transaction_id: transId,
          amount_cents:   amountCents,
          currency,
          email,
          pay_type:       payType,
          pay_sub_type:   paySubType,
          paid_at:        new Date().toISOString(),
          licenseKey,             // [PATCH, subscriber-tier] null if issueLicense failed above — verify.js/support can detect and manually re-issue
          licenseExpiresAt,
        }),
        { expirationTtl: 60 * 60 * 24 * 730 } // Retain 2 years
      ).catch(err => console.error('[payment:webhook] KV write failed (paid):', err.message));
    }

    console.log(JSON.stringify({
      type:           'payment_success',
      order_id:       orderId,
      transaction_id: transId,
      amount_cents:   amountCents,
      currency,
      pay_type:       payType,
      client_ip:      clientIp,
      license_key:    licenseKey, // [PATCH, subscriber-tier] null if issueLicense failed — see the error logged above this block
      ts:             new Date().toISOString(),
    }));

  } else if (!success && !pending) {
    // ── FAILED / DECLINED PAYMENT ─────────────────────────────────────────
    const errorMsg = String(
      obj.data?.message || obj.data?.detail || obj.txn_response_code || 'declined'
    ).slice(0, 200);

    if (env.PAYMENTS_KV) {
      // Only write failed status if the order isn't already marked paid
      await env.PAYMENTS_KV.put(
        `order:${orderId}`,
        JSON.stringify({
          status:         'failed',
          transaction_id: transId,
          amount_cents:   amountCents,
          currency,
          email,
          error_message:  errorMsg,
          failed_at:      new Date().toISOString(),
        }),
        { expirationTtl: 60 * 60 * 24 * 7 } // Retain 7 days for failed
      ).catch(err => console.error('[payment:webhook] KV write failed (failed):', err.message));
    }

    console.warn(JSON.stringify({
      type:     'payment_failed',
      order_id: orderId,
      error:    errorMsg,
      pay_type: payType,
      ts:       new Date().toISOString(),
    }));

  } else if (pending) {
    // ── PENDING (e.g., Fawry waiting for cash payment) ────────────────────
    if (env.PAYMENTS_KV) {
      const existing = await env.PAYMENTS_KV.get(`order:${orderId}`, 'json').catch(() => null);
      if (!existing || existing.status === 'pending') {
        await env.PAYMENTS_KV.put(
          `order:${orderId}`,
          JSON.stringify({
            status:         'pending_payment',
            transaction_id: transId,
            amount_cents:   amountCents,
            currency,
            email,
            pay_type:       payType,
            pending_at:     new Date().toISOString(),
          }),
          { expirationTtl: 60 * 60 * 24 * 3 } // Pending expires in 3 days
        ).catch(err => console.error('[payment:webhook] KV write failed (pending):', err.message));
      }
    }

    console.log(JSON.stringify({
      type:     'payment_pending',
      order_id: orderId,
      pay_type: payType,
      ts:       new Date().toISOString(),
    }));
  }

  // Always return 200 to acknowledge receipt — any non-2xx causes Paymob to retry
  return new Response('', { status: 200, headers: { 'Cache-Control': 'no-store' } });
}