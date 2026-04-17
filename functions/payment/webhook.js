/**
 * POST /api/payment/webhook
 * ─────────────────────────────────────────────────────────────────────────────
 * Receives Paymob transaction webhooks.
 * Verifies HMAC-SHA512 signature BEFORE any processing.
 * Uses timing-safe comparison to prevent timing attacks.
 * Idempotent: duplicate webhooks for the same paid order are ignored.
 *
 * Required Cloudflare Pages env vars:
 *   PAYMOB_HMAC_SECRET  — HMAC secret from Paymob dashboard (Settings → Security)
 *
 * Optional:
 *   PAYMENTS_KV         — KV namespace binding for payment records
 *
 * Paymob sends HMAC as:
 *   - Query parameter: ?hmac=<sha512hex>
 *   - OR request header: hmac: <sha512hex>
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Civil Engineering Suite — Eng. Aymn Asi © 2026
 */

'use strict';

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
  if (env.PAYMENTS_KV) {
    const existing = await env.PAYMENTS_KV.get(`order:${orderId}`, 'json').catch(() => null);
    if (existing?.status === 'paid') {
      // Already confirmed — ACK without processing to stop Paymob retries
      return new Response('', { status: 200, headers: { 'Cache-Control': 'no-store' } });
    }
  }

  // ── Process by outcome ────────────────────────────────────────────────────
  if (success && !pending) {
    // ── CONFIRMED PAYMENT ─────────────────────────────────────────────────
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
