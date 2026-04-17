/**
 * GET /api/payment/verify?order_id=<id>
 * ─────────────────────────────────────────────────────────────────────────────
 * Verifies payment status for a given Paymob order ID.
 * Strategy: KV lookup first (fast), then Paymob API fallback (authoritative).
 *
 * Required Cloudflare Pages env vars:
 *   PAYMOB_SECRET_KEY  — for direct Paymob API fallback queries
 *
 * Optional:
 *   PAYMENTS_KV        — KV namespace binding (fast path — returns immediately)
 *
 * Response shape:
 *   { verified: true,  order_id: "...", currency: "EGP" }  — confirmed paid
 *   { verified: false, order_id: "...", reason: "..." }     — not paid / unknown
 *   { verified: false, error: "..." }                       — request/config error
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Civil Engineering Suite — Eng. Aymn Asi © 2026
 */

'use strict';

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control':          'no-store, no-cache',
  'Content-Type':           'application/json',
};

function jsonRes(status, body) {
  return new Response(JSON.stringify(body), { status, headers: SECURITY_HEADERS });
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== 'GET') {
    return new Response('Method Not Allowed', {
      status: 405,
      headers: { Allow: 'GET', 'Cache-Control': 'no-store' },
    });
  }

  const url     = new URL(request.url);
  const orderId = (url.searchParams.get('order_id') || '').trim();

  // Order IDs from Paymob are positive integers — strict validation
  if (!orderId || !/^\d{1,20}$/.test(orderId)) {
    return jsonRes(400, { verified: false, error: 'order_id must be a numeric string' });
  }

  // ── KV fast path ──────────────────────────────────────────────────────────
  if (env.PAYMENTS_KV) {
    const record = await env.PAYMENTS_KV
      .get(`order:${orderId}`, 'json')
      .catch(() => null);

    if (record?.status === 'paid') {
      return jsonRes(200, {
        verified:  true,
        order_id:  orderId,
        currency:  record.currency || null,
        paid_at:   record.paid_at  || null,
      });
    }

    if (record?.status === 'failed') {
      return jsonRes(200, {
        verified:  false,
        order_id:  orderId,
        reason:    'payment_failed',
        error_msg: record.error_message || null,
      });
    }

    if (record?.status === 'pending_payment') {
      return jsonRes(200, {
        verified:  false,
        order_id:  orderId,
        reason:    'pending_payment',
        currency:  record.currency || null,
      });
    }
  }

  // ── Paymob API fallback ────────────────────────────────────────────────────
  const secretKey = (env.PAYMOB_SECRET_KEY || '').trim();
  if (!secretKey) {
    console.error('[payment:verify] PAYMOB_SECRET_KEY not configured');
    return jsonRes(503, { verified: false, error: 'Payment service not configured' });
  }

  let paymobRes;
  try {
    paymobRes = await fetch(
      `https://accept.paymob.com/api/ecommerce/orders/${encodeURIComponent(orderId)}`,
      { headers: { Authorization: `Token ${secretKey}` } }
    );
  } catch (err) {
    console.error('[payment:verify] Paymob API unreachable:', err.message);
    return jsonRes(502, { verified: false, error: 'Payment gateway unreachable' });
  }

  if (paymobRes.status === 404) {
    return jsonRes(200, { verified: false, order_id: orderId, reason: 'order_not_found' });
  }

  if (!paymobRes.ok) {
    console.error('[payment:verify] Paymob returned', paymobRes.status);
    return jsonRes(502, { verified: false, error: 'Gateway error during verification' });
  }

  let order;
  try {
    order = await paymobRes.json();
  } catch {
    return jsonRes(502, { verified: false, error: 'Invalid gateway response' });
  }

  // An order is paid when Paymob locks it (no further changes) and paid_amount > 0
  const paidAmount = Number(order.paid_amount_cents) || 0;
  const isLocked   = order.is_payment_locked === true;
  const verified   = paidAmount > 0 && isLocked;

  // Back-fill KV for future fast-path lookups
  if (verified && env.PAYMENTS_KV) {
    await env.PAYMENTS_KV.put(
      `order:${orderId}`,
      JSON.stringify({
        status:       'paid',
        amount_cents: paidAmount,
        currency:     order.currency || '',
        paid_at:      new Date().toISOString(),
      }),
      { expirationTtl: 60 * 60 * 24 * 730 }
    ).catch(() => null);
  }

  return jsonRes(200, {
    verified,
    order_id: orderId,
    currency: order.currency || null,
    ...(verified
      ? { paid_at: new Date().toISOString() }
      : { reason: paidAmount > 0 ? 'not_locked' : 'not_paid' }
    ),
  });
}
