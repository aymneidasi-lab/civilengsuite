/**
 * POST /api/payment/create-intention
 * ─────────────────────────────────────────────────────────────────────────────
 * Creates a Paymob v2 Payment Intention server-side.
 * The secret key is NEVER exposed to the client.
 *
 * Required Cloudflare Pages env vars (set in dashboard → Settings → Variables):
 *   PAYMOB_SECRET_KEY          — Paymob Secret Key  (sk_live_...)
 *   PAYMOB_PUBLIC_KEY          — Paymob Public Key  (pk_live_...)
 *   PAYMOB_INTEGRATIONS_EGP    — comma-separated integration IDs for EGP
 *                                (Cards / Meeza / Vodafone Cash / Fawry / ValU)
 *   PAYMOB_INTEGRATIONS_GULF   — comma-separated integration IDs for Gulf currencies
 *                                (Cards / Apple Pay — same IDs across SAR/AED/KWD/BHD/OMR/QAR)
 *
 * Optional:
 *   PAYMENTS_KV                — KV namespace binding (bind in Pages dashboard)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Civil Engineering Suite — Eng. Aymn Asi © 2026
 */

'use strict';

// ── Product catalog ───────────────────────────────────────────────────────────
// Prices in smallest currency unit (piasters / halalas / fils / baisa / dirhams)
// KWD, BHD, OMR = 3-decimal currencies → multiply display price by 1000
const PRODUCTS = {
  'footing-pro-personal': {
    name_en: 'Footing Pro v.2026 — Personal License',
    name_ar: 'فوتينج برو v.2026 — ترخيص شخصي',
    prices: {
      EGP: 49900,  // 499.00 EGP
      SAR: 4900,   // 49.00  SAR
      AED: 4900,   // 49.00  AED
      KWD: 4900,   // 4.900  KWD
      BHD: 1900,   // 1.900  BHD
      OMR: 4900,   // 4.900  OMR
      QAR: 4900,   // 49.00  QAR
    },
  },
};

const GULF_CURRENCIES  = new Set(['SAR', 'AED', 'KWD', 'BHD', 'OMR', 'QAR']);
const ALLOWED_CURRENCIES = new Set(['EGP', 'SAR', 'AED', 'KWD', 'BHD', 'OMR', 'QAR']);

const SITE_ORIGIN = 'https://civilengsuite.is-a.dev';

// ── Response factories ────────────────────────────────────────────────────────
const BASE_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control': 'no-store',
  'Vary': 'Origin',
};

function jsonOk(data, origin) {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: {
      ...BASE_HEADERS,
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': origin || SITE_ORIGIN,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}

function jsonError(status, message) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { ...BASE_HEADERS, 'Content-Type': 'application/json' },
  });
}

// ── Input helpers ─────────────────────────────────────────────────────────────
function sanitize(val, max = 100) {
  return String(val ?? '').trim().slice(0, max);
}

function isValidEmail(email) {
  return /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(email);
}

function isValidPhone(phone) {
  // Strip formatting, then check for 7–18 digits with optional leading +
  const stripped = phone.replace(/[\s\-().]/g, '');
  return /^\+?[0-9]{7,18}$/.test(stripped);
}

// ── Integration IDs by currency ───────────────────────────────────────────────
function getIntegrationIds(env, currency) {
  const envKey = GULF_CURRENCIES.has(currency)
    ? 'PAYMOB_INTEGRATIONS_GULF'
    : `PAYMOB_INTEGRATIONS_${currency}`;
  const raw = (env[envKey] || '').trim();
  if (!raw) return [];
  return raw
    .split(',')
    .map(s => parseInt(s.trim(), 10))
    .filter(n => Number.isFinite(n) && n > 0);
}

// ── Main handler ──────────────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method;

  // ── CORS preflight ─────────────────────────────────────────────────────────
  if (method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        ...BASE_HEADERS,
        'Access-Control-Allow-Origin':  SITE_ORIGIN,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age':       '3600',
      },
    });
  }

  if (method !== 'POST') {
    return new Response('Method Not Allowed', {
      status: 405,
      headers: { ...BASE_HEADERS, Allow: 'POST, OPTIONS' },
    });
  }

  // ── CSRF: validate origin ──────────────────────────────────────────────────
  const origin  = request.headers.get('Origin') || '';
  const referer = request.headers.get('Referer') || '';
  if (!origin.startsWith(SITE_ORIGIN) && !referer.startsWith(SITE_ORIGIN)) {
    return jsonError(403, 'Forbidden');
  }

  // ── Content-Type check ─────────────────────────────────────────────────────
  const ct = request.headers.get('Content-Type') || '';
  if (!ct.includes('application/json')) {
    return jsonError(415, 'Content-Type must be application/json');
  }

  // ── Parse body ─────────────────────────────────────────────────────────────
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'Invalid JSON body');
  }

  // ── Validate product ───────────────────────────────────────────────────────
  const productId = sanitize(body.product_id, 60);
  const product   = PRODUCTS[productId];
  if (!product) return jsonError(400, 'Unknown product');

  // ── Validate currency ──────────────────────────────────────────────────────
  const currency = sanitize(body.currency, 3).toUpperCase();
  if (!ALLOWED_CURRENCIES.has(currency)) return jsonError(400, 'Unsupported currency');

  const amount = product.prices[currency];
  if (!amount) return jsonError(400, 'Product not available in this currency');

  // ── Validate customer fields ───────────────────────────────────────────────
  const firstName = sanitize(body.first_name, 50);
  const lastName  = sanitize(body.last_name,  50);
  const email     = sanitize(body.email, 150).toLowerCase();
  const phone     = sanitize(body.phone, 25);

  if (!firstName)                    return jsonError(400, 'first_name is required');
  if (!lastName)                     return jsonError(400, 'last_name is required');
  if (!email || !isValidEmail(email)) return jsonError(400, 'A valid email address is required');
  if (!phone || !isValidPhone(phone)) return jsonError(400, 'A valid phone number is required');

  // ── Env validation ─────────────────────────────────────────────────────────
  const secretKey = (env.PAYMOB_SECRET_KEY || '').trim();
  const publicKey = (env.PAYMOB_PUBLIC_KEY || '').trim();
  if (!secretKey || !publicKey) {
    console.error('[payment:create-intention] PAYMOB_SECRET_KEY or PAYMOB_PUBLIC_KEY not set');
    return jsonError(503, 'Payment gateway not configured');
  }

  const integrationIds = getIntegrationIds(env, currency);
  if (!integrationIds.length) {
    console.error(`[payment:create-intention] No integration IDs for currency ${currency}`);
    return jsonError(503, 'No payment methods configured for this currency');
  }

  const clientIp = (request.headers.get('CF-Connecting-IP') || 'unknown')
    .split(',')[0].trim().slice(0, 45);

  // ── Build Paymob Intention payload ─────────────────────────────────────────
  const intentionBody = {
    amount,
    currency,
    payment_methods: integrationIds,
    items: [{
      name:        product.name_en,
      amount,
      description: `${product.name_en} — ${product.name_ar}`,
      quantity:    1,
    }],
    billing_data: {
      first_name:   firstName,
      last_name:    lastName,
      email,
      phone_number: phone,
    },
    customer: {
      first_name: firstName,
      last_name:  lastName,
      email,
    },
    notification_url: `${SITE_ORIGIN}/api/payment/webhook`,
    redirection_url:  `${SITE_ORIGIN}/payment/success`,
    metadata: {
      product_id: productId,
      client_ip:  clientIp,
      ts:         new Date().toISOString(),
    },
  };

  // ── Call Paymob v2 Intention API ───────────────────────────────────────────
  let paymobRes;
  try {
    paymobRes = await fetch('https://accept.paymob.com/v1/intention/', {
      method: 'POST',
      headers: {
        Authorization:  `Token ${secretKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(intentionBody),
    });
  } catch (err) {
    console.error('[payment:create-intention] Network error reaching Paymob:', err.message);
    return jsonError(502, 'Payment gateway unreachable — please try again');
  }

  if (!paymobRes.ok) {
    const errBody = await paymobRes.text().catch(() => '');
    console.error(
      `[payment:create-intention] Paymob returned ${paymobRes.status}:`,
      errBody.slice(0, 400)
    );
    return jsonError(502, 'Payment gateway returned an error — please try again');
  }

  let data;
  try {
    data = await paymobRes.json();
  } catch {
    return jsonError(502, 'Invalid response from payment gateway');
  }

  if (!data.client_secret) {
    console.error('[payment:create-intention] No client_secret in Paymob response');
    return jsonError(502, 'Payment initiation failed — please try again');
  }

  // ── Optionally store pending order in KV ───────────────────────────────────
  const intentionId = data.id || data.order_id || null;
  if (env.PAYMENTS_KV && intentionId) {
    await env.PAYMENTS_KV.put(
      `order:${intentionId}`,
      JSON.stringify({
        status:     'pending',
        product_id: productId,
        currency,
        amount,
        email,
        created_at: new Date().toISOString(),
      }),
      { expirationTtl: 60 * 60 * 24 } // Pending orders expire in 24 h
    ).catch(err => console.warn('[payment:create-intention] KV write error:', err.message));
  }

  // ── Return only client-safe fields ────────────────────────────────────────
  return jsonOk({
    client_secret: data.client_secret,
    public_key:    publicKey,
    order_id:      intentionId,
    amount,
    currency,
  }, origin.startsWith(SITE_ORIGIN) ? origin : SITE_ORIGIN);
}
