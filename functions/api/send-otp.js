/**
 * Cloudflare Pages Function — /api/send-otp
 * File location in your CF Pages project: functions/api/send-otp.js
 *
 * Setup:
 *  1. Create free account at resend.com
 *  2. Go to API Keys → Create API Key → copy it
 *  3. In Cloudflare Pages dashboard → your project → Settings →
 *     Environment Variables → Add: RESEND_API_KEY = re_XXXXXXXXXXXXXXXX
 *  4. Optional but recommended: verify your domain at resend.com/domains
 *     Then change RESEND_FROM below to: 'Suite <noreply@yourdomain.com>'
 */

/* ── Allowed origins — add your custom domain here if you have one ── */
const ALLOWED_ORIGINS = [
  'https://civilengsuite.pages.dev',
  'https://footing-pro.pages.dev',
  'http://127.0.0.1:5500',   /* local dev */
  'http://localhost:5500',   /* local dev */
];

/* ── Sender address — change once you verify a domain on resend.com ── */
const RESEND_FROM = 'Civil Engineering Suite <onboarding@resend.dev>';

/* ── Rate limit: max requests per IP per 10-minute window ── */
const RATE_LIMIT   = 5;
const WINDOW_MS    = 10 * 60 * 1000; /* 10 minutes */

/* In-memory rate limit store (resets per isolate/cold-start — good enough) */
const _rateMap = new Map();

function isRateLimited(ip) {
  const now  = Date.now();
  const entry = _rateMap.get(ip) || { count: 0, window: now + WINDOW_MS };
  if (now > entry.window) { entry.count = 0; entry.window = now + WINDOW_MS; }
  entry.count++;
  _rateMap.set(ip, entry);
  return entry.count > RATE_LIMIT;
}

/* ── Strict email format check (server-side duplicate of client check) ── */
function isValidEmail(email) {
  return /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(email);
}

/* ── CORS helper ── */
function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin' : ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary'                        : 'Origin',
  };
}

function json(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

/* ═══════════════════════════════════════════════════════════ HANDLER */
export async function onRequestPost(context) {
  const origin = context.request.headers.get('Origin') || '';
  const ip     = context.request.headers.get('CF-Connecting-IP') || 'unknown';

  /* Rate limit */
  if (isRateLimited(ip)) {
    return json({ error: 'Too many requests — try again in 10 minutes.' }, 429, origin);
  }

  /* Parse body */
  let body;
  try {
    body = await context.request.json();
  } catch {
    return json({ error: 'Invalid JSON body.' }, 400, origin);
  }

  const { to_email, to_name, otp_code } = body;

  /* Input validation */
  if (!to_email || !isValidEmail(to_email)) {
    return json({ error: 'Invalid email address.' }, 400, origin);
  }
  if (!otp_code || !/^\d{6}$/.test(otp_code)) {
    return json({ error: 'Invalid OTP format.' }, 400, origin);
  }

  /* Get API key from CF environment */
  const RESEND_API_KEY = context.env.RESEND_API_KEY;
  if (!RESEND_API_KEY) {
    console.error('[send-otp] RESEND_API_KEY environment variable is not set.');
    return json({ error: 'Server configuration error.' }, 500, origin);
  }

  const safeName = (to_name || 'there').replace(/[<>&"]/g, '');

  /* Build email HTML */
  const emailHtml = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verification Code</title></head>
<body style="margin:0;padding:0;background:#f7f9fc;font-family:'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f7f9fc;padding:40px 0;">
    <tr><td align="center">
      <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;
             border:1px solid #dde3ea;overflow:hidden;max-width:480px;">
        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#0A1A2E,#1A3A5C);padding:28px 36px;">
            <h1 style="margin:0;color:#F5D88A;font-size:1.1rem;font-weight:700;letter-spacing:0.04em;">
              🏗️ Civil Engineering Suite
            </h1>
          </td>
        </tr>
        <!-- Body -->
        <tr>
          <td style="padding:36px;">
            <p style="margin:0 0 16px;color:#1a1a2e;font-size:1rem;">
              Hi <strong>${safeName}</strong>,
            </p>
            <p style="margin:0 0 24px;color:#5a6a7a;font-size:0.95rem;line-height:1.6;">
              Your email verification code for the contact form is:
            </p>
            <!-- OTP Code -->
            <div style="background:#f0f4f8;border:2px dashed #C17B1A;border-radius:10px;
                        text-align:center;padding:24px;margin:0 0 24px;">
              <span style="font-size:2.4rem;font-weight:900;letter-spacing:0.3em;
                           color:#C17B1A;font-family:'Courier New',monospace;">
                ${otp_code}
              </span>
            </div>
            <p style="margin:0 0 8px;color:#5a6a7a;font-size:0.9rem;">
              ⏱️ This code expires in <strong>10 minutes</strong>.
            </p>
            <p style="margin:0 0 24px;color:#5a6a7a;font-size:0.9rem;">
              If you did not request this, you can safely ignore this email.
            </p>
            <hr style="border:none;border-top:1px solid #dde3ea;margin:0 0 20px;">
            <p style="margin:0;color:#9aa5b1;font-size:0.8rem;">
              — Civil Engineering Suite · Eng. Aymn Asi
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  /* Send via Resend */
  let resendRes;
  try {
    resendRes = await fetch('https://api.resend.com/emails', {
      method : 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type' : 'application/json',
      },
      body: JSON.stringify({
        from   : RESEND_FROM,
        to     : [to_email],
        subject: 'Your verification code — Civil Engineering Suite',
        html   : emailHtml,
      }),
    });
  } catch (err) {
    console.error('[send-otp] Resend fetch failed:', err);
    return json({ error: 'Failed to reach email provider.' }, 502, origin);
  }

  if (!resendRes.ok) {
    const errBody = await resendRes.text();
    console.error('[send-otp] Resend error:', resendRes.status, errBody);
    return json({ error: 'Email provider rejected the request.' }, 502, origin);
  }

  return json({ success: true }, 200, origin);
}

/* ── Preflight ── */
export async function onRequestOptions(context) {
  const origin = context.request.headers.get('Origin') || '';
  return new Response(null, { status: 204, headers: corsHeaders(origin) });
}
