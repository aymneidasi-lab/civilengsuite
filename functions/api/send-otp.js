/**
 * Cloudflare Pages Function — /api/send-otp
 * File location in your CF Pages project: functions/api/send-otp.js
 *
 * SENDS VIA GMAIL SMTP -- not Resend. No domain verification needed;
 * Gmail's own sending domain is already trusted by every mail provider.
 *
 * WHY THIS EXISTS: the Resend version (see git history / previous
 * delivery) requires verifying a domain you own before it can email
 * anyone but your own account. That's free but requires owning a
 * domain. This version is free with zero domain requirement, at the
 * cost of sending from a @gmail.com address instead of a branded one,
 * and needing one new dependency (worker-mailer) that talks raw SMTP
 * over Cloudflare Workers' TCP sockets API.
 *
 * ── SETUP ────────────────────────────────────────────────────────────
 *  1. On the Gmail account you want to send FROM: turn on 2-Step
 *     Verification at myaccount.google.com/security (required -- Gmail
 *     will not issue an App Password without it).
 *  2. Generate an App Password at myaccount.google.com/apppasswords
 *     -> App name: anything (e.g. "Civil Engineering Suite OTP") ->
 *     copy the 16-character code it shows you. This is NOT your normal
 *     Gmail password and won't be shown again.
 *  3. Cloudflare Pages -> your project -> Settings -> Environment
 *     Variables -> add:
 *       GMAIL_ADDRESS = youraccount@gmail.com
 *       GMAIL_APP_PASSWORD = the 16-character code (spaces are fine,
 *                             this code strips them automatically)
 *  4. Add "worker-mailer" as a dependency (see package.json) so
 *     Cloudflare's build installs it before bundling this function.
 *  5. Redeploy.
 *
 *  Optional, for extra capacity/resilience later: add a second account
 *  as GMAIL_ADDRESS_1 + GMAIL_APP_PASSWORD_1 (matched by the same
 *  numeric suffix -- an address without its matching password, or vice
 *  versa, is skipped and logged, not fatal). Not required to start --
 *  a free Gmail account's own daily send limit is far more than a
 *  contact-form OTP flow will use.
 */

import { WorkerMailer } from 'worker-mailer';

/* ── Allowed origins — add your custom domain here if you have one ── */
const ALLOWED_ORIGINS = [
  'https://civilengsuite.pages.dev',
  'https://footing-pro.pages.dev',
  'http://127.0.0.1:5500',   /* local dev */
  'http://localhost:5500',   /* local dev */
];

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

/* ═══════════════════════════════════════ GMAIL ACCOUNT RING ══════════
   Same discovery contract as buildKeyRing() used for the other providers
   in this project (any _N suffix, case-insensitive) but for a PAIRED
   credential: GMAIL_ADDRESS_N needs a matching GMAIL_APP_PASSWORD_N with
   the same suffix, or that slot is skipped (logged, not fatal) rather
   than sent with a missing half of the pair. ═══════════════════════ */

function buildGmailAccountRing(env) {
  const addrPattern = /^GMAIL_ADDRESS(?:_(\d+))?$/i;
  const passPattern = /^GMAIL_APP_PASSWORD(?:_(\d+))?$/i;

  const addrsBySuffix = new Map();
  const passBySuffix  = new Map();

  for (const name of Object.keys(env || {})) {
    const am = addrPattern.exec(name);
    if (am) {
      const value = env[name]?.trim?.();
      if (value) addrsBySuffix.set(am[1] !== undefined ? parseInt(am[1], 10) : -1, value);
      continue;
    }
    const pm = passPattern.exec(name);
    if (pm) {
      const value = env[name]?.trim?.();
      if (value) passBySuffix.set(pm[1] !== undefined ? parseInt(pm[1], 10) : -1, value);
    }
  }

  const suffixes = [...addrsBySuffix.keys()].sort((a, b) => a - b);
  const accounts = [];
  const skipped = [];
  for (const suffix of suffixes) {
    const address  = addrsBySuffix.get(suffix);
    const password = passBySuffix.get(suffix);
    const label = suffix === -1 ? 'GMAIL_ADDRESS' : `GMAIL_ADDRESS_${suffix}`;
    if (!password) { skipped.push(label); continue; }
    // App Passwords are displayed by Google with spaces, e.g.
    // "abcd efgh ijkl mnop" -- accepted with or without them, strip to
    // be safe regardless of how it was pasted into the env var.
    accounts.push({ address, password: password.replace(/\s+/g, ''), suffix, label });
  }

  return { accounts, skipped };
}

// Module-scoped ring pointer — best-effort spreading across requests
// within a reused isolate, not relied on for correctness (same pattern
// as the other rotation points in this project).
const ringPointer = { i: 0 };

/**
 * Round-robin + selective failover walk over the Gmail account ring.
 * Only 'auth_failed' (bad app password / 2FA not enabled on that
 * specific account) and 'rate_limited' (that account's own daily send
 * cap) are treated as account-specific and advance the ring; anything
 * else (malformed message, DNS/network failure reaching smtp.gmail.com)
 * would fail identically for every account, so it breaks immediately.
 */
async function rotateAndSendGmail(pointerState, accounts, sendOneFn) {
  if (accounts.length === 0) {
    const err = new Error('Gmail: no complete GMAIL_ADDRESS/GMAIL_APP_PASSWORD pair configured');
    err.category = 'no_accounts_configured';
    throw err;
  }

  const startIdx = pointerState.i % accounts.length;
  pointerState.i = (pointerState.i + 1) % accounts.length;

  const attemptErrors = [];
  for (let step = 0; step < accounts.length; step++) {
    const idx = (startIdx + step) % accounts.length;
    try {
      await sendOneFn(accounts[idx]);
      return { accountIndex: idx, accountsTried: step + 1 };
    } catch (err) {
      attemptErrors.push({ idx, category: err.category || 'other', message: err.message });
      const isAccountSpecific = err.category === 'auth_failed' || err.category === 'rate_limited';
      if (!isAccountSpecific) break;
    }
  }

  const summary = attemptErrors.map(e => `account#${e.idx}:${e.category}`).join(', ');
  const err = new Error(`Gmail: ${attemptErrors.length} account(s) tried, all failed [${summary}]`);
  err.category = 'exhausted';
  throw err;
}

/**
 * One send attempt through a specific Gmail account via SMTP (port 465,
 * implicit TLS -- avoids the extra STARTTLS upgrade round-trip that
 * port 587 needs). Throws a categorized Error on failure so
 * rotateAndSendGmail can decide whether to try the next account.
 *
 * Error classification is message-text matching, not structured codes --
 * confirmed against worker-mailer v1.2.1's actual source, which throws
 * plain Error objects (e.g. "Invalid login: " + <server response>) with
 * no separate error-code field to branch on. Patterns below match both
 * the library's own wrapper text and Gmail's standard SMTP enhanced
 * status codes (534-5.7.9 app password required, 535-5.7.8 bad
 * credentials, 421-4.7.0 / 454-4.7.0 temporary throttle).
 */
async function singleSendGmail({ address, password }, { toEmail, subject, html }) {
  try {
    await WorkerMailer.send(
      {
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        credentials: { username: address, password },
      },
      {
        from: { name: 'Civil Engineering Suite', email: address },
        to: toEmail,
        subject,
        html,
      },
    );
  } catch (sendErr) {
    const msg = String(sendErr?.message || sendErr);
    const err = new Error(`Gmail send failed (${address}): ${msg}`);
    if (/invalid login|no supported auth|authentication|credential|5\.7\.(0|8|9|14)/i.test(msg)) {
      err.category = 'auth_failed';
    } else if (/rate|too many|try again later|4\.7\.|4\.5\.3|421|454/i.test(msg)) {
      err.category = 'rate_limited';
    } else {
      err.category = 'other';
    }
    throw err;
  }
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

  /* Build the Gmail account ring from CF environment */
  const { accounts, skipped } = buildGmailAccountRing(context.env);
  if (skipped.length) {
    console.warn(`[send-otp] Incomplete Gmail credential pair(s), skipped: ${skipped.join(', ')}`);
  }
  if (accounts.length === 0) {
    console.error('[send-otp] No complete GMAIL_ADDRESS/GMAIL_APP_PASSWORD pair is set.');
    return json({ error: 'Server configuration error.' }, 500, origin);
  }

  const safeName = (to_name || 'there').replace(/[<>&"]/g, '');

  /* Build email HTML — identical template, unchanged */
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

  /* Send via Gmail SMTP, walking the account ring on account-specific failures */
  try {
    const { accountIndex, accountsTried } = await rotateAndSendGmail(
      ringPointer,
      accounts,
      (account) => singleSendGmail(account, {
        toEmail: to_email,
        subject: 'Your verification code — Civil Engineering Suite',
        html: emailHtml,
      }),
    );
    if (accountsTried > 1) {
      console.warn(`[send-otp] Gmail succeeded on ${accounts[accountIndex].label} after ${accountsTried - 1} failed attempt(s).`);
    }
  } catch (err) {
    console.error(`[send-otp] Gmail send failed: ${err.message}`);
    return json({ error: 'Failed to send verification email.' }, 502, origin);
  }

  return json({ success: true }, 200, origin);
}

/* ── Preflight ── */
export async function onRequestOptions(context) {
  const origin = context.request.headers.get('Origin') || '';
  return new Response(null, { status: 204, headers: corsHeaders(origin) });
}
