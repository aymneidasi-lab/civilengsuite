/**
 * Cloudflare Pages Function — /api/send-otp
 * File location in your CF Pages project: functions/api/send-otp.js
 *
 * Sends OTP verification emails via Gmail SMTP (worker-mailer), not Resend.
 *
 * [ROOT-CAUSE] The file this replaces was still the RESEND SANDBOX version
 * (RESEND_FROM = 'onboarding@resend.dev'). Per Resend's own docs
 * (resend.com/docs/knowledge-base/403-error-resend-dev-domain), that
 * address "can only send emails to the email address associated with
 * your Resend account" — every other recipient gets a silent 403, which
 * the old code correctly caught and turned into a generic 500. The
 * `to_email` wiring in that file was never the problem; the provider was.
 * That is why it only ever worked for the one address the Resend account
 * was signed up with. This file switches transport to Gmail SMTP, which
 * has no such single-recipient restriction once authenticated — the
 * `GMAIL_ADDRESS` you configure is the AUTHENTICATING account, not a
 * delivery allow-list.
 *
 * Setup:
 *  1. Cloudflare Pages → your project → Settings → Runtime →
 *     Compatibility Flags → add `nodejs_compat` for Production (and
 *     Preview, if used). Not load-bearing for THIS library version — its
 *     compiled bundle imports no `node:` builtins and no `Buffer`, verified
 *     by inspecting node_modules/worker-mailer/dist/index.mjs directly —
 *     but it's worker-mailer's own documented Quick-Start prerequisite.
 *     Zero cost to add; removes one variable if something misbehaves.
 *     (This tab is not the same as "Variables and secrets" — the two
 *     screenshots provided only show the latter.)
 *  2. Settings → Variables and secrets → GMAIL_ADDRESS / GMAIL_APP_PASSWORD
 *     (Secret type is fine — encryption only blocks reading the value back
 *     in the dashboard, not runtime access). Optional standby accounts:
 *     GMAIL_ADDRESS_1 / GMAIL_APP_PASSWORD_1, _2, etc. Each pair must
 *     share the same numeric suffix.
 *  3. package.json (project root) must list "worker-mailer": "^1.2.1" —
 *     already present in this project's package.json; confirm the build
 *     log shows it installing (Cloudflare only runs `npm install` on
 *     deploy, not retroactively for already-live deployments).
 *
 * [GMAIL-RING] Mirrors the buildKeyRing() convention used for
 * RESEND_API_KEY_N / GROQ_API_KEY_N elsewhere in this codebase, adapted
 * for PAIRED credentials — an address alone or a password alone can't
 * authenticate anything, so both halves of a suffix must be present.
 * Unlike the Resend ring, every Gmail pair is a fully independent Google
 * account (independent quota, independent sending reputation), so there
 * is no Resend-style "account-wide failure, stop rotating" branch here —
 * every failure just advances to the next pair.
 */

import { WorkerMailer } from '../_lib/worker-mailer.mjs';

/* ── Allowed origins — add your custom domain here if you have one ── */
const ALLOWED_ORIGINS = [
  'https://civilengsuite.pages.dev',
  'https://footing-pro.pages.dev',
  'http://127.0.0.1:5500',   /* local dev */
  'http://localhost:5500',   /* local dev */
];

/* ── Gmail SMTP transport config ──
   Port 465 + secure:true = implicit TLS from the first byte, no STARTTLS
   upgrade handshake. Chosen over 587+startTls for one fewer negotiated
   step in a from-scratch SMTP/TLS client; Gmail supports both. */
const GMAIL_HOST    = 'smtp.gmail.com';
const GMAIL_PORT    = 465;
const SENDER_NAME   = 'Civil Engineering Suite';
const ADDRESS_BASE  = 'GMAIL_ADDRESS';
const PASSWORD_BASE = 'GMAIL_APP_PASSWORD';

/* ── Rate limit: max requests per IP per 10-minute window ── */
const RATE_LIMIT = 5;
const WINDOW_MS  = 10 * 60 * 1000; /* 10 minutes */

/* In-memory rate limit store (resets per isolate/cold-start — good enough).
   Resource note: entries are never explicitly evicted, only their count/
   window fields are reset in place once their window elapses. Release
   mechanism is isolate recycling, not a TTL sweep — pre-existing,
   unchanged, out of scope for this fix (see Resource Lifecycle
   Verification in the response this file shipped with). */
const _rateMap = new Map();

function isRateLimited(ip) {
  const now = Date.now();
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

function json(body, status, origin, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin), ...(extraHeaders || {}) },
  });
}

/**
 * buildGmailRing — finds every GMAIL_ADDRESS(_N) / GMAIL_APP_PASSWORD(_N)
 * pair in the environment, case-insensitive, matched by numeric suffix
 * (base name with no suffix = index -1, tried first). A name present on
 * only one side of a pair is reported in `incomplete` and skipped, since
 * it can't authenticate anything alone. Identical (address, password)
 * pairs pasted into two slots are de-duplicated.
 *
 * @param {object} env
 * @returns {{ pairs: {address:string, password:string, addressName:string}[], incomplete: string[] }}
 */
function buildGmailRing(env) {
  const addrPattern = new RegExp(`^${ADDRESS_BASE}(?:_(\\d+))?$`, 'i');
  const passPattern = new RegExp(`^${PASSWORD_BASE}(?:_(\\d+))?$`, 'i');

  const addrs  = new Map(); // suffix -> { name, value }
  const passes = new Map(); // suffix -> { name, value }

  for (const name of Object.keys(env || {})) {
    let m = addrPattern.exec(name);
    if (m) {
      const value = env[name]?.trim?.();
      if (value) addrs.set(m[1] !== undefined ? parseInt(m[1], 10) : -1, { name, value });
      continue;
    }
    m = passPattern.exec(name);
    if (m) {
      const value = env[name]?.trim?.();
      if (value) passes.set(m[1] !== undefined ? parseInt(m[1], 10) : -1, { name, value });
    }
  }

  const suffixes = [...new Set([...addrs.keys(), ...passes.keys()])].sort((a, b) => a - b);

  const pairs = [];
  const incomplete = [];
  const seenValues = new Set();

  for (const suf of suffixes) {
    const a = addrs.get(suf);
    const p = passes.get(suf);
    if (a && p) {
      const dedupeKey = `${a.value.toLowerCase()}::${p.value}`;
      if (seenValues.has(dedupeKey)) continue; // same pair pasted into two slots
      seenValues.add(dedupeKey);
      pairs.push({ address: a.value, password: p.value, addressName: a.name });
    } else {
      incomplete.push((a || p).name);
    }
  }

  return { pairs, incomplete };
}

/**
 * Tries each ring pair in FIXED order (index 0 first). Every pair is an
 * independent Gmail account, so — unlike the Resend ring this replaces —
 * there is no "account-wide, stop rotating" case: every failure just
 * advances to the next pair.
 *
 * The connection is opened, used, and closed entirely inside this
 * function's loop body. It is never created at module scope: Cloudflare
 * Workers TCP sockets cannot be created in global scope and shared across
 * requests (developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)
 * — each invocation of this handler must open its own.
 */
async function sendViaGmailRing(pairs, emailOptions) {
  const attempts = [];

  for (let i = 0; i < pairs.length; i++) {
    const { address, password, addressName } = pairs[i];
    let mailer;
    try {
      mailer = await WorkerMailer.connect({
        credentials: { username: address, password },
        authType: ['plain', 'login'],
        host: GMAIL_HOST,
        port: GMAIL_PORT,
        secure: true,
        socketTimeoutMs: 10000,
        responseTimeoutMs: 10000,
      });
    } catch (err) {
      // No mailer instance exists to close here — connect() itself failed
      // (bad credentials, network/DNS failure, or a timed-out handshake).
      // Any partially-opened socket is reclaimed by the Workers runtime
      // when this request's execution context ends — there is no handle
      // for request-scoped code to close early.
      attempts.push({ index: i, name: addressName, stage: 'connect', message: String(err?.message || err) });
      continue;
    }

    try {
      await mailer.send({
        ...emailOptions,
        from: { name: SENDER_NAME, email: address }, // must match the authenticating account
      });
      return { ok: true, keyIndex: i, keysTried: i + 1 };
    } catch (err) {
      attempts.push({ index: i, name: addressName, stage: 'send', message: String(err?.message || err) });
      continue;
    } finally {
      // Runs on both the success return and the caught failure. close()
      // is internally defensive (it wraps its own QUIT/socket-close in
      // try/catch), so it's safe unconditionally in a finally block and
      // won't mask whatever error is already in flight.
      //
      // This is why the ring calls WorkerMailer.connect()+send()+close()
      // directly instead of the static WorkerMailer.send() one-off
      // helper: that helper's internal body is
      // `await r.send(t), await r.close()` with no try/finally around
      // it, so a failed send leaks the connection — confirmed by reading
      // node_modules/worker-mailer/dist/index.mjs directly.
      await mailer.close();
    }
  }

  return { ok: false, keysTried: attempts.length, attempts };
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

  /* Get Gmail credential ring from CF environment */
  const { pairs: gmailPairs, incomplete } = buildGmailRing(context.env);
  if (incomplete.length > 0) {
    console.warn('[send-otp] Incomplete Gmail credential pair(s), skipped:', incomplete.join(', '));
  }
  if (gmailPairs.length === 0) {
    console.error('[send-otp] No complete GMAIL_ADDRESS*/GMAIL_APP_PASSWORD* pair is set.');
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

  /* Plain-text alternative — same content as emailHtml, no markup.
     Kept in sync by hand since the HTML is hand-written, not templated
     from a shared content object; update both if the copy changes.
     Absence of a text/plain part on an otherwise HTML-only message is a
     cited spam-filter signal, independent of authentication correctness. */
  const emailText =
`Hi ${safeName},

Your email verification code for the contact form is: ${otp_code}

This code expires in 10 minutes.

If you did not request this, you can safely ignore this email.

— Civil Engineering Suite · Eng. Aymn Asi`;

  /* Send via Gmail SMTP, rotating the ring on any failure */
  const result = await sendViaGmailRing(gmailPairs, {
    to     : { name: safeName, email: to_email },
    subject: 'Your verification code — Civil Engineering Suite',
    html   : emailHtml,
    text   : emailText,
  });

  if (!result.ok) {
    console.error('[send-otp] Gmail ring exhausted:', JSON.stringify({
      pairsConfigured: gmailPairs.length,
      attempts: result.attempts,
    }));
    return json({ error: 'Email provider rejected the request.' }, 502, origin);
  }

  console.log('[send-otp] sent', JSON.stringify({
    keyIndex : result.keyIndex,
    keysTried: result.keysTried,
  }));

  return json({ success: true }, 200, origin, { 'X-OTP-KeyIndex': String(result.keyIndex) });
}

/* ── Preflight ── */
export async function onRequestOptions(context) {
  const origin = context.request.headers.get('Origin') || '';
  return new Response(null, { status: 204, headers: corsHeaders(origin) });
}
