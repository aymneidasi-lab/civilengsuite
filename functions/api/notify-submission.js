/**
 * Cloudflare Pages Function — /api/notify-submission
 * File location in your CF Pages project: functions/api/notify-submission.js
 *
 * [WHY THIS FILE EXISTS] Web3Forms already delivers contact-form
 * submissions and drives the visitor-facing "Message sent" success state
 * — that keeps working, completely unchanged. What was landing in spam
 * is specifically Web3Forms' OWNER-facing notification (From: "PCsuite
 * Website" <notify+{hash}@web3forms.com>), because Gmail is evaluating a
 * message from a third-party relay domain it has no history with — a
 * structurally different problem from the OTP spam issue, which was a
 * content/display-name issue on mail Gmail's own MTA was already
 * relaying (see [SPAM-FOLDER-FIX] in send-otp.js).
 *
 * This endpoint adds a SECOND, independent owner-notification sent via
 * Gmail SMTP self-send: authenticate as GMAIL_ADDRESS, send TO that same
 * GMAIL_ADDRESS. Self-to-self mail through Gmail's own MTA doesn't have
 * a third-party relay's cold-sender problem — it's the same mechanism
 * that already fixed OTP deliverability, applied to a path where the
 * account is BOTH sender and recipient. Web3Forms is not removed,
 * disabled, or modified anywhere; this is purely additive redundancy for
 * the one recipient (the site owner) who was actually missing mail.
 *
 * [TRIGGER] Called from client-side JS, in parallel with (not gating,
 * not gated by) the existing Web3Forms fetch — see the submit handler in
 * pc_suite_v20.html / footing_pro_v20_merged.html. Fire-and-forget: the
 * client never awaits this before proceeding, and swallows any failure
 * silently. A failure here must never surface to the visitor or affect
 * the Web3Forms-driven success/error UI.
 *
 * [WHY THIS DUPLICATES buildGmailRing/sendViaGmailRing FROM send-otp.js
 * INSTEAD OF IMPORTING THEM] send-otp.js is already deployed and its
 * spam fix is confirmed working. Refactoring its internals into a shared
 * module to satisfy this file would touch a proven file for a DRY
 * benefit only — pure downside risk, no functional gain. It also isn't
 * a clean 1:1 reuse: this file's send function picks the recipient
 * dynamically per ring-pair attempt (see sendSelfNotifyViaGmailRing
 * below), which send-otp.js's version doesn't do and shouldn't be made
 * to do just for this. Two call sites with a real behavioral difference
 * between them — duplication is the lower-risk choice. If a third
 * endpoint ever needs this pattern, extract functions/_lib/gmail-
 * sender.mjs at that point, not before.
 *
 * Setup: none beyond what send-otp.js already requires. Same
 * GMAIL_ADDRESS(_N)/GMAIL_APP_PASSWORD(_N) secrets, same project, same
 * compatibility flags. No new environment variables to add.
 */

import { WorkerMailer } from '../_lib/worker-mailer.mjs';

/* ── Allowed origins — keep in sync with functions/api/send-otp.js ── */
const ALLOWED_ORIGINS = [
  'https://civilengsuite.pages.dev',
  'https://footing-pro.pages.dev',
  'http://127.0.0.1:5500',   /* local dev */
  'http://localhost:5500',   /* local dev */
];

const GMAIL_HOST    = 'smtp.gmail.com';
const GMAIL_PORT    = 465;
const ADDRESS_BASE  = 'GMAIL_ADDRESS';
const PASSWORD_BASE = 'GMAIL_APP_PASSWORD';

/* Same reasoning as send-otp.js's [SPAM-FOLDER-FIX]: a person's name
   next to a personal @gmail.com From address is the low-suspicion
   pairing; a brand name next to it reads structurally like
   impersonation — even on a message a Gmail account sends to itself. */
const SENDER_PERSON_NAME = 'Eng. Aymn Asi';

/* ── Rate limit: separate pool from send-otp.js's, same shape/values.
   This endpoint can't be used to spam third parties (recipient is
   always whichever Gmail account authenticates, never attacker-
   controlled) — the limit here exists to stop quota exhaustion /
   annoyance-flooding of the owner's own inbox, not third-party abuse. */
const RATE_LIMIT = 5;
const WINDOW_MS  = 10 * 60 * 1000; /* 10 minutes */

/* In-memory, isolate-scoped — identical resource shape to send-otp.js's
   _rateMap. No explicit eviction; entries are reset in place once their
   window elapses. Released by isolate recycling, not a TTL sweep. */
const _rateMap = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  const entry = _rateMap.get(ip) || { count: 0, window: now + WINDOW_MS };
  if (now > entry.window) { entry.count = 0; entry.window = now + WINDOW_MS; }
  entry.count++;
  _rateMap.set(ip, entry);
  return entry.count > RATE_LIMIT;
}

function isValidEmail(email) {
  return /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(email);
}

/* Full HTML-context escaping (& first — order matters, escaping & after
   the others would double-escape the entities they just produced). The
   `message` field is free-text up to 2000 chars straight from a public
   form; every one of these characters is attacker-reachable. */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

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
 * buildGmailRing — identical matching/de-duplication logic to
 * send-otp.js's function of the same name: every GMAIL_ADDRESS(_N) /
 * GMAIL_APP_PASSWORD(_N) pair in the environment, case-insensitive,
 * matched by numeric suffix, incomplete pairs skipped and reported.
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
      if (seenValues.has(dedupeKey)) continue;
      seenValues.add(dedupeKey);
      pairs.push({ address: a.value, password: p.value, addressName: a.name });
    } else {
      incomplete.push((a || p).name);
    }
  }

  return { pairs, incomplete };
}

/**
 * sendSelfNotifyViaGmailRing — deliberately NOT the same signature as
 * send-otp.js's sendViaGmailRing. There, `to` is fixed once before the
 * loop (an external visitor address, the same for every ring attempt).
 * Here, `to` MUST be recomputed on every attempt to equal the CURRENT
 * pair's own address: if pair 0 fails and pair 1 (a different Google
 * account) succeeds, the notification has to land in pair 1's inbox —
 * pair 0 never authenticated, so it has no standing to receive a
 * "self-sent" message, and sending pair-1-authenticated mail to pair-0's
 * different address would just be an ordinary external send again,
 * losing the self-send reliability property this file exists for.
 *
 * Connection lifecycle identical to send-otp.js: opened, used, and
 * closed entirely inside one loop iteration, never at module scope
 * (Cloudflare Workers TCP sockets can't be created in global scope and
 * shared across requests). close() runs in a finally block on both the
 * success and failure paths.
 */
async function sendSelfNotifyViaGmailRing(pairs, emailOptionsBase) {
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
      attempts.push({ index: i, name: addressName, stage: 'connect', message: String(err?.message || err) });
      continue;
    }

    try {
      await mailer.send({
        ...emailOptionsBase,
        from: { name: SENDER_PERSON_NAME, email: address },
        to  : { name: SENDER_PERSON_NAME, email: address }, // self-send — see doc comment above
      });
      return { ok: true, keyIndex: i, keysTried: i + 1 };
    } catch (err) {
      attempts.push({ index: i, name: addressName, stage: 'send', message: String(err?.message || err) });
      continue;
    } finally {
      await mailer.close();
    }
  }

  return { ok: false, keysTried: attempts.length, attempts };
}

/* ═══════════════════════════════════════════════════════════ HANDLER */
export async function onRequestPost(context) {
  const origin = context.request.headers.get('Origin') || '';
  const ip     = context.request.headers.get('CF-Connecting-IP') || 'unknown';

  if (isRateLimited(ip)) {
    return json({ error: 'Too many requests — try again in 10 minutes.' }, 429, origin);
  }

  let body;
  try {
    body = await context.request.json();
  } catch {
    return json({ error: 'Invalid JSON body.' }, 400, origin);
  }

  const { name, email, message, site_label } = body || {};

  /* Server-side validation mirrors the HTML form's own maxlength
     attributes (name 100 / email 150 / message 2000) — a direct POST
     bypasses the browser entirely, so none of that is enforceable
     client-side alone. Compute each trimmed/capped value FIRST, then
     validate that exact value — validating the raw input and using a
     different (later-trimmed) value to send would let a
     whitespace-only field slip through. */
  const safeName = String(name || '').trim().slice(0, 100);
  if (!safeName) {
    return json({ error: 'Name is required.' }, 400, origin);
  }

  const safeEmail = String(email || '').trim().slice(0, 150);
  if (!safeEmail || !isValidEmail(safeEmail)) {
    return json({ error: 'Invalid email address.' }, 400, origin);
  }

  const safeMessage = String(message || '').trim().slice(0, 2000);
  if (!safeMessage) {
    return json({ error: 'Message is required.' }, 400, origin);
  }

  const safeSiteLabel = (String(site_label || '').trim().slice(0, 60)) || 'Website';

  const { pairs: gmailPairs, incomplete } = buildGmailRing(context.env);
  if (incomplete.length > 0) {
    console.warn('[notify-submission] Incomplete Gmail credential pair(s), skipped:', incomplete.join(', '));
  }
  if (gmailPairs.length === 0) {
    console.error('[notify-submission] No complete GMAIL_ADDRESS*/GMAIL_APP_PASSWORD* pair is set.');
    return json({ error: 'Server configuration error.' }, 500, origin);
  }

  const escName    = escapeHtml(safeName);
  const escEmail   = escapeHtml(safeEmail);
  const escMessage = escapeHtml(safeMessage).replace(/\n/g, '<br>');
  const escSite    = escapeHtml(safeSiteLabel);

  const emailHtml = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>New website message</title></head>
<body style="margin:0;padding:0;background:#f7f9fc;font-family:'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f7f9fc;padding:40px 0;">
    <tr><td align="center">
      <table width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;
             border:1px solid #dde3ea;overflow:hidden;max-width:520px;">
        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#0A1A2E,#1A3A5C);padding:24px 32px;">
            <h1 style="margin:0;color:#F5D88A;font-size:1rem;font-weight:700;letter-spacing:0.04em;">
              New message — ${escSite}
            </h1>
          </td>
        </tr>
        <!-- Body -->
        <tr>
          <td style="padding:32px;">
            <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 20px;">
              <tr>
                <td style="padding:0 0 10px;color:#5a6a7a;font-size:0.85rem;width:90px;vertical-align:top;">Name</td>
                <td style="padding:0 0 10px;color:#1a1a2e;font-size:0.95rem;">${escName}</td>
              </tr>
              <tr>
                <td style="padding:0 0 10px;color:#5a6a7a;font-size:0.85rem;vertical-align:top;">Email</td>
                <td style="padding:0 0 10px;color:#1a1a2e;font-size:0.95rem;">${escEmail}</td>
              </tr>
            </table>
            <hr style="border:none;border-top:1px solid #dde3ea;margin:0 0 20px;">
            <p style="margin:0 0 8px;color:#5a6a7a;font-size:0.85rem;">Message</p>
            <p style="margin:0 0 24px;color:#1a1a2e;font-size:0.95rem;line-height:1.6;">${escMessage}</p>
            <hr style="border:none;border-top:1px solid #dde3ea;margin:0 0 16px;">
            <p style="margin:0;color:#9aa5b1;font-size:0.78rem;">
              Sent automatically via Gmail SMTP self-notify — reply to this email to respond directly to ${escName}.
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  /* Plain-text alternative — kept in sync by hand, same as send-otp.js.
     Absence of a text/plain part on an HTML-only message is a cited
     spam-filter signal independent of authentication correctness. */
  const emailText =
`New message — ${safeSiteLabel}

Name: ${safeName}
Email: ${safeEmail}

Message:
${safeMessage}

— Reply to this email to respond directly to ${safeName}.`;

  const result = await sendSelfNotifyViaGmailRing(gmailPairs, {
    reply  : { name: safeName, email: safeEmail }, // hit Reply in Gmail → goes straight to the visitor
    subject: `New message — ${safeSiteLabel}: ${safeName}`,
    html   : emailHtml,
    text   : emailText,
  });

  if (!result.ok) {
    console.error('[notify-submission] Gmail ring exhausted:', JSON.stringify({
      pairsConfigured: gmailPairs.length,
      attempts: result.attempts,
    }));
    return json({ error: 'Email provider rejected the request.' }, 502, origin);
  }

  console.log('[notify-submission] sent', JSON.stringify({
    keyIndex : result.keyIndex,
    keysTried: result.keysTried,
  }));

  return json({ success: true }, 200, origin, { 'X-Notify-KeyIndex': String(result.keyIndex) });
}

/* ── Preflight ── */
export async function onRequestOptions(context) {
  const origin = context.request.headers.get('Origin') || '';
  return new Response(null, { status: 204, headers: corsHeaders(origin) });
}
