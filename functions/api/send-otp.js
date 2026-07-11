/**
 * Cloudflare Pages Function — /api/send-otp
 * File location in your CF Pages project: functions/api/send-otp.js
 *
 * Setup:
 *  1. Create free account at resend.com
 *  2. Go to API Keys → Create API Key → copy it
 *  3. In Cloudflare Pages dashboard → your project → Settings →
 *     Environment Variables → Add: RESEND_API_KEY = re_XXXXXXXXXXXXXXXX
 *     Optional standby key(s): RESEND_API_KEY_1, RESEND_API_KEY_2, ...
 *  4. REQUIRED before this can email anyone but yourself: verify a domain
 *     at resend.com/domains, then change RESEND_FROM below to an address
 *     on that domain. See [V3-DOMAIN] below — this is not optional polish.
 *
 * [V3-DOMAIN] RESEND_FROM is currently 'onboarding@resend.dev', Resend's
 * sandbox address. Per Resend's own docs
 * (resend.com/docs/knowledge-base/403-error-resend-dev-domain), that
 * address "can only send emails to the email address associated with
 * your Resend account" — every other recipient gets a 403. That includes
 * every real visitor filling out the contact form. This is true for ANY
 * key on ANY account using this address, so it is NOT fixed by adding
 * more keys, more standby slots, or more accounts to the ring below —
 * only by verifying a real sending domain and updating RESEND_FROM to
 * use it. Until that happens, this endpoint only works for sending OTPs
 * to whichever single address owns the account behind whichever key
 * happens to be tried. classifyResendFailure() below detects this
 * specific 403 by message content and fails fast with a distinct log
 * line rather than burning the rest of the ring on a guaranteed repeat.
 *
 * [V2-KEYRING] Resend's rate limit (10 req/s) and email quota (Free plan:
 * 100/day, 3000/mo) are enforced per TEAM/account, shared across every
 * API key that account owns (resend.com/docs/api-reference/rate-limit:
 * "This limit applies across all API keys associated with your team").
 * Unlike ELEVEN_API_KEY_N / GROQ_API_KEY_N in stt.js/tts.js/chat.js,
 * adding RESEND_API_KEY_1..N from the SAME account adds zero capacity.
 * The ring below exists so a revoked/rotated-out primary key doesn't
 * cause an outage — it advances to the next key ONLY on a confirmed
 * dead-key response, never on 429 or a [V3-DOMAIN]-type 403, since those
 * repeat identically across every key sharing the same cause.
 *
 * On a ring built from SEVERAL DIFFERENT people's own separate Resend
 * accounts (as opposed to several keys within one account): each
 * account's quota genuinely is independent, so this is not the "zero
 * benefit" case described above. It is, however, still very likely
 * exactly the pattern Resend's Acceptable Use Policy is written to
 * prevent — pooling several accounts' quotas behind one shared
 * application to exceed what any single account is meant to have
 * (resend.com/legal/acceptable-use: "Users are expressly forbidden from
 * creating or using an account or multiple accounts with the aim of
 * circumventing any quotas or limits"), regardless of whether one person
 * or thirteen people hold the individual accounts. This file will use
 * however many keys are configured without judging where they came
 * from, but that judgment call — and the [V3-DOMAIN] verification,
 * which every one of those accounts needs independently unless they all
 * verify the SAME domain — is left to you, not assumed here.
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
const RESEND_BASE_NAME = 'RESEND_API_KEY';

/* ── Rate limit: max requests per IP per 10-minute window ── */
const RATE_LIMIT   = 5;
const WINDOW_MS    = 10 * 60 * 1000; /* 10 minutes */

/* In-memory rate limit store (resets per isolate/cold-start — good enough).
   Resource note: entries are never explicitly evicted, only their count/
   window fields are reset in place once their window elapses. Release
   mechanism is isolate recycling, not a TTL sweep — unchanged from the
   original file; flagged here, not fixed, since it's outside this
   change's scope (see Resource Lifecycle Verification in the response
   this file shipped with). */
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

function json(body, status, origin, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin), ...(extraHeaders || {}) },
  });
}

/**
 * buildKeyRing — identical matching convention to buildKeyRing() in
 * stt.js/tts.js: case-insensitive `^BASE(?:_(\d+))?$`, de-duplicated by
 * value, sorted base-name-first then ascending numeric suffix.
 *
 * @param {object} env
 * @param {string} baseName  e.g. 'RESEND_API_KEY' (case is irrelevant)
 * @returns {{ keys: string[], matchedNames: string[] }}
 */
function buildKeyRing(env, baseName) {
  const pattern = new RegExp(`^${baseName}(?:_(\\d+))?$`, 'i');
  const found = []; // { name, suffix: number|-1 (for base), value }

  for (const name of Object.keys(env || {})) {
    const m = pattern.exec(name);
    if (!m) continue;
    const value = env[name]?.trim?.();
    if (!value) continue;
    const suffix = m[1] !== undefined ? parseInt(m[1], 10) : -1;
    found.push({ name, suffix, value });
  }

  found.sort((a, b) => a.suffix - b.suffix);

  const keys = [];
  const matchedNames = [];
  const seenValues = new Set();
  for (const f of found) {
    if (seenValues.has(f.value)) continue; // same key pasted into two slots
    seenValues.add(f.value);
    keys.push(f.value);
    matchedNames.push(f.name);
  }

  return { keys, matchedNames };
}

/**
 * Classifies a failed Resend /emails response.
 * keySpecific=true  -> this credential is the problem, try the next one.
 * keySpecific=false -> every key on this account fails identically
 *                       (rate limit, quota, validation, domain, 5xx) —
 *                       stop rotating and surface the error.
 *
 * 403 is NOT a single case. Resend returns 403 for two unrelated reasons
 * (resend.com/docs/api-reference/errors,
 *  resend.com/docs/knowledge-base/403-error-resend-dev-domain):
 *   - invalid_api_key ("API key is invalid...")            -> key-specific
 *   - sandbox domain restriction ("You can only send testing
 *     emails to your own email address... verify a domain...") when
 *     RESEND_FROM is still onboarding@resend.dev            -> NOT key-specific
 * The second case fires identically for every key in the ring that
 * hasn't verified a sending domain — rotating through the rest of the
 * ring would just burn every remaining key on the same guaranteed 403.
 * Differentiated by message content, not status code alone.
 */
async function classifyResendFailure(res) {
  let rawText = '';
  let bodyJson = null;
  try {
    rawText = await res.text();
    bodyJson = rawText ? JSON.parse(rawText) : null;
  } catch { /* non-JSON error body — rawText still used below */ }

  const message = bodyJson?.message || bodyJson?.error || rawText.slice(0, 300) || `HTTP ${res.status}`;
  const label   = bodyJson?.name || bodyJson?.type || bodyJson?.code || '';

  const isSandboxDomainRestriction = res.status === 403
    && /only send.{0,20}(testing )?emails? to your own|verify a domain/i.test(message);
  const isInvalidKey = res.status === 403
    && (label === 'invalid_api_key' || /api key is invalid/i.test(message));

  let keySpecific;
  if (res.status === 403) {
    // Unrecognized 403 message defaults to NOT key-specific: safer to fail
    // fast and surface it than to burn the whole ring on an unknown cause.
    keySpecific = isInvalidKey && !isSandboxDomainRestriction;
  } else {
    keySpecific = res.status === 401;
  }

  return { status: res.status, label, message, keySpecific, isSandboxDomainRestriction };
}

/**
 * Tries each ring key in FIXED order (index 0 first) — no round-robin
 * start offset. Round-robin spreads load across INDEPENDENT quota pools
 * (ElevenLabs/Groq/etc.); Resend's quota is pooled per-account across
 * every key (see [V2-KEYRING] header note), so there is nothing to
 * spread — index 0 is always the first attempt, later slots are pure
 * failover for a dead primary key.
 */
async function sendViaResendRing(keys, payload) {
  const attempts = [];

  for (let i = 0; i < keys.length; i++) {
    let res;
    try {
      res = await fetch('https://api.resend.com/emails', {
        method : 'POST',
        headers: {
          'Authorization': `Bearer ${keys[i]}`,
          'Content-Type' : 'application/json',
        },
        body: JSON.stringify(payload),
      });
    } catch (err) {
      // Network-layer failure is independent of which key is used —
      // burning the rest of the ring on it would not help.
      attempts.push({ index: i, network: true, message: String((err && err.message) || err) });
      break;
    }

    if (res.ok) {
      let data = null;
      try { data = await res.json(); } catch { /* Resend returns JSON on 2xx; ignore parse edge case */ }
      return { ok: true, keyIndex: i, keysTried: i + 1, data };
    }

    const failure = await classifyResendFailure(res);
    attempts.push({ index: i, ...failure });

    if (!failure.keySpecific) break; // account-wide failure — every remaining key would repeat it
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

  /* Get API key ring from CF environment */
  const { keys: resendKeys, matchedNames } = buildKeyRing(context.env, RESEND_BASE_NAME);
  if (resendKeys.length === 0) {
    console.error('[send-otp] No RESEND_API_KEY* environment variable is set.');
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

  /* Send via Resend, rotating the ring only on a confirmed-dead key */
  const result = await sendViaResendRing(resendKeys, {
    from   : RESEND_FROM,
    to     : [to_email],
    subject: 'Your verification code — Civil Engineering Suite',
    html   : emailHtml,
  });

  if (!result.ok) {
    const last = result.attempts[result.attempts.length - 1];

    if (last && last.isSandboxDomainRestriction) {
      // This will fire for EVERY real site visitor as long as RESEND_FROM
      // is still onboarding@resend.dev — it is not a per-request fluke.
      // Loud, distinct log line on purpose: this is a one-time setup gap,
      // not a runtime condition worth quietly retrying.
      console.error('[send-otp] BLOCKED: RESEND_FROM is still the onboarding@resend.dev sandbox '
        + 'address, which can only deliver to the sending account\'s own email. Verify a domain at '
        + 'resend.com/domains and update RESEND_FROM before this endpoint can reach real recipients. '
        + JSON.stringify({ keysConfigured: resendKeys.length, matchedNames }));
      return json({ error: 'Email sending is not fully configured yet — contact the site owner.' }, 500, origin);
    }

    console.error('[send-otp] Resend ring exhausted:', JSON.stringify({
      keysConfigured: resendKeys.length,
      matchedNames,
      attempts: result.attempts,
    }));
    const status = last && last.status === 429 ? 429 : 502;
    const clientMsg = status === 429
      ? 'Email provider is rate-limited — try again shortly.'
      : 'Email provider rejected the request.';
    return json({ error: clientMsg }, status, origin);
  }

  console.log('[send-otp] sent', JSON.stringify({
    emailId : result.data?.id,
    keyIndex: result.keyIndex,
    keysTried: result.keysTried,
    keyName : matchedNames[result.keyIndex],
  }));

  return json({ success: true }, 200, origin, { 'X-OTP-KeyIndex': String(result.keyIndex) });
}

/* ── Preflight ── */
export async function onRequestOptions(context) {
  const origin = context.request.headers.get('Origin') || '';
  return new Response(null, { status: 204, headers: corsHeaders(origin) });
}
