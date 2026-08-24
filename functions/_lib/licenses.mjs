// functions/_lib/licenses.mjs
// ============================================================================
// Three-tier access control: developer / subscriber / regular.
// Single source of truth for license issuance, device-slot binding, and the
// regular-tier one-file lifetime quota. Imported by chat.js and
// dev-upload.js. NOT wired into vision.js in this pass — that file was not
// provided for review; see integration notes in the accompanying patch.
//
// DELIBERATELY NOT MERGED WITH isDeveloperMode:
// This module answers "does this caller get elevated FILE/QUOTA limits."
// It does NOT answer "is this caller the site owner" — that stays exactly
// isDeveloperMode, computed exactly as chat.js already does it, gating
// exactly what it already gates (DEVELOPER_SYSTEM_PROMPT, confidentiality-
// block suppression, session save/load/list/delete, the new admin commands
// below). A subscriber getting developer-level FILE limits is the explicit
// goal; a subscriber seeing developer-only confidential prompt content is
// not, and collapsing the two into one flag would do that silently. Callers
// should compute:
//   const hasElevatedAccess = isDeveloperMode || (await validateLicense(...)).ok;
// and pass hasElevatedAccess to extractTextFiles/resolveKvFiles, while every
// existing isDeveloperMode call site for prompt-building stays untouched.
//
// KV NAMESPACE: env.CES_LICENSES (new binding — Cloudflare Pages ->
// Settings -> Functions -> KV namespace bindings, same process already used
// for CES_CHAT_KV / CES_SESSIONS / CES_DEV_UPLOADS).
//
// KV WRITE BUDGET — READ THIS BEFORE ADDING CALLS ANYWHERE ELSE:
// Cloudflare Workers KV's free-tier quota (100,000 reads / 1,000 writes /
// 1,000 deletes / 1,000 lists per day, resets 00:00 UTC) is scoped to the
// ACCOUNT, not per namespace (developers.cloudflare.com/workers/platform/
// pricing/; confirmed against independent trackers, current Aug 2026).
// Splitting data into a separate namespace — as this codebase already does
// for CES_DEV_UPLOADS and CES_SESSIONS — buys organizational isolation, NOT
// extra write budget: every PUT/DELETE against ANY namespace on this
// account draws from the same shared daily pool CES_CHAT_KV's rate limiter
// already competes for. That is true of CES_LICENSES too. Every function
// below is read-first / write-rarely for that reason:
//   issueLicense / revokeLicense / resetDevices  — admin-triggered, rare,
//     1 write each. Not a budget concern at any realistic admin volume.
//   validateLicense — called on EVERY chat message from an active
//     subscriber, but is a KV READ in the common case (returning device
//     already in devices[]). It writes exactly once per NEW device, i.e.
//     at most MAX_DEVICES_PER_LICENSE (2) times over the ENTIRE LIFE of a
//     license, not per login and not per message. [REVISED — fingerprint-
//     aware rebind] does not change this count: a "new token, fingerprint
//     matches an existing slot" rebind still costs exactly 1 write (same
//     write that would have happened anyway), it's just a smarter write —
//     see this function's own comment.
//   checkFreeFileQuota — READ only.
//   consumeFreeFileQuota — [REVISED] up to FREE_FILES_PER_WINDOW (3)
//     writes per identity per rolling 24h window, not once-ever — see
//     that function's own header for the concrete daily budget impact.
//   checkAndConsumeFreeMessageQuota — [NEW] up to FREE_MESSAGES_PER_WINDOW
//     (15) writes per identity per rolling 24h window. This is the
//     heaviest write source in this module by far — see its own header
//     for the account-wide ceiling this implies and the recommended
//     off-ramp once you approach it.
// Before deploying, check actual current daily write volume (Cloudflare
// dashboard -> Workers KV -> Metrics) — this module's math assumes it isn't
// already close to the account-wide 1,000/day ceiling from existing
// features (rate limiting, dev-upload, session save). That figure isn't
// something this review could observe from static files.
//
// KEY SCHEMA:
//   license:{LICENSE-KEY}   -> JSON LicenseRecord, no TTL (persists until
//                              explicitly revoked — revocation does not
//                              delete the key, so misuse/support history
//                              survives; see revokeLicense).
//   freequota:{identity}    -> JSON { count, resetsAt }, TTL = time left in
//                              the current rolling window.
//   freemsgs:{identity}     -> JSON { count, resetsAt }, same shape/TTL
//                              logic as freequota, separate counter/cap.
//
// LicenseRecord:
//   {
//     licenseKey:  string,               // 'CES-XXXX-XXXX-XXXX-XXXX'
//     tier:        'subscriber',
//     status:      'active' | 'revoked',
//     createdAt:   ISO string,
//     expiresAt:   ISO string,            // per-license — set at issuance,
//                                          // NOT a global constant. Pass
//                                          // whatever durationDays this
//                                          // subscriber actually paid for.
//     revokedAt:   ISO string,            // present only if status is
//                                          // 'revoked'
//     note:        string,                // free-text admin note (buyer
//                                          // email/contact — this project
//                                          // has no user-accounts table,
//                                          // so this is the only place to
//                                          // keep a human-readable link
//                                          // back to who holds the key)
//     devices: [                          // max 2
//       {
//         token:       string,            // client-generated, primary key
//         boundAt:     ISO string,
//         fingerprint: string | null,     // [NEW] FingerprintJS visitorId
//                                          // captured at bind time, if the
//                                          // caller sent one. Optional and
//                                          // absent until the frontend is
//                                          // wired to send it — every
//                                          // fingerprint-aware code path
//                                          // below degrades to pure
//                                          // device-token behavior when
//                                          // it's missing.
//         rebindCount: number,            // [NEW] present only once >0 —
//                                          // see validateLicense
//       }, ...
//     ]
//   }
//
// FINGERPRINT INTEGRATION — WHY THIS ISN'T "OPTION 3":
// The three device-lock designs discussed were (1) device token only,
// (2) token primary + fingerprint logged but inert, (3) fingerprint as
// the PRIMARY gate. (3) was explicitly not recommended: the open-source
// FingerprintJS visitorId is documented at roughly 40-60% cross-device
// accuracy (vs. 99.5% for the paid product) — good enough to be a useful
// hint, not good enough to be the thing that DENIES a request on its own.
// What's implemented below combines all three signals without handing
// fingerprint that authority:
//   - The device TOKEN remains the only thing that can grant instant,
//     no-questions-asked access (a matching token is definitionally the
//     same session that was already trusted).
//   - A fingerprint match is used ONLY to reclassify what would otherwise
//     be treated as "device #3, reject" or "brand-new device, consume a
//     slot" into "this looks like a device we already know, re-attach its
//     token" — i.e. fingerprint can make the system MORE forgiving of a
//     returning legitimate device, never less forgiving of a genuinely
//     new one. It is never used to reject a request that the token logic
//     alone would have accepted, and a fingerprint MISMATCH never denies
//     anything by itself — it only gets logged (console.warn — no KV
//     write) as a possible credential-sharing signal for manual review.
//   - Net effect vs. token-only: closes (partially — see caveat in
//     validateLicense) the "clear localStorage to mint a free 3rd device"
//     gap, at zero extra KV write cost (same write that already
//     happened, redirected to the right slot instead of a new one).
// ============================================================================
// LICENSE KEY / DEVICE TOKEN ENTROPY, AND WHY NEITHER USES
// hmacTimingSafeEqual (chat.js / dev-upload.js's constant-time compare):
// That helper exists because DEVELOPER_PASSWORD is a short, human-chosen,
// FIXED secret compared against attacker input on every request — exactly
// the shape a timing side-channel or dictionary attack targets. Neither
// value here has that shape:
//   - licenseKey is a KV LOOKUP KEY (`license:${key}`), not a value
//     compared byte-for-byte against a known secret — KV.get() either
//     finds the row or returns null. There is no meaningful timing
//     side-channel on "did this key exist in the store."
//   - deviceToken is itself server-generated, crypto.randomUUID() from the
//     CLIENT (see integration notes) — high-entropy random data compared
//     against other high-entropy random data. A dictionary attack is
//     meaningless against 122 bits of randomness.
//   - The license key alphabet below (32 symbols, Crockford-style — no
//     0/O/1/I to avoid transcription errors) at 16 symbols is 32^16 ≈
//     1.2 x 10^24 combinations — brute-forcing it is infeasible at any
//     request rate this rate-limited endpoint could ever sustain, so this
//     module adds no dedicated anti-brute-force throttle of its own; it
//     relies on chat.js's existing per-IP checkRateLimit(), which already
//     runs before any of this code does (see chat.js step 1).
// ============================================================================

const MAX_DEVICES_PER_LICENSE = 2;
const LICENSE_KEY_GROUPS = 4;
const LICENSE_KEY_GROUP_LEN = 4;
const LICENSE_KEY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 symbols, no 0/O/1/I

function randomLicenseKey() {
  const need = LICENSE_KEY_GROUPS * LICENSE_KEY_GROUP_LEN;
  const bytes = crypto.getRandomValues(new Uint8Array(need));
  const groups = [];
  for (let g = 0; g < LICENSE_KEY_GROUPS; g++) {
    let group = '';
    for (let i = 0; i < LICENSE_KEY_GROUP_LEN; i++) {
      group += LICENSE_KEY_ALPHABET[bytes[g * LICENSE_KEY_GROUP_LEN + i] % LICENSE_KEY_ALPHABET.length];
    }
    groups.push(group);
  }
  return 'CES-' + groups.join('-');
}

function normalizeKey(raw) {
  return typeof raw === 'string' ? raw.trim().toUpperCase() : '';
}

// [NEW] KV metadata attached to every license write, so listLicenses()
// below can render a full admin table from ONE list() call instead of one
// GET per key (Workers KV's list() returns metadata inline). Kept well
// under KV's 1024-byte key+metadata limit — note is truncated further
// here (200 chars) than the 500-char cap on the full record, since this
// copy rides alongside every list() page entry, not just one record.
function buildLicenseMetadata(record) {
  return {
    status: record.status,
    expiresAt: record.expiresAt,
    deviceCount: Array.isArray(record.devices) ? record.devices.length : 0,
    note: typeof record.note === 'string' ? record.note.slice(0, 200) : '',
    lastUsedAt: record.lastUsedAt || null,
    totalDaysActive: Number(record.totalDaysActive) || 0,
    createdAt: record.createdAt,
  };
}

// [NEW] Throttled activity stamp for the "consumption" view of a license —
// true per-message counting would need a KV write on every single chat/
// vision turn, which directly violates this file's own write-budget
// doctrine (see file header) and risks the account-wide daily write cap.
// This is the honest middle ground: updates at most once per UTC calendar
// day regardless of message volume, so it rides for free on writes that
// already happen elsewhere in validateLicense (new-device bind,
// fingerprint rebind) and costs exactly one extra write on days it
// doesn't (known device, first message of a new day) — never more than
// 1 extra write per license per day. Mutates `record` in place; returns
// true if it did (caller decides whether/how to persist that).
function stampDailyActivity(record) {
  const today = new Date().toISOString().slice(0, 10);
  if (record.lastUsedAt && record.lastUsedAt.slice(0, 10) === today) return false;
  record.lastUsedAt = new Date().toISOString();
  record.totalDaysActive = (Number(record.totalDaysActive) || 0) + 1;
  return true;
}

// ── Admin operations — call these ONLY from a call site already gated by
//    the real isDeveloperMode (site-owner) check. This module does not
//    authenticate its own callers. ──────────────────────────────────────────

// Write count: 1. Rare/manual — issued by the site owner per paying
// subscriber, not a per-request path.
export async function issueLicense(env, { durationDays, note = '' } = {}) {
  if (!env.CES_LICENSES) {
    return { ok: false, error: 'CES_LICENSES KV namespace is not bound on the server.', code: 'KV_NOT_BOUND' };
  }
  const days = Number(durationDays);
  if (!Number.isFinite(days) || days <= 0) {
    return { ok: false, error: 'durationDays must be a positive number.', code: 'BAD_DURATION' };
  }
  const licenseKey = randomLicenseKey();
  const now = new Date();
  const record = {
    licenseKey,
    tier: 'subscriber',
    status: 'active',
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + days * 86400000).toISOString(),
    note: typeof note === 'string' ? note.slice(0, 500) : '',
    devices: [],
  };
  try {
    await env.CES_LICENSES.put(`license:${licenseKey}`, JSON.stringify(record), { metadata: buildLicenseMetadata(record) });
  } catch (err) {
    console.error('[licenses.mjs] issueLicense KV write failed:', err.message);
    return { ok: false, error: 'Storage error while issuing license. Please retry.', code: 'KV_WRITE_FAILED' };
  }
  return { ok: true, license: record };
}

// Write count: 1. Does not delete the record — a revoked key stays visible
// via lookup (support/audit trail) but validateLicense will reject it on
// status.
export async function revokeLicense(env, licenseKeyRaw) {
  if (!env.CES_LICENSES) {
    return { ok: false, error: 'CES_LICENSES KV namespace is not bound on the server.', code: 'KV_NOT_BOUND' };
  }
  const licenseKey = normalizeKey(licenseKeyRaw);
  if (!licenseKey) return { ok: false, error: 'licenseKey is required.', code: 'BAD_INPUT' };

  let raw;
  try {
    raw = await env.CES_LICENSES.get(`license:${licenseKey}`);
  } catch (err) {
    console.error('[licenses.mjs] revokeLicense KV read failed:', err.message);
    return { ok: false, error: 'Storage error. Please retry.', code: 'KV_READ_FAILED' };
  }
  if (!raw) return { ok: false, error: 'License not found.', code: 'NOT_FOUND' };

  let record;
  try { record = JSON.parse(raw); } catch { return { ok: false, error: 'Stored license record is corrupted.', code: 'CORRUPT' }; }

  record.status = 'revoked';
  record.revokedAt = new Date().toISOString();
  try {
    await env.CES_LICENSES.put(`license:${licenseKey}`, JSON.stringify(record), { metadata: buildLicenseMetadata(record) });
  } catch (err) {
    console.error('[licenses.mjs] revokeLicense KV write failed:', err.message);
    return { ok: false, error: 'Storage error while revoking. Please retry.', code: 'KV_WRITE_FAILED' };
  }
  return { ok: true, license: record };
}

// Write count: 1. The "customer got a new phone" path CES's own analysis
// (see thread this module implements) correctly identified as something
// that SHOULD require contacting the owner — this is that action.
export async function resetDevices(env, licenseKeyRaw) {
  if (!env.CES_LICENSES) {
    return { ok: false, error: 'CES_LICENSES KV namespace is not bound on the server.', code: 'KV_NOT_BOUND' };
  }
  const licenseKey = normalizeKey(licenseKeyRaw);
  if (!licenseKey) return { ok: false, error: 'licenseKey is required.', code: 'BAD_INPUT' };

  let raw;
  try {
    raw = await env.CES_LICENSES.get(`license:${licenseKey}`);
  } catch (err) {
    console.error('[licenses.mjs] resetDevices KV read failed:', err.message);
    return { ok: false, error: 'Storage error. Please retry.', code: 'KV_READ_FAILED' };
  }
  if (!raw) return { ok: false, error: 'License not found.', code: 'NOT_FOUND' };

  let record;
  try { record = JSON.parse(raw); } catch { return { ok: false, error: 'Stored license record is corrupted.', code: 'CORRUPT' }; }

  record.devices = [];
  try {
    await env.CES_LICENSES.put(`license:${licenseKey}`, JSON.stringify(record), { metadata: buildLicenseMetadata(record) });
  } catch (err) {
    console.error('[licenses.mjs] resetDevices KV write failed:', err.message);
    return { ok: false, error: 'Storage error while resetting devices. Please retry.', code: 'KV_WRITE_FAILED' };
  }
  return { ok: true, license: record };
}

// ── Hot path — called on every chat.js request that carries a licenseKey.
//    No auth gate needed above this one: the licenseKey IS the credential.
//    See file header for the write-count guarantee (0 or 1, never more —
//    fingerprint-awareness does not change that count, see below).
export async function validateLicense(env, licenseKeyRaw, deviceTokenRaw, fingerprintIdRaw) {
  const licenseKey = normalizeKey(licenseKeyRaw);
  const deviceToken = typeof deviceTokenRaw === 'string' ? deviceTokenRaw.trim() : '';
  // Optional — absent until the frontend sends FingerprintJS's visitorId.
  // Every branch below treats '' the same as "not provided."
  const fingerprintId = typeof fingerprintIdRaw === 'string' ? fingerprintIdRaw.trim() : '';
  if (!licenseKey || !deviceToken) return { ok: false, reason: 'MISSING_FIELDS' };
  if (!env.CES_LICENSES) return { ok: false, reason: 'KV_NOT_BOUND' };

  let raw;
  try {
    raw = await env.CES_LICENSES.get(`license:${licenseKey}`);
  } catch (err) {
    console.error('[licenses.mjs] validateLicense KV read failed:', err.message);
    // Fail CLOSED (to regular tier), not open: a KV outage must not grant
    // every caller claiming any licenseKey developer-level file limits.
    return { ok: false, reason: 'KV_ERROR' };
  }
  if (!raw) return { ok: false, reason: 'NOT_FOUND' };

  let record;
  try { record = JSON.parse(raw); } catch { return { ok: false, reason: 'CORRUPT' }; }

  if (record.status !== 'active') return { ok: false, reason: 'REVOKED' };
  if (!record.expiresAt || new Date(record.expiresAt).getTime() <= Date.now()) {
    return { ok: false, reason: 'EXPIRED', expiresAt: record.expiresAt };
  }

  const devices = Array.isArray(record.devices) ? record.devices : [];
  const knownByToken = devices.find((d) => d && d.token === deviceToken);
  if (knownByToken) {
    // Known device. Pure read in the common case — no write, no matter how
    // many messages this subscriber sends today.
    //
    // Integrated signal #1: same TOKEN, but a DIFFERENT fingerprint than
    // what this slot was bound with. The token still wins (it's the
    // credential, and fingerprint is too unreliable to override it) — this
    // is logged only, not blocked, and costs zero KV writes (console.warn
    // reaches Cloudflare's request logs without touching the KV budget).
    // This is a genuinely different anomaly shape than the rebind case
    // below: a stolen/shared TOKEN looks like this (same token, new
    // device); a cleared-storage RETURNING device looks like the rebind
    // case (new token, same fingerprint). Distinguishing them is exactly
    // why both checks exist rather than one.
    if (fingerprintId && knownByToken.fingerprint && knownByToken.fingerprint !== fingerprintId) {
      console.warn(
        '[licenses.mjs] Fingerprint mismatch on known device token for', licenseKey,
        '— possible token sharing. Not blocking (fingerprint alone is not reliable enough to deny); review manually if this recurs.',
      );
    }
    // [NEW] The one case that previously did 0 writes ever, on purpose —
    // see file header's write-budget doctrine. Still 0 writes for every
    // message except the first one on a new UTC calendar day; see
    // stampDailyActivity's own header for why this stays within budget.
    if (stampDailyActivity(record)) {
      try {
        await env.CES_LICENSES.put(`license:${licenseKey}`, JSON.stringify(record), { metadata: buildLicenseMetadata(record) });
      } catch (err) {
        // Non-fatal: the subscriber is already validated above. Losing
        // this write only means "last used" looks one day stale in the
        // admin view — not a reason to fail a paying subscriber's request.
        console.error('[licenses.mjs] validateLicense activity-stamp write failed (non-fatal):', err.message);
      }
    }
    return { ok: true, license: record };
  }

  // Token not recognized. Integrated signal #2, before treating this as a
  // brand-new device: does the fingerprint match a slot we already have?
  // If so, this is very likely the SAME physical device returning after
  // clearing localStorage / an incognito session / a browser reinstall —
  // re-attach its token to that slot instead of consuming a new one.
  //
  // CAVEAT — this does not fully close the loophole, and shouldn't be
  // oversold as doing so: a fingerprint match is a HINT (40-60% reliable
  // alone), not proof. A user who specifically wants to defeat this would
  // need to change BOTH signals (clear storage AND alter/spoof enough
  // fingerprint entropy to no longer match) rather than just one — that
  // is a real increase in the effort required over token-only, not a
  // hard guarantee. Treat it as raising the cost of evasion, not
  // eliminating it.
  if (fingerprintId) {
    const rebindTarget = devices.find((d) => d && d.fingerprint && d.fingerprint === fingerprintId);
    if (rebindTarget) {
      rebindTarget.token = deviceToken;
      rebindTarget.rebindAt = new Date().toISOString();
      rebindTarget.rebindCount = (Number(rebindTarget.rebindCount) || 0) + 1;
      record.devices = devices;
      stampDailyActivity(record); // [NEW] rides this same write, no extra one
      try {
        await env.CES_LICENSES.put(`license:${licenseKey}`, JSON.stringify(record), { metadata: buildLicenseMetadata(record) });
      } catch (err) {
        console.error('[licenses.mjs] validateLicense rebind write failed (failing open on this request):', err.message);
        return { ok: true, license: record };
      }
      console.info('[licenses.mjs] Device rebind (fingerprint match, new token) for', licenseKey, '— rebindCount now', rebindTarget.rebindCount);
      return { ok: true, license: record };
    }
  }

  if (devices.length >= MAX_DEVICES_PER_LICENSE) {
    return { ok: false, reason: 'DEVICE_LIMIT', deviceCount: devices.length };
  }

  // Genuinely new device by every signal available. The only "fresh slot"
  // write on this path, and it can happen at most MAX_DEVICES_PER_LICENSE
  // times ever for this license (rebinds above reuse a slot instead of
  // counting against this).
  devices.push({
    token: deviceToken,
    boundAt: new Date().toISOString(),
    fingerprint: fingerprintId || null,
  });
  record.devices = devices;
  stampDailyActivity(record); // [NEW] rides this same write, no extra one
  try {
    await env.CES_LICENSES.put(`license:${licenseKey}`, JSON.stringify(record), { metadata: buildLicenseMetadata(record) });
  } catch (err) {
    console.error('[licenses.mjs] validateLicense device-bind write failed (failing open on this request):', err.message);
    // Fail OPEN here, unlike the read above: the device WAS legitimately
    // entitled to a slot — the fact KV.put() transiently failed shouldn't
    // deny a paying subscriber this one message. The bind attempt simply
    // retries on their next message (same devices.length check).
    return { ok: true, license: record };
  }
  return { ok: true, license: record };
}

// ── Shared rolling-24h-window counter — internal, not exported. Both the
//    file quota and the message quota below are thin wrappers around this;
//    the window math (a real source of off-by-one bugs — see the
//    "does NOT slide forward" note) exists in exactly one place instead of
//    two copies drifting apart over time. ────────────────────────────────
const KV_MIN_TTL_SECONDS = 60; // Cloudflare KV's own floor on expirationTtl

async function _readDailyCounter(env, key, maxPerWindow) {
  const raw = await env.CES_LICENSES.get(key);
  if (!raw) return { count: 0, remaining: maxPerWindow, resetsAt: null };
  const state = JSON.parse(raw);
  const count = Number(state.count) || 0;
  if (count >= maxPerWindow) {
    return { count, remaining: 0, resetsAt: state.resetsAt, exceeded: true };
  }
  return { count, remaining: maxPerWindow - count, resetsAt: state.resetsAt };
}

// WINDOW SEMANTICS: the 24h window starts at the FIRST touch in a fresh
// window and does NOT slide forward on touches 2, 3, ... N — i.e. this is
// "N uses, then wait out the rest of a day from your first one," not
// "always N uses available in whatever trailing 24h you look at." The
// alternative (refresh the TTL on every touch) would let a user who
// touches it exactly once every 23 hours stay permanently mid-window and
// never see the count actually reset to 0 — the fixed-origin version here
// avoids that.
//
// amount (default 1): lets a single message that attaches several files at
// once (e.g. vision.js receiving one image AND one text file in the same
// request) charge all of them in ONE read+write instead of N round trips —
// a batch of 3 costs the same 1 write as a batch of 1, not 3x.
async function _touchDailyCounter(env, key, windowSeconds, amount = 1) {
  const raw = await env.CES_LICENSES.get(key);
  const now = Date.now();
  let count = 0;
  let ttl = windowSeconds;
  let resetsAt = new Date(now + windowSeconds * 1000).toISOString();
  if (raw) {
    const state = JSON.parse(raw);
    count = Number(state.count) || 0;
    const remainingMs = new Date(state.resetsAt).getTime() - now;
    if (remainingMs > KV_MIN_TTL_SECONDS * 1000) {
      // Still inside the existing window — keep ITS origin/expiry.
      ttl = Math.ceil(remainingMs / 1000);
      resetsAt = state.resetsAt;
    } else {
      // Existing window has effectively expired — start a fresh one.
      count = 0;
    }
  }
  count += Math.max(1, Math.floor(Number(amount)) || 1);
  await env.CES_LICENSES.put(key, JSON.stringify({ count, resetsAt }), {
    expirationTtl: Math.max(ttl, KV_MIN_TTL_SECONDS),
  });
  return { count, resetsAt };
}

// ── Regular-tier daily FILE quota. [REVISED — was a one-time lifetime cap
//    (1 file, ever); now FREE_FILES_PER_WINDOW files per rolling 24h
//    window, any type, chosen freely by the user. identity is caller-
//    supplied — chat.js/dev-upload.js pass clientIp (CF-Connecting-IP),
//    consistent with the existing rate limiter's own accepted IP-as-
//    identity tradeoff (shared NAT/office IPs share one quota).
//
//    WRITE COST: up to FREE_FILES_PER_WINDOW (3) writes per identity per
//    rolling 24h window — 50 free users each using their full 3/day is
//    150 writes/day from this feature alone, stacking with every other KV
//    write source on the account (see file header). Both functions fail
//    OPEN on missing identity / unbound KV / KV errors — this is a soft
//    product throttle, not a security boundary. ─────────────────────────
const FREE_FILES_PER_WINDOW = 3;
const FREE_FILE_WINDOW_SECONDS = 86400; // 24h

export async function checkFreeFileQuota(env, identity) {
  const id = typeof identity === 'string' ? identity.trim() : '';
  if (!id || id === 'unknown' || !env.CES_LICENSES) {
    return { ok: true, remaining: FREE_FILES_PER_WINDOW };
  }
  try {
    const r = await _readDailyCounter(env, `freequota:${id}`, FREE_FILES_PER_WINDOW);
    return r.exceeded
      ? { ok: false, reason: 'FREE_QUOTA_USED', remaining: 0, resetsAt: r.resetsAt }
      : { ok: true, remaining: r.remaining, resetsAt: r.resetsAt };
  } catch (err) {
    console.error('[licenses.mjs] checkFreeFileQuota read failed (failing open):', err.message);
    return { ok: true, remaining: FREE_FILES_PER_WINDOW };
  }
}

// Call ONLY after the upload(s) this quota gates have actually succeeded —
// integration notes: after KV.put of a staged file (dev-upload.js) or
// after a multi-file vision.js/chat.js request is confirmed valid, not
// before, so a client that uploads-then-abandons doesn't burn quota on a
// file nobody ever attached to a message.
//
// count (default 1): how many of the daily allowance to charge in this one
// call — e.g. a vision.js request with 1 image + 1 text file passes 2,
// costing 1 read + 1 write total rather than calling this twice.
export async function consumeFreeFileQuota(env, identity, count = 1) {
  const id = typeof identity === 'string' ? identity.trim() : '';
  if (!id || id === 'unknown' || !env.CES_LICENSES) return;
  try {
    await _touchDailyCounter(env, `freequota:${id}`, FREE_FILE_WINDOW_SECONDS, count);
  } catch (err) {
    console.error('[licenses.mjs] consumeFreeFileQuota write failed (non-fatal):', err.message);
  }
}

// ── Regular-tier daily MESSAGE quota. [NEW — per explicit request: "3
//    files stays, and suggest a text-message limit too."]
//
//    FREE_MESSAGES_PER_WINDOW = 15/day is this reviewer's suggested
//    number, not a measured one — there was no traffic data available to
//    tune it against. Reasoning: this product is a civil-engineering
//    calculation assistant, not a casual chat app — 15 messages is enough
//    for a free user to genuinely test whether the assistant helps with a
//    real question (attach a calc, ask 2-3 follow-ups), but clearly short
//    of what an actual full workflow needs, which is the "bait AND
//    redirect" balance that was asked for. Tune FREE_MESSAGES_PER_WINDOW
//    directly if it should feel more or less generous.
//
//    ATOMIC CHECK-AND-CONSUME, unlike the file quota: a chat message is a
//    single user action (not the file quota's two-step "upload, maybe
//    attach later" shape), so there's no "uploaded but never used" case
//    to guard against by delaying the write. Trade-off, stated plainly: if
//    every provider in chat.js's fallback chain happens to fail AFTER this
//    consumes, the user loses one of their 15 for a reply they never
//    got. Wiring consumption to the actual stream-completion point
//    instead would remove that, but requires tracing chat.js's streaming/
//    fallback logic in full first — flagged as a possible follow-up
//    rather than guessed at now.
//
//    WRITE COST — THE ONE TO WATCH: unlike the file quota (naturally rare
//    — most messages don't attach a file), this runs on EVERY regular-
//    tier chat message. A free user who sends all 15 daily messages costs
//    15 writes that day, not up to 3. On the shared account-wide 1,000-
//    writes/day KV budget (see file header), that ceiling arrives at
//    roughly 1000 / 15 ≈ 66 free users maxing out their daily messages —
//    BEFORE counting the file quota, license writes, rate limiting, or
//    anything else already drawing from the same pool. If usage
//    approaches that, the standard fix is the $5/month Workers Paid plan
//    (developers.cloudflare.com/workers/platform/pricing/), which raises
//    included KV operations to 1,000,000/month (~33,000/day) — roughly a
//    33x increase — not a redesign of this function. Check Cloudflare
//    dashboard -> Workers KV -> Metrics periodically rather than guessing
//    at real traffic. ───────────────────────────────────────────────────
const FREE_MESSAGES_PER_WINDOW = 15;
const FREE_MESSAGE_WINDOW_SECONDS = 86400; // 24h

export async function checkAndConsumeFreeMessageQuota(env, identity) {
  const id = typeof identity === 'string' ? identity.trim() : '';
  if (!id || id === 'unknown' || !env.CES_LICENSES) {
    return { ok: true, remaining: FREE_MESSAGES_PER_WINDOW };
  }
  try {
    const peek = await _readDailyCounter(env, `freemsgs:${id}`, FREE_MESSAGES_PER_WINDOW);
    if (peek.exceeded) {
      return { ok: false, reason: 'FREE_MESSAGE_QUOTA_USED', remaining: 0, resetsAt: peek.resetsAt };
    }
    const r = await _touchDailyCounter(env, `freemsgs:${id}`, FREE_MESSAGE_WINDOW_SECONDS);
    return { ok: true, remaining: Math.max(FREE_MESSAGES_PER_WINDOW - r.count, 0), resetsAt: r.resetsAt };
  } catch (err) {
    console.error('[licenses.mjs] checkAndConsumeFreeMessageQuota failed (failing open):', err.message);
    return { ok: true, remaining: FREE_MESSAGES_PER_WINDOW };
  }
}

// ── [NEW] Full admin CRUD — listing, single-record detail, general edit,
//    and hard delete. Same caller-authenticates-first contract as
//    issueLicense/revokeLicense/resetDevices above: call these ONLY from
//    a site already gated by the real isDeveloperMode check. ───────────

const LIST_LICENSES_MAX_LIMIT = 200;

// Write count: 0 (list() is a read op; the only writes are the rare
// fallback path below, and even those are metadata BACKFILLS onto
// records that already exist unchanged — see comment inline). Paginated
// via KV's own cursor: pass the previous call's `cursor` back in to
// continue. limit is capped at 200/call — KV's own list() hard cap is
// 1000, but a devCommand JSON response (and the chat bubble rendering
// it) that large is impractical; page instead of dumping everything.
export async function listLicenses(env, { cursor, limit = 50, statusFilter } = {}) {
  if (!env.CES_LICENSES) {
    return { ok: false, error: 'CES_LICENSES KV namespace is not bound on the server.', code: 'KV_NOT_BOUND' };
  }
  const pageSize = Math.min(Math.max(1, Number(limit) || 50), LIST_LICENSES_MAX_LIMIT);

  let page;
  try {
    page = await env.CES_LICENSES.list({ prefix: 'license:', cursor: cursor || undefined, limit: pageSize });
  } catch (err) {
    console.error('[licenses.mjs] listLicenses KV list failed:', err.message);
    return { ok: false, error: 'Storage error while listing licenses. Please retry.', code: 'KV_LIST_FAILED' };
  }

  const licenses = [];
  for (const entry of page.keys) {
    const licenseKey = entry.name.slice('license:'.length);
    if (entry.metadata && typeof entry.metadata === 'object') {
      licenses.push({ licenseKey, ...entry.metadata }); // fast path — no extra read
      continue;
    }
    // Fallback for a license written before this feature existed (no
    // metadata attached at put() time yet — issue/revoke/reset/validate
    // all backfill it on their next write, so this path only ever fires
    // for a record nothing has touched since this feature shipped). One
    // extra GET, scoped to exactly the records that need it.
    try {
      const raw = await env.CES_LICENSES.get(entry.name);
      if (!raw) continue;
      const record = JSON.parse(raw);
      licenses.push({ licenseKey, ...buildLicenseMetadata(record) });
    } catch (err) {
      console.warn('[licenses.mjs] listLicenses fallback read failed for', licenseKey, '— omitted from this page:', err.message);
    }
  }

  const filtered = statusFilter ? licenses.filter((l) => l.status === statusFilter) : licenses;
  return {
    ok: true,
    licenses: filtered,
    cursor: page.list_complete ? null : page.cursor,
    listComplete: !!page.list_complete,
  };
}

// Write count: 0. Full record (source of truth, not the metadata
// summary) — for a "view details" admin lookup, and as the read-half of
// updateLicense/deleteLicense below.
export async function getLicense(env, licenseKeyRaw) {
  if (!env.CES_LICENSES) {
    return { ok: false, error: 'CES_LICENSES KV namespace is not bound on the server.', code: 'KV_NOT_BOUND' };
  }
  const licenseKey = normalizeKey(licenseKeyRaw);
  if (!licenseKey) return { ok: false, error: 'licenseKey is required.', code: 'BAD_INPUT' };

  let raw;
  try {
    raw = await env.CES_LICENSES.get(`license:${licenseKey}`);
  } catch (err) {
    console.error('[licenses.mjs] getLicense KV read failed:', err.message);
    return { ok: false, error: 'Storage error. Please retry.', code: 'KV_READ_FAILED' };
  }
  if (!raw) return { ok: false, error: 'License not found.', code: 'NOT_FOUND' };

  let record;
  try { record = JSON.parse(raw); } catch { return { ok: false, error: 'Stored license record is corrupted.', code: 'CORRUPT' }; }
  return { ok: true, license: record };
}

// Write count: 1, only if the record exists AND at least one recognized
// field was provided. General-purpose edit: extend or replace expiry,
// force a status change (including un-revoking), and/or overwrite the
// note — in any combination in one call. Deliberately does NOT touch
// devices[]; resetDevices already owns that with its own tested
// semantics, and folding it in here would just be the same operation
// under a second name.
export async function updateLicense(env, licenseKeyRaw, { extendDays, setExpiresAt, setStatus, setNote } = {}) {
  if (!env.CES_LICENSES) {
    return { ok: false, error: 'CES_LICENSES KV namespace is not bound on the server.', code: 'KV_NOT_BOUND' };
  }
  const licenseKey = normalizeKey(licenseKeyRaw);
  if (!licenseKey) return { ok: false, error: 'licenseKey is required.', code: 'BAD_INPUT' };

  const hasExtend = extendDays !== undefined && extendDays !== null && extendDays !== '';
  const hasSetExpiry = typeof setExpiresAt === 'string' && setExpiresAt.trim() !== '';
  if (hasExtend && hasSetExpiry) {
    return { ok: false, error: 'Provide extendDays OR setExpiresAt, not both.', code: 'CONFLICTING_FIELDS' };
  }
  if (hasExtend && (!Number.isFinite(Number(extendDays)) || Number(extendDays) === 0)) {
    return { ok: false, error: 'extendDays must be a non-zero number (negative shortens).', code: 'BAD_DURATION' };
  }
  if (hasSetExpiry && Number.isNaN(new Date(setExpiresAt).getTime())) {
    return { ok: false, error: 'setExpiresAt must be a valid ISO date string.', code: 'BAD_DATE' };
  }
  if (setStatus !== undefined && setStatus !== 'active' && setStatus !== 'revoked') {
    return { ok: false, error: "setStatus must be 'active' or 'revoked'.", code: 'BAD_STATUS' };
  }
  const hasNote = typeof setNote === 'string';
  if (!hasExtend && !hasSetExpiry && setStatus === undefined && !hasNote) {
    return { ok: false, error: 'Provide at least one field to update (extendDays, setExpiresAt, setStatus, setNote).', code: 'NO_FIELDS' };
  }

  let raw;
  try {
    raw = await env.CES_LICENSES.get(`license:${licenseKey}`);
  } catch (err) {
    console.error('[licenses.mjs] updateLicense KV read failed:', err.message);
    return { ok: false, error: 'Storage error. Please retry.', code: 'KV_READ_FAILED' };
  }
  if (!raw) return { ok: false, error: 'License not found.', code: 'NOT_FOUND' };

  let record;
  try { record = JSON.parse(raw); } catch { return { ok: false, error: 'Stored license record is corrupted.', code: 'CORRUPT' }; }

  if (hasExtend) {
    const base = record.expiresAt ? new Date(record.expiresAt).getTime() : Date.now();
    record.expiresAt = new Date(base + Number(extendDays) * 86400000).toISOString();
  } else if (hasSetExpiry) {
    record.expiresAt = new Date(setExpiresAt).toISOString();
  }
  if (setStatus !== undefined) {
    record.status = setStatus;
    if (setStatus === 'revoked') record.revokedAt = new Date().toISOString();
    else delete record.revokedAt; // un-revoking clears an audit stamp that no longer applies
  }
  if (hasNote) record.note = setNote.slice(0, 500);

  try {
    await env.CES_LICENSES.put(`license:${licenseKey}`, JSON.stringify(record), { metadata: buildLicenseMetadata(record) });
  } catch (err) {
    console.error('[licenses.mjs] updateLicense KV write failed:', err.message);
    return { ok: false, error: 'Storage error while updating. Please retry.', code: 'KV_WRITE_FAILED' };
  }
  return { ok: true, license: record };
}

// Write count: 1 delete. IRREVERSIBLE — unlike revokeLicense, this
// removes the record entirely; no audit trail survives it. Prefer
// revokeLicense for ordinary cancellations/refunds (keeps history, and
// is itself reversible via updateLicense's setStatus:'active'); reserve
// this for genuine cleanup — test keys, a duplicate issuance, an
// explicit support request to actually erase a record.
export async function deleteLicense(env, licenseKeyRaw) {
  if (!env.CES_LICENSES) {
    return { ok: false, error: 'CES_LICENSES KV namespace is not bound on the server.', code: 'KV_NOT_BOUND' };
  }
  const licenseKey = normalizeKey(licenseKeyRaw);
  if (!licenseKey) return { ok: false, error: 'licenseKey is required.', code: 'BAD_INPUT' };

  let existed;
  try {
    existed = await env.CES_LICENSES.get(`license:${licenseKey}`);
  } catch (err) {
    console.error('[licenses.mjs] deleteLicense KV read failed:', err.message);
    return { ok: false, error: 'Storage error. Please retry.', code: 'KV_READ_FAILED' };
  }
  if (!existed) return { ok: false, error: 'License not found.', code: 'NOT_FOUND' };

  try {
    await env.CES_LICENSES.delete(`license:${licenseKey}`);
  } catch (err) {
    console.error('[licenses.mjs] deleteLicense KV delete failed:', err.message);
    return { ok: false, error: 'Storage error while deleting. Please retry.', code: 'KV_DELETE_FAILED' };
  }
  return { ok: true, licenseKey };
}
