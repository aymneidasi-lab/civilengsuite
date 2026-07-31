// ============================================================================
// SAVE THIS FILE AS:  functions/_lib/sessions.mjs
// (sibling of the existing functions/_lib/rotation.mjs)
// ============================================================================
// ── Persistent Developer Sessions — KV-backed save/load/list/delete ────────
// [v27] Extracted out of functions/api/chat.js, mirroring the existing
// functions/_lib/rotation.mjs split. Two call sites need this identically:
// functions/api/chat.js (devCommand save/load/list/delete/delete_all, plus
// the natural-language save/load/list triggers) and the dedicated REST
// endpoints functions/delete/[sessionName].js and functions/delete/all.js.

// ── Persistent Developer Sessions (v20) — save/load via KV ─────────────────
// See CHANGELOG v20 at the top of this file for the full design rationale
// (binding choice, body-vs-headers, sessionKey-vs-devPassword, ordering).
const DEV_SESSION_KV_PREFIX      = 'dev_chat:';
const DEV_SESSION_KEY_MAX_LEN    = 128;        // sessionKey length cap
const DEV_SESSION_MAX_SERIALIZED = 1_000_000;  // ~1MB guard on stored JSON size
// v26: charset enforced on WRITE (save) only, never on read (load/list).
// Enforcing it on load too would lock the developer out of any session
// saved before this validation existed (spaces, punctuation, etc. were
// previously unrestricted) — those must stay loadable. New saves are
// restricted to Latin letters/digits, the Arabic block (U+0600-U+06FF,
// which also covers Arabic-Indic digits), underscore, and hyphen — this
// app is Arabic/English only (see cesGetSttLang()), so this isn't a
// narrower charset than the product actually needs. No \p{L}/u-flag
// property escapes here on purpose, so the identical pattern can be
// reused verbatim on the frontend without depending on a modern regex
// engine in whatever browser/webview embeds the chat widget.
const DEV_SESSION_NAME_PATTERN   = /^[A-Za-z0-9\u0600-\u06FF_-]+$/;
// v27: reserved sessionKey values, write-time only — a session named "all"
// would be unreachable via the static DELETE /delete/all route (which
// Cloudflare always matches before the dynamic /delete/[sessionName]).
const DEV_SESSION_RESERVED_NAMES = new Set(['all']);
// v26: the exact, deterministic confirmation devCommand:'activate' returns.
// Kept as a single literal (not templated per-language) — see the /dev
// handler's rationale comment in the frontend for why English-only is the
// right call here despite the app being bilingual elsewhere.
const DEV_ACTIVATION_BANNER      = '🔒 Developer mode active — Eng. Aymn Asi authenticated.';

// saveConversation() — writes { history, title, savedAt, messageCount } to
// `${DEV_SESSION_KV_PREFIX}${sessionKey}` in the given KV binding. No
// expirationTtl is set: unlike checkRateLimit()'s counters, session data is
// meant to persist until explicitly overwritten by a later save under the
// same sessionKey. `kv` is env.CES_SESSIONS, injected by the caller (never
// read from `env` directly in here — keeps this testable with a mock KV).
// `title` is optional (v21) — omit it or pass ''/null/undefined and the
// stored record gets title: null; existing 3-arg call sites are unaffected.
// `options.overwrite` (v27, default false) — probes for an existing key
// FIRST via kv.list({prefix, limit:1}) (metadata only, never the value —
// same reasoning listSessions() documents below) and refuses to write if
// found, returning existing metadata so the caller can show what it would
// overwrite. NOT an atomic compare-and-swap (KV has none to expose) — see
// PAGES-INTEGRATION.md / the SessionCoordinator DO for the actual guarantee
// if this feature's concurrency (currently: one DEVELOPER_PASSWORD) ever
// changes.
async function saveConversation(kv, sessionKey, history, title, options) {
  const overwrite = !!(options && options.overwrite);
  const fullKey = DEV_SESSION_KV_PREFIX + sessionKey;
  if (!overwrite) {
    try {
      const probe = await kv.list({ prefix: fullKey, limit: 1 });
      const match = probe.keys.find((k) => k.name === fullKey);
      if (match) {
        const meta = match.metadata && typeof match.metadata === 'object' ? match.metadata : null;
        return {
          ok: false,
          error: `A session named "${sessionKey}" already exists.`,
          code: 'SESSION_EXISTS',
          existing: {
            title: meta && typeof meta.title === 'string' ? meta.title : null,
            savedAt: meta && typeof meta.savedAt === 'string' ? meta.savedAt : null,
            messageCount: meta && typeof meta.messageCount === 'number' ? meta.messageCount : null,
          },
        };
      }
    } catch (err) {
      console.error('[chat.js] saveConversation existence-check KV list error:', err.message);
      return { ok: false, error: 'Failed to check for an existing session before saving.', code: 'KV_LIST_ERROR' };
    }
  }
  const payload = {
    history,
    title: (typeof title === 'string' && title) ? title : null,
    savedAt: new Date().toISOString(),
    messageCount: history.length,
  };
  let serialized;
  try {
    serialized = JSON.stringify(payload);
  } catch (err) {
    console.error('[chat.js] saveConversation JSON.stringify error:', err.message);
    return { ok: false, error: 'Conversation history could not be serialized.', code: 'SERIALIZE_ERROR' };
  }
  if (serialized.length > DEV_SESSION_MAX_SERIALIZED) {
    return {
      ok: false,
      error: `Conversation too large to save (${serialized.length} chars, limit ${DEV_SESSION_MAX_SERIALIZED}).`,
      code: 'SESSION_TOO_LARGE',
    };
  }
  // v25: metadata mirrors {title, savedAt, messageCount} onto the KV key
  // entry itself (KV metadata cap is 1024 bytes serialized — this object is
  // a few dozen bytes, nowhere close). This is what makes listSessions()
  // below cheap: namespace.list() returns metadata inline with each key
  // name, so the list command never has to kv.get() every session just to
  // show the developer what's in it. Existing keys written before this
  // change have no metadata — listSessions() treats that as "unknown", not
  // an error (see the fallback there).
  try {
    await kv.put(fullKey, serialized, {
      metadata: {
        title: payload.title,
        savedAt: payload.savedAt,
        messageCount: payload.messageCount,
      },
    });
    return { ok: true, savedAt: payload.savedAt, messageCount: payload.messageCount };
  } catch (err) {
    console.error('[chat.js] saveConversation KV put error:', err.message);
    return { ok: false, error: 'Failed to save conversation to storage.', code: 'KV_WRITE_ERROR' };
  }
}

// loadConversation() — reads `${DEV_SESSION_KV_PREFIX}${sessionKey}` back
// from the given KV binding and returns the stored history array. Three
// distinct failure modes are reported with distinct `code` values so the
// client can render each correctly (missing vs corrupted vs KV outage):
//   SESSION_NOT_FOUND — kv.get() returned null (key never saved, or a typo
//     in sessionKey — Cloudflare KV has no "did you mean" for this).
//   SESSION_CORRUPTED — a value exists but isn't valid JSON, or doesn't
//     contain a `history` array (should only happen from external tampering
//     with the KV namespace directly, since saveConversation() above is the
//     only writer and always writes valid, matching JSON).
//   KV_READ_ERROR — the kv.get() call itself threw (KV outage/binding issue).
async function loadConversation(kv, sessionKey) {
  let raw;
  try {
    raw = await kv.get(DEV_SESSION_KV_PREFIX + sessionKey);
  } catch (err) {
    console.error('[chat.js] loadConversation KV get error:', err.message);
    return { ok: false, error: 'Failed to read conversation from storage.', code: 'KV_READ_ERROR' };
  }
  if (raw === null) {
    return { ok: false, error: 'No saved session found for this key.', code: 'SESSION_NOT_FOUND' };
  }
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (err) {
    console.error('[chat.js] loadConversation JSON.parse error (corrupted KV value):', err.message);
    return { ok: false, error: 'Saved session data is corrupted.', code: 'SESSION_CORRUPTED' };
  }
  if (!payload || !Array.isArray(payload.history)) {
    return { ok: false, error: 'Saved session data is corrupted.', code: 'SESSION_CORRUPTED' };
  }
  return {
    ok: true,
    history: payload.history,
    title: typeof payload.title === 'string' ? payload.title : null,
    savedAt: typeof payload.savedAt === 'string' ? payload.savedAt : null,
    messageCount: typeof payload.messageCount === 'number' ? payload.messageCount : payload.history.length,
  };
}

// listSessions() — enumerates every key under DEV_SESSION_KV_PREFIX via the
// KV binding's native list({prefix}) call. This is the actual fix for the
// problem the request was written to solve: KV has no query/index layer, so
// naming keys with a shared prefix and using list({prefix}) is the
// documented way to get "just the names" without a full-namespace scan
// (list() only ever walks keys under the prefix, not the whole namespace)
// and without reading each value (list() returns metadata, not the value —
// see saveConversation()'s kv.put(..., {metadata}) above, which is what
// populates title/savedAt/messageCount here for free).
//
// Pagination: the binding caps each list() call at 1000 keys and signals
// more with list_complete === false + a cursor. A single developer's
// session count will never approach that, but the loop below still drains
// the cursor correctly rather than silently truncating at 1000 — anything
// else is a latent bug waiting for a user who saves a lot of sessions.
// MAX_PAGES is a hard stop (100 pages = up to 100,000 keys) purely as a
// runaway-loop guard against a corrupted or unexpectedly huge cursor chain;
// it is not expected to ever bind in practice.
//
// Like saveConversation()/loadConversation(), `kv` is injected by the
// caller (env.CES_SESSIONS) rather than read from `env` in here.
const DEV_SESSION_LIST_MAX_PAGES = 100;

async function listSessions(kv, prefix) {
  const sessions = [];
  let cursor;
  let pages = 0;
  try {
    do {
      const page = await kv.list({ prefix, cursor });
      for (const key of page.keys) {
        const meta = key.metadata && typeof key.metadata === 'object' ? key.metadata : null;
        sessions.push({
          name: key.name.slice(prefix.length),
          title: meta && typeof meta.title === 'string' ? meta.title : null,
          savedAt: meta && typeof meta.savedAt === 'string' ? meta.savedAt : null,
          messageCount: meta && typeof meta.messageCount === 'number' ? meta.messageCount : null,
        });
      }
      cursor = page.list_complete ? undefined : page.cursor;
      pages += 1;
    } while (cursor && pages < DEV_SESSION_LIST_MAX_PAGES);
  } catch (err) {
    console.error('[chat.js] listSessions KV list error:', err.message);
    return { ok: false, error: 'Failed to list saved sessions from storage.', code: 'KV_LIST_ERROR' };
  }

  // Most-recently-saved first. Sessions with no savedAt (pre-v25 keys with
  // no metadata) sort to the end rather than being placed arbitrarily.
  sessions.sort((a, b) => {
    if (a.savedAt && b.savedAt) return b.savedAt.localeCompare(a.savedAt);
    if (a.savedAt) return -1;
    if (b.savedAt) return 1;
    return a.name.localeCompare(b.name);
  });

  return { ok: true, sessions };
}

// deleteConversation() — deletes `${DEV_SESSION_KV_PREFIX}${sessionKey}`.
// [v27] Existence checked first (same list()-based probe as the save-time
// duplicate check) purely so the caller gets an honest SESSION_NOT_FOUND —
// kv.delete() on an absent key is a silent no-op either way. No charset
// validation, mirroring loadConversation()'s permissiveness: a session
// saved before the charset restriction existed must stay deletable.
async function deleteConversation(kv, sessionKey) {
  const fullKey = DEV_SESSION_KV_PREFIX + sessionKey;
  try {
    const probe = await kv.list({ prefix: fullKey, limit: 1 });
    const exists = probe.keys.some((k) => k.name === fullKey);
    if (!exists) {
      return { ok: false, error: 'No saved session found for this key.', code: 'SESSION_NOT_FOUND' };
    }
  } catch (err) {
    console.error('[chat.js] deleteConversation existence-check KV list error:', err.message);
    return { ok: false, error: 'Failed to verify the session before deletion.', code: 'KV_LIST_ERROR' };
  }
  try {
    await kv.delete(fullKey);
    return { ok: true, sessionKey };
  } catch (err) {
    console.error('[chat.js] deleteConversation KV delete error:', err.message);
    return { ok: false, error: 'Failed to delete the session from storage.', code: 'KV_DELETE_ERROR' };
  }
}

// deleteAllConversations() — wipes every key under DEV_SESSION_KV_PREFIX.
// [v27] TWO PHASES, STRICTLY SEPARATED: fully enumerate every list() page
// into a plain array FIRST, with zero deletes issued during that walk, THEN
// delete from the array. Interleaving delete() with an in-progress list()
// pagination risks skipping keys depending on the store's cursor semantics
// (Cloudflare KV's list() is documented as lexicographic/key-ordered, which
// likely tolerates this, but "likely" isn't worth relying on when fully
// decoupling the two phases is free and removes the question for any
// paginated store this ever runs against). BATCHED via
// DEV_SESSION_DELETE_BATCH_SIZE + Promise.allSettled (not Promise.all) so
// one transient KV failure doesn't abort the run or lose track of what was
// already removed; deleting an absent key is a no-op, so retrying a
// partial-failure response is always safe.
const DEV_SESSION_DELETE_BATCH_SIZE = 25;

async function deleteAllConversations(kv, prefix) {
  let cursor;
  let pages = 0;
  const allNames = [];
  try {
    do {
      const page = await kv.list({ prefix, cursor });
      for (const key of page.keys) allNames.push(key.name);
      cursor = page.list_complete ? undefined : page.cursor;
      pages += 1;
    } while (cursor && pages < DEV_SESSION_LIST_MAX_PAGES);
  } catch (err) {
    console.error('[chat.js] deleteAllConversations KV list error:', err.message);
    return { ok: false, error: 'Failed to enumerate sessions for deletion. Nothing was deleted.', code: 'KV_LIST_ERROR', deletedCount: 0, failures: [] };
  }

  let deletedCount = 0;
  const failures = [];
  for (let i = 0; i < allNames.length; i += DEV_SESSION_DELETE_BATCH_SIZE) {
    const batch = allNames.slice(i, i + DEV_SESSION_DELETE_BATCH_SIZE);
    const results = await Promise.allSettled(batch.map((name) => kv.delete(name)));
    results.forEach((r, idx) => {
      if (r.status === 'fulfilled') deletedCount += 1;
      else failures.push({ key: batch[idx], error: String((r.reason && r.reason.message) || r.reason) });
    });
  }
  if (failures.length > 0) {
    console.error('[chat.js] deleteAllConversations partial failure:', failures.length, 'of', deletedCount + failures.length, 'keys failed');
    return {
      ok: false,
      error: `Deleted ${deletedCount} session(s), but ${failures.length} failed. Retry to clean up the rest.`,
      code: 'PARTIAL_DELETE_FAILURE',
      deletedCount,
      failures,
    };
  }
  return { ok: true, deletedCount };
}

export {
  DEV_SESSION_KV_PREFIX,
  DEV_SESSION_KEY_MAX_LEN,
  DEV_SESSION_MAX_SERIALIZED,
  DEV_SESSION_NAME_PATTERN,
  DEV_SESSION_RESERVED_NAMES,
  DEV_ACTIVATION_BANNER,
  DEV_SESSION_LIST_MAX_PAGES,
  DEV_SESSION_DELETE_BATCH_SIZE,
  saveConversation,
  loadConversation,
  listSessions,
  deleteConversation,
  deleteAllConversations,
};
