// functions/_lib/contextAnchor.mjs
//
// Fixes the failure class reported 2026-08: the model asserting a
// previously-suggested code/file change exists in the user's actual file,
// disconnected from what was actually uploaded. Root cause (confirmed by
// reading chat.js + footing_pro_v71's sendMessage()): uploaded text-file
// content is sent to the model exactly once — on the request that carries
// it — then never persisted. The client (footing_pro_v71.html:18600;
// pc_suite shares the byte-identical script block) pushes only a
// content-free label back into `history`:
//   history.push({ role: 'user', text: buildFileShareLabel(filesForSend, text) })
// which resolves to "[Attached text file: NAME]", not the file's content.
// Server-side, there is no default session store for ordinary traffic —
// rawHistory IS body.history, nothing more (chat.js:5995: `const rawHistory
// = Array.isArray(body.history) ? body.history : [];`). So one turn after
// upload, the file's content is gone from both client and server; the only
// remaining trace in context is the model's OWN prior reply about it, with
// nothing marking that reply as unconfirmed. Compounded by
// `rawHistory.slice(-10)` (chat.js:6132), which drops even that trace
// after ~5 exchanges.
//
// This module does NOT touch that slice — recency windowing for ordinary
// chat flow is a reasonable, deliberate token-budget device and stays as
// is (v12 QUOTA FIX rationale still applies). It adds a separate, small,
// always-included anchor for the one category of content that must not be
// subject to recency at all: the current text of files still under
// discussion. Pure functions, zero I/O — same philosophy as factGuard.mjs:
// deterministic, no KV, nothing added to CES_CHAT_KV/CES_SESSIONS' write
// budget (Workers KV free plan: 1,000 writes/day, account-wide, confirmed
// current as of this writing).
//
// CALL SITE: chat.js, immediately before `const recentHistory =
// rawHistory.slice(-10)` (~line 6132) — must run on the FULL rawHistory,
// not the sliced one, or this defeats its own purpose. See the accompanying
// chat.js patch notes for the exact insertion.
//
// KNOWN LIMITATION: block boundaries are delimiter-based (matching chat.js's
// own buildTextFilesBlock() output), not a structured format — same
// trade-off class as documentGuard's PDF_PAGE_SOFT_CAP being a soft, not
// exact, cap. A file whose own content happens to contain the literal
// substring "--- End of <its own name> ---" will truncate early. Not
// defended against here; not observed in real traffic as of this writing.

'use strict';

// Matches chat.js's buildTextFilesBlock() output (chat.js ~line 1798):
// "--- Attached file: NAME (truncated)? ---\nCONTENT...\n--- End of NAME ---"
const FULL_BLOCK_OPEN_RE = /--- Attached file: (.+?)(?: \(truncated\))? ---\n/g;

// Matches the client's content-free fallback (footing_pro_v71.html:17700-
// 17703 / pc_suite, byte-identical per REPO_STRUCTURE.txt's confirmed
// byte-identical main-app <script> block): "[Attached text file: NAME]" or
// "[Attached N text files: a, b, c]".
const LABEL_SINGLE_RE = /\[Attached text file: (.+?)\]/g;
const LABEL_MULTI_RE  = /\[Attached \d+ text files: (.+?)\]/g;

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Walks the FULL history once and returns, per distinct file name, the most
 * recently seen full-content block (last write wins), plus the set of names
 * seen only as content-free labels with no full block anywhere.
 *
 * @param {Array<{role?:string,text?:string}>} fullHistory
 * @returns {{ anchors: Map<string,{content:string,truncated:boolean,turnsAgo:number}>, staleLabelsOnly: Set<string> }}
 */
function scanFileHistory(fullHistory) {
  const anchors = new Map();
  const staleLabelsOnly = new Set();

  for (let i = 0; i < fullHistory.length; i++) {
    const turn = fullHistory[i];
    const text = typeof turn?.text === 'string' ? turn.text : '';
    if (!text) continue;
    const turnsAgo = fullHistory.length - 1 - i;

    FULL_BLOCK_OPEN_RE.lastIndex = 0;
    let openMatch;
    while ((openMatch = FULL_BLOCK_OPEN_RE.exec(text)) !== null) {
      const name = openMatch[1];
      const contentStart = openMatch.index + openMatch[0].length;
      const endRe = new RegExp(`\\n--- End of ${escapeRegExp(name)} ---`);
      const endMatch = endRe.exec(text.slice(contentStart));
      if (!endMatch) continue; // malformed/unmatched block — skip, don't guess
      const content = text.slice(contentStart, contentStart + endMatch.index);
      const truncated = content.includes('[\u26A0'); // '[⚠' truncation-notice marker
      anchors.set(name, { content, truncated, turnsAgo }); // later turn overwrites earlier
      staleLabelsOnly.delete(name);
    }

    LABEL_SINGLE_RE.lastIndex = 0;
    let lm;
    while ((lm = LABEL_SINGLE_RE.exec(text)) !== null) {
      if (!anchors.has(lm[1])) staleLabelsOnly.add(lm[1]);
    }
    LABEL_MULTI_RE.lastIndex = 0;
    let mm;
    while ((mm = LABEL_MULTI_RE.exec(text)) !== null) {
      for (const name of mm[1].split(',').map(s => s.trim()).filter(Boolean)) {
        if (!anchors.has(name)) staleLabelsOnly.add(name);
      }
    }
  }

  // Full content recovered anywhere in the scan always wins over a
  // label-only sighting, regardless of chronological order between them.
  for (const name of anchors.keys()) staleLabelsOnly.delete(name);

  return { anchors, staleLabelsOnly };
}

// ~1,500 tokens — bounded like promptBudget.mjs's other tiers. Large enough
// for 2-3 real calculation/code files; small enough that a long-forgotten
// conversation can't silently balloon the prompt. Eviction is oldest-first
// by turnsAgo (see below), not insertion order.
const DEFAULT_MAX_ANCHOR_TOTAL_CHARS = 6000;

/**
 * @param {Array<{role?:string,text?:string}>} fullHistory - the complete,
 *   UNSLICED rawHistory array.
 * @param {string[]} [currentlyAttachedNames] - names already present in
 *   THIS request's live upload (e.g.
 *   textFilesResult.files.concat(kvFilesResult.files).map(f => f.name)) —
 *   excluded here so a just-re-uploaded file isn't duplicated between the
 *   live turn and the anchor block.
 * @param {{maxTotalChars?: number}} [opts]
 * @returns {{
 *   promptBlock: string,
 *   anchoredFiles: Array<{name:string, turnsAgo:number, truncated:boolean, chars:number}>,
 *   evictedFiles: Array<{name:string, turnsAgo:number}>,
 *   staleLabelsOnly: string[],
 * }}
 */
export function extractPersistentFileAnchors(fullHistory, currentlyAttachedNames = [], opts = {}) {
  const maxTotalChars = opts.maxTotalChars ?? DEFAULT_MAX_ANCHOR_TOTAL_CHARS;
  if (!Array.isArray(fullHistory) || fullHistory.length === 0) {
    return { promptBlock: '', anchoredFiles: [], evictedFiles: [], staleLabelsOnly: [] };
  }

  const liveNames = new Set(currentlyAttachedNames);
  const { anchors, staleLabelsOnly } = scanFileHistory(fullHistory);
  for (const name of liveNames) { anchors.delete(name); staleLabelsOnly.delete(name); }

  // Most-recently-touched first, so budget eviction below drops the OLDEST
  // material first, not an arbitrary map-insertion order.
  const ordered = [...anchors.entries()].sort((a, b) => a[1].turnsAgo - b[1].turnsAgo);

  const anchoredFiles = [];
  const evictedFiles = [];
  let budget = maxTotalChars;
  const parts = [];
  for (const [name, info] of ordered) {
    if (info.content.length > budget) {
      evictedFiles.push({ name, turnsAgo: info.turnsAgo });
      continue;
    }
    budget -= info.content.length;
    anchoredFiles.push({ name, turnsAgo: info.turnsAgo, truncated: info.truncated, chars: info.content.length });
    parts.push(
      `\n--- Previously shared file (still in scope, from ${info.turnsAgo} turn(s) ago): ${name} ---\n` +
      info.content +
      `\n--- End of ${name} ---`
    );
  }

  const staleList = [...staleLabelsOnly];
  let block = '';
  if (parts.length > 0 || staleList.length > 0 || evictedFiles.length > 0) {
    block += `\n\n════════════════════════════════════════\n`;
    block += `PREVIOUSLY SHARED FILES — CURRENT CONTENT, NOT THIS TURN'S UPLOAD\n`;
    block += `════════════════════════════════════════\n`;
    block += `Most recent version of each file the user attached earlier in this conversation,\n`;
    block += `re-included here because it would otherwise age out of the recent-turns window\n`;
    block += `long before the conversation itself is over. Treat this section — not your own\n`;
    block += `earlier remarks about these files — as their current ground truth.`;
    block += parts.join('');
    if (staleList.length > 0) {
      block += `\n\nNOTE — mentioned earlier but content is no longer available (only a label\n`;
      block += `survived — e.g. a dev session saved before this mechanism existed): ` +
        staleList.join(', ') + `.\n`;
      block += `Do not describe their contents from memory of your own prior reply — say the\n`;
      block += `content isn't available and ask the user to re-share the file.\n`;
    }
    if (evictedFiles.length > 0) {
      block += `\n\nNOTE — excluded from this prompt to stay within the attachment budget (oldest\n`;
      block += `excluded first): ` +
        evictedFiles.map(f => `${f.name} (${f.turnsAgo} turns ago)`).join(', ') + `.\n`;
      block += `Ask the user to re-attach one of these if the current question needs it.\n`;
    }
  }

  return { promptBlock: block, anchoredFiles, evictedFiles, staleLabelsOnly: staleList };
}

// Exposed for contextAnchor.test.mjs only — not part of the public surface
// chat.js should call.
export function __testables() {
  return { scanFileHistory, escapeRegExp };
}
