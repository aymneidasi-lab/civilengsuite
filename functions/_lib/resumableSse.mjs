// [PATCH] NEW — client-facing SSE chunk writer, paired with the chunk-index
// support added to sseStream.mjs.
//
// ── Why this is a separate file from sseStream.mjs ──────────────────────
// sseStream.mjs's iterSseEvents() decodes frames arriving FROM the upstream
// provider (Gemini/Groq/OpenRouter/Workers AI). What actually reaches the
// browser is whatever streamSanitizer.mjs's StreamingSanitizer lets through
// AFTER its holdback-margin + detect-and-retract gate — text can be held
// back briefly, or retracted, before it's ever forwarded. If chunkIndex
// were assigned at the iterSseEvents layer, a retracted upstream frame
// would still have consumed an index the client was never actually told
// about. chunkIndex has to be assigned at the point text is actually
// written to the client stream — i.e. here.
//
// ── Wire contract (verified directly against chat.js's and vision.js's
//    actual sendEvent() call sites, and against consumeAiSseStream()'s
//    parser in pc_suite_v46.html / footing_pro_v46.html — not assumed) ───
//   {"delta": "...", "chunkIndex": N}                        — per streamed segment, 0-based, monotonic per response
//   {"progress": "gemini"|"workers-ai"|"groq"|"openrouter", "tier"?: "primary"|"fallback"}  — no chunkIndex; carries no reply text (see writeProgress)
//   {"redacted": true, "reply": "...", "chunkIndex": N}       — NOT terminal; always followed by a writeDone() call, same as today's sendEvent({redacted...}); sendEvent({done:true})
//   {"error": "...", "chunkIndex": N, ...extra}               — NOT terminal, same reason; vision.js's extra `status` field rides through `extra`
//   {"done": true, "finalChunkIndex": N, ...extraFields}      — the ONLY terminal frame; exactly once
// chunkIndex/finalChunkIndex are additive fields only — every field the
// frontend already reads (delta/redacted/reply/error/done/truncated/
// interrupted/devMode/source/sources/...) is unchanged, so this is safe to
// deploy even before the frontend patch lands (older clients just ignore
// the new field).
//
// [REVISION] An earlier draft of this file had writeError()/writeRedacted()
// each set the terminal latch themselves, on the assumption a single call
// would both send the frame and close the stream. Once chat.js/vision.js
// were actually in hand, neither one works that way: both ALWAYS follow
// redacted/error with a separate, distinct writeDone() call (see the six
// redaction sites in chat.js and the two error sites across chat.js/
// vision.js). Fixed here to match the real call pattern exactly rather
// than the pattern this file originally guessed at.
//
// ── Integration — chat.js / vision.js ────────────────────────────────────
// Both files build a single SSE Response via `new ReadableStream({ async
// start(controller) {...} })`, with a local `sendEvent(obj)` closure doing
// `controller.enqueue(encoder.encode('data: ' + JSON.stringify(obj) +
// '\n\n'))` guarded by a local `streamClosed` flag. Construct ONE
// SseChunkWriter in place of that closure, keeping the SAME guard (it's
// local Worker-controller resilience this class is deliberately agnostic
// to — see the constructor's `write` param doc — not lost, just moved one
// level out to where `streamClosed`/`controller` already live):
//
//     import { SseChunkWriter } from '../_lib/resumableSse.mjs';
//     const encoder = new TextEncoder();
//     const stream = new ReadableStream({
//       async start(controller) {
//         let streamClosed = false;
//         function closeStream() { if (!streamClosed) { streamClosed = true; controller.close(); } }
//         const sseWriter = new SseChunkWriter((chunk) => {
//           if (streamClosed) return;
//           try { controller.enqueue(chunk); }
//           catch { streamClosed = true; }
//         }, encoder);
//         ...
//         sseWriter.writeDelta(sanitizedText);
//         sseWriter.writeProgress('gemini', { tier: 'primary' });
//         sseWriter.writeRedacted(REDACT_MSG); sseWriter.writeDone({});
//         sseWriter.writeError(friendlyMessage);                    sseWriter.writeDone({});
//         sseWriter.writeError(friendlyMessage, { status: 429 });    sseWriter.writeDone({ extracted, extractStatus }); // vision.js's error path also carries extraction results
//         sseWriter.writeDone({ truncated: true, interrupted: false, source: sourceTag, ...(sources.length && { sources }), ...(isDeveloperMode && { devMode: true }) });
//         closeStream();
//       },
//     });
//
// One writer instance per HTTP response — never share across requests.
// For a TransformStream-based response the write function is the same
// shape: chunk => writer.write(chunk) (return value intentionally not
// awaited — see class comment).
//
// ── Client resume handshake (read on the request; act on today) ─────────
// The client may send `resume: true` and `lastChunkIndex: <int>` on the
// POST body. Neither field changes what gets generated — continuation
// semantics are driven entirely by the EXISTING `history[...].truncated
// === true` convention, same one the manual "كمل" flow already relies on.
// Treat the two new fields as diagnostic-only for now:
//     if (body.resume) console.log('[resume]', { lastChunkIndex: body.lastChunkIndex });
// `lastChunkIndex` is also the hook a future Durable-Object-backed live-
// buffer resume would consume — nothing here requires building that.

export class SseChunkWriter {
  // write:   function(Uint8Array) -> void. Call site supplies this so the
  //          class stays agnostic to which streaming primitive chat.js/
  //          vision.js uses. Called fire-and-forget, not awaited, even
  //          when `write` returns a Promise (e.g. a TransformStream
  //          writer): SSE delta writes are fire-and-forget by nature in
  //          every provider-cascade caller this project has. If a call
  //          site needs backpressure-aware writes, await write() at the
  //          call site instead — see the TransformStream note above.
  // encoder: a TextEncoder instance. Optional — one is created if omitted.
  constructor(write, encoder) {
    if (typeof write !== 'function') {
      throw new TypeError('SseChunkWriter: write must be a function(Uint8Array)');
    }
    this._write = write;
    this._encoder = encoder || new TextEncoder();
    this._chunkIndex = 0;
    this._done = false;
  }

  // Number of writeDelta() calls made so far (== the chunkIndex that will
  // be assigned to the NEXT delta). Read this if you need to log/compare
  // against a client's lastChunkIndex without waiting for writeDone().
  get chunkIndex() { return this._chunkIndex; }
  get isDone() { return this._done; }

  writeDelta(text) {
    if (this._done) return false; // defensive no-op after writeDone() — see class note
    this._emit({ delta: text, chunkIndex: this._chunkIndex++ });
    return true;
  }

  // Non-terminal, purely informational (which provider/tier is currently
  // being attempted) — matches sendEvent({progress:'gemini', tier:...}) /
  // sendEvent({progress:'workers-ai'}) etc exactly. No chunkIndex: this
  // carries no reply text, so counting it would desync chunkIndex from
  // "how much of the reply the client has rendered", the only thing
  // lastChunkIndex needs to answer accurately. Unrecognized by today's
  // frontend parser (handleEventData only reads delta/redacted/error/
  // done) — harmless no-op there until/unless it's taught to show it.
  writeProgress(provider, extra) {
    if (this._done) return false;
    this._emit(Object.assign({ progress: provider }, extra));
    return true;
  }

  // Non-terminal — matches real usage exactly: chat.js's six redaction
  // sites all follow this with their OWN separate writeDone({}) call, one
  // synchronous step later. Do not assume this closes the stream; call
  // writeDone() yourself immediately after, same as today's
  // sendEvent({redacted:true,reply}); sendEvent({done:true}).
  writeRedacted(reply) {
    if (this._done) return false;
    this._emit({ redacted: true, reply, chunkIndex: this._chunkIndex });
    return true;
  }

  // Non-terminal, same reason as writeRedacted — chat.js's exhausted-
  // layers path and vision.js's no-winner path both follow this with
  // their own writeDone() call. `extra` carries fields beyond the message
  // itself; vision.js's only caller today uses it for {status}, matching
  // sendEvent({error, status}) — chat.js's callers omit it, matching its
  // plain sendEvent({error}).
  writeError(message, extra) {
    if (this._done) return false;
    this._emit(Object.assign({ error: message, chunkIndex: this._chunkIndex }, extra));
    return true;
  }

  // Terminal — the ONLY method that closes the writer. Covers every real
  // ending: a clean finish, a truncated/interrupted finish, and the frame
  // that always follows writeRedacted()/writeError(). `fields` merges in
  // whatever the caller already sends today: {truncated:true},
  // {interrupted:true}, {devMode:true}, {source, sources}, {extracted,
  // extractStatus}, any combination, or {} for a bare done. Call exactly
  // once per response, even on a path that never streamed a single delta
  // (chunkIndex will just be 0).
  writeDone(fields) {
    if (this._done) return false;
    this._done = true;
    this._emit(Object.assign({ done: true, finalChunkIndex: this._chunkIndex }, fields));
    return true;
  }

  _emit(obj) {
    this._write(this._encoder.encode('data: ' + JSON.stringify(obj) + '\n\n'));
  }
}
