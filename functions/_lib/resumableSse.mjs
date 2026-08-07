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
// about, and a client-visible "chunk 7" would not correspond to the 7th
// thing the model said upstream. chunkIndex has to be assigned at the
// point text is actually written to the client stream — i.e. here.
//
// ── Wire contract (must match consumeAiSseStream()'s parser in
//    pc_suite_v46.html / footing_pro_v46.html exactly — see that file's
//    handleEventData()) ─────────────────────────────────────────────────
//   {"delta": "...", "chunkIndex": N}                — per streamed token/segment, N is 0-based and monotonic per HTTP response
//   {"redacted": true, "reply": "...", "chunkIndex": N}
//   {"error": "...", "chunkIndex": N}
//   {"done": true, "finalChunkIndex": N, ...extraFields}   — exactly once, terminal
// `chunkIndex`/`finalChunkIndex` are additive fields only — every field
// the frontend already reads (delta/redacted/reply/error/done/truncated/
// interrupted/devMode) is unchanged, so this is safe to deploy even before
// the frontend patch lands (older clients just ignore the new field).
//
// ── Integration — chat.js / vision.js (NOT included; apply by hand) ─────
// Both files build a single SSE Response per the repo's own [PATCH] notes
// ("single SSE Response instead of buffered JSON"). Wherever that response
// body currently does the equivalent of:
//
//     controller.enqueue(encoder.encode('data: ' + JSON.stringify({ delta: text }) + '\n\n'));
//
// construct ONE SseChunkWriter when that ReadableStream/TransformStream is
// created, and replace every such hand-rolled enqueue with the matching
// writeXxx() call:
//
//     import { SseChunkWriter } from '../_lib/resumableSse.mjs';
//     const encoder = new TextEncoder();
//     let sseWriter;
//     const body = new ReadableStream({
//       start(controller) {
//         sseWriter = new SseChunkWriter(chunk => controller.enqueue(chunk), encoder);
//         // ... existing provider-cascade / raceKeyPool / StreamingSanitizer
//         // logic goes here, calling the writer as sanitized output becomes
//         // available ...
//       },
//     });
//     ...
//     sseWriter.writeDelta(sanitizedText);
//     ...
//     sseWriter.writeDone({ truncated: true });   // MAX_TOKENS cutoff
//     sseWriter.writeDone({ interrupted: true }); // upstream provider dropped after commit
//     sseWriter.writeDone({ devMode: true });     // omit the field entirely for a normal, non-dev turn
//     sseWriter.writeError('...');
//     sseWriter.writeRedacted(fullReply);
//
// One writer instance per HTTP response — do not share an instance across
// requests/isolates (see Resource Lifecycle Verification in the
// accompanying advisory for why: each instance's counter and `_done` latch
// are per-response state, and Cloudflare Workers gives no guarantee two
// requests land on the same isolate to begin with).
//
// If the response is built with a TransformStream instead of a raw
// ReadableStream, the write function is the same shape:
//   const { readable, writable } = new TransformStream();
//   const streamWriter = writable.getWriter();
//   const sseWriter = new SseChunkWriter(chunk => streamWriter.write(chunk), encoder);
//   // ^ write() returns a Promise here; SseChunkWriter does not await it
//   // (see class comment below for why that's the correct choice, not an
//   // oversight) — if you need backpressure-aware writes, await
//   // streamWriter.write() yourself at the call site instead of inside
//   // this class, since only the caller knows whether backpressure should
//   // stall provider consumption or just buffer.
//
// ── Client resume handshake (read on the request; act on today) ─────────
// The client may now send `resume: true` and `lastChunkIndex: <int>` in
// the POST body when replaying a turn after a dropped connection (see the
// frontend patch's buildContinuationBody()). Neither field changes what
// gets generated — continuation semantics (skip the normal history slice,
// tell the model to pick up where the partial reply stopped) are driven
// entirely by the EXISTING `history[...].truncated === true` convention,
// unchanged, the same one the manual "كمل" flow already relies on. Treat
// the two new fields as diagnostic-only for now:
//
//     if (body.resume) {
//       console.log('[resume]', { lastChunkIndex: body.lastChunkIndex, sessionHint: body.history?.length });
//     }
//
// `lastChunkIndex` is also the exact hook a future Durable-Object-backed
// live-buffer resume would consume (replay buffered chunks after that
// index instead of re-prompting) — nothing here requires building that;
// today's continuation-based recovery is complete without it.

export class SseChunkWriter {
  // write:   function(Uint8Array) -> void. Call site supplies this so the
  //          class stays agnostic to which streaming primitive chat.js
  //          uses (ReadableStreamDefaultController#enqueue,
  //          WritableStreamDefaultWriter#write, etc). Deliberately called
  //          fire-and-forget, not awaited, even when `write` returns a
  //          Promise (e.g. a TransformStream writer): SSE delta writes are
  //          fire-and-forget by nature in every provider-cascade caller
  //          this project has (Gemini/Groq/OpenRouter/Workers AI all push
  //          deltas as they arrive; nothing here should stall provider
  //          consumption on browser-side backpressure). If a call site
  //          needs backpressure-aware writes, await write() at the call
  //          site instead — see the TransformStream note above.
  // encoder: a TextEncoder instance. Optional — one is created if omitted;
  //          pass your own to reuse a single encoder across writers.
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
    if (this._done) return false; // defensive no-op after a terminal write — see class note
    this._emit({ delta: text, chunkIndex: this._chunkIndex++ });
    return true;
  }

  // Terminal — reply was fully redacted (confidentiality gate) and
  // replaced wholesale. Matches streamSanitizer.mjs's existing
  // {redacted:true, reply} shape.
  writeRedacted(reply) {
    if (this._done) return false;
    this._done = true;
    this._emit({ redacted: true, reply, chunkIndex: this._chunkIndex });
    return true;
  }

  // Terminal — hard error before/during generation.
  writeError(message) {
    if (this._done) return false;
    this._done = true;
    this._emit({ error: message, chunkIndex: this._chunkIndex });
    return true;
  }

  // Terminal — normal or abnormal end of a turn. `fields` merges in
  // whatever the caller already sends today: {truncated:true},
  // {interrupted:true}, {devMode:true}, any combination, or {} for a
  // clean finish. Always call exactly once per response, even on a path
  // that never streamed a single delta (chunkIndex will just be 0).
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
