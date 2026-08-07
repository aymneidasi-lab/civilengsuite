// Generic SSE (Server-Sent Events) frame decoder for upstream provider
// streams. Provider-agnostic: yields the raw string payload of each
// `data: ...` line (multi-line `data:` fields are joined per the SSE spec).
// Does NOT interpret `[DONE]` or JSON — callers do that, since Gemini has
// no [DONE] sentinel (terminates on a non-empty finishReason instead) while
// Groq/OpenRouter/Workers AI do use one. Handles chunk boundaries that land
// mid-event, mid-line, or mid-UTF8-codepoint.
//
// [PATCH] Retry-mechanism support (paired with the NEW functions/_lib/
// resumableSse.mjs, which assigns the CLIENT-facing chunkIndex — see that
// file's header for why that happens there and not here):
//   1. `opts.withIndex` — yields {data, index} instead of a bare string.
//      `index` counts UPSTREAM PROVIDER frames decoded by THIS generator,
//      0-based, reset every call (i.e. per upstream HTTP request). It is
//      NOT the same number as the chunkIndex the browser eventually sees:
//      a caller that delays, merges, or drops frames before forwarding to
//      the client (streamSanitizer.mjs's holdback-margin does exactly
//      this) must assign the client-facing chunkIndex at the point it
//      actually writes to the client stream, not reuse this index.
//      Existing callers are unaffected — omitting `opts` (or passing
//      `{withIndex:false}`) yields bare strings exactly as before.
//   2. reader.read() failures no longer silently discard whatever partial
//      event was sitting in `buf` — they're re-thrown as SseUpstreamError,
//      carrying `.partial` (best-effort recovered text of that undrained
//      event; '' if nothing was salvageable) and `.cause` (the original
//      error, also wired through the standard ES2022 Error `cause` chain).
//      A caller wrapping this generator in its own upstream-retry loop
//      (streamingProviders.mjs) can then decide whether to keep `.partial`
//      before re-issuing the request to the provider, instead of losing an
//      already-decoded trailing fragment purely because the connection
//      reset one line before the next blank-line boundary.
export async function* iterSseEvents(reader, opts) {
  const withIndex = !!(opts && opts.withIndex);
  const decoder = new TextDecoder('utf-8');
  let buf = '';
  let index = 0;

  for (;;) {
    let value, done;
    try {
      ({ value, done } = await reader.read());
    } catch (cause) {
      throw new SseUpstreamError(cause, recoverPartial(buf));
    }
    if (value) buf += decoder.decode(value, { stream: true });
    if (done) {
      buf += decoder.decode(); // flush any trailing multi-byte sequence
      if (buf.trim()) {
        if (withIndex) {
          for (const item of drain(buf, true)) yield { data: item, index: index++ };
        } else {
          yield* drain(buf, true);
        }
      }
      return;
    }
    // An event ends at a blank line (\n\n or \r\n\r\n). Keep the last,
    // possibly-incomplete event in `buf` for the next read.
    let idx;
    while ((idx = indexOfBlankLine(buf)) !== -1) {
      const block = buf.slice(0, idx.start);
      buf = buf.slice(idx.end);
      if (withIndex) {
        for (const item of drain(block, false)) yield { data: item, index: index++ };
      } else {
        yield* drain(block, false);
      }
    }
  }
}

// Thrown by iterSseEvents when reader.read() itself rejects (upstream
// connection reset, provider edge drop, etc — distinct from a well-formed
// stream that simply ends). `.partial` is the best-effort recovered text
// of whatever event was still sitting in the internal buffer, undrained,
// at the moment of failure.
export class SseUpstreamError extends Error {
  constructor(cause, partial) {
    const msg = 'SSE upstream read failed: ' + (cause && cause.message ? cause.message : String(cause));
    super(msg, { cause });
    this.name = 'SseUpstreamError';
    this.cause = cause; // redundant with the {cause} option above — kept as an
                         // own property for callers that read .cause directly
                         // without relying on the ES2022 Error-cause chain.
    this.partial = partial;
  }
}

function recoverPartial(buf) {
  if (!buf || !buf.trim()) return '';
  const items = [...drain(buf, true)];
  return items.length ? items.join('\n') : '';
}

function indexOfBlankLine(s) {
  const a = s.indexOf('\n\n');
  const b = s.indexOf('\r\n\r\n');
  if (a === -1 && b === -1) return -1;
  if (a === -1) return { start: b, end: b + 4 };
  if (b === -1) return { start: a, end: a + 2 };
  return a < b ? { start: a, end: a + 2 } : { start: b, end: b + 4 };
}

function* drain(block, isFinalFlush) {
  if (!block) return;
  const dataLines = [];
  for (const rawLine of block.split(/\r\n|\n/)) {
    const line = rawLine.trimEnd();
    if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).replace(/^ /, ''));
    }
    // event:, id:, retry: lines are intentionally ignored — none of the
    // four providers this project talks to require them.
  }
  if (dataLines.length) yield dataLines.join('\n');
  else if (isFinalFlush && block.trim().startsWith('data:')) {
    // Defensive: a stream that ends without a trailing blank line.
    yield block.trim().slice(5).replace(/^ /, '');
  }
}
