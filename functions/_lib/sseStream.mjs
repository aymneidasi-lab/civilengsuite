// Generic SSE (Server-Sent Events) frame decoder for upstream provider
// streams. Provider-agnostic: yields the raw string payload of each
// `data: ...` line (multi-line `data:` fields are joined per the SSE spec).
// Does NOT interpret `[DONE]` or JSON — callers do that, since Gemini has
// no [DONE] sentinel (terminates on a non-empty finishReason instead) while
// Groq/OpenRouter/Workers AI do use one. Handles chunk boundaries that land
// mid-event, mid-line, or mid-UTF8-codepoint.
export async function* iterSseEvents(reader) {
  const decoder = new TextDecoder('utf-8');
  let buf = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (value) buf += decoder.decode(value, { stream: true });
    if (done) {
      buf += decoder.decode(); // flush any trailing multi-byte sequence
      if (buf.trim()) yield* drain(buf, true);
      return;
    }
    // An event ends at a blank line (\n\n or \r\n\r\n). Keep the last,
    // possibly-incomplete event in `buf` for the next read.
    let idx;
    while ((idx = indexOfBlankLine(buf)) !== -1) {
      const block = buf.slice(0, idx.start);
      buf = buf.slice(idx.end);
      yield* drain(block, false);
    }
  }
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
