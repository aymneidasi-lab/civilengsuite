// Pure, side-effect-free extraction of a text delta + completion signal from
// one already-SSE-decoded `data: ...` payload string (as yielded by
// iterSseEvents). Kept separate from the network/retry code so the parsing
// logic can be unit-tested against literal provider payloads without any
// fetch mocking.

// Gemini :streamGenerateContent?alt=sse -- no [DONE] sentinel; a chunk is
// final when finishReason is non-empty. The last chunk can carry no text
// part at all (e.g. a bare thoughtSignature) -- must not throw on that.
export function extractGeminiDelta(dataStr) {
  let obj;
  try { obj = JSON.parse(dataStr); } catch { return { text: '', finished: false, parseError: true }; }
  const candidate = obj?.candidates?.[0];
  const parts = candidate?.content?.parts || [];
  const text = parts
    .filter((p) => !p?.thought && typeof p?.text === 'string')
    .map((p) => p.text)
    .join('');
  const finishReason = candidate?.finishReason || '';
  // [PATCH — search bridge] groundingMetadata is only present on grounded
  // responses (google_search tool declared AND the model actually chose to
  // search this turn) and, empirically for every other per-chunk field this
  // function already reads (finishReason included), is not guaranteed to be
  // filled in until the terminal chunk. Surfaced as `null` rather than
  // omitted so callers can `d.groundingMetadata ?? previous` without an
  // `in`/`hasOwnProperty` check. Groq/OpenRouter/Workers AI extractors below
  // never set this key — runStream()'s handling of it is a plain truthy
  // check, so it's a no-op for those three providers, not a special case.
  const groundingMetadata = candidate?.groundingMetadata || null;
  return { text, finished: finishReason !== '', finishReason, groundingMetadata };
}

// Groq + OpenRouter (OpenAI-compatible chat.completions, stream:true).
// Terminates on the literal string "[DONE]" (not JSON).
export function extractOpenAiCompatDelta(dataStr) {
  if (dataStr.trim() === '[DONE]') return { text: '', finished: true, done: true };
  let obj;
  try { obj = JSON.parse(dataStr); } catch { return { text: '', finished: false, parseError: true }; }
  const choice = obj?.choices?.[0];
  const text = typeof choice?.delta?.content === 'string' ? choice.delta.content : '';
  const finished = !!choice?.finish_reason;
  return { text, finished, finishReason: choice?.finish_reason || null };
}

// Cloudflare Workers AI (env.AI.run(model, {stream:true})). Wire format is
// `data: {"response":"...", "p":"..."}` per Cloudflare's own streaming
// examples, terminated by a literal "[DONE]" event (also OpenAI-style).
export function extractWorkersAiDelta(dataStr) {
  if (dataStr.trim() === '[DONE]') return { text: '', finished: true, done: true };
  let obj;
  try { obj = JSON.parse(dataStr); } catch { return { text: '', finished: false, parseError: true }; }
  const text = typeof obj?.response === 'string' ? obj.response : '';
  return { text, finished: false };
}
