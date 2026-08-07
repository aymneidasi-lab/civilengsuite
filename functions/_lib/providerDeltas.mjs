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
  return { text, finished: finishReason !== '', finishReason };
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
