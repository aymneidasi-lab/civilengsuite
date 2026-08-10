// functions/_lib/imageGen.mjs
// Zero-cost text-to-image generation via Cloudflare Workers AI — the SAME
// env.AI binding chat.js's callWorkersAIWithRetry already uses for the
// Layer-3 text fallback. No new API key, no new secret, no wrangler.toml
// change. Binding calls do not draw from SUBREQUEST_BUDGET_FREE_PLAN —
// that counter is fetch()-only (see streamingProviders.mjs's own comment
// on callWorkersAIStreaming for the identical point re: text) — so
// nothing here takes a `budget` param.
//
// TWO MODELS, TRIED IN ORDER, SAME env.AI BINDING, SAME FREE NEURON POOL:
//   1. '@cf/black-forest-labs/flux-1-schnell' — fast, cheap (4 steps by
//      design), primary.
//   2. '@cf/bytedance/stable-diffusion-xl-lightning' — different model
//      family, used only if #1 throws/times out/returns something
//      unusable. A different model, not a same-model retry: recovers
//      from an outage or deprecation of #1 specifically, which a retry
//      against the same model does nothing for.
//
// A single-model version of this file (and two independent attempts at
// adding this exact fallback before it) assumed both models return
// { image: <base64 string> }. Verified against Cloudflare's own docs and
// two independent official usage examples that this is wrong for #2:
//   - developers.cloudflare.com/workers-ai/models/stable-diffusion-xl-base-1.0
//     and .../stable-diffusion-v1-5-img2img (same Stable Diffusion
//     pipeline family as the Lightning model): "The binding returns a
//     ReadableStream with the output."
//   - Cloudflare's own blog usage example for that family:
//       const response = await env.AI.run("@cf/bytedance/stable-diffusion-xl-lightning", inputs);
//       return new Response(response, { headers: { "content-type": "image/jpg" } });
//     — response is passed directly as a Response body, not read as
//     response.image.
// normalizeImageResult() below handles both shapes so this fallback
// actually works instead of silently returning EMPTY_IMAGE whenever it's
// reached. It also takes `num_steps` (not `steps`) — a second, unrelated
// reason a shared call path across both models needs to be parameterized
// per-model, not copy-pasted.
//
// PROMPT STEERING (added after a live-traffic report: "draw combined
// footing" produced a cartoon foot kicking a ball, not a foundation
// diagram). Both models are general-purpose consumer/art diffusion
// models — neither has meaningful training on engineering-drawing
// datasets — so raw user prompts get mapped to whatever the model's
// broadest, most common association with the words is. That is
// especially bad for this app specifically: "footing" (this app's own
// namesake term) reads as feet/shoes/sports far more often in general
// image-caption data than as a foundation element. buildEngineeringPrompt()
// wraps every prompt in blueprint/line-drawing style framing plus an
// explicit civil-engineering reading of the common ambiguous terms; the
// Stable-Diffusion-family fallback additionally gets a real
// negative_prompt (flux-1-schnell's documented input schema is prompt +
// steps only — no negative_prompt field — so its steering is
// positive-language-only). This raises the odds of an on-topic,
// technical-looking illustration; it does not make either model capable
// of a dimensionally-correct or professionally-accurate engineering
// drawing — both are fast/cheap models traded for speed over precision,
// and neither should be treated as a substitute for actual drafting.
// PROMPT ITERATION 2 (after a second live report): the v1 template above
// asked for "labeled cross-section, dimension lines" — which is exactly
// what produced a diagram with a fake "50mm" width callout, a "6m" label
// on an unrelated segment, and garbled text ("bem", "Slad", "Slap" for
// "beam"/"slab") dressed up in confident technical typography. This is
// not a prompt-wording problem: diffusion models of this class do not
// compose or spell text reliably at all — they paint plausible-looking
// glyph shapes, not characters — and neither model here has any grounding
// in real structural magnitudes to begin with, so any number they render
// is invented regardless of phrasing. A wrong-but-confident-looking
// dimension on a foundation is worse than no dimension, so the fix is to
// stop asking for labels/numbers entirely rather than trying to get them
// right. buildEngineeringPrompt() below asks for a clean unlabeled
// outline; NEGATIVE_PROMPT explicitly excludes text/digits for the model
// that supports it. The frontend also carries a fixed disclaimer under
// every generated image now (see appendBotImageBubble in pc_suite/
// footing_pro) — this reduces the odds of fabricated numbers, it does
// not guarantee a completely text-free result, and a user should never
// treat a generated image as a source of actual dimensions.
//
// PROMPT ITERATION 3 (root-caused from a separate live report: an Arabic
// prompt — e.g. "قاعدة مشتركة" (combined footing) — came back completely
// unrelated to the term, not just stylistically off the way iterations
// 1-2 were). Different root cause from iterations 1-2, and stacking two
// independent gaps, not one:
//   1. The disambiguation clause below ("footing"/"column"/"beam"/... are
//      structural, not feet/furniture/light) is English-only by
//      construction. It does nothing for an Arabic token, because the
//      model never sees a disambiguation for a word it can't match
//      against that list in the first place.
//   2. Both models here are general consumer/art checkpoints (see file
//      header) with text encoders trained on overwhelmingly
//      English-captioned data. A non-English token that isn't also
//      common in English captions is weakly represented in that
//      embedding space — the model doesn't error, it just falls back
//      toward whatever the rest of the prompt weakly conditions it
//      toward, which is why the result reads as "unrelated" rather than
//      "wrong flavor of related."
// ARABIC_ENGINEERING_GLOSSARY below is a fixed, bounded dictionary of
// this app's own domain vocabulary (its own product line — footing /
// beam / column / deflection / earthquake / wall / reinforcement /
// section-property, per REPO_STRUCTURE's public/ product folders) mapped
// to disambiguated English. translateKnownTerms() replaces every matched
// Arabic phrase with its English gloss BEFORE the prompt is built,
// longest-phrase-first, so "قاعدة مشتركة" matches as one unit instead of
// "قاعدة" matching first and stranding "مشتركة" untranslated.
// This is a fixed glossary, not machine translation — it covers this
// app's own known vocabulary, not arbitrary Arabic text. A term outside
// the glossary is left as-is; the English framing/disambiguation still
// applies to whatever English text surrounds it, same as iteration 2.
// This is deliberately NOT upgraded to a translation model call (e.g.
// Workers AI's m2m100) — that is a new model invocation, a new failure
// mode, and new latency/neuron cost stacked onto a path that is
// explicitly budgeted as free; a scope boundary, not an oversight.
// hadUnmappedArabic on translateKnownTerms()'s return is surfaced for
// server-side logging only — chat.js does not currently branch on it.
const ARABIC_ENGINEERING_GLOSSARY = [
  ['قاعدة منفردة', 'isolated column footing (spread footing)'],
  ['قاعدة منفصلة', 'isolated column footing (spread footing)'],
  ['قاعدة مشتركة', 'combined footing (two columns on one footing base)'],
  // 'شريطية' is genuinely ambiguous across the wider field (it's the
  // standard textbook word for "strip/continuous" footing), but this
  // specific product does not use it that way: footing_pro_v52.html's
  // own FAQ copy names one of its three live products "القاعدة
  // الشريطية (Strap)" — Strap spelled out in English, in their own
  // Arabic text, presumably because they know the word is ambiguous too.
  // Matching the site's own usage here, not the textbook-generic one, so
  // this glossary doesn't disagree with the product it's actually
  // sitting on. footingDiagram.mjs's classifyFootingDiagram() reaches
  // the same call on the same evidence — see its own header comment —
  // so this is the second of two places that decision had to be made
  // consistently, not a one-off. Genuine strip/continuous-wall footing
  // is a real, different, physically distinct element (long uniform
  // strip under a wall or row of columns, unlike a strap's two
  // separate footings tied by a beam with no soil bearing under the
  // beam) — kept reachable under a more specific phrase below rather
  // than dropped, since it is still correct engineering vocabulary,
  // just not what this product means by the bare word.
  ['قاعدة شريطية تحت حائط', 'strip footing / continuous wall footing (long uniform footing under a wall)'],
  ['قاعدة شريطية', 'strap footing (a beam tying two separate footings together, no soil bearing under the beam)'],
  ['قاعدة لبشة', 'raft foundation (mat foundation)'],
  ['قاعدة حصيرة', 'raft foundation (mat foundation)'],
  // Shape descriptors for the combined-footing product line specifically
  // — added because "قاعدة مشتركة" alone left "مستطيلة"/"شبه منحرفة"
  // stranded as untranslated residue on the site's own primary product
  // name, "القاعدة المشتركة المستطيلة" ("مشتركة" matched, "المستطيلة"
  // didn't). Scoped to this glossary's own domain, not general Arabic
  // adjectives — "مستطيلة" out of context just means "rectangular", but
  // every use of it in this app's chat is describing a footing.
  ['مستطيلة', 'rectangular (footing shape)'],
  ['شبه منحرفة', 'trapezoidal (tapered footing shape)'],
  ['شبه منحرف', 'trapezoidal (tapered footing shape)'],
  ['قبعة خوازيق', 'pile cap'],
  ['كمرة رابطة', 'tie beam (grade beam)'],
  ['كمرة ربط', 'tie beam (grade beam)'],
  ['رقبة العمود', 'column pedestal (footing neck)'],
  ['حائط استنادي', 'retaining wall'],
  ['حائط قص', 'shear wall'],
  ['غطاء خرساني', 'concrete cover'],
  ['شبكة تسليح', 'reinforcement mesh'],
  ['حديد تسليح', 'reinforcement steel bars (rebar)'],
  ['تسليح خرساني', 'concrete reinforcement (rebar)'],
  ['كانات', 'stirrups'],
  ['خوازيق', 'piles'],
  ['خازوق', 'pile'],
  ['قاعدة', 'foundation footing'],
  ['أساسات', 'foundations'],
  ['أساس', 'foundation'],
  ['أعمدة', 'structural columns'],
  ['عمود', 'structural column'],
  ['كمرات', 'structural beams'],
  ['كمرة', 'structural beam'],
  ['بلاطة', 'concrete slab'],
  ['سقف', 'concrete slab / roof structure'],
  ['خرسانة', 'concrete'],
  ['تسليح', 'reinforcement (rebar)'],
  ['حديد', 'steel reinforcement'],
  ['حائط', 'wall'],
  ['تربة', 'soil'],
  ['هبوط', 'settlement / deflection'],
];

// Sorted once at module load — longest Arabic phrase first, independent
// of the order the table above happens to be written in, so multi-word
// entries are always tried before any single word they contain. Each
// phrase becomes a regex, not a plain substring: every word in it gets
// an optional leading '(?:ال)?' (the Arabic definite article), so
// "القاعدة الشريطية" matches as one full unit — article included — the
// same way "قاعدة شريطية" does. Without this, a SHORTER single-word
// entry could still match inside a longer 'ال'-prefixed word a longer
// phrase hadn't already consumed (e.g. plain "قاعدة" matching inside
// "القاعدة"), stranding the leading 'ال' outside the match and
// corrupting the result: "القاعدة الشريطية" produced "الfoundation
// footing الشريطية" under the old .split()/.join() approach — caught by
// testing this exact definite-article phrasing, not by inspection.
// footingDiagram.mjs's classifyFootingDiagram() hit the identical root
// cause (Arabic nouns are just as often written definite as indefinite,
// and this product's own FAQ copy leans definite — "القاعدة المشتركة
// المستطيلة", "القاعدة الشريطية"); that function fixed it by
// normalizing the input once up front (stripAl()), which is safe there
// because it only needs a yes/no classification. This function returns
// the actual surrounding text, not just a verdict, so blanket-stripping
// 'ال' from every token in arbitrary user text would silently mangle
// words that have nothing to do with this glossary — a per-phrase
// regex match keeps the fix scoped to only the vocabulary this glossary
// actually knows about.
function buildArabicMatcher(phrase) {
  const pattern = phrase.split(/\s+/).map((word) => `(?:ال)?${word}`).join('\\s+');
  return new RegExp(pattern, 'g');
}

const SORTED_GLOSSARY = ARABIC_ENGINEERING_GLOSSARY
  .slice()
  .sort((a, b) => b[0].length - a[0].length)
  .map(([arabic, english]) => [buildArabicMatcher(arabic), english]);

const ARABIC_RANGE_RE = /[\u0600-\u06FF]/;

// Exported for unit testing. Pure string function, no I/O.
export function translateKnownTerms(text) {
  let out = text;
  for (const [matcher, english] of SORTED_GLOSSARY) {
    out = out.replace(matcher, english);
  }
  return { text: out, hadUnmappedArabic: ARABIC_RANGE_RE.test(out) };
}

function buildEngineeringPrompt(userPrompt) {
  const { text: translated, hadUnmappedArabic } = translateKnownTerms(userPrompt);
  const base = `Technical civil/structural engineering line-art diagram, drafting/blueprint style, black-and-white: ${translated}. Interpret every term in a civil engineering and construction context (e.g. "footing", "column", "beam", "pile", "slab" are structural or foundation elements — not feet, furniture, light, or unrelated meanings). Clean geometric outline only, hatching to indicate concrete/material sections, no text, no numbers, no dimension labels, no measurements, no annotations, no watermark — a pure unlabeled line-art schematic on a white background.`;
  // Belt-and-suspenders: if Arabic script survives the glossary pass (a
  // term outside the fixed dictionary), add one more explicit steer
  // rather than silently sending mixed-script text into an
  // English-majority text encoder with zero framing around the
  // untranslated part.
  return hadUnmappedArabic
    ? `${base} The description may still include Arabic engineering terminology alongside the English framing above; read any remaining non-English words as construction/civil-engineering vocabulary, never as unrelated everyday objects.`
    : base;
}
const NEGATIVE_PROMPT = 'cartoon, comic, anime, photo, photorealistic, people, hands, faces, feet, shoes, sports, sketchbook, colored pencils, watercolor, painting, colorful, playful, cute, watermark, signature, text, numbers, digits, dimension labels, measurements, handwritten text, illegible writing, gibberish text, blurry';

const MODEL_ATTEMPTS = [
  { model: '@cf/black-forest-labs/flux-1-schnell',
    buildParams: (p) => ({ prompt: buildEngineeringPrompt(p), steps: 4 }) },                                              // max 8 per docs; 4 is the model's own default
  { model: '@cf/bytedance/stable-diffusion-xl-lightning',
    buildParams: (p) => ({ prompt: buildEngineeringPrompt(p), num_steps: 4, negative_prompt: NEGATIVE_PROMPT }) },        // max 20 per docs; 4 is the commonly-recommended value for this "few-step" model, not its own default of 20
];

const MAX_PROMPT_CHARS = 500; // UX bound for a chat text field, not a cost lever — diffusion cost scales with steps/resolution, not prompt length
const RETRY_DELAY_MS = 1200;  // matches callWorkersAIWithRetry's own retry delay, applied between model attempts

// Returns { ok: true, prompt } or { ok: false, code, maxChars? }. Codes
// only, no user-facing text — chat.js already owns the likelyArabic /
// English message choice for every other validation error on this
// endpoint (see its rate-limit and devCommand branches); duplicating that
// decision in here would just be a second place for the two languages to
// drift out of sync.
export function validateImagePrompt(raw) {
  const prompt = typeof raw === 'string' ? raw.trim() : '';
  if (!prompt) {
    return { ok: false, code: 'PROMPT_REQUIRED' };
  }
  if (prompt.length > MAX_PROMPT_CHARS) {
    return { ok: false, code: 'PROMPT_TOO_LONG', maxChars: MAX_PROMPT_CHARS };
  }
  return { ok: true, prompt };
}

// String.fromCharCode.apply(null, hugeArray) can overflow the call stack
// for a full-size image (a few hundred KB of bytes) — chunking keeps
// every call well under any engine's argument-count limit. btoa/
// ReadableStream/Response are Workers-runtime globals; no import needed.
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const CHUNK = 8192;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

// Normalizes either of Workers AI's known text-to-image output shapes —
// { image: <base64> } (flux-1-schnell) or a ReadableStream / ArrayBuffer /
// TypedArray of raw bytes (the Stable-Diffusion-family models, including
// stable-diffusion-xl-lightning — see the header comment) — to a plain
// base64 string. Returns null, not a throw, if the shape is unrecognized:
// an unrecognized response is a "try the next model" condition for the
// caller, not a hard failure.
async function normalizeImageResult(result) {
  if (result && typeof result.image === 'string' && result.image) {
    return result.image;
  }
  let buffer = null;
  if (result instanceof ReadableStream) {
    buffer = await new Response(result).arrayBuffer();
  } else if (result instanceof ArrayBuffer) {
    buffer = result;
  } else if (ArrayBuffer.isView(result)) {
    buffer = result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength);
  }
  if (!buffer || buffer.byteLength === 0) return null;
  return arrayBufferToBase64(buffer);
}

// One attempt against one model, bounded by a non-cancelling timeout —
// env.AI.run() has no documented AbortSignal parameter (verified Aug
// 2026), so this only bounds how long THIS function waits, not the
// call's own server-side lifetime (see chat.js's Resource Lifecycle notes
// at the call site). Both handlers are attached directly to
// aiBinding.run()'s own promise — not a bare Promise.race against a timer
// with the run() promise left bare — so a late settlement after the
// timeout has already won never has zero listeners; nothing here can
// produce an unhandled-rejection warning.
function runOnce(aiBinding, model, params, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('WORKERS_AI_IMAGE_TIMEOUT')), timeoutMs);
    aiBinding.run(model, params).then(
      (res) => { clearTimeout(timer); resolve(res); },
      (err) => { clearTimeout(timer); reject(err); },
    );
  });
}

// Tries each entry in MODEL_ATTEMPTS in order, moving to the next on
// either a thrown error (timeout, transient Workers AI failure) or a
// successful call whose output normalizeImageResult() can't parse.
// Returns { ok: true, base64, mime, model } — model is whichever one
// actually produced the image, for the response's `source` field and
// server-side logs — or { ok: false, httpStatus: 0, errStatus, errBody }
// once every entry has failed.
export async function generateImageWorkersAI(aiBinding, prompt, opts = {}) {
  if (!aiBinding) {
    return { ok: false, httpStatus: 0, errStatus: 'NOT_BOUND', errBody: 'env.AI is not bound on this Pages project.' };
  }
  const timeoutMs = opts.timeoutMs ?? 20000; // diffusion is slower than chat.js's PROVIDER_TIMEOUT_MS (8000ms, sized for an LLM text reply)

  let lastErr = '';
  for (let i = 0; i < MODEL_ATTEMPTS.length; i++) {
    const { model, buildParams } = MODEL_ATTEMPTS[i];
    if (i > 0) await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
    try {
      const raw = await runOnce(aiBinding, model, buildParams(prompt), timeoutMs);
      const base64 = await normalizeImageResult(raw);
      if (base64) {
        return { ok: true, base64, mime: 'image/jpeg', model };
      }
      lastErr = `${model}: response had no recognizable image payload`;
      console.warn(`[imageGen.mjs] ${lastErr}`);
    } catch (err) {
      lastErr = `${model}: ${err.message}`;
      console.warn(`[imageGen.mjs] attempt failed — ${lastErr}`);
    }
  }
  console.error('[imageGen.mjs] all models failed:', lastErr);
  return { ok: false, httpStatus: 0, errStatus: 'WORKERS_AI_IMAGE_ERROR', errBody: lastErr };
}
