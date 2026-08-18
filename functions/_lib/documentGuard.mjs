// functions/_lib/documentGuard.mjs
// ─────────────────────────────────────────────────────────────────────────
// PDF ingestion guard for vision.js's "Insert Text / PDF" document path.
// Pure functions, no Workers-specific APIs beyond atob() (a Web-standard
// global present in both Cloudflare Workers and browsers, and in Node 18+)
// — testable standalone, no Miniflare/wrangler needed.
//
// SCOPE: validates a client-supplied {data, mimeType, name} PDF payload
// before it is embedded as a Gemini inline_data part. This file does NOT
// parse, render, or OCR the PDF. Gemini's own document-understanding path
// (each page treated as an image for vision, plus free native-text
// extraction — ai.google.dev/gemini-api/docs/document-processing, current
// as of 2026-06) does that server-side, at Google's expense, not this
// Worker's 10ms-CPU budget. This file only bounds size/page count and
// sniffs the magic bytes so a mislabeled or malicious upload can't reach
// the model as something it claims to be but isn't.
// ─────────────────────────────────────────────────────────────────────────

export const PDF_MIME_TYPE = 'application/pdf';

// Ceiling on the base64 STRING length the client sends (not raw bytes).
// Gemini's inline-payload ceiling is ~20MB on the raw decoded file
// (ai.google.dev/gemini-api/docs/document-processing — "request payload
// size exceeds the limit" above that). Base64 inflates raw bytes by ~4/3,
// so an 18,000,000-char base64 string decodes to ~13.5MB raw — comfortably
// under Gemini's 20MB raw ceiling with headroom for JSON framing, the
// system prompt, and the user's own message text sharing the same request.
export const MAX_PDF_BASE64_CHARS = 18_000_000;

// Soft cap, not a hard rejection boundary — see estimatePdfPageCount()'s
// own docstring for why an exact count is not guaranteed. Sized against the
// same ~258-token-per-page vision cost vision.js's MAX_IMAGES_PER_REQUEST is
// sized against: 40 pages ~= 10,320 tokens.
export const PDF_PAGE_SOFT_CAP = 40;

// Same base64-alphabet check vision.js's validateOneImage() already applies
// to image data — reused for consistency, not re-derived.
const BASE64_RE = /^[A-Za-z0-9+/]+=*$/;

// Strips a data: URL prefix if present (FileReader.readAsDataURL()'s
// output), mirroring validateOneImage()'s own handling in vision.js.
function stripDataUrlPrefix(raw) {
  let data = typeof raw === 'string' ? raw.trim() : '';
  if (data.startsWith('data:') && data.includes(',')) data = data.split(',')[1];
  return data;
}

// Decodes only the first 12 base64 chars (-> 9 raw bytes) to sniff the PDF
// magic number ("%PDF-", 5 bytes) — avoids paying the CPU cost of decoding
// an entire multi-megabyte file for a check that only ever needs the head.
function sniffPdfMagicBytes(base64Data) {
  const head = base64Data.slice(0, 12);
  let raw;
  try {
    raw = atob(head);
  } catch {
    return false;
  }
  return raw.startsWith('%PDF-');
}

// Heuristic page-count estimate via a byte-level regex scan of the decoded
// PDF — NOT a real PDF parse (no xref/object-stream resolution). Matches
// "/Type" followed by "/Page" but not "/Pages" (the tree-node object, which
// would double-count every page under it).
//
// KNOWN LIMITATION: PDFs using compressed cross-reference streams or object
// streams (common in PDF 1.5+ output — many scanner and "print to PDF"
// tools produce these) store page objects inside a compressed stream this
// regex cannot see into. In that case this returns null ("unknown") rather
// than a wrong number, and the caller treats null as "allow through, rely
// on the byte-size cap instead." This function is a soft signal, never the
// security boundary — MAX_PDF_BASE64_CHARS is exact and is that boundary.
function estimatePdfPageCount(base64Data) {
  let raw;
  try {
    raw = atob(base64Data);
  } catch {
    return null;
  }
  const matches = raw.match(/\/Type\s*\/Page(?!s)/g);
  if (!matches || matches.length === 0) return null;
  return matches.length;
}

// Full validation entry point.
// Returns either:
//   { ok: true,  mimeType, data, name, estimatedPages }
//   { ok: false, error }   — error is a bilingual string ready to drop
//                            straight into a 400 json({error}) response,
//                            matching vision.js's existing error style.
export function validatePdfDocument(entry, likelyArabicMsg) {
  const rawMime = (typeof entry?.mimeType === 'string' && entry.mimeType) ||
                  (typeof entry?.mime === 'string' && entry.mime) || '';
  const mimeType = rawMime.trim().toLowerCase();
  const name = typeof entry?.name === 'string' && entry.name.trim()
    ? entry.name.trim().slice(0, 200)
    : 'document.pdf';

  if (mimeType !== PDF_MIME_TYPE) {
    return {
      ok: false,
      error: likelyArabicMsg
        ? 'نوع المستند غير مدعوم. المسموح به حالياً ملفات PDF فقط.'
        : 'Unsupported document type. Only PDF is currently supported.',
    };
  }

  const data = stripDataUrlPrefix(entry?.data);
  if (!data) {
    return {
      ok: false,
      error: likelyArabicMsg ? `بيانات المستند "${name}" فارغة.` : `Document "${name}" has no data.`,
    };
  }
  if (data.length < 100 || !BASE64_RE.test(data)) {
    return {
      ok: false,
      error: likelyArabicMsg
        ? `بيانات المستند "${name}" ليست Base64 صالحة.`
        : `Document "${name}" data is not valid base64.`,
    };
  }
  if (data.length > MAX_PDF_BASE64_CHARS) {
    const approxMb = Math.floor((MAX_PDF_BASE64_CHARS * 0.75) / 1_000_000);
    return {
      ok: false,
      error: likelyArabicMsg
        ? `ملف "${name}" كبير جداً. الحد الأقصى تقريباً ${approxMb} ميجابايت.`
        : `"${name}" is too large. Maximum is roughly ${approxMb}MB.`,
    };
  }
  if (!sniffPdfMagicBytes(data)) {
    return {
      ok: false,
      error: likelyArabicMsg
        ? `"${name}" لا يبدو ملف PDF صالح (فشل التحقق من توقيع الملف).`
        : `"${name}" doesn't look like a valid PDF (magic-byte check failed).`,
    };
  }

  const estimatedPages = estimatePdfPageCount(data);
  if (estimatedPages !== null && estimatedPages > PDF_PAGE_SOFT_CAP) {
    return {
      ok: false,
      error: likelyArabicMsg
        ? `"${name}" فيه صفحات كتير أوي (~${estimatedPages} صفحة). الحد الأقصى تقريباً ${PDF_PAGE_SOFT_CAP} صفحة في الرسالة الواحدة.`
        : `"${name}" has too many pages (~${estimatedPages}). Maximum is roughly ${PDF_PAGE_SOFT_CAP} pages per message.`,
    };
  }

  return { ok: true, mimeType: PDF_MIME_TYPE, data, name, estimatedPages };
}

// Exported for the standalone test file and for anyone auditing the
// heuristic directly — not consumed elsewhere in vision.js.
export { sniffPdfMagicBytes, estimatePdfPageCount };
