// Run: node documentGuard.test.mjs
// Pure-Node test — no Miniflare/wrangler, no network. Exercises the exact
// functions vision.js will call, against hand-built synthetic PDF byte
// streams (not real PDFs — minimal structures with just enough shape to
// exercise the magic-byte sniff and the page-count regex).

import {
  PDF_MIME_TYPE,
  MAX_PDF_BASE64_CHARS,
  PDF_PAGE_SOFT_CAP,
  validatePdfDocument,
  sniffPdfMagicBytes,
  estimatePdfPageCount,
} from './documentGuard.mjs';

let pass = 0, fail = 0;
function check(label, cond) {
  if (cond) { pass++; console.log('  ok  -', label); }
  else { fail++; console.log('  FAIL -', label); }
}

// ── Fixture builders ────────────────────────────────────────────────────
function buildSyntheticPdf(pageCount) {
  let body = '%PDF-1.4\n';
  body += '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n';
  body += '2 0 obj\n<< /Type /Pages /Kids [';
  for (let i = 0; i < pageCount; i++) body += `${3 + i} 0 R `;
  body += `] /Count ${pageCount} >>\nendobj\n`;
  for (let i = 0; i < pageCount; i++) {
    body += `${3 + i} 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n`;
  }
  body += '%%EOF';
  return body;
}
function toBase64(str) { return btoa(str); }

const pdf3pages = toBase64(buildSyntheticPdf(3));
const pdf60pages = toBase64(buildSyntheticPdf(60));
const notAPdf = toBase64('this is just a plain text file, not a pdf at all');
const pngMagicBytes = toBase64('\x89PNG\r\n\x1a\n' + 'x'.repeat(200)); // real PNG header, wrong type

console.log('documentGuard.mjs — test run\n');

// ── sniffPdfMagicBytes ──────────────────────────────────────────────────
console.log('sniffPdfMagicBytes():');
check('accepts real %PDF- header', sniffPdfMagicBytes(pdf3pages) === true);
check('rejects plain text disguised as pdf', sniffPdfMagicBytes(notAPdf) === false);
check('rejects PNG magic bytes', sniffPdfMagicBytes(pngMagicBytes) === false);
check('rejects empty string without throwing', sniffPdfMagicBytes('') === false);
check('rejects garbage non-base64 without throwing', sniffPdfMagicBytes('!!!not-base64!!!') === false);

// ── estimatePdfPageCount ────────────────────────────────────────────────
console.log('\nestimatePdfPageCount():');
check('counts 3 pages correctly', estimatePdfPageCount(pdf3pages) === 3);
check('counts 60 pages correctly', estimatePdfPageCount(pdf60pages) === 60);
check('does NOT double-count /Type /Pages as a page', (() => {
  // buildSyntheticPdf emits exactly one "/Type /Pages" (the tree node) plus
  // N "/Type /Page" (the leaves) — if the regex wrongly matched /Pages too,
  // pdf3pages would count as 4, not 3. Already covered by the count===3
  // check above; this asserts the mechanism directly against a
  // pages-only fragment with zero real page objects.
  const onlyTreeNode = toBase64('%PDF-1.4\n<< /Type /Pages /Count 0 >>');
  return estimatePdfPageCount(onlyTreeNode) === null; // no /Type /Page matches at all
})());
check('returns null (unknown) for non-pdf content, not a false count', estimatePdfPageCount(notAPdf) === null);

// ── validatePdfDocument — happy path ────────────────────────────────────
console.log('\nvalidatePdfDocument() — happy path:');
{
  const res = validatePdfDocument({ data: pdf3pages, mimeType: PDF_MIME_TYPE, name: 'footing-plan.pdf' }, false);
  check('accepts a valid small PDF', res.ok === true);
  check('reports estimatedPages === 3', res.estimatedPages === 3);
  check('preserves the filename', res.name === 'footing-plan.pdf');
}
{
  // data: URL prefix, as FileReader.readAsDataURL() produces client-side
  const res = validatePdfDocument({ data: 'data:application/pdf;base64,' + pdf3pages, mimeType: 'application/pdf', name: 'x.pdf' }, false);
  check('strips a data: URL prefix correctly', res.ok === true && res.data === pdf3pages);
}
{
  // mimeType arriving as `mime` (alias) instead of `mimeType`
  const res = validatePdfDocument({ data: pdf3pages, mime: PDF_MIME_TYPE, name: 'x.pdf' }, false);
  check('accepts the `mime` field alias', res.ok === true);
}

// ── validatePdfDocument — rejection paths ───────────────────────────────
console.log('\nvalidatePdfDocument() — rejection paths:');
check('rejects wrong mimeType', validatePdfDocument({ data: pdf3pages, mimeType: 'image/png', name: 'x.pdf' }, false).ok === false);
check('rejects missing data', validatePdfDocument({ data: '', mimeType: PDF_MIME_TYPE, name: 'x.pdf' }, false).ok === false);
check('rejects non-base64 data', validatePdfDocument({ data: '!!!not base64###', mimeType: PDF_MIME_TYPE, name: 'x.pdf' }, false).ok === false);
check('rejects content failing the magic-byte sniff', validatePdfDocument({ data: notAPdf, mimeType: PDF_MIME_TYPE, name: 'x.pdf' }, false).ok === false);
check('rejects a PDF over the page soft-cap', validatePdfDocument({ data: pdf60pages, mimeType: PDF_MIME_TYPE, name: 'x.pdf' }, false).ok === false);
{
  const tooBig = 'A'.repeat(MAX_PDF_BASE64_CHARS + 1);
  check('rejects data over MAX_PDF_BASE64_CHARS', validatePdfDocument({ data: tooBig, mimeType: PDF_MIME_TYPE, name: 'x.pdf' }, false).ok === false);
}
check('Arabic error string returned when likelyArabicMsg=true', /[\u0600-\u06FF]/.test(
  validatePdfDocument({ data: pdf3pages, mimeType: 'image/png', name: 'x.pdf' }, true).error
));

// ── PDF_PAGE_SOFT_CAP boundary ──────────────────────────────────────────
console.log('\nboundary check:');
{
  const exactlyAtCap = toBase64(buildSyntheticPdf(PDF_PAGE_SOFT_CAP));
  const oneOverCap = toBase64(buildSyntheticPdf(PDF_PAGE_SOFT_CAP + 1));
  check(`accepts exactly ${PDF_PAGE_SOFT_CAP} pages (at cap)`, validatePdfDocument({ data: exactlyAtCap, mimeType: PDF_MIME_TYPE, name: 'x.pdf' }, false).ok === true);
  check(`rejects ${PDF_PAGE_SOFT_CAP + 1} pages (one over cap)`, validatePdfDocument({ data: oneOverCap, mimeType: PDF_MIME_TYPE, name: 'x.pdf' }, false).ok === false);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
