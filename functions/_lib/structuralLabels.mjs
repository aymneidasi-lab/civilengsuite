// functions/_lib/structuralLabels.mjs
//
// Central EN/AR label dictionary for the deterministic (computed)
// structural-diagram path — Plan Step 4. Fixes the concrete gap Step 0
// found in footingDiagram.mjs: renderPlanView/renderSectionView drew
// "PLAN"/"SECTION A-A" and raw internal tags ("col1"/"col2") regardless
// of `lang`, while renderFootingDiagramSVG's own sheet title/caption
// were already correctly localized — a "per file" language switch, not
// "per cell" (every text-producing element must carry its own lang
// decision; see this app's plan document, rule 5, for why that
// distinction matters here specifically).
//
// Scope: this file backs footingDiagram.mjs only, per Step 4's own text
// ("استبدل كل النصوص المباشرة في footingDiagram.mjs"). beamDiagram.mjs
// already has its own working `L = {en:{...}, ar:{...}}` dictionary
// (see that file's own header) built the same shape as this one and as
// footingDiagram.mjs's own GENERIC_L — migrating beamDiagram.mjs onto
// this shared file is real future work (Step 18's "توسع مستقبلي" note
// applies) but is out of THIS step's scope and untested here; do not
// assume it has been done.
//
// Column-tag values (columnA/columnB) are copied verbatim from
// footingDiagram.mjs's own GENERIC_L.colA/colB so a reader sees the
// identical term whether a drawing came from the generic (/image,
// no-numbers) path or the computed (/diagram) path — a deliberate
// consistency choice, not a coincidence.
//
// PARENTHESES AND EM-DASH WARNING: any Arabic value in this file that
// may render inside an element using scriptFontStack (view-title,
// col-tag, cut-label, sheet-title, sheet-caption — anything localized)
// must not contain "(", ")", or an em/en-dash. footingDiagram.mjs's own
// renderFootingDiagramSVG header already documents why: Noto Naskh
// Arabic (the font scriptFontStack actually selects for lang==='ar')
// has no glyph for either, confirmed there by isolated-glyph probing
// against cairosvg. sectionAAWithColumn() below composes the Arabic
// "through column" phrase with a plain space instead of the English
// version's parenthetical for exactly this reason — this is not a
// stylistic choice, it is a tofu-avoidance requirement. Run
// assertNoUnsafeArabicPunctuation() (bottom of this file) against any
// new Arabic value added here before shipping it.

// Step 17 addendum — the two file-header points not already covered above:
// Safety limits (MAX_*): this file defines none. It is a pure lookup
// dictionary + string-composition helpers; the only quantity that scales
// with input (MAX_COLUMNS, referenced in columnTag()'s comment below) is
// enforced in footingDiagram.mjs, which owns that schema field.
// Drawn extent vs. actual cut length: not applicable here — this file has
// no geometry, only label text. See structuralDrawingKit.mjs's header for
// the canonical explanation of that distinction where it does apply.
// Fully deterministic: no env.AI, no network call, no randomness — every
// export here is a pure function of STRUCTURAL_LABELS and its arguments.

export const STRUCTURAL_LABELS = {
  en: {
    footIsolated: 'Isolated Footing',
    footCombined: 'Combined Footing',
    footStrip: 'Strip Footing',
    footRaft: 'Raft Foundation',
    plan: 'PLAN',
    sectionAA: 'SECTION A-A',
    through: 'through',
    column: 'COLUMN',
    columnA: 'COLUMN A',
    columnB: 'COLUMN B',
    cutLetter: 'A',
    // [Step 14.2] pedestal/dowels/mesh — see footingDiagram.mjs's
    // computeFootingExtras() for the compute side these back. Column
    // headers (dowelCount/dowelDia/dowelProjection/meshDia/meshSpacing)
    // are named per-field, not generically ("Count"/"Dia"), because the
    // Step 14.3 workshop table is ONE summary row with each optional
    // group contributing its own dedicated columns (blank cell when
    // that group is absent) — not a multi-row schedule like beamDiagram.
    // mjs's bar list. Decided here so 14.3 doesn't have to re-litigate
    // table shape mid-session.
    pedestal: 'Pedestal',
    dowel: 'Dowel',
    mesh: 'Mesh',
    concreteVolume: 'Concrete Volume',
    dowelCount: 'Dowel Count',
    dowelDia: 'Dowel Dia',
    dowelProjection: 'Dowel Projection',
    meshDia: 'Mesh Dia',
    meshSpacing: 'Mesh Spacing',
    // [Step 14.2] Reworded from the original ("no dowels... simplified")
    // for the same reason the Arabic value below was — that text became
    // inaccurate once pedestal/dowels/mesh became real optional inputs.
    // New wording is accurate whether or not the caller supplies them.
    captionComputed: 'Schematic computed from the entered values — verify against your own design. Reinforcement is simplified: one representative bottom-mesh layer; pedestal and dowels are drawn only when explicitly specified in the input — this is not a construction/shop drawing (no stirrups, no development-length detailing).',
  },
  ar: {
    footIsolated: 'قاعدة منفردة',
    footCombined: 'قاعدة مشتركة',
    footStrip: 'قاعدة شريطية',
    footRaft: 'قاعدة لبشة',
    plan: 'مسقط أفقي',
    sectionAA: 'قطاع أ-أ',
    through: 'عند',
    column: 'عمود',
    columnA: 'عمود أ',
    columnB: 'عمود ب',
    cutLetter: 'أ',
    // [Step 14.2] "أسياخ الانتظار" هو المصطلح الهندسي العربي المتعارف
    // عليه لـdowels (أسياخ ربط العمود بالقاعدة) في هذا السياق (ECP 203) —
    // وليس ترجمة حرفية مُختلَقة. "برمة" مأخوذ حرفياً من نفس المصطلح
    // المستخدم في خطة_تجزئة_الخطوة_14.md نفسها للاتساق.
    pedestal: 'برمة',
    dowel: 'أسياخ الانتظار',
    mesh: 'شبكة التسليح',
    concreteVolume: 'حجم الخرسانة',
    dowelCount: 'عدد الأسياخ',
    dowelDia: 'قطر الأسياخ',
    dowelProjection: 'امتداد الأسياخ',
    meshDia: 'قطر الشبكة',
    meshSpacing: 'تباعد الشبكة',
    // [Step 14.2] أُعيدت صياغتها عن النص الأصلي ("لا dowels... التسليح
    // مبسّط") لأن ذلك النص أصبح غير دقيق بعد إضافة برمة/dowels/mesh
    // الاختيارية: الصياغة الجديدة صحيحة في الحالتين معاً — سواء زُوِّدت
    // هذه الحقول أو لم تُزوَّد — بدل نص شرطي يتغير حسب المدخلات. بلا
    // أقواس ولا شرطة طويلة/متوسطة (راجع تحذير أعلى الملف).
    captionComputed: 'رسم تخطيطي محسوب من القيم المُدخلة، للتحقق فقط. التسليح مبسّط: شبكة سفلية تمثيلية واحدة؛ البرمة وأسياخ الانتظار تُرسم فقط عند تحديدها صراحة في المدخلات؛ بلا كانات ولا تفاصيل أطوال ربط. هذا ليس رسم تنفيذي.',
  },
};

const FOOTING_TYPE_TO_KEY = {
  isolated: 'footIsolated', combined: 'footCombined', strip: 'footStrip', raft: 'footRaft',
};

// translate(key, lang) -> string, per Plan Step 4's own required
// signature. Falls back to English, then to the raw key itself, rather
// than throwing — a missing key on a schematic-generator's hot path
// should degrade to visible-but-ugly, never 500 the request.
export function translate(key, lang) {
  const L = STRUCTURAL_LABELS[lang] || STRUCTURAL_LABELS.en;
  return L[key] ?? STRUCTURAL_LABELS.en[key] ?? key;
}

// Sheet title for a given footing type ('isolated'|'combined'|'strip'|
// 'raft') — replaces footingDiagram.mjs's own module-scope TITLES table.
export function footingTitle(type, lang) {
  return translate(FOOTING_TYPE_TO_KEY[type] || 'footIsolated', lang);
}

// Column tag for the Nth column (0-based index) of a given footing
// type. 'combined' has exactly 2 columns by construction and uses the
// lettered COLUMN A / COLUMN B convention (matching GENERIC_L).
// 'strip'/'raft' have 2..MAX_COLUMNS (12) and use COLUMN <n> — a fixed
// two-letter scheme does not scale to 12 the way a number does. Digits
// are never translated (Latin-by-convention throughout this app, same
// rule as B=/L=/D=/mm/Ø — see footingDiagram.mjs's own header).
export function columnTag(type, index, lang) {
  if (type === 'combined') {
    return index === 0 ? translate('columnA', lang) : translate('columnB', lang);
  }
  return `${translate('column', lang)} ${index + 1}`;
}

// "SECTION A-A" alone, or "SECTION A-A (through COLUMN A)" for the
// numbered-column types. Arabic composes with a plain space rather than
// the English parenthetical — see the PARENTHESES AND EM-DASH WARNING
// above; this is a correctness requirement, not a style preference.
export function sectionTitle(type, columnIndexOrNull, lang) {
  const base = translate('sectionAA', lang);
  if (columnIndexOrNull == null) return base;
  const tag = columnTag(type, columnIndexOrNull, lang);
  return lang === 'ar' ? `${base} ${translate('through', lang)} ${tag}` : `${base} (${translate('through', lang)} ${tag})`;
}

// Dev-time guard, not called on the request path: throws if any Arabic
// dictionary value contains a glyph Noto Naskh Arabic doesn't carry
// (see the file-header warning). Call this from a test, not from
// render code — it is O(dictionary size), trivial, but has no reason
// to run on every request.
export function assertNoUnsafeArabicPunctuation() {
  const unsafe = /[()\u2013\u2014]/; // ( ) – —
  const offenders = [];
  for (const [key, val] of Object.entries(STRUCTURAL_LABELS.ar)) {
    if (unsafe.test(val)) offenders.push(`${key}: "${val}"`);
  }
  if (offenders.length) {
    throw new Error(`Unsafe punctuation for Noto Naskh Arabic in STRUCTURAL_LABELS.ar: ${offenders.join('; ')}`);
  }
  return true;
}
