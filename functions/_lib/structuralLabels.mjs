// shared/structuralLabels.mjs
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
// against cairosvg. sectionTitle() below composes the Arabic "through
// column" phrase with a plain space instead of the English version's
// parenthetical for exactly this reason — this is not a stylistic
// choice, it is a tofu-avoidance requirement. Run
// assertNoUnsafeArabicPunctuation() (bottom of this file) against any
// new Arabic value added here before shipping it.
//
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
//
// [Integration merge — this pass] This file previously existed as two
// byte-divergent copies, one shipped alongside each of two footingDiagram
// lineages that forked from a common Step-17 ancestor and were never
// reconciled:
//   (a) footing/footingDiagram.mjs (ties/band/multi-layer/dual-section
//       cut views — Steps 20-21), and
//   (b) footing/footingDiagram.extended.mjs (blinding concrete,
//       dowel-lap-length dimension, column main-bar callout, level
//       markers — "this session", forked before Step 20 existed).
// Both copies were byte-identical for every key through meshSpacing and
// for all five exported functions below; they diverged only in which
// keys each fork appended afterward. This merge takes the union of both
// key sets. tieDia/tieSpacing/tieCount are declared once below (both
// forks used the identical EN and AR strings for these three — verified
// by direct diff before merging, not assumed). No key's value was
// changed from either source file; nothing was removed.
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
    // [Step 20] ties/band — see footing/footingDiagram.mjs's
    // computeFootingExtras() for the compute side. Same per-field
    // table-column naming already established for dowel*/mesh* above
    // (tieDia/tieSpacing/tieCount, bandWidth/bandDia/bandSpacing), not
    // generic "Dia"/"Spacing", for the identical reason: one summary
    // row, one dedicated column per optional group. tieDia/tieSpacing/
    // tieCount are also read by footing/footingDiagram.extended.mjs's
    // own ties block (added independently under "this session" below) —
    // same three keys, same values in both forks, declared once here.
    ties: 'Ties',
    tieDia: 'Tie Dia',
    tieSpacing: 'Tie Spacing',
    tieCount: 'Tie Count',
    band: 'Band',
    bandWidth: 'Band Width',
    bandDia: 'Band Bar Dia',
    bandSpacing: 'Band Bar Spacing',
    // Plan-view layer callouts — wording matches the Egyptian code
    // detailing guide's own four-layer breakdown (top/bottom x
    // longitudinal/transverse) rather than a generic "top"/"bottom", so
    // a reader cross-checking against that guide sees matching terms.
    topLongitudinal: 'Top Longitudinal',
    bottomLongitudinal: 'Bottom Longitudinal',
    topTransverse: 'Top Transverse',
    bottomTransverse: 'Bottom Transverse',
    // [Step 20] Appended to captionComputed ONLY when the drawing
    // actually has a second (top) layer and/or a band — see
    // renderFootingDiagramSVG's own hasExtras branch. Kept as a SEPARATE
    // key, never concatenated into captionComputed itself, so the
    // no-extras caption stays byte-identical to its pre-Step-20 value
    // (same backward-compatibility reasoning Step 14.2's own reworded
    // captionComputed comment already documents).
    captionExtrasLegend: 'When shown: dashed blue marks a top layer, solid red a bottom layer, and a heavier red line a concentrated band.',
    // [Step 20, revised] Reports the same gross/net pair the guide draws
    // as two stacked dimension lines (طول/عرض القاعدة العادية vs
    // المسلحة), but as text in the caption — see renderPlanView's own
    // comment on why the drawn version was tried and rejected after
    // actually rendering it.
    reinforcedExtentNote: 'Net-of-cover reinforced extent',
    // [Step 21] combined/strip now show TWO sections: a primary
    // longitudinal cut (through the column line, matching the Egyptian
    // code guide's own قطاع رأس ١-١ — both columns and the span between
    // them) and the pre-Step-21 single-column transverse cut, kept as a
    // secondary "side" view per direct request. isolated/raft are
    // unaffected (see renderFootingDiagramSVG's own type check) and keep
    // using sectionTitle/translatedSectionTitle exactly as before.
    longitudinalSectionTitle: 'LONGITUDINAL SECTION',
    transverseSectionTitle: 'TRANSVERSE SECTION',
    // [Bugfix, this session] Added independently in the
    // footingDiagram.extended.mjs fork for its blinding/dowel-leg/tie
    // rendering code (levelMarker x2, the dowel lap-length dimension,
    // the blinding thickness/projection dimensions). tieCount/tieDia/
    // tieSpacing themselves are declared once above (kit block) — same
    // values in both forks, confirmed by diff.
    topFootingLevel: 'Top of Footing Level',
    foundingLevel: 'Founding Level',
    blindingThickness: 'Blinding Thickness',
    blindingProjection: 'Blinding Projection',
    dowelLapLength: 'Dowel Lap Length',
    // [This session] columnBars — the column's own main longitudinal
    // reinforcement, drawn continuing above the dowel lap length up to
    // a break symbol (see footingDiagram.extended.mjs's
    // computeColumnBarGeometry/renderSectionView block). Only a
    // table-less inline "N ØD" callout on the drawing itself uses this —
    // no dedicated schedule column, so no english table-header string is
    // needed beyond this one label used as the on-drawing tag.
    columnBarsLabel: 'Column Bars',
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
    // [Step 20] "كانات" و"شريحة تركيز التسليح" منقولان حرفياً من نص دليل
    // التفاصيل الانشائية للكود المصري ٢٠٠١ (شكل ١٦-٣) نفسه — وليسا ترجمة
    // مُختلَقة — حتى تُطابق التسمية على الرسم المصطلح الوارد في الدليل
    // مباشرة. بلا أقواس ولا شرطات (راجع تحذير أعلى الملف).
    ties: 'كانات',
    tieDia: 'قطر الكانات',
    tieSpacing: 'تباعد الكانات',
    tieCount: 'عدد الكانات',
    band: 'شريحة التركيز',
    bandWidth: 'عرض شريحة التركيز',
    bandDia: 'قطر أسياخ الشريحة',
    bandSpacing: 'تباعد أسياخ الشريحة',
    // نفس تسميات دليل الكود المصري بالحرف: "تسليح علوي طولي"، "تسليح سفلي
    // طولي"، "تسليح علوي عرضي"، "تسليح سفلي عرضي" (شكل ١٦-٣).
    topLongitudinal: 'تسليح علوي طولي',
    bottomLongitudinal: 'تسليح سفلي طولي',
    topTransverse: 'تسليح علوي عرضي',
    bottomTransverse: 'تسليح سفلي عرضي',
    captionExtrasLegend: 'عند ظهورها: الأزرق المتقطع يمثل الطبقة العلوية، الأحمر المتصل الطبقة السفلية، والخط الأحمر الأثقل شريحة التركيز.',
    reinforcedExtentNote: 'امتداد القاعدة المسلحة بعد خصم الغطاء الخرساني',
    longitudinalSectionTitle: 'قطاع طولي',
    transverseSectionTitle: 'قطاع عرضي',
    // [Bugfix, this session] نفس الثمانية مفاتيح المُضافة في نسخة en أعلاه
    // — كانت مفقودة من القاموسين معاً (ar وen)، فكانت translate() ترجع
    // اسم المفتاح الخام بلا أي ترجمة بأي لغة. المصطلحات أدناه مطابقة
    // حرفياً لتسميات شكل ٢-١٦ في دليل التفاصيل الانشائية (ECP 203) —
    // "منسوب ظهر القاعدة المسلحة"/"منسوب التأسيس"/"طول التماس" هي ألفاظ
    // الدليل نفسه، وليست ترجمة مُختلَقة. بلا أقواس ولا شرطة طويلة/متوسطة
    // (راجع تحذير أعلى الملف) — تم فحصها يدوياً وستُتحقق أيضاً عبر
    // assertNoUnsafeArabicPunctuation().
    topFootingLevel: 'منسوب ظهر القاعدة المسلحة',
    foundingLevel: 'منسوب التأسيس',
    blindingThickness: 'سمك الخرسانة العادية',
    blindingProjection: 'بروز الخرسانة العادية',
    dowelLapLength: 'طول التماس',
    // [This session] انظر التعليق المقابل في نسخة en أعلاه — تسمية واحدة
    // تُستخدم كوسم داخل الرسم فقط لمجموعة أسياخ العمود الرئيسية.
    columnBarsLabel: 'أسياخ العمود',
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
