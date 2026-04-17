/**
 * payment/checkout.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Handles: language toggle, country/currency selection, form validation,
 *          API call to /api/payment/create-intention, Paymob.checkout() launch.
 *
 * Depends on: Paymob pay.js loaded before this script (via defer in HTML).
 * No eval, no innerHTML for user data, no inline handlers.
 *
 * Civil Engineering Suite — Eng. Aymn Asi © 2026
 */

'use strict';

// ── Country / currency catalog ────────────────────────────────────────────────
const COUNTRIES = [
  {
    code: 'EG', currency: 'EGP', phone_prefix: '+20',
    name_ar: 'مصر', name_en: 'Egypt',
    price_display_ar: '499.00 ج.م', price_display_en: '499.00 EGP',
    methods_ar: 'فيزا · ماستركارد · ميزة · فودافون كاش · فوري',
    methods_en: 'Visa · Mastercard · Meeza · Vodafone Cash · Fawry',
  },
  {
    code: 'SA', currency: 'SAR', phone_prefix: '+966',
    name_ar: 'المملكة العربية السعودية', name_en: 'Saudi Arabia',
    price_display_ar: '49.00 ر.س', price_display_en: '49.00 SAR',
    methods_ar: 'فيزا · ماستركارد · آبل باي', methods_en: 'Visa · Mastercard · Apple Pay',
  },
  {
    code: 'AE', currency: 'AED', phone_prefix: '+971',
    name_ar: 'الإمارات العربية المتحدة', name_en: 'United Arab Emirates',
    price_display_ar: '49.00 د.إ', price_display_en: '49.00 AED',
    methods_ar: 'فيزا · ماستركارد · آبل باي', methods_en: 'Visa · Mastercard · Apple Pay',
  },
  {
    code: 'KW', currency: 'KWD', phone_prefix: '+965',
    name_ar: 'الكويت', name_en: 'Kuwait',
    price_display_ar: '4.900 د.ك', price_display_en: '4.900 KWD',
    methods_ar: 'فيزا · ماستركارد', methods_en: 'Visa · Mastercard',
  },
  {
    code: 'BH', currency: 'BHD', phone_prefix: '+973',
    name_ar: 'البحرين', name_en: 'Bahrain',
    price_display_ar: '1.900 د.ب', price_display_en: '1.900 BHD',
    methods_ar: 'فيزا · ماستركارد', methods_en: 'Visa · Mastercard',
  },
  {
    code: 'OM', currency: 'OMR', phone_prefix: '+968',
    name_ar: 'سلطنة عُمان', name_en: 'Oman',
    price_display_ar: '4.900 ر.ع', price_display_en: '4.900 OMR',
    methods_ar: 'فيزا · ماستركارد', methods_en: 'Visa · Mastercard',
  },
  {
    code: 'QA', currency: 'QAR', phone_prefix: '+974',
    name_ar: 'قطر', name_en: 'Qatar',
    price_display_ar: '49.00 ر.ق', price_display_en: '49.00 QAR',
    methods_ar: 'فيزا · ماستركارد', methods_en: 'Visa · Mastercard',
  },
];

// ── Bilingual string table ────────────────────────────────────────────────────
const STRINGS = {
  ar: {
    pageTitle:      'شراء الترخيص',
    pageSubtitle:   'ترخيص شخصي — يعمل على جهاز واحد فقط',
    productName:    'فوتينج برو v.2026 — ترخيص شخصي',
    productSub:     'برنامج تصميم القواعد المشتركة',
    sectionCountry: '🌍 الدولة والسعر',
    sectionCustomer:'بيانات العميل',
    labelCountry:   'الدولة',
    labelPrice:     'السعر',
    labelFirst:     'الاسم الأول *',
    labelLast:      'الاسم الأخير *',
    labelEmail:     'البريد الإلكتروني *',
    labelPhone:     'رقم الهاتف *',
    placeholderFirst: 'محمد',
    placeholderLast:  'أحمد',
    placeholderEmail: 'example@email.com',
    placeholderPhone: '10xxxxxxxx',
    btnPay:         'ادفع الآن',
    btnLoading:     'جاري التحميل…',
    lockNote:       '🔒 مدعوم بـ Paymob — مشفّر بـ TLS 256-bit',
    errFirstName:   'الرجاء إدخال الاسم الأول',
    errLastName:    'الرجاء إدخال الاسم الأخير',
    errEmail:       'الرجاء إدخال بريد إلكتروني صحيح',
    errPhone:       'الرجاء إدخال رقم هاتف صحيح',
    errGeneric:     'حدث خطأ. يرجى المحاولة مرة أخرى.',
    errGateway:     'تعذّر الاتصال ببوابة الدفع. يرجى المحاولة مرة أخرى.',
    errPaymobMissing:'خدمة الدفع غير متاحة مؤقتاً. يرجى المحاولة لاحقاً.',
    features: [
      '17 وحدة هندسية', 'متوافق مع ACI 318-19',
      'واجهة عربي + إنجليزي', '100% بدون إنترنت',
      'قفل شخصي للجهاز', 'ملف Excel واحد',
    ],
  },
  en: {
    pageTitle:      'Purchase License',
    pageSubtitle:   'Personal License — runs on a single device',
    productName:    'Footing Pro v.2026 — Personal License',
    productSub:     'Combined Footing Design Software',
    sectionCountry: '🌍 Country & Price',
    sectionCustomer:'Customer Information',
    labelCountry:   'Country',
    labelPrice:     'Price',
    labelFirst:     'First Name *',
    labelLast:      'Last Name *',
    labelEmail:     'Email Address *',
    labelPhone:     'Phone Number *',
    placeholderFirst: 'Mohamed',
    placeholderLast:  'Ahmed',
    placeholderEmail: 'example@email.com',
    placeholderPhone: '10xxxxxxxx',
    btnPay:         'Pay Now',
    btnLoading:     'Loading…',
    lockNote:       '🔒 Powered by Paymob — TLS 256-bit Encrypted',
    errFirstName:   'Please enter your first name',
    errLastName:    'Please enter your last name',
    errEmail:       'Please enter a valid email address',
    errPhone:       'Please enter a valid phone number',
    errGeneric:     'An error occurred. Please try again.',
    errGateway:     'Could not reach payment gateway. Please try again.',
    errPaymobMissing:'Payment service temporarily unavailable. Please try later.',
    features: [
      '17 Engineering Modules', 'ACI 318-19 Compliant',
      'Arabic + English UI', '100% Offline',
      'Personal Device Lock', 'Single Excel File',
    ],
  },
};

// ── State ─────────────────────────────────────────────────────────────────────
let lang          = 'ar';
let currentCountry = COUNTRIES[0]; // Egypt default

// ── DOM refs — fetched once after DOMContentLoaded ────────────────────────────
let $ = {};

// ── Language toggle ───────────────────────────────────────────────────────────
function applyLang(newLang) {
  lang = newLang;
  const dir = lang === 'ar' ? 'rtl' : 'ltr';
  document.documentElement.setAttribute('lang', lang);
  document.documentElement.setAttribute('dir', dir);

  const s = STRINGS[lang];
  $.langBtn.textContent     = lang === 'ar' ? 'EN' : 'عربي';
  $.pageTitle.textContent   = s.pageTitle;
  $.pageSubtitle.textContent= s.pageSubtitle;
  $.productName.textContent = s.productName;
  $.productSub.textContent  = s.productSub;
  $.sectionCountry.textContent = s.sectionCountry;
  $.sectionCustomer.textContent= s.sectionCustomer;
  $.labelCountry.textContent= s.labelCountry;
  $.labelPrice.textContent  = s.labelPrice;
  $.labelFirst.textContent  = s.labelFirst;
  $.labelLast.textContent   = s.labelLast;
  $.labelEmail.textContent  = s.labelEmail;
  $.labelPhone.textContent  = s.labelPhone;
  $.inputFirst.placeholder  = s.placeholderFirst;
  $.inputLast.placeholder   = s.placeholderLast;
  $.inputEmail.placeholder  = s.placeholderEmail;
  $.inputPhone.placeholder  = s.placeholderPhone;
  $.lockNote.textContent    = s.lockNote;
  $.btnText.textContent     = s.btnPay;

  // Rebuild feature list
  $.featuresList.innerHTML = '';
  s.features.forEach(feat => {
    const li = document.createElement('li');
    li.textContent = feat;
    $.featuresList.appendChild(li);
  });

  // Update country selector options
  Array.from($.countrySelect.options).forEach((opt, i) => {
    opt.textContent = lang === 'ar'
      ? COUNTRIES[i].name_ar
      : COUNTRIES[i].name_en;
  });

  // Update methods badge
  updateMethodsBadge();
}

// ── Country change ────────────────────────────────────────────────────────────
function applyCountry(countryCode) {
  currentCountry = COUNTRIES.find(c => c.code === countryCode) || COUNTRIES[0];
  $.phonePrefix.textContent = currentCountry.phone_prefix;
  $.priceValue.textContent  = lang === 'ar'
    ? currentCountry.price_display_ar
    : currentCountry.price_display_en;
  updateMethodsBadge();
}

function updateMethodsBadge() {
  $.methodsBadge.textContent = lang === 'ar'
    ? currentCountry.methods_ar
    : currentCountry.methods_en;
}

// ── Validation ────────────────────────────────────────────────────────────────
function clearError(inputEl, errEl) {
  inputEl.classList.remove('invalid');
  errEl.textContent = '';
}

function setError(inputEl, errEl, msg) {
  inputEl.classList.add('invalid');
  errEl.textContent = msg;
  return false;
}

function isValidEmail(email) {
  return /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(email);
}

function isValidPhone(phone) {
  const stripped = phone.replace(/[\s\-().]/g, '');
  return /^\+?[0-9]{7,18}$/.test(stripped);
}

function validateForm() {
  const s = STRINGS[lang];
  let valid = true;

  const firstName = $.inputFirst.value.trim();
  const lastName  = $.inputLast.value.trim();
  const email     = $.inputEmail.value.trim();
  const phone     = $.inputPhone.value.trim();

  clearError($.inputFirst, $.errFirst);
  clearError($.inputLast,  $.errLast);
  clearError($.inputEmail, $.errEmail);
  clearError($.inputPhone, $.errPhone);

  if (!firstName) { setError($.inputFirst, $.errFirst, s.errFirstName); valid = false; }
  if (!lastName)  { setError($.inputLast,  $.errLast,  s.errLastName);  valid = false; }
  if (!email || !isValidEmail(email)) {
    setError($.inputEmail, $.errEmail, s.errEmail); valid = false;
  }
  if (!phone || !isValidPhone(phone)) {
    setError($.inputPhone, $.errPhone, s.errPhone); valid = false;
  }

  return valid;
}

// ── Show / hide global error banner ──────────────────────────────────────────
function showBanner(msg) {
  $.errorBanner.textContent = msg;
  $.errorBanner.classList.add('visible');
}
function hideBanner() {
  $.errorBanner.classList.remove('visible');
  $.errorBanner.textContent = '';
}

// ── Loading state ─────────────────────────────────────────────────────────────
function setLoading(on) {
  $.payBtn.disabled = on;
  $.payBtn.classList.toggle('loading', on);
  if (!on) $.btnText.textContent = STRINGS[lang].btnPay;
}

// ── Payment flow ──────────────────────────────────────────────────────────────
async function handlePay() {
  hideBanner();

  if (!validateForm()) return;

  // Guard: Paymob SDK must be loaded
  if (typeof Paymob === 'undefined' || typeof Paymob.checkout !== 'function') {
    showBanner(STRINGS[lang].errPaymobMissing);
    return;
  }

  setLoading(true);

  const body = JSON.stringify({
    product_id: 'footing-pro-personal',
    currency:   currentCountry.currency,
    first_name: $.inputFirst.value.trim(),
    last_name:  $.inputLast.value.trim(),
    email:      $.inputEmail.value.trim().toLowerCase(),
    phone:      currentCountry.phone_prefix + $.inputPhone.value.trim(),
  });

  let intentData;
  try {
    const res = await fetch('/api/payment/create-intention', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });

    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      showBanner(errJson.error || STRINGS[lang].errGateway);
      setLoading(false);
      return;
    }

    intentData = await res.json();
  } catch {
    showBanner(STRINGS[lang].errGateway);
    setLoading(false);
    return;
  }

  if (!intentData.client_secret || !intentData.public_key) {
    showBanner(STRINGS[lang].errGeneric);
    setLoading(false);
    return;
  }

  setLoading(false);

  // ── Launch Paymob hosted checkout modal ───────────────────────────────────
  try {
    Paymob.checkout({
      publicKey:    intentData.public_key,
      clientSecret: intentData.client_secret,
    });
  } catch (err) {
    console.error('[checkout] Paymob.checkout() threw:', err);
    showBanner(STRINGS[lang].errPaymobMissing);
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  // Cache DOM refs
  $ = {
    langBtn:        document.getElementById('lang-btn'),
    pageTitle:      document.getElementById('page-title'),
    pageSubtitle:   document.getElementById('page-subtitle'),
    productName:    document.getElementById('product-name'),
    productSub:     document.getElementById('product-sub'),
    featuresList:   document.getElementById('features-list'),
    sectionCountry: document.getElementById('section-country'),
    sectionCustomer:document.getElementById('section-customer'),
    labelCountry:   document.getElementById('label-country'),
    labelPrice:     document.getElementById('label-price'),
    countrySelect:  document.getElementById('country-select'),
    phonePrefix:    document.getElementById('phone-prefix'),
    priceValue:     document.getElementById('price-value'),
    inputFirst:     document.getElementById('first-name'),
    inputLast:      document.getElementById('last-name'),
    inputEmail:     document.getElementById('email'),
    inputPhone:     document.getElementById('phone'),
    labelFirst:     document.getElementById('label-first'),
    labelLast:      document.getElementById('label-last'),
    labelEmail:     document.getElementById('label-email'),
    labelPhone:     document.getElementById('label-phone'),
    errFirst:       document.getElementById('err-first'),
    errLast:        document.getElementById('err-last'),
    errEmail:       document.getElementById('err-email'),
    errPhone:       document.getElementById('err-phone'),
    payBtn:         document.getElementById('pay-btn'),
    btnText:        document.getElementById('btn-text'),
    errorBanner:    document.getElementById('error-banner'),
    lockNote:       document.getElementById('lock-note'),
    methodsBadge:   document.getElementById('methods-badge'),
  };

  // Populate country select
  COUNTRIES.forEach((c, i) => {
    const opt = document.createElement('option');
    opt.value = c.code;
    opt.textContent = c.name_ar; // Default AR, applyLang will update
    if (i === 0) opt.selected = true;
    $.countrySelect.appendChild(opt);
  });

  // Wire events
  $.langBtn.addEventListener('click', function () {
    applyLang(lang === 'ar' ? 'en' : 'ar');
    // Update price display text on toggle
    $.priceValue.textContent = lang === 'ar'
      ? currentCountry.price_display_ar
      : currentCountry.price_display_en;
  });

  $.countrySelect.addEventListener('change', function () {
    applyCountry(this.value);
  });

  $.payBtn.addEventListener('click', handlePay);

  // Clear field errors on input
  ['inputFirst', 'inputLast', 'inputEmail', 'inputPhone'].forEach(key => {
    const errKey = 'err' + key.replace('input', '');
    $[key].addEventListener('input', function () {
      clearError($[key], $[errKey]);
    });
  });

  // Apply default language and country
  applyLang('ar');
  applyCountry('EG');
});
