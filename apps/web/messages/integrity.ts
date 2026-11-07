import type { CatalogShape } from '../i18n/types';

export const integrityEn = {
  metadata: 'Admin Integrity Verification',
  title: 'Integrity verification',
  introduction:
    'Run the canonical-v2 verifier independently of audit-search filters, one explicit bounded page at a time.',
  denied: 'This workspace does not grant chain-verification access. No verification was requested.',
  initial: 'No verification has run. Start at genesis to capture a sequence bound.',
  checking: 'Checking one bounded verification page...',
  noRecords: 'No records checked.',
  complete: 'Verification complete for the captured database-relative range.',
  partial: 'Clean partial segment. Verification is not complete.',
  noEvidence: 'No verification evidence.',
  failed: 'Verification stopped at the first integrity failure.',
  incomplete:
    'Run incomplete. The requested page supplied no accepted verification evidence. Start a new run to try again.',
  stopped:
    'Verification stopped. No complete-run conclusion was reached. Start a new run to continue from genesis.',
  changed: 'Chain selection changed. Start a new run; no prior progress is reused.',
  verify: 'Verify a chain',
  chain: 'Chain',
  audit: 'Audit chain',
  ledger: 'Security ledger',
  instructions:
    'Start at genesis, with at most {limit, number} chain nodes per page. The first response captures the upper sequence bound; later pages keep that exact bound and the previous page’s hash. New records are not chased.',
  start: 'Start new run',
  continue: 'Continue verification',
  stop: 'Stop verification',
  failureEnd: '{description} No continuation is allowed for this run.',
  progress: 'Verification progress',
  notCaptured: 'Not captured yet',
  none: 'None',
  notProvided: 'Not provided',
  fields: {
    chain: 'Chain',
    bound: 'Captured through sequence',
    pages: 'Accepted pages',
    checked: 'Chain nodes checked, cumulative',
    pageChecked: 'Chain nodes checked, last page',
    limit: 'Work limit per page',
    after: 'Page after sequence',
    first: 'First checked sequence',
    last: 'Last checked sequence',
    seedSource: 'Seed source',
    seedHash: 'Seed hash',
    lastHash: 'Last hash',
    failure: 'Failure code',
    broken: 'First failure sequence',
    expected: 'Expected hash',
    stored: 'Stored hash',
  },
  page: 'Last accepted verification page',
  empty:
    'The reported chain is empty at the captured bound. No payload or record content was verified; this is not proof that no activity occurred.',
  failureCounts:
    'Failure-page counts describe visited nodes, not successfully verified payloads. Earlier clean pages do not make this a complete proof.',
  seed: {
    genesis: 'Genesis',
    supplied_predecessor: 'Prior page hash (supplied predecessor)',
    database_predecessor: 'Stored database predecessor',
  },
  erasedCounts:
    'Erasure annotations checked: {page, number} on the last page; {total, number} cumulative. These are a subset of {checked, number} checked chain nodes, not extra work.',
  retainedCounts:
    'Retained payloads recomputed: {page, number} on the last clean page; {total, number} cumulative.',
  erasureLimits:
    'Erased payloads retain chain links and erasure annotations, but their original bodies cannot be recomputed. A fully erased ledger can have clean surviving links without verifying its erased content. An annotation does not establish legal authorization or that the purge operator honored retention and holds.',
  auditCounts:
    'Retained audit payloads were recomputed for the {count, number} checked nodes on this clean page.',
  scope: 'Backend scope',
  original: 'Original technical evidence',
  scopes: {
    audit:
      'Verification covers only the stored segment relative to its reported seed. It does not establish complete ingestion, detection of tail truncation, or independent historical authenticity.',
    ledger:
      'Verification covers database-relative chain links and retained payloads. Erasure annotations do not prove receipt chaining or legal authorization; original erased bodies are not recomputed. It does not establish complete ingestion or independent historical authenticity.',
  },
  limits: 'Verification limits',
  relativeLimits:
    'Verification is database-relative to the reported seed and bound. It does not prove complete event ingestion, independent historical authenticity, or protection from a coherent privileged rewrite or rollback.',
  snapshotLimits:
    'Each page uses its own database snapshot, not one multi-page global snapshot or an independently authenticated head. A continued run does not authenticate new tail records. A durable-head check does not independently detect a coherent privileged rollback; preserve the backend’s reported scope when interpreting any result.',
  sequenceLimits:
    'Sequence gaps are valid; counts are not percentages. Stop and failures end continuation. Backgrounding, session changes, and navigation discard progress rather than silently restoring a proof. No audit payloads or other accounts are fetched by this view.',
  failures: {
    chain_mismatch: 'The stored chain link differs from the recomputed link.',
    leaf_mismatch: 'A retained payload does not reproduce its stored leaf hash.',
    predecessor_mismatch:
      'The stored predecessor changed from the prior page hash supplied for this run.',
    invalid_leaf_hash: 'A stored leaf digest has an invalid format.',
    invalid_chain_hash: 'A stored chain digest has an invalid format.',
    record_not_serializable: 'A retained record could not be serialized in canonical format.',
    head_mismatch: 'The checked end does not agree with the stored logical head.',
    payload_absent_without_erasure_record:
      'A payload is absent without an authorizing erasure record.',
    no_stored_records:
      'No stored records were available in the reported range. This is no verification evidence, not proof of no activity.',
  },
} as const;

export const integrityFa = {
  metadata: 'مدیریت بررسی تمامیت داده‌ها',
  title: 'بررسی تمامیت داده‌ها',
  introduction:
    'بررسی‌کنندهٔ canonical-v2 را مستقل از فیلترهای جست‌وجوی ممیزی، هر بار برای یک صفحهٔ محدود و با اقدام صریح اجرا کنید.',
  denied: 'این بخش مجوز بررسی زنجیره را نمی‌دهد. هیچ بررسی‌ای درخواست نشد.',
  initial: 'هنوز بررسی‌ای اجرا نشده است. برای ثبت مرز توالی، از ابتدای زنجیره آغاز کنید.',
  checking: 'در حال بررسی یک صفحهٔ محدود...',
  noRecords: 'هیچ سابقه‌ای بررسی نشد.',
  complete: 'بررسی بازهٔ ثبت‌شده، نسبت به وضعیت پایگاه داده کامل شد.',
  partial: 'بخش بررسی‌شده سالم است. بررسی کامل نشده است.',
  noEvidence: 'شواهدی برای بررسی وجود ندارد.',
  failed: 'بررسی در نخستین خطای تمامیت متوقف شد.',
  incomplete:
    'بررسی ناتمام است. صفحهٔ درخواستی شواهد پذیرفته‌شده‌ای ارائه نکرد. برای تلاش مجدد، بررسی تازه‌ای آغاز کنید.',
  stopped:
    'بررسی متوقف شد. نتیجه‌ای برای کل بررسی به دست نیامد. برای ادامه از ابتدای زنجیره، بررسی تازه‌ای آغاز کنید.',
  changed: 'زنجیرهٔ انتخاب‌شده تغییر کرد. بررسی تازه‌ای آغاز کنید؛ پیشرفت قبلی استفاده نمی‌شود.',
  verify: 'بررسی زنجیره',
  chain: 'زنجیره',
  audit: 'زنجیرهٔ ممیزی',
  ledger: 'دفتر ثبت امنیتی',
  instructions:
    'از ابتدای زنجیره با حداکثر {limit, number} گره در هر صفحه آغاز کنید. نخستین پاسخ، مرز بالای توالی را ثبت می‌کند؛ صفحه‌های بعد همان مرز دقیق و درهم‌ساز صفحهٔ قبل را حفظ می‌کنند. سوابق تازه دنبال نمی‌شوند.',
  start: 'آغاز بررسی تازه',
  continue: 'ادامهٔ بررسی',
  stop: 'توقف بررسی',
  failureEnd: '{description} ادامهٔ این بررسی مجاز نیست.',
  progress: 'پیشرفت بررسی',
  notCaptured: 'هنوز ثبت نشده',
  none: 'هیچ‌کدام',
  notProvided: 'ارائه نشده',
  fields: {
    chain: 'زنجیره',
    bound: 'مرز توالی ثبت‌شده',
    pages: 'صفحه‌های پذیرفته‌شده',
    checked: 'مجموع گره‌های بررسی‌شده',
    pageChecked: 'گره‌های بررسی‌شده در صفحهٔ آخر',
    limit: 'سقف کار هر صفحه',
    after: 'صفحه پس از توالی',
    first: 'نخستین توالی بررسی‌شده',
    last: 'آخرین توالی بررسی‌شده',
    seedSource: 'منبع مقدار آغازین',
    seedHash: 'درهم‌ساز آغازین',
    lastHash: 'آخرین درهم‌ساز',
    failure: 'کد خطا',
    broken: 'توالی نخستین خطا',
    expected: 'درهم‌ساز مورد انتظار',
    stored: 'درهم‌ساز ذخیره‌شده',
  },
  page: 'آخرین صفحهٔ پذیرفته‌شدهٔ بررسی',
  empty:
    'زنجیرهٔ گزارش‌شده در مرز ثبت‌شده خالی است. هیچ محتوا یا سابقه‌ای بررسی نشد؛ این اثبات نبود فعالیت نیست.',
  failureCounts:
    'شمارش صفحهٔ خطا، گره‌های بازدیدشده را نشان می‌دهد، نه محتواهای موفقیت‌آمیز بررسی‌شده را. صفحه‌های سالم پیشین، این نتیجه را به اثبات کامل تبدیل نمی‌کنند.',
  seed: {
    genesis: 'ابتدای زنجیره',
    supplied_predecessor: 'درهم‌ساز صفحهٔ قبل (پیشینِ ارائه‌شده)',
    database_predecessor: 'مقدار پیشینِ ذخیره‌شده در پایگاه داده',
  },
  erasedCounts:
    'یادداشت‌های حذف بررسی‌شده: {page, number} در صفحهٔ آخر؛ در مجموع {total, number}. این موارد زیرمجموعهٔ {checked, number} گرهٔ بررسی‌شده‌اند و کار اضافی محسوب نمی‌شوند.',
  retainedCounts:
    'محتواهای نگهداری‌شده که دوباره محاسبه شدند: {page, number} در آخرین صفحهٔ سالم؛ در مجموع {total, number}.',
  erasureLimits:
    'برای محتواهای حذف‌شده، پیوندهای زنجیره و یادداشت حذف باقی می‌مانند، اما بدنهٔ اصلی قابل محاسبهٔ مجدد نیست. دفتر کاملاً پاک‌شده ممکن است پیوندهای باقی‌ماندهٔ سالم داشته باشد، بدون آنکه محتوای حذف‌شده بررسی شود. یادداشت حذف، مجوز قانونی یا رعایت سیاست نگهداری و توقیف قانونی توسط عامل پاک‌سازی را اثبات نمی‌کند.',
  auditCounts:
    'محتوای ممیزی نگهداری‌شده برای {count, number} گرهٔ بررسی‌شده در این صفحهٔ سالم دوباره محاسبه شد.',
  scope: 'دامنهٔ گزارش‌شدهٔ سرور',
  original: 'شواهد فنی اصلی',
  scopes: {
    audit:
      'بررسی فقط بخش ذخیره‌شده را نسبت به مقدار آغازین گزارش‌شده پوشش می‌دهد. ورود کامل داده، تشخیص قطع‌شدن انتهای زنجیره یا اصالت تاریخی مستقل را اثبات نمی‌کند.',
    ledger:
      'بررسی، پیوندهای زنجیره و محتوای نگهداری‌شده را نسبت به پایگاه داده پوشش می‌دهد. یادداشت‌های حذف، زنجیره‌شدن رسیدها یا مجوز قانونی را اثبات نمی‌کنند؛ بدنهٔ اصلیِ حذف‌شده دوباره محاسبه نمی‌شود. ورود کامل داده یا اصالت تاریخی مستقل اثبات نمی‌شود.',
  },
  limits: 'محدودیت‌های بررسی',
  relativeLimits:
    'بررسی نسبت به پایگاه داده، مقدار آغازین و مرز گزارش‌شده انجام می‌شود. ورود کامل رویدادها، اصالت تاریخی مستقل یا محافظت در برابر بازنویسی یا بازگردانی منسجم توسط عامل دارای دسترسی ویژه را اثبات نمی‌کند.',
  snapshotLimits:
    'هر صفحه نمای لحظه‌ای جداگانه‌ای از پایگاه داده دارد؛ نه یک نمای کلی برای همهٔ صفحه‌ها یا سرِ زنجیره‌ای که مستقل احراز اصالت شده باشد. ادامهٔ بررسی، سوابق تازهٔ انتهای زنجیره را احراز اصالت نمی‌کند. بررسی سرِ پایدار زنجیره، بازگردانی منسجم توسط عامل دارای دسترسی ویژه را مستقل تشخیص نمی‌دهد؛ هنگام تفسیر نتیجه، دامنهٔ گزارش‌شدهٔ سرور را حفظ کنید.',
  sequenceLimits:
    'وجود فاصله در توالی معتبر است؛ شمارش‌ها درصد نیستند. توقف و خطا ادامه را پایان می‌دهند. رفتن به پس‌زمینه، تغییر نشست و جابه‌جایی صفحه، پیشرفت را پاک می‌کنند و اثباتی را بی‌اطلاع بازنمی‌گردانند. این بخش محتوای ممیزی یا حساب‌های دیگر را دریافت نمی‌کند.',
  failures: {
    chain_mismatch: 'پیوند ذخیره‌شدهٔ زنجیره با پیوند محاسبه‌شده مطابقت ندارد.',
    leaf_mismatch: 'محتوای نگهداری‌شده، درهم‌ساز برگ ذخیره‌شده را بازتولید نمی‌کند.',
    predecessor_mismatch:
      'مقدار پیشین ذخیره‌شده با درهم‌ساز صفحهٔ قبلی که برای این بررسی ارائه شد تفاوت دارد.',
    invalid_leaf_hash: 'قالب چکیدهٔ ذخیره‌شدهٔ برگ نامعتبر است.',
    invalid_chain_hash: 'قالب چکیدهٔ ذخیره‌شدهٔ زنجیره نامعتبر است.',
    record_not_serializable: 'سابقهٔ نگهداری‌شده در قالب استاندارد قابل سریال‌سازی نبود.',
    head_mismatch: 'انتهای بررسی‌شده با سرِ منطقی ذخیره‌شده مطابقت ندارد.',
    payload_absent_without_erasure_record: 'محتوا بدون سابقهٔ مجوز حذف موجود نیست.',
    no_stored_records:
      'در بازهٔ گزارش‌شده سابقهٔ ذخیره‌شده‌ای موجود نبود. این شواهد بررسی نیست و نبود فعالیت را اثبات نمی‌کند.',
  },
} as const satisfies CatalogShape<typeof integrityEn>;
