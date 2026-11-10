import type { CatalogShape } from '../i18n/types';

export const auditEn = {
  metadata: 'Admin Audit Logs',
  title: 'Audit logs',
  introduction:
    'Search bounded UTC windows. Raw events are sensitive disclosures, not independently verified evidence.',
  denied: 'This workspace does not grant raw audit-log access. No audit records were requested.',
  initial: 'Review the UTC window, then search explicitly. No query has run.',
  changed:
    'Filters changed. Search explicitly to load results; previous cursor history was cleared.',
  loading: 'Loading one audit-log page...',
  loaded:
    '{count, plural, one {# record loaded on this page.} other {# records loaded on this page.}} {more, select, yes {Older matching records are available.} other {No older matching records were reported for this request.}}',
  query: 'Bounded event query',
  search: 'Search audit logs',
  start: 'Start time (Gregorian UTC)',
  end: 'End time (Gregorian UTC)',
  event: 'Event type (exact)',
  eventHelp:
    'Optional. Up to 100 lowercase letters, digits, periods, or underscores. No patterns or partial matching.',
  size: 'Page size',
  sizeHelp: '1-{maximum, number} records per request.',
  windowHelp:
    'Enter Gregorian dates and UTC times, independent of display calendar and time zone preferences. Both bounds are inclusive and may be equal. Maximum window: {seconds, number} seconds. The last-24-hours default is shortened when the configured maximum is smaller.',
  lastDay: 'Use last 24 hours',
  clear: 'Clear query',
  cleared: 'Audit filters, records, and cursor history cleared.',
  cancelled: 'Audit request cancelled. No result was accepted.',
  cancel: 'Cancel audit request',
  submitted:
    'Submitted window: <startValue>{start}</startValue> to <endValue>{end}</endValue>. Event type: <eventValue>{event}</eventValue>. Filters stay fixed for page navigation.',
  draftPreview: 'Valid draft Gregorian UTC window (not submitted): <start></start> to <end></end>. Event type: <eventValue>{event}</eventValue>. Page size: {size}. Search explicitly to submit.',
  all: 'All',
  region: 'Audit results',
  resultView: 'Audit result view', compactRows: 'Compact rows', tableView: 'Table view',
  caption: 'Audit results ordered by descending chain sequence',
  eventTime: 'Event time (UTC)',
  eventType: 'Event type',
  actionStatus: 'Action status',
  sequence: 'Sequence',
  details: 'Details',
  viewDetails: 'View details for sequence {sequence}',
  empty: 'No audit records matched this page of the submitted query.',
  pagination: 'Audit cursor pagination',
  newer: 'Newer records',
  pageCount:
    '{count, plural, one {# record on this page.} other {# records on this page.}} No total is calculated.',
  older: 'Older records',
  historyDropped:
    'Earlier cursor history was discarded. Start a new search to revisit newer pages beyond the retained history.',
  retention:
    'Only the current page and up to {limit, number} page cursors are kept in memory. Each page is a separate, durably audited read, not a frozen global collection. Late ingestion can change later searches. Nothing polls for freshness; search again explicitly to refresh.',
  detailTitle: 'Audit record details',
  detailDescription:
    'Sequence <sequenceValue>{sequence}</sequenceValue>. Stored hashes are record fields, not proof of chain verification.',
  fields: {
    record: 'Record reference',
    actor: 'Actor reference',
    service: 'Actor service reference',
    subject: 'Subject reference',
    ip: 'Client IP',
    agent: 'User agent',
    leaf: 'Stored leaf hash',
    chain: 'Stored chain hash',
  },
  notRecorded: 'Not recorded',
  missingSubject:
    'A missing subject reference does not explain why it is absent. No account lookup or integrity conclusion is implied.',
  payload: 'Payload text',
  payloadLabel: 'Audit payload text',
  close: 'Close details',
  privateCleared:
    'Private query data was cleared. Session and administrative access must be checked again before continuing.',
  validation: {
    start: 'Enter a valid start time in UTC.',
    end: 'Enter a valid end time in UTC.',
    order: 'End time must be at or after start time.',
    window: 'Use a UTC window no longer than {seconds, number} seconds.',
    event: 'Use 1-100 lowercase letters, digits, periods, or underscores for an exact event type.',
    size: 'Enter a whole page size from 1 to {maximum, number}.',
  },
  failure: {
    denied:
      'Administrative access was denied. Private results were cleared; your normal account session has not been signed out.',
    rateLimited:
      'Request rate limited. Try again later with an explicit request. Nothing will retry automatically.',
    retryAfter:
      'Request rate limited. Wait {seconds, number} seconds before another explicit request. Nothing will retry automatically.',
    invalidResponse:
      'The response was malformed, oversized, or inconsistent with this request. No new result was accepted.',
    rejected:
      'The requested query or verification boundary was rejected. Review the inputs and start a new query or run.',
    missingHead:
      'Verification state is missing. This is not evidence of an intact or empty chain. Start a new run only after the service is available.',
    unavailable:
      'This administrative endpoint is unavailable on this deployment. No result was returned.',
    session:
      'The session is no longer available. Private results were cleared; check the current session before continuing.',
    service:
      'The service could not return an audited result. No new result was accepted; this is not an empty result or an integrity finding.',
    unknown:
      'The request could not be completed. No new result was accepted. Check the connection before another explicit request.',
  },
} as const;

export const auditFa = {
  metadata: 'مدیریت سوابق ممیزی',
  title: 'سوابق ممیزی',
  introduction:
    'در بازه‌های محدود UTC جست‌وجو کنید. رویدادهای خام، داده‌های حساسِ افشاشده هستند و شواهد مستقلاً تأییدشده محسوب نمی‌شوند.',
  denied: 'این بخش مجوز دسترسی به سوابق خام ممیزی را نمی‌دهد. هیچ سابقه‌ای درخواست نشد.',
  initial: 'بازهٔ UTC را بررسی و سپس صریحاً جست‌وجو کنید. هنوز پرس‌وجویی اجرا نشده است.',
  changed:
    'فیلترها تغییر کردند. برای دریافت نتایج صریحاً جست‌وجو کنید؛ تاریخچهٔ نشانگرهای صفحه پاک شد.',
  loading: 'در حال بارگیری یک صفحه از سوابق ممیزی...',
  loaded:
    '{count, plural, one {# سابقه در این صفحه بارگیری شد.} other {# سابقه در این صفحه بارگیری شد.}} {more, select, yes {سوابق قدیمی‌ترِ منطبق در دسترس‌اند.} other {برای این درخواست، سابقهٔ منطبق قدیمی‌تری گزارش نشد.}}',
  query: 'پرس‌وجوی محدود رویدادها',
  search: 'جست‌وجوی سوابق ممیزی',
  start: 'زمان آغاز (میلادی، UTC)',
  end: 'زمان پایان (میلادی، UTC)',
  event: 'نوع دقیق رویداد',
  eventHelp:
    'اختیاری؛ حداکثر ۱۰۰ حرف کوچک لاتین، رقم، نقطه یا زیرخط. الگو و تطبیق جزئی پذیرفته نیست.',
  size: 'تعداد در هر صفحه',
  sizeHelp: '۱ تا {maximum, number} سابقه در هر درخواست.',
  windowHelp:
    'تاریخ‌های میلادی و زمان‌های UTC را مستقل از تنظیمات تقویم و منطقهٔ زمانی نمایش وارد کنید. هر دو مرز در بازه محسوب می‌شوند و می‌توانند برابر باشند. حداکثر بازه: {seconds, number} ثانیه. اگر سقف پیکربندی‌شده کوتاه‌تر باشد، بازهٔ پیش‌فرض ۲۴ ساعت اخیر نیز کوتاه می‌شود.',
  lastDay: 'استفاده از ۲۴ ساعت اخیر',
  clear: 'پاک کردن پرس‌وجو',
  cleared: 'فیلترها، سوابق و تاریخچهٔ نشانگرهای ممیزی پاک شدند.',
  cancelled: 'درخواست ممیزی لغو شد. هیچ نتیجه‌ای پذیرفته نشد.',
  cancel: 'لغو درخواست ممیزی',
  submitted:
    'بازهٔ ارسال‌شده: از <startValue>{start}</startValue> تا <endValue>{end}</endValue>. نوع رویداد: <eventValue>{event}</eventValue>. فیلترها هنگام جابه‌جایی بین صفحه‌ها ثابت می‌مانند.',
  draftPreview: 'بازهٔ معتبر پیش‌نویس میلادی UTC (ارسال نشده): از <start></start> تا <end></end>. نوع رویداد: <eventValue>{event}</eventValue>. اندازهٔ صفحه: {size}. برای ارسال، صریحاً جست‌وجو کنید.',
  all: 'همه',
  region: 'نتایج ممیزی',
  resultView: 'نمای نتایج ممیزی', compactRows: 'ردیف‌های فشرده', tableView: 'نمای جدول',
  caption: 'نتایج ممیزی به ترتیب نزولی شمارهٔ توالی زنجیره',
  eventTime: 'زمان رویداد (UTC)',
  eventType: 'نوع رویداد',
  actionStatus: 'وضعیت اقدام',
  sequence: 'شمارهٔ توالی',
  details: 'جزئیات',
  viewDetails: 'مشاهدهٔ جزئیات توالی {sequence}',
  empty: 'هیچ سابقهٔ ممیزی با این صفحه از پرس‌وجوی ارسال‌شده مطابقت نداشت.',
  pagination: 'صفحه‌بندی ممیزی با نشانگر',
  newer: 'سوابق جدیدتر',
  pageCount:
    '{count, plural, one {# سابقه در این صفحه.} other {# سابقه در این صفحه.}} تعداد کل محاسبه نمی‌شود.',
  older: 'سوابق قدیمی‌تر',
  historyDropped:
    'بخش قدیمی تاریخچهٔ نشانگرها حذف شد. برای بازگشت به صفحه‌های جدیدترِ خارج از تاریخچهٔ نگهداری‌شده، جست‌وجوی تازه‌ای آغاز کنید.',
  retention:
    'فقط صفحهٔ فعلی و حداکثر {limit, number} نشانگر صفحه در حافظه می‌مانند. هر صفحه یک خواندن جداگانه با ثبت پایدار ممیزی است؛ مجموعهٔ کلی ثابت نیست. ورود دیرهنگام داده ممکن است جست‌وجوهای بعدی را تغییر دهد. برای تازه‌سازی، دوباره صریحاً جست‌وجو کنید؛ پایش خودکاری وجود ندارد.',
  detailTitle: 'جزئیات سابقهٔ ممیزی',
  detailDescription:
    'توالی <sequenceValue>{sequence}</sequenceValue>. درهم‌سازهای ذخیره‌شده فیلدهای سابقه‌اند و اثبات بررسی تمامیت زنجیره نیستند.',
  fields: {
    record: 'شناسهٔ مرجع سابقه',
    actor: 'شناسهٔ مرجع عامل',
    service: 'شناسهٔ مرجع سرویس عامل',
    subject: 'شناسهٔ مرجع شخص',
    ip: 'نشانی IP کارخواه',
    agent: 'عامل کاربر',
    leaf: 'درهم‌ساز ذخیره‌شدهٔ برگ',
    chain: 'درهم‌ساز ذخیره‌شدهٔ زنجیره',
  },
  notRecorded: 'ثبت نشده',
  missingSubject:
    'نبود شناسهٔ مرجع شخص، علت نبود آن را مشخص نمی‌کند. از آن جست‌وجوی حساب یا نتیجه‌گیری دربارهٔ تمامیت داده‌ها استنباط نمی‌شود.',
  payload: 'متن محتوای ثبت‌شده',
  payloadLabel: 'متن محتوای سابقهٔ ممیزی',
  close: 'بستن جزئیات',
  privateCleared:
    'داده‌های خصوصی پرس‌وجو پاک شدند. پیش از ادامه، نشست و دسترسی مدیریتی باید دوباره بررسی شوند.',
  validation: {
    start: 'زمان آغاز معتبری بر اساس UTC وارد کنید.',
    end: 'زمان پایان معتبری بر اساس UTC وارد کنید.',
    order: 'زمان پایان باید برابر یا پس از زمان آغاز باشد.',
    window: 'بازهٔ UTC نباید بیش از {seconds, number} ثانیه باشد.',
    event: 'برای نوع دقیق رویداد از ۱ تا ۱۰۰ حرف کوچک لاتین، رقم، نقطه یا زیرخط استفاده کنید.',
    size: 'تعداد هر صفحه را به‌صورت عدد صحیح از ۱ تا {maximum, number} وارد کنید.',
  },
  failure: {
    denied: 'دسترسی مدیریتی رد شد. نتایج خصوصی پاک شدند؛ نشست عادی حساب شما بسته نشده است.',
    rateLimited:
      'درخواست با محدودیت نرخ روبه‌رو شد. بعداً صریحاً دوباره تلاش کنید. هیچ تلاشی خودکار تکرار نمی‌شود.',
    retryAfter:
      'درخواست با محدودیت نرخ روبه‌رو شد. پیش از درخواست صریح بعدی {seconds, number} ثانیه صبر کنید. هیچ تلاشی خودکار تکرار نمی‌شود.',
    invalidResponse:
      'پاسخ بدقالب، بیش از حد بزرگ یا ناسازگار با این درخواست بود. هیچ نتیجهٔ تازه‌ای پذیرفته نشد.',
    rejected:
      'پرس‌وجو یا مرز بررسی درخواستی رد شد. ورودی‌ها را بررسی و پرس‌وجو یا بررسی تازه‌ای آغاز کنید.',
    missingHead:
      'وضعیت بررسی موجود نیست. این مدرکی برای سالم یا خالی بودن زنجیره نیست. فقط پس از در دسترس قرار گرفتن سرویس، بررسی تازه‌ای آغاز کنید.',
    unavailable: 'این نقطهٔ پایانی مدیریتی در این استقرار در دسترس نیست. نتیجه‌ای بازگردانده نشد.',
    session: 'نشست دیگر در دسترس نیست. نتایج خصوصی پاک شدند؛ پیش از ادامه نشست فعلی را بررسی کنید.',
    service:
      'سرویس نتوانست نتیجه‌ای همراه با ثبت ممیزی ارائه کند. هیچ نتیجهٔ تازه‌ای پذیرفته نشد؛ این نتیجهٔ خالی یا یافته‌ای دربارهٔ تمامیت نیست.',
    unknown:
      'درخواست کامل نشد. هیچ نتیجهٔ تازه‌ای پذیرفته نشد. پیش از درخواست صریح بعدی اتصال را بررسی کنید.',
  },
} as const satisfies CatalogShape<typeof auditEn>;
