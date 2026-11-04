import type { CatalogShape } from '../i18n/types';

export const legalEn = {
  title: 'DPO and Legal',
  introduction:
    'Purpose-limited legal operations. Class B records are pseudonymized personal data, not anonymous. Investigative access is not permission to disclose externally.',
  denied:
    'No legal operation is available to this session. A false capability does not distinguish missing permission from deployment prerequisites. No legal records were requested.',
  sectionsLabel: 'Legal workspace sections',
  sections: { holds: 'Legal Holds', preservation: 'Preservation', attribution: 'Attribution' },
  workspaceNotice:
    'Only the selected authorized section is mounted. No legal operation runs on load or while typing. Leaving a section, hiding this page, or losing authority clears its private state. There are no browser-saved drafts, exports, uploads, or external transfers.',
  sectionNotice: {
    attribution:
      'Search one explicit email and UTC window against currently eligible indexed ledger records. An email may match distinct historical account references; do not merge them or infer verified real-world identity. An empty or final page is not proof of no historical activity.',
    preservation:
      'Record a freeze-before-order preservation request independently of a case workflow or full disclosure order. Its advisory expiry never releases the hold automatically. Preservation history is available in Legal Holds by request kind.',
    holds:
      'Each Legal Hold or preservation request is independent and overrides retention until explicit release. Release resumes original clocks and may allow immediate purge eligibility. A hold cannot restore erased data, extend recovery, or establish an immutable evidence snapshot.',
  },
  buttons: {
    hold: 'Apply Legal Hold',
    preservation: 'Record preservation',
    lookup: 'Start attribution inquiry',
    clearInquiry: 'Clear inquiry',
    details: 'View restricted details',
    select: 'Select reference',
    clearSelection: 'Clear selection',
    nextLookup: 'Next attribution page',
    closeDetails: 'Close details',
    read: 'Read Legal Holds',
    clearRead: 'Clear hold query',
    cancelRead: 'Cancel hold read',
    release: 'Release request',
    previous: 'Previous hold page',
    next: 'Next hold page',
  },
  state: {
    releaseResume:
      'The prior target was cleared. Read Legal Holds and select an authorized request row again before fresh release verification.',
    lookupAccepted:
      '{count} indexed records accepted on this page. Each further page requires fresh verification.',
    confirmed:
      'The legal response is confirmed. No list refresh was made automatically. Read Legal Holds explicitly for a current snapshot.',
    expired:
      'Verification expired. Private form data was cleared. Start fresh verification and reenter the original request.',
    cancelled:
      'The legal workflow was cancelled before transmission. Its private state was cleared.',
    lookupUnconfirmed:
      'No attribution result was accepted. This is not a no-match result. Start a new inquiry explicitly with fresh verification.',
    writeUnconfirmed:
      'Legal write outcome unconfirmed. Nothing was retried and rollback is not implied. Reconcile the original external intake operation before a fresh, explicit attempt.',
    inquiryCleared: 'Inquiry and current page cleared. Reenter all inputs for a new run.',
    cleared:
      'Private legal inputs, references, results, operation UUIDs, cursors, and verification were cleared. Recheck your session and access before continuing.',
  },
  outcome: {
    noRetry:
      'No automatic retransmission was made. No durable recovery draft is kept in this browser.',
    released:
      'Request <value>{id}</value> is released, including if already released. This does not prove this caller changed it. Other independent holds may remain.',
    replayed: 'Existing request replayed; current state returned.',
    created: 'New legal request created.',
    alreadyReleased: 'This request is already released; replay did not reactivate it.',
    observedAt: 'Observed at: <time></time>',
    presence: 'Account record present: {account}. Ledger payload present: {ledger}.',
    presenceNotice:
      'Account presence includes soft-deleted records. Payload presence can include unindexed or expired records and says nothing about completeness. The hold is valid even if both observations are false.',
    transactionNotice:
      'Lookup and hold creation are separate transactions. This response does not promise that all previously displayed evidence survived until this hold committed.',
    listingUnavailable:
      'Listing is not available to this session. Release requires an authorized list row; no account-profile resolver or inferred target is used.',
  },
  attribution: {
    title: 'Current attribution page',
    scope: 'Fixed UTC scope: <start></start> to <end></end>. Page size: {size}.',
    highWater: 'High-water sequence: <value>{sequence}</value>.',
    observedAt: 'Original observation: <time></time>.',
    checkedAt: 'Eligibility checked: <time></time>.',
    empty:
      'No matching indexed, currently eligible records were returned on this page in this scope. This is not proof of no activity, no account, or a complete history.',
    region: 'Attribution results, horizontally scrollable',
    caption:
      'Pseudonymized personal data ordered by ascending sequence, not verified inclusion evidence',
    missingField: 'Not present in this returned projection',
    selected: 'Selected original reference: <value>{id}</value>.',
    selectionNotice:
      'This selection conveys only a reference, not proof that the account still exists or who owned it. Confirm each independent operation with fresh verification.',
    final: 'No continuation was returned. This is not a complete-history finding.',
    coverageNotice:
      'Only this page is retained; no previous-page cache or fetch-all exists. Current retention and holds are rechecked on every page; release may remove expired matches. Later ingestion above the bound is outside this run. The cursor has no advertised age expiry, and no countdown is inferred. Coverage does not promise every historical pepper generation is searchable. Missing selected metadata does not prove it never existed.',
  },
  evidence: {
    original: 'Original backend note (unchanged)',
    unknown:
      'This backend note is not a recognized fixed explanation. It is shown unchanged below; no translation or completeness claim is inferred.',
    preservation:
      'Preservation does not restore purged data. Ingestion may still be pending. Account and ledger presence are observations, not completeness guarantees. The <field>expires_at</field> date is advisory only and does not automatically release the hold.',
    coverage:
      'Only matching indexed retained records are covered. Ingestion may still be pending. Unindexed or purged history is not covered. Separate account references do not establish that they belong to one person.',
  },
  details: {
    title: 'Restricted legal request details',
    description:
      'Restricted narrative data, rendered as inert text. Missing purged details are not empty original values.',
    purged: 'Restricted details were purged. The original values are not available.',
  },
  fields: {
    requestKind: 'Request kind',
    holdId: 'Hold request UUID',
    accountRef: 'Original account reference',
    status: 'Status',
    appliedBy: 'Applied by (opaque reference)',
    releasedBy: 'Released by (opaque reference)',
    appliedAt: 'Applied at (UTC)',
    advisoryReviewAt: 'Advisory review at (UTC)',
    releasedAt: 'Released at (UTC)',
    reason: 'Reason',
    requestingAuthority: 'Requesting authority',
    legalBasis: 'Legal basis',
    eventRef: 'Event reference',
    eventType: 'Event type',
    eventTime: 'Event time (UTC)',
    retainUntil: 'Retain until (UTC)',
    sequence: 'Sequence',
    selection: 'Reference selection',
    holdStatus: 'Hold status',
    size: 'Page size',
    applied: 'Applied (UTC)',
    review: 'Advisory review (UTC)',
    released: 'Released (UTC)',
    actors: 'Actor references',
    actions: 'Actions',
    requestId: 'Operation UUID',
    identifier: 'Email for attribution',
    transientEmail: 'Transient email input (not evidence)',
    caseReference: 'Case reference',
    purpose: 'Inquiry purpose',
    startTime: 'Start time (UTC)',
    endTime: 'End time (UTC)',
    disclosure: 'Additional disclosure fields',
    reviewAt: 'Review at (UTC)',
    expiresAt: 'Expires at (UTC)',
  },
  disclosure: {
    client_ip: 'Client IP',
    ip_subnet: 'IP subnet',
    user_agent: 'User agent',
    device_fingerprint: 'Device fingerprint',
    client_id: 'Client ID',
    scope: 'Scope',
  },
  values: {
    hold: 'Legal Hold',
    preservation: 'Preservation',
    preservationRequest: 'Preservation request',
    active: 'Active',
    released: 'Released',
    all: 'All',
    yes: 'Yes',
    no: 'No',
    notRecorded: 'Not recorded',
    notReturned: 'Not returned',
    notSupplied: 'Not supplied',
    coreOnly: 'None (core metadata only)',
    serverFixed: '<value>{kind}</value> (server fixed)',
  },
  read: {
    title: 'Read independent requests',
    initial:
      'Choose a reference or explicitly select all original references, then read. No request has run.',
    changed: 'Filters changed. Read explicitly for a new snapshot.',
    loading: 'Loading one bounded Legal Holds page...',
    accepted:
      '{count} requests on this page. Total {total} in this response snapshot, not a stable multi-page inventory.',
    invalid:
      'Enter a canonical nonzero account reference or explicitly select all original references, and a page size from 1 to {max}. Invalid input never becomes an all-subject query.',
    allReferences: 'All original references',
    filterHelp:
      'The reference is the original <id>users.id</id>, retained independently after deletion. An all-subject read is explicit and bounded to at most {max} requests per page. No account-profile browsing is granted.',
    empty:
      'No requests were returned on this page of the submitted filters. This is not a missing-request API response or proof of no historical hold.',
    region: 'Legal Holds, horizontally scrollable',
    caption: 'Independent Legal Hold and preservation requests',
    appliedBy: 'Applied by: <value>{id}</value>',
    releasedBy: 'Released by: <value>{id}</value>',
    pagination: 'Legal Holds offset pagination',
    snapshot: 'Offset {offset}; {count} of {total} in this response snapshot.',
  },
  action: {
    titles: {
      hold: 'Apply Legal Hold',
      preservation: 'Record preservation',
      release: 'Release Legal Hold request',
      lookup: 'Attribution inquiry',
    },
    confirmations: {
      hold: 'Confirm Legal Hold',
      preservation: 'Confirm preservation',
      release: 'Confirm release',
      lookup: 'Confirm lookup',
    },
    invalidLookup:
      'Use a bare email of at most 320 UTF-8 bytes, authority and case reference of 1-255 bytes, purpose of 1-4096 bytes, explicit ordered RFC3339 UTC bounds within the configured window, and an allowed page size.',
    invalidCreate:
      'Use canonical nonzero UUIDs, a reason of 1-4096 UTF-8 bytes, authority and legal basis of 1-255 bytes where required, and an optional RFC3339 UTC date with at most six fractional digits. Blank narratives are invalid.',
    description:
      'Verify first, then review the exact legal operation and confirm explicitly. Verification is one-use and expires. Cancellation or leaving this workflow clears its sensitive data.',
    sending: 'Sending one legal request. Do not submit again.',
    verified: 'Verification complete. Review and confirm before verification expires.',
    expiry:
      'Single-use verification expires at <time></time>. Expiry clears the form and requires fresh verification.',
    prepare: 'Prepare legal request',
    createHelp:
      'Use the original <id>account_ref</id> from controlled intake, not an email or a profile lookup. Record your operation UUID and exact normalized inputs in that external record. The browser does not generate a UUID or keep a recovery draft. Reason: 1-4096 UTF-8 bytes; authority and legal basis: 1-255. Optional date: RFC3339 UTC ending in Z, at most six fractional digits; past dates are allowed. Dates never release a hold automatically.',
    lookupHelp:
      'Bare email up to 320 UTF-8 bytes; authority and case reference 1-255; purpose 1-4096. Enter explicit RFC3339 UTC bounds ending in Z. Maximum window: {seconds} seconds. Page size: 1-{max}. No provider-specific email normalization is performed here.',
    disclosure: 'Additional disclosure for this inquiry purpose',
    disclosureHelp:
      'All optional fields start unchecked. Only explicitly selected supported metadata is requested.',
    review: 'Review request',
    confirm: 'Confirm legal request',
    releaseWarning:
      'Release affects only this immutable hold request UUID. Other holds may remain. Original retention clocks resume, which may allow immediate eligibility at the next purge; release never resets retention. A 204 also covers an already released request and does not prove this caller changed it.',
    lookupWarning:
      'Class B records are pseudonymized personal data, not anonymous. An indexed match is not verified real-world identity or permission to disclose externally. Sequence position is not an inclusion proof. This request is for one page only.',
    createWarning:
      'Each request is independent. Holds override retention until explicit release; review and expiry dates are advisory. A hold cannot restore erased data, extend account recovery, or create an immutable evidence snapshot.',
    idempotencyWarning:
      'Idempotency is scoped to the original reference, request kind, and UUID, not the actor or a global UUID. Changing target or kind creates another independent hold. Exact replay may return an already released request and never reactivates it; a cleaned narrative tombstone conflicts instead of recreating it. Preserve this exact normalized tuple in controlled external intake before confirming.',
    acknowledgeCreate:
      'I reviewed the target, operation UUID, request kind, and normalized inputs.',
    acknowledgeRelease: 'I reviewed this hold request UUID and the release consequences.',
    acknowledgeLookup:
      'I reviewed the inquiry purpose, fixed scope, and selected disclosure fields.',
    submitting: 'Submitting legal request...',
    frozen:
      'Inputs are now frozen. To change the target or scope, cancel and start fresh verification. Nothing retries automatically after transmission.',
  },
  failure: {
    conflict:
      'The original operation conflicts with these inputs or its retained tombstone. Reconcile the exact original request in controlled external intake. Do not replace the UUID or try to reactivate a released request.',
    notFound:
      'The API could not find this hold request. This is not proof that no historical hold or activity existed.',
    verification:
      'Fresh single-use verification is required. Reenter the request and verify again; no old grant will be reused.',
    denied:
      'Legal access was denied. Private legal data was cleared. Recheck capabilities; your ordinary account session has not been signed out.',
    session:
      'The session must be checked again. No result was accepted and no write success is inferred from session loss.',
    unavailable: 'This legal endpoint is unavailable on this deployment. No result was accepted.',
    rateLimited:
      'The request was rate limited. Wait before another explicit attempt; nothing will retry automatically.',
    retryAfter:
      'The request was rate limited. Wait {seconds} seconds before another explicit attempt; nothing will retry automatically.',
    invalidRequest:
      'The legal inputs or continuation scope were rejected. Correct the inputs or explicitly start a new inquiry; no filter or cursor was silently removed.',
    invalidResponse:
      'The response was malformed, oversized, or inconsistent with this request. No result was accepted. Use an explicitly smaller page or inquiry scope, never an automatic retry.',
    service:
      'The legal service could not provide an audited result. No result was accepted; this is not an empty result or a promise of rollback.',
    unknown:
      'No legal result was accepted. Check availability before an explicit new attempt; nothing was retried.',
  },
} as const;

export const legalFa = {
  title: 'مسئول حفاظت از داده و امور حقوقی',
  introduction:
    'عملیات حقوقی محدود به هدف مشخص. سوابق رده B داده‌های شخصی مستعارسازی‌شده‌اند، نه داده‌های ناشناس. دسترسی برای بررسی، مجوز افشای اطلاعات به خارج از سامانه نیست.',
  denied:
    'هیچ عملیات حقوقی برای این نشست در دسترس نیست. غیرفعال بودن یک قابلیت مشخص نمی‌کند که مجوز وجود ندارد یا پیش‌نیازهای استقرار فراهم نیست. هیچ سابقه حقوقی درخواست نشده است.',
  sectionsLabel: 'بخش‌های فضای کاری حقوقی',
  sections: {
    holds: 'دستورهای نگهداشت حقوقی',
    preservation: 'حفظ پیشگیرانه',
    attribution: 'انتساب',
  },
  workspaceNotice:
    'فقط بخش انتخاب‌شده‌ای که مجوز آن را دارید بارگذاری می‌شود. هنگام باز شدن صفحه یا تایپ کردن، هیچ عملیات حقوقی اجرا نمی‌شود. خروج از بخش، پنهان شدن صفحه یا از دست رفتن مجوز، وضعیت خصوصی آن را پاک می‌کند. هیچ پیش‌نویسی در مرورگر ذخیره نمی‌شود و امکان خروجی گرفتن، بارگذاری یا انتقال به خارج وجود ندارد.',
  sectionNotice: {
    attribution:
      'یک نشانی ایمیل مشخص و یک بازه زمانی UTC را در سوابق نمایه‌شده دفتر ثبت که هم‌اکنون واجد شرایط‌اند جست‌وجو کنید. یک ایمیل ممکن است با شناسه‌های اصلی حساب‌های تاریخی متفاوتی مطابقت داشته باشد؛ آن‌ها را ادغام نکنید و هویت تأییدشده یک شخص در دنیای واقعی را از آن نتیجه نگیرید. خالی بودن صفحه یا رسیدن به صفحه آخر، نبود فعالیت تاریخی را اثبات نمی‌کند.',
    preservation:
      'درخواست حفظ پیشگیرانه پیش از صدور دستور را مستقل از گردش کار پرونده یا دستور کامل افشا ثبت کنید. تاریخ انقضای آن صرفاً برای بازبینی است و هرگز نگهداشت را خودکار لغو نمی‌کند. سابقه حفظ پیشگیرانه در بخش دستورهای نگهداشت حقوقی، بر اساس نوع درخواست، در دسترس است.',
    holds:
      'هر دستور نگهداشت حقوقی یا درخواست حفظ پیشگیرانه مستقل است و تا لغو صریح، بر قواعد مدت نگهداری اولویت دارد. لغو نگهداشت، محاسبه مدت‌های اصلی را از سر می‌گیرد و ممکن است داده‌ها بلافاصله واجد شرایط پاک‌سازی شوند. نگهداشت نمی‌تواند داده‌های پاک‌شده را برگرداند، مهلت بازیابی را تمدید کند یا نسخه‌ای تغییرناپذیر از شواهد ایجاد کند.',
  },
  buttons: {
    hold: 'اعمال دستور نگهداشت حقوقی',
    preservation: 'ثبت حفظ پیشگیرانه',
    lookup: 'آغاز استعلام انتساب',
    clearInquiry: 'پاک کردن استعلام',
    details: 'مشاهده جزئیات محدودشده',
    select: 'انتخاب شناسه اصلی',
    clearSelection: 'پاک کردن انتخاب',
    nextLookup: 'صفحه بعدی انتساب',
    closeDetails: 'بستن جزئیات',
    read: 'خواندن دستورهای نگهداشت حقوقی',
    clearRead: 'پاک کردن پرس‌وجوی نگهداشت',
    cancelRead: 'لغو خواندن نگهداشت',
    release: 'لغو نگهداشت درخواست',
    previous: 'صفحه قبلی نگهداشت',
    next: 'صفحه بعدی نگهداشت',
  },
  state: {
    releaseResume:
      'هدف قبلی پاک شد. پیش از تأیید هویت مجدد برای لغو نگهداشت، دستورهای نگهداشت حقوقی را بخوانید و دوباره ردیف درخواستی را که مجوز دسترسی به آن دارید انتخاب کنید.',
    lookupAccepted:
      '{count} سابقه نمایه‌شده در این صفحه پذیرفته شد. هر صفحه بعدی به تأیید هویت مجدد نیاز دارد.',
    confirmed:
      'پاسخ عملیات حقوقی تأیید شده است. فهرست به‌صورت خودکار بازخوانی نشد. برای مشاهده وضعیت فعلی، دستورهای نگهداشت حقوقی را صریحاً بخوانید.',
    expired:
      'اعتبار تأیید هویت منقضی شد. داده‌های خصوصی فرم پاک شدند. تأیید هویت مجدد را آغاز و درخواست اصلی را دوباره وارد کنید.',
    cancelled: 'گردش کار حقوقی پیش از ارسال لغو شد. وضعیت خصوصی آن پاک شد.',
    lookupUnconfirmed:
      'هیچ نتیجه انتسابی پذیرفته نشد. این به معنای نبود مطابقت نیست. استعلام جدید را صریحاً و با تأیید هویت مجدد آغاز کنید.',
    writeUnconfirmed:
      'نتیجه عملیات نوشتن حقوقی تأیید نشده است. هیچ تلاشی تکرار نشد و بازگردانی تغییرات نیز از این وضعیت استنباط نمی‌شود. پیش از تلاش مجدد و صریح، عملیات اصلی را با پرونده پذیرش کنترل‌شده خارج از سامانه تطبیق دهید.',
    inquiryCleared:
      'استعلام و صفحه فعلی پاک شدند. برای اجرای جدید، همه ورودی‌ها را دوباره وارد کنید.',
    cleared:
      'ورودی‌های خصوصی حقوقی، شناسه‌های اصلی، نتایج، UUIDهای عملیات، نشانگرهای ادامه و تأیید هویت پاک شدند. پیش از ادامه، نشست و دسترسی خود را دوباره بررسی کنید.',
  },
  outcome: {
    noRetry:
      'هیچ ارسال مجدد خودکاری انجام نشد. هیچ پیش‌نویس ماندگاری برای بازیابی در این مرورگر نگهداری نمی‌شود.',
    released:
      'نگهداشت درخواست <value>{id}</value> لغو شده است؛ این پاسخ شامل حالتی نیز می‌شود که قبلاً لغو شده باشد. این پاسخ اثبات نمی‌کند که این فراخواننده وضعیت را تغییر داده است. ممکن است نگهداشت‌های مستقل دیگری همچنان برقرار باشند.',
    replayed: 'درخواست موجود بازاجرا شد؛ وضعیت فعلی آن بازگردانده شد.',
    created: 'درخواست حقوقی جدید ایجاد شد.',
    alreadyReleased: 'نگهداشت این درخواست قبلاً لغو شده است؛ بازاجرا آن را دوباره فعال نکرد.',
    observedAt: 'زمان مشاهده: <time></time>',
    presence: 'وجود رکورد حساب: {account}. وجود محتوای دفتر ثبت: {ledger}.',
    presenceNotice:
      'وجود حساب شامل رکوردهای حذف نرم‌شده نیز می‌شود. وجود محتوا ممکن است شامل سوابق نمایه‌نشده یا منقضی‌شده باشد و چیزی درباره کامل بودن آن‌ها نمی‌گوید. حتی اگر هر دو مشاهده منفی باشند، نگهداشت معتبر است.',
    transactionNotice:
      'جست‌وجو و ایجاد نگهداشت دو تراکنش جداگانه‌اند. این پاسخ تضمین نمی‌کند که همه شواهد نمایش‌داده‌شده قبلی تا زمان ثبت نهایی این نگهداشت باقی مانده باشند.',
    listingUnavailable:
      'مشاهده فهرست برای این نشست در دسترس نیست. لغو نگهداشت به یک ردیف فهرست با دسترسی مجاز نیاز دارد؛ هیچ جست‌وجوی نمایه حساب یا هدف استنباط‌شده‌ای استفاده نمی‌شود.',
  },
  attribution: {
    title: 'صفحه فعلی انتساب',
    scope: 'بازه ثابت UTC: از <start></start> تا <end></end>. اندازه صفحه: {size}.',
    highWater: 'حد بالای شماره توالی: <value>{sequence}</value>.',
    observedAt: 'زمان مشاهده اولیه: <time></time>.',
    checkedAt: 'زمان بررسی شرایط: <time></time>.',
    empty:
      'در این صفحه و این محدوده، هیچ سابقه نمایه‌شده مطابقی که هم‌اکنون واجد شرایط باشد بازگردانده نشد. این نتیجه، نبود فعالیت، نبود حساب یا کامل بودن تاریخچه را اثبات نمی‌کند.',
    region: 'نتایج انتساب، با امکان پیمایش افقی',
    caption:
      'داده‌های شخصی مستعارسازی‌شده به ترتیب صعودی شماره توالی؛ نه شواهد تأییدشده درج در دفتر ثبت',
    missingField: 'در فیلدهای بازگردانده‌شده این پاسخ موجود نیست',
    selected: 'شناسه اصلی انتخاب‌شده: <value>{id}</value>.',
    selectionNotice:
      'این انتخاب فقط یک شناسه اصلی را منتقل می‌کند؛ نه اثباتی بر وجود کنونی حساب است و نه نشان می‌دهد چه کسی مالک آن بوده است. هر عملیات مستقل را با تأیید هویت مجدد تأیید کنید.',
    final: 'نشانگر ادامه‌ای بازگردانده نشد. این نتیجه به معنای کامل بودن تاریخچه نیست.',
    coverageNotice:
      'فقط همین صفحه نگهداری می‌شود؛ نه حافظه نهانی صفحه‌های قبلی وجود دارد و نه دریافت یکجای همه نتایج. وضعیت کنونی نگهداری و نگهداشت‌ها در هر صفحه دوباره بررسی می‌شود؛ لغو نگهداشت ممکن است مطابقت‌های منقضی‌شده را حذف کند. داده‌هایی که بعداً با شماره توالی بالاتر از حد وارد شوند، خارج از این اجرا هستند. برای نشانگر ادامه، انقضای مبتنی بر عمر اعلام نشده و شمارش معکوسی از آن استنباط نمی‌شود. این پوشش تضمین نمی‌کند که همه نسل‌های تاریخی کلید محرمانه نمایه‌سازی (pepper) قابل جست‌وجو باشند. نبود فراداده انتخاب‌شده اثبات نمی‌کند که آن داده هرگز وجود نداشته است.',
  },
  evidence: {
    original: 'یادداشت اصلی سرور (بدون تغییر)',
    unknown:
      'این یادداشت سرور از توضیحات ثابت شناخته‌شده نیست. متن آن در ادامه بدون تغییر نمایش داده می‌شود؛ هیچ ترجمه یا ادعایی درباره کامل بودن از آن استنباط نمی‌شود.',
    preservation:
      'حفظ پیشگیرانه، داده‌های پاک‌سازی‌شده را بازنمی‌گرداند. ممکن است ورود داده‌ها هنوز در انتظار انجام باشد. وجود حساب و محتوای دفتر ثبت صرفاً مشاهده است، نه تضمین کامل بودن. تاریخ <field>expires_at</field> فقط جنبه توصیه‌ای برای بازبینی دارد و نگهداشت را خودکار لغو نمی‌کند.',
    coverage:
      'پوشش فقط شامل سوابق نگهداری‌شده و نمایه‌شده‌ای است که مطابقت دارند. ممکن است ورود داده‌ها هنوز در انتظار انجام باشد. تاریخچه نمایه‌نشده یا پاک‌سازی‌شده در این پوشش نیست. شناسه‌های اصلی حساب‌های جداگانه ثابت نمی‌کنند که آن حساب‌ها متعلق به یک شخص هستند.',
  },
  details: {
    title: 'جزئیات محدودشده درخواست حقوقی',
    description:
      'شرح‌های دارای دسترسی محدود به‌صورت متن غیرقابل‌اجرا نمایش داده می‌شوند. نبود جزئیات پاک‌سازی‌شده به معنای خالی بودن مقادیر اصلی نیست.',
    purged: 'جزئیات محدودشده پاک‌سازی شده‌اند. مقادیر اصلی در دسترس نیستند.',
  },
  fields: {
    requestKind: 'نوع درخواست',
    holdId: 'UUID درخواست نگهداشت',
    accountRef: 'شناسه اصلی حساب',
    status: 'وضعیت',
    appliedBy: 'اعمال‌کننده (شناسه غیرقابل تفسیر)',
    releasedBy: 'لغوکننده (شناسه غیرقابل تفسیر)',
    appliedAt: 'زمان اعمال (UTC)',
    advisoryReviewAt: 'زمان پیشنهادی بازبینی (UTC)',
    releasedAt: 'زمان لغو نگهداشت (UTC)',
    reason: 'دلیل',
    requestingAuthority: 'مرجع درخواست‌کننده',
    legalBasis: 'مبنای قانونی',
    eventRef: 'شناسه رویداد',
    eventType: 'نوع رویداد',
    eventTime: 'زمان رویداد (UTC)',
    retainUntil: 'نگهداری تا (UTC)',
    sequence: 'شماره توالی',
    selection: 'انتخاب شناسه اصلی',
    holdStatus: 'وضعیت نگهداشت',
    size: 'اندازه صفحه',
    applied: 'اعمال (UTC)',
    review: 'بازبینی پیشنهادی (UTC)',
    released: 'لغو نگهداشت (UTC)',
    actors: 'شناسه‌های عاملان',
    actions: 'عملیات',
    requestId: 'UUID عملیات',
    identifier: 'ایمیل برای انتساب',
    transientEmail: 'ایمیل ورودی موقت (نه مدرک)',
    caseReference: 'شناسه پرونده',
    purpose: 'هدف استعلام',
    startTime: 'زمان آغاز (UTC)',
    endTime: 'زمان پایان (UTC)',
    disclosure: 'فیلدهای افشای اضافی',
    reviewAt: 'زمان بازبینی (UTC)',
    expiresAt: 'زمان انقضا (UTC)',
  },
  disclosure: {
    client_ip: 'نشانی IP کارخواه',
    ip_subnet: 'زیرشبکه IP',
    user_agent: 'عامل کاربر',
    device_fingerprint: 'اثر انگشت دستگاه',
    client_id: 'شناسه کارخواه',
    scope: 'دامنه دسترسی',
  },
  values: {
    hold: 'دستور نگهداشت حقوقی',
    preservation: 'حفظ پیشگیرانه',
    preservationRequest: 'درخواست حفظ پیشگیرانه',
    active: 'فعال',
    released: 'لغوشده',
    all: 'همه',
    yes: 'بله',
    no: 'خیر',
    notRecorded: 'ثبت نشده',
    notReturned: 'بازگردانده نشده',
    notSupplied: 'ارائه نشده',
    coreOnly: 'هیچ‌کدام (فقط فراداده اصلی)',
    serverFixed: '<value>{kind}</value> (مقدار ثابت سرور)',
  },
  read: {
    title: 'خواندن درخواست‌های مستقل',
    initial:
      'یک شناسه اصلی را انتخاب کنید یا همه شناسه‌های اصلی را صریحاً انتخاب کنید، سپس بخوانید. هنوز هیچ درخواستی اجرا نشده است.',
    changed: 'فیلترها تغییر کردند. برای مشاهده وضعیت جدید، صریحاً درخواست خواندن بدهید.',
    loading: 'در حال خواندن یک صفحه محدود از دستورهای نگهداشت حقوقی…',
    accepted:
      '{count} درخواست در این صفحه. مجموع {total} در نمای لحظه‌ای این پاسخ؛ این شمارش، فهرست ثابت چندصفحه‌ای نیست.',
    invalid:
      'یک شناسه اصلی حساب با قالب استاندارد و غیرصفر وارد کنید یا همه شناسه‌های اصلی را صریحاً انتخاب کنید؛ اندازه صفحه نیز باید از 1 تا {max} باشد. ورودی نامعتبر هرگز به پرس‌وجوی همه اشخاص تبدیل نمی‌شود.',
    allReferences: 'همه شناسه‌های اصلی',
    filterHelp:
      'این شناسه همان <id>users.id</id> اصلی است که پس از حذف نیز مستقل نگهداری می‌شود. خواندن اطلاعات همه اشخاص باید صریح باشد و به حداکثر {max} درخواست در هر صفحه محدود است. هیچ مجوزی برای مرور نمایه حساب‌ها اعطا نمی‌شود.',
    empty:
      'در این صفحه با فیلترهای ارسال‌شده، هیچ درخواستی بازگردانده نشد. این نه پاسخ «درخواست یافت نشد» از API است و نه اثبات نبود نگهداشت در گذشته.',
    region: 'دستورهای نگهداشت حقوقی، با امکان پیمایش افقی',
    caption: 'دستورهای مستقل نگهداشت حقوقی و درخواست‌های حفظ پیشگیرانه',
    appliedBy: 'اعمال‌کننده: <value>{id}</value>',
    releasedBy: 'لغوکننده: <value>{id}</value>',
    pagination: 'صفحه‌بندی دستورهای نگهداشت حقوقی بر اساس آفست',
    snapshot: 'آفست {offset}؛ {count} از {total} در نمای لحظه‌ای این پاسخ.',
  },
  action: {
    titles: {
      hold: 'اعمال دستور نگهداشت حقوقی',
      preservation: 'ثبت حفظ پیشگیرانه',
      release: 'لغو درخواست نگهداشت حقوقی',
      lookup: 'استعلام انتساب',
    },
    confirmations: {
      hold: 'تأیید نگهداشت حقوقی',
      preservation: 'تأیید حفظ پیشگیرانه',
      release: 'تأیید لغو نگهداشت',
      lookup: 'تأیید جست‌وجو',
    },
    invalidLookup:
      'فقط نشانی ایمیل با حداکثر 320 بایت UTF-8، مرجع و شناسه پرونده هرکدام 1 تا 255 بایت، هدف 1 تا 4096 بایت، مرزهای صریح و مرتب RFC3339 در UTC در محدوده زمانی پیکربندی‌شده و اندازه صفحه مجاز را وارد کنید.',
    invalidCreate:
      'UUIDهای استاندارد و غیرصفر، دلیل با 1 تا 4096 بایت UTF-8، مرجع و مبنای قانونی در موارد الزامی با 1 تا 255 بایت و در صورت نیاز تاریخ RFC3339 در UTC با حداکثر شش رقم اعشار وارد کنید. شرح خالی معتبر نیست.',
    description:
      'ابتدا هویت خود را تأیید کنید، سپس عملیات حقوقی دقیق را بازبینی و صریحاً تأیید کنید. تأیید هویت یک‌بارمصرف است و منقضی می‌شود. لغو یا خروج از این گردش کار، داده‌های حساس آن را پاک می‌کند.',
    sending: 'در حال ارسال یک درخواست حقوقی. دوباره ارسال نکنید.',
    verified: 'تأیید هویت کامل شد. پیش از انقضای اعتبار آن، درخواست را بازبینی و تأیید کنید.',
    expiry:
      'اعتبار تأیید هویت یک‌بارمصرف در <time></time> منقضی می‌شود. انقضا فرم را پاک می‌کند و به تأیید هویت مجدد نیاز دارد.',
    prepare: 'آماده‌سازی درخواست حقوقی',
    createHelp:
      'از <id>account_ref</id> اصلی پرونده پذیرش کنترل‌شده استفاده کنید، نه ایمیل یا جست‌وجوی نمایه. UUID عملیات و ورودی‌های دقیق نرمال‌شده را در همان پرونده خارج از سامانه ثبت کنید. مرورگر UUID تولید نمی‌کند و پیش‌نویس بازیابی نگه نمی‌دارد. دلیل: 1 تا 4096 بایت UTF-8؛ مرجع و مبنای قانونی: 1 تا 255 بایت. تاریخ اختیاری: RFC3339 در UTC با پسوند Z و حداکثر شش رقم اعشار؛ تاریخ گذشته مجاز است. تاریخ‌ها هرگز نگهداشت را خودکار لغو نمی‌کنند.',
    lookupHelp:
      'فقط نشانی ایمیل با حداکثر 320 بایت UTF-8؛ مرجع و شناسه پرونده هرکدام 1 تا 255 بایت؛ هدف 1 تا 4096 بایت. مرزهای صریح RFC3339 در UTC با پسوند Z وارد کنید. حداکثر بازه: {seconds} ثانیه. اندازه صفحه: 1 تا {max}. در اینجا هیچ نرمال‌سازی اختصاصی ارائه‌دهنده ایمیل انجام نمی‌شود.',
    disclosure: 'افشای اضافی برای هدف این استعلام',
    disclosureHelp:
      'در ابتدا هیچ فیلد اختیاری انتخاب نشده است. فقط فراداده پشتیبانی‌شده‌ای درخواست می‌شود که صریحاً انتخاب شده باشد.',
    review: 'بازبینی درخواست',
    confirm: 'تأیید درخواست حقوقی',
    releaseWarning:
      'لغو نگهداشت فقط بر این UUID تغییرناپذیر درخواست اثر می‌گذارد. ممکن است نگهداشت‌های دیگری باقی بمانند. محاسبه مدت‌های اصلی نگهداری از سر گرفته می‌شود و ممکن است در پاک‌سازی بعدی، داده‌ها بلافاصله واجد شرایط حذف باشند؛ لغو نگهداشت هرگز مدت نگهداری را از نو آغاز نمی‌کند. پاسخ 204 شامل درخواست ازپیش‌لغوشده نیز هست و اثبات نمی‌کند که این فراخواننده وضعیت را تغییر داده است.',
    lookupWarning:
      'سوابق رده B داده‌های شخصی مستعارسازی‌شده‌اند، نه ناشناس. مطابقت در نمایه به معنای هویت تأییدشده در دنیای واقعی یا مجوز افشای اطلاعات به خارج از سامانه نیست. موقعیت شماره توالی، اثبات درج در دفتر ثبت نیست. این درخواست فقط برای یک صفحه است.',
    createWarning:
      'هر درخواست مستقل است. نگهداشت‌ها تا لغو صریح بر قواعد مدت نگهداری اولویت دارند؛ تاریخ‌های بازبینی و انقضا صرفاً توصیه‌ای‌اند. نگهداشت نمی‌تواند داده‌های پاک‌شده را بازگرداند، مهلت بازیابی حساب را تمدید کند یا نسخه‌ای تغییرناپذیر از شواهد بسازد.',
    idempotencyWarning:
      'یکسان‌اثری تکرار درخواست به شناسه اصلی، نوع درخواست و UUID محدود است، نه به عامل یا یک UUID سراسری. تغییر هدف یا نوع، نگهداشت مستقل دیگری ایجاد می‌کند. بازاجرای دقیق ممکن است درخواستی ازپیش‌لغوشده را بازگرداند و هرگز آن را دوباره فعال نمی‌کند؛ اگر فقط رکورد نشانه باقی مانده و شرح آن پاک‌سازی شده باشد، به‌جای ایجاد دوباره، تعارض گزارش می‌شود. پیش از تأیید، این مجموعه دقیق مقادیر نرمال‌شده را در پرونده پذیرش کنترل‌شده خارج از سامانه حفظ کنید.',
    acknowledgeCreate: 'هدف، UUID عملیات، نوع درخواست و ورودی‌های نرمال‌شده را بازبینی کرده‌ام.',
    acknowledgeRelease: 'UUID این درخواست نگهداشت و پیامدهای لغو آن را بازبینی کرده‌ام.',
    acknowledgeLookup: 'هدف استعلام، محدوده ثابت و فیلدهای افشای انتخاب‌شده را بازبینی کرده‌ام.',
    submitting: 'در حال ارسال درخواست حقوقی…',
    frozen:
      'ورودی‌ها اکنون تثبیت شده‌اند. برای تغییر هدف یا محدوده، لغو کنید و تأیید هویت مجدد را آغاز کنید. پس از ارسال، هیچ تلاشی خودکار تکرار نمی‌شود.',
  },
  failure: {
    conflict:
      'عملیات اصلی با این ورودی‌ها یا رکورد نشانه باقی‌مانده آن تعارض دارد. درخواست اصلی دقیق را با پرونده پذیرش کنترل‌شده خارج از سامانه تطبیق دهید. UUID را جایگزین نکنید و برای فعال کردن دوباره درخواست لغوشده تلاش نکنید.',
    notFound:
      'API نتوانست این درخواست نگهداشت را پیدا کند. این نتیجه اثبات نمی‌کند که در گذشته نگهداشت یا فعالیتی وجود نداشته است.',
    verification:
      'تأیید هویت مجدد و یک‌بارمصرف لازم است. درخواست را دوباره وارد و هویت خود را دوباره تأیید کنید؛ هیچ مجوز موقت قدیمی دوباره استفاده نمی‌شود.',
    denied:
      'دسترسی حقوقی رد شد. داده‌های خصوصی حقوقی پاک شدند. قابلیت‌ها را دوباره بررسی کنید؛ نشست عادی حساب شما بسته نشده است.',
    session:
      'نشست باید دوباره بررسی شود. هیچ نتیجه‌ای پذیرفته نشد و از دست رفتن نشست، دلیلی بر موفقیت عملیات نوشتن نیست.',
    unavailable: 'این نقطه پایانی حقوقی در این استقرار در دسترس نیست. هیچ نتیجه‌ای پذیرفته نشد.',
    rateLimited:
      'درخواست با محدودیت نرخ روبه‌رو شد. پیش از تلاش صریح بعدی صبر کنید؛ هیچ تلاشی خودکار تکرار نمی‌شود.',
    retryAfter:
      'درخواست با محدودیت نرخ روبه‌رو شد. پیش از تلاش صریح بعدی {seconds} ثانیه صبر کنید؛ هیچ تلاشی خودکار تکرار نمی‌شود.',
    invalidRequest:
      'ورودی‌های حقوقی یا محدوده ادامه رد شدند. ورودی‌ها را اصلاح کنید یا استعلام جدیدی را صریحاً آغاز کنید؛ هیچ فیلتر یا نشانگر ادامه‌ای بی‌اطلاع حذف نشده است.',
    invalidResponse:
      'پاسخ بدقالب، بیش از حد بزرگ یا ناسازگار با این درخواست بود. هیچ نتیجه‌ای پذیرفته نشد. صریحاً صفحه یا محدوده استعلام کوچک‌تری انتخاب کنید؛ هرگز تلاش خودکار را جایگزین نکنید.',
    service:
      'سرویس حقوقی نتوانست نتیجه‌ای همراه با ثبت ممیزی ارائه کند. هیچ نتیجه‌ای پذیرفته نشد؛ این نه نتیجه خالی است و نه تضمین بازگردانی تغییرات.',
    unknown:
      'هیچ نتیجه حقوقی پذیرفته نشد. پیش از تلاش جدید و صریح، در دسترس بودن سرویس را بررسی کنید؛ هیچ تلاشی تکرار نشد.',
  },
} as const satisfies CatalogShape<typeof legalEn>;
