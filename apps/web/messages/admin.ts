import type { CatalogShape } from '../i18n/types';

export const adminEn = {
  metadata: {
    accounts: 'Admin Accounts',
    title: 'Admin control panel | Hatef Identity',
    template: '%s | Hatef Identity',
  },
  overview: {
    title: 'Admin control panel',
    description:
      'Elevated access is limited to your current permissions. Reads and actions are durably audited; access is checked again by the API on every operation.',
    workspaces: 'Available workspaces',
    accounts: 'Accounts',
    accountsDescription: 'Read permitted account metadata and review available status actions.',
    audit: 'Audit logs',
    auditDescription: 'Search a bounded UTC window. Every disclosed page is audited.',
    integrity: 'Integrity',
    integrityDescription: 'Verify audit or security-ledger links in explicit, bounded pages.',
    legal: 'DPO and Legal',
    legalDescription:
      'Manage independent Legal Holds, preservation requests, and bounded attribution inquiries.',
    clearing:
      'Private results and drafts are cleared when this page is backgrounded or left. Return to revalidate access. No operation, search, or verification continues automatically in the background.',
  },
  statuses: {
    active: 'Active',
    suspended: 'Suspended',
    banned: 'Banned',
    pending_verification: 'Pending verification',
    pending_deletion: 'Pending deletion',
  },
  accounts: {
    title: 'Accounts',
    description:
      'Read bounded account pages and review individual accounts. Each disclosure is audited.',
    denied: 'This workspace does not grant account-read access. No accounts were requested.',
    initial: 'Apply filters to load a bounded account page.',
    changed: 'Inputs changed. Submit an explicit query to load results.',
    lookingUp: 'Looking up the exact email...',
    loading: 'Loading accounts...',
    matchesLoaded:
      '{count, plural, one {# matching account loaded.} other {# matching accounts loaded.}}',
    pageLoaded:
      '{count, plural, one {# account on this page loaded.} other {# accounts on this page loaded.}}',
    sizeError: 'Enter a whole page size from 1 to {maximum, number}.',
    emailError: 'Enter one complete email address. The canonical address must fit 254 UTF-8 bytes.',
    canonicalEmail: 'Canonical email: <value>{email}</value>',
    directory: 'Account directory',
    filter: 'Filter accounts',
    accountStatus: 'Account status',
    allStatuses: 'All statuses',
    pageSize: 'Page size',
    apply: 'Apply filters',
    sizeHelp:
      'Up to {maximum, number} accounts per page. Only the current page is retained in memory.',
    safeMetadata: 'This workspace lists safe account metadata only.',
    lookup: 'Exact email lookup',
    email: 'Exact email',
    find: 'Find account',
    clear: 'Clear lookup',
    lookupCleared: 'Lookup query and result cleared.',
    emailHelp:
      'Explicit exact matching only. The address is sent in the request body, never in the URL; no search runs while typing.',
    cancelled: 'Account request cancelled. No result was accepted.',
    cancel: 'Cancel account request',
    resultsRegion: 'Account results, horizontally scrollable',
    lookupResult: 'Exact email lookup result',
    results: 'Account results',
    reference: 'Account reference',
    status: 'Status',
    emailColumn: 'Email',
    created: 'Created (UTC)',
    view: 'View account {id}',
    notProvided: 'Not provided',
    noMatch: 'No account matched the exact email.',
    empty: 'No accounts returned on this page for the selected status.',
    pagination: 'Account pagination',
    previous: 'Previous page',
    next: 'Next page',
    range: '{start, number}-{end, number} of {total, number} matching accounts',
    emptyRange: '0 of {total, number} matching accounts',
    offsetLimit:
      'The offset limit has been reached. Narrow the status filter or use an authorized exact lookup.',
  },
  detail: {
    title: 'Account details',
    description:
      'Only metadata permitted for this session is shown. Every account read and status action is audited.',
    back: 'Back to accounts',
    unavailable: 'Account access is not available for this session.',
    invalidReference: 'Invalid account reference.',
    loading: 'Loading account...',
    confirmedLoading: 'Status change confirmed. Loading current account state...',
    loaded: 'Current account state loaded.',
    confirmedLoaded: 'Status change confirmed. Current account state loaded.',
    pendingUnavailable: 'The pending action is no longer available. Review current account state.',
    confirmedRefreshFailed: 'Status change confirmed, but refreshing the current account failed.',
    checking: 'Checking current account state before verification...',
    changed: 'The account changed. Review the updated state before choosing a new action.',
    conflict:
      'The account changed. Read current state, review it, and start a new action with fresh verification. No status change was confirmed.',
    expired:
      'Verification expired. The reason was cleared. Start a new action with fresh verification.',
    denied: 'The status change was not permitted. No change was confirmed.',
    status: 'Status',
    revision: 'Lifecycle revision',
    email: 'Email',
    mfa: 'MFA enabled',
    yes: 'Yes',
    no: 'No',
    created: 'Created',
    updated: 'Updated',
    deleted: 'Deletion recorded',
    actions: 'Status actions',
    ineligible: 'This account is not eligible for a status change.',
    requirements:
      'Every action requires fresh verification, a reason, and final confirmation. Restrictions do not expire automatically.',
    read: 'Read current state',
  },
  moderation: {
    actions: { active: 'Reactivate', suspended: 'Suspend', banned: 'Ban' },
    titles: { active: 'Reactivate account', suspended: 'Suspend account', banned: 'Ban account' },
    confirm: { active: 'Confirm reactivate', suspended: 'Confirm suspend', banned: 'Confirm ban' },
    account: 'Account <reference>{id}</reference>',
    statuses:
      'Current status: <current>{currentStatus}</current>. Proposed status: <proposed>{proposedStatus}</proposed>.',
    consequences:
      'Suspension and ban remain until explicit restoration. They are not erasure and do not prevent re-registration. Subsequent live credential checks reject old credentials; already admitted requests and offline JWT consumers may retain bounded residual access. Reactivation never restores old credentials.',
    instructions:
      'Verify first, then enter the reason and explicitly confirm. Cancel before sending to make no change.',
    sending: 'Sending status change. Do not submit again.',
    verified:
      'Verification complete. Enter a reason and review the final confirmation before verification expires.',
    checking: 'Verification complete. Checking the pinned account before final confirmation.',
    form: 'Confirm account status change',
    review:
      'Confirm <current>{currentStatus}</current> to <proposed>{proposedStatus}</proposed> for the account above, at revision <revision>{revisionValue}</revision>.',
    expires:
      'Single-use verification expires at <deadline></deadline>. Expiry or leaving this page clears the reason and requires fresh verification.',
    reason: 'Moderation reason',
    reasonHelp:
      'Required for every action. At most 2,000 UTF-8 bytes; avoid unnecessary personal information.',
    reasonError: 'Enter a reason using no more than 2,000 UTF-8 bytes.',
    acknowledged:
      'I reviewed the account, current status, new status, and consequences of this action.',
    submitting: 'Submitting status change...',
  },
} as const;

export const adminFa = {
  metadata: {
    accounts: 'مدیریت حساب‌ها',
    title: 'پنل مدیریت | هویت هاتف',
    template: '%s | هویت هاتف',
  },
  overview: {
    title: 'پنل مدیریت',
    description:
      'دسترسی مدیریتی به مجوزهای فعلی شما محدود است. مشاهده‌ها و اقدامات در سوابق ممیزی به‌صورت پایدار ثبت می‌شوند؛ API در هر عملیات، دسترسی را دوباره بررسی می‌کند.',
    workspaces: 'بخش‌های در دسترس',
    accounts: 'حساب‌ها',
    accountsDescription:
      'فرادادهٔ مجاز حساب‌ها را مشاهده کنید و اقدامات قابل انجام برای تغییر وضعیت را بررسی کنید.',
    audit: 'سوابق ممیزی',
    auditDescription:
      'در یک بازهٔ محدود بر اساس UTC جست‌وجو کنید. ارائهٔ هر صفحه از نتایج در سوابق ممیزی ثبت می‌شود.',
    integrity: 'تمامیت داده‌ها',
    integrityDescription:
      'پیوندهای زنجیرهٔ ممیزی یا دفتر ثبت امنیتی را در صفحه‌های محدود و با اقدام صریح بررسی کنید.',
    legal: 'حفاظت از داده‌ها و امور حقوقی',
    legalDescription:
      'دستورهای مستقل نگهداشت قانونی، درخواست‌های حفظ داده و استعلام‌های انتساب محدود را مدیریت کنید.',
    clearing:
      'با رفتن این صفحه به پس‌زمینه یا ترک آن، نتایج خصوصی و پیش‌نویس‌ها پاک می‌شوند. پس از بازگشت، دسترسی دوباره اعتبارسنجی می‌شود. هیچ عملیات، جست‌وجو یا بررسی‌ای به‌طور خودکار در پس‌زمینه ادامه نمی‌یابد.',
  },
  statuses: {
    active: 'فعال',
    suspended: 'تعلیق‌شده',
    banned: 'مسدودشده',
    pending_verification: 'در انتظار تأیید',
    pending_deletion: 'در انتظار حذف',
  },
  accounts: {
    title: 'حساب‌ها',
    description:
      'صفحه‌های محدود حساب‌ها را مشاهده و هر حساب را جداگانه بررسی کنید. هر بار ارائهٔ داده در سوابق ممیزی ثبت می‌شود.',
    denied: 'این بخش مجوز مشاهدهٔ حساب‌ها را در اختیار شما نمی‌گذارد. هیچ حسابی درخواست نشد.',
    initial: 'برای بارگیری یک صفحهٔ محدود از حساب‌ها، فیلترها را اعمال کنید.',
    changed: 'ورودی‌ها تغییر کردند. برای بارگیری نتایج، درخواست جست‌وجو را صریحاً ارسال کنید.',
    lookingUp: 'در حال جست‌وجوی ایمیل دقیق...',
    loading: 'در حال بارگیری حساب‌ها...',
    matchesLoaded:
      '{count, plural, one {# حساب منطبق بارگیری شد.} other {# حساب منطبق بارگیری شد.}}',
    pageLoaded:
      '{count, plural, one {# حساب در این صفحه بارگیری شد.} other {# حساب در این صفحه بارگیری شد.}}',
    sizeError: 'تعداد حساب‌های هر صفحه را به‌صورت عدد صحیح از ۱ تا {maximum, number} وارد کنید.',
    emailError: 'یک نشانی ایمیل کامل وارد کنید. نشانی استاندارد باید حداکثر ۲۵۴ بایت UTF-8 باشد.',
    canonicalEmail: 'ایمیل استاندارد: <value>{email}</value>',
    directory: 'فهرست حساب‌ها',
    filter: 'فیلتر حساب‌ها',
    accountStatus: 'وضعیت حساب',
    allStatuses: 'همهٔ وضعیت‌ها',
    pageSize: 'تعداد در هر صفحه',
    apply: 'اعمال فیلترها',
    sizeHelp: 'حداکثر {maximum, number} حساب در هر صفحه. فقط صفحهٔ فعلی در حافظه نگه داشته می‌شود.',
    safeMetadata: 'این بخش فقط فرادادهٔ محدود و مجاز حساب‌ها را فهرست می‌کند.',
    lookup: 'جست‌وجوی ایمیل دقیق',
    email: 'ایمیل دقیق',
    find: 'یافتن حساب',
    clear: 'پاک کردن جست‌وجو',
    lookupCleared: 'ورودی و نتیجهٔ جست‌وجو پاک شدند.',
    emailHelp:
      'تطبیق دقیق، فقط با اقدام صریح انجام می‌شود. نشانی در بدنهٔ درخواست ارسال می‌شود و هرگز در URL قرار نمی‌گیرد؛ هنگام تایپ جست‌وجویی انجام نمی‌شود.',
    cancelled: 'درخواست حساب لغو شد. هیچ نتیجه‌ای پذیرفته نشد.',
    cancel: 'لغو درخواست حساب',
    resultsRegion: 'نتایج حساب‌ها، با امکان پیمایش افقی',
    lookupResult: 'نتیجهٔ جست‌وجوی ایمیل دقیق',
    results: 'نتایج حساب‌ها',
    reference: 'شناسهٔ مرجع حساب',
    status: 'وضعیت',
    emailColumn: 'ایمیل',
    created: 'زمان ایجاد (UTC)',
    view: 'مشاهدهٔ حساب {id}',
    notProvided: 'ارائه نشده',
    noMatch: 'هیچ حسابی با ایمیل دقیق مطابقت نداشت.',
    empty: 'برای وضعیت انتخاب‌شده، هیچ حسابی در این صفحه بازگردانده نشد.',
    pagination: 'صفحه‌بندی حساب‌ها',
    previous: 'صفحهٔ قبل',
    next: 'صفحهٔ بعد',
    range: '{start, number} تا {end, number} از {total, number} حساب منطبق',
    emptyRange: '۰ از {total, number} حساب منطبق',
    offsetLimit:
      'به سقف جابه‌جایی در نتایج رسیده‌اید. فیلتر وضعیت را محدودتر کنید یا با مجوز لازم، جست‌وجوی دقیق انجام دهید.',
  },
  detail: {
    title: 'جزئیات حساب',
    description:
      'فقط فرادادهٔ مجاز برای این نشست نمایش داده می‌شود. هر مشاهدهٔ حساب و اقدام تغییر وضعیت در سوابق ممیزی ثبت می‌شود.',
    back: 'بازگشت به حساب‌ها',
    unavailable: 'دسترسی به حساب‌ها برای این نشست فراهم نیست.',
    invalidReference: 'شناسهٔ مرجع حساب نامعتبر است.',
    loading: 'در حال بارگیری حساب...',
    confirmedLoading: 'تغییر وضعیت تأیید شد. در حال بارگیری وضعیت فعلی حساب...',
    loaded: 'وضعیت فعلی حساب بارگیری شد.',
    confirmedLoaded: 'تغییر وضعیت تأیید شد. وضعیت فعلی حساب بارگیری شد.',
    pendingUnavailable: 'اقدام در انتظار، دیگر در دسترس نیست. وضعیت فعلی حساب را بررسی کنید.',
    confirmedRefreshFailed: 'تغییر وضعیت تأیید شد، اما دریافت وضعیت فعلی حساب ناموفق بود.',
    checking: 'در حال بررسی وضعیت فعلی حساب پیش از تأیید هویت...',
    changed: 'حساب تغییر کرده است. پیش از انتخاب اقدام جدید، وضعیت به‌روز را بررسی کنید.',
    conflict:
      'حساب تغییر کرده است. وضعیت فعلی را دریافت و بررسی کنید، سپس با تأیید هویت مجدد اقدام تازه‌ای را آغاز کنید. هیچ تغییر وضعیتی تأیید نشد.',
    expired:
      'اعتبار تأیید هویت منقضی شد. دلیل واردشده پاک شد. با تأیید هویت مجدد اقدام تازه‌ای را آغاز کنید.',
    denied: 'تغییر وضعیت مجاز نبود. هیچ تغییری تأیید نشد.',
    status: 'وضعیت',
    revision: 'نسخهٔ چرخهٔ عمر',
    email: 'ایمیل',
    mfa: 'احراز هویت چندعاملی فعال است',
    yes: 'بله',
    no: 'خیر',
    created: 'زمان ایجاد',
    updated: 'زمان به‌روزرسانی',
    deleted: 'زمان ثبت حذف',
    actions: 'اقدامات تغییر وضعیت',
    ineligible: 'این حساب واجد شرایط تغییر وضعیت نیست.',
    requirements:
      'هر اقدام به تأیید هویت مجدد، درج دلیل و تأیید نهایی نیاز دارد. محدودیت‌ها به‌طور خودکار پایان نمی‌یابند.',
    read: 'دریافت وضعیت فعلی',
  },
  moderation: {
    actions: { active: 'فعال‌سازی مجدد', suspended: 'تعلیق', banned: 'مسدودسازی' },
    titles: { active: 'فعال‌سازی مجدد حساب', suspended: 'تعلیق حساب', banned: 'مسدودسازی حساب' },
    confirm: {
      active: 'تأیید فعال‌سازی مجدد',
      suspended: 'تأیید تعلیق',
      banned: 'تأیید مسدودسازی',
    },
    account: 'حساب <reference>{id}</reference>',
    statuses:
      'وضعیت فعلی: <current>{currentStatus}</current>. وضعیت پیشنهادی: <proposed>{proposedStatus}</proposed>.',
    consequences:
      'تعلیق و مسدودسازی تا رفع صریح محدودیت باقی می‌مانند. این اقدامات به معنای حذف داده‌ها نیستند و مانع ثبت‌نام مجدد نمی‌شوند. بررسی‌های بعدی اعتبارنامه در سامانه، اعتبارنامه‌های قبلی را رد می‌کنند؛ درخواست‌هایی که قبلاً پذیرفته شده‌اند و مصرف‌کنندگان آفلاین JWT ممکن است برای مدتی محدود همچنان دسترسی داشته باشند. فعال‌سازی مجدد هرگز اعتبارنامه‌های قبلی را بازنمی‌گرداند.',
    instructions:
      'ابتدا هویت خود را تأیید کنید، سپس دلیل را وارد کنید و صریحاً تأیید نهایی را انجام دهید. با لغو پیش از ارسال، تغییری انجام نمی‌شود.',
    sending: 'در حال ارسال تغییر وضعیت. دوباره ارسال نکنید.',
    verified:
      'تأیید هویت انجام شد. پیش از انقضای اعتبار آن، دلیل را وارد کنید و تأیید نهایی را بررسی کنید.',
    checking: 'تأیید هویت انجام شد. در حال بررسی حساب تثبیت‌شده پیش از تأیید نهایی.',
    form: 'تأیید تغییر وضعیت حساب',
    review:
      'تغییر وضعیت حساب بالا از <current>{currentStatus}</current> به <proposed>{proposedStatus}</proposed> را در نسخهٔ <revision>{revisionValue}</revision> تأیید کنید.',
    expires:
      'اعتبار تأیید هویت یک‌بارمصرف در <deadline></deadline> منقضی می‌شود. انقضا یا ترک این صفحه، دلیل را پاک می‌کند و تأیید هویت مجدد لازم خواهد بود.',
    reason: 'دلیل اقدام مدیریتی',
    reasonHelp:
      'برای هر اقدام الزامی است. حداکثر ۲٬۰۰۰ بایت UTF-8؛ از درج اطلاعات شخصی غیرضروری خودداری کنید.',
    reasonError: 'دلیلی با حداکثر ۲٬۰۰۰ بایت UTF-8 وارد کنید.',
    acknowledged: 'حساب، وضعیت فعلی، وضعیت جدید و پیامدهای این اقدام را بررسی کرده‌ام.',
    submitting: 'در حال ارسال تغییر وضعیت...',
  },
} as const satisfies CatalogShape<typeof adminEn>;
