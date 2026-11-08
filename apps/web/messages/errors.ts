import type { CatalogShape } from '../i18n/types';

export const errorsEn = {
  uncertain:
    'The response was lost. The action may already have completed. Refresh the saved state before trying a new action.',
  keyUnavailable:
    'Secure browser key storage is unavailable. Allow IndexedDB and Web Crypto, then sign in again. If site storage is damaged, clear it before signing in. Access cannot continue without the browser key.',
  unsupported:
    'Passkeys require a supported browser and a secure connection. Use a supported browser to continue.',
  cancelled:
    'The passkey request was cancelled or timed out. Start a new verification to try again.',
  authenticatorSecurity:
    'The passkey could not be used on this origin. Check the secure site address and try again.',
  invalidCredentialsWebauthn:
    'Verification failed or expired. Start a new passkey verification with a device PIN or biometrics.',
  invalidCredentials:
    'Verification failed or expired. Use a current authenticator code or start a new passkey verification.',
  challengeInvalid:
    'The passkey ceremony expired or could not be verified. Start again with fresh verification.',
  userVerificationWebauthn:
    'This action requires a passkey with a device PIN or biometric verification.',
  userVerification:
    'Use a passkey with a device PIN or biometric verification, or your enrolled authenticator app.',
  noFactorWebauthn:
    'This action requires a passkey with a device PIN or biometric verification. No suitable passkey verification is available. You can manage your passkeys in Security.',
  noFactor: 'No supported verification factor is available for this account.',
  deletionDisabled: 'Account deletion is currently unavailable.',
  freshVerification: 'Fresh verification is required. Start the action again.',
  lastCredential: 'Your last passkey cannot be removed. Add another passkey first.',
  notFound: 'This item is no longer available. Refresh the list to see its current state.',
  profileConflict:
    'The saved profile changed. Refresh the saved profile, review your draft, then save again.',
  accountConflict:
    'The account changed. Read its current state and review it before starting a new action with fresh verification.',
  notModeratable: 'This account is not eligible for a status change.',
  forbidden:
    'You do not have permission for this operation. Your normal account session is still available.',
  sessionChanged:
    'The browser session changed. Private data has been cleared. Verify the current session before continuing.',
  sessionRequired: 'Your session is no longer available. Sign in again to continue.',
  rateLimitedSeconds:
    'Too many attempts. Wait {seconds, plural, one {# second} other {# seconds}} before trying again.',
  rateLimited: 'Too many attempts. Please try again later.',
  nonce: 'The secure request could not be authorized. Start a new action to try again.',
  network: 'The service could not be reached. Check your connection and try again.',
  temporarilyUnavailable:
    'The service is temporarily unavailable. Your session could not be verified. Please try again later.',
  serviceUnavailable:
    'The administrative service is unavailable. No result can be shown. Please try again later.',
  invalidResponse:
    'The service returned an invalid or oversized response. No result can be trusted.',
  unknownSequence: 'The requested verification boundary is no longer available. Start a new run.',
  missingHead:
    'Verification state is unavailable. This is not evidence of an intact or empty chain.',
  requestFailed: 'The request could not be completed. Please try again.',
  nameSingleLine: 'Use a single line without control characters.',
  nameTooLong: 'Use at most 80 characters.',
} as const;

export const errorsFa = {
  uncertain:
    'پاسخ دریافت نشد. ممکن است عملیات پیش‌تر انجام شده باشد. پیش از آغاز عملیات جدید، وضعیت ذخیره‌شده را تازه‌سازی کنید.',
  keyUnavailable:
    'فضای امن نگهداری کلید مرورگر در دسترس نیست. دسترسی به IndexedDB و Web Crypto را فعال کنید و دوباره وارد شوید. اگر فضای ذخیره‌سازی سایت آسیب دیده است، پیش از ورود آن را پاک کنید. ادامهٔ دسترسی بدون کلید مرورگر ممکن نیست.',
  unsupported:
    'کلیدهای عبور به مرورگر پشتیبانی‌شده و اتصال امن نیاز دارند. برای ادامه از مرورگر پشتیبانی‌شده استفاده کنید.',
  cancelled:
    'درخواست کلید عبور لغو شد یا مهلت آن پایان یافت. برای تلاش دوباره، تأیید هویت جدیدی آغاز کنید.',
  authenticatorSecurity:
    'استفاده از کلید عبور در این مبدأ ممکن نشد. نشانی امن سایت را بررسی کنید و دوباره تلاش کنید.',
  invalidCredentialsWebauthn:
    'تأیید هویت ناموفق بود یا منقضی شد. تأیید جدید با کلید عبور و پین دستگاه یا زیست‌سنجی را آغاز کنید.',
  invalidCredentials:
    'تأیید هویت ناموفق بود یا منقضی شد. از کد فعلی برنامهٔ رمزساز استفاده کنید یا تأیید جدید با کلید عبور را آغاز کنید.',
  challengeInvalid:
    'فرایند کلید عبور منقضی شد یا قابل تأیید نبود. با تأیید هویت تازه دوباره آغاز کنید.',
  userVerificationWebauthn:
    'این عملیات به کلید عبور همراه با تأیید پین دستگاه یا زیست‌سنجی نیاز دارد.',
  userVerification:
    'از کلید عبور همراه با تأیید پین دستگاه یا زیست‌سنجی، یا برنامهٔ رمزساز ثبت‌شدهٔ خود استفاده کنید.',
  noFactorWebauthn:
    'این عملیات به کلید عبور همراه با تأیید پین دستگاه یا زیست‌سنجی نیاز دارد. روش مناسب تأیید با کلید عبور در دسترس نیست. می‌توانید کلیدهای عبور را در بخش امنیت مدیریت کنید.',
  noFactor: 'هیچ عامل تأیید هویت پشتیبانی‌شده‌ای برای این حساب در دسترس نیست.',
  deletionDisabled: 'حذف حساب در حال حاضر در دسترس نیست.',
  freshVerification: 'تأیید هویت تازه لازم است. عملیات را دوباره آغاز کنید.',
  lastCredential: 'آخرین کلید عبور شما قابل حذف نیست. ابتدا کلید عبور دیگری اضافه کنید.',
  notFound: 'این مورد دیگر در دسترس نیست. برای مشاهدهٔ وضعیت فعلی، فهرست را تازه‌سازی کنید.',
  profileConflict:
    'نمایهٔ ذخیره‌شده تغییر کرده است. نمایه را تازه‌سازی کنید، پیش‌نویس خود را بررسی کنید و دوباره ذخیره کنید.',
  accountConflict:
    'حساب تغییر کرده است. پیش از آغاز عملیات جدید با تأیید هویت تازه، وضعیت فعلی آن را بخوانید و بررسی کنید.',
  notModeratable: 'این حساب واجد شرایط تغییر وضعیت نیست.',
  forbidden: 'مجوز این عملیات را ندارید. نشست عادی حساب شما همچنان در دسترس است.',
  sessionChanged:
    'نشست مرورگر تغییر کرده است. داده‌های خصوصی پاک شدند. پیش از ادامه، نشست فعلی را تأیید کنید.',
  sessionRequired: 'نشست شما دیگر در دسترس نیست. برای ادامه دوباره وارد شوید.',
  rateLimitedSeconds:
    'تعداد تلاش‌ها بیش از حد مجاز است. پیش از تلاش دوباره {seconds, plural, one {# ثانیه} other {# ثانیه}} صبر کنید.',
  rateLimited: 'تعداد تلاش‌ها بیش از حد مجاز است. بعداً دوباره تلاش کنید.',
  nonce: 'درخواست امن مجاز شناخته نشد. برای تلاش دوباره، عملیات جدیدی آغاز کنید.',
  network: 'اتصال به سرویس ممکن نشد. اتصال خود را بررسی کنید و دوباره تلاش کنید.',
  temporarilyUnavailable:
    'سرویس موقتاً در دسترس نیست. نشست شما قابل تأیید نبود. بعداً دوباره تلاش کنید.',
  serviceUnavailable:
    'سرویس مدیریتی در دسترس نیست. هیچ نتیجه‌ای قابل نمایش نیست. بعداً دوباره تلاش کنید.',
  invalidResponse:
    'سرویس پاسخی نامعتبر یا بیش از اندازه بزرگ برگرداند. هیچ نتیجه‌ای قابل اعتماد نیست.',
  unknownSequence: 'مرز تأیید درخواستی دیگر در دسترس نیست. اجرای جدیدی آغاز کنید.',
  missingHead: 'وضعیت تأیید در دسترس نیست. این امر نشانهٔ سالم یا خالی بودن زنجیره نیست.',
  requestFailed: 'درخواست انجام نشد. دوباره تلاش کنید.',
  nameSingleLine: 'از یک خط بدون نویسه‌های کنترلی استفاده کنید.',
  nameTooLong: 'حداکثر از ۸۰ نویسه استفاده کنید.',
} as const satisfies CatalogShape<typeof errorsEn>;
