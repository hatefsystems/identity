import type { CatalogShape } from '../i18n/types';

export const authEn = {
  brand: 'Hatef Identity',
  homeLabel: 'Hatef Identity home',
  tagline: 'One identity for the Hatef ecosystem.',
  home: {
    title: 'Hatef Identity Platform',
    description:
      'Centralized, privacy-first Identity Provider (IdP) and unified access portal for the Hatef ecosystem.',
    welcome: 'Welcome',
    welcomeDescription: 'Sign in to manage your identity, security settings, and privacy.',
    signIn: 'Sign in',
    register: 'Create an account',
  },
  pages: {
    login: {
      metadata: 'Sign in | Hatef Identity',
      title: 'Sign in to Hatef',
      description: 'Sign in to your account with a passkey. Password sign-in is not available yet.',
      new: 'New to Hatef?',
    },
    register: {
      metadata: 'Create an account | Hatef Identity',
      title: 'Create your account',
      description: 'Verify your existing email and Iranian mobile number, then create a passkey.',
      existing: 'Already have an account?',
    },
    forgot: {
      metadata: 'Password reset unavailable | Hatef Identity',
      title: 'Password reset unavailable',
      description: 'Password reset is not available. No reset email can be requested here.',
    },
    reset: {
      metadata: 'Password reset unavailable | Hatef Identity',
      title: 'Password reset unavailable',
      description:
        'Password reset is not available. This page cannot verify a reset link or change a password.',
    },
    totp: {
      metadata: 'Authenticator sign-in unavailable | Hatef Identity',
      title: 'Authenticator sign-in unavailable',
      description:
        'Authenticator-code sign-in is not available on this page. Do not enter a code here.',
    },
    passkey: {
      metadata: 'Sign in with a passkey | Hatef Identity',
      title: 'Sign in with a passkey',
      description: 'Use a passkey already saved on your device or security key.',
    },
    reclaim: {
      metadata: 'Recover your account | Hatef Identity',
      title: 'Recover your account',
      description:
        'Cancel a pending account deletion using the recovery link from your email and strong verification.',
      footer: 'Recovery does not sign you in or restore old sessions.',
    },
    returnSignIn: 'Return to sign in',
  },
  fields: {
    email: 'Email address',
    password: 'Password',
    newPassword: 'New password',
    confirmPassword: 'Confirm password',
    code: 'Authenticator code',
    passwordHint: 'Use a long, unique password. You can include spaces.',
    emailHint: 'Use the primary email address for your account.',
    codeHint: 'Enter the six-digit code from your authenticator app, not an email or text message.',
    show: 'Show {label}',
    showPassword: 'Show password',
    hidePassword: 'Hide password',
    showNewPassword: 'Show new password',
    hideNewPassword: 'Hide new password',
    showConfirmPassword: 'Show confirm password',
    hideConfirmPassword: 'Hide confirm password',
    hide: 'Hide {label}',
  },
  preview: {
    title: 'UI preview',
    notice: 'This form is not connected yet. Do not enter real credentials.',
  },
  availability: {
    notice:
      'Use a passkey to sign in to an existing account, or create an account with email, phone and passkey verification.',
  },
  validation: {
    emailRequired: 'Enter your email address.',
    emailInvalid: 'Enter a valid email address.',
    passwordRequired: 'Enter your password.',
    newPasswordRequired: 'Enter a new password.',
    confirmationRequired: 'Confirm your password.',
    passwordMismatch: 'Passwords do not match.',
    code: 'Enter exactly six digits (0-9).',
  },
  forms: {
    rateLimited: 'Too many attempts. Please try again later.',
    login: {
      label: 'Password sign in',
      submit: 'Sign in with password',
      pending: 'Signing in...',
      success: 'Sign-in completed.',
      error: 'We could not sign you in. Check your details and try again.',
      separator: 'or use your password',
      forgot: 'Forgot password?',
    },
    register: {
      label: 'Create an account',
      submit: 'Create account',
      pending: 'Creating your account...',
      success: 'Registration completed. Return to sign in to continue.',
      error: 'We could not complete registration. Please try again.',
    },
    passkey: {
      label: 'Passkey sign in',
      submit: 'Use a passkey',
      intro:
        'Use a fingerprint, face recognition, device PIN, or a security key. Your device chooses the account, so you do not need to enter an email address.',
      pending: 'Complete the prompt on your device.',
      success: 'Passkey verification completed.',
      error: 'We could not verify the passkey. Please try again.',
      cancelled: 'The passkey request was cancelled. You can try again.',
      unsupported:
        'Passkeys are not supported in this browser. Try a browser that supports passkeys.',
    },
    totp: {
      label: 'Authenticator verification',
      submit: 'Verify code',
      pending: 'Verifying your code...',
      success: 'Code verification completed.',
      error:
        'We could not verify that code. Use the current code from your authenticator and try again.',
    },
    forgot: {
      label: 'Request a password reset',
      submit: 'Send reset link',
      pending: 'Requesting a reset link...',
      success:
        'If an account matches that email address, you will receive a password reset link. Check your inbox and spam folder.',
      error: 'We could not request a reset link. Please try again.',
    },
    reset: {
      label: 'Set a new password',
      submit: 'Reset password',
      pending: 'Resetting your password...',
      success: 'Password reset completed. Return to sign in with your new password.',
      error: 'We could not reset your password. Please try again or request a new link.',
      expired: 'This reset link has expired. Request a new link to continue.',
      invalid: 'This reset link cannot be used. Request a new link to continue.',
      newLink: 'Request a new reset link',
    },
  },
  passkey: {
    continue: 'Continue with a passkey',
    use: 'Use a passkey',
    intro:
      'Use a fingerprint, face recognition, device PIN, or a security key for an existing account. Your device chooses the account; no email address is needed.',
    pending: 'Complete the passkey prompt. Your session will be checked before opening the portal.',
    verifying: 'Verifying passkey...',
    cancel: 'Cancel sign in',
    cancelled: 'Sign-in cancelled here before passkey verification was sent. Start again when you are ready.',
    notCompleted: 'Sign-in was not completed. The passkey prompt may have closed, timed out, or been unavailable. Start again when you are ready.',
    unconfirmed: 'Sign-in outcome not confirmed. Verification may already have completed, but this page could not confirm your session. The request has not been retried. Start a new sign-in only when you are ready.',
    noScript:
      'JavaScript is required for secure passkey sign-in. No credentials are submitted without it.',
  },
  reclaim: {
    closed:
      'This page no longer holds a usable recovery link. Reopen the link in your recovery email to continue.',
    hidden:
      'The code and verification were cleared when this page was hidden. Return here and start again for fresh verification. If the page no longer holds the link, reopen it from your recovery email. The original five-minute page limit and the deadline in your email are unchanged.',
    opaque:
      'The recovery link or verification could not be accepted. Use the link in your recovery email and fresh verification. This page cannot identify the reason.',
    rateLimited:
      'Too many attempts. Wait before trying again. Reopen the email if this page has cleared the link.',
    unavailable:
      'Recovery could not be verified. The service may be unavailable. Start again with fresh verification when it is available.',
    preparing: 'Preparing fresh account recovery verification...',
    codeError: 'Enter the six-digit code from your authenticator app.',
    passkeyPending: 'Complete PIN or biometric verification on your authenticator.',
    codePending: 'Verifying your authenticator code...',
    confirmedTitle: 'Account recovered',
    unconfirmedTitle: 'Recovery outcome unconfirmed',
    confirmed:
      'Account deletion has been cancelled. The recovery link and verification have been cleared. Sign in normally to start a new session; old sessions remain invalid.',
    unconfirmed:
      'The recovery response was lost or interrupted. Recovery may already have completed, but this page cannot confirm it. The request has not been retried. The link and verification have been cleared. Reopen the recovery email for fresh verification; an unavailable link does not prove whether recovery succeeded.',
    signIn: 'Sign in to your account',
    intro:
      'Opening this page does not recover your account. Start explicitly when you are ready. The link is held privately in this page for at most five minutes, without extending the deadline in your email. Leaving or reloading clears it.',
    samePhone:
      'If verification asks for a code from an authenticator on this phone, open the authenticator first, then return here and start fresh verification. Enter the current code or use one-time-code autofill if available. Switching apps after starting clears the code and verification; start again on return. The service chooses the verification method.',
    passkeyHint:
      'Use your account passkey with a device PIN or biometric verification. The service selected this verification method; a touch-only key cannot complete recovery.',
    passkey: 'Recover with a passkey',
    form: 'Account recovery verification',
    code: 'Authenticator code',
    codeHint:
      'Use the six-digit code from your enrolled authenticator app. English, Persian and Arabic-Indic digits are accepted. If you need to switch apps, return here and start fresh verification before entering the code. The link is kept only for the remainder of its original five-minute page limit. Email, text-message and recovery codes are not accepted here.',
    recover: 'Recover account',
    start: 'Start account recovery',
    cancelled: 'Verification cancelled. Start again when you are ready.',
    cancel: 'Cancel recovery',
    noScript:
      'JavaScript is required for secure account recovery and to clear the link from the address bar. No recovery request is submitted without it. Close this page when finished.',
  },
} as const;

export const authFa = {
  brand: 'هویت هاتف',
  homeLabel: 'صفحهٔ اصلی هویت هاتف',
  tagline: 'یک هویت برای زیست‌بوم هاتف.',
  home: {
    title: 'سامانهٔ هویت هاتف',
    description:
      'ارائه‌دهندهٔ متمرکز هویت با اولویت حریم خصوصی و درگاه یکپارچهٔ دسترسی به زیست‌بوم هاتف.',
    welcome: 'خوش آمدید',
    welcomeDescription: 'برای مدیریت هویت، تنظیمات امنیتی و حریم خصوصی خود وارد شوید.',
    signIn: 'ورود',
    register: 'ایجاد حساب',
  },
  pages: {
    login: {
      metadata: 'ورود | هویت هاتف',
      title: 'ورود به هاتف',
      description: 'با کلید عبور وارد حساب خود شوید. ورود با گذرواژه هنوز در دسترس نیست.',
      new: 'تازه به هاتف پیوسته‌اید؟',
    },
    register: {
      metadata: 'ایجاد حساب | هویت هاتف',
      title: 'حساب خود را ایجاد کنید',
      description: 'ایمیل موجود و شمارهٔ همراه ایران خود را تأیید کنید، سپس کلید عبور بسازید.',
      existing: 'از قبل حساب دارید؟',
    },
    forgot: {
      metadata: 'بازنشانی گذرواژه در دسترس نیست | هویت هاتف',
      title: 'بازنشانی گذرواژه در دسترس نیست',
      description: 'بازنشانی گذرواژه در دسترس نیست. در اینجا نمی‌توان ایمیل بازنشانی درخواست کرد.',
    },
    reset: {
      metadata: 'بازنشانی گذرواژه در دسترس نیست | هویت هاتف',
      title: 'بازنشانی گذرواژه در دسترس نیست',
      description:
        'بازنشانی گذرواژه در دسترس نیست. این صفحه نمی‌تواند پیوند بازنشانی را تأیید کند یا گذرواژه را تغییر دهد.',
    },
    totp: {
      metadata: 'ورود با رمزساز در دسترس نیست | هویت هاتف',
      title: 'ورود با رمزساز در دسترس نیست',
      description:
        'ورود با کد رمزساز در این صفحه در دسترس نیست. در اینجا کدی وارد نکنید.',
    },
    passkey: {
      metadata: 'ورود با کلید عبور | هویت هاتف',
      title: 'ورود با کلید عبور',
      description:
        'از کلید عبوری که از قبل روی دستگاه یا کلید امنیتی خود ذخیره کرده‌اید استفاده کنید.',
    },
    reclaim: {
      metadata: 'بازیابی حساب | هویت هاتف',
      title: 'بازیابی حساب شما',
      description: 'با پیوند بازیابی ایمیل و تأیید هویت قوی، حذف در انتظار حساب را لغو کنید.',
      footer: 'بازیابی باعث ورود شما یا بازگرداندن نشست‌های قدیمی نمی‌شود.',
    },
    returnSignIn: 'بازگشت به ورود',
  },
  fields: {
    email: 'نشانی ایمیل',
    password: 'گذرواژه',
    newPassword: 'گذرواژهٔ جدید',
    confirmPassword: 'تکرار گذرواژه',
    code: 'کد رمزساز',
    passwordHint: 'از گذرواژه‌ای طولانی و یکتا استفاده کنید. فاصله نیز مجاز است.',
    emailHint: 'از ایمیل اصلی حساب خود استفاده کنید.',
    codeHint: 'کد شش‌رقمی برنامهٔ رمزساز خود را وارد کنید، نه کد ایمیل یا پیامک.',
    show: 'نمایش {label}',
    showPassword: 'نمایش گذرواژه',
    hidePassword: 'پنهان‌کردن گذرواژه',
    showNewPassword: 'نمایش گذرواژهٔ جدید',
    hideNewPassword: 'پنهان‌کردن گذرواژهٔ جدید',
    showConfirmPassword: 'نمایش تکرار گذرواژه',
    hideConfirmPassword: 'پنهان‌کردن تکرار گذرواژه',
    hide: 'پنهان‌کردن {label}',
  },
  preview: {
    title: 'پیش‌نمایش رابط کاربری',
    notice: 'این فرم هنوز متصل نیست. اطلاعات ورود واقعی را وارد نکنید.',
  },
  availability: {
    notice:
      'برای ورود به حساب موجود از کلید عبور استفاده کنید، یا با تأیید ایمیل، تلفن و کلید عبور حساب بسازید.',
  },
  validation: {
    emailRequired: 'نشانی ایمیل خود را وارد کنید.',
    emailInvalid: 'یک نشانی ایمیل معتبر وارد کنید.',
    passwordRequired: 'گذرواژهٔ خود را وارد کنید.',
    newPasswordRequired: 'یک گذرواژهٔ جدید وارد کنید.',
    confirmationRequired: 'گذرواژهٔ خود را تکرار کنید.',
    passwordMismatch: 'گذرواژه‌ها یکسان نیستند.',
    code: 'دقیقاً شش رقم انگلیسی (0-9) وارد کنید.',
  },
  forms: {
    rateLimited: 'تعداد تلاش‌ها بیش از حد است. بعداً دوباره تلاش کنید.',
    login: {
      label: 'ورود با گذرواژه',
      submit: 'ورود با گذرواژه',
      pending: 'در حال ورود...',
      success: 'ورود انجام شد.',
      error: 'ورود انجام نشد. اطلاعات خود را بررسی و دوباره تلاش کنید.',
      separator: 'یا از گذرواژهٔ خود استفاده کنید',
      forgot: 'گذرواژه را فراموش کرده‌اید؟',
    },
    register: {
      label: 'ایجاد حساب',
      submit: 'ایجاد حساب',
      pending: 'در حال ایجاد حساب شما...',
      success: 'ثبت‌نام انجام شد. برای ادامه به صفحهٔ ورود بازگردید.',
      error: 'ثبت‌نام کامل نشد. دوباره تلاش کنید.',
    },
    passkey: {
      label: 'ورود با کلید عبور',
      submit: 'استفاده از کلید عبور',
      intro:
        'از اثر انگشت، تشخیص چهره، پین دستگاه یا کلید امنیتی استفاده کنید. دستگاه شما حساب را انتخاب می‌کند؛ نیازی به واردکردن ایمیل نیست.',
      pending: 'درخواست روی دستگاه خود را تکمیل کنید.',
      success: 'تأیید کلید عبور انجام شد.',
      error: 'کلید عبور تأیید نشد. دوباره تلاش کنید.',
      cancelled: 'درخواست کلید عبور لغو شد. می‌توانید دوباره تلاش کنید.',
      unsupported:
        'این مرورگر از کلید عبور پشتیبانی نمی‌کند. مرورگری را امتحان کنید که از کلید عبور پشتیبانی کند.',
    },
    totp: {
      label: 'تأیید با رمزساز',
      submit: 'تأیید کد',
      pending: 'در حال تأیید کد شما...',
      success: 'تأیید کد انجام شد.',
      error: 'کد تأیید نشد. از کد فعلی برنامهٔ رمزساز خود استفاده و دوباره تلاش کنید.',
    },
    forgot: {
      label: 'درخواست بازنشانی گذرواژه',
      submit: 'ارسال پیوند بازنشانی',
      pending: 'در حال درخواست پیوند بازنشانی...',
      success:
        'اگر حسابی با این ایمیل مطابقت داشته باشد، پیوند بازنشانی گذرواژه دریافت می‌کنید. صندوق ورودی و پوشهٔ هرزنامه را بررسی کنید.',
      error: 'درخواست پیوند بازنشانی انجام نشد. دوباره تلاش کنید.',
    },
    reset: {
      label: 'تعیین گذرواژهٔ جدید',
      submit: 'بازنشانی گذرواژه',
      pending: 'در حال بازنشانی گذرواژهٔ شما...',
      success: 'بازنشانی گذرواژه انجام شد. برای ورود با گذرواژهٔ جدید بازگردید.',
      error: 'گذرواژه بازنشانی نشد. دوباره تلاش کنید یا پیوند جدیدی درخواست کنید.',
      expired: 'مهلت پیوند بازنشانی پایان یافته است. برای ادامه پیوند جدیدی درخواست کنید.',
      invalid: 'این پیوند بازنشانی قابل استفاده نیست. برای ادامه پیوند جدیدی درخواست کنید.',
      newLink: 'درخواست پیوند بازنشانی جدید',
    },
  },
  passkey: {
    continue: 'ادامه با کلید عبور',
    use: 'استفاده از کلید عبور',
    intro:
      'برای حساب موجود از اثر انگشت، تشخیص چهره، پین دستگاه یا کلید امنیتی استفاده کنید. دستگاه شما حساب را انتخاب می‌کند؛ نیازی به ایمیل نیست.',
    pending: 'درخواست کلید عبور را تکمیل کنید. پیش از بازشدن درگاه، نشست شما بررسی می‌شود.',
    verifying: 'در حال تأیید کلید عبور...',
    cancel: 'لغو ورود',
    cancelled: 'ورود در این صفحه پیش از ارسال تأیید کلید عبور لغو شد. هنگامی که آماده هستید دوباره آغاز کنید.',
    notCompleted: 'ورود کامل نشد. ممکن است درخواست کلید عبور بسته شده، مهلتش پایان یافته یا در دسترس نبوده باشد. هنگامی که آماده هستید دوباره آغاز کنید.',
    unconfirmed: 'نتیجهٔ ورود تأیید نشده است. ممکن است تأیید هویت انجام شده باشد، اما این صفحه نتوانست نشست شما را تأیید کند. درخواست تکرار نشده است. ورود جدید را فقط هنگامی که آماده هستید آغاز کنید.',
    noScript:
      'برای ورود امن با کلید عبور، جاوااسکریپت لازم است. بدون آن هیچ اطلاعات ورودی ارسال نمی‌شود.',
  },
  reclaim: {
    closed:
      'این صفحه دیگر پیوند بازیابی قابل استفاده‌ای ندارد. برای ادامه، پیوند را از ایمیل بازیابی دوباره باز کنید.',
    hidden:
      'با پنهان‌شدن صفحه، کد و تأیید هویت پاک شدند. به اینجا بازگردید و برای تأیید هویت تازه دوباره آغاز کنید. اگر صفحه دیگر پیوند را نگه نمی‌دارد، آن را از ایمیل بازیابی دوباره باز کنید. مهلت اولیهٔ پنج‌دقیقه‌ای صفحه و مهلت درج‌شده در ایمیل تغییر نکرده‌اند.',
    opaque:
      'پیوند بازیابی یا تأیید هویت پذیرفته نشد. از پیوند ایمیل بازیابی و تأیید هویت تازه استفاده کنید. این صفحه نمی‌تواند علت را مشخص کند.',
    rateLimited:
      'تعداد تلاش‌ها بیش از حد است. پیش از تلاش دوباره صبر کنید. اگر پیوند از این صفحه پاک شده، ایمیل را دوباره باز کنید.',
    unavailable:
      'بازیابی قابل تأیید نبود. ممکن است سرویس در دسترس نباشد. پس از دسترسی به سرویس، دوباره با تأیید هویت تازه آغاز کنید.',
    preparing: 'در حال آماده‌سازی تأیید هویت تازه برای بازیابی حساب...',
    codeError: 'کد شش‌رقمی برنامهٔ رمزساز خود را وارد کنید.',
    passkeyPending: 'تأیید پین یا زیست‌سنجی را در ابزار احراز هویت خود تکمیل کنید.',
    codePending: 'در حال تأیید کد رمزساز شما...',
    confirmedTitle: 'حساب بازیابی شد',
    unconfirmedTitle: 'نتیجهٔ بازیابی تأیید نشده است',
    confirmed:
      'حذف حساب لغو شد. پیوند بازیابی و تأیید هویت پاک شدند. برای آغاز نشست جدید، به روش معمول وارد شوید؛ نشست‌های قدیمی نامعتبر می‌مانند.',
    unconfirmed:
      'پاسخ بازیابی دریافت نشد یا قطع شد. ممکن است بازیابی انجام شده باشد، اما این صفحه نمی‌تواند آن را تأیید کند. درخواست تکرار نشده است. پیوند و تأیید هویت پاک شده‌اند. برای تأیید هویت تازه، ایمیل بازیابی را دوباره باز کنید؛ در دسترس نبودن پیوند، موفقیت یا شکست بازیابی را اثبات نمی‌کند.',
    signIn: 'ورود به حساب شما',
    intro:
      'بازکردن این صفحه حساب شما را بازیابی نمی‌کند. هنگامی که آماده هستید، صریحاً آغاز کنید. پیوند حداکثر پنج دقیقه به‌صورت خصوصی در این صفحه نگه داشته می‌شود و مهلت ایمیل شما را تمدید نمی‌کند. ترک یا بارگذاری دوبارهٔ صفحه آن را پاک می‌کند.',
    samePhone:
      'اگر تأیید هویت به کد برنامهٔ رمزساز روی همین تلفن نیاز دارد، ابتدا رمزساز را باز کنید، سپس به اینجا بازگردید و تأیید هویت تازه را آغاز کنید. کد فعلی را وارد کنید یا در صورت دسترسی از تکمیل خودکار کد یک‌بارمصرف استفاده کنید. جابه‌جایی بین برنامه‌ها پس از آغاز، کد و تأیید هویت را پاک می‌کند؛ پس از بازگشت دوباره آغاز کنید. سرویس روش تأیید هویت را انتخاب می‌کند.',
    passkeyHint:
      'از کلید عبور حساب خود همراه با پین دستگاه یا تأیید زیست‌سنجی استفاده کنید. سرویس این روش تأیید هویت را انتخاب کرده است؛ کلید صرفاً لمسی نمی‌تواند بازیابی را تکمیل کند.',
    passkey: 'بازیابی با کلید عبور',
    form: 'تأیید هویت بازیابی حساب',
    code: 'کد رمزساز',
    codeHint:
      'از کد شش‌رقمی برنامهٔ رمزساز ثبت‌شدهٔ خود استفاده کنید. رقم‌های انگلیسی، فارسی و عربی پذیرفته می‌شوند. اگر باید بین برنامه‌ها جابه‌جا شوید، پس از بازگشت و پیش از واردکردن کد، تأیید هویت تازه را آغاز کنید. پیوند فقط تا پایان مهلت اولیهٔ پنج‌دقیقه‌ای صفحه نگه داشته می‌شود. کد ایمیل، پیامک و بازیابی در اینجا پذیرفته نمی‌شود.',
    recover: 'بازیابی حساب',
    start: 'آغاز بازیابی حساب',
    cancelled: 'تأیید هویت لغو شد. هنگامی که آماده هستید دوباره آغاز کنید.',
    cancel: 'لغو بازیابی',
    noScript:
      'برای بازیابی امن حساب و پاک‌کردن پیوند از نوار نشانی، جاوااسکریپت لازم است. بدون آن هیچ درخواست بازیابی ارسال نمی‌شود. پس از پایان، این صفحه را ببندید.',
  },
} as const satisfies CatalogShape<typeof authEn>;
