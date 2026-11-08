// Package notification owns the small, versioned catalog for existing senders.
// Locale is presentation only, never authentication or recovery authority.
package notification

// Locale is an allowlisted presentation identifier, independent of authority.
type Locale string

// Supported locales match the browser catalog identifiers exactly.
const (
	English      Locale = "en"
	Persian      Locale = "fa-IR"
	LocaleHeader        = "X-Hatef-Notification-Locale"
)

// Valid reports whether the locale has an explicitly reviewed template.
func (l Locale) Valid() bool { return l == English || l == Persian }

// RequestLocale accepts only one exact, bounded header value. It deliberately
// does not negotiate Accept-Language or inspect another tab's preference cookie.
func RequestLocale(values []string) Locale {
	if len(values) == 1 && len(values[0]) <= len(Persian) {
		if locale := Locale(values[0]); locale.Valid() {
			return locale
		}
	}
	return English
}

// TemplateVersion identifies immutable prose frozen in a queued delivery.
type TemplateVersion int

// Version1 remains available while encrypted deliveries can still reference it.
// Change the version, not an existing template, when revising mail prose.
const Version1 TemplateVersion = 1

// CurrentVersion is the template revision emitted by new delivery intents.
const CurrentVersion = Version1

// DeletionTemplate contains the complete reviewed mail explanations.
type DeletionTemplate struct {
	Subject, Intro, Deactivated, Deadline, Instructions, LinkCaption, Recovery, Retention string
}

// Templates is a value copy of the locale's existing notification templates.
type Templates struct {
	Direction string
	Deletion  DeletionTemplate
	SMS       string
}

// Catalog returns values, not a mutable shared map. Persisted locale/version
// lookups never fall back: unknown queued presentation must fail closed.
func Catalog(locale Locale, version TemplateVersion) (Templates, bool) {
	if version != Version1 {
		return Templates{}, false
	}
	switch locale {
	case English:
		return Templates{
			Direction: "ltr",
			SMS:       "Your Hatef verification code is %s",
			Deletion: DeletionTemplate{
				Subject:      "Account deletion requested",
				Intro:        "Account deletion was requested.",
				Deactivated:  "Access to your identity account has been deactivated.",
				Deadline:     "You can recover your account until %s. This is the original recovery deadline; email retries do not extend it.",
				Instructions: "Open this link and verify with your configured passkey or authenticator app:",
				LinkCaption:  "Recover your account",
				Recovery:     "Recovery requires a strong factor and does not sign you in automatically. If you did not request deletion, recover your account before the deadline.",
				Retention:    "After the deadline the account is eligible for erasure, subject to lawful retention. Do not forward this recovery link.",
			},
		}, true
	case Persian:
		return Templates{
			Direction: "rtl",
			SMS:       "کد تأیید هویت هاتف شما: %s",
			Deletion: DeletionTemplate{
				Subject:      "درخواست حذف حساب",
				Intro:        "حذف حساب درخواست شده است.",
				Deactivated:  "دسترسی به حساب هویت شما غیرفعال شده است.",
				Deadline:     "تا %s می\u200cتوانید حساب خود را بازیابی کنید. این همان مهلت اصلی بازیابی است؛ ارسال دوبارهٔ ایمیل آن را تمدید نمی\u200cکند.",
				Instructions: "این پیوند را باز کنید و با کلید عبور یا برنامهٔ رمزساز تنظیم\u200cشدهٔ خود، هویتتان را تأیید کنید:",
				LinkCaption:  "بازیابی حساب",
				Recovery:     "بازیابی به یک عامل احراز هویت قوی نیاز دارد و شما را خودکار وارد حساب نمی\u200cکند. اگر حذف را درخواست نکرده\u200cاید، پیش از پایان مهلت حساب خود را بازیابی کنید.",
				Retention:    "پس از پایان مهلت، حساب با رعایت الزامات قانونی نگهداری داده، واجد شرایط حذف می\u200cشود. این پیوند بازیابی را برای دیگران نفرستید.",
			},
		}, true
	default:
		return Templates{}, false
	}
}
