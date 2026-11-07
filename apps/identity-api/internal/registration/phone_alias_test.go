package registration

import "testing"

func TestSignupPhoneAliasesShareCanonicalAdmissionBudget(t *testing.T) {
	for _, phone := range []string{"+989123456789", "09123456789", "989123456789", "+98 (912) 345-6789"} {
		t.Run(phone, func(t *testing.T) {
			service, authority, _, _, _, _, _ := signupFixture(t)
			limiter := &signupLimiter{denyAt: 3}
			service.deps.Limiter = limiter
			_, err := service.Start(t.Context(), "subscriber@example.com", phone, authority.JKT, "198.51.100.5")
			if err != ErrRateLimited {
				t.Fatalf("Start = %v; want canonical phone admission denial", err)
			}
			if len(limiter.keys) != 3 || limiter.keys[2] != "rate:registration:phone:"+digest("+989123456789") {
				t.Fatalf("phone alias did not share the canonical admission budget")
			}
		})
	}
}

func TestSignupPhoneRejectsUnsupportedIdentifiersBeforeAdmission(t *testing.T) {
	for _, phone := range []string{"", "+12025550123", "00989123456789", "0912345678", "091234567890", "۰۹۱۲۳۴۵۶۷۸۹", "0912345678x", " 09123456789 ", "09123456789\n"} {
		t.Run(phone, func(t *testing.T) {
			service, authority, _, _, _, _, _ := signupFixture(t)
			limiter := &signupLimiter{}
			service.deps.Limiter = limiter
			_, err := service.Start(t.Context(), "subscriber@example.com", phone, authority.JKT, "198.51.100.5")
			if err != ErrInvalid || len(limiter.keys) != 0 {
				t.Fatalf("unsupported phone reached admission: %v", err)
			}
		})
	}
}
