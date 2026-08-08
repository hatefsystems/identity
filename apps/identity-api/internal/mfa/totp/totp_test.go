package totp

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateSecret(t *testing.T) {
	s1, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if len(s1) != 32 {
		t.Errorf("expected 32-char secret string, got %d (%q)", len(s1), s1)
	}

	s2, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret (2): %v", err)
	}
	if s1 == s2 {
		t.Error("expected distinct CSPRNG secrets, got identical strings")
	}
}

func TestGenerateURI(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	account := "user@example.com"
	issuer := "Hatef Identity"

	uri := GenerateURI(secret, account, issuer)
	if !strings.HasPrefix(uri, "otpauth://totp/Hatef%20Identity:user@example.com?") {
		t.Errorf("unexpected URI prefix in: %s", uri)
	}
	if !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Errorf("URI missing secret parameter: %s", uri)
	}
	if !strings.Contains(uri, "issuer=Hatef+Identity") && !strings.Contains(uri, "issuer=Hatef%20Identity") {
		t.Errorf("URI missing issuer parameter: %s", uri)
	}
	if !strings.Contains(uri, "digits=6") {
		t.Errorf("URI missing digits=6: %s", uri)
	}
	if !strings.Contains(uri, "period=30") {
		t.Errorf("URI missing period=30: %s", uri)
	}
}

func TestRFC6238TestVectors(t *testing.T) {
	// RFC 6238 Appendix A test secret: "12345678901234567890" in ASCII = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" in Base32
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	tests := []struct {
		unixTime int64
		expected string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}

	for _, tc := range tests {
		tm := time.Unix(tc.unixTime, 0).UTC()
		code, err := GenerateCode(secret, tm)
		if err != nil {
			t.Fatalf("GenerateCode(%d): %v", tc.unixTime, err)
		}
		if code != tc.expected {
			t.Errorf("time=%d: expected code %s, got %s", tc.unixTime, tc.expected, code)
		}

		// Validate
		if !ValidateCode(secret, code, tm, 0) {
			t.Errorf("ValidateCode failed for valid code %s at time %d", code, tc.unixTime)
		}
	}
}

func TestValidateCodeWindowDrift(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	now := time.Now().UTC()
	codeNow, err := GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	// Exact time
	if !ValidateCode(secret, codeNow, now, 0) {
		t.Error("expected exact match to validate with windowSteps = 0")
	}

	// -30 seconds
	past30s := now.Add(-30 * time.Second)
	codePast30s, err := GenerateCode(secret, past30s)
	if err != nil {
		t.Fatalf("GenerateCode(-30s): %v", err)
	}

	// Should fail with windowSteps = 0 if time steps differ
	// Should pass with windowSteps = 1
	if !ValidateCode(secret, codePast30s, now, 1) {
		t.Error("expected code from -30s to validate with windowSteps = 1")
	}

	// +30 seconds
	future30s := now.Add(30 * time.Second)
	codeFuture30s, err := GenerateCode(secret, future30s)
	if err != nil {
		t.Fatalf("GenerateCode(+30s): %v", err)
	}

	if !ValidateCode(secret, codeFuture30s, now, 1) {
		t.Error("expected code from +30s to validate with windowSteps = 1")
	}

	// Invalid code
	if ValidateCode(secret, "000000", now, 1) && codeNow != "000000" {
		t.Error("expected bogus code to fail validation")
	}

	// Malformed passcode length
	if ValidateCode(secret, "123", now, 1) {
		t.Error("expected short code to fail validation")
	}
	if ValidateCode(secret, "abcdef", now, 1) {
		t.Error("expected non-digit code to fail validation")
	}
}

func TestParseSecretEdgeCases(t *testing.T) {
	if _, err := parseSecret(""); err == nil {
		t.Error("expected error for empty secret")
	}
	if _, err := parseSecret("!!!invalid!!!"); err == nil {
		t.Error("expected error for invalid base32 secret")
	}
}
