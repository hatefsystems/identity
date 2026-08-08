package config

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testMockChallengeKey is a fixed, obviously-fake mock-derivation key long
// enough to pass the minimum-length check. Real deployments receive this from
// the KMS; it is only spelled out here so the production-environment cases can
// satisfy the requirement without inventing a secret per test.
const testMockChallengeKey = "test-only-mock-challenge-key-not-a-real-secret"

// clearWebAuthnEnv unsets every WebAuthn variable for the duration of the test
// so a value leaking in from the developer's shell cannot change the outcome.
// t.Setenv also fails the test if it is run in parallel, which is what we want.
func clearWebAuthnEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		EnvWebAuthnRPID,
		EnvWebAuthnRPDisplayName,
		EnvWebAuthnRPOrigins,
		EnvWebAuthnChallengeTTL,
		EnvWebAuthnUserVerification,
		EnvWebAuthnResidentKey,
		EnvWebAuthnNamedLoginFloor,
		EnvWebAuthnMockChallengeKey,
	} {
		t.Setenv(key, "")
	}
}

// TestLoadWebAuthnDevelopmentDefaults proves the service runs with no WebAuthn
// configuration at all in development: a localhost Relying Party is defaulted.
func TestLoadWebAuthnDevelopmentDefaults(t *testing.T) {
	clearWebAuthnEnv(t)

	cfg, err := LoadWebAuthn("development")
	if err != nil {
		t.Fatalf("LoadWebAuthn: %v", err)
	}
	if cfg.RPID != "localhost" {
		t.Errorf("RPID = %q, want %q", cfg.RPID, "localhost")
	}
	if cfg.RPDisplayName != "Hatef Identity" {
		t.Errorf("RPDisplayName = %q, want %q", cfg.RPDisplayName, "Hatef Identity")
	}
	if len(cfg.RPOrigins) != 1 || cfg.RPOrigins[0] != "http://localhost:8080" {
		t.Errorf("RPOrigins = %v, want [http://localhost:8080]", cfg.RPOrigins)
	}
	if cfg.ChallengeTTL != 5*time.Minute {
		t.Errorf("ChallengeTTL = %v, want %v", cfg.ChallengeTTL, 5*time.Minute)
	}
	if cfg.UserVerification != "preferred" {
		t.Errorf("UserVerification = %q, want %q", cfg.UserVerification, "preferred")
	}
}

func TestLoadWebAuthnExplicitValues(t *testing.T) {
	clearWebAuthnEnv(t)
	t.Setenv(EnvWebAuthnRPID, "identity.hatef.ir")
	t.Setenv(EnvWebAuthnRPDisplayName, "Hatef ID")
	t.Setenv(EnvWebAuthnRPOrigins, "https://identity.hatef.ir,https://hatef.ir")
	t.Setenv(EnvWebAuthnChallengeTTL, "2m")
	t.Setenv(EnvWebAuthnUserVerification, "required")
	t.Setenv(EnvWebAuthnResidentKey, "preferred")
	t.Setenv(EnvWebAuthnNamedLoginFloor, "250ms")
	// Required outside development, so every production-environment case must
	// supply it.
	t.Setenv(EnvWebAuthnMockChallengeKey, testMockChallengeKey)

	cfg, err := LoadWebAuthn("production")
	if err != nil {
		t.Fatalf("LoadWebAuthn: %v", err)
	}
	if cfg.RPID != "identity.hatef.ir" {
		t.Errorf("RPID = %q, want %q", cfg.RPID, "identity.hatef.ir")
	}

	if cfg.RPDisplayName != "Hatef ID" {
		t.Errorf("RPDisplayName = %q, want %q", cfg.RPDisplayName, "Hatef ID")
	}
	want := []string{"https://identity.hatef.ir", "https://hatef.ir"}
	if len(cfg.RPOrigins) != len(want) {
		t.Fatalf("RPOrigins = %v, want %v", cfg.RPOrigins, want)
	}
	for i, o := range want {
		if cfg.RPOrigins[i] != o {
			t.Errorf("RPOrigins[%d] = %q, want %q", i, cfg.RPOrigins[i], o)
		}
	}
	if cfg.ChallengeTTL != 2*time.Minute {
		t.Errorf("ChallengeTTL = %v, want %v", cfg.ChallengeTTL, 2*time.Minute)
	}
	if cfg.UserVerification != "required" {
		t.Errorf("UserVerification = %q, want %q", cfg.UserVerification, "required")
	}
	if cfg.ResidentKey != "preferred" {
		t.Errorf("ResidentKey = %q, want %q", cfg.ResidentKey, "preferred")
	}
	if cfg.NamedLoginFloor != 250*time.Millisecond {
		t.Errorf("NamedLoginFloor = %v, want %v", cfg.NamedLoginFloor, 250*time.Millisecond)
	}
	if len(cfg.MockChallengeKey) < minWebAuthnMockChallengeKeyLen {
		t.Errorf("len(MockChallengeKey) = %d, want at least %d",
			len(cfg.MockChallengeKey), minWebAuthnMockChallengeKeyLen)
	}
}

// TestLoadWebAuthnTrimsRPID covers a stray-whitespace value, which would
// otherwise produce an RP ID no browser matches.
func TestLoadWebAuthnTrimsRPID(t *testing.T) {
	clearWebAuthnEnv(t)
	t.Setenv(EnvWebAuthnRPID, "  identity.hatef.ir  ")
	t.Setenv(EnvWebAuthnRPOrigins, "https://identity.hatef.ir")
	t.Setenv(EnvWebAuthnMockChallengeKey, testMockChallengeKey)

	cfg, err := LoadWebAuthn("production")

	if err != nil {
		t.Fatalf("LoadWebAuthn: %v", err)
	}
	if cfg.RPID != "identity.hatef.ir" {
		t.Errorf("RPID = %q, want the trimmed %q", cfg.RPID, "identity.hatef.ir")
	}
}

// TestLoadWebAuthnRejectsRPIDWithSchemeOrPort guards the single most common
// WebAuthn misconfiguration: an RP ID that is a URL rather than a bare domain.
func TestLoadWebAuthnRejectsRPIDWithSchemeOrPort(t *testing.T) {
	tests := []struct {
		name string
		rpid string
	}{
		{name: "https scheme", rpid: "https://identity.hatef.ir"},
		{name: "http scheme", rpid: "http://localhost"},
		{name: "port", rpid: "localhost:8080"},
		{name: "path", rpid: "identity.hatef.ir/auth"},
		{name: "trailing slash", rpid: "identity.hatef.ir/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearWebAuthnEnv(t)
			t.Setenv(EnvWebAuthnRPID, tc.rpid)
			t.Setenv(EnvWebAuthnRPOrigins, "https://identity.hatef.ir")

			_, err := LoadWebAuthn("production")
			if err == nil {
				t.Fatalf("LoadWebAuthn(%q) succeeded, want a bare-domain error", tc.rpid)
			}
			if !strings.Contains(err.Error(), "must be a bare domain") {
				t.Errorf("error = %q, want it to mention the bare-domain requirement", err.Error())
			}
		})
	}
}

// TestLoadWebAuthnRejectsRPIDWithSchemeInDevelopment proves the bare-domain rule
// is not relaxed in development: it is a correctness rule, not a security one.
func TestLoadWebAuthnRejectsRPIDWithSchemeInDevelopment(t *testing.T) {
	clearWebAuthnEnv(t)
	t.Setenv(EnvWebAuthnRPID, "http://localhost")

	if _, err := LoadWebAuthn("development"); err == nil {
		t.Fatal("LoadWebAuthn succeeded with a URL RP ID in development, want an error")
	}
}

func TestLoadWebAuthnRequiresRPIDOutsideDevelopment(t *testing.T) {
	clearWebAuthnEnv(t)
	t.Setenv(EnvWebAuthnRPOrigins, "https://identity.hatef.ir")

	for _, env := range []string{"staging", "production"} {
		t.Run(env, func(t *testing.T) {
			_, err := LoadWebAuthn(env)
			if err == nil {
				t.Fatalf("LoadWebAuthn(%q) succeeded without %s, want an error", env, EnvWebAuthnRPID)
			}
			if !strings.Contains(err.Error(), EnvWebAuthnRPID) {
				t.Errorf("error = %q, want it to name %s", err.Error(), EnvWebAuthnRPID)
			}
		})
	}
}

func TestLoadWebAuthnRequiresOriginsOutsideDevelopment(t *testing.T) {
	clearWebAuthnEnv(t)
	t.Setenv(EnvWebAuthnRPID, "identity.hatef.ir")

	_, err := LoadWebAuthn("production")
	if err == nil {
		t.Fatalf("LoadWebAuthn succeeded without %s, want an error", EnvWebAuthnRPOrigins)
	}
	if !strings.Contains(err.Error(), EnvWebAuthnRPOrigins) {
		t.Errorf("error = %q, want it to name %s", err.Error(), EnvWebAuthnRPOrigins)
	}
}

// TestLoadWebAuthnRejectsPlaintextOriginOutsideDevelopment enforces the
// secure-context requirement: outside development every origin must be https.
func TestLoadWebAuthnRejectsPlaintextOriginOutsideDevelopment(t *testing.T) {
	tests := []struct {
		name    string
		origins string
	}{
		{name: "single http origin", origins: "http://identity.hatef.ir"},
		{name: "http mixed with https", origins: "https://identity.hatef.ir,http://hatef.ir"},
		{name: "scheme-less origin", origins: "identity.hatef.ir"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearWebAuthnEnv(t)
			t.Setenv(EnvWebAuthnRPID, "identity.hatef.ir")
			t.Setenv(EnvWebAuthnRPOrigins, tc.origins)

			_, err := LoadWebAuthn("production")
			if err == nil {
				t.Fatalf("LoadWebAuthn(%q) succeeded, want an https-origin error", tc.origins)
			}
			if !strings.Contains(err.Error(), "https origin") {
				t.Errorf("error = %q, want it to mention the https requirement", err.Error())
			}
		})
	}
}

// TestLoadWebAuthnAllowsPlaintextOriginInDevelopment is the counterpart: plain
// HTTP localhost is a browser-sanctioned secure context, so it must be allowed.
func TestLoadWebAuthnAllowsPlaintextOriginInDevelopment(t *testing.T) {
	clearWebAuthnEnv(t)
	t.Setenv(EnvWebAuthnRPID, "localhost")
	t.Setenv(EnvWebAuthnRPOrigins, "http://localhost:3000")

	cfg, err := LoadWebAuthn("development")
	if err != nil {
		t.Fatalf("LoadWebAuthn: %v", err)
	}
	if len(cfg.RPOrigins) != 1 || cfg.RPOrigins[0] != "http://localhost:3000" {
		t.Errorf("RPOrigins = %v, want [http://localhost:3000]", cfg.RPOrigins)
	}
}

func TestLoadWebAuthnChallengeTTLBounds(t *testing.T) {
	tests := []struct {
		name       string
		ttl        string
		wantErr    bool
		wantSubstr string
		want       time.Duration
	}{
		{name: "accepted", ttl: "90s", want: 90 * time.Second},
		{name: "at the cap", ttl: "15m", want: 15 * time.Minute},
		{name: "over the cap", ttl: "16m", wantErr: true, wantSubstr: "must not exceed"},
		{name: "far over the cap", ttl: "24h", wantErr: true, wantSubstr: "must not exceed"},
		{name: "zero rejected", ttl: "0s", wantErr: true, wantSubstr: "must be positive"},
		{name: "negative rejected", ttl: "-1m", wantErr: true, wantSubstr: "must be positive"},
		{name: "unparseable rejected", ttl: "five minutes", wantErr: true, wantSubstr: "invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearWebAuthnEnv(t)
			t.Setenv(EnvWebAuthnChallengeTTL, tc.ttl)

			cfg, err := LoadWebAuthn("development")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("LoadWebAuthn(TTL=%q) succeeded, want an error", tc.ttl)
				}
				if !strings.Contains(err.Error(), tc.wantSubstr) {
					t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadWebAuthn(TTL=%q): %v", tc.ttl, err)
			}
			if cfg.ChallengeTTL != tc.want {
				t.Errorf("ChallengeTTL = %v, want %v", cfg.ChallengeTTL, tc.want)
			}
		})
	}
}

func TestLoadWebAuthnUserVerificationValues(t *testing.T) {
	for _, uv := range []string{"required", "preferred", "discouraged"} {
		t.Run("accepts "+uv, func(t *testing.T) {
			clearWebAuthnEnv(t)
			t.Setenv(EnvWebAuthnUserVerification, uv)

			cfg, err := LoadWebAuthn("development")
			if err != nil {
				t.Fatalf("LoadWebAuthn(%q): %v", uv, err)
			}
			if cfg.UserVerification != uv {
				t.Errorf("UserVerification = %q, want %q", cfg.UserVerification, uv)
			}
		})
	}

	for _, uv := range []string{"Required", "yes", "true", "none"} {
		t.Run("rejects "+uv, func(t *testing.T) {
			clearWebAuthnEnv(t)
			t.Setenv(EnvWebAuthnUserVerification, uv)

			_, err := LoadWebAuthn("development")
			if err == nil {
				t.Fatalf("LoadWebAuthn(%q) succeeded, want an error", uv)
			}
			if !strings.Contains(err.Error(), EnvWebAuthnUserVerification) {
				t.Errorf("error = %q, want it to name %s", err.Error(), EnvWebAuthnUserVerification)
			}
		})
	}
}

// TestLoadWebAuthnResidentKeyDefaultsToRequired proves discoverable credentials
// are the default outcome of registration. If this ever silently relaxed,
// authenticators could create non-discoverable credentials and usernameless
// login — the primary path — would stop working for those accounts.
func TestLoadWebAuthnResidentKeyDefaultsToRequired(t *testing.T) {
	clearWebAuthnEnv(t)

	cfg, err := LoadWebAuthn("development")
	if err != nil {
		t.Fatalf("LoadWebAuthn: %v", err)
	}
	if cfg.ResidentKey != "required" {
		t.Errorf("ResidentKey = %q, want %q", cfg.ResidentKey, "required")
	}
}

func TestLoadWebAuthnResidentKeyValues(t *testing.T) {
	for _, rk := range []string{"required", "preferred", "discouraged"} {
		t.Run("accepts "+rk, func(t *testing.T) {
			clearWebAuthnEnv(t)
			t.Setenv(EnvWebAuthnResidentKey, rk)

			cfg, err := LoadWebAuthn("development")
			if err != nil {
				t.Fatalf("LoadWebAuthn(%q): %v", rk, err)
			}
			if cfg.ResidentKey != rk {
				t.Errorf("ResidentKey = %q, want %q", cfg.ResidentKey, rk)
			}
		})
	}

	for _, rk := range []string{"Required", "yes", "resident"} {
		t.Run("rejects "+rk, func(t *testing.T) {
			clearWebAuthnEnv(t)
			t.Setenv(EnvWebAuthnResidentKey, rk)

			_, err := LoadWebAuthn("development")
			if err == nil {
				t.Fatalf("LoadWebAuthn(%q) succeeded, want an error", rk)
			}
			if !strings.Contains(err.Error(), EnvWebAuthnResidentKey) {
				t.Errorf("error = %q, want it to name %s", err.Error(), EnvWebAuthnResidentKey)
			}
		})
	}
}

func TestLoadWebAuthnNamedLoginFloorBounds(t *testing.T) {
	tests := []struct {
		name       string
		floor      string
		wantErr    bool
		wantSubstr string
		want       time.Duration
	}{
		{name: "default", floor: "", want: defaultWebAuthnNamedLoginFloor},
		{name: "accepted", floor: "300ms", want: 300 * time.Millisecond},
		{name: "at the cap", floor: "2s", want: 2 * time.Second},
		{name: "over the cap", floor: "3s", wantErr: true, wantSubstr: "must not exceed"},
		{name: "unparseable rejected", floor: "soon", wantErr: true, wantSubstr: "invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearWebAuthnEnv(t)
			if tc.floor != "" {
				t.Setenv(EnvWebAuthnNamedLoginFloor, tc.floor)
			}

			cfg, err := LoadWebAuthn("development")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("LoadWebAuthn(floor=%q) succeeded, want an error", tc.floor)
				}
				if !strings.Contains(err.Error(), tc.wantSubstr) {
					t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadWebAuthn(floor=%q): %v", tc.floor, err)
			}
			if cfg.NamedLoginFloor != tc.want {
				t.Errorf("NamedLoginFloor = %v, want %v", cfg.NamedLoginFloor, tc.want)
			}
		})
	}
}

// TestLoadWebAuthnRequiresMockKeyOutsideDevelopment enforces the
// no-hardcoded-secrets rule for the one WebAuthn secret. Booting production
// without it would make every decoy locally computable, quietly restoring the
// account-enumeration oracle the mock ceremony exists to close.
func TestLoadWebAuthnRequiresMockKeyOutsideDevelopment(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		t.Run(env, func(t *testing.T) {
			clearWebAuthnEnv(t)
			t.Setenv(EnvWebAuthnRPID, "identity.hatef.ir")
			t.Setenv(EnvWebAuthnRPOrigins, "https://identity.hatef.ir")

			_, err := LoadWebAuthn(env)
			if err == nil {
				t.Fatalf("LoadWebAuthn(%q) succeeded without %s, want an error",
					env, EnvWebAuthnMockChallengeKey)
			}
			if !strings.Contains(err.Error(), EnvWebAuthnMockChallengeKey) {
				t.Errorf("error = %q, want it to name %s", err.Error(), EnvWebAuthnMockChallengeKey)
			}
		})
	}
}

// TestLoadWebAuthnRejectsShortMockKey proves a too-short key is refused rather
// than silently accepted: a guessable key is as good as no key at all.
func TestLoadWebAuthnRejectsShortMockKey(t *testing.T) {
	clearWebAuthnEnv(t)
	t.Setenv(EnvWebAuthnMockChallengeKey, "too-short")

	_, err := LoadWebAuthn("development")
	if err == nil {
		t.Fatal("LoadWebAuthn succeeded with a short mock key, want an error")
	}
	if !strings.Contains(err.Error(), "at least") {
		t.Errorf("error = %q, want it to state the minimum length", err.Error())
	}
}

// TestLoadWebAuthnGeneratesDevelopmentMockKey proves development needs no
// configuration at all: a random per-process key is minted so the service boots.
func TestLoadWebAuthnGeneratesDevelopmentMockKey(t *testing.T) {
	clearWebAuthnEnv(t)

	first, err := LoadWebAuthn("development")
	if err != nil {
		t.Fatalf("LoadWebAuthn: %v", err)
	}
	if len(first.MockChallengeKey) < minWebAuthnMockChallengeKeyLen {
		t.Fatalf("len(MockChallengeKey) = %d, want at least %d",
			len(first.MockChallengeKey), minWebAuthnMockChallengeKeyLen)
	}

	second, err := LoadWebAuthn("development")
	if err != nil {
		t.Fatalf("LoadWebAuthn: %v", err)
	}
	if reflect.DeepEqual(first.MockChallengeKey, second.MockChallengeKey) {
		t.Error("the generated development key repeated; it must be random per load")
	}
}

// TestLoadWebAuthnAcceptsBase64MockKey proves the KMS-shaped form (base64 key
// material) is decoded rather than used as literal text.
func TestLoadWebAuthnAcceptsBase64MockKey(t *testing.T) {
	clearWebAuthnEnv(t)
	raw := bytes.Repeat([]byte{0x5A}, 32)
	t.Setenv(EnvWebAuthnMockChallengeKey, base64.StdEncoding.EncodeToString(raw))

	cfg, err := LoadWebAuthn("development")
	if err != nil {
		t.Fatalf("LoadWebAuthn: %v", err)
	}
	if !bytes.Equal(cfg.MockChallengeKey, raw) {
		t.Errorf("MockChallengeKey = %x, want the decoded %x", cfg.MockChallengeKey, raw)
	}
}

// TestLoadWebAuthnErrorsReturnZeroConfig guards against a caller accidentally
// using a partially-populated config after ignoring the error.

func TestLoadWebAuthnErrorsReturnZeroConfig(t *testing.T) {
	clearWebAuthnEnv(t)
	t.Setenv(EnvWebAuthnRPID, "identity.hatef.ir")
	t.Setenv(EnvWebAuthnUserVerification, "bogus")

	cfg, err := LoadWebAuthn("development")
	if err == nil {
		t.Fatal("LoadWebAuthn succeeded, want an error")
	}
	// RPOrigins is a slice, so the struct is not comparable with ==;
	// reflect.DeepEqual is the equivalent whole-value assertion.
	if !reflect.DeepEqual(cfg, WebAuthnConfig{}) {
		t.Errorf("config = %+v, want the zero value alongside an error", cfg)
	}
}

func TestSplitOrigins(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "single", in: "https://a.example", want: []string{"https://a.example"}},
		{
			name: "multiple with spaces",
			in:   " https://a.example , https://b.example ",
			want: []string{"https://a.example", "https://b.example"},
		},
		{
			name: "trailing comma dropped",
			in:   "https://a.example,",
			want: []string{"https://a.example"},
		},
		{
			name: "blank entries dropped",
			in:   "https://a.example,,  ,https://b.example",
			want: []string{"https://a.example", "https://b.example"},
		},
		{
			name: "trailing slash trimmed so origins compare exactly",
			in:   "https://a.example/,https://b.example",
			want: []string{"https://a.example", "https://b.example"},
		},
		{name: "only separators", in: " , , ", want: []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := splitOrigins(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("splitOrigins(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("splitOrigins(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}
