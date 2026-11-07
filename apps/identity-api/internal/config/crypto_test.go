package config

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// randB64 returns a base64-encoded random byte slice of the given length.
func randB64(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestLoadCryptoValid(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	kekB64 := randB64(t, 32)
	pepperB64 := randB64(t, 32)
	t.Setenv(EnvMasterKEK, kekB64)
	t.Setenv(EnvMasterKEKVersion, "3")
	t.Setenv(EnvBlindIndexPepper, pepperB64)

	cfg, err := LoadCrypto()
	if err != nil {
		t.Fatalf("LoadCrypto: %v", err)
	}

	wantKEK, _ := base64.StdEncoding.DecodeString(kekB64)
	if !bytes.Equal(cfg.MasterKEK, wantKEK) {
		t.Error("MasterKEK does not match decoded input")
	}
	if len(cfg.MasterKEK) != 32 {
		t.Errorf("MasterKEK len = %d, want 32", len(cfg.MasterKEK))
	}
	if cfg.MasterKEKVersion != 3 {
		t.Errorf("MasterKEKVersion = %d, want 3", cfg.MasterKEKVersion)
	}
	if len(cfg.BlindIndexPepper) != 32 {
		t.Errorf("BlindIndexPepper len = %d, want 32", len(cfg.BlindIndexPepper))
	}
}

func TestLoadCryptoDefaultVersion(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv(EnvMasterKEK, randB64(t, 32))
	t.Setenv(EnvMasterKEKVersion, "")
	t.Setenv(EnvBlindIndexPepper, randB64(t, 32))

	cfg, err := LoadCrypto()
	if err != nil {
		t.Fatalf("LoadCrypto: %v", err)
	}
	if cfg.MasterKEKVersion != 1 {
		t.Errorf("default MasterKEKVersion = %d, want 1", cfg.MasterKEKVersion)
	}
}

func TestLoadCryptoMissingKEK(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv(EnvMasterKEK, "")
	t.Setenv(EnvBlindIndexPepper, randB64(t, 32))
	if _, err := LoadCrypto(); err == nil {
		t.Fatal("LoadCrypto with missing KEK = nil error, want error")
	}
}

func TestLoadCryptoMissingPepper(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv(EnvMasterKEK, randB64(t, 32))
	t.Setenv(EnvBlindIndexPepper, "")
	if _, err := LoadCrypto(); err == nil {
		t.Fatal("LoadCrypto with missing pepper = nil error, want error")
	}
}

func TestLoadCryptoInvalidBase64(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv(EnvMasterKEK, "not!valid!base64!")
	t.Setenv(EnvBlindIndexPepper, randB64(t, 32))
	if _, err := LoadCrypto(); err == nil {
		t.Fatal("LoadCrypto with invalid base64 KEK = nil error, want error")
	}
}

func TestLoadCryptoWrongKEKSize(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	cases := map[string]int{
		"16-bytes": 16,
		"24-bytes": 24,
		"48-bytes": 48,
	}
	for name, size := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(EnvMasterKEK, randB64(t, size))
			t.Setenv(EnvBlindIndexPepper, randB64(t, 32))
			if _, err := LoadCrypto(); err == nil {
				t.Fatalf("LoadCrypto with %d-byte KEK = nil error, want error", size)
			}
		})
	}
}

func TestLoadCryptoShortPepper(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv(EnvMasterKEK, randB64(t, 32))
	t.Setenv(EnvBlindIndexPepper, randB64(t, 16))
	if _, err := LoadCrypto(); err == nil {
		t.Fatal("LoadCrypto with short pepper = nil error, want error")
	}
}

func TestLoadCryptoInvalidVersion(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	cases := map[string]string{
		"non-numeric":  "abc",
		"out-of-range": "256",
		"negative":     "-1",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(EnvMasterKEK, randB64(t, 32))
			t.Setenv(EnvBlindIndexPepper, randB64(t, 32))
			t.Setenv(EnvMasterKEKVersion, value)
			if _, err := LoadCrypto(); err == nil {
				t.Fatalf("LoadCrypto with version %q = nil error, want error", value)
			}
		})
	}
}

func TestCryptoPublicSentinelIsProductionOnly(t *testing.T) {
	for _, environment := range []string{"development", "test", "production"} {
		for _, key := range []string{EnvMasterKEK, EnvBlindIndexPepper} {
			t.Run(environment+"/"+key, func(t *testing.T) {
				t.Setenv("APP_ENV", environment)
				t.Setenv(EnvMasterKEK, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
				t.Setenv(EnvBlindIndexPepper, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
				t.Setenv(key, base64.StdEncoding.EncodeToString(make([]byte, 32)))
				_, err := LoadCrypto()
				if environment == "production" {
					if err == nil || !strings.Contains(err.Error(), key) {
						t.Fatalf("public sentinel accepted or wrong setting: %v", err)
					}
				} else if err != nil {
					t.Fatalf("explicit primitive test vector rejected: %v", err)
				}
			})
		}
	}
}

func TestCryptoRejectsOnlyExactPublicSentinel(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv(EnvMasterKEKVersion, "")
	t.Setenv(EnvBlindIndexPepperVersion, "")
	for _, value := range [][]byte{append(make([]byte, 31), 1), bytes.Repeat([]byte{1}, 32)} {
		t.Setenv(EnvMasterKEK, base64.StdEncoding.EncodeToString(value))
		t.Setenv(EnvBlindIndexPepper, base64.StdEncoding.EncodeToString(value))
		if _, err := LoadCrypto(); err != nil {
			t.Fatalf("unapproved entropy heuristic: %v", err)
		}
	}
	t.Setenv(EnvBlindIndexPepper, base64.StdEncoding.EncodeToString(make([]byte, 33)))
	if _, err := LoadBlindIndexPepper(); err != nil {
		t.Fatalf("non-sentinel pepper rejected: %v", err)
	}
}

func TestEnvelopeCryptoIndependentOfLookupAndAPISecrets(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv(EnvMasterKEK, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	t.Setenv(EnvMasterKEKVersion, "")
	for _, key := range []string{EnvBlindIndexPepper, EnvBlindIndexPepperVersion, EnvOIDCClients, EnvOIDCSigningKey, "SMS_GATEWAY_API_KEY"} {
		t.Setenv(key, "unrelated-invalid-setting")
	}
	if _, err := LoadEnvelopeCrypto(); err != nil {
		t.Fatalf("encryption depends on unrelated secrets: %v", err)
	}
}

func TestLoadBlindIndexPepperVersionBounds(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int16
		bad  bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"-0", 0, false},
		{"+7", 7, false},
		{"32767", 32767, false},
		{"-1", 0, true},
		{"32768", 0, true},
		{"65536", 0, true},
		{"18446744073709551616", 0, true},
		{"invalid", 0, true},
	} {
		t.Run("value_"+tc.raw, func(t *testing.T) {
			t.Setenv(EnvBlindIndexPepperVersion, tc.raw)
			got, err := LoadBlindIndexPepperVersion()
			if (err != nil) != tc.bad || (!tc.bad && got != tc.want) {
				t.Fatalf("version %q = %d, %v; want %d, error=%t", tc.raw, got, err, tc.want, tc.bad)
			}
		})
	}
}
