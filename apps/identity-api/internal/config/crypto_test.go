package config

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
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
	t.Setenv(EnvMasterKEK, "")
	t.Setenv(EnvBlindIndexPepper, randB64(t, 32))
	if _, err := LoadCrypto(); err == nil {
		t.Fatal("LoadCrypto with missing KEK = nil error, want error")
	}
}

func TestLoadCryptoMissingPepper(t *testing.T) {
	t.Setenv(EnvMasterKEK, randB64(t, 32))
	t.Setenv(EnvBlindIndexPepper, "")
	if _, err := LoadCrypto(); err == nil {
		t.Fatal("LoadCrypto with missing pepper = nil error, want error")
	}
}

func TestLoadCryptoInvalidBase64(t *testing.T) {
	t.Setenv(EnvMasterKEK, "not!valid!base64!")
	t.Setenv(EnvBlindIndexPepper, randB64(t, 32))
	if _, err := LoadCrypto(); err == nil {
		t.Fatal("LoadCrypto with invalid base64 KEK = nil error, want error")
	}
}

func TestLoadCryptoWrongKEKSize(t *testing.T) {
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
	t.Setenv(EnvMasterKEK, randB64(t, 32))
	t.Setenv(EnvBlindIndexPepper, randB64(t, 16))
	if _, err := LoadCrypto(); err == nil {
		t.Fatal("LoadCrypto with short pepper = nil error, want error")
	}
}

func TestLoadCryptoInvalidVersion(t *testing.T) {
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
