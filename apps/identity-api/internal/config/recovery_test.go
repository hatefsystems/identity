package config

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
)

// clearRecoveryEnv unsets every recovery variable so a test starts from a known
// state regardless of the ambient environment (t.Setenv restores them on
// cleanup).
func clearRecoveryEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		EnvRecoveryCount,
		EnvRecoveryEntropyBits,
		EnvRecoveryLowThreshold,
		EnvRecoveryPerAccountPerHour,
		EnvRecoveryPerSubnetPerHour,
		EnvRecoveryHashPepper,
	} {
		t.Setenv(k, "")
	}
}

func TestLoadRecoveryDefaults(t *testing.T) {
	clearRecoveryEnv(t)

	cfg, err := LoadRecovery()
	if err != nil {
		t.Fatalf("LoadRecovery: %v", err)
	}
	if cfg.Count != defaultRecoveryCount {
		t.Errorf("Count = %d, want %d", cfg.Count, defaultRecoveryCount)
	}
	if cfg.EntropyBits != defaultRecoveryEntropyBits {
		t.Errorf("EntropyBits = %d, want %d", cfg.EntropyBits, defaultRecoveryEntropyBits)
	}
	if cfg.LowThreshold != defaultRecoveryLowThreshold {
		t.Errorf("LowThreshold = %d, want %d", cfg.LowThreshold, defaultRecoveryLowThreshold)
	}
	if cfg.PerAccountPerHour != defaultRecoveryPerAccountPerHour {
		t.Errorf("PerAccountPerHour = %d, want %d", cfg.PerAccountPerHour, defaultRecoveryPerAccountPerHour)
	}
	if cfg.PerSubnetPerHour != defaultRecoveryPerSubnetPerHour {
		t.Errorf("PerSubnetPerHour = %d, want %d", cfg.PerSubnetPerHour, defaultRecoveryPerSubnetPerHour)
	}
	if cfg.HashPepper != nil {
		t.Errorf("HashPepper = %v, want nil when unset", cfg.HashPepper)
	}
	// The default entropy must satisfy the domain floor, or New would reject it.
	if cfg.EntropyBits < recovery.MinEntropyBits {
		t.Errorf("default EntropyBits %d is below the %d floor", cfg.EntropyBits, recovery.MinEntropyBits)
	}
}

func TestLoadRecoveryOverrides(t *testing.T) {
	clearRecoveryEnv(t)
	t.Setenv(EnvRecoveryCount, "8")
	t.Setenv(EnvRecoveryEntropyBits, "200")
	t.Setenv(EnvRecoveryLowThreshold, "2")
	t.Setenv(EnvRecoveryPerAccountPerHour, "15")
	t.Setenv(EnvRecoveryPerSubnetPerHour, "25")

	cfg, err := LoadRecovery()
	if err != nil {
		t.Fatalf("LoadRecovery: %v", err)
	}
	if cfg.Count != 8 {
		t.Errorf("Count = %d, want 8", cfg.Count)
	}
	if cfg.EntropyBits != 200 {
		t.Errorf("EntropyBits = %d, want 200", cfg.EntropyBits)
	}
	if cfg.LowThreshold != 2 {
		t.Errorf("LowThreshold = %d, want 2", cfg.LowThreshold)
	}
	if cfg.PerAccountPerHour != 15 {
		t.Errorf("PerAccountPerHour = %d, want 15", cfg.PerAccountPerHour)
	}
	if cfg.PerSubnetPerHour != 25 {
		t.Errorf("PerSubnetPerHour = %d, want 25", cfg.PerSubnetPerHour)
	}
}

func TestLoadRecoveryRejectsSubFloorEntropy(t *testing.T) {
	clearRecoveryEnv(t)
	t.Setenv(EnvRecoveryEntropyBits, "127")

	if _, err := LoadRecovery(); err == nil {
		t.Fatal("LoadRecovery with entropy below the floor = nil error, want error")
	}
}

func TestLoadRecoveryAcceptsFloorEntropy(t *testing.T) {
	clearRecoveryEnv(t)
	t.Setenv(EnvRecoveryEntropyBits, "128")

	cfg, err := LoadRecovery()
	if err != nil {
		t.Fatalf("LoadRecovery at the floor = %v, want nil", err)
	}
	if cfg.EntropyBits != recovery.MinEntropyBits {
		t.Errorf("EntropyBits = %d, want %d", cfg.EntropyBits, recovery.MinEntropyBits)
	}
}

func TestLoadRecoveryRejectsNonPositiveInt(t *testing.T) {
	cases := map[string]string{
		EnvRecoveryCount:             "0",
		EnvRecoveryLowThreshold:      "-1",
		EnvRecoveryPerAccountPerHour: "abc",
		EnvRecoveryPerSubnetPerHour:  "-5",
	}
	for envKey, badValue := range cases {
		t.Run(envKey+"="+badValue, func(t *testing.T) {
			clearRecoveryEnv(t)
			t.Setenv(envKey, badValue)
			if _, err := LoadRecovery(); err == nil {
				t.Errorf("LoadRecovery with %s=%q = nil error, want error", envKey, badValue)
			}
		})
	}
}

func TestLoadRecoveryValidPepper(t *testing.T) {
	clearRecoveryEnv(t)
	raw := bytes.Repeat([]byte{0x7}, 24)
	t.Setenv(EnvRecoveryHashPepper, base64.StdEncoding.EncodeToString(raw))

	cfg, err := LoadRecovery()
	if err != nil {
		t.Fatalf("LoadRecovery with a valid pepper = %v, want nil", err)
	}
	if !bytes.Equal(cfg.HashPepper, raw) {
		t.Error("HashPepper does not match the decoded input")
	}
}

func TestLoadRecoveryInvalidPepperBase64(t *testing.T) {
	clearRecoveryEnv(t)
	t.Setenv(EnvRecoveryHashPepper, "not!valid!base64!")

	if _, err := LoadRecovery(); err == nil {
		t.Fatal("LoadRecovery with a non-base64 pepper = nil error, want error")
	}
}

func TestLoadRecoveryShortPepper(t *testing.T) {
	clearRecoveryEnv(t)
	// 15 bytes: one short of the 16-byte minimum.
	raw := bytes.Repeat([]byte{0x1}, minRecoveryHashPepperBytes-1)
	t.Setenv(EnvRecoveryHashPepper, base64.StdEncoding.EncodeToString(raw))

	if _, err := LoadRecovery(); err == nil {
		t.Fatal("LoadRecovery with a short pepper = nil error, want error")
	}
}

// TestLoadRecoveryConfigDrivesService is a guard against config/domain drift: the
// values LoadRecovery produces must be accepted by recovery.New unchanged.
func TestLoadRecoveryConfigDrivesService(t *testing.T) {
	clearRecoveryEnv(t)
	cfg, err := LoadRecovery()
	if err != nil {
		t.Fatalf("LoadRecovery: %v", err)
	}

	if cfg.EntropyBits < recovery.MinEntropyBits {
		t.Fatalf("loaded EntropyBits %d would be rejected by recovery.New", cfg.EntropyBits)
	}
}
