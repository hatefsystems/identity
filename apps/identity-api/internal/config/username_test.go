package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"testing/quick"
)

const usernamePolicyFixture = `{"id":"d0bbd127-a362-42d0-91e1-78bb8b273d79","normalization":"nfc-four-fold-v1","folds":[{"from":"\u064a","to":"\u06cc"},{"from":"\u0643","to":"\u06a9"},{"from":"\u0624","to":"\u0648"},{"from":"\u0626","to":"\u06cc"}],"reserved_names":[]}`
const usernameRegexFixture = `[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+(?:\.[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+)*`

func setUsernameFixture(t *testing.T) {
	t.Helper()
	t.Setenv("APP_ENV", "test")
	t.Setenv(EnvUsernameEnabled, "true")
	t.Setenv(EnvUsernamePolicyJSON, usernamePolicyFixture)
	t.Setenv(EnvUsernameRegex, usernameRegexFixture)
	t.Setenv(EnvUsernameLookupKey, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x59}, 32)))
	t.Setenv(EnvUsernameLookupKeyID, "username-test-1")
	t.Setenv(EnvBlindIndexPepper, "")
}

func TestUsernameConfigDisabledIsolation(t *testing.T) {
	for _, mode := range []string{"", "false"} {
		t.Run("disabled-"+mode, func(t *testing.T) {
			t.Setenv(EnvUsernameEnabled, mode)
			t.Setenv("APP_ENV", "invalid")
			for _, key := range []string{EnvUsernamePolicyJSON, EnvUsernameRegex, EnvUsernameLookupKey, EnvUsernameLookupKeyID} {
				t.Setenv(key, "invalid")
			}
			cfg, err := LoadUsername()
			if err != nil || cfg.Enabled || cfg.Normalizer != nil {
				t.Fatal("disabled feature loaded unrelated configuration")
			}
		})
	}
}

func TestUsernameConfigExplicitRequiredAndStrict(t *testing.T) {
	for _, key := range []string{EnvUsernamePolicyJSON, EnvUsernameRegex, EnvUsernameLookupKey, EnvUsernameLookupKeyID, "APP_ENV"} {
		t.Run("missing-"+key, func(t *testing.T) {
			setUsernameFixture(t)
			t.Setenv(key, "")
			if cfg, err := LoadUsername(); err == nil || cfg.Enabled || cfg.Normalizer != nil {
				t.Fatal("required configuration defaulted")
			}
		})
	}
	for _, test := range []struct{ key, value string }{
		{EnvUsernameEnabled, "TRUE"}, {EnvUsernameEnabled, "true "}, {"APP_ENV", "prod"},
		{EnvUsernameRegex, ".*"}, {EnvUsernameRegex, `x)|(?:y`}, {EnvUsernameRegex, strings.Repeat("x", 4097)},
		{EnvUsernamePolicyJSON, strings.Replace(usernamePolicyFixture, `"reserved_names":[]`, `"reserved_names":null`, 1)},
		{EnvUsernamePolicyJSON, strings.Replace(usernamePolicyFixture, `"id":`, `"extra":1,"id":`, 1)},
		{EnvUsernamePolicyJSON, strings.Replace(usernamePolicyFixture, `"normalization":`, `"normalization":"nfc-four-fold-v1","normalization":`, 1)},
		{EnvUsernamePolicyJSON, strings.Replace(usernamePolicyFixture, `"to":"\u06cc"`, `"to":"\u0633"`, 1)},
		{EnvUsernameLookupKey, "private-invalid-key-material"},
		{EnvUsernameLookupKey, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31))},
		{EnvUsernameLookupKey, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + "\n"},
		{EnvUsernameLookupKeyID, " bad"},
	} {
		t.Run("invalid-"+test.key, func(t *testing.T) {
			setUsernameFixture(t)
			t.Setenv(test.key, test.value)
			_, err := LoadUsername()
			if err == nil {
				t.Fatal("invalid configuration admitted")
			}
			if strings.Contains(err.Error(), test.value) && len(test.value) > 16 {
				t.Fatal("configuration value disclosed by error")
			}
		})
	}
}

func TestUsernameConfigKeyIsolationProductionAndImmutability(t *testing.T) {
	setUsernameFixture(t)
	cfg, err := LoadUsername()
	if err != nil || !cfg.Enabled || cfg.Normalizer == nil {
		t.Fatal(err)
	}
	authority := cfg.Normalizer.Authority()
	t.Setenv(EnvUsernameRegex, "invalid[")
	t.Setenv(EnvUsernameLookupKey, "invalid")
	if cfg.Normalizer.Authority() != authority {
		t.Fatal("environment edit mutated active policy")
	}
	setUsernameFixture(t)
	t.Setenv(EnvBlindIndexPepper, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x59}, 32)))
	if _, err := LoadUsername(); err == nil {
		t.Fatal("shared lookup pepper admitted")
	}
	setUsernameFixture(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv(EnvUsernameLookupKey, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	if _, err := LoadUsername(); err == nil {
		t.Fatal("public all-zero production key admitted")
	}
	setUsernameFixture(t)
	t.Setenv(EnvUsernameLookupKey, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64)))
	if _, err := LoadUsername(); err != nil {
		t.Fatal("valid long key rejected")
	}
}

func TestUsernameConfigCanonicalKeyProperty(t *testing.T) {
	setUsernameFixture(t)
	property := func(key []byte) bool {
		t.Setenv(EnvUsernameLookupKey, base64.StdEncoding.EncodeToString(key))
		cfg, err := LoadUsername()
		if len(key) < 32 {
			return err != nil && cfg.Normalizer == nil && !cfg.Enabled
		}
		if err != nil || !cfg.Enabled || cfg.Normalizer == nil {
			return false
		}
		authority := cfg.Normalizer.Authority()
		t.Setenv(EnvUsernameLookupKey, base64.StdEncoding.EncodeToString(key)+"\n")
		_, err = LoadUsername()
		return err != nil && cfg.Normalizer.Authority() == authority
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 250}); err != nil {
		t.Fatal(err)
	}
}
