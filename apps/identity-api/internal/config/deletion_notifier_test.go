package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func deletionNotifierEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		EnvDeletionSMTPHost, EnvDeletionSMTPPort, EnvDeletionSMTPTLSMode, EnvDeletionSMTPUsername,
		EnvDeletionSMTPPassword, EnvDeletionSMTPFrom, EnvDeletionSMTPPublicOrigin, EnvDeletionSMTPTimeout,
		EnvDeletionSMTPCABundle, EnvDeletionNotifierDatabaseURL, EnvDeletionNotifierBatchSize,
		EnvDeletionNotifierConcurrency, EnvDeletionNotifierLeaseDuration, EnvDeletionNotifierRetryBase,
		EnvDeletionNotifierRetryMax, EnvDeletionNotifierPollInterval, EnvDeletionNotifierStartupTimeout,
		"APP_ENV", EnvGDPRGracePeriod, EnvGDPRReclaimMaxAttempts,
	} {
		t.Setenv(key, "")
	}
	t.Setenv(EnvDeletionSMTPHost, "relay.example.test")
	t.Setenv(EnvDeletionSMTPUsername, "notifier")
	t.Setenv(EnvDeletionSMTPPassword, "private-password")
	t.Setenv(EnvDeletionSMTPFrom, "accounts@example.test")
	t.Setenv(EnvDeletionSMTPPublicOrigin, "https://identity.example.test")
	t.Setenv(EnvDeletionNotifierDatabaseURL, "postgres://notifier:private-password@localhost/identity")
}

func TestDeletionNotifierDefaults(t *testing.T) {
	deletionNotifierEnvironment(t)
	cfg, err := LoadDeletionNotifier()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMTP.TLSMode != DeletionSMTPStartTLS || cfg.SMTP.Port != 587 || cfg.SMTP.Timeout != 15*time.Second ||
		cfg.SMTP.CABundlePath != "" || cfg.BatchSize != 50 || cfg.Concurrency != 4 || cfg.LeaseDuration != time.Minute ||
		cfg.RetryBase != 30*time.Second || cfg.RetryMax != time.Hour || cfg.PollInterval != 5*time.Second || cfg.StartupTimeout != 15*time.Second ||
		cfg.GracePeriod != 720*time.Hour || cfg.ReclaimMaxAttempts != 5 {
		t.Fatal("SMTP/worker defaults changed")
	}
	t.Setenv(EnvDeletionSMTPTLSMode, DeletionSMTPImplicit)
	implicit, err := LoadDeletionSMTP()
	if err != nil || implicit.Port != 465 {
		t.Fatal("implicit TLS did not select its secure default port")
	}
}

func TestDeletionNotifierOverrides(t *testing.T) {
	deletionNotifierEnvironment(t)
	for key, value := range map[string]string{
		EnvDeletionSMTPHost: "::1", EnvDeletionSMTPPort: "2465", EnvDeletionSMTPTLSMode: DeletionSMTPImplicit,
		EnvDeletionSMTPFrom: "support+deletion@example.test", EnvDeletionSMTPPublicOrigin: "https://[::1]:8443",
		EnvDeletionSMTPTimeout: "2s", EnvDeletionSMTPCABundle: "/run/secrets/relay-ca.pem",
		EnvDeletionNotifierBatchSize: "17", EnvDeletionNotifierConcurrency: "2", EnvDeletionNotifierLeaseDuration: "20s",
		EnvDeletionNotifierRetryBase: "3s", EnvDeletionNotifierRetryMax: "8s",
		EnvDeletionNotifierPollInterval: "25ms", EnvDeletionNotifierStartupTimeout: "3s",
	} {
		t.Setenv(key, value)
	}
	cfg, err := LoadDeletionNotifier()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMTP.Host != "::1" || cfg.SMTP.Port != 2465 || cfg.SMTP.Timeout != 2*time.Second || cfg.SMTP.CABundlePath != "/run/secrets/relay-ca.pem" ||
		cfg.BatchSize != 17 || cfg.Concurrency != 2 || cfg.LeaseDuration != 20*time.Second || cfg.RetryBase != 3*time.Second ||
		cfg.RetryMax != 8*time.Second || cfg.PollInterval != 25*time.Millisecond || cfg.StartupTimeout != 3*time.Second {
		t.Fatal("SMTP/worker bounds did not apply")
	}
}

func TestDeletionSMTPRequiredConfiguration(t *testing.T) {
	for _, key := range []string{EnvDeletionSMTPHost, EnvDeletionSMTPUsername, EnvDeletionSMTPPassword, EnvDeletionSMTPFrom, EnvDeletionSMTPPublicOrigin} {
		t.Run(key, func(t *testing.T) {
			deletionNotifierEnvironment(t)
			t.Setenv(key, "")
			if _, err := LoadDeletionSMTP(); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal("missing required SMTP setting was not identified")
			}
		})
	}
}

func TestDeletionSMTPRejectsInsecureOrAmbiguousConfiguration(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{EnvDeletionSMTPTLSMode, "plaintext"}, {EnvDeletionSMTPTLSMode, "opportunistic"}, {EnvDeletionSMTPTLSMode, "STARTTLS"},
		{EnvDeletionSMTPHost, "relay.example.test:587"}, {EnvDeletionSMTPHost, "relay.example.test\r\nAUTH PLAIN private"},
		{EnvDeletionSMTPHost, " relay.example.test"}, {EnvDeletionSMTPHost, "Relay.example.test"},
		{EnvDeletionSMTPHost, "relay.example.test."}, {EnvDeletionSMTPHost, "[::1]"}, {EnvDeletionSMTPHost, "fe80::1%lo"},
		{EnvDeletionSMTPHost, "::ffff:127.0.0.1"}, {EnvDeletionSMTPHost, "bad_host.example.test"},
		{EnvDeletionSMTPHost, strings.Repeat("a", 64) + ".example.test"},
		{EnvDeletionSMTPPort, "0"}, {EnvDeletionSMTPPort, "65536"}, {EnvDeletionSMTPPort, "private-password"},
		{EnvDeletionSMTPUsername, " "}, {EnvDeletionSMTPUsername, "private\nusername"}, {EnvDeletionSMTPUsername, strings.Repeat("a", 257)},
		{EnvDeletionSMTPPassword, "   "}, {EnvDeletionSMTPPassword, "private\r\npassword"}, {EnvDeletionSMTPPassword, strings.Repeat("a", 1025)},
		{EnvDeletionSMTPFrom, "Sender <private@example.test>"}, {EnvDeletionSMTPFrom, "a@example.test,b@example.test"},
		{EnvDeletionSMTPFrom, "a@example.test\r\nBcc: private@example.test"}, {EnvDeletionSMTPFrom, "a@127.0.0.1"},
		{EnvDeletionSMTPPublicOrigin, "http://localhost"}, {EnvDeletionSMTPPublicOrigin, "https://identity.example.test/"},
		{EnvDeletionSMTPPublicOrigin, "https://private:password@identity.example.test"},
		{EnvDeletionSMTPPublicOrigin, "https://identity.example.test?token=private"},
		{EnvDeletionSMTPPublicOrigin, "https://identity.example.test#token=private"},
		{EnvDeletionSMTPPublicOrigin, "https://identity.example.test#"}, {EnvDeletionSMTPPublicOrigin, "https://identity.example.test?"},
		{EnvDeletionSMTPPublicOrigin, "https://identity.example.test:443"}, {EnvDeletionSMTPPublicOrigin, "https://127.1"},
		{EnvDeletionSMTPPublicOrigin, "https://identity.example.test:08443"}, {EnvDeletionSMTPPublicOrigin, "https://IDENTITY.example.test"},
		{EnvDeletionSMTPPublicOrigin, "https://identity.example.test/\r\nprivate"},
		{EnvDeletionSMTPTimeout, "0"}, {EnvDeletionSMTPTimeout, "1ns"}, {EnvDeletionSMTPTimeout, "61s"},
		{EnvDeletionSMTPTimeout, "private-password"}, {EnvDeletionSMTPCABundle, "private\npath"},
	} {
		t.Run(tc.key+"/"+fmt.Sprint(len(tc.value)), func(t *testing.T) {
			deletionNotifierEnvironment(t)
			t.Setenv(tc.key, tc.value)
			_, err := LoadDeletionSMTP()
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatal("unsafe SMTP configuration accepted or setting unidentified")
			}
			if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "private") {
				t.Fatal("configuration error retained a supplied secret")
			}
		})
	}
}

func TestDeletionSMTPAddressValidation(t *testing.T) {
	for _, address := range []string{"a@example.test", "a@EXAMPLE.test", "first.last+tag@example.test", "a!#$%&'*+-/=?^_`{|}~b@example.test", strings.Repeat("a", 64) + "@example.test"} {
		if err := ValidateDeletionSMTPAddress(address); err != nil {
			t.Fatal("valid dot-atom address rejected")
		}
	}
	for _, address := range []string{
		"", "@example.test", "a@", "a@@example.test", "a@localhost", "a@127.0.0.1", "a@[127.0.0.1]", "a@[::1]",
		"a@example.test.", "a@-example.test", ".a@example.test", "a.@example.test", "a..b@example.test",
		"a@example.test,b@example.test", "a@example.test;", "<a@example.test>", "Name <a@example.test>", "a(comment)@example.test",
		"\"a b\"@example.test", "a b@example.test", "a\tb@example.test", "a\x00b@example.test", "a\x7fb@example.test",
		"a@example.test\r\nBcc: b@example.test", "jos\u00e9@example.test", "a@ex\u00e1mple.test", strings.Repeat("a", 65) + "@example.test",
	} {
		if err := ValidateDeletionSMTPAddress(address); err == nil {
			t.Fatal("invalid, internationalized, or multiple-recipient address accepted")
		}
	}
}

func TestDeletionSMTPDirectConfigurationRejectsSASLSeparators(t *testing.T) {
	deletionNotifierEnvironment(t)
	cfg, err := LoadDeletionSMTP()
	if err != nil {
		t.Fatal(err)
	}
	for _, username := range []bool{false, true} {
		invalid := cfg
		if username {
			invalid.Username = "private\x00username"
		} else {
			invalid.Password = "private\x00password"
		}
		if err := invalid.Validate(); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("direct config accepted a SASL separator or exposed credentials")
		}
	}
}

func TestDeletionNotifierIsolationAndBounds(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{EnvDeletionNotifierDatabaseURL, ""}, {EnvDeletionNotifierDatabaseURL, " "}, {EnvDeletionNotifierDatabaseURL, "private\nDSN"},
		{EnvDeletionNotifierBatchSize, "0"}, {EnvDeletionNotifierBatchSize, "201"},
		{EnvDeletionNotifierConcurrency, "0"}, {EnvDeletionNotifierConcurrency, "17"},
		{EnvDeletionNotifierLeaseDuration, "19s"}, {EnvDeletionNotifierLeaseDuration, "6m"},
		{EnvDeletionNotifierRetryBase, "0s"}, {EnvDeletionNotifierRetryBase, "2h"},
		{EnvDeletionNotifierRetryMax, "1s"}, {EnvDeletionNotifierRetryMax, "25h"},
		{EnvDeletionNotifierPollInterval, "1ms"}, {EnvDeletionNotifierPollInterval, "2m"},
		{EnvDeletionNotifierStartupTimeout, "1ns"}, {EnvDeletionNotifierStartupTimeout, "2m"},
		{EnvDeletionNotifierStartupTimeout, "private-password"}, {EnvDeletionNotifierBatchSize, "private-password"},
	} {
		t.Run(tc.key+"/"+fmt.Sprint(len(tc.value)), func(t *testing.T) {
			deletionNotifierEnvironment(t)
			t.Setenv("DATABASE_URL", "postgres://api:private-password@localhost/identity")
			t.Setenv(tc.key, tc.value)
			if _, err := LoadDeletionNotifier(); err == nil || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "private") {
				t.Fatal("invalid worker bound accepted, API credentials substituted, or error disclosed value")
			}
		})
	}
	deletionNotifierEnvironment(t)
	t.Setenv("DATABASE_URL", "unrelated private API DSN")
	t.Setenv("GDPR_DELETION_ENABLED", "false")
	t.Setenv(EnvBlindIndexPepper, "unrelated private pepper")
	if _, err := LoadDeletionNotifier(); err != nil {
		t.Fatal("delivery depends on API switch, API credentials, or lookup pepper")
	}
}

func TestDeletionNotifierSharedPolicyAndAPIIndependence(t *testing.T) {
	deletionNotifierEnvironment(t)
	t.Setenv("GDPR_DELETION_ENABLED", "unrelated invalid switch")
	t.Setenv(EnvGDPRPurgeBatchSize, "unrelated invalid batch")
	t.Setenv(EnvGDPRPurgeDryRun, "unrelated invalid dry run")
	t.Setenv(EnvGDPRDeletePerAccountPerDay, "unrelated invalid rate")
	if _, err := LoadDeletionNotifier(); err != nil {
		t.Fatal("notification drainage depends on unrelated API/purge settings")
	}
	for _, environment := range []string{"", "production", "staging", "development", "test"} {
		for _, grace := range []string{"24h", "720h", "721h"} {
			t.Run(environment+"/"+grace, func(t *testing.T) {
				t.Setenv("APP_ENV", environment)
				t.Setenv(EnvGDPRGracePeriod, grace)
				_, err := LoadDeletionNotifier()
				wantValid := grace == "720h" || environment == "development" || environment == "test"
				if (err == nil) != wantValid {
					t.Fatal("worker recovery window diverged from production policy")
				}
			})
		}
	}
	for _, tc := range []struct{ key, value string }{
		{EnvGDPRGracePeriod, "23h"}, {EnvGDPRGracePeriod, "private-token"},
		{EnvGDPRReclaimMaxAttempts, "0"}, {EnvGDPRReclaimMaxAttempts, "2147483648"}, {EnvGDPRReclaimMaxAttempts, "private-token"},
	} {
		t.Run(tc.key+"/"+fmt.Sprint(len(tc.value)), func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			_, err := LoadDeletionNotifier()
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("invalid shared policy accepted or disclosed")
			}
		})
	}
}
