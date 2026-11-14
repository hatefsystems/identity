package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
)

func productionStartupEnvironment(t *testing.T) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	nextKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nextDER, err := x509.MarshalPKCS8PrivateKey(nextKey)
	if err != nil {
		t.Fatal(err)
	}
	encodedNextKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nextDER}))
	for name, value := range map[string]string{
		"APP_ENV":                             "production",
		"PORTAL_ORIGIN":                       "https://identity.example.test",
		"OIDC_ISSUER":                         "https://identity.example.test",
		"OIDC_SIGNING_KEY_ACTIVE_PEM":         encodedKey,
		"OIDC_SIGNING_KEY_NEXT_PEM":           encodedNextKey,
		"OIDC_SIGNING_KEY_PREVIOUS_PEM":       "",
		"OIDC_CLIENTS_JSON":                   `[{"client_id":"portal","redirect_uris":["https://identity.example.test/callback"],"token_endpoint_auth_method":"none","allowed_scopes":["openid"]}]`,
		"WEBAUTHN_RP_ID":                      "identity.example.test",
		"WEBAUTHN_RP_ORIGINS":                 "https://identity.example.test",
		"WEBAUTHN_MOCK_CHALLENGE_KEY":         base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)),
		"DATABASE_URL":                        "postgres://127.0.0.1:1/invalid?sslmode=disable",
		"REDIS_URL":                           "redis://127.0.0.1:1/0",
		"NATS_URL":                            "nats://127.0.0.1:1",
		"ENVELOPE_MASTER_KEK":                 base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		"ENVELOPE_MASTER_KEK_VERSION":         "1",
		"ENVELOPE_BLIND_INDEX_PEPPER":         base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32)),
		"ENVELOPE_BLIND_INDEX_PEPPER_VERSION": "7",
		"STEPUP_REPLAY_HMAC_KEY":              base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32)),
		"SESSION_COOKIE_SECURE":               "true",
		"SESSION_COOKIE_NAME":                 "__Host-session",
		"SESSION_ABSOLUTE_TTL":                "24h",
		"SESSION_IDLE_TTL":                    "2h",
		"SMS_ENABLED":                         "false",
		"REGISTRATION_ENABLED":                "false",
		"USERNAME_ENABLED":                    "false",
		"ADMIN_ENABLED":                       "false",
		"GRPC_ENABLED":                        "false",
		"GDPR_DELETION_ENABLED":               "false",
	} {
		t.Setenv(name, value)
	}
}

func TestComposedStartupRejectsInvalidSettingsBeforeDial(t *testing.T) {
	for _, test := range []struct{ name, value, want string }{
		{"APP_ENV", "", "APP_ENV"},
		{"APP_ENV", " development", "APP_ENV"},
		{"APP_ENV", "staging", "APP_ENV"},
		{"OIDC_ISSUER", "https://identity.example.test?", "issuer"},
		{"OIDC_ISSUER", "https://identity.example.test#", "issuer"},
		{"OIDC_SIGNING_KEY_ACTIVE_PEM", "", "KEY"},
		{"OIDC_CLIENTS_JSON", `[{"client_id":"portal","redirect_uris":["https://identity.example.test/callback#"],"token_endpoint_auth_method":"none","allowed_scopes":["openid"]}]`, "redirect"},
		{"DATABASE_URL", "", "DATABASE_URL"},
		{"REDIS_URL", "", "REDIS_URL"},
		{"NATS_URL", "", "NATS_URL"},
		{"SESSION_COOKIE_SECURE", "false", "session cookie"},
		{"ENVELOPE_MASTER_KEK", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "ENVELOPE_MASTER_KEK"},
		{"ENVELOPE_BLIND_INDEX_PEPPER", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "ENVELOPE_BLIND_INDEX_PEPPER"},
		{"STEPUP_REPLAY_HMAC_KEY", "", "STEPUP_REPLAY_HMAC_KEY"},
		{"SMS_ENABLED", "true", "SMS_PROVIDER"},
		{"REGISTRATION_ENABLED", "true", "REGISTRATION_PENDING_CAPACITY"},
	} {
		t.Run(test.name+"/"+test.want, func(t *testing.T) {
			productionStartupEnvironment(t)
			t.Setenv(test.name, test.value)
			err := run(slog.New(slog.DiscardHandler))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("startup did not reject %s before connection: %v", test.name, err)
			}
			if strings.Contains(err.Error(), "ping redis") || strings.Contains(err.Error(), "ping database") {
				t.Fatal("configuration rejection was hidden behind a connection attempt")
			}
		})
	}
}

func TestProductionStartupPreflightAcceptsValidInputsWithoutDial(t *testing.T) {
	productionStartupEnvironment(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStartupInputs(cfg); err != nil {
		t.Fatal(err)
	}
	oidcCfg, err := config.LoadOIDC(cfg.Environment)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := buildKeyManager(oidcCfg, cfg.Environment, slog.New(slog.DiscardHandler))
	if err != nil || manager == nil {
		t.Fatalf("independent production signing keys were not admitted: %v", err)
	}
}

func TestExplicitDevelopmentStartupPreflightAllowsAbsentServices(t *testing.T) {
	productionStartupEnvironment(t)
	t.Setenv("APP_ENV", "development")
	for _, name := range []string{"DATABASE_URL", "REDIS_URL", "NATS_URL", "ENVELOPE_MASTER_KEK", "ENVELOPE_BLIND_INDEX_PEPPER", "STEPUP_REPLAY_HMAC_KEY"} {
		t.Setenv(name, "")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStartupInputs(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledRegistrationCompositionDoesNotLoadDeliveryOrCleanupSecrets(t *testing.T) {
	productionStartupEnvironment(t)
	for _, mode := range []string{"development", "test", "production"} {
		t.Run(mode, func(t *testing.T) {
			service, ready, err := buildRegistrationService(mode, nil, nil, nil, nil, nil)
			if err != nil || service != nil || ready != nil {
				t.Fatalf("disabled registration acquired unrelated dependencies: %v", err)
			}
		})
	}
}

func enabledRegistrationEnvironment(t *testing.T) {
	t.Helper()
	productionStartupEnvironment(t)
	for name, value := range map[string]string{
		"REGISTRATION_ENABLED":              "true",
		"REGISTRATION_PENDING_CAPACITY":     "10",
		"REGISTRATION_GLOBAL_DAILY_LIMIT":   "5",
		"REGISTRATION_EMAIL_HOURLY_LIMIT":   "2",
		"SMS_ENABLED":                       "true",
		"SMS_PROVIDER":                      "smsir",
		"SMS_IR_KEY_MODE":                   "live",
		"SMS_GATEWAY_API_KEY":               "isolated-fixture-key-not-a-live-provider-credential",
		"SMS_IR_TEMPLATE_ID":                "123",
		"SMS_IR_CODE_PARAMETER":             "CODE",
		"SMS_OTP_HASH_PEPPER":               base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x45}, 32)),
		"SMS_OTP_GLOBAL_PER_DAY":            "5",
		"SMS_OTP_MAX_PENDING_SIGNUP":        "10",
		"REGISTRATION_SMTP_HOST":            "smtp.example.test",
		"REGISTRATION_SMTP_PORT":            "587",
		"REGISTRATION_SMTP_TLS_MODE":        "starttls",
		"REGISTRATION_SMTP_USERNAME":        "fixture-user",
		"REGISTRATION_SMTP_PASSWORD":        "fixture-only-password",
		"REGISTRATION_SMTP_FROM":            "signup@example.test",
		"REGISTRATION_SMTP_PUBLIC_ORIGIN":   "https://identity.example.test",
		"REGISTRATION_CLEANUP_DATABASE_URL": "",
		"USERNAME_ENABLED":                  "true",
		"USERNAME_POLICY_JSON":              `{"id":"4793a0e0-60b0-4571-a9b1-3879123819bb","normalization":"nfc-four-fold-v1","folds":[{"from":"\u064a","to":"\u06cc"},{"from":"\u0643","to":"\u06a9"},{"from":"\u0624","to":"\u0648"},{"from":"\u0626","to":"\u06cc"}],"reserved_names":[]}`,
		"USERNAME_REGEX":                    `[\x{0639}\x{0644}\x{06CC}]+`,
		"USERNAME_LOOKUP_KEY":               base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32)),
		"USERNAME_LOOKUP_KEY_ID":            "startup-fixture-v1",
	} {
		t.Setenv(name, value)
	}
}

func TestEnabledRegistrationRequiresCleanupConfigurationBeforeDial(t *testing.T) {
	enabledRegistrationEnvironment(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	err = validateStartupInputs(cfg)
	if err == nil || !strings.Contains(err.Error(), "cleanup database URL") {
		t.Fatalf("registration did not require actual cleanup identity admission: %v", err)
	}
}

func TestEnabledRegistrationCompositionNeverFallsBackToMemory(t *testing.T) {
	enabledRegistrationEnvironment(t)
	service, ready, err := buildRegistrationService("production", nil, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "durable ownership") || service != nil || ready != nil {
		t.Fatalf("enabled registration accepted missing authority: %v", err)
	}
}

func TestRegistrationUsernamePolicyRequiredBeforeDial(t *testing.T) {
	for _, setting := range []string{"USERNAME_ENABLED", "USERNAME_POLICY_JSON", "USERNAME_REGEX", "USERNAME_LOOKUP_KEY", "USERNAME_LOOKUP_KEY_ID"} {
		t.Run(setting, func(t *testing.T) {
			enabledRegistrationEnvironment(t)
			t.Setenv("REGISTRATION_CLEANUP_DATABASE_URL", "postgres://127.0.0.1:1/cleanup?sslmode=disable")
			t.Setenv(setting, "")
			err := run(slog.New(slog.DiscardHandler))
			if err == nil || !strings.Contains(err.Error(), "USERNAME") || strings.Contains(err.Error(), "ping redis") || strings.Contains(err.Error(), "ping database") {
				t.Fatalf("missing username policy did not reject before dial: %v", err)
			}
		})
	}
}

func TestDisabledUsernameCompositionIgnoresUnusedSecrets(t *testing.T) {
	productionStartupEnvironment(t)
	for _, setting := range []string{"USERNAME_POLICY_JSON", "USERNAME_REGEX", "USERNAME_LOOKUP_KEY", "USERNAME_LOOKUP_KEY_ID"} {
		t.Setenv(setting, "unused-invalid-secret")
	}
	service, ready, err := buildUsernameService(nil)
	if err != nil || service != nil || ready != nil {
		t.Fatal("disabled usernames acquired dependency or parsed unused secrets", err)
	}
}

func TestAuditCompositionUsesConfiguredGenerationAndCanonicalEmail(t *testing.T) {
	productionStartupEnvironment(t)
	for _, generation := range []struct {
		encoded string
		want    int16
	}{{"0", 0}, {"7", 7}} {
		t.Run(generation.encoded, func(t *testing.T) {
			t.Setenv(config.EnvBlindIndexPepperVersion, generation.encoded)
			indexer, err := buildAuditIndexer()
			if err != nil {
				t.Fatal(err)
			}
			if int16(indexer.Version()) != generation.want {
				t.Fatal("audit composition dropped the configured generation")
			}
			first, err := indexer.ComputeEmail("\u00fcser@xn--bcher-kva.test")
			if err != nil || len(first) != 64 {
				t.Fatalf("canonical audit identity failed: %v", err)
			}
			second, err := indexer.ComputeEmail(" U\u0308SER@B\u00dcCHER.test ")
			if err != nil || first != second {
				t.Fatalf("audit composition disagrees on canonical email: %v", err)
			}
		})
	}
}

func TestDisabledSMSCompositionKeepsDBOnlyRemovalWithoutDeliverySecrets(t *testing.T) {
	productionStartupEnvironment(t)
	for _, name := range []string{"SMS_GATEWAY_API_KEY", "SMS_OTP_HASH_PEPPER", "ENVELOPE_MASTER_KEK", "ENVELOPE_BLIND_INDEX_PEPPER"} {
		t.Setenv(name, "invalid-and-unused-when-delivery-is-disabled")
	}
	// pgxpool is lazy with zero minimum connections. No dependency is dialed by
	// disabled construction, and the fixture is closed without running a query.
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/invalid?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	service, err := buildSMSOTPService("production", pool, nil, slog.New(slog.DiscardHandler))
	if err != nil || service == nil || service.DeliveryEnabled() {
		t.Fatalf("disabled SMS lost independent phone removal: %v", err)
	}
}
