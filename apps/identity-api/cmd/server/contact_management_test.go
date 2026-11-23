package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
)

func contactCompositionEnvironment(t *testing.T) {
	t.Helper()
	productionStartupEnvironment(t)
	for _, name := range []string{"CONTACT_MANAGEMENT_PROOFS_ENABLED", "CONTACT_MANAGEMENT_PROOFS_EMAIL_ENABLED", "CONTACT_MANAGEMENT_PROOFS_SMS_ENABLED", "CONTACT_MANAGEMENT_EMAIL_OWNERSHIP_ENABLED", "CONTACT_MANAGEMENT_BINDING_KEY", "LOGIN_CODE_HMAC_KEY", "SMS_OTP_HASH_PEPPER", "CONTACT_CHANGE_SMS_IR_TEMPLATE_ID", "CONTACT_REMOVAL_SMS_IR_TEMPLATE_ID"} {
		t.Setenv(name, "")
	}
}

func TestContactMaintenanceDefaultOffAndRetainedKeysRequireReaders(t *testing.T) {
	contactCompositionEnvironment(t)
	manager, proofs, err := buildContactMaintenance("development", nil, nil, nil, nil, accountpolicy.Policy{})
	if err != nil || manager != nil || proofs != nil {
		t.Fatal("default-off contact composition acquired dependencies or authority")
	}
	change, removal, err := buildContactSMSSenders("production")
	if err != nil || change != nil || removal != nil {
		t.Fatal("default-off contact composition activated provider templates")
	}
	for _, name := range []string{"CONTACT_MANAGEMENT_BINDING_KEY", "LOGIN_CODE_HMAC_KEY", "SMS_OTP_HASH_PEPPER"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{36}, 32)))
			manager, proofs, err := buildContactMaintenance("development", nil, nil, nil, nil, accountpolicy.Policy{})
			if err == nil || manager != nil || proofs != nil {
				t.Fatal("configured finite reader protection was silently discarded")
			}
		})
	}
}

func TestContactMaintenanceProviderFreeReadRemovalNeedsOnlyEvidenceCrypto(t *testing.T) {
	contactCompositionEnvironment(t)
	t.Setenv(config.EnvBlindIndexPepper, "")
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/invalid?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	sessions, err := buildSessionManager("production", nil, nil)
	if err == nil || sessions != nil {
		t.Fatal("production sessions unexpectedly accepted missing shared authority")
	}
	sessions, err = buildSessionManager("development", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager, proofs, err := buildContactMaintenance("production", pool, nil, sessions, nil, accountpolicy.Policy{})
	if err != nil || manager == nil || proofs != nil {
		t.Fatal("provider-free read/removal required code, provider or blind-index keys")
	}
	t.Setenv(config.EnvMasterKEK, "invalid-required-evidence-key")
	manager, proofs, err = buildContactMaintenance("production", pool, nil, sessions, nil, accountpolicy.Policy{})
	if err == nil || manager != nil || proofs != nil {
		t.Fatal("provider-free contact readers bypassed required evidence crypto")
	}
}
