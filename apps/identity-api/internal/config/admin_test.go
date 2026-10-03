package config

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func cleanAdminEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{EnvAdminEnabled, EnvAdminGovernancePolicyID, EnvLegalWorkflowEnabled, EnvLegalWorkflowPolicyID, EnvAdminAllowedOrigins, EnvAdminContextRetention, EnvAdminLegalReleasedRetention, EnvAdminPageSizeDefault, EnvAdminPageSizeMax, EnvAdminAuditMaxWindow, EnvAdminChainVerifyMaxLimit, EnvAdminRequestTimeout, EnvAdminPerActorPerMinute, EnvAdminPerSubnetPerMinute} {
		t.Setenv(key, "")
	}
	t.Setenv("APP_ENV", "development")
}

func TestAdminDefaultsAndLoad(t *testing.T) {
	cleanAdminEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Enabled || cfg.Admin.PageSizeDefault != 50 || cfg.Admin.PageSizeMax != 200 || cfg.Admin.AuditMaxWindow != 744*time.Hour || cfg.Admin.ContextRetention != 0 {
		t.Fatalf("unexpected admin defaults: %+v", cfg.Admin)
	}
	if cfg.Admin.WorkflowEnabled || cfg.Admin.WorkflowPolicyID != "" || cfg.Admin.GovernancePolicyID != "" {
		t.Fatal("governance approval must not be defaulted")
	}
}

func TestAdminInvalidBounds(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{EnvAdminPageSizeDefault, "2147483648"}, {EnvAdminPageSizeMax, "201"},
		{EnvAdminPageSizeDefault, "0"}, {EnvAdminPageSizeMax, "-1"},
		{EnvAdminChainVerifyMaxLimit, "5001"}, {EnvAdminAuditMaxWindow, "745h"},
		{EnvAdminRequestTimeout, "11s"}, {EnvAdminPerActorPerMinute, "-1"},
		{EnvAdminContextRetention, "0s"}, {EnvAdminLegalReleasedRetention, "invalid"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			cleanAdminEnv(t)
			t.Setenv(tc.key, tc.value)
			if _, err := LoadAdmin(); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}

func TestAdminEnableRequiresExplicitPolicy(t *testing.T) {
	cleanAdminEnv(t)
	t.Setenv(EnvAdminEnabled, "true")
	if _, err := LoadAdmin(); err == nil {
		t.Fatal("enabled without policy")
	}
	t.Setenv(EnvAdminAllowedOrigins, "https://identity.example")
	t.Setenv(EnvAdminContextRetention, "720h")
	t.Setenv(EnvAdminLegalReleasedRetention, "1440h")
	if _, err := LoadAdmin(); err == nil {
		t.Fatal("numeric retention alone enabled unapproved admin")
	}
	t.Setenv(EnvAdminGovernancePolicyID, uuid.NewString())
	if _, err := LoadAdmin(); err != nil {
		t.Fatal(err)
	}
}

func TestAdminGovernanceConfig(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{EnvAdminGovernancePolicyID, "not-a-uuid"}, {EnvAdminGovernancePolicyID, uuid.Nil.String()},
		{EnvLegalWorkflowPolicyID, "not-a-uuid"}, {EnvLegalWorkflowPolicyID, uuid.Nil.String()},
		{EnvLegalWorkflowEnabled, "unknown"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			cleanAdminEnv(t)
			t.Setenv(tc.key, tc.value)
			if _, err := LoadAdmin(); err == nil {
				t.Fatal("accepted invalid governance config while intake disabled")
			}
		})
	}
	cleanAdminEnv(t)
	t.Setenv(EnvLegalWorkflowEnabled, "true")
	t.Setenv(EnvLegalWorkflowPolicyID, uuid.NewString())
	if _, err := LoadAdmin(); err == nil {
		t.Fatal("workflow enabled without admin")
	}
	t.Setenv(EnvAdminEnabled, "true")
	t.Setenv(EnvAdminAllowedOrigins, "https://identity.example")
	t.Setenv(EnvAdminContextRetention, "720h")
	t.Setenv(EnvAdminLegalReleasedRetention, "1440h")
	t.Setenv(EnvAdminGovernancePolicyID, uuid.NewString())
	t.Setenv(EnvLegalWorkflowPolicyID, "")
	if _, err := LoadAdmin(); err == nil {
		t.Fatal("workflow enabled without versioned policy")
	}
	t.Setenv(EnvLegalWorkflowPolicyID, uuid.NewString())
	cfg, err := LoadAdmin()
	if err != nil || !cfg.WorkflowEnabled {
		t.Fatalf("valid explicit workflow config rejected: %v", err)
	}
}

func TestAdminMaintenanceConfigIndependentOfIntake(t *testing.T) {
	cleanAdminEnv(t)
	id, workflowID := uuid.NewString(), uuid.NewString()
	t.Setenv(EnvAdminGovernancePolicyID, id)
	t.Setenv(EnvLegalWorkflowPolicyID, workflowID)
	t.Setenv(EnvAdminContextRetention, "720h")
	t.Setenv(EnvAdminLegalReleasedRetention, "1440h")
	cfg, err := LoadAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled || cfg.WorkflowEnabled || cfg.GovernancePolicyID != id || cfg.WorkflowPolicyID != workflowID ||
		cfg.ContextRetention != 720*time.Hour || cfg.LegalReleasedRetention != 1440*time.Hour {
		t.Fatal("disabled intake discarded maintenance policy config")
	}
}

func TestAdminOrigins(t *testing.T) {
	for _, origin := range []string{"*", "null", "https://example.test/path", "https://example.test/", "https://user:secret@example.test", "https://example.test?key=value", "https://example.test#fragment", "https://example.test,"} {
		t.Run(origin, func(t *testing.T) {
			cleanAdminEnv(t)
			t.Setenv(EnvAdminAllowedOrigins, origin)
			if _, err := LoadAdmin(); err == nil {
				t.Fatal("accepted unsafe origin")
			}
		})
	}
	cleanAdminEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv(EnvAdminAllowedOrigins, "http://example.test")
	if _, err := LoadAdmin(); err == nil {
		t.Fatal("accepted cleartext production origin")
	}
}
