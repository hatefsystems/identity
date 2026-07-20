package config

import "testing"

func TestLoadOIDCDevelopmentDefaultsIssuer(t *testing.T) {
	t.Setenv(EnvOIDCIssuer, "")
	t.Setenv(EnvOIDCSigningKey, "")
	t.Setenv(EnvOIDCSigningKeyNext, "")

	cfg, err := LoadOIDC("development")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Issuer != defaultDevIssuer {
		t.Errorf("issuer = %q, want dev default %q", cfg.Issuer, defaultDevIssuer)
	}
	if cfg.HasKeys() {
		t.Error("expected no keys in bare development config")
	}
}

func TestLoadOIDCTrimsTrailingSlash(t *testing.T) {
	t.Setenv(EnvOIDCIssuer, "https://identity.hatef.ir/")
	t.Setenv(EnvOIDCSigningKey, "active-pem")
	t.Setenv(EnvOIDCSigningKeyNext, "next-pem")

	cfg, err := LoadOIDC("development")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Issuer != "https://identity.hatef.ir" {
		t.Errorf("issuer = %q, want trailing slash trimmed", cfg.Issuer)
	}
	if !cfg.HasKeys() {
		t.Error("HasKeys should be true when active and next are set")
	}
}

func TestLoadOIDCProductionRequiresHTTPSIssuer(t *testing.T) {
	t.Setenv(EnvOIDCIssuer, "http://identity.hatef.ir")
	t.Setenv(EnvOIDCSigningKey, "active-pem")
	t.Setenv(EnvOIDCSigningKeyNext, "next-pem")

	if _, err := LoadOIDC("production"); err == nil {
		t.Fatal("expected error for non-https issuer in production")
	}
}

func TestLoadOIDCProductionRequiresKeys(t *testing.T) {
	t.Setenv(EnvOIDCIssuer, "https://identity.hatef.ir")
	t.Setenv(EnvOIDCSigningKey, "")
	t.Setenv(EnvOIDCSigningKeyNext, "")

	if _, err := LoadOIDC("production"); err == nil {
		t.Fatal("expected error when signing keys are missing in production")
	}
}

func TestLoadOIDCProductionValid(t *testing.T) {
	t.Setenv(EnvOIDCIssuer, "https://identity.hatef.ir")
	t.Setenv(EnvOIDCSigningKey, "active-pem")
	t.Setenv(EnvOIDCSigningKeyNext, "next-pem")
	t.Setenv(EnvOIDCSigningKeyPrev, "prev-pem")

	cfg, err := LoadOIDC("production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(cfg.PreviousKeyPEM) != "prev-pem" {
		t.Errorf("previous key = %q, want prev-pem", cfg.PreviousKeyPEM)
	}
}
