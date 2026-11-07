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

func TestOIDCIssuerStructure(t *testing.T) {
	for _, environment := range []string{"development", "test", "production"} {
		for _, issuer := range []string{
			"https://identity.example.test?", "https://identity.example.test#", "https://identity.example.test/path?",
			"https://identity.example.test/path#", "https://identity.example.test?x=1", "https://identity.example.test#x",
			"https://user:secret@identity.example.test", "https:///path", "https:identity.example.test",
			"//identity.example.test", "https://identity.example.test:65536", "https://bad_host.example.test",
			"https://identity.example.test:", "https://identity.example.test\\callback", " https://identity.example.test",
		} {
			t.Run(environment+"/"+issuer, func(t *testing.T) {
				t.Setenv(EnvOIDCIssuer, issuer)
				t.Setenv(EnvOIDCSigningKey, "active-pem")
				t.Setenv(EnvOIDCSigningKeyNext, "next-pem")
				if _, err := LoadOIDC(environment); err == nil {
					t.Fatal("invalid issuer accepted")
				}
				if _, err := LoadPortal(environment, issuer, []string{"https://identity.example.test"}); err == nil {
					t.Fatal("portal accepted invalid issuer")
				}
			})
		}
	}
}

func TestOIDCDevelopmentOnlyConveniences(t *testing.T) {
	for _, environment := range []string{"development", "test", "production"} {
		for _, tc := range []struct {
			name, issuer, active, next string
			validDev                   bool
		}{
			{name: "default", validDev: true},
			{name: "local HTTP", issuer: "http://localhost:8080", active: "active", next: "next", validDev: true},
			{name: "remote HTTP", issuer: "http://identity.example.test", active: "active", next: "next"},
			{name: "missing active", issuer: "https://identity.example.test", next: "next", validDev: true},
			{name: "missing next", issuer: "https://identity.example.test", active: "active", validDev: true},
			{name: "whitespace keys", issuer: "https://identity.example.test", active: " \t", next: "\n", validDev: true},
		} {
			t.Run(environment+"/"+tc.name, func(t *testing.T) {
				t.Setenv(EnvOIDCIssuer, tc.issuer)
				t.Setenv(EnvOIDCSigningKey, tc.active)
				t.Setenv(EnvOIDCSigningKeyNext, tc.next)
				_, err := LoadOIDC(environment)
				if (err == nil) != (environment == "development" && tc.validDev) {
					t.Fatalf("unexpected convenience: %v", err)
				}
			})
		}
	}
}

func TestOIDCPreservesSupportedIssuerPath(t *testing.T) {
	t.Setenv(EnvOIDCIssuer, "https://identity.example.test/tenant/issuer")
	t.Setenv(EnvOIDCSigningKey, "active-pem")
	t.Setenv(EnvOIDCSigningKeyNext, "next-pem")
	cfg, err := LoadOIDC("test")
	if err != nil || cfg.Issuer != "https://identity.example.test/tenant/issuer" {
		t.Fatalf("issuer path changed: %+v, %v", cfg, err)
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
