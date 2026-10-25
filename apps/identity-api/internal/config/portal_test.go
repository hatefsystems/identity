package config

import "testing"

func TestPortalOriginBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     string
		origin  string
		issuer  string
		allowed string
		want    string
	}{
		{name: "canonical HTTPS", env: "production", origin: "https://idp.example", issuer: "https://idp.example", allowed: "https://idp.example", want: "https://idp.example"},
		{name: "issuer path", env: "production", origin: "https://idp.example", issuer: "https://idp.example/issuer", allowed: "https://idp.example", want: "https://idp.example"},
		{name: "development default", env: "development", issuer: "http://localhost:8080", allowed: "http://localhost:8080", want: "http://localhost:8080"},
		{name: "loopback IP", env: "development", origin: "http://127.0.0.1:3000", issuer: "http://127.0.0.1:3000", allowed: "http://127.0.0.1:3000", want: "http://127.0.0.1:3000"},
		{name: "loopback IPv6", env: "development", origin: "http://[::1]:3000", issuer: "http://[::1]:3000", allowed: "http://[::1]:3000", want: "http://[::1]:3000"},
		{name: "production unset", env: "production", issuer: "https://idp.example", allowed: "https://idp.example"},
		{name: "production HTTP", env: "production", origin: "http://localhost:8080", issuer: "http://localhost:8080", allowed: "http://localhost:8080"},
		{name: "development remote HTTP", env: "development", origin: "http://idp.example", issuer: "http://idp.example", allowed: "http://idp.example"},
		{name: "issuer mismatch", env: "production", origin: "https://idp.example", issuer: "https://other.example", allowed: "https://idp.example"},
		{name: "RP origin mismatch", env: "production", origin: "https://idp.example", issuer: "https://idp.example", allowed: "https://sibling.idp.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvPortalOrigin, tc.origin)
			got, err := LoadPortal(tc.env, tc.issuer, []string{tc.allowed})
			if tc.want == "" {
				if err == nil {
					t.Fatalf("invalid boundary accepted: %q", got)
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("origin=%q err=%v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestPortalOriginRejectsNoncanonicalInput(t *testing.T) {
	for _, raw := range []string{
		"", "null", "//idp.example", "https://idp.example/", "https://idp.example/path", "https://idp.example?x=1",
		"https://idp.example?", "https://idp.example#", "https://idp.example#fragment", "https://user@idp.example",
		"https://IDP.example", "https://idp.example.", "https://idp.example:443", "https://idp.example:0444",
		"https://idp.example:", "https://idp.example:65536", "https://bad_host.example", "https://-bad.example",
		" https://idp.example", "https://idp.example ", "https://[fe80::1%25eth0]", "javascript:alert(1)",
		"https://127.1", "https://2130706433", "https://0177.0.0.1", "https://0x7f000001",
		"https://0x7f.0.0.1", "https://example.123", "https://example.0xff", "https://0x",
		"https://[::ffff:127.0.0.1]",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := canonicalPortalOrigin(raw, "production"); err == nil {
				t.Fatal("noncanonical origin accepted")
			}
		})
	}
}

func TestSessionCookieCannotDowngradeOutsideLocalHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, env, origin, cookie, secure string
		valid                             bool
	}{
		{name: "production hardened", env: "production", origin: "https://idp.example", cookie: "__Host-session", secure: "true", valid: true},
		{name: "production insecure", env: "production", origin: "https://idp.example", cookie: "session", secure: "false"},
		{name: "production unprefixed", env: "production", origin: "https://idp.example", cookie: "session", secure: "true"},
		{name: "local override", env: "development", origin: "http://localhost:3000", cookie: "session", secure: "false", valid: true},
		{name: "HTTPS is hardened in development", env: "development", origin: "https://localhost:3000", cookie: "session", secure: "false"},
		{name: "remote development is not local", env: "development", origin: "http://idp.example", cookie: "session", secure: "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("APP_ENV", tc.env)
			t.Setenv(EnvPortalOrigin, tc.origin)
			t.Setenv("SESSION_COOKIE_NAME", tc.cookie)
			t.Setenv("SESSION_COOKIE_SECURE", tc.secure)
			t.Setenv("SESSION_ABSOLUTE_TTL", "24h")
			t.Setenv("SESSION_IDLE_TTL", "2h")
			_, err := LoadSession()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}
