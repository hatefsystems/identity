package identitygrpc

import (
	"strings"
	"testing"
)

func TestNewServiceRequiresDependencies(t *testing.T) {
	for _, missing := range []string{"validator", "queries", "DPoP", "recorder", "typed nil validator", "typed nil queries", "typed nil recorder"} {
		t.Run(missing, func(t *testing.T) {
			cfg := testConfig(t)
			switch missing {
			case "validator":
				cfg.Validator = nil
			case "queries":
				cfg.Queries = nil
			case "DPoP":
				cfg.DPoP = nil
			case "recorder":
				cfg.Recorder = nil
			case "typed nil validator":
				cfg.Validator = tokenValidatorFunc(nil)
			case "typed nil queries":
				cfg.Queries = (*queryFuncs)(nil)
			case "typed nil recorder":
				cfg.Recorder = (*testRecorder)(nil)
			}
			if s, err := NewService(cfg); err == nil || s != nil {
				t.Fatal("missing dependency accepted")
			}
		})
	}
	cfg := testConfig(t)
	cfg.Policies, cfg.Logger = nil, nil
	if s, err := NewService(cfg); err != nil || s == nil {
		t.Fatalf("deny-all token policy or default logger rejected: %v", err)
	}
}

func TestNewServiceValidatesExactPolicy(t *testing.T) {
	for _, id := range []string{"", "resource", "https://identity.test/workload", "spiffe://identity.test", "spiffe://identity.test/workload/*", testCaller + "?role=admin", "spiffe://identity.test/" + strings.Repeat("a", maxContextLength)} {
		t.Run("identity/"+id, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Policies = map[string]ValidationPolicy{id: {Audiences: []string{testAudience}}}
			if s, err := NewService(cfg); err == nil || s != nil {
				t.Fatal("invalid workload policy accepted")
			}
		})
	}
	for _, audience := range []string{"", " ", "https://identity.test\n", "audience with spaces", "*", "https://*.identity.test", strings.Repeat("a", maxContextLength+1), string([]byte{0xff})} {
		t.Run("audience/"+audience, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Policies[testCaller] = ValidationPolicy{Audiences: []string{audience}}
			if s, err := NewService(cfg); err == nil || s != nil {
				t.Fatal("invalid audience accepted")
			}
		})
	}
	cfg := testConfig(t)
	cfg.Policies[testCaller] = ValidationPolicy{Origins: []string{testOrigin}}
	if _, err := NewService(cfg); err == nil {
		t.Fatal("audience-less policy accepted")
	}
	for _, origin := range []string{
		"", "*", "https://*.resource.test", "http://resource.test", "ftp://resource.test",
		"https://resource.test/", "https://resource.test/path", "https://resource.test?", "https://resource.test?q=1",
		"https://resource.test#", "https://resource.test#fragment", "https://user:secret@resource.test",
		"https://RESOURCE.TEST", "https://resource.test:443", "https://resource.test:0", "https://resource.test:65536",
		"https://resource.test:", "https://[resource.test]", "https://[127.0.0.1]", "https://[::1%25zone]",
	} {
		t.Run("origin/"+origin, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.AllowHTTP = true
			cfg.Policies[testCaller] = ValidationPolicy{Audiences: []string{testAudience}, Origins: []string{origin}}
			if s, err := NewService(cfg); err == nil || s != nil {
				t.Fatal("noncanonical or unsafe resource origin accepted")
			}
		})
	}
}

func TestLocalHTTPRequiresExplicitLoopbackPolicy(t *testing.T) {
	for _, origin := range []string{"http://localhost", "http://127.0.0.1:8080", "http://127.1.2.3", "http://[::1]:8080", "http://[::ffff:127.0.0.1]"} {
		t.Run(origin, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Policies[testCaller] = ValidationPolicy{Audiences: []string{testAudience}, Origins: []string{origin}}
			if _, err := NewService(cfg); err == nil {
				t.Fatal("HTTP accepted without explicit development opt-in")
			}
			cfg.AllowHTTP = true
			if _, err := NewService(cfg); err != nil {
				t.Fatalf("explicit loopback HTTP rejected: %v", err)
			}
		})
	}
	for _, host := range []string{"localhost.attacker.test", "service.localhost", "127.0.0.1.attacker.test", "127.1", "2130706433", "0.0.0.0", "[::]", "192.168.1.2"} {
		cfg := testConfig(t)
		cfg.AllowHTTP = true
		cfg.Policies[testCaller] = ValidationPolicy{Audiences: []string{testAudience}, Origins: []string{"http://" + host}}
		if _, err := NewService(cfg); err == nil {
			t.Errorf("non-loopback HTTP origin accepted: %s", host)
		}
	}
}

func TestResourceOriginCanonicalization(t *testing.T) {
	for _, tc := range []struct{ uri, origin string }{
		{"HTTPS://RESOURCE.TEST:443/objects/%2F?q=1", testOrigin},
		{"https://resource.test:8443/objects/one?token=private", "https://resource.test:8443"},
		{"https://[0:0:0:0:0:0:0:1]:443/", "https://[::1]"},
		{"http://localhost:80/", "http://localhost"},
	} {
		u, origin, err := resourceURI(tc.uri, true)
		if err != nil || u == nil || origin != tc.origin {
			t.Errorf("resourceURI(%q) origin=%q err=%v", tc.uri, origin, err)
		}
	}
	for _, raw := range []string{"/objects/one", "https:resource.test/one", "https:///objects/one", "https://resource.test/%zz", "https://resource.test/?q=%zz", "https://resource.test/has space", "https://resource.test/\n", "https://resource.test\\@other.test/", "https://-invalid.test", "https://resource..test"} {
		if _, _, err := resourceURI(raw, true); err == nil {
			t.Errorf("invalid URI accepted: %q", raw)
		}
	}
}
