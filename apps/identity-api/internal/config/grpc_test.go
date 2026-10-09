package config

import (
	"testing"
	"time"
)

func grpcEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("GRPC_ENABLED", "true")
	t.Setenv("GRPC_ADDR", "127.0.0.1:9090")
	t.Setenv("GRPC_TRUST_DOMAIN", "test.local")
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent.sock")
	t.Setenv("GRPC_REQUEST_TIMEOUT", "2s")
	t.Setenv("GRPC_METHOD_GRANTS_JSON", `{"/hatef.identity.v1.IdentityService/ValidateToken":["spiffe://test.local/search"]}`)
	t.Setenv("GRPC_VALIDATION_POLICIES_JSON", `{"spiffe://test.local/search":{"audiences":["https://id.test"],"origins":["https://search.test"]}}`)
}

func TestGRPCConfigDisabled(t *testing.T) {
	t.Setenv("GRPC_ENABLED", "false")
	t.Setenv("GRPC_METHOD_GRANTS_JSON", "invalid")
	cfg, err := LoadGRPC()
	if err != nil || cfg.Enabled {
		t.Fatalf("disabled gRPC: %+v %v", cfg, err)
	}
}

func TestGRPCConfigEnabled(t *testing.T) {
	grpcEnvironment(t)
	cfg, err := LoadGRPC()
	if err != nil || !cfg.Enabled || cfg.RequestTimeout != 2*time.Second || len(cfg.ValidationPolicies) != 1 {
		t.Fatalf("config: %+v %v", cfg, err)
	}
	t.Setenv("GRPC_METHOD_GRANTS_JSON", "{}")
	t.Setenv("GRPC_VALIDATION_POLICIES_JSON", "{}")
	if _, err := LoadGRPC(); err != nil {
		t.Fatalf("explicit deny-all policy: %v", err)
	}
}

func TestGRPCConfigRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"GRPC_ADDR", ":9090"}, {"GRPC_ADDR", "127.0.0.1:0"}, {"GRPC_ADDR", "127.0.0.1:65536"},
		{"GRPC_TRUST_DOMAIN", "spiffe://test.local"}, {"GRPC_TRUST_DOMAIN", ""},
		{"SPIFFE_ENDPOINT_SOCKET", ""}, {"SPIFFE_ENDPOINT_SOCKET", "tcp://remote:8081"},
		{"SPIFFE_ENDPOINT_SOCKET", "unix://remote/tmp/socket"}, {"SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/socket?secret=foo"},
		{"GRPC_REQUEST_TIMEOUT", "0s"}, {"GRPC_REQUEST_TIMEOUT", "31s"},
		{"GRPC_METHOD_GRANTS_JSON", ""}, {"GRPC_METHOD_GRANTS_JSON", "null"},
		{"GRPC_METHOD_GRANTS_JSON", `{"/other.Service/Method":[]}`},
		{"GRPC_METHOD_GRANTS_JSON", `{"/hatef.identity.v1.IdentityService/ValidateToken":["spiffe://foreign/service"]}`},
		{"GRPC_METHOD_GRANTS_JSON", `{"/hatef.identity.v1.IdentityService/ValidateToken":[],"/hatef.identity.v1.IdentityService/ValidateToken":[]}`},
		{"GRPC_VALIDATION_POLICIES_JSON", "{}"}, {"GRPC_VALIDATION_POLICIES_JSON", "null"},
		{"GRPC_VALIDATION_POLICIES_JSON", `{"spiffe://test.local/search":{"audiences":[],"origins":[]}}`},
		{"GRPC_VALIDATION_POLICIES_JSON", `{"spiffe://test.local/search":{"audiences":["https://id.test"],"unknown":true}}`},
		{"GRPC_VALIDATION_POLICIES_JSON", `{} {}`},
	} {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			grpcEnvironment(t)
			t.Setenv(tc.key, tc.value)
			if _, err := LoadGRPC(); err == nil {
				t.Fatal("unsafe gRPC configuration accepted")
			}
		})
	}
}
