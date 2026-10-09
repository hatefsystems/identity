package config

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

// GRPCValidationPolicy restricts the audiences and origins a workload may validate.
type GRPCValidationPolicy struct {
	Audiences []string `json:"audiences"`
	Origins   []string `json:"origins"`
}

// GRPCConfig configures the opt-in private, workload-authenticated listener.
type GRPCConfig struct {
	Enabled            bool
	Address            string
	TrustDomain        string
	WorkloadAPI        string
	Grants             map[string][]string
	ValidationPolicies map[string]GRPCValidationPolicy
	RequestTimeout     time.Duration
}

// LoadGRPC has no public or plaintext default and performs no network I/O.
// Explicit empty grant/policy maps are valid and deny every RPC.
func LoadGRPC() (GRPCConfig, error) {
	enabled, err := getEnvBool("GRPC_ENABLED", false)
	if err != nil {
		return GRPCConfig{}, err
	}
	if !enabled {
		return GRPCConfig{}, nil
	}
	cfg := GRPCConfig{Enabled: true, Address: getEnv("GRPC_ADDR", "127.0.0.1:9090"),
		TrustDomain: os.Getenv("GRPC_TRUST_DOMAIN"), WorkloadAPI: os.Getenv("SPIFFE_ENDPOINT_SOCKET")}
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" || strings.TrimSpace(cfg.Address) != cfg.Address {
		return GRPCConfig{}, errors.New("config: invalid GRPC_ADDR")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return GRPCConfig{}, errors.New("config: invalid GRPC_ADDR port")
	}
	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil || td.String() != cfg.TrustDomain {
		return GRPCConfig{}, errors.New("config: canonical GRPC_TRUST_DOMAIN required")
	}
	endpoint, err := url.Parse(cfg.WorkloadAPI)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return GRPCConfig{}, errors.New("config: local SPIFFE_ENDPOINT_SOCKET required")
	}
	localUnix := endpoint.Scheme == "unix" && endpoint.Host == "" && strings.HasPrefix(endpoint.Path, "/")
	localPipe := endpoint.Scheme == "npipe" && ((endpoint.Host == "" && strings.HasPrefix(endpoint.Path, "//./pipe/")) ||
		(endpoint.Host == "." && strings.HasPrefix(endpoint.Path, "/pipe/")))
	if !localUnix && !localPipe {
		return GRPCConfig{}, errors.New("config: Workload API must use a local unix socket or named pipe")
	}
	if err := decodeGRPCJSON(os.Getenv("GRPC_METHOD_GRANTS_JSON"), &cfg.Grants); err != nil || cfg.Grants == nil {
		return GRPCConfig{}, errors.New("config: explicit valid GRPC_METHOD_GRANTS_JSON required")
	}
	if err := decodeGRPCJSON(os.Getenv("GRPC_VALIDATION_POLICIES_JSON"), &cfg.ValidationPolicies); err != nil || cfg.ValidationPolicies == nil {
		return GRPCConfig{}, errors.New("config: explicit valid GRPC_VALIDATION_POLICIES_JSON required")
	}
	validateCallers := make(map[string]bool)
	for method, ids := range cfg.Grants {
		switch method {
		case identityv1.IdentityService_ValidateToken_FullMethodName, identityv1.IdentityService_CheckPermission_FullMethodName, identityv1.IdentityService_GetInternalUserInfo_FullMethodName:
		default:
			return GRPCConfig{}, errors.New("config: unregistered method in GRPC_METHOD_GRANTS_JSON")
		}
		for _, raw := range ids {
			id, err := spiffeid.FromString(raw)
			if err != nil || len(raw) > 2048 || id.Path() == "" || !id.MemberOf(td) {
				return GRPCConfig{}, errors.New("config: invalid workload grant")
			}
			if method == identityv1.IdentityService_ValidateToken_FullMethodName {
				validateCallers[raw] = true
			}
		}
	}
	for caller := range validateCallers {
		policy, exists := cfg.ValidationPolicies[caller]
		if !exists || len(policy.Audiences) == 0 {
			return GRPCConfig{}, errors.New("config: ValidateToken caller requires an audience policy")
		}
	}
	for caller, policy := range cfg.ValidationPolicies {
		if !validateCallers[caller] {
			return GRPCConfig{}, errors.New("config: validation policy requires an explicit ValidateToken grant")
		}
		for _, audience := range policy.Audiences {
			if audience == "" || len(audience) > 2048 || audience != strings.TrimSpace(audience) {
				return GRPCConfig{}, errors.New("config: invalid validation audience")
			}
		}
	}
	cfg.RequestTimeout, err = getEnvDuration("GRPC_REQUEST_TIMEOUT", 2*time.Second)
	if err != nil || cfg.RequestTimeout > 30*time.Second {
		return GRPCConfig{}, errors.New("config: GRPC_REQUEST_TIMEOUT must be positive and at most 30s")
	}
	return cfg, nil
}

func decodeGRPCJSON(raw string, target any) error {
	if raw == "" || len(raw) > 64*1024 {
		return errors.New("invalid policy size")
	}
	check := json.NewDecoder(strings.NewReader(raw))
	if err := checkGRPCJSONValue(check, 0); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("invalid trailing policy data")
	}
	return nil
}

// Duplicate policy keys are rejected instead of silently replacing a grant.
func checkGRPCJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("policy nesting too deep")
	}
	value, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := value.(json.Delim)
	if !ok {
		return nil
	}
	keys := make(map[string]bool)
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return errors.New("duplicate policy key")
			}
			keys[name] = true
		}
		if err := checkGRPCJSONValue(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
