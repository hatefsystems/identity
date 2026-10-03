package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AdminConfig holds the bounds applied to the administrative REST surface at
// /api/v1/admin/* (docs/api-design.md §1.7).
//
// Every value here is a denial-of-service bound rather than a feature toggle.
// The admin endpoints run privileged queries over the largest tables in the
// system — users, mvp_audit_logs, security_event_ledger — so an unbounded page
// size or an unbounded time window is a way to turn one authorized request into
// a full table scan. Nothing here is secret.
//
// Note what these bounds are not: they are not a substitute for rate limiting.
// An admin holding admin.users.read.pii can still enumerate the user table one
// capped page at a time. internal/ratelimit exists but no HTTP middleware
// consumes it yet; a global limiter is its own task. Every access is
// audit-logged in the meantime.
type AdminConfig struct {
	Enabled                bool
	GovernancePolicyID     string
	WorkflowEnabled        bool
	WorkflowPolicyID       string
	AllowedOrigins         []string
	ContextRetention       time.Duration
	LegalReleasedRetention time.Duration
	RequestTimeout         time.Duration
	PerActorPerMinute      int
	PerSubnetPerMinute     int
	// PageSizeDefault is the page size applied when a list request omits
	// ?limit=.
	PageSizeDefault int32
	// PageSizeMax is the hard ceiling on ?limit=. Requests above it are
	// clamped rather than rejected: an admin asking for too much should get
	// the most that is safe to serve, not an error they must guess their way
	// out of.
	PageSizeMax int32
	// AuditMaxWindow caps the span between start_time and end_time on
	// GET /audit-logs. The endpoint already requires both bounds (that is the
	// documented DoS guard); this caps how far apart they may be, which is the
	// half that actually limits the scan.
	AuditMaxWindow time.Duration
	// ChainVerifyMaxLimit caps how many rows one chain-verification call may
	// recompute. Verification is CPU-bound SHA-256 over serialized rows, so
	// this bounds request latency; callers walk longer chains by following
	// next_after_seq.
	ChainVerifyMaxLimit int32
}

// Environment variable names for the admin surface.
const (
	EnvAdminEnabled                = "ADMIN_ENABLED"
	EnvAdminGovernancePolicyID     = "ADMIN_GOVERNANCE_POLICY_ID"
	EnvLegalWorkflowEnabled        = "LEGAL_WORKFLOW_ENABLED"
	EnvLegalWorkflowPolicyID       = "LEGAL_WORKFLOW_POLICY_ID"
	EnvAdminAllowedOrigins         = "ADMIN_ALLOWED_ORIGINS"
	EnvAdminContextRetention       = "ADMIN_CONTEXT_RETENTION"
	EnvAdminLegalReleasedRetention = "ADMIN_LEGAL_RELEASED_RETENTION"
	EnvAdminRequestTimeout         = "ADMIN_REQUEST_TIMEOUT"
	EnvAdminPerActorPerMinute      = "ADMIN_PER_ACTOR_PER_MINUTE"
	EnvAdminPerSubnetPerMinute     = "ADMIN_PER_SUBNET_PER_MINUTE"
	EnvAdminPageSizeDefault        = "ADMIN_PAGE_SIZE_DEFAULT"
	EnvAdminPageSizeMax            = "ADMIN_PAGE_SIZE_MAX"
	EnvAdminAuditMaxWindow         = "ADMIN_AUDIT_MAX_WINDOW"
	EnvAdminChainVerifyMaxLimit    = "ADMIN_CHAIN_VERIFY_MAX_LIMIT"
)

// Defaults for the admin surface.
const (
	defaultAdminPageSizeDefault     = 50
	defaultAdminPageSizeMax         = 200
	defaultAdminAuditMaxWindow      = 31 * 24 * time.Hour
	defaultAdminChainVerifyMaxLimit = 5000
)

// LoadAdmin reads the admin surface configuration from the environment.
//
// Unlike most Load* functions here it takes no environment argument: the
// defaults are production-safe on their own, and there is no development
// relaxation that would make sense (a larger page cap is not more convenient,
// only slower).
func LoadAdmin() (AdminConfig, error) {
	enabled, err := getEnvBool(EnvAdminEnabled, false)
	if err != nil {
		return AdminConfig{}, err
	}
	workflowEnabled, err := getEnvBool(EnvLegalWorkflowEnabled, false)
	if err != nil {
		return AdminConfig{}, err
	}
	pageSizeDefault, err := getEnvPositiveInt(EnvAdminPageSizeDefault, defaultAdminPageSizeDefault)
	if err != nil {
		return AdminConfig{}, err
	}
	pageSizeMax, err := getEnvPositiveInt(EnvAdminPageSizeMax, defaultAdminPageSizeMax)
	if err != nil {
		return AdminConfig{}, err
	}
	auditMaxWindow, err := getEnvDuration(EnvAdminAuditMaxWindow, defaultAdminAuditMaxWindow)
	if err != nil {
		return AdminConfig{}, err
	}
	chainVerifyMaxLimit, err := getEnvPositiveInt(EnvAdminChainVerifyMaxLimit, defaultAdminChainVerifyMaxLimit)
	if err != nil {
		return AdminConfig{}, err
	}
	if pageSizeDefault < 1 || pageSizeDefault > 200 {
		return AdminConfig{}, fmt.Errorf("config: default page size must be 1..200")
	}
	if pageSizeMax < 1 || pageSizeMax > 200 {
		return AdminConfig{}, fmt.Errorf("config: maximum page size must be 1..200")
	}
	if chainVerifyMaxLimit < 1 || chainVerifyMaxLimit > 5000 {
		return AdminConfig{}, fmt.Errorf("config: verification size must be 1..5000")
	}
	contextRetention, err := getEnvDuration(EnvAdminContextRetention, 0)
	if err != nil {
		return AdminConfig{}, err
	}
	legalRetention, err := getEnvDuration(EnvAdminLegalReleasedRetention, 0)
	if err != nil {
		return AdminConfig{}, err
	}
	requestTimeout, err := getEnvDuration(EnvAdminRequestTimeout, 5*time.Second)
	if err != nil {
		return AdminConfig{}, err
	}
	actorLimit, err := getEnvPositiveInt(EnvAdminPerActorPerMinute, 60)
	if err != nil {
		return AdminConfig{}, err
	}
	subnetLimit, err := getEnvPositiveInt(EnvAdminPerSubnetPerMinute, 120)
	if err != nil {
		return AdminConfig{}, err
	}
	var origins []string
	if raw := strings.TrimSpace(os.Getenv(EnvAdminAllowedOrigins)); raw != "" {
		for _, entry := range strings.Split(raw, ",") {
			origin := strings.TrimSpace(entry)
			u, parseErr := url.Parse(origin)
			if parseErr != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "https" && u.Scheme != "http") {
				return AdminConfig{}, fmt.Errorf("config: %s requires exact HTTP(S) origins without paths", EnvAdminAllowedOrigins)
			}
			if getEnv("APP_ENV", "development") != "development" && u.Scheme != "https" {
				return AdminConfig{}, fmt.Errorf("config: admin origins require HTTPS outside development")
			}
			origins = append(origins, origin)
		}
	}

	cfg := AdminConfig{
		Enabled:                enabled,
		GovernancePolicyID:     strings.TrimSpace(os.Getenv(EnvAdminGovernancePolicyID)),
		WorkflowEnabled:        workflowEnabled,
		WorkflowPolicyID:       strings.TrimSpace(os.Getenv(EnvLegalWorkflowPolicyID)),
		AllowedOrigins:         origins,
		ContextRetention:       contextRetention,
		LegalReleasedRetention: legalRetention,
		RequestTimeout:         requestTimeout,
		PerActorPerMinute:      actorLimit,
		PerSubnetPerMinute:     subnetLimit,
		PageSizeDefault:        int32(pageSizeDefault),
		PageSizeMax:            int32(pageSizeMax),
		AuditMaxWindow:         auditMaxWindow,
		ChainVerifyMaxLimit:    int32(chainVerifyMaxLimit),
	}
	if err := cfg.validate(); err != nil {
		return AdminConfig{}, err
	}
	return cfg, nil
}

// validate rejects internally inconsistent combinations.
func (c AdminConfig) validate() error {
	for key, value := range map[string]string{EnvAdminGovernancePolicyID: c.GovernancePolicyID, EnvLegalWorkflowPolicyID: c.WorkflowPolicyID} {
		if value != "" {
			id, err := uuid.Parse(value)
			if err != nil || id == uuid.Nil {
				return fmt.Errorf("config: %s requires a nonzero policy UUID", key)
			}
		}
	}
	if c.Enabled && c.GovernancePolicyID == "" {
		return fmt.Errorf("config: enabling admin requires %s", EnvAdminGovernancePolicyID)
	}
	if c.WorkflowEnabled && (!c.Enabled || c.WorkflowPolicyID == "") {
		return fmt.Errorf("config: enabling legal workflow requires admin and %s", EnvLegalWorkflowPolicyID)
	}
	if c.Enabled && (len(c.AllowedOrigins) == 0 || c.ContextRetention <= 0 || c.LegalReleasedRetention <= 0) {
		return fmt.Errorf("config: enabling admin requires explicit origins and approved context/legal-record retention durations")
	}
	if c.AuditMaxWindow <= 0 || c.AuditMaxWindow > defaultAdminAuditMaxWindow || c.RequestTimeout <= 0 || c.RequestTimeout > 10*time.Second {
		return fmt.Errorf("config: admin window must be within 31 days and request timeout within 10 seconds")
	}
	// A default above the maximum would be silently clamped on every request,
	// making the configured default a lie. Fail at startup instead.
	if c.PageSizeDefault > c.PageSizeMax {
		return fmt.Errorf("config: %s (%d) must not exceed %s (%d)",
			EnvAdminPageSizeDefault, c.PageSizeDefault, EnvAdminPageSizeMax, c.PageSizeMax)
	}
	return nil
}
