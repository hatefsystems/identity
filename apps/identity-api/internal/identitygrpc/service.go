// Package identitygrpc implements workload-authorized identity queries. Register
// Service only behind grpcauth's mTLS transport and admission interceptors.
package identitygrpc

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/grpcauth"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

const (
	maxCompactLength       = 16 * 1024
	maxContextLength       = 2 * 1024
	maxAuditSPIFFEIDLength = 255
)

// TokenValidator verifies both the signed access token and its current authority.
// Only token.ErrInactiveToken denotes a negative authentication result.
type TokenValidator interface {
	Validate(context.Context, string, string) (token.ValidatedAccessToken, error)
}

// Queries is satisfied by db.New(primaryPool), independently of ADMIN_ENABLED.
type Queries interface {
	UserHasPermission(context.Context, db.UserHasPermissionParams) (bool, error)
	GetInternalUserInfo(context.Context, uuid.UUID) (db.GetInternalUserInfoRow, error)
}

// ValidationPolicy grants exact audiences and canonical resource origins to one
// admitted workload. An empty origin set denies all DPoP resource validation.
type ValidationPolicy struct {
	Audiences []string `json:"audiences"`
	Origins   []string `json:"origins"`
}

// Config supplies concurrency-safe dependencies whose lifetimes the caller owns.
// Recorder must provide best-effort delivery; routine reads are not ledger events.
type Config struct {
	Validator TokenValidator
	Queries   Queries
	DPoP      *dpop.Validator
	Policies  map[string]ValidationPolicy
	AllowHTTP bool
	Recorder  audit.Recorder
	Logger    *slog.Logger
}

// Service implements the existing three unary RPCs. Policy is immutable after
// construction; token authority, permissions, and profiles are never cached.
type Service struct {
	identityv1.UnimplementedIdentityServiceServer
	validator TokenValidator
	queries   Queries
	dpop      *dpop.Validator
	policies  map[spiffeid.ID]validationPolicy
	allowHTTP bool
	recorder  audit.Recorder
	logger    *slog.Logger
}

var _ identityv1.IdentityServiceServer = (*Service)(nil)
var _ Queries = (*db.Queries)(nil)

// NewService validates and copies all policy. It opens no backing connections.
func NewService(cfg Config) (*Service, error) {
	if nilDependency(cfg.Validator) || nilDependency(cfg.Queries) || cfg.DPoP == nil || nilDependency(cfg.Recorder) {
		return nil, errors.New("identitygrpc: validator, queries, DPoP validator, and audit recorder are required")
	}
	policies, err := copyPolicies(cfg.Policies, cfg.AllowHTTP)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		validator: cfg.Validator, queries: cfg.Queries, dpop: cfg.DPoP,
		policies: policies, allowHTTP: cfg.AllowHTTP, recorder: cfg.Recorder, logger: logger,
	}, nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// ValidateToken returns a point-in-time decision, not a cacheable authorization.
func (s *Service) ValidateToken(ctx context.Context, req *identityv1.ValidateTokenRequest) (*identityv1.ValidateTokenResponse, error) {
	caller, ok := grpcauth.IdentityFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "workload authentication required")
	}
	if err := ctx.Err(); err != nil {
		return nil, dependencyError(ctx, err)
	}
	if req == nil || len(req.AccessToken) > maxCompactLength || strings.TrimSpace(req.AccessToken) == "" ||
		len(req.DpopProof) > maxCompactLength || !validAudience(req.ExpectedAudience) || len(req.HttpUri) > maxContextLength {
		return nil, status.Error(codes.InvalidArgument, "invalid validation request")
	}
	isDPoP := strings.EqualFold(req.AuthorizationScheme, "DPoP")
	if !isDPoP && !strings.EqualFold(req.AuthorizationScheme, "Bearer") {
		return nil, status.Error(codes.InvalidArgument, "invalid authorization scheme")
	}
	var origin, proofURI string
	if isDPoP || req.HttpMethod != "" || req.HttpUri != "" {
		if !validHTTPMethod(req.HttpMethod) {
			return nil, status.Error(codes.InvalidArgument, "invalid HTTP context")
		}
		u, canonicalOrigin, err := resourceURI(req.HttpUri, s.allowHTTP)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid HTTP context")
		}
		origin = canonicalOrigin
		// RFC 9449 excludes the query. Never derive method or URI from the proof.
		u.RawQuery, u.ForceQuery = "", false
		proofURI = u.String()
	}
	policy := s.policies[caller]
	if _, allowed := policy.audiences[req.ExpectedAudience]; !allowed {
		return nil, status.Error(codes.PermissionDenied, "validation policy denied")
	}
	if origin != "" {
		if _, allowed := policy.origins[origin]; !allowed {
			return nil, status.Error(codes.PermissionDenied, "validation policy denied")
		}
	}

	claims, err := s.validator.Validate(ctx, req.AccessToken, req.ExpectedAudience)
	if ctx.Err() != nil {
		return nil, dependencyError(ctx, ctx.Err())
	}
	if err != nil {
		if errors.Is(err, token.ErrInactiveToken) {
			return &identityv1.ValidateTokenResponse{}, nil
		}
		return nil, dependencyError(ctx, err)
	}
	var principal identityv1.PrincipalType
	var userID string
	switch claims.PrincipalType {
	case token.PrincipalUser:
		id, err := uuid.Parse(claims.Subject)
		if err != nil || id == uuid.Nil {
			return nil, status.Error(codes.Internal, "invalid validated identity")
		}
		principal, userID = identityv1.PrincipalType_PRINCIPAL_TYPE_USER, claims.Subject
	case token.PrincipalClient:
		principal = identityv1.PrincipalType_PRINCIPAL_TYPE_CLIENT
	default:
		return nil, status.Error(codes.Internal, "invalid validated identity")
	}
	if claims.Subject == "" || claims.ClientID == "" || claims.ExpiresAt <= 0 {
		return nil, status.Error(codes.Internal, "invalid validated identity")
	}
	if claims.DPoPJKT != "" {
		if !isDPoP {
			return invalidProof(), nil
		}
		params := dpop.VerifyParams{
			Method: req.HttpMethod, URL: proofURI, AccessToken: req.AccessToken,
			Realm: "rs:" + origin, ExpectedJKT: claims.DPoPJKT, RequireNonce: true,
		}
		if _, err := s.dpop.Validate(ctx, req.DpopProof, params); err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, dpop.ErrStoreUnavailable) {
				return nil, dependencyError(ctx, err)
			}
			var challenge *dpop.NonceChallenge
			if errors.As(err, &challenge) && errors.Is(err, dpop.ErrNonceRequired) {
				if challenge == nil || challenge.Realm != params.Realm || challenge.JKT != claims.DPoPJKT {
					return nil, status.Error(codes.Internal, "invalid proof challenge")
				}
				nonce, err := s.dpop.IssueNonce(ctx, challenge.Realm, challenge.JKT)
				if err != nil || ctx.Err() != nil {
					return nil, dependencyError(ctx, err)
				}
				if nonce == "" {
					return nil, status.Error(codes.Internal, "invalid proof challenge")
				}
				return &identityv1.ValidateTokenResponse{DpopOutcome: identityv1.DpopOutcome_DPOP_OUTCOME_USE_NONCE, DpopNonce: nonce}, nil
			}
			if errors.Is(err, dpop.ErrInvalidParams) || errors.Is(err, dpop.ErrNonceRequired) {
				return nil, status.Error(codes.Internal, "proof validation failed")
			}
			return invalidProof(), nil
		}
	} else if isDPoP || req.DpopProof != "" {
		return invalidProof(), nil
	}
	if err := ctx.Err(); err != nil {
		return nil, dependencyError(ctx, err)
	}
	return &identityv1.ValidateTokenResponse{
		Active: true, UserId: userID, ClientId: claims.ClientID, Subject: claims.Subject,
		PrincipalType: principal, Scopes: strings.Fields(claims.Scope), ExpiresAt: claims.ExpiresAt,
	}, nil
}

func invalidProof() *identityv1.ValidateTokenResponse {
	return &identityv1.ValidateTokenResponse{DpopOutcome: identityv1.DpopOutcome_DPOP_OUTCOME_INVALID_PROOF}
}

// CheckPermission evaluates the exact permission predicate without role, scope,
// wildcard, or administrator special cases.
func (s *Service) CheckPermission(ctx context.Context, req *identityv1.CheckPermissionRequest) (*identityv1.CheckPermissionResponse, error) {
	if _, ok := grpcauth.IdentityFromContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "workload authentication required")
	}
	if err := ctx.Err(); err != nil {
		return nil, dependencyError(ctx, err)
	}
	if req == nil || len(req.Permission) > 100*utf8.UTFMax || !utf8.ValidString(req.Permission) || strings.TrimSpace(req.Permission) == "" ||
		utf8.RuneCountInString(req.Permission) > 100 || strings.ContainsFunc(req.Permission, unicode.IsControl) {
		return nil, status.Error(codes.InvalidArgument, "invalid permission request")
	}
	id, err := uuid.Parse(req.UserId)
	if err != nil || id == uuid.Nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user ID")
	}
	allowed, err := s.queries.UserHasPermission(ctx, db.UserHasPermissionParams{UserID: id, PermissionID: req.Permission})
	if err != nil || ctx.Err() != nil {
		return nil, dependencyError(ctx, err)
	}
	return &identityv1.CheckPermissionResponse{Allowed: allowed}, nil
}

// GetInternalUserInfo discloses only the approved status-dependent projection.
func (s *Service) GetInternalUserInfo(ctx context.Context, req *identityv1.GetInternalUserInfoRequest) (*identityv1.GetInternalUserInfoResponse, error) {
	caller, ok := grpcauth.IdentityFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "workload authentication required")
	}
	if err := ctx.Err(); err != nil {
		return nil, dependencyError(ctx, err)
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid profile request")
	}
	id, err := uuid.Parse(req.UserId)
	if err != nil || id == uuid.Nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user ID")
	}
	profile, err := s.queries.GetInternalUserInfo(ctx, id)
	if ctx.Err() != nil {
		return nil, dependencyError(ctx, ctx.Err())
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, dependencyError(ctx, err)
	}
	if profile.ID != id {
		return nil, status.Error(codes.Internal, "invalid stored profile")
	}
	response := &identityv1.GetInternalUserInfoResponse{UserId: id.String()}
	switch profile.Status {
	case "active":
		response.Status, response.Email = identityv1.UserStatus_USER_STATUS_ACTIVE, profile.Email
	case "pending_verification":
		response.Status, response.Email = identityv1.UserStatus_USER_STATUS_PENDING_VERIFICATION, profile.Email
	case "suspended":
		response.Status = identityv1.UserStatus_USER_STATUS_SUSPENDED
	case "banned":
		response.Status = identityv1.UserStatus_USER_STATUS_BANNED
	case "pending_deletion":
		return nil, status.Error(codes.NotFound, "user not found")
	default:
		return nil, status.Error(codes.Internal, "invalid stored profile")
	}
	event := audit.Event{
		EventType: audit.EventGRPCProfileRead, ActionStatus: audit.StatusSuccess,
		ActorSPIFFEID: caller.String(), SubjectID: &id,
		Payload: map[string]any{"email_disclosed": response.Email != ""},
	}
	if len(event.ActorSPIFFEID) > maxAuditSPIFFEIDLength {
		event.ActorSPIFFEID = ""
		event.Payload["actor_spiffe_id_omitted"] = true
	}
	if err := s.recorder.Record(ctx, event); err != nil {
		// Recorder errors may contain their payload. Do not reproduce them.
		s.logger.WarnContext(ctx, "identitygrpc: profile-read audit unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, dependencyError(ctx, err)
	}
	return response, nil
}

func dependencyError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "request deadline exceeded")
	default:
		return status.Error(codes.Unavailable, "identity service unavailable")
	}
}
