// Package grpcauth authenticates SPIFFE workloads and enforces exact-method
// grants at gRPC admission. Construct an Authorizer with New; its zero value
// is not usable. Workload permissions are independent of user/admin RBAC.
package grpcauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

const (
	maxMethodLength   = 512
	maxSPIFFEIDLength = 2048
	// mvp_audit_logs.actor_spiffe_id is VARCHAR(255). Do not truncate an
	// identity into another principal or poison the asynchronous audit batch.
	maxAuditSPIFFEIDLength = 255
)

var fullMethodPattern = regexp.MustCompile(`^/[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*/[A-Za-z_][A-Za-z0-9_]*$`)

// Config supplies explicit policy and locally maintained trust material.
// Bundles and Recorder must be concurrency-safe. The caller owns their lifetime.
type Config struct {
	// TrustDomain is a bare canonical name, such as "hatef.ir", not a URI.
	TrustDomain string
	// Grants maps exact full RPC methods to exact workload SPIFFE IDs. There
	// are no default grants; an empty policy denies every method.
	Grants map[string][]string
	// Bundles should be backed by a maintained local source, such as a
	// workloadapi.X509Source, rather than a network request on each lookup.
	Bundles  x509bundle.Source
	Recorder audit.Recorder
	Logger   *slog.Logger
}

// Authorizer is an immutable method policy over a dynamically maintained bundle
// source. Each new RPC is verified against the current trust material.
type Authorizer struct {
	trustDomain spiffeid.TrustDomain
	grants      map[string]map[spiffeid.ID]struct{}
	bundles     x509bundle.Source
	recorder    audit.Recorder
	logger      *slog.Logger
	now         func() time.Time
}

// New validates and copies cfg's grants. Mutating the input policy after New
// returns cannot change permissions. It neither opens nor closes any source.
func New(cfg Config) (*Authorizer, error) {
	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil || td.String() != cfg.TrustDomain {
		return nil, errors.New("grpcauth: a canonical trust domain name is required")
	}
	if cfg.Bundles == nil || cfg.Recorder == nil {
		return nil, errors.New("grpcauth: bundle source and audit recorder are required")
	}
	grants := make(map[string]map[spiffeid.ID]struct{}, len(cfg.Grants))
	for method, identities := range cfg.Grants {
		if !validMethod(method) {
			return nil, errors.New("grpcauth: invalid full RPC method in policy")
		}
		allowed := make(map[spiffeid.ID]struct{}, len(identities))
		for _, raw := range identities {
			id, err := spiffeid.FromString(raw)
			if err != nil || len(raw) > maxSPIFFEIDLength || id.Path() == "" || !id.MemberOf(td) {
				return nil, fmt.Errorf("grpcauth: invalid workload identity for method %s", method)
			}
			allowed[id] = struct{}{}
		}
		grants[method] = allowed
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Authorizer{
		trustDomain: td,
		grants:      grants,
		bundles:     cfg.Bundles,
		recorder:    cfg.Recorder,
		logger:      logger,
		now:         time.Now,
	}, nil
}

func validMethod(method string) bool {
	return len(method) <= maxMethodLength && fullMethodPattern.MatchString(method)
}

func (a *Authorizer) authorize(ctx context.Context, method string) (context.Context, error) {
	id, code, reason := a.authenticate(ctx)
	if code == codes.OK {
		if _, allowed := a.grants[method][id]; allowed {
			return context.WithValue(ctx, identityContextKey{}, id), nil
		}
		code, reason = codes.PermissionDenied, "method_not_granted"
	}
	a.recordDenial(ctx, id, method, code, reason)
	switch code {
	case codes.PermissionDenied:
		return nil, status.Error(code, "permission denied")
	case codes.Unavailable:
		return nil, status.Error(code, "workload verification unavailable")
	default:
		return nil, status.Error(codes.Unauthenticated, "workload authentication required")
	}
}

func (a *Authorizer) authenticate(ctx context.Context) (spiffeid.ID, codes.Code, string) {
	var unknown spiffeid.ID
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return unknown, codes.Unauthenticated, "missing_tls"
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || !info.State.HandshakeComplete || info.State.Version < tls.VersionTLS13 {
		return unknown, codes.Unauthenticated, "invalid_tls"
	}
	certs := info.State.PeerCertificates
	if len(certs) == 0 || slices.Contains(certs, nil) {
		return unknown, codes.Unauthenticated, "missing_certificate"
	}
	leaf := certs[0]
	if len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return unknown, codes.Unauthenticated, "invalid_identity"
	}
	id, err := x509svid.IDFromCert(leaf)
	if err != nil || len(id.String()) > maxSPIFFEIDLength || id.Path() == "" || !id.MemberOf(a.trustDomain) {
		return unknown, codes.Unauthenticated, "invalid_identity"
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return unknown, codes.Unauthenticated, "invalid_certificate_usage"
	}
	// x509svid.Verify uses ExtKeyUsageAny. Check the SVID profile separately,
	// including an explicitly present but empty EKU extension.
	hasEKU := len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			hasEKU = true
			break
		}
	}
	if hasEKU && (!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) ||
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)) {
		return unknown, codes.Unauthenticated, "invalid_certificate_usage"
	}
	bundle, err := a.bundles.GetX509BundleForTrustDomain(a.trustDomain)
	if err != nil || bundle == nil || bundle.TrustDomain() != a.trustDomain {
		return unknown, codes.Unavailable, "trust_unavailable"
	}
	// Snapshot once so rotation cannot change the roots between checking source
	// availability and verifying the chain. Certificate objects remain read-only.
	bundle = bundle.Clone()
	roots := bundle.X509Authorities()
	if len(roots) == 0 || slices.Contains(roots, nil) {
		return unknown, codes.Unavailable, "trust_unavailable"
	}
	// Custom SPIFFE TLS verification does not populate TLSInfo.VerifiedChains.
	// Reverify the actual peer chain, even on an already established connection.
	verifiedID, _, err := x509svid.Verify(certs, bundle, x509svid.WithTime(a.now()))
	if err != nil {
		return unknown, codes.Unauthenticated, "invalid_certificate"
	}
	return verifiedID, codes.OK, ""
}

func (a *Authorizer) recordDenial(ctx context.Context, id spiffeid.ID, method string, code codes.Code, reason string) {
	if !validMethod(method) {
		method = "unknown"
	}
	event := audit.Event{
		EventType:     audit.EventGRPCAccessDenied,
		ActionStatus:  audit.StatusFailure,
		ActorSPIFFEID: id.String(),
		Payload: map[string]any{
			"method": method,
			"status": code.String(),
			"reason": reason,
		},
	}
	if len(event.ActorSPIFFEID) > maxAuditSPIFFEIDLength {
		event.ActorSPIFFEID = ""
		event.Payload["actor_spiffe_id_omitted"] = true
	}
	if err := a.recorder.Record(ctx, event); err != nil {
		// Recorder errors can contain payloads; never copy their text to logs.
		a.logger.WarnContext(ctx, "grpcauth: access-denied audit unavailable",
			slog.String("method", method), slog.String("status", code.String()))
	}
}
