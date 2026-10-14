// Package grpcauth authenticates SPIFFE workloads and enforces exact-method
// grants at gRPC admission. Construct an Authorizer with New; its zero value
// is not usable. Workload permissions are independent of user/admin RBAC.
package grpcauth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sync/atomic"
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
	// AdmissionCacheSize bounds the successful-verification cache. Zero selects a
	// default. The cache never weakens a decision: see admissioncache.go.
	AdmissionCacheSize int
}

// Authorizer is a replaceable method policy over a dynamically maintained bundle
// source. Each new connection is verified against the current trust material.
type Authorizer struct {
	trustDomain spiffeid.TrustDomain
	// grants is swapped atomically by SetGrants.
	//
	// It is a pointer rather than a plain map because revoking a compromised
	// workload's access is the one policy change that must not wait for a process
	// restart. Readers take the pointer once per call, so a reload is invisible
	// to an in-flight admission decision: it either sees the whole old policy or
	// the whole new one, never a half-applied mixture.
	grants   atomic.Pointer[map[string]map[spiffeid.ID]struct{}]
	bundles  x509bundle.Source
	recorder audit.Recorder
	logger   *slog.Logger
	now      func() time.Time
	// admissions memoizes successful path verifications keyed on the peer leaf and
	// the current trust set, so the per-RPC decision stays authoritative without
	// repeating the public-key work on every call. See admissioncache.go.
	admissions *admissionCache
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
	grants, err := compileGrants(td, cfg.Grants)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	a := &Authorizer{
		trustDomain: td,
		bundles:     cfg.Bundles,
		recorder:    cfg.Recorder,
		logger:      logger,
		now:         time.Now,
		admissions:  newAdmissionCache(cfg.AdmissionCacheSize),
	}
	a.grants.Store(&grants)
	return a, nil
}

// compileGrants validates and copies a policy. Mutating the input afterwards
// cannot change permissions.
func compileGrants(td spiffeid.TrustDomain, raw map[string][]string) (map[string]map[spiffeid.ID]struct{}, error) {
	grants := make(map[string]map[spiffeid.ID]struct{}, len(raw))
	for method, identities := range raw {
		if !validMethod(method) {
			return nil, errors.New("grpcauth: invalid full RPC method in policy")
		}
		allowed := make(map[spiffeid.ID]struct{}, len(identities))
		for _, id := range identities {
			parsed, err := spiffeid.FromString(id)
			if err != nil || len(id) > maxSPIFFEIDLength || parsed.Path() == "" || !parsed.MemberOf(td) {
				return nil, fmt.Errorf("grpcauth: invalid workload identity for method %s", method)
			}
			allowed[parsed] = struct{}{}
		}
		grants[method] = allowed
	}
	return grants, nil
}

// SetGrants replaces the method policy atomically.
//
// Revoking a compromised workload is the one policy change that should not
// require a process restart, which is why this exists rather than the policy
// being fixed at construction. The whole policy is validated before anything is
// published, so a malformed reload leaves the previous policy in force instead of
// opening or closing methods by accident.
//
// It does not touch the trust bundle: rotation is the bundle source's job.
func (a *Authorizer) SetGrants(raw map[string][]string) error {
	grants, err := compileGrants(a.trustDomain, raw)
	if err != nil {
		return err
	}
	a.grants.Store(&grants)
	a.logger.Info("grpcauth: method policy reloaded", slog.Int("methods", len(grants)))
	return nil
}

func validMethod(method string) bool {
	return len(method) <= maxMethodLength && fullMethodPattern.MatchString(method)
}

func (a *Authorizer) authorize(ctx context.Context, method string) (context.Context, error) {
	id, code, reason := a.authenticate(ctx)
	if code == codes.OK {
		// One load per decision, so a concurrent SetGrants cannot be observed
		// half-applied.
		grants := *a.grants.Load()
		if _, allowed := grants[method][id]; allowed {
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

// authenticate resolves the caller's verified identity for one RPC.
//
// The decision is made per RPC, not per connection, and that is deliberate.
// Removing a workload from the trust bundle, letting its SVID expire, or losing
// the trust source must all take effect on calls over connections that are
// already established — otherwise revoking a compromised workload would wait for
// it to reconnect, which it has no reason to do.
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
	return a.verifyPeer(info.State)
}

// verifyPeer performs the SVID admission check against a completed handshake.
func (a *Authorizer) verifyPeer(state tls.ConnectionState) (spiffeid.ID, codes.Code, string) {
	var unknown spiffeid.ID
	if !state.HandshakeComplete || state.Version < tls.VersionTLS13 {
		return unknown, codes.Unauthenticated, "invalid_tls"
	}
	certs := state.PeerCertificates
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
	// Require clientAuth only.
	//
	// This is validating a *client* certificate, so serverAuth is irrelevant here.
	// SPIRE happens to set both today, but the SPIFFE X.509-SVID profile does not
	// require it: an issuer that sets only clientAuth produces a conformant SVID,
	// and rejecting it would surface as "invalid_certificate_usage", which reads
	// like a trust-bundle problem and would send an operator looking in the wrong
	// place entirely.
	if hasEKU && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return unknown, codes.Unauthenticated, "invalid_certificate_usage"
	}
	// The trust source is consulted on every call, never cached: an unavailable
	// source must fail closed immediately rather than coast on a previous answer.
	bundle, err := a.bundles.GetX509BundleForTrustDomain(a.trustDomain)
	if err != nil || bundle == nil || bundle.TrustDomain() != a.trustDomain {
		return unknown, codes.Unavailable, "trust_unavailable"
	}
	// Snapshot once so rotation cannot change the roots between checking source
	// availability and verifying the chain. Certificate objects remain read-only.
	roots, ok := bundleRoots(bundle)
	if !ok {
		return unknown, codes.Unavailable, "trust_unavailable"
	}

	now := a.now()
	key := admissionKey{leaf: sha256.Sum256(leaf.Raw), trustSet: trustSetDigest(roots)}
	if cached, hit := a.admissions.lookup(key, now); hit {
		// A hit means this exact leaf was already verified against this exact trust
		// set, and is still inside its validity window. A full verification could
		// not reach a different conclusion, so skipping it changes cost, not
		// authority. Any change to the leaf or the trust set is a different key.
		return cached, codes.OK, ""
	}

	// Custom SPIFFE TLS verification does not populate TLSInfo.VerifiedChains, so
	// the actual peer chain is verified here rather than trusted from the
	// handshake — including on an already established connection.
	verifiedID, _, err := x509svid.Verify(certs, x509bundle.FromX509Authorities(a.trustDomain, roots),
		x509svid.WithTime(now))
	if err != nil {
		return unknown, codes.Unauthenticated, "invalid_certificate"
	}
	a.admissions.store(key, admissionEntry{
		id: verifiedID, notBefore: leaf.NotBefore, notAfter: leaf.NotAfter,
	})
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
