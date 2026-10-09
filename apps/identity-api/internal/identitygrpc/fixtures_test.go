package identitygrpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/test/bufconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/grpcauth"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

const (
	testDomain   = "identity.test"
	testCaller   = "spiffe://identity.test/workload/resource"
	testOther    = "spiffe://identity.test/workload/other"
	testServer   = "spiffe://identity.test/workload/identity"
	testAudience = "https://identity.test"
	testOrigin   = "https://resource.test"
	testURI      = testOrigin + "/objects/one"
	testToken    = "opaque-access-token-for-validator-fixture"
	testUserID   = "d4ab8c9a-b67e-4dbb-82a9-28c9fd662bfc"
)

type tokenValidatorFunc func(context.Context, string, string) (token.ValidatedAccessToken, error)

func (f tokenValidatorFunc) Validate(ctx context.Context, compact, audience string) (token.ValidatedAccessToken, error) {
	return f(ctx, compact, audience)
}

type queryFuncs struct {
	permission func(context.Context, db.UserHasPermissionParams) (bool, error)
	profile    func(context.Context, uuid.UUID) (db.GetInternalUserInfoRow, error)
}

func (q queryFuncs) UserHasPermission(ctx context.Context, arg db.UserHasPermissionParams) (bool, error) {
	if q.permission == nil {
		return false, errors.New("unexpected permission query")
	}
	return q.permission(ctx, arg)
}

func (q queryFuncs) GetInternalUserInfo(ctx context.Context, id uuid.UUID) (db.GetInternalUserInfoRow, error) {
	if q.profile == nil {
		return db.GetInternalUserInfoRow{}, errors.New("unexpected profile query")
	}
	return q.profile(ctx, id)
}

type testRecorder struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (r *testRecorder) Record(_ context.Context, event audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return r.err
}

func (r *testRecorder) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

func validClaims() token.ValidatedAccessToken {
	return token.ValidatedAccessToken{
		PrincipalType: token.PrincipalUser, Subject: testUserID, ClientID: "resource-client",
		Scope: "openid profile objects.read", ExpiresAt: time.Now().Add(time.Minute).Unix(),
	}
}

func validRequest() *identityv1.ValidateTokenRequest {
	return &identityv1.ValidateTokenRequest{
		AccessToken: testToken, ExpectedAudience: testAudience, AuthorizationScheme: "Bearer",
	}
}

func testConfig(t *testing.T) Config {
	t.Helper()
	validator, err := dpop.NewValidator(dpop.NewMemoryReplayGuard(), dpop.NewMemoryNonceStore())
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Validator: tokenValidatorFunc(func(context.Context, string, string) (token.ValidatedAccessToken, error) { return validClaims(), nil }),
		Queries: queryFuncs{
			permission: func(context.Context, db.UserHasPermissionParams) (bool, error) { return true, nil },
			profile: func(_ context.Context, id uuid.UUID) (db.GetInternalUserInfoRow, error) {
				return db.GetInternalUserInfoRow{ID: id, Status: "active", Email: "profile@example.invalid"}, nil
			},
		},
		DPoP:     validator,
		Policies: map[string]ValidationPolicy{testCaller: {Audiences: []string{testAudience}, Origins: []string{testOrigin}}},
		Recorder: &testRecorder{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func testService(t *testing.T, cfg Config) *Service {
	t.Helper()
	service, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func rpcContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func allGrants(caller string) map[string][]string {
	return map[string][]string{
		identityv1.IdentityService_ValidateToken_FullMethodName:       {caller},
		identityv1.IdentityService_CheckPermission_FullMethodName:     {caller},
		identityv1.IdentityService_GetInternalUserInfo_FullMethodName: {caller},
	}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral RPC test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) issue(t *testing.T, rawID string) *x509svid.SVID {
	t.Helper()
	id := spiffeid.RequireFromString(rawID)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(1)),
		Subject:      pkix.Name{CommonName: "This is not a workload identity"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:        []*url.URL{id.URL()},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{cert}, PrivateKey: key}
}

type fixedSVID struct{ svid *x509svid.SVID }

func (s fixedSVID) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

type testBundles struct {
	mu     sync.RWMutex
	bundle *x509bundle.Bundle
	err    error
}

func (s *testBundles) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundle, s.err
}

func (s *testBundles) set(bundle *x509bundle.Bundle, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle, s.err = bundle, err
}

type mtlsHarness struct {
	service  *Service
	ca       *testCA
	listener *bufconn.Listener
	bundles  *testBundles
	admitted atomic.Int64
}

func newMTLSHarness(t *testing.T, cfg Config, grants map[string][]string) *mtlsHarness {
	t.Helper()
	ca := newTestCA(t)
	bundles := &testBundles{bundle: x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString(testDomain), []*x509.Certificate{ca.cert})}
	auth, err := grpcauth.New(grpcauth.Config{TrustDomain: testDomain, Grants: grants, Bundles: bundles, Recorder: cfg.Recorder, Logger: cfg.Logger})
	if err != nil {
		t.Fatal(err)
	}
	options, err := auth.ServerOptions(fixedSVID{ca.issue(t, testServer)})
	if err != nil {
		t.Fatal(err)
	}
	h := &mtlsHarness{service: testService(t, cfg), ca: ca, bundles: bundles, listener: bufconn.Listen(1024 * 1024)}
	options = append(options, grpc.MaxRecvMsgSize(64*1024), grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		p, ok := peer.FromContext(ctx)
		if !ok {
			t.Error("admitted call has no transport peer")
		} else if info, ok := p.AuthInfo.(credentials.TLSInfo); !ok || !info.State.HandshakeComplete || info.State.Version != tls.VersionTLS13 || len(info.State.PeerCertificates) == 0 {
			t.Error("admitted call did not use real mutually authenticated TLS 1.3")
		}
		if _, ok := grpcauth.IdentityFromContext(ctx); !ok {
			t.Error("admitted call has no grpcauth identity")
		}
		h.admitted.Add(1)
		return handler(ctx, req)
	}))
	server := grpc.NewServer(options...)
	identityv1.RegisterIdentityServiceServer(server, h.service)
	done := make(chan error, 1)
	go func() { done <- server.Serve(h.listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = h.listener.Close()
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("Serve: %v", err)
		}
	})
	return h
}

func (h *mtlsHarness) client(t *testing.T, caller string) identityv1.IdentityServiceClient {
	t.Helper()
	bundle := x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString(testDomain), []*x509.Certificate{h.ca.cert})
	config := tlsconfig.MTLSClientConfig(fixedSVID{h.ca.issue(t, caller)}, bundle, tlsconfig.AuthorizeID(spiffeid.RequireFromString(testServer)))
	config.MinVersion = tls.VersionTLS13
	return h.clientWithCredentials(t, credentials.NewTLS(config))
}

func (h *mtlsHarness) clientWithCredentials(t *testing.T, creds credentials.TransportCredentials) identityv1.IdentityServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///identitygrpc.test", grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return h.listener.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return identityv1.NewIdentityServiceClient(conn)
}
