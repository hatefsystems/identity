package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

type runtimeSource struct {
	svid        *x509svid.SVID
	bundle      *x509bundle.Bundle
	closed      atomic.Int32
	unavailable atomic.Bool
}

func (s *runtimeSource) GetX509SVID() (*x509svid.SVID, error) {
	if s.unavailable.Load() {
		return nil, errors.New("source unavailable")
	}
	return s.svid, nil
}
func (s *runtimeSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if s.unavailable.Load() || td != s.bundle.TrustDomain() {
		return nil, errors.New("bundle unavailable")
	}
	return s.bundle, nil
}
func (s *runtimeSource) Close() error { s.closed.Add(1); return nil }

type runtimeTokenValidator func(context.Context, string, string) (token.ValidatedAccessToken, error)

func (f runtimeTokenValidator) Validate(ctx context.Context, compact, audience string) (token.ValidatedAccessToken, error) {
	return f(ctx, compact, audience)
}

type runtimeQueries struct{}

func (runtimeQueries) UserHasPermission(context.Context, db.UserHasPermissionParams) (bool, error) {
	return false, nil
}
func (runtimeQueries) GetInternalUserInfo(context.Context, uuid.UUID) (db.GetInternalUserInfoRow, error) {
	return db.GetInternalUserInfoRow{}, errors.New("unused profile")
}

type runtimeAudit struct{}

func (runtimeAudit) Record(context.Context, audit.Event) error { return nil }

func runtimeFixture(t *testing.T) (config.GRPCConfig, grpcDependencies, *runtimeSource, *runtimeSource) {
	t.Helper()
	td := spiffeid.RequireTrustDomainFromString("runtime.test")
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	bundle := x509bundle.FromX509Authorities(td, []*x509.Certificate{ca})
	makeSource := func(path string, serial int64) *runtimeSource {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id := spiffeid.RequireFromString("spiffe://runtime.test/" + path)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), URIs: []*url.URL{id.URL()},
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return &runtimeSource{svid: &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{cert}, PrivateKey: key}, bundle: bundle}
	}
	serverSource, callerSource := makeSource("identity", 2), makeSource("caller", 3)
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	proofs, err := dpop.NewValidator(dpop.NewMemoryReplayGuard(), dpop.NewMemoryNonceStore())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.GRPCConfig{Enabled: true, Address: "127.0.0.1:0", TrustDomain: td.String(), WorkloadAPI: "unix:///fixture", RequestTimeout: time.Second,
		Grants:             map[string][]string{identityv1.IdentityService_ValidateToken_FullMethodName: {callerSource.svid.ID.String()}},
		ValidationPolicies: map[string]config.GRPCValidationPolicy{callerSource.svid.ID.String(): {Audiences: []string{"https://issuer.test"}}}}
	deps := grpcDependencies{Queries: runtimeQueries{}, Redis: rdb, Recorder: runtimeAudit{}, DPoP: proofs,
		DatabaseReady: func(context.Context) error { return nil }, Validator: runtimeTokenValidator(func(context.Context, string, string) (token.ValidatedAccessToken, error) {
			return token.ValidatedAccessToken{PrincipalType: token.PrincipalClient, Subject: "client", ClientID: "client", ExpiresAt: time.Now().Add(time.Minute).Unix()}, nil
		})}
	return cfg, deps, serverSource, callerSource
}

func startRuntime(t *testing.T, cfg config.GRPCConfig, deps grpcDependencies, source, caller *runtimeSource) (*privateGRPC, identityv1.IdentityServiceClient) {
	t.Helper()
	runtime, err := buildPrivateGRPC(t.Context(), cfg, deps, nil, func(ctx context.Context, _ string) (workloadSource, error) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 10*time.Second {
			t.Error("startup deadline missing")
		}
		return source, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Ready(t.Context()) == nil {
		t.Fatal("unstarted listener is ready")
	}
	go func() { _ = runtime.Start() }()
	tlsConfig := tlsconfig.MTLSClientConfig(caller, caller, tlsconfig.AuthorizeID(source.svid.ID))
	tlsConfig.MinVersion = tls.VersionTLS13
	conn, err := grpc.NewClient(runtime.listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = runtime.Shutdown(ctx)
		_ = runtime.Close()
	})
	return runtime, identityv1.NewIdentityServiceClient(conn)
}

func runtimeRequest() *identityv1.ValidateTokenRequest {
	return &identityv1.ValidateTokenRequest{AccessToken: "fixture", ExpectedAudience: "https://issuer.test", AuthorizationScheme: "Bearer"}
}

func TestPrivateGRPCDisabledAndStartupCleanup(t *testing.T) {
	if got, err := buildPrivateGRPC(t.Context(), config.GRPCConfig{}, grpcDependencies{}, nil, func(context.Context, string) (workloadSource, error) {
		t.Fatal("disabled source opened")
		return nil, nil
	}); err != nil || got != nil {
		t.Fatal(err)
	}
	cfg, deps, source, _ := runtimeFixture(t)
	missing := deps
	missing.Redis = nil
	if _, err := buildPrivateGRPC(t.Context(), cfg, missing, nil, nil); err == nil {
		t.Fatal("missing dependency accepted")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	cfg.Address = listener.Addr().String()
	if _, err := buildPrivateGRPC(t.Context(), cfg, deps, nil, func(context.Context, string) (workloadSource, error) { return source, nil }); err == nil {
		t.Fatal("bind conflict accepted")
	}
	if source.closed.Load() != 1 {
		t.Fatal("source leaked on bind failure")
	}
}

func TestPrivateGRPCAdmissionAndReadiness(t *testing.T) {
	cfg, deps, source, caller := runtimeFixture(t)
	runtime, client := startRuntime(t, cfg, deps, source, caller)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	response, err := client.ValidateToken(ctx, runtimeRequest())
	if err != nil || !response.Active {
		t.Fatalf("mTLS call: %+v %v", response, err)
	}
	if err := runtime.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CheckPermission(ctx, &identityv1.CheckPermissionRequest{UserId: uuid.NewString(), Permission: "read"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("method bypass: %v", err)
	}
	source.unavailable.Store(true)
	if runtime.Ready(ctx) == nil {
		t.Fatal("stale trust reported ready")
	}
	if _, err := client.ValidateToken(ctx, runtimeRequest()); status.Code(err) != codes.Unavailable {
		t.Fatalf("trust failure hidden: %v", err)
	}
}

func TestPrivateGRPCRequestDeadline(t *testing.T) {
	cfg, deps, source, caller := runtimeFixture(t)
	cfg.RequestTimeout = 20 * time.Millisecond
	deps.Validator = runtimeTokenValidator(func(ctx context.Context, _, _ string) (token.ValidatedAccessToken, error) {
		<-ctx.Done()
		return token.ValidatedAccessToken{}, ctx.Err()
	})
	_, client := startRuntime(t, cfg, deps, source, caller)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := client.ValidateToken(ctx, runtimeRequest()); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("deadline not enforced: %v", err)
	}
}

func TestPrivateGRPCForcedShutdownIsBounded(t *testing.T) {
	cfg, deps, source, caller := runtimeFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	deps.Validator = runtimeTokenValidator(func(context.Context, string, string) (token.ValidatedAccessToken, error) {
		close(entered)
		<-release
		return token.ValidatedAccessToken{}, token.ErrInactiveToken
	})
	runtime, client := startRuntime(t, cfg, deps, source, caller)
	defer close(release)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	clientDone := make(chan error, 1)
	go func() { _, err := client.ValidateToken(ctx, runtimeRequest()); clientDone <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	shutdown, stop := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer stop()
	start := time.Now()
	if err := runtime.Shutdown(shutdown); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("force stop: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("forced shutdown waited for an uncooperative handler")
	}
	if runtime.Ready(t.Context()) == nil {
		t.Fatal("stopped listener is ready")
	}
	select {
	case err := <-clientDone:
		if err == nil {
			t.Fatal("forced shutdown left a successful pending call")
		}
	case <-time.After(time.Second):
		t.Fatal("forced shutdown did not close the client transport")
	}
	runtime.listener.mu.Lock()
	remaining := len(runtime.listener.connections)
	runtime.listener.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("forced shutdown left %d live sockets", remaining)
	}
}
