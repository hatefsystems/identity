package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/grpcauth"
	"github.com/hatefsystems/identity/apps/identity-api/internal/identitygrpc"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

type workloadSource interface {
	x509svid.Source
	x509bundle.Source
	Close() error
}

type workloadSourceFactory func(context.Context, string) (workloadSource, error)

type grpcDependencies struct {
	Validator     identitygrpc.TokenValidator
	Queries       identitygrpc.Queries
	DPoP          *dpop.Validator
	Recorder      audit.Recorder
	Redis         redis.UniversalClient
	DatabaseReady func(context.Context) error
	AllowHTTP     bool
}

type privateGRPC struct {
	server      *grpc.Server
	listener    *grpcListener
	source      workloadSource
	trustDomain spiffeid.TrustDomain
	deps        grpcDependencies
	running     atomic.Bool
	stopped     atomic.Bool
	forceStop   sync.Once
}

func openWorkloadSource(ctx context.Context, address string) (workloadSource, error) {
	return workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(address)))
}

func buildPrivateGRPC(ctx context.Context, cfg config.GRPCConfig, deps grpcDependencies, logger *slog.Logger, open workloadSourceFactory) (*privateGRPC, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if deps.Validator == nil || deps.Queries == nil || deps.DPoP == nil || deps.Recorder == nil || deps.Redis == nil || deps.DatabaseReady == nil {
		return nil, errors.New("main: enabled gRPC requires PostgreSQL, Redis and identity services")
	}
	if cfg.RequestTimeout <= 0 || cfg.RequestTimeout > 30*time.Second {
		return nil, errors.New("main: invalid gRPC request deadline")
	}
	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil || td.String() != cfg.TrustDomain {
		return nil, errors.New("main: invalid gRPC trust domain")
	}
	policies := make(map[string]identitygrpc.ValidationPolicy, len(cfg.ValidationPolicies))
	for caller, policy := range cfg.ValidationPolicies {
		policies[caller] = identitygrpc.ValidationPolicy{Audiences: policy.Audiences, Origins: policy.Origins}
	}
	service, err := identitygrpc.NewService(identitygrpc.Config{Validator: deps.Validator, Queries: deps.Queries,
		DPoP: deps.DPoP, Recorder: deps.Recorder, Logger: logger, Policies: policies, AllowHTTP: deps.AllowHTTP})
	if err != nil {
		return nil, err
	}
	if open == nil {
		open = openWorkloadSource
	}
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := deps.DatabaseReady(startup); err != nil {
		return nil, errors.New("main: gRPC database unavailable")
	}
	if err := deps.Redis.Ping(startup).Err(); err != nil {
		return nil, errors.New("main: gRPC Redis unavailable")
	}
	source, err := open(startup, cfg.WorkloadAPI)
	if err != nil {
		return nil, errors.New("main: gRPC workload identity unavailable")
	}
	if source == nil {
		return nil, errors.New("main: gRPC workload source missing")
	}
	owned := true
	defer func() {
		if owned {
			_ = source.Close()
		}
	}()
	if err := usableWorkloadSource(source, td); err != nil {
		return nil, err
	}
	gate, err := grpcauth.New(grpcauth.Config{TrustDomain: cfg.TrustDomain, Grants: cfg.Grants, Bundles: source, Recorder: deps.Recorder, Logger: logger})
	if err != nil {
		return nil, err
	}
	options, err := gate.ServerOptions(source)
	if err != nil {
		return nil, err
	}
	options = append(options, grpc.ConnectionTimeout(5*time.Second), grpc.MaxRecvMsgSize(64*1024),
		grpc.MaxSendMsgSize(64*1024), grpc.MaxHeaderListSize(16*1024), grpc.MaxConcurrentStreams(100),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: 5 * time.Minute, MaxConnectionAgeGrace: 30 * time.Second}),
		grpc.ChainUnaryInterceptor(boundedRPC(cfg.RequestTimeout)))
	server := grpc.NewServer(options...)
	identityv1.RegisterIdentityServiceServer(server, service)
	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		server.Stop()
		return nil, errors.New("main: cannot bind private gRPC listener")
	}
	owned = false
	tracked := &grpcListener{Listener: listener, connections: make(map[*grpcConnection]struct{})}
	return &privateGRPC{server: server, listener: tracked, source: source, trustDomain: td, deps: deps}, nil
}

func boundedRPC(timeout time.Duration) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		response, err := next(ctx, request)
		if ctx.Err() != nil {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		return response, err
	}
}

func usableWorkloadSource(source workloadSource, domain spiffeid.TrustDomain) error {
	failure := errors.New("main: usable local gRPC identity and trust are required")
	svid, err := source.GetX509SVID()
	if err != nil || svid == nil || svid.PrivateKey == nil || len(svid.Certificates) == 0 || !svid.ID.MemberOf(domain) || svid.ID.Path() == "" {
		return failure
	}
	for _, cert := range svid.Certificates {
		if cert == nil {
			return failure
		}
	}
	leaf := svid.Certificates[0]
	if len(leaf.URIs) != 1 || leaf.URIs[0] == nil || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return failure
	}
	id, _, err := x509svid.Verify(svid.Certificates, source, x509svid.WithTime(time.Now()))
	if err != nil || id != svid.ID {
		return failure
	}
	certificateKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return failure
	}
	privateKey, err := x509.MarshalPKIXPublicKey(svid.PrivateKey.Public())
	if err != nil || !bytes.Equal(certificateKey, privateKey) {
		return failure
	}
	return nil
}

func (s *privateGRPC) Start() error {
	if s.stopped.Load() {
		return nil
	}
	s.running.Store(true)
	defer s.running.Store(false)
	err := s.server.Serve(s.listener)
	if errors.Is(err, grpc.ErrServerStopped) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *privateGRPC) Ready(ctx context.Context) error {
	if s.stopped.Load() || !s.running.Load() {
		return errors.New("gRPC listener unavailable")
	}
	if err := usableWorkloadSource(s.source, s.trustDomain); err != nil {
		return err
	}
	if err := s.deps.DatabaseReady(ctx); err != nil {
		return errors.New("gRPC database unavailable")
	}
	if err := s.deps.Redis.Ping(ctx).Err(); err != nil {
		return errors.New("gRPC Redis unavailable")
	}
	return nil
}

func (s *privateGRPC) Shutdown(ctx context.Context) error {
	s.stopped.Store(true)
	s.running.Store(false)
	// Also closes a listener acquired during startup but never passed to Serve.
	_ = s.listener.Close()
	done := make(chan struct{})
	go func() { s.server.GracefulStop(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.stopNow()
		return ctx.Err()
	}
}

func (s *privateGRPC) Close() error {
	s.stopped.Store(true)
	_ = s.listener.Close()
	s.stopNow()
	return s.source.Close()
}

func (s *privateGRPC) stopNow() {
	s.listener.closeConnections()
	// grpc 1.81 can hold its mutex while GracefulStop waits for a handler,
	// blocking even Stop. Close transports independently, then let gRPC finish
	// bookkeeping asynchronously instead of defeating the shutdown deadline.
	s.forceStop.Do(func() { go s.server.Stop() })
}

type grpcListener struct {
	net.Listener
	mu          sync.Mutex
	connections map[*grpcConnection]struct{}
	closed      bool
}

func (l *grpcListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tracked := &grpcConnection{Conn: conn, owner: l}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	l.connections[tracked] = struct{}{}
	l.mu.Unlock()
	return tracked, nil
}

func (l *grpcListener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return l.Listener.Close()
}

func (l *grpcListener) closeConnections() {
	l.mu.Lock()
	connections := make([]*grpcConnection, 0, len(l.connections))
	for conn := range l.connections {
		connections = append(connections, conn)
	}
	l.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

type grpcConnection struct {
	net.Conn
	owner *grpcListener
}

func (c *grpcConnection) Close() error {
	err := c.Conn.Close()
	c.owner.mu.Lock()
	delete(c.owner.connections, c)
	c.owner.mu.Unlock()
	return err
}
