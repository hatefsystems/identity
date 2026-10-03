package grpcauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type transportObservation struct {
	id, serial     string
	verifiedChains int
	resumed        bool
}

// The health protocol is only a test fixture, not an authorization exemption.
type transportService struct {
	healthpb.UnimplementedHealthServer
	observations  chan transportObservation
	continueWatch <-chan struct{}
}

func (s *transportService) observe(ctx context.Context) error {
	id, ok := IdentityFromContext(ctx)
	if !ok {
		return status.Error(codes.Internal, "missing admitted identity")
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Internal, "missing peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return status.Error(codes.Internal, "missing TLS certificate")
	}
	select {
	case s.observations <- transportObservation{
		id: id.String(), serial: info.State.PeerCertificates[0].SerialNumber.String(),
		verifiedChains: len(info.State.VerifiedChains), resumed: info.State.DidResume,
	}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *transportService) Check(ctx context.Context, _ *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	if err := s.observe(ctx); err != nil {
		return nil, err
	}
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (s *transportService) Watch(_ *healthpb.HealthCheckRequest, stream grpc.ServerStreamingServer[healthpb.HealthCheckResponse]) error {
	if err := s.observe(stream.Context()); err != nil {
		return err
	}
	response := &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}
	if err := stream.Send(response); err != nil {
		return err
	}
	if s.continueWatch == nil {
		return nil
	}
	for {
		select {
		case _, ok := <-s.continueWatch:
			if !ok {
				return nil
			}
			if err := stream.Send(response); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func newTransportServer(t *testing.T, a *Authorizer, source *testSVIDSource, resume <-chan struct{}) (*bufconn.Listener, *transportService) {
	t.Helper()
	options, err := a.ServerOptions(source)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(options...)
	service := &transportService{observations: make(chan transportObservation, 16), continueWatch: resume}
	healthpb.RegisterHealthServer(server, service)
	listener := bufconn.Listen(1024 * 1024)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("Serve: %v", err)
		}
	})
	return listener, service
}

func transportClientConfig(source *testSVIDSource, bundle x509bundle.Source) *tls.Config {
	config := tlsconfig.MTLSClientConfig(source, bundle, tlsconfig.AuthorizeID(spiffeid.RequireFromString(testServerID)))
	config.MinVersion = tls.VersionTLS13
	return config
}

func newTransportClient(t *testing.T, listener *bufconn.Listener, creds credentials.TransportCredentials) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///grpcauth.test",
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func transportContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func observeTransport(t *testing.T, service *transportService, id string) transportObservation {
	t.Helper()
	select {
	case observation := <-service.observations:
		if observation.id != id || observation.resumed || observation.verifiedChains != 0 {
			t.Fatalf("unexpected SDK TLS observation: %+v", observation)
		}
		return observation
	case <-transportContext(t).Done():
		t.Fatal("handler did not observe the admitted TLS identity")
		return transportObservation{}
	}
}

func TestTransportGuardsUnaryAndStream(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newTestCA(t, now)
	r := &testRecorder{}
	a := newTestAuthorizer(t, testBundle(ca.cert), r, map[string][]string{
		healthpb.Health_Check_FullMethodName: {testClientID},
		healthpb.Health_Watch_FullMethodName: {testClientID},
	}, newTestClock(now))
	listener, service := newTransportServer(t, a, &testSVIDSource{svid: ca.issue(t, testServerID, nil)}, nil)
	conn := newTransportClient(t, listener, credentials.NewTLS(transportClientConfig(&testSVIDSource{svid: ca.issue(t, testClientID, nil)}, testBundle(ca.cert))))
	client, ctx := healthpb.NewHealthClient(conn), transportContext(t)
	if response, err := client.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil || response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("Check: %v, %v", response, err)
	}
	observeTransport(t, service, testClientID)
	stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response, err := stream.Recv(); err != nil || response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("Watch: %v, %v", response, err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("stream result = %v, want EOF", err)
	}
	observeTransport(t, service, testClientID)
	if len(r.snapshot()) != 0 {
		t.Fatal("permitted RPCs produced denial events")
	}
	if _, err := client.List(ctx, &healthpb.HealthListRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unlisted registered method = %v", err)
	}
	checkDenial(t, r.snapshot(), healthpb.Health_List_FullMethodName, codes.PermissionDenied, testClientID)
	if err := conn.Invoke(ctx, "/unregistered.Service/Method", &healthpb.HealthCheckRequest{}, &healthpb.HealthCheckResponse{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("unregistered dispatch = %v", err)
	}
	if len(r.snapshot()) != 1 {
		t.Fatal("unregistered method incorrectly claimed interceptor audit coverage")
	}

	otherConn := newTransportClient(t, listener, credentials.NewTLS(transportClientConfig(&testSVIDSource{svid: ca.issue(t, testOtherID, nil)}, testBundle(ca.cert))))
	other := healthpb.NewHealthClient(otherConn)
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-spiffe-id", testClientID, "authorization", "Bearer synthetic-secret"))
	if _, err := other.Check(ctx, &healthpb.HealthCheckRequest{Service: "synthetic-payload-secret"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ungranted unary = %v", err)
	}
	checkDenial(t, r.snapshot()[1:], healthpb.Health_Check_FullMethodName, codes.PermissionDenied, testOtherID)
	deniedStream, err := other.Watch(ctx, &healthpb.HealthCheckRequest{})
	if err == nil {
		_, err = deniedStream.Recv()
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ungranted stream = %v", err)
	}
	checkDenial(t, r.snapshot()[2:], healthpb.Health_Watch_FullMethodName, codes.PermissionDenied, testOtherID)
	if len(service.observations) != 0 {
		t.Fatal("denied method reached business handler")
	}
}

func TestTransportRejectsInvalidCredentials(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca, otherCA := newTestCA(t, now), newTestCA(t, now)
	for _, name := range []string{"plaintext", "no client certificate", "untrusted root", "wrong trust domain", "expired", "no URI", "wrong server identity", "TLS 1.2", "source unavailable", "invalid EKU"} {
		t.Run(name, func(t *testing.T) {
			r := &testRecorder{}
			a := newTestAuthorizer(t, testBundle(ca.cert), r, map[string][]string{healthpb.Health_Check_FullMethodName: {testClientID}}, newTestClock(now))
			serverSource := &testSVIDSource{svid: ca.issue(t, testServerID, nil)}
			clientSource := &testSVIDSource{svid: ca.issue(t, testClientID, nil)}
			config := transportClientConfig(clientSource, testBundle(ca.cert))
			switch name {
			case "no client certificate":
				config = tlsconfig.TLSClientConfig(testBundle(ca.cert), tlsconfig.AuthorizeID(spiffeid.RequireFromString(testServerID)))
				config.MinVersion = tls.VersionTLS13
			case "untrusted root":
				clientSource.set(otherCA.issue(t, testClientID, nil))
			case "wrong trust domain":
				clientSource.set(ca.issue(t, "spiffe://other.ir/workload", nil))
			case "expired":
				clientSource.set(ca.issue(t, testClientID, func(c *x509.Certificate) { c.NotAfter = now.Add(-time.Minute) }))
			case "no URI":
				clientSource.set(ca.issue(t, testClientID, func(c *x509.Certificate) { c.URIs = nil }))
			case "wrong server identity":
				serverSource.set(ca.issue(t, testOtherID, nil))
			case "TLS 1.2":
				config.MinVersion, config.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
			case "source unavailable":
				serverSource.err = errors.New("SVID temporarily unavailable")
			case "invalid EKU":
				clientSource.set(ca.issue(t, testClientID, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }))
			}
			creds := credentials.NewTLS(config)
			if name == "plaintext" {
				creds = insecure.NewCredentials()
			}
			listener, service := newTransportServer(t, a, serverSource, nil)
			conn := newTransportClient(t, listener, creds)
			_, err := healthpb.NewHealthClient(conn).Check(transportContext(t), &healthpb.HealthCheckRequest{})
			if err == nil || len(service.observations) != 0 {
				t.Fatalf("invalid credentials reached handler: err=%v", err)
			}
			if name == "invalid EKU" {
				if status.Code(err) != codes.Unauthenticated {
					t.Fatalf("SDK-verified certificate with unsuitable EKU = %v", err)
				}
				checkDenial(t, r.snapshot(), healthpb.Health_Check_FullMethodName, codes.Unauthenticated, "")
			} else if len(r.snapshot()) != 0 {
				t.Fatal("handshake rejection incorrectly claimed interceptor audit coverage")
			}
		})
	}
}

func TestTransportRevalidatesAdmissionsButNotOpenStreams(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca, otherCA := newTestCA(t, now), newTestCA(t, now)
	clock, r := newTestClock(now), &testRecorder{}
	bundles := &testBundleSource{bundle: testBundle(ca.cert)}
	a := newTestAuthorizer(t, bundles, r, map[string][]string{
		healthpb.Health_Check_FullMethodName: {testClientID},
		healthpb.Health_Watch_FullMethodName: {testClientID},
	}, clock)
	resume := make(chan struct{}, 1)
	serverSource := &testSVIDSource{svid: ca.issue(t, testServerID, nil)}
	listener, service := newTransportServer(t, a, serverSource, resume)
	clientSource := &testSVIDSource{svid: ca.issue(t, testClientID, nil)}
	config := transportClientConfig(clientSource, testBundle(ca.cert))
	conn := newTransportClient(t, listener, credentials.NewTLS(config))
	client, ctx := healthpb.NewHealthClient(conn), transportContext(t)
	if _, err := client.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	first := observeTransport(t, service, testClientID)
	watch, err := client.Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := watch.Recv(); err != nil {
		t.Fatal(err)
	}
	observeTransport(t, service, testClientID)

	for _, tc := range []struct {
		name   string
		change func()
		code   codes.Code
	}{
		{"removed trust", func() { bundles.set(testBundle(otherCA.cert), nil) }, codes.Unauthenticated},
		{"expired identity", func() {
			bundles.set(testBundle(ca.cert), nil)
			clock.set(now.Add(2 * time.Hour))
		}, codes.Unauthenticated},
		{"unavailable source", func() {
			clock.set(now)
			bundles.set(nil, errors.New("trust source temporarily unavailable"))
		}, codes.Unavailable},
	} {
		tc.change()
		if _, err := client.Check(ctx, &healthpb.HealthCheckRequest{}); status.Code(err) != tc.code {
			t.Fatalf("%s, unary on established connection = %v", tc.name, err)
		}
		newWatch, err := client.Watch(ctx, &healthpb.HealthCheckRequest{})
		if err == nil {
			_, err = newWatch.Recv()
		}
		if status.Code(err) != tc.code {
			t.Fatalf("%s, new stream on established connection = %v", tc.name, err)
		}
		// Keep the changed trust/expiry state in effect while the admitted
		// stream sends another message. New streams above must still fail.
		resume <- struct{}{}
		if response, err := watch.Recv(); err != nil || response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			t.Fatalf("%s revoked an admitted stream: %v, %v", tc.name, response, err)
		}
	}
	close(resume)
	if _, err := watch.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("admitted stream result = %v", err)
	}
	if len(service.observations) != 0 {
		t.Fatal("rejected admissions reached a business handler")
	}
	if events := r.snapshot(); len(events) != 6 {
		t.Fatalf("denial count = %d, want 6", len(events))
	} else {
		for _, event := range events {
			if event.ActorSPIFFEID != "" || event.Security != nil {
				t.Fatal("unverified peer retained audit attribution")
			}
		}
	}

	// Updating both sources permits a new handshake with rotated roots/SVIDs,
	// without changing the immutable identity-to-method policy.
	bundles.set(testBundle(otherCA.cert), nil)
	serverSource.set(otherCA.issue(t, testServerID, nil))
	clientSource.set(otherCA.issue(t, testClientID, nil))
	// Trust only the new CA, proving that the server also refreshed its SVID.
	renewedConfig := transportClientConfig(clientSource, testBundle(otherCA.cert))
	renewed := healthpb.NewHealthClient(newTransportClient(t, listener, credentials.NewTLS(renewedConfig)))
	if _, err := renewed.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("rotated SVID and root = %v", err)
	}
	if observation := observeTransport(t, service, testClientID); observation.serial == first.serial {
		t.Fatal("new connection did not present the renewed certificate")
	}
	if len(r.snapshot()) != 6 {
		t.Fatal("successful rotation emitted an access event")
	}
}

func TestTransportDoesNotResumeAnOldIdentity(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca, r := newTestCA(t, now), &testRecorder{}
	a := newTestAuthorizer(t, testBundle(ca.cert), r, map[string][]string{healthpb.Health_Check_FullMethodName: {testClientID}}, newTestClock(now))
	listener, service := newTransportServer(t, a, &testSVIDSource{svid: ca.issue(t, testServerID, nil)}, nil)
	source := &testSVIDSource{svid: ca.issue(t, testClientID, nil)}
	config := transportClientConfig(source, testBundle(ca.cert))
	config.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	ctx := transportContext(t)
	first := newTransportClient(t, listener, credentials.NewTLS(config))
	if _, err := healthpb.NewHealthClient(first).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	observeTransport(t, service, testClientID)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	source.set(ca.issue(t, testOtherID, nil))
	second := newTransportClient(t, listener, credentials.NewTLS(config))
	if _, err := healthpb.NewHealthClient(second).Check(ctx, &healthpb.HealthCheckRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("new connection retained old identity authority: %v", err)
	}
	checkDenial(t, r.snapshot(), healthpb.Health_Check_FullMethodName, codes.PermissionDenied, testOtherID)
	source.set(ca.issue(t, testClientID, nil))
	third := newTransportClient(t, listener, credentials.NewTLS(config))
	if _, err := healthpb.NewHealthClient(third).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	observeTransport(t, service, testClientID)
}
