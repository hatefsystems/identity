package grpcauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

func TestNewValidation(t *testing.T) {
	t.Parallel()
	valid := func() Config {
		return Config{TrustDomain: testDomain, Bundles: testBundle(), Recorder: &testRecorder{}, Grants: map[string][]string{testMethod: {testClientID}}}
	}
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{"missing bundle source", func(c *Config) { c.Bundles = nil }},
		{"missing recorder", func(c *Config) { c.Recorder = nil }},
	}
	for _, td := range []string{"", "HATEF.IR", " hatef.ir", "hatef.ir ", "spiffe://hatef.ir", "spiffe://hatef.ir/workload", "hatef.ir:443", "hatef.ir/path", "*.hatef.ir"} {
		tests = append(tests, struct {
			name   string
			change func(*Config)
		}{"domain " + td, func(c *Config) { c.TrustDomain = td }})
	}
	for _, method := range []string{"", "hatef.identity.v1.IdentityService/ValidateToken", "/Service", "/Service/", "/Service/*", "/*/Method", "/Service/Method/Extra", "/Service/Method?secret", "/Service/Method\n", "/bad-service/Method", "/Service/1Method", "/bad..Service/Method", "/Service/.Method", "/" + strings.Repeat("s", 510) + "/M"} {
		tests = append(tests, struct {
			name   string
			change func(*Config)
		}{"method " + method, func(c *Config) { c.Grants = map[string][]string{method: {testClientID}} }})
	}
	for _, id := range []string{"", "search-core", "spiffe://hatef.ir", "spiffe://hatef.ir/", "spiffe://other.ir/ns/identity/sa/search-core", "spiffe://hatef.ir/ns/identity/sa/*", "spiffe://hatef.ir:443/workload", "spiffe://user@hatef.ir/workload", "spiffe://hatef.ir/workload?secret", "spiffe://hatef.ir/workload#secret", "spiffe://hatef.ir/ns/%2f/sa/search-core", "spiffe://hatef.ir/ns/../search-core", "spiffe://hatef.ir//search-core", "spiffe://hatef.ir/workload/", "spiffe://hatef.ir/" + strings.Repeat("a", 2049-len("spiffe://hatef.ir/"))} {
		tests = append(tests, struct {
			name   string
			change func(*Config)
		}{"identity " + id, func(c *Config) { c.Grants[testMethod] = []string{id} }})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.change(&cfg)
			if a, err := New(cfg); err == nil || a != nil {
				t.Fatalf("New(invalid config) = %v, %v; want nil authorizer and error", a, err)
			}
		})
	}
	for name, grants := range map[string]map[string][]string{
		"nil deny all":        nil,
		"empty deny all":      {},
		"empty method grant":  {testMethod: {}},
		"duplicate exact IDs": {testMethod: {testClientID, testClientID}},
		"boundary lengths":    {"/" + strings.Repeat("s", 509) + "/M": {"spiffe://hatef.ir/" + strings.Repeat("a", 2048-len("spiffe://hatef.ir/"))}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid()
			cfg.Grants = grants
			a, err := New(cfg)
			if err != nil || a == nil || a.now == nil {
				t.Fatalf("New(valid config) = %v, %v", a, err)
			}
		})
	}
}

func TestExactMethodPolicy(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newTestCA(t, now)
	for _, tc := range []struct {
		name, id, method string
		grants           map[string][]string
		want             codes.Code
	}{
		{"explicit grant", testClientID, testMethod, map[string][]string{testMethod: {testClientID}}, codes.OK},
		{"another method", testClientID, testOtherMethod, map[string][]string{testMethod: {testClientID}}, codes.PermissionDenied},
		{"method suffix", testClientID, testMethod + "Extra", map[string][]string{testMethod: {testClientID}}, codes.PermissionDenied},
		{"method case", testClientID, "/hatef.identity.v1.IdentityService/validatetoken", map[string][]string{testMethod: {testClientID}}, codes.PermissionDenied},
		{"different service", testOtherID, testMethod, map[string][]string{testMethod: {testClientID}}, codes.PermissionDenied},
		{"different namespace", "spiffe://hatef.ir/ns/search/sa/search-core", testMethod, map[string][]string{testMethod: {testClientID}}, codes.PermissionDenied},
		{"ID prefix", testClientID + "-extra", testMethod, map[string][]string{testMethod: {testClientID}}, codes.PermissionDenied},
		{"no health bypass", testClientID, "/grpc.health.v1.Health/Check", map[string][]string{testMethod: {testClientID}}, codes.PermissionDenied},
		{"no reflection bypass", testClientID, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", map[string][]string{testMethod: {testClientID}}, codes.PermissionDenied},
		{"nil policy", testClientID, testMethod, nil, codes.PermissionDenied},
		{"empty policy", testClientID, testMethod, map[string][]string{}, codes.PermissionDenied},
		{"empty grant", testClientID, testMethod, map[string][]string{testMethod: {}}, codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certs := ca.issue(t, tc.id, nil).Certificates
			for _, stream := range []bool{false, true} {
				r := &testRecorder{}
				a := newTestAuthorizer(t, testBundle(ca.cert), r, tc.grants, newTestClock(now))
				_ = checkAdmission(testPeerContext(certs), t, a, tc.method, stream, tc.want, tc.id)
				if tc.want == codes.OK {
					if len(r.snapshot()) != 0 {
						t.Fatal("successful admission emitted a denial")
					}
				} else {
					checkDenial(t, r.snapshot(), tc.method, tc.want, tc.id)
				}
			}
		})
	}
}

type claimedTLS struct{}

func (claimedTLS) AuthType() string { return "tls" }

func TestAuthenticationMatrix(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca, otherCA := newTestCA(t, now), newTestCA(t, now)
	good := ca.issue(t, testClientID, nil)
	goodContext := testPeerContext(good.Certificates)
	type authCase struct {
		name   string
		ctx    context.Context
		bundle *x509bundle.Bundle
		err    error
		want   codes.Code
		actor  string
	}
	var cases []authCase
	add := func(name string, certs []*x509.Certificate, want codes.Code) {
		actor := ""
		if want == codes.OK {
			actor = testClientID
		}
		cases = append(cases, authCase{name: name, ctx: testPeerContext(certs), bundle: testBundle(ca.cert), want: want, actor: actor})
	}
	add("valid with empty SDK verified chains", good.Certificates, codes.OK)
	for _, tc := range []struct {
		name string
		info credentials.AuthInfo
	}{
		{"missing auth info", nil},
		{"string claiming TLS", claimedTLS{}},
		{"unfinished handshake", func() credentials.TLSInfo {
			i := testTLSInfo(good.Certificates)
			i.State.HandshakeComplete = false
			return i
		}()},
		{"TLS 1.2", func() credentials.TLSInfo {
			i := testTLSInfo(good.Certificates)
			i.State.Version = tls.VersionTLS12
			return i
		}()},
		{"missing TLS version", func() credentials.TLSInfo { i := testTLSInfo(good.Certificates); i.State.Version = 0; return i }()},
		{"convenience ID without certificate", func() credentials.TLSInfo { i := testTLSInfo(nil); i.SPIFFEID = testURL(t, testClientID); return i }()},
	} {
		cases = append(cases, authCase{name: tc.name, ctx: peer.NewContext(context.Background(), &peer.Peer{AuthInfo: tc.info}), bundle: testBundle(ca.cert), want: codes.Unauthenticated})
	}
	cases = append(cases,
		authCase{name: "no peer", ctx: context.Background(), bundle: testBundle(ca.cert), want: codes.Unauthenticated},
		authCase{name: "nil peer", ctx: peer.NewContext(context.Background(), nil), bundle: testBundle(ca.cert), want: codes.Unauthenticated},
		authCase{name: "metadata is not TLS", ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-spiffe-id", testClientID, "authorization", "Bearer fake-secret")), bundle: testBundle(ca.cert), want: codes.Unauthenticated},
	)
	add("one-way TLS", nil, codes.Unauthenticated)
	add("nil leaf", []*x509.Certificate{nil}, codes.Unauthenticated)
	add("nil intermediate", []*x509.Certificate{good.Certificates[0], nil}, codes.Unauthenticated)
	nilURI := *good.Certificates[0]
	nilURI.URIs = []*url.URL{nil}
	add("nil URI", []*x509.Certificate{&nilURI}, codes.Unauthenticated)
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
		want   codes.Code
	}{
		{"absent URI ignores CN and DNS", func(c *x509.Certificate) {
			c.URIs = nil
			c.Subject.CommonName = testClientID
			c.DNSNames = []string{"search-core.hatef.ir"}
		}, codes.Unauthenticated},
		{"two SPIFFE URIs", func(c *x509.Certificate) { c.URIs = append(c.URIs, testURL(t, testOtherID)) }, codes.Unauthenticated},
		{"mixed URI types", func(c *x509.Certificate) { c.URIs = append(c.URIs, testURL(t, "https://hatef.ir/secret")) }, codes.Unauthenticated},
		{"non URI SANs allowed", func(c *x509.Certificate) {
			c.DNSNames = []string{"other.example"}
			c.EmailAddresses = []string{"test@example.org"}
		}, codes.OK},
		{"CA leaf", func(c *x509.Certificate) { c.IsCA = true }, codes.Unauthenticated},
		{"certificate signing usage", func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }, codes.Unauthenticated},
		{"CRL signing usage", func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCRLSign }, codes.Unauthenticated},
		{"no digital signature", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }, codes.Unauthenticated},
		{"no key usage", func(c *x509.Certificate) { c.KeyUsage = 0 }, codes.Unauthenticated},
		{"client auth only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, codes.Unauthenticated},
		{"server auth only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }, codes.Unauthenticated},
		{"any EKU is not both", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }, codes.Unauthenticated},
		{"unknown EKU only", func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		}, codes.Unauthenticated},
		{"explicit empty EKU", func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0}}}
		}, codes.Unauthenticated},
		{"absent EKU allowed", func(c *x509.Certificate) { c.ExtKeyUsage = nil }, codes.OK},
		{"expired", func(c *x509.Certificate) { c.NotAfter = now.Add(-time.Second) }, codes.Unauthenticated},
		{"not yet valid", func(c *x509.Certificate) { c.NotBefore = now.Add(time.Second) }, codes.Unauthenticated},
		{"unknown critical extension", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}, codes.Unauthenticated},
	} {
		add(tc.name, ca.issue(t, testClientID, tc.change).Certificates, tc.want)
	}
	for _, uri := range []string{"https://hatef.ir/workload", "spiffe://hatef.ir", "spiffe://hatef.ir/", "spiffe://other.ir/ns/identity/sa/search-core", "spiffe://hatef.ir:443/workload", "spiffe://user@hatef.ir/workload", "spiffe://hatef.ir/workload?secret", "spiffe://hatef.ir/workload#secret", "spiffe://hatef.ir/ns/%2F/sa/search-core", "spiffe://hatef.ir/ns/%2e%2e/search-core", "spiffe://hatef.ir/ns/../search-core", "spiffe://hatef.ir//search-core", "spiffe://hatef.ir/workload/", "spiffe://hatef.ir/" + strings.Repeat("a", 2049-len("spiffe://hatef.ir/"))} {
		add("URI "+uri, ca.issue(t, testClientID, func(c *x509.Certificate) { c.URIs = []*url.URL{testURL(t, uri)} }).Certificates, codes.Unauthenticated)
	}
	add("untrusted signing root", otherCA.issue(t, testClientID, nil).Certificates, codes.Unauthenticated)
	badDER := append([]byte(nil), good.Certificates[0].Raw...)
	badDER[len(badDER)-1] ^= 1
	badSignature, err := x509.ParseCertificate(badDER)
	if err != nil {
		t.Fatal(err)
	}
	add("invalid signature", []*x509.Certificate{badSignature}, codes.Unauthenticated)
	intermediate := ca.issue(t, testClientID, func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage = x509.KeyUsageCertSign; c.ExtKeyUsage = nil })
	intermediateCA := &testCA{cert: intermediate.Certificates[0], key: intermediate.PrivateKey, now: now}
	chained := intermediateCA.issue(t, testClientID, nil)
	add("valid intermediate", []*x509.Certificate{chained.Certificates[0], intermediateCA.cert}, codes.OK)
	add("missing intermediate", chained.Certificates, codes.Unauthenticated)
	for _, tc := range []struct {
		name    string
		certs   []*x509.Certificate
		claimed string
		want    codes.Code
		actor   string
	}{
		{"forged convenience identity", ca.issue(t, testOtherID, nil).Certificates, testClientID, codes.PermissionDenied, testOtherID},
		{"incorrect convenience field ignored", good.Certificates, testOtherID, codes.OK, testClientID},
		{"forged verified chains ignored", otherCA.issue(t, testClientID, nil).Certificates, testClientID, codes.Unauthenticated, ""},
	} {
		info := testTLSInfo(tc.certs)
		info.SPIFFEID = testURL(t, tc.claimed)
		info.State.VerifiedChains = [][]*x509.Certificate{good.Certificates}
		ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: info})
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-spiffe-id", testClientID))
		cases = append(cases, authCase{name: tc.name, ctx: ctx, bundle: testBundle(ca.cert), want: tc.want, actor: tc.actor})
	}
	for _, tc := range []struct {
		name   string
		bundle *x509bundle.Bundle
		err    error
	}{
		{"bundle source error", testBundle(ca.cert), errors.New("private source error")},
		{"missing bundle", nil, nil},
		{"empty bundle", testBundle(), nil},
		{"nil root", testBundle(nil), nil},
		{"wrong bundle domain", x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("other.ir"), []*x509.Certificate{ca.cert}), nil},
	} {
		cases = append(cases, authCase{name: tc.name, ctx: goodContext, bundle: tc.bundle, err: tc.err, want: codes.Unavailable})
	}
	publicMessages := map[codes.Code]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, stream := range []bool{false, true} {
				r := &testRecorder{}
				a := newTestAuthorizer(t, &testBundleSource{bundle: tc.bundle, err: tc.err}, r, map[string][]string{testMethod: {testClientID}}, newTestClock(now))
				err := checkAdmission(tc.ctx, t, a, testMethod, stream, tc.want, tc.actor)
				if tc.want == codes.OK {
					if len(r.snapshot()) != 0 {
						t.Fatal("success emitted denial")
					}
					continue
				}
				checkDenial(t, r.snapshot(), testMethod, tc.want, tc.actor)
				message := status.Convert(err).Message()
				if previous, ok := publicMessages[tc.want]; ok && message != previous {
					t.Errorf("public message %q differs from %q for the same status", message, previous)
				}
				publicMessages[tc.want] = message
				if message == "" || strings.Contains(message, "spiffe://") || strings.Contains(message, "private source error") {
					t.Errorf("unsafe public message %q", message)
				}
			}
		})
	}
}

func TestPolicyCopiesInputsAndConcurrentAdmissions(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newTestCA(t, now)
	ctx := testPeerContext(ca.issue(t, testClientID, nil).Certificates)
	ids := []string{testClientID}
	grants := map[string][]string{testMethod: ids}
	bundle := testBundle(ca.cert)
	source, recorder := &testBundleSource{bundle: bundle}, &testRecorder{}
	a := newTestAuthorizer(t, source, recorder, grants, newTestClock(now))
	ids[0] = testOtherID
	delete(grants, testMethod)
	grants[testOtherMethod] = []string{testClientID}
	_ = checkAdmission(ctx, t, a, testMethod, false, codes.OK, testClientID)
	_ = checkAdmission(ctx, t, a, testOtherMethod, false, codes.PermissionDenied, testClientID)
	const workers, iterations = 8, 20
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				_, err := a.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: testMethod}, func(ctx context.Context, _ any) (any, error) {
					if id, ok := IdentityFromContext(ctx); !ok || id.String() != testClientID {
						return nil, errors.New("lost authenticated identity")
					}
					return nil, nil
				})
				if err != nil {
					t.Errorf("concurrent admission: %v", err)
				}
				err = a.StreamServerInterceptor()(nil, &testServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: testOtherMethod}, func(any, grpc.ServerStream) error {
					t.Error("mutated policy granted a stream")
					return nil
				})
				if status.Code(err) != codes.PermissionDenied {
					t.Errorf("concurrent rejection: %v", err)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations*workers; i++ {
			ids[0] = testOtherID
			grants[testMethod] = []string{testOtherID}
			delete(grants, testOtherMethod)
			bundle.SetX509Authorities([]*x509.Certificate{ca.cert})
			source.set(bundle, nil)
		}
	}()
	close(start)
	wg.Wait()
	if got := source.calls.Load(); got != 2+2*workers*iterations {
		t.Errorf("bundle lookups = %d, want one per admission", got)
	}
	if got := len(recorder.snapshot()); got != 1+workers*iterations {
		t.Errorf("denials = %d", got)
	}
}

func TestBundleSourceIsReadOncePerAdmission(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newTestCA(t, now)
	ctx := testPeerContext(ca.issue(t, testClientID, nil).Certificates)
	for _, stream := range []bool{false, true} {
		var calls atomic.Int64
		source := testBundleFunc(func(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
			if td.String() != testDomain {
				t.Errorf("lookup domain = %q", td)
			}
			if calls.Add(1) == 1 {
				return testBundle(ca.cert), nil
			}
			return nil, errors.New("source changed after snapshot")
		})
		a := newTestAuthorizer(t, source, &testRecorder{}, map[string][]string{testMethod: {testClientID}}, newTestClock(now))
		_ = checkAdmission(ctx, t, a, testMethod, stream, codes.OK, testClientID)
		if calls.Load() != 1 {
			t.Fatalf("source called %d times for one admission", calls.Load())
		}
		_ = checkAdmission(ctx, t, a, testMethod, stream, codes.Unavailable, "")
	}
}

func TestDenialAuditRedactionAndRecorderFailure(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newTestCA(t, now)
	secret := "sensitive-token-proof-private-error"
	validCtx := testPeerContext(ca.issue(t, testClientID, nil).Certificates)
	invalidCtx := testPeerContext(ca.issue(t, testClientID, func(c *x509.Certificate) { c.URIs = []*url.URL{testURL(t, "spiffe://hatef.ir/workload?"+secret)} }).Certificates)
	for _, tc := range []struct {
		name, method string
		ctx          context.Context
		sourceErr    error
		want         codes.Code
		actor        string
	}{
		{"authenticated", testOtherMethod, validCtx, nil, codes.PermissionDenied, testClientID},
		{"unverified identity", testMethod, invalidCtx, nil, codes.Unauthenticated, ""},
		{"bundle failure", testMethod, validCtx, errors.New(secret), codes.Unavailable, ""},
		{"malformed method", "/Service/Method?" + secret, validCtx, nil, codes.PermissionDenied, testClientID},
		{"long method", "/Service/" + strings.Repeat("x", 513) + secret, validCtx, nil, codes.PermissionDenied, testClientID},
		{"control characters", "/Service/Method\n" + secret, validCtx, nil, codes.PermissionDenied, testClientID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, stream := range []bool{false, true} {
				for _, recorderErr := range []error{nil, errors.New(secret)} {
					r := &testRecorder{err: recorderErr}
					var logs bytes.Buffer
					a := newTestAuthorizer(t, &testBundleSource{bundle: testBundle(ca.cert), err: tc.sourceErr}, r, nil, newTestClock(now))
					a.logger = slog.New(slog.NewJSONHandler(&logs, nil))
					ctx := metadata.NewIncomingContext(tc.ctx, metadata.Pairs("authorization", "Bearer "+secret, "dpop", secret, "x-spiffe-id", secret, "user-agent", secret, "x-forwarded-for", secret))
					err := checkAdmission(ctx, t, a, tc.method, stream, tc.want, tc.actor)
					method := tc.method
					if tc.name == "malformed method" || tc.name == "long method" || tc.name == "control characters" {
						method = "unknown"
					}
					checkDenial(t, r.snapshot(), method, tc.want, tc.actor)
					encoded, marshalErr := json.Marshal(r.snapshot())
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					for name, output := range map[string]string{"events": string(encoded), "logs": logs.String(), "public error": err.Error()} {
						if strings.Contains(output, secret) {
							t.Errorf("%s leaked secret: %s", name, output)
						}
					}
					if recorderErr != nil && logs.Len() == 0 {
						t.Error("recorder failure emitted no operational warning")
					}
				}
			}
		})
	}
}

func TestLongVerifiedIdentityDoesNotOverflowAuditStorage(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newTestCA(t, now)
	for _, length := range []int{255, 256, 2048} {
		id := "spiffe://hatef.ir/" + strings.Repeat("a", length-len("spiffe://hatef.ir/"))
		ctx := testPeerContext(ca.issue(t, id, nil).Certificates)
		for _, stream := range []bool{false, true} {
			r := &testRecorder{err: errors.New("private recorder error: " + id)}
			var logs bytes.Buffer
			a := newTestAuthorizer(t, testBundle(ca.cert), r, map[string][]string{testMethod: {id}}, newTestClock(now))
			a.logger = slog.New(slog.NewJSONHandler(&logs, nil))
			_ = checkAdmission(ctx, t, a, testMethod, stream, codes.OK, id)
			if len(r.snapshot()) != 0 {
				t.Fatal("successful admission emitted an audit event")
			}
			_ = checkAdmission(ctx, t, a, testOtherMethod, stream, codes.PermissionDenied, id)
			events := r.snapshot()
			if length == 255 {
				checkDenial(t, events, testOtherMethod, codes.PermissionDenied, id)
			} else {
				if len(events) != 1 || events[0].ActorSPIFFEID != "" || len(events[0].Payload) != 4 || events[0].Payload["actor_spiffe_id_omitted"] != true {
					t.Fatalf("overlength actor was not safely omitted: %+v", events)
				}
				encoded, err := json.Marshal(events)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), id) {
					t.Fatal("overlength identity was copied into audit payload")
				}
			}
			if strings.Contains(logs.String(), id) {
				t.Fatal("recorder failure leaked the identity through its error")
			}
		}
	}
}

func checkAdmission(ctx context.Context, t *testing.T, a *Authorizer, method string, stream bool, want codes.Code, wantID string) error {
	t.Helper()
	calls := 0
	handler := func(ctx context.Context) {
		calls++
		id, ok := IdentityFromContext(ctx)
		if !ok || id.String() != wantID {
			t.Errorf("handler identity = %q, %v; want %q", id, ok, wantID)
		}
	}
	var err error
	if stream {
		err = a.StreamServerInterceptor()(nil, &testServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: method}, func(_ any, stream grpc.ServerStream) error { handler(stream.Context()); return nil })
	} else {
		var response any
		response, err = a.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, func(ctx context.Context, _ any) (any, error) { handler(ctx); return "response", nil })
		if want == codes.OK && response != "response" {
			t.Errorf("response = %v", response)
		}
		if want != codes.OK && response != nil {
			t.Errorf("rejected response = %v", response)
		}
	}
	if status.Code(err) != want {
		t.Fatalf("stream=%v status = %v, want %v: %v", stream, status.Code(err), want, err)
	}
	wantCalls := 0
	if want == codes.OK {
		wantCalls = 1
	}
	if calls != wantCalls {
		t.Fatalf("handler calls = %d, want %d", calls, wantCalls)
	}
	if id, ok := IdentityFromContext(ctx); ok || !id.IsZero() {
		t.Error("input context acquired an identity")
	}
	return err
}

func checkDenial(t *testing.T, events []audit.Event, method string, code codes.Code, actor string) {
	t.Helper()
	if len(events) != 1 {
		t.Fatalf("denial events = %d, want 1", len(events))
	}
	e := events[0]
	if e.EventType != audit.EventGRPCAccessDenied || e.ActionStatus != audit.StatusFailure {
		t.Errorf("event classification = %q/%q", e.EventType, e.ActionStatus)
	}
	if e.ActorSPIFFEID != actor {
		t.Errorf("actor = %q, want %q", e.ActorSPIFFEID, actor)
	}
	if e.ActorID != uuid.Nil || e.SubjectID != nil || e.Security != nil || e.ClientIP != "" || e.UserAgent != "" {
		t.Errorf("unexpected user, ledger, or request attribution: %+v", e)
	}
	if len(e.Payload) != 3 || e.Payload["method"] != method || e.Payload["status"] != code.String() {
		t.Errorf("payload = %#v", e.Payload)
	}
	reason, ok := e.Payload["reason"].(string)
	if !ok {
		t.Fatalf("reason is not a string: %T", e.Payload["reason"])
	}
	switch reason {
	case "missing_tls", "invalid_tls", "missing_certificate", "invalid_identity", "invalid_certificate_usage", "trust_unavailable", "invalid_certificate", "method_not_granted":
	default:
		t.Errorf("unbounded or unknown denial reason %q", reason)
	}
}
