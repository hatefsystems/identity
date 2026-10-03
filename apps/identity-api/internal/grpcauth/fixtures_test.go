package grpcauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

const (
	testDomain      = "hatef.ir"
	testClientID    = "spiffe://hatef.ir/ns/identity/sa/search-core"
	testOtherID     = "spiffe://hatef.ir/ns/identity/sa/other-service"
	testServerID    = "spiffe://hatef.ir/ns/identity/sa/idp-core"
	testMethod      = "/hatef.identity.v1.IdentityService/ValidateToken"
	testOtherMethod = "/hatef.identity.v1.IdentityService/CheckPermission"
)

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	now  time.Time
}

func newTestCA(t *testing.T, now time.Time) *testCA {
	t.Helper()
	key := testKey(t)
	template := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: "Ephemeral test CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return &testCA{cert: testSign(t, template, template, key, key), key: key, now: now}
}

func (ca *testCA) issue(t *testing.T, rawID string, change func(*x509.Certificate)) *x509svid.SVID {
	t.Helper()
	id, err := spiffeid.FromString(rawID)
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	template := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: "Not an authorization identity"},
		NotBefore:             ca.now.Add(-time.Hour),
		NotAfter:              ca.now.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:                  []*url.URL{id.URL()},
	}
	if change != nil {
		change(template)
	}
	return &x509svid.SVID{
		ID:           id,
		Certificates: []*x509.Certificate{testSign(t, template, ca.cert, key, ca.key)},
		PrivateKey:   key,
	}
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

func testSign(t *testing.T, template, parent *x509.Certificate, key, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func testURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func testBundle(certs ...*x509.Certificate) *x509bundle.Bundle {
	return x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString(testDomain), certs)
}

type testBundleSource struct {
	mu     sync.RWMutex
	bundle *x509bundle.Bundle
	err    error
	calls  atomic.Int64
}

func (s *testBundleSource) GetX509BundleForTrustDomain(_ spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.calls.Add(1)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundle, s.err
}

func (s *testBundleSource) set(bundle *x509bundle.Bundle, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle, s.err = bundle, err
}

type testBundleFunc func(spiffeid.TrustDomain) (*x509bundle.Bundle, error)

func (f testBundleFunc) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return f(td)
}

type testSVIDSource struct {
	mu   sync.RWMutex
	svid *x509svid.SVID
	err  error
}

func (s *testSVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.svid, s.err
}

func (s *testSVIDSource) set(svid *x509svid.SVID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.svid = svid
}

type testClock struct{ value atomic.Int64 }

func newTestClock(now time.Time) *testClock {
	c := &testClock{}
	c.set(now)
	return c
}

func (c *testClock) now() time.Time    { return time.Unix(0, c.value.Load()).UTC() }
func (c *testClock) set(now time.Time) { c.value.Store(now.UnixNano()) }

type testRecorder struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (r *testRecorder) Record(_ context.Context, event audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	payload := make(map[string]any, len(event.Payload))
	for key, value := range event.Payload {
		payload[key] = value
	}
	event.Payload = payload
	r.events = append(r.events, event)
	return r.err
}

func (r *testRecorder) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

func newTestAuthorizer(t *testing.T, bundles x509bundle.Source, recorder audit.Recorder, grants map[string][]string, clock *testClock) *Authorizer {
	t.Helper()
	a, err := New(Config{
		TrustDomain: testDomain, Bundles: bundles, Recorder: recorder, Grants: grants,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if clock != nil {
		// Install once, before any interceptor or transport can use the authorizer.
		a.now = clock.now
	}
	return a
}

func testTLSInfo(certs []*x509.Certificate) credentials.TLSInfo {
	return credentials.TLSInfo{
		State: tls.ConnectionState{
			HandshakeComplete: true,
			Version:           tls.VersionTLS13,
			CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
			PeerCertificates:  certs,
		},
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
	}
}

func testPeerContext(certs []*x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: testTLSInfo(certs)})
}
