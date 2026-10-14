package grpcauth

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
)

// Coverage for the two mechanisms added alongside the per-RPC cost reduction:
// the successful-verification cache, and hot-reloadable method grants.
//
// The cache is the sensitive one. Admission is still decided per RPC — trust
// removal, SVID expiry and trust-source outage must all affect calls on
// connections that are already established — so the cache is only sound if a hit
// is impossible whenever a real verification could reach a different conclusion.
// These tests pin each of those paths.

func cacheTestAuthorizer(t *testing.T, ca *testCA, now time.Time) (*Authorizer, *testBundleSource) {
	t.Helper()
	source := &testBundleSource{bundle: testBundle(ca.cert)}
	a, err := New(Config{
		TrustDomain: testDomain, Bundles: source, Recorder: &testRecorder{},
		Grants: map[string][]string{testMethod: {testClientID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return now }
	return a, source
}

// TestAdmissionCacheAvoidsRepeatedPathVerification is the performance claim,
// asserted by observable behaviour rather than by timing: the second call for the
// same leaf and trust set must not repeat the path build.
func TestAdmissionCacheAvoidsRepeatedPathVerification(t *testing.T) {
	t.Parallel()
	now := time.Now()
	ca := newTestCA(t, now)
	a, source := cacheTestAuthorizer(t, ca, now)

	svid := ca.issue(t, testClientID, nil)
	state := testTLSInfo(svid.Certificates).State

	for i := range 5 {
		id, code, reason := a.verifyPeer(state)
		if code != codes.OK {
			t.Fatalf("call %d: code = %v (%s)", i, code, reason)
		}
		if id.String() != testClientID {
			t.Fatalf("call %d: identity = %q", i, id.String())
		}
	}

	// The trust source is still consulted on every call: an unavailable source has
	// to fail closed immediately rather than coast on a cached answer.
	if calls := source.calls.Load(); calls < 5 {
		t.Errorf("bundle source consulted %d times across 5 calls; it must be read every time", calls)
	}

	// Exactly one entry, for one (leaf, trust set) pair.
	a.admissions.mu.RLock()
	entries := len(a.admissions.entries)
	a.admissions.mu.RUnlock()
	if entries != 1 {
		t.Errorf("cache holds %d entries after 5 calls for one peer, want 1", entries)
	}
}

// TestAdmissionCacheKeyedOnTrustSet is the revocation property. Replacing the
// trust bundle must deny immediately, on the same connection, with no reconnect.
func TestAdmissionCacheKeyedOnTrustSet(t *testing.T) {
	t.Parallel()
	now := time.Now()
	ca := newTestCA(t, now)
	other := newTestCA(t, now)
	a, source := cacheTestAuthorizer(t, ca, now)

	svid := ca.issue(t, testClientID, nil)
	state := testTLSInfo(svid.Certificates).State
	if _, code, reason := a.verifyPeer(state); code != codes.OK {
		t.Fatalf("initial admission: %v (%s)", code, reason)
	}

	// Authority removed and replaced: a cached success must not survive it.
	source.set(testBundle(other.cert), nil)
	if _, code, _ := a.verifyPeer(state); code != codes.Unauthenticated {
		t.Fatalf("code after trust removal = %v, want Unauthenticated; the cache outlived its trust set", code)
	}

	// Adding an authority alongside the original is also a different trust set,
	// and must be re-verified rather than served from the earlier entry.
	source.set(testBundle(ca.cert, other.cert), nil)
	if _, code, reason := a.verifyPeer(state); code != codes.OK {
		t.Fatalf("code after trust extension = %v (%s), want OK", code, reason)
	}

	// Restoring the original authority is a third distinct trust set.
	source.set(testBundle(ca.cert), nil)
	if _, code, reason := a.verifyPeer(state); code != codes.OK {
		t.Fatalf("code after trust restoration = %v (%s), want OK", code, reason)
	}
}

// TestAdmissionCacheRejectsExpiredOnHit covers the other time-dependent input: a
// cached entry must stop being usable when its leaf's validity window closes,
// even though neither the leaf nor the trust set changed.
func TestAdmissionCacheRejectsExpiredOnHit(t *testing.T) {
	t.Parallel()
	now := time.Now()
	ca := newTestCA(t, now)
	a, _ := cacheTestAuthorizer(t, ca, now)

	svid := ca.issue(t, testClientID, func(c *x509.Certificate) { c.NotAfter = now.Add(time.Minute) })
	state := testTLSInfo(svid.Certificates).State
	if _, code, reason := a.verifyPeer(state); code != codes.OK {
		t.Fatalf("initial admission: %v (%s)", code, reason)
	}

	// Move past the leaf's expiry. The entry is present and the trust set is
	// unchanged, so only the validity re-check can catch this.
	a.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, code, _ := a.verifyPeer(state); code != codes.Unauthenticated {
		t.Fatalf("code after expiry = %v, want Unauthenticated; the cache served an expired SVID", code)
	}
	// The dead entry must not be retained.
	a.admissions.mu.RLock()
	entries := len(a.admissions.entries)
	a.admissions.mu.RUnlock()
	if entries != 0 {
		t.Errorf("cache retains %d entries after serving an expired leaf, want 0", entries)
	}
}

// TestAdmissionCacheNeverCachesFailures keeps a transient outage from pinning a
// legitimate workload out.
func TestAdmissionCacheNeverCachesFailures(t *testing.T) {
	t.Parallel()
	now := time.Now()
	ca := newTestCA(t, now)
	other := newTestCA(t, now)
	a, source := cacheTestAuthorizer(t, ca, now)

	// Fails: issued by an authority outside the bundle.
	foreign := other.issue(t, testClientID, nil)
	foreignState := testTLSInfo(foreign.Certificates).State
	if _, code, _ := a.verifyPeer(foreignState); code != codes.Unauthenticated {
		t.Fatal("a foreign-issued SVID was admitted")
	}
	a.admissions.mu.RLock()
	entries := len(a.admissions.entries)
	a.admissions.mu.RUnlock()
	if entries != 0 {
		t.Errorf("a failed verification was cached (%d entries)", entries)
	}

	// Trust-source outage must be Unavailable, not a cached verdict either way.
	source.set(nil, context.DeadlineExceeded)
	if _, code, _ := a.verifyPeer(testTLSInfo(ca.issue(t, testClientID, nil).Certificates).State); code != codes.Unavailable {
		t.Fatalf("code with an unavailable trust source = %v, want Unavailable", code)
	}
}

// TestAdmissionCacheIsBounded keeps an attacker-influenced population from
// growing without limit: any trust-domain member can present fresh SVIDs.
func TestAdmissionCacheIsBounded(t *testing.T) {
	t.Parallel()
	now := time.Now()
	ca := newTestCA(t, now)
	source := &testBundleSource{bundle: testBundle(ca.cert)}
	a, err := New(Config{
		TrustDomain: testDomain, Bundles: source, Recorder: &testRecorder{},
		Grants:             map[string][]string{testMethod: {testClientID}},
		AdmissionCacheSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return now }

	// Every SVID has a fresh serial, so each is a distinct leaf and a distinct key.
	for range 20 {
		svid := ca.issue(t, testClientID, nil)
		if _, code, reason := a.verifyPeer(testTLSInfo(svid.Certificates).State); code != codes.OK {
			t.Fatalf("admission: %v (%s)", code, reason)
		}
	}
	a.admissions.mu.RLock()
	entries := len(a.admissions.entries)
	a.admissions.mu.RUnlock()
	if entries > 4 {
		t.Errorf("cache holds %d entries with a limit of 4", entries)
	}
}

// TestTrustSetDigestDistinguishesAuthoritySets pins the key's discriminating
// power directly: if two different trust sets collapsed to one digest, a removed
// authority would be served from cache.
func TestTrustSetDigestDistinguishesAuthoritySets(t *testing.T) {
	t.Parallel()
	now := time.Now()
	first := newTestCA(t, now)
	second := newTestCA(t, now)

	a := trustSetDigest([]*x509.Certificate{first.cert})
	b := trustSetDigest([]*x509.Certificate{second.cert})
	ab := trustSetDigest([]*x509.Certificate{first.cert, second.cert})
	ba := trustSetDigest([]*x509.Certificate{second.cert, first.cert})
	empty := trustSetDigest(nil)

	for name, pair := range map[string][2][32]byte{
		"different authority": {a, b},
		"added authority":     {a, ab},
		"reordered":           {ab, ba},
		"empty vs populated":  {empty, a},
	} {
		if pair[0] == pair[1] {
			t.Errorf("%s produced the same trust-set digest", name)
		}
	}
	// Same set, same digest: otherwise every call would miss and the cache would
	// be pointless.
	if trustSetDigest([]*x509.Certificate{first.cert}) != a {
		t.Error("the same authority set produced two different digests")
	}
}

// TestSetGrantsAppliesWithoutRestart is the revocation path the review called
// for: a compromised workload's access must be removable in place.
func TestSetGrantsAppliesWithoutRestart(t *testing.T) {
	t.Parallel()
	now := time.Now()
	ca := newTestCA(t, now)
	a, _ := cacheTestAuthorizer(t, ca, now)

	svid := ca.issue(t, testClientID, nil)
	ctx := testPeerContext(svid.Certificates)

	if _, err := a.authorize(ctx, testMethod); err != nil {
		t.Fatalf("initial authorize: %v", err)
	}
	// Not granted yet.
	if _, err := a.authorize(ctx, testOtherMethod); err == nil {
		t.Fatal("an ungranted method was permitted")
	}

	// Grant the second method and revoke the first, in place.
	if err := a.SetGrants(map[string][]string{testOtherMethod: {testClientID}}); err != nil {
		t.Fatalf("SetGrants: %v", err)
	}
	if _, err := a.authorize(ctx, testOtherMethod); err != nil {
		t.Fatalf("authorize after grant reload: %v", err)
	}
	if _, err := a.authorize(ctx, testMethod); err == nil {
		t.Fatal("a revoked method was still permitted after reload")
	}
}

// TestSetGrantsRejectsInvalidPolicyAtomically keeps a malformed reload from
// leaving the service with a partially applied, and therefore unknown, policy.
func TestSetGrantsRejectsInvalidPolicyAtomically(t *testing.T) {
	t.Parallel()
	now := time.Now()
	ca := newTestCA(t, now)
	a, _ := cacheTestAuthorizer(t, ca, now)

	svid := ca.issue(t, testClientID, nil)
	ctx := testPeerContext(svid.Certificates)

	for name, policy := range map[string]map[string][]string{
		"invalid method":       {"not-a-method": {testClientID}},
		"foreign trust domain": {testOtherMethod: {"spiffe://other.test/ns/x/sa/y"}},
		"identity with no path": {testOtherMethod: {"spiffe://hatef.ir"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := a.SetGrants(policy); err == nil {
				t.Fatal("an invalid policy was accepted")
			}
			// The previous policy must still be in force, in full.
			if _, err := a.authorize(ctx, testMethod); err != nil {
				t.Fatalf("a rejected reload disturbed the live policy: %v", err)
			}
		})
	}
}
