package grpcauth

import (
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// admissionCache memoizes successful SVID path verifications.
//
// # Why this exists
//
// Admission is decided per RPC, because trust-bundle removal, SVID expiry and
// trust-source outage must all affect calls on connections that are already
// established. But the expensive part of that decision — building and verifying
// the certificate path — only depends on two things: the peer's leaf, and the set
// of trust authorities. Neither changes between two calls on the same connection
// under a stable bundle, so verifying again produces a result already known.
//
// Keying on both inputs is what keeps the shortcut sound rather than merely fast.
// A new leaf is a different key. A rotated, extended, or emptied trust bundle is
// a different key. So a cache hit is only possible when a full verification would
// provably reach the same conclusion, and every revocation path still forces a
// real verification:
//
//   - authority removed  -> trust-set digest changes -> miss -> verify -> denied
//   - bundle unavailable -> no digest to compute      -> never reaches the cache
//   - SVID expired       -> validity re-checked on every hit, below
//
// Only successes are cached. Caching a failure would mean a transient outage
// could pin a legitimate workload out, and failures are not on the hot path.
type admissionCache struct {
	mu      sync.RWMutex
	entries map[admissionKey]admissionEntry
	// limit bounds memory. The population is the number of distinct workload
	// leaves times live trust-set generations, which is small, but it is attacker
	// influenced: any trust-domain member can present a fresh short-lived SVID.
	limit int
}

// admissionKey identifies one (leaf, trust set) pair.
//
// Both halves are digests rather than the values themselves, so the key is fixed
// size and the cache cannot retain certificate material.
type admissionKey struct {
	leaf     [sha256.Size]byte
	trustSet [sha256.Size]byte
}

type admissionEntry struct {
	id spiffeid.ID
	// notBefore and notAfter are the verified leaf's validity window, re-checked
	// on every hit. Without this the cache would keep admitting an expired SVID
	// for as long as the bundle stayed unchanged.
	notBefore time.Time
	notAfter  time.Time
}

func newAdmissionCache(limit int) *admissionCache {
	if limit <= 0 {
		limit = defaultAdmissionCacheLimit
	}
	return &admissionCache{entries: make(map[admissionKey]admissionEntry, limit), limit: limit}
}

// defaultAdmissionCacheLimit is sized for a service mesh: a few hundred distinct
// workload leaves across a couple of live trust generations.
const defaultAdmissionCacheLimit = 1024

// lookup returns a previously verified identity for this exact (leaf, trust set)
// pair, if it is still inside its validity window at now.
func (c *admissionCache) lookup(key admissionKey, now time.Time) (spiffeid.ID, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return spiffeid.ID{}, false
	}
	if now.Before(entry.notBefore) || now.After(entry.notAfter) {
		// Expired or not yet valid. Drop it so the slot is not held by an entry
		// that can never be used again.
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return spiffeid.ID{}, false
	}
	return entry.id, true
}

// store records a successful verification.
func (c *admissionCache) store(key admissionKey, entry admissionEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.limit {
		// Clear rather than evict one entry. An LRU would need per-hit bookkeeping
		// on the read path, and the cost of a cleared cache is one extra real
		// verification per live connection — bounded, self-correcting, and far
		// cheaper than making every hit take a write lock.
		c.entries = make(map[admissionKey]admissionEntry, c.limit)
	}
	c.entries[key] = entry
}

// trustSetDigest summarizes a bundle's authorities.
//
// It covers the count and each authority's full DER in order, so adding,
// removing, replacing, or reordering an authority all produce a different digest.
// Hashing a handful of CA certificates is orders of magnitude cheaper than the
// public-key operations a path verification performs, which is what makes the
// cache worthwhile.
func trustSetDigest(roots []*x509.Certificate) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("hatef.grpcauth.trustset.v1\x00"))
	var length [8]byte
	putUint64(&length, uint64(len(roots)))
	_, _ = h.Write(length[:])
	for _, root := range roots {
		putUint64(&length, uint64(len(root.Raw)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(root.Raw)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func putUint64(dst *[8]byte, v uint64) {
	for i := 7; i >= 0; i-- {
		dst[i] = byte(v)
		v >>= 8
	}
}

// bundleRoots snapshots a bundle's authorities, returning false when the trust
// material is unusable. The snapshot is taken once so rotation cannot change the
// roots between computing the digest and verifying against them.
func bundleRoots(bundle *x509bundle.Bundle) ([]*x509.Certificate, bool) {
	if bundle == nil {
		return nil, false
	}
	roots := bundle.Clone().X509Authorities()
	if len(roots) == 0 {
		return nil, false
	}
	for _, root := range roots {
		if root == nil {
			return nil, false
		}
	}
	return roots, true
}
