package ledgerproof

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
)

// ErrInvalidManifest reports inconsistent erasure coordinates or counts.
var ErrInvalidManifest = errors.New("ledgerproof: invalid erasure span manifest")

// SpanManifest binds the exact sorted, disjoint, maximally coalesced inclusive
// erasure coordinates. It changes receipt content, not audit canonical format.
func SpanManifest(spans [][2]int64, deleted, highwater int64) (string, error) {
	if deleted < 0 || highwater < 0 {
		return "", ErrInvalidManifest
	}
	h := sha256.New()
	_, _ = h.Write([]byte("identity/security-ledger-erasure-spans/v1\x00"))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(len(spans)))
	_, _ = h.Write(buf[:])
	var count, previous int64
	for i, span := range spans {
		first, last := span[0], span[1]
		if first <= 0 || last <= 0 || last < first || last > highwater ||
			(i > 0 && (first <= previous || first-previous == 1)) {
			return "", ErrInvalidManifest
		}
		size := last - first + 1
		if count > math.MaxInt64-size {
			return "", ErrInvalidManifest
		}
		count += size
		binary.BigEndian.PutUint64(buf[:], uint64(first))
		_, _ = h.Write(buf[:])
		binary.BigEndian.PutUint64(buf[:], uint64(last))
		_, _ = h.Write(buf[:])
		previous = last
	}
	if count != deleted {
		return "", ErrInvalidManifest
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
