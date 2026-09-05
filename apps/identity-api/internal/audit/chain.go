package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// This file owns the ledgers' tamper-evidence primitive:
//
//	chain_hash(N) = SHA-256( chain_hash(N-1) || serialize(record(N)) )
//
// It lives in package audit rather than in the signer because two independent
// components must agree on it byte-for-byte: the signing consumer that writes the
// chain (Task 5.2) and the verification endpoint that recomputes it from genesis
// (Task 5.3). A second implementation of serialize() would be a latent integrity
// alarm, so there is exactly one.
//
// # Why length-prefixed binary and not JSON
//
// A hash input must have exactly one encoding. JSON does not: key order, unicode
// escaping, whitespace, and integer/float rendering are all encoder-dependent, and
// a Go version or library upgrade that changes any of them would invalidate every
// previously stored chain_hash with no code change and no way to tell the
// difference from real tampering. Length-prefixing every field removes both the
// ambiguity and the concatenation attack: without it, fields ("ab","c") and
// ("a","bc") hash identically, so an attacker could shift a byte from one column
// into the next and preserve the digest.

// Domain separation prefixes. The two ledgers are independent chains that share a
// formula, so their serializations must not be interchangeable: without a prefix a
// crafted ledger record could be replayed as an audit record (or vice versa) with a
// matching digest. The trailing NUL keeps the prefix unambiguous against the first
// length field.
const (
	auditDomainPrefix  = "hatef.audit.v1\x00"
	ledgerDomainPrefix = "hatef.ledger.v1\x00"
)

// ChainHashHexLen is the length of a hex-encoded SHA-256 chain hash, matching the
// CHAR(64) columns on both tables.
const ChainHashHexLen = 2 * sha256.Size

// GenesisChainHash is the predecessor digest used for the first record in a chain:
// 32 zero bytes. A fixed, well-known seed means the very first record is chained
// like every other one, so verification has no special case that could be abused to
// forge a new "first" record.
var GenesisChainHash = [sha256.Size]byte{}

// ErrInvalidChainHash reports a stored chain_hash that is not 64 hex characters,
// which means the column was written by something other than this package.
var ErrInvalidChainHash = errors.New("audit: stored chain_hash is not a 64-character hex SHA-256 digest")

// AuditRecord is the exact set of mvp_audit_logs fields covered by the chain, in
// hash order.
//
// UserID is absent by design and must stay absent. mvp_audit_logs.user_id is
// ON DELETE SET NULL, so a GDPR hard delete rewrites it to NULL while leaving the
// rest of the row byte-identical. Hashing it would make every purged subject's rows
// fail verification forever — a correct erasure presenting as permanent tampering.
// Post-deletion attribution is security_event_ledger's job. See the package doc.
type AuditRecord struct {
	ID            string
	ActorID       string
	ActorSPIFFEID string
	EventType     string
	ActionStatus  string
	ClientIP      string
	UserAgent     string
	// Payload is the persisted JSONB text exactly as stored. The publisher
	// serializes the payload once and ships the string so the hashed bytes and the
	// stored bytes cannot diverge through a re-marshal.
	Payload   string
	Timestamp time.Time
}

// LedgerRecord is the set of security_event_ledger fields covered by that chain,
// in hash order. Nullable columns are pointers so NULL and "" hash differently:
// "this attribute was absent" and "this attribute was empty" are different claims
// about an event, and collapsing them would let one be rewritten as the other.
type LedgerRecord struct {
	ID                 string
	AccountRef         string
	IdentityBlindIndex *string
	EventType          string
	ClientIP           *string
	IPSubnet           *string
	UserAgent          *string
	DeviceFingerprint  *string
	ClientID           *string
	Scope              *string
	Timestamp          time.Time
	RetainUntil        time.Time
}

// SerializeAudit returns the canonical hash input for one mvp_audit_logs row.
func SerializeAudit(r AuditRecord) []byte {
	buf := make([]byte, 0, 256)
	buf = append(buf, auditDomainPrefix...)
	buf = appendField(buf, r.ID)
	buf = appendField(buf, r.ActorID)
	buf = appendField(buf, r.ActorSPIFFEID)
	buf = appendField(buf, r.EventType)
	buf = appendField(buf, r.ActionStatus)
	buf = appendField(buf, r.ClientIP)
	buf = appendField(buf, r.UserAgent)
	buf = appendField(buf, r.Payload)
	buf = appendField(buf, FormatChainTime(r.Timestamp))
	return buf
}

// SerializeLedger returns the canonical hash input for one security_event_ledger
// row.
func SerializeLedger(r LedgerRecord) []byte {
	buf := make([]byte, 0, 256)
	buf = append(buf, ledgerDomainPrefix...)
	buf = appendField(buf, r.ID)
	buf = appendField(buf, r.AccountRef)
	buf = appendNullable(buf, r.IdentityBlindIndex)
	buf = appendField(buf, r.EventType)
	buf = appendNullable(buf, r.ClientIP)
	buf = appendNullable(buf, r.IPSubnet)
	buf = appendNullable(buf, r.UserAgent)
	buf = appendNullable(buf, r.DeviceFingerprint)
	buf = appendNullable(buf, r.ClientID)
	buf = appendNullable(buf, r.Scope)
	buf = appendField(buf, FormatChainTime(r.Timestamp))
	buf = appendField(buf, FormatChainTime(r.RetainUntil))
	return buf
}

// ChainHash computes the hex digest for a record given its predecessor's raw
// digest.
func ChainHash(prev [sha256.Size]byte, body []byte) string {
	h := sha256.New()
	h.Write(prev[:])
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// DecodeChainHash converts a stored hex chain_hash back into the raw 32 bytes used
// as the next record's predecessor.
//
// Rehashing the hex text instead would still chain, but it would silently accept a
// truncated or non-hex column, so the malformed value would propagate into every
// later digest rather than being reported here.
func DecodeChainHash(stored string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	if len(stored) != ChainHashHexLen {
		return out, fmt.Errorf("%w: got %d characters", ErrInvalidChainHash, len(stored))
	}
	raw, err := hex.DecodeString(stored)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrInvalidChainHash, err)
	}
	copy(out[:], raw)
	return out, nil
}

// FormatChainTime renders a timestamp for hashing: UTC, RFC 3339 with nanoseconds.
//
// Normalizing to UTC matters because timestamptz carries no zone through
// PostgreSQL — a value written as +03:30 comes back as UTC, so hashing the
// publisher's local rendering would never verify. Nanosecond precision is used
// because PostgreSQL stores microseconds; truncating further would make two
// distinct rows hash the same field value.
func FormatChainTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// appendField writes uint32be(len(s)) || s.
func appendField(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

// appendNullable writes 0x00 for NULL, or 0x01 followed by a length-prefixed
// value. The tag byte is what keeps NULL distinguishable from "".
func appendNullable(dst []byte, s *string) []byte {
	if s == nil {
		return append(dst, 0x00)
	}
	dst = append(dst, 0x01)
	return appendField(dst, *s)
}
