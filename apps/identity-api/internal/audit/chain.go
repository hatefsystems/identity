package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
)

// This file owns the ledgers' tamper-evidence primitive. As of format v2 it is
// computed in two stages:
//
//	leaf_hash(N)  = SHA-256( leaf_prefix  || serialize(record(N)) )
//	chain_hash(N) = SHA-256( chain_prefix || chain_hash(N-1) || leaf_hash(N) )
//
// # Why two stages
//
// In v1 the digest covered the record and was stored on the record's own row, so
// erasing a row removed a chain link. Recovering from that required erased-span
// checkpoints that recorded a removed segment's predecessor and terminal digests,
// compaction of adjacent spans, and a second copy of serialize() in PL/pgSQL to
// re-derive bodies inside the purge routine.
//
// Splitting the leaf out removes the whole problem. The chain is computed over
// leaf digests and lives in its own append-only table that is never deleted; the
// record body lives in a separate table that may be erased freely. A retention
// purge or a GDPR erasure drops a body and leaves every digest in place, so the
// chain stays complete and verifiable from genesis forever. Verification of a
// retained record recomputes its leaf from the body and compares; an erased
// record's leaf is simply retained without a body to re-derive it from.
//
// It lives in package audit rather than in the signer because three independent
// components must agree on it byte-for-byte: the signing consumer that writes the
// chain, the verification endpoint that recomputes it, and the retention worker
// that proves what it erased. A second implementation of serialize() would be a
// latent integrity alarm, so there is exactly one — in this file, in this
// language. Format v2 deliberately removed the PL/pgSQL copy that v1 required.
//
// # Why length-prefixed binary and not JSON
//
// A hash input must have exactly one encoding. JSON does not: key order, unicode
// escaping, whitespace, and integer/float rendering are all encoder-dependent, and
// a Go version or library upgrade that changes any of them would invalidate every
// previously stored digest with no code change and no way to tell the difference
// from real tampering. Length-prefixing every field removes both the ambiguity and
// the concatenation attack: without it, fields ("ab","c") and ("a","bc") hash
// identically, so an attacker could shift a byte from one column into the next and
// preserve the digest.

// Domain separation prefixes.
//
// There are four, not two. The leaf prefixes keep the two ledgers' bodies from
// being interchangeable: without them a crafted ledger body could be replayed as
// an audit body with a matching digest. The chain prefixes do the same job one
// level up, and additionally make each chain's genesis distinct, so an audit
// genesis digest can never seed a ledger chain. The trailing NUL keeps every
// prefix unambiguous against the first length field.
const (
	auditLeafPrefix   = "hatef.audit.body.v2\x00"
	ledgerLeafPrefix  = "hatef.ledger.body.v2\x00"
	auditChainPrefix  = "hatef.audit.chain.v2\x00"
	ledgerChainPrefix = "hatef.ledger.chain.v2\x00"
)

// DigestSize is the raw length of every leaf and chain digest. Both are stored as
// BYTEA(32) rather than the v1 CHAR(64) hex text, which halves the storage cost of
// the chain tables' only two columns.
const DigestSize = sha256.Size

// ChainHashHexLen is the length of a hex-encoded digest. Storage is binary; hex is
// only used at the admin API boundary and in operator runbooks.
const ChainHashHexLen = 2 * DigestSize

// Digest is one raw SHA-256 leaf or chain digest.
type Digest [DigestSize]byte

// Hex renders the digest for an API response or a runbook.
func (d Digest) Hex() string { return hex.EncodeToString(d[:]) }

// Bytes returns a copy suitable for a BYTEA bind parameter.
func (d Digest) Bytes() []byte {
	out := make([]byte, DigestSize)
	copy(out, d[:])
	return out
}

// Errors reported for malformed stored digests. A stored value that is not exactly
// 32 bytes was written by something other than this package.
var (
	// ErrInvalidChainHash reports a stored digest of the wrong length.
	ErrInvalidChainHash = errors.New("audit: stored digest is not a 32-byte SHA-256 value")
	// ErrFieldTooLarge reports a field that cannot be length-prefixed.
	ErrFieldTooLarge = errors.New("audit: field exceeds serialization limit")
)

// Genesis digests: the predecessor used for the first record in each chain.
//
// v1 used 32 zero bytes. A derived seed is strictly better: a zeroed, truncated,
// or default-initialized column can no longer be mistaken for a legitimate
// genesis, so a verifier cannot be tricked into accepting a forged new "first"
// record by blanking the predecessor. The first record is still chained exactly
// like every other one, so verification has no special case.
var (
	auditGenesis  = deriveGenesis(auditChainPrefix)
	ledgerGenesis = deriveGenesis(ledgerChainPrefix)
)

func deriveGenesis(prefix string) Digest {
	return Digest(sha256.Sum256([]byte(prefix + "genesis")))
}

// GoldenAuditGenesisHex and GoldenLedgerGenesisHex restate the two genesis
// digests as literals.
//
// They exist because migration 00015 has to embed the same two values in the
// chain heads' CHECK constraints, and a CHECK cannot call into Go. That makes the
// migration the one place the canonical format is duplicated outside this file,
// so the duplication is pinned from both ends: chain_golden_test.go asserts these
// constants equal what the code derives, and internal/migrate's
// TestGenesisMatchesMigration asserts the migration contains exactly these
// strings. A format change that updated one and not the other would otherwise
// surface as an opaque constraint violation during genesis bootstrap.
const (
	GoldenAuditGenesisHex  = "5c358544585235f7ae29b4a8370d5541ddd6bd40c81321fc92bbb54b31887ebb"
	GoldenLedgerGenesisHex = "6ece92219999993f2dc5b43d677c333fa6836745079b919355360170f3ea2c54"
)

// Genesis returns the audit chain's genesis predecessor digest.
func Genesis() Digest { return auditGenesis }

// LedgerGenesis returns the security ledger's genesis predecessor digest.
func LedgerGenesis() Digest { return ledgerGenesis }

// AuditRecord is the exact set of audit_log_payload fields covered by the chain,
// in hash order.
//
// UserID is absent by design and must stay absent. The user reference is
// ON DELETE SET NULL, so a GDPR hard delete rewrites it to NULL while leaving the
// rest of the row byte-identical. Hashing it would make every purged subject's
// rows fail verification forever — a correct erasure presenting as permanent
// tampering. Post-deletion attribution is the security ledger's job.
//
//revive:disable-next-line:exported -- Paired with LedgerRecord in the public chain format.
type AuditRecord struct {
	ID            string
	ActorID       string
	ActorSPIFFEID string
	EventType     string
	ActionStatus  string
	ClientIP      string
	UserAgent     string
	// Payload is the persisted TEXT exactly as stored. The publisher
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
	// BlindIndexVersion identifies which pepper generation produced
	// IdentityBlindIndex. It is hashed unconditionally, including when the index
	// itself is NULL, because it records which pepper *would* have applied.
	//
	// Without it the pepper can never be rotated: the index is inside the signed
	// body and the payload table forbids UPDATE, so a rotation would silently
	// orphan the lookup path for every historical row with no way to tell which
	// generation any given row used. Versioning it is what keeps a compromised
	// pepper retirable.
	BlindIndexVersion int16
	EventType         string
	ClientIP          *string
	IPSubnet          *string
	UserAgent         *string
	DeviceFingerprint *string
	ClientID          *string
	Scope             *string
	Timestamp         time.Time
	RetainUntil       time.Time
}

// SerializeAudit returns the canonical body for one audit record. The leaf prefix
// is applied by LeafAudit, not here, so the body and the digest stay separable.
func SerializeAudit(r AuditRecord) ([]byte, error) {
	buf := make([]byte, 0, 256)
	var err error
	for _, field := range []string{
		r.ID, r.ActorID, r.ActorSPIFFEID, r.EventType, r.ActionStatus,
		r.ClientIP, r.UserAgent, r.Payload, FormatChainTime(r.Timestamp),
	} {
		if buf, err = appendField(buf, field); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// SerializeLedger returns the canonical body for one security ledger record.
func SerializeLedger(r LedgerRecord) ([]byte, error) {
	buf := make([]byte, 0, 256)
	var err error
	if buf, err = appendField(buf, r.ID); err != nil {
		return nil, err
	}
	if buf, err = appendField(buf, r.AccountRef); err != nil {
		return nil, err
	}
	if buf, err = appendNullable(buf, r.IdentityBlindIndex); err != nil {
		return nil, err
	}
	if buf, err = appendField(buf, strconv.FormatInt(int64(r.BlindIndexVersion), 10)); err != nil {
		return nil, err
	}
	if buf, err = appendField(buf, r.EventType); err != nil {
		return nil, err
	}
	for _, field := range []*string{
		r.ClientIP, r.IPSubnet, r.UserAgent, r.DeviceFingerprint, r.ClientID, r.Scope,
	} {
		if buf, err = appendNullable(buf, field); err != nil {
			return nil, err
		}
	}
	if buf, err = appendField(buf, FormatChainTime(r.Timestamp)); err != nil {
		return nil, err
	}
	return appendField(buf, FormatChainTime(r.RetainUntil))
}

// LeafAudit computes one audit record's leaf digest.
func LeafAudit(r AuditRecord) (Digest, error) {
	body, err := SerializeAudit(r)
	if err != nil {
		return Digest{}, err
	}
	return leaf(auditLeafPrefix, body), nil
}

// LeafLedger computes one ledger record's leaf digest.
func LeafLedger(r LedgerRecord) (Digest, error) {
	body, err := SerializeLedger(r)
	if err != nil {
		return Digest{}, err
	}
	return leaf(ledgerLeafPrefix, body), nil
}

func leaf(prefix string, body []byte) Digest {
	h := sha256.New()
	_, _ = h.Write([]byte(prefix))
	_, _ = h.Write(body)
	var out Digest
	copy(out[:], h.Sum(nil))
	return out
}

// ChainAudit links one audit leaf onto its predecessor.
func ChainAudit(prev, leafHash Digest) Digest {
	return chain(auditChainPrefix, prev, leafHash)
}

// ChainLedger links one ledger leaf onto its predecessor.
func ChainLedger(prev, leafHash Digest) Digest {
	return chain(ledgerChainPrefix, prev, leafHash)
}

func chain(prefix string, prev, leafHash Digest) Digest {
	h := sha256.New()
	_, _ = h.Write([]byte(prefix))
	_, _ = h.Write(prev[:])
	_, _ = h.Write(leafHash[:])
	var out Digest
	copy(out[:], h.Sum(nil))
	return out
}

// DecodeDigest converts a stored BYTEA value into a Digest.
//
// The length check is load-bearing rather than defensive: silently accepting a
// short or over-long column would propagate the malformed value into every later
// digest instead of being reported at the row that carries it.
func DecodeDigest(stored []byte) (Digest, error) {
	var out Digest
	if len(stored) != DigestSize {
		return out, fmt.Errorf("%w: got %d bytes", ErrInvalidChainHash, len(stored))
	}
	copy(out[:], stored)
	return out, nil
}

// DecodeDigestHex converts hex text (an admin API argument, or an operator-supplied
// runbook value) into a Digest.
func DecodeDigestHex(stored string) (Digest, error) {
	var out Digest
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

// NormalizeChainTime prepares new timestamps for PostgreSQL's microsecond
// precision before hashing AND insertion. Do not apply it as a historical repair:
// existing digests must be verified against exactly the values that survived.
func NormalizeChainTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}

// FormatChainTime renders the exact supplied timestamp in UTC. RFC3339Nano
// preserves microseconds without changing the existing serialization contract.
func FormatChainTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// appendField writes uint32be(len(s)) || s.
//
// An over-long field is an error rather than a panic: this runs inside the
// single-writer signing worker, and killing the only process that can advance the
// chain is a worse outcome than refusing one record.
func appendField(dst []byte, s string) ([]byte, error) {
	length := uint64(len(s))
	if length > math.MaxUint32 {
		return nil, fmt.Errorf("%w: %d bytes", ErrFieldTooLarge, len(s))
	}
	dst = binary.BigEndian.AppendUint32(dst, uint32(length))
	return append(dst, s...), nil
}

// appendNullable writes 0x00 for NULL, or 0x01 followed by a length-prefixed
// value. The tag byte is what keeps NULL distinguishable from "".
func appendNullable(dst []byte, s *string) ([]byte, error) {
	if s == nil {
		return append(dst, 0x00), nil
	}
	dst = append(dst, 0x01)
	return appendField(dst, *s)
}
