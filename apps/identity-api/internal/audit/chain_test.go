package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// This file covers the tamper-evidence primitive both ledgers depend on. Three
// independent components must agree on it byte-for-byte — the signing consumer
// that writes the chain, the verification endpoint that recomputes it, and the
// retention worker that proves what it erased — so every property asserted here
// is a compatibility contract, not an implementation detail. A change that breaks
// one of these tests invalidates every digest already stored, with no way to
// distinguish the break from real tampering.

// fixedTime is an arbitrary but stable instant with sub-second precision, used so
// timestamp serialization is deterministic across runs.
var fixedTime = time.Date(2026, 3, 14, 15, 9, 26, 535897932, time.UTC)

// sampleAudit returns a fully populated AuditRecord. Every field is non-empty so a
// mutation test can prove each one reaches the digest.
func sampleAudit() AuditRecord {
	return AuditRecord{
		ID:            "6f1d3c2b-0000-4000-8000-000000000001",
		ActorID:       "6f1d3c2b-0000-4000-8000-000000000002",
		ActorSPIFFEID: APIActorSPIFFEID,
		EventType:     EventLoginSucceeded,
		ActionStatus:  StatusSuccess,
		ClientIP:      "203.0.113.5",
		UserAgent:     "Mozilla/5.0",
		Payload:       `{"method":"webauthn"}`,
		Timestamp:     fixedTime,
	}
}

// sampleLedger returns a fully populated LedgerRecord, including every nullable
// column set to a non-nil value.
func sampleLedger() LedgerRecord {
	blindIndex := strings.Repeat("a", 64)
	clientIP := "203.0.113.5"
	subnet := "203.0.113.0/24"
	userAgent := "Mozilla/5.0"
	device := "device-1"
	clientID := "search-engine"
	scope := "openid profile"
	return LedgerRecord{
		ID:                 "6f1d3c2b-0000-4000-8000-000000000001",
		AccountRef:         "6f1d3c2b-0000-4000-8000-000000000003",
		IdentityBlindIndex: &blindIndex,
		BlindIndexVersion:  1,
		EventType:          EventLoginSucceeded,
		ClientIP:           &clientIP,
		IPSubnet:           &subnet,
		UserAgent:          &userAgent,
		DeviceFingerprint:  &device,
		ClientID:           &clientID,
		Scope:              &scope,
		Timestamp:          fixedTime,
		RetainUntil:        fixedTime.Add(8760 * time.Hour),
	}
}

func mustSerializeAudit(t *testing.T, r AuditRecord) []byte {
	t.Helper()
	body, err := SerializeAudit(r)
	if err != nil {
		t.Fatalf("SerializeAudit: %v", err)
	}
	return body
}

func mustSerializeLedger(t *testing.T, r LedgerRecord) []byte {
	t.Helper()
	body, err := SerializeLedger(r)
	if err != nil {
		t.Fatalf("SerializeLedger: %v", err)
	}
	return body
}

func mustLeafAudit(t *testing.T, r AuditRecord) Digest {
	t.Helper()
	d, err := LeafAudit(r)
	if err != nil {
		t.Fatalf("LeafAudit: %v", err)
	}
	return d
}

func mustLeafLedger(t *testing.T, r LedgerRecord) Digest {
	t.Helper()
	d, err := LeafLedger(r)
	if err != nil {
		t.Fatalf("LeafLedger: %v", err)
	}
	return d
}

// TestLeafHashMatchesFormula pins the leaf stage against an independent
// computation rather than against LeafAudit's own output. A self-consistent
// implementation of the wrong formula would still chain, verify against itself,
// and be undetectable until an external auditor recomputed it.
func TestLeafHashMatchesFormula(t *testing.T) {
	t.Parallel()

	body := mustSerializeAudit(t, sampleAudit())
	want := sha256.New()
	want.Write([]byte(auditLeafPrefix))
	want.Write(body)

	got := mustLeafAudit(t, sampleAudit())
	if !bytes.Equal(got[:], want.Sum(nil)) {
		t.Errorf("LeafAudit = %s, want %s", got.Hex(), hex.EncodeToString(want.Sum(nil)))
	}
}

// TestChainHashMatchesFormula pins the chain stage the same way:
// chain_hash(N) = SHA-256(chain_prefix || chain_hash(N-1) || leaf_hash(N)).
func TestChainHashMatchesFormula(t *testing.T) {
	t.Parallel()

	prev := Digest(sha256.Sum256([]byte("previous record")))
	leafHash := mustLeafAudit(t, sampleAudit())

	want := sha256.New()
	want.Write([]byte(auditChainPrefix))
	want.Write(prev[:])
	want.Write(leafHash[:])

	got := ChainAudit(prev, leafHash)
	if !bytes.Equal(got[:], want.Sum(nil)) {
		t.Errorf("ChainAudit = %s, want %s", got.Hex(), hex.EncodeToString(want.Sum(nil)))
	}
}

func TestDigestHexIsLowerCaseSHA256(t *testing.T) {
	t.Parallel()

	got := ChainAudit(AuditGenesis(), mustLeafAudit(t, sampleAudit())).Hex()
	if len(got) != ChainHashHexLen {
		t.Errorf("digest hex length = %d, want %d", len(got), ChainHashHexLen)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("digest is not hex: %v", err)
	}
	if got != strings.ToLower(got) {
		t.Errorf("digest = %q, want lower-case hex so stored values compare byte-for-byte", got)
	}
}

// TestGenesisIsDerivedNotZero is the v2 change to the seed. v1 used 32 zero bytes,
// which made a zeroed, truncated, or default-initialized predecessor column
// indistinguishable from a legitimate genesis — so blanking a predecessor could
// pass off a forged record as the first one.
func TestGenesisIsDerivedNotZero(t *testing.T) {
	t.Parallel()

	var zero Digest
	for name, got := range map[string]Digest{"audit": AuditGenesis(), "ledger": LedgerGenesis()} {
		if got == zero {
			t.Errorf("%s genesis is 32 zero bytes; a blanked column would be accepted as genesis", name)
		}
	}
	if AuditGenesis() == LedgerGenesis() {
		t.Error("the two chains share a genesis digest; an audit genesis could seed the ledger chain")
	}
	if want := Digest(sha256.Sum256([]byte(auditChainPrefix + "genesis"))); AuditGenesis() != want {
		t.Errorf("audit genesis = %s, want %s", AuditGenesis().Hex(), want.Hex())
	}
	if want := Digest(sha256.Sum256([]byte(ledgerChainPrefix + "genesis"))); LedgerGenesis() != want {
		t.Errorf("ledger genesis = %s, want %s", LedgerGenesis().Hex(), want.Hex())
	}
}

// TestChainDetectsTamperedPredecessor is the property the whole design exists for:
// altering record N invalidates the stored digest of N+1. Without it the chain
// would be a per-row checksum, which an attacker who can write rows can simply
// recompute.
func TestChainDetectsTamperedPredecessor(t *testing.T) {
	t.Parallel()

	first := sampleAudit()
	second := sampleAudit()
	second.ID = "6f1d3c2b-0000-4000-8000-00000000000f"

	tip1 := ChainAudit(AuditGenesis(), mustLeafAudit(t, first))
	chain2 := ChainAudit(tip1, mustLeafAudit(t, second))

	// An auditor recomputing after record 1's action_status was flipped to hide a
	// failed login must not arrive at the stored chain2.
	tampered := first
	tampered.ActionStatus = StatusFailure
	tamperedTip := ChainAudit(AuditGenesis(), mustLeafAudit(t, tampered))
	if ChainAudit(tamperedTip, mustLeafAudit(t, second)) == chain2 {
		t.Error("tampering with record 1 left record 2's chain digest valid; the chain provides no tamper evidence")
	}
}

// TestChainDetectsRemovedChainNode covers deletion. In v2 a removed *payload* is
// legitimate and must not break anything (see TestErasedPayloadKeepsChainIntact),
// but a removed *chain node* is tampering and must still be caught — seq gaps are
// explicitly not evidence, so the chain has to carry it.
func TestChainDetectsRemovedChainNode(t *testing.T) {
	t.Parallel()

	records := make([]AuditRecord, 3)
	for i := range records {
		rec := sampleAudit()
		rec.ID = "6f1d3c2b-0000-4000-8000-00000000000" + string(rune('1'+i))
		records[i] = rec
	}

	chains := make([]Digest, len(records))
	tip := AuditGenesis()
	for i, rec := range records {
		tip = ChainAudit(tip, mustLeafAudit(t, rec))
		chains[i] = tip
	}

	// Replay skipping the middle node, as a reader would after someone deleted it.
	tip = AuditGenesis()
	for _, rec := range []AuditRecord{records[0], records[2]} {
		tip = ChainAudit(tip, mustLeafAudit(t, rec))
	}
	if tip == chains[2] {
		t.Error("removing node 2 still reproduced node 3's stored digest; a deletion would be invisible")
	}
}

// TestErasedPayloadKeepsChainIntact is the whole point of the v2 split, expressed
// at the format level: the chain is computed over leaf digests, so a verifier that
// no longer has a record's body still reproduces every later digest. In v1 this
// was impossible, which is why erasure needed checkpoints that recorded a removed
// span's predecessor and terminal hashes.
func TestErasedPayloadKeepsChainIntact(t *testing.T) {
	t.Parallel()

	records := make([]LedgerRecord, 4)
	for i := range records {
		rec := sampleLedger()
		rec.ID = "6f1d3c2b-0000-4000-8000-00000000001" + string(rune('0'+i))
		records[i] = rec
	}

	// The signer's view: leaves retained in the chain table, bodies in the payload
	// table.
	leaves := make([]Digest, len(records))
	chains := make([]Digest, len(records))
	tip := LedgerGenesis()
	for i, rec := range records {
		leaves[i] = mustLeafLedger(t, rec)
		tip = ChainLedger(tip, leaves[i])
		chains[i] = tip
	}

	// A retention purge erases records 1 and 2's bodies. Their leaves remain, so a
	// verifier walking the chain table reproduces the head exactly.
	replay := LedgerGenesis()
	for i := range records {
		replay = ChainLedger(replay, leaves[i])
	}
	if replay != chains[len(chains)-1] {
		t.Fatalf("chain head after payload erasure = %s, want %s", replay.Hex(), chains[len(chains)-1].Hex())
	}

	// A retained body must still verify against its own retained leaf.
	if mustLeafLedger(t, records[3]) != leaves[3] {
		t.Error("a retained payload no longer reproduces its stored leaf digest")
	}
	// And a tampered retained body must not.
	tampered := records[3]
	other := "rewritten"
	tampered.ClientID = &other
	if mustLeafLedger(t, tampered) == leaves[3] {
		t.Error("rewriting a retained payload still reproduced its leaf digest")
	}
}

// TestLeafAndChainPrefixesAreNotInterchangeable closes the cross-stage replay: a
// leaf digest must not be usable where a chain digest is expected, or vice versa.
func TestLeafAndChainPrefixesAreNotInterchangeable(t *testing.T) {
	t.Parallel()

	prefixes := map[string]string{
		"audit leaf":   auditLeafPrefix,
		"ledger leaf":  ledgerLeafPrefix,
		"audit chain":  auditChainPrefix,
		"ledger chain": ledgerChainPrefix,
	}
	seen := make(map[string]string, len(prefixes))
	for name, prefix := range prefixes {
		if !strings.HasSuffix(prefix, "\x00") {
			t.Errorf("%s prefix %q does not end with NUL; it is not self-delimiting", name, prefix)
		}
		if other, dup := seen[prefix]; dup {
			t.Errorf("%s and %s share the prefix %q", name, other, prefix)
		}
		seen[prefix] = name
		for otherName, otherPrefix := range prefixes {
			if name == otherName {
				continue
			}
			if strings.HasPrefix(prefix, otherPrefix) {
				t.Errorf("%s prefix %q is a prefix of %s %q; the domains overlap", name, prefix, otherName, otherPrefix)
			}
		}
	}

	// The same body hashed into the two ledgers' leaf domains must differ.
	body := mustSerializeAudit(t, sampleAudit())
	if leaf(auditLeafPrefix, body) == leaf(ledgerLeafPrefix, body) {
		t.Error("one body produced the same leaf in both domains; a record could be replayed across chains")
	}
	// And the same (prev, leaf) pair chained in the two domains must differ.
	prev := AuditGenesis()
	leafHash := mustLeafAudit(t, sampleAudit())
	if ChainAudit(prev, leafHash) == ChainLedger(prev, leafHash) {
		t.Error("one (prev, leaf) pair produced the same chain digest in both domains")
	}
}

// TestSerializeAuditIsLengthPrefixed proves the concatenation attack is closed.
// Without length prefixes ("ab","c") and ("a","bc") hash identically, so a value
// could be shifted between adjacent columns while preserving the digest.
func TestSerializeAuditIsLengthPrefixed(t *testing.T) {
	t.Parallel()

	left := sampleAudit()
	left.EventType = "ab"
	left.ActionStatus = "c"

	right := sampleAudit()
	right.EventType = "a"
	right.ActionStatus = "bc"

	if bytes.Equal(mustSerializeAudit(t, left), mustSerializeAudit(t, right)) {
		t.Error("adjacent fields ab|c and a|bc serialized identically; a byte can be shifted between columns undetected")
	}
}

func TestSerializeLedgerIsLengthPrefixed(t *testing.T) {
	t.Parallel()

	leftClientID := "ab"
	leftScope := "c"
	left := sampleLedger()
	left.ClientID = &leftClientID
	left.Scope = &leftScope

	rightClientID := "a"
	rightScope := "bc"
	right := sampleLedger()
	right.ClientID = &rightClientID
	right.Scope = &rightScope

	if bytes.Equal(mustSerializeLedger(t, left), mustSerializeLedger(t, right)) {
		t.Error("adjacent nullable fields ab|c and a|bc serialized identically")
	}
}

// TestSerializeLedgerDistinguishesNullFromEmpty is why the nullable columns are
// pointers. "This attribute did not apply" and "it applied and was empty" are
// different claims about an event; collapsing them would let one be rewritten as
// the other without breaking the chain.
func TestSerializeLedgerDistinguishesNullFromEmpty(t *testing.T) {
	t.Parallel()

	empty := ""
	for _, tc := range []struct {
		field string
		null  func(*LedgerRecord)
		blank func(*LedgerRecord)
	}{
		{"identity_blind_index",
			func(r *LedgerRecord) { r.IdentityBlindIndex = nil },
			func(r *LedgerRecord) { r.IdentityBlindIndex = &empty }},
		{"client_ip",
			func(r *LedgerRecord) { r.ClientIP = nil },
			func(r *LedgerRecord) { r.ClientIP = &empty }},
		{"ip_subnet",
			func(r *LedgerRecord) { r.IPSubnet = nil },
			func(r *LedgerRecord) { r.IPSubnet = &empty }},
		{"user_agent",
			func(r *LedgerRecord) { r.UserAgent = nil },
			func(r *LedgerRecord) { r.UserAgent = &empty }},
		{"device_fingerprint",
			func(r *LedgerRecord) { r.DeviceFingerprint = nil },
			func(r *LedgerRecord) { r.DeviceFingerprint = &empty }},
		{"client_id",
			func(r *LedgerRecord) { r.ClientID = nil },
			func(r *LedgerRecord) { r.ClientID = &empty }},
		{"scope",
			func(r *LedgerRecord) { r.Scope = nil },
			func(r *LedgerRecord) { r.Scope = &empty }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			t.Parallel()

			nullRec := sampleLedger()
			tc.null(&nullRec)
			blankRec := sampleLedger()
			tc.blank(&blankRec)

			if bytes.Equal(mustSerializeLedger(t, nullRec), mustSerializeLedger(t, blankRec)) {
				t.Errorf("%s: NULL and \"\" hash identically; one could be rewritten as the other", tc.field)
			}
		})
	}
}

// TestBlindIndexVersionIsHashedEvenWhenIndexIsNull is what makes pepper rotation
// possible. The version has to be inside the signed body unconditionally: if it
// were omitted when the index is NULL, a row's pepper generation could be
// reassigned afterwards, and a purged subject's row could be re-indexed under a
// different pepper without breaking the chain.
func TestBlindIndexVersionIsHashedEvenWhenIndexIsNull(t *testing.T) {
	t.Parallel()

	for _, withIndex := range []bool{true, false} {
		base := sampleLedger()
		if !withIndex {
			base.IdentityBlindIndex = nil
		}
		bumped := base
		bumped.BlindIndexVersion = base.BlindIndexVersion + 1

		if bytes.Equal(mustSerializeLedger(t, base), mustSerializeLedger(t, bumped)) {
			t.Errorf("blind index present=%v: changing blind_index_version did not change the hash input", withIndex)
		}
	}
}

// TestSerializeAuditCoversEveryField catches the failure mode that silently
// weakens the chain: a column that is persisted but left out of the hash input can
// be rewritten at will while verification still passes.
func TestSerializeAuditCoversEveryField(t *testing.T) {
	t.Parallel()

	base := mustSerializeAudit(t, sampleAudit())
	for name, mutate := range map[string]func(*AuditRecord){
		"ID":            func(r *AuditRecord) { r.ID = "6f1d3c2b-0000-4000-8000-0000000000ff" },
		"ActorID":       func(r *AuditRecord) { r.ActorID = "6f1d3c2b-0000-4000-8000-0000000000fe" },
		"ActorSPIFFEID": func(r *AuditRecord) { r.ActorSPIFFEID = SystemActorSPIFFEID },
		"EventType":     func(r *AuditRecord) { r.EventType = EventLoginFailed },
		"ActionStatus":  func(r *AuditRecord) { r.ActionStatus = StatusFailure },
		"ClientIP":      func(r *AuditRecord) { r.ClientIP = "198.51.100.7" },
		"UserAgent":     func(r *AuditRecord) { r.UserAgent = "curl/8.0" },
		"Payload":       func(r *AuditRecord) { r.Payload = `{"method":"password"}` },
		"Timestamp":     func(r *AuditRecord) { r.Timestamp = fixedTime.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := sampleAudit()
			mutate(&rec)
			if bytes.Equal(base, mustSerializeAudit(t, rec)) {
				t.Errorf("changing %s did not change the hash input; that column is outside the chain and can be rewritten undetected", name)
			}
		})
	}
}

func TestSerializeLedgerCoversEveryField(t *testing.T) {
	t.Parallel()

	other := "changed"
	base := mustSerializeLedger(t, sampleLedger())
	for name, mutate := range map[string]func(*LedgerRecord){
		"ID":                 func(r *LedgerRecord) { r.ID = "6f1d3c2b-0000-4000-8000-0000000000ff" },
		"AccountRef":         func(r *LedgerRecord) { r.AccountRef = "6f1d3c2b-0000-4000-8000-0000000000fe" },
		"IdentityBlindIndex": func(r *LedgerRecord) { r.IdentityBlindIndex = &other },
		"BlindIndexVersion":  func(r *LedgerRecord) { r.BlindIndexVersion = 7 },
		"EventType":          func(r *LedgerRecord) { r.EventType = EventRTRBreach },
		"ClientIP":           func(r *LedgerRecord) { r.ClientIP = &other },
		"IPSubnet":           func(r *LedgerRecord) { r.IPSubnet = &other },
		"UserAgent":          func(r *LedgerRecord) { r.UserAgent = &other },
		"DeviceFingerprint":  func(r *LedgerRecord) { r.DeviceFingerprint = &other },
		"ClientID":           func(r *LedgerRecord) { r.ClientID = &other },
		"Scope":              func(r *LedgerRecord) { r.Scope = &other },
		"Timestamp":          func(r *LedgerRecord) { r.Timestamp = fixedTime.Add(time.Nanosecond) },
		// retain_until is inside the chain on purpose: it is the retention decision
		// itself, so extending or shortening it after the fact must be detectable.
		"RetainUntil": func(r *LedgerRecord) { r.RetainUntil = r.RetainUntil.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := sampleLedger()
			mutate(&rec)
			if bytes.Equal(base, mustSerializeLedger(t, rec)) {
				t.Errorf("changing %s did not change the hash input; that column is outside the ledger chain", name)
			}
		})
	}
}

// TestSerializeIsDeterministic guards against any future encoder-dependent
// serialization (map iteration, JSON) creeping in: the same record must produce
// the same bytes on every call in every process.
func TestSerializeIsDeterministic(t *testing.T) {
	t.Parallel()

	for i := 0; i < 32; i++ {
		if !bytes.Equal(mustSerializeAudit(t, sampleAudit()), mustSerializeAudit(t, sampleAudit())) {
			t.Fatal("SerializeAudit is not deterministic")
		}
		if !bytes.Equal(mustSerializeLedger(t, sampleLedger()), mustSerializeLedger(t, sampleLedger())) {
			t.Fatal("SerializeLedger is not deterministic")
		}
	}
}

// TestFormatChainTimeNormalizesToUTC covers the round-trip through PostgreSQL:
// timestamptz carries no zone, so a value written as +03:30 comes back as UTC. If
// the publisher's local rendering were hashed, nothing would ever verify.
func TestFormatChainTimeNormalizesToUTC(t *testing.T) {
	t.Parallel()

	tehran := time.FixedZone("+0330", int((3*time.Hour + 30*time.Minute).Seconds()))
	local := fixedTime.In(tehran)

	if got, want := FormatChainTime(local), FormatChainTime(fixedTime); got != want {
		t.Errorf("FormatChainTime(local) = %q, want %q; the same instant must hash identically in any zone", got, want)
	}
	if !strings.HasSuffix(FormatChainTime(local), "Z") {
		t.Errorf("FormatChainTime(%q) is not rendered as UTC", local)
	}
}

// TestFormatChainTimeKeepsSubSecondPrecision matters because PostgreSQL stores
// microseconds: truncating to seconds would make two distinct rows hash the same
// field value, so their order could be swapped.
func TestFormatChainTimeKeepsSubSecondPrecision(t *testing.T) {
	t.Parallel()

	earlier := time.Date(2026, 3, 14, 15, 9, 26, 1000, time.UTC) // +1µs
	later := time.Date(2026, 3, 14, 15, 9, 26, 2000, time.UTC)   // +2µs

	if FormatChainTime(earlier) == FormatChainTime(later) {
		t.Error("two timestamps one microsecond apart rendered identically; PostgreSQL-precision rows would be interchangeable")
	}
}

func TestDecodeDigestRoundTrip(t *testing.T) {
	t.Parallel()

	want := ChainAudit(AuditGenesis(), mustLeafAudit(t, sampleAudit()))

	got, err := DecodeDigest(want.Bytes())
	if err != nil {
		t.Fatalf("DecodeDigest: %v", err)
	}
	if got != want {
		t.Errorf("DecodeDigest round trip = %s, want %s", got.Hex(), want.Hex())
	}

	fromHex, err := DecodeDigestHex(want.Hex())
	if err != nil {
		t.Fatalf("DecodeDigestHex: %v", err)
	}
	if fromHex != want {
		t.Errorf("DecodeDigestHex round trip = %s, want %s", fromHex.Hex(), want.Hex())
	}
}

// TestDigestBytesIsACopy matters because the returned slice becomes a bind
// parameter: handing out the digest's backing array would let a caller mutate a
// value that has already been hashed into the next record.
func TestDigestBytesIsACopy(t *testing.T) {
	t.Parallel()

	d := ChainAudit(AuditGenesis(), mustLeafAudit(t, sampleAudit()))
	raw := d.Bytes()
	raw[0] ^= 0xff
	if d.Bytes()[0] == raw[0] {
		t.Error("Digest.Bytes aliases the digest; a caller could mutate a committed value")
	}
}

// TestDecodeDigestRejectsMalformed keeps a bad column from propagating. Silently
// accepting a short value would carry the corruption into every later digest.
func TestDecodeDigestRejectsMalformed(t *testing.T) {
	t.Parallel()

	for name, stored := range map[string][]byte{
		"empty":     {},
		"nil":       nil,
		"too short": bytes.Repeat([]byte{0xab}, DigestSize-1),
		"too long":  bytes.Repeat([]byte{0xab}, DigestSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := DecodeDigest(stored); !errors.Is(err, ErrInvalidChainHash) {
				t.Errorf("DecodeDigest(%x) error = %v, want ErrInvalidChainHash", stored, err)
			}
		})
	}
}

func TestDecodeDigestHexRejectsMalformed(t *testing.T) {
	t.Parallel()

	for name, stored := range map[string]string{
		"empty":      "",
		"too short":  strings.Repeat("a", ChainHashHexLen-1),
		"too long":   strings.Repeat("a", ChainHashHexLen+1),
		"not hex":    strings.Repeat("z", ChainHashHexLen),
		"whitespace": strings.Repeat("a", ChainHashHexLen-1) + " ",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := DecodeDigestHex(stored); !errors.Is(err, ErrInvalidChainHash) {
				t.Errorf("DecodeDigestHex(%q) error = %v, want ErrInvalidChainHash", stored, err)
			}
		})
	}
}
