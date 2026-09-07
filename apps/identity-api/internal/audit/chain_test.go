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

// This file covers the tamper-evidence primitive both ledgers depend on. Two
// independent components must agree on it byte-for-byte — the signing consumer that
// writes the chain (Task 5.2) and the verification endpoint that recomputes it from
// genesis (Task 5.3) — so every property asserted here is a compatibility contract,
// not an implementation detail. A change that breaks one of these tests invalidates
// every chain_hash already stored, with no way to distinguish the break from real
// tampering.

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

// TestChainHashMatchesFormula pins the recurrence against an independent
// computation rather than against ChainHash's own output. The task text specifies
// chain_hash(N) = SHA-256(chain_hash(N-1) || serialize(record(N))), and a
// self-consistent implementation of the wrong formula would still chain, verify
// against itself, and be undetectable until an external auditor recomputed it.
func TestChainHashMatchesFormula(t *testing.T) {
	t.Parallel()

	prev := sha256.Sum256([]byte("previous record"))
	body := SerializeAudit(sampleAudit())

	want := sha256.New()
	want.Write(prev[:])
	want.Write(body)
	expected := hex.EncodeToString(want.Sum(nil))

	if got := ChainHash(prev, body); got != expected {
		t.Errorf("ChainHash = %q, want %q", got, expected)
	}
}

func TestChainHashIsHexSHA256(t *testing.T) {
	t.Parallel()

	got := ChainHash(GenesisChainHash, SerializeAudit(sampleAudit()))
	if len(got) != ChainHashHexLen {
		t.Errorf("ChainHash length = %d, want %d (the CHAR(64) column width)", len(got), ChainHashHexLen)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("ChainHash is not hex: %v", err)
	}
	if got != strings.ToLower(got) {
		t.Errorf("ChainHash = %q, want lower-case hex so stored values compare byte-for-byte", got)
	}
}

// TestGenesisChainHashIsZero fixes the well-known seed. Verification walks from it,
// so changing the value would make every existing chain unverifiable.
func TestGenesisChainHashIsZero(t *testing.T) {
	t.Parallel()

	var zero [sha256.Size]byte
	if GenesisChainHash != zero {
		t.Errorf("GenesisChainHash = %x, want %d zero bytes", GenesisChainHash, sha256.Size)
	}
}

// TestChainDetectsTamperedPredecessor is the property the whole design exists for:
// altering record N invalidates the stored hash of N+1. Without it the chain would
// be a per-row checksum, which an attacker who can write rows can simply recompute.
func TestChainDetectsTamperedPredecessor(t *testing.T) {
	t.Parallel()

	first := sampleAudit()
	second := sampleAudit()
	second.ID = "6f1d3c2b-0000-4000-8000-00000000000f"

	// Honest chain.
	hash1 := ChainHash(GenesisChainHash, SerializeAudit(first))
	tip1, err := DecodeChainHash(hash1)
	if err != nil {
		t.Fatalf("DecodeChainHash: %v", err)
	}
	hash2 := ChainHash(tip1, SerializeAudit(second))

	// An auditor recomputing after record 1's action_status was flipped to hide a
	// failed login must not arrive at the stored hash2.
	tampered := first
	tampered.ActionStatus = StatusFailure
	tamperedTip, err := DecodeChainHash(ChainHash(GenesisChainHash, SerializeAudit(tampered)))
	if err != nil {
		t.Fatalf("DecodeChainHash tampered: %v", err)
	}
	if recomputed := ChainHash(tamperedTip, SerializeAudit(second)); recomputed == hash2 {
		t.Error("tampering with record 1 left record 2's chain hash valid; the chain provides no tamper evidence")
	}
}

// TestChainDetectsRemovedRecord covers the deletion case called out in migration
// 00006: seq gaps are explicitly not evidence, so removing a row must be caught by
// the chain instead.
func TestChainDetectsRemovedRecord(t *testing.T) {
	t.Parallel()

	records := make([]AuditRecord, 3)
	for i := range records {
		rec := sampleAudit()
		rec.ID = "6f1d3c2b-0000-4000-8000-00000000000" + string(rune('1'+i))
		records[i] = rec
	}

	hashes := make([]string, len(records))
	tip := GenesisChainHash
	for i, rec := range records {
		hashes[i] = ChainHash(tip, SerializeAudit(rec))
		next, err := DecodeChainHash(hashes[i])
		if err != nil {
			t.Fatalf("DecodeChainHash: %v", err)
		}
		tip = next
	}

	// Replay skipping the middle record, as a reader would after someone deleted it.
	tip = GenesisChainHash
	surviving := []AuditRecord{records[0], records[2]}
	var last string
	for _, rec := range surviving {
		last = ChainHash(tip, SerializeAudit(rec))
		next, err := DecodeChainHash(last)
		if err != nil {
			t.Fatalf("DecodeChainHash: %v", err)
		}
		tip = next
	}
	if last == hashes[2] {
		t.Error("removing record 2 still reproduced record 3's stored hash; a deletion would be invisible")
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

	if bytes.Equal(SerializeAudit(left), SerializeAudit(right)) {
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

	if bytes.Equal(SerializeLedger(left), SerializeLedger(right)) {
		t.Error("adjacent nullable fields ab|c and a|bc serialized identically")
	}
}

// TestSerializeDomainsAreSeparated keeps the two chains non-interchangeable. They
// share a formula, so without distinct prefixes a crafted ledger record could be
// replayed as an audit record with a matching digest.
func TestSerializeDomainsAreSeparated(t *testing.T) {
	t.Parallel()

	auditBytes := SerializeAudit(sampleAudit())
	ledgerBytes := SerializeLedger(sampleLedger())

	if !bytes.HasPrefix(auditBytes, []byte(auditDomainPrefix)) {
		t.Errorf("audit serialization does not start with %q", auditDomainPrefix)
	}
	if !bytes.HasPrefix(ledgerBytes, []byte(ledgerDomainPrefix)) {
		t.Errorf("ledger serialization does not start with %q", ledgerDomainPrefix)
	}
	if bytes.HasPrefix(auditBytes, []byte(ledgerDomainPrefix)) || bytes.HasPrefix(ledgerBytes, []byte(auditDomainPrefix)) {
		t.Error("the two domain prefixes overlap; a record from one chain could be replayed into the other")
	}
	if auditDomainPrefix == ledgerDomainPrefix {
		t.Fatal("domain prefixes are identical")
	}
	// The prefixes must be self-delimiting against the first length field, which is
	// what the trailing NUL provides.
	for name, prefix := range map[string]string{"audit": auditDomainPrefix, "ledger": ledgerDomainPrefix} {
		if !strings.HasSuffix(prefix, "\x00") {
			t.Errorf("%s domain prefix %q does not end with NUL; it is not self-delimiting", name, prefix)
		}
	}
}

// TestSerializeLedgerDistinguishesNullFromEmpty is why the nullable columns are
// pointers. "This attribute did not apply" and "it applied and was empty" are
// different claims about an event; collapsing them would let one be rewritten as the
// other without breaking the chain.
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

			if bytes.Equal(SerializeLedger(nullRec), SerializeLedger(blankRec)) {
				t.Errorf("%s: NULL and \"\" hash identically; one could be rewritten as the other", tc.field)
			}
		})
	}
}

// TestSerializeAuditCoversEveryField catches the failure mode that silently weakens
// the chain: a column that is persisted but left out of the hash input can be
// rewritten at will while verification still passes.
func TestSerializeAuditCoversEveryField(t *testing.T) {
	t.Parallel()

	base := SerializeAudit(sampleAudit())
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
			if bytes.Equal(base, SerializeAudit(rec)) {
				t.Errorf("changing %s did not change the hash input; that column is outside the chain and can be rewritten undetected", name)
			}
		})
	}
}

func TestSerializeLedgerCoversEveryField(t *testing.T) {
	t.Parallel()

	other := "changed"
	base := SerializeLedger(sampleLedger())
	for name, mutate := range map[string]func(*LedgerRecord){
		"ID":                 func(r *LedgerRecord) { r.ID = "6f1d3c2b-0000-4000-8000-0000000000ff" },
		"AccountRef":         func(r *LedgerRecord) { r.AccountRef = "6f1d3c2b-0000-4000-8000-0000000000fe" },
		"IdentityBlindIndex": func(r *LedgerRecord) { r.IdentityBlindIndex = &other },
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
			if bytes.Equal(base, SerializeLedger(rec)) {
				t.Errorf("changing %s did not change the hash input; that column is outside the ledger chain", name)
			}
		})
	}
}

// TestSerializeIsDeterministic guards against any future encoder-dependent
// serialization (map iteration, JSON) creeping in: the same record must produce the
// same bytes on every call in every process.
func TestSerializeIsDeterministic(t *testing.T) {
	t.Parallel()

	for i := 0; i < 32; i++ {
		if !bytes.Equal(SerializeAudit(sampleAudit()), SerializeAudit(sampleAudit())) {
			t.Fatal("SerializeAudit is not deterministic")
		}
		if !bytes.Equal(SerializeLedger(sampleLedger()), SerializeLedger(sampleLedger())) {
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

func TestDecodeChainHashRoundTrip(t *testing.T) {
	t.Parallel()

	hash := ChainHash(GenesisChainHash, SerializeAudit(sampleAudit()))
	raw, err := DecodeChainHash(hash)
	if err != nil {
		t.Fatalf("DecodeChainHash: %v", err)
	}
	if got := hex.EncodeToString(raw[:]); got != hash {
		t.Errorf("round trip = %q, want %q", got, hash)
	}
}

// TestDecodeChainHashRejectsMalformed keeps a bad column from propagating. Rehashing
// the hex text instead of decoding it would silently accept a truncated value and
// carry the corruption into every later digest.
func TestDecodeChainHashRejectsMalformed(t *testing.T) {
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

			if _, err := DecodeChainHash(stored); !errors.Is(err, ErrInvalidChainHash) {
				t.Errorf("DecodeChainHash(%q) error = %v, want ErrInvalidChainHash", stored, err)
			}
		})
	}
}
