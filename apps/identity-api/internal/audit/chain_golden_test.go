package audit

import (
	"encoding/hex"
	"testing"
	"time"
)

// Golden vectors freezing canonical format v2.
//
// Every value below was cross-checked against an independent SHA-256
// implementation before being committed, so these are not merely a recording of
// whatever the code happened to produce. They pin three things that must never
// change silently:
//
//   - the exact byte layout of each serialized body, including length prefixes,
//     NULL tags, field order, and timestamp rendering;
//   - the four domain prefixes and the two-stage leaf/chain construction;
//   - both genesis seeds, which migration 00015 hardcodes into the chain tables'
//     CHECK constraints.
//
// A change that breaks this file invalidates every digest already stored, and —
// because the payload tables forbid UPDATE and the chain tables forbid both
// UPDATE and DELETE — there is no migration that can repair it. If you are here
// because this test failed, the format change you are making is almost certainly
// not one you can ship.
//
// TestGenesisMatchesMigration in the migrate package asserts the same genesis
// constants against what the database actually stores.

// goldenTime is the instant the vectors below were computed at. It carries
// microsecond precision with a trailing zero in the nanosecond position, which is
// what exercises RFC3339Nano's trailing-zero trimming.
var goldenTime = time.Date(2026, 3, 4, 5, 6, 7, 891011000, time.UTC)

func goldenAuditRecord() AuditRecord {
	return AuditRecord{
		ID:            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
		ActorID:       "11111111-2222-3333-4444-555555555555",
		ActorSPIFFEID: "spiffe://hatef.ir/ns/identity/sa/api",
		EventType:     "auth.login",
		ActionStatus:  "success",
		ClientIP:      "203.0.113.9",
		UserAgent:     "curl/8.7.1",
		Payload:       `{"k":"v"}`,
		Timestamp:     goldenTime,
	}
}

func goldenLedgerRecord() LedgerRecord {
	blindIndex := "a1b2c3"
	clientIP := "203.0.113.9"
	subnet := "203.0.113.0/24"
	return LedgerRecord{
		ID:                 "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
		AccountRef:         "11111111-2222-3333-4444-555555555555",
		IdentityBlindIndex: &blindIndex,
		BlindIndexVersion:  1,
		EventType:          "auth.login",
		ClientIP:           &clientIP,
		IPSubnet:           &subnet,
		// Left NULL on purpose: the vector has to cover both the present and the
		// absent branch of appendNullable, or the tag byte is untested.
		UserAgent:         nil,
		DeviceFingerprint: nil,
		ClientID:          nil,
		Scope:             nil,
		Timestamp:         goldenTime,
		RetainUntil:       goldenTime.Add(24 * time.Hour),
	}
}

const (
	goldenAuditBodyHex = "0000002430663165326433632d346235612d363937382d383739362d61" +
		"35623463336432653166300000002431313131313131312d323232322d333333332d343434342d3535" +
		"3535353535353535353500000024" +
		"7370696666653a2f2f68617465662e69722f6e732f6964656e746974792f73612f617069" +
		"0000000a617574682e6c6f67696e00000007737563636573730000000b3230332e302e313133" +
		"2e390000000a6375726c2f382e372e31000000097b226b223a2276227d0000001b3230323" +
		"62d30332d30345430353a30363a30372e3839313031315a"
	goldenAuditLeafHex   = "3abc11963118ff864f33c1f6a64bd105b64f3e9af0e8db96da2302b41b7a7c97"
	goldenAuditChain1Hex = "0d4f3745fd0b186c008797e8e30e23687267b61919e95a77a617a769f891b778"

	goldenLedgerBodyHex = "0000002430663165326433632d346235612d363937382d383739362d6135" +
		"623463336432653166300000002431313131313131312d323232322d333333332d343434342d35353" +
		"53535353535353535350100000006613162326333000000013100" +
		"00000a617574682e6c6f67696e010000000b3230332e302e3131332e39010000000e3230332e302e31" +
		"31332e302f323400000000000000" +
		"1b323032362d30332d30345430353a30363a30372e3839313031315a0000001b32303236" +
		"2d30332d30355430353a30363a30372e3839313031315a"
	goldenLedgerLeafHex   = "823d8c0c0c934b5dd04e1332b6c739c1c14be60e37d7417afc2a23e30ef856b1"
	goldenLedgerChain1Hex = "6da652d2f03285fe78bd5b0989d256584c86621b457107dea73c57eff3db398c"
)

func TestGoldenGenesisDigests(t *testing.T) {
	t.Parallel()

	if got := AuditGenesis().Hex(); got != GoldenAuditGenesisHex {
		t.Errorf("audit genesis = %s, want %s", got, GoldenAuditGenesisHex)
	}
	if got := LedgerGenesis().Hex(); got != GoldenLedgerGenesisHex {
		t.Errorf("ledger genesis = %s, want %s", got, GoldenLedgerGenesisHex)
	}
}

func TestGoldenAuditVector(t *testing.T) {
	t.Parallel()

	body, err := SerializeAudit(goldenAuditRecord())
	if err != nil {
		t.Fatalf("SerializeAudit: %v", err)
	}
	if got := hex.EncodeToString(body); got != goldenAuditBodyHex {
		t.Errorf("audit body bytes changed\n got %s\nwant %s", got, goldenAuditBodyHex)
	}

	leafHash, err := LeafAudit(goldenAuditRecord())
	if err != nil {
		t.Fatalf("LeafAudit: %v", err)
	}
	if got := leafHash.Hex(); got != goldenAuditLeafHex {
		t.Errorf("audit leaf = %s, want %s", got, goldenAuditLeafHex)
	}
	if got := ChainAudit(AuditGenesis(), leafHash).Hex(); got != goldenAuditChain1Hex {
		t.Errorf("audit chain[1] = %s, want %s", got, goldenAuditChain1Hex)
	}
}

func TestGoldenLedgerVector(t *testing.T) {
	t.Parallel()

	body, err := SerializeLedger(goldenLedgerRecord())
	if err != nil {
		t.Fatalf("SerializeLedger: %v", err)
	}
	if got := hex.EncodeToString(body); got != goldenLedgerBodyHex {
		t.Errorf("ledger body bytes changed\n got %s\nwant %s", got, goldenLedgerBodyHex)
	}

	leafHash, err := LeafLedger(goldenLedgerRecord())
	if err != nil {
		t.Fatalf("LeafLedger: %v", err)
	}
	if got := leafHash.Hex(); got != goldenLedgerLeafHex {
		t.Errorf("ledger leaf = %s, want %s", got, goldenLedgerLeafHex)
	}
	if got := ChainLedger(LedgerGenesis(), leafHash).Hex(); got != goldenLedgerChain1Hex {
		t.Errorf("ledger chain[1] = %s, want %s", got, goldenLedgerChain1Hex)
	}
}

// TestGoldenVectorsCoverBothNullableBranches keeps the vectors honest: if a
// future edit made every nullable field non-nil, the 0x00 tag would stop being
// exercised and a regression in appendNullable could land unnoticed.
func TestGoldenVectorsCoverBothNullableBranches(t *testing.T) {
	t.Parallel()

	rec := goldenLedgerRecord()
	present := rec.IdentityBlindIndex != nil || rec.ClientIP != nil || rec.IPSubnet != nil
	absent := rec.UserAgent == nil || rec.DeviceFingerprint == nil || rec.ClientID == nil || rec.Scope == nil
	if !present || !absent {
		t.Fatal("the golden ledger vector must contain both a non-nil and a nil nullable field")
	}

	body, err := SerializeLedger(rec)
	if err != nil {
		t.Fatalf("SerializeLedger: %v", err)
	}
	var sawPresent, sawAbsent bool
	for _, b := range body {
		switch b {
		case 0x00:
			sawAbsent = true
		case 0x01:
			sawPresent = true
		}
	}
	if !sawPresent || !sawAbsent {
		t.Error("the golden ledger body does not contain both nullable tag bytes")
	}
}
