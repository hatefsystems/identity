package migrate

import (
	"strings"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

// Migration 00015 hardcodes both genesis digests into the chain heads' CHECK
// constraints, because a CHECK cannot call into Go. That duplication is the only
// place the canonical format is restated outside internal/audit, so it needs a
// test: a format change that updated the Go constant but not the migration would
// produce a database that rejects the signer's very first write, and the failure
// would surface as an opaque constraint violation at genesis bootstrap rather
// than as a clear format mismatch here.
//
// It reads the embedded migration rather than the on-disk file so it checks what
// actually ships in the binary.
func TestGenesisMatchesMigration(t *testing.T) {
	t.Parallel()

	raw, err := db.Migrations.ReadFile("migrations/00015_chain_payload_split.sql")
	if err != nil {
		t.Fatalf("read embedded migration: %v", err)
	}
	sql := string(raw)

	for name, want := range map[string]string{
		"audit":  audit.GoldenAuditGenesisHex,
		"ledger": audit.GoldenLedgerGenesisHex,
	} {
		literal := `'\x` + want + `'::bytea`
		if !strings.Contains(sql, literal) {
			t.Errorf("migration 00015 does not contain the %s genesis digest %s;\n"+
				"the schema's CHECK constraint and internal/audit disagree about the canonical format",
				name, want)
		}
	}

	// Guard against the opposite drift: the migration must not still carry v1's
	// all-zero genesis, which a blanked column could satisfy.
	for _, stale := range []string{"repeat('0', 64)", `'\x` + strings.Repeat("00", 32) + `'::bytea`} {
		if strings.Contains(sql, stale) {
			t.Errorf("migration 00015 still accepts the v1 zero genesis via %q", stale)
		}
	}
}

// TestGenesisConstantsMatchDerivation closes the loop: the exported golden
// constants must equal what the live code derives. Without this the parity test
// above could pass against two stale values.
func TestGenesisConstantsMatchDerivation(t *testing.T) {
	t.Parallel()

	if got := audit.Genesis().Hex(); got != audit.GoldenAuditGenesisHex {
		t.Errorf("audit genesis = %s, golden constant = %s", got, audit.GoldenAuditGenesisHex)
	}
	if got := audit.LedgerGenesis().Hex(); got != audit.GoldenLedgerGenesisHex {
		t.Errorf("ledger genesis = %s, golden constant = %s", got, audit.GoldenLedgerGenesisHex)
	}
}
