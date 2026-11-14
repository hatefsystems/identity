package migrate

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

func TestBundledBaselineInventory(t *testing.T) {
	t.Parallel()
	entries, err := db.Migrations.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].Name() != "00001_initial_schema.sql" || entries[1].Name() != "00002_registration_attempts.sql" || entries[2].Name() != "00003_username_reservations.sql" {
		t.Fatalf("binary must embed the baseline, registration and username migrations: %v", entries)
	}
	// Provider construction and source listing must not connect to PostgreSQL.
	database, err := sql.Open("pgx", "postgres://localhost/unused?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	p, err := NewProvider(database)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.runner(0)
	if err != nil {
		t.Fatal(err)
	}
	sources := r.ListSources()
	if len(sources) != 3 || sources[0].Version != 1 || sources[0].Path != "00001_initial_schema.sql" ||
		sources[1].Version != 2 || sources[1].Path != "00002_registration_attempts.sql" ||
		sources[2].Version != 3 || sources[2].Path != "00003_username_reservations.sql" {
		t.Fatalf("unexpected bundled runner sources: %+v", sources)
	}
}

// The baseline hardcodes both genesis digests into the chain heads' CHECK
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

	raw, err := db.Migrations.ReadFile("migrations/00001_initial_schema.sql")
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
			t.Errorf("baseline does not contain the %s genesis digest %s;\n"+
				"the schema's CHECK constraint and internal/audit disagree about the canonical format",
				name, want)
		}
	}

	// Guard against the opposite drift: the migration must not still carry v1's
	// all-zero genesis, which a blanked column could satisfy.
	for _, stale := range []string{"repeat('0', 64)", `'\x` + strings.Repeat("00", 32) + `'::bytea`} {
		if strings.Contains(sql, stale) {
			t.Errorf("baseline still accepts the v1 zero genesis via %q", stale)
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
