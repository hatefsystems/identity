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
	expected := []string{"00001_initial_schema.sql", "00002_registration_attempts.sql", "00003_username_reservations.sql", "00004_geography_catalog.sql", "00005_private_account_data.sql", "00006_optional_email_contact_evidence.sql", "00007_account_deletion_action_proofs.sql", "00008_password_change_action_proofs.sql", "00009_first_passkey_enrollment_action_proofs.sql", "00010_mfa_enrollment_authorization.sql", "00011_contact_management.sql"}
	if len(entries) != len(expected) {
		t.Fatalf("binary must embed the complete launch migration inventory: %v", entries)
	}
	for i, name := range expected {
		if entries[i].Name() != name {
			t.Fatalf("unexpected bundled migration: %s", entries[i].Name())
		}
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
	if len(sources) != len(expected) {
		t.Fatalf("unexpected bundled runner sources: %+v", sources)
	}
	for i, name := range expected {
		if sources[i].Version != int64(i+1) || sources[i].Path != name {
			t.Fatalf("unexpected bundled runner source: %+v", sources[i])
		}
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
