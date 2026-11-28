package migrate

import (
	"context"
	"strings"
	"testing"
)

func TestPrivateProfileRevisionMigrationPreservesUnboundRows(t *testing.T) {
	for _, populated := range []bool{false, true} {
		name := "empty"
		if populated {
			name = "populated"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
			defer cancel()
			database := openTestDB(ctx, t)
			provider, err := NewProvider(database)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.UpTo(ctx, 11); err != nil {
				t.Fatal(err)
			}
			if populated {
				execFixture(ctx, t, database, `WITH account AS (
					INSERT INTO users(email,status) VALUES ('private-migration@fixture.invalid','active') RETURNING id
				) INSERT INTO private_profile(account_id,details_encrypted) SELECT id,decode(repeat('ab',100),'hex') FROM account`)
			}
			_, err = provider.Up(ctx)
			if populated {
				if err == nil || !strings.Contains(err.Error(), "requires an empty private_profile table") {
					t.Fatal("migration must refuse existing unbound ciphertext", err)
				}
				var preserved bool
				if err := database.QueryRowContext(ctx, `SELECT count(*)=1 AND bool_and(details_encrypted=decode(repeat('ab',100),'hex')) FROM private_profile`).Scan(&preserved); err != nil || !preserved {
					t.Fatal("migration refusal changed the stored bytes")
				}
				if version, err := provider.GetDBVersion(ctx); err != nil || version != 11 {
					t.Fatal("migration refusal advanced lineage", version, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var required bool
			if err := database.QueryRowContext(ctx, `SELECT is_nullable='NO' FROM information_schema.columns WHERE table_schema='public' AND table_name='private_profile' AND column_name='profile_revision'`).Scan(&required); err != nil || !required {
				t.Fatal("private write revision is missing or optional")
			}
			if _, err := provider.Down(ctx); err == nil || !strings.Contains(err.Error(), "forward-only") {
				t.Fatal("private profile migration allowed rollback", err)
			}
			if version, err := provider.GetDBVersion(ctx); err != nil || version != 12 {
				t.Fatal("private profile migration did not advance and preserve lineage", version, err)
			}
		})
	}
}
