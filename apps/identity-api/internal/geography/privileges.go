package geography

import (
	"context"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/dbprivilege"
)

// CheckPrivileges proves a dedicated reader/importer login without modifying ACLs.
// The CLI calls it before check/import; the API's existing runtime pool is separate.
func CheckPrivileges(ctx context.Context, database db.DBTX, importer bool) error {
	tables := []dbprivilege.Table{
		{Name: "public.geography_catalogs", Select: true},
		{Name: "public.geography_types", Select: true},
		{Name: "public.geography_places", Select: true},
		{Name: "public.geography_place_versions", Select: true},
		{Name: "public.geography_catalog_state", Select: true},
	}
	if importer {
		tables[0].InsertColumns = []string{"revision", "country", "source_release", "cities_sha256", "types_sha256", "cities_bytes", "types_bytes", "place_count", "type_count", "province_count", "importer_version", "normalization_version"}
		tables[1].Insert = true
		tables[2].Insert = true
		tables[3].Insert = true
		tables[2].UpdateColumns = []string{"last_seen_revision"}
		tables[4].UpdateColumns = []string{"active_revision"}
	}
	guards := make([]dbprivilege.Guard, 0, 10)
	for _, g := range []struct{ table, name, truncate string }{
		{"geography_catalogs", "geography_catalogs_guard", "geography_catalogs_no_truncate"},
		{"geography_types", "geography_types_guard", "geography_types_no_truncate"},
		{"geography_places", "geography_places_guard", "geography_places_no_truncate"},
		{"geography_place_versions", "geography_versions_guard", "geography_versions_no_truncate"},
		{"geography_catalog_state", "geography_state_guard", "geography_state_no_truncate"},
	} {
		guards = append(guards, dbprivilege.Guard{Table: "public." + g.table, Name: g.name, Function: "public.geography_catalog_guard()", Type: 31},
			dbprivilege.Guard{Table: "public." + g.table, Name: g.truncate, Function: "public.geography_catalog_guard()", Type: 34})
	}
	if dbprivilege.Check(ctx, database, dbprivilege.Contract{Tables: tables, Guards: guards}) != nil {
		return ErrUnavailable
	}
	return nil
}
