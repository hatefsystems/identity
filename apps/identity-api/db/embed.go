// Package db exposes the SQL migration files as an embedded filesystem so the
// migration runner (cmd/migrate) and integration tests apply the exact same
// migrations that ship inside the compiled binary — no on-disk path coupling.
package db

import "embed"

// Migrations contains the goose-versioned SQL migration files. sqlc reads the
// same files from db/migrations as its schema source (see sqlc.yaml), keeping
// the generated code and the applied schema in lockstep.
//
//go:embed migrations/*.sql
var Migrations embed.FS
