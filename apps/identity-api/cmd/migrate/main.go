// Command migrate applies the embedded goose SQL migrations (db/migrations)
// to the PostgreSQL instance addressed by DATABASE_URL.
//
// Usage:
//
//	migrate up      apply all pending migrations
//	migrate down    roll back the most recent migration
//	migrate reset   roll back everything (dev/test only)
//	migrate status  print per-migration applied state
//
// DATABASE_URL is read from the environment (see .env.example); credentials
// are never hardcoded (DoD #3).
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

// commandTimeout bounds a single migration run so a wedged database lock
// fails loudly instead of hanging CI forever.
const commandTimeout = 2 * time.Minute

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: migrate <up|down|reset|status>")
	}
	command := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	sqldb, err := migrate.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer func() { _ = sqldb.Close() }()

	switch command {
	case "up":
		if err := migrate.Up(ctx, sqldb); err != nil {
			return err
		}
		fmt.Println("migrations applied")
	case "down":
		if err := migrate.Down(ctx, sqldb); err != nil {
			return err
		}
		fmt.Println("rolled back one migration")
	case "reset":
		if err := migrate.Reset(ctx, sqldb); err != nil {
			return err
		}
		fmt.Println("rolled back all migrations")
	case "status":
		statuses, err := migrate.Status(ctx, sqldb)
		if err != nil {
			return err
		}
		for _, s := range statuses {
			fmt.Printf("%-10s %s\n", s.State, s.Source.Path)
		}
	default:
		return fmt.Errorf("unknown command %q (expected up, down, reset, or status)", command)
	}
	return nil
}
