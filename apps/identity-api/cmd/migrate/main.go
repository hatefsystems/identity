// Command migrate applies the embedded goose SQL migrations (db/migrations)
// to the PostgreSQL instance addressed by DATABASE_URL.
//
// Usage:
//
//	migrate up      apply all pending migrations
//	migrate up-to N apply pending migrations through version N
//	migrate down    roll back a future migration; baseline is forward-only
//	migrate reset   refuse reset; fresh setup requires separate explicit scope
//	migrate status  print per-migration applied state without changing the DB
//
// DATABASE_URL is read from the environment (see .env.example); credentials
// are never hardcoded (DoD #3).
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
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
	if len(args) == 0 {
		return fmt.Errorf("usage: migrate <up|up-to VERSION|down|reset|status>")
	}
	command := args[0]
	var target int64
	if command == "up-to" {
		if len(args) != 2 {
			return fmt.Errorf("usage: migrate up-to VERSION")
		}
		var err error
		target, err = strconv.ParseInt(args[1], 10, 64)
		if err != nil || target < 1 || strconv.FormatInt(target, 10) != args[1] {
			return fmt.Errorf("migrate: version must be a positive decimal integer")
		}
	} else if len(args) != 1 || (command != "up" && command != "down" && command != "reset" && command != "status") {
		return fmt.Errorf("usage: migrate <up|up-to VERSION|down|reset|status>")
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	sqldb, err := migrate.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer func() { _ = sqldb.Close() }()

	switch command {
	case "up-to":
		if err := migrate.UpTo(ctx, sqldb, target); err != nil {
			return err
		}
		fmt.Printf("migrations applied through version %d\n", target)
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
