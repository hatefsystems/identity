// Command geography validates and imports explicit operator-owned full snapshots.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/geography"
)

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "geography:", err)
		os.Exit(1)
	}
}
func run(args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 || args[0] != "check" && args[0] != "import" {
		return fmt.Errorf("usage: geography <check|import> --cities=PATH --types=PATH --manifest=PATH")
	}
	command := args[0]
	flags := flag.NewFlagSet("geography "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cities := flags.String("cities", "", "explicit complete places file")
	types := flags.String("types", "", "explicit types file")
	manifest := flags.String("manifest", "", "operator-prepared complete snapshot manifest")
	apply := flags.String("apply-plan", "", "checked change-plan digest")
	retirement := flags.String("retirement-digest", "", "checked retirement acknowledgement")
	seen := make(map[string]bool)
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
			if seen[name] {
				return geography.ErrInvalid
			}
			seen[name] = true
		}
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *cities == "" || *types == "" || *manifest == "" || command == "check" && (seen["apply-plan"] || seen["retirement-digest"]) || command == "import" && *apply == "" {
		return geography.ErrInvalid
	}
	env := "GEOGRAPHY_CHECK_DATABASE_URL"
	if command == "import" {
		env = "GEOGRAPHY_IMPORT_DATABASE_URL"
	}
	dsn := strings.TrimSpace(getenv(env))
	if dsn == "" {
		return fmt.Errorf("%s is required", env)
	}
	snapshot, err := geography.Load(*cities, *types, *manifest)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return geography.ErrUnavailable
	}
	config.MaxConns = 1
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	config.ConnConfig.RuntimeParams["application_name"] = "geography-operator"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return geography.ErrUnavailable
	}
	defer pool.Close()
	if err := geography.CheckPrivileges(ctx, pool, command == "import"); err != nil {
		return err
	}
	service := geography.New(pool)
	var plan geography.Plan
	if command == "check" {
		plan, err = service.Check(ctx, snapshot)
	} else {
		plan, err = service.Import(ctx, snapshot, *apply, *retirement)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(plan)
}
