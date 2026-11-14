// Command username is an operator-only inactive installer/read-only preflight.
// There is intentionally no activation, cutover, rename, clear or reindex command.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, diagnostic io.Writer) int {
	fail := func(message string) int { _, _ = fmt.Fprintln(diagnostic, "username: "+message); return 1 }
	if len(args) == 0 || (args[0] != "install" && args[0] != "preflight") {
		return fail("use install (inactive only) or preflight (read-only); activation/reindex unavailable")
	}
	mode := args[0]
	flags := flag.NewFlagSet("username", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	maxRows := flags.Int64("max-rows", 100000, "maximum surviving accounts to inspect; a capped scan is incomplete")
	pageSize := flags.Int("page-size", 250, "bounded account SQL page size (1..1000)")
	maxIssues := flags.Int("max-issues", 100, "maximum restricted review issues (1..1000)")
	timeout := flags.Duration("timeout", 5*time.Minute, "total operation deadline (1s..1h)")
	candidatePolicy := flags.String("candidate-policy", "", "inactive installed candidate policy JSON file")
	candidateRegex := flags.String("candidate-regex", "", "candidate regex source file (exact bytes; no trimming)")
	candidateKeyID := flags.String("candidate-key-id", "", "candidate lookup key identifier")
	candidateKeyEnv := flags.String("candidate-key-env", "", "environment variable holding candidate base64 lookup key")
	parseErr := flags.Parse(args[1:])
	if parseErr == flag.ErrHelp {
		_, _ = fmt.Fprintln(out, "username install: immutable inactive installation only; username preflight: read-only snapshot, never activation")
		flags.SetOutput(out)
		flags.PrintDefaults()
		_, _ = fmt.Fprintln(out, "Requires enabled USERNAME_* configuration and a separately provisioned operator DATABASE_URL; preflight also requires USERNAME_REVIEW_KEY and envelope configuration.")
		return 0
	}
	if parseErr != nil || flags.NArg() != 0 {
		return fail("invalid arguments")
	}
	if *timeout < time.Second || *timeout > time.Hour || *pageSize < 1 || *pageSize > 1000 || *maxRows < 1 || *maxRows > 1000000 || *maxIssues < 1 || *maxIssues > 1000 {
		return fail("operation bounds are invalid")
	}
	cfg, err := config.LoadUsername()
	if err != nil || !cfg.Enabled || cfg.Normalizer == nil {
		return fail("enabled username configuration is required")
	}
	n := cfg.Normalizer
	candidate := n
	hasCandidate := *candidatePolicy != "" || *candidateRegex != "" || *candidateKeyID != "" || *candidateKeyEnv != ""
	if hasCandidate {
		if mode != "preflight" || *candidatePolicy == "" || *candidateRegex == "" || *candidateKeyID == "" || *candidateKeyEnv == "" {
			return fail("complete candidate options are required for preflight only")
		}
		raw, err := readBounded(*candidatePolicy, username.MaxArtifactBytes)
		if err != nil {
			return fail("candidate policy cannot be read")
		}
		policy, err := username.DecodePolicy(raw)
		clear(raw)
		if err != nil {
			return fail("candidate policy is invalid or not approved")
		}
		regex, err := readBounded(*candidateRegex, username.MaxRegexBytes)
		if err != nil {
			return fail("candidate regex cannot be read")
		}
		key, err := base64.StdEncoding.DecodeString(os.Getenv(*candidateKeyEnv))
		if err != nil || len(key) < 32 {
			clear(key)
			return fail("candidate key configuration is invalid")
		}
		candidate, err = username.New(policy, string(regex), key, *candidateKeyID)
		clear(key)
		if err != nil {
			return fail("candidate normalizer is invalid or not approved")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fail("operator DATABASE_URL is required")
	}
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fail("operator database configuration is invalid")
	}
	poolCfg.MaxConns = 1
	poolCfg.ConnConfig.ConnectTimeout = 5 * time.Second
	poolCfg.ConnConfig.RuntimeParams["application_name"] = "username-operator"
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fail("operator database is unavailable")
	}
	defer pool.Close()
	if mode == "install" {
		if err := username.InstallInactive(ctx, pool, n); err != nil {
			return fail("inactive installation failed; privileges or immutable identity unproven")
		}
		if json.NewEncoder(out).Encode(struct {
			Installed bool `json:"installed"`
			Active    bool `json:"active"`
		}{true, false}) != nil {
			return fail("report write failed")
		}
		return 0
	}
	reviewKey, err := base64.StdEncoding.DecodeString(os.Getenv("USERNAME_REVIEW_KEY"))
	if err != nil || len(reviewKey) < 32 {
		clear(reviewKey)
		return fail("independent USERNAME_REVIEW_KEY is required for restricted references")
	}
	defer clear(reviewKey)
	cryptoCfg, err := config.LoadEnvelopeCrypto()
	if err != nil {
		return fail("envelope configuration is required")
	}
	provider, err := kms.NewMockProvider(cryptoCfg.MasterKEK, cryptoCfg.MasterKEKVersion)
	clear(cryptoCfg.MasterKEK)
	if err != nil {
		return fail("envelope provider is unavailable")
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		return fail("envelope provider is unavailable")
	}
	report, err := username.Preflight(ctx, pool, cipher, n, candidate, username.PreflightOptions{
		PageSize: int32(*pageSize), MaxRows: *maxRows, MaxIssues: *maxIssues, Timeout: *timeout, ReviewKey: reviewKey,
	})
	if json.NewEncoder(out).Encode(report) != nil {
		return fail("report write failed")
	}
	if err != nil || !report.Complete || !report.Clean {
		return 1
	}
	return 0
}

func readBounded(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return nil, fmt.Errorf("input exceeds resource bound")
	}
	return raw, nil
}
