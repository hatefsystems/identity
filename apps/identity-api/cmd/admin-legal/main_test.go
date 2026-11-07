package main

import (
	"context"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestInvalidMaintenanceOptionsFailBeforeConnecting(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://must-not-be-used.invalid/test")
	for _, tc := range []struct {
		operation string
		limit     int
		file      string
		dry       bool
	}{
		{"", 500, "", false}, {"unknown", 500, "", false}, {"cleanup", 0, "", false},
		{"cleanup", 1001, "", false}, {"cleanup", 500, "", true}, {"backfill", 500, "", false},
	} {
		if err := run(context.Background(), options{operation: tc.operation, limit: tc.limit, policyFile: tc.file, dryRun: tc.dry}); err == nil || strings.Contains(err.Error(), "connect") {
			t.Fatalf("accepted invalid operation/options %+v", tc)
		}
	}
}

func TestOperationSpecificFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--operation=workflow-cleanup", "--limit=500", "--dry-run"},
		{"--operation=workflow-status", "--limit=1000"},
		{"--operation=cleanup", "--limit=1000"},
		{"--operation=policy-install", "--policy-file=approved.json"},
		{"--operation=lookup-probe"},
		{"--operation=ledger-receipts", "--limit=1000", "--receipt-proof-limit=10000"},
	} {
		if _, err := parseOptions(args); err != nil {
			t.Fatalf("valid options %v: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"--operation=backfill", "--limit=1000"},
		{"--operation=workflow-cleanup", "--limit=501"},
		{"--operation=workflow-status", "--limit=1001"},
		{"--operation=workflow-status", "--dry-run=false"},
		{"--operation=workflow-status", "--policy-file="},
		{"--operation=workflow-cleanup", "--receipt-proof-limit=1"},
		{"--operation=lookup-probe", "--limit=500"},
		{"--operation=policy-install", "--limit=500", "--policy-file=p.json"},
		{"--operation=policy-install"},
		{"--operation=cleanup", "--diagnostic"},
		{"--operation=ledger-receipts", "--dry-run"},
		{"--operation=ledger-receipts", "--receipt-proof-limit=0"},
		{"--operation=ledger-receipts", "--receipt-proof-limit=10001"},
		{"--operation=cleanup", "unexpected"},
	} {
		if _, err := parseOptions(args); err == nil {
			t.Fatalf("accepted unsupported options %v", args)
		}
	}
	opts, err := parseOptions([]string{"--operation=ledger-receipts"})
	if err != nil || opts.limit != 100 || opts.proofLimit != 1000 {
		t.Fatalf("receipt defaults=%+v %v", opts, err)
	}
}

func TestReceiptCredentialsNeverFallBack(t *testing.T) {
	t.Setenv("APP_ENV", "invalid-inspection-does-not-use-mode")
	t.Setenv("DATABASE_URL", "postgres://must-not-be-used.invalid/test")
	t.Setenv("LEDGER_RECEIPTS_DATABASE_URL", "")
	opts, err := parseOptions([]string{"--operation=ledger-receipts"})
	if err != nil {
		t.Fatal(err)
	}
	if err = run(context.Background(), opts); err == nil || err.Error() != "LEDGER_RECEIPTS_DATABASE_URL required" {
		t.Fatalf("receipt read credentials fell back: %v", err)
	}
}

func TestRemovedBackfillRejectsBeforeConfigurationOrDial(t *testing.T) {
	t.Setenv("APP_ENV", "")
	t.Setenv("DATABASE_URL", "invalid-connection-config")
	if _, err := parseOptions([]string{"--operation=backfill"}); err == nil || err.Error() != "invalid operation" {
		t.Fatalf("removed operation parsed: %v", err)
	}
	if err := run(context.Background(), options{operation: "backfill", limit: 500}); err == nil || err.Error() != "invalid operation" {
		t.Fatalf("removed operation accessed configuration or database: %v", err)
	}
}

func TestEnvironmentDependentOperationsRejectInvalidModesBeforeDial(t *testing.T) {
	t.Setenv("DATABASE_URL", "invalid-connection-config")
	for _, mode := range []string{"", " ", "production ", "Development", "staging", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("APP_ENV", mode)
			for _, operation := range []string{"cleanup", "lookup-probe", "policy-install", "workflow-cleanup", "workflow-status"} {
				opts := options{operation: operation, limit: 500}
				if operation == "policy-install" {
					opts.policyFile = "never-opened.json"
				}
				err := run(context.Background(), opts)
				if err == nil || !strings.Contains(err.Error(), "APP_ENV") {
					t.Fatalf("%s reached database before mode validation: %v", operation, err)
				}
			}
		})
	}
}

func TestHelpAndStatusOptionsDoNotLoadSecrets(t *testing.T) {
	t.Setenv("APP_ENV", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("MASTER_KEK", "")
	t.Setenv("BLIND_INDEX_PEPPER", "")
	if _, err := parseOptions([]string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help required runtime configuration: %v", err)
	}
	if _, err := parseOptions([]string{"--operation=workflow-status"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_ENV", "production")
	if err := run(context.Background(), options{operation: "workflow-status", limit: 500}); err == nil || err.Error() != "DATABASE_URL required" {
		t.Fatalf("read-only workflow status loaded application secrets: %v", err)
	}
}
