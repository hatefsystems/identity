package main

import (
	"context"
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
		{"cleanup", 1001, "", false}, {"cleanup", 500, "", true}, {"backfill", 500, "artifact.json", false},
	} {
		if err := run(context.Background(), tc.operation, tc.limit, tc.file, tc.dry); err == nil {
			t.Fatalf("accepted invalid operation/options %+v", tc)
		}
	}
}
