package main

import (
	"strings"
	"testing"
)

func TestInvalidMigrationOptionsBeforeConnection(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	for _, args := range [][]string{nil, {"unknown"}, {"up", "1"}, {"up-to"}, {"up-to", "0"}, {"up-to", "-1"}, {"up-to", "01"}, {"up-to", "1", "2"}, {"up-to", "9223372036854775808"}} {
		if err := run(args); err == nil || strings.Contains(err.Error(), "DATABASE_URL") {
			t.Fatalf("options were not validated first: %v, %v", args, err)
		}
	}
	for _, command := range [][]string{{"up-to", "1"}, {"up-to", "2"}, {"status"}} {
		if err := run(command); err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
			t.Fatalf("valid migration options %v: %v", command, err)
		}
	}
}
