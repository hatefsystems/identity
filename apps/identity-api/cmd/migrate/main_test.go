package main

import (
	"strings"
	"testing"
)

func TestInvalidMigrationOptionsBeforeConnection(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	for _, args := range [][]string{nil, {"unknown"}, {"up", "19"}, {"up-to"}, {"up-to", "0"}, {"up-to", "-1"}, {"up-to", "019"}, {"up-to", "15", "20"}, {"up-to", "9223372036854775808"}} {
		if err := run(args); err == nil || strings.Contains(err.Error(), "DATABASE_URL") {
			t.Fatalf("options were not validated first: %v, %v", args, err)
		}
	}
	if err := run([]string{"up-to", "19"}); err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("valid cutover options: %v", err)
	}
}
