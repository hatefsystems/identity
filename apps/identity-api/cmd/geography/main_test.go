package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIExplicitCredentialBoundary(t *testing.T) {
	for _, command := range []string{"check", "import"} {
		args := []string{command, "--cities=/nonexistent", "--types=/nonexistent", "--manifest=/nonexistent"}
		if command == "import" {
			args = append(args, "--apply-plan="+strings.Repeat("0", 64))
		}
		var accessed []string
		var output bytes.Buffer
		err := run(args, func(key string) string {
			accessed = append(accessed, key)
			if key == "DATABASE_URL" {
				return "private-credential"
			}
			return ""
		}, &output)
		env := "GEOGRAPHY_CHECK_DATABASE_URL"
		if command == "import" {
			env = "GEOGRAPHY_IMPORT_DATABASE_URL"
		}
		if err == nil || err.Error() != env+" is required" || len(accessed) != 1 || accessed[0] != env || output.Len() != 0 {
			t.Fatal("credential boundary", err, accessed)
		}
	}
}
func TestCLIRejectsAmbiguousOrUnsafeArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"up"}, {"check"}, {"import", "--cities=x", "--types=y", "--manifest=z"}, {"check", "--cities=x", "--cities=y", "--types=y", "--manifest=z"}, {"check", "--cities=x", "--types=y", "--manifest=z", "--apply-plan=x"}, {"check", "--cities=x", "--types=y", "--manifest=z", "unexpected"}} {
		if run(args, func(string) string { t.Fatal("invalid flags reached credentials"); return "" }, &bytes.Buffer{}) == nil {
			t.Fatal("invalid args accepted")
		}
	}
}
