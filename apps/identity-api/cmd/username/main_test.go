package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorDoesNotExposeActivationOrReindex(t *testing.T) {
	for _, command := range []string{"activate", "cutover", "reindex", "rename", "clear"} {
		var out, diagnostic bytes.Buffer
		if run([]string{command}, &out, &diagnostic) == 0 || out.Len() != 0 || !strings.Contains(diagnostic.String(), "activation/reindex unavailable") {
			t.Fatal("unexpected operational authority")
		}
	}
}

func TestOperatorBoundsFailBeforeDatabase(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if run([]string{"preflight", "--max-rows=0"}, &out, &diagnostic) == 0 || out.Len() != 0 || !strings.Contains(diagnostic.String(), "bounds are invalid") {
		t.Fatal("unbounded scan accepted")
	}
}

func TestOperatorHelpDoesNotOpenDatabase(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if run([]string{"preflight", "--help"}, &out, &diagnostic) != 0 || diagnostic.Len() != 0 || !strings.Contains(out.String(), "max-rows") || !strings.Contains(out.String(), "never activation") {
		t.Fatal("operator help unavailable")
	}
}

func TestReadBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "candidate")
	raw := []byte("exact bytes\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		path  string
		limit int
		fail  bool
	}{
		{"exact bound", path, len(raw), false},
		{"redundant separator", dir + "/./candidate", len(raw), false},
		{"over bound", path, len(raw) - 1, true},
		{"missing file", filepath.Join(dir, "missing"), len(raw), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readBounded(tc.path, tc.limit)
			if (err != nil) != tc.fail || (!tc.fail && !bytes.Equal(got, raw)) {
				t.Fatalf("bounded read failed: error=%v", err)
			}
		})
	}
}
