package main

import (
	"bytes"
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
