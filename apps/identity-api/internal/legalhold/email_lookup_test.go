package legalhold

import (
	"context"
	"errors"
	"testing"
)

func TestLookupCursorScopeUsesCanonicalEmailWithoutCompatibilityFolding(t *testing.T) {
	s, store, req := lookupFixture(t)
	req.Identifier = "\u00fcser@example.test"
	index, err := s.indexer.ComputeEmail(req.Identifier)
	if err != nil {
		t.Fatal(err)
	}
	for i := range store.events {
		store.events[i].IdentityBlindIndex = &index
	}
	first, err := s.Lookup(context.Background(), req)
	if err != nil || first.NextCursor == "" {
		t.Fatalf("canonical lookup did not produce a continuation: %v", err)
	}
	req.Cursor = first.NextCursor
	req.Identifier = " U\u0308SER@EXAMPLE.TEST "
	if _, err := s.Lookup(context.Background(), req); err != nil {
		t.Fatalf("canonical-equivalent identifier changed cursor scope: %v", err)
	}
	req.Identifier = "\uff55\u0308ser@example.test"
	if _, err := s.Lookup(context.Background(), req); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("NFKC-distinct identifier reused cursor scope: %v", err)
	}
}
