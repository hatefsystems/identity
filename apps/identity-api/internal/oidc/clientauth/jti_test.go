package clientauth

import (
	"context"
	"testing"
	"time"
)

func TestMemoryJTIGuardFirstUseSucceeds(t *testing.T) {
	g := NewMemoryJTIGuard()
	fresh, err := g.Remember(context.Background(), "abc", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if !fresh {
		t.Error("first use of a jti must report fresh")
	}
}

func TestMemoryJTIGuardReplayRejected(t *testing.T) {
	g := NewMemoryJTIGuard()
	exp := time.Now().Add(time.Minute)
	if fresh, _ := g.Remember(context.Background(), "abc", exp); !fresh {
		t.Fatal("first use should be fresh")
	}
	fresh, err := g.Remember(context.Background(), "abc", exp)
	if err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if fresh {
		t.Error("replayed jti must not report fresh")
	}
}

func TestMemoryJTIGuardExpiredEntryReusable(t *testing.T) {
	g := NewMemoryJTIGuard()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return base }

	// Record with a short expiry.
	if fresh, _ := g.Remember(context.Background(), "abc", base.Add(time.Second)); !fresh {
		t.Fatal("first use should be fresh")
	}

	// Advance beyond expiry: the same jti is now reusable (a replay would
	// anyway be rejected as an expired assertion upstream).
	g.now = func() time.Time { return base.Add(2 * time.Second) }
	fresh, err := g.Remember(context.Background(), "abc", base.Add(3*time.Second))
	if err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if !fresh {
		t.Error("expired jti entry should be reclaimable")
	}
}

func TestMemoryJTIGuardDistinctJTIs(t *testing.T) {
	g := NewMemoryJTIGuard()
	exp := time.Now().Add(time.Minute)
	if fresh, _ := g.Remember(context.Background(), "a", exp); !fresh {
		t.Error("jti a should be fresh")
	}
	if fresh, _ := g.Remember(context.Background(), "b", exp); !fresh {
		t.Error("jti b should be fresh")
	}
}
