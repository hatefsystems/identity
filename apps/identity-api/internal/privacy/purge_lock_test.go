package privacy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPurgeHeldOldestDoesNotStarveUnheld(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 2})
	for i := 0; i < 4; i++ {
		id := h.world.addPendingUser(h.clock.now(), 10*time.Hour)
		h.world.holds[id] = true
	}
	unheld := h.world.addPendingUser(h.clock.now(), 2*time.Hour)
	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.world.exists(unheld) || stats.Purged != 1 || stats.SkippedLegalHold != 1 {
		t.Fatalf("held batch starved deletion or skip audit: %+v", stats)
	}
}

func TestPurgeAccountLockFailureIsClosed(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 2})
	id := h.world.addPendingUser(h.clock.now(), 2*time.Hour)
	h.world.accountLockErr = errors.New("lock unavailable")
	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !h.world.exists(id) || stats.Failed != 1 || h.world.deleteCalls != 0 || h.world.committed != 0 {
		t.Fatalf("purge proceeded without account lock: %+v", stats)
	}
}
