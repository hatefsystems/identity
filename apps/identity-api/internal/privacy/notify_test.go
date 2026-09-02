package privacy

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestLogNotifierRedactsTokenAndAddresses is the reason LogNotifier exists as a
// distinct type rather than a closure: a development log that contained the reclaim
// token would itself be a way to reclaim an account, and one that contained the
// addresses would leak Class A PII into a stream with no retention policy.
func TestLogNotifierRedactsTokenAndAddresses(t *testing.T) {
	var buf bytes.Buffer
	notifier := NewLogNotifier(slog.New(slog.NewJSONHandler(&buf, nil)))

	const (
		token   = "n0tAr3alTok3nButLooksLikeOne_0123456789abcdef"
		primary = "primary@example.test"
		backup  = "backup@example.test"
	)
	backupAddr := backup
	expires := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

	if err := notifier.NotifyDeletionRequested(context.Background(), DeletionNotice{
		PrimaryEmail: primary,
		BackupEmail:  &backupAddr,
		ReclaimToken: token,
		ExpiresAt:    expires,
	}); err != nil {
		t.Fatalf("NotifyDeletionRequested: %v", err)
	}

	out := buf.String()
	for _, secret := range []string{token, primary, backup} {
		if strings.Contains(out, secret) {
			t.Errorf("log line leaked %q: %s", secret, out)
		}
	}
	// The non-sensitive diagnostics must survive, or the line is useless locally.
	if !strings.Contains(out, "has_backup_email") {
		t.Errorf("log line dropped has_backup_email: %s", out)
	}
	if !strings.Contains(out, "2026-04-01") {
		t.Errorf("log line dropped the expiry: %s", out)
	}
}

// TestLogNotifierIsMarkedDevelopmentOnly: wiring relies on this marker to keep the
// deletion routes unmounted outside development, so it must never report false.
func TestLogNotifierIsMarkedDevelopmentOnly(t *testing.T) {
	if !NewLogNotifier(nil).IsDevelopmentOnly() {
		t.Fatal("LogNotifier.IsDevelopmentOnly() = false; it delivers nothing and must never gate a real recovery window")
	}
}

func TestLogNotifierNilLoggerFallback(t *testing.T) {
	if err := NewLogNotifier(nil).NotifyDeletionRequested(
		context.Background(), DeletionNotice{}); err != nil {
		t.Fatalf("NotifyDeletionRequested with a nil logger: %v", err)
	}
}

// TestNotifierInterfaceIsSatisfied documents the seam production will replace.
func TestNotifierInterfaceIsSatisfied(_ *testing.T) {
	var _ Notifier = NewLogNotifier(nil)
}
