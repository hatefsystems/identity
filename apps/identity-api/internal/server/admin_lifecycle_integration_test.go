//go:build integration

package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
)

func TestAdminLifecycleTransitionsIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	ctx := context.Background()
	previousAuth := f.target.AuthVersion
	for i, tc := range []struct {
		status   string
		revision int64
		subject  string
	}{
		{"suspended", 1, lifecycle.SubjectSuspended},
		{"suspended", 1, lifecycle.SubjectSuspended},
		{"banned", 2, lifecycle.SubjectUpdated},
		{"active", 3, lifecycle.SubjectUpdated},
	} {
		response := f.request(t, "moderator", "PATCH", "/users/"+f.target.ID.String()+"/status",
			`{"status":"`+tc.status+`","reason":"restricted lifecycle test reason"}`, f.grant(t, "moderator"))
		if response.Code != http.StatusNoContent {
			t.Fatalf("moderation %d: status %d", i, response.Code)
		}
		user, err := db.New(f.pool).GetUserByIDForAdmin(ctx, f.target.ID)
		if err != nil || user.Status != tc.status || user.LifecycleRevision != tc.revision || user.AuthVersion != previousAuth+1 {
			t.Fatalf("lifecycle/security revision mismatch after transition %d: %v", i, err)
		}
		previousAuth = user.AuthVersion
		var count int64
		if err := f.pool.QueryRow(ctx, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND NOT admin_action", user.ID).Scan(&count); err != nil || count != tc.revision {
			t.Fatalf("same-state moderation emitted a lifecycle event: %d, %v", count, err)
		}
		var payload string
		if err := f.pool.QueryRow(ctx, "SELECT payload FROM event_outbox WHERE lifecycle_user_id=$1 AND lifecycle_revision=$2", user.ID, tc.revision).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		event, err := lifecycle.UnmarshalEvent([]byte(payload))
		if err != nil || event.EventType != tc.subject || strconv.FormatUint(event.GetRevision(), 10) != strconv.FormatInt(tc.revision, 10) || strings.Contains(payload, user.Email) || strings.Contains(payload, "restricted lifecycle test reason") {
			t.Fatalf("invalid or sensitive lifecycle metadata: %v", err)
		}
	}
}

type rejectLifecycleBeginner struct{ pool *pgxpool.Pool }

func (b rejectLifecycleBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return rejectLifecycleTx{tx}, nil
}

type rejectLifecycleTx struct{ pgx.Tx }

func (tx rejectLifecycleTx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(query, "-- name: InsertLifecycleEvent") {
		return pgconn.CommandTag{}, errors.New("injected lifecycle failure")
	}
	return tx.Tx.Exec(ctx, query, args...)
}

func TestLifecycleFailureRollsBackModerationIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	actions, err := adminaction.New(rejectLifecycleBeginner{f.pool}, f.enc, "identity.audit.admin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.deps.AdminActions = actions
	response := f.request(t, "moderator", "PATCH", "/users/"+f.target.ID.String()+"/status",
		`{"status":"suspended","reason":"must not commit"}`, f.grant(t, "moderator"))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing lifecycle intent returned success: %d", response.Code)
	}
	user, err := db.New(f.pool).GetUserByIDForAdmin(context.Background(), f.target.ID)
	if err != nil || user.Status != f.target.Status || user.AuthVersion != f.target.AuthVersion || user.LifecycleRevision != 0 {
		t.Fatalf("lifecycle failure committed account state: %v", err)
	}
}
