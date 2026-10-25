package webauthn

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

func TestRegistrationNameFrozenAcrossRedisInstances(t *testing.T) {
	f := newFixture(t)
	_, stores := redisChallengeStores(t)
	for _, store := range stores {
		store.now = f.svc.now
	}
	f.svc.challenges = stores[0]
	other, err := New(testConfig(), f.users, f.creds, stores[1])
	if err != nil {
		t.Fatal(err)
	}
	other.now = f.svc.now
	options, err := f.svc.BeginRegistration(f.ctx(), f.user.ID, "test-session", "  Personal \u06a9\u0644\u06cc\u062f  ")
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(f.auth.attestation(challengeOf(options.Response.Challenge)), &response); err != nil {
		t.Fatal(err)
	}
	response["name"] = json.RawMessage(`"Injected replacement"`)
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	row, err := other.FinishRegistration(f.ctx(), f.user.ID, "test-session", body)
	if err != nil || row.Name != "Personal \u06a9\u0644\u06cc\u062f" {
		t.Fatalf("pending name was not preserved: %q, %v", row.Name, err)
	}
	listed, err := f.svc.ListCredentials(f.ctx(), f.user.ID)
	if err != nil || len(listed) != 1 || listed[0].Name != row.Name {
		t.Fatalf("persisted named credential: %+v %v", listed, err)
	}
}

func TestRegistrationInvalidNameCannotAllocateChallenge(t *testing.T) {
	for _, name := range []string{strings.Repeat("x", 81), "\xff", "line\nbreak", "tab\tname", "\u2028name", "name\u007f"} {
		f := newFixture(t)
		if _, err := f.svc.BeginRegistration(f.ctx(), f.user.ID, "test-session", name); !errors.Is(err, profile.ErrInvalidName) {
			t.Fatalf("invalid name accepted: %v", err)
		}
		if len(f.challenges.byChallenge) != 0 || f.creds.count(f.user.ID) != 0 {
			t.Fatal("invalid name allocated ceremony or credential state")
		}
	}
}

func TestRenameCredentialIsCosmeticAndOwnerScoped(t *testing.T) {
	f := newFixture(t)
	original := f.register(t, f.auth)
	before := f.users.mustGet(t, f.user.ID)
	for _, name := range []string{"  First name  ", "\u06a9\u0644\u06cc\u062f", ""} {
		row, err := f.svc.RenameCredential(f.ctx(), f.user.ID, original.ID, name)
		if err != nil || row.Name != strings.TrimSpace(name) || !bytes.Equal(row.PublicKey, original.PublicKey) || row.SignCount != original.SignCount || row.UserID != original.UserID {
			t.Fatalf("rename changed authority or lost the name: %+v %v", row, err)
		}
	}
	if after := f.users.mustGet(t, f.user.ID); after.AuthVersion != before.AuthVersion || after.LifecycleRevision != before.LifecycleRevision || f.creds.count(f.user.ID) != 1 {
		t.Fatal("cosmetic rename changed account authority or final-key count")
	}
	foreign := db.User{ID: uuid.New(), Email: "other@example.invalid", Status: "active"}
	f.users.byID[foreign.ID] = foreign
	for _, target := range []struct {
		user uuid.UUID
		id   []byte
	}{
		{foreign.ID, original.ID}, {f.user.ID, []byte("missing")}, {f.user.ID, nil},
	} {
		if _, err := f.svc.RenameCredential(f.ctx(), target.user, target.id, "New name"); !errors.Is(err, ErrCredentialNotFound) {
			t.Fatalf("foreign/missing credential was distinguishable: %v", err)
		}
	}
	if _, err := f.svc.RenameCredential(f.ctx(), f.user.ID, original.ID, "bad\nname"); !errors.Is(err, profile.ErrInvalidName) {
		t.Fatalf("invalid rename: %v", err)
	}
	f.creds.renameErr = errBoom
	if _, err := f.svc.RenameCredential(f.ctx(), f.user.ID, original.ID, "New name"); !errors.Is(err, errBoom) {
		t.Fatalf("rename swallowed store outage: %v", err)
	}
}

func TestRenameCredentialRechecksCapturedAuthorityUnderLock(t *testing.T) {
	for _, changedVersion := range []bool{false, true} {
		f := newFixture(t)
		row := f.register(t, f.auth)
		f.svc.accounts = &ceremonyEpoch{}
		ctx := session.WithSession(f.ctx(), session.Session{
			ID: "test-session", UserID: f.user.ID.String(), AuthVersionSet: true,
			Kind: session.KindAuthenticated, DPoPJKT: testBrowserJKT,
		})
		user := f.users.mustGet(t, f.user.ID)
		if changedVersion {
			user.AuthVersion++
		} else {
			user.Status = "suspended"
		}
		f.users.byID[user.ID] = user
		if _, err := f.svc.RenameCredential(ctx, user.ID, row.ID, "Not saved"); !errors.Is(err, ErrAccountNotActive) {
			t.Fatalf("stale account authority renamed a credential: %v", err)
		}
		if f.creds.byUser[user.ID][0].Name != "" {
			t.Fatal("rejected rename mutated credential")
		}
	}
}
