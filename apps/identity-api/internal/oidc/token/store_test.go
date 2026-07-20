package token

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNewSecret(t *testing.T) {
	secret, hash, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	if secret == "" || hash == "" {
		t.Fatal("NewSecret returned empty secret or hash")
	}
	if HashSecret(secret) != hash {
		t.Error("hash does not match HashSecret(secret)")
	}

	other, _, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	if secret == other {
		t.Error("two generated secrets must differ")
	}
}

func TestMemoryCodeStoreConsumeSingleUse(t *testing.T) {
	store := NewMemoryCodeStore()
	data := AuthorizationCodeData{ClientID: "app", UserID: "user-1", ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.Save("hash-1", data); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Consume("hash-1")
	if err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if got.ClientID != "app" || got.UserID != "user-1" {
		t.Errorf("Consume returned wrong data: %+v", got)
	}

	if _, err := store.Consume("hash-1"); !errors.Is(err, ErrCodeNotFound) {
		t.Errorf("second Consume: want ErrCodeNotFound, got %v", err)
	}
}

func TestMemoryCodeStoreConsumeConcurrent(t *testing.T) {
	store := NewMemoryCodeStore()
	if err := store.Save("hash-c", AuthorizationCodeData{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	const attempts = 32
	var wg sync.WaitGroup
	wins := make(chan struct{}, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Consume("hash-c"); err == nil {
				wins <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(wins)

	var winners int
	for range wins {
		winners++
	}
	if winners != 1 {
		t.Errorf("exactly one concurrent Consume must win, got %d", winners)
	}
}

func TestMemoryCodeStoreExpiry(t *testing.T) {
	store := NewMemoryCodeStore()
	base := time.Now()
	store.now = func() time.Time { return base.Add(2 * time.Minute) }
	if err := store.Save("hash-e", AuthorizationCodeData{ExpiresAt: base.Add(time.Minute)}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := store.Consume("hash-e"); !errors.Is(err, ErrCodeNotFound) {
		t.Errorf("expired code: want ErrCodeNotFound, got %v", err)
	}
}

func TestMemoryRefreshTokenStoreLifecycle(t *testing.T) {
	store := NewMemoryRefreshTokenStore()
	data := RefreshTokenData{
		FamilyID:  "fam-1",
		UserID:    "user-1",
		ClientID:  "app",
		Status:    StatusActive,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.Save("h1", data); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Get("h1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusActive {
		t.Errorf("fresh token status = %q, want active", got.Status)
	}

	if err := store.MarkRotated("h1"); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	got, err = store.Get("h1")
	if err != nil {
		t.Fatalf("Get after rotate: %v", err)
	}
	if got.Status != StatusRotated {
		t.Errorf("rotated token status = %q, want rotated", got.Status)
	}

	if err := store.MarkRotated("missing"); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("MarkRotated on missing hash: want ErrRefreshTokenNotFound, got %v", err)
	}
}

func TestMemoryRefreshTokenStoreExpiry(t *testing.T) {
	store := NewMemoryRefreshTokenStore()
	base := time.Now()
	store.now = func() time.Time { return base.Add(2 * time.Hour) }
	if err := store.Save("h-exp", RefreshTokenData{Status: StatusActive, ExpiresAt: base.Add(time.Hour)}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := store.Get("h-exp"); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("expired token: want ErrRefreshTokenNotFound, got %v", err)
	}
}

func TestMemoryRefreshTokenStoreRevokeFamily(t *testing.T) {
	store := NewMemoryRefreshTokenStore()
	exp := time.Now().Add(time.Hour)
	mustSave(t, store, "f1-a", RefreshTokenData{FamilyID: "fam-1", UserID: "u1", Status: StatusRotated, ExpiresAt: exp})
	mustSave(t, store, "f1-b", RefreshTokenData{FamilyID: "fam-1", UserID: "u1", Status: StatusActive, ExpiresAt: exp})
	mustSave(t, store, "f2-a", RefreshTokenData{FamilyID: "fam-2", UserID: "u1", Status: StatusActive, ExpiresAt: exp})

	if err := store.RevokeFamily("fam-1"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	assertStatus(t, store, "f1-a", StatusRevoked)
	assertStatus(t, store, "f1-b", StatusRevoked)
	assertStatus(t, store, "f2-a", StatusActive)
}

func TestMemoryRefreshTokenStoreRevokeAllForUser(t *testing.T) {
	store := NewMemoryRefreshTokenStore()
	exp := time.Now().Add(time.Hour)
	mustSave(t, store, "u1-f1", RefreshTokenData{FamilyID: "fam-1", UserID: "u1", Status: StatusActive, ExpiresAt: exp})
	mustSave(t, store, "u1-f2", RefreshTokenData{FamilyID: "fam-2", UserID: "u1", Status: StatusActive, ExpiresAt: exp})
	mustSave(t, store, "u2-f3", RefreshTokenData{FamilyID: "fam-3", UserID: "u2", Status: StatusActive, ExpiresAt: exp})

	if err := store.RevokeAllForUser("u1"); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	// Every family of u1 is revoked; the unrelated user is untouched.
	assertStatus(t, store, "u1-f1", StatusRevoked)
	assertStatus(t, store, "u1-f2", StatusRevoked)
	assertStatus(t, store, "u2-f3", StatusActive)
}

func mustSave(t *testing.T, store *MemoryRefreshTokenStore, hash string, data RefreshTokenData) {
	t.Helper()
	if err := store.Save(hash, data); err != nil {
		t.Fatalf("Save(%q): %v", hash, err)
	}
}

func assertStatus(t *testing.T, store *MemoryRefreshTokenStore, hash, want string) {
	t.Helper()
	got, err := store.Get(hash)
	if err != nil {
		t.Fatalf("Get(%q): %v", hash, err)
	}
	if got.Status != want {
		t.Errorf("token %q status = %q, want %q", hash, got.Status, want)
	}
}
