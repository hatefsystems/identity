package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestNewSecret(t *testing.T) {
	secret, hash, err := NewSecret()
	if err != nil || secret == "" || hash == "" || HashSecret(secret) != hash {
		t.Fatalf("secret generation failed: %v", err)
	}
	other, _, err := NewSecret()
	if err != nil || secret == other {
		t.Fatalf("secret repeated: %v", err)
	}
}

func storeFixture(id, user string) (GrantData, RefreshTokenData) {
	expires := time.Now().Add(time.Hour)
	g := GrantData{ID: id, PrincipalType: PrincipalUser, Subject: user, ClientID: "app", Scope: "openid",
		SessionID: "session-" + user, AuthVersion: 9007199254740993, AuthVersionSet: true, Status: StatusActive, ExpiresAt: expires}
	r := RefreshTokenData{FamilyID: id, UserID: user, ClientID: g.ClientID, Scope: g.Scope, SessionID: g.SessionID,
		AuthVersion: g.AuthVersion, AuthVersionSet: true, Status: StatusActive, ExpiresAt: expires}
	return g, r
}

func codeFixture() AuthorizationCodeData {
	return AuthorizationCodeData{UserID: "user", SessionID: "session", AuthVersionSet: true, ClientID: "app",
		RedirectURI: "https://app.test/cb", CodeChallenge: "challenge", ExpiresAt: time.Now().Add(time.Minute)}
}

func eachStore(t *testing.T, test func(*testing.T, RefreshTokenStore, RefreshTokenStore)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		s := NewMemoryRefreshTokenStore()
		test(t, s, s)
	})
	t.Run("redis", func(t *testing.T) {
		server := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1})
		t.Cleanup(func() { _ = client.Close() })
		a, err := NewRedisRefreshTokenStore(client)
		if err != nil {
			t.Fatal(err)
		}
		b, err := NewRedisRefreshTokenStore(client)
		if err != nil {
			t.Fatal(err)
		}
		test(t, a, b)
	})
}

func TestCodeStoreSingleUseAndCancellation(t *testing.T) {
	for _, backend := range []string{"memory", "redis"} {
		t.Run(backend, func(t *testing.T) {
			var a, b AuthorizationCodeStore
			if backend == "memory" {
				a = NewMemoryCodeStore()
				b = a
			} else {
				server := miniredis.RunT(t)
				client := redis.NewClient(&redis.Options{Addr: server.Addr()})
				t.Cleanup(func() { _ = client.Close() })
				var err error
				a, err = NewRedisCodeStore(client)
				if err != nil {
					t.Fatal(err)
				}
				b, err = NewRedisCodeStore(client)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := a.Save(t.Context(), "hash", codeFixture()); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			wins := make(chan bool, 32)
			for range 32 {
				wg.Go(func() {
					got, err := b.Consume(t.Context(), "hash")
					if err == nil && got.SessionID != "session" {
						t.Error("lost code linkage")
					}
					if err != nil && !errors.Is(err, ErrCodeNotFound) {
						t.Error(err)
					}
					wins <- err == nil
				})
			}
			wg.Wait()
			close(wins)
			count := 0
			for won := range wins {
				if won {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("consume winners = %d", count)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := a.Consume(ctx, "hash"); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}

func TestGrantStoreAtomicRotation(t *testing.T) {
	eachStore(t, func(t *testing.T, a, b RefreshTokenStore) {
		g, r := storeFixture("family", "user")
		if err := a.CreateGrant(t.Context(), g, "first", r); err != nil {
			t.Fatal(err)
		}
		if loaded, err := b.GetGrant(t.Context(), g.ID); err != nil || loaded.AuthVersion != g.AuthVersion {
			t.Fatalf("version lost: %+v %v", loaded, err)
		}
		var wg sync.WaitGroup
		results := make(chan error, 16)
		for i := range 16 {
			wg.Go(func() { results <- b.Rotate(t.Context(), "first", r, fmt.Sprintf("next-%d", i), r) })
		}
		wg.Wait()
		close(results)
		winners := 0
		for err := range results {
			if err == nil {
				winners++
			} else if !errors.Is(err, ErrRefreshReuse) {
				t.Error(err)
			}
		}
		if winners != 1 {
			t.Fatalf("rotation winners = %d", winners)
		}
		old, err := a.Get(t.Context(), "first")
		if err != nil || old.Status != StatusRotated {
			t.Fatalf("old secret not retired: %+v %v", old, err)
		}
		grant, err := a.GetGrant(t.Context(), g.ID)
		if err != nil || grant.Status != StatusActive {
			t.Fatalf("ordinary rotation revoked access tokens: %+v %v", grant, err)
		}
		if err := a.Rotate(t.Context(), "absent", r, "other", r); !errors.Is(err, ErrRefreshTokenNotFound) {
			t.Fatal(err)
		}
	})
}

func TestGrantStoreFamilyAndUserRevocation(t *testing.T) {
	eachStore(t, func(t *testing.T, a, b RefreshTokenStore) {
		for _, item := range []struct{ id, user string }{{"one", "alice"}, {"two", "alice"}, {"three", "bob"}} {
			g, r := storeFixture(item.id, item.user)
			if err := a.CreateGrant(t.Context(), g, item.id, r); err != nil {
				t.Fatal(err)
			}
		}
		if err := b.RevokeFamily(t.Context(), "one"); err != nil {
			t.Fatal(err)
		}
		assertStatus(t, a, "one", StatusRevoked)
		assertStatus(t, a, "two", StatusActive)
		if err := b.RevokeAllForUser(t.Context(), "alice"); err != nil {
			t.Fatal(err)
		}
		assertStatus(t, a, "two", StatusRevoked)
		assertStatus(t, a, "three", StatusActive)
		_, stale := storeFixture("two", "alice")
		if err := a.Rotate(t.Context(), "two", stale, "resurrected", stale); !errors.Is(err, ErrRefreshReuse) {
			t.Fatalf("revocation lost: %v", err)
		}
		if _, err := a.Get(t.Context(), "resurrected"); !errors.Is(err, ErrRefreshTokenNotFound) {
			t.Fatalf("revoked successor created: %v", err)
		}
	})
}

func TestMemoryCredentialExpiry(t *testing.T) {
	code := NewMemoryCodeStore()
	data := codeFixture()
	if err := code.Save(t.Context(), "code", data); err != nil {
		t.Fatal(err)
	}
	code.now = func() time.Time { return data.ExpiresAt }
	if _, err := code.Consume(t.Context(), "code"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatal(err)
	}
	g, r := storeFixture("family", "user")
	store := NewMemoryRefreshTokenStore()
	if err := store.CreateGrant(t.Context(), g, "hash", r); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return g.ExpiresAt }
	if _, err := store.Get(t.Context(), "hash"); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Fatal(err)
	}
}

func TestRedisCredentialTTLAndCorruption(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1, DialTimeout: 50 * time.Millisecond, ReadTimeout: 50 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })
	store, err := NewRedisRefreshTokenStore(client)
	if err != nil {
		t.Fatal(err)
	}
	g, r := storeFixture("family", "user")
	if err := store.CreateGrant(t.Context(), g, "hash", r); err != nil {
		t.Fatal(err)
	}
	for _, key := range server.Keys() {
		if server.TTL(key) <= 0 {
			t.Errorf("missing TTL: %s", key)
		}
	}
	if err := client.Set(t.Context(), redisGrantPrefix+g.ID, "invalid state", time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetGrant(t.Context(), g.ID); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Set(t.Context(), redisGrantPrefix+g.ID, encoded, time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	server.FastForward(2 * time.Hour)
	if _, err := store.Get(t.Context(), "hash"); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Fatal(err)
	}
	server.Close()
	if _, err := store.GetGrant(t.Context(), g.ID); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("outage hidden: %v", err)
	}
}

func assertStatus(t *testing.T, store RefreshTokenStore, hash, want string) {
	t.Helper()
	got, err := store.Get(t.Context(), hash)
	if err != nil || got.Status != want {
		t.Fatalf("status for %s = %s, %v; want %s", hash, got.Status, err, want)
	}
}
