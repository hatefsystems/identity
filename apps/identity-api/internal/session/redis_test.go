package session

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type redisFixture struct {
	server        *miniredis.Miniredis
	first, second *RedisStore
	now           time.Time
}

func newRedisFixture(t *testing.T) *redisFixture {
	t.Helper()
	f := &redisFixture{server: miniredis.RunT(t), now: time.Now().UTC()}
	f.server.SetTime(f.now)
	stores := []*RedisStore{}
	for range 2 {
		client := redis.NewClient(&redis.Options{
			Addr: f.server.Addr(), MaxRetries: -1, ContextTimeoutEnabled: true,
			DialTimeout: 100 * time.Millisecond, ReadTimeout: 100 * time.Millisecond, WriteTimeout: 100 * time.Millisecond,
		})
		t.Cleanup(func() { _ = client.Close() })
		store, err := NewRedisStore(client)
		if err != nil {
			t.Fatal(err)
		}
		store.now = func() time.Time { return f.now }
		stores = append(stores, store)
	}
	f.first, f.second = stores[0], stores[1]
	return f
}

func (f *redisFixture) advance(by time.Duration) {
	f.now = f.now.Add(by)
	f.server.FastForward(by)
	f.server.SetTime(f.now)
}

func TestNewRedisStoreRequiresClient(t *testing.T) {
	var typedNil *redis.Client
	for _, client := range []redis.UniversalClient{nil, typedNil} {
		if _, err := NewRedisStore(client); !errors.Is(err, ErrStoreUnavailable) {
			t.Fatalf("NewRedisStore(nil): %v", err)
		}
	}
}

func TestRedisStorePreservesEveryFieldAndExactVersions(t *testing.T) {
	f := newRedisFixture(t)
	for _, kind := range []Kind{KindAuthenticated, KindRecoveryEnrollment} {
		for _, version := range []int64{0, 1, 1<<53 + 1, math.MaxInt64} {
			for _, captured := range []bool{false, true} {
				name := fmt.Sprintf("%s-%d-%t", kind, version, captured)
				t.Run(name, func(t *testing.T) {
					s := liveSession(f.now, "owner", name)
					s.Kind, s.AuthVersion, s.AuthVersionSet = kind, version, captured
					s.IP, s.UserAgent, s.DPoPJKT = "203.0.113.15", "browser \"quoted\"\nagent", "jkt-fingerprint"
					hash := HashToken(name)
					if err := f.first.Create(t.Context(), hash, s); err != nil {
						t.Fatal(err)
					}
					for _, lookup := range []func() (Session, error){
						func() (Session, error) { return f.second.Get(t.Context(), hash) },
						func() (Session, error) { return f.second.GetByID(t.Context(), s.UserID, s.ID) },
					} {
						got, err := lookup()
						if err != nil || !reflect.DeepEqual(got, s) {
							t.Fatalf("round trip = %+v, %v; want %+v", got, err, s)
						}
					}
					if got := f.first.client.HGet(t.Context(), redisTokenKey(hash), "auth_version").Val(); got != strconv.FormatInt(version, 10) {
						t.Fatalf("version stored imprecisely: %q", got)
					}
					if err := f.second.Touch(t.Context(), hash, s.AbsoluteExpiry.Add(time.Hour)); err != nil {
						t.Fatal(err)
					}
					got, err := f.first.Get(t.Context(), hash)
					s.IdleExpiry = s.AbsoluteExpiry
					if err != nil || !reflect.DeepEqual(got, s) {
						t.Fatalf("touch changed immutable fields: %+v, %v", got, err)
					}
				})
			}
		}
	}
}

func TestRedisStoreFiniteTTLsAndLookupDoesNotTouch(t *testing.T) {
	f := newRedisFixture(t)
	s := liveSession(f.now, "owner", "id")
	hash := HashToken("cookie")
	if err := f.first.Create(t.Context(), hash, s); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]time.Duration{
		redisTokenKey(hash): 2 * time.Hour, redisIDKey(s.UserID, s.ID): 2 * time.Hour, redisUserKey(s.UserID): 24 * time.Hour,
	} {
		if got := f.server.TTL(key); got < want || got > want+time.Millisecond {
			t.Fatalf("TTL %s = %v, want %v within rounding", key, got, want)
		}
	}
	f.advance(time.Hour)
	before := f.server.TTL(redisTokenKey(hash))
	for range 3 {
		got, err := f.second.GetByID(t.Context(), s.UserID, s.ID)
		if err != nil || !reflect.DeepEqual(got, s) {
			t.Fatalf("read-only lookup changed session: %+v, %v", got, err)
		}
	}
	if got := f.server.TTL(redisTokenKey(hash)); got != before {
		t.Fatalf("lookup extended TTL: %v -> %v", before, got)
	}
	if err := f.second.Touch(t.Context(), hash, f.now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	touched, err := f.first.Get(t.Context(), hash)
	if err != nil || !touched.LastSeenAt.Equal(f.now) || !touched.IdleExpiry.Equal(f.now.Add(2*time.Hour)) {
		t.Fatalf("cross-instance touch: %+v, %v", touched, err)
	}
	if err := f.first.Touch(t.Context(), hash, s.IdleExpiry); err != nil {
		t.Fatal(err)
	}
	got, err := f.second.Get(t.Context(), hash)
	if err != nil || !reflect.DeepEqual(got, touched) {
		t.Fatalf("delayed touch regressed state: %+v, %v", got, err)
	}
	// Inserting a shorter session must not shorten the existing owner's index.
	short := liveSession(f.now, s.UserID, "short")
	short.AbsoluteExpiry, short.IdleExpiry = f.now.Add(time.Hour), f.now.Add(time.Hour)
	ownerTTL := f.server.TTL(redisUserKey(s.UserID))
	if err := f.second.Create(t.Context(), HashToken("short"), short); err != nil {
		t.Fatal(err)
	}
	if got := f.server.TTL(redisUserKey(s.UserID)); got != ownerTTL {
		t.Fatalf("owner index shortened: %v -> %v", ownerTTL, got)
	}
}

func TestRedisStoreExactExpiryBoundaries(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		t.Run(fmt.Sprintf("absolute=%t", absolute), func(t *testing.T) {
			f := newRedisFixture(t)
			sessions := make([]Session, 6)
			for i := range sessions {
				s := liveSession(f.now, "owner", strconv.Itoa(i))
				s.Kind = KindRecoveryEnrollment
				if absolute {
					s.IdleExpiry = s.AbsoluteExpiry
				}
				if i == 4 {
					s.EnrollmentClaimed = true
				}
				sessions[i] = s
				if err := f.first.Create(t.Context(), HashToken(s.ID), s); err != nil {
					t.Fatal(err)
				}
			}
			// Deliberately leave Redis TTLs unadvanced: the scripts must enforce
			// the exact stored deadline, not depend solely on Redis millisecond TTLs.
			f.now = sessions[0].IdleExpiry.Add(-time.Nanosecond)
			f.server.SetTime(f.now)
			if _, err := f.second.Get(t.Context(), HashToken("0")); err != nil {
				t.Fatalf("before expiry: %v", err)
			}
			f.now = sessions[0].IdleExpiry
			f.server.SetTime(f.now)
			if _, err := f.second.Get(t.Context(), HashToken("0")); err != ErrSessionNotFound {
				t.Fatalf("get at expiry: %v", err)
			}
			if _, err := f.second.GetByID(t.Context(), "owner", "1"); err != ErrSessionNotFound {
				t.Fatalf("ID lookup at expiry: %v", err)
			}
			if err := f.second.Touch(t.Context(), HashToken("2"), f.now.Add(time.Hour)); err != ErrSessionNotFound {
				t.Fatalf("touch resurrected expiry: %v", err)
			}
			if claimed, err := f.second.ClaimRecoveryEnrollment(t.Context(), "owner", "3"); err != nil || claimed {
				t.Fatalf("claim at expiry: %v, %v", claimed, err)
			}
			if err := f.second.ReleaseRecoveryEnrollment(t.Context(), "owner", "4"); err != nil {
				t.Fatal(err)
			}
			if listed, err := f.second.ListForUser(t.Context(), "owner"); err != nil || len(listed) != 0 {
				t.Fatalf("list at expiry: %+v, %v", listed, err)
			}
			for _, s := range sessions {
				if _, err := f.first.Get(t.Context(), HashToken(s.ID)); err != ErrSessionNotFound {
					t.Fatalf("expired session survived operation: %s, %v", s.ID, err)
				}
			}
		})
	}
}

func TestRedisStoreRedisClockAndTTLAlsoEnforceExpiry(t *testing.T) {
	for _, advanceTTL := range []bool{false, true} {
		f := newRedisFixture(t)
		// Redis TIME has microsecond precision, independently of stored nanos.
		s := liveSession(f.now.Truncate(time.Microsecond), "owner", "id")
		if err := f.first.Create(t.Context(), "hash", s); err != nil {
			t.Fatal(err)
		}
		if advanceTTL {
			f.server.FastForward(2*time.Hour + time.Millisecond)
		} else {
			f.server.SetTime(s.IdleExpiry)
		}
		// The instance clock has not moved; Redis still closes authority.
		if err := f.second.Touch(t.Context(), "hash", s.AbsoluteExpiry); err != ErrSessionNotFound {
			t.Fatalf("Redis expiry ignored (TTL=%t): %v", advanceTTL, err)
		}
	}
}

func TestRedisStoreNeverReconstructsMissingAuthority(t *testing.T) {
	for _, missing := range []string{"record", "id", "owner", "reset"} {
		t.Run(missing, func(t *testing.T) {
			f := newRedisFixture(t)
			s := liveSession(f.now, "owner", "id")
			s.Kind = KindRecoveryEnrollment
			if err := f.first.Create(t.Context(), "hash", s); err != nil {
				t.Fatal(err)
			}
			switch missing {
			case "record":
				f.server.Del(redisTokenKey("hash"))
			case "id":
				f.server.Del(redisIDKey(s.UserID, s.ID))
			case "owner":
				f.server.Del(redisUserKey(s.UserID))
			case "reset":
				f.server.FlushAll()
			}
			before := f.server.Keys()
			if _, err := f.second.Get(t.Context(), "hash"); err != ErrSessionNotFound {
				t.Fatalf("cookie lookup after loss: %v", err)
			}
			if _, err := f.second.GetByID(t.Context(), s.UserID, s.ID); err != ErrSessionNotFound {
				t.Fatalf("ID lookup after loss: %v", err)
			}
			if err := f.second.Touch(t.Context(), "hash", s.AbsoluteExpiry); err != ErrSessionNotFound {
				t.Fatalf("touch after loss: %v", err)
			}
			if claimed, err := f.second.ClaimRecoveryEnrollment(t.Context(), s.UserID, s.ID); err != nil || claimed {
				t.Fatalf("claim after loss: %v, %v", claimed, err)
			}
			if err := f.second.ReleaseRecoveryEnrollment(t.Context(), s.UserID, s.ID); err != nil {
				t.Fatal(err)
			}
			if after := f.server.Keys(); !reflect.DeepEqual(before, after) {
				t.Fatalf("missing state was reconstructed: %v -> %v", before, after)
			}
		})
	}
}

func TestRedisStoreOwnershipAndNewestFirstListing(t *testing.T) {
	f := newRedisFixture(t)
	for _, s := range []Session{
		liveSession(f.now, "a:b", "c"), liveSession(f.now, "a", "b:c"),
		liveSession(f.now, "owner", "old"), liveSession(f.now.Add(time.Minute), "owner", "new"),
	} {
		if err := f.first.Create(t.Context(), HashToken(s.UserID+s.ID), s); err != nil {
			t.Fatal(err)
		}
	}
	listed, err := f.second.ListForUser(t.Context(), "owner")
	if err != nil || len(listed) != 2 || listed[0].ID != "new" || listed[1].ID != "old" {
		t.Fatalf("ordered owner list: %+v, %v", listed, err)
	}
	if _, err := f.second.GetByID(t.Context(), "intruder", "old"); err != ErrSessionNotFound {
		t.Fatalf("foreign lookup: %v", err)
	}
	if removed, err := f.second.DeleteForUser(t.Context(), "intruder", "old"); err != nil || removed {
		t.Fatalf("foreign delete: %v, %v", removed, err)
	}
	if err := f.second.DeleteAllForUser(t.Context(), "a:b"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.first.GetByID(t.Context(), "a", "b:c"); err != nil {
		t.Fatalf("delimiter collision revoked another owner: %v", err)
	}
}

func TestRedisStoreRejectsMalformedState(t *testing.T) {
	mutations := map[string]func(*redisFixture, Session){
		"missing field":      func(f *redisFixture, _ Session) { f.server.HDel(redisTokenKey("hash"), "auth_version_set") },
		"unknown field":      func(f *redisFixture, _ Session) { f.server.HSet(redisTokenKey("hash"), "extra", "value") },
		"unknown kind":       func(f *redisFixture, _ Session) { f.server.HSet(redisTokenKey("hash"), "kind", "unknown") },
		"negative version":   func(f *redisFixture, _ Session) { f.server.HSet(redisTokenKey("hash"), "auth_version", "-1") },
		"fractional version": func(f *redisFixture, _ Session) { f.server.HSet(redisTokenKey("hash"), "auth_version", "1.5") },
		"overflow version": func(f *redisFixture, _ Session) {
			f.server.HSet(redisTokenKey("hash"), "auth_version", "9223372036854775808")
		},
		"invalid boolean":   func(f *redisFixture, _ Session) { f.server.HSet(redisTokenKey("hash"), "auth_version_set", "true") },
		"invalid claim":     func(f *redisFixture, _ Session) { f.server.HSet(redisTokenKey("hash"), "enrollment_claimed", "1") },
		"invalid timestamp": func(f *redisFixture, _ Session) { f.server.HSet(redisTokenKey("hash"), "created_at", "NaN") },
		"reversed time": func(f *redisFixture, s Session) {
			f.server.HSet(redisTokenKey("hash"), "last_seen_at", strconv.FormatInt(s.CreatedAt.Add(-time.Second).UnixNano(), 10))
		},
		"idle exceeds absolute": func(f *redisFixture, s Session) {
			f.server.HSet(redisTokenKey("hash"), "idle_expiry", strconv.FormatInt(s.AbsoluteExpiry.Add(time.Second).UnixNano(), 10))
		},
		"persistent record": func(f *redisFixture, _ Session) { f.first.client.Persist(t.Context(), redisTokenKey("hash")) },
		"persistent owner":  func(f *redisFixture, s Session) { f.first.client.Persist(t.Context(), redisUserKey(s.UserID)) },
		"persistent ID":     func(f *redisFixture, s Session) { f.first.client.Persist(t.Context(), redisIDKey(s.UserID, s.ID)) },
		"wrong record type": func(f *redisFixture, _ Session) {
			f.first.client.Set(t.Context(), redisTokenKey("hash"), "bad", time.Hour)
		},
		"wrong owner type": func(f *redisFixture, s Session) {
			f.first.client.Set(t.Context(), redisUserKey(s.UserID), "bad", time.Hour)
		},
		"wrong ID type": func(f *redisFixture, s Session) {
			f.server.Del(redisIDKey(s.UserID, s.ID))
			f.server.HSet(redisIDKey(s.UserID, s.ID), "bad", "value")
			f.server.SetTTL(redisIDKey(s.UserID, s.ID), time.Hour)
		},
		"wrong index target": func(f *redisFixture, s Session) { f.server.HSet(redisUserKey(s.UserID), s.ID, "another-hash") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newRedisFixture(t)
			s := liveSession(f.now, "owner", "id")
			if err := f.first.Create(t.Context(), "hash", s); err != nil {
				t.Fatal(err)
			}
			mutate(f, s)
			if _, err := f.second.Get(t.Context(), "hash"); !errors.Is(err, ErrStoreUnavailable) || errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("corruption collapsed to absence: %v", err)
			}
			if _, err := f.second.GetByID(t.Context(), s.UserID, s.ID); !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("corrupt ID lookup: %v", err)
			}
			if err := f.second.Touch(t.Context(), "hash", s.AbsoluteExpiry); !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("corrupt touch: %v", err)
			}
		})
	}
}

func TestRedisStoreCorruptOwnerIndexCannotRevokeForeignSession(t *testing.T) {
	f := newRedisFixture(t)
	for _, user := range []string{"owner", "foreign"} {
		if err := f.first.Create(t.Context(), user+"-hash", liveSession(f.now, user, "id")); err != nil {
			t.Fatal(err)
		}
	}
	f.server.HSet(redisUserKey("owner"), "id", "foreign-hash")
	if err := f.second.DeleteAllForUser(t.Context(), "owner"); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("corrupt bulk revoke: %v", err)
	}
	if _, err := f.first.Get(t.Context(), "foreign-hash"); err != nil {
		t.Fatalf("bulk revoke crossed ownership: %v", err)
	}
}

func TestRedisStoreBulkDeletionIncludesEverySessionAndMissingRecords(t *testing.T) {
	f := newRedisFixture(t)
	for _, id := range []string{"normal", "restricted", "evicted"} {
		s := liveSession(f.now, "owner", id)
		if id == "restricted" {
			s.Kind = KindRecoveryEnrollment
			s.EnrollmentClaimed = true
		}
		if err := f.first.Create(t.Context(), id, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.first.Create(t.Context(), "foreign", liveSession(f.now, "foreign", "id")); err != nil {
		t.Fatal(err)
	}
	f.server.Del(redisTokenKey("evicted"))
	for range 2 {
		if err := f.second.DeleteAllForUser(t.Context(), "owner"); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"normal", "restricted", "evicted"} {
		if _, err := f.first.GetByID(t.Context(), "owner", id); err != ErrSessionNotFound {
			t.Fatalf("bulk deletion left %s: %v", id, err)
		}
		if f.server.Exists(redisTokenKey(id)) {
			t.Fatalf("bulk deletion retained record %s", id)
		}
		if ttl := f.server.TTL(redisIDKey("owner", id)); ttl <= 0 || ttl > 24*time.Hour+time.Millisecond {
			t.Fatalf("revocation marker %s has unbounded TTL %v", id, ttl)
		}
	}
	if sessions, err := f.first.ListForUser(t.Context(), "owner"); err != nil || len(sessions) != 0 {
		t.Fatalf("bulk deletion left sessions: %+v, %v", sessions, err)
	}
	if _, err := f.first.Get(t.Context(), "foreign"); err != nil {
		t.Fatalf("bulk deletion leaked to foreign user: %v", err)
	}
	f.advance(24*time.Hour + time.Millisecond)
	if keys := f.server.Keys(); len(keys) != 0 {
		t.Fatalf("expired records, indexes, or markers leaked: %v", keys)
	}
}

func TestRedisStoreCreationDoesNotReplaceExistingAuthority(t *testing.T) {
	f := newRedisFixture(t)
	s := liveSession(f.now, "owner", "id")
	if err := f.first.Create(t.Context(), "hash", s); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		hash string
		s    Session
	}{
		{"hash", liveSession(f.now, "foreign", "other")},
		{"another-hash", s},
	} {
		if err := f.second.Create(t.Context(), test.hash, test.s); !errors.Is(err, ErrStoreUnavailable) {
			t.Fatalf("duplicate authority replaced: %v", err)
		}
	}
	got, err := f.first.Get(t.Context(), "hash")
	if err != nil || !reflect.DeepEqual(got, s) {
		t.Fatalf("duplicate creation changed authority: %+v, %v", got, err)
	}
	f.advance(time.Hour)
	later := liveSession(f.now, "owner", "later")
	if err := f.second.Create(t.Context(), "later-hash", later); err != nil {
		t.Fatal(err)
	}
	if ttl := f.server.TTL(redisUserKey("owner")); ttl < 24*time.Hour || ttl > 24*time.Hour+time.Millisecond {
		t.Fatalf("owner index did not retain latest absolute lifetime: %v", ttl)
	}
}

func TestRedisStoreEnrollmentClaimRaces(t *testing.T) {
	f := newRedisFixture(t)
	s := liveSession(f.now, "owner", "recovery")
	s.Kind, s.AuthVersion, s.AuthVersionSet = KindRecoveryEnrollment, math.MaxInt64, true
	if err := f.first.Create(t.Context(), "hash", s); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 32 {
		store := []*RedisStore{f.first, f.second}[i%2]
		wg.Go(func() {
			<-start
			claimed, err := store.ClaimRecoveryEnrollment(t.Context(), s.UserID, s.ID)
			if err != nil {
				t.Errorf("claim: %v", err)
			}
			if claimed {
				winners.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("claim winners = %d, want 1", winners.Load())
	}
	if err := f.second.ReleaseRecoveryEnrollment(t.Context(), "foreign", s.ID); err != nil {
		t.Fatal(err)
	}
	if claimed, err := f.first.ClaimRecoveryEnrollment(t.Context(), s.UserID, s.ID); err != nil || claimed {
		t.Fatalf("foreign release changed claim: %v, %v", claimed, err)
	}
	got, err := f.second.GetByID(t.Context(), s.UserID, s.ID)
	s.EnrollmentClaimed = true
	if err != nil || !reflect.DeepEqual(got, s) {
		t.Fatalf("claim changed unrelated fields: %+v, %v", got, err)
	}
	ttl := f.server.TTL(redisTokenKey("hash"))
	if err := f.second.ReleaseRecoveryEnrollment(t.Context(), s.UserID, s.ID); err != nil {
		t.Fatal(err)
	}
	if claimed, err := f.first.ClaimRecoveryEnrollment(t.Context(), s.UserID, s.ID); err != nil || !claimed {
		t.Fatalf("released claim could not retry: %v, %v", claimed, err)
	}
	if f.server.TTL(redisTokenKey("hash")) != ttl {
		t.Fatal("claim or release changed TTL")
	}
	if err := f.second.Delete(t.Context(), "hash"); err != nil {
		t.Fatal(err)
	}
	if err := f.first.ReleaseRecoveryEnrollment(t.Context(), s.UserID, s.ID); err != nil {
		t.Fatal(err)
	}
	if claimed, err := f.first.ClaimRecoveryEnrollment(t.Context(), s.UserID, s.ID); err != nil || claimed {
		t.Fatalf("deleted claim revived: %v, %v", claimed, err)
	}
	if err := f.first.Create(t.Context(), "normal", liveSession(f.now, s.UserID, "normal")); err != nil {
		t.Fatal(err)
	}
	if claimed, err := f.second.ClaimRecoveryEnrollment(t.Context(), s.UserID, "normal"); err != nil || claimed {
		t.Fatalf("normal session claimed recovery: %v, %v", claimed, err)
	}
}

func TestRedisStoreTouchAndRevocationRacesNeverRestoreState(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		t.Run(fmt.Sprintf("bulk=%t", bulk), func(t *testing.T) {
			f := newRedisFixture(t)
			if err := f.first.Create(t.Context(), "foreign-hash", liveSession(f.now, "foreign", "id")); err != nil {
				t.Fatal(err)
			}
			for round := range 8 {
				s := liveSession(f.now, "owner", strconv.Itoa(round))
				s.Kind = KindRecoveryEnrollment
				hash := HashToken(s.ID)
				if err := f.first.Create(t.Context(), hash, s); err != nil {
					t.Fatal(err)
				}
				var wg sync.WaitGroup
				start := make(chan struct{})
				for i := range 16 {
					store := []*RedisStore{f.first, f.second}[i%2]
					wg.Go(func() {
						<-start
						if err := store.Touch(t.Context(), hash, s.AbsoluteExpiry); err != nil && err != ErrSessionNotFound {
							t.Errorf("touch: %v", err)
						}
						if _, err := store.ClaimRecoveryEnrollment(t.Context(), s.UserID, s.ID); err != nil {
							t.Errorf("claim: %v", err)
						}
						if err := store.ReleaseRecoveryEnrollment(t.Context(), s.UserID, s.ID); err != nil {
							t.Errorf("release: %v", err)
						}
					})
				}
				wg.Go(func() {
					<-start
					var err error
					if bulk {
						err = f.second.DeleteAllForUser(t.Context(), s.UserID)
					} else {
						_, err = f.second.DeleteForUser(t.Context(), s.UserID, s.ID)
					}
					if err != nil {
						t.Errorf("revoke: %v", err)
					}
				})
				close(start)
				wg.Wait()
				for _, store := range []*RedisStore{f.first, f.second} {
					if _, err := store.Get(t.Context(), hash); err != ErrSessionNotFound {
						t.Fatalf("revoked record restored: %v", err)
					}
					if err := store.Touch(t.Context(), hash, s.AbsoluteExpiry); err != ErrSessionNotFound {
						t.Fatalf("delayed touch restored record: %v", err)
					}
				}
				if f.server.Exists(redisTokenKey(hash)) || f.server.Exists(redisUserKey(s.UserID)) {
					t.Fatal("record or owner index survived revocation")
				}
				if err := f.first.Create(t.Context(), hash, s); !errors.Is(err, ErrStoreUnavailable) {
					t.Fatalf("delayed Create restored revoked session: %v", err)
				}
			}
			if _, err := f.first.Get(t.Context(), "foreign-hash"); err != nil {
				t.Fatalf("revocation affected another user: %v", err)
			}
		})
	}
}

func TestRedisStoreOutagesAreNotMissingState(t *testing.T) {
	f := newRedisFixture(t)
	s := liveSession(f.now, "owner", "id")
	if err := f.first.Create(t.Context(), "hash", s); err != nil {
		t.Fatal(err)
	}
	f.server.SetError("ERR test backend outage")
	operations := []func() error{
		func() error { return f.second.Create(t.Context(), "new", s) },
		func() error { _, err := f.second.Get(t.Context(), "hash"); return err },
		func() error { _, err := f.second.GetByID(t.Context(), s.UserID, s.ID); return err },
		func() error { return f.second.Touch(t.Context(), "hash", s.AbsoluteExpiry) },
		func() error { return f.second.Delete(t.Context(), "hash") },
		func() error { _, err := f.second.ListForUser(t.Context(), s.UserID); return err },
		func() error { _, err := f.second.DeleteForUser(t.Context(), s.UserID, s.ID); return err },
		func() error { return f.second.DeleteAllForUser(t.Context(), s.UserID) },
		func() error { _, err := f.second.ClaimRecoveryEnrollment(t.Context(), s.UserID, s.ID); return err },
		func() error { return f.second.ReleaseRecoveryEnrollment(t.Context(), s.UserID, s.ID) },
	}
	for i, operation := range operations {
		if err := operation(); !errors.Is(err, ErrStoreUnavailable) || errors.Is(err, ErrSessionNotFound) {
			t.Errorf("operation %d misclassified outage: %v", i, err)
		}
	}
	f.server.Close()
	if _, err := f.first.Get(t.Context(), "hash"); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("connection outage misclassified: %v", err)
	}
}

func TestRedisStoreCancellation(t *testing.T) {
	f := newRedisFixture(t)
	testStoreCancellation(t, f.first)
}

type waitingRedisClient struct{ redis.UniversalClient }

func (*waitingRedisClient) EvalSha(ctx context.Context, _ string, _ []string, _ ...any) *redis.Cmd {
	<-ctx.Done()
	return redis.NewCmdResult(nil, ctx.Err())
}

func TestRedisStorePropagatesDeadlineIntoBackendCall(t *testing.T) {
	store, err := NewRedisStore(&waitingRedisClient{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if _, err := store.GetByID(ctx, "owner", "id"); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("deadline propagation: %v", err)
	}
}

func TestRedisManagersShareStateWithoutLookupAccountRevalidation(t *testing.T) {
	f := newRedisFixture(t)
	state := &testAccountState{active: true}
	var managers []*Manager
	for _, store := range []*RedisStore{f.first, f.second} {
		codec, err := NewCookieCodec(CookieConfig{Name: "session", TTL: 24 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		manager, err := NewManager(store, codec, ManagerConfig{AbsoluteTTL: 24 * time.Hour, IdleTTL: 2 * time.Hour, AccountState: state})
		if err != nil {
			t.Fatal(err)
		}
		manager.now = func() time.Time { return f.now }
		managers = append(managers, manager)
	}
	first, second := managers[0], managers[1]
	for _, kind := range []Kind{KindAuthenticated, KindRecoveryEnrollment} {
		rec := httptest.NewRecorder()
		s, err := first.IssueContext(t.Context(), rec, IssueParams{UserID: "owner", Kind: kind, AuthVersionSet: true})
		if err != nil {
			t.Fatal(err)
		}
		f.advance(time.Minute)
		state.err = errors.New("unexpected account revalidation")
		got, err := second.LookupByID(t.Context(), s.UserID, s.ID)
		if err != nil || !reflect.DeepEqual(got, s) {
			t.Fatalf("lookup touched state, lost zero version, or revalidated account: %+v, %v", got, err)
		}
		if _, err := second.Authenticate(requestWithCookies(rec)); !errors.Is(err, state.err) {
			t.Fatalf("cookie authentication skipped account gate: %v", err)
		}
		state.err = nil
		if _, err := second.Authenticate(requestWithCookies(rec)); err != nil {
			t.Fatalf("cross-manager cookie authentication: %v", err)
		}
		if kind == KindRecoveryEnrollment {
			if claimed, err := second.ClaimRecoveryEnrollment(t.Context(), s.UserID, s.ID); err != nil || !claimed {
				t.Fatalf("manager claim: %v, %v", claimed, err)
			}
			if claimed, err := first.ClaimRecoveryEnrollment(t.Context(), s.UserID, s.ID); err != nil || claimed {
				t.Fatalf("manager double claim: %v, %v", claimed, err)
			}
		}
		if removed, err := second.RevokeByID(t.Context(), s.UserID, s.ID); err != nil || !removed {
			t.Fatalf("cross-manager revoke: %v, %v", removed, err)
		}
		if _, err := first.LookupByID(t.Context(), s.UserID, s.ID); err != ErrSessionNotFound {
			t.Fatalf("revoked lookup: %v", err)
		}
		if _, err := first.Authenticate(requestWithCookies(rec)); err != ErrSessionNotFound {
			t.Fatalf("revoked cookie: %v", err)
		}
	}
}

func TestRedisManagerDoesNotIssueCookieOnStorageFailure(t *testing.T) {
	f := newRedisFixture(t)
	m := newTestManager(t, &f.now)
	m.store = f.first
	f.server.SetError("ERR test backend outage")
	rec := httptest.NewRecorder()
	if _, err := m.IssueContext(context.Background(), rec, IssueParams{UserID: "owner"}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("issuance failure: %v", err)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("failed persistence issued a cookie")
	}
}
