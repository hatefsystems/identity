//go:build integration

package profile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/geography"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

type privateDatabase struct {
	profileDatabase
	private *PrivateService
	geo     *geography.Service
	manager *session.Manager
	u       db.User
	sess    session.Session
}

func privateManager(t *testing.T, ttl time.Duration) *session.Manager {
	t.Helper()
	cookie, err := session.NewCookieCodec(session.CookieConfig{Name: session.DefaultCookieName, Secure: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(session.NewMemoryStore(), cookie, session.ManagerConfig{AbsoluteTTL: ttl, IdleTTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func privateIssue(t *testing.T, manager *session.Manager, u db.User) session.Session {
	t.Helper()
	sess, err := manager.IssueContext(t.Context(), httptest.NewRecorder(), session.IssueParams{UserID: u.ID.String(), AuthVersion: u.AuthVersion, AuthVersionSet: true, DPoPJKT: "private-test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func privateDatabaseFixture(t *testing.T) privateDatabase {
	t.Helper()
	f := newProfileDatabase(t)
	geo := geography.New(f.pool)
	cities := []byte(`[{"Id":7001,"Name":"Province","ParentId":null,"CenterType":2},{"Id":7002,"Name":"Locality","ParentId":7001,"CenterType":5}]`)
	types := []byte(`[{"Id":2,"Name":"Province"},{"Id":5,"Name":"City"}]`)
	cityHash, typeHash := sha256.Sum256(cities), sha256.Sum256(types)
	manifest, err := json.Marshal(geography.Manifest{Country: "IR", SourceRelease: "private-test", CitiesSHA256: hex.EncodeToString(cityHash[:]), TypesSHA256: hex.EncodeToString(typeHash[:]), CitiesBytes: int64(len(cities)), TypesBytes: int64(len(types)), PlaceCount: 2, TypeCount: 2, ProvinceCount: 1, CompleteSnapshot: true})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := geography.Parse(cities, types, manifest)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := geo.Check(f.ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := geo.Import(f.ctx, snapshot, plan.PlanDigest, ""); err != nil {
		t.Fatal(err)
	}
	manager := privateManager(t, time.Hour)
	u := profileUser(t, f)
	sess := privateIssue(t, manager, u)
	svc, err := NewPrivate(f.pool, privateCipher(t), nil, geo, manager)
	if err != nil {
		t.Fatal(err)
	}
	return privateDatabase{profileDatabase: f, private: svc, geo: geo, manager: manager, u: u, sess: sess}
}

func privateComplete(revision string) PrivateUpdate {
	given, family, gender := privateGiven, privateFamily, "female"
	return PrivateUpdate{ExpectedRevision: revision, GivenName: &given, FamilyName: &family, Gender: &gender, Birthday: &BirthdayInput{Calendar: "gregorian", Date: "2000-03-20"}, Location: &geography.LocationInput{Country: "IR", ProvinceID: "7001", LocalityID: "7002"}}
}

type privateStoredState struct {
	blob             []byte
	created, updated time.Time
}

func privateStored(t *testing.T, f privateDatabase) privateStoredState {
	t.Helper()
	var state privateStoredState
	if err := f.pool.QueryRow(f.ctx, `SELECT details_encrypted,created_at,updated_at FROM private_profile WHERE account_id=$1`, f.u.ID).Scan(&state.blob, &state.created, &state.updated); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestPrivateFirstPartialNoopConflictAndRollbackIntegration(t *testing.T) {
	for _, rejectOutbox := range []bool{false, true} {
		t.Run(strconv.FormatBool(rejectOutbox), func(t *testing.T) {
			f := privateDatabaseFixture(t)
			profileExec(t, f.profileDatabase, `UPDATE users SET lifecycle_revision=9007199254740993,display_name='Public name',updated_at='2000-01-01Z' WHERE id=$1`, f.u.ID)
			initial, err := f.private.Get(f.ctx, f.sess)
			if err != nil || initial.PrivateData != nil || initial.Username != nil || initial.LifecycleRevision != "9007199254740993" {
				t.Fatal("uninitialized profile not truthfully absent")
			}
			gender := "female"
			if _, err := f.private.Update(f.ctx, f.sess, PrivateUpdate{ExpectedRevision: initial.LifecycleRevision, Gender: &gender}); !errors.Is(err, ErrInvalidPrivateData) {
				t.Fatal("incomplete first save accepted")
			}
			if rejectOutbox {
				profileExec(t, f.profileDatabase, `ALTER TABLE event_outbox ADD CONSTRAINT reject_private CHECK(subject <> 'identity.user.updated')`)
			}
			first, err := f.private.Update(f.ctx, f.sess, privateComplete(initial.LifecycleRevision))
			if rejectOutbox {
				if !errors.Is(err, ErrUnavailable) || first.Changed {
					t.Fatal("outbox failure was not required")
				}
				after, err := f.private.Get(f.ctx, f.sess)
				if err != nil || after.PrivateData != nil || after.LifecycleRevision != initial.LifecycleRevision || profileIntentCount(t, f.profileDatabase, f.u.ID) != 0 {
					t.Fatal("first save outbox failure did not roll back data/revision")
				}
				return
			}
			if err != nil || !first.Changed || first.Snapshot.LifecycleRevision != "9007199254740994" || *first.Snapshot.PrivateData != privateDataFixture(t) {
				t.Fatalf("first private save failed: %v", err)
			}
			before := privateStored(t, f)
			var payload string
			if err := f.pool.QueryRow(f.ctx, `SELECT payload FROM event_outbox WHERE lifecycle_user_id=$1`, f.u.ID).Scan(&payload); err != nil {
				t.Fatal(err)
			}
			event, err := lifecycle.UnmarshalEvent([]byte(payload))
			if err != nil || event.SchemaVersion != 2 || len(event.ChangedFields) != 1 || event.ChangedFields[0] != "private_profile" || event.GetRevision() != 9007199254740994 {
				t.Fatal("private event not coarse versioned metadata")
			}
			for _, secret := range []string{"given_name", "family_name", "birthday", "gender", "location", privateGiven, privateFamily, "2000-03-20", "7001"} {
				if strings.Contains(payload, secret) {
					t.Fatal("private field/value disclosed in lifecycle intent")
				}
			}
			noop := privateComplete(first.Snapshot.LifecycleRevision)
			given := "  \u0639\u0644\u064a  "
			noop.GivenName, noop.Birthday = &given, &BirthdayInput{Calendar: "jalali", Date: first.Snapshot.PrivateData.Birthday.Jalali}
			unchanged, err := f.private.Update(f.ctx, f.sess, noop)
			if err != nil || unchanged.Changed {
				t.Fatal("equivalent normalized private profile changed")
			}
			after := privateStored(t, f)
			if !bytes.Equal(before.blob, after.blob) || !before.created.Equal(after.created) || !before.updated.Equal(after.updated) || profileIntentCount(t, f.profileDatabase, f.u.ID) != 1 {
				t.Fatal("no-op rewrote encrypted bytes, time or intent")
			}
			noop.ExpectedRevision = initial.LifecycleRevision
			if _, err := f.private.Update(f.ctx, f.sess, noop); !errors.Is(err, ErrConflict) {
				t.Fatal("stale no-op bypassed exact >2^53 revision")
			}
			gender = "male"
			partial, err := f.private.Update(f.ctx, f.sess, PrivateUpdate{ExpectedRevision: first.Snapshot.LifecycleRevision, Gender: &gender})
			if err != nil || !partial.Changed || partial.Snapshot.PrivateData.Gender != GenderMale || partial.Snapshot.PrivateData.Birthday != first.Snapshot.PrivateData.Birthday || partial.Snapshot.PrivateData.Location != first.Snapshot.PrivateData.Location || partial.Snapshot.LifecycleRevision != "9007199254740995" {
				t.Fatal("partial edit damaged whole fields or revision")
			}
			public := loadProfileUser(t, f.profileDatabase, f.u.ID)
			if public.DisplayName != "Public name" || public.AuthVersion != f.u.AuthVersion || !public.UpdatedAt.Time.Equal(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) {
				t.Fatal("private edit changed independent public/auth state")
			}
			// An edit to an existing protected child also rolls back exact bytes.
			stable := privateStored(t, f)
			profileExec(t, f.profileDatabase, `ALTER TABLE event_outbox ADD CONSTRAINT reject_private CHECK(subject <> 'identity.user.updated') NOT VALID`)
			gender = "female"
			if _, err := f.private.Update(f.ctx, f.sess, PrivateUpdate{ExpectedRevision: partial.Snapshot.LifecycleRevision, Gender: &gender}); !errors.Is(err, ErrUnavailable) {
				t.Fatal("existing child outbox failure accepted")
			}
			after = privateStored(t, f)
			if !bytes.Equal(stable.blob, after.blob) || !stable.updated.Equal(after.updated) || loadProfileUser(t, f.profileDatabase, f.u.ID).LifecycleRevision != 9007199254740995 || profileIntentCount(t, f.profileDatabase, f.u.ID) != 2 {
				t.Fatal("existing-child failure did not roll back entire edit")
			}
		})
	}
}

func TestPrivateRacingEditsIntegration(t *testing.T) {
	f := privateDatabaseFixture(t)
	first, err := f.private.Update(f.ctx, f.sess, privateComplete("0"))
	if err != nil {
		t.Fatal(err)
	}
	start, results := make(chan struct{}), make(chan error, 2)
	for _, name := range []string{"\u0631\u0636\u0627", "\u0633\u0627\u0631\u0627"} {
		go func() {
			<-start
			_, err := f.private.Update(f.ctx, f.sess, PrivateUpdate{ExpectedRevision: first.Snapshot.LifecycleRevision, GivenName: &name})
			results <- err
		}()
	}
	close(start)
	winners, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			winners++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if winners != 1 || conflicts != 1 || loadProfileUser(t, f.profileDatabase, f.u.ID).LifecycleRevision != 2 || profileIntentCount(t, f.profileDatabase, f.u.ID) != 2 {
		t.Fatal("racing private edits did not have one winner")
	}
}

func TestPrivateWholeBirthdayLocationValidationIntegration(t *testing.T) {
	f := privateDatabaseFixture(t)
	first, err := f.private.Update(f.ctx, f.sess, privateComplete("0"))
	if err != nil {
		t.Fatal(err)
	}
	for _, update := range []PrivateUpdate{
		{Birthday: &BirthdayInput{Calendar: "gregorian"}},
		{Birthday: &BirthdayInput{Date: "2000-03-20"}},
		{Birthday: &BirthdayInput{Calendar: "gregorian", Date: "2000-02-30"}},
		{Location: &geography.LocationInput{Country: "IR"}},
		{Location: &geography.LocationInput{Country: "IR", ProvinceID: "7002"}},
		{Location: &geography.LocationInput{Country: "IR", ProvinceID: "7001", LocalityID: "7001"}},
	} {
		update.ExpectedRevision = first.Snapshot.LifecycleRevision
		if _, err := f.private.Update(f.ctx, f.sess, update); err == nil {
			t.Fatal("private whole field bypassed validator")
		}
	}
	changed, err := f.private.Update(f.ctx, f.sess, PrivateUpdate{ExpectedRevision: first.Snapshot.LifecycleRevision, Birthday: &BirthdayInput{Calendar: "jalali", Date: "1380-01-01"}, Location: &geography.LocationInput{Country: "IR", ProvinceID: "7001"}})
	if err != nil || changed.Snapshot.PrivateData.Birthday.Gregorian != "2001-03-21" || changed.Snapshot.PrivateData.Birthday.Jalali != "1380-01-01" || changed.Snapshot.PrivateData.Location.LocalityID != "" {
		t.Fatal("birthday pair/location whole replacement failed")
	}
}

func TestPrivateSubstitutionAndErasureIntegration(t *testing.T) {
	f := privateDatabaseFixture(t)
	var columns string
	if err := f.pool.QueryRow(f.ctx, `SELECT string_agg(column_name,',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name='private_profile'`).Scan(&columns); err != nil || columns != "account_id,details_encrypted,created_at,updated_at" {
		t.Fatal("private account child contains plaintext attribute columns")
	}
	if _, err := f.private.Update(f.ctx, f.sess, privateComplete("0")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO private_profile(account_id,details_encrypted) VALUES($1,$2)`, f.u.ID, bytes.Repeat([]byte{1}, 100)); err == nil {
		t.Fatal("account can own more than one private profile")
	}
	other := profileUser(t, f.profileDatabase)
	otherSession := privateIssue(t, f.manager, other)
	stored := privateStored(t, f)
	profileExec(t, f.profileDatabase, `INSERT INTO private_profile(account_id,details_encrypted) VALUES($1,$2)`, other.ID, stored.blob)
	if _, err := f.private.Get(f.ctx, otherSession); !errors.Is(err, ErrUnreadable) {
		t.Fatal("cross-account encrypted profile substitution accepted")
	}
	raw, err := json.Marshal(privatePayload{f.u.ID.String(), "hatef.identity.username.assignment", privateDataFixture(t)})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := f.private.cipher.Encrypt(f.ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	profileExec(t, f.profileDatabase, `UPDATE private_profile SET details_encrypted=$2 WHERE account_id=$1`, f.u.ID, blob)
	if _, err := f.private.Get(f.ctx, f.sess); !errors.Is(err, ErrUnreadable) {
		t.Fatal("cross-purpose profile substitution accepted")
	}
	// Hard deletion uses the existing lifecycle query, not a private-data cleanup.
	profileExec(t, f.profileDatabase, `UPDATE users SET status='pending_deletion',deleted_at='2000-01-01Z' WHERE id=$1`, f.u.ID)
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := username.AcquireOwnershipGuard(f.ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := pglock.LockAccount(f.ctx, tx, f.u.ID); err != nil {
		t.Fatal(err)
	}
	u, err := db.New(tx).GetUserForUpdateIncludingDeleted(f.ctx, f.u.ID)
	if err != nil {
		t.Fatal(err)
	}
	count, err := db.New(tx).HardDeleteUser(f.ctx, db.HardDeleteUserParams{ID: f.u.ID, DeletedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}})
	if err != nil || count != 1 {
		t.Fatal("hard deletion failed")
	}
	if err := lifecycle.EnqueueDeletion(f.ctx, db.New(tx), f.u.ID, u.LifecycleRevision); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	var children int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM private_profile WHERE account_id=$1`, f.u.ID).Scan(&children); err != nil || children != 0 {
		t.Fatal("private child survived hard deletion")
	}
	if _, err := f.private.Get(f.ctx, f.sess); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("deleted private account remained readable")
	}
}

func TestPrivateSessionRecheckedAfterAccountLockIntegration(t *testing.T) {
	for _, mode := range []string{"revoked edit", "revoked stale", "revoked noop", "revoked read", "expired edit", "moderated"} {
		t.Run(mode, func(t *testing.T) {
			f := privateDatabaseFixture(t)
			first, err := f.private.Update(f.ctx, f.sess, privateComplete("0"))
			if err != nil {
				t.Fatal(err)
			}
			before := privateStored(t, f)
			if mode == "expired edit" {
				f.manager = privateManager(t, 150*time.Millisecond)
				f.sess = privateIssue(t, f.manager, f.u)
				f.private.sessions = f.manager
			}
			tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if err := pglock.LockAccount(f.ctx, tx, f.u.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := db.New(tx).GetUserForUpdateIncludingDeleted(f.ctx, f.u.ID); err != nil {
				t.Fatal(err)
			}
			gender, revision := "male", first.Snapshot.LifecycleRevision
			if mode == "revoked noop" {
				gender = "female"
			}
			if mode == "revoked stale" {
				revision = "0"
			}
			result := make(chan error, 1)
			go func() {
				if mode == "revoked read" {
					_, err := f.private.Get(f.ctx, f.sess)
					result <- err
					return
				}
				_, err := f.private.Update(f.ctx, f.sess, PrivateUpdate{ExpectedRevision: revision, Gender: &gender})
				result <- err
			}()
			select {
			case err := <-result:
				t.Fatalf("private edit bypassed account lock: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			switch mode {
			case "expired edit":
				time.Sleep(170 * time.Millisecond)
			case "moderated":
				if _, err := db.New(tx).ModerateUserStatus(f.ctx, db.ModerateUserStatusParams{ID: f.u.ID, Status: "banned"}); err != nil {
					t.Fatal(err)
				}
			default:
				if revoked, err := f.manager.RevokeByID(f.ctx, f.sess.UserID, f.sess.ID); err != nil || !revoked {
					t.Fatal("individual revocation failed")
				}
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("private stale authority reached revision/no-op decision: %v", err)
			}
			after := privateStored(t, f)
			if !bytes.Equal(before.blob, after.blob) || !before.updated.Equal(after.updated) || loadProfileUser(t, f.profileDatabase, f.u.ID).LifecycleRevision != 1 || profileIntentCount(t, f.profileDatabase, f.u.ID) != 1 {
				t.Fatal("stale live authority edited private state")
			}
		})
	}
}

type privateCallbackAuthority struct {
	manager  *session.Manager
	callback func()
}

func (f privateCallbackAuthority) LookupByID(ctx context.Context, userID, sessionID string) (session.Session, error) {
	sess, err := f.manager.LookupByID(ctx, userID, sessionID)
	if err == nil {
		f.callback()
	}
	return sess, err
}

func TestPrivateUsernameAndRevisionOneLockedSnapshotIntegration(t *testing.T) {
	f := privateDatabaseFixture(t)
	if _, err := f.private.Update(f.ctx, f.sess, privateComplete("0")); err != nil {
		t.Fatal(err)
	}
	policy := username.Policy{ID: uuid.New(), Normalization: username.NormalizationV1, MinLetters: 1, MaxCodePoints: 40, Folds: []username.Fold{{From: "\u064a", To: "\u06cc"}, {From: "\u0643", To: "\u06a9"}, {From: "\u0624", To: "\u0648"}, {From: "\u0626", To: "\u06cc"}}, ReservedNames: []string{}}
	normalizer, err := username.New(policy, `[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+(?:\.[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+)*`, bytes.Repeat([]byte{0x59}, 32), "private-test-key")
	if err != nil {
		t.Fatal(err)
	}
	names, err := username.NewStore(f.pool, f.private.cipher, normalizer)
	if err != nil {
		t.Fatal(err)
	}
	a := normalizer.Authority()
	profileExec(t, f.profileDatabase, `INSERT INTO username_policy_artifacts(policy_id,fingerprint,artifact) VALUES($1,$2,$3)`, a.PolicyID, a.Fingerprint[:], normalizer.CanonicalArtifact())
	profileExec(t, f.profileDatabase, `INSERT INTO username_lookup_keys(key_id,key_verifier) VALUES($1,$2)`, a.KeyID, a.KeyVerifier[:])
	profileExec(t, f.profileDatabase, `UPDATE username_active_policy SET policy_id=$1,fingerprint=$2,epoch=1,key_id=$3,key_verifier=$4,admission_state='open' WHERE singleton`, a.PolicyID, a.Fingerprint[:], a.KeyID, a.KeyVerifier[:])
	f.private.names = names
	chosen, err := normalizer.Normalize(privateGiven)
	if err != nil {
		t.Fatal(err)
	}
	writer := make(chan error, 1)
	f.private.sessions = privateCallbackAuthority{manager: f.manager, callback: func() {
		go func() {
			tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				writer <- err
				return
			}
			defer rollbackPrivate(tx)
			if err := names.Assign(f.ctx, tx, f.u.ID, f.u.AuthVersion, chosen); err != nil {
				writer <- err
				return
			}
			if _, err := db.New(tx).AdvanceUserLifecycleRevision(f.ctx, f.u.ID); err != nil {
				writer <- err
				return
			}
			writer <- tx.Commit(f.ctx)
		}()
		select {
		case err := <-writer:
			t.Fatalf("username writer bypassed private snapshot lock: %v", err)
		case <-time.After(30 * time.Millisecond):
		}
	}}
	before, err := f.private.Get(f.ctx, f.sess)
	if err != nil || before.Username != nil || before.PrivateData == nil || before.LifecycleRevision != "1" {
		t.Fatal("GET mixed username/revision snapshots")
	}
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	f.private.sessions = f.manager
	after, err := f.private.Get(f.ctx, f.sess)
	if err != nil || after.Username == nil || after.Username.Display != chosen.Display() || after.LifecycleRevision != "2" || *after.PrivateData != *before.PrivateData {
		t.Fatal("protected username did not use current guarded transaction")
	}
	// No normalizer cannot silently disguise a populated assignment as absence.
	f.private.names = nil
	if _, err := f.private.Get(f.ctx, f.sess); !errors.Is(err, ErrUnavailable) {
		t.Fatal("populated username with unavailable authority reported absent")
	}
}
