package webauthn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// testNow is the fixed instant the ceremony fixtures start from, so challenge
// expiry is asserted against arithmetic rather than the wall clock.
var testNow = time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)

// errBoom stands in for an arbitrary infrastructure failure (connection reset,
// timeout) that is neither pgx.ErrNoRows nor a domain error, proving those are
// wrapped rather than mistaken for a "not found" outcome.
var errBoom = errors.New("boom")

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeUserStore is an in-memory UserStore. SetWebauthnUserHandle reproduces the
// real query's "only write while the column is NULL" semantics, which is what
// the concurrent-registration guard in FinishRegistration relies on.
type fakeUserStore struct {
	mu      sync.Mutex
	byID    map[uuid.UUID]db.User
	byEmail map[string]uuid.UUID

	// getByIDErr/getByEmailErr/setHandleErr inject failures on the matching
	// call; pgx.ErrNoRows is injected the same way as any other error.
	getByIDErr    error
	getByEmailErr error
	setHandleErr  error
	// setHandleAffected overrides the rows-affected result when non-nil,
	// simulating a concurrent writer that won the race.
	setHandleAffected *int64
	// setHandleCalls counts writes so "the handle is pinned exactly once" is
	// observable.
	setHandleCalls int
}

func newFakeUserStore(users ...db.User) *fakeUserStore {
	s := &fakeUserStore{
		byID:    make(map[uuid.UUID]db.User, len(users)),
		byEmail: make(map[string]uuid.UUID, len(users)),
	}
	for _, u := range users {
		s.byID[u.ID] = u
		s.byEmail[u.Email] = u.ID
	}
	return s
}

func (f *fakeUserStore) GetUserByEmail(_ context.Context, email string) (db.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getByEmailErr != nil {
		return db.User{}, f.getByEmailErr
	}
	id, ok := f.byEmail[email]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return f.byID[id], nil
}

func (f *fakeUserStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getByIDErr != nil {
		return db.User{}, f.getByIDErr
	}
	u, ok := f.byID[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (f *fakeUserStore) SetWebauthnUserHandle(_ context.Context, arg db.SetWebauthnUserHandleParams) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setHandleCalls++
	if f.setHandleErr != nil {
		return 0, f.setHandleErr
	}
	if f.setHandleAffected != nil {
		return *f.setHandleAffected, nil
	}
	u, ok := f.byID[arg.ID]
	if !ok || len(u.WebauthnUserHandle) != 0 {
		return 0, nil
	}
	u.WebauthnUserHandle = arg.WebauthnUserHandle
	f.byID[u.ID] = u
	return 1, nil
}

// mustGet returns the current state of a stored user.
func (f *fakeUserStore) mustGet(t *testing.T, id uuid.UUID) db.User {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		t.Fatalf("user %s is not in the fake store", id)
	}
	return u
}

// fakeCredentialStore is an in-memory CredentialStore.
type fakeCredentialStore struct {
	mu     sync.Mutex
	byUser map[uuid.UUID][]db.WebauthnCredential

	createErr error
	listErr   error
	lockErr   error
	updateErr error
	// updateAffected overrides the rows-affected result of the counter update
	// when non-nil (0 means the row vanished mid-ceremony).
	updateAffected *int64
	// lockOverride replaces the row returned by GetWebauthnCredentialForUpdate,
	// simulating a concurrent assertion that advanced the counter after this
	// ceremony loaded its credential list.
	lockOverride *db.WebauthnCredential
	// updated records every counter write for assertions.
	updated []db.UpdateWebauthnSignCountParams
}

func (f *fakeCredentialStore) CreateWebauthnCredential(_ context.Context, arg db.CreateWebauthnCredentialParams) (db.WebauthnCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return db.WebauthnCredential{}, f.createErr
	}
	row := db.WebauthnCredential{
		ID:              arg.ID,
		UserID:          arg.UserID,
		PublicKey:       arg.PublicKey,
		AttestationType: arg.AttestationType,
		SignCount:       arg.SignCount,
		UserPresent:     arg.UserPresent,
		UserVerified:    arg.UserVerified,
		BackupEligible:  arg.BackupEligible,
		BackupState:     arg.BackupState,
		Aaguid:          arg.Aaguid,
		CreatedAt:       pgtype.Timestamptz{Time: testNow, Valid: true},
	}
	if f.byUser == nil {
		f.byUser = make(map[uuid.UUID][]db.WebauthnCredential)
	}
	f.byUser[arg.UserID] = append(f.byUser[arg.UserID], row)
	return row, nil
}

func (f *fakeCredentialStore) ListWebauthnCredentialsByUser(_ context.Context, userID uuid.UUID) ([]db.WebauthnCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	rows := f.byUser[userID]
	out := make([]db.WebauthnCredential, len(rows))
	copy(out, rows)
	return out, nil
}

func (f *fakeCredentialStore) GetWebauthnCredentialForUpdate(_ context.Context, id []byte) (db.WebauthnCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lockErr != nil {
		return db.WebauthnCredential{}, f.lockErr
	}
	if f.lockOverride != nil {
		return *f.lockOverride, nil
	}
	for _, rows := range f.byUser {
		for _, row := range rows {
			if bytes.Equal(row.ID, id) {
				return row, nil
			}
		}
	}
	return db.WebauthnCredential{}, pgx.ErrNoRows
}

func (f *fakeCredentialStore) UpdateWebauthnSignCount(_ context.Context, arg db.UpdateWebauthnSignCountParams) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return 0, f.updateErr
	}
	f.updated = append(f.updated, arg)
	if f.updateAffected != nil {
		return *f.updateAffected, nil
	}
	for userID, rows := range f.byUser {
		for i, row := range rows {
			if bytes.Equal(row.ID, arg.ID) {
				rows[i].SignCount = arg.SignCount
				rows[i].LastUsedAt = pgtype.Timestamptz{Time: testNow, Valid: true}
				f.byUser[userID] = rows
				return 1, nil
			}
		}
	}
	return 0, nil
}

// count returns how many credentials a user currently owns.
func (f *fakeCredentialStore) count(userID uuid.UUID) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.byUser[userID])
}

// ---------------------------------------------------------------------------
// Software authenticator
// ---------------------------------------------------------------------------

// Authenticator data flag bits (WebAuthn Level 3 §6.1). Backup Eligible (0x08)
// and Backup State (0x10) are deliberately left clear: the library rejects an
// assertion whose BE flag disagrees with the stored credential, so both
// ceremonies must report the same (false) value.
const (
	flagUserPresent  byte = 0x01
	flagUserVerified byte = 0x04
	flagAttestedData byte = 0x40
)

// credentialIDLen is the fixed width of this authenticator's credential IDs.
// Keeping it a constant means the 2-byte length prefix in attested credential
// data is written from an untyped constant, with no narrowing conversion to
// audit, and the invariant is asserted where the prefix is built.
const credentialIDLen = 32

// softAuthenticator is a minimal ES256 software authenticator: enough of a
// roaming key to produce byte-exact attestation and assertion responses so the
// service is exercised through the real go-webauthn verifier rather than a stub.
// rpID, origin, and signCount are mutable so tests can forge the phishing and
// cloned-authenticator cases.
type softAuthenticator struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	credID []byte
	aaguid []byte
	// rpID is the domain the authenticator believes it is signing for; a
	// mismatch with the RP's configured RPID must fail verification.
	rpID string
	// origin is written into clientDataJSON and checked against RPOrigins.
	origin string
	// signCount is the counter reported by the next ceremony.
	signCount uint32
}

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate authenticator key: %v", err)
	}
	credID := make([]byte, credentialIDLen)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("generate credential id: %v", err)
	}
	aaguid := make([]byte, 16)
	if _, err := rand.Read(aaguid); err != nil {
		t.Fatalf("generate aaguid: %v", err)
	}
	return &softAuthenticator{
		t:      t,
		key:    key,
		credID: credID,
		aaguid: aaguid,
		rpID:   "localhost",
		origin: "http://localhost:8080",
	}
}

// coseKey encodes the public key exactly as an authenticator would: a CTAP2
// canonical CBOR COSE_Key with integer labels.
func (a *softAuthenticator) coseKey() []byte {
	a.t.Helper()

	// Bytes returns the uncompressed SEC 1 point (0x04 || X || Y); its two
	// 32-byte coordinates are exactly what a COSE_Key carries. Reading them
	// this way avoids the deprecated big.Int PublicKey.X/Y fields.
	point, err := a.key.PublicKey.Bytes()
	if err != nil {
		a.t.Fatalf("encode public key: %v", err)
	}
	if len(point) != 65 || point[0] != 0x04 {
		a.t.Fatalf("point = %d bytes starting %#x, want a 65-byte uncompressed P-256 point", len(point), point[0])
	}

	key := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: point[1:33],
		YCoord: point[33:65],
	}
	encoded, err := webauthncbor.Marshal(key)
	if err != nil {
		a.t.Fatalf("marshal COSE key: %v", err)
	}
	return encoded
}

// authData builds authenticatorData: rpIdHash(32) || flags(1) || counter(4) and,
// for registration, the attested credential data (AAGUID || credIdLen || credId
// || COSE key).
func (a *softAuthenticator) authData(flags byte, attested bool) []byte {
	rpIDHash := sha256.Sum256([]byte(a.rpID))
	out := make([]byte, 0, 128)
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, a.signCount)
	out = append(out, counter...)
	if attested {
		out = append(out, a.aaguid...)
		if len(a.credID) != credentialIDLen {
			a.t.Fatalf("credential id is %d bytes, want %d", len(a.credID), credentialIDLen)
		}
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, credentialIDLen)
		out = append(out, length...)
		out = append(out, a.credID...)
		out = append(out, a.coseKey()...)
	}
	return out
}

// clientData builds the clientDataJSON the browser would produce, echoing the
// server-issued challenge and the origin the ceremony ran on.
func (a *softAuthenticator) clientData(ceremony protocol.CeremonyType, challenge string) []byte {
	a.t.Helper()
	encoded, err := json.Marshal(map[string]any{
		"type":        string(ceremony),
		"challenge":   challenge,
		"origin":      a.origin,
		"crossOrigin": false,
	})
	if err != nil {
		a.t.Fatalf("marshal client data: %v", err)
	}
	return encoded
}

// publicKeyCredential is the envelope common to both ceremony responses.
func (a *softAuthenticator) publicKeyCredential() protocol.PublicKeyCredential {
	return protocol.PublicKeyCredential{
		Credential: protocol.Credential{
			ID:   base64.RawURLEncoding.EncodeToString(a.credID),
			Type: "public-key",
		},
		RawID: a.credID,
	}
}

// attestation returns the JSON body of navigator.credentials.create() for the
// given challenge, using "none" attestation (the conveyance the platform asks
// for, since it does not verify attestation certificates).
func (a *softAuthenticator) attestation(challenge string) []byte {
	a.t.Helper()

	// Declared locally with explicit CBOR tags: protocol.AttestationObject's
	// own field set is shaped for decoding, not encoding.
	attestationObject := struct {
		Format       string         `cbor:"fmt"`
		AttStatement map[string]any `cbor:"attStmt"`
		AuthData     []byte         `cbor:"authData"`
	}{
		Format:       "none",
		AttStatement: map[string]any{},
		AuthData:     a.authData(flagUserPresent|flagUserVerified|flagAttestedData, true),
	}
	raw, err := webauthncbor.Marshal(attestationObject)
	if err != nil {
		a.t.Fatalf("marshal attestation object: %v", err)
	}

	body, err := json.Marshal(protocol.CredentialCreationResponse{
		PublicKeyCredential: a.publicKeyCredential(),
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: a.clientData(protocol.CreateCeremony, challenge),
			},
			AttestationObject: raw,
		},
	})
	if err != nil {
		a.t.Fatalf("marshal attestation response: %v", err)
	}
	return body
}

// assertion returns the JSON body of navigator.credentials.get() for the given
// challenge, signing over authenticatorData || SHA-256(clientDataJSON) as the
// spec requires.
func (a *softAuthenticator) assertion(challenge string, userHandle []byte) []byte {
	a.t.Helper()

	clientDataJSON := a.clientData(protocol.AssertCeremony, challenge)
	authData := a.authData(flagUserPresent|flagUserVerified, false)

	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)

	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatalf("sign assertion: %v", err)
	}

	body, err := json.Marshal(protocol.CredentialAssertionResponse{
		PublicKeyCredential: a.publicKeyCredential(),
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: clientDataJSON},
			AuthenticatorData:     authData,
			Signature:             signature,
			UserHandle:            userHandle,
		},
	})
	if err != nil {
		a.t.Fatalf("marshal assertion response: %v", err)
	}
	return body
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

// ceremonyFixture wires a real Service over the in-memory fakes with a pinned
// clock, so both the challenge store and the service agree on "now".
type ceremonyFixture struct {
	svc        *Service
	users      *fakeUserStore
	creds      *fakeCredentialStore
	challenges *MemoryChallengeStore
	user       db.User
	auth       *softAuthenticator
	clock      *time.Time
}

func newFixture(t *testing.T) *ceremonyFixture {
	t.Helper()

	user := db.User{ID: uuid.New(), Email: "passkey@example.com"}
	users := newFakeUserStore(user)
	creds := &fakeCredentialStore{}

	clock := testNow
	challenges := newFixedChallengeStore(&clock)

	svc, err := New(testConfig(), users, creds, challenges)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svc.now = func() time.Time { return clock }

	return &ceremonyFixture{
		svc:        svc,
		users:      users,
		creds:      creds,
		challenges: challenges,
		user:       user,
		auth:       newSoftAuthenticator(t),
		clock:      &clock,
	}
}

// advance moves the shared clock forward, expiring pending challenges.
func (f *ceremonyFixture) advance(d time.Duration) { *f.clock = f.clock.Add(d) }

// ctx is a convenience for the many single-use contexts below.
func (f *ceremonyFixture) ctx() context.Context { return context.Background() }

// handle returns the user's currently persisted WebAuthn user handle.
func (f *ceremonyFixture) handle(t *testing.T) []byte {
	t.Helper()
	return f.users.mustGet(t, f.user.ID).WebauthnUserHandle
}

// register drives a full attestation ceremony with the supplied authenticator.
func (f *ceremonyFixture) register(t *testing.T, auth *softAuthenticator) db.WebauthnCredential {
	t.Helper()

	options, err := f.svc.BeginRegistration(f.ctx(), f.user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	row, err := f.svc.FinishRegistration(f.ctx(), f.user.ID, auth.attestation(challengeOf(options.Response.Challenge)))
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	return row
}

// login drives a full assertion ceremony with the supplied authenticator.
func (f *ceremonyFixture) login(t *testing.T, auth *softAuthenticator) (uuid.UUID, error) {
	t.Helper()

	options, err := f.svc.BeginLogin(f.ctx(), f.user.Email)
	if err != nil {
		return uuid.Nil, err
	}
	return f.svc.FinishLogin(f.ctx(), auth.assertion(challengeOf(options.Response.Challenge), f.handle(t)))
}

// challengeOf renders an options challenge exactly as the browser echoes it back
// inside clientDataJSON: unpadded base64url.
func challengeOf(challenge protocol.URLEncodedBase64) string {
	return base64.RawURLEncoding.EncodeToString(challenge)
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// TestRegistrationThenLoginHappyPath is the end-to-end proof that the options
// this service emits, signed by a real ES256 authenticator, verify through the
// library and produce an authenticated user.
func TestRegistrationThenLoginHappyPath(t *testing.T) {
	fx := newFixture(t)

	row := fx.register(t, fx.auth)

	if !bytes.Equal(row.ID, fx.auth.credID) {
		t.Errorf("stored credential id = %x, want %x", row.ID, fx.auth.credID)
	}
	if row.UserID != fx.user.ID {
		t.Errorf("credential user = %s, want %s", row.UserID, fx.user.ID)
	}
	if len(row.PublicKey) == 0 {
		t.Error("stored credential has no public key")
	}
	if row.AttestationType != "none" {
		t.Errorf("attestation type = %q, want %q", row.AttestationType, "none")
	}
	if !row.UserPresent || !row.UserVerified {
		t.Errorf("flags: UserPresent=%v UserVerified=%v, want both true", row.UserPresent, row.UserVerified)
	}
	if row.BackupEligible || row.BackupState {
		t.Errorf("flags: BackupEligible=%v BackupState=%v, want both false", row.BackupEligible, row.BackupState)
	}
	if got := row.Aaguid; !bytes.Equal(got[:], fx.auth.aaguid) {
		t.Errorf("aaguid = %x, want %x", got[:], fx.auth.aaguid)
	}
	if len(fx.handle(t)) != userHandleByteLen {
		t.Fatalf("persisted handle = %x, want %d bytes", fx.handle(t), userHandleByteLen)
	}

	// A second ceremony with an advanced counter signs in.
	fx.auth.signCount = 1
	userID, err := fx.login(t, fx.auth)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if userID != fx.user.ID {
		t.Errorf("authenticated user = %s, want %s", userID, fx.user.ID)
	}
}

// TestBeginRegistrationOptions locks in the RP binding and the anonymised
// 64-bit user handle carried in the creation options.
func TestBeginRegistrationOptions(t *testing.T) {
	fx := newFixture(t)

	options, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if options.Response.RelyingParty.ID != "localhost" {
		t.Errorf("rp.id = %q, want %q", options.Response.RelyingParty.ID, "localhost")
	}
	if options.Response.RelyingParty.Name != "Hatef Identity" {
		t.Errorf("rp.name = %q, want %q", options.Response.RelyingParty.Name, "Hatef Identity")
	}
	if len(options.Response.Challenge) < 16 {
		t.Errorf("challenge = %d bytes, want at least 16", len(options.Response.Challenge))
	}

	// User.ID is typed `any` in the library, so assert on the wire form.
	raw, err := json.Marshal(options)
	if err != nil {
		t.Fatalf("marshal options: %v", err)
	}
	var wire struct {
		PublicKey struct {
			User struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal options: %v", err)
	}
	handle, err := base64.RawURLEncoding.DecodeString(wire.PublicKey.User.ID)
	if err != nil {
		t.Fatalf("user.id is not base64url: %v", err)
	}
	if len(handle) != userHandleByteLen {
		t.Errorf("user.id = %d bytes, want %d (a random 64-bit handle)", len(handle), userHandleByteLen)
	}
	if bytes.Equal(handle, fx.user.ID[:]) || strings.Contains(wire.PublicKey.User.ID, fx.user.ID.String()) {
		t.Error("user.id leaks the account UUID; it must be an unlinkable random handle")
	}
	if wire.PublicKey.User.Name != fx.user.Email {
		t.Errorf("user.name = %q, want %q", wire.PublicKey.User.Name, fx.user.Email)
	}
	if wire.PublicKey.User.DisplayName != fx.user.Email {
		t.Errorf("user.displayName = %q, want %q", wire.PublicKey.User.DisplayName, fx.user.Email)
	}
}

// TestBeginRegistrationStoresChallenge proves the pending ceremony is keyed by
// the challenge, owned by the caller, and stamped with the configured TTL.
func TestBeginRegistrationStoresChallenge(t *testing.T) {
	fx := newFixture(t)

	options, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	pending, err := fx.challenges.Take(challengeOf(options.Response.Challenge))
	if err != nil {
		t.Fatalf("challenge was not stored under its own value: %v", err)
	}
	if pending.UserRef != fx.user.ID {
		t.Errorf("UserRef = %s, want %s", pending.UserRef, fx.user.ID)
	}
	if want := testNow.Add(5 * time.Minute); !pending.Expires.Equal(want) {
		t.Errorf("Expires = %s, want %s", pending.Expires, want)
	}
	if len(pending.Session.UserID) != userHandleByteLen {
		t.Errorf("session user handle = %d bytes, want %d", len(pending.Session.UserID), userHandleByteLen)
	}
}

// TestBeginRegistrationDoesNotPersistHandle proves an abandoned ceremony never
// pins a handle to the account.
func TestBeginRegistrationDoesNotPersistHandle(t *testing.T) {
	fx := newFixture(t)

	if _, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID); err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if got := fx.handle(t); len(got) != 0 {
		t.Errorf("handle = %x after begin only, want it unset until the ceremony completes", got)
	}
	if fx.users.setHandleCalls != 0 {
		t.Errorf("SetWebauthnUserHandle calls = %d, want 0", fx.users.setHandleCalls)
	}
}

func TestBeginRegistrationUnknownUser(t *testing.T) {
	fx := newFixture(t)

	if _, err := fx.svc.BeginRegistration(fx.ctx(), uuid.New()); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("error = %v, want ErrUserNotFound", err)
	}
}

// TestBeginRegistrationWrapsStoreFailures proves an infrastructure fault is not
// silently downgraded to a domain error.
func TestBeginRegistrationWrapsStoreFailures(t *testing.T) {
	t.Run("user store", func(t *testing.T) {
		fx := newFixture(t)
		fx.users.getByIDErr = errBoom

		_, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID)
		if !errors.Is(err, errBoom) {
			t.Fatalf("error = %v, want it to wrap errBoom", err)
		}
		if errors.Is(err, ErrUserNotFound) {
			t.Error("a transport failure was reported as ErrUserNotFound")
		}
		if !strings.Contains(err.Error(), "webauthn: load user") {
			t.Errorf("error = %q, want it to mention the failing operation", err)
		}
	})

	t.Run("credential store", func(t *testing.T) {
		fx := newFixture(t)
		fx.creds.listErr = errBoom

		_, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID)
		if !errors.Is(err, errBoom) {
			t.Fatalf("error = %v, want it to wrap errBoom", err)
		}
		if !strings.Contains(err.Error(), "webauthn: list credentials") {
			t.Errorf("error = %q, want it to mention the failing operation", err)
		}
	})
}

// TestBeginRegistrationExcludesRegisteredCredentials proves an authenticator
// that is already enrolled is offered in excludeCredentials, so it refuses to
// create a duplicate.
func TestBeginRegistrationExcludesRegisteredCredentials(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth)

	options, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if len(options.Response.CredentialExcludeList) != 1 {
		t.Fatalf("len(excludeCredentials) = %d, want 1", len(options.Response.CredentialExcludeList))
	}
	if got := options.Response.CredentialExcludeList[0].CredentialID; !bytes.Equal(got, fx.auth.credID) {
		t.Errorf("excludeCredentials[0] = %x, want %x", []byte(got), fx.auth.credID)
	}
}

// TestBeginRegistrationReusesPersistedHandle proves every credential on an
// account signs over the same user handle.
func TestBeginRegistrationReusesPersistedHandle(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth)
	first := fx.handle(t)

	options, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	pending, err := fx.challenges.Take(challengeOf(options.Response.Challenge))
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if !bytes.Equal(pending.Session.UserID, first) {
		t.Errorf("second ceremony handle = %x, want the persisted %x", pending.Session.UserID, first)
	}
}

func TestFinishRegistrationMalformedBody(t *testing.T) {
	fx := newFixture(t)

	bodies := map[string][]byte{
		"empty":              nil,
		"not json":           []byte("<html>"),
		"empty object":       []byte(`{}`),
		"missing id":         []byte(`{"type":"public-key","rawId":"AAAA","response":{}}`),
		"wrong type":         []byte(`{"id":"AAAA","type":"password","rawId":"AAAA","response":{}}`),
		"non base64url id":   []byte(`{"id":"!!!!","type":"public-key","rawId":"AAAA","response":{}}`),
		"truncated envelope": []byte(`{"id":"AAAA","type":"public-key"`),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			if _, err := fx.svc.FinishRegistration(fx.ctx(), fx.user.ID, body); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

// TestFinishRegistrationForeignChallenge proves a challenge issued to another
// account cannot be completed by the caller, even with a valid signature.
func TestFinishRegistrationForeignChallenge(t *testing.T) {
	fx := newFixture(t)
	victim := db.User{ID: uuid.New(), Email: "victim@example.com"}
	fx.users.byID[victim.ID] = victim
	fx.users.byEmail[victim.Email] = victim.ID

	options, err := fx.svc.BeginRegistration(fx.ctx(), victim.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	body := fx.auth.attestation(challengeOf(options.Response.Challenge))
	if _, err := fx.svc.FinishRegistration(fx.ctx(), fx.user.ID, body); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("error = %v, want ErrChallengeNotFound", err)
	}
	if fx.creds.count(victim.ID) != 0 || fx.creds.count(fx.user.ID) != 0 {
		t.Error("a credential was stored for a mismatched challenge")
	}
}

// TestFinishRegistrationChallengeIsSingleUse proves an attestation response
// cannot be replayed.
func TestFinishRegistrationChallengeIsSingleUse(t *testing.T) {
	fx := newFixture(t)

	options, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	body := fx.auth.attestation(challengeOf(options.Response.Challenge))

	if _, err := fx.svc.FinishRegistration(fx.ctx(), fx.user.ID, body); err != nil {
		t.Fatalf("first FinishRegistration: %v", err)
	}
	if _, err := fx.svc.FinishRegistration(fx.ctx(), fx.user.ID, body); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("replayed error = %v, want ErrChallengeNotFound", err)
	}
	if got := fx.creds.count(fx.user.ID); got != 1 {
		t.Errorf("credentials = %d, want 1 (the replay must not store a second row)", got)
	}
}

func TestFinishRegistrationExpiredChallenge(t *testing.T) {
	fx := newFixture(t)

	options, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	fx.advance(5*time.Minute + time.Second)

	body := fx.auth.attestation(challengeOf(options.Response.Challenge))
	if _, err := fx.svc.FinishRegistration(fx.ctx(), fx.user.ID, body); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("error = %v, want ErrChallengeExpired", err)
	}
}

// TestFinishRegistrationRejectsForgedCeremony covers the phishing-resistance
// properties: a response produced for a different origin or a different RP ID
// must not verify.
func TestFinishRegistrationRejectsForgedCeremony(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*softAuthenticator)
	}{
		{
			name:   "wrong origin",
			mutate: func(a *softAuthenticator) { a.origin = "https://identity.hatef.ir.evil.example" },
		},
		{
			name:   "wrong rp id",
			mutate: func(a *softAuthenticator) { a.rpID = "evil.example" },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			tc.mutate(fx.auth)

			options, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID)
			if err != nil {
				t.Fatalf("BeginRegistration: %v", err)
			}
			body := fx.auth.attestation(challengeOf(options.Response.Challenge))

			if _, err := fx.svc.FinishRegistration(fx.ctx(), fx.user.ID, body); !errors.Is(err, ErrVerification) {
				t.Fatalf("error = %v, want ErrVerification", err)
			}
			if fx.creds.count(fx.user.ID) != 0 {
				t.Error("a forged ceremony stored a credential")
			}
			if len(fx.handle(t)) != 0 {
				t.Error("a forged ceremony pinned a user handle")
			}
		})
	}
}

// TestFinishRegistrationPersistsHandleOnce proves the handle is written on the
// first passkey only and shared by every later credential.
func TestFinishRegistrationPersistsHandleOnce(t *testing.T) {
	fx := newFixture(t)

	fx.register(t, fx.auth)
	handle := fx.handle(t)
	if fx.users.setHandleCalls != 1 {
		t.Fatalf("SetWebauthnUserHandle calls after first registration = %d, want 1", fx.users.setHandleCalls)
	}

	second := newSoftAuthenticator(t)
	fx.register(t, second)

	if fx.users.setHandleCalls != 1 {
		t.Errorf("SetWebauthnUserHandle calls after second registration = %d, want 1", fx.users.setHandleCalls)
	}
	if got := fx.handle(t); !bytes.Equal(got, handle) {
		t.Errorf("handle = %x after second registration, want the original %x", got, handle)
	}
	if got := fx.creds.count(fx.user.ID); got != 2 {
		t.Errorf("credentials = %d, want 2", got)
	}
}

// TestFinishRegistrationConcurrentHandleWrite proves that losing the race to
// pin the handle aborts the registration rather than storing a credential bound
// to a handle the account no longer advertises.
func TestFinishRegistrationConcurrentHandleWrite(t *testing.T) {
	fx := newFixture(t)
	var none int64
	fx.users.setHandleAffected = &none

	options, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	body := fx.auth.attestation(challengeOf(options.Response.Challenge))

	_, err = fx.svc.FinishRegistration(fx.ctx(), fx.user.ID, body)
	if err == nil {
		t.Fatal("FinishRegistration succeeded, want a concurrent-registration error")
	}
	if !strings.Contains(err.Error(), "concurrent registration") {
		t.Errorf("error = %q, want it to describe the concurrent write", err)
	}
	if fx.creds.count(fx.user.ID) != 0 {
		t.Error("a credential was stored despite the failed handle write")
	}
}

// TestFinishRegistrationWrapsStoreFailures proves persistence faults surface as
// wrapped internal errors, not as verification failures.
func TestFinishRegistrationWrapsStoreFailures(t *testing.T) {
	tests := []struct {
		name       string
		arrange    func(*ceremonyFixture)
		wantSubstr string
	}{
		{
			name:       "handle write",
			arrange:    func(fx *ceremonyFixture) { fx.users.setHandleErr = errBoom },
			wantSubstr: "webauthn: persist user handle",
		},
		{
			name:       "credential insert",
			arrange:    func(fx *ceremonyFixture) { fx.creds.createErr = errBoom },
			wantSubstr: "webauthn: persist credential",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)

			options, err := fx.svc.BeginRegistration(fx.ctx(), fx.user.ID)
			if err != nil {
				t.Fatalf("BeginRegistration: %v", err)
			}
			body := fx.auth.attestation(challengeOf(options.Response.Challenge))
			tc.arrange(fx)

			_, err = fx.svc.FinishRegistration(fx.ctx(), fx.user.ID, body)
			if !errors.Is(err, errBoom) {
				t.Fatalf("error = %v, want it to wrap errBoom", err)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantSubstr)
			}
			if errors.Is(err, ErrVerification) {
				t.Error("a storage fault was reported as a verification failure")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

// TestBeginLoginOptions proves the assertion options bind the RP ID and offer
// exactly the account's registered credentials.
func TestBeginLoginOptions(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth)

	options, err := fx.svc.BeginLogin(fx.ctx(), fx.user.Email)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if options.Response.RelyingPartyID != "localhost" {
		t.Errorf("rpId = %q, want %q", options.Response.RelyingPartyID, "localhost")
	}
	if len(options.Response.AllowedCredentials) != 1 {
		t.Fatalf("len(allowCredentials) = %d, want 1", len(options.Response.AllowedCredentials))
	}
	if got := options.Response.AllowedCredentials[0].CredentialID; !bytes.Equal(got, fx.auth.credID) {
		t.Errorf("allowCredentials[0] = %x, want %x", []byte(got), fx.auth.credID)
	}
	if len(options.Response.Challenge) < 16 {
		t.Errorf("challenge = %d bytes, want at least 16", len(options.Response.Challenge))
	}

	pending, err := fx.challenges.Take(challengeOf(options.Response.Challenge))
	if err != nil {
		t.Fatalf("challenge was not stored: %v", err)
	}
	if pending.UserRef != fx.user.ID {
		t.Errorf("UserRef = %s, want %s", pending.UserRef, fx.user.ID)
	}
}

// TestBeginLoginRejectsUnusableAccounts covers the three states that cannot
// start a user-named ceremony. Callers collapse them into one opaque failure;
// the usernameless path and the enumeration-proof mock challenge land in 4.3.
func TestBeginLoginRejectsUnusableAccounts(t *testing.T) {
	t.Run("unknown email", func(t *testing.T) {
		fx := newFixture(t)
		if _, err := fx.svc.BeginLogin(fx.ctx(), "nobody@example.com"); !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("error = %v, want ErrUserNotFound", err)
		}
	})

	t.Run("no handle", func(t *testing.T) {
		fx := newFixture(t)
		if _, err := fx.svc.BeginLogin(fx.ctx(), fx.user.Email); !errors.Is(err, ErrNoCredentials) {
			t.Fatalf("error = %v, want ErrNoCredentials", err)
		}
	})

	t.Run("handle but no credentials", func(t *testing.T) {
		fx := newFixture(t)
		// A handle survives credential deletion, so this state is reachable.
		user := fx.users.mustGet(t, fx.user.ID)
		user.WebauthnUserHandle = bytes.Repeat([]byte{0xAB}, userHandleByteLen)
		fx.users.byID[user.ID] = user

		if _, err := fx.svc.BeginLogin(fx.ctx(), fx.user.Email); !errors.Is(err, ErrNoCredentials) {
			t.Fatalf("error = %v, want ErrNoCredentials", err)
		}
	})

	t.Run("store failure", func(t *testing.T) {
		fx := newFixture(t)
		fx.users.getByEmailErr = errBoom

		_, err := fx.svc.BeginLogin(fx.ctx(), fx.user.Email)
		if !errors.Is(err, errBoom) {
			t.Fatalf("error = %v, want it to wrap errBoom", err)
		}
		if errors.Is(err, ErrUserNotFound) {
			t.Error("a transport failure was reported as ErrUserNotFound")
		}
	})
}

func TestFinishLoginMalformedBody(t *testing.T) {
	fx := newFixture(t)

	bodies := map[string][]byte{
		"empty":        nil,
		"not json":     []byte("nope"),
		"empty object": []byte(`{}`),
		"wrong type":   []byte(`{"id":"AAAA","type":"password","rawId":"AAAA","response":{}}`),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			if _, err := fx.svc.FinishLogin(fx.ctx(), body); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

// TestFinishLoginUnknownChallenge proves an assertion that was never issued a
// challenge is rejected before any credential lookup.
func TestFinishLoginUnknownChallenge(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth)

	forged := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	body := fx.auth.assertion(forged, fx.handle(t))

	if _, err := fx.svc.FinishLogin(fx.ctx(), body); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("error = %v, want ErrChallengeNotFound", err)
	}
}

// TestFinishLoginChallengeIsSingleUse proves a captured assertion cannot be
// replayed to mint a second session.
func TestFinishLoginChallengeIsSingleUse(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth)
	fx.auth.signCount = 1

	options, err := fx.svc.BeginLogin(fx.ctx(), fx.user.Email)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	body := fx.auth.assertion(challengeOf(options.Response.Challenge), fx.handle(t))

	if _, err := fx.svc.FinishLogin(fx.ctx(), body); err != nil {
		t.Fatalf("first FinishLogin: %v", err)
	}
	if _, err := fx.svc.FinishLogin(fx.ctx(), body); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("replayed error = %v, want ErrChallengeNotFound", err)
	}
}

func TestFinishLoginExpiredChallenge(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth)
	fx.auth.signCount = 1

	options, err := fx.svc.BeginLogin(fx.ctx(), fx.user.Email)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	fx.advance(5*time.Minute + time.Nanosecond)

	body := fx.auth.assertion(challengeOf(options.Response.Challenge), fx.handle(t))
	if _, err := fx.svc.FinishLogin(fx.ctx(), body); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("error = %v, want ErrChallengeExpired", err)
	}
}

// TestFinishLoginRejectsForgedCeremony is the phishing-resistance assertion for
// login: a response signed for another origin or another RP ID never
// authenticates, even though the challenge itself is genuine.
func TestFinishLoginRejectsForgedCeremony(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*softAuthenticator)
	}{
		{
			name:   "wrong origin",
			mutate: func(a *softAuthenticator) { a.origin = "https://identity.hatef.ir.evil.example" },
		},
		{
			name:   "wrong rp id",
			mutate: func(a *softAuthenticator) { a.rpID = "evil.example" },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			fx.register(t, fx.auth)
			fx.auth.signCount = 1
			tc.mutate(fx.auth)

			options, err := fx.svc.BeginLogin(fx.ctx(), fx.user.Email)
			if err != nil {
				t.Fatalf("BeginLogin: %v", err)
			}
			body := fx.auth.assertion(challengeOf(options.Response.Challenge), fx.handle(t))

			userID, err := fx.svc.FinishLogin(fx.ctx(), body)
			if !errors.Is(err, ErrVerification) {
				t.Fatalf("error = %v, want ErrVerification", err)
			}
			if userID != uuid.Nil {
				t.Errorf("user id = %s, want uuid.Nil on failure", userID)
			}
		})
	}
}

// TestFinishLoginRejectsForeignSignature proves the assertion must be signed by
// the private key of a credential the account actually owns.
func TestFinishLoginRejectsForeignSignature(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth)

	// A different key pair re-using the enrolled credential ID: the ID matches
	// a stored credential, but the signature cannot.
	impostor := newSoftAuthenticator(t)
	impostor.credID = fx.auth.credID
	impostor.signCount = 1

	options, err := fx.svc.BeginLogin(fx.ctx(), fx.user.Email)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	body := impostor.assertion(challengeOf(options.Response.Challenge), fx.handle(t))

	if _, err := fx.svc.FinishLogin(fx.ctx(), body); !errors.Is(err, ErrVerification) {
		t.Fatalf("error = %v, want ErrVerification", err)
	}
}

// TestFinishLoginRejectsHandleMismatch proves the defensive check that the
// account's handle still matches the one the challenge was issued for.
func TestFinishLoginRejectsHandleMismatch(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth)
	fx.auth.signCount = 1

	options, err := fx.svc.BeginLogin(fx.ctx(), fx.user.Email)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	body := fx.auth.assertion(challengeOf(options.Response.Challenge), fx.handle(t))

	// The stored handle changes after the ceremony began.
	user := fx.users.mustGet(t, fx.user.ID)
	user.WebauthnUserHandle = bytes.Repeat([]byte{0xEE}, userHandleByteLen)
	fx.users.byID[user.ID] = user

	if _, err := fx.svc.FinishLogin(fx.ctx(), body); !errors.Is(err, ErrVerification) {
		t.Fatalf("error = %v, want ErrVerification", err)
	}
}

// TestFinishLoginAdvancesSignCount proves the observed counter is persisted, so
// the next assertion is compared against a moving baseline.
func TestFinishLoginAdvancesSignCount(t *testing.T) {
	fx := newFixture(t)
	row := fx.register(t, fx.auth)
	if row.SignCount != 0 {
		t.Fatalf("initial sign count = %d, want 0", row.SignCount)
	}

	fx.auth.signCount = 7
	if _, err := fx.login(t, fx.auth); err != nil {
		t.Fatalf("login: %v", err)
	}

	if len(fx.creds.updated) != 1 {
		t.Fatalf("counter writes = %d, want 1", len(fx.creds.updated))
	}
	if got := fx.creds.updated[0].SignCount; got != 7 {
		t.Errorf("persisted sign count = %d, want 7", got)
	}
	if !bytes.Equal(fx.creds.updated[0].ID, fx.auth.credID) {
		t.Errorf("counter written for %x, want %x", fx.creds.updated[0].ID, fx.auth.credID)
	}

	// The stored baseline moved, so replaying counter 7 is now a clone.
	fx.auth.signCount = 7
	if _, err := fx.login(t, fx.auth); !errors.Is(err, ErrCredentialCloned) {
		t.Fatalf("error = %v, want ErrCredentialCloned", err)
	}
}

// TestFinishLoginDetectsClonedAuthenticator covers the signature-counter audit
// from docs/architecture.md: a counter that fails to advance means the private
// key may have been extracted.
func TestFinishLoginDetectsClonedAuthenticator(t *testing.T) {
	tests := []struct {
		name       string
		registerAt uint32
		loginAt    uint32
	}{
		{name: "counter regressed", registerAt: 5, loginAt: 3},
		{name: "counter unchanged", registerAt: 5, loginAt: 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			fx.auth.signCount = tc.registerAt
			fx.register(t, fx.auth)

			fx.auth.signCount = tc.loginAt
			userID, err := fx.login(t, fx.auth)
			if !errors.Is(err, ErrCredentialCloned) {
				t.Fatalf("error = %v, want ErrCredentialCloned", err)
			}
			if userID != uuid.Nil {
				t.Errorf("user id = %s, want uuid.Nil on a rejected login", userID)
			}
			if len(fx.creds.updated) != 0 {
				t.Error("a rejected login still advanced the stored counter")
			}
		})
	}
}

// TestFinishLoginAllowsCounterlessAuthenticator proves the one legitimate
// exception: authenticators that do not implement a counter always report zero.
func TestFinishLoginAllowsCounterlessAuthenticator(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth) // registered at counter 0

	for i := 0; i < 3; i++ {
		userID, err := fx.login(t, fx.auth) // still 0
		if err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
		if userID != fx.user.ID {
			t.Fatalf("authenticated user = %s, want %s", userID, fx.user.ID)
		}
	}
}

// TestFinishLoginDetectsConcurrentCounterAdvance proves the re-read under
// SELECT ... FOR UPDATE closes the check-then-write window: another assertion
// that advanced the counter after this ceremony loaded its credential list
// makes this one a replay.
func TestFinishLoginDetectsConcurrentCounterAdvance(t *testing.T) {
	fx := newFixture(t)
	row := fx.register(t, fx.auth)

	// The locked row reports a counter beyond the one this assertion carries.
	locked := row
	locked.SignCount = 9
	fx.creds.lockOverride = &locked

	fx.auth.signCount = 3
	if _, err := fx.login(t, fx.auth); !errors.Is(err, ErrCredentialCloned) {
		t.Fatalf("error = %v, want ErrCredentialCloned", err)
	}
	if len(fx.creds.updated) != 0 {
		t.Error("the counter was written despite the stale assertion")
	}
}

// TestFinishLoginCredentialRemovedMidCeremony proves a credential deleted
// between the two steps fails the login instead of panicking or authenticating.
func TestFinishLoginCredentialRemovedMidCeremony(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth)
	fx.auth.signCount = 1

	options, err := fx.svc.BeginLogin(fx.ctx(), fx.user.Email)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	body := fx.auth.assertion(challengeOf(options.Response.Challenge), fx.handle(t))
	fx.creds.lockErr = pgx.ErrNoRows

	if _, err := fx.svc.FinishLogin(fx.ctx(), body); !errors.Is(err, ErrVerification) {
		t.Fatalf("error = %v, want ErrVerification", err)
	}
}

// TestFinishLoginCounterUpdateWroteNothing proves a vanished row at write time
// fails the login rather than reporting success.
func TestFinishLoginCounterUpdateWroteNothing(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth)
	fx.auth.signCount = 1

	var none int64
	fx.creds.updateAffected = &none

	if _, err := fx.login(t, fx.auth); !errors.Is(err, ErrVerification) {
		t.Fatalf("error = %v, want ErrVerification", err)
	}
}

// TestFinishLoginWrapsStoreFailures proves counter-write faults are internal
// errors, not silent successes.
func TestFinishLoginWrapsStoreFailures(t *testing.T) {
	fx := newFixture(t)
	fx.register(t, fx.auth)
	fx.auth.signCount = 1
	fx.creds.updateErr = errBoom

	_, err := fx.login(t, fx.auth)
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want it to wrap errBoom", err)
	}
	if !strings.Contains(err.Error(), "webauthn: update sign count") {
		t.Errorf("error = %q, want it to mention the failing operation", err)
	}
}

// ---------------------------------------------------------------------------
// Key listing
// ---------------------------------------------------------------------------

func TestListCredentials(t *testing.T) {
	fx := newFixture(t)

	empty, err := fx.svc.ListCredentials(fx.ctx(), fx.user.ID)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("len(credentials) = %d, want 0 before registration", len(empty))
	}

	fx.register(t, fx.auth)
	fx.register(t, newSoftAuthenticator(t))

	rows, err := fx.svc.ListCredentials(fx.ctx(), fx.user.ID)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("len(credentials) = %d, want 2", len(rows))
	}
	if !bytes.Equal(rows[0].ID, fx.auth.credID) {
		t.Errorf("credentials[0] = %x, want %x", rows[0].ID, fx.auth.credID)
	}

	// Another account's credentials are never returned.
	other, err := fx.svc.ListCredentials(fx.ctx(), uuid.New())
	if err != nil {
		t.Fatalf("ListCredentials for another account: %v", err)
	}
	if len(other) != 0 {
		t.Errorf("len(credentials) = %d for an unrelated account, want 0", len(other))
	}
}

func TestListCredentialsWrapsStoreFailure(t *testing.T) {
	fx := newFixture(t)
	fx.creds.listErr = errBoom

	_, err := fx.svc.ListCredentials(fx.ctx(), fx.user.ID)
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want it to wrap errBoom", err)
	}
	if !strings.Contains(err.Error(), "webauthn: list credentials") {
		t.Errorf("error = %q, want it to mention the failing operation", err)
	}
}
