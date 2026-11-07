//go:build integration

package server

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
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/registration"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// These fixtures never adopt/migrate the supplied DATABASE_URL. The shared
// helper creates a uniquely named child DB and confirms its teardown.
type signupIntegrationDB struct {
	*pgxpool.Pool
	failAfter           atomic.Int32
	writes              atomic.Int32
	unknownCommit       atomic.Bool
	unknownBeforeCommit atomic.Bool
}
type signupIntegrationTx struct {
	pgx.Tx
	database *signupIntegrationDB
}
type signupFailureRow struct {
	pgx.Row
	database *signupIntegrationDB
	mutation bool
}

func signupMutation(sql string) bool {
	for _, name := range []string{"CreateUser", "AdvanceUserLifecycleRevision", "InsertLifecycleEvent", "SetWebauthnUserHandle", "CreateWebauthnCredential", "SetUserPhone", "CompleteRegistrationAttempt", "SaveRegistrationAttempt"} {
		if strings.HasPrefix(sql, "-- name: "+name+" ") {
			return true
		}
	}
	return false
}
func (d *signupIntegrationDB) wrote() error {
	n := d.writes.Add(1)
	if d.failAfter.Load() == n {
		return errors.New("injected failure after durable SQL write")
	}
	return nil
}
func (d *signupIntegrationDB) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := d.Pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &signupIntegrationTx{tx, d}, nil
}
func (tx *signupIntegrationTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tag, err := tx.Tx.Exec(ctx, sql, args...)
	if err == nil && signupMutation(sql) {
		err = tx.database.wrote()
	}
	return tag, err
}
func (tx *signupIntegrationTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return signupFailureRow{tx.Tx.QueryRow(ctx, sql, args...), tx.database, signupMutation(sql)}
}
func (r signupFailureRow) Scan(dest ...any) error {
	err := r.Row.Scan(dest...)
	if err == nil && r.mutation {
		err = r.database.wrote()
	}
	return err
}
func (tx *signupIntegrationTx) Commit(ctx context.Context) error {
	if tx.database.unknownBeforeCommit.Swap(false) {
		return errors.New("injected precommit connection failure")
	}
	if err := tx.Tx.Commit(ctx); err != nil {
		return err
	}
	if tx.database.unknownCommit.Swap(false) {
		return errors.New("injected lost positive commit response")
	}
	return nil
}

type signupIntegrationMail struct {
	mu      sync.Mutex
	token   string
	attempt string
	err     error
	before  func()
}

func (m *signupIntegrationMail) Send(_ context.Context, _ string, message []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.before != nil {
		m.before()
	}
	text := string(message)
	marker := "#attempt_id="
	start := strings.Index(text, marker)
	if start < 0 {
		return errors.New("missing verification fragment")
	}
	fragment := strings.Split(text[start+len(marker):], "\r\n")[0]
	values := strings.Split(fragment, "&token=")
	if len(values) != 2 {
		return errors.New("malformed verification fragment")
	}
	m.attempt, m.token = values[0], values[1]
	return m.err
}

type signupIntegrationSender struct {
	mu    sync.Mutex
	codes map[string]string
	err   error
}

func (s *signupIntegrationSender) SendCode(_ context.Context, phone, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[phone] = code
	return s.err
}
func (s *signupIntegrationSender) code(phone string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.codes[phone]
}

type signupIntegration struct {
	ctx      context.Context
	database *signupIntegrationDB
	cipher   *envelope.Encryptor
	index    *blindindex.Indexer
	limiter  *ratelimit.RedisLimiter
	mail     *signupIntegrationMail
	sender   *signupIntegrationSender
	phone    *smsotp.Service
	otps     *smsotp.RedisOTPStore
	wa       *webauthn.Service
	store    *registration.Store
	service  *registration.Service
	server   *Server
	client   *portalTestClient
	sequence int
}

func newSignupIntegration(t *testing.T) *signupIntegration {
	t.Helper()
	if os.Getenv("REQUIRE_REGISTRATION_INTEGRATION") == "1" && (os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_URL") == "") {
		t.Fatal("mandatory registration integration requires isolated PostgreSQL and Redis")
	}
	ctx, pool, otps := phoneIntegrationServices(t)
	opts, err := redis.ParseURL(os.Getenv("REDIS_URL"))
	if err != nil {
		t.Fatal("invalid fixture Redis config")
	}
	opts.ContextTimeoutEnabled = true
	opts.MaxRetries = -1
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	if client.Ping(ctx).Err() != nil {
		t.Fatal("configured fixture Redis unavailable")
	}
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{7}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	index, err := blindindex.New(bytes.Repeat([]byte{8}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := ratelimit.NewRedisLimiter(client)
	if err != nil {
		t.Fatal(err)
	}
	users, err := smsotp.NewUserStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	sender := &signupIntegrationSender{codes: map[string]string{}}
	phone, err := smsotp.New(smsotp.Config{HashPepper: bytes.Repeat([]byte{9}, 32), SignupEnabled: true, GlobalPerDay: 100000, MaxPendingSignup: 100}, users, cipher, index, limiter, otps, sender)
	if err != nil {
		t.Fatal(err)
	}
	challenges, err := webauthn.NewRedisChallengeStore(client)
	if err != nil {
		t.Fatal(err)
	}
	wa, err := webauthn.New(webauthn.Config{RPID: "identity.example", RPOrigins: []string{testPortalOrigin}, RPDisplayName: "Identity", ChallengeTTL: time.Minute, MockChallengeKey: bytes.Repeat([]byte{10}, 32)}, db.New(pool), db.New(pool), challenges, webauthn.WithTransacter(pool))
	if err != nil {
		t.Fatal(err)
	}
	database := &signupIntegrationDB{Pool: pool}
	store, err := registration.NewStore(database, cipher, 100)
	if err != nil {
		t.Fatal(err)
	}
	mail := &signupIntegrationMail{}
	email, err := registration.NewEmail(registration.EmailConfig{From: "identity@example.com", PublicOrigin: testPortalOrigin}, mail)
	if err != nil {
		t.Fatal(err)
	}
	service, err := registration.NewService(registration.Deps{Store: store, Database: database, Email: email, Phone: phone, WebAuthn: wa, Encryptor: cipher, Indexer: index, Limiter: limiter, GlobalDailyLimit: 100000, EmailHourlyLimit: 10})
	if err != nil {
		t.Fatal(err)
	}
	browser := newPortalTestClient(t, testPortalOrigin)
	server := New(config.Config{Environment: "production", PortalOrigin: testPortalOrigin}, nil, Deps{Registration: service, WebAuthn: wa, DPoPValidator: browser.validator})
	return &signupIntegration{ctx: ctx, database: database, cipher: cipher, index: index, limiter: limiter, mail: mail, sender: sender, phone: phone, otps: otps, wa: wa, store: store, service: service, server: server, client: browser}
}

func (f *signupIntegration) request(t *testing.T, operation string, body any, want int) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := registrationPath
	if operation != "" {
		path += "/" + operation
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	r.RemoteAddr = fmt.Sprintf("198.51.%d.9:12345", f.sequence)
	f.client.sign(t, r)
	w := boundaryServe(t, f.server, r, want)
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("signup minted session cookie")
	}
	return w
}
func signupAuthorityBody(a registration.Authority) map[string]any {
	return map[string]any{"attempt_id": a.AttemptID.String(), "capability": base64.RawURLEncoding.EncodeToString(a.Capability)}
}
func signupRandomPhone(t *testing.T) string {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1000000000))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("+989%09d", n.Int64())
}
func (f *signupIntegration) start(t *testing.T, email, phone string) registration.Authority {
	t.Helper()
	f.sequence++
	w := f.request(t, "start", map[string]string{"email": email, "phone": phone}, 201)
	var response struct {
		AttemptID      string `json:"attempt_id"`
		Capability     string `json:"capability"`
		CanonicalEmail string `json:"canonical_email"`
		EmailSent      bool   `json:"email_sent"`
	}
	if json.Unmarshal(w.Body.Bytes(), &response) != nil || !response.EmailSent {
		t.Fatal("pending proof email not issued")
	}
	id, err := uuid.Parse(response.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := base64.RawURLEncoding.DecodeString(response.Capability)
	if err != nil || len(capability) != 32 {
		t.Fatal("invalid independent signup capability")
	}
	if response.Capability == f.mail.token {
		t.Fatal("email token reused signup capability")
	}
	return registration.Authority{AttemptID: id, Capability: capability, JKT: f.client.jkt}
}
func (f *signupIntegration) prove(t *testing.T, a registration.Authority, phone string) *protocol.CredentialCreation {
	t.Helper()
	f.request(t, "email/verify", map[string]string{"attempt_id": a.AttemptID.String(), "token": f.mail.token}, 204)
	w := f.request(t, "phone/send", signupAuthorityBody(a), 200)
	var response struct {
		ID string `json:"verification_id"`
	}
	if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.ID == "" {
		t.Fatal("missing phone challenge")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := f.otps.Delete(ctx, response.ID); err != nil {
			t.Error("owned OTP cleanup failed")
		}
	})
	body := signupAuthorityBody(a)
	body["verification_id"] = response.ID
	body["code"] = f.sender.code(phone)
	f.request(t, "phone/verify", body, 204)
	w = f.request(t, "passkey/options", signupAuthorityBody(a), 200)
	var options protocol.CredentialCreation
	if json.Unmarshal(w.Body.Bytes(), &options) != nil {
		t.Fatal("invalid passkey options")
	}
	return &options
}
func (f *signupIntegration) inventory(t *testing.T) (int, int, int, int) {
	t.Helper()
	var users, credentials, roles, events int
	if f.database.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM webauthn_credentials),(SELECT count(*) FROM user_roles),(SELECT count(*) FROM event_outbox WHERE subject='identity.user.created')`).Scan(&users, &credentials, &roles, &events) != nil {
		t.Fatal("fixture inventory failed")
	}
	return users, credentials, roles, events
}
func (f *signupIntegration) assertInventory(t *testing.T, wantUsers, wantCredentials, wantEvents int) {
	t.Helper()
	users, credentials, roles, events := f.inventory(t)
	if users != wantUsers || credentials != wantCredentials || roles != 0 || events != wantEvents {
		t.Fatalf("account birth inventory users=%d credentials=%d roles=%d intents=%d", users, credentials, roles, events)
	}
}

type signupAuthenticator struct {
	key        *ecdsa.PrivateKey
	id         []byte
	handle     []byte
	cose       []byte
	origin, rp string
}

func newSignupAuthenticator(t *testing.T, options *protocol.CredentialCreation) *signupAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)}, Curve: int64(webauthncose.P256), XCoord: point[1:33], YCoord: point[33:]})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(options.Response.User.ID)
	var encoded string
	_ = json.Unmarshal(raw, &encoded)
	handle, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(handle) != 8 {
		t.Fatal("handle is not independent8 bytes")
	}
	id := make([]byte, 32)
	if _, err = rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &signupAuthenticator{key: key, id: id, handle: handle, cose: cose, origin: testPortalOrigin, rp: "identity.example"}
}
func (a *signupAuthenticator) authData(flags byte, count uint32, attested bool) []byte {
	rpHash := sha256.Sum256([]byte(a.rp))
	data := append([]byte{}, rpHash[:]...)
	data = append(data, flags)
	data = binary.BigEndian.AppendUint32(data, count)
	if attested {
		data = append(data, make([]byte, 16)...)
		data = binary.BigEndian.AppendUint16(data, uint16(len(a.id)))
		data = append(data, a.id...)
		data = append(data, a.cose...)
	}
	return data
}
func (a *signupAuthenticator) credential(t *testing.T, options *protocol.CredentialCreation, uv bool) json.RawMessage {
	t.Helper()
	flags := byte(0x41)
	if uv {
		flags |= 0x04
	}
	object, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(flags, 0, true)})
	if err != nil {
		t.Fatal(err)
	}
	clientData, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": base64.RawURLEncoding.EncodeToString(options.Response.Challenge), "origin": a.origin, "crossOrigin": false})
	enc := base64.RawURLEncoding.EncodeToString
	body, _ := json.Marshal(map[string]any{"id": enc(a.id), "rawId": enc(a.id), "type": "public-key", "authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{"credProps": map[string]bool{"rk": true}}, "response": map[string]any{"clientDataJSON": enc(clientData), "attestationObject": enc(object), "transports": []string{"internal"}}})
	return body
}
func (a *signupAuthenticator) assertion(t *testing.T, options *protocol.CredentialAssertion) []byte {
	t.Helper()
	clientData, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(options.Response.Challenge), "origin": a.origin, "crossOrigin": false})
	authData := a.authData(0x05, 1, false)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(bytes.Clone(authData), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	body, _ := json.Marshal(map[string]any{"id": enc(a.id), "rawId": enc(a.id), "type": "public-key", "response": map[string]any{"clientDataJSON": enc(clientData), "authenticatorData": enc(authData), "signature": enc(signature), "userHandle": enc(a.handle)}})
	return body
}

func TestRegistrationHTTPAtomicBirthAndLostResponseFreshLoginIntegration(t *testing.T) {
	f := newSignupIntegration(t)
	phone := signupRandomPhone(t)
	email := "\u062d\u0633\u0627\u0628" + uuid.NewString() + "@example.com"
	f.mail.before = func() {
		var count int
		if f.database.QueryRow(f.ctx, "SELECT count(*) FROM registration_attempts").Scan(&count) != nil || count != 1 {
			t.Error("mail sent before pending SQL commit")
		}
	}
	a := f.start(t, email, phone)
	f.assertInventory(t, 0, 0, 0)
	if _, err := f.service.PasskeyOptions(f.ctx, a); !errors.Is(err, registration.ErrProofRequired) {
		t.Fatal("unproven contacts got ceremony")
	}
	options := f.prove(t, a, phone)
	f.assertInventory(t, 0, 0, 0)
	auth := newSignupAuthenticator(t, options)
	credential := auth.credential(t, options, true)
	f.database.unknownCommit.Store(true)
	if _, err := f.service.Complete(f.ctx, a, credential); !errors.Is(err, registration.ErrOutcomeUnknown) {
		t.Fatal("lost commit response not explicit")
	}
	f.assertInventory(t, 1, 1, 1)
	result := f.request(t, "result", signupAuthorityBody(a), 200)
	var receipt registration.Outcome
	if json.Unmarshal(result.Body.Bytes(), &receipt) != nil || receipt.Next != "login" || receipt.State != "completed" {
		t.Fatal("durable receipt not recovered")
	}
	if replay, err := f.service.Complete(f.ctx, a, credential); err != nil || !replay.ReceiptExpiresAt.Equal(*receipt.ReceiptExpiresAt) {
		t.Fatal("same completion did not return exact receipt")
	}
	if _, err := f.service.Complete(f.ctx, a, json.RawMessage(`{"changed":true}`)); !errors.Is(err, registration.ErrConflict) {
		t.Fatal("changed completed request accepted")
	}
	f.assertInventory(t, 1, 1, 1)
	user, err := db.New(f.database.Pool).GetUserByEmail(f.ctx, email)
	if err != nil || user.PasswordHash != nil || user.LifecycleRevision != 1 || !bytes.Equal(user.WebauthnUserHandle, auth.handle) {
		t.Fatal("account birth mapping incomplete")
	}
	plain, err := f.cipher.Decrypt(f.ctx, user.PhoneEncrypted)
	if err != nil || string(plain) != phone {
		t.Fatal("verified encrypted phone did not match frozen proof")
	}
	ctx := dpop.WithProof(f.ctx, &dpop.Proof{JKT: a.JKT})
	loginOptions, err := f.wa.BeginDiscoverableLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	login, err := f.wa.FinishLoginVersioned(ctx, auth.assertion(t, loginOptions))
	if err != nil || login.ID != user.ID || login.DPoPJKT != a.JKT {
		t.Fatal("fresh normal discoverable login failed")
	}
}

func TestRegistrationSQLFailureAfterEveryBirthWriteIntegration(t *testing.T) {
	f := newSignupIntegration(t)
	for write := int32(1); write <= 7; write++ {
		t.Run(fmt.Sprintf("write_%d", write), func(t *testing.T) {
			phone := signupRandomPhone(t)
			a := f.start(t, uuid.NewString()+"@example.com", phone)
			options := f.prove(t, a, phone)
			auth := newSignupAuthenticator(t, options)
			f.database.writes.Store(0)
			f.database.failAfter.Store(write)
			if _, err := f.service.Complete(f.ctx, a, auth.credential(t, options, true)); err == nil {
				t.Fatal("injected write failure reported success")
			}
			f.database.failAfter.Store(0)
			f.assertInventory(t, 0, 0, 0)
			result, err := f.service.Result(f.ctx, a)
			if err != nil || result.State != "pending" {
				t.Fatal("failed birth changed durable outcome")
			}
		})
	}
}

func TestRegistrationTwoReplicaAndDuplicateIdentityIntegration(t *testing.T) {
	f := newSignupIntegration(t)
	phone := signupRandomPhone(t)
	email := uuid.NewString() + "@example.com"
	a := f.start(t, email, phone)
	options := f.prove(t, a, phone)
	auth := newSignupAuthenticator(t, options)
	credential := auth.credential(t, options, true)
	store, err := registration.NewStore(f.database, f.cipher, 100)
	if err != nil {
		t.Fatal(err)
	}
	emailSender, err := registration.NewEmail(registration.EmailConfig{From: "identity@example.com", PublicOrigin: testPortalOrigin}, f.mail)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := registration.NewService(registration.Deps{Store: store, Database: f.database, Email: emailSender, Phone: f.phone, WebAuthn: f.wa, Encryptor: f.cipher, Indexer: f.index, Limiter: f.limiter, GlobalDailyLimit: 100000, EmailHourlyLimit: 10})
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for _, service := range []*registration.Service{f.service, replica} {
		wg.Add(1)
		go func(service *registration.Service) {
			defer wg.Done()
			<-gate
			if result, err := service.Complete(f.ctx, a, credential); err != nil || result.State != "completed" {
				t.Errorf("replica finalization failed: %v", err)
			}
		}(service)
	}
	close(gate)
	wg.Wait()
	f.assertInventory(t, 1, 1, 1)
	// SQL uniqueness remains authoritative; a canonical-equivalent mailbox must
	// never attach another credential to the first user.
	phone = signupRandomPhone(t)
	duplicate := f.start(t, strings.ToUpper(email), phone)
	options = f.prove(t, duplicate, phone)
	auth = newSignupAuthenticator(t, options)
	if _, err = f.service.Complete(f.ctx, duplicate, auth.credential(t, options, true)); !errors.Is(err, registration.ErrConflict) {
		t.Fatal("duplicate identity attached credential")
	}
	f.assertInventory(t, 1, 1, 1)
	// Two independently proven attempts compete for one new canonical identity.
	email = uuid.NewString() + "@example.com"
	firstPhone, secondPhone := signupRandomPhone(t), signupRandomPhone(t)
	first := f.start(t, email, firstPhone)
	firstOptions := f.prove(t, first, firstPhone)
	firstAuth := newSignupAuthenticator(t, firstOptions)
	second := f.start(t, strings.ToUpper(email), secondPhone)
	secondOptions := f.prove(t, second, secondPhone)
	secondAuth := newSignupAuthenticator(t, secondOptions)
	var won, conflicted atomic.Int32
	gate = make(chan struct{})
	for _, candidate := range []struct {
		service   *registration.Service
		authority registration.Authority
		body      json.RawMessage
	}{{f.service, first, firstAuth.credential(t, firstOptions, true)}, {replica, second, secondAuth.credential(t, secondOptions, true)}} {
		wg.Add(1)
		go func(candidate struct {
			service   *registration.Service
			authority registration.Authority
			body      json.RawMessage
		}) {
			defer wg.Done()
			<-gate
			_, err := candidate.service.Complete(f.ctx, candidate.authority, candidate.body)
			if err == nil {
				won.Add(1)
			} else if errors.Is(err, registration.ErrConflict) {
				conflicted.Add(1)
			} else {
				t.Errorf("duplicate identity race failure: %v", err)
			}
		}(candidate)
	}
	close(gate)
	wg.Wait()
	if won.Load() != 1 || conflicted.Load() != 1 {
		t.Fatal("duplicate identity finalization did not have one authoritative winner")
	}
	f.assertInventory(t, 2, 2, 2)
}

func TestRegistrationBindingsExpiryCollisionsAndConsumeFailureIntegration(t *testing.T) {
	f := newSignupIntegration(t)
	phone := signupRandomPhone(t)
	a := f.start(t, uuid.NewString()+"@example.com", phone)
	foreign := a
	foreign.JKT = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{22}, 32))
	token, _ := base64.RawURLEncoding.DecodeString(f.mail.token)
	if err := f.service.VerifyEmail(f.ctx, a.AttemptID, token, foreign.JKT); !errors.Is(err, registration.ErrUnauthorized) {
		t.Fatal("wrong browser verified email")
	}
	if _, err := f.service.Result(f.ctx, foreign); !errors.Is(err, registration.ErrUnauthorized) {
		t.Fatal("wrong JKT read receipt")
	}
	if _, err := f.service.Result(f.ctx, registration.Authority{AttemptID: a.AttemptID, Capability: token, JKT: a.JKT}); !errors.Is(err, registration.ErrUnauthorized) {
		t.Fatal("email token became signup capability")
	}
	f.request(t, "email/verify", map[string]string{"attempt_id": a.AttemptID.String(), "token": f.mail.token}, 204)
	id, err := f.service.SendPhone(f.ctx, a, fmt.Sprintf("198.51.%d.9", f.sequence))
	if err != nil {
		t.Fatal(err)
	}
	f.database.writes.Store(0)
	f.database.failAfter.Store(1)
	if err = f.service.VerifyPhone(f.ctx, a, id, f.sender.code(phone)); !errors.Is(err, registration.ErrRestartRequired) {
		t.Fatal("SQL-failed consumed OTP not restart-required")
	}
	f.database.failAfter.Store(0)
	if err = f.service.VerifyPhone(f.ctx, a, id, f.sender.code(phone)); !errors.Is(err, registration.ErrProofRequired) {
		t.Fatal("consumed OTP resurrected")
	}
	f.assertInventory(t, 0, 0, 0)
	// A separate proof-complete attempt isolates the real handle constraint.
	phone = signupRandomPhone(t)
	a = f.start(t, uuid.NewString()+"@example.com", phone)
	options := f.prove(t, a, phone)
	auth := newSignupAuthenticator(t, options)
	for _, kind := range []string{"origin", "rp", "uv"} {
		copy := *auth
		if kind == "origin" {
			copy.origin = "https://attacker.example"
		}
		if kind == "rp" {
			copy.rp = "attacker.example"
		}
		if _, err = f.service.Complete(f.ctx, a, copy.credential(t, options, kind != "uv")); err == nil {
			t.Fatal("invalid signed signup accepted")
		}
	}
	if _, err = f.database.Exec(f.ctx, "INSERT INTO users(email,status,webauthn_user_handle) VALUES($1,'active',$2)", uuid.NewString()+"@collision.invalid", auth.handle); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Complete(f.ctx, a, auth.credential(t, options, true)); !errors.Is(err, registration.ErrNewCeremony) {
		t.Fatal("handle collision did not require new ceremony")
	}
	f.assertInventory(t, 1, 0, 0)
	result, err := f.service.Result(f.ctx, a)
	if err != nil || result.State != "failed" {
		t.Fatal("handle collision attempt remained usable")
	}
	// Missing/corrupted envelopes and expired proof clocks are fail closed.
	phone = signupRandomPhone(t)
	a = f.start(t, uuid.NewString()+"@example.com", phone)
	if _, err = f.database.Exec(f.ctx, "UPDATE registration_attempts SET details_encrypted=overlay(details_encrypted placing '\\x00'::bytea from 1 for 1) WHERE id=$1", a.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Result(f.ctx, a); err == nil {
		t.Fatal("corrupted attempt admitted")
	}
}

func TestRegistrationSignupAuthorityCannotUseSessionRoutesIntegration(t *testing.T) {
	f := newSignupIntegration(t)
	a := f.start(t, uuid.NewString()+"@example.com", signupRandomPhone(t))
	codec, err := session.NewCookieCodec(session.CookieConfig{Name: "__Host-session", Secure: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	f.server.deps.SessionManager = manager
	guard, ok := f.server.sessionGuard("registration test")
	if !ok {
		t.Fatal("no session guard")
	}
	for _, path := range []string{"/api/v1/users/me", "/api/v1/auth/webauthn/register/verify", "/api/v1/auth/recovery-codes", "/api/v1/auth/stepup/verify", "/api/v1/admin/users/lookup"} {
		// Exercise the common real guard, without substituting signup for cookies.
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(a.Capability))
		f.client.sign(t, r)
		w := httptest.NewRecorder()
		guard.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("signup authority entered session route") })).ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatal("signup token authenticated account route")
		}
	}
}

func TestRegistrationReservedIdentitiesAndCredentialCollisionsIntegration(t *testing.T) {
	f := newSignupIntegration(t)
	for _, kind := range []string{"pending_deletion_email", "pending_deletion_phone", "credential"} {
		t.Run(kind, func(t *testing.T) {
			phone := signupRandomPhone(t)
			email := uuid.NewString() + "@example.com"
			a := f.start(t, email, phone)
			options := f.prove(t, a, phone)
			auth := newSignupAuthenticator(t, options)
			var owner uuid.UUID
			reservationEmail := uuid.NewString() + "@reservation.invalid"
			if kind == "pending_deletion_email" {
				reservationEmail = email
			}
			if err := f.database.QueryRow(f.ctx, "INSERT INTO users(email,status,deleted_at) VALUES($1,'pending_deletion',clock_timestamp()) RETURNING id", reservationEmail).Scan(&owner); err != nil {
				t.Fatal(err)
			}
			if kind == "pending_deletion_phone" {
				index := f.index.Compute(phone)
				encrypted, err := f.cipher.Encrypt(f.ctx, []byte(phone))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.database.Exec(f.ctx, "UPDATE users SET phone_blind_index=$2,phone_encrypted=$3 WHERE id=$1", owner, index, encrypted); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "credential" {
				if _, err := db.New(f.database.Pool).CreateWebauthnCredential(f.ctx, db.CreateWebauthnCredentialParams{ID: auth.id, UserID: owner, PublicKey: auth.cose, AttestationType: "none", UserPresent: true, UserVerified: true}); err != nil {
					t.Fatal(err)
				}
			}
			users, credentials, roles, events := f.inventory(t)
			if _, err := f.service.Complete(f.ctx, a, auth.credential(t, options, true)); !errors.Is(err, registration.ErrConflict) {
				t.Fatal("SQL reservation/collision not a sanitized conflict")
			}
			u, c, r, e := f.inventory(t)
			if u != users || c != credentials || r != roles || e != events {
				t.Fatal("conflict attached credentials or committed partial birth")
			}
		})
	}
}

func TestRegistrationProofExpiryAndUnknownPhoneCommitIntegration(t *testing.T) {
	f := newSignupIntegration(t)
	for _, commitWins := range []bool{false, true} {
		t.Run(fmt.Sprintf("phone_commit_%t", commitWins), func(t *testing.T) {
			phone := signupRandomPhone(t)
			a := f.start(t, uuid.NewString()+"@example.com", phone)
			token, _ := base64.RawURLEncoding.DecodeString(f.mail.token)
			if err := f.service.VerifyEmail(f.ctx, a.AttemptID, token, a.JKT); err != nil {
				t.Fatal(err)
			}
			id, err := f.service.SendPhone(f.ctx, a, fmt.Sprintf("198.51.%d.9", f.sequence))
			if err != nil {
				t.Fatal(err)
			}
			if commitWins {
				f.database.unknownCommit.Store(true)
			} else {
				f.database.unknownBeforeCommit.Store(true)
			}
			err = f.service.VerifyPhone(f.ctx, a, id, f.sender.code(phone))
			if commitWins && err != nil || !commitWins && !errors.Is(err, registration.ErrRestartRequired) {
				t.Fatal("unknown phone SQL outcome resolved incorrectly")
			}
			result, err := f.service.Result(f.ctx, a)
			if err != nil || result.PhoneVerified != commitWins {
				t.Fatal("durable phone proof differs from result")
			}
			if err := f.phone.ConsumeSignupCode(f.ctx, a.AttemptID, a.JKT, phone, id, f.sender.code(phone)); !errors.Is(err, smsotp.ErrNoActiveCode) {
				t.Fatal("unknown commit restored Redis proof")
			}
		})
	}
	phone := signupRandomPhone(t)
	a := f.start(t, uuid.NewString()+"@example.com", phone)
	options := f.prove(t, a, phone)
	auth := newSignupAuthenticator(t, options)
	// Move every authoritative clock together, preserving the schema's fixed
	// durations and frozen bindings, rather than relying on a wall-clock sleep.
	if _, err := f.database.Exec(f.ctx, `UPDATE registration_attempts SET
		created_at=created_at-interval '20 minutes',expires_at=expires_at-interval '20 minutes',
		email_token_issued_at=email_token_issued_at-interval '20 minutes',email_token_expires_at=email_token_expires_at-interval '20 minutes',
		email_verified_at=email_verified_at-interval '20 minutes',phone_verified_at=phone_verified_at-interval '20 minutes',
		passkey_created_at=passkey_created_at-interval '20 minutes',passkey_expires_at=passkey_expires_at-interval '20 minutes' WHERE id=$1`, a.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Complete(f.ctx, a, auth.credential(t, options, true)); !errors.Is(err, registration.ErrExpired) {
		t.Fatal("expired pending authority created account")
	}
	if _, err := f.service.Result(f.ctx, a); !errors.Is(err, registration.ErrExpired) {
		t.Fatal("expired pending capability regained authority")
	}
	f.assertInventory(t, 0, 0, 0)
}

func TestRegistrationHTTPPublicProofReplayDoesNotAllocateIntegration(t *testing.T) {
	f := newSignupIntegration(t)
	f.sequence++
	body, _ := json.Marshal(map[string]string{"email": uuid.NewString() + "@example.com", "phone": signupRandomPhone(t)})
	request := httptest.NewRequest(http.MethodPost, registrationPath+"/start", bytes.NewReader(body))
	request.RemoteAddr = fmt.Sprintf("198.51.%d.9:12345", f.sequence)
	f.client.sign(t, request)
	proof := request.Header.Get("DPoP")
	boundaryServe(t, f.server, request, http.StatusCreated)
	request = httptest.NewRequest(http.MethodPost, registrationPath+"/start", bytes.NewReader(body))
	request.RemoteAddr = fmt.Sprintf("198.51.%d.9:12345", f.sequence)
	f.client.prepare(request)
	request.Header.Set("DPoP", proof)
	boundaryServe(t, f.server, request, http.StatusUnauthorized)
	var attempts int
	if f.database.QueryRow(f.ctx, "SELECT count(*) FROM registration_attempts").Scan(&attempts) != nil || attempts != 1 {
		t.Fatal("transport proof replay allocated another attempt")
	}
	f.assertInventory(t, 0, 0, 0)
}
