//go:build portalfixture

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

const fixtureRunID = "0123456789abcdef0123456789abcdef"

func TestFixtureDatabaseBoundary(t *testing.T) {
	runID := "0123456789abcdef0123456789abcdef"
	for _, dsn := range []string{
		"postgres://127.0.0.1:1234/portal_browser_" + runID + "?sslmode=disable",
		"postgresql://localhost:1234/portal_browser_" + runID,
		"postgres://[::1]:1234/portal_browser_" + runID,
	} {
		if err := validateDatabase(dsn, runID); err != nil {
			t.Fatal("valid disposable database rejected")
		}
	}
	for _, dsn := range []string{
		"postgres://127.0.0.1/identity", "postgres://db.internal/portal_browser_" + runID,
		"postgres://127.0.0.1/portal_browser_other", "postgres://127.0.0.1/portal_browser_" + runID + "?host=db.internal",
		"postgres://127.0.0.1/portal_browser_" + runID + "?dbname=identity",
		"postgres://127.0.0.1/portal_browser_" + runID + "#fragment", "host=127.0.0.1 dbname=identity",
	} {
		if validateDatabase(dsn, runID) == nil {
			t.Fatal("unsafe database accepted")
		}
	}
}

func TestFixtureCredentialMatchesCDPAndCOSE(t *testing.T) {
	handle := []byte("12345678")
	cred, id, cose, err := newCredential(handle)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(cred.PrivateKey)
	if err != nil {
		t.Fatal("invalid private-key encoding")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal("CDP credential is not PKCS8")
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve.Params().Name != "P-256" {
		t.Fatal("expected P-256 fixture")
	}
	var fields map[int]any
	if err := webauthncbor.Unmarshal(cose, &fields); err != nil {
		t.Fatal("invalid COSE fixture")
	}
	x, xOK := fields[-2].([]byte)
	y, yOK := fields[-3].([]byte)
	if !xOK || !yOK || sha256.Sum256(x) != sha256.Sum256(privateKey.X.FillBytes(make([]byte, 32))) || sha256.Sum256(y) != sha256.Sum256(privateKey.Y.FillBytes(make([]byte, 32))) {
		t.Fatal("COSE public key does not match CDP private key")
	}
	if cred.RPID != "localhost" || !cred.IsResidentCredential || len(id) != 32 || cred.CredentialID != base64.StdEncoding.EncodeToString(id) || cred.UserHandle != base64.StdEncoding.EncodeToString(handle) {
		t.Fatal("invalid discoverable CDP fixture")
	}
}

func TestFixtureSessionHashUsesCanonicalBase64URL(t *testing.T) {
	sum := sha256.Sum256([]byte("fixture session"))
	valid := base64.RawURLEncoding.EncodeToString(sum[:])
	if !validSessionHash(valid) {
		t.Fatal("canonical session hash was rejected")
	}
	for _, value := range []string{"", valid + "=", base64.RawURLEncoding.EncodeToString(sum[:31]), "not-a-session-hash"} {
		if validSessionHash(value) {
			t.Fatalf("invalid session hash was accepted: %q", value)
		}
	}
}

func TestFixtureCertificateIsLocalAndShortLived(t *testing.T) {
	material, err := localCertificate()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(material["cert"]))
	if block == nil {
		t.Fatal("missing local certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("invalid local certificate")
	}
	if cert.VerifyHostname("localhost") != nil || cert.VerifyHostname("127.0.0.1") != nil || cert.VerifyHostname("example.com") == nil || cert.NotAfter.Sub(cert.NotBefore).Minutes() > 62 {
		t.Fatal("certificate escaped local test boundary")
	}
}

func TestFixtureRejectsUnarmedAndProductionRuns(t *testing.T) {
	for _, action := range []string{"seed", "totp-code", "migrate"} {
		t.Run(action, func(t *testing.T) {
			t.Setenv("PORTAL_FIXTURE_ALLOW", "")
			if run([]string{action}) == nil {
				t.Fatal("unarmed fixture accepted")
			}
			t.Setenv("PORTAL_FIXTURE_ALLOW", "1")
			t.Setenv("PORTAL_FIXTURE_RUN_ID", fixtureRunID)
			t.Setenv("APP_ENV", "production")
			if run([]string{action}) == nil {
				t.Fatal("production fixture accepted")
			}
		})
	}
}

func fixtureKEK(t *testing.T) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("cannot generate test KEK")
	}
	t.Setenv(config.EnvMasterKEK, base64.StdEncoding.EncodeToString(key))
	t.Setenv(config.EnvMasterKEKVersion, "37")
}

type seedTransaction struct {
	pgx.Tx
	user       db.User
	committed  bool
	rolledBack bool
	failMFA    bool
}

func (s *seedTransaction) Begin(context.Context) (pgx.Tx, error) { return s, nil }
func (s *seedTransaction) Commit(context.Context) error {
	s.committed = true
	return nil
}
func (s *seedTransaction) Rollback(context.Context) error {
	s.rolledBack = true
	return nil
}
func (s *seedTransaction) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "INSERT INTO users") {
		s.user = db.User{ID: args[0].(uuid.UUID), Email: args[1].(string), Status: "active"}
	}
	if strings.Contains(sql, "is_mfa_enabled = TRUE") {
		if s.failMFA {
			return pgconn.CommandTag{}, errors.New("private driver diagnostic must not escape")
		}
		if args[0] != s.user.ID {
			return pgconn.CommandTag{}, errors.New("wrong TOTP account")
		}
		s.user.IsMfaEnabled = true
		s.user.MfaTotpSecretEncrypted = args[1].([]byte)
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func TestFixtureSeedTOTPIsOptInAndTransactional(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		fail       bool
	}{
		{"omitted", `{}`, false},
		{"disabled", `{"totp":false}`, false},
		{"enabled", `{"credentials":2,"totp":true}`, false},
		{"rollback", `{"totp":true}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input request
			if err := json.Unmarshal([]byte(tc.body), &input); err != nil {
				t.Fatal("invalid test request")
			}
			t.Setenv(config.EnvMasterKEK, "")
			if input.TOTP {
				fixtureKEK(t)
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal("cannot capture fixture JSON")
			}
			previous := os.Stdout
			os.Stdout = writer
			t.Cleanup(func() {
				os.Stdout = previous
				_ = reader.Close()
				_ = writer.Close()
			})
			tx := &seedTransaction{failMFA: tc.fail}
			err = seed(context.Background(), tx, fixtureRunID, input.Credentials, input.TOTP)
			os.Stdout = previous
			_ = writer.Close()
			output, readErr := io.ReadAll(reader)
			if readErr != nil {
				t.Fatal("cannot read captured fixture JSON")
			}
			if tc.fail {
				if err == nil || tx.committed || !tx.rolledBack || len(output) != 0 || strings.Contains(err.Error(), "private driver") {
					t.Fatal("failed TOTP seed must roll back without output or private diagnostics")
				}
				return
			}
			if err != nil || !tx.committed || tx.user.IsMfaEnabled != input.TOTP {
				t.Fatal("seed did not commit the requested factor state")
			}
			var result map[string]json.RawMessage
			if json.Unmarshal(output, &result) != nil || len(result) != 3 || result["user_id"] == nil || result["email"] == nil || result["credentials"] == nil {
				t.Fatal("seed output must retain its existing contract without TOTP material")
			}
			if input.TOTP {
				if _, err := currentTOTPCode(context.Background(), tx.user, fixtureRunID, time.Now()); err != nil {
					t.Fatal("seeded TOTP ciphertext is not usable")
				}
			} else if len(tx.user.MfaTotpSecretEncrypted) != 0 {
				t.Fatal("seed enabled TOTP without explicit opt-in")
			}
		})
	}
	for _, body := range []string{`{"totp":"true"}`, `{"totp":1}`, `{"totp":{}}`} {
		if json.Unmarshal([]byte(body), new(request)) == nil {
			t.Fatal("non-boolean TOTP opt-in accepted")
		}
	}
}

type fixtureUsers struct {
	mfa.UserStore
	user db.User
}

func (s fixtureUsers) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	if id != s.user.ID {
		return db.User{}, pgx.ErrNoRows
	}
	return s.user, nil
}

func TestFixtureTOTPMatchesProductionMFAAndCrossReplicaReplay(t *testing.T) {
	fixtureKEK(t)
	ctx := context.Background()
	ciphertext, err := newTOTPSecret(ctx)
	if err != nil || len(ciphertext) == 0 || ciphertext[0] != 37 {
		t.Fatal("fixture must use the configured production envelope version")
	}
	user := db.User{ID: uuid.New(), Email: "portal@" + fixtureRunID + ".example.test", Status: "active", IsMfaEnabled: true, MfaTotpSecretEncrypted: ciphertext}
	enc, err := fixtureEncryptor()
	if err != nil {
		t.Fatal("cannot construct production-compatible decryptor")
	}
	secret, err := enc.Decrypt(ctx, ciphertext)
	if err != nil || len(secret) != 32 || bytes.Contains(ciphertext, secret) {
		t.Fatal("expected an encrypted production TOTP secret")
	}
	defer clear(secret)
	now := time.Now()
	code, err := currentTOTPCode(ctx, user, fixtureRunID, now)
	if err != nil || !totp.ValidateCode(string(secret), code.Code, now, 0) {
		t.Fatal("fixture code must match the real TOTP engine")
	}
	encoded, err := json.Marshal(code)
	var output map[string]json.RawMessage
	if err != nil || json.Unmarshal(encoded, &output) != nil || len(output) != 2 || output["code"] == nil || output["expires_at"] == nil || bytes.Contains(encoded, secret) {
		t.Fatal("current-code JSON must contain only code and step boundary")
	}
	boundary := now.UTC().Truncate(30 * time.Second).Add(30 * time.Second)
	if code.ExpiresAt != boundary {
		t.Fatal("incorrect current-step boundary")
	}
	next, err := currentTOTPCode(ctx, user, fixtureRunID, boundary)
	if err != nil || next.ExpiresAt != boundary.Add(30*time.Second) || !totp.ValidateCode(string(secret), next.Code, boundary, 0) {
		t.Fatal("fixture must follow the real clock without rotating or resetting the secret")
	}
	redisServer := miniredis.RunT(t)
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatal("cannot generate test replay key")
	}
	active, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatal("cannot generate test signing key")
	}
	nextKey, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatal("cannot generate test next signing key")
	}
	keyStore, err := keys.NewManager(active, nextKey, nil)
	if err != nil {
		t.Fatal("cannot create test key manager")
	}
	for replica := range 2 {
		client := redis.NewClient(&redis.Options{Addr: redisServer.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
		t.Cleanup(func() { _ = client.Close() })
		guard, err := stepup.NewRedisReplayGuard(client, hmacKey)
		if err != nil {
			t.Fatal("cannot create production replay guard")
		}
		replicaEncryptor, err := fixtureEncryptor()
		if err != nil {
			t.Fatal("cannot create independent replica encryptor")
		}
		users := fixtureUsers{user: user}
		mfaService, err := mfa.New(mfa.Config{}, users, replicaEncryptor)
		if err != nil {
			t.Fatal("cannot create production MFA service")
		}
		svc, err := stepup.New(stepup.Config{Issuer: "https://localhost:43210"}, keyStore, users, nil, mfaService, guard)
		if err != nil {
			t.Fatal("cannot create production step-up service")
		}
		again, err := currentTOTPCode(ctx, user, fixtureRunID, now)
		if err != nil || again != code {
			t.Fatal("code retrieval changed the factor or consumed replay state")
		}
		grant, _, err := svc.Verify(ctx, stepup.VerifyParams{UserID: user.ID, SessionID: uuid.NewString(), Method: stepup.MethodTOTP, Code: again.Code})
		if replica == 0 && (err != nil || grant == "") {
			t.Fatal("real MFA and step-up must accept the first fixture code")
		}
		if replica == 1 && (!errors.Is(err, stepup.ErrCodeReplayed) || grant != "") {
			t.Fatal("the second replica must reject the same code even in a different session")
		}
	}
}

func TestFixtureTOTPRefusesForeignInactiveMissingAndCorruptFactors(t *testing.T) {
	fixtureKEK(t)
	ciphertext, err := newTOTPSecret(context.Background())
	if err != nil {
		t.Fatal("cannot create test ciphertext")
	}
	for name, mutate := range map[string]func(*testing.T, *db.User){
		"foreign":    func(_ *testing.T, u *db.User) { u.Email = "portal@another-run.example.test" },
		"suffix":     func(_ *testing.T, u *db.User) { u.Email += ".invalid" },
		"deleted":    func(_ *testing.T, u *db.User) { u.DeletedAt.Valid = true },
		"missing":    func(_ *testing.T, u *db.User) { u.ID = uuid.Nil },
		"inactive":   func(_ *testing.T, u *db.User) { u.Status = "suspended" },
		"disabled":   func(_ *testing.T, u *db.User) { u.IsMfaEnabled = false },
		"no secret":  func(_ *testing.T, u *db.User) { u.MfaTotpSecretEncrypted = nil },
		"tampered":   func(_ *testing.T, u *db.User) { u.MfaTotpSecretEncrypted[len(ciphertext)-1] ^= 1 },
		"malformed":  func(_ *testing.T, u *db.User) { u.MfaTotpSecretEncrypted = []byte("private malformed ciphertext") },
		"wrong KEK":  func(t *testing.T, _ *db.User) { fixtureKEK(t) },
		"bad config": func(t *testing.T, _ *db.User) { t.Setenv(config.EnvMasterKEKVersion, "private invalid version") },
	} {
		t.Run(name, func(t *testing.T) {
			user := db.User{ID: uuid.New(), Email: "portal@" + fixtureRunID + ".example.test", Status: "active", IsMfaEnabled: true, MfaTotpSecretEncrypted: bytes.Clone(ciphertext)}
			mutate(t, &user)
			output, err := currentTOTPCode(context.Background(), user, fixtureRunID, time.Now())
			if err == nil || output != (totpCode{}) || strings.Contains(err.Error(), "private") {
				t.Fatal("invalid fixture factor must fail without a code or private diagnostic")
			}
		})
	}
}

func TestFixtureAuditBoundary(t *testing.T) {
	t.Setenv(config.EnvAuditStreamName, "PORTAL_BROWSER_AUDIT_"+fixtureRunID)
	t.Setenv(config.EnvAuditSubject, "identity.audit.logs")
	for _, endpoint := range []string{"nats://127.0.0.1:4222", "nats://localhost:43210", "nats://[::1]:43210"} {
		t.Setenv(config.EnvNATSURL, endpoint)
		if _, err := fixtureAuditConfig(fixtureRunID); err != nil {
			t.Fatal("valid fixture audit configuration rejected")
		}
	}
	for _, endpoint := range []string{"", "nats://remote.test:4222", "tls://localhost:4222", "nats://localhost", "nats://localhost:0", "nats://localhost:65536", "nats://user:private@localhost:4222", "nats://localhost:4222/path", "nats://localhost:4222?", "nats://localhost:4222?token=private", "nats://localhost:4222#private"} {
		t.Setenv(config.EnvNATSURL, endpoint)
		if _, err := fixtureAuditConfig(fixtureRunID); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("unsafe NATS endpoint accepted or disclosed")
		}
	}
	t.Setenv(config.EnvNATSURL, "nats://localhost:4222")
	for _, name := range []string{"IDENTITY_AUDIT", "PORTAL_BROWSER_AUDIT", "PORTAL_BROWSER_AUDIT_another-run"} {
		t.Setenv(config.EnvAuditStreamName, name)
		if _, err := fixtureAuditConfig(fixtureRunID); err == nil {
			t.Fatal("unowned audit stream accepted")
		}
	}
}

type fixtureJetStream struct {
	jetstream.JetStream
	streams  int
	foreign  bool
	failure  bool
	created  *jetstream.StreamConfig
	lookedUp string
}

func (s *fixtureJetStream) AccountInfo(context.Context) (*jetstream.AccountInfo, error) {
	if s.failure {
		return nil, errors.New("private broker diagnostic")
	}
	info := &jetstream.AccountInfo{}
	info.Streams = s.streams
	return info, nil
}
func (s *fixtureJetStream) Stream(_ context.Context, name string) (jetstream.Stream, error) {
	s.lookedUp = name
	if s.foreign {
		return nil, jetstream.ErrStreamNotFound
	}
	return nil, nil
}
func (s *fixtureJetStream) CreateOrUpdateStream(_ context.Context, cfg jetstream.StreamConfig) (jetstream.Stream, error) {
	s.created = &cfg
	return nil, nil
}

func TestFixtureAuditStreamUsesProductionPolicyWithoutClaimingForeignStreams(t *testing.T) {
	t.Setenv(config.EnvNATSURL, "nats://localhost:43210")
	t.Setenv(config.EnvAuditStreamName, "PORTAL_BROWSER_AUDIT_"+fixtureRunID)
	cfg, err := fixtureAuditConfig(fixtureRunID)
	if err != nil {
		t.Fatal("cannot load fixture audit config")
	}
	for _, js := range []*fixtureJetStream{{}, {streams: 1}, {streams: 1, foreign: true}, {streams: 2}, {failure: true}} {
		err := ensureAuditStream(context.Background(), js, cfg)
		if js.foreign || js.streams > 1 || js.failure {
			if err == nil || js.created != nil || strings.Contains(err.Error(), "private") {
				t.Fatal("fixture must not change an unowned or unavailable broker")
			}
			continue
		}
		stream := js.created
		if err != nil || stream == nil || stream.Name != cfg.StreamName || (js.streams == 1 && js.lookedUp != cfg.StreamName) {
			t.Fatal("fixture must provision only its own stream, idempotently")
		}
		if len(stream.Subjects) != 1 || stream.Subjects[0] != config.StreamSubjectPattern || stream.Retention != jetstream.WorkQueuePolicy || stream.Storage != jetstream.FileStorage || stream.Discard != jetstream.DiscardNew || stream.MaxAge != 0 || !stream.DenyDelete || !stream.DenyPurge || stream.MaxBytes != cfg.StreamMaxBytes || stream.Duplicates != cfg.DuplicateWindow || stream.Replicas != 1 {
			t.Fatal("fixture audit topology diverges from the production helper")
		}
	}
}
