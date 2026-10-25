//go:build portalfixture

// Command portal-fixture provisions disposable browser-test data. It is excluded
// from ordinary builds and runtime images; it never registers an HTTP endpoint.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

var runIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type request struct {
	Credentials int    `json:"credentials,omitempty"`
	TOTP        bool   `json:"totp,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	Code        string `json:"code,omitempty"`
}

type totpCode struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

type credential struct {
	CredentialID         string `json:"credentialId"`
	IsResidentCredential bool   `json:"isResidentCredential"`
	RPID                 string `json:"rpId"`
	PrivateKey           string `json:"privateKey"`
	UserHandle           string `json:"userHandle"`
	SignCount            uint32 `json:"signCount"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		// Inputs include one-time codes and private fixture material. Never print
		// decoder/driver errors, connection strings, or the request body.
		fmt.Fprintln(os.Stderr, "portal-fixture: operation failed:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 || (args[0] != "tls" && args[0] != "migrate" && args[0] != "seed" && args[0] != "totp-code" && args[0] != "expire-session" && args[0] != "consume-code") {
		return errors.New("expected tls, migrate, seed, totp-code, expire-session, or consume-code")
	}
	runID := os.Getenv("PORTAL_FIXTURE_RUN_ID")
	if os.Getenv("PORTAL_FIXTURE_ALLOW") != "1" || !runIDPattern.MatchString(runID) || os.Getenv("APP_ENV") == "production" {
		return errors.New("explicit disposable-fixture configuration is required")
	}
	var input request
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 8193))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return errors.New("expected a bounded fixture JSON object on stdin")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected trailing fixture input")
	}
	if args[0] == "tls" {
		output, err := localCertificate()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(output)
	}
	dsn := os.Getenv("DATABASE_URL")
	if err := validateDatabase(dsn, runID); err != nil {
		return err
	}
	opts, err := redis.ParseURL(os.Getenv("REDIS_URL"))
	if err != nil || opts == nil {
		return errors.New("a disposable loopback Redis URL is required")
	}
	host, _, err := net.SplitHostPort(opts.Addr)
	if err != nil || !loopback(host) || opts.DB != 0 {
		return errors.New("fixture Redis must be a dedicated loopback database zero")
	}
	opts.ContextTimeoutEnabled, opts.MaxRetries = true, -1
	opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = time.Second, time.Second, time.Second
	client := redis.NewClient(opts)
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	owner, err := client.Get(ctx, "portal-fixture:owner").Result()
	if args[0] == "migrate" && errors.Is(err, redis.Nil) {
		size, sizeErr := client.DBSize(ctx).Result()
		if sizeErr != nil || size != 0 {
			return errors.New("refusing to claim a nonempty Redis instance")
		}
		claimed, claimErr := client.SetNX(ctx, "portal-fixture:owner", runID, time.Hour).Result()
		if claimErr != nil || !claimed {
			return errors.New("cannot claim disposable Redis")
		}
		owner, err = runID, nil
	}
	if err != nil || owner != runID {
		return errors.New("fixture Redis does not belong to this run")
	}
	if args[0] == "migrate" {
		sqldb, err := migrate.Open(ctx, dsn)
		if err != nil {
			return errors.New("cannot connect to disposable PostgreSQL")
		}
		defer func() { _ = sqldb.Close() }()
		if err := migrate.Up(ctx, sqldb); err != nil {
			return errors.New("cannot migrate disposable PostgreSQL")
		}
		if err := provisionAuditStream(ctx, runID); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]bool{"migrated": true})
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return errors.New("cannot open disposable PostgreSQL")
	}
	defer pool.Close()
	if args[0] == "seed" {
		return seed(ctx, pool, runID, input.Credentials, input.TOTP)
	}
	userID, err := uuid.Parse(input.UserID)
	if err != nil || userID == uuid.Nil {
		return errors.New("invalid fixture subject")
	}
	var owned bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND email LIKE $2)`, userID, "%@"+runID+".example.test").Scan(&owned); err != nil || !owned {
		return errors.New("subject does not belong to this fixture run")
	}
	if args[0] == "totp-code" {
		user, err := db.New(pool).GetUserByID(ctx, userID)
		if err != nil {
			return errors.New("cannot load fixture TOTP account")
		}
		output, err := currentTOTPCode(ctx, user, runID, time.Now())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(output)
	}
	if args[0] == "consume-code" {
		svc, err := recovery.New(recovery.Config{}, db.New(pool), recovery.WithTransacter(pool))
		if err != nil {
			return errors.New("cannot construct fixture recovery verifier")
		}
		err = svc.Verify(ctx, userID, input.Code, "127.0.0.1")
		if err != nil && !errors.Is(err, recovery.ErrInvalidCode) {
			return errors.New("fixture recovery verification failed")
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]bool{"consumed": err == nil})
	}
	if _, err := uuid.Parse(input.SessionID); err != nil {
		return errors.New("invalid fixture session")
	}
	store, err := session.NewRedisStore(client)
	if err != nil {
		return errors.New("cannot open fixture session store")
	}
	if _, err := store.GetByID(ctx, input.UserID, input.SessionID); err != nil {
		return errors.New("fixture session is not live or owner-scoped")
	}
	// Exercise native expiry, not a public revocation bypass. This test-only
	// knowledge of the versioned layout must track internal/session/redis.go.
	idKey := fmt.Sprintf("identity:session:v1:id:%d:%s:%s", len(input.UserID), input.UserID, input.SessionID)
	hash, err := client.Get(ctx, idKey).Result()
	if err != nil || !validSessionHash(hash) {
		return errors.New("cannot resolve fixture session record")
	}
	pipe := client.TxPipeline()
	pipe.PExpire(ctx, "identity:session:v1:token:"+hash, time.Millisecond)
	pipe.PExpire(ctx, idKey, time.Millisecond)
	if _, err := pipe.Exec(ctx); err != nil {
		return errors.New("cannot expire fixture session")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]bool{"expiring": true})
}

func validSessionHash(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateDatabase(dsn, runID string) error {
	u, err := url.Parse(dsn)
	if err != nil || u == nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || !loopback(u.Hostname()) || u.Path != "/portal_browser_"+runID || u.Fragment != "" {
		return errors.New("fixture database must be a run-owned loopback portal_browser_<run-id> URL")
	}
	for key := range u.Query() {
		if key != "sslmode" {
			return errors.New("fixture database URL may only configure sslmode")
		}
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !loopback(cfg.Host) || cfg.Database != "portal_browser_"+runID {
		return errors.New("fixture database resolved outside its run boundary")
	}
	return nil
}

func fixtureAuditConfig(runID string) (config.AuditConfig, error) {
	cfg, err := config.LoadAudit("test")
	if err != nil {
		return config.AuditConfig{}, errors.New("invalid fixture audit configuration")
	}
	u, err := url.Parse(cfg.NATSURL)
	if err != nil || u == nil || u.Scheme != "nats" || !loopback(u.Hostname()) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return config.AuditConfig{}, errors.New("fixture NATS must be a dedicated loopback URL")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return config.AuditConfig{}, errors.New("fixture NATS requires an explicit TCP port")
	}
	if !runIDPattern.MatchString(runID) || cfg.StreamName != "PORTAL_BROWSER_AUDIT_"+runID {
		return config.AuditConfig{}, errors.New("audit stream does not belong to this fixture run")
	}
	return cfg, nil
}

func provisionAuditStream(ctx context.Context, runID string) error {
	cfg, err := fixtureAuditConfig(runID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	nc, js, err := natsjs.Connect(ctx, cfg.NATSURL, "portal-fixture", logger)
	if err != nil {
		return errors.New("cannot connect to disposable JetStream")
	}
	defer nc.Close()
	return ensureAuditStream(ctx, js, cfg)
}

func ensureAuditStream(ctx context.Context, js jetstream.JetStream, cfg config.AuditConfig) error {
	info, err := js.AccountInfo(ctx)
	if err != nil {
		return errors.New("cannot inspect disposable JetStream")
	}
	if info.Streams > 0 {
		if info.Streams != 1 {
			return errors.New("refusing to provision a nonempty JetStream instance")
		}
		if _, err := js.Stream(ctx, cfg.StreamName); err != nil {
			return errors.New("fixture JetStream does not belong to this run")
		}
	}
	if _, err := natsjs.EnsureStream(ctx, js, natsjs.StreamOptions{
		Name: cfg.StreamName, Subjects: cfg.StreamSubjects(),
		MaxBytes: cfg.StreamMaxBytes, Duplicates: cfg.DuplicateWindow,
	}); err != nil {
		return errors.New("cannot provision fixture audit stream")
	}
	return nil
}

func fixtureEncryptor() (*envelope.Encryptor, error) {
	cfg, err := config.LoadEnvelopeCrypto()
	if err != nil {
		return nil, errors.New("invalid fixture envelope configuration")
	}
	defer clear(cfg.MasterKEK)
	provider, err := kms.NewMockProvider(cfg.MasterKEK, cfg.MasterKEKVersion)
	if err != nil {
		return nil, errors.New("cannot construct fixture KMS provider")
	}
	enc, err := envelope.New(provider)
	if err != nil {
		return nil, errors.New("cannot construct fixture envelope encryptor")
	}
	return enc, nil
}

func newTOTPSecret(ctx context.Context) ([]byte, error) {
	enc, err := fixtureEncryptor()
	if err != nil {
		return nil, err
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, errors.New("cannot generate fixture TOTP secret")
	}
	// Use the same envelope format as buildMFAService, including its nil AAD.
	ciphertext, err := enc.Encrypt(ctx, []byte(secret))
	if err != nil {
		return nil, errors.New("cannot encrypt fixture TOTP secret")
	}
	return ciphertext, nil
}

func currentTOTPCode(ctx context.Context, user db.User, runID string, now time.Time) (totpCode, error) {
	if !runIDPattern.MatchString(runID) || user.ID == uuid.Nil || !strings.HasSuffix(user.Email, "@"+runID+".example.test") || user.DeletedAt.Valid {
		return totpCode{}, errors.New("subject does not belong to this fixture run")
	}
	if user.Status != "active" || !user.IsMfaEnabled || len(user.MfaTotpSecretEncrypted) == 0 {
		return totpCode{}, errors.New("fixture account has no active TOTP factor")
	}
	enc, err := fixtureEncryptor()
	if err != nil {
		return totpCode{}, err
	}
	secret, err := enc.Decrypt(ctx, user.MfaTotpSecretEncrypted)
	if err != nil {
		return totpCode{}, errors.New("cannot decrypt fixture TOTP secret")
	}
	defer clear(secret)
	code, err := totp.GenerateCode(string(secret), now)
	if err != nil {
		return totpCode{}, errors.New("cannot generate fixture TOTP code")
	}
	// This is the production engine's 30-second step boundary, not its drift
	// window. Never consume or reset the real API's shared replay guard here.
	return totpCode{Code: code, ExpiresAt: now.UTC().Truncate(30 * time.Second).Add(30 * time.Second)}, nil
}

func newCredential(handle []byte) (credential, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return credential{}, nil, nil, errors.New("cannot generate fixture key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return credential{}, nil, nil, errors.New("cannot encode fixture key")
	}
	cose, err := webauthncbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1,
		-2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		return credential{}, nil, nil, errors.New("cannot encode fixture public key")
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return credential{}, nil, nil, errors.New("cannot generate fixture credential ID")
	}
	return credential{
		CredentialID: base64.StdEncoding.EncodeToString(id), IsResidentCredential: true,
		RPID: "localhost", PrivateKey: base64.StdEncoding.EncodeToString(der),
		UserHandle: base64.StdEncoding.EncodeToString(handle),
	}, id, cose, nil
}

func seed(ctx context.Context, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, runID string, count int, enableTOTP bool) error {
	if count == 0 {
		count = 1
	}
	if count < 1 || count > 2 {
		return errors.New("fixture credential count must be one or two")
	}
	handle := make([]byte, 8)
	if _, err := rand.Read(handle); err != nil {
		return errors.New("cannot generate fixture handle")
	}
	userID := uuid.New()
	email := "portal-" + userID.String() + "@" + runID + ".example.test"
	tx, err := pool.Begin(ctx)
	if err != nil {
		return errors.New("cannot begin fixture transaction")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// An intentionally non-JavaScript-safe revision tests decimal-string handling.
	if _, err := tx.Exec(ctx, `INSERT INTO users (id,email,webauthn_user_handle,display_name,lifecycle_revision) VALUES ($1,$2,$3,'',9007199254740993)`, userID, email, handle); err != nil {
		return errors.New("cannot insert fixture account (apply portal migration first)")
	}
	credentials := make([]credential, 0, count)
	for i := range count {
		cred, id, cose, err := newCredential(handle)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO webauthn_credentials (id,user_id,public_key,attestation_type,user_present,user_verified,aaguid,name) VALUES ($1,$2,$3,'none',true,true,$4,$5)`, id, userID, cose, uuid.Nil, fmt.Sprintf("Fixture passkey %d", i+1)); err != nil {
			return errors.New("cannot insert fixture public credential")
		}
		credentials = append(credentials, cred)
	}
	if enableTOTP {
		ciphertext, err := newTOTPSecret(ctx)
		if err != nil {
			return err
		}
		affected, err := db.New(tx).CompleteMfaTotpEnrollment(ctx, db.CompleteMfaTotpEnrollmentParams{
			ID: userID, MfaTotpSecretEncrypted: ciphertext,
		})
		if err != nil || affected != 1 {
			return errors.New("cannot enable fixture TOTP factor")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("cannot commit fixture account")
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		UserID      string       `json:"user_id"`
		Email       string       `json:"email"`
		Credentials []credential `json:"credentials"`
	}{userID.String(), email, credentials})
}

func localCertificate() (map[string]string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("cannot generate local TLS key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errors.New("cannot generate local TLS serial")
	}
	certificate := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return nil, errors.New("cannot create local TLS certificate")
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.New("cannot encode local TLS private key")
	}
	return map[string]string{
		"cert": strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))),
		"key":  strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}))),
	}, nil
}
