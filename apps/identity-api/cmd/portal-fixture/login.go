//go:build portalfixture

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

type loginAccount struct {
	fixtureAccount
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"`
	Phone       string `json:"phone"`
	AuthVersion string `json:"auth_version"`
	TOTP        bool   `json:"totp"`
}

func loginCredentialCount(scenario string) (int, bool, error) {
	switch scenario {
	case "password-only":
		return 0, true, nil
	case "passkey-only":
		return 1, false, nil
	case "dual":
		return 1, true, nil
	default:
		return 0, false, errors.New("unsupported login credential fixture")
	}
}

func loginFixture(ctx context.Context, pool *pgxpool.Pool, runID, action string, input request) (any, error) {
	if action == "login-policy" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, errors.New("cannot generate owned username key")
		}
		defer clear(key)
		policy := username.Policy{ID: uuid.New(), Normalization: username.NormalizationV1,
			Folds: []username.Fold{{From: "\u0624", To: "\u0648"}, {From: "\u0626", To: "\u06cc"}, {From: "\u0643", To: "\u06a9"}, {From: "\u064a", To: "\u06cc"}}, ReservedNames: []string{}}
		regex := `[\x{0627}\x{0628}\x{062A}-\x{062F}]+`
		keyID := "portal-login-" + runID
		normalizer, err := username.New(policy, regex, key, keyID)
		if err != nil {
			return nil, errors.New("cannot admit owned username policy")
		}
		authority := normalizer.Authority()
		tx, err := pool.Begin(ctx)
		if err != nil {
			return nil, errors.New("cannot begin owned username installation")
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var empty bool
		if err := tx.QueryRow(ctx, `SELECT admission_state='uninstalled' FROM username_active_policy WHERE singleton FOR UPDATE`).Scan(&empty); err != nil || !empty {
			return nil, errors.New("refusing to replace an installed username authority")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO username_policy_artifacts(policy_id,fingerprint,artifact) VALUES($1,$2,$3)`, authority.PolicyID, authority.Fingerprint[:], normalizer.CanonicalArtifact()); err != nil {
			return nil, errors.New("cannot install owned username artifact")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO username_lookup_keys(key_id,key_verifier) VALUES($1,$2)`, keyID, authority.KeyVerifier[:]); err != nil {
			return nil, errors.New("cannot install owned username verifier")
		}
		if _, err := tx.Exec(ctx, `UPDATE username_active_policy SET policy_id=$1,fingerprint=$2,epoch=1,key_id=$3,key_verifier=$4,admission_state='open' WHERE singleton`, authority.PolicyID, authority.Fingerprint[:], keyID, authority.KeyVerifier[:]); err != nil {
			return nil, errors.New("cannot activate owned username authority")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, errors.New("cannot commit owned username authority")
		}
		encoded, _ := json.Marshal(normalizer.Policy())
		return map[string]string{"USERNAME_ENABLED": "true", "USERNAME_POLICY_JSON": string(encoded), "USERNAME_REGEX": regex, "USERNAME_LOOKUP_KEY": base64.StdEncoding.EncodeToString(key), "USERNAME_LOOKUP_KEY_ID": keyID}, nil
	}
	count, withPassword, err := loginCredentialCount(input.Scenario)
	if err != nil {
		return nil, err
	}
	roles, err := fixtureRoles(input.Role)
	if err != nil || len(roles) > 0 && (os.Getenv("PORTAL_FIXTURE_ADMIN") != "1" || os.Getenv("APP_ENV") != "test") {
		return nil, errors.New("login role fixtures require explicit administrative mode")
	}
	account, err := seedCredentialAccount(ctx, pool, runID, count, input.TOTP || len(roles) > 0)
	if err != nil {
		return nil, err
	}
	id := uuid.MustParse(account.UserID)
	name := ""
	alphabet := []rune{0x0627, 0x0628, 0x062a, 0x062b, 0x062c, 0x062d, 0x062e, 0x062f}
	for _, b := range id {
		name += string(alphabet[int(b)%len(alphabet)])
	}
	phone := fmt.Sprintf("+989%09d", binary.BigEndian.Uint64(id[:8])%1_000_000_000)
	secret := ""
	var hash *string
	if withPassword {
		secret = " fixture login " + uuid.NewString() + " "
		encoded, err := password.HashContext(ctx, secret)
		if err != nil {
			return nil, errors.New("cannot hash owned login password")
		}
		hash = &encoded
	}
	cipher, err := fixtureEncryptor()
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadUsername()
	if err != nil || !cfg.Enabled {
		return nil, errors.New("login fixture requires admitted username configuration")
	}
	namespace, err := username.NewStore(pool, cipher, cfg.Normalizer)
	if err != nil {
		return nil, errors.New("cannot create owned username store")
	}
	value, err := cfg.Normalizer.Normalize(name)
	if err != nil {
		return nil, errors.New("cannot normalize owned username")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, errors.New("cannot begin owned login contact transaction")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := namespace.Assign(ctx, tx, id, 0, value); err != nil {
		return nil, errors.New("cannot assign owned fixture username")
	}
	phoneBlob, err := cipher.Encrypt(ctx, []byte(phone))
	if err != nil {
		return nil, errors.New("cannot encrypt owned phone")
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET password_hash=$2,phone_encrypted=$3 WHERE id=$1`, id, hash, phoneBlob); err != nil {
		return nil, errors.New("cannot set owned credential configuration")
	}
	for _, proof := range []struct{ channel, destination, method string }{{contactproof.Email, account.Email, contactproof.EmailLink}, {contactproof.Phone, phone, contactproof.SMSOTP}} {
		blob, err := contactproof.Seal(ctx, cipher, id, proof.channel, proof.destination, proof.method, time.Now())
		if err != nil {
			return nil, errors.New("cannot seal owned contact evidence")
		}
		err = db.New(tx).PutContactVerificationEvidence(ctx, db.PutContactVerificationEvidenceParams{UserID: id, Channel: proof.channel, EvidenceEncrypted: blob})
		clear(blob)
		if err != nil {
			return nil, errors.New("cannot persist owned contact evidence")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, errors.New("cannot commit owned login contacts")
	}
	// Administrative provisioning uses the audited production transaction and bumps
	// authority before any browser earns a session. Never restamp an old session.
	if len(roles) > 0 {
		if _, err := adminFixture(ctx, pool, runID, "admin-grant", request{UserID: id.String(), Role: input.Role}); err != nil {
			return nil, err
		}
	}
	var version string
	if err := pool.QueryRow(ctx, `SELECT auth_version::text FROM users WHERE id=$1`, id).Scan(&version); err != nil {
		return nil, errors.New("cannot capture post-grant authority")
	}
	return loginAccount{account, name, secret, phone, version, input.TOTP || len(roles) > 0}, nil
}
