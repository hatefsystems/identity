package username

import (
	"bytes"
	"context"
	"crypto/sha256"
	"regexp"

	"github.com/jackc/pgx/v5"

	schema "github.com/hatefsystems/identity/apps/identity-api/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/dbprivilege"
)

// CheckSchema verifies the global nonpartial constraint and enabled immutable
// guards. It does not attest deployed role separation or authorize activation.
func CheckSchema(ctx context.Context, q db.DBTX) error {
	if q == nil {
		return ErrUnavailable
	}
	var ok bool
	// Compare actual function bodies with the bundled migration, not merely OIDs.
	// A renamed permissive trigger function must not satisfy readiness.
	ownershipBody, registryBody, err := bundledGuardBodies()
	if err != nil {
		return ErrUnavailable
	}
	err = q.QueryRow(ctx, `SELECT
        EXISTS(SELECT 1 FROM pg_constraint c JOIN pg_index i ON i.indexrelid=c.conindid
            JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=i.indkey[0]
            WHERE c.conrelid='public.users'::regclass AND c.conname='users_username_key_unique'
            AND c.contype='u' AND NOT c.condeferrable AND i.indimmediate
            AND NOT i.indnullsnotdistinct AND i.indisunique AND i.indisvalid AND i.indpred IS NULL
            AND i.indexprs IS NULL AND i.indnkeyatts=1 AND a.attname='username_key')
        AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.users'::regclass
            AND conname='users_username_tuple' AND contype='c' AND convalidated
            AND pg_get_constraintdef(oid)=$1)
        AND ARRAY(SELECT attname::text FROM pg_attribute
            WHERE attrelid='public.users'::regclass AND attnum>0 AND NOT attisdropped ORDER BY attnum)
            =ARRAY['id','email','password_hash','backup_email_encrypted','backup_email_blind_index',
                'phone_encrypted','phone_blind_index','mfa_totp_secret_encrypted','is_mfa_enabled','status',
                'created_at','updated_at','deleted_at','webauthn_user_handle','auth_version','auth_epoch',
                'lifecycle_revision','display_name','username_key','username_details_encrypted',
                'username_policy_id','username_policy_fingerprint','username_policy_epoch','username_lookup_key_id']
        AND NOT EXISTS(SELECT 1 FROM (VALUES
            ('username_key','bytea'),('username_details_encrypted','bytea'),('username_policy_id','uuid'),
            ('username_policy_fingerprint','bytea'),('username_policy_epoch','bigint'),('username_lookup_key_id','text')
        ) expected(name,type) WHERE NOT EXISTS(SELECT 1 FROM pg_attribute a
            WHERE a.attrelid='public.users'::regclass AND a.attname=expected.name
            AND a.atttypid=to_regtype(expected.type) AND NOT a.attnotnull AND NOT a.attisdropped
            AND NOT EXISTS(SELECT 1 FROM pg_attrdef d WHERE d.adrelid=a.attrelid AND d.adnum=a.attnum)))
        AND NOT EXISTS(SELECT 1 FROM (VALUES
            ('public.users','users_username_immutable','public.username_ownership_guard()',31),
            ('public.users','users_username_no_truncate','public.username_registry_immutable()',34),
            ('public.username_policy_artifacts','username_artifact_immutable','public.username_registry_immutable()',27),
            ('public.username_policy_artifacts','username_artifact_no_truncate','public.username_registry_immutable()',34),
            ('public.username_lookup_keys','username_key_immutable','public.username_registry_immutable()',27),
            ('public.username_lookup_keys','username_key_no_truncate','public.username_registry_immutable()',34),
            ('public.username_active_policy','username_active_no_delete','public.username_registry_immutable()',11),
            ('public.username_active_policy','username_active_no_truncate','public.username_registry_immutable()',34)
        ) AS required(relation,name,fn,mask) WHERE NOT EXISTS(SELECT 1 FROM pg_trigger t
            WHERE t.tgrelid=to_regclass(required.relation) AND t.tgname=required.name
            AND t.tgfoid=to_regprocedure(required.fn) AND t.tgtype=required.mask
            AND NOT t.tgisinternal AND t.tgenabled IN ('O','A') AND t.tgqual IS NULL))
        AND EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid='public.users'::regclass
            AND t.tgname='users_username_immutable'
            AND ARRAY(SELECT a.attname::text FROM pg_attribute a WHERE a.attrelid=t.tgrelid
                AND a.attnum=ANY(t.tgattr) ORDER BY a.attname)=ARRAY[
                'id','username_details_encrypted','username_key','username_lookup_key_id',
                'username_policy_epoch','username_policy_fingerprint','username_policy_id'])
        AND NOT EXISTS(SELECT 1 FROM pg_proc WHERE oid IN
            ('public.username_ownership_guard()'::regprocedure,'public.username_registry_immutable()'::regprocedure)
            AND (prosecdef OR proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public']))
        AND EXISTS(SELECT 1 FROM pg_proc WHERE oid='public.username_ownership_guard()'::regprocedure AND prosrc=$2)
        AND EXISTS(SELECT 1 FROM pg_proc WHERE oid='public.username_registry_immutable()'::regprocedure AND prosrc=$3)`,
		usernameTupleConstraint, ownershipBody, registryBody).Scan(&ok)
	if err != nil || !ok {
		return ErrUnavailable
	}
	return nil
}

const usernameTupleConstraint = `CHECK ((((username_key IS NULL) AND (username_details_encrypted IS NULL) AND (username_policy_id IS NULL) AND (username_policy_fingerprint IS NULL) AND (username_policy_epoch IS NULL) AND (username_lookup_key_id IS NULL)) OR ((username_key IS NOT NULL) AND (octet_length(username_key) = 32) AND (username_details_encrypted IS NOT NULL) AND ((octet_length(username_details_encrypted) >= 90) AND (octet_length(username_details_encrypted) <= 16384)) AND (username_policy_id IS NOT NULL) AND (username_policy_fingerprint IS NOT NULL) AND (octet_length(username_policy_fingerprint) = 32) AND (username_policy_epoch IS NOT NULL) AND (username_policy_epoch > 0) AND (username_lookup_key_id IS NOT NULL))))`

func bundledGuardBodies() (string, string, error) {
	raw, err := schema.Migrations.ReadFile("migrations/00003_username_reservations.sql")
	if err != nil {
		return "", "", ErrUnavailable
	}
	body := func(name string) string {
		pattern := regexp.MustCompile(`(?s)CREATE FUNCTION public\.` + name + `\(\) RETURNS trigger\s+LANGUAGE plpgsql SET search_path = pg_catalog, public AS \$\$(.*?)\$\$;`)
		match := pattern.FindSubmatch(raw)
		if len(match) != 2 {
			return ""
		}
		return string(match[1])
	}
	ownership, registry := body("username_ownership_guard"), body("username_registry_immutable")
	if ownership == "" || registry == "" {
		return "", "", ErrUnavailable
	}
	return ownership, registry, nil
}

// CheckReady cannot install/activate a policy as an API startup side effect.
func (s *Store) CheckReady(ctx context.Context) error {
	if err := CheckSchema(ctx, s.database); err != nil {
		return err
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ErrUnavailable
	}
	defer rollbackUsername(tx)
	if err := s.Guard(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func registryGuards() []dbprivilege.Guard {
	return []dbprivilege.Guard{
		{Table: "public.username_policy_artifacts", Name: "username_artifact_immutable", Function: "public.username_registry_immutable()", Type: 27},
		{Table: "public.username_policy_artifacts", Name: "username_artifact_no_truncate", Function: "public.username_registry_immutable()", Type: 34},
		{Table: "public.username_lookup_keys", Name: "username_key_immutable", Function: "public.username_registry_immutable()", Type: 27},
		{Table: "public.username_lookup_keys", Name: "username_key_no_truncate", Function: "public.username_registry_immutable()", Type: 34},
	}
}

// ProbeInstaller proves an actual insert-only, non-owner operator identity. It
// rejects role membership, grant options, DDL/trigger and active-row mutation.
func ProbeInstaller(ctx context.Context, q db.DBTX) error {
	return dbprivilege.Check(ctx, q, dbprivilege.Contract{Tables: []dbprivilege.Table{
		{Name: "public.username_policy_artifacts", Select: true, Insert: true},
		{Name: "public.username_lookup_keys", Select: true, Insert: true},
	}, Guards: registryGuards()})
}

// InstallInactive registers immutable content and an independent key verifier.
// It cannot activate, close/open admission, reindex, backfill or mutate users.
func InstallInactive(ctx context.Context, database Database, n *Normalizer) error {
	if database == nil || n == nil {
		return ErrUnavailable
	}
	tx, err := database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ErrUnavailable
	}
	defer rollbackUsername(tx)
	if err := ProbeInstaller(ctx, tx); err != nil {
		return err
	}
	// Installer-only namespace, distinct from account/legal-policy locks.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(550513,1)`); err != nil {
		return ErrUnavailable
	}
	q := db.New(tx)
	a := n.Authority()
	if err := q.InstallUsernameArtifact(ctx, db.InstallUsernameArtifactParams{
		PolicyID: a.PolicyID, Fingerprint: a.Fingerprint[:], Artifact: n.CanonicalArtifact(),
	}); err != nil {
		return ErrUnavailable
	}
	artifact, err := q.GetUsernameArtifact(ctx, a.PolicyID)
	if err != nil || !bytes.Equal(artifact.Fingerprint, a.Fingerprint[:]) || !bytes.Equal(artifact.Artifact, n.CanonicalArtifact()) {
		return ErrPolicyMismatch
	}
	if err := q.InstallUsernameLookupKey(ctx, db.InstallUsernameLookupKeyParams{KeyID: a.KeyID, KeyVerifier: a.KeyVerifier[:]}); err != nil {
		return ErrUnavailable
	}
	key, err := q.GetUsernameLookupKey(ctx, a.KeyID)
	if err != nil || !bytes.Equal(key.KeyVerifier, a.KeyVerifier[:]) {
		return ErrPolicyMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func decodeStoredArtifact(row db.UsernamePolicyArtifact) (Policy, error) {
	p, source, err := DecodeCanonicalArtifact(row.Artifact)
	digest := sha256.Sum256(row.Artifact)
	if err != nil || p.ID != row.PolicyID || !bytes.Equal(digest[:], row.Fingerprint) {
		return Policy{}, ErrPolicyMismatch
	}
	// This nonsecret validation key never represents installed/historical key
	// material; the normalizer is used only to verify canonical serialization.
	validator, err := New(p, source, make([]byte, 32), "artifact-validation")
	if err != nil || !bytes.Equal(validator.CanonicalArtifact(), row.Artifact) {
		return Policy{}, ErrPolicyMismatch
	}
	return p, nil
}

func installedNormalizer(ctx context.Context, q db.DBTX, n *Normalizer) error {
	a := n.Authority()
	row, err := db.New(q).GetUsernameArtifact(ctx, a.PolicyID)
	if err != nil || !bytes.Equal(row.Fingerprint, a.Fingerprint[:]) || !bytes.Equal(row.Artifact, n.CanonicalArtifact()) {
		return ErrPolicyMismatch
	}
	key, err := db.New(q).GetUsernameLookupKey(ctx, a.KeyID)
	if err != nil || !bytes.Equal(key.KeyVerifier, a.KeyVerifier[:]) {
		return ErrPolicyMismatch
	}
	return nil
}
