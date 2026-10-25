//go:build integration

package identitygrpc

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	embedded "github.com/hatefsystems/identity/apps/identity-api/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

func integrationDependency(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if strings.TrimSpace(value) == "" {
		if os.Getenv("REQUIRE_GRPC_INTEGRATION") == "1" {
			t.Fatalf("%s is required for mandatory gRPC integration tests", name)
		}
		t.Skipf("%s is not configured; use REQUIRE_GRPC_INTEGRATION=1 to require real dependencies", name)
	}
	return value
}

func integrationDatabase(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := integrationDependency(t, "DATABASE_URL")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid PostgreSQL integration configuration")
	}
	t.Cleanup(admin.Close)
	ping, stop := context.WithTimeout(ctx, 5*time.Second)
	err = admin.Ping(ping)
	stop()
	if err != nil {
		t.Fatal("configured PostgreSQL integration dependency is unavailable")
	}
	schema := "grpc_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid PostgreSQL integration configuration")
	}
	// Missing extensions are installed by the migrations into this owned schema,
	// not public. An already installed public extension is only reused.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	cfg.MaxConns = 6
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// Reuse the real identity/RBAC and lifecycle migrations in an isolated
	// schema. Unrelated retention migrations deliberately target public.
	files := fstest.MapFS{}
	entries, err := fs.ReadDir(embedded.Migrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() > "00010_account_auth_version.sql" && entry.Name() != "00016_user_lifecycle_events.sql" && entry.Name() != "00017_profile_names.sql" {
			continue
		}
		data, err := fs.ReadFile(embedded.Migrations, "migrations/"+entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = &fstest.MapFile{Data: data}
	}
	sqlDB := stdlib.OpenDB(*cfg.ConnConfig)
	defer func() { _ = sqlDB.Close() }()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	return ctx, pool
}

func TestProfileAndPermissionDatabaseIntegration(t *testing.T) {
	t.Setenv("ADMIN_ENABLED", "false")
	ctx, pool := integrationDatabase(t)
	queries := db.New(pool)
	id, roleID := uuid.New(), "grpc-"+uuid.NewString()
	email, permission := id.String()+"@grpc-integration.invalid", "grpc.objects.read."+uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO users
		(id, email, status, password_hash, phone_encrypted, backup_email_encrypted, mfa_totp_secret_encrypted, display_name)
		VALUES ($1,$2,'active',$3,$4,$4,$4,'Private display name')`, id, email, "must-not-disclose-password-hash", []byte("must-not-disclose-ciphertext")); err != nil {
		t.Fatal(err)
	}
	if _, err := queries.CreateRole(ctx, db.CreateRoleParams{ID: roleID, Description: "gRPC integration fixture"}); err != nil {
		t.Fatal(err)
	}
	if _, err := queries.CreatePermission(ctx, db.CreatePermissionParams{ID: permission, Description: "gRPC integration fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := queries.AddPermissionToRole(ctx, db.AddPermissionToRoleParams{RoleID: roleID, PermissionID: permission}); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	cfg.Queries = queries
	client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
	if profile, err := client.GetInternalUserInfo(ctx, &identityv1.GetInternalUserInfoRequest{UserId: id.String()}); err != nil || profile == nil || profile.LifecycleRevision != 0 {
		t.Fatalf("uncaptured account must start at revision zero: %v, %v", profile, err)
	}
	check := func(t *testing.T, want bool, permission string) {
		t.Helper()
		response, err := client.CheckPermission(ctx, &identityv1.CheckPermissionRequest{UserId: id.String(), Permission: permission})
		if err != nil || response.GetAllowed() != want {
			t.Fatalf("live permission=%v want=%v err=%v", response, want, err)
		}
	}
	check(t, false, permission)
	if err := queries.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: id, RoleID: roleID}); err != nil {
		t.Fatal(err)
	}
	check(t, true, permission)
	for _, absent := range []string{permission + ".missing", "grpc.*", strings.ToUpper(permission), roleID} {
		check(t, false, absent)
	}
	if _, err := queries.RemoveRoleFromUser(ctx, db.RemoveRoleFromUserParams{UserID: id, RoleID: roleID}); err != nil {
		t.Fatal(err)
	}
	check(t, false, permission)
	if err := queries.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: id, RoleID: roleID}); err != nil {
		t.Fatal(err)
	}

	for i, tc := range []struct {
		name, stored string
		status       identityv1.UserStatus
		email        bool
		deleted      bool
		code         codes.Code
	}{
		{"active", "active", identityv1.UserStatus_USER_STATUS_ACTIVE, true, false, codes.OK},
		{"pending verification", "pending_verification", identityv1.UserStatus_USER_STATUS_PENDING_VERIFICATION, true, false, codes.OK},
		{"suspended", "suspended", identityv1.UserStatus_USER_STATUS_SUSPENDED, false, false, codes.OK},
		{"banned", "banned", identityv1.UserStatus_USER_STATUS_BANNED, false, false, codes.OK},
		{"pending deletion", "pending_deletion", 0, false, false, codes.NotFound},
		{"soft deleted", "active", 0, false, true, codes.NotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			revision := int64(i + 1)
			var deletedAt *time.Time
			if tc.deleted {
				now := time.Now()
				deletedAt = &now
			}
			if _, err := pool.Exec(ctx, "UPDATE users SET status=$2, deleted_at=$3, lifecycle_revision=$4 WHERE id=$1", id, tc.stored, deletedAt, revision); err != nil {
				t.Fatal(err)
			}
			row, queryErr := queries.GetInternalUserInfo(ctx, id)
			response, err := client.GetInternalUserInfo(ctx, &identityv1.GetInternalUserInfoRequest{UserId: id.String()})
			if status.Code(err) != tc.code {
				t.Fatalf("profile=%v err=%v", response, err)
			}
			if tc.code == codes.NotFound {
				if !errors.Is(queryErr, pgx.ErrNoRows) || response != nil {
					t.Fatalf("SQL did not exclude deleted/pending-deletion profile: %v", queryErr)
				}
			} else {
				wireRevision, parseErr := strconv.ParseUint(strconv.FormatInt(revision, 10), 10, 64)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				want := &identityv1.GetInternalUserInfoResponse{UserId: id.String(), Status: tc.status, LifecycleRevision: wireRevision}
				if tc.email {
					want.Email = email
					want.DisplayName = "Private display name"
				}
				if queryErr != nil || row.ID != id || row.Email != want.Email || row.DisplayName != want.DisplayName || row.LifecycleRevision != revision || !proto.Equal(response, want) {
					t.Fatalf("SQL or RPC profile minimization failed: %v", queryErr)
				}
			}
			check(t, tc.stored == "active" && !tc.deleted, permission)
		})
	}
	if _, err := pool.Exec(ctx, "DELETE FROM users WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	check(t, false, permission)
	for _, missing := range []uuid.UUID{id, uuid.New()} {
		if response, err := client.GetInternalUserInfo(ctx, &identityv1.GetInternalUserInfoRequest{UserId: missing.String()}); response != nil || status.Code(err) != codes.NotFound {
			t.Fatalf("hard-deleted/missing profile=%v err=%v", response, err)
		}
	}
	pool.Close()
	if response, err := client.CheckPermission(ctx, &identityv1.CheckPermissionRequest{UserId: id.String(), Permission: permission}); response != nil || status.Code(err) != codes.Unavailable {
		t.Fatalf("closed DB was a negative permission assertion: %v %v", response, err)
	}
	if response, err := client.GetInternalUserInfo(ctx, &identityv1.GetInternalUserInfoRequest{UserId: id.String()}); response != nil || status.Code(err) != codes.Unavailable {
		t.Fatalf("closed DB was a missing profile assertion: %v %v", response, err)
	}
}

func TestDPoPRealRedisIntegration(t *testing.T) {
	rawURL := integrationDependency(t, "REDIS_URL")
	key := proofKey(t)
	var clients []identityv1.IdentityServiceClient
	for range 2 {
		options, err := redis.ParseURL(rawURL)
		if err != nil {
			t.Fatal("invalid Redis integration configuration")
		}
		options.DialTimeout, options.ReadTimeout, options.WriteTimeout, options.MaxRetries = time.Second, time.Second, time.Second, -1
		options.ContextTimeoutEnabled = true
		store := redis.NewClient(options)
		t.Cleanup(func() { _ = store.Close() })
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = store.Ping(ctx).Err()
		cancel()
		if err != nil {
			t.Fatal("configured Redis integration dependency is unavailable")
		}
		cfg := boundConfig(t, key, redisDPoP(t, store))
		clients = append(clients, newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller))
	}
	// The service-level fixture deliberately stubs token authority. Full issuance,
	// session/account gating, and grant revocation belong to the token roundtrip.
	req := proofRequest(signProof(t, key, proofClaims("")))
	challenge, err := clients[0].ValidateToken(rpcContext(t), req)
	assertProofOutcome(t, challenge, err, identityv1.DpopOutcome_DPOP_OUTCOME_USE_NONCE)
	req.DpopProof = signProof(t, key, proofClaims(challenge.DpopNonce))
	if response, err := clients[1].ValidateToken(rpcContext(t), req); err != nil || !response.GetActive() {
		t.Fatalf("real Redis cross-instance proof=%v err=%v", response, err)
	}
	response, err := clients[0].ValidateToken(rpcContext(t), req)
	assertProofOutcome(t, response, err, identityv1.DpopOutcome_DPOP_OUTCOME_USE_NONCE)
}

func TestDisplayNameRevisionSnapshotDatabaseIntegration(t *testing.T) {
	ctx, pool := integrationDatabase(t)
	queries := db.New(pool)
	u, err := queries.CreateUser(ctx, db.CreateUserParams{Email: uuid.NewString() + "@grpc-integration.invalid", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	const base = int64(1<<53 + 1)
	if _, err := pool.Exec(ctx, "UPDATE users SET display_name=$2,lifecycle_revision=$3 WHERE id=$1", u.ID, strconv.FormatInt(base, 10), base); err != nil {
		t.Fatal(err)
	}
	svc, err := profile.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	cfg.Queries = queries
	client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
	finished := make(chan error, 1)
	go func() {
		for revision := base; revision < base+20; revision++ {
			if _, err := svc.Update(ctx, u.ID, u.AuthVersion, strconv.FormatInt(revision+1, 10), strconv.FormatInt(revision, 10)); err != nil {
				finished <- err
				return
			}
		}
		finished <- nil
	}()
	for range 50 {
		response, err := client.GetInternalUserInfo(ctx, &identityv1.GetInternalUserInfoRequest{UserId: u.ID.String()})
		if err != nil || response == nil || response.DisplayName != strconv.FormatUint(response.LifecycleRevision, 10) || response.LifecycleRevision < uint64(base) {
			t.Fatalf("concurrent gRPC name/revision snapshot tore: %v", err)
		}
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	response, err := client.GetInternalUserInfo(ctx, &identityv1.GetInternalUserInfoRequest{UserId: u.ID.String()})
	if err != nil || response.LifecycleRevision != uint64(base+20) || response.DisplayName != strconv.FormatInt(base+20, 10) {
		t.Fatal("latest shared profile snapshot was not visible")
	}
}
