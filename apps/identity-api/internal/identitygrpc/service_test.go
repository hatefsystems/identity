package identitygrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

func TestFrozenWireContract(t *testing.T) {
	for _, tc := range []struct {
		message proto.Message
		fields  []protoreflect.Name
	}{
		{&identityv1.ValidateTokenRequest{}, []protoreflect.Name{"access_token", "dpop_proof", "expected_audience", "http_method", "http_uri", "authorization_scheme"}},
		{&identityv1.ValidateTokenResponse{}, []protoreflect.Name{"active", "user_id", "scopes", "client_id", "expires_at", "principal_type", "subject", "dpop_outcome", "dpop_nonce"}},
		{&identityv1.CheckPermissionRequest{}, []protoreflect.Name{"user_id", "permission"}},
		{&identityv1.CheckPermissionResponse{}, []protoreflect.Name{"allowed"}},
		{&identityv1.GetInternalUserInfoRequest{}, []protoreflect.Name{"user_id"}},
		{&identityv1.GetInternalUserInfoResponse{}, []protoreflect.Name{"user_id", "email", "display_name", "status", "lifecycle_revision"}},
	} {
		descriptor := tc.message.ProtoReflect().Descriptor()
		for i, name := range tc.fields {
			field := descriptor.Fields().ByName(name)
			if field == nil || field.Number() != protoreflect.FieldNumber(i+1) {
				t.Errorf("wire field %s.%s was removed or renumbered", descriptor.FullName(), name)
			}
		}
	}
	for i, value := range []identityv1.UserStatus{
		identityv1.UserStatus_USER_STATUS_UNSPECIFIED,
		identityv1.UserStatus_USER_STATUS_ACTIVE,
		identityv1.UserStatus_USER_STATUS_SUSPENDED,
		identityv1.UserStatus_USER_STATUS_PENDING_VERIFICATION,
		identityv1.UserStatus_USER_STATUS_PENDING_DELETION,
		identityv1.UserStatus_USER_STATUS_BANNED,
	} {
		if int(value) != i {
			t.Errorf("wire user status %s was renumbered", value)
		}
	}
}

func TestProfileRevisionAdditiveWireCompatibility(t *testing.T) {
	current := (&identityv1.GetInternalUserInfoResponse{}).ProtoReflect().Descriptor()
	revision := current.Fields().ByName("lifecycle_revision")
	if revision == nil || revision.Number() != 5 || revision.Kind() != protoreflect.Uint64Kind || revision.HasPresence() {
		t.Fatal("profile lifecycle revision must remain an additive uint64 field 5")
	}
	// Model an already deployed client with precisely the original four fields.
	legacyMessage := protodesc.ToDescriptorProto(current)
	legacyMessage.Field = legacyMessage.Field[:4]
	legacyFile, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("profile_legacy_fixture.proto"), Package: proto.String("hatef.identity.legacyfixture"), Syntax: proto.String("proto3"),
		Dependency:  []string{"hatef/identity/v1/common.proto"},
		MessageType: []*descriptorpb.DescriptorProto{legacyMessage},
	}, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	legacyDescriptor := legacyFile.Messages().Get(0)
	wantLegacy := &identityv1.GetInternalUserInfoResponse{
		UserId: testUserID, Email: "profile@example.invalid", Status: identityv1.UserStatus_USER_STATUS_ACTIVE,
	}
	wantCurrent := proto.Clone(wantLegacy).(*identityv1.GetInternalUserInfoResponse)
	wantCurrent.LifecycleRevision = 1<<53 + 1
	newWire, err := proto.Marshal(wantCurrent)
	if err != nil {
		t.Fatal(err)
	}
	legacy := dynamicpb.NewMessage(legacyDescriptor)
	if err := proto.Unmarshal(newWire, legacy); err != nil || len(legacy.GetUnknown()) == 0 {
		t.Fatalf("legacy client could not preserve the unknown additive revision: %v", err)
	}
	forwarded, err := proto.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var currentAgain identityv1.GetInternalUserInfoResponse
	if err := proto.Unmarshal(forwarded, &currentAgain); err != nil || !proto.Equal(&currentAgain, wantCurrent) {
		t.Fatalf("legacy protobuf forwarding changed original fields or revision: %v", err)
	}
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(newWire, legacy); err != nil {
		t.Fatal(err)
	}
	oldWire, err := proto.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(oldWire, &currentAgain); err != nil || !proto.Equal(&currentAgain, wantLegacy) || currentAgain.LifecycleRevision != 0 {
		t.Fatalf("old profile snapshot no longer decodes with a zero revision: %v", err)
	}
}

func assertNoClaims(t *testing.T, response *identityv1.ValidateTokenResponse) {
	t.Helper()
	if response == nil || response.Active || response.UserId != "" || response.Subject != "" || response.ClientId != "" ||
		response.PrincipalType != identityv1.PrincipalType_PRINCIPAL_TYPE_UNSPECIFIED || response.ExpiresAt != 0 || len(response.Scopes) != 0 {
		t.Fatalf("inactive response leaked claims: %v", response)
	}
}

func TestHandlersRequireAdmittedWorkloadIdentity(t *testing.T) {
	cfg := testConfig(t)
	var calls atomic.Int64
	cfg.Validator = tokenValidatorFunc(func(context.Context, string, string) (token.ValidatedAccessToken, error) {
		calls.Add(1)
		return validClaims(), nil
	})
	cfg.Queries = queryFuncs{
		permission: func(context.Context, db.UserHasPermissionParams) (bool, error) { calls.Add(1); return true, nil },
		profile: func(context.Context, uuid.UUID) (db.GetInternalUserInfoRow, error) {
			calls.Add(1)
			return db.GetInternalUserInfoRow{}, nil
		},
	}
	s := testService(t, cfg)
	for _, ctx := range []context.Context{
		context.Background(),
		metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-spiffe-id", testCaller, "authorization", "Bearer "+testToken)),
	} {
		if _, err := s.ValidateToken(ctx, validRequest()); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("ValidateToken: %v", err)
		}
		if _, err := s.CheckPermission(ctx, &identityv1.CheckPermissionRequest{UserId: testUserID, Permission: "read"}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("CheckPermission: %v", err)
		}
		if _, err := s.GetInternalUserInfo(ctx, &identityv1.GetInternalUserInfoRequest{UserId: testUserID}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("GetInternalUserInfo: %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unadmitted call reached a dependency")
	}
}

func TestNilRequestsAndCanceledContexts(t *testing.T) {
	cfg := testConfig(t)
	admitted := make(chan context.Context, 1)
	cfg.Validator = tokenValidatorFunc(func(ctx context.Context, _, _ string) (token.ValidatedAccessToken, error) {
		admitted <- context.WithoutCancel(ctx)
		return validClaims(), nil
	})
	h := newMTLSHarness(t, cfg, allGrants(testCaller))
	if _, err := h.client(t, testCaller).ValidateToken(rpcContext(t), validRequest()); err != nil {
		t.Fatal(err)
	}
	ctx := <-admitted // The identity came from a real mTLS admission, not a test setter.
	for _, call := range []func(context.Context) error{
		func(ctx context.Context) error { _, err := h.service.ValidateToken(ctx, nil); return err },
		func(ctx context.Context) error { _, err := h.service.CheckPermission(ctx, nil); return err },
		func(ctx context.Context) error { _, err := h.service.GetInternalUserInfo(ctx, nil); return err },
	} {
		if err := call(ctx); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("nil request: %v", err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := call(canceled); status.Code(err) != codes.Canceled {
			t.Fatalf("canceled context: %v", err)
		}
	}
}

func TestValidateTokenMalformedEnvelopeMTLS(t *testing.T) {
	cfg := testConfig(t)
	var calls atomic.Int64
	cfg.Validator = tokenValidatorFunc(func(context.Context, string, string) (token.ValidatedAccessToken, error) {
		calls.Add(1)
		return validClaims(), nil
	})
	client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
	for _, tc := range []struct {
		name   string
		change func(*identityv1.ValidateTokenRequest)
	}{
		{"empty token", func(r *identityv1.ValidateTokenRequest) { r.AccessToken = "" }},
		{"blank token", func(r *identityv1.ValidateTokenRequest) { r.AccessToken = " \n" }},
		{"oversized token", func(r *identityv1.ValidateTokenRequest) { r.AccessToken = strings.Repeat("a", maxCompactLength+1) }},
		{"oversized proof", func(r *identityv1.ValidateTokenRequest) { r.DpopProof = strings.Repeat("a", maxCompactLength+1) }},
		{"empty audience", func(r *identityv1.ValidateTokenRequest) { r.ExpectedAudience = "" }},
		{"oversized audience", func(r *identityv1.ValidateTokenRequest) { r.ExpectedAudience = strings.Repeat("a", maxContextLength+1) }},
		{"malformed audience", func(r *identityv1.ValidateTokenRequest) { r.ExpectedAudience = "some audience" }},
		{"missing scheme", func(r *identityv1.ValidateTokenRequest) { r.AuthorizationScheme = "" }},
		{"unknown scheme", func(r *identityv1.ValidateTokenRequest) { r.AuthorizationScheme = "Basic" }},
		{"scheme whitespace", func(r *identityv1.ValidateTokenRequest) { r.AuthorizationScheme = " Bearer" }},
		{"missing HTTP context", func(r *identityv1.ValidateTokenRequest) { r.AuthorizationScheme = "DPoP" }},
		{"partial HTTP context", func(r *identityv1.ValidateTokenRequest) { r.HttpMethod = "GET" }},
		{"invalid method", func(r *identityv1.ValidateTokenRequest) { r.HttpMethod, r.HttpUri = "GET /bad", testURI }},
		{"oversized method", func(r *identityv1.ValidateTokenRequest) { r.HttpMethod, r.HttpUri = strings.Repeat("A", 65), testURI }},
		{"oversized URI", func(r *identityv1.ValidateTokenRequest) {
			r.HttpMethod, r.HttpUri = "GET", testOrigin+"/"+strings.Repeat("a", maxContextLength)
		}},
		{"relative URI", func(r *identityv1.ValidateTokenRequest) { r.HttpMethod, r.HttpUri = "GET", "/objects/one" }},
		{"userinfo", func(r *identityv1.ValidateTokenRequest) {
			r.HttpMethod, r.HttpUri = "GET", "https://user:secret@resource.test/objects/one"
		}},
		{"fragment", func(r *identityv1.ValidateTokenRequest) { r.HttpMethod, r.HttpUri = "GET", testURI+"#fragment" }},
		{"empty fragment", func(r *identityv1.ValidateTokenRequest) { r.HttpMethod, r.HttpUri = "GET", testURI+"#" }},
		{"HTTP", func(r *identityv1.ValidateTokenRequest) {
			r.HttpMethod, r.HttpUri = "GET", "http://resource.test/objects/one"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			tc.change(req)
			if response, err := client.ValidateToken(rpcContext(t), req); response != nil || status.Code(err) != codes.InvalidArgument {
				t.Fatalf("response=%v err=%v", response, err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("malformed envelope reached token validation")
	}
}

func TestValidateTokenExactLimitsMTLS(t *testing.T) {
	cfg := testConfig(t)
	audience := strings.Repeat("a", maxContextLength)
	cfg.Policies[testCaller] = ValidationPolicy{Audiences: []string{audience}, Origins: []string{testOrigin}}
	client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
	req := validRequest()
	req.AccessToken, req.ExpectedAudience = strings.Repeat("a", maxCompactLength), audience
	req.HttpMethod, req.HttpUri = "GET", testOrigin+"/"+strings.Repeat("a", maxContextLength-len(testOrigin)-1)
	if response, err := client.ValidateToken(rpcContext(t), req); err != nil || !response.GetActive() {
		t.Fatalf("exact token/audience/URI limits rejected: %v %v", response, err)
	}
	req.DpopProof = strings.Repeat("a", maxCompactLength)
	response, err := client.ValidateToken(rpcContext(t), req)
	if err != nil || response.GetDpopOutcome() != identityv1.DpopOutcome_DPOP_OUTCOME_INVALID_PROOF {
		t.Fatalf("exact proof limit rejected as malformed envelope: %v %v", response, err)
	}
	assertNoClaims(t, response)
}

func TestValidateTokenPrincipalAndErrorResultsMTLS(t *testing.T) {
	user, machine := validClaims(), validClaims()
	machine.PrincipalType, machine.Subject, machine.ClientID = token.PrincipalClient, testUserID, testUserID
	for _, tc := range []struct {
		name   string
		claims token.ValidatedAccessToken
		err    error
		code   codes.Code
	}{
		{"user", user, nil, codes.OK},
		{"UUID-shaped client", machine, nil, codes.OK},
		{"inactive", user, token.ErrInactiveToken, codes.OK},
		{"wrapped inactive", user, fmt.Errorf("invalid authority: %w", token.ErrInactiveToken), codes.OK},
		{"dependency outage", user, errors.New("backend secret@private.invalid " + testToken), codes.Unavailable},
		{"wrapped canceled", user, fmt.Errorf("dependency: %w", context.Canceled), codes.Canceled},
		{"wrapped deadline", user, fmt.Errorf("dependency: %w", context.DeadlineExceeded), codes.DeadlineExceeded},
		{"empty validated result", token.ValidatedAccessToken{}, nil, codes.Internal},
		{"unknown principal", token.ValidatedAccessToken{PrincipalType: "legacy", Subject: testUserID, ClientID: "client", ExpiresAt: 10}, nil, codes.Internal},
		{"invalid user subject", token.ValidatedAccessToken{PrincipalType: token.PrincipalUser, Subject: "not-a-user", ClientID: "client", ExpiresAt: 10}, nil, codes.Internal},
		{"zero user subject", token.ValidatedAccessToken{PrincipalType: token.PrincipalUser, Subject: uuid.Nil.String(), ClientID: "client", ExpiresAt: 10}, nil, codes.Internal},
		{"missing client", token.ValidatedAccessToken{PrincipalType: token.PrincipalUser, Subject: testUserID, ExpiresAt: 10}, nil, codes.Internal},
		{"missing expiry", token.ValidatedAccessToken{PrincipalType: token.PrincipalClient, Subject: "client", ClientID: "client"}, nil, codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			var calls atomic.Int64
			cfg.Validator = tokenValidatorFunc(func(_ context.Context, compact, audience string) (token.ValidatedAccessToken, error) {
				calls.Add(1)
				if compact != testToken || audience != testAudience {
					t.Error("validator did not receive exact presented token and audience")
				}
				return tc.claims, tc.err
			})
			client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
			req := validRequest()
			req.AuthorizationScheme = "bEaReR"
			response, err := client.ValidateToken(rpcContext(t), req)
			if status.Code(err) != tc.code || calls.Load() != 1 {
				t.Fatalf("calls=%d response=%v err=%v", calls.Load(), response, err)
			}
			if err != nil {
				if response != nil || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "secret@") {
					t.Fatal("error leaked claims or backend details")
				}
				return
			}
			if tc.err != nil {
				assertNoClaims(t, response)
				if !proto.Equal(response, &identityv1.ValidateTokenResponse{}) {
					t.Fatal("inactive token leaked an unrelated proof challenge")
				}
				return
			}
			want := &identityv1.ValidateTokenResponse{Active: true, Subject: tc.claims.Subject, ClientId: tc.claims.ClientID,
				Scopes: strings.Fields(tc.claims.Scope), ExpiresAt: tc.claims.ExpiresAt, PrincipalType: identityv1.PrincipalType_PRINCIPAL_TYPE_CLIENT}
			if tc.claims.PrincipalType == token.PrincipalUser {
				want.PrincipalType, want.UserId = identityv1.PrincipalType_PRINCIPAL_TYPE_USER, tc.claims.Subject
			}
			if !proto.Equal(response, want) {
				t.Fatalf("response=%v want=%v", response, want)
			}
			if len(cfg.Recorder.(*testRecorder).snapshot()) != 0 {
				t.Fatal("token hot path emitted routine audit")
			}
		})
	}
}

func TestImmutablePoliciesAndLiveValidationMTLS(t *testing.T) {
	cfg := testConfig(t)
	var calls atomic.Int64
	cfg.Validator = tokenValidatorFunc(func(context.Context, string, string) (token.ValidatedAccessToken, error) {
		if calls.Add(1) == 1 {
			return validClaims(), nil
		}
		return validClaims(), token.ErrInactiveToken
	})
	h := newMTLSHarness(t, cfg, allGrants(testCaller))
	client := h.client(t, testCaller)
	entry := cfg.Policies[testCaller]
	entry.Audiences[0], entry.Origins[0] = "https://attacker.test", "https://attacker.test"
	delete(cfg.Policies, testCaller)
	req := validRequest()
	req.HttpMethod, req.HttpUri = "GET", testURI
	if response, err := client.ValidateToken(rpcContext(t), req); err != nil || !response.GetActive() {
		t.Fatalf("input mutation changed copied policy: %v %v", response, err)
	}
	response, err := client.ValidateToken(rpcContext(t), req)
	if err != nil || calls.Load() != 2 {
		t.Fatalf("live authority not rechecked: %v", err)
	}
	assertNoClaims(t, response)
	for _, audience := range []string{"https://attacker.test", testAudience + "/", strings.ToUpper(testAudience)} {
		req.ExpectedAudience = audience
		if _, err := client.ValidateToken(rpcContext(t), req); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("non-exact audience accepted: %v", err)
		}
	}
	req.ExpectedAudience, req.HttpUri = testAudience, "https://resource.test.attacker.test/objects/one"
	if _, err := client.ValidateToken(rpcContext(t), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("origin suffix matched policy: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatal("policy denial consulted credential authority")
	}
}

func TestPermissionValidationAndLiveExactReadsMTLS(t *testing.T) {
	cfg := testConfig(t)
	var calls atomic.Int64
	var revoked atomic.Bool
	cfg.Queries = queryFuncs{permission: func(_ context.Context, arg db.UserHasPermissionParams) (bool, error) {
		calls.Add(1)
		if arg.UserID != uuid.MustParse(testUserID) {
			t.Error("permission query received wrong subject")
		}
		return !revoked.Load() && (arg.PermissionID == "objects.read" || arg.PermissionID == strings.Repeat("\u00e9", 100)), nil
	}}
	client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
	for _, permission := range []string{"objects.read", "objects.*", "Objects.Read", " objects.read ", "moderator", strings.Repeat("\u00e9", 100)} {
		response, err := client.CheckPermission(rpcContext(t), &identityv1.CheckPermissionRequest{UserId: testUserID, Permission: permission})
		want := permission == "objects.read" || permission == strings.Repeat("\u00e9", 100)
		if err != nil || response.GetAllowed() != want {
			t.Fatalf("exact permission=%q: %v %v", permission, response, err)
		}
	}
	revoked.Store(true)
	if response, err := client.CheckPermission(rpcContext(t), &identityv1.CheckPermissionRequest{UserId: testUserID, Permission: "objects.read"}); err != nil || response.GetAllowed() {
		t.Fatalf("positive permission cached: %v %v", response, err)
	}
	before := calls.Load()
	for _, req := range []*identityv1.CheckPermissionRequest{
		{}, {UserId: "bad", Permission: "objects.read"}, {UserId: uuid.Nil.String(), Permission: "objects.read"},
		{UserId: testUserID}, {UserId: testUserID, Permission: " \t"},
		{UserId: testUserID, Permission: "objects\nread"}, {UserId: testUserID, Permission: "objects\x00read"},
		{UserId: testUserID, Permission: strings.Repeat("a", 101)}, {UserId: testUserID, Permission: strings.Repeat("\u00e9", 101)},
	} {
		if response, err := client.CheckPermission(rpcContext(t), req); response != nil || status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid permission request: %v %v", response, err)
		}
	}
	if calls.Load() != before || len(cfg.Recorder.(*testRecorder).snapshot()) != 0 {
		t.Fatal("malformed permission reached database or hot path emitted audit")
	}
}

func TestProfilesMinimizeEveryStatusAndAuditMTLS(t *testing.T) {
	for _, tc := range []struct {
		name, stored string
		status       identityv1.UserStatus
		email        bool
		queryErr     error
		code         codes.Code
	}{
		{"active", "active", identityv1.UserStatus_USER_STATUS_ACTIVE, true, nil, codes.OK},
		{"pending verification", "pending_verification", identityv1.UserStatus_USER_STATUS_PENDING_VERIFICATION, true, nil, codes.OK},
		{"suspended", "suspended", identityv1.UserStatus_USER_STATUS_SUSPENDED, false, nil, codes.OK},
		{"banned", "banned", identityv1.UserStatus_USER_STATUS_BANNED, false, nil, codes.OK},
		{"pending deletion", "pending_deletion", 0, false, nil, codes.NotFound},
		{"deleted", "", 0, false, pgx.ErrNoRows, codes.NotFound},
		{"missing", "", 0, false, fmt.Errorf("lookup: %w", pgx.ErrNoRows), codes.NotFound},
		{"unknown", "unexpected-private-status", 0, false, nil, codes.Internal},
		{"outage", "", 0, false, errors.New("profile@example.invalid ciphertext database failure"), codes.Unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Queries = queryFuncs{profile: func(_ context.Context, id uuid.UUID) (db.GetInternalUserInfoRow, error) {
				return db.GetInternalUserInfoRow{ID: id, Status: tc.stored, Email: "profile@example.invalid", DisplayName: "Private display name", LifecycleRevision: 42}, tc.queryErr
			}}
			client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
			response, err := client.GetInternalUserInfo(rpcContext(t), &identityv1.GetInternalUserInfoRequest{UserId: testUserID})
			if status.Code(err) != tc.code {
				t.Fatalf("profile=%v err=%v", response, err)
			}
			events := cfg.Recorder.(*testRecorder).snapshot()
			if err != nil {
				if response != nil || len(events) != 0 || strings.Contains(err.Error(), "@example") || strings.Contains(err.Error(), "ciphertext") || strings.Contains(err.Error(), "private-status") {
					t.Fatal("failed read leaked stored data or emitted disclosure event")
				}
				return
			}
			want := &identityv1.GetInternalUserInfoResponse{UserId: testUserID, Status: tc.status, LifecycleRevision: 42}
			if tc.email {
				want.Email = "profile@example.invalid"
				want.DisplayName = "Private display name"
			}
			if !proto.Equal(response, want) {
				t.Fatalf("profile=%v want=%v", response, want)
			}
			if len(events) != 1 {
				t.Fatalf("disclosures=%d", len(events))
			}
			e := events[0]
			if e.EventType != audit.EventGRPCProfileRead || e.ActionStatus != audit.StatusSuccess || e.ActorSPIFFEID != testCaller ||
				e.ActorID != uuid.Nil || e.SubjectID == nil || *e.SubjectID != uuid.MustParse(testUserID) || e.Security != nil ||
				e.ClientIP != "" || e.UserAgent != "" || !reflect.DeepEqual(e.Payload, map[string]any{"email_disclosed": tc.email, "display_name_disclosed": tc.email}) || audit.IsLedgerEventType(e.EventType) {
				t.Fatalf("unsafe or incomplete routine disclosure audit: %+v", e)
			}
			encoded, err := json.Marshal(e)
			if err != nil || bytes.Contains(encoded, []byte("profile@example.invalid")) || bytes.Contains(encoded, []byte("Private display name")) {
				t.Fatal("audit copied profile PII")
			}
		})
	}
}

func TestProfileRevisionIsLiveAndRejectsCorruptSignedStateMTLS(t *testing.T) {
	for _, storedStatus := range []string{"active", "pending_verification", "suspended", "banned"} {
		t.Run(storedStatus, func(t *testing.T) {
			cfg := testConfig(t)
			var revision, calls atomic.Int64
			cfg.Queries = queryFuncs{profile: func(_ context.Context, id uuid.UUID) (db.GetInternalUserInfoRow, error) {
				calls.Add(1)
				value := revision.Load()
				return db.GetInternalUserInfoRow{ID: id, Status: storedStatus, Email: "profile@example.invalid", DisplayName: strconv.FormatInt(value, 10), LifecycleRevision: value}, nil
			}}
			client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
			values := []int64{0, 1, 1<<53 + 1, math.MaxInt64, -1, math.MinInt64, 2}
			for _, value := range values {
				revision.Store(value)
				before := len(cfg.Recorder.(*testRecorder).snapshot())
				response, err := client.GetInternalUserInfo(rpcContext(t), &identityv1.GetInternalUserInfoRequest{UserId: testUserID})
				if value < 0 {
					if response != nil || status.Code(err) != codes.Internal || len(cfg.Recorder.(*testRecorder).snapshot()) != before {
						t.Fatalf("negative stored revision was disclosed or cast to uint64: %v, %v", response, err)
					}
					if strings.Contains(err.Error(), "profile@example.invalid") || strings.Contains(err.Error(), testUserID) {
						t.Fatal("corrupt revision error exposed profile data")
					}
					continue
				}
				if err != nil || response == nil || response.LifecycleRevision != uint64(value) || len(cfg.Recorder.(*testRecorder).snapshot()) != before+1 {
					t.Fatalf("live snapshot revision=%d response=%v err=%v", value, response, err)
				}
				if storedStatus == "suspended" || storedStatus == "banned" {
					if response.Email != "" || response.DisplayName != "" {
						t.Fatal("revision disclosure bypassed status-dependent profile redaction")
					}
				} else if response.DisplayName != strconv.FormatInt(value, 10) {
					t.Fatal("name and revision did not come from the same snapshot")
				}
			}
			if calls.Load() != int64(len(values)) {
				t.Fatal("profile revisions were cached instead of read live")
			}
		})
	}
}

func TestProfileInputAndQueryInvariantsMTLS(t *testing.T) {
	cfg := testConfig(t)
	var calls atomic.Int64
	cfg.Queries = queryFuncs{profile: func(context.Context, uuid.UUID) (db.GetInternalUserInfoRow, error) {
		calls.Add(1)
		return db.GetInternalUserInfoRow{ID: uuid.New(), Status: "active", Email: "private@example.invalid"}, nil
	}}
	client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
	for _, rawID := range []string{"", "not-a-uuid", uuid.Nil.String(), " " + testUserID} {
		if _, err := client.GetInternalUserInfo(rpcContext(t), &identityv1.GetInternalUserInfoRequest{UserId: rawID}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("malformed profile user ID: %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("malformed profile user ID reached DB")
	}
	if response, err := client.GetInternalUserInfo(rpcContext(t), &identityv1.GetInternalUserInfoRequest{UserId: testUserID}); response != nil || status.Code(err) != codes.Internal {
		t.Fatalf("mismatched query subject accepted: %v %v", response, err)
	}
}

func TestProfileAuditOmissionAndSanitizedFailureMTLS(t *testing.T) {
	for _, length := range []int{255, 256} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			prefix := "spiffe://identity.test/"
			caller := prefix + strings.Repeat("a", length-len(prefix))
			cfg := testConfig(t)
			recorder := &testRecorder{err: errors.New("private@example.invalid " + testToken + " " + caller)}
			var logs bytes.Buffer
			cfg.Recorder, cfg.Logger = recorder, slog.New(slog.NewJSONHandler(&logs, nil))
			client := newMTLSHarness(t, cfg, allGrants(caller)).client(t, caller)
			response, err := client.GetInternalUserInfo(rpcContext(t), &identityv1.GetInternalUserInfoRequest{UserId: testUserID})
			if err != nil || response.GetEmail() != "profile@example.invalid" {
				t.Fatalf("best-effort audit failure changed disclosure: %v %v", response, err)
			}
			events := recorder.snapshot()
			if len(events) != 1 {
				t.Fatalf("audit attempts=%d", len(events))
			}
			event := events[0]
			if length == 255 && event.ActorSPIFFEID != caller || length > 255 && (event.ActorSPIFFEID != "" || event.Payload["actor_spiffe_id_omitted"] != true) {
				t.Fatal("actor identity was truncated or omission was not bounded")
			}
			encoded, err := json.Marshal(event.Payload)
			if err != nil || bytes.Contains(encoded, []byte(caller)) || strings.Contains(logs.String(), "@example") || strings.Contains(logs.String(), testToken) || strings.Contains(logs.String(), caller) {
				t.Fatal("recorder failure or oversized actor leaked to payload/logs")
			}
			if !strings.Contains(logs.String(), "profile-read audit unavailable") {
				t.Fatal("audit outage not observable")
			}
		})
	}
}

func TestWorkloadMethodDenialAndTrustFailuresMTLS(t *testing.T) {
	cfg := testConfig(t)
	h := newMTLSHarness(t, cfg, map[string][]string{identityv1.IdentityService_ValidateToken_FullMethodName: {testCaller}})
	client := h.client(t, testCaller)
	ctx := metadata.NewOutgoingContext(rpcContext(t), metadata.Pairs("x-spiffe-id", testCaller, "authorization", "Bearer "+testToken))
	if response, err := client.ValidateToken(ctx, validRequest()); err != nil || !response.GetActive() {
		t.Fatalf("granted method failed: %v %v", response, err)
	}
	before := h.admitted.Load()
	if _, err := client.CheckPermission(ctx, &identityv1.CheckPermissionRequest{UserId: testUserID, Permission: "read"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ungranted permission method: %v", err)
	}
	if _, err := client.GetInternalUserInfo(ctx, &identityv1.GetInternalUserInfoRequest{UserId: testUserID}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ungranted profile method: %v", err)
	}
	if _, err := h.client(t, testOther).ValidateToken(ctx, validRequest()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("metadata forged caller identity: %v", err)
	}
	if h.admitted.Load() != before || len(cfg.Recorder.(*testRecorder).snapshot()) != 3 {
		t.Fatal("denied workload reached business logic or lost denial audit")
	}
	if _, err := h.clientWithCredentials(t, insecure.NewCredentials()).ValidateToken(rpcContext(t), validRequest()); err == nil || h.admitted.Load() != before {
		t.Fatal("plaintext connection reached service")
	}
	h.bundles.set(nil, errors.New("private trust source details"))
	if _, err := client.ValidateToken(ctx, validRequest()); status.Code(err) != codes.Unavailable || strings.Contains(err.Error(), "private") {
		t.Fatalf("trust dependency failure misclassified: %v", err)
	}
	if h.admitted.Load() != before {
		t.Fatal("trust outage reached handler")
	}
}

func TestQueriesPropagateSanitizedDependencyErrorsMTLS(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code codes.Code
	}{
		{errors.New("database secret dsn profile@example.invalid"), codes.Unavailable},
		{fmt.Errorf("database: %w", context.Canceled), codes.Canceled},
		{fmt.Errorf("database: %w", context.DeadlineExceeded), codes.DeadlineExceeded},
	} {
		t.Run(tc.code.String(), func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Queries = queryFuncs{
				permission: func(context.Context, db.UserHasPermissionParams) (bool, error) { return true, tc.err },
				profile: func(context.Context, uuid.UUID) (db.GetInternalUserInfoRow, error) {
					return db.GetInternalUserInfoRow{}, tc.err
				},
			}
			client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
			permission, err := client.CheckPermission(rpcContext(t), &identityv1.CheckPermissionRequest{UserId: testUserID, Permission: "read"})
			if permission != nil || status.Code(err) != tc.code || strings.Contains(err.Error(), "secret") {
				t.Fatalf("permission dependency failure: %v %v", permission, err)
			}
			profile, err := client.GetInternalUserInfo(rpcContext(t), &identityv1.GetInternalUserInfoRequest{UserId: testUserID})
			if profile != nil || status.Code(err) != tc.code || strings.Contains(err.Error(), "@example") {
				t.Fatalf("profile dependency failure: %v %v", profile, err)
			}
		})
	}
}

func TestCancellationReachesEveryHandlerDependencyMTLS(t *testing.T) {
	for _, method := range []string{"token", "permission", "profile"} {
		for _, deadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deadline=%v", method, deadline), func(t *testing.T) {
				cfg := testConfig(t)
				entered, observed := make(chan struct{}), make(chan error, 1)
				wait := func(ctx context.Context) error {
					close(entered)
					<-ctx.Done()
					observed <- ctx.Err()
					return fmt.Errorf("canceled backing call: %w", ctx.Err())
				}
				cfg.Validator = tokenValidatorFunc(func(ctx context.Context, _, _ string) (token.ValidatedAccessToken, error) {
					return validClaims(), wait(ctx)
				})
				cfg.Queries = queryFuncs{
					permission: func(ctx context.Context, _ db.UserHasPermissionParams) (bool, error) { return true, wait(ctx) },
					profile: func(ctx context.Context, _ uuid.UUID) (db.GetInternalUserInfoRow, error) {
						return db.GetInternalUserInfoRow{}, wait(ctx)
					},
				}
				client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				}
				defer cancel()
				result := make(chan error, 1)
				go func() {
					var err error
					switch method {
					case "token":
						_, err = client.ValidateToken(ctx, validRequest())
					case "permission":
						_, err = client.CheckPermission(ctx, &identityv1.CheckPermissionRequest{UserId: testUserID, Permission: "read"})
					case "profile":
						_, err = client.GetInternalUserInfo(ctx, &identityv1.GetInternalUserInfoRequest{UserId: testUserID})
					}
					result <- err
				}()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("call did not reach dependency before cancellation")
				}
				want := codes.DeadlineExceeded
				if !deadline {
					want = codes.Canceled
					cancel()
				}
				if err := <-result; status.Code(err) != want {
					t.Fatalf("cancellation result: %v", err)
				}
				select {
				case err := <-observed:
					if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("dependency lost cancellation: %v", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("RPC cancellation did not reach dependency")
				}
			})
		}
	}
}
