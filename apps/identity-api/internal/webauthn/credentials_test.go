package webauthn

import (
	"bytes"
	"math"
	"testing"

	"github.com/google/uuid"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// TestQueriesSatisfyStores is a compile-time assertion that the generated
// *db.Queries keeps satisfying the narrow store interfaces the service depends
// on, so a future sqlc regeneration that changes a signature fails here.
func TestQueriesSatisfyStores(_ *testing.T) {
	var (
		_ UserStore       = (*db.Queries)(nil)
		_ CredentialStore = (*db.Queries)(nil)
	)
}

func TestSignCountToUint32(t *testing.T) {
	tests := []struct {
		name string
		in   int64
		want uint32
	}{
		{name: "zero", in: 0, want: 0},
		{name: "typical", in: 42, want: 42},
		{name: "negative clamps to zero", in: -1, want: 0},
		{name: "large negative clamps to zero", in: math.MinInt64, want: 0},
		{name: "max uint32 passes through", in: math.MaxUint32, want: math.MaxUint32},
		{name: "above max clamps down", in: math.MaxUint32 + 1, want: math.MaxUint32},
		{name: "max int64 clamps down", in: math.MaxInt64, want: math.MaxUint32},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := signCountToUint32(tc.in); got != tc.want {
				t.Errorf("signCountToUint32(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestAAGUIDRoundTrip(t *testing.T) {
	id := uuid.MustParse("adce0002-35bc-c60a-648b-0b25f1f05503")

	raw := aaguidToBytes(id)
	if len(raw) != 16 {
		t.Fatalf("len(aaguidToBytes) = %d, want 16", len(raw))
	}
	if got := aaguidFromBytes(raw); got != id {
		t.Errorf("aaguidFromBytes(aaguidToBytes(%v)) = %v, want round trip", id, got)
	}

	// Mutating the returned slice must not corrupt the source UUID: the helper
	// copies into a local before slicing.
	raw[0] ^= 0xff
	if got := aaguidToBytes(id); got[0] == raw[0] {
		t.Error("aaguidToBytes returned an aliased slice; mutation leaked back into the UUID")
	}
}

func TestAAGUIDFromBytesEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{name: "nil", in: nil},
		{name: "empty", in: []byte{}},
		{name: "too short", in: []byte{1, 2, 3}},
		{name: "too long", in: bytes.Repeat([]byte{0xab}, 17)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := aaguidFromBytes(tc.in); got != uuid.Nil {
				t.Errorf("aaguidFromBytes(%x) = %v, want uuid.Nil", tc.in, got)
			}
		})
	}
}

func TestDBToCredential(t *testing.T) {
	aaguid := uuid.MustParse("adce0002-35bc-c60a-648b-0b25f1f05503")
	row := db.WebauthnCredential{
		ID:              []byte("credential-id"),
		PublicKey:       []byte("cose-public-key"),
		AttestationType: "none",
		SignCount:       7,
		UserPresent:     true,
		UserVerified:    true,
		BackupEligible:  true,
		BackupState:     false,
		Aaguid:          aaguid,
	}

	cred := dbToCredential(row)

	if !bytes.Equal(cred.ID, row.ID) {
		t.Errorf("ID = %x, want %x", cred.ID, row.ID)
	}
	if !bytes.Equal(cred.PublicKey, row.PublicKey) {
		t.Errorf("PublicKey = %x, want %x", cred.PublicKey, row.PublicKey)
	}
	if cred.Authenticator.SignCount != 7 {
		t.Errorf("Authenticator.SignCount = %d, want 7", cred.Authenticator.SignCount)
	}
	if got := aaguidFromBytes(cred.Authenticator.AAGUID); got != aaguid {
		t.Errorf("Authenticator.AAGUID = %v, want %v", got, aaguid)
	}
	if cred.Authenticator.CloneWarning {
		t.Error("Authenticator.CloneWarning = true on a freshly mapped row, want false")
	}
	want := gowebauthn.CredentialFlags{
		UserPresent:    true,
		UserVerified:   true,
		BackupEligible: true,
		BackupState:    false,
	}
	if cred.Flags != want {
		t.Errorf("Flags = %+v, want %+v", cred.Flags, want)
	}
}

// TestDBToCredentialClampsCorruptSignCount proves a corrupted (negative) stored
// counter degrades to zero rather than wrapping into a huge uint32, which would
// permanently lock the credential out via the clone check.
func TestDBToCredentialClampsCorruptSignCount(t *testing.T) {
	cred := dbToCredential(db.WebauthnCredential{ID: []byte("x"), SignCount: -5})
	if cred.Authenticator.SignCount != 0 {
		t.Errorf("Authenticator.SignCount = %d, want 0", cred.Authenticator.SignCount)
	}
}

func TestDBToCredentials(t *testing.T) {
	rows := []db.WebauthnCredential{
		{ID: []byte("a"), SignCount: 1},
		{ID: []byte("b"), SignCount: 2},
	}

	creds := dbToCredentials(rows)
	if len(creds) != 2 {
		t.Fatalf("len(creds) = %d, want 2", len(creds))
	}
	for i, row := range rows {
		if !bytes.Equal(creds[i].ID, row.ID) {
			t.Errorf("creds[%d].ID = %x, want %x", i, creds[i].ID, row.ID)
		}
	}

	// An empty list must map to an empty (non-nil) slice so the library's
	// exclusion/allow-credentials construction is well-defined.
	if got := dbToCredentials(nil); got == nil || len(got) != 0 {
		t.Errorf("dbToCredentials(nil) = %v, want empty non-nil slice", got)
	}
}

func TestCredentialToCreateParams(t *testing.T) {
	userID := uuid.New()
	aaguid := uuid.MustParse("adce0002-35bc-c60a-648b-0b25f1f05503")
	cred := &gowebauthn.Credential{
		ID:              []byte("new-credential"),
		PublicKey:       []byte("cose-key"),
		AttestationType: "packed",
		Flags: gowebauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: true,
			BackupState:    true,
		},
		Authenticator: gowebauthn.Authenticator{
			AAGUID:    aaguidToBytes(aaguid),
			SignCount: 3,
		},
	}

	params := credentialToCreateParams(userID, cred)

	if params.UserID != userID {
		t.Errorf("UserID = %v, want %v", params.UserID, userID)
	}
	if !bytes.Equal(params.ID, cred.ID) {
		t.Errorf("ID = %x, want %x", params.ID, cred.ID)
	}
	if !bytes.Equal(params.PublicKey, cred.PublicKey) {
		t.Errorf("PublicKey = %x, want %x", params.PublicKey, cred.PublicKey)
	}
	if params.AttestationType != "packed" {
		t.Errorf("AttestationType = %q, want %q", params.AttestationType, "packed")
	}
	if params.SignCount != 3 {
		t.Errorf("SignCount = %d, want 3", params.SignCount)
	}
	if params.Aaguid != aaguid {
		t.Errorf("Aaguid = %v, want %v", params.Aaguid, aaguid)
	}
	if !params.UserPresent || !params.UserVerified || !params.BackupEligible || !params.BackupState {
		t.Errorf("flags = %+v, want all true", params)
	}
}

// TestCredentialToCreateParamsWithoutAAGUID covers authenticators that withhold
// their AAGUID (privacy-preserving platform keys): the row stores the nil UUID.
func TestCredentialToCreateParamsWithoutAAGUID(t *testing.T) {
	params := credentialToCreateParams(uuid.New(), &gowebauthn.Credential{ID: []byte("x")})
	if params.Aaguid != uuid.Nil {
		t.Errorf("Aaguid = %v, want uuid.Nil", params.Aaguid)
	}
}

// TestCredentialMappingRoundTrip asserts a credential survives the
// insert-then-load cycle unchanged for the fields an assertion depends on.
func TestCredentialMappingRoundTrip(t *testing.T) {
	userID := uuid.New()
	original := &gowebauthn.Credential{
		ID:              []byte("round-trip-id"),
		PublicKey:       []byte("round-trip-key"),
		AttestationType: "none",
		Flags:           gowebauthn.CredentialFlags{UserPresent: true, BackupEligible: true},
		Authenticator:   gowebauthn.Authenticator{SignCount: 11},
	}

	params := credentialToCreateParams(userID, original)
	// Simulate the DB returning exactly what was inserted.
	row := db.WebauthnCredential{
		ID:              params.ID,
		UserID:          params.UserID,
		PublicKey:       params.PublicKey,
		AttestationType: params.AttestationType,
		SignCount:       params.SignCount,
		UserPresent:     params.UserPresent,
		UserVerified:    params.UserVerified,
		BackupEligible:  params.BackupEligible,
		BackupState:     params.BackupState,
		Aaguid:          params.Aaguid,
	}

	got := dbToCredential(row)
	if !bytes.Equal(got.ID, original.ID) || !bytes.Equal(got.PublicKey, original.PublicKey) {
		t.Errorf("round trip changed identity: got ID=%x key=%x", got.ID, got.PublicKey)
	}
	if got.Flags != original.Flags {
		t.Errorf("Flags = %+v, want %+v", got.Flags, original.Flags)
	}
	if got.Authenticator.SignCount != original.Authenticator.SignCount {
		t.Errorf("SignCount = %d, want %d", got.Authenticator.SignCount, original.Authenticator.SignCount)
	}
}
