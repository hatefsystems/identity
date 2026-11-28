package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/geography"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

const privateGiven = "\u0639\u0644\u06cc"
const privateFamily = "\u0645\u0624\u0645\u0646\u06cc"

func privateCipher(t *testing.T) *envelope.Encryptor {
	t.Helper()
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x54}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func privateDataFixture(t *testing.T) PrivateData {
	t.Helper()
	birthday, err := NormalizeBirthday("gregorian", "2000-03-20", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return PrivateData{GivenName: privateGiven, FamilyName: privateFamily, Birthday: PrivateBirthday(birthday), Gender: GenderFemale,
		Location: geography.ValidatedLocation{LocationInput: geography.LocationInput{Country: "IR", ProvinceID: "7001", LocalityID: "7002"}, CatalogRevision: "1"}}
}

func TestPrivateEnvelopeBindingsAndStrictPayload(t *testing.T) {
	svc := &PrivateService{cipher: privateCipher(t)}
	id, data := uuid.New(), privateDataFixture(t)
	const revision = int64(9007199254740993)
	blob, err := svc.seal(t.Context(), id, revision, data)
	if err != nil || bytes.Contains(blob, []byte(privateGiven)) {
		t.Fatal("private attributes not protected")
	}
	opened, err := svc.open(t.Context(), id, revision, blob)
	if err != nil || *opened != data {
		t.Fatal("private profile did not round trip")
	}
	if _, err := svc.open(t.Context(), uuid.New(), revision, blob); !errors.Is(err, ErrUnreadable) {
		t.Fatal("cross-account substitution accepted")
	}
	if _, err := svc.open(t.Context(), id, revision+1, blob); !errors.Is(err, ErrUnreadable) {
		t.Fatal("same-account revision substitution accepted")
	}
	corrupt := bytes.Clone(blob)
	corrupt[len(corrupt)-1] ^= 1
	for _, bad := range [][]byte{nil, {}, corrupt, bytes.Repeat([]byte{1}, 16385)} {
		if _, err := svc.open(t.Context(), id, revision, bad); !errors.Is(err, ErrUnreadable) {
			t.Fatal("unreadable protected data reported as absent")
		}
	}
	for _, mode := range []string{"purpose", "uppercase account", "birthday pair", "name", "gender", "catalog revision", "missing write revision", "unknown", "duplicate", "null"} {
		t.Run(mode, func(t *testing.T) {
			payload := privatePayload{id.String(), privatePurpose, "9007199254740993", data}
			switch mode {
			case "purpose":
				payload.Purpose = "hatef.identity.username.assignment"
			case "uppercase account":
				payload.AccountID = strings.ToUpper(id.String())
			case "birthday pair":
				payload.Data.Birthday.Jalali = "1380-01-01"
			case "name":
				payload.Data.GivenName = " Private "
			case "gender":
				payload.Data.Gender = "other"
			case "catalog revision":
				payload.Data.Location.CatalogRevision = "01"
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing write revision":
				raw = bytes.Replace(raw, []byte(`"revision":"9007199254740993",`), nil, 1)
			case "unknown":
				raw = bytes.Replace(raw, []byte(`"purpose":`), []byte(`"email":"private@invalid","purpose":`), 1)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"purpose":`), []byte(`"purpose":"duplicate","purpose":`), 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"gender":"female"`), []byte(`"gender":null`), 1)
			}
			forged, err := svc.cipher.Encrypt(t.Context(), raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.open(t.Context(), id, revision, forged); !errors.Is(err, ErrUnreadable) {
				t.Fatal("authenticated but invalid private payload accepted")
			}
		})
	}
}

func TestPrivateStrictUpdateContract(t *testing.T) {
	for _, raw := range []string{
		`{"expected_revision":"0"}`, `{"expected_revision":0,"gender":"male"}`, `{"expected_revision":"01","gender":"male"}`,
		`{"expected_revision":"9223372036854775808","gender":"male"}`, `{"expected_revision":"0","gender":null}`,
		`{"expected_revision":"0","Gender":"male"}`, `{"expected_revision":"0","gender":"male","gender":"female"}`,
		`{"expected_revision":"0","gender":"male","username":"forged"}`, `{"expected_revision":"0","email":"mail@invalid"}`,
		`{"expected_revision":"0","mobile":"123"}`, `{"expected_revision":"0","display_name":"public"}`,
		`{"expected_revision":"0","birthday":{"calendar":"gregorian","date":"2000-03-20","date":"2001-01-01"}}`,
		`{"expected_revision":"0","birthday":{"gregorian":"2000-03-20","jalali":"1379-01-01"}}`,
		`{"expected_revision":"0","location":{"country":"IR","province_id":"7001","catalog_revision":"1"}}`,
		`{"expected_revision":"0","location":{"country":"IR","province_id":null}}`,
		`{"expected_revision":"0","given_name":"\ud800"}`, `{"expected_revision":"0","given_name":"\udc00"}`,
		`{"expected_revision":"0","gender":"male"} {}`, `[]`, `null`,
	} {
		if _, err := DecodePrivateUpdate([]byte(raw)); err == nil {
			t.Fatalf("private endpoint accepted invalid structure: %s", raw)
		}
	}
	for _, raw := range []string{`{"expected_revision":"9007199254740993","gender":"male"}`, `{"expected_revision":"0","location":{"country":"IR","province_id":"7001"}}`} {
		if _, err := DecodePrivateUpdate([]byte(raw)); err != nil {
			t.Fatal("valid private partial input rejected")
		}
	}
}

type privateLocationFixture struct {
	calls int
	err   error
}

func (f *privateLocationFixture) ValidateForUpdate(_ context.Context, _ pgx.Tx, in geography.LocationInput) (geography.ValidatedLocation, error) {
	f.calls++
	return geography.ValidatedLocation{LocationInput: in, CatalogRevision: "1"}, f.err
}

func TestPrivateFirstWholeFieldsAndNormalizedMerge(t *testing.T) {
	data := privateDataFixture(t)
	location := &privateLocationFixture{}
	svc := &PrivateService{location: location}
	gender := "male"
	if _, err := svc.merge(t.Context(), nil, nil, PrivateUpdate{Gender: &gender}); !errors.Is(err, ErrInvalidPrivateData) {
		t.Fatal("incomplete first save accepted")
	}
	name := "  \u0639\u0644\u064a  "
	merged, err := svc.merge(t.Context(), nil, &data, PrivateUpdate{GivenName: &name, Birthday: &BirthdayInput{Calendar: "jalali", Date: data.Birthday.Jalali}, Location: &data.Location.LocationInput})
	if err != nil || merged != data || location.calls != 0 {
		t.Fatal("equivalent private merge revalidated catalog or changed data")
	}
	for _, birthday := range []BirthdayInput{{Date: "2000-03-20"}, {Calendar: "gregorian"}, {Calendar: "gregorian", Date: "2000-02-30"}} {
		if _, err := svc.merge(t.Context(), nil, &data, PrivateUpdate{Birthday: &birthday}); !errors.Is(err, ErrInvalidBirthday) {
			t.Fatal("partial/invalid birthday accepted")
		}
	}
	for _, in := range []geography.LocationInput{{Country: "IR"}, {ProvinceID: "7001"}} {
		location.err = geography.ErrInvalid
		if _, err := svc.merge(t.Context(), nil, &data, PrivateUpdate{Location: &in}); !errors.Is(err, ErrInvalidPrivateData) {
			t.Fatal("partial location accepted")
		}
	}
}

type privateAuthorityFixture struct {
	live session.Session
	err  error
}

func (f privateAuthorityFixture) LookupByID(context.Context, string, string) (session.Session, error) {
	return f.live, f.err
}

func TestPrivateSessionRecheckIndividualAuthority(t *testing.T) {
	captured := session.Session{ID: uuid.NewString(), UserID: uuid.NewString(), Kind: session.KindAuthenticated, AuthVersionSet: true, AuthVersion: 7, DPoPJKT: "key", AbsoluteExpiry: time.Now().Add(time.Hour), IdleExpiry: time.Now().Add(time.Minute)}
	for _, mode := range []string{"valid", "revoked", "expired", "idle expired", "foreign", "kind", "version", "proof", "infrastructure"} {
		live, want := captured, ErrUnauthorized
		var cause error
		switch mode {
		case "valid":
			want = nil
		case "revoked":
			cause = session.ErrSessionNotFound
		case "expired":
			live.AbsoluteExpiry = time.Now().Add(-time.Second)
		case "idle expired":
			live.IdleExpiry = time.Now().Add(-time.Second)
		case "foreign":
			live.ID = uuid.NewString()
		case "kind":
			live.Kind = session.KindRecoveryEnrollment
		case "version":
			live.AuthVersion++
		case "proof":
			live.DPoPJKT = "other"
		case "infrastructure":
			cause, want = session.ErrStoreUnavailable, ErrUnavailable
		}
		svc := &PrivateService{sessions: privateAuthorityFixture{live, cause}}
		if err := svc.recheck(t.Context(), captured); !errors.Is(err, want) {
			t.Fatalf("private session recheck %s: %v", mode, err)
		}
	}
	if _, err := privateSubject(session.Session{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("missing private subject accepted")
	}
}
