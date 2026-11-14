package username

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
)

func TestUsernameAuthenticatedPayloadBindings(t *testing.T) {
	n := fixtureNormalizer(t)
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x92}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	account := uuid.New()
	v, _ := n.Normalize("\u0643.\u0624")
	blob, err := n.Seal(t.Context(), cipher, account, v)
	if err != nil {
		t.Fatal(err)
	}
	got, err := n.Open(t.Context(), cipher, account, blob)
	if err != nil || got != v {
		t.Fatal("protected value did not round trip")
	}
	second, _ := n.Seal(t.Context(), cipher, account, v)
	if bytes.Equal(blob, second) {
		t.Fatal("encryption not randomized")
	}
	if _, err := n.Open(t.Context(), cipher, uuid.New(), blob); err != ErrInvalidPayload {
		t.Fatal("wrong-account substitution accepted")
	}
	blob[len(blob)-1] ^= 1
	if _, err := n.Open(t.Context(), cipher, account, blob); err != ErrInvalidPayload {
		t.Fatal("unauthenticated bytes accepted")
	}
	for _, change := range []func(*protectedPayload){
		func(p *protectedPayload) { p.Purpose = "profile" },
		func(p *protectedPayload) { p.AccountID = uuid.New() },
		func(p *protectedPayload) { p.Authority.PolicyID = uuid.New() },
		func(p *protectedPayload) { p.Authority.Fingerprint[0]++ },
		func(p *protectedPayload) { p.Authority.KeyID = "other" },
		func(p *protectedPayload) { p.Authority.KeyVerifier[0]++ },
		func(p *protectedPayload) { p.SecurityName = p.Display },
		func(p *protectedPayload) { p.Display = "\u0643.\u0648\u0654" },
	} {
		p := protectedPayload{account, payloadPurpose, v.Display(), v.SecurityName(), v.Authority()}
		change(&p)
		plain, _ := json.Marshal(p)
		sealed, _ := cipher.Encrypt(t.Context(), plain)
		if _, err := n.Open(t.Context(), cipher, account, sealed); err != ErrInvalidPayload {
			t.Fatal("invalid protected binding accepted")
		}
	}
	if _, err := n.Seal(t.Context(), cipher, uuid.Nil, v); err != ErrInvalidPayload {
		t.Fatal("missing account accepted")
	}
	if _, err := n.Seal(t.Context(), cipher, account, Value{}); err == nil {
		t.Fatal("zero value sealed")
	}
	if _, err := n.Open(t.Context(), cipher, account, bytes.Repeat([]byte{1}, maxCiphertextBytes+1)); err != ErrInvalidPayload {
		t.Fatal("unbounded ciphertext accepted")
	}
	// A re-sealed historical value may no longer match new-assignment syntax.
	narrow, err := New(fixturePolicy(), `\x{0633}{3}`, bytes.Repeat([]byte{0x59}, 32), "username-test-1")
	if err != nil {
		t.Fatal(err)
	}
	historical, err := narrow.NormalizeLookup("\u0633")
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(protectedPayload{account, payloadPurpose, historical.Display(), historical.SecurityName(), historical.Authority()})
	sealed, _ := cipher.Encrypt(t.Context(), plain)
	if got, err := narrow.Open(t.Context(), cipher, account, sealed); err != nil || got != historical {
		t.Fatal("read retroactively imposed assignment regex")
	}
}
