package contactproof

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
)

func proofCipher(t *testing.T) Cipher {
	t.Helper()
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{7}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func TestEvidenceExactBindingAndOriginalTime(t *testing.T) {
	cipher, id := proofCipher(t), uuid.New()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	for _, tc := range []struct{ channel, destination, method string }{
		{Email, "person@example.test", EmailLink}, {Email, "person@example.test", EmailOTP}, {Phone, "+989123456789", SMSOTP},
	} {
		blob, err := Seal(t.Context(), cipher, id, tc.channel, tc.destination, tc.method, at)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(blob, []byte(tc.destination)) {
			t.Fatal("destination persisted unprotected")
		}
		evidence, err := Open(t.Context(), cipher, blob, id, tc.channel, tc.destination)
		if err != nil || evidence == nil || evidence.Method != tc.method || !evidence.VerifiedAt.Equal(at) {
			t.Fatal("original proof time/method lost", err)
		}
		for _, mismatch := range []struct {
			id                   uuid.UUID
			channel, destination string
		}{
			{uuid.New(), tc.channel, tc.destination}, {id, "other", tc.destination}, {id, tc.channel, "other@example.test"},
		} {
			if e, err := Open(t.Context(), cipher, blob, mismatch.id, mismatch.channel, mismatch.destination); e != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("substituted proof accepted")
			}
		}
		blob[len(blob)-1] ^= 1
		if e, err := Open(t.Context(), cipher, blob, id, tc.channel, tc.destination); e != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("tampered envelope accepted")
		}
	}
}

func TestEvidenceAbsentUnreadableAndCrossPurpose(t *testing.T) {
	cipher, id := proofCipher(t), uuid.New()
	if e, err := Open(t.Context(), cipher, nil, id, Email, "person@example.test"); e != nil || err != nil {
		t.Fatal("absence is not a normal unverified state")
	}
	if e, err := Open(t.Context(), cipher, make([]byte, 90), id, Email, "person@example.test"); e != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("unreadable evidence confused with absence")
	}
	plain, err := json.Marshal(Evidence{"private_profile", id, Email, "person@example.test", EmailLink, time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := cipher.Encrypt(t.Context(), plain)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	if e, err := Open(t.Context(), cipher, blob, id, Email, "person@example.test"); e != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("cross-purpose evidence accepted")
	}
}

func TestEmailOTPMethodCannotBeRelabeledOrUsedForPhone(t *testing.T) {
	cipher, id := proofCipher(t), uuid.New()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	for _, tc := range []struct{ channel, destination, method string }{
		{Phone, "+989123456789", EmailOTP}, {Email, "owner@example.test", SMSOTP}, {Email, "owner@example.test", "otp"},
	} {
		if _, err := Seal(t.Context(), cipher, id, tc.channel, tc.destination, tc.method, at); err != ErrInvalid {
			t.Fatal("untruthful channel/method evidence admitted", err)
		}
	}
	blob, err := Seal(t.Context(), cipher, id, Email, "owner@example.test", EmailOTP, at)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		e, err := Open(t.Context(), cipher, blob, id, Email, "owner@example.test")
		if err != nil || e == nil || e.Method != EmailOTP || !e.VerifiedAt.Equal(at) {
			t.Fatal("durable evidence read renewed time or fabricated link method", err)
		}
	}
}
