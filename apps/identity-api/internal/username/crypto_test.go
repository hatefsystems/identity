package username

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"testing/quick"

	"github.com/google/uuid"
)

func TestUsernameExactHMACDomainsAndMetadataIndependentEquality(t *testing.T) {
	key := bytes.Repeat([]byte{0x59}, 32)
	n := fixtureNormalizer(t)
	v, err := n.Normalize("\u0643.\u0626")
	if err != nil {
		t.Fatal(err)
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("hatef.identity.username.lookup\x00\u06a9.\u06cc"))
	digest := v.Key()
	if !hmac.Equal(digest[:], h.Sum(nil)) {
		t.Fatal("lookup is not exact-byte domain-separated HMAC")
	}
	for _, message := range []string{v.SecurityName(), "hatef.identity.username.lookup" + v.SecurityName(), "hatef.identity.username.lookup\x00" + v.SecurityName() + "\x00", "hatef.identity.username.key-verifier\x00"} {
		h.Reset()
		_, _ = h.Write([]byte(message))
		if hmac.Equal(digest[:], h.Sum(nil)) {
			t.Fatal("unexpected domain or byte equivalence")
		}
	}
	p := fixturePolicy()
	p.ID = uuid.New()
	other, err := New(p, fixtureRegex, key, "different-key-label")
	if err != nil {
		t.Fatal(err)
	}
	otherValue, _ := other.Normalize(v.Display())
	if otherValue.Key() != v.Key() || other.Authority().KeyVerifier != n.Authority().KeyVerifier || other.Authority().Fingerprint == n.Authority().Fingerprint {
		t.Fatal("metadata changed the uniqueness namespace")
	}
	if n.Validate(otherValue) != ErrPolicyMismatch {
		t.Fatal("stale policy value admitted")
	}
	key[0]++
	wrongKey, _ := New(fixturePolicy(), fixtureRegex, key, n.Authority().KeyID)
	wrongValue, _ := wrongKey.Normalize(v.Display())
	if wrongKey.Authority().KeyVerifier == n.Authority().KeyVerifier || wrongValue.Key() == v.Key() || wrongKey.Authority().Fingerprint != n.Authority().Fingerprint {
		t.Fatal("same key ID concealed changed secret")
	}
}

func TestUsernameKeyAndIDHaveNoDefaults(t *testing.T) {
	for _, key := range [][]byte{nil, bytes.Repeat([]byte{1}, 31)} {
		if _, err := New(fixturePolicy(), fixtureRegex, key, "test"); err == nil {
			t.Fatal("missing/short key admitted")
		}
	}
	for _, id := range []string{"", " key", "key ", "key\n", "\u0633", string(bytes.Repeat([]byte{'a'}, 129))} {
		if _, err := New(fixturePolicy(), fixtureRegex, bytes.Repeat([]byte{1}, 32), id); err == nil {
			t.Fatal("invalid key ID admitted")
		}
	}
	if _, err := New(fixturePolicy(), fixtureRegex, bytes.Repeat([]byte{1}, 64), "long-key"); err != nil {
		t.Fatal("at-least-32-byte key wrongly fixed at 32")
	}
}

func TestUsernameExactCryptoProperties(t *testing.T) {
	alphabet := []rune(supportedScalars)
	property := func(material []byte, indices []uint8) bool {
		key := sha256.Sum256(material)
		p := fixturePolicy()
		n, err := New(p, fixtureRegex, key[:], "property-key")
		if err != nil {
			return false
		}
		input := "\u0643"
		for _, index := range indices {
			input += string(alphabet[int(index)%(len(alphabet)-1)])
		}
		v, err := n.Normalize(input)
		if err != nil {
			return false
		}
		h := hmac.New(sha256.New, key[:])
		_, _ = h.Write(append([]byte("hatef.identity.username.lookup\x00"), []byte(v.SecurityName())...))
		digest := v.Key()
		if !hmac.Equal(digest[:], h.Sum(nil)) {
			return false
		}
		p.ID = uuid.New()
		other, err := New(p, fixtureRegex, key[:], "changed-label")
		if err != nil {
			return false
		}
		equivalent, err := other.Normalize(v.SecurityName())
		if err != nil || equivalent.Key() != digest || other.Authority().KeyVerifier != n.Authority().KeyVerifier {
			return false
		}
		key[0] ^= 1
		different, err := New(fixturePolicy(), fixtureRegex, key[:], "property-key")
		return err == nil && different.Authority().KeyVerifier != n.Authority().KeyVerifier && different.Authority().Fingerprint == n.Authority().Fingerprint
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
