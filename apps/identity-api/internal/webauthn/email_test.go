package webauthn

import (
	"bytes"
	"errors"
	"testing"
)

func TestNamedLoginCanonicalEmailMatchesRealAndDecoyIdentities(t *testing.T) {
	for _, real := range []bool{false, true} {
		t.Run(map[bool]string{false: "decoy", true: "real"}[real], func(t *testing.T) {
			f := newFixture(t)
			canonical := "\u00fcser@example.test"
			if real {
				f.users.mu.Lock()
				delete(f.users.byEmail, f.user.Email)
				f.user.Email = canonical
				f.users.byID[f.user.ID] = f.user
				f.users.byEmail[canonical] = f.user.ID
				f.users.mu.Unlock()
				f.register(t, f.auth)
			}
			var first []byte
			for _, input := range []string{canonical, " U\u0308SER@EXAMPLE.TEST "} {
				options, err := f.svc.BeginLogin(f.ctx(), input)
				if err != nil || len(options.Response.AllowedCredentials) != 1 {
					t.Fatalf("canonical named login failed: %v", err)
				}
				id := options.Response.AllowedCredentials[0].CredentialID
				if first != nil && !bytes.Equal(first, id) {
					t.Fatal("canonical equivalents selected different credentials")
				}
				if real && !bytes.Equal(id, f.auth.credID) {
					t.Fatal("canonical real identity was replaced with a decoy")
				}
				first = append([]byte(nil), id...)
			}
		})
	}
}

func TestNamedLoginInvalidEmailDoesNotAllocateADecoy(t *testing.T) {
	f := newFixture(t)
	for _, email := range []string{"a\u200cb@example.test", "a\ufffdb@example.test", "a..b@example.test", "\xff@example.test"} {
		if _, err := f.svc.BeginLogin(f.ctx(), email); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("invalid identity accepted: %v", err)
		}
	}
}
