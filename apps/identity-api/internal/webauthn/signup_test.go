package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/google/uuid"
)

func TestSignupCeremonyIsResidentUVAndNeverPersistsAccount(t *testing.T) {
	f := newFixture(t)
	handle := bytes.Repeat([]byte{7}, 8)
	options, ceremony, err := f.svc.BeginSignup(f.ctx(), "passkey@example.com", handle, testBrowserJKT, f.clock.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	rawHandle, _ := json.Marshal(options.Response.User.ID)
	var encodedHandle string
	_ = json.Unmarshal(rawHandle, &encodedHandle)
	wireHandle, _ := base64.RawURLEncoding.DecodeString(encodedHandle)
	if options.Response.AuthenticatorSelection.ResidentKey != protocol.ResidentKeyRequirementRequired || options.Response.AuthenticatorSelection.UserVerification != protocol.VerificationRequired || !bytes.Equal(wireHandle, handle) || f.users.setHandleCalls != 0 {
		t.Fatal("signup weakened resident/UV or wrote account")
	}
	credential, err := f.svc.VerifySignup(f.ctx(), "passkey@example.com", handle, testBrowserJKT, ceremony, f.auth.attestation(challengeOf(options.Response.Challenge)))
	if err != nil || credential.UserID != uuid.Nil || !credential.UserVerified || !credential.UserPresent {
		t.Fatalf("verified signup credential: %v", err)
	}
	if len(f.creds.byUser[f.user.ID]) != 0 || f.users.setHandleCalls != 0 {
		t.Fatal("crypto-only signup persisted")
	}
	// Mapping the verified public key into ordinary account stores permits fresh
	// discoverable login; signup itself never claims authenticated authority.
	u := f.user
	u.WebauthnUserHandle = handle
	f.users.byID[u.ID] = u
	credential.UserID = u.ID
	if _, err := f.creds.CreateWebauthnCredential(f.ctx(), credential); err != nil {
		t.Fatal(err)
	}
	f.auth.signCount++
	if id, err := f.discoverableLogin(t, f.auth, handle); err != nil || id != u.ID {
		t.Fatalf("fresh discoverable login: %v", err)
	}
}
func TestSignupCeremonyRejectsWrongFrozenBindingAndCrypto(t *testing.T) {
	for _, kind := range []string{"jkt", "purpose", "handle", "email", "expiry", "origin", "rp", "uv"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			handle := bytes.Repeat([]byte{7}, 8)
			email := "passkey@example.com"
			jkt := testBrowserJKT
			options, ceremony, err := f.svc.BeginSignup(f.ctx(), email, handle, jkt, f.clock.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "jkt":
				jkt = "other"
			case "purpose":
				var c signupCeremony
				_ = json.Unmarshal(ceremony, &c)
				c.Purpose = "login"
				ceremony, _ = json.Marshal(c)
			case "handle":
				handle[0]++
			case "email":
				email = "other@example.com"
			case "expiry":
				f.advance(time.Minute)
			case "origin":
				f.auth.origin = "https://attacker.example.com"
			case "rp":
				f.auth.rpID = "attacker.example.com"
			}
			body := f.auth.attestation(challengeOf(options.Response.Challenge))
			if kind == "uv" {
				var response protocol.CredentialCreationResponse
				_ = json.Unmarshal(body, &response)
				var object map[string]any
				_ = webauthncbor.Unmarshal(response.AttestationResponse.AttestationObject, &object)
				authData := object["authData"].([]byte)
				authData[32] &= ^byte(flagUserVerified)
				object["authData"] = authData
				response.AttestationResponse.AttestationObject, _ = webauthncbor.Marshal(object)
				body, _ = json.Marshal(response)
			}
			if _, err := f.svc.VerifySignup(f.ctx(), email, handle, jkt, ceremony, body); err == nil {
				t.Fatal("invalid signup verified")
			}
		})
	}
	f := newFixture(t)
	if _, _, err := f.svc.BeginSignup(f.ctx(), "passkey@example.com", make([]byte, 7), testBrowserJKT, f.clock.Add(time.Minute)); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("caller handle accepted")
	}
}
