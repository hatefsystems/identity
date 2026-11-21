package accountpolicy

import (
	"errors"
	"testing"
)

func TestResultingPrimaryAndPrivilegedProtection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state State
		want  error
	}{
		{"last primary", State{}, ErrLastCredential},
		{"TOTP is not primary", State{TOTP: true}, ErrLastCredential},
		{"password survives", State{Password: true}, nil},
		{"passkey survives", State{Passkeys: 1}, nil},
		{"privileged password alone", State{Password: true, Privileged: true}, ErrLastFactor},
		{"privileged password TOTP", State{Password: true, TOTP: true, Privileged: true}, nil},
		{"privileged passkey", State{Passkeys: 1, Privileged: true}, nil},
		{"privileged TOTP only", State{TOTP: true, Privileged: true}, ErrLastCredential},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.state.Check(); !errors.Is(err, tc.want) {
				t.Fatalf("resulting protection: got %v, want %v", err, tc.want)
			}
		})
	}
}
