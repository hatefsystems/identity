package username

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

const payloadPurpose = "hatef.identity.username.assignment"
const maxPayloadBytes = 16 * 1024
const maxCiphertextBytes = maxPayloadBytes + 1024

// Cipher is implemented by the existing authenticated envelope encryptor.
type Cipher interface {
	Encrypt(context.Context, []byte) ([]byte, error)
	Decrypt(context.Context, []byte) ([]byte, error)
}

type protectedPayload struct {
	AccountID    uuid.UUID `json:"account_id"`
	Purpose      string    `json:"purpose"`
	Display      string    `json:"display"`
	SecurityName string    `json:"security_name"`
	Authority    Authority `json:"authority"`
}

// Seal requires a real account ID and an admitted, unreserved assignment. An
// authenticated internal account/purpose binding protects ciphertext swaps.
func (n *Normalizer) Seal(ctx context.Context, cipher Cipher, accountID uuid.UUID, v Value) ([]byte, error) {
	if cipher == nil || accountID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if err := n.Validate(v); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(protectedPayload{accountID, payloadPurpose, v.display, v.security, v.authority})
	if err != nil || len(plain) > maxPayloadBytes {
		return nil, ErrInvalidPayload
	}
	sealed, err := cipher.Encrypt(ctx, plain)
	if err != nil || len(sealed) == 0 || len(sealed) > maxCiphertextBytes {
		return nil, ErrInvalidPayload
	}
	return sealed, nil
}

// Open checks account/purpose/policy/key bindings and reconstructs the exact key.
// Current admission/reserved policy is not retroactively imposed on a read.
func (n *Normalizer) Open(ctx context.Context, cipher Cipher, accountID uuid.UUID, blob []byte) (Value, error) {
	if n == nil || cipher == nil || accountID == uuid.Nil || len(blob) == 0 || len(blob) > maxCiphertextBytes {
		return Value{}, ErrInvalidPayload
	}
	plain, err := cipher.Decrypt(ctx, blob)
	if err != nil {
		return Value{}, ErrInvalidPayload
	}
	var payload protectedPayload
	if strictJSON(plain, &payload, maxPayloadBytes) != nil || payload.AccountID != accountID || payload.Purpose != payloadPurpose || payload.Authority != n.authority {
		return Value{}, ErrInvalidPayload
	}
	v, err := n.NormalizeLookup(payload.Display)
	if err != nil || v.display != payload.Display || v.security != payload.SecurityName {
		return Value{}, ErrInvalidPayload
	}
	return v, nil
}
