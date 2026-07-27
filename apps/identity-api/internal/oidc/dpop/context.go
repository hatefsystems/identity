package dpop

import "context"

// contextKey is an unexported type for context keys defined in this package so
// values stored here cannot collide with keys from other packages.
type contextKey int

const proofContextKey contextKey = iota

// WithProof returns a copy of ctx carrying the validated DPoP proof so
// downstream handlers can read the confirmation thumbprint (cnf.jkt) and bind
// or check issued tokens against it.
func WithProof(ctx context.Context, proof *Proof) context.Context {
	return context.WithValue(ctx, proofContextKey, proof)
}

// ProofFromContext returns the validated DPoP proof previously stored by the
// middleware, or nil when the request was not DPoP-bound.
func ProofFromContext(ctx context.Context) *Proof {
	proof, _ := ctx.Value(proofContextKey).(*Proof)
	return proof
}
