package stepup

import "context"

// contextKey is an unexported type for context keys defined in this package so
// values stored here cannot collide with keys from other packages.
type contextKey int

const grantContextKey contextKey = iota

// WithGrant returns a copy of ctx carrying the validated step-up grant so
// downstream handlers — and the audit pipeline in Task 5.2 — can record which
// factor authorised the sensitive operation without re-parsing the header.
func WithGrant(ctx context.Context, g *Grant) context.Context {
	return context.WithValue(ctx, grantContextKey, g)
}

// GrantFromContext returns the grant previously stored by RequireStepUp and
// true, or nil and false when the request was not step-up authorised.
func GrantFromContext(ctx context.Context) (*Grant, bool) {
	g, ok := ctx.Value(grantContextKey).(*Grant)
	return g, ok && g != nil
}
