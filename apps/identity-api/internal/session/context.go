package session

import "context"

// contextKey is an unexported type for context keys defined in this package so
// values stored here cannot collide with keys from other packages.
type contextKey int

const sessionContextKey contextKey = iota

// WithSession returns a copy of ctx carrying the authenticated session so
// downstream handlers can read the owning user and session metadata without
// re-reading the cookie or touching the store.
func WithSession(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, s)
}

// FromContext returns the session previously stored by RequireSession and
// true, or the zero Session and false when the request was not
// session-authenticated.
func FromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionContextKey).(Session)
	return s, ok
}
