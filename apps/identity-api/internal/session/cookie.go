package session

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HostPrefix is the strict cookie name prefix mandated by
// docs/architecture.md ("Session Management & Transport Hardening") and
// threat-modeling.md I2. Browsers only honor a __Host- cookie when it is set
// with Secure, Path=/, and no Domain attribute, which pins the cookie to the
// exact origin and blocks subdomain/cross-site injection.
const HostPrefix = "__Host-"

// DefaultCookieName is the production default session cookie name. It carries
// the __Host- prefix so the browser enforces the origin-pinning invariants.
const DefaultCookieName = HostPrefix + "session"

// Cookie-related sentinel errors.
var (
	// ErrInsecureHostPrefix is returned when a cookie name uses the __Host-
	// prefix but Secure is disabled — a combination browsers silently reject,
	// so we fail fast at construction rather than ship a cookie that never
	// authenticates.
	ErrInsecureHostPrefix = errors.New("session: __Host- cookie prefix requires Secure=true")
	// ErrEmptyCookieName is returned when the configured cookie name is empty.
	ErrEmptyCookieName = errors.New("session: cookie name must not be empty")
)

// CookieConfig captures the hardened attributes applied to the session cookie.
// The zero value is not valid; use NewCookieCodec so the __Host-/Secure
// invariant is checked once at startup.
type CookieConfig struct {
	// Name is the cookie name. In production it must carry the __Host- prefix.
	Name string
	// Secure sets the Secure attribute. It must be true whenever Name uses the
	// __Host- prefix. It is only ever disabled for plain-HTTP local
	// development, where the __Host- prefix is dropped as well.
	Secure bool
	// TTL is the max age applied to the cookie. It should match the session's
	// absolute lifetime so the browser discards the cookie no later than the
	// server discards the session.
	TTL time.Duration
}

// CookieCodec writes and clears the session cookie with the strict security
// attributes required by Task 4.1: HttpOnly, Secure, SameSite=Strict, Path=/,
// no Domain, and (in production) the __Host- name prefix.
type CookieCodec struct {
	cfg CookieConfig
}

// NewCookieCodec validates the configuration and returns a codec. It enforces
// the browser rule that a __Host- prefixed cookie is only accepted when Secure
// is set, failing fast so a misconfiguration cannot silently disable session
// authentication.
func NewCookieCodec(cfg CookieConfig) (*CookieCodec, error) {
	if cfg.Name == "" {
		return nil, ErrEmptyCookieName
	}
	if strings.HasPrefix(cfg.Name, HostPrefix) && !cfg.Secure {
		return nil, ErrInsecureHostPrefix
	}
	if cfg.TTL <= 0 {
		return nil, fmt.Errorf("session: cookie TTL must be positive, got %v", cfg.TTL)
	}
	return &CookieCodec{cfg: cfg}, nil
}

// Name reports the configured cookie name.
func (c *CookieCodec) Name() string { return c.cfg.Name }

// Write sets the session cookie carrying the opaque token. Every hardening
// attribute is applied here: HttpOnly blocks script access (mitigating token
// theft via XSS), Secure restricts transmission to HTTPS, SameSite=Strict
// blocks cross-site sends (CSRF/cross-site tracking), Path=/ scopes it to the
// whole origin, and an unset Domain keeps it host-only — together satisfying
// the __Host- prefix contract (docs/architecture.md, threat-modeling.md I2).
func (c *CookieCodec) Write(w http.ResponseWriter, token string) {
	// #nosec G124 -- HttpOnly and SameSite=Strict are set unconditionally;
	// Secure is driven by CookieConfig.Secure, and NewCookieCodec already
	// enforces that a __Host- prefixed cookie can never be constructed with
	// Secure=false. It is only relaxed for a non-prefixed plain-HTTP dev cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     c.cfg.Name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   c.cfg.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(c.cfg.TTL.Seconds()),
		// Domain is intentionally left empty: a host-only cookie is required
		// for the __Host- prefix and prevents the cookie leaking to
		// subdomains.
	})
}

// Clear writes an immediately-expired cookie with the identical attributes so
// the browser drops the session cookie on logout. The attributes must match
// Write (Path, Secure, SameSite, name) or the browser will not overwrite the
// existing cookie.
func (c *CookieCodec) Clear(w http.ResponseWriter) {
	// #nosec G124 -- Mirrors Write: HttpOnly and SameSite=Strict are set
	// unconditionally and Secure is driven by CookieConfig.Secure, which
	// NewCookieCodec has already validated against the __Host- prefix. This
	// call only expires the existing cookie with matching attributes.
	http.SetCookie(w, &http.Cookie{
		Name:     c.cfg.Name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   c.cfg.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// Read extracts the opaque session token from the request cookie. It returns
// http.ErrNoCookie when the cookie is absent.
func (c *CookieCodec) Read(r *http.Request) (string, error) {
	ck, err := r.Cookie(c.cfg.Name)
	if err != nil {
		return "", err
	}
	if ck.Value == "" {
		return "", http.ErrNoCookie
	}
	return ck.Value, nil
}
