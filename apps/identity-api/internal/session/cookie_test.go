package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewCookieCodecRejectsEmptyName(t *testing.T) {
	if _, err := NewCookieCodec(CookieConfig{Name: "", Secure: true, TTL: time.Hour}); err != ErrEmptyCookieName {
		t.Fatalf("NewCookieCodec(empty name) error = %v, want ErrEmptyCookieName", err)
	}
}

func TestNewCookieCodecRejectsInsecureHostPrefix(t *testing.T) {
	_, err := NewCookieCodec(CookieConfig{Name: DefaultCookieName, Secure: false, TTL: time.Hour})
	if err != ErrInsecureHostPrefix {
		t.Fatalf("NewCookieCodec(__Host- without Secure) error = %v, want ErrInsecureHostPrefix", err)
	}
}

func TestNewCookieCodecRejectsNonPositiveTTL(t *testing.T) {
	if _, err := NewCookieCodec(CookieConfig{Name: "session", Secure: false, TTL: 0}); err == nil {
		t.Fatal("NewCookieCodec(TTL=0) succeeded, want error")
	}
}

func TestNewCookieCodecAcceptsHostPrefixWithSecure(t *testing.T) {
	c, err := NewCookieCodec(CookieConfig{Name: DefaultCookieName, Secure: true, TTL: time.Hour})
	if err != nil {
		t.Fatalf("NewCookieCodec(__Host- with Secure): unexpected error: %v", err)
	}
	if c.Name() != DefaultCookieName {
		t.Fatalf("Name() = %q, want %q", c.Name(), DefaultCookieName)
	}
}

func TestNewCookieCodecAcceptsPlainDevCookie(t *testing.T) {
	// A non-prefixed cookie may run insecure for plain-HTTP local dev.
	if _, err := NewCookieCodec(CookieConfig{Name: "session", Secure: false, TTL: time.Hour}); err != nil {
		t.Fatalf("NewCookieCodec(dev cookie): unexpected error: %v", err)
	}
}

func newTestCodec(t *testing.T, name string, secure bool) *CookieCodec {
	t.Helper()
	c, err := NewCookieCodec(CookieConfig{Name: name, Secure: secure, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewCookieCodec: %v", err)
	}
	return c
}

func TestCookieWriteAttributes(t *testing.T) {
	c := newTestCodec(t, DefaultCookieName, true)
	rec := httptest.NewRecorder()
	c.Write(rec, "opaque-token")

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Write emitted %d cookies, want 1", len(cookies))
	}
	ck := cookies[0]
	if ck.Name != DefaultCookieName {
		t.Errorf("cookie name = %q, want %q", ck.Name, DefaultCookieName)
	}
	if ck.Value != "opaque-token" {
		t.Errorf("cookie value = %q, want %q", ck.Value, "opaque-token")
	}
	if ck.Path != "/" {
		t.Errorf("cookie Path = %q, want /", ck.Path)
	}
	if !ck.HttpOnly {
		t.Error("cookie is not HttpOnly")
	}
	if !ck.Secure {
		t.Error("cookie is not Secure")
	}
	if ck.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %v, want Strict", ck.SameSite)
	}
	if ck.Domain != "" {
		t.Errorf("cookie Domain = %q, want empty (host-only for __Host-)", ck.Domain)
	}
	if ck.MaxAge <= 0 {
		t.Errorf("cookie MaxAge = %d, want positive", ck.MaxAge)
	}
}

func TestCookieClearExpires(t *testing.T) {
	c := newTestCodec(t, DefaultCookieName, true)
	rec := httptest.NewRecorder()
	c.Clear(rec)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Clear emitted %d cookies, want 1", len(cookies))
	}
	ck := cookies[0]
	if ck.MaxAge >= 0 {
		t.Errorf("cleared cookie MaxAge = %d, want negative", ck.MaxAge)
	}
	// Attributes must still match Write so the browser overwrites the cookie.
	if ck.Path != "/" || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode {
		t.Errorf("cleared cookie attributes do not match Write: %+v", ck)
	}
}

func TestCookieReadRoundTrip(t *testing.T) {
	c := newTestCodec(t, "session", false)
	rec := httptest.NewRecorder()
	c.Write(rec, "the-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, ck := range rec.Result().Cookies() {
		req.AddCookie(ck)
	}

	got, err := c.Read(req)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != "the-token" {
		t.Fatalf("Read = %q, want %q", got, "the-token")
	}
}

func TestCookieReadMissing(t *testing.T) {
	c := newTestCodec(t, "session", false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := c.Read(req); err != http.ErrNoCookie {
		t.Fatalf("Read(no cookie) error = %v, want http.ErrNoCookie", err)
	}
}

func TestCookieReadEmptyValue(t *testing.T) {
	c := newTestCodec(t, "session", false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// #nosec G124 -- test-only cookie added to a request (not set on a response); transport attributes are irrelevant.
	req.AddCookie(&http.Cookie{Name: "session", Value: ""})
	if _, err := c.Read(req); err != http.ErrNoCookie {

		t.Fatalf("Read(empty value) error = %v, want http.ErrNoCookie", err)
	}
}
