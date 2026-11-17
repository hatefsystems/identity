package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/geography"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
)

// GeographyReader leaves snapshot consistency and domain bounds in geography.
type GeographyReader interface {
	Provinces(context.Context, geography.ListInput) (geography.Page, error)
	Localities(context.Context, geography.ListInput) (geography.Page, error)
	Lookup(context.Context, string, string) (geography.Place, error)
}

func (s *Server) registerGeographyRoutes() {
	s.router.With(s.geographyAdmission).Get("/api/v1/geography/provinces", s.handleGeographyList(false))
	s.router.With(s.geographyAdmission).Get("/api/v1/geography/localities", s.handleGeographyList(true))
	s.router.With(s.geographyAdmission).Get("/api/v1/geography/places/{id}", s.handleGeographyLookup())
}

// All three reads, including invalid requests, share both anonymous budgets.
// Missing Redis never falls back to development-only memory authority.
func (s *Server) geographyAdmission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.deps.Geography == nil || s.deps.GeographyLimiter == nil || s.cfg.Geography.Validate() != nil {
			writeGeographyError(w, geography.ErrUnavailable)
			return
		}
		ip := clientip.FromRequest(r)
		if ip == "" {
			writeGeographyError(w, geography.ErrUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Geography.LimiterTimeout)
		defer cancel()
		for _, bucket := range []struct {
			dimension string
			value     string
			limit     int
		}{
			{"ip", ip, s.cfg.Geography.PerIPPerMinute},
			{"subnet", ratelimit.Subnet(ip), s.cfg.Geography.PerSubnetPerMinute},
		} {
			digest := sha256.Sum256([]byte(bucket.value))
			allowed, err := s.deps.GeographyLimiter.Allow(ctx, "rate:geography:"+bucket.dimension+":v1:"+hex.EncodeToString(digest[:]), bucket.limit, time.Minute)
			if err != nil || ctx.Err() != nil {
				writeGeographyError(w, geography.ErrUnavailable)
				return
			}
			if !allowed {
				w.Header().Set("Retry-After", "60")
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleGeographyList(localities bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed := []string{"country", "q", "limit", "cursor"}
		if localities {
			allowed = append(allowed, "province_id")
		}
		values, err := geographyQuery(r, allowed)
		if err != nil {
			writeGeographyError(w, err)
			return
		}
		input := geography.ListInput{
			Country: values.Get("country"), ProvinceID: values.Get("province_id"),
			Query: values.Get("q"), Cursor: values.Get("cursor"), Limit: s.cfg.Geography.PageSizeDefault,
		}
		if localities && !geographyDecimalID(input.ProvinceID) || len(input.Query) > 256 || utf8.RuneCountInString(input.Query) > 80 || len(input.Cursor) > 2048 {
			writeGeographyError(w, geography.ErrInvalid)
			return
		}
		if raw, present := values["limit"]; present {
			if !geographyDecimalID(raw[0]) {
				writeGeographyError(w, geography.ErrInvalid)
				return
			}
			limit, _ := strconv.ParseInt(raw[0], 10, 64)
			if limit > int64(s.cfg.Geography.PageSizeMax) {
				writeGeographyError(w, geography.ErrInvalid)
				return
			}
			input.Limit = int(limit)
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Geography.QueryTimeout)
		defer cancel()
		var page geography.Page
		if localities {
			page, err = s.deps.Geography.Localities(ctx, input)
		} else {
			page, err = s.deps.Geography.Provinces(ctx, input)
		}
		if ctx.Err() != nil {
			err = geography.ErrUnavailable
		}
		if err != nil {
			writeGeographyError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, page)
	}
}

func (s *Server) handleGeographyLookup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		values, err := geographyQuery(r, []string{"country", "revision"})
		id, revision := chi.URLParam(r, "id"), values.Get("revision")
		_, hasRevision := values["revision"]
		if err != nil || !geographyDecimalID(id) || hasRevision && !geographyDecimalID(revision) {
			writeGeographyError(w, geography.ErrInvalid)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Geography.QueryTimeout)
		defer cancel()
		place, err := s.deps.Geography.Lookup(ctx, id, revision)
		if ctx.Err() != nil {
			err = geography.ErrUnavailable
		}
		if err != nil {
			writeGeographyError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, place)
	}
}

func geographyQuery(r *http.Request, allowed []string) (url.Values, error) {
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 || len(r.URL.RawQuery) > 8*1024 {
		return nil, geography.ErrInvalid
	}
	// ParseQuery otherwise accepts empty segments and bare keys, or returns a
	// usable partial map alongside malformed escapes. None are valid admission.
	for _, part := range strings.Split(r.URL.RawQuery, "&") {
		if part == "" || !strings.Contains(part, "=") {
			return nil, geography.ErrInvalid
		}
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || values.Get("country") != "IR" {
		return nil, geography.ErrInvalid
	}
	for key, value := range values {
		known := false
		for _, name := range allowed {
			known = known || key == name
		}
		if !known || len(value) != 1 || !utf8.ValidString(value[0]) || strings.ContainsFunc(value[0], unicode.IsControl) {
			return nil, geography.ErrInvalid
		}
	}
	return values, nil
}

// Never round source identities through floats or admit alternate decimal forms.
func geographyDecimalID(raw string) bool {
	if len(raw) == 0 || len(raw) > 19 || raw[0] < '1' || raw[0] > '9' {
		return false
	}
	for i := 1; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
	}
	_, err := strconv.ParseInt(raw, 10, 64)
	return err == nil
}

func writeGeographyError(w http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "temporarily_unavailable"
	switch {
	case errors.Is(err, geography.ErrInvalid):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, geography.ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, geography.ErrCatalogChanged):
		status, code = http.StatusConflict, "catalog_changed"
	}
	writeJSON(w, status, map[string]string{"error": code})
}
