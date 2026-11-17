package geography

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type unavailableDB struct {
	called   int
	options  pgx.TxOptions
	deadline time.Time
}

func (d *unavailableDB) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	d.called++
	d.options = opts
	d.deadline, _ = ctx.Deadline()
	return nil, errors.New("private database diagnostic")
}
func TestServiceAdmissionAndAvailability(t *testing.T) {
	database := &unavailableDB{}
	svc := New(database)
	for _, in := range []ListInput{{Country: "XX"}, {Country: "IR", Limit: 51}, {Country: "IR", Limit: -1}, {Country: "IR", Query: "\x00"}, {Country: "IR", Query: strings.Repeat("x", 81)}, {Country: "IR", Query: strings.Repeat("\U0001f600", 65)}, {Country: "IR", Cursor: strings.Repeat("x", 2049)}, {Country: "IR", ProvinceID: "1"}} {
		if _, err := svc.Provinces(t.Context(), in); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad list admitted", err)
		}
	}
	for _, id := range []string{"", "0", "01", "-1", "1.0", "1e0", "9223372036854775808"} {
		if _, err := svc.Lookup(t.Context(), id, ""); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad ID admitted", err)
		}
		if _, err := svc.Localities(t.Context(), ListInput{Country: "IR", ProvinceID: id}); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad province admitted", err)
		}
		if _, err := svc.Validate(t.Context(), LocationInput{Country: "IR", ProvinceID: id}); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad validator admitted", err)
		}
	}
	if database.called != 0 {
		t.Fatal("invalid input reached database")
	}
	started := time.Now()
	if _, err := svc.Provinces(t.Context(), ListInput{Country: "IR"}); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private") {
		t.Fatal("availability classification", err)
	}
	if database.options.IsoLevel != pgx.RepeatableRead || database.options.AccessMode != pgx.ReadOnly || database.deadline.IsZero() || time.Until(database.deadline) > time.Second || database.deadline.Before(started) {
		t.Fatal("read snapshot/deadline not bounded")
	}
	if _, err := New(nil).Lookup(t.Context(), "1", ""); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
func TestCursorAdmissionAndBinding(t *testing.T) {
	encode := func(c cursor) string { raw, _ := json.Marshal(c); return base64.RawURLEncoding.EncodeToString(raw) }
	valid := cursor{"1", "localities", "1", "Shared", "11"}
	in := ListInput{Country: "IR", ProvinceID: "1", Query: " Shared ", Cursor: encode(valid)}
	normalized, _, err := listAdmission(in, "localities")
	if err != nil || normalized.Query != "Shared" || normalized.Limit != 20 {
		t.Fatal(err)
	}
	for name, c := range map[string]cursor{"revision": {"0", "localities", "1", "Shared", "11"}, "endpoint": {"1", "provinces", "1", "Shared", "11"}, "province": {"1", "localities", "2", "Shared", "11"}, "query": {"1", "localities", "1", "Other", "11"}, "id": {"1", "localities", "1", "Shared", "01"}} {
		t.Run(name, func(t *testing.T) {
			bad := in
			bad.Cursor = encode(c)
			if _, _, err := listAdmission(bad, "localities"); !errors.Is(err, ErrInvalid) {
				t.Fatal(err)
			}
		})
	}
	raw := `{"r":"1","r":"1","e":"localities","p":"1","q":"Shared","n":"Shared","i":"11"}`
	in.Cursor = base64.RawURLEncoding.EncodeToString([]byte(raw))
	if _, _, err := listAdmission(in, "localities"); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate cursor key accepted")
	}
}
