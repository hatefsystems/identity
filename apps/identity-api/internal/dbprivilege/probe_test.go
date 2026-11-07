package dbprivilege

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

type probeDB struct {
	db.DBTX
	value bool
	err   error
	data  []byte
	bound bool
}

func (q *probeDB) QueryRow(ctx context.Context, _ string, args ...any) pgx.Row {
	q.data = args[0].([]byte)
	deadline, ok := ctx.Deadline()
	q.bound = ok && time.Until(deadline) <= 10*time.Second
	return probeRow{q.value, q.err}
}

type probeRow struct {
	value bool
	err   error
}

func (r probeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*bool) = r.value
	return nil
}

func TestCheckFailsClosedAndSanitizesCatalogErrors(t *testing.T) {
	if !errors.Is(Check(context.Background(), nil, Contract{}), ErrUnsafe) {
		t.Fatal("nil database accepted")
	}
	for _, q := range []*probeDB{{value: false}, {err: errors.New("private-role-dsn-sentinel")}, {err: pgx.ErrNoRows}} {
		if err := Check(context.Background(), q, Contract{}); err != ErrUnsafe {
			t.Fatalf("unsafe catalog result was not sanitized: %v", err)
		}
	}
}

func TestCheckUsesBoundedReadOnlyCatalogAndNonNullArrays(t *testing.T) {
	q := &probeDB{value: true}
	if err := Check(context.Background(), q, Contract{Tables: []Table{{Name: "public.example", Select: true}}}); err != nil || !q.bound {
		t.Fatal("bounded valid probe failed")
	}
	var encoded map[string]json.RawMessage
	if err := json.Unmarshal(q.data, &encoded); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Sequences", "Functions", "Guards"} {
		if string(encoded[name]) != "[]" {
			t.Fatalf("%s would cause a null catalog recordset", name)
		}
	}
	var tables []map[string]json.RawMessage
	if err := json.Unmarshal(encoded["Tables"], &tables); err != nil || string(tables[0]["UpdateColumns"]) != "[]" {
		t.Fatal("column allowance was not normalized")
	}
}
