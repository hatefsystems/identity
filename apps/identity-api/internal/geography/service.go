// Package geography owns immutable geography snapshots and bounded public reads.
package geography

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"golang.org/x/text/unicode/norm"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// Errors classify input, identity, stale pagination and dependency failures.
var (
	ErrInvalid        = errors.New("geography: invalid input")
	ErrNotFound       = errors.New("geography: not found")
	ErrCatalogChanged = errors.New("geography: catalog changed")
	ErrUnavailable    = errors.New("geography: unavailable")
)

// DB is implemented by pgxpool.Pool. Reads use one read-only snapshot.
type DB interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// Service resolves catalog reads and imports without runtime schema changes.
type Service struct{ database DB }

// New constructs a service over a pool-compatible transaction provider.
func New(database DB) *Service { return &Service{database: database} }

// ListInput binds bounded browsing/search to country and optional province.
type ListInput struct {
	Country, ProvinceID, Query, Cursor string
	Limit                              int
}

// Type preserves the original source type identity and label.
type Type struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Summary describes one ancestor in root-to-parent order.
type Summary struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	TypeID    string `json:"type_id"`
	TypeLabel string `json:"type_label"`
}

// Place resolves one identity at one complete immutable snapshot.
type Place struct {
	ID              string    `json:"id"`
	Label           string    `json:"label"`
	Type            Type      `json:"type"`
	Province        Summary   `json:"province"`
	Ancestors       []Summary `json:"ancestors"`
	Retired         bool      `json:"retired"`
	Selectable      bool      `json:"selectable"`
	CatalogRevision string    `json:"catalog_revision"`
}

// Page binds keyset results and their cursor to one active revision.
type Page struct {
	CatalogRevision string  `json:"catalog_revision"`
	Items           []Place `json:"items"`
	NextCursor      string  `json:"next_cursor"`
}

// LocationInput preserves the registration location contract.
type LocationInput struct {
	Country    string `json:"country"`
	ProvinceID string `json:"province_id"`
	LocalityID string `json:"locality_id,omitempty"`
}

// ValidatedLocation adds the server-owned snapshot binding for future storage.
type ValidatedLocation struct {
	LocationInput
	CatalogRevision string `json:"catalog_revision"`
}

func decimal(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != s {
		return 0, ErrInvalid
	}
	return n, nil
}
func number(n int64) string { return strconv.FormatInt(n, 10) }

// Normalize is versioned independently from display labels; it never changes IDs.
func Normalize(s string) string {
	s = norm.NFC.String(s)
	s = strings.NewReplacer("\u064a", "\u06cc", "\u0643", "\u06a9", "\u00a0", " ", "\u200c", " ").Replace(s)
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == ' ' }), " ")
}
func likePrefix(s string) string {
	return strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(s) + "%"
}
func prefixUpper(s string) string {
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r < utf8.MaxRune {
			r++
			if r >= 0xd800 && r <= 0xdfff {
				r = 0xe000
			}
			return s[:len(s)-size] + string(r)
		}
		s = s[:len(s)-size]
	}
	return ""
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func (s *Service) read(ctx context.Context) (pgx.Tx, int64, error) {
	if s == nil || s.database == nil {
		return nil, 0, ErrUnavailable
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	revision, err := db.New(tx).GeographyActiveRevision(ctx)
	if err != nil || revision == nil {
		rollback(tx)
		return nil, 0, ErrUnavailable
	}
	return tx, *revision, nil
}

const placeSQL = `WITH RECURSIVE path AS (
 SELECT v.id,v.label,v.type_id,v.parent_id,v.province_id,t.label AS type_label,0 AS depth
 FROM public.geography_place_versions v JOIN public.geography_types t ON t.revision=v.revision AND t.id=v.type_id
 WHERE v.revision=$1 AND v.id=$2
 UNION ALL
 SELECT v.id,v.label,v.type_id,v.parent_id,v.province_id,t.label,p.depth+1
 FROM path p JOIN public.geography_place_versions v ON v.revision=$1 AND v.id=p.parent_id
 JOIN public.geography_types t ON t.revision=v.revision AND t.id=v.type_id WHERE p.depth<32
) SELECT id,label,type_id,type_label,depth FROM path ORDER BY depth DESC`

func resolve(ctx context.Context, tx pgx.Tx, id, revision, active int64, retired bool) (Place, error) {
	rows, err := tx.Query(ctx, placeSQL, revision, id)
	if err != nil {
		return Place{}, ErrUnavailable
	}
	defer rows.Close()
	path := make([]Summary, 0, 5)
	for rows.Next() {
		var n, typ int64
		var label, typeLabel string
		var depth int
		if rows.Scan(&n, &label, &typ, &typeLabel, &depth) != nil {
			return Place{}, ErrUnavailable
		}
		path = append(path, Summary{number(n), label, number(typ), typeLabel})
	}
	if rows.Err() != nil {
		return Place{}, ErrUnavailable
	}
	if len(path) == 0 {
		return Place{}, ErrNotFound
	}
	if path[0].TypeID != "2" || len(path) > 33 {
		return Place{}, ErrUnavailable
	}
	leaf := path[len(path)-1]
	return Place{ID: leaf.ID, Label: leaf.Label, Type: Type{leaf.TypeID, leaf.TypeLabel}, Province: path[0],
		Ancestors: path[:len(path)-1], Retired: retired, Selectable: revision == active && !retired && (leaf.TypeID == "2" || leaf.TypeID == "5" || leaf.TypeID == "7"), CatalogRevision: number(revision)}, nil
}

// Lookup resolves current membership, explicit history, or retired last-seen data.
func (s *Service) Lookup(ctx context.Context, id, revision string) (Place, error) {
	n, err := decimal(id)
	if err != nil {
		return Place{}, err
	}
	var requested int64
	if revision != "" {
		requested, err = decimal(revision)
		if err != nil {
			return Place{}, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	tx, active, err := s.read(ctx)
	if err != nil {
		return Place{}, err
	}
	defer rollback(tx)
	q := db.New(tx)
	identity, err := q.GeographyIdentity(ctx, n)
	if errors.Is(err, pgx.ErrNoRows) {
		return Place{}, ErrNotFound
	}
	if err != nil {
		return Place{}, ErrUnavailable
	}
	var member bool
	if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.geography_place_versions WHERE revision=$1 AND id=$2)`, active, n).Scan(&member) != nil {
		return Place{}, ErrUnavailable
	}
	resolved := requested
	if resolved == 0 {
		resolved = active
		if !member {
			resolved = identity.LastSeenRevision
		}
	}
	return resolve(ctx, tx, n, resolved, active, !member)
}

type cursor struct {
	Revision string `json:"r"`
	Endpoint string `json:"e"`
	Province string `json:"p"`
	Query    string `json:"q"`
	ID       string `json:"i"`
}

func listAdmission(in ListInput, endpoint string) (ListInput, cursor, error) {
	if in.Country != "IR" || !utf8.ValidString(in.Query) || utf8.RuneCountInString(in.Query) > 80 || len(in.Query) > 256 || len(in.Cursor) > 2048 {
		return in, cursor{}, ErrInvalid
	}
	for _, r := range in.Query {
		if unicode.IsControl(r) {
			return in, cursor{}, ErrInvalid
		}
	}
	if in.Limit == 0 {
		in.Limit = 20
	}
	if in.Limit < 1 || in.Limit > 50 {
		return in, cursor{}, ErrInvalid
	}
	if endpoint == "localities" {
		if _, err := decimal(in.ProvinceID); err != nil {
			return in, cursor{}, err
		}
	} else if in.ProvinceID != "" {
		return in, cursor{}, ErrInvalid
	}
	in.Query = Normalize(in.Query)
	c := cursor{Endpoint: endpoint, Province: in.ProvinceID, Query: in.Query}
	if in.Cursor != "" {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(in.Cursor)
		if err != nil || strictJSON(raw, &c) != nil || c.Endpoint != endpoint || c.Province != in.ProvinceID || c.Query != in.Query {
			return in, cursor{}, ErrInvalid
		}
		if _, err := decimal(c.Revision); err != nil {
			return in, cursor{}, err
		}
		if _, err := decimal(c.ID); err != nil {
			return in, cursor{}, err
		}
	}
	return in, c, nil
}

// Provinces lists active province roots using normalized prefix search.
func (s *Service) Provinces(ctx context.Context, in ListInput) (Page, error) {
	return s.list(ctx, in, "provinces")
}

// Localities lists active type-5/type-7 identities in an active province.
func (s *Service) Localities(ctx context.Context, in ListInput) (Page, error) {
	return s.list(ctx, in, "localities")
}
func (s *Service) list(ctx context.Context, in ListInput, endpoint string) (Page, error) {
	in, c, err := listAdmission(in, endpoint)
	if err != nil {
		return Page{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	tx, revision, err := s.read(ctx)
	if err != nil {
		return Page{}, err
	}
	defer rollback(tx)
	if c.Revision != "" && c.Revision != number(revision) {
		return Page{}, ErrCatalogChanged
	}
	var province, after int64
	if endpoint == "localities" {
		province, _ = decimal(in.ProvinceID)
		var valid bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.geography_place_versions WHERE revision=$1 AND id=$2 AND type_id=2)`, revision, province).Scan(&valid) != nil {
			return Page{}, ErrUnavailable
		}
		if !valid {
			return Page{}, ErrInvalid
		}
	}
	if c.ID != "" {
		after, _ = decimal(c.ID)
	}
	// Separate constant predicates preserve PostgreSQL's partial-index plans.
	predicate := `type_id=2`
	if endpoint == "localities" {
		predicate = `type_id IN (5,7) AND province_id=$6`
	}
	var afterName string
	if after > 0 {
		// The immutable snapshot owns the key, not cursor-supplied label bytes.
		// This also keeps cursors bounded when NFC expands a display label.
		keyPredicate := `type_id=2`
		keyArgs := []any{revision, after}
		if endpoint == "localities" {
			keyPredicate = `type_id IN (5,7) AND province_id=$3`
			keyArgs = append(keyArgs, province)
		}
		err := tx.QueryRow(ctx, `SELECT search_label FROM public.geography_place_versions WHERE revision=$1 AND id=$2 AND `+keyPredicate, keyArgs...).Scan(&afterName)
		if errors.Is(err, pgx.ErrNoRows) {
			return Page{}, ErrInvalid
		}
		if err != nil {
			return Page{}, ErrUnavailable
		}
		if !strings.HasPrefix(afterName, in.Query) {
			return Page{}, ErrInvalid
		}
	}
	args := []any{revision, likePrefix(in.Query), afterName, after, in.Limit + 1}
	if endpoint == "localities" {
		args = append(args, province)
	}
	// Explicit C-collated bounds retain indexed prefix search even after pgx's
	// prepared statement crosses PostgreSQL's generic-plan threshold.
	if in.Query != "" {
		args = append(args, in.Query)
		predicate += ` AND search_label >= $` + strconv.Itoa(len(args)) + `::text COLLATE "C"`
		if upper := prefixUpper(in.Query); upper != "" {
			args = append(args, upper)
			predicate += ` AND search_label < $` + strconv.Itoa(len(args)) + `::text COLLATE "C"`
		}
	}
	sql := `SELECT id,search_label FROM public.geography_place_versions WHERE revision=$1 AND ` + predicate + `
      AND search_label LIKE $2 ESCAPE '\' AND (search_label,id)>($3::text COLLATE "C",$4::bigint)
      ORDER BY search_label COLLATE "C",id LIMIT $5`
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return Page{}, ErrUnavailable
	}
	type key struct {
		id   int64
		name string
	}
	keys := make([]key, 0, in.Limit+1)
	for rows.Next() {
		var k key
		if rows.Scan(&k.id, &k.name) != nil {
			rows.Close()
			return Page{}, ErrUnavailable
		}
		keys = append(keys, k)
	}
	rows.Close()
	if rows.Err() != nil {
		return Page{}, ErrUnavailable
	}
	page := Page{CatalogRevision: number(revision), Items: make([]Place, 0, in.Limit)}
	if len(keys) > in.Limit {
		keys = keys[:in.Limit]
		last := keys[len(keys)-1]
		encoded, _ := json.Marshal(cursor{number(revision), endpoint, in.ProvinceID, in.Query, number(last.id)})
		page.NextCursor = base64.RawURLEncoding.EncodeToString(encoded)
	}
	for _, k := range keys {
		p, err := resolve(ctx, tx, k.id, revision, revision, false)
		if err != nil {
			return Page{}, err
		}
		page.Items = append(page.Items, p)
	}
	return page, nil
}

// Validate verifies all IDs against one current snapshot, never client metadata.
func (s *Service) Validate(ctx context.Context, in LocationInput) (ValidatedLocation, error) {
	if in.Country != "IR" {
		return ValidatedLocation{}, ErrInvalid
	}
	province, err := decimal(in.ProvinceID)
	if err != nil {
		return ValidatedLocation{}, err
	}
	var locality int64
	if in.LocalityID != "" {
		locality, err = decimal(in.LocalityID)
		if err != nil {
			return ValidatedLocation{}, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	tx, revision, err := s.read(ctx)
	if err != nil {
		return ValidatedLocation{}, err
	}
	defer rollback(tx)
	var valid bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.geography_place_versions WHERE revision=$1 AND id=$2 AND type_id=2)
      AND ($3::bigint=0 OR EXISTS(SELECT 1 FROM public.geography_place_versions WHERE revision=$1 AND id=$3 AND type_id IN (5,7) AND province_id=$2))`, revision, province, locality).Scan(&valid)
	if err != nil {
		return ValidatedLocation{}, ErrUnavailable
	}
	if !valid {
		return ValidatedLocation{}, ErrInvalid
	}
	return ValidatedLocation{in, number(revision)}, nil
}
