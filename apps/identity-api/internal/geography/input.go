package geography

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Admission and metadata versions are fixed for this importer implementation.
const (
	MaxCitiesBytes       = 64 << 20
	MaxTypesBytes        = 64 << 10
	MaxPlaces            = 250000
	MaxTypes             = 64
	ImporterVersion      = "geography-import-v1"
	NormalizationVersion = "nfc-yeh-kaf-space-v1"
)

// Manifest is an operator assertion, never generated as evidence of completeness.
type Manifest struct {
	Country                 string  `json:"country"`
	SourceRelease           string  `json:"source_release"`
	CitiesSHA256            string  `json:"cities_sha256"`
	TypesSHA256             string  `json:"types_sha256"`
	CitiesBytes             int64   `json:"cities_bytes"`
	TypesBytes              int64   `json:"types_bytes"`
	PlaceCount              int     `json:"place_count"`
	TypeCount               int     `json:"type_count"`
	ProvinceCount           int     `json:"province_count"`
	ExpectedCurrentRevision *string `json:"expected_current_revision"`
	CompleteSnapshot        bool    `json:"complete_snapshot"`
}
type sourcePlace struct {
	ID     *int64          `json:"Id"`
	Name   *string         `json:"Name"`
	Parent json.RawMessage `json:"ParentId"`
	Type   *int64          `json:"CenterType"`
}
type sourceType struct {
	ID   *int64  `json:"Id"`
	Name *string `json:"Name"`
}
type record struct {
	ID          int64
	Label       string
	TypeID      int64
	ParentID    *int64
	ProvinceID  int64
	SearchLabel string
}

// Snapshot cannot be fabricated by external callers; admission owns its contents.
type Snapshot struct {
	manifest Manifest
	places   []record
	types    []sourceType
}

func readBounded(path string, maximum int64) ([]byte, error) {
	if path == "" {
		return nil, ErrInvalid
	}
	// Refuse devices/FIFOs before opening; a complete snapshot is a regular file.
	info, err := os.Stat(filepath.Clean(path))
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, ErrInvalid
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, ErrInvalid
	}
	defer func() { _ = file.Close() }()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum {
		return nil, ErrInvalid
	}
	return raw, nil
}

// strictJSON rejects duplicate/unknown/case-variant keys, trailing values,
// excessive nesting, invalid UTF-8 and unpaired JSON surrogate escapes.
func strictJSON(raw []byte, dst any) error {
	if !utf8.Valid(raw) || !validEscapes(raw) {
		return ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	typ := reflect.TypeOf(dst)
	if typ == nil || typ.Kind() != reflect.Pointer {
		return ErrInvalid
	}
	if scanJSON(dec, typ.Elem(), 0) != nil {
		return ErrInvalid
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrInvalid
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(dst) != nil {
		return ErrInvalid
	}
	return nil
}
func scanJSON(dec *json.Decoder, typ reflect.Type, depth int) error {
	if depth > 16 {
		return ErrInvalid
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return ErrInvalid
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := make(map[string]bool)
		fields := make(map[string]reflect.Type)
		if typ.Kind() == reflect.Struct {
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				name := strings.Split(f.Tag.Get("json"), ",")[0]
				if name == "" {
					name = f.Name
				}
				fields[name] = f.Type
			}
		}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return ErrInvalid
			}
			name, ok := key.(string)
			if !ok || keys[name] || len(keys) >= 64 {
				return ErrInvalid
			}
			keys[name] = true
			field, ok := fields[name]
			if !ok {
				return ErrInvalid
			}
			if scanJSON(dec, field, depth+1) != nil {
				return ErrInvalid
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		if typ.Kind() != reflect.Slice {
			return ErrInvalid
		}
		count := 0
		for dec.More() {
			count++
			if count > MaxPlaces || scanJSON(dec, typ.Elem(), depth+1) != nil {
				return ErrInvalid
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func validEscapes(raw []byte) bool {
	// Validate only inside JSON strings. json.Decoder validates all other syntax.
	inside := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		var n uint16
		for j := 1; j <= 4; j++ {
			b := raw[i+j]
			var d byte
			switch {
			case b >= '0' && b <= '9':
				d = b - '0'
			case b >= 'a' && b <= 'f':
				d = b - 'a' + 10
			case b >= 'A' && b <= 'F':
				d = b - 'A' + 10
			default:
				return false
			}
			n = n*16 + uint16(d)
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low := raw[i+3 : i+7]
			decoded, err := hex.DecodeString(string(low))
			if err != nil || len(decoded) != 2 {
				return false
			}
			v := uint16(decoded[0])<<8 | uint16(decoded[1])
			if v < 0xdc00 || v > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
func labelValid(s string) bool {
	if !utf8.ValidString(s) || len(s) > 1024 || utf8.RuneCountInString(s) > 256 || strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validDigest(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}
func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// Load admits explicit local files. It never discovers paths or mutates a database.
func Load(citiesPath, typesPath, manifestPath string) (*Snapshot, error) {
	cities, err := readBounded(citiesPath, MaxCitiesBytes)
	if err != nil {
		return nil, err
	}
	types, err := readBounded(typesPath, MaxTypesBytes)
	if err != nil {
		return nil, err
	}
	manifest, err := readBounded(manifestPath, 16<<10)
	if err != nil {
		return nil, err
	}
	return Parse(cities, types, manifest)
}

// Parse supports synthetic fixtures and admits the same strict format as Load.
func Parse(cities, types, manifest []byte) (*Snapshot, error) {
	if len(cities) == 0 || len(cities) > MaxCitiesBytes || len(types) == 0 || len(types) > MaxTypesBytes || len(manifest) > 16<<10 {
		return nil, ErrInvalid
	}
	var m Manifest
	if strictJSON(manifest, &m) != nil {
		return nil, ErrInvalid
	}
	// Null is required for initial import; an omitted base is not an assertion.
	var fields map[string]json.RawMessage
	if json.Unmarshal(manifest, &fields) != nil || len(fields) != 11 {
		return nil, ErrInvalid
	}
	if m.Country != "IR" || !m.CompleteSnapshot || !labelValid(m.SourceRelease) || len(m.SourceRelease) > 256 ||
		!validDigest(m.CitiesSHA256) || !validDigest(m.TypesSHA256) || m.CitiesSHA256 != digest(cities) || m.TypesSHA256 != digest(types) ||
		m.CitiesBytes != int64(len(cities)) || m.TypesBytes != int64(len(types)) {
		return nil, ErrInvalid
	}
	if m.ExpectedCurrentRevision != nil {
		if _, err := decimal(*m.ExpectedCurrentRevision); err != nil {
			return nil, err
		}
	}
	var places []sourcePlace
	var sourceTypes []sourceType
	if strictJSON(cities, &places) != nil || strictJSON(types, &sourceTypes) != nil || len(places) < 1 || len(places) > MaxPlaces || len(sourceTypes) < 1 || len(sourceTypes) > MaxTypes ||
		len(places) != m.PlaceCount || len(sourceTypes) != m.TypeCount {
		return nil, ErrInvalid
	}
	knownTypes := make(map[int64]bool, len(sourceTypes))
	for _, t := range sourceTypes {
		if t.ID == nil || *t.ID <= 0 || t.Name == nil || !labelValid(*t.Name) || knownTypes[*t.ID] {
			return nil, ErrInvalid
		}
		knownTypes[*t.ID] = true
	}
	byID := make(map[int64]int, len(places))
	records := make([]record, len(places))
	provinces := 0
	for i, p := range places {
		if p.ID == nil || *p.ID <= 0 || p.Type == nil || !knownTypes[*p.Type] || p.Name == nil || !labelValid(*p.Name) || len(p.Parent) == 0 {
			return nil, ErrInvalid
		}
		if _, exists := byID[*p.ID]; exists {
			return nil, ErrInvalid
		}
		byID[*p.ID] = i
		var parent *int64
		if json.Unmarshal(p.Parent, &parent) != nil || parent != nil && (*parent <= 0 || *parent == *p.ID) {
			return nil, ErrInvalid
		}
		if *p.Type == 2 {
			provinces++
			if parent != nil {
				return nil, ErrInvalid
			}
		} else if parent == nil {
			return nil, ErrInvalid
		}
		records[i] = record{*p.ID, *p.Name, *p.Type, parent, 0, Normalize(*p.Name)}
	}
	if provinces == 0 || provinces != m.ProvinceCount {
		return nil, ErrInvalid
	}
	// Bounded walks both detect cycles and allow variable depths/type-5 nesting.
	for i := range records {
		current := i
		for depth := 0; ; depth++ {
			if depth > 32 {
				return nil, ErrInvalid
			}
			p := records[current]
			if p.ParentID == nil {
				if p.TypeID != 2 {
					return nil, ErrInvalid
				}
				records[i].ProvinceID = p.ID
				break
			}
			next, ok := byID[*p.ParentID]
			if !ok {
				return nil, ErrInvalid
			}
			current = next
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	sort.Slice(sourceTypes, func(i, j int) bool { return *sourceTypes[i].ID < *sourceTypes[j].ID })
	return &Snapshot{m, records, sourceTypes}, nil
}
