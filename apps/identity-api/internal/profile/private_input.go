package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/hatefsystems/identity/apps/identity-api/internal/geography"
)

// ErrInvalidPrivateData rejects malformed or incomplete private-profile input.
var ErrInvalidPrivateData = errors.New("profile: invalid private data")

// BirthdayInput accepts one calendar; clients cannot supply a derived pair.
type BirthdayInput struct {
	Calendar string `json:"calendar"`
	Date     string `json:"date"`
}

// PrivateUpdate distinguishes omitted fields from explicit zero values. Nulls
// are rejected at decoding; birthday and location are replaced as whole fields.
type PrivateUpdate struct {
	ExpectedRevision string                   `json:"expected_revision"`
	GivenName        *string                  `json:"given_name,omitempty"`
	FamilyName       *string                  `json:"family_name,omitempty"`
	Birthday         *BirthdayInput           `json:"birthday,omitempty"`
	Gender           *string                  `json:"gender,omitempty"`
	Location         *geography.LocationInput `json:"location,omitempty"`
}

// DecodePrivateUpdate rejects unknown, duplicate, case-variant and null fields,
// including within whole birthday/location values. No contact/public data fits.
func DecodePrivateUpdate(raw []byte) (PrivateUpdate, error) {
	var in PrivateUpdate
	if privateJSON(raw, &in) != nil || in.GivenName == nil && in.FamilyName == nil && in.Birthday == nil && in.Gender == nil && in.Location == nil {
		return PrivateUpdate{}, ErrInvalidPrivateData
	}
	if _, err := parseRevision(in.ExpectedRevision); err != nil {
		return PrivateUpdate{}, err
	}
	return in, nil
}

// privateJSON is bounded and typed, also for the authenticated stored payload.
func privateJSON(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > 8192 || !utf8.Valid(raw) || !privateEscapes(raw) {
		return ErrInvalidPrivateData
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if scanPrivateJSON(decoder, reflect.TypeOf(dst).Elem(), 0) != nil {
		return ErrInvalidPrivateData
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidPrivateData
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(dst) != nil {
		return ErrInvalidPrivateData
	}
	return nil
}

func privateFields(typ reflect.Type, fields map[string]reflect.Type) {
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Anonymous {
			privateFields(f.Type, fields)
			continue
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" {
			name = f.Name
		}
		fields[name] = f.Type
	}
}

func scanPrivateJSON(decoder *json.Decoder, typ reflect.Type, depth int) error {
	if depth > 4 {
		return ErrInvalidPrivateData
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return ErrInvalidPrivateData
	}
	if delimiter, ok := token.(json.Delim); ok {
		if delimiter != '{' || typ.Kind() != reflect.Struct {
			return ErrInvalidPrivateData
		}
		fields, seen := map[string]reflect.Type{}, map[string]bool{}
		privateFields(typ, fields)
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			field, allowed := fields[name]
			if err != nil || !ok || !allowed || seen[name] {
				return ErrInvalidPrivateData
			}
			seen[name] = true
			if scanPrivateJSON(decoder, field, depth+1) != nil {
				return ErrInvalidPrivateData
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalidPrivateData
		}
		return nil
	}
	// Every scalar in this contract is a string, including UUID and revisions.
	if _, ok := token.(string); !ok {
		return ErrInvalidPrivateData
	}
	return nil
}

func privateEscapes(raw []byte) bool {
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
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil || n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
