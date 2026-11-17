package geography

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const syntheticTypes = `[{"Id":2,"Name":"Province"},{"Id":3,"Name":"County"},{"Id":5,"Name":"Urban"},{"Id":7,"Name":"Village"}]`
const syntheticCities = `[{"Id":1,"Name":"North","ParentId":null,"CenterType":2},{"Id":2,"Name":"South","ParentId":null,"CenterType":2},{"Id":10,"Name":"County","ParentId":1,"CenterType":3},{"Id":11,"Name":"Shared","ParentId":10,"CenterType":5},{"Id":12,"Name":"Shared","ParentId":11,"CenterType":5},{"Id":13,"Name":"Village","ParentId":12,"CenterType":7},{"Id":20,"Name":"Shared","ParentId":2,"CenterType":7}]`

func manifestFor(cities, types string, base *string) []byte {
	var places []sourcePlace
	var ts []sourceType
	_ = json.Unmarshal([]byte(cities), &places)
	_ = json.Unmarshal([]byte(types), &ts)
	provinces := 0
	for _, p := range places {
		if p.Type != nil && *p.Type == 2 {
			provinces++
		}
	}
	raw, _ := json.Marshal(Manifest{Country: "IR", SourceRelease: "synthetic-v1", CitiesSHA256: digest([]byte(cities)), TypesSHA256: digest([]byte(types)), CitiesBytes: int64(len(cities)), TypesBytes: int64(len(types)), PlaceCount: len(places), TypeCount: len(ts), ProvinceCount: provinces, ExpectedCurrentRevision: base, CompleteSnapshot: true})
	return raw
}
func fixtureSnapshot(t *testing.T, cities string, base *string) *Snapshot {
	t.Helper()
	s, err := Parse([]byte(cities), []byte(syntheticTypes), manifestFor(cities, syntheticTypes, base))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestAdmissionValidGraphAndExactIdentities(t *testing.T) {
	snapshot := fixtureSnapshot(t, syntheticCities, nil)
	if len(snapshot.places) != 7 || snapshot.places[5].ProvinceID != 1 || snapshot.places[5].TypeID != 7 {
		t.Fatal("variable hierarchy/type-5 nesting not retained")
	}
	cities := strings.Replace(syntheticCities, `"Id":20`, `"Id":9223372036854775807`, 1)
	s := fixtureSnapshot(t, cities, nil)
	if number(s.places[len(s.places)-1].ID) != "9223372036854775807" {
		t.Fatal("BIGINT source identity lost precision")
	}
}
func TestAdmissionRejectsGraphAndStrictJSON(t *testing.T) {
	cases := map[string]string{
		"empty": "[]", "null": "null", "object": "{}", "trailing": syntheticCities + " {}",
		"duplicateID":         strings.Replace(syntheticCities, `"Id":20`, `"Id":13`, 1),
		"missingParent":       strings.Replace(syntheticCities, `"ParentId":10`, `"ParentId":999`, 1),
		"selfParent":          strings.Replace(syntheticCities, `"ParentId":10`, `"ParentId":11`, 1),
		"cycle":               strings.Replace(syntheticCities, `"ParentId":10`, `"ParentId":13`, 1),
		"nonProvinceRoot":     strings.Replace(syntheticCities, `"ParentId":10`, `"ParentId":null`, 1),
		"provinceChild":       strings.Replace(syntheticCities, `"ParentId":null`, `"ParentId":2`, 1),
		"unknownType":         strings.Replace(syntheticCities, `"CenterType":3`, `"CenterType":4`, 1),
		"missingField":        strings.Replace(syntheticCities, `"ParentId":null,`, "", 1),
		"nullType":            strings.Replace(syntheticCities, `"CenterType":3`, `"CenterType":null`, 1),
		"nullLabel":           strings.Replace(syntheticCities, `"Name":"County"`, `"Name":null`, 1),
		"emptyLabel":          strings.Replace(syntheticCities, "County", "", 1),
		"blankLabel":          strings.Replace(syntheticCities, "County", "   ", 1),
		"nullByte":            strings.Replace(syntheticCities, "County", `\u0000`, 1),
		"unknownField":        strings.Replace(syntheticCities, `"Id":1`, `"Id":1,"Unknown":1`, 1),
		"duplicateKey":        strings.Replace(syntheticCities, `"Id":1`, `"Id":1,"Id":1`, 1),
		"escapedDuplicateKey": strings.Replace(syntheticCities, `"Id":1`, `"Id":1,"\u0049d":1`, 1),
		"caseVariant":         strings.Replace(syntheticCities, `"Id":1`, `"id":1`, 1),
		"stringID":            strings.Replace(syntheticCities, `"Id":1`, `"Id":"1"`, 1),
		"floatID":             strings.Replace(syntheticCities, `"Id":1`, `"Id":1.0`, 1),
		"exponentID":          strings.Replace(syntheticCities, `"Id":1`, `"Id":1e0`, 1),
		"overflowID":          strings.Replace(syntheticCities, `"Id":1`, `"Id":9223372036854775808`, 1),
		"negativeID":          strings.Replace(syntheticCities, `"Id":1`, `"Id":-1`, 1),
		"zeroID":              strings.Replace(syntheticCities, `"Id":1`, `"Id":0`, 1),
		"longLabel":           strings.Replace(syntheticCities, "County", strings.Repeat("x", 257), 1),
		"longUTF8Label":       strings.Replace(syntheticCities, "County", strings.Repeat("\U0001f600", 257), 1),
		"invalidUTF8":         strings.Replace(syntheticCities, "County", string([]byte{0xff}), 1),
		"unpairedHigh":        strings.Replace(syntheticCities, "County", `\ud800`, 1),
		"unpairedLow":         strings.Replace(syntheticCities, "County", `\udfff`, 1),
		"nested":              strings.Replace(syntheticCities, `"ParentId":10`, `"ParentId":`+strings.Repeat("[", 17)+"10"+strings.Repeat("]", 17), 1),
	}
	for name, cities := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(cities), []byte(syntheticTypes), manifestFor(cities, syntheticTypes, nil))
			if !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid input accepted", err)
			}
		})
	}
	for name, types := range map[string]string{"empty": "[]", "duplicate": `[{"Id":2,"Name":"Province"},{"Id":2,"Name":"Province"}]`, "nullLabel": `[{"Id":2,"Name":null}]`, "excess": strings.Repeat(" ", MaxTypesBytes+1)} {
		t.Run("types-"+name, func(t *testing.T) {
			if _, err := Parse([]byte(syntheticCities), []byte(types), manifestFor(syntheticCities, types, nil)); !errors.Is(err, ErrInvalid) {
				t.Fatal(err)
			}
		})
	}
}
func TestManifestSafeguards(t *testing.T) {
	original := manifestFor(syntheticCities, syntheticTypes, nil)
	for name, mutate := range map[string]func(map[string]any){
		"incomplete":       func(m map[string]any) { m["complete_snapshot"] = false },
		"wrongCountry":     func(m map[string]any) { m["country"] = "XX" },
		"missingBase":      func(m map[string]any) { delete(m, "expected_current_revision") },
		"numericBase":      func(m map[string]any) { m["expected_current_revision"] = 1 },
		"noncanonicalBase": func(m map[string]any) { m["expected_current_revision"] = "01" },
		"size":             func(m map[string]any) { m["cities_bytes"] = 1 },
		"hash":             func(m map[string]any) { m["cities_sha256"] = strings.Repeat("0", 64) },
		"count":            func(m map[string]any) { m["place_count"] = 6 },
		"provinceCount":    func(m map[string]any) { m["province_count"] = 1 },
		"unknown":          func(m map[string]any) { m["unknown"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal(original, &m)
			mutate(m)
			raw, _ := json.Marshal(m)
			if _, err := Parse([]byte(syntheticCities), []byte(syntheticTypes), raw); !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe manifest accepted", err)
			}
		})
	}
	truncated := syntheticCities[:len(syntheticCities)-1]
	if _, err := Parse([]byte(truncated), []byte(syntheticTypes), original); !errors.Is(err, ErrInvalid) {
		t.Fatal("changed bytes accepted")
	}
}
func TestHierarchyLimits(t *testing.T) {
	for _, edges := range []int{32, 33} {
		cities := `[{"Id":1,"Name":"Root","ParentId":null,"CenterType":2}`
		for i := 1; i <= edges; i++ {
			cities += fmt.Sprintf(`,{"Id":%d,"Name":"Nested","ParentId":%d,"CenterType":5}`, i+1, i)
		}
		cities += "]"
		_, err := Parse([]byte(cities), []byte(syntheticTypes), manifestFor(cities, syntheticTypes, nil))
		if edges == 32 && err != nil || edges == 33 && !errors.Is(err, ErrInvalid) {
			t.Fatal("hierarchy bound", edges, err)
		}
	}
}

func TestAdmissionSizeCountAndLabelBounds(t *testing.T) {
	if _, err := Parse(bytes.Repeat([]byte(" "), MaxCitiesBytes+1), []byte(syntheticTypes), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("places byte limit ignored")
	}
	if _, err := Parse([]byte(syntheticCities), bytes.Repeat([]byte(" "), MaxTypesBytes+1), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("types byte limit ignored")
	}
	if _, err := Parse([]byte(syntheticCities), []byte(syntheticTypes), bytes.Repeat([]byte(" "), (16<<10)+1)); !errors.Is(err, ErrInvalid) {
		t.Fatal("manifest byte limit ignored")
	}
	entries := make([]string, MaxTypes+1)
	for i := range entries {
		entries[i] = fmt.Sprintf(`{"Id":%d,"Name":"Type"}`, i+1)
	}
	types := "[" + strings.Join(entries, ",") + "]"
	if _, err := Parse([]byte(syntheticCities), []byte(types), manifestFor(syntheticCities, types, nil)); !errors.Is(err, ErrInvalid) {
		t.Fatal("type count limit ignored")
	}
	// Count rejection precedes graph admission, keeping diagnostics bounded.
	repeated := bytes.Repeat([]byte(`{"Id":1,"Name":"Root","ParentId":null,"CenterType":2},`), MaxPlaces+1)
	cities := "[" + string(repeated[:len(repeated)-1]) + "]"
	if _, err := Parse([]byte(cities), []byte(syntheticTypes), manifestFor(cities, syntheticTypes, nil)); !errors.Is(err, ErrInvalid) {
		t.Fatal("place count limit ignored")
	}
	label := strings.Repeat("\U0001f600", 256)
	accepted := strings.Replace(syntheticCities, "County", label, 1)
	if fixtureSnapshot(t, accepted, nil).places[2].Label != label {
		t.Fatal("boundary label bytes changed")
	}
}

func TestExplicitRegularFileAdmission(t *testing.T) {
	directory := t.TempDir()
	if _, err := readBounded(directory, 16); !errors.Is(err, ErrInvalid) {
		t.Fatal("directory admitted")
	}
	if _, err := readBounded(filepath.Join(directory, "missing"), 16); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing file admitted")
	}
	path := filepath.Join(directory, "synthetic.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readBounded(path, 2); err != nil || string(raw) != "[]" {
		t.Fatal("explicit file", err)
	}
	if _, err := readBounded(path, 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized file admitted")
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(path, 2); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty file admitted")
	}
}
func TestNormalizationAndLiteralPrefix(t *testing.T) {
	if got := Normalize("  \u064a\u0643\u00a0\u200c  e\u0301  "); got != "\u06cc\u06a9 \u00e9" {
		t.Fatal(got)
	}
	if got := likePrefix(`%_\`); got != `\%\_\\%` {
		t.Fatal("wildcards not escaped", got)
	}
	// Valid surrogate pairs survive as their exact Unicode scalar value.
	cities := strings.Replace(syntheticCities, "County", `\ud83d\ude00`, 1)
	if fixtureSnapshot(t, cities, nil).places[2].Label != "\U0001f600" {
		t.Fatal("surrogate pair changed")
	}
}
