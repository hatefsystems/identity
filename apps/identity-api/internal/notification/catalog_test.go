package notification

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRequestLocale(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		want   Locale
	}{
		{"english", []string{"en"}, English},
		{"persian", []string{"fa-IR"}, Persian},
		{"missing", nil, English},
		{"empty", []string{""}, English},
		{"unknown", []string{"ar"}, English},
		{"language alias", []string{"fa"}, English},
		{"case alias", []string{"FA-ir"}, English},
		{"whitespace", []string{" fa-IR"}, English},
		{"list", []string{"fa-IR,en"}, English},
		{"duplicate", []string{"fa-IR", "fa-IR"}, English},
		{"conflict", []string{"fa-IR", "en"}, English},
		{"quality", []string{"fa-IR;q=1"}, English},
		{"oversized", []string{strings.Repeat("fa-IR", 10000)}, English},
		{"header injection", []string{"fa-IR\r\nBcc: private@example.test"}, English},
		{"bidi", []string{"fa\u202eIR"}, English},
		{"invalid utf8", []string{"\xff"}, English},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := RequestLocale(tc.values); got != tc.want {
				t.Fatal("unexpected request locale")
			}
		})
	}
}

func TestCatalogCompletenessAndInterpolation(t *testing.T) {
	for _, locale := range []Locale{English, Persian} {
		t.Run(string(locale), func(t *testing.T) {
			t.Parallel()
			catalog, ok := Catalog(locale, Version1)
			if !ok || (locale == Persian && catalog.Direction != "rtl") || (locale == English && catalog.Direction != "ltr") {
				t.Fatal("catalog language/direction missing")
			}
			fields := reflect.ValueOf(catalog.Deletion)
			for i := range fields.NumField() {
				text := fields.Field(i).String()
				if text == "" || !utf8.ValidString(text) || strings.ContainsAny(text, "\r\n<>") {
					t.Fatal("catalog field missing or unsafe")
				}
			}
			for _, template := range []string{catalog.SMS, catalog.Deletion.Deadline} {
				if strings.Count(template, "%s") != 1 || strings.Count(template, "%") != 1 {
					t.Fatal("template must interpolate exactly one unchanged value")
				}
				if result := fmt.Sprintf(template, "001234"); strings.Count(result, "001234") != 1 || strings.Contains(result, "%!") {
					t.Fatal("interpolation changed the technical value")
				}
			}
			original := catalog
			catalog.SMS = "changed"
			fresh, _ := Catalog(locale, Version1)
			if fresh != original {
				t.Fatal("caller changed a shared catalog")
			}
		})
	}
	for _, locale := range []Locale{"", "fa", "en-US", "fa-IR\r\n"} {
		if _, ok := Catalog(locale, Version1); ok {
			t.Fatal("persisted locale silently fell back")
		}
	}
	for _, version := range []TemplateVersion{-1, 0, 2, 999} {
		if _, ok := Catalog(English, version); ok {
			t.Fatal("unsupported template version accepted")
		}
	}
}
