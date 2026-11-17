package config

import (
	"testing"
	"time"
)

func clearGeographyEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{EnvGeographyPageSizeDefault, EnvGeographyPageSizeMax, EnvGeographyQueryTimeout, EnvGeographyLimiterTimeout, EnvGeographyPerIPPerMinute, EnvGeographyPerSubnetPerMinute} {
		t.Setenv(name, "")
	}
}

func TestGeographyDefaultsAndRuntimeComposition(t *testing.T) {
	clearGeographyEnvironment(t)
	t.Setenv("APP_ENV", "development")
	c, err := LoadGeography()
	if err != nil {
		t.Fatal(err)
	}
	if c.PageSizeDefault != 20 || c.PageSizeMax != 50 || c.QueryTimeout != time.Second || c.LimiterTimeout != 250*time.Millisecond || c.PerIPPerMinute != 120 || c.PerSubnetPerMinute != 600 {
		t.Fatalf("incorrect anonymous read defaults: %+v", c)
	}
	loaded, err := Load()
	if err != nil || loaded.Geography != c || (GeographyConfig{}).WithDefaults() != c {
		t.Fatalf("runtime composition differs: %+v, %v", loaded.Geography, err)
	}
	// No operator/crypto/delivery settings belong to reader configuration.
	for _, name := range []string{"DATABASE_URL", "GEOGRAPHY_IMPORT_DATABASE_URL", EnvMasterKEK, "SMS_GATEWAY_API_KEY"} {
		t.Setenv(name, "invalid-unrelated-secret")
	}
	if _, err := LoadGeography(); err != nil {
		t.Fatalf("reader bounds loaded unrelated credentials: %v", err)
	}
}

func TestGeographyConfigOnlyAdmitsBoundedOverrides(t *testing.T) {
	clearGeographyEnvironment(t)
	for _, tc := range []struct{ name, value string }{
		{EnvGeographyPageSizeDefault, "0"},
		{EnvGeographyPageSizeDefault, "51"},
		{EnvGeographyPageSizeMax, "0"},
		{EnvGeographyPageSizeMax, "51"},
		{EnvGeographyPageSizeMax, "19"},
		{EnvGeographyPageSizeMax, " 50"},
		{EnvGeographyPageSizeMax, "1e2"},
		{EnvGeographyQueryTimeout, "0s"},
		{EnvGeographyQueryTimeout, "1001ms"},
		{EnvGeographyQueryTimeout, "bad"},
		{EnvGeographyLimiterTimeout, "-1ms"},
		{EnvGeographyLimiterTimeout, "1001ms"},
		{EnvGeographyPerIPPerMinute, "121"},
		{EnvGeographyPerIPPerMinute, "0"},
		{EnvGeographyPerIPPerMinute, "9223372036854775808"},
		{EnvGeographyPerSubnetPerMinute, "601"},
		{EnvGeographyPerSubnetPerMinute, "-1"},
	} {
		t.Run(tc.name+"/"+tc.value, func(t *testing.T) {
			t.Setenv(tc.name, tc.value)
			if _, err := LoadGeography(); err == nil {
				t.Fatalf("unbounded or malformed setting admitted: %s=%s", tc.name, tc.value)
			}
		})
	}
	for name, value := range map[string]string{
		EnvGeographyPageSizeDefault: "10", EnvGeographyPageSizeMax: "25",
		EnvGeographyQueryTimeout: "500ms", EnvGeographyLimiterTimeout: "100ms",
		EnvGeographyPerIPPerMinute: "60", EnvGeographyPerSubnetPerMinute: "300",
	} {
		t.Setenv(name, value)
	}
	c, err := LoadGeography()
	if err != nil || c.PageSizeDefault != 10 || c.PageSizeMax != 25 || c.QueryTimeout != 500*time.Millisecond || c.LimiterTimeout != 100*time.Millisecond || c.PerIPPerMinute != 60 || c.PerSubnetPerMinute != 300 {
		t.Fatalf("safe overrides not applied: %+v, %v", c, err)
	}
}
