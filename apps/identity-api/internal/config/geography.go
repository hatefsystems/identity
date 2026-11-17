package config

import (
	"fmt"
	"time"
)

// Geography settings may tighten, but never exceed, the public read budgets.
const (
	EnvGeographyPageSizeDefault    = "GEOGRAPHY_PAGE_SIZE_DEFAULT"
	EnvGeographyPageSizeMax        = "GEOGRAPHY_PAGE_SIZE_MAX"
	EnvGeographyQueryTimeout       = "GEOGRAPHY_QUERY_TIMEOUT"
	EnvGeographyLimiterTimeout     = "GEOGRAPHY_LIMITER_TIMEOUT"
	EnvGeographyPerIPPerMinute     = "GEOGRAPHY_PER_IP_PER_MINUTE"
	EnvGeographyPerSubnetPerMinute = "GEOGRAPHY_PER_SUBNET_PER_MINUTE"
)

// GeographyConfig bounds anonymous catalog reads, without importer credentials.
type GeographyConfig struct {
	PageSizeDefault    int
	PageSizeMax        int
	QueryTimeout       time.Duration
	LimiterTimeout     time.Duration
	PerIPPerMinute     int
	PerSubnetPerMinute int
}

// WithDefaults supplies the same safe defaults to explicit test composition.
func (c GeographyConfig) WithDefaults() GeographyConfig {
	if c.PageSizeDefault == 0 {
		c.PageSizeDefault = 20
	}
	if c.PageSizeMax == 0 {
		c.PageSizeMax = 50
	}
	if c.QueryTimeout == 0 {
		c.QueryTimeout = time.Second
	}
	if c.LimiterTimeout == 0 {
		c.LimiterTimeout = 250 * time.Millisecond
	}
	if c.PerIPPerMinute == 0 {
		c.PerIPPerMinute = 120
	}
	if c.PerSubnetPerMinute == 0 {
		c.PerSubnetPerMinute = 600
	}
	return c
}

// Validate also protects composition that bypasses environment loading.
func (c GeographyConfig) Validate() error {
	if c.PageSizeDefault < 1 || c.PageSizeMax > 50 || c.PageSizeDefault > c.PageSizeMax {
		return fmt.Errorf("config: geography page sizes require 1 <= default <= maximum <= 50")
	}
	if c.QueryTimeout <= 0 || c.QueryTimeout > time.Second || c.LimiterTimeout <= 0 || c.LimiterTimeout > time.Second {
		return fmt.Errorf("config: geography query and limiter timeouts must be positive and at most one second")
	}
	if c.PerIPPerMinute < 1 || c.PerIPPerMinute > 120 || c.PerSubnetPerMinute < 1 || c.PerSubnetPerMinute > 600 {
		return fmt.Errorf("config: geography minute budgets must be 1..120 per IP and 1..600 per subnet")
	}
	return nil
}

// LoadGeography loads only resource bounds; the API reuses its runtime DB pool.
func LoadGeography() (GeographyConfig, error) {
	c := (GeographyConfig{}).WithDefaults()
	for _, field := range []struct {
		name  string
		value *int
	}{
		{EnvGeographyPageSizeDefault, &c.PageSizeDefault},
		{EnvGeographyPageSizeMax, &c.PageSizeMax},
		{EnvGeographyPerIPPerMinute, &c.PerIPPerMinute},
		{EnvGeographyPerSubnetPerMinute, &c.PerSubnetPerMinute},
	} {
		value, err := getEnvPositiveInt(field.name, *field.value)
		if err != nil {
			return GeographyConfig{}, err
		}
		*field.value = value
	}
	for _, field := range []struct {
		name  string
		value *time.Duration
	}{
		{EnvGeographyQueryTimeout, &c.QueryTimeout},
		{EnvGeographyLimiterTimeout, &c.LimiterTimeout},
	} {
		value, err := getEnvDuration(field.name, *field.value)
		if err != nil {
			return GeographyConfig{}, err
		}
		*field.value = value
	}
	if err := c.Validate(); err != nil {
		return GeographyConfig{}, err
	}
	return c, nil
}
