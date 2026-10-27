package main

import (
	"log/slog"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
)

func TestPrivacyWiringNeverEnablesMissingDependencies(t *testing.T) {
	for _, enabled := range []string{"false", "true"} {
		t.Run(enabled, func(t *testing.T) {
			for key, value := range map[string]string{
				config.EnvGDPRDeletionEnabled:          enabled,
				config.EnvGDPRGracePeriod:              "720h",
				config.EnvGDPRPurgeBatchSize:           "100",
				config.EnvGDPRPurgeDryRun:              "false",
				config.EnvGDPRReclaimMaxAttempts:       "5",
				config.EnvGDPRReclaimPerAccountPerHour: "10",
				config.EnvGDPRReclaimPerSubnetPerHour:  "20",
				config.EnvGDPRDeletePerAccountPerDay:   "3",
			} {
				t.Setenv(key, value)
			}
			svc, available, err := buildPrivacyService("production", nil, nil, nil, nil, nil, nil, nil, slog.New(slog.DiscardHandler))
			if svc != nil || available || (err != nil) != (enabled == "true") {
				t.Fatalf("missing-dependency wiring: service=%v enabled=%v error=%v", svc != nil, available, err)
			}
		})
	}
}
