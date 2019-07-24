package main

import (
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/test"
)

func TestValidCleanupConfig(t *testing.T) {
	testCases := []struct {
		name        string
		config      CleanupConfig
		expectedErr error
	}{
		{
			name: "invalid grace period",
			config: CleanupConfig{
				GracePeriod: cmd.ConfigDuration{Duration: time.Hour * -1},
			},
			expectedErr: errInvalidGracePeriod,
		},
		{
			name: "invalid parallelism",
			config: CleanupConfig{
				GracePeriod: cmd.ConfigDuration{Duration: time.Hour},
				Parallelism: 0,
			},
			expectedErr: errInvalidParallelism,
		},
		{
			name: "invalid batch sizse",
			config: CleanupConfig{
				GracePeriod: cmd.ConfigDuration{Duration: time.Hour},
				Parallelism: 1,
				BatchSize:   -1,
			},
			expectedErr: errInvalidNegativeValue,
		},
		{
			name: "invalid max DPS",
			config: CleanupConfig{
				GracePeriod: cmd.ConfigDuration{Duration: time.Hour},
				Parallelism: 1,
				BatchSize:   1,
				MaxDPS:      -1,
			},
			expectedErr: errInvalidNegativeValue,
		},
		{
			name: "valid",
			config: CleanupConfig{
				GracePeriod: cmd.ConfigDuration{Duration: time.Hour},
				Parallelism: 1,
				BatchSize:   1,
				MaxDPS:      1,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.config.Valid()
			test.AssertEquals(t, actual, tc.expectedErr)
		})
	}
}
