package main

import (
	"encoding/json"
	"testing"

	"github.com/jmhodges/clock"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

func TestNewJobs(t *testing.T) {
	onlyCertStatusConfig := `{
	"janitor": {
		"certificates": {
			"enabled": false
		},
		"certificateStatus": {
			"enabled": true,
			"gracePeriod": "1h"
		},
		"certificatesPerName": {
			"enabled": false
		}
	}
}`
	allConfig := `{
	"janitor": {
		"certificates": {
			"enabled": true,
			"gracePeriod": "1h"
		},
		"certificateStatus": {
			"enabled": true,
			"gracePeriod": "1h"
		},
		"certificatesPerName": {
			"enabled": true,
			"gracePeriod": "169h"
		}
	}
}`
	testCases := []struct {
		name              string
		config            string
		expectedTableJobs []string
		expectedError     error
	}{
		{
			name:          "no jobs enabled",
			config:        `{}`,
			expectedError: errNoJobsConfigured,
		},
		{
			name:              "only certificate status enabled",
			config:            onlyCertStatusConfig,
			expectedTableJobs: []string{"certificateStatus"},
		},
		{
			name:              "only certificates enabled",
			config:            allConfig,
			expectedTableJobs: []string{"certificates", "certificateStatus", "certificatesPerName"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var config Config
			err := json.Unmarshal([]byte(tc.config), &config)
			test.AssertNotError(t, err, "error unmarshaling tc Config")

			jobs, err := newJobs(nil, blog.UseMock(), clock.NewFake(), config)
			test.AssertEquals(t, err, tc.expectedError)

			var tableMap map[string]bool
			if err != nil {
				for _, j := range jobs {
					tableMap[j.table] = true
				}
				for _, expected := range tc.expectedTableJobs {
					if _, present := tableMap[expected]; !present {
						t.Errorf("expected batchedDBJob with table %q to be present", expected)
					}
				}
			}
		})
	}
}
