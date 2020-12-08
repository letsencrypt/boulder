package janitor

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jmhodges/clock"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

func TestNewJobs(t *testing.T) {
	onlyCertStatusConfig := `{
	"jobConfigs": [
		{
			"enabled": false,
			"table": "certificates"
		},
		{
			"enabled": true,
			"table": "certificateStatus",
			"gracePeriod": "2184h",
			"batchSize": 1,
			"parallelism": 1
		},
		{
			"enabled": false,
			"table": "certificatesPerName"
		}
	]
}`
	allConfig := `{
	"jobConfigs": [
		{
			"enabled": true,
			"table": "certificates",
			"gracePeriod": "2184h",
			"batchSize": 1,
			"parallelism": 1
		},
		{
			"enabled": true,
			"table": "certificateStatus",
			"gracePeriod": "2184h",
			"batchSize": 1,
			"parallelism": 1
		},
		{
			"enabled": true,
			"table": "certificatesPerName",
			"gracePeriod": "2184h",
			"batchSize": 1,
			"parallelism": 1
		}
	]
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
			var config JanitorConfig
			err := json.Unmarshal([]byte(tc.config), &config)
			test.AssertNotError(t, err, "error unmarshaling tc Config")

			jobs, err := newJobs(config.JobConfigs, nil, blog.UseMock(), clock.NewFake())
			fmt.Printf("For config %v got error %v\n", config.JobConfigs, err)
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
