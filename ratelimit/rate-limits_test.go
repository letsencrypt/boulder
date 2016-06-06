package ratelimit

import (
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
)

func TestEnabled(t *testing.T) {
	policy := RateLimitPolicy{
		Threshold: 10,
	}
	if !policy.Enabled() {
		t.Errorf("Policy should have been enabled.")
	}
}

func TestNotEnabled(t *testing.T) {
	policy := RateLimitPolicy{
		Threshold: 0,
	}
	if policy.Enabled() {
		t.Errorf("Policy should not have been enabled.")
	}
}

func TestGetThreshold(t *testing.T) {
	policy := RateLimitPolicy{
		Threshold: 1,
		Overrides: map[string]int{
			"key": 2,
		},
		RegistrationOverrides: map[int64]int{
			101: 3,
		},
	}
	if policy.GetThreshold("foo", 11) != 1 {
		t.Errorf("threshold should have been 1")
	}
	if policy.GetThreshold("key", 11) != 2 {
		t.Errorf("threshold should have been 2")
	}
	if policy.GetThreshold("key", 101) != 3 {
		t.Errorf("threshold should have been 3")
	}
	if policy.GetThreshold("foo", 101) != 3 {
		t.Errorf("threshold should have been 3")
	}
}

func TestWindowBegin(t *testing.T) {
	policy := RateLimitPolicy{
		Window: cmd.ConfigDuration{Duration: 24 * time.Hour},
	}
	now := time.Date(2015, 9, 22, 0, 0, 0, 0, time.UTC)
	expected := time.Date(2015, 9, 21, 0, 0, 0, 0, time.UTC)
	actual := policy.WindowBegin(now)
	if actual != expected {
		t.Errorf("Incorrect WindowBegin: %s, expected %s", actual, expected)
	}
}
