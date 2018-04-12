package ratelimit

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/test"
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

func TestLoadPolicies(t *testing.T) {
	policy := New()

	policyContent, readErr := ioutil.ReadFile("../test/rate-limit-policies.yml")
	test.AssertNotError(t, readErr, "Failed to load rate-limit-policies.yml")

	// Test that loading a good policy from YAML doesn't error
	err := policy.LoadPolicies(policyContent)
	test.AssertNotError(t, err, "Failed to parse rate-limit-policies.yml")

	// Test that the CertificatesPerName section parsed correctly
	certsPerName := policy.CertificatesPerName()
	test.AssertEquals(t, certsPerName.Threshold, 2)
	test.AssertDeepEquals(t, certsPerName.Overrides, map[string]int{
		"ratelimit.me":          1,
		"lim.it":                0,
		"le.wtf":                10000,
		"le1.wtf":               10000,
		"le2.wtf":               10000,
		"le3.wtf":               10000,
		"nginx.wtf":             10000,
		"good-caa-reserved.com": 10000,
		"bad-caa-reserved.com":  10000,
		"ecdsa.le.wtf":          10000,
		"must-staple.le.wtf":    10000,
	})
	test.AssertDeepEquals(t, certsPerName.RegistrationOverrides, map[int64]int{
		101: 1000,
	})

	// Test that the RegistrationsPerIP section parsed correctly
	regsPerIP := policy.RegistrationsPerIP()
	test.AssertEquals(t, regsPerIP.Threshold, 10000)
	test.AssertDeepEquals(t, regsPerIP.Overrides, map[string]int{
		"127.0.0.1": 1000000,
	})
	test.AssertEquals(t, len(regsPerIP.RegistrationOverrides), 0)

	// Test that the PendingAuthorizationsPerAccount section parsed correctly
	pendingAuthsPerAcct := policy.PendingAuthorizationsPerAccount()
	test.AssertEquals(t, pendingAuthsPerAcct.Threshold, 150)
	test.AssertEquals(t, len(pendingAuthsPerAcct.Overrides), 0)
	test.AssertEquals(t, len(pendingAuthsPerAcct.RegistrationOverrides), 0)

	// Test that the CertificatesPerFQDN section parsed correctly
	certsPerFQDN := policy.CertificatesPerFQDNSet()
	test.AssertEquals(t, certsPerFQDN.Threshold, 5)
	test.AssertDeepEquals(t, certsPerFQDN.Overrides, map[string]int{
		"le.wtf":                10000,
		"le1.wtf":               10000,
		"le2.wtf":               10000,
		"le3.wtf":               10000,
		"le.wtf,le1.wtf":        10000,
		"good-caa-reserved.com": 10000,
		"nginx.wtf":             10000,
		"ecdsa.le.wtf":          10000,
		"must-staple.le.wtf":    10000,
	})
	test.AssertEquals(t, len(certsPerFQDN.RegistrationOverrides), 0)

	// Test that loading invalid YAML generates an error
	err = policy.LoadPolicies([]byte("err"))
	test.AssertError(t, err, "Failed to generate error loading invalid yaml policy file")
	// Re-check a field of policy to make sure a LoadPolicies error doesn't
	// corrupt the existing policies
	test.AssertDeepEquals(t, policy.RegistrationsPerIP().Overrides, map[string]int{
		"127.0.0.1": 1000000,
	})

	// Test that the RateLimitConfig accessors do not panic when there has been no
	// `LoadPolicy` call, and instead return empty RateLimitPolicy objects with default
	// values.
	emptyPolicy := New()
	test.AssertEquals(t, emptyPolicy.CertificatesPerName().Threshold, 0)
	test.AssertEquals(t, emptyPolicy.RegistrationsPerIP().Threshold, 0)
	test.AssertEquals(t, emptyPolicy.RegistrationsPerIP().Threshold, 0)
	test.AssertEquals(t, emptyPolicy.PendingAuthorizationsPerAccount().Threshold, 0)
	test.AssertEquals(t, emptyPolicy.CertificatesPerFQDNSet().Threshold, 0)
}
