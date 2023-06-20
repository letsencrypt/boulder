package ratelimits

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func Test_loadLimits(t *testing.T) {
	_, err := loadLimits("test/defaults.yml")
	test.AssertNotError(t, err, "should not error")

	_, err = loadLimits("test/overrides.yml")
	test.AssertNotError(t, err, "should not error")

	_, err = loadLimits("")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("test/does-not-exist.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("test/busted_burst.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("test/busted_count.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("test/busted_period.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("test/busted_override_name.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("test/busted_override_limit.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("test/busted_override_empty_name.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("test/busted_override_empty_id.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("test/busted_name.yml")
	test.AssertError(t, err, "should error")

}
