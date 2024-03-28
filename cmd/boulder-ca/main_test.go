package notmain

import (
	"testing"

	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/test"
)

func TestValidateCertificateProfiles(t *testing.T) {
	defaultProfile := issuance.ProfileConfig{}
	namedProfile := issuance.ProfileConfig{Name: "iOnlyKnowFineDiningAndBreathing"}

	testCases := []struct {
		testName                 string
		profileConfigs           []issuance.ProfileConfig
		configDefaultProfileName string
		expectFailure            bool
	}{
		{
			// The configDefaultProfileName value gets set earlier in
			// //cmd/boulder-ca if its missing. We'll have to set it ourselves
			// for this test.
			testName:                 "default profile name matches default profile config",
			configDefaultProfileName: issuance.DefaultCertProfileName,
			profileConfigs:           []issuance.ProfileConfig{defaultProfile},
		},
		{
			testName:                 "custom profile name does not match default profile config",
			configDefaultProfileName: "rudiments",
			profileConfigs:           []issuance.ProfileConfig{defaultProfile},
			expectFailure:            true,
		},
		{
			testName:                 "custom profile name matches profile config",
			configDefaultProfileName: "iOnlyKnowFineDiningAndBreathing",
			profileConfigs:           []issuance.ProfileConfig{namedProfile},
		},
		{
			testName:                 "custom profile name does not match profile config",
			configDefaultProfileName: "dystopia",
			profileConfigs:           []issuance.ProfileConfig{namedProfile},
			expectFailure:            true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			var profiles []*issuance.Profile

			for _, config := range tc.profileConfigs {
				profile, err := issuance.NewProfile(config, nil)
				test.AssertNotError(t, err, "Couldn't create profile")
				profiles = append(profiles, profile)
				test.AssertEquals(t, len(profiles), 1)
				if !tc.expectFailure {
					test.Assert(t, validateDefaultCertificateProfileName(profile, profiles, tc.configDefaultProfileName), "Given profile name did not match the configured profile name")
				} else {
					test.Assert(t, !validateDefaultCertificateProfileName(profile, profiles, tc.configDefaultProfileName), "Given profile name matched the configured profile name, but should not have")
				}
			}
		})
	}
}
