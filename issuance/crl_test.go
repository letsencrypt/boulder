package issuance

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/crl/idp"
	"github.com/letsencrypt/boulder/test"
)

func TestNewCRLProfile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		config      CRLProfileConfig
		expected    *CRLProfile
		expectedErr string
	}{
		{
			name:        "validity too long",
			config:      CRLProfileConfig{ValidityInterval: config.Duration{Duration: 30 * 24 * time.Hour}},
			expected:    nil,
			expectedErr: "lifetime cannot be more than 10 days",
		},
		{
			name:        "validity too short",
			config:      CRLProfileConfig{ValidityInterval: config.Duration{Duration: 0}},
			expected:    nil,
			expectedErr: "lifetime must be positive",
		},
		{
			name: "negative backdate",
			config: CRLProfileConfig{
				ValidityInterval: config.Duration{Duration: 7 * 24 * time.Hour},
				MaxBackdate:      config.Duration{Duration: -time.Hour},
			},
			expected:    nil,
			expectedErr: "backdate must be non-negative",
		},
		{
			name: "happy path",
			config: CRLProfileConfig{
				ValidityInterval: config.Duration{Duration: 7 * 24 * time.Hour},
				MaxBackdate:      config.Duration{Duration: time.Hour},
			},
			expected: &CRLProfile{
				validityInterval: 7 * 24 * time.Hour,
				maxBackdate:      time.Hour,
			},
			expectedErr: "",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			actual, err := NewCRLProfile(tc.config)
			if err != nil {
				if tc.expectedErr == "" {
					t.Errorf("NewCRLProfile expected success but got %q", err)
					return
				}
				test.AssertContains(t, err.Error(), tc.expectedErr)
			} else {
				if tc.expectedErr != "" {
					t.Errorf("NewCRLProfile succeeded but expected error %q", tc.expectedErr)
					return
				}
				test.AssertEquals(t, actual.validityInterval, tc.expected.validityInterval)
				test.AssertEquals(t, actual.maxBackdate, tc.expected.maxBackdate)
				test.AssertNotNil(t, actual.lints, "lint registry should be populated")
			}
		})
	}
}

func TestIssueCRL(t *testing.T) {
	clk := clock.NewFake()
	clk.Set(time.Now())

	issuer, err := newIssuer(defaultIssuerConfig(), issuerCert, issuerSigner, clk)
	test.AssertNotError(t, err, "creating test issuer")

	defaultProfile := CRLProfile{
		validityInterval: 7 * 24 * time.Hour,
		maxBackdate:      1 * time.Hour,
		lints:            lint.GlobalRegistry(),
	}

	defaultRequest := CRLRequest{
		Number:     big.NewInt(123),
		Shard:      100,
		ThisUpdate: clk.Now().Add(-time.Second),
		Entries: []x509.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(987),
				RevocationTime: clk.Now().Add(-24 * time.Hour),
				ReasonCode:     1,
			},
		},
		DeprecatedIDPBaseURL: "http://old.crl.url",
	}

	req := defaultRequest
	req.ThisUpdate = clk.Now().Add(-24 * time.Hour)
	_, err = issuer.IssueCRL(&defaultProfile, &req)
	test.AssertError(t, err, "too old crl issuance should fail")
	test.AssertContains(t, err.Error(), "ThisUpdate is too far in the past")

	req = defaultRequest
	req.ThisUpdate = clk.Now().Add(time.Second)
	_, err = issuer.IssueCRL(&defaultProfile, &req)
	test.AssertError(t, err, "future crl issuance should fail")
	test.AssertContains(t, err.Error(), "ThisUpdate is in the future")

	req = defaultRequest
	req.Entries = append(req.Entries, x509.RevocationListEntry{
		SerialNumber:   big.NewInt(876),
		RevocationTime: clk.Now().Add(-24 * time.Hour),
		ReasonCode:     6,
	})
	_, err = issuer.IssueCRL(&defaultProfile, &req)
	test.AssertError(t, err, "invalid reason code should result in lint failure")
	test.AssertContains(t, err.Error(), "Reason code not included in BR")

	req = defaultRequest
	res, err := issuer.IssueCRL(&defaultProfile, &req)
	test.AssertNotError(t, err, "crl issuance should have succeeded")
	parsedRes, err := x509.ParseRevocationList(res)
	test.AssertNotError(t, err, "parsing test crl")
	test.AssertEquals(t, parsedRes.Issuer.CommonName, issuer.Cert.Subject.CommonName)
	test.AssertDeepEquals(t, parsedRes.Number, big.NewInt(123))
	expectUpdate := req.ThisUpdate.Add(-time.Second).Add(defaultProfile.validityInterval).Truncate(time.Second).UTC()
	test.AssertEquals(t, parsedRes.NextUpdate, expectUpdate)
	test.AssertEquals(t, len(parsedRes.Extensions), 3)

	idps, err := idp.GetIDPURIs(parsedRes.Extensions)
	test.AssertNotError(t, err, "getting IDP URIs from test CRL")
	test.AssertEquals(t, idps[0], "http://crl-url.example.org/100.crl")
	test.AssertEquals(t, idps[1], "http://old.crl.url/0/100.crl")

	req = defaultRequest
	req.DeprecatedIDPBaseURL = ""
	issuer.crlURLBase = ""
	_, err = issuer.IssueCRL(&defaultProfile, &req)
	test.AssertError(t, err, "crl issuance with no IDP should fail")
	test.AssertContains(t, err.Error(), "must contain an issuingDistributionPoint")
}
