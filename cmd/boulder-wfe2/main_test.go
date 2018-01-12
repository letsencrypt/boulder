package main

import (
	"fmt"
	"io/ioutil"
	"testing"

	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/test"
)

func TestLoadCertificateChains(t *testing.T) {
	// Read some cert bytes to use for expected chain content
	certBytesA, err := ioutil.ReadFile("../../test/test-ca.pem")
	test.AssertNotError(t, err, "Error reading../../test/test-ca.pem")
	certBytesB, err := ioutil.ReadFile("../../test/test-ca2.pem")
	test.AssertNotError(t, err, "Error reading../../test/test-ca2.pem")

	// Make a .pem file with invalid contents
	invalidPEMFile, _ := ioutil.TempFile("", "invalid.pem")
	err = ioutil.WriteFile(invalidPEMFile.Name(), []byte(""), 0640)
	test.AssertNotError(t, err, "Error writing invalid PEM tmp file")

	// Make a .pem file with a valid cert but also some leftover bytes
	leftoverPEMFile, _ := ioutil.TempFile("", "leftovers.pem")
	leftovers := "vegan curry, cold rice, soy milk"
	leftoverBytes := append(certBytesA, []byte(leftovers)...)
	err = ioutil.WriteFile(leftoverPEMFile.Name(), leftoverBytes, 0640)
	test.AssertNotError(t, err, "Error writing leftover PEM tmp file")

	testCases := []struct {
		Name           string
		Input          map[string][]string
		ExpectedResult map[string]string
		ExpectedError  error
	}{
		{
			Name:           "No input",
			Input:          nil,
			ExpectedResult: nil,
			ExpectedError:  nil,
		},
		{
			Name: "AIA Issuer without chain files",
			Input: map[string][]string{
				"http://break.the.chain.com": []string{},
			},
			ExpectedResult: nil,
			ExpectedError: berrors.MalformedError(
				"CertificateChain entry for AIA issuer url \"http://break.the.chain.com\" " +
					"has no chain file names configured"),
		},
		{
			Name: "Missing chain file",
			Input: map[string][]string{
				"http://where.is.my.mind": []string{"/tmp/does.not.exist.pem"},
			},
			ExpectedResult: nil,
			ExpectedError: berrors.MalformedError(
				"CertificateChain entry for AIA issuer url \"http://where.is.my.mind\" " +
					"has an invalid chain file: \"/tmp/does.not.exist.pem\" - error reading " +
					"contents"),
		},
		{
			Name: "Invalid PEM chain file",
			Input: map[string][]string{
				"http://ok.go": []string{invalidPEMFile.Name()},
			},
			ExpectedResult: nil,
			ExpectedError: berrors.MalformedError(
				"CertificateChain entry for AIA issuer url \"http://ok.go\" has an "+
					"invalid chain file: %q - contents did not decode as PEM",
				invalidPEMFile.Name()),
		},
		{
			Name: "PEM chain file that isn't a cert",
			Input: map[string][]string{
				"http://not-a-cert.com": []string{"../../test/test-root.key"},
			},
			ExpectedResult: nil,
			ExpectedError: berrors.MalformedError(
				"CertificateChain entry for AIA issuer url \"http://not-a-cert.com\" has an invalid chain file: \"../../test/test-root.key\" - PEM block type incorrect, found \"PRIVATE KEY\", expected \"CERTIFICATE\""),
		},
		{
			Name: "PEM chain file with leftover bytes",
			Input: map[string][]string{
				"http://tasty.leftovers.com": []string{leftoverPEMFile.Name()},
			},
			ExpectedResult: nil,
			ExpectedError: berrors.MalformedError(
				"CertificateChain entry for AIA issuer url \"http://tasty.leftovers.com\" has an invalid chain file: %q - PEM contents had unused remainder input (%d bytes)",
				leftoverPEMFile.Name(),
				len([]byte(leftovers)),
			),
		},
		{
			Name: "One PEM file chain",
			Input: map[string][]string{
				"http://single-cert-chain.com": []string{"../../test/test-ca.pem"},
			},
			ExpectedResult: map[string]string{
				"http://single-cert-chain.com": fmt.Sprintf("%s\n", string(certBytesA)),
			},
			ExpectedError: nil,
		},
		{
			Name: "Two PEM file chain",
			Input: map[string][]string{
				"http://two-cert-chain.com": []string{"../../test/test-ca.pem", "../../test/test-ca2.pem"},
			},
			ExpectedResult: map[string]string{
				"http://two-cert-chain.com": fmt.Sprintf("%s\n%s\n", string(certBytesA), string(certBytesB)),
			},
			ExpectedError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result, err := loadCertificateChains(tc.Input)
			if tc.ExpectedError == nil && err != nil {
				t.Errorf("Expected nil error, got %#v\n", err)
			}
			if tc.ExpectedError != nil {
				test.AssertEquals(t, err.Error(), tc.ExpectedError.Error())
			}
			test.AssertEquals(t, len(result), len(tc.ExpectedResult))
			for url, chain := range result {
				test.AssertEquals(t, tc.ExpectedResult[url], chain)
			}
		})
	}
}
