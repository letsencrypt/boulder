package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

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

	// Make a .pem file that is test-ca2.pem but with Windows/DOS CRLF line
	// endings
	crlfPEM, _ := ioutil.TempFile("", "crlf.pem")
	crlfPEMBytes := []byte(strings.Replace(string(certBytesB), "\n", "\r\n", -1))
	err = ioutil.WriteFile(crlfPEM.Name(), crlfPEMBytes, 0640)
	test.AssertNotError(t, err, "ioutil.WriteFile failed")

	// Make a .pem file that is test-ca.pem but with no trailing newline
	abruptPEM, _ := ioutil.TempFile("", "abrupt.pem")
	abruptPEMBytes := certBytesA[:len(certBytesA)-1]
	err = ioutil.WriteFile(abruptPEM.Name(), abruptPEMBytes, 0640)
	test.AssertNotError(t, err, "ioutil.WriteFile failed")

	testCases := []struct {
		Name           string
		Input          map[string][]string
		ExpectedResult map[string][]byte
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
			ExpectedError: fmt.Errorf(
				"CertificateChain entry for AIA issuer url \"http://break.the.chain.com\" " +
					"has no chain file names configured"),
		},
		{
			Name: "Missing chain file",
			Input: map[string][]string{
				"http://where.is.my.mind": []string{"/tmp/does.not.exist.pem"},
			},
			ExpectedResult: nil,
			ExpectedError: fmt.Errorf("CertificateChain entry for AIA issuer url \"http://where.is.my.mind\" " +
				"has an invalid chain file: \"/tmp/does.not.exist.pem\" - error reading " +
				"contents: open /tmp/does.not.exist.pem: no such file or directory"),
		},
		{
			Name: "PEM chain file with Windows CRLF line endings",
			Input: map[string][]string{
				"http://windows.sad.zone": []string{crlfPEM.Name()},
			},
			ExpectedResult: nil,
			ExpectedError: fmt.Errorf("CertificateChain entry for AIA issuer url \"http://windows.sad.zone\" "+
				"has an invalid chain file: %q - contents had CRLF line endings", crlfPEM.Name()),
		},
		{
			Name: "Invalid PEM chain file",
			Input: map[string][]string{
				"http://ok.go": []string{invalidPEMFile.Name()},
			},
			ExpectedResult: nil,
			ExpectedError: fmt.Errorf(
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
			ExpectedError: fmt.Errorf(
				"CertificateChain entry for AIA issuer url \"http://not-a-cert.com\" has " +
					"an invalid chain file: \"../../test/test-root.key\" - PEM block type " +
					"incorrect, found \"PRIVATE KEY\", expected \"CERTIFICATE\""),
		},
		{
			Name: "PEM chain file with leftover bytes",
			Input: map[string][]string{
				"http://tasty.leftovers.com": []string{leftoverPEMFile.Name()},
			},
			ExpectedResult: nil,
			ExpectedError: fmt.Errorf(
				"CertificateChain entry for AIA issuer url \"http://tasty.leftovers.com\" "+
					"has an invalid chain file: %q - PEM contents had unused remainder input "+
					"(%d bytes)",
				leftoverPEMFile.Name(),
				len([]byte(leftovers)),
			),
		},
		{
			Name: "One PEM file chain",
			Input: map[string][]string{
				"http://single-cert-chain.com": []string{"../../test/test-ca.pem"},
			},
			ExpectedResult: map[string][]byte{
				"http://single-cert-chain.com": []byte(fmt.Sprintf("\n%s", string(certBytesA))),
			},
			ExpectedError: nil,
		},
		{
			Name: "Two PEM file chain",
			Input: map[string][]string{
				"http://two-cert-chain.com": []string{"../../test/test-ca.pem", "../../test/test-ca2.pem"},
			},
			ExpectedResult: map[string][]byte{
				"http://two-cert-chain.com": []byte(fmt.Sprintf("\n%s\n%s", string(certBytesA), string(certBytesB))),
			},
			ExpectedError: nil,
		},
		{
			Name: "One PEM file chain, no trailing newline",
			Input: map[string][]string{
				"http://single-cert-chain.nonewline.com": []string{abruptPEM.Name()},
			},
			ExpectedResult: map[string][]byte{
				// NOTE(@cpu): There should be a trailing \n added by the WFE that we
				// expect in the format specifier below.
				"http://single-cert-chain.nonewline.com": []byte(fmt.Sprintf("\n%s\n", string(abruptPEMBytes))),
			},
			ExpectedError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result, err := loadCertificateChains(tc.Input)
			if tc.ExpectedError == nil && err != nil {
				t.Errorf("Expected nil error, got %#v\n", err)
			} else if tc.ExpectedError != nil && err == nil {
				t.Errorf("Expected non-nil error, got nil err")
			} else if tc.ExpectedError != nil {
				test.AssertEquals(t, err.Error(), tc.ExpectedError.Error())
			}
			test.AssertEquals(t, len(result), len(tc.ExpectedResult))
			for url, chain := range result {
				test.Assert(t, bytes.Compare(chain, tc.ExpectedResult[url]) == 0, "Chain bytes did not match expected")
			}
		})
	}
}
