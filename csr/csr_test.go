package csr

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/test"
	oldx509 "github.com/letsencrypt/go/src/crypto/x509"
	"github.com/letsencrypt/go/src/crypto/x509/pkix"
)

var testingPolicy = &goodkey.KeyPolicy{
	AllowRSA:           true,
	AllowECDSANISTP256: true,
	AllowECDSANISTP384: true,
}

type mockPA struct{}

func (pa *mockPA) ChallengesFor(identifier core.AcmeIdentifier) (challenges []core.Challenge, combinations [][]int) {
	return
}

func (pa *mockPA) WillingToIssue(id core.AcmeIdentifier) error {
	if id.Value == "bad-name.com" {
		return errors.New("")
	}
	return nil
}

func TestVerifyCSR(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "error generating test key")
	signedReqBytes, err := oldx509.CreateCertificateRequest(rand.Reader, &oldx509.CertificateRequest{PublicKey: private.PublicKey, SignatureAlgorithm: oldx509.SHA256WithRSA}, private)
	test.AssertNotError(t, err, "error generating test CSR")
	signedReq, err := oldx509.ParseCertificateRequest(signedReqBytes)
	test.AssertNotError(t, err, "error parsing test CSR")
	brokenSignedReq := new(oldx509.CertificateRequest)
	*brokenSignedReq = *signedReq
	brokenSignedReq.Signature = []byte{1, 1, 1, 1}
	signedReqWithHosts := new(oldx509.CertificateRequest)
	*signedReqWithHosts = *signedReq
	signedReqWithHosts.DNSNames = []string{"a.com", "b.com"}
	signedReqWithLongCN := new(oldx509.CertificateRequest)
	*signedReqWithLongCN = *signedReq
	signedReqWithLongCN.Subject.CommonName = strings.Repeat("a", maxCNLength+1)
	signedReqWithBadName := new(oldx509.CertificateRequest)
	*signedReqWithBadName = *signedReq
	signedReqWithBadName.DNSNames = []string{"bad-name.com"}

	cases := []struct {
		csr           *oldx509.CertificateRequest
		maxNames      int
		keyPolicy     *goodkey.KeyPolicy
		pa            core.PolicyAuthority
		regID         int64
		expectedError error
	}{
		{
			&oldx509.CertificateRequest{},
			0,
			testingPolicy,
			&mockPA{},
			0,
			errors.New("invalid public key in CSR"),
		},
		{
			&oldx509.CertificateRequest{PublicKey: private.PublicKey},
			1,
			testingPolicy,
			&mockPA{},
			0,
			errors.New("signature algorithm not supported"),
		},
		{
			brokenSignedReq,
			1,
			testingPolicy,
			&mockPA{},
			0,
			errors.New("invalid signature on CSR"),
		},
		{
			signedReq,
			1,
			testingPolicy,
			&mockPA{},
			0,
			errors.New("at least one DNS name is required"),
		},
		{
			signedReqWithLongCN,
			1,
			testingPolicy,
			&mockPA{},
			0,
			errors.New("CN was longer than 64 bytes"),
		},
		{
			signedReqWithHosts,
			1,
			testingPolicy,
			&mockPA{},
			0,
			errors.New("CSR contains more than 1 DNS names"),
		},
		{
			signedReqWithBadName,
			1,
			testingPolicy,
			&mockPA{},
			0,
			errors.New("policy forbids issuing for: bad-name.com"),
		},
	}

	for _, c := range cases {
		err := VerifyCSR(c.csr, c.maxNames, c.keyPolicy, c.pa, false, c.regID)
		test.AssertDeepEquals(t, c.expectedError, err)
	}
}

func TestNormalizeCSR(t *testing.T) {
	cases := []struct {
		csr           *oldx509.CertificateRequest
		forceCN       bool
		expectedCN    string
		expectedNames []string
	}{
		{
			&oldx509.CertificateRequest{DNSNames: []string{"a.com"}},
			true,
			"a.com",
			[]string{"a.com"},
		},
		{
			&oldx509.CertificateRequest{Subject: pkix.Name{CommonName: "A.com"}, DNSNames: []string{"a.com"}},
			true,
			"a.com",
			[]string{"a.com"},
		},
		{
			&oldx509.CertificateRequest{DNSNames: []string{"a.com"}},
			false,
			"",
			[]string{"a.com"},
		},
		{
			&oldx509.CertificateRequest{DNSNames: []string{"a.com", "a.com"}},
			false,
			"",
			[]string{"a.com"},
		},
		{
			&oldx509.CertificateRequest{Subject: pkix.Name{CommonName: "A.com"}, DNSNames: []string{"B.com"}},
			false,
			"a.com",
			[]string{"a.com", "b.com"},
		},
	}
	for _, c := range cases {
		normalizeCSR(c.csr, c.forceCN)
		test.AssertEquals(t, c.expectedCN, c.csr.Subject.CommonName)
		test.AssertDeepEquals(t, c.expectedNames, c.expectedNames)
	}
}
