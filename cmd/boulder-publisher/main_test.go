package main

import (
	"crypto/x509"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
)

func setup(t *testing.T) [][]*x509.Certificate {
	// Load a chain with one intermediate
	testIntermediateCert, err := core.LoadCertBundle("test/testIntermediate.pem")
	test.AssertNotError(t, err, "Unable to read test/testIntermediate.pem")

	// Load a chain with two intermediates
	testCA2Cert, err := core.LoadCert("../../test/test-ca2.pem")
	test.AssertNotError(t, err, "Unable to load ../../test/test-ca2.pem")

	testCA2CrossCert, err := core.LoadCert("../../test/test-ca2-cross.pem")
	test.AssertNotError(t, err, "Unable to load ../../test/test-ca2-cross.pem")
	return [][]*x509.Certificate{testIntermediateCert, {testCA2Cert, testCA2CrossCert}}
}

func Test_getBundleForChain(t *testing.T) {
	chains := setup(t)
	loadCertBundleChain := chains[0]
	loadCertChain := chains[1]
	type args struct {
		chain []*x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want []ct.ASN1Cert
	}{
		// Simulating c.Common.CT.IntermediateBundleFilename
		// TODO(5269): Refactor this after all configs have migrated to `Chains`.
		{"One intermediate via core.LoadCertBundle", args{loadCertBundleChain}, []ct.ASN1Cert{{Data: loadCertBundleChain[0].Raw}}},
		// Simulating c.Publisher.Chains
		{"Two intermediates via core.LoadCert", args{loadCertChain}, []ct.ASN1Cert{{Data: loadCertChain[0].Raw}, {Data: loadCertChain[1].Raw}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := getBundleForChain(tt.args.chain)
			test.AssertDeepEquals(t, bundle, tt.want)
		})
	}
}
