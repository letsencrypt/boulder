// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/cloudflare/cfssl/signer/local"
	_ "github.com/mattn/go-sqlite3"

	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
)

var CA_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
	"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\n" +
	"-----END RSA PRIVATE KEY-----"

var CA_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
	"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\n" +
	"-----END CERTIFICATE-----"

// CSR generated by Go:
// * Random public key
// * CN = not-example.com
// * DNSNames = not-example.com
var CSR_HEX = "3082028c30820174020100301a311830160603550403130f" +
	"6e6f742d6578616d706c652e636f6d30820122300d06092a" +
	"864886f70d01010105000382010f003082010a0282010100" +
	"aac67dd1e11fae980048b0ac91be005f21d9df8bb38461cc" +
	"a7dfad601a00e91ae488c240a03ec53a5752a33d837d2d9c" +
	"357c6a99ea7e55fe75482524480bb367aa85f75541bd0284" +
	"ede1ab9b54925a5c9f88d08f9dc857ee707a59d3503b31ea" +
	"64e42099acd70d2204c872ef49983e44cc2bc24389159fc5" +
	"f6ca41b80540fb7a2fbf8aa43af7f539782f20f185d416cc" +
	"66a88e5f8913a292b4a217e5b12e8244a9686af3b49ac88b" +
	"215c6eb097c4befa3e66257a1358791e2bc471c18ba2ca6e" +
	"161d2dcb53ebcb06e6b4b2e6cd42ff970581bc4971009cbd" +
	"7ccc3f89648db720e2908a1be613a9c3afb46b477261c1bc" +
	"c057bc749a102e6bd9dc45d87b2d97c50203010001a02d30" +
	"2b06092a864886f70d01090e311e301c301a0603551d1104" +
	"133011820f6e6f742d6578616d706c652e636f6d300d0609" +
	"2a864886f70d01010b05000382010100a37025c2cb88b4fa" +
	"f3c8417820a78a069b92cef45a3d2f3fbd18f41a07128258" +
	"38bc55e6c1c416e5f34c365924391294741c23657ffa77e4" +
	"aa3d589b560cbb9156aae175637cbb5061d69eefa7f432ca" +
	"c9e4d03feaa367954cf6986a72ca76307c01852db72b43ae" +
	"5ab7f673b81b58e06d8af1f681cd7c88d2fbc8c80d592a3f" +
	"7c3ea20035b73c8e6afc8daea4d168fe469f7da9e4bac660" +
	"fc207d1d93dce118dc7381e69fa4af37bb4d4d6d5342fa55" +
	"7798a363aa04cf350ad1748e96eabee04fa379dd98524ea1" +
	"53f07e1654e6077f4aaaf5c5b27edaf0385b48e0fc281424" +
	"6363a01370c89e666169276eb133731cff2379d46d2fff9d" +
	"f277b6d23fa24f9b"

func TestIssueCertificate(t *testing.T) {
	// Decode pre-generated values
	caKeyPEM, _ := pem.Decode([]byte(CA_KEY_PEM))
	caKey, _ := x509.ParsePKCS1PrivateKey(caKeyPEM.Bytes)

	caCertPEM, _ := pem.Decode([]byte(CA_CERT_PEM))
	caCert, _ := x509.ParseCertificate(caCertPEM.Bytes)

	csrDER, _ := hex.DecodeString(CSR_HEX)
	csr, _ := x509.ParseCertificateRequest(csrDER)

	// Create a CFSSL local signer
	signer, _ := local.NewSigner(caKey, caCert, x509.SHA256WithRSA, nil)

	// Create an SA
	sa, err := sa.NewSQLStorageAuthority("sqlite3", ":memory:")
	test.AssertNotError(t, err, "Failed to create SA")
	sa.InitTables()

	// Create a CA
	/*
		// Uncomment to test with a remote signer
		ca, err := NewCertificateAuthorityImpl("localhost:9000", "79999d86250c367a2b517a1ae7d409c1", "ee")
		test.AssertNotError(t, err, "Failed to create CA")
		ca.SA = sa
	*/
	ca := CertificateAuthorityImpl{
		Signer: signer,
		SA:     sa,
		PA:     policy.NewPolicyAuthorityImpl(),
	}

	// Sign CSR
	certObj, err := ca.IssueCertificate(*csr)
	test.AssertNotError(t, err, "Failed to sign certificate")

	// Verify cert contents
	cert, err := x509.ParseCertificate(certObj.DER)
	test.AssertNotError(t, err, "Certificate failed to parse")

	test.AssertEquals(t, cert.Subject.CommonName, "not-example.com")

	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "not-example.com" {
		t.Errorf("Improper list of domain names %v", cert.DNSNames)
	}

	// Verify that the cert got stored in the DB
	_, err = sa.GetCertificate(certObj.ID)
	test.AssertNotError(t, err, "Certificate not found in database")
}
