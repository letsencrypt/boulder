// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ra

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"testing"

	"github.com/cloudflare/cfssl/signer/local"
	_ "github.com/mattn/go-sqlite3"

	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/jose"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
)

func TestForbiddenIdentifier(t *testing.T) {
	shouldBeAccepted := []string{
		"www.zombo.com",
		"zombo.com",
		"www.163.com", // Technically disallowed (all-numeric label) but actually common.
		"163.com",
		"zom-bo.com",
		"zombo-.com",
		"www.zom-bo.com",
		"www.zombo-.com",
	}
	shouldBeForbidden := []string{
		"127.0.0.1",
		"10.0.0.10",
		"192.168.1.1",
		"123.45.78.12",
		"",
		"0",
		"1",
		"*",
		"**",
		"*.*",
		"zombo*com",
		"*.com",
		"*.zombo.com",
		".",
		"..",
		"a..",
		"..a",
		".a.",
		".....",
		"www.zombo_com.com",
		"\uFEFF", // Byte order mark
		"\uFEFFwww.zombo.com",
		"www.zömbo.com", // No non-ASCII for now.
		"xn--hmr.net",   // No punycode for now.
		"xn--.net",      // No punycode for now.
		"www.xn--hmr.net",
		"www.zom\u202Ebo.com", // Right-to-Left Override
		"\u202Ewww.zombo.com",
		"www.zom\u200Fbo.com", // Right-to-Left Mark
		"\u200Fwww.zombo.com",
		// 6 * 26 characters = too long for DNS label (max 63).
		"www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com",
		// Labels can't start with dash.
		"www.-ombo.com",
		// Underscores are technically disallowed in DNS. Some DNS
		// implementations accept them but we will be conservative.
		"www.zom_bo.com",
		// All-numeric final label not okay.
		"www.zombo.163",
		"zombocom",
		"a.b.c.d.e.f.g.h.i.j.k", // Too many DNS labels
	}

	for _, identifier := range shouldBeForbidden {
		if !forbiddenIdentifier(identifier) {
			t.Error("Identifier was not correctly forbidden: ", identifier)
		}
	}

	for _, identifier := range shouldBeAccepted {
		if forbiddenIdentifier(identifier) {
			t.Error("Identifier was incorrectly forbidden: ", identifier)
		}
	}
}

type DummyValidationAuthority struct {
	Called   bool
	Argument core.Authorization
}

func (dva *DummyValidationAuthority) UpdateValidations(authz core.Authorization) (err error) {
	dva.Called = true
	dva.Argument = authz
	return
}

var (
	// These values we simulate from the client
	AccountKeyJSON = []byte(`{
     "kty": "EC",
     "crv": "P-521",
     "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
     "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
   }`)
	AccountKey = jose.JsonWebKey{}

	AuthzRequest = core.Authorization{
		Identifier: core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: "example.com",
		},
	}

	ResponseIndex = 0
	Response      = core.Challenge{
		Path: "Hf5GrX4Q7EBax9hc2jJnfw",
	}

	ExampleCSR = &x509.CertificateRequest{}

	// These values are populated by the tests as we go
	AuthzInitial  = core.Authorization{}
	AuthzUpdated  = core.Authorization{}
	AuthzFromVA   = core.Authorization{}
	AuthzFinal    = core.Authorization{}
	AuthzFinalWWW = core.Authorization{}
)

func initAuthorities(t *testing.T) (core.CertificateAuthority, *DummyValidationAuthority, *sa.SQLStorageAuthority, core.RegistrationAuthority) {
	err := json.Unmarshal(AccountKeyJSON, &AccountKey)
	test.AssertNotError(t, err, "Failed to unmarshall JWK")

	sa, err := sa.NewSQLStorageAuthority("sqlite3", ":memory:")
	test.AssertNotError(t, err, "Failed to create SA")
	sa.InitTables()

	va := &DummyValidationAuthority{}

	// PEM files in certificate-authority_test.go
	caKeyPEM, _ := pem.Decode([]byte(CA_KEY_PEM))
	caKey, _ := x509.ParsePKCS1PrivateKey(caKeyPEM.Bytes)
	caCertPEM, _ := pem.Decode([]byte(CA_CERT_PEM))
	caCert, _ := x509.ParseCertificate(caCertPEM.Bytes)
	signer, _ := local.NewSigner(caKey, caCert, x509.SHA256WithRSA, nil)
	ca := ca.CertificateAuthorityImpl{Signer: signer, SA: sa}
	csrDER, _ := hex.DecodeString(CSR_HEX)
	ExampleCSR, _ = x509.ParseCertificateRequest(csrDER)

	ra := NewRegistrationAuthorityImpl()
	ra.SA = sa
	ra.VA = va
	ra.CA = &ca

	return &ca, va, sa, &ra
}

func assertAuthzEqual(t *testing.T, a1, a2 core.Authorization) {
	test.Assert(t, a1.ID == a2.ID, "ret != DB: ID")
	test.Assert(t, a1.Identifier == a2.Identifier, "ret != DB: Identifier")
	test.Assert(t, a1.Status == a2.Status, "ret != DB: Status")
	test.Assert(t, a1.Key.Equals(a2.Key), "ret != DB: Key")
	// Not testing: Contact, Challenges
}

func TestNewAuthorization(t *testing.T) {
	_, _, sa, ra := initAuthorities(t)

	authz, err := ra.NewAuthorization(AuthzRequest, AccountKey)
	test.AssertNotError(t, err, "NewAuthorization failed")

	// Verify that returned authz same as DB
	dbAuthz, err := sa.GetAuthorization(authz.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the returned authz has the right information
	test.Assert(t, authz.Key.Equals(AccountKey), "Initial authz did not get the right key")
	test.Assert(t, authz.Identifier == AuthzRequest.Identifier, "Initial authz had wrong identifier")
	test.Assert(t, authz.Status == core.StatusPending, "Initial authz not pending")

	// TODO Verify challenges

	// If we get to here, we'll use this authorization for the next test
	AuthzInitial = authz

	// TODO Test failure cases
	t.Log("DONE TestNewAuthorization")
}

func TestUpdateAuthorization(t *testing.T) {
	_, va, sa, ra := initAuthorities(t)
	AuthzInitial.ID, _ = sa.NewPendingAuthorization()
	sa.UpdatePendingAuthorization(AuthzInitial)

	authz, err := ra.UpdateAuthorization(AuthzInitial, ResponseIndex, Response)
	test.AssertNotError(t, err, "UpdateAuthorization failed")

	// Verify that returned authz same as DB
	dbAuthz, err := sa.GetAuthorization(authz.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the VA got the authz, and it's the same as the others
	test.Assert(t, va.Called, "Authorization was not passed to the VA")
	assertAuthzEqual(t, authz, va.Argument)

	// Verify that the responses are reflected
	test.Assert(t, len(va.Argument.Challenges) > 0, "Authz passed to VA has no challenges")
	simpleHttps := va.Argument.Challenges[0]
	test.Assert(t, simpleHttps.Path == Response.Path, "simpleHttps changed")

	// If we get to here, we'll use this authorization for the next test
	AuthzUpdated = authz

	// TODO Test failure cases
	t.Log("DONE TestUpdateAuthorization")
}

func TestOnValidationUpdate(t *testing.T) {
	_, _, sa, ra := initAuthorities(t)
	AuthzUpdated.ID, _ = sa.NewPendingAuthorization()
	sa.UpdatePendingAuthorization(AuthzUpdated)

	// Simulate a successful simpleHttps challenge
	AuthzFromVA = AuthzUpdated
	AuthzFromVA.Challenges[0].Status = core.StatusValid

	ra.OnValidationUpdate(AuthzFromVA)

	// Verify that the Authz in the DB is the same except for Status->StatusValid
	AuthzFromVA.Status = core.StatusValid
	dbAuthz, err := sa.GetAuthorization(AuthzFromVA.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, AuthzFromVA, dbAuthz)
	t.Log(" ~~> from VA: ", AuthzFromVA.Status)
	t.Log(" ~~> from DB: ", dbAuthz.Status)

	// If we get to here, we'll use this authorization for the next test
	AuthzFinal = dbAuthz

	// TODO Test failure cases
	t.Log("DONE TestOnValidationUpdate")
}

func TestNewCertificate(t *testing.T) {
	_, _, sa, ra := initAuthorities(t)
	AuthzFinal.ID, _ = sa.NewPendingAuthorization()
	sa.UpdatePendingAuthorization(AuthzFinal)
	sa.FinalizeAuthorization(AuthzFinal)

	// Inject another final authorization to cover www.example.com
	AuthzFinalWWW = AuthzFinal
	AuthzFinalWWW.Identifier.Value = "www.example.com"
	AuthzFinalWWW.ID, _ = sa.NewPendingAuthorization()
	sa.FinalizeAuthorization(AuthzFinalWWW)

	// Construct a cert request referencing the two authorizations
	url1, _ := url.Parse("http://doesnt.matter/" + AuthzFinal.ID)
	url2, _ := url.Parse("http://doesnt.matter/" + AuthzFinalWWW.ID)
	certRequest := core.CertificateRequest{
		CSR:            ExampleCSR,
		Authorizations: []core.AcmeURL{core.AcmeURL(*url1), core.AcmeURL(*url2)},
	}

	cert, err := ra.NewCertificate(certRequest, AccountKey)
	test.AssertNotError(t, err, "Failed to issue certificate")

	// Verify that cert shows up and is as expected
	dbCert, err := sa.GetCertificate(cert.ID)
	test.AssertNotError(t, err, "Could not fetch certificate from database")
	test.Assert(t, bytes.Compare(cert.DER, dbCert) == 0, "Certificates differ")

	// TODO Test failure cases
	t.Log("DONE TestOnValidationUpdate")
}

var CA_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
	"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\n" +
	"-----END RSA PRIVATE KEY-----"

var CA_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
	"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\n" +
	"-----END CERTIFICATE-----"

// CSR generated by Go:
// * Random public key
// * CN = example.com
// * DNSNames = example.com, www.example.com
var CSR_HEX = "308202953082017d0201003016311430120603" +
	"550403130b6578616d706c652e636f6d30820122300d06092a864886f70d0101010500038201" +
	"0f003082010a0282010100baaf16e891828470cad87b849a73356f65e20ad3699fd5583a7200" +
	"e924512d9eeb1dbe16441ad7bd804fa2e5726a06f0af5279012fe6354a5677259f5591984aa9" +
	"99b8ea3ea10fbd5ecfa30e5f563b41c419374decfc98ea62c611046ad011c326470a2426f46d" +
	"be6cc44fae3b247e19710810585f9f3ad7f64b2f305aebb72e2829866f89b20b03a300b7ff5f" +
	"4e6204f41420d9fa731252692cee8e616636723abe8a7053fd86e2673190fa8b618ada5bc735" +
	"ba57a145af86904a8f55a288d4d6ba9e501530f23f197f5b623443193fc92b7f87d6abbf740d" +
	"9fc92800c7e0e1484d5eec6ffae1007c139c1ec19d67e749743fe8d8396fe190cfbcf2f90e05" +
	"230203010001a03a303806092a864886f70d01090e312b302930270603551d110420301e820b" +
	"6578616d706c652e636f6d820f7777772e6578616d706c652e636f6d300d06092a864886f70d" +
	"01010b05000382010100514c622dc866b31c86777a26e9b2911618ce5b188591f08007b42772" +
	"3497b733676a7d493c434fc819b8089869442fd299aa99ff7f7b9df881843727f0c8b89ca62a" +
	"f8a12b38c963e9210148c4e1c0fc964aef2605f88ed777e6497d2e43e9a9713835d1ae96260c" +
	"ca826c34c7ae52c77f5d8468643ee1936eadf04e1ebf8bbbb68b0ec7d0ef694432451292e4a3" +
	"1989fd8339c07e01e04b6dd3834872b828d3f5b2b4dadda0596396e15fbdf446998066a74873" +
	"2baf53f3f7ebb849e83cf734753c35ab454d1b62e1741a6514c5c575c0c805b4d668fcf71746" +
	"ef32017613a52d6b807e2977f4fbc0a88b2e263347c4d9e35435333cf4f8288be53df41228ec"
