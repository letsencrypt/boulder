//go:build integration

package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"
	"golang.org/x/crypto/ocsp"

	"github.com/letsencrypt/boulder/crl/idp"
	"github.com/letsencrypt/boulder/test"
	ocsp_helper "github.com/letsencrypt/boulder/test/ocsp/helper"
)

// isPrecert returns true if the provided cert has an extension with the OID
// equal to OIDExtensionCTPoison.
func isPrecert(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDExtensionCTPoison) {
			return true
		}
	}
	return false
}

// getALLCRLs fetches and parses each certificate for each configured CA.
// Returns a map from issuer SKID (hex) to a list of that issuer's CRLs.
func getAllCRLs(t *testing.T) map[string][]*x509.RevocationList {
	t.Helper()
	b, err := os.ReadFile(path.Join(os.Getenv("BOULDER_CONFIG_DIR"), "ca.json"))
	if err != nil {
		t.Fatalf("reading CA config: %s", err)
	}

	var conf struct {
		CA struct {
			Issuance struct {
				Issuers []struct {
					CRLURLBase string
					Location   struct {
						CertFile string
					}
				}
			}
		}
	}

	err = json.Unmarshal(b, &conf)
	if err != nil {
		t.Fatalf("unmarshaling CA config: %s", err)
	}

	ret := make(map[string][]*x509.RevocationList)

	for _, issuer := range conf.CA.Issuance.Issuers {
		issuerPEMBytes, err := os.ReadFile(issuer.Location.CertFile)
		if err != nil {
			t.Fatalf("reading CRL issuer: %s", err)
		}

		block, _ := pem.Decode(issuerPEMBytes)
		issuerCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing CRL issuer: %s", err)
		}

		issuerSKID := hex.EncodeToString(issuerCert.SubjectKeyId)

		// 10 is the number of shards configured in test/config*/crl-updater.json
		for i := range 10 {
			crlURL := fmt.Sprintf("%s%d.crl", issuer.CRLURLBase, i+1)
			resp, err := http.Get(crlURL)
			if err != nil {
				t.Fatalf("getting CRL from %s: %s", crlURL, err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("fetching %s: status code %d", crlURL, resp.StatusCode)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("reading CRL from %s: %s", crlURL, err)
			}
			resp.Body.Close()

			list, err := x509.ParseRevocationList(body)
			if err != nil {
				t.Fatalf("parsing CRL from %s: %s (bytes: %x)", crlURL, err, body)
			}

			err = list.CheckSignatureFrom(issuerCert)
			if err != nil {
				t.Errorf("checking CRL signature on %s from %s: %s",
					crlURL, issuerCert.Subject, err)
			}

			idpURIs, err := idp.GetIDPURIs(list.Extensions)
			if err != nil {
				t.Fatalf("getting IDP URIs: %s", err)
			}
			if len(idpURIs) != 1 {
				t.Errorf("CRL at %s: expected 1 IDP URI, got %s", crlURL, idpURIs)
			}
			if idpURIs[0] != crlURL {
				t.Errorf("fetched CRL from %s, got IDP of %s (should be same)", crlURL, idpURIs[0])
			}

			ret[issuerSKID] = append(ret[issuerSKID], list)
		}
	}
	return ret
}

func checkRevoked(t *testing.T, revocations map[string][]*x509.RevocationList, cert *x509.Certificate, expectedReason int) {
	t.Helper()
	akid := hex.EncodeToString(cert.AuthorityKeyId)
	if len(revocations[akid]) == 0 {
		t.Errorf("no CRLs found for authorityKeyID %s", akid)
	}
	var matchingCRLs []string
	var count int
	for _, list := range revocations[akid] {
		for _, entry := range list.RevokedCertificateEntries {
			count++
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				idpURIs, err := idp.GetIDPURIs(list.Extensions)
				if err != nil {
					t.Errorf("getting IDP URIs: %s", err)
				}
				idpURI := idpURIs[0]
				if entry.ReasonCode != expectedReason {
					t.Errorf("revoked certificate %x in CRL %s: revocation reason %d, want %d", cert.SerialNumber, idpURI, entry.ReasonCode, expectedReason)
				}
				matchingCRLs = append(matchingCRLs, idpURI)
			}
		}
	}
	if len(matchingCRLs) == 0 {
		t.Errorf("searching for %x in CRLs: no entry on combined CRLs of length %d", cert.SerialNumber, count)
	}

	// If the cert has a CRLDP, it must be listed on the CRL served at that URL.
	if len(cert.CRLDistributionPoints) > 0 {
		expectedCRLDP := cert.CRLDistributionPoints[0]
		found := false
		for _, crl := range matchingCRLs {
			if crl == expectedCRLDP {
				found = true
			}
		}
		if !found {
			t.Errorf("revoked certificate %x: seen on CRLs %s, want to see on CRL %s", cert.SerialNumber, matchingCRLs, expectedCRLDP)
		}
	}
}

// TestRevocation tests that a certificate can be revoked using all of the
// RFC 8555 revocation authentication mechanisms. It does so for both certs and
// precerts (with no corresponding final cert), and for both the Unspecified and
// keyCompromise revocation reasons.
func TestRevocation(t *testing.T) {
	t.Parallel()

	type authMethod string
	var (
		byAccount authMethod = "byAccount"
		byAuth    authMethod = "byAuth"
		byKey     authMethod = "byKey"
	)

	type certKind string
	var (
		finalcert certKind = "cert"
		precert   certKind = "precert"
	)

	type testCase struct {
		method authMethod
		reason int
		kind   certKind
	}

	issueAndRevoke := func(tc testCase) *x509.Certificate {
		issueClient, err := makeClient()
		test.AssertNotError(t, err, "creating acme client")

		certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		test.AssertNotError(t, err, "creating random cert key")

		domain := fmt.Sprintf("%s.%s.%d.revokeme.%s", tc.kind, tc.method, tc.reason, random_domain())

		// Try to issue a certificate for the name.
		var cert *x509.Certificate
		switch tc.kind {
		case finalcert:
			res, err := authAndIssue(issueClient, certKey, []string{domain}, true)
			test.AssertNotError(t, err, "authAndIssue failed")
			cert = res.certs[0]

		case precert:
			// Make sure the ct-test-srv will reject generating SCTs for the domain,
			// so we only get a precert and no final cert.
			err := ctAddRejectHost(domain)
			test.AssertNotError(t, err, "adding ct-test-srv reject host")

			_, err = authAndIssue(issueClient, certKey, []string{domain}, true)
			test.AssertError(t, err, "expected error from authAndIssue, was nil")
			if !strings.Contains(err.Error(), "urn:ietf:params:acme:error:serverInternal") ||
				!strings.Contains(err.Error(), "SCT embedding") {
				t.Fatal(err)
			}

			// Instead recover the precertificate from CT.
			cert, err = ctFindRejection([]string{domain})
			if err != nil || cert == nil {
				t.Fatalf("couldn't find rejected precert for %q", domain)
			}
			// And make sure the cert we found is in fact a precert.
			if !isPrecert(cert) {
				t.Fatal("precert was missing poison extension")
			}

		default:
			t.Fatalf("unrecognized cert kind %q", tc.kind)
		}

		// Initially, the cert should have a Good OCSP response.
		ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Good)
		_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
		test.AssertNotError(t, err, "requesting OCSP for precert")

		// Set up the account and key that we'll use to revoke the cert.
		var revokeClient *client
		var revokeKey crypto.Signer
		switch tc.method {
		case byAccount:
			// When revoking by account, use the same client and key as were used
			// for the original issuance.
			revokeClient = issueClient
			revokeKey = revokeClient.PrivateKey

		case byAuth:
			// When revoking by auth, create a brand new client, authorize it for
			// the same domain, and use that account and key for revocation. Ignore
			// errors from authAndIssue because all we need is the auth, not the
			// issuance.
			revokeClient, err = makeClient()
			test.AssertNotError(t, err, "creating second acme client")
			_, _ = authAndIssue(revokeClient, certKey, []string{domain}, true)
			revokeKey = revokeClient.PrivateKey

		case byKey:
			// When revoking by key, create a brand new client and use it with
			// the cert's key for revocation.
			revokeClient, err = makeClient()
			test.AssertNotError(t, err, "creating second acme client")
			revokeKey = certKey

		default:
			t.Fatalf("unrecognized revocation method %q", tc.method)
		}

		// Revoke the cert using the specified key and client.
		err = revokeClient.RevokeCertificate(
			revokeClient.Account,
			cert,
			revokeKey,
			tc.reason,
		)
		test.AssertNotError(t, err, "revocation should have succeeded")

		return cert
	}

	// revocationCheck represents a deferred that a specific certificate is revoked.
	//
	// We defer these checks for performance reasons: we want to run crl-updater once,
	// after all certificates have been revoked.
	type revocationCheck func(t *testing.T, allCRLs map[string][]*x509.RevocationList)
	var revocationChecks []revocationCheck
	var rcMu sync.Mutex
	var wg sync.WaitGroup

	for _, kind := range []certKind{precert, finalcert} {
		for _, reason := range []int{ocsp.Unspecified, ocsp.KeyCompromise} {
			for _, method := range []authMethod{byAccount, byAuth, byKey} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					cert := issueAndRevoke(testCase{
						method: method,
						reason: reason,
						kind:   kind,
						// We do not expect any of these revocation requests to error.
						// The ones done byAccount will succeed as requested, but will not
						// result in the key being blocked for future issuance.
						// The ones done byAuth will succeed, but will be overwritten to have
						// reason code 5 (cessationOfOperation).
						// The ones done byKey will succeed, but will be overwritten to have
						// reason code 1 (keyCompromise), and will block the key.
					})

					// If the request was made by demonstrating control over the
					// names, the reason should be overwritten to CessationOfOperation (5),
					// and if the request was made by key, then the reason should be set to
					// KeyCompromise (1).
					expectedReason := reason
					switch method {
					case byAuth:
						expectedReason = ocsp.CessationOfOperation
					case byKey:
						expectedReason = ocsp.KeyCompromise
					default:
					}

					check := func(t *testing.T, allCRLs map[string][]*x509.RevocationList) {
						_, err := ocsp_helper.ReqDER(cert.Raw, ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked).WithExpectReason(expectedReason))
						test.AssertNotError(t, err, "requesting OCSP for revoked cert")

						checkRevoked(t, allCRLs, cert, expectedReason)
					}

					rcMu.Lock()
					revocationChecks = append(revocationChecks, check)
					rcMu.Unlock()
				}()
			}
		}
	}

	wg.Wait()

	runUpdater(t, path.Join(os.Getenv("BOULDER_CONFIG_DIR"), "crl-updater.json"))
	allCRLs := getAllCRLs(t)

	for _, check := range revocationChecks {
		check(t, allCRLs)
	}
}

// TestReRevocation verifies that a certificate can have its revocation
// information updated only when both of the following are true:
// a) The certificate was not initially revoked for reason keyCompromise; and
// b) The second request is authenticated using the cert's keypair.
// In which case the revocation reason (but not revocation date) will be
// updated to be keyCompromise.
func TestReRevocation(t *testing.T) {
	t.Parallel()

	type authMethod string
	var (
		byAccount authMethod = "byAccount"
		byKey     authMethod = "byKey"
	)

	type testCase struct {
		method1     authMethod
		reason1     int
		method2     authMethod
		reason2     int
		expectError bool
	}

	testCases := []testCase{
		{method1: byAccount, reason1: 0, method2: byAccount, reason2: 0, expectError: true},
		{method1: byAccount, reason1: 1, method2: byAccount, reason2: 1, expectError: true},
		{method1: byAccount, reason1: 0, method2: byKey, reason2: 1, expectError: false},
		{method1: byAccount, reason1: 1, method2: byKey, reason2: 1, expectError: true},
		{method1: byKey, reason1: 1, method2: byKey, reason2: 1, expectError: true},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			issueClient, err := makeClient()
			test.AssertNotError(t, err, "creating acme client")

			certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			test.AssertNotError(t, err, "creating random cert key")

			// Try to issue a certificate for the name.
			domain := random_domain()
			res, err := authAndIssue(issueClient, certKey, []string{domain}, true)
			test.AssertNotError(t, err, "authAndIssue failed")
			cert := res.certs[0]

			// Initially, the cert should have a Good OCSP response.
			ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Good)
			_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			test.AssertNotError(t, err, "requesting OCSP for precert")

			// Set up the account and key that we'll use to revoke the cert.
			var revokeClient *client
			var revokeKey crypto.Signer
			switch tc.method1 {
			case byAccount:
				// When revoking by account, use the same client and key as were used
				// for the original issuance.
				revokeClient = issueClient
				revokeKey = revokeClient.PrivateKey

			case byKey:
				// When revoking by key, create a brand new client and use it with
				// the cert's key for revocation.
				revokeClient, err = makeClient()
				test.AssertNotError(t, err, "creating second acme client")
				revokeKey = certKey

			default:
				t.Fatalf("unrecognized revocation method %q", tc.method1)
			}

			// Revoke the cert using the specified key and client.
			err = revokeClient.RevokeCertificate(
				revokeClient.Account,
				cert,
				revokeKey,
				tc.reason1,
			)
			test.AssertNotError(t, err, "initial revocation should have succeeded")

			// Check the OCSP response for the certificate again. It should now be
			// revoked.
			ocspConfig = ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked).WithExpectReason(tc.reason1)
			_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			test.AssertNotError(t, err, "requesting OCSP for revoked cert")

			// Set up the account and key that we'll use to *re*-revoke the cert.
			switch tc.method2 {
			case byAccount:
				// When revoking by account, use the same client and key as were used
				// for the original issuance.
				revokeClient = issueClient
				revokeKey = revokeClient.PrivateKey

			case byKey:
				// When revoking by key, create a brand new client and use it with
				// the cert's key for revocation.
				revokeClient, err = makeClient()
				test.AssertNotError(t, err, "creating second acme client")
				revokeKey = certKey

			default:
				t.Fatalf("unrecognized revocation method %q", tc.method2)
			}

			// Re-revoke the cert using the specified key and client.
			err = revokeClient.RevokeCertificate(
				revokeClient.Account,
				cert,
				revokeKey,
				tc.reason2,
			)

			switch tc.expectError {
			case true:
				test.AssertError(t, err, "second revocation should have failed")

				// Check the OCSP response for the certificate again. It should still be
				// revoked, with the same reason.
				ocspConfig = ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked).WithExpectReason(tc.reason1)
				_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
				test.AssertNotError(t, err, "requesting OCSP for revoked cert")

			case false:
				test.AssertNotError(t, err, "second revocation should have succeeded")

				// Check the OCSP response for the certificate again. It should now be
				// revoked with reason keyCompromise.
				ocspConfig = ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked).WithExpectReason(tc.reason2)
				_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
				test.AssertNotError(t, err, "requesting OCSP for revoked cert")
			}
		})
	}
}

func TestRevokeWithKeyCompromiseBlocksKey(t *testing.T) {
	t.Parallel()

	type authMethod string
	var (
		byAccount authMethod = "byAccount"
		byKey     authMethod = "byKey"
	)

	// Test keyCompromise revocation both when revoking by certificate key and
	// revoking by subscriber key. Both should work, although with slightly
	// different behavior.
	for _, method := range []authMethod{byKey, byAccount} {
		c, err := makeClient("mailto:example@letsencrypt.org")
		test.AssertNotError(t, err, "creating acme client")

		certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		test.AssertNotError(t, err, "failed to generate cert key")

		res, err := authAndIssue(c, certKey, []string{random_domain()}, true)
		test.AssertNotError(t, err, "authAndIssue failed")
		cert := res.certs[0]

		// Revoke the cert with reason keyCompromise, either authenticated via the
		// issuing account, or via the certificate key itself.
		switch method {
		case byAccount:
			err = c.RevokeCertificate(c.Account, cert, c.PrivateKey, ocsp.KeyCompromise)
		case byKey:
			err = c.RevokeCertificate(acme.Account{}, cert, certKey, ocsp.KeyCompromise)
		}
		test.AssertNotError(t, err, "failed to revoke certificate")

		// Check the OCSP response. It should be revoked with reason = 1 (keyCompromise).
		ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked).WithExpectReason(ocsp.KeyCompromise)
		_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
		test.AssertNotError(t, err, "requesting OCSP for revoked cert")

		// Attempt to create a new account using the compromised key. This should
		// work when the key was just *reported* as compromised, but fail when
		// the compromise was demonstrated/proven.
		_, err = c.NewAccount(certKey, false, true)
		switch method {
		case byAccount:
			test.AssertNotError(t, err, "NewAccount failed with a non-blocklisted key")
		case byKey:
			test.AssertError(t, err, "NewAccount didn't fail with a blocklisted key")
			test.AssertEquals(t, err.Error(), `acme: error code 400 "urn:ietf:params:acme:error:badPublicKey": public key is forbidden`)
		}
	}
}

func TestBadKeyRevoker(t *testing.T) {
	// Both accounts have two email addresses, one of which is shared between
	// them. All three addresses should receive mail, because the revocation
	// request is signed by the certificate key, not an account key, so we don't
	// know who requested the revocation. Finally, a third account with no address
	// to ensure the bad-key-revoker handles that gracefully.
	revokerClient, err := makeClient("mailto:revoker@letsencrypt.org", "mailto:shared@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	revokeeClient, err := makeClient("mailto:shared@letsencrypt.org", "mailto:revokee@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	noContactClient, err := makeClient()
	test.AssertNotError(t, err, "creating acme client")

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate cert key")

	res, err := authAndIssue(revokerClient, certKey, []string{random_domain()}, true)
	test.AssertNotError(t, err, "authAndIssue failed")
	badCert := res.certs[0]
	t.Logf("Generated to-be-revoked cert with serial %x", badCert.SerialNumber)

	certs := []*x509.Certificate{}
	for _, c := range []*client{revokerClient, revokeeClient, noContactClient} {
		cert, err := authAndIssue(c, certKey, []string{random_domain()}, true)
		t.Logf("TestBadKeyRevoker: Issued cert with serial %x", cert.certs[0].SerialNumber)
		test.AssertNotError(t, err, "authAndIssue failed")
		certs = append(certs, cert.certs[0])
	}

	err = revokerClient.RevokeCertificate(
		acme.Account{},
		badCert,
		certKey,
		ocsp.KeyCompromise,
	)
	test.AssertNotError(t, err, "failed to revoke certificate")

	ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked).WithExpectReason(ocsp.KeyCompromise)
	_, err = ocsp_helper.ReqDER(badCert.Raw, ocspConfig)
	test.AssertNotError(t, err, "ReqDER failed")

	for _, cert := range certs {
		for i := range 5 {
			t.Logf("TestBadKeyRevoker: Requesting OCSP for cert with serial %x (attempt %d)", cert.SerialNumber, i)
			_, err := ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			if err != nil {
				t.Logf("TestBadKeyRevoker: Got bad response: %s", err.Error())
				if i >= 4 {
					t.Fatal("timed out waiting for correct OCSP status")
				}
				time.Sleep(time.Second)
				continue
			}
			break
		}
	}

	revokeeCount, err := http.Get("http://boulder.service.consul:9381/count?to=revokee@letsencrypt.org&from=bad-key-revoker@test.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = revokeeCount.Body.Close() }()
	body, err := io.ReadAll(revokeeCount.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "1\n")

	revokerCount, err := http.Get("http://boulder.service.consul:9381/count?to=revoker@letsencrypt.org&from=bad-key-revoker@test.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = revokerCount.Body.Close() }()
	body, err = io.ReadAll(revokerCount.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "1\n")

	sharedCount, err := http.Get("http://boulder.service.consul:9381/count?to=shared@letsencrypt.org&from=bad-key-revoker@test.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = sharedCount.Body.Close() }()
	body, err = io.ReadAll(sharedCount.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "1\n")
}

func TestBadKeyRevokerByAccount(t *testing.T) {
	// Both accounts have two email addresses, one of which is shared between
	// them. No accounts should receive any mail, because the revocation request
	// is signed by the account key (not the cert key) and so will not be
	// propagated to other certs sharing the same key.
	revokerClient, err := makeClient("mailto:revoker-moz@letsencrypt.org", "mailto:shared-moz@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	revokeeClient, err := makeClient("mailto:shared-moz@letsencrypt.org", "mailto:revokee-moz@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	noContactClient, err := makeClient()
	test.AssertNotError(t, err, "creating acme client")

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate cert key")

	res, err := authAndIssue(revokerClient, certKey, []string{random_domain()}, true)
	test.AssertNotError(t, err, "authAndIssue failed")
	badCert := res.certs[0]
	t.Logf("Generated to-be-revoked cert with serial %x", badCert.SerialNumber)

	certs := []*x509.Certificate{}
	for _, c := range []*client{revokerClient, revokeeClient, noContactClient} {
		cert, err := authAndIssue(c, certKey, []string{random_domain()}, true)
		t.Logf("TestBadKeyRevokerByAccount: Issued cert with serial %x", cert.certs[0].SerialNumber)
		test.AssertNotError(t, err, "authAndIssue failed")
		certs = append(certs, cert.certs[0])
	}

	err = revokerClient.RevokeCertificate(
		revokerClient.Account,
		badCert,
		revokerClient.PrivateKey,
		ocsp.KeyCompromise,
	)
	test.AssertNotError(t, err, "failed to revoke certificate")

	ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked).WithExpectReason(ocsp.KeyCompromise)
	_, err = ocsp_helper.ReqDER(badCert.Raw, ocspConfig)
	test.AssertNotError(t, err, "ReqDER failed")

	ocspConfig = ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Good)
	for _, cert := range certs {
		for i := range 5 {
			t.Logf("TestBadKeyRevoker: Requesting OCSP for cert with serial %x (attempt %d)", cert.SerialNumber, i)
			_, err := ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			if err != nil {
				t.Logf("TestBadKeyRevoker: Got bad response: %s", err.Error())
				if i >= 4 {
					t.Fatal("timed out waiting for correct OCSP status")
				}
				time.Sleep(time.Second)
				continue
			}
			break
		}
	}

	revokeeCount, err := http.Get("http://boulder.service.consul:9381/count?to=revokee-moz@letsencrypt.org&from=bad-key-revoker@test.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = revokeeCount.Body.Close() }()
	body, err := io.ReadAll(revokeeCount.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "0\n")

	revokerCount, err := http.Get("http://boulder.service.consul:9381/count?to=revoker-moz@letsencrypt.org&from=bad-key-revoker@test.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = revokerCount.Body.Close() }()
	body, err = io.ReadAll(revokerCount.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "0\n")

	sharedCount, err := http.Get("http://boulder.service.consul:9381/count?to=shared-moz@letsencrypt.org&from=bad-key-revoker@test.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = sharedCount.Body.Close() }()
	body, err = io.ReadAll(sharedCount.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "0\n")
}
