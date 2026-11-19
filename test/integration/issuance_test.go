//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/issuancelog"
)

// TestCommonNameInCSR ensures that CSRs which have a CN set result in certs
// with the same CN set.
func TestCommonNameInCSR(t *testing.T) {
	t.Parallel()

	// Create an account.
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Put together some names.
	cn := random_domain()
	san1 := random_domain()
	san2 := random_domain()
	idents := []acme.Identifier{
		{Type: "dns", Value: cn},
		{Type: "dns", Value: san1},
		{Type: "dns", Value: san2},
	}

	// Issue a cert. authAndIssue includes the 0th name as the CN by default.
	ir, err := authAndIssue(client, key, idents, true, "")
	test.AssertNotError(t, err, "failed to issue test cert")
	cert := ir.certs[0]

	// Ensure that the CN is incorporated into the SANs.
	test.AssertSliceContains(t, cert.DNSNames, cn)
	test.AssertSliceContains(t, cert.DNSNames, san1)
	test.AssertSliceContains(t, cert.DNSNames, san2)

	// Ensure that the CN is preserved as the CN.
	test.AssertEquals(t, cert.Subject.CommonName, cn)
}

// TestFirstCSRSANHoistedToCN ensures that CSRs which have no CN set result in
// certs with the first CSR SAN hoisted into the CN field.
func TestFirstCSRSANHoistedToCN(t *testing.T) {
	t.Parallel()

	// Create an account.
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Create some names that we can sort.
	san1 := "a" + random_domain()
	san2 := "b" + random_domain()
	idents := []acme.Identifier{
		{Type: "dns", Value: san2},
		{Type: "dns", Value: san1},
	}

	// Issue a cert using a CSR with no CN set, and the SANs in *non*-alpha order.
	ir, err := authAndIssue(client, key, idents, false, "")
	test.AssertNotError(t, err, "failed to issue test cert")
	cert := ir.certs[0]

	// Ensure that the SANs are correct, and sorted alphabetically.
	test.AssertEquals(t, cert.DNSNames[0], san1)
	test.AssertEquals(t, cert.DNSNames[1], san2)

	// Ensure that the first SAN from the CSR is the CN.
	test.Assert(t, cert.Subject.CommonName == san2, "first SAN should have been hoisted")
}

// TestCommonNameSANsTooLong tests that, when the names in an order and CSR are
// too long to be hoisted into the CN, the correct behavior results.
func TestCommonNameSANsTooLong(t *testing.T) {
	t.Parallel()

	// Create an account.
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Put together some names.
	san1 := fmt.Sprintf("thisdomainnameis.morethan64characterslong.forthesakeoftesting.%s", random_domain())
	san2 := fmt.Sprintf("thisdomainnameis.morethan64characterslong.forthesakeoftesting.%s", random_domain())
	idents := []acme.Identifier{
		{Type: "dns", Value: san1},
		{Type: "dns", Value: san2},
	}

	// Issue a cert using a CSR with no CN set.
	ir, err := authAndIssue(client, key, idents, false, "")
	test.AssertNotError(t, err, "failed to issue test cert")
	cert := ir.certs[0]

	// Ensure that the SANs are correct.
	test.AssertSliceContains(t, cert.DNSNames, san1)
	test.AssertSliceContains(t, cert.DNSNames, san2)

	// Ensure that the CN is empty.
	test.AssertEquals(t, cert.Subject.CommonName, "")
}

// TestIssuanceProfiles verifies that profile selection works, and results in
// measurable differences between certificates issued under different profiles.
// It does not test the omission of the keyEncipherment KU, because all of our
// integration test framework assumes ECDSA pubkeys for the sake of speed,
// and ECDSA certs don't get the keyEncipherment KU in either profile.
func TestIssuanceProfiles(t *testing.T) {
	t.Parallel()

	// Create an account.
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	profiles := client.Directory().Meta.Profiles
	if len(profiles) < 2 {
		t.Fatal("ACME server not advertising multiple profiles")
	}

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Get one cert for each profile that we know the test server advertises.
	res, err := authAndIssue(client, key, []acme.Identifier{{Type: "dns", Value: random_domain()}}, true, "legacy")
	test.AssertNotError(t, err, "failed to issue under legacy profile")
	test.AssertEquals(t, res.Order.Profile, "legacy")
	legacy := res.certs[0]

	res, err = authAndIssue(client, key, []acme.Identifier{{Type: "dns", Value: random_domain()}}, true, "modern")
	test.AssertNotError(t, err, "failed to issue under modern profile")
	test.AssertEquals(t, res.Order.Profile, "modern")
	modern := res.certs[0]

	res, err = authAndIssue(client, key, []acme.Identifier{{Type: "dns", Value: random_domain()}}, true, "shortlived")
	test.AssertNotError(t, err, "failed to issue under shortlived profile")
	test.AssertEquals(t, res.Order.Profile, "shortlived")
	shortlived := res.certs[0]

	// Check that each profile worked as expected.
	test.Assert(t, len(legacy.Subject.CommonName) > 0, "legacy profile should have CN")
	test.AssertEquals(t, modern.Subject.CommonName, "")
	test.AssertEquals(t, shortlived.Subject.CommonName, "")

	test.AssertDeepEquals(t, legacy.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	test.AssertDeepEquals(t, modern.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	test.AssertDeepEquals(t, shortlived.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	test.AssertEquals(t, len(legacy.SubjectKeyId), 20)
	test.AssertEquals(t, len(modern.SubjectKeyId), 0)
	test.AssertEquals(t, len(shortlived.SubjectKeyId), 0)

	test.AssertEquals(t, legacy.NotAfter.Add(time.Second).Sub(legacy.NotBefore), 90*24*time.Hour)
	test.AssertEquals(t, modern.NotAfter.Add(time.Second).Sub(modern.NotBefore), 45*24*time.Hour)
	test.AssertEquals(t, shortlived.NotAfter.Add(time.Second).Sub(shortlived.NotBefore), 160*time.Hour)
}

// TestIssuanceMTC issues from an MTC profile.
func TestIssuanceMTC(t *testing.T) {
	t.Parallel()
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		t.Skip("MTC issuance only available in config-next (due to orders table migrations in boulder_sa_next)")
	}

	client, err := makeClient()
	if err != nil {
		t.Fatalf("creating acme client: %s", err)
	}

	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("generating keypair: %s", err)
	}

	idents := []acme.Identifier{{Type: "dns", Value: random_domain()}}

	ir, err := authAndIssue(client, key, idents, true, "mtcshortlived")
	test.AssertNotError(t, err, "failed to issue test MTC")

	// Ensure that the SANs are correct.
	test.AssertSliceContains(t, ir.certs[0].DNSNames, idents[0].Value)
}

// TestMTCCheckpointMirrored issues a standalone certificate, then checks that
// the mtca's served checkpoint includes the certificate's log entry and that
// the mtpublisher publishes that checkpoint to both sunlight mirrors.
func TestMTCCheckpointMirrored(t *testing.T) {
	t.Parallel()
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		t.Skip("MTC issuance only available in config-next (due to orders table migrations in boulder_sa_next)")
	}

	client, err := makeClient()
	if err != nil {
		t.Fatalf("creating acme client: %s", err)
	}

	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("generating keypair: %s", err)
	}

	ir, err := authAndIssue(client, key, []acme.Identifier{{Type: "dns", Value: random_domain()}}, true, "mtcshortlived")
	if err != nil {
		t.Fatalf("issuing test MTC: %s", err)
	}

	// The certificate's serial number holds the log number and the index of its
	// log entry.
	serial := ir.certs[0].SerialNumber
	if !serial.IsUint64() {
		t.Fatalf("certificate serial number %s is not an unsigned 64-bit integer", serial)
	}
	logNumber, entryIndex, err := core.DecodeMTCSerial(serial.Uint64())
	if err != nil {
		t.Fatalf("decoding certificate serial number %s: %s", serial, err)
	}
	logID, err := issuancelog.Config{CAID: "44947.4.1", LogNumber: logNumber}.Load()
	if err != nil {
		t.Fatalf("loading the issuance log ID: %s", err)
	}

	caCert, err := core.LoadCert("test/certs/webpki/mtca-1.cert.pem")
	if err != nil {
		t.Fatalf("loading the MTCA certificate: %s", err)
	}
	caPubKey, ok := caCert.PublicKey.(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("MTCA certificate public key is %T, want *mldsa.PublicKey", caCert.PublicKey)
	}
	caVerifier, err := cosignature.NewVerifier(logID.CAID(), caPubKey)
	if err != nil {
		t.Fatalf("creating the MTCA verifier: %s", err)
	}

	// The mtcb builds a standalone certificate only once the served checkpoint
	// includes the certificate's subtree, so the served checkpoint is read once,
	// without polling.
	servedURL := "http://boulder-seaweedfs:8333/boulder-mtc-tiles/" + logID.CheckpointPath()
	served, servedNote, err := checkpoint.Open(fetchCheckpoint(t, servedURL), caVerifier)
	if err != nil {
		t.Fatalf("opening the served checkpoint at %s: %s", servedURL, err)
	}
	if len(servedNote.UnverifiedSigs) != 0 {
		t.Errorf("served checkpoint at %s has %d signature lines by other keys, want only the MTCA's", servedURL, len(servedNote.UnverifiedSigs))
	}
	if served.Origin != logID.Origin() {
		t.Fatalf("served checkpoint origin = %q, want %q", served.Origin, logID.Origin())
	}
	if served.Tree.N <= entryIndex {
		t.Fatalf("served checkpoint tree size = %d, want more than the certificate's entry index %d", served.Tree.N, entryIndex)
	}

	monitoringPrefixes := []string{
		"http://boulder-seaweedfs:8333/boulder-sunlight/mirror",
		"http://boulder-seaweedfs:8333/boulder-sunlight2/mirror",
	}
	originHash := sha256.Sum256([]byte(logID.Origin()))
	deadline := time.Now().Add(5 * time.Second)
	for _, monitoringPrefix := range monitoringPrefixes {
		mirrorURL := monitoringPrefix + "/" + hex.EncodeToString(originHash[:]) + "/checkpoint"
		for {
			var mirrorTreeSize int64
			signedNote := fetchCheckpoint(t, mirrorURL)
			if signedNote != nil {
				// Only the note text is read. The signature lines on the
				// mirror checkpoint are sunlight's to get right.
				noteText, _, found := strings.Cut(string(signedNote), "\n\n")
				if !found {
					t.Fatalf("mirror checkpoint at %s has no signature lines: %q", mirrorURL, signedNote)
				}
				var mirrored *checkpoint.Checkpoint
				mirrored, err = checkpoint.Unmarshal([]byte(noteText + "\n"))
				if err != nil {
					t.Fatalf("parsing the mirror checkpoint at %s: %s", mirrorURL, err)
				}
				mirrorTreeSize = mirrored.Tree.N
			}
			// Other tests issue MTCs concurrently, so the mirror checkpoint may
			// already be past the served checkpoint read above.
			if mirrorTreeSize >= served.Tree.N {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("mirror checkpoint at %s has tree size %d, want at least %d", mirrorURL, mirrorTreeSize, served.Tree.N)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// fetchCheckpoint fetches the checkpoint at url, a signed note. It returns nil
// while the checkpoint does not exist yet.
func fetchCheckpoint(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("fetching %s: %s", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %s", url, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetching %s: status %d", url, resp.StatusCode)
	}
	return body
}

// TestIPShortLived verifies that we will allow IP address identifiers only in
// orders that use the shortlived profile.
func TestIPShortLived(t *testing.T) {
	t.Parallel()

	// Create an account.
	client, err := makeClient("mailto:example@letsencrypt.org")
	if err != nil {
		t.Fatalf("creating acme client: %s", err)
	}

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("creating random cert key: %s", err)
	}

	// Create an IP address identifier to request.
	ip := "64.112.117.122"
	idents := []acme.Identifier{
		{Type: "ip", Value: ip},
	}

	// Ensure we fail under each other profile that we know the test server advertises.
	_, err = authAndIssue(client, key, idents, false, "legacy")
	if err == nil {
		t.Error("issued for IP address identifier under legacy profile")
	}
	if !strings.Contains(err.Error(), "Profile \"legacy\" does not permit IP address identifiers") {
		t.Fatalf("issuing under legacy profile failed for the wrong reason: %s", err)
	}

	_, err = authAndIssue(client, key, idents, false, "modern")
	if err == nil {
		t.Error("issued for IP address identifier under modern profile")
	}
	if !strings.Contains(err.Error(), "Profile \"modern\" does not permit IP address identifiers") {
		t.Fatalf("issuing under legacy profile failed for the wrong reason: %s", err)
	}

	// Get one cert for the shortlived profile.
	res, err := authAndIssue(client, key, idents, false, "shortlived")
	if err != nil {
		t.Errorf("issuing under shortlived profile: %s", err)
	}
	if res.Order.Profile != "shortlived" {
		t.Errorf("got '%s' profile, wanted 'shortlived'", res.Order.Profile)
	}
	cert := res.certs[0]

	// Check that the shortlived profile worked as expected.
	if cert.IPAddresses[0].String() != ip {
		t.Errorf("got cert with first IP SAN '%s', wanted '%s'", cert.IPAddresses[0], ip)
	}
}

// TestIPCNRejected verifies that we will reject IP address identifiers when
// they occur in the Subject CommonName.
func TestIPCNRejected(t *testing.T) {
	t.Parallel()

	// Create an account.
	client, err := makeClient("mailto:example@letsencrypt.org")
	if err != nil {
		t.Fatalf("creating acme client: %s", err)
	}

	// Create an IP address identifier to request.
	ip := "64.112.117.122"
	ipParsed := net.ParseIP(ip)
	idents := []acme.Identifier{
		{Type: "ip", Value: ip},
	}

	order, err := client.Client.NewOrderExtension(client.Account, idents, acme.OrderExtension{Profile: "shortlived"})
	if err != nil {
		t.Fatalf("creating order: %s", err)
	}

	if len(order.Authorizations) != 1 {
		t.Fatalf("Got %d authorizations, expected 1", len(order.Authorizations))
	}
	auth, err := client.Client.FetchAuthorization(client.Account, order.Authorizations[0])
	chal, ok := auth.ChallengeMap[acme.ChallengeTypeHTTP01]
	if !ok {
		t.Fatalf("no HTTP challenge at %s", order.Authorizations[0])
	}

	_, err = testSrvClient.AddHTTP01Response(chal.Token, chal.KeyAuthorization)
	if err != nil {
		t.Fatalf("adding HTTP challenge response: %s", err)
	}
	defer testSrvClient.RemoveHTTP01Response(chal.Token)

	chal, err = client.Client.UpdateChallenge(client.Account, chal)
	if err != nil {
		t.Fatalf("updating challenge: %s", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("creating random cert key: %s", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: ip},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          key.Public(),
		IPAddresses:        []net.IP{ipParsed},
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatalf("making csr: %s", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		t.Fatalf("parsing csr: %s", err)
	}

	_, err = client.Client.FinalizeOrder(client.Account, order, csr)
	if err == nil {
		t.Errorf("Finalizing order with IP in CN: got nil error, want badCSR error")
	}
	if !strings.Contains(err.Error(), "CSR contains IP address in Common Name") {
		t.Errorf("issuing with IP in CN failed for the wrong reason: %s", err)
	}

}
