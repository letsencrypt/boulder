package sa

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/db"
	berrors "github.com/letsencrypt/boulder/errors"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
)

// findIssuedName is a small helper test function to directly query the
// issuedNames table for a given name to find a serial (or return an err).
func findIssuedName(dbMap db.OneSelector, name string) (string, error) {
	var issuedNamesSerial string
	err := dbMap.SelectOne(
		&issuedNamesSerial,
		`SELECT serial FROM issuedNames
		WHERE reversedName = ?
		ORDER BY notBefore DESC
		LIMIT 1`,
		ReverseName(name))
	return issuedNamesSerial, err
}

func TestAddPrecertificate(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	reg := createWorkingRegistration(t, sa)

	addPrecert := func(expectIssuedNamesUpdate bool) {
		// Create a throw-away self signed certificate with a random name and
		// serial number
		serial, testCert := test.ThrowAwayCert(t, 1)

		// Add the cert as a precertificate
		ocspResp := []byte{0, 0, 1}
		regID := reg.Id
		issuedTime := time.Date(2018, 4, 1, 7, 0, 0, 0, time.UTC)
		_, err := sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
			Der:      testCert.Raw,
			RegID:    regID,
			Ocsp:     ocspResp,
			Issued:   issuedTime.UnixNano(),
			IssuerID: 1,
		})
		test.AssertNotError(t, err, "Couldn't add test cert")

		// It should have the expected certificate status
		certStatus, err := sa.GetCertificateStatus(ctx, &sapb.Serial{Serial: serial})
		test.AssertNotError(t, err, "Couldn't get status for test cert")
		test.Assert(
			t,
			bytes.Equal(certStatus.OcspResponse, ocspResp),
			fmt.Sprintf("OCSP responses don't match, expected: %x, got %x", certStatus.OcspResponse, ocspResp),
		)
		test.AssertEquals(t, clk.Now().UnixNano(), certStatus.OcspLastUpdated)

		issuedNamesSerial, err := findIssuedName(sa.dbMap, testCert.DNSNames[0])
		if expectIssuedNamesUpdate {
			// If we expectIssuedNamesUpdate then there should be no err and the
			// expected serial
			test.AssertNotError(t, err, "expected no err querying issuedNames for precert")
			test.AssertEquals(t, issuedNamesSerial, serial)

			// We should also be able to call AddCertificate with the same cert
			// without it being an error. The duplicate err on inserting to
			// issuedNames should be ignored.
			_, err := sa.AddCertificate(ctx, &sapb.AddCertificateRequest{
				Der:    testCert.Raw,
				RegID:  regID,
				Issued: issuedTime.UnixNano(),
			})
			test.AssertNotError(t, err, "unexpected err adding final cert after precert")
		} else {
			// Otherwise we expect an ErrDatabaseOp that indicates NoRows because
			// AddCertificate not AddPrecertificate will be updating this table.
			test.AssertEquals(t, db.IsNoRows(err), true)
		}
	}

	addPrecert(true)
}

func TestAddPreCertificateDuplicate(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	reg := createWorkingRegistration(t, sa)

	_, testCert := test.ThrowAwayCert(t, 1)

	_, err := sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:      testCert.Raw,
		Issued:   clk.Now().UnixNano(),
		RegID:    reg.Id,
		IssuerID: 1,
	})
	test.AssertNotError(t, err, "Couldn't add test certificate")

	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:      testCert.Raw,
		Issued:   clk.Now().UnixNano(),
		RegID:    reg.Id,
		IssuerID: 1,
	})
	test.AssertDeepEquals(t, err, berrors.DuplicateError("cannot add a duplicate cert"))

}

func TestAddPrecertificateIncomplete(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := createWorkingRegistration(t, sa)

	// Create a throw-away self signed certificate with a random name and
	// serial number
	_, testCert := test.ThrowAwayCert(t, 1)

	// Add the cert as a precertificate
	ocspResp := []byte{0, 0, 1}
	regID := reg.Id
	_, err := sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    testCert.Raw,
		RegID:  regID,
		Ocsp:   ocspResp,
		Issued: time.Date(2018, 4, 1, 7, 0, 0, 0, time.UTC).UnixNano(),
		// Leaving out IssuerID
	})

	test.AssertError(t, err, "Adding precert with no issuer did not fail")
}

func TestAddPrecertificateKeyHash(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()
	reg := createWorkingRegistration(t, sa)

	serial, testCert := test.ThrowAwayCert(t, 1)
	_, err := sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:      testCert.Raw,
		RegID:    reg.Id,
		Ocsp:     []byte{1, 2, 3},
		Issued:   testCert.NotBefore.UnixNano(),
		IssuerID: 1,
	})
	test.AssertNotError(t, err, "failed to add precert")

	var keyHashes []keyHashModel
	_, err = sa.dbMap.Select(&keyHashes, "SELECT * FROM keyHashToSerial")
	test.AssertNotError(t, err, "failed to retrieve rows from keyHashToSerial")
	test.AssertEquals(t, len(keyHashes), 1)
	test.AssertEquals(t, keyHashes[0].CertSerial, serial)
	test.AssertEquals(t, keyHashes[0].CertNotAfter, testCert.NotAfter)
	spkiHash := sha256.Sum256(testCert.RawSubjectPublicKeyInfo)
	test.Assert(t, bytes.Equal(keyHashes[0].KeyHash, spkiHash[:]), "spki hash mismatch")
}
