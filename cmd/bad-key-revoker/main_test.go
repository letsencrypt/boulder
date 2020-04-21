package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/mocks"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
	"google.golang.org/grpc"
)

func TestMain(m *testing.M) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSelectUncheckedRows(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	bkr := &badKeyRevoker{dbMap: dbMap, uncheckedBatchSize: 1}

	hashA := make([]byte, 32)
	hashA[0] = 1
	hashB := make([]byte, 32)
	hashB[0] = 2
	hashC := make([]byte, 32)
	hashC[0] = 3
	_, err = dbMap.Exec(`INSERT INTO blockedKeys
		(keyHash, added, source, revokedBy, extantCertificatesChecked)
		VALUES
		(?, ?, ?, ?, ?)`,
		hashA,
		time.Now(),
		"API",
		1,
		false,
	)
	test.AssertNotError(t, err, "failed to add test row")
	_, err = dbMap.Exec(`INSERT INTO blockedKeys
		(keyHash, added, source, revokedBy, extantCertificatesChecked)
		VALUES
		(?, ?, ?, ?, ?)`,
		hashB,
		time.Now(),
		"API",
		2,
		false,
	)
	test.AssertNotError(t, err, "failed to add test row")
	_, err = dbMap.Exec(`INSERT INTO blockedKeys
		(keyHash, added, source, revokedBy, extantCertificatesChecked)
		VALUES
		(?, ?, ?, ?, ?)`,
		hashC,
		time.Now(),
		"API",
		2,
		true,
	)
	test.AssertNotError(t, err, "failed to add test row")

	rows, err := bkr.selectUncheckedRows()
	test.AssertNotError(t, err, "selectUncheckedRows failed")
	test.AssertEquals(t, len(rows), 2)
	test.AssertByteEquals(t, rows[0].KeyHash, hashA)
	test.AssertEquals(t, rows[0].RevokedBy, int64(1))
	test.AssertByteEquals(t, rows[1].KeyHash, hashB)
	test.AssertEquals(t, rows[1].RevokedBy, int64(2))
}

func TestFindUnrevoked(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	res, err := dbMap.Exec(
		"INSERT INTO registrations (jwk, jwk_sha256, contact, agreement, initialIP, createdAt, status, LockCol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		[]byte{},
		"ff",
		"[]",
		"yes",
		[]byte{},
		time.Now(),
		string(core.StatusValid),
		0,
	)
	test.AssertNotError(t, err, "failed to insert test registrations row")
	regID, err := res.LastInsertId()
	test.AssertNotError(t, err, "failed to get registration ID")

	bkr := &badKeyRevoker{dbMap: dbMap, certificatesBatchSize: 1}

	hashA := make([]byte, 32)
	hashA[0] = 1
	_, err = dbMap.Exec(
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		hashA,
		time.Now(),
		"ff",
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")
	_, err = dbMap.Exec(
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		hashA,
		time.Now(),
		"ee",
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")
	_, err = dbMap.Exec(
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		hashA,
		time.Now(),
		"dd",
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")
	_, err = dbMap.Exec(
		"INSERT INTO certificateStatus (serial, status, isExpired, ocspLAstUpdated, revokedDate, revokedReason, lastExpirationNagSent) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"ff",
		string(core.StatusValid),
		false,
		time.Now(),
		time.Time{},
		0,
		time.Time{},
	)
	test.AssertNotError(t, err, "failed to insert test certificateStatus row")
	_, err = dbMap.Exec(
		"INSERT INTO certificates (serial, registrationID, der, digest, issued, expires) VALUES (?, ?, ?, ?, ?, ?)",
		"ff",
		regID,
		[]byte{1, 2, 3},
		[]byte{},
		time.Now(),
		time.Now(),
	)
	test.AssertNotError(t, err, "failed to insert test certificates row")
	_, err = dbMap.Exec(
		"INSERT INTO certificateStatus (serial, status, isExpired, ocspLAstUpdated, revokedDate, revokedReason, lastExpirationNagSent) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"ee",
		string(core.StatusValid),
		true,
		time.Now(),
		time.Time{},
		0,
		time.Time{},
	)
	test.AssertNotError(t, err, "failed to insert test certificateStatus row")
	_, err = dbMap.Exec(
		"INSERT INTO certificates (serial, registrationID, der, digest, issued, expires) VALUES (?, ?, ?, ?, ?, ?)",
		"ee",
		regID,
		[]byte{1, 2, 3},
		[]byte{},
		time.Now(),
		time.Now(),
	)
	test.AssertNotError(t, err, "failed to insert test certificates row")
	_, err = dbMap.Exec(
		"INSERT INTO certificateStatus (serial, status, isExpired, ocspLAstUpdated, revokedDate, revokedReason, lastExpirationNagSent) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"dd",
		string(core.StatusRevoked),
		false,
		time.Now(),
		time.Time{},
		0,
		time.Time{},
	)
	test.AssertNotError(t, err, "failed to insert test certificateStatus row")
	_, err = dbMap.Exec(
		"INSERT INTO certificates (serial, registrationID, der, digest, issued, expires) VALUES (?, ?, ?, ?, ?, ?)",
		"dd",
		regID,
		[]byte{1, 2, 3},
		[]byte{},
		time.Now(),
		time.Now(),
	)
	test.AssertNotError(t, err, "failed to insert test certificates row")

	rows, err := bkr.findUnrevoked(unchecked{KeyHash: hashA, RevokedBy: 10})
	test.AssertNotError(t, err, "findUnrevoked failed")
	test.AssertEquals(t, len(rows), 1)
	test.AssertEquals(t, rows[0].Serial, "ff")
	test.AssertEquals(t, rows[0].RegistrationID, int64(1))
	test.AssertEquals(t, rows[0].RevokedBy, int64(10))
	test.AssertByteEquals(t, rows[0].DER, []byte{1, 2, 3})
}

func TestResolveContacts(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	bkr := &badKeyRevoker{dbMap: dbMap}

	res, err := dbMap.Exec(
		"INSERT INTO registrations (jwk, jwk_sha256, contact, agreement, initialIP, createdAt, status, LockCol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		[]byte{},
		"ff",
		"[]",
		"yes",
		[]byte{},
		time.Now(),
		string(core.StatusValid),
		0,
	)
	test.AssertNotError(t, err, "failed to insert test registrations row")
	regIDA, err := res.LastInsertId()
	test.AssertNotError(t, err, "failed to get registration ID")
	res, err = dbMap.Exec(
		"INSERT INTO registrations (jwk, jwk_sha256, contact, agreement, initialIP, createdAt, status, LockCol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		[]byte{},
		"ee",
		`["example.com"]`,
		"yes",
		[]byte{},
		time.Now(),
		string(core.StatusValid),
		0,
	)
	test.AssertNotError(t, err, "failed to insert test registrations row")
	regIDB, err := res.LastInsertId()
	test.AssertNotError(t, err, "failed to get registration ID")
	res, err = dbMap.Exec(
		"INSERT INTO registrations (jwk, jwk_sha256, contact, agreement, initialIP, createdAt, status, LockCol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		[]byte{},
		"dd",
		`["example.com"]`,
		"yes",
		[]byte{},
		time.Now(),
		string(core.StatusValid),
		0,
	)
	test.AssertNotError(t, err, "failed to insert test registrations row")
	regIDC, err := res.LastInsertId()
	test.AssertNotError(t, err, "failed to get registration ID")
	res, err = dbMap.Exec(
		"INSERT INTO registrations (jwk, jwk_sha256, contact, agreement, initialIP, createdAt, status, LockCol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		[]byte{},
		"cc",
		`["example-2.com"]`,
		"yes",
		[]byte{},
		time.Now(),
		string(core.StatusValid),
		0,
	)
	test.AssertNotError(t, err, "failed to insert test registrations row")
	regIDD, err := res.LastInsertId()
	test.AssertNotError(t, err, "failed to get registration ID")

	idToEmail, err := bkr.resolveContacts([]int64{regIDA, regIDB, regIDC, regIDD})
	test.AssertNotError(t, err, "resolveContacts failed")
	test.AssertDeepEquals(t, idToEmail, map[int64]string{
		regIDB: "example.com",
		regIDC: "example.com",
		regIDD: "example-2.com",
	})
}

func TestSendMessages(t *testing.T) {
	mm := &mocks.Mailer{}
	bkr := &badKeyRevoker{mailer: mm}

	maxSerials = 2
	err := bkr.sendMessages(map[string][]string{
		"example.com": []string{"a", "b", "c"},
	})
	test.AssertNotError(t, err, "sendMessages failed")
	test.AssertEquals(t, len(mm.Messages), 1)
	test.AssertEquals(t, mm.Messages[0].To, "example.com")
	test.AssertEquals(t, mm.Messages[0].Subject, emailSubject)
	test.AssertEquals(t, mm.Messages[0].Body, "Hello,\n\nThe public key associated with certificates which you have issued has been marked as compromised. As such we are required to revoke any certificates which contain this public key.\n\nThe following currently unexpired certificates that you've issued contain this public key and have been revoked:\na\nb\nand 1 more certificates.\n")

}

type mockRevoker struct {
	revoked int
	mu      sync.Mutex
}

func (mr *mockRevoker) AdministrativelyRevokeCertificate(ctx context.Context, in *rapb.AdministrativelyRevokeCertificateRequest, opts ...grpc.CallOption) (*corepb.Empty, error) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.revoked++
	return nil, nil
}

func TestInvoke(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	mm := &mocks.Mailer{}
	mr := &mockRevoker{}
	bkr := &badKeyRevoker{dbMap: dbMap, uncheckedBatchSize: 1, certificatesBatchSize: 1, raClient: mr, mailer: mm}

	// populate DB with all the test data
	res, err := dbMap.Exec(
		"INSERT INTO registrations (jwk, jwk_sha256, contact, agreement, initialIP, createdAt, status, LockCol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		[]byte{},
		"ff",
		`["example.com"]`,
		"yes",
		[]byte{},
		time.Now(),
		string(core.StatusValid),
		0,
	)
	test.AssertNotError(t, err, "failed to insert test registrations row")
	regIDA, err := res.LastInsertId()
	test.AssertNotError(t, err, "failed to get registration ID")
	res, err = dbMap.Exec(
		"INSERT INTO registrations (jwk, jwk_sha256, contact, agreement, initialIP, createdAt, status, LockCol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		[]byte{},
		"ee",
		`["example.com"]`,
		"yes",
		[]byte{},
		time.Now(),
		string(core.StatusValid),
		0,
	)
	test.AssertNotError(t, err, "failed to insert test registrations row")
	regIDB, err := res.LastInsertId()
	test.AssertNotError(t, err, "failed to get registration ID")
	res, err = dbMap.Exec(
		"INSERT INTO registrations (jwk, jwk_sha256, contact, agreement, initialIP, createdAt, status, LockCol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		[]byte{},
		"dd",
		`["other.example.com"]`,
		"yes",
		[]byte{},
		time.Now(),
		string(core.StatusValid),
		0,
	)
	test.AssertNotError(t, err, "failed to insert test registrations row")
	regIDC, err := res.LastInsertId()
	test.AssertNotError(t, err, "failed to get registration ID")

	hashA := make([]byte, 32)
	hashA[0] = 1
	_, err = dbMap.Exec(`INSERT INTO blockedKeys
		(keyHash, added, source, revokedBy, extantCertificatesChecked)
		VALUES
		(?, ?, ?, ?, ?)`,
		hashA,
		time.Now(),
		"API",
		regIDC,
		false,
	)
	test.AssertNotError(t, err, "failed to add test row")
	_, err = dbMap.Exec(
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		hashA,
		time.Now(),
		"ff",
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")
	_, err = dbMap.Exec(
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		hashA,
		time.Now(),
		"ee",
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")
	_, err = dbMap.Exec(
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		hashA,
		time.Now(),
		"dd",
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")
	_, err = dbMap.Exec(
		"INSERT INTO certificateStatus (serial, status, isExpired, ocspLAstUpdated, revokedDate, revokedReason, lastExpirationNagSent) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"ff",
		string(core.StatusValid),
		false,
		time.Now(),
		time.Time{},
		0,
		time.Time{},
	)
	test.AssertNotError(t, err, "failed to insert test certificateStatus row")
	_, err = dbMap.Exec(
		"INSERT INTO certificates (serial, registrationID, der, digest, issued, expires) VALUES (?, ?, ?, ?, ?, ?)",
		"ff",
		regIDA,
		[]byte{1, 2, 3},
		[]byte{},
		time.Now(),
		time.Now(),
	)
	test.AssertNotError(t, err, "failed to insert test certificates row")
	_, err = dbMap.Exec(
		"INSERT INTO certificateStatus (serial, status, isExpired, ocspLAstUpdated, revokedDate, revokedReason, lastExpirationNagSent) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"ee",
		string(core.StatusValid),
		false,
		time.Now(),
		time.Time{},
		0,
		time.Time{},
	)
	test.AssertNotError(t, err, "failed to insert test certificateStatus row")
	_, err = dbMap.Exec(
		"INSERT INTO certificates (serial, registrationID, der, digest, issued, expires) VALUES (?, ?, ?, ?, ?, ?)",
		"ee",
		regIDB,
		[]byte{1, 2, 3},
		[]byte{},
		time.Now(),
		time.Now(),
	)
	test.AssertNotError(t, err, "failed to insert test certificates row")
	_, err = dbMap.Exec(
		"INSERT INTO certificateStatus (serial, status, isExpired, ocspLAstUpdated, revokedDate, revokedReason, lastExpirationNagSent) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"dd",
		string(core.StatusValid),
		false,
		time.Now(),
		time.Time{},
		0,
		time.Time{},
	)
	test.AssertNotError(t, err, "failed to insert test certificateStatus row")
	_, err = dbMap.Exec(
		"INSERT INTO certificates (serial, registrationID, der, digest, issued, expires) VALUES (?, ?, ?, ?, ?, ?)",
		"dd",
		regIDC,
		[]byte{1, 2, 3},
		[]byte{},
		time.Now(),
		time.Now(),
	)
	test.AssertNotError(t, err, "failed to insert test certificates row")
	hashB := make([]byte, 32)
	hashB[0] = 2
	_, err = dbMap.Exec(`INSERT INTO blockedKeys
		(keyHash, added, source, revokedBy, extantCertificatesChecked)
		VALUES
		(?, ?, ?, ?, ?)`,
		hashB,
		time.Now(),
		"API",
		regIDC,
		false,
	)
	test.AssertNotError(t, err, "failed to insert test blockKeys row")
	_, err = dbMap.Exec(
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		hashB,
		time.Now(),
		"cc",
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")
	_, err = dbMap.Exec(
		"INSERT INTO certificateStatus (serial, status, isExpired, ocspLAstUpdated, revokedDate, revokedReason, lastExpirationNagSent) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"cc",
		string(core.StatusRevoked),
		true,
		time.Now(),
		time.Time{},
		0,
		time.Time{},
	)
	test.AssertNotError(t, err, "failed to insert test certificateStatus row")
	_, err = dbMap.Exec(
		"INSERT INTO certificates (serial, registrationID, der, digest, issued, expires) VALUES (?, ?, ?, ?, ?, ?)",
		"cc",
		regIDC,
		[]byte{1, 2, 3},
		[]byte{},
		time.Now(),
		time.Now(),
	)
	test.AssertNotError(t, err, "failed to insert test certificates row")

	noWork, err := bkr.invoke()
	test.AssertNotError(t, err, "invoke failed")
	test.AssertEquals(t, noWork, false)
	test.AssertEquals(t, mr.revoked, 3)
	test.AssertEquals(t, len(mm.Messages), 1)
	test.AssertEquals(t, mm.Messages[0].To, "example.com")

	var checked struct {
		ExtantCertificatesChecked bool
	}
	err = dbMap.SelectOne(&checked, "SELECT extantCertificatesChecked FROM blockedKeys WHERE keyHash = ?", hashA)
	test.AssertNotError(t, err, "failed to select row from blockedKeys")
	test.AssertEquals(t, checked.ExtantCertificatesChecked, true)
	checked.ExtantCertificatesChecked = false
	err = dbMap.SelectOne(&checked, "SELECT extantCertificatesChecked FROM blockedKeys WHERE keyHash = ?", hashB)
	test.AssertNotError(t, err, "failed to select row from blockedKeys")
	test.AssertEquals(t, checked.ExtantCertificatesChecked, true)

	noWork, err = bkr.invoke()
	test.AssertNotError(t, err, "invoke failed")
	test.AssertEquals(t, noWork, true)
}
