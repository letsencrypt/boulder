package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"html/template"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mocks"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
	"google.golang.org/grpc"
)

func randHash(t *testing.T) []byte {
	t.Helper()
	h := make([]byte, 32)
	_, err := rand.Read(h)
	test.AssertNotError(t, err, "failed to read rand")
	return h
}

func insertBlockedRow(t *testing.T, dbMap *db.WrappedMap, hash []byte, by int64, checked bool) {
	t.Helper()
	_, err := dbMap.Exec(`INSERT INTO blockedKeys
		(keyHash, added, source, revokedBy, extantCertificatesChecked)
		VALUES
		(?, ?, ?, ?, ?)`,
		hash,
		time.Now(),
		1,
		by,
		checked,
	)
	test.AssertNotError(t, err, "failed to add test row")
}

func TestSelectUncheckedRows(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	bkr := &badKeyRevoker{
		dbMap:  dbMap,
		logger: blog.NewMock(),
	}

	hashA, hashB, hashC := randHash(t), randHash(t), randHash(t)
	insertBlockedRow(t, dbMap, hashA, 1, true)
	row, err := bkr.selectUncheckedKey()
	test.AssertError(t, err, "selectUncheckedKey didn't fail with no rows to process")
	test.Assert(t, db.IsNoRows(err), "returned error is not sql.ErrNoRows")
	insertBlockedRow(t, dbMap, hashB, 1, false)
	insertBlockedRow(t, dbMap, hashC, 1, false)
	row, err = bkr.selectUncheckedKey()
	test.AssertNotError(t, err, "selectUncheckKey failed")
	test.AssertByteEquals(t, row.KeyHash, hashB)
	test.AssertEquals(t, row.RevokedBy, int64(1))
}

func insertRegistration(t *testing.T, dbMap *db.WrappedMap, addrs ...string) int64 {
	t.Helper()
	jwkHash := make([]byte, 2)
	_, err := rand.Read(jwkHash)
	test.AssertNotError(t, err, "failed to read rand")
	contactStr := "[]"
	if len(addrs) > 0 {
		contacts := []string{}
		for _, addr := range addrs {
			contacts = append(contacts, fmt.Sprintf(`"mailto:%s"`, addr))
		}
		contactStr = fmt.Sprintf("[%s]", strings.Join(contacts, ","))
	}
	res, err := dbMap.Exec(
		"INSERT INTO registrations (jwk, jwk_sha256, contact, agreement, initialIP, createdAt, status, LockCol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		[]byte{},
		fmt.Sprintf("%x", jwkHash),
		contactStr,
		"yes",
		[]byte{},
		time.Now(),
		string(core.StatusValid),
		0,
	)
	test.AssertNotError(t, err, "failed to insert test registrations row")
	regID, err := res.LastInsertId()
	test.AssertNotError(t, err, "failed to get registration ID")
	return regID
}

type ExpiredStatus bool

const (
	Expired   = ExpiredStatus(true)
	Unexpired = ExpiredStatus(false)
	Revoked   = core.OCSPStatusRevoked
	Unrevoked = core.OCSPStatusGood
)

func insertGoodCert(t *testing.T, dbMap *db.WrappedMap, keyHash []byte, serial string, regID int64) {
	insertCert(t, dbMap, keyHash, serial, regID, Unexpired, Unrevoked)
}

func insertCert(t *testing.T, dbMap *db.WrappedMap, keyHash []byte, serial string, regID int64, expiredStatus ExpiredStatus, status core.OCSPStatus) {
	t.Helper()
	_, err := dbMap.Exec(
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		keyHash,
		time.Now(),
		serial,
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")

	_, err = dbMap.Exec(
		"INSERT INTO certificateStatus (serial, status, isExpired, ocspLastUpdated, revokedDate, revokedReason, lastExpirationNagSent) VALUES (?, ?, ?, ?, ?, ?, ?)",
		serial,
		status,
		expiredStatus,
		time.Now(),
		time.Time{},
		0,
		time.Time{},
	)
	test.AssertNotError(t, err, "failed to insert test certificateStatus row")

	_, err = dbMap.Exec(
		"INSERT INTO precertificates (serial, registrationID, der, issued, expires) VALUES (?, ?, ?, ?, ?)",
		serial,
		regID,
		[]byte{1, 2, 3},
		time.Now(),
		time.Now(),
	)
	test.AssertNotError(t, err, "failed to insert test certificateStatus row")

	_, err = dbMap.Exec(
		"INSERT INTO certificates (serial, registrationID, der, digest, issued, expires) VALUES (?, ?, ?, ?, ?, ?)",
		serial,
		regID,
		[]byte{1, 2, 3},
		[]byte{},
		time.Now(),
		time.Now(),
	)
	test.AssertNotError(t, err, "failed to insert test certificates row")
}

// Test that we produce an error when a serial from the keyHashToSerial table
// does not have a corresponding entry in the certificateStatus and
// precertificates table.
func TestFindUnrevokedNoRows(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	hashA := randHash(t)
	_, err = dbMap.Exec(
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		hashA,
		time.Now(),
		"zz",
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")

	bkr := &badKeyRevoker{dbMap: dbMap, serialBatchSize: 1, maxRevocations: 10}
	_, err = bkr.findUnrevoked(uncheckedBlockedKey{KeyHash: hashA})
	test.Assert(t, db.IsNoRows(err), "expected NoRows error")
}

func TestFindUnrevoked(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	regID := insertRegistration(t, dbMap)

	bkr := &badKeyRevoker{dbMap: dbMap, serialBatchSize: 1, maxRevocations: 10}

	hashA := randHash(t)
	// insert valid, unexpired
	insertCert(t, dbMap, hashA, "ff", regID, Unexpired, Unrevoked)
	// insert valid, expired
	insertCert(t, dbMap, hashA, "ee", regID, Expired, Unrevoked)
	// insert revoked
	insertCert(t, dbMap, hashA, "dd", regID, Unexpired, Revoked)

	rows, err := bkr.findUnrevoked(uncheckedBlockedKey{KeyHash: hashA})
	test.AssertNotError(t, err, "findUnrevoked failed")
	test.AssertEquals(t, len(rows), 1)
	test.AssertEquals(t, rows[0].Serial, "ff")
	test.AssertEquals(t, rows[0].RegistrationID, int64(1))
	test.AssertByteEquals(t, rows[0].DER, []byte{1, 2, 3})

	bkr.maxRevocations = 0
	_, err = bkr.findUnrevoked(uncheckedBlockedKey{KeyHash: hashA})
	test.AssertError(t, err, "findUnrevoked didn't fail with 0 maxRevocations")
	test.AssertEquals(t, err.Error(), fmt.Sprintf("too many certificates to revoke associated with %x: got 1, max 0", hashA))
}

func TestResolveContacts(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	bkr := &badKeyRevoker{dbMap: dbMap}

	regIDA := insertRegistration(t, dbMap)
	regIDB := insertRegistration(t, dbMap, "example.com", "example-2.com")
	regIDC := insertRegistration(t, dbMap, "example.com")
	regIDD := insertRegistration(t, dbMap, "example-2.com")

	idToEmail, err := bkr.resolveContacts([]int64{regIDA, regIDB, regIDC, regIDD})
	test.AssertNotError(t, err, "resolveContacts failed")
	test.AssertDeepEquals(t, idToEmail, map[int64][]string{
		regIDA: {""},
		regIDB: {"example.com", "example-2.com"},
		regIDC: {"example.com"},
		regIDD: {"example-2.com"},
	})
}

var testTemplate = template.Must(template.New("testing").Parse("{{range .}}{{.}}\n{{end}}"))

func TestSendMessage(t *testing.T) {
	mm := &mocks.Mailer{}
	bkr := &badKeyRevoker{mailer: mm, emailSubject: "testing", emailTemplate: testTemplate}

	maxSerials = 2
	err := bkr.sendMessage("example.com", []string{"a", "b", "c"})
	test.AssertNotError(t, err, "sendMessages failed")
	test.AssertEquals(t, len(mm.Messages), 1)
	test.AssertEquals(t, mm.Messages[0].To, "example.com")
	test.AssertEquals(t, mm.Messages[0].Subject, bkr.emailSubject)
	test.AssertEquals(t, mm.Messages[0].Body, "a\nb\nand 1 more certificates.\n")

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

func TestRevokeCerts(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	mm := &mocks.Mailer{}
	mr := &mockRevoker{}
	bkr := &badKeyRevoker{dbMap: dbMap, raClient: mr, mailer: mm, emailSubject: "testing", emailTemplate: testTemplate}

	err = bkr.revokeCerts([]string{"revoker@example.com", "revoker-b@example.com"}, map[string][]unrevokedCertificate{
		"revoker@example.com":   {{ID: 0, Serial: "ff"}},
		"revoker-b@example.com": {{ID: 0, Serial: "ff"}},
		"other@example.com":     {{ID: 1, Serial: "ee"}},
	})
	test.AssertNotError(t, err, "revokeCerts failed")
	test.AssertEquals(t, len(mm.Messages), 1)
	test.AssertEquals(t, mm.Messages[0].To, "other@example.com")
	test.AssertEquals(t, mm.Messages[0].Subject, bkr.emailSubject)
	test.AssertEquals(t, mm.Messages[0].Body, "ee\n")
}

func TestCertificateAbsent(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	// populate DB with all the test data
	regIDA := insertRegistration(t, dbMap, "example.com")
	hashA := randHash(t)
	insertBlockedRow(t, dbMap, hashA, regIDA, false)

	// Add an entry to keyHashToSerial but not to certificateStatus or certificate
	// status, and expect an error.
	_, err = dbMap.Exec(
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		hashA,
		time.Now(),
		"ffaaee",
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")

	bkr := &badKeyRevoker{
		dbMap:           dbMap,
		maxRevocations:  1,
		serialBatchSize: 1,
		raClient:        &mockRevoker{},
		mailer:          &mocks.Mailer{},
		emailSubject:    "testing",
		emailTemplate:   testTemplate,
		logger:          blog.NewMock(),
	}
	_, err = bkr.invoke()
	test.AssertError(t, err, "expected error when row in keyHashToSerial didn't have a matching cert")
}

func TestInvoke(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	mm := &mocks.Mailer{}
	mr := &mockRevoker{}
	bkr := &badKeyRevoker{
		dbMap:           dbMap,
		maxRevocations:  10,
		serialBatchSize: 1,
		raClient:        mr,
		mailer:          mm,
		emailSubject:    "testing",
		emailTemplate:   testTemplate,
		logger:          blog.NewMock(),
	}

	// populate DB with all the test data
	regIDA := insertRegistration(t, dbMap, "example.com")
	regIDB := insertRegistration(t, dbMap, "example.com")
	regIDC := insertRegistration(t, dbMap, "other.example.com", "uno.example.com")
	regIDD := insertRegistration(t, dbMap)
	hashA := randHash(t)
	insertBlockedRow(t, dbMap, hashA, regIDC, false)
	insertGoodCert(t, dbMap, hashA, "ff", regIDA)
	insertGoodCert(t, dbMap, hashA, "ee", regIDB)
	insertGoodCert(t, dbMap, hashA, "dd", regIDC)
	insertGoodCert(t, dbMap, hashA, "cc", regIDD)

	noWork, err := bkr.invoke()
	test.AssertNotError(t, err, "invoke failed")
	test.AssertEquals(t, noWork, false)
	test.AssertEquals(t, mr.revoked, 4)
	test.AssertEquals(t, len(mm.Messages), 1)
	test.AssertEquals(t, mm.Messages[0].To, "example.com")

	var checked struct {
		ExtantCertificatesChecked bool
	}
	err = dbMap.SelectOne(&checked, "SELECT extantCertificatesChecked FROM blockedKeys WHERE keyHash = ?", hashA)
	test.AssertNotError(t, err, "failed to select row from blockedKeys")
	test.AssertEquals(t, checked.ExtantCertificatesChecked, true)

	// add a row with no associated valid certificates
	hashB := randHash(t)
	insertBlockedRow(t, dbMap, hashB, regIDC, false)
	insertCert(t, dbMap, hashB, "bb", regIDA, Expired, Revoked)

	noWork, err = bkr.invoke()
	test.AssertNotError(t, err, "invoke failed")
	test.AssertEquals(t, noWork, false)

	checked.ExtantCertificatesChecked = false
	err = dbMap.SelectOne(&checked, "SELECT extantCertificatesChecked FROM blockedKeys WHERE keyHash = ?", hashB)
	test.AssertNotError(t, err, "failed to select row from blockedKeys")
	test.AssertEquals(t, checked.ExtantCertificatesChecked, true)

	noWork, err = bkr.invoke()
	test.AssertNotError(t, err, "invoke failed")
	test.AssertEquals(t, noWork, true)
}

func TestInvokeRevokerHasNoExtantCerts(t *testing.T) {
	// This test checks that when the user who revoked the initial
	// certificate that added the row to blockedKeys doesn't have any
	// extant certificates themselves their contact email is still
	// resolved and we avoid sending any emails to accounts that
	// share the same email.
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetSATestDatabase(t)()

	mm := &mocks.Mailer{}
	mr := &mockRevoker{}
	bkr := &badKeyRevoker{dbMap: dbMap,
		maxRevocations:  10,
		serialBatchSize: 1,
		raClient:        mr,
		mailer:          mm,
		emailSubject:    "testing",
		emailTemplate:   testTemplate,
		logger:          blog.NewMock(),
	}

	// populate DB with all the test data
	regIDA := insertRegistration(t, dbMap, "a@example.com")
	regIDB := insertRegistration(t, dbMap, "a@example.com")
	regIDC := insertRegistration(t, dbMap, "b@example.com")

	hashA := randHash(t)

	insertBlockedRow(t, dbMap, hashA, regIDA, false)

	insertGoodCert(t, dbMap, hashA, "ee", regIDB)
	insertGoodCert(t, dbMap, hashA, "dd", regIDB)
	insertGoodCert(t, dbMap, hashA, "cc", regIDC)
	insertGoodCert(t, dbMap, hashA, "bb", regIDC)

	noWork, err := bkr.invoke()
	test.AssertNotError(t, err, "invoke failed")
	test.AssertEquals(t, noWork, false)
	test.AssertEquals(t, mr.revoked, 4)
	test.AssertEquals(t, len(mm.Messages), 1)
	test.AssertEquals(t, mm.Messages[0].To, "b@example.com")
}
