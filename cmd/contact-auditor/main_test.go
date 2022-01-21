package notmain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

var (
	regA *corepb.Registration
	regB *corepb.Registration
	regC *corepb.Registration
	regD *corepb.Registration
)

const (
	emailARaw = "test@example.com"
	emailBRaw = "example@notexample.com"
	emailCRaw = "test-example@notexample.com"
	telNum    = "666-666-7777"
)

func TestMailAuditor(t *testing.T) {
	testCtx := setup(t)
	defer testCtx.cleanUp()

	// Add some test registrations.
	testCtx.addRegistrations(t)

	// Should be 0 since we haven't added registrations.
	resChan := make(chan *result, 10)
	err := testCtx.c.run(resChan)
	test.AssertNotError(t, err, "received error")
	test.AssertEquals(t, len(resChan), 0)
}

func TestMailAuditorWithResults(t *testing.T) {
	testCtx := setup(t)
	defer testCtx.cleanUp()

	// Add some test registrations.
	testCtx.addRegistrations(t)

	// Now add some certificates.
	testCtx.addCertificates(t)

	resChan := make(chan *result, 10)
	err := testCtx.c.run(resChan)
	test.AssertNotError(t, err, "received error")

	// We should get back A, B, C, and D
	test.AssertEquals(t, len(resChan), 4)
	for entry := range resChan {
		err := validateContacts(entry.id, entry.createdAt, entry.contacts)
		switch entry.id {
		case regA.Id:
			// Contact validation policy sad path.
			test.AssertDeepEquals(t, entry.contacts, []string{"mailto:test@example.com"})
			test.AssertError(t, err, "failed to error on a contact that violates our e-mail policy")
		case regB.Id:
			// Ensure grace period was respected.
			test.AssertDeepEquals(t, entry.contacts, []string{"mailto:example@notexample.com"})
			test.AssertNotError(t, err, "received error for a valid contact entry")
		case regC.Id:
			// Contact validation happy path.
			test.AssertDeepEquals(t, entry.contacts, []string{"mailto:test-example@notexample.com"})
			test.AssertNotError(t, err, "received error for a valid contact entry")

			// Unmarshal Contact sad path.
			_, err := unmarshalContact([]byte("[ mailto:test@example.com ]"))
			test.AssertError(t, err, "failed to error while unmarshaling invalid Contact JSON")

			// Fix our JSON and ensure that the contact field returns
			// errors for our 2 additional contacts
			contacts, err := unmarshalContact([]byte(`[ "mailto:test@example.com", "tel:666-666-7777" ]`))
			test.AssertNotError(t, err, "received error while unmarshaling valid Contact JSON")

			// Ensure Contact validation now fails.
			err = validateContacts(entry.id, entry.createdAt, contacts)
			test.AssertError(t, err, "failed to error on 2 invalid Contact entries")
		case regD.Id:
			test.AssertDeepEquals(t, entry.contacts, []string{"tel:666-666-7777"})
			test.AssertError(t, err, "failed to error on an invalid contact entry")
		default:
			t.Errorf("ID: %d was not expected", entry.id)
		}
	}

	// Load results file.
	data, err := ioutil.ReadFile(testCtx.c.resultsFile.Name())
	if err != nil {
		t.Error(err)
	}

	// Results file should contain 2 newlines, 1 for each result.
	contentLines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	test.AssertEquals(t, len(contentLines), 2)

	// Each result entry should contain five tab separated columns.
	for _, line := range contentLines {
		test.AssertEquals(t, len(strings.Split(line, "\t")), 5)
	}
}

type testCtx struct {
	c       contactAuditor
	dbMap   *db.WrappedMap
	ssa     *sa.SQLStorageAuthority
	cleanUp func()
}

func (tc testCtx) addRegistrations(t *testing.T) {
	emailA := "mailto:" + emailARaw
	emailB := "mailto:" + emailBRaw
	emailC := "mailto:" + emailCRaw
	tel := "tel:" + telNum

	// Every registration needs a unique JOSE key
	jsonKeyA := []byte(`{
  "kty":"RSA",
  "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "e":"AQAB"
}`)
	jsonKeyB := []byte(`{
  "kty":"RSA",
  "n":"z8bp-jPtHt4lKBqepeKF28g_QAEOuEsCIou6sZ9ndsQsEjxEOQxQ0xNOQezsKa63eogw8YS3vzjUcPP5BJuVzfPfGd5NVUdT-vSSwxk3wvk_jtNqhrpcoG0elRPQfMVsQWmxCAXCVRz3xbcFI8GTe-syynG3l-g1IzYIIZVNI6jdljCZML1HOMTTW4f7uJJ8mM-08oQCeHbr5ejK7O2yMSSYxW03zY-Tj1iVEebROeMv6IEEJNFSS4yM-hLpNAqVuQxFGetwtwjDMC1Drs1dTWrPuUAAjKGrP151z1_dE74M5evpAhZUmpKv1hY-x85DC6N0hFPgowsanmTNNiV75w",
  "e":"AAEAAQ"
}`)
	jsonKeyC := []byte(`{
  "kty":"RSA",
  "n":"rFH5kUBZrlPj73epjJjyCxzVzZuV--JjKgapoqm9pOuOt20BUTdHqVfC2oDclqM7HFhkkX9OSJMTHgZ7WaVqZv9u1X2yjdx9oVmMLuspX7EytW_ZKDZSzL-sCOFCuQAuYKkLbsdcA3eHBK_lwc4zwdeHFMKIulNvLqckkqYB9s8GpgNXBDIQ8GjR5HuJke_WUNjYHSd8jY1LU9swKWsLQe2YoQUz_ekQvBvBCoaFEtrtRaSJKNLIVDObXFr2TLIiFiM0Em90kK01-eQ7ZiruZTKomll64bRFPoNo4_uwubddg3xTqur2vdF3NyhTrYdvAgTem4uC0PFjEQ1bK_djBQ",
  "e":"AQAB"
}`)
	jsonKeyD := []byte(`{
  "kty":"RSA",
  "n":"rFH5kUBZrlPj73epjJjyCxzVzZuV--JjKgapoqm9pOuOt20BUTdHqVfC2oDclqM7HFhkkX9OSJMTHgZ7WaVqZv9u1X2yjdx9oVmMLuspX7EytW_ZKDZSzL-FCOFCuQAuYKkLbsdcA3eHBK_lwc4zwdeHFMKIulNvLqckkqYB9s8GpgNXBDIQ8GjR5HuJke_WUNjYHSd8jY1LU9swKWsLQe2YoQUz_ekQvBvBCoaFEtrtRaSJKNLIVDObXFr2TLIiFiM0Em90kK01-eQ7ZiruZTKomll64bRFPoNo4_uwubddg3xTqur2vdF3NyhTrYdvAgTem4uC0PFjEQ1bK_djBQ",
  "e":"AQAB"
}`)

	initialIP, err := net.ParseIP("127.0.0.1").MarshalText()
	test.AssertNotError(t, err, "Couldn't create initialIP")

	regA = &corepb.Registration{
		Id:        1,
		Contact:   []string{emailA},
		Key:       jsonKeyA,
		InitialIP: initialIP,
	}
	regB = &corepb.Registration{
		Id:        2,
		Contact:   []string{emailB},
		Key:       jsonKeyB,
		InitialIP: initialIP,
	}
	regC = &corepb.Registration{
		Id:        3,
		Contact:   []string{emailC},
		Key:       jsonKeyC,
		InitialIP: initialIP,
	}
	// Reg D has a `tel:` contact ACME URL
	regD = &corepb.Registration{
		Id:        4,
		Contact:   []string{tel},
		Key:       jsonKeyD,
		InitialIP: initialIP,
	}

	// Add the four test registrations
	ctx := context.Background()
	regA, err = tc.ssa.NewRegistration(ctx, regA)
	test.AssertNotError(t, err, "Couldn't store regA")
	regB, err = tc.ssa.NewRegistration(ctx, regB)
	test.AssertNotError(t, err, "Couldn't store regB")
	regC, err = tc.ssa.NewRegistration(ctx, regC)
	test.AssertNotError(t, err, "Couldn't store regC")
	regD, err = tc.ssa.NewRegistration(ctx, regD)
	test.AssertNotError(t, err, "Couldn't store regD")
}

func (tc testCtx) addCertificates(t *testing.T) {
	serial1 := big.NewInt(1336)
	serial1String := core.SerialToString(serial1)
	serial2 := big.NewInt(1337)
	serial2String := core.SerialToString(serial2)
	serial3 := big.NewInt(1338)
	serial3String := core.SerialToString(serial3)
	serial4 := big.NewInt(1339)
	serial4String := core.SerialToString(serial4)
	n := bigIntFromB64("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw==")
	e := intFromB64("AQAB")
	d := bigIntFromB64("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ==")
	p := bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")
	q := bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")

	testKey := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: e},
		D:         d,
		Primes:    []*big.Int{p, q},
	}

	fc := newFakeClock(t)

	// Add one cert for RegA that expires in 30 days
	rawCertA := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy A",
		},
		NotAfter:     fc.Now().Add(30 * 24 * time.Hour),
		DNSNames:     []string{"example-a.com"},
		SerialNumber: serial1,
	}
	certDerA, _ := x509.CreateCertificate(rand.Reader, &rawCertA, &rawCertA, &testKey.PublicKey, &testKey)
	certA := &core.Certificate{
		RegistrationID: regA.Id,
		Serial:         serial1String,
		Expires:        rawCertA.NotAfter,
		DER:            certDerA,
	}
	err := tc.dbMap.Insert(certA)
	test.AssertNotError(t, err, "Couldn't add certA")
	_, err = tc.dbMap.Exec(
		"INSERT INTO issuedNames (reversedName, serial, notBefore) VALUES (?,?,0)",
		"com.example-a",
		serial1String,
	)
	test.AssertNotError(t, err, "Couldn't add issued name for certA")

	// Add one cert for RegB that already expired 30 days ago
	rawCertB := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy B",
		},
		NotAfter:     fc.Now().Add(-30 * 24 * time.Hour),
		DNSNames:     []string{"example-b.com"},
		SerialNumber: serial2,
	}
	certDerB, _ := x509.CreateCertificate(rand.Reader, &rawCertB, &rawCertB, &testKey.PublicKey, &testKey)
	certB := &core.Certificate{
		RegistrationID: regB.Id,
		Serial:         serial2String,
		Expires:        rawCertB.NotAfter,
		DER:            certDerB,
	}
	err = tc.dbMap.Insert(certB)
	test.AssertNotError(t, err, "Couldn't add certB")
	_, err = tc.dbMap.Exec(
		"INSERT INTO issuedNames (reversedName, serial, notBefore) VALUES (?,?,0)",
		"com.example-b",
		serial2String,
	)
	test.AssertNotError(t, err, "Couldn't add issued name for certB")

	// Add one cert for RegC that expires in 30 days
	rawCertC := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy C",
		},
		NotAfter:     fc.Now().Add(30 * 24 * time.Hour),
		DNSNames:     []string{"example-c.com"},
		SerialNumber: serial3,
	}
	certDerC, _ := x509.CreateCertificate(rand.Reader, &rawCertC, &rawCertC, &testKey.PublicKey, &testKey)
	certC := &core.Certificate{
		RegistrationID: regC.Id,
		Serial:         serial3String,
		Expires:        rawCertC.NotAfter,
		DER:            certDerC,
	}
	err = tc.dbMap.Insert(certC)
	test.AssertNotError(t, err, "Couldn't add certC")
	_, err = tc.dbMap.Exec(
		"INSERT INTO issuedNames (reversedName, serial, notBefore) VALUES (?,?,0)",
		"com.example-c",
		serial3String,
	)
	test.AssertNotError(t, err, "Couldn't add issued name for certC")

	// Add one cert for RegD that expires in 30 days
	rawCertD := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy D",
		},
		NotAfter:     fc.Now().Add(30 * 24 * time.Hour),
		DNSNames:     []string{"example-d.com"},
		SerialNumber: serial4,
	}
	certDerD, _ := x509.CreateCertificate(rand.Reader, &rawCertD, &rawCertD, &testKey.PublicKey, &testKey)
	certD := &core.Certificate{
		RegistrationID: regD.Id,
		Serial:         serial4String,
		Expires:        rawCertD.NotAfter,
		DER:            certDerD,
	}
	err = tc.dbMap.Insert(certD)
	test.AssertNotError(t, err, "Couldn't add certD")
	_, err = tc.dbMap.Exec(
		"INSERT INTO issuedNames (reversedName, serial, notBefore) VALUES (?,?,0)",
		"com.example-d",
		serial4String,
	)
	test.AssertNotError(t, err, "Couldn't add issued name for certD")
}

func setup(t *testing.T) testCtx {
	log := blog.UseMock()

	// Using DBConnSAFullPerms to be able to insert registrations and
	// certificates
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, sa.DbSettings{})
	if err != nil {
		t.Fatalf("Couldn't connect to the database: %s", err)
	}

	// Make temp results file
	file, err := ioutil.TempFile("", fmt.Sprintf("audit-%s", time.Now().Format("2006-01-02T15:04")))
	if err != nil {
		t.Fatal(err)
	}

	cleanUp := func() {
		test.ResetSATestDatabase(t)
		file.Close()
		os.Remove(file.Name())
	}

	db, err := makeDBConnection(vars.DBConnSAMailer)
	if err != nil {
		t.Fatalf("Couldn't connect to the database: %s", err)
	}

	ssa, err := sa.NewSQLStorageAuthority(dbMap, dbMap, clock.New(), log, metrics.NoopRegisterer, 1)
	if err != nil {
		t.Fatalf("unable to create SQLStorageAuthority: %s", err)
	}

	return testCtx{
		c: contactAuditor{
			db:          db,
			resultsFile: file,
			logger:      blog.NewMock(),
		},
		dbMap:   dbMap,
		ssa:     ssa,
		cleanUp: cleanUp,
	}
}

func bigIntFromB64(b64 string) *big.Int {
	bytes, _ := base64.URLEncoding.DecodeString(b64)
	x := big.NewInt(0)
	x.SetBytes(bytes)
	return x
}

func intFromB64(b64 string) int {
	return int(bigIntFromB64(b64).Int64())
}

func newFakeClock(t *testing.T) clock.FakeClock {
	const fakeTimeFormat = "2006-01-02T15:04:05.999999999Z"
	ft, err := time.Parse(fakeTimeFormat, fakeTimeFormat)
	if err != nil {
		t.Fatal(err)
	}
	fc := clock.NewFake()
	fc.Set(ft.UTC())
	return fc
}
