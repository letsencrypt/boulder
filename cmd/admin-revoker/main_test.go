package notmain

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	akamaipb "github.com/letsencrypt/boulder/akamai/proto"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	ira "github.com/letsencrypt/boulder/test/inmem/ra"
	isa "github.com/letsencrypt/boulder/test/inmem/sa"
	"github.com/letsencrypt/boulder/test/vars"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type mockCA struct {
	mocks.MockCA
}

func (ca *mockCA) GenerateOCSP(context.Context, *capb.GenerateOCSPRequest, ...grpc.CallOption) (*capb.OCSPResponse, error) {
	return &capb.OCSPResponse{Response: []byte("fakeocspbytes")}, nil
}

type mockPurger struct{}

func (mp *mockPurger) Purge(context.Context, *akamaipb.PurgeRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func TestRevokeBatch(t *testing.T) {
	log := blog.UseMock()
	fc := clock.NewFake()
	// Set to some non-zero time.
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	dbMap, err := sa.NewDbMap(vars.DBConnSA, sa.DbSettings{})
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	ssa, err := sa.NewSQLStorageAuthority(dbMap, dbMap, fc, log, metrics.NoopRegisterer, 1)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}
	defer test.ResetSATestDatabase(t)
	reg := satest.CreateWorkingRegistration(t, isa.SA{Impl: ssa})

	issuer, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "Failed to load test issuer")
	signer, err := test.LoadSigner("../../test/hierarchy/int-r3.key.pem")
	test.AssertNotError(t, err, "Failed to load test signer")

	ra := ra.NewRegistrationAuthorityImpl(fc,
		log,
		metrics.NoopRegisterer,
		1,
		goodkey.KeyPolicy{},
		100,
		true,
		300*24*time.Hour,
		7*24*time.Hour,
		nil,
		nil,
		0,
		nil,
		&mockPurger{},
		[]*issuance.Certificate{issuer},
	)
	ra.SA = isa.SA{Impl: ssa}
	ra.CA = &mockCA{}
	rac := ira.RA{Impl: ra}

	r := revoker{
		rac:   rac,
		sac:   isa.SA{Impl: ssa},
		dbMap: dbMap,
		clk:   fc,
		log:   log,
	}

	serialFile, err := ioutil.TempFile("", "serials")
	test.AssertNotError(t, err, "Failed to open temp file")
	defer os.Remove(serialFile.Name())

	serials := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	for _, serial := range serials {
		template := &x509.Certificate{
			SerialNumber: serial,
			DNSNames:     []string{"asd"},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer.Certificate, signer.Public(), signer)
		test.AssertNotError(t, err, "Failed to generate test cert")
		_, err = ssa.AddPrecertificate(context.Background(), &sapb.AddCertificateRequest{
			Der:      der,
			RegID:    reg.Id,
			Issued:   time.Now().UnixNano(),
			IssuerID: 1,
		})
		test.AssertNotError(t, err, "Failed to add test cert")
		_, err = ssa.AddCertificate(context.Background(), &sapb.AddCertificateRequest{
			Der:    der,
			RegID:  reg.Id,
			Issued: time.Now().UnixNano(),
		})
		test.AssertNotError(t, err, "Failed to add test cert")
		_, err = serialFile.WriteString(fmt.Sprintf("%s\n", core.SerialToString(serial)))
		test.AssertNotError(t, err, "Failed to write serial to temp file")
	}

	err = r.revokeBySerialBatch(context.Background(), serialFile.Name(), 0, 2)
	test.AssertNotError(t, err, "revokeBatch failed")

	for _, serial := range serials {
		status, err := ssa.GetCertificateStatus(context.Background(), &sapb.Serial{Serial: core.SerialToString(serial)})
		test.AssertNotError(t, err, "Failed to retrieve certificate status")
		test.AssertEquals(t, core.OCSPStatus(status.Status), core.OCSPStatusRevoked)
	}
}

func TestVerifyRSAKeyPair(t *testing.T) {
	msgHash := sha256.New()
	_, err := msgHash.Write([]byte("verifiable"))
	test.AssertNotError(t, err, "Failed to hash 'verifiable' message: %s")

	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed while generating test key 1")

	err = verifyRSAKeyPair(privKey1, &privKey1.PublicKey, msgHash)
	test.AssertNotError(t, err, "Failed to verify valid key pair")

	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed while generating test key 2")

	err = verifyRSAKeyPair(privKey1, &privKey2.PublicKey, msgHash)
	test.AssertError(t, err, "Failed to detect invalid key pair")
}

func TestVerifyECDSAKeyPair(t *testing.T) {
	msgHash := sha256.New()
	_, err := msgHash.Write([]byte("verifiable"))
	test.AssertNotError(t, err, "Failed to hash 'verifiable' message: %s")

	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "Failed while generating test key 1")

	err = verifyECDSAKeyPair(privKey1, &privKey1.PublicKey, msgHash)
	test.AssertNotError(t, err, "Failed to verify valid key pair")

	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "Failed while generating test key 2")

	err = verifyECDSAKeyPair(privKey1, &privKey2.PublicKey, msgHash)
	test.AssertError(t, err, "Failed to detect invalid key pair")
}

func TestCountCertsMatchingSPKIHash(t *testing.T) {
	testCtx := setup(t)
	// defer testCtx.cleanUp()

	type entry struct {
		jwk      string
		serial   *big.Int
		names    []string
		testKey  *rsa.PrivateKey
		spkiHash []byte
	}

	testKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 1")

	testKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 2")

	testKey3, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 3")

	testJWK1 := `{"kty":"RSA","n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ","e":"AQAB"}`
	testJWK2 := `{"kty":"RSA","n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw","e":"AQAB"}`
	testJWK3 := `{"kty":"RSA","n":"uTQER6vUA1RDixS8xsfCRiKUNGRzzyIK0MhbS2biClShbb0hSx2mPP7gBvis2lizZ9r-y9hL57kNQoYCKndOBg0FYsHzrQ3O9AcoV1z2Mq-XhHZbFrVYaXI0M3oY9BJCWog0dyi3XC0x8AxC1npd1U61cToHx-3uSvgZOuQA5ffEn5L38Dz1Ti7OV3E4XahnRJvejadUmTkki7phLBUXm5MnnyFm0CPpf6ApV7zhLjN5W-nV0WL17o7v8aDgV_t9nIdi1Y26c3PlCEtiVHZcebDH5F1Deta3oLLg9-g6rWnTqPbY3knffhp4m0scLD6e33k8MtzxDX_D7vHsg0_X1w","e":"AQAB"}`

	entries := []entry{
		{jwk: testJWK1, serial: big.NewInt(1), names: []string{"example-1337.com"}, testKey: testKey1},
		{jwk: testJWK2, serial: big.NewInt(2), names: []string{"example-1338.com"}, testKey: testKey2},
		{jwk: testJWK3, serial: big.NewInt(3), names: []string{"example-1339.com"}, testKey: testKey3},
	}

	for _, entry := range entries {
		regId := testCtx.addRegistation(t, entry.names, entry.jwk)
		cert := testCtx.addCertificate(t, entry.serial, entry.names, entry.testKey.PublicKey, regId)
		entry.spkiHash, err = getPublicKeySPKIHash(cert.PublicKey)
		test.AssertNotError(t, err, "Failed to get SPKI hash for test cert")
	}

	count, err := testCtx.revoker.countCertsMatchingSPKIHash(entries[0].spkiHash)
	test.AssertNotError(t, err, "countCertsMatchingSPKIHash for 'entries[0].spkiHash' failed")
	test.AssertEquals(t, count, 1)
}

type testCtx struct {
	revoker revoker
	ssa     sapb.StorageAuthorityClient
	cleanUp func()
	issuer  *issuance.Certificate
	signer  crypto.Signer
}

func (c testCtx) addRegistation(t *testing.T, names []string, jwk string) int64 {
	initialIP, err := net.ParseIP("127.0.0.1").MarshalText()
	test.AssertNotError(t, err, "Failed to create initialIP")

	reg := &corepb.Registration{
		Id:        1,
		Contact:   []string{fmt.Sprintf("hello@%s", names[0])},
		Key:       []byte(jwk),
		InitialIP: initialIP,
	}

	reg, err = c.ssa.NewRegistration(context.Background(), reg)
	test.AssertNotError(t, err, "Failed to store test registration")
	return reg.Id
}

func (c testCtx) addCertificate(t *testing.T, serial *big.Int, names []string, pubKey rsa.PublicKey, regId int64) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"tests"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		DNSNames:     names,
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, template, c.issuer.Certificate, &pubKey, c.signer)
	test.AssertNotError(t, err, "Failed to generate test cert")

	_, err = c.ssa.AddPrecertificate(
		context.Background(), &sapb.AddCertificateRequest{
			Der:      rawCert,
			RegID:    regId,
			Issued:   time.Now().UnixNano(),
			IssuerID: 1,
		},
	)
	test.AssertNotError(t, err, "Failed to add test precert")

	cert, err := x509.ParseCertificate(rawCert)
	test.AssertNotError(t, err, "Failed to parse test cert")
	return cert
}

func setup(t *testing.T) testCtx {
	log := blog.UseMock()
	fc := clock.NewFake()
	fc.Set(time.Now())

	dbMap, err := sa.NewDbMap(vars.DBConnSA, sa.DbSettings{})
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}

	ssa, err := sa.NewSQLStorageAuthority(dbMap, dbMap, fc, log, metrics.NoopRegisterer, 1)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}
	cleanUp := test.ResetSATestDatabase(t)

	issuer, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "Failed to load test issuer")

	signer, err := test.LoadSigner("../../test/hierarchy/int-r3.key.pem")
	test.AssertNotError(t, err, "Failed to load test signer")

	ra := ra.NewRegistrationAuthorityImpl(
		fc,
		log,
		metrics.NoopRegisterer,
		1,
		goodkey.KeyPolicy{},
		100,
		true,
		300*24*time.Hour,
		7*24*time.Hour,
		nil,
		nil,
		0,
		nil,
		&mockPurger{},
		[]*issuance.Certificate{issuer},
	)

	ra.SA = isa.SA{Impl: ssa}
	ra.CA = &mockCA{}
	rac := ira.RA{Impl: ra}

	return testCtx{
		revoker: revoker{rac, isa.SA{Impl: ssa}, dbMap, fc, log},
		ssa:     isa.SA{Impl: ssa},
		cleanUp: cleanUp,
		issuer:  issuer,
		signer:  signer,
	}
}
