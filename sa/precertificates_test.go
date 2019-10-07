package sa

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	berrors "github.com/letsencrypt/boulder/errors"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
)

func TestAddPrecertificate(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	certDER, err := ioutil.ReadFile("test-cert2.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")
	serial := "ffa0160630d618b2eb5c0510824b14274856"
	ocspResp := []byte{0, 0, 1}
	regID := reg.ID
	issuedTime := time.Date(2018, 4, 1, 7, 0, 0, 0, time.UTC).UnixNano()
	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    certDER,
		RegID:  &regID,
		Ocsp:   ocspResp,
		Issued: &issuedTime,
	})
	test.AssertNotError(t, err, "Couldn't add test-cert2.der")

	certStatus, err := sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, "Couldn't get status for test-cert2.der")
	test.Assert(
		t,
		bytes.Compare(certStatus.OCSPResponse, ocspResp) == 0,
		fmt.Sprintf("OCSP responses don't match, expected: %x, got %x", certStatus.OCSPResponse, ocspResp),
	)
	test.Assert(
		t,
		clk.Now().Equal(certStatus.OCSPLastUpdated),
		fmt.Sprintf("OCSPLastUpdated doesn't match, expected %s, got %s", clk.Now(), certStatus.OCSPLastUpdated),
	)

	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    certDER,
		RegID:  &regID,
		Ocsp:   ocspResp,
		Issued: &issuedTime,
	})
	if err == nil {
		t.Fatalf("Expected error inserting duplicate precertificate, got none")
	}
	if !berrors.Is(err, berrors.Duplicate) {
		t.Fatalf("Expected berrors.Duplicate inserting duplicate precertificate, got %#v", err)
	}
}
