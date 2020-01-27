package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/test"
)

func TestGenerateDefs(t *testing.T) {
	clk := clock.NewFake()

	_, err := generateDefs(clk, 1, 0, "", 1, 2)
	test.AssertError(t, err, "generateDefs didn't fail with a overlap > period")

	_, err = generateDefs(clk, 1, 0, "asd", 3, 2)
	test.AssertError(t, err, "generateDefs didn't fail with an invalid start date")

	defs, err := generateDefs(clk, 2, 3, "", time.Hour*2, time.Hour)
	test.AssertNotError(t, err, "generateDefs failed")
	test.AssertEquals(t, len(defs), 2)

	test.AssertEquals(t, defs[0].num, 3)
	test.Assert(t, defs[0].start.Equal(clk.Now()), "CRL definition had wrong start date")
	test.Assert(t, defs[0].end.Equal(clk.Now().Add(time.Hour*2)), "CRL definition had wrong end date")
	test.AssertEquals(t, defs[1].num, 4)
	test.Assert(t, defs[1].start.Equal(clk.Now().Add(time.Hour)), "CRL definition had wrong start date")
	test.Assert(t, defs[1].end.Equal(clk.Now().Add(time.Hour*3)), "CRL definition had wrong end date")

	defs, err = generateDefs(clk, 1, 0, "1970-01-01T02:00:00Z", time.Hour*2, time.Hour)
	test.AssertNotError(t, err, "generateDefs failed")
	test.AssertEquals(t, len(defs), 1)
	test.Assert(t, defs[0].start.Equal(clk.Now().Add(time.Hour*2)), "CRL definition had wrong start date")
	test.Assert(t, defs[0].end.Equal(clk.Now().Add(time.Hour*4)), "CRL definition had wrong end date")

}

func TestGenerateCRL(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	test.AssertNotError(t, err, "rsa.GenerateKey failed")
	iss := &x509.Certificate{
		PublicKey: k.PublicKey,
	}
	now := time.Now()
	tmp, err := ioutil.TempDir("", "crls")
	test.AssertNotError(t, err, "ioutil.TempDir failed")
	defer os.RemoveAll(tmp)
	err = generateCRL(iss, k, crlDef{
		num:   5,
		start: now,
		end:   now.Add(time.Hour),
	}, tmp, "test-crls")
	test.AssertNotError(t, err, "generateCRL failed")

	testCRLBytes, err := ioutil.ReadFile(path.Join(tmp, "test-crls-5.pem"))
	test.AssertNotError(t, err, "ioutil.ReadFile failed")

	testCRL, err := x509.ParseCRL(testCRLBytes)
	test.AssertNotError(t, err, "x509.ParseCRL failed")
	test.AssertEquals(t, len(testCRL.TBSCertList.RevokedCertificates), 0)
}
