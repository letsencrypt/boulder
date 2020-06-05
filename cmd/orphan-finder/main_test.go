package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/jmhodges/clock"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
)

var log = blog.UseMock()

type mockSA struct {
	certificates    []core.Certificate
	precertificates []core.Certificate
	clk             clock.FakeClock
}

func (m *mockSA) AddSerial(ctx context.Context, req *sapb.AddSerialRequest) (*corepb.Empty, error) {
	return nil, nil
}

func (m *mockSA) AddCertificate(ctx context.Context, der []byte, regID int64, _ []byte, issued *time.Time) (string, error) {
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	cert := core.Certificate{
		DER:            der,
		RegistrationID: regID,
		Serial:         core.SerialToString(parsed.SerialNumber),
	}
	if issued == nil {
		cert.Issued = m.clk.Now()
	} else {
		cert.Issued = *issued
	}
	m.certificates = append(m.certificates, cert)
	return "", nil
}

func (m *mockSA) GetCertificate(ctx context.Context, s string) (core.Certificate, error) {
	if len(m.certificates) == 0 {
		return core.Certificate{}, berrors.NotFoundError("no certs stored")
	}
	for _, cert := range m.certificates {
		if cert.Serial == s {
			return cert, nil
		}
	}
	return core.Certificate{}, berrors.NotFoundError("no cert stored for requested serial")
}

func (m *mockSA) AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*corepb.Empty, error) {
	parsed, err := x509.ParseCertificate(req.Der)
	if err != nil {
		return nil, err
	}
	precert := core.Certificate{
		DER:            req.Der,
		RegistrationID: *req.RegID,
		Serial:         core.SerialToString(parsed.SerialNumber),
	}
	if req.Issued == nil {
		precert.Issued = m.clk.Now()
	} else {
		precert.Issued = time.Unix(0, *req.Issued)
	}
	m.precertificates = append(m.precertificates, precert)
	return &corepb.Empty{}, nil
}

func (m *mockSA) GetPrecertificate(ctx context.Context, req *sapb.Serial) (*corepb.Certificate, error) {
	if len(m.precertificates) == 0 {
		return nil, berrors.NotFoundError("no precerts stored")
	}
	for _, precert := range m.precertificates {
		if precert.Serial == *req.Serial {
			return bgrpc.CertToPB(precert), nil
		}
	}
	return nil, berrors.NotFoundError("no precert stored for requested serial")
}

type mockCA struct{}

func (ca *mockCA) GenerateOCSP(context.Context, *capb.GenerateOCSPRequest, ...grpc.CallOption) (*capb.OCSPResponse, error) {
	return &capb.OCSPResponse{
		Response: []byte("HI"),
	}, nil
}

func checkNoErrors(t *testing.T) {
	logs := log.GetAllMatching("ERR:")
	if len(logs) != 0 {
		t.Errorf("Found error logs:")
		for _, ll := range logs {
			t.Error(ll)
		}
	}
}

func mustLoadCert(filename string) *x509.Certificate {
	cert, err := core.LoadCert(filename)
	if err != nil {
		panic(err)
	}
	return cert
}

func TestParseLine(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	sa := &mockSA{}
	ca := &mockCA{}
	issuers, err := loadIssuers([]string{"testdata/minica1.pem", "testdata/minica2.pem"})
	test.AssertNotError(t, err, "loading issuers")

	backdateDuration := time.Hour
	of := orphanFinder{log, sa, ca, issuers, backdateDuration}

	testCert := mustLoadCert("testdata/example.com/cert.pem")
	testCertDERHex := hex.EncodeToString(testCert.Raw)
	testPreCert := mustLoadCert("testdata/example.com/precert.pem")
	testPreCertDERHex := hex.EncodeToString(testPreCert.Raw)

	logLine := func(typ orphanType, der, regID, orderID string) string {
		return fmt.Sprintf(
			"0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: "+
				"[AUDIT] Failed RPC to store at SA, orphaning %s: "+
				"cert=[%s] err=[context deadline exceeded], regID=[%s], orderID=[%s]",
			typ, der, regID, orderID)
	}

	testCases := []struct {
		Name           string
		LogLine        string
		ExpectFound    bool
		ExpectAdded    bool
		ExpectNoErrors bool
		ExpectAddedDER string
		ExpectRegID    int
	}{
		{
			Name:           "Empty line",
			LogLine:        "",
			ExpectFound:    false,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Empty cert in line",
			LogLine:        logLine(certOrphan, "", "1337", "0"),
			ExpectFound:    true,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Invalid cert in line",
			LogLine:        logLine(certOrphan, "deadbeef", "", ""),
			ExpectFound:    true,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Valid cert in line",
			LogLine:        logLine(certOrphan, testCertDERHex, "1001", "0"),
			ExpectFound:    true,
			ExpectAdded:    true,
			ExpectAddedDER: testCertDERHex,
			ExpectRegID:    1001,
			ExpectNoErrors: true,
		},
		{
			Name:        "Already inserted cert in line",
			LogLine:     logLine(certOrphan, testCertDERHex, "1001", "0"),
			ExpectFound: true,
			// ExpectAdded is false because we have already added this cert in the
			// previous "Valid cert in line" test case.
			ExpectAdded:    false,
			ExpectNoErrors: true,
		},
		{
			Name:           "Empty precert in line",
			LogLine:        logLine(precertOrphan, "", "1337", "0"),
			ExpectFound:    true,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Invalid precert in line",
			LogLine:        logLine(precertOrphan, "deadbeef", "", ""),
			ExpectFound:    true,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Valid precert in line",
			LogLine:        logLine(precertOrphan, testPreCertDERHex, "9999", "0"),
			ExpectFound:    true,
			ExpectAdded:    true,
			ExpectAddedDER: testPreCertDERHex,
			ExpectRegID:    9999,
			ExpectNoErrors: true,
		},
		{
			Name:        "Already inserted precert in line",
			LogLine:     logLine(precertOrphan, testPreCertDERHex, "1001", "0"),
			ExpectFound: true,
			// ExpectAdded is false because we have already added this cert in the
			// previous "Valid cert in line" test case.
			ExpectAdded:    false,
			ExpectNoErrors: true,
		},
		{
			Name:           "Unknown orphan type",
			LogLine:        logLine(unknownOrphan, testPreCertDERHex, "1001", "0"),
			ExpectFound:    false,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			log.Clear()
			found, added, typ := of.storeParsedLogLine(tc.LogLine)
			t.Logf("%s", log.GetAllMatching(".*"))
			test.AssertEquals(t, found, tc.ExpectFound)
			test.AssertEquals(t, added, tc.ExpectAdded)
			logs := log.GetAllMatching("ERR:")
			if tc.ExpectNoErrors {
				test.AssertEquals(t, len(logs), 0)
			}

			if tc.ExpectAdded {
				// Decode the precert/cert DER we expect the testcase added to get the
				// certificate serial
				der, _ := hex.DecodeString(tc.ExpectAddedDER)
				testCert, _ := x509.ParseCertificate(der)
				testCertSerial := core.SerialToString(testCert.SerialNumber)

				// Fetch the precert/cert using the correct mock SA function
				var storedCert core.Certificate
				switch typ {
				case precertOrphan:
					resp, err := sa.GetPrecertificate(context.Background(), &sapb.Serial{Serial: &testCertSerial})
					test.AssertNotError(t, err, "Error getting test precert serial from SA")
					precert, err := bgrpc.PBToCert(resp)
					test.AssertNotError(t, err, "Error getting test precert from GetPrecertificate pb response")
					storedCert = precert
				case certOrphan:
					cert, err := sa.GetCertificate(context.Background(), testCertSerial)
					test.AssertNotError(t, err, "Error getting test cert serial from SA")
					storedCert = cert
				default:
					t.Fatalf("unknown orphan type returned: %s", typ)
				}
				// The orphan should have been added with the correct registration ID from the log line
				test.AssertEquals(t, storedCert.RegistrationID, int64(tc.ExpectRegID))
				// The Issued timestamp should be the certificate's NotBefore timestamp offset by the backdateDuration
				expectedIssued := testCert.NotBefore.Add(backdateDuration)
				test.Assert(t, storedCert.Issued.Equal(expectedIssued),
					fmt.Sprintf("stored cert issued date (%s) was not equal to expected (%s)",
						storedCert.Issued, expectedIssued))
			}
		})
	}
}

func TestNotOrphan(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	sa := &mockSA{}
	ca := &mockCA{}
	issuers, err := loadIssuers([]string{"../../test/test-ca.pem", "../../test/test-ca2.pem"})
	test.AssertNotError(t, err, "loading issuers")
	of := orphanFinder{log, sa, ca, issuers, time.Hour}

	log.Clear()
	found, added, typ := of.storeParsedLogLine("cert=fakeout")
	test.AssertEquals(t, found, false)
	test.AssertEquals(t, added, false)
	test.AssertEquals(t, typ, unknownOrphan)
	checkNoErrors(t)
}
