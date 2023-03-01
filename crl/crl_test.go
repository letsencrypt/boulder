package crl

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/jmhodges/clock"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/linter"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/ocsp"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/test"
	"github.com/prometheus/client_golang/prometheus"
)

type testCtx struct {
	pa             core.PolicyAuthority
	ocsp           *ocsp.OcspImpl
	crl            *CrlImpl
	certExpiry     time.Duration
	certBackdate   time.Duration
	serialPrefix   int
	maxNames       int
	boulderIssuers []*issuance.Issuer
	keyPolicy      goodkey.KeyPolicy
	fc             clock.FakeClock
	stats          prometheus.Registerer
	signatureCount *prometheus.CounterVec
	signErrorCount *prometheus.CounterVec
	logger         *blog.Mock
}

// Useful key and certificate files.
const caKeyFile = "../test/test-ca.key"
const caCertFile = "../test/test-ca.pem"
const caCertFile2 = "../test/test-ca2.pem"

var caKey crypto.Signer
var caCert *issuance.Certificate
var caCert2 *issuance.Certificate
var caLinter *linter.Linter
var caLinter2 *linter.Linter

func init() {
	var err error
	caCert, caKey, err = issuance.LoadIssuer(issuance.IssuerLoc{
		File:     caKeyFile,
		CertFile: caCertFile,
	})
	if err != nil {
		panic(fmt.Sprintf("Unable to load %q and %q: %s", caKeyFile, caCertFile, err))
	}
	caCert2, err = issuance.LoadCertificate(caCertFile2)
	if err != nil {
		panic(fmt.Sprintf("Unable to parse %q: %s", caCertFile2, err))
	}
	caLinter, _ = linter.New(caCert.Certificate, caKey, []string{"n_subject_common_name_included"})
	caLinter2, _ = linter.New(caCert2.Certificate, caKey, []string{"n_subject_common_name_included"})
}

func setup(t *testing.T) *testCtx {
	features.Reset()
	fc := clock.NewFake()
	fc.Add(1 * time.Hour)

	pa, err := policy.New(nil, blog.NewMock())
	test.AssertNotError(t, err, "Couldn't create PA")
	err = pa.SetHostnamePolicyFile("../test/hostname-policy.yaml")
	test.AssertNotError(t, err, "Couldn't set hostname policy")

	boulderProfile := func(rsa, ecdsa bool) *issuance.Profile {
		res, _ := issuance.NewProfile(
			issuance.ProfileConfig{
				AllowMustStaple: true,
				AllowCTPoison:   true,
				AllowSCTList:    true,
				AllowCommonName: true,
				Policies: []issuance.PolicyInformation{
					{OID: "2.23.140.1.2.1"},
				},
				MaxValidityPeriod:   config.Duration{Duration: time.Hour * 8760},
				MaxValidityBackdate: config.Duration{Duration: time.Hour},
			},
			issuance.IssuerConfig{
				UseForECDSALeaves: ecdsa,
				UseForRSALeaves:   rsa,
				IssuerURL:         "http://not-example.com/issuer-url",
				OCSPURL:           "http://not-example.com/ocsp",
				CRLURL:            "http://not-example.com/crl",
			},
		)
		return res
	}
	boulderIssuers := []*issuance.Issuer{
		// Must list ECDSA-only issuer first, so it is the default for ECDSA.
		{
			Cert:    caCert2,
			Signer:  caKey,
			Profile: boulderProfile(false, true),
			Linter:  caLinter2,
			Clk:     fc,
		},
		{
			Cert:    caCert,
			Signer:  caKey,
			Profile: boulderProfile(true, true),
			Linter:  caLinter,
			Clk:     fc,
		},
	}

	keyPolicy := goodkey.KeyPolicy{
		AllowRSA:           true,
		AllowECDSANISTP256: true,
		AllowECDSANISTP384: true,
	}
	signatureCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signatures",
			Help: "Number of signatures",
		},
		[]string{"purpose", "issuer"})
	signErrorCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "signature_errors",
		Help: "A counter of signature errors labelled by error type",
	}, []string{"type"})

	ocsp, err := ocsp.NewOCSPImpl(
		boulderIssuers,
		time.Hour,
		0,
		time.Second,
		blog.NewMock(),
		metrics.NoopRegisterer,
		signatureCount,
		signErrorCount,
		fc,
	)
	test.AssertNotError(t, err, "Failed to create ocsp impl")

	crl, err := NewCRLImpl(
		boulderIssuers,
		time.Hour,
		"http://c.boulder.test",
		100,
		blog.NewMock(),
	)
	test.AssertNotError(t, err, "Failed to create crl impl")

	return &testCtx{
		pa:             pa,
		ocsp:           ocsp,
		crl:            crl,
		certExpiry:     8760 * time.Hour,
		certBackdate:   time.Hour,
		serialPrefix:   17,
		maxNames:       2,
		boulderIssuers: boulderIssuers,
		keyPolicy:      keyPolicy,
		fc:             fc,
		stats:          metrics.NoopRegisterer,
		signatureCount: signatureCount,
		signErrorCount: signErrorCount,
		logger:         blog.NewMock(),
	}
}

func TestId(t *testing.T) {
	thisUpdate := time.Now()
	out := Id(1337, Number(thisUpdate), 1)
	expectCRLId := fmt.Sprintf("{\"issuerID\":1337,\"crlNumber\":%d,\"shardIdx\":1}", big.NewInt(thisUpdate.UnixNano()))
	test.AssertEquals(t, string(out), expectCRLId)
}

type mockGenerateCRLBidiStream struct {
	grpc.ServerStream
	input  <-chan *capb.GenerateCRLRequest
	output chan<- *capb.GenerateCRLResponse
}

func (s mockGenerateCRLBidiStream) Recv() (*capb.GenerateCRLRequest, error) {
	next, ok := <-s.input
	if !ok {
		return nil, io.EOF
	}
	return next, nil
}

func (s mockGenerateCRLBidiStream) Send(entry *capb.GenerateCRLResponse) error {
	s.output <- entry
	return nil
}

func TestGenerateCRL(t *testing.T) {
	testCtx := setup(t)
	crli := testCtx.crl
	errs := make(chan error, 1)

	// Test that we get an error when no metadata is sent.
	ins := make(chan *capb.GenerateCRLRequest)
	go func() {
		errs <- crli.GenerateCRL(mockGenerateCRLBidiStream{input: ins, output: nil})
	}()
	close(ins)
	err := <-errs
	test.AssertError(t, err, "can't generate CRL with no metadata")
	test.AssertContains(t, err.Error(), "no crl metadata received")

	// Test that we get an error when incomplete metadata is sent.
	ins = make(chan *capb.GenerateCRLRequest)
	go func() {
		errs <- crli.GenerateCRL(mockGenerateCRLBidiStream{input: ins, output: nil})
	}()
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Metadata{
			Metadata: &capb.CRLMetadata{},
		},
	}
	close(ins)
	err = <-errs
	test.AssertError(t, err, "can't generate CRL with incomplete metadata")
	test.AssertContains(t, err.Error(), "got incomplete metadata message")

	// Test that we get an error when unrecognized metadata is sent.
	ins = make(chan *capb.GenerateCRLRequest)
	go func() {
		errs <- crli.GenerateCRL(mockGenerateCRLBidiStream{input: ins, output: nil})
	}()
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Metadata{
			Metadata: &capb.CRLMetadata{
				IssuerNameID: 1,
				ThisUpdate:   time.Now().UnixNano(),
			},
		},
	}
	close(ins)
	err = <-errs
	test.AssertError(t, err, "can't generate CRL with bad metadata")
	test.AssertContains(t, err.Error(), "got unrecognized IssuerNameID")

	// Test that we get an error when two metadata are sent.
	ins = make(chan *capb.GenerateCRLRequest)
	go func() {
		errs <- crli.GenerateCRL(mockGenerateCRLBidiStream{input: ins, output: nil})
	}()
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Metadata{
			Metadata: &capb.CRLMetadata{
				IssuerNameID: int64(testCtx.boulderIssuers[0].Cert.NameID()),
				ThisUpdate:   time.Now().UnixNano(),
			},
		},
	}
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Metadata{
			Metadata: &capb.CRLMetadata{
				IssuerNameID: int64(testCtx.boulderIssuers[0].Cert.NameID()),
				ThisUpdate:   time.Now().UnixNano(),
			},
		},
	}
	close(ins)
	err = <-errs
	test.AssertError(t, err, "can't generate CRL with duplicate metadata")
	test.AssertContains(t, err.Error(), "got more than one metadata message")

	// Test that we get an error when an entry has a bad serial.
	ins = make(chan *capb.GenerateCRLRequest)
	go func() {
		errs <- crli.GenerateCRL(mockGenerateCRLBidiStream{input: ins, output: nil})
	}()
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Entry{
			Entry: &corepb.CRLEntry{
				Serial:    "123",
				Reason:    1,
				RevokedAt: time.Now().UnixNano(),
			},
		},
	}
	close(ins)
	err = <-errs
	test.AssertError(t, err, "can't generate CRL with bad serials")
	test.AssertContains(t, err.Error(), "Invalid serial number")

	// Test that we get an error when an entry has a bad revocation time.
	ins = make(chan *capb.GenerateCRLRequest)
	go func() {
		errs <- crli.GenerateCRL(mockGenerateCRLBidiStream{input: ins, output: nil})
	}()
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Entry{
			Entry: &corepb.CRLEntry{
				Serial:    "deadbeefdeadbeefdeadbeefdeadbeefdead",
				Reason:    1,
				RevokedAt: 0,
			},
		},
	}
	close(ins)
	err = <-errs
	test.AssertError(t, err, "can't generate CRL with bad serials")
	test.AssertContains(t, err.Error(), "got empty or zero revocation timestamp")

	// Test that generating an empty CRL works.
	ins = make(chan *capb.GenerateCRLRequest)
	outs := make(chan *capb.GenerateCRLResponse)
	go func() {
		errs <- crli.GenerateCRL(mockGenerateCRLBidiStream{input: ins, output: outs})
		close(outs)
	}()
	crlBytes := make([]byte, 0)
	done := make(chan struct{})
	go func() {
		for resp := range outs {
			crlBytes = append(crlBytes, resp.Chunk...)
		}
		close(done)
	}()
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Metadata{
			Metadata: &capb.CRLMetadata{
				IssuerNameID: int64(testCtx.boulderIssuers[0].Cert.NameID()),
				ThisUpdate:   time.Now().UnixNano(),
			},
		},
	}
	close(ins)
	err = <-errs
	<-done
	test.AssertNotError(t, err, "generating empty CRL should work")
	test.Assert(t, len(crlBytes) > 0, "should have gotten some CRL bytes")
	crl, err := x509.ParseCRL(crlBytes)
	test.AssertNotError(t, err, "should be able to parse empty CRL")
	test.AssertEquals(t, len(crl.TBSCertList.RevokedCertificates), 0)
	err = testCtx.boulderIssuers[0].Cert.CheckCRLSignature(crl)
	test.AssertNotError(t, err, "CRL signature should validate")

	// Test that generating a CRL with some entries works.
	ins = make(chan *capb.GenerateCRLRequest)
	outs = make(chan *capb.GenerateCRLResponse)
	go func() {
		errs <- crli.GenerateCRL(mockGenerateCRLBidiStream{input: ins, output: outs})
		close(outs)
	}()
	crlBytes = make([]byte, 0)
	done = make(chan struct{})
	go func() {
		for resp := range outs {
			crlBytes = append(crlBytes, resp.Chunk...)
		}
		close(done)
	}()
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Metadata{
			Metadata: &capb.CRLMetadata{
				IssuerNameID: int64(testCtx.boulderIssuers[0].Cert.NameID()),
				ThisUpdate:   time.Now().UnixNano(),
			},
		},
	}
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Entry{
			Entry: &corepb.CRLEntry{
				Serial:    "000000000000000000000000000000000000",
				RevokedAt: time.Now().UnixNano(),
				// Reason 0, Unspecified, is omitted.
			},
		},
	}
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Entry{
			Entry: &corepb.CRLEntry{
				Serial:    "111111111111111111111111111111111111",
				Reason:    1, // keyCompromise
				RevokedAt: time.Now().UnixNano(),
			},
		},
	}
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Entry{
			Entry: &corepb.CRLEntry{
				Serial:    "444444444444444444444444444444444444",
				Reason:    4, // superseded
				RevokedAt: time.Now().UnixNano(),
			},
		},
	}
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Entry{
			Entry: &corepb.CRLEntry{
				Serial:    "555555555555555555555555555555555555",
				Reason:    5, // cessationOfOperation
				RevokedAt: time.Now().UnixNano(),
			},
		},
	}
	ins <- &capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Entry{
			Entry: &corepb.CRLEntry{
				Serial:    "999999999999999999999999999999999999",
				Reason:    9, // privilegeWithdrawn
				RevokedAt: time.Now().UnixNano(),
			},
		},
	}
	close(ins)
	err = <-errs
	<-done
	test.AssertNotError(t, err, "generating empty CRL should work")
	test.Assert(t, len(crlBytes) > 0, "should have gotten some CRL bytes")
	crl, err = x509.ParseCRL(crlBytes)
	test.AssertNotError(t, err, "should be able to parse empty CRL")
	test.AssertEquals(t, len(crl.TBSCertList.RevokedCertificates), 5)
	err = testCtx.boulderIssuers[0].Cert.CheckCRLSignature(crl)
	test.AssertNotError(t, err, "CRL signature should validate")
}
