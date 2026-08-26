package storer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/jmhodges/clock"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/crl/idp"
	cspb "github.com/letsencrypt/boulder/crl/storer/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
)

// fakeSA is a fake sapb.StorageAuthorityReadOnlyClient whose GetSerialMetadata
// returns the configured expiry for known serials, and NotFound otherwise.
type fakeSA struct {
	sapb.StorageAuthorityReadOnlyClient
	expires map[string]time.Time
}

func (f *fakeSA) GetSerialMetadata(_ context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*sapb.SerialMetadata, error) {
	expires, ok := f.expires[req.Serial]
	if !ok {
		return nil, berrors.NotFoundError("serial %q not found", req.Serial)
	}
	return &sapb.SerialMetadata{Serial: req.Serial, Expires: timestamppb.New(expires)}, nil
}

type fakeUploadCRLServerStream struct {
	grpc.ServerStream
	input <-chan *cspb.UploadCRLRequest
}

func (s *fakeUploadCRLServerStream) Recv() (*cspb.UploadCRLRequest, error) {
	next, ok := <-s.input
	if !ok {
		return nil, io.EOF
	}
	return next, nil
}

func (s *fakeUploadCRLServerStream) SendAndClose(*emptypb.Empty) error {
	return nil
}

func (s *fakeUploadCRLServerStream) Context() context.Context {
	return context.Background()
}

func setupTestUploadCRL(t *testing.T) (*crlStorer, *issuance.Issuer) {
	t.Helper()

	r3, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "loading fake RSA issuer cert")
	issuerE1, err := issuance.LoadIssuer(
		issuance.IssuerConfig{
			Location: issuance.IssuerLoc{
				File:     "../../test/hierarchy/int-e1.key.pem",
				CertFile: "../../test/hierarchy/int-e1.cert.pem",
			},
			IssuerURL:  "http://not-example.com/issuer-url",
			CRLURLBase: "http://not-example.com/crl/",
			CRLShards:  1,
		}, clock.NewFake())
	test.AssertNotError(t, err, "loading fake ECDSA issuer cert")

	storer, err := New(
		[]*issuance.Certificate{r3, issuerE1.Cert},
		nil,
		&fakeSA{},
		core.DefaultMaxCRLRead,
		metrics.NoopRegisterer, blog.NewMock(), clock.NewFake(),
	)
	test.AssertNotError(t, err, "creating test crl-storer")

	return storer, issuerE1
}

// Test that we get an error when no metadata is sent.
func TestUploadCRLNoMetadata(t *testing.T) {
	storer, _ := setupTestUploadCRL(t)
	errs := make(chan error, 1)

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	close(ins)
	err := <-errs
	test.AssertError(t, err, "can't upload CRL with no metadata")
	test.AssertContains(t, err.Error(), "no metadata")
}

// Test that we get an error when incomplete metadata is sent.
func TestUploadCRLIncompleteMetadata(t *testing.T) {
	storer, _ := setupTestUploadCRL(t)
	errs := make(chan error, 1)

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{},
		},
	}
	close(ins)
	err := <-errs
	test.AssertError(t, err, "can't upload CRL with incomplete metadata")
	test.AssertContains(t, err.Error(), "incomplete metadata")
}

// Test that we get an error when a bad issuer is sent.
func TestUploadCRLUnrecognizedIssuer(t *testing.T) {
	storer, _ := setupTestUploadCRL(t)
	errs := make(chan error, 1)

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: 1,
				Number:       1,
			},
		},
	}
	close(ins)
	err := <-errs
	test.AssertError(t, err, "can't upload CRL with unrecognized issuer")
	test.AssertContains(t, err.Error(), "unrecognized")
}

// Test that we get an error when two metadata are sent.
func TestUploadCRLMultipleMetadata(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	errs := make(chan error, 1)

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(iss.Cert.NameID()),
				Number:       1,
			},
		},
	}
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(iss.Cert.NameID()),
				Number:       1,
			},
		},
	}
	close(ins)
	err := <-errs
	test.AssertError(t, err, "can't upload CRL with multiple metadata")
	test.AssertContains(t, err.Error(), "more than one")
}

// Test that we get an error when a CRL is too large
func TestUploadCRLTooManyBytes(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	storer.maxCRLSize = 3
	errs := make(chan error, 1)

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(iss.Cert.NameID()),
				Number:       1,
			},
		},
	}
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_CrlChunk{
			CrlChunk: []byte("just more bytes than configured above"),
		},
	}
	close(ins)
	err := <-errs
	test.AssertError(t, err, "can't upload oversized CRL")
	test.AssertContains(t, err.Error(), "crl too large")
}

// Test that we get an error when a malformed CRL is sent.
func TestUploadCRLMalformedBytes(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	errs := make(chan error, 1)

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(iss.Cert.NameID()),
				Number:       1,
			},
		},
	}
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_CrlChunk{
			CrlChunk: []byte("this is not a valid crl"),
		},
	}
	close(ins)
	err := <-errs
	test.AssertError(t, err, "can't upload unparsable CRL")
	test.AssertContains(t, err.Error(), "parsing CRL")
}

// Test that we get an error when an invalid CRL (signed by a throwaway
// private key but tagged as being from a "real" issuer) is sent.
func TestUploadCRLInvalidSignature(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	errs := make(chan error, 1)

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(iss.Cert.NameID()),
				Number:       1,
			},
		},
	}
	fakeSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating throwaway signer")
	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(1),
		},
		iss.Cert.Certificate,
		fakeSigner,
	)
	test.AssertNotError(t, err, "creating test CRL")
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_CrlChunk{
			CrlChunk: crlBytes,
		},
	}
	close(ins)
	err = <-errs
	test.AssertError(t, err, "can't upload unverifiable CRL")
	test.AssertContains(t, err.Error(), "validating signature")
}

// Test that we get an error if the CRL Numbers mismatch.
func TestUploadCRLMismatchedNumbers(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	errs := make(chan error, 1)

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(iss.Cert.NameID()),
				Number:       1,
			},
		},
	}
	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(2),
		},
		iss.Cert.Certificate,
		iss.Signer,
	)
	test.AssertNotError(t, err, "creating test CRL")
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_CrlChunk{
			CrlChunk: crlBytes,
		},
	}
	close(ins)
	err = <-errs
	test.AssertError(t, err, "can't upload CRL with mismatched number")
	test.AssertContains(t, err.Error(), "mismatched")
}

// fakeSimpleS3 implements the simpleS3 interface, provides prevBytes for
// downloads, and checks that uploads match the expectBytes.
type fakeSimpleS3 struct {
	prevBytes   []byte
	expectBytes []byte
}

func (p *fakeSimpleS3) Bucket() string {
	return "fakebucket"
}

func (p *fakeSimpleS3) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	recvBytes, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(p.expectBytes, recvBytes) {
		return nil, errors.New("received bytes did not match expectation")
	}
	return &s3.PutObjectOutput{}, nil
}

func (p *fakeSimpleS3) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if p.prevBytes != nil {
		return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(p.prevBytes))}, nil
	}
	return nil, &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 404}}}
}

// Test that the correct bytes get propagated to S3.
func TestUploadCRLSuccess(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	errs := make(chan error, 1)

	idpExt, err := idp.MakeUserCertsExt([]string{"http://c.ex.org"})
	test.AssertNotError(t, err, "creating test IDP extension")

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(iss.Cert.NameID()),
				Number:       2,
			},
		},
	}

	prevCRLBytes, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			ThisUpdate: storer.clk.Now(),
			NextUpdate: storer.clk.Now().Add(time.Hour),
			Number:     big.NewInt(1),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(123), RevocationTime: time.Now().Add(-time.Hour)},
			},
			ExtraExtensions: []pkix.Extension{idpExt},
		},
		iss.Cert.Certificate,
		iss.Signer,
	)
	test.AssertNotError(t, err, "creating test CRL")

	storer.clk.Sleep(time.Minute)

	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			ThisUpdate: storer.clk.Now(),
			NextUpdate: storer.clk.Now().Add(time.Hour),
			Number:     big.NewInt(2),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(123), RevocationTime: time.Now().Add(-time.Hour)},
			},
			ExtraExtensions: []pkix.Extension{idpExt},
		},
		iss.Cert.Certificate,
		iss.Signer,
	)
	test.AssertNotError(t, err, "creating test CRL")

	storer.s3Client = &fakeSimpleS3{prevBytes: prevCRLBytes, expectBytes: crlBytes}
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_CrlChunk{
			CrlChunk: crlBytes,
		},
	}
	close(ins)
	err = <-errs
	test.AssertNotError(t, err, "uploading valid CRL should work")
}

// Test that the correct bytes get propagated to S3 for a CRL with to predecessor.
func TestUploadNewCRLSuccess(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	errs := make(chan error, 1)

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(iss.Cert.NameID()),
				Number:       1,
			},
		},
	}

	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(1),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(123), RevocationTime: time.Now().Add(-time.Hour)},
			},
		},
		iss.Cert.Certificate,
		iss.Signer,
	)
	test.AssertNotError(t, err, "creating test CRL")

	storer.s3Client = &fakeSimpleS3{expectBytes: crlBytes}
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_CrlChunk{
			CrlChunk: crlBytes,
		},
	}
	close(ins)
	err = <-errs
	test.AssertNotError(t, err, "uploading valid CRL should work")
}

// Test that we get an error when the previous CRL has a higher CRL number.
func TestUploadCRLBackwardsNumber(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	errs := make(chan error, 1)

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(iss.Cert.NameID()),
				Number:       1,
			},
		},
	}

	prevCRLBytes, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			ThisUpdate: storer.clk.Now(),
			NextUpdate: storer.clk.Now().Add(time.Hour),
			Number:     big.NewInt(2),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(123), RevocationTime: time.Now().Add(-time.Hour)},
			},
		},
		iss.Cert.Certificate,
		iss.Signer,
	)
	test.AssertNotError(t, err, "creating test CRL")

	storer.clk.Sleep(time.Minute)

	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			ThisUpdate: storer.clk.Now(),
			NextUpdate: storer.clk.Now().Add(time.Hour),
			Number:     big.NewInt(1),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(123), RevocationTime: time.Now().Add(-time.Hour)},
			},
		},
		iss.Cert.Certificate,
		iss.Signer,
	)
	test.AssertNotError(t, err, "creating test CRL")

	storer.s3Client = &fakeSimpleS3{prevBytes: prevCRLBytes, expectBytes: crlBytes}
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_CrlChunk{
			CrlChunk: crlBytes,
		},
	}
	close(ins)
	err = <-errs
	test.AssertError(t, err, "uploading out-of-order numbers should fail")
	test.AssertContains(t, err.Error(), "crlNumber not strictly increasing")
}

// uploadWithRemovedEntry runs UploadCRL for a CRL containing serial 123 whose
// predecessor contained serials 123 and 456, and returns the resulting error.
func uploadWithRemovedEntry(t *testing.T, storer *crlStorer, iss *issuance.Issuer) error {
	t.Helper()
	errs := make(chan error, 1)

	idpExt, err := idp.MakeUserCertsExt([]string{"http://c.ex.org"})
	test.AssertNotError(t, err, "creating test IDP extension")

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(iss.Cert.NameID()),
				Number:       2,
			},
		},
	}

	prevCRLBytes, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			ThisUpdate: storer.clk.Now(),
			NextUpdate: storer.clk.Now().Add(time.Hour),
			Number:     big.NewInt(1),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(123), RevocationTime: storer.clk.Now().Add(-time.Hour)},
				{SerialNumber: big.NewInt(456), RevocationTime: storer.clk.Now().Add(-time.Hour)},
			},
			ExtraExtensions: []pkix.Extension{idpExt},
		},
		iss.Cert.Certificate,
		iss.Signer,
	)
	test.AssertNotError(t, err, "creating test CRL")

	storer.clk.Sleep(time.Minute)

	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			ThisUpdate: storer.clk.Now(),
			NextUpdate: storer.clk.Now().Add(time.Hour),
			Number:     big.NewInt(2),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(123), RevocationTime: storer.clk.Now().Add(-time.Hour)},
			},
			ExtraExtensions: []pkix.Extension{idpExt},
		},
		iss.Cert.Certificate,
		iss.Signer,
	)
	test.AssertNotError(t, err, "creating test CRL")

	storer.s3Client = &fakeSimpleS3{prevBytes: prevCRLBytes, expectBytes: crlBytes}
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_CrlChunk{
			CrlChunk: crlBytes,
		},
	}
	close(ins)
	return <-errs
}

// Test that an entry may be dropped once its certificate has expired.
func TestUploadCRLRemovedExpiredEntry(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	storer.sa = &fakeSA{expires: map[string]time.Time{
		core.SerialToString(big.NewInt(456)): storer.clk.Now().Add(-25 * time.Hour),
	}}
	err := uploadWithRemovedEntry(t, storer, iss)
	test.AssertNotError(t, err, "dropping an expired entry should work")
}

// Test that we get an error when an entry is dropped before its certificate
// has expired.
func TestUploadCRLRemovedUnexpiredEntry(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	storer.sa = &fakeSA{expires: map[string]time.Time{
		core.SerialToString(big.NewInt(456)): storer.clk.Now().Add(24 * time.Hour),
	}}
	err := uploadWithRemovedEntry(t, storer, iss)
	test.AssertError(t, err, "dropping an unexpired entry should fail")
	test.AssertContains(t, err.Error(), "appeared on the previous CRL but is missing from this one")
}

// Test that we get an error when an entry is dropped for a certificate which
// expired after the previous CRL was issued.
func TestUploadCRLRemovedRecentlyExpiredEntry(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	storer.sa = &fakeSA{expires: map[string]time.Time{
		core.SerialToString(big.NewInt(456)): storer.clk.Now().Add(30 * time.Second),
	}}
	err := uploadWithRemovedEntry(t, storer, iss)
	test.AssertError(t, err, "dropping an entry which expired after the previous CRL should fail")
	test.AssertContains(t, err.Error(), "lookbackPeriod must cover the gap since that CRL (currently 1m0s, and growing")
}

// Test that dropped entries are not checked when no SA is configured.
//
// TODO(#8983): Remove this once saReadOnlyService is in production configs.
func TestUploadCRLRemovedEntryNoSA(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	storer.sa = nil
	err := uploadWithRemovedEntry(t, storer, iss)
	test.AssertNotError(t, err, "dropping an entry with no SA configured should work")
}

// Test that we get an error when the SA doesn't know a dropped entry's serial.
func TestUploadCRLRemovedUnknownEntry(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	err := uploadWithRemovedEntry(t, storer, iss)
	test.AssertError(t, err, "dropping an unknown entry should fail")
	test.AssertContains(t, err.Error(), "looking up serial")
	test.AssertErrorIs(t, err, berrors.NotFound)
}

// brokenSimpleS3 implements the simpleS3 interface. It returns errors for all
// uploads and downloads.
type brokenSimpleS3 struct{}

func (p *brokenSimpleS3) Bucket() string {
	return "fake bucket"
}

func (p *brokenSimpleS3) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return nil, errors.New("sorry")
}

func (p *brokenSimpleS3) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return nil, errors.New("oops")
}

// Test that we get an error when S3 falls over.
func TestUploadCRLBrokenS3(t *testing.T) {
	storer, iss := setupTestUploadCRL(t)
	errs := make(chan error, 1)

	ins := make(chan *cspb.UploadCRLRequest)
	go func() {
		errs <- storer.UploadCRL(&fakeUploadCRLServerStream{input: ins})
	}()
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(iss.Cert.NameID()),
				Number:       1,
			},
		},
	}
	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(1),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(123), RevocationTime: time.Now().Add(-time.Hour)},
			},
		},
		iss.Cert.Certificate,
		iss.Signer,
	)
	test.AssertNotError(t, err, "creating test CRL")
	storer.s3Client = &brokenSimpleS3{}
	ins <- &cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_CrlChunk{
			CrlChunk: crlBytes,
		},
	}
	close(ins)
	err = <-errs
	test.AssertError(t, err, "uploading to broken S3 should fail")
	test.AssertContains(t, err.Error(), "getting previous CRL")
}
