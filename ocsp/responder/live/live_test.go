package live

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/test"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc"
)

// mockOCSPGenerator is an ocspGenerator that always emits the provided bytes
// when serial number 1 is requested, but otherwise returns an error.
type mockOCSPGenerator struct {
	resp []byte
}

func (m mockOCSPGenerator) GenerateOCSP(ctx context.Context, in *rapb.GenerateOCSPRequest, opts ...grpc.CallOption) (*capb.OCSPResponse, error) {
	expectedSerial := core.SerialToString(big.NewInt(1))
	if in.Serial != expectedSerial {
		return nil, fmt.Errorf("expected serial %s, got %s", expectedSerial, in.Serial)
	}

	return &capb.OCSPResponse{Response: m.resp}, nil
}

func TestLiveResponse(t *testing.T) {
	// Make a fake CA to sign OCSP with
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1337),
		BasicConstraintsValid: true,
		IsCA:                  true,
		Subject:               pkix.Name{CommonName: "test CA"},
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	issuer, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatal(err)
	}

	eeSerial := big.NewInt(1)

	respBytes, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
		SerialNumber: eeSerial,
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	source := New(mockOCSPGenerator{respBytes}, 1)
	resp, err := source.Response(context.Background(), &ocsp.Request{
		SerialNumber: eeSerial,
	})
	test.AssertNotError(t, err, "getting response")
	test.AssertByteEquals(t, resp.Raw, respBytes)
	expectedSerial := "000000000000000000000000000000000001"
	if core.SerialToString(resp.SerialNumber) != expectedSerial {
		t.Errorf("expected serial %s, got %s", expectedSerial, resp.SerialNumber)
	}
}
