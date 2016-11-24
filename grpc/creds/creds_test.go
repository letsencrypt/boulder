package creds

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
)

func TestServerTransportCredentials(t *testing.T) {
	acceptedSANs := map[string]struct{}{
		"boulder-client": struct{}{},
	}
	goodCert, err := core.LoadCert("../../test/grpc-creds/boulder-client/cert.pem")
	test.AssertNotError(t, err, "core.LoadCert('../../grpc-creds/boulder-client/cert.pem') failed")
	badCert, err := core.LoadCert("../../test/test-root.pem")
	test.AssertNotError(t, err, "core.LoadCert('../../test-root.pem') failed")
	servTLSConfig := &tls.Config{}

	// NewServerCredentials with a nil serverTLSConfig should return an error
	_, err = NewServerCredentials(nil, acceptedSANs)
	test.AssertEquals(t, err, NilServerConfigErr)

	// A creds with a nil acceptedSANs list should consider any peer valid
	bcreds := &serverTransportCredentials{servTLSConfig, nil}
	emptyState := tls.ConnectionState{}
	err = bcreds.validateClient(emptyState)
	test.AssertNotError(t, err, "validateClient() errored for emptyState")

	// A creds given an empty TLS ConnectionState to verify should return an error
	bcreds = &serverTransportCredentials{servTLSConfig, acceptedSANs}
	err = bcreds.validateClient(emptyState)
	test.AssertEquals(t, err, EmptyPeerCertsErr)

	// A creds should reject peers that don't have a leaf certificate with
	// a SAN on the accepted list.
	wrongState := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{badCert},
	}
	err = bcreds.validateClient(wrongState)
	test.AssertEquals(t, err, SANNotAcceptedErr)

	// A creds should accept peers that have a leaf certificate with a SAN
	// that is on the accepted list
	rightState := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{goodCert},
	}
	err = bcreds.validateClient(rightState)
	test.AssertNotError(t, err, "validateClient(rightState) failed")

	// A creds configured with an IP SAN in the accepted list should accept a peer
	// that has a leaf certificate containing an IP address SAN present in the
	// accepted list.
	acceptedIPSans := map[string]struct{}{
		"127.0.0.1": struct{}{},
	}
	bcreds = &serverTransportCredentials{servTLSConfig, acceptedIPSans}
	err = bcreds.validateClient(rightState)
	test.AssertNotError(t, err, "validateClient(rightState) failed with an IP accepted SAN list")
}
