package creds

import (
	"crypto/tls"
	"errors"
	"net"

	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
)

var (
	ClientHandshakeNopErr = errors.New(
		"boulder/grpc/creds: Client-side handshakes are not implemented with " +
			"serverTransportCredentials")
	OverrideServerNameNopErr = errors.New(
		"boulder/grpc/creds: OverrideServerName() is not implemented with " +
			"serverTransportCredentials")
	NilServerConfigErr = errors.New(
		"boulder/grpc/creds: `serverConfig` must not be nil")
	EmptyPeerCertsErr = errors.New(
		"boulder/grpc/creds: validateClient given state with empty PeerCertificates")
	SANNotAcceptedErr = errors.New(
		"boulder/grpc/creds: peer's client certificate SAN entries did not match " +
			"any entries on accepted SAN list.")
)

// serverTransportCredentials is a grpc/credentials.TransportCredentials which supports
// filtering acceptable peer connections by a list of accepted client certificate SANs
type serverTransportCredentials struct {
	serverConfig *tls.Config
	acceptedSANs map[string]struct{}
}

// NewServerCredentials returns a new initialized grpc/credentials.TransportCredentials for server usage
func NewServerCredentials(serverConfig *tls.Config, acceptedSANs map[string]struct{}) (credentials.TransportCredentials, error) {
	if serverConfig == nil {
		return nil, NilServerConfigErr
	}

	return &serverTransportCredentials{serverConfig, acceptedSANs}, nil
}

// validateClient checks a peer's client certificate's SAN entries against
// a list of accepted SANs. If the client certificate does not have a SAN on the
// list it is rejected.
//
// Note 1: This function *only* verifies the SAN entries! Callers are expected to
// have provided the `tls.ConnectionState` from returned from a validate (e.g.
// non-error producing) `conn.Handshake()`.
//
// Note 2: We do *not* consider the client certificate subject common name. The
// CN field is deprecated and should be present as a DNS SAN!
func (tc *serverTransportCredentials) validateClient(peerState tls.ConnectionState) error {
	/*
	 * If there's no list of accepted SANs, all clients are OK
	 *
	 * TODO(@cpu): This should be converted to a hard error at initialization time
	 * once we have deployed & updated all gRPC configurations to have an accepted
	 * SAN list configured
	 */
	if tc.acceptedSANs == nil {
		return nil
	}

	// If `conn.Handshake()` is called before `validateClient` this should not
	// occur. We return an error in this event primarily for unit tests that may
	// call `validateClient` with manufactured & artificial connection states.
	if len(peerState.PeerCertificates) < 1 {
		return EmptyPeerCertsErr
	}

	// Since we call `conn.Handshake()` before `validateClient` and ensure
	// a non-error response we don't need to validate anything except the presence
	// of an accepted SAN in the leaf entry of `PeerCertificates`. The tls
	// package's `serverHandshake` and in particular, `processCertsFromClient`
	// will address everything else as an error returned from `Handshake()`.
	var valid bool
	leaf := peerState.PeerCertificates[0]

	// First check the DNS subject alternate names against the accepted list
	for _, dnsName := range leaf.DNSNames {
		if _, ok := tc.acceptedSANs[dnsName]; ok {
			valid = true
		}
	}
	// Next check the IP address subject alternate names against the accepted list
	for _, ip := range leaf.IPAddresses {
		if _, ok := tc.acceptedSANs[ip.String()]; ok {
			valid = true
		}
	}

	// If none of the DNS or IP SANs on the leaf certificate matched the
	// accepted list, the client isn't valid and we error
	if !valid {
		return SANNotAcceptedErr
	}

	// Otherwise, the peer is valid!
	return nil
}

// ServerHandshake does the authentication handshake for servers. It returns
// the authenticated connection and the corresponding auth information about
// the connection.
func (tc *serverTransportCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// Perform the server <- client TLS handshake. This will validate the peer's
	// client certificate.
	conn := tls.Server(rawConn, tc.serverConfig)
	if err := conn.Handshake(); err != nil {
		return nil, nil, err
	}

	// In addition to the validation from `conn.Handshake()` we apply further
	// constraints on what constitutes a valid peer
	if err := tc.validateClient(conn.ConnectionState()); err != nil {
		return nil, nil, err
	}

	return conn, credentials.TLSInfo{conn.ConnectionState()}, nil
}

// ClientHandshake is not implemented for a `serverTransportCredentials`, use
// a `clientTransportCredentials` if you require `ClientHandshake`.
func (tc *serverTransportCredentials) ClientHandshake(ctx context.Context, addr string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ClientHandshakeNopErr
}

// Info provides the ProtocolInfo of this TransportCredentials.
func (tc *serverTransportCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2", // We *only* support TLS 1.2
	}
}

// GetRequestMetadata returns nil, nil since TLS credentials do not have metadata.
func (tc *serverTransportCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return nil, nil
}

// RequireTransportSecurity always returns true because TLS is transport security
func (tc *serverTransportCredentials) RequireTransportSecurity() bool {
	return true
}

// Clone returns a copy of the serverTransportCredentials
func (tc *serverTransportCredentials) Clone() credentials.TransportCredentials {
	clone, _ := NewServerCredentials(tc.serverConfig, tc.acceptedSANs)
	return clone
}

// OverrideServerName is not implemented and here only to satisfy the interface
func (tc *serverTransportCredentials) OverrideServerName(serverNameOverride string) error {
	return OverrideServerNameNopErr
}
