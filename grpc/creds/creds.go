package creds

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
)

// transportCredentials is a grpc/credentials.TransportCredentials which supports
// connecting to, and verifying multiple DNS names
type transportCredentials struct {
	roots   *x509.CertPool
	clients []tls.Certificate
}

// New returns a new initialized grpc/credentials.TransportCredentials
func New(rootCAs *x509.CertPool, clientCerts []tls.Certificate) credentials.TransportCredentials {
	return &transportCredentials{rootCAs, clientCerts}
}

// ClientHandshake performs the TLS handshake for a client -> server connection
func (tc *transportCredentials) ClientHandshake(ctx context.Context, addr string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, err
	}
	conn := tls.Client(rawConn, &tls.Config{
		ServerName:   host,
		RootCAs:      tc.roots,
		Certificates: tc.clients,
		MinVersion:   tls.VersionTLS12, // Override default of tls.VersionTLS10
		MaxVersion:   tls.VersionTLS12, // Same as default in golang <= 1.6
	})
	errChan := make(chan error, 1)
	go func() {
		errChan <- conn.Handshake()
	}()
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case err := <-errChan:
		if err != nil {
			_ = rawConn.Close()
			return nil, nil, fmt.Errorf("boulder/grpc/creds: TLS handshake failed: %s", err)
		}
		return conn, nil, nil
	}
}

// ServerHandshake performs the TLS handshake for a server <- client connection
func (tc *transportCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("boulder/grpc/creds: Server-side handshakes are not implemented")
}

// Info returns information about the transport protocol used
func (tc *transportCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2", // We *only* support TLS 1.2
	}
}

// GetRequestMetadata returns nil, nil since TLS credentials do not have metadata.
func (tc *transportCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return nil, nil
}

// RequireTransportSecurity always returns true because TLS is transport security
func (tc *transportCredentials) RequireTransportSecurity() bool {
	return true
}
