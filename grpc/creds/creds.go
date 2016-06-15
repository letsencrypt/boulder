package creds

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
)

// transportCredentials is a grpc/credentials.TransportCredentials which supports
// connecting to, and verifying multiple DNS names
type transportCredentials struct {
	configs map[string]*tls.Config
}

// New returns a new initialized grpc/credentials.TransportCredentials
func New(addrs []string, rootCAs *x509.CertPool, clientCerts []tls.Certificate) (credentials.TransportCredentials, error) {
	configs := make(map[string]*tls.Config, len(addrs))
	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		configs[addr] = &tls.Config{
			ServerName:   host,
			RootCAs:      rootCAs,
			Certificates: clientCerts,
			MinVersion:   tls.VersionTLS12, // Override default of tls.VersionTLS10
			MaxVersion:   tls.VersionTLS12, // Same as default in golang <= 1.6
		}
	}
	return &transportCredentials{configs}, nil
}

// ClientHandshake performs the TLS handshake for a client -> server connection
func (tc *transportCredentials) ClientHandshake(addr string, rawConn net.Conn, timeout time.Duration) (net.Conn, credentials.AuthInfo, error) {
	config, present := tc.configs[addr]
	if !present {
		return nil, nil, fmt.Errorf("boulder/grpc/creds: Unexpected name, no TLS configuration present for \"%s\"", addr)
	}
	conn := tls.Client(rawConn, config)
	errChan := make(chan error, 1)
	go func() {
		errChan <- conn.Handshake()
	}()
	select {
	case <-time.After(timeout):
		return nil, nil, errors.New("boulder/grpc/creds: TLS handshake timed out")
	case err := <-errChan:
		if err != nil {
			_ = rawConn.Close()
			return nil, nil, err
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
