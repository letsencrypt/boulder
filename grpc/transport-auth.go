package grpc

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
)

// MultiNameAuthenticator does a thing
type MultiNameAuthenticator struct {
	names map[string]*tls.Config
}

// NewMultiNameTLS also does a thing
func NewMultiNameTLS(names map[string]*tls.Config) credentials.TransportAuthenticator {
	return &MultiNameAuthenticator{names}
}

func (mna *MultiNameAuthenticator) ClientHandshake(addr string, rawConn net.Conn, timeout time.Duration) (net.Conn, credentials.AuthInfo, error) {
	var errChannel chan error
	if timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(timeout, func() {
			errChannel <- errors.New("boulder/grpc: Dial timed out")
		})
	}
	config, present := mna.names[addr]
	if !present {
		return nil, nil, fmt.Errorf("boulder/grpc: Unexpected name, no TLS configuration present for \"%s\"", addr)
	}
	conn := tls.Client(rawConn, config)
	var err error
	if timeout == 0 {
		err = conn.Handshake()
	} else {
		go func() {
			errChannel <- conn.Handshake()
		}()
		err = <-errChannel
	}
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	return conn, nil, nil
}

func (mna *MultiNameAuthenticator) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("boulder/grpc: Server-side handshakes are not implemented")
}

func (mna *MultiNameAuthenticator) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
	}
}

func (mna *MultiNameAuthenticator) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return nil, nil
}

func (mna *MultiNameAuthenticator) RequireTransportSecurity() bool {
	return true
}
