package va

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"golang.org/x/crypto/cryptobyte"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
)

// testECHPublicName is the public name in configs from newTestECHKey.
const testECHPublicName = "public.example"

// newTestECHKey returns a serialized ECHConfigList advertising
// testECHPublicName, and the server key for its single config.
func newTestECHKey(t *testing.T) ([]byte, tls.EncryptedClientHelloKey) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ECH key: %s", err)
	}

	var b cryptobyte.Builder
	b.AddUint16(0xfe0d) // ECHConfig version
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0)     // config_id
		b.AddUint16(0x20) // DHKEM(X25519, HKDF-SHA256)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(priv.PublicKey().Bytes())
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(1) // HKDF-SHA256
			b.AddUint16(1) // AES-128-GCM
		})
		b.AddUint8(0) // maximum_name_length
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(testECHPublicName))
		})
		b.AddUint16(0) // extensions
	})
	config, err := b.Bytes()
	if err != nil {
		t.Fatalf("marshaling ECHConfig: %s", err)
	}

	var lb cryptobyte.Builder
	lb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(config)
	})
	list, err := lb.Bytes()
	if err != nil {
		t.Fatalf("marshaling ECHConfigList: %s", err)
	}

	return list, tls.EncryptedClientHelloKey{
		Config:      config,
		PrivateKey:  priv.Bytes(),
		SendAsRetry: true,
	}
}

// echTestServer is a TLS server that reports the state of each handshake it
// completes.
type echTestServer struct {
	addr   string
	states chan tls.ConnectionState
}

func newECHTestServer(t *testing.T, config *tls.Config) *echTestServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("listening: %s", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &echTestServer{addr: ln.Addr().String(), states: make(chan tls.ConnectionState, 10)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				tlsConn, ok := conn.(*tls.Conn)
				if !ok {
					return
				}
				err := tlsConn.Handshake()
				if err != nil {
					return
				}
				srv.states <- tlsConn.ConnectionState()
			}()
		}
	}()
	return srv
}

// nextState returns the state of the server's next completed handshake.
func (s *echTestServer) nextState(t *testing.T) tls.ConnectionState {
	t.Helper()
	select {
	case state := <-s.states:
		return state
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the server to complete a handshake")
	}
	return tls.ConnectionState{}
}

// countingDialer counts calls to its DialTLSContext, which dials with dial.
type countingDialer struct {
	calls atomic.Int64
	dial  tlsDialerFunc
}

func (d *countingDialer) DialTLSContext(ctx context.Context, network, addr string, config *tls.Config) (*tls.Conn, error) {
	d.calls.Add(1)
	return d.dial(ctx, network, addr, config)
}

// testDialer returns a preresolvedDialer for addr, an IP:port, with the given
// timeout.
func testDialer(t *testing.T, addr string, timeout time.Duration) *preresolvedDialer {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("splitting %q: %s", addr, err)
	}
	return &preresolvedDialer{ip: netip.MustParseAddr(host), port: port, hostname: host, timeout: timeout}
}

// echFakeDNS is an ipFakeDNS that also serves HTTPS records, or httpsErr if it
// is set.
type echFakeDNS struct {
	ipFakeDNS
	https        map[string][]*dns.HTTPS
	httpsErr     error
	httpsLookups atomic.Int64
}

func (c *echFakeDNS) LookupHTTPS(_ context.Context, hostname string) (*bdns.Result[*dns.HTTPS], string, error) {
	c.httpsLookups.Add(1)
	if c.httpsErr != nil {
		return nil, "echFakeDNS", c.httpsErr
	}
	return &bdns.Result[*dns.HTTPS]{Final: c.https[hostname]}, "echFakeDNS", nil
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m io_prometheus_client.Metric
	err := c.Write(&m)
	if err != nil {
		t.Fatalf("reading counter: %s", err)
	}
	return m.GetCounter().GetValue()
}

func httpsRR(priority uint16, target string, params ...dns.SVCBKeyValue) *dns.HTTPS {
	return &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET},
		Priority: priority,
		Target:   target,
		Value:    params,
	}}
}

func echParam(b ...byte) *dns.SVCBECHConfig {
	return &dns.SVCBECHConfig{ECH: b}
}

func TestECHConfigListFromHTTPS(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		rrs  []*dns.HTTPS
		want []byte
	}{
		{
			name: "no records",
			want: nil,
		},
		{
			name: "service mode with ech",
			rrs:  []*dns.HTTPS{httpsRR(1, ".", echParam(1))},
			want: []byte{1},
		},
		{
			name: "service mode without ech",
			rrs:  []*dns.HTTPS{httpsRR(1, ".", &dns.SVCBAlpn{Alpn: []string{"h2"}})},
			want: nil,
		},
		{
			name: "alias mode overrides service mode",
			rrs: []*dns.HTTPS{
				httpsRR(0, "cdn.example.net."),
				httpsRR(1, ".", echParam(1)),
			},
			want: nil,
		},
		{
			name: "other target",
			rrs:  []*dns.HTTPS{httpsRR(1, "cdn.example.net.", echParam(1))},
			want: nil,
		},
		{
			name: "target is owner name",
			rrs:  []*dns.HTTPS{httpsRR(1, "Example.COM.", echParam(1))},
			want: []byte{1},
		},
		{
			name: "matching port",
			rrs:  []*dns.HTTPS{httpsRR(1, ".", &dns.SVCBPort{Port: 443}, echParam(1))},
			want: []byte{1},
		},
		{
			name: "other port",
			rrs:  []*dns.HTTPS{httpsRR(1, ".", &dns.SVCBPort{Port: 8443}, echParam(1))},
			want: nil,
		},
		{
			name: "supported mandatory keys",
			rrs: []*dns.HTTPS{httpsRR(1, ".",
				&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_ECHCONFIG}},
				&dns.SVCBAlpn{Alpn: []string{"h2"}},
				echParam(1),
			)},
			want: []byte{1},
		},
		{
			name: "unsupported mandatory key",
			rrs: []*dns.HTTPS{httpsRR(1, ".",
				&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_DOHPATH}},
				&dns.SVCBDoHPath{Template: "/dns-query{?dns}"},
				echParam(1),
			)},
			want: nil,
		},
		{
			name: "lowest priority wins",
			rrs: []*dns.HTTPS{
				httpsRR(3, ".", echParam(3)),
				httpsRR(1, ".", echParam(1)),
				httpsRR(2, ".", echParam(2)),
			},
			want: []byte{1},
		},
		{
			name: "best record without ech is skipped",
			rrs: []*dns.HTTPS{
				httpsRR(1, "."),
				httpsRR(2, ".", echParam(2)),
			},
			want: []byte{2},
		},
		{
			name: "empty ech",
			rrs:  []*dns.HTTPS{httpsRR(1, ".", echParam())},
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := echConfigListFromHTTPS(tc.rrs, 443)
			if !bytes.Equal(got, tc.want) {
				t.Errorf("echConfigListFromHTTPS() = %x, want %x", got, tc.want)
			}
		})
	}
}

func TestGetAddrsECH(t *testing.T) {
	// Not parallel, because it sets feature flags.
	ech := []byte{1, 2, 3}
	fake := &echFakeDNS{https: map[string][]*dns.HTTPS{
		"example.com": {httpsRR(1, ".", echParam(ech...))},
	}}
	va, _ := setup(nil, "", nil, fake)

	addrs, got, resolvers, err := va.getAddrs(t.Context(), "example.com", 443)
	if err != nil {
		t.Fatalf("getAddrs with ECH disabled: %s", err)
	}
	if len(addrs) == 0 || got != nil || fake.httpsLookups.Load() != 0 || slices.Contains(resolvers, "echFakeDNS") {
		t.Errorf("with ECH disabled, got %d addrs, ECH %x, %d HTTPS lookups, and resolvers %q; want addrs, no ECH, no lookups, and no HTTPS resolver",
			len(addrs), got, fake.httpsLookups.Load(), resolvers)
	}

	features.Set(features.Config{ValidationUsesECH: true})
	defer features.Reset()

	addrs, got, resolvers, err = va.getAddrs(t.Context(), "example.com", 0)
	if err != nil {
		t.Fatalf("getAddrs without a TLS port: %s", err)
	}
	if len(addrs) == 0 || got != nil || fake.httpsLookups.Load() != 0 || slices.Contains(resolvers, "echFakeDNS") {
		t.Errorf("without a TLS port, got %d addrs, ECH %x, %d HTTPS lookups, and resolvers %q; want addrs, no ECH, no lookups, and no HTTPS resolver",
			len(addrs), got, fake.httpsLookups.Load(), resolvers)
	}

	addrs, got, resolvers, err = va.getAddrs(t.Context(), "example.com", 443)
	if err != nil {
		t.Fatalf("getAddrs: %s", err)
	}
	if len(addrs) == 0 || !bytes.Equal(got, ech) || !slices.Contains(resolvers, "echFakeDNS") {
		t.Errorf("got %d addrs, ECH %x, and resolvers %q; want addrs, ECH %x, and the HTTPS resolver",
			len(addrs), got, resolvers, ech)
	}

	_, got, _, err = va.getAddrs(t.Context(), "other.example.com", 443)
	if err != nil || got != nil {
		t.Errorf("for a name without HTTPS records, got ECH %x and err %v; want neither", got, err)
	}

	fake.httpsErr = errors.New("SERVFAIL")
	addrs, got, _, err = va.getAddrs(t.Context(), "example.com", 443)
	if err != nil {
		t.Fatalf("getAddrs with a failed HTTPS lookup: %s", err)
	}
	if len(addrs) == 0 || got != nil {
		t.Errorf("with a failed HTTPS lookup, got %d addrs and ECH %x; want addrs and no ECH", len(addrs), got)
	}

	for result, want := range map[string]float64{"found": 1, "absent": 1, "error": 1} {
		got := counterValue(t, va.metrics.echConfigLookups.WithLabelValues(result))
		if got != want {
			t.Errorf("ech_config_lookups{result=%q} = %v, want %v", result, got, want)
		}
	}
}

func TestDialTLSWithECH(t *testing.T) {
	t.Parallel()

	const name = "example.com"
	cert := testTLSCert([]string{name}, nil, nil)
	echConfigList, echKey := newTestECHKey(t)
	_, otherKey := newTestECHKey(t)

	for _, tc := range []struct {
		name          string
		server        *tls.Config
		echConfigList []byte
		// outerHandshakes is how many handshakes the server completes using
		// the outer ClientHello before the final one.
		outerHandshakes int
		wantStatus      core.ECHStatus
		wantOutcome     string
	}{
		{
			name:          "no ECH config",
			server:        &tls.Config{Certificates: []tls.Certificate{*cert}, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{echKey}},
			echConfigList: nil,
			wantStatus:    "",
		},
		{
			name:          "accepted",
			server:        &tls.Config{Certificates: []tls.Certificate{*cert}, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{echKey}},
			echConfigList: echConfigList,
			wantStatus:    core.ECHAccepted,
			wantOutcome:   "accepted",
		},
		{
			name:            "accepted with retry configs",
			server:          &tls.Config{Certificates: []tls.Certificate{*cert}, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{otherKey}},
			echConfigList:   echConfigList,
			outerHandshakes: 1,
			wantStatus:      core.ECHAccepted,
			wantOutcome:     "accepted_retry",
		},
		{
			name:            "rejected by a server without ECH",
			server:          &tls.Config{Certificates: []tls.Certificate{*cert}},
			echConfigList:   echConfigList,
			outerHandshakes: 1,
			wantStatus:      core.ECHRejected,
			wantOutcome:     "rejected",
		},
		{
			name:          "TLS 1.2 server",
			server:        &tls.Config{Certificates: []tls.Certificate{*cert}, MaxVersion: tls.VersionTLS12},
			echConfigList: echConfigList,
			wantStatus:    core.ECHFailed,
			wantOutcome:   "failed",
		},
		{
			name:          "malformed ECH config",
			server:        &tls.Config{Certificates: []tls.Certificate{*cert}},
			echConfigList: []byte{0x00, 0x01, 0x02},
			wantStatus:    core.ECHFailed,
			wantOutcome:   "failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			va, _ := setup(nil, "", nil, nil)
			srv := newECHTestServer(t, tc.server)

			base := &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
			dialer := testDialer(t, srv.addr, 10*time.Second)
			conn, status, err := va.dialTLSWithECH(t.Context(), dialer.DialTLSContext, srv.addr, base, tc.echConfigList)
			if err != nil {
				t.Fatalf("dialTLSWithECH: %s", err)
			}
			defer conn.Close()

			if status != tc.wantStatus {
				t.Errorf("got status %q, want %q", status, tc.wantStatus)
			}
			wantAccepted := tc.wantStatus == core.ECHAccepted
			if conn.ConnectionState().ECHAccepted != wantAccepted {
				t.Errorf("got client ECHAccepted %t, want %t", conn.ConnectionState().ECHAccepted, wantAccepted)
			}

			for range tc.outerHandshakes {
				state := srv.nextState(t)
				if state.ServerName != testECHPublicName || state.ECHAccepted {
					t.Errorf("got outer handshake with ServerName %q and ECHAccepted %t, want %s and false",
						state.ServerName, state.ECHAccepted, testECHPublicName)
				}
			}
			state := srv.nextState(t)
			if state.ServerName != name {
				t.Errorf("server saw ServerName %q, want %q", state.ServerName, name)
			}
			if state.ECHAccepted != wantAccepted {
				t.Errorf("got server ECHAccepted %t, want %t", state.ECHAccepted, wantAccepted)
			}

			for _, outcome := range []string{"accepted", "accepted_retry", "rejected", "failed"} {
				want := 0.0
				if outcome == tc.wantOutcome {
					want = 1
				}
				got := counterValue(t, va.metrics.echHandshakes.WithLabelValues(outcome))
				if got != want {
					t.Errorf("ech_handshakes{outcome=%q} = %v, want %v", outcome, got, want)
				}
			}
		})
	}
}

func TestDialTLSWithECHErrors(t *testing.T) {
	t.Parallel()

	echConfigList, _ := newTestECHKey(t)
	base := &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}
	dialErr := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}

	t.Run("dial error", func(t *testing.T) {
		t.Parallel()
		va, _ := setup(nil, "", nil, nil)
		dialer := &countingDialer{dial: func(context.Context, string, string, *tls.Config) (*tls.Conn, error) {
			return nil, dialErr
		}}

		_, status, err := va.dialTLSWithECH(t.Context(), dialer.DialTLSContext, "192.0.2.1:443", base, echConfigList)
		opErr, ok := errors.AsType[*net.OpError](err)
		if !ok || opErr.Op != "dial" {
			t.Errorf("got error %v, want the dial error", err)
		}
		if status != "" {
			t.Errorf("got status %q, want none", status)
		}
		if dialer.calls.Load() != 1 {
			t.Errorf("dialed %d times, want 1", dialer.calls.Load())
		}
	})

	t.Run("dial error on retry", func(t *testing.T) {
		t.Parallel()
		va, _ := setup(nil, "", nil, nil)
		_, otherKey := newTestECHKey(t)
		srv := newECHTestServer(t, &tls.Config{
			Certificates:             []tls.Certificate{*testTLSCert([]string{"example.com"}, nil, nil)},
			EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{otherKey},
		})
		srvDialer := testDialer(t, srv.addr, 10*time.Second)
		dialer := &countingDialer{}
		dialer.dial = func(ctx context.Context, network, addr string, config *tls.Config) (*tls.Conn, error) {
			// Let the first attempt get rejected with retry configs, then fail.
			if dialer.calls.Load() > 1 {
				return nil, dialErr
			}
			return srvDialer.DialTLSContext(ctx, network, addr, config)
		}

		_, status, err := va.dialTLSWithECH(t.Context(), dialer.DialTLSContext, srv.addr, base, echConfigList)
		opErr, ok := errors.AsType[*net.OpError](err)
		if !ok || opErr.Op != "dial" {
			t.Errorf("got error %v, want the dial error", err)
		}
		if status != core.ECHRejected {
			t.Errorf("got status %q, want %q", status, core.ECHRejected)
		}
		if dialer.calls.Load() != 2 {
			t.Errorf("dialed %d times, want 2", dialer.calls.Load())
		}
		got := counterValue(t, va.metrics.echHandshakes.WithLabelValues("rejected"))
		if got != 1 {
			t.Errorf(`ech_handshakes{outcome="rejected"} = %v, want 1`, got)
		}
	})

	t.Run("handshake timeout", func(t *testing.T) {
		t.Parallel()
		va, _ := setup(nil, "", nil, nil)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listening: %s", err)
		}
		defer ln.Close()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				// Never respond, so the handshakes time out.
				defer conn.Close()
			}
		}()

		dialer := &countingDialer{dial: testDialer(t, ln.Addr().String(), 100*time.Millisecond).DialTLSContext}
		_, status, err := va.dialTLSWithECH(t.Context(), dialer.DialTLSContext, ln.Addr().String(), base, echConfigList)
		if err == nil {
			t.Fatal("dialTLSWithECH succeeded against a silent server")
		}
		if status != core.ECHFailed {
			t.Errorf("got status %q, want %q", status, core.ECHFailed)
		}
		if dialer.calls.Load() != 2 {
			t.Errorf("dialed %d times, want 2: with ECH, then without", dialer.calls.Load())
		}
		got := counterValue(t, va.metrics.echHandshakes.WithLabelValues("failed"))
		if got != 1 {
			t.Errorf(`ech_handshakes{outcome="failed"} = %v, want 1`, got)
		}
	})
}
