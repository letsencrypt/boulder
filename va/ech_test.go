package va

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/features"
)

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
