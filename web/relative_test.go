package web

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestRelativeEndpoint(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		tls    bool
		host   string
		xHost  string
		xProto string
		want   string
	}{
		{
			name: "direct http",
			host: "backend.example:4001",
			want: "http://backend.example:4001/acme/new-order",
		},
		{
			name: "direct https",
			tls:  true,
			host: "backend.example:4001",
			want: "https://backend.example:4001/acme/new-order",
		},
		{
			name:  "forwarded host only",
			host:  "backend.example:4001",
			xHost: "proxy.example",
			want:  "http://proxy.example/acme/new-order",
		},
		{
			name:   "forwarded proto only",
			host:   "backend.example:4001",
			xProto: "https",
			want:   "https://backend.example:4001/acme/new-order",
		},
		{
			name:   "forwarded host and proto",
			host:   "backend.example:4001",
			xHost:  "proxy.example",
			xProto: "https",
			want:   "https://proxy.example/acme/new-order",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			request := &http.Request{
				Host:   tc.host,
				Header: http.Header{},
			}
			if tc.tls {
				request.TLS = &tls.ConnectionState{}
			}
			if tc.xHost != "" {
				request.Header.Set("X-Forwarded-Host", tc.xHost)
			}
			if tc.xProto != "" {
				request.Header.Set("X-Forwarded-Proto", tc.xProto)
			}

			got := RelativeEndpoint(request, "/acme/new-order")
			if got != tc.want {
				t.Errorf("RelativeEndpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}
