package web

import (
	"net/http"
	"testing"
)

func TestRelativeEndpointHonorsForwardedHost(t *testing.T) {
	request := &http.Request{
		Host:   "backend.example:4001",
		Header: http.Header{},
	}
	request.Header.Set("X-Forwarded-Host", "proxy.example")
	request.Header.Set("X-Forwarded-Proto", "https")

	got := RelativeEndpoint(request, "/acme/new-order")
	want := "https://proxy.example/acme/new-order"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRelativeEndpointWithoutForwardedHost(t *testing.T) {
	request := &http.Request{
		Host:   "backend.example:4001",
		Header: http.Header{},
	}

	got := RelativeEndpoint(request, "/acme/new-order")
	want := "http://backend.example:4001/acme/new-order"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
