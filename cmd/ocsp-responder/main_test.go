package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp"
)

func TestCacheControl(t *testing.T) {
	src := make(ocsp.InMemorySource)
	h := handler(src, 10*time.Second)
	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(w, r)
	expected := "max-age=10"
	actual := w.Header().Get("Cache-Control")
	if actual != expected {
		t.Errorf("Cache-Control value: want %#v, got %#v", expected, actual)
	}
}
