package metrics

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestPromScope(t *testing.T) {
	reg := prometheus.NewRegistry()
	testSrv := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer testSrv.Close()
	scope := NewPromScope(reg)
	scope2 := scope.NewScope("component")
	scope.Inc("boops", 1)
	scope2.Inc("bleeps", 1)
	resp, err := http.Get(testSrv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "boops 1\n") {
		t.Error("No boops found:\n", string(body))
	}
	if !strings.Contains(string(body), "component_bleeps 1\n") {
		t.Error("No component bleeps found:\n", string(body))
	}
}
