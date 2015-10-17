package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	cfocsp "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/crypto/ocsp"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
)

func TestCacheControl(t *testing.T) {
	src := make(cfocsp.InMemorySource)
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

var (
	req  = mustRead("./testdata/ocsp.req")
	resp = mustRead("./testdata/ocsp.resp")
)

func TestHandler(t *testing.T) {
	ocspReq, err := ocsp.ParseRequest(req)
	if err != nil {
		t.Fatalf("ocsp.ParseRequest: %s", err)
	}
	src := make(cfocsp.InMemorySource)
	src[ocspReq.SerialNumber.String()] = resp

	h := handler(src, 10*time.Second)
	w := httptest.NewRecorder()
	r, err := http.NewRequest("POST", "/", bytes.NewReader(req))
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Code: want %d, got %d", http.StatusOK, w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), resp) {
		t.Errorf("Mismatched body: want %#v, got %#v", resp, w.Body.Bytes())
	}
}

func TestDBHandler(t *testing.T) {
	src, err := makeDBSource("mysql+tcp://ocsp_resp@localhost:3306/boulder_sa_test", "./testdata/test-ca.der.pem", false)
	if err != nil {
		t.Fatalf("makeDBSource: %s", err)
	}
	defer test.ResetSATestDatabase(t)
	ocspResp, err := ocsp.ParseResponse(resp, nil)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse: %s", err)
	}

	status := &core.CertificateStatus{
		Serial:          core.SerialToString(ocspResp.SerialNumber),
		OCSPLastUpdated: time.Now(),
		OCSPResponse:    resp,
	}
	setupDBMap, err := sa.NewDbMap("mysql+tcp://test_setup@localhost:3306/boulder_sa_test")
	if err != nil {
		t.Fatal(err)
	}
	err = setupDBMap.Insert(status)
	if err != nil {
		t.Fatalf("unable to insert response: %s", err)
	}

	h := handler(src, 10*time.Second)
	w := httptest.NewRecorder()
	r, err := http.NewRequest("POST", "/", bytes.NewReader(req))
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Code: want %d, got %d", http.StatusOK, w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), resp) {
		t.Errorf("Mismatched body: want %#v, got %#v", resp, w.Body.Bytes())
	}

}

func mustRead(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		panic(fmt.Sprintf("open %#v: %s", path, err))
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		panic(fmt.Sprintf("read all %#v: %s", path, err))
	}
	return b
}
