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
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/sa"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
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
	dbMap, err := sa.NewDbMap("mysql+tcp://boulder@localhost:3306/boulder_sa_test")
	test.AssertNotError(t, err, "Could not connect to database")
	src, err := makeDBSource(dbMap, "./testdata/test-ca.der.pem", blog.GetAuditLogger())
	if err != nil {
		t.Fatalf("makeDBSource: %s", err)
	}
	defer test.ResetTestDatabase(t, dbMap.Db)
	ocspResp, err := ocsp.ParseResponse(resp, nil)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse: %s", err)
	}

	status := &core.CertificateStatus{
		Serial:          core.SerialToString(ocspResp.SerialNumber),
		OCSPLastUpdated: time.Now(),
		OCSPResponse:    resp,
	}
	err = dbMap.Insert(status)
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

type brokenMap struct{}

func (bm brokenMap) SelectOne(_ interface{}, _ string, _ ...interface{}) error {
	return fmt.Errorf("Failure!")
}

func (bm brokenMap) Insert(_ ...interface{}) error {
	return nil
}

func TestErrorLog(t *testing.T) {
	src, err := makeDBSource(brokenMap{}, "./testdata/test-ca.der.pem", blog.GetAuditLogger())
	test.AssertNotError(t, err, "Failed to create broken dbMap")

	src.log.SyslogWriter = mocks.NewSyslogWriter()
	mockLog := src.log.SyslogWriter.(*mocks.SyslogWriter)

	ocspReq, err := ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to parse OCSP request")

	_, found := src.Response(ocspReq)
	test.Assert(t, !found, "Somehow found OCSP response")

	test.AssertEquals(t, len(mockLog.GetAllMatching("Failed to retrieve response from certificateStatus table")), 1)
	test.AssertEquals(t, len(mockLog.GetAllMatching("Failed to retrieve response from ocspResponses table")), 1)
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
