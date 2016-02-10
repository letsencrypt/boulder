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

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	cfocsp "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/crypto/ocsp"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

var (
	req      = mustRead("./testdata/ocsp.req")
	resp     = mustRead("./testdata/ocsp.resp")
	stats, _ = statsd.NewNoopClient()
)

func TestMux(t *testing.T) {
	ocspReq, err := ocsp.ParseRequest(req)
	if err != nil {
		t.Fatalf("ocsp.ParseRequest: %s", err)
	}
	src := make(cfocsp.InMemorySource)
	src[ocspReq.SerialNumber.String()] = resp
	h := mux(stats, "/foobar/", src)
	type muxTest struct {
		method   string
		path     string
		reqBody  []byte
		respBody []byte
	}
	mts := []muxTest{{"POST", "/foobar/", req, resp}, {"GET", "/", nil, nil}}
	for i, mt := range mts {
		w := httptest.NewRecorder()
		r, err := http.NewRequest(mt.method, mt.path, bytes.NewReader(mt.reqBody))
		if err != nil {
			t.Fatalf("#%d, NewRequest: %s", i, err)
		}
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("Code: want %d, got %d", http.StatusOK, w.Code)
		}
		if !bytes.Equal(w.Body.Bytes(), mt.respBody) {
			t.Errorf("Mismatched body: want %#v, got %#v", mt.respBody, w.Body.Bytes())
		}

	}
}

func TestDBHandler(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAOcspResp)
	test.AssertNotError(t, err, "Could not connect to database")
	src, err := makeDBSource(dbMap, "./testdata/test-ca.der.pem", blog.GetAuditLogger())
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

	h := cfocsp.NewResponder(src)
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

// brokenSelector allows us to test what happens when gorp SelectOne statements
// throw errors and satisfies the dbSelector interface
type brokenSelector struct{}

func (bs brokenSelector) SelectOne(_ interface{}, _ string, _ ...interface{}) error {
	return fmt.Errorf("Failure!")
}

func TestErrorLog(t *testing.T) {
	src, err := makeDBSource(brokenSelector{}, "./testdata/test-ca.der.pem", blog.GetAuditLogger())
	test.AssertNotError(t, err, "Failed to create broken dbMap")

	src.log.SyslogWriter = mocks.NewSyslogWriter()
	mockLog := src.log.SyslogWriter.(*mocks.SyslogWriter)

	ocspReq, err := ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to parse OCSP request")

	_, found := src.Response(ocspReq)
	test.Assert(t, !found, "Somehow found OCSP response")

	test.AssertEquals(t, len(mockLog.GetAllMatching("Failed to retrieve response from certificateStatus table")), 1)
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
