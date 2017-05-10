package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	cfocsp "github.com/cloudflare/cfssl/ocsp"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

var (
	req   = mustRead("./testdata/ocsp.req")
	resp  = dbResponse{mustRead("./testdata/ocsp.resp"), time.Now()}
	stats = metrics.NewNoopScope()
)

func TestMux(t *testing.T) {
	ocspReq, err := ocsp.ParseRequest(req)
	if err != nil {
		t.Fatalf("ocsp.ParseRequest: %s", err)
	}
	doubleSlashBytes, err := base64.StdEncoding.DecodeString("MFMwUTBPME0wSzAJBgUrDgMCGgUABBR+5mrncpqz/PiiIGRsFqEtYHEIXQQUqEpqYwR93brm0Tm3pkVl7/Oo7KECEgO/AC2R1FW8hePAj4xp//8Jhw==")
	if err != nil {
		t.Fatalf("failed to decode double slash OCSP request")
	}
	doubleSlashReq, err := ocsp.ParseRequest(doubleSlashBytes)
	if err != nil {
		t.Fatalf("failed to parse double slash OCSP request")
	}
	src := make(cfocsp.InMemorySource)
	src[ocspReq.SerialNumber.String()] = resp.OCSPResponse
	src[doubleSlashReq.SerialNumber.String()] = resp.OCSPResponse
	h := mux(stats, "/foobar/", src)
	type muxTest struct {
		method   string
		path     string
		reqBody  []byte
		respBody []byte
	}
	mts := []muxTest{
		{"POST", "/foobar/", req, resp.OCSPResponse},
		{"GET", "/", nil, nil},
		{"GET", "/foobar/MFMwUTBPME0wSzAJBgUrDgMCGgUABBR+5mrncpqz/PiiIGRsFqEtYHEIXQQUqEpqYwR93brm0Tm3pkVl7/Oo7KECEgO/AC2R1FW8hePAj4xp//8Jhw==", nil, resp.OCSPResponse},
	}
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
	src, err := makeDBSource(mockSelector{}, "./testdata/test-ca.der.pem", blog.NewMock())
	if err != nil {
		t.Fatalf("makeDBSource: %s", err)
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
	if !bytes.Equal(w.Body.Bytes(), resp.OCSPResponse) {
		t.Errorf("Mismatched body: want %#v, got %#v", resp, w.Body.Bytes())
	}

	// check response with zero OCSPLastUpdated is ignored
	resp.OCSPLastUpdated = time.Time{}
	defer func() { resp.OCSPLastUpdated = time.Now() }()
	w = httptest.NewRecorder()
	r, _ = http.NewRequest("POST", "/", bytes.NewReader(req))
	unauthorizedErrorResponse := []byte{0x30, 0x03, 0x0A, 0x01, 0x06}
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Code: want %d, got %d", http.StatusOK, w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), unauthorizedErrorResponse) {
		t.Errorf("Mismatched body: want %#v, got %#v", unauthorizedErrorResponse, w.Body.Bytes())
	}
}

// mockSelector always returns the same certificateStatus
type mockSelector struct{}

func (bs mockSelector) SelectOne(output interface{}, _ string, _ ...interface{}) error {
	outputPtr, ok := output.(*dbResponse)
	if !ok {
		return fmt.Errorf("incorrect output type %T", output)
	}
	*outputPtr = resp
	return nil
}

// brokenSelector allows us to test what happens when gorp SelectOne statements
// throw errors and satisfies the dbSelector interface
type brokenSelector struct{}

func (bs brokenSelector) SelectOne(_ interface{}, _ string, _ ...interface{}) error {
	return fmt.Errorf("Failure!")
}

func TestErrorLog(t *testing.T) {
	mockLog := blog.NewMock()
	src, err := makeDBSource(brokenSelector{}, "./testdata/test-ca.der.pem", mockLog)
	test.AssertNotError(t, err, "Failed to create broken dbMap")

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
