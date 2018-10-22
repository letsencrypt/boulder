package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"gopkg.in/go-gorp/gorp.v2"

	"golang.org/x/crypto/ocsp"

	cfocsp "github.com/cloudflare/cfssl/ocsp"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
	"github.com/prometheus/client_golang/prometheus"
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
	ocspStats := statsShim{responseTypes: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ocspResponses-test",
		},
		[]string{"type"},
	)}
	h := mux(stats, "/foobar/", src, &ocspStats)
	type muxTest struct {
		method       string
		path         string
		reqBody      []byte
		respBody     []byte
		expectedType string
	}
	mts := []muxTest{
		{"POST", "/foobar/", req, resp.OCSPResponse, "Success"},
		{"GET", "/", nil, nil, ""},
		{"GET", "/foobar/MFMwUTBPME0wSzAJBgUrDgMCGgUABBR+5mrncpqz/PiiIGRsFqEtYHEIXQQUqEpqYwR93brm0Tm3pkVl7/Oo7KECEgO/AC2R1FW8hePAj4xp//8Jhw==", nil, resp.OCSPResponse, "Success"},
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
		if mt.expectedType != "" {
			test.AssertEquals(t, 1, test.CountCounterVec("type", mt.expectedType, ocspStats.responseTypes))
			ocspStats.responseTypes.Reset()
		}
	}
}

func TestDBHandler(t *testing.T) {
	src, err := makeDBSource(mockSelector{}, "./testdata/test-ca.der.pem", nil, time.Second, blog.NewMock())
	if err != nil {
		t.Fatalf("makeDBSource: %s", err)
	}

	h := cfocsp.NewResponder(src, nil)
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
type mockSelector struct {
	mockSqlExecutor
}

func (bs mockSelector) WithContext(context.Context) gorp.SqlExecutor {
	return bs
}

func (bs mockSelector) SelectOne(output interface{}, _ string, _ ...interface{}) error {
	outputPtr, ok := output.(*dbResponse)
	if !ok {
		return fmt.Errorf("incorrect output type %T", output)
	}
	*outputPtr = resp
	return nil
}

// To mock out WithContext, we need to be able to return objects that satisfy
// gorp.SqlExecutor. That's a pretty big interface, so we specify one no-op mock
// that we can embed everywhere we need to satisfy it.
// Note: mockSqlExecutor does *not* implement WithContext. The expectation is
// that structs that embed mockSqlExecutor will define their own WithContext
// that returns a reference to themselves. That makes it easy for those structs
// to override the specific methods they need to implement (e.g. SelectOne).
type mockSqlExecutor struct{}

func (mse mockSqlExecutor) Get(i interface{}, keys ...interface{}) (interface{}, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) Insert(list ...interface{}) error {
	return fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) Update(list ...interface{}) (int64, error) {
	return 0, fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) Delete(list ...interface{}) (int64, error) {
	return 0, fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) Exec(query string, args ...interface{}) (sql.Result, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) Select(i interface{}, query string, args ...interface{}) ([]interface{}, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) SelectInt(query string, args ...interface{}) (int64, error) {
	return 0, fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) SelectNullInt(query string, args ...interface{}) (sql.NullInt64, error) {
	return sql.NullInt64{}, fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) SelectFloat(query string, args ...interface{}) (float64, error) {
	return 0, fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) SelectNullFloat(query string, args ...interface{}) (sql.NullFloat64, error) {
	return sql.NullFloat64{}, fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) SelectStr(query string, args ...interface{}) (string, error) {
	return "", fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) SelectNullStr(query string, args ...interface{}) (sql.NullString, error) {
	return sql.NullString{}, fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) SelectOne(holder interface{}, query string, args ...interface{}) error {
	return fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (mse mockSqlExecutor) QueryRow(query string, args ...interface{}) *sql.Row {
	return nil
}

// brokenSelector allows us to test what happens when gorp SelectOne statements
// throw errors and satisfies the dbSelector interface
type brokenSelector struct {
	mockSqlExecutor
}

func (bs brokenSelector) SelectOne(_ interface{}, _ string, _ ...interface{}) error {
	return fmt.Errorf("Failure!")
}

func (bs brokenSelector) WithContext(context.Context) gorp.SqlExecutor {
	return bs
}

func TestErrorLog(t *testing.T) {
	mockLog := blog.NewMock()
	src, err := makeDBSource(brokenSelector{}, "./testdata/test-ca.der.pem", nil, time.Second, mockLog)
	test.AssertNotError(t, err, "Failed to create broken dbMap")

	ocspReq, err := ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to parse OCSP request")

	_, _, err = src.Response(ocspReq)
	test.AssertEquals(t, err.Error(), "Failure!")

	test.AssertEquals(t, len(mockLog.GetAllMatching("Looking up OCSP response")), 1)
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

func TestRequiredSerialPrefix(t *testing.T) {
	mockLog := blog.NewMock()
	src, err := makeDBSource(mockSelector{}, "./testdata/test-ca.der.pem", []string{"nope"}, time.Second, mockLog)
	test.AssertNotError(t, err, "failed to create DBSource")

	ocspReq, err := ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to parse OCSP request")

	_, _, err = src.Response(ocspReq)
	test.AssertEquals(t, err, cfocsp.ErrNotFound)

	fmt.Println(core.SerialToString(ocspReq.SerialNumber))

	src, err = makeDBSource(mockSelector{}, "./testdata/test-ca.der.pem", []string{"00", "nope"}, time.Second, mockLog)
	test.AssertNotError(t, err, "failed to create DBSource")
	_, _, err = src.Response(ocspReq)
	test.AssertNotError(t, err, "src.Response failed with acceptable prefix")
}
