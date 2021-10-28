package notmain

import (
	"bytes"
	"context"
	"crypto"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/go-gorp/gorp/v3"

	"golang.org/x/crypto/ocsp"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	bocsp "github.com/letsencrypt/boulder/ocsp"
	"github.com/letsencrypt/boulder/test"
)

var (
	issuerID = int64(3568119531)
	req      = mustRead("./testdata/ocsp.req")
	resp     = core.CertificateStatus{
		OCSPResponse:    mustRead("./testdata/ocsp.resp"),
		IsExpired:       false,
		OCSPLastUpdated: time.Now(),
		IssuerID:        issuerID,
	}
	stats = metrics.NoopRegisterer
)

func mustRead(path string) []byte {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("read %#v: %s", path, err))
	}
	return b
}

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
	responses := map[string][]byte{
		ocspReq.SerialNumber.String():        resp.OCSPResponse,
		doubleSlashReq.SerialNumber.String(): resp.OCSPResponse,
	}
	src := bocsp.NewMemorySource(responses, blog.NewMock())
	h := mux(stats, "/foobar/", src, blog.NewMock())
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
	}
}

func TestNewFilter(t *testing.T) {
	_, err := newFilter([]string{}, []string{})
	test.AssertError(t, err, "Didn't error when creating empty filter")

	_, err = newFilter([]string{"/tmp/doesnotexist.foo"}, []string{})
	test.AssertError(t, err, "Didn't error on non-existent issuer cert")

	f, err := newFilter([]string{"./testdata/test-ca.der.pem"}, []string{"00"})
	test.AssertNotError(t, err, "Errored when creating good filter")
	test.AssertEquals(t, len(f.issuerKeyHashes), 1)
	test.AssertEquals(t, len(f.serialPrefixes), 1)
	test.AssertEquals(t, hex.EncodeToString(f.issuerKeyHashes[issuance.IssuerID(issuerID)]), "fb784f12f96015832c9f177f3419b32e36ea4189")
}

func TestCheckRequest(t *testing.T) {
	f, err := newFilter([]string{"./testdata/test-ca.der.pem"}, []string{"00"})
	test.AssertNotError(t, err, "Errored when creating good filter")

	ocspReq, err := ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to prepare fake ocsp request")
	test.AssertNotError(t, f.checkRequest(ocspReq), "Rejected good ocsp request with bad hash algorithm")

	ocspReq, err = ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to prepare fake ocsp request")
	// Select a bad hash algorithm.
	ocspReq.HashAlgorithm = crypto.MD5
	test.AssertError(t, f.checkRequest((ocspReq)), "Accepted ocsp request with bad hash algorithm")

	ocspReq, err = ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to prepare fake ocsp request")
	// Make the hash invalid.
	ocspReq.IssuerKeyHash[0]++
	test.AssertError(t, f.checkRequest(ocspReq), "Accepted ocsp request with bad issuer key hash")

	ocspReq, err = ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to prepare fake ocsp request")
	// Make the serial prefix wrong by incrementing the first byte by 1.
	serialStr := []byte(core.SerialToString(ocspReq.SerialNumber))
	serialStr[0] = serialStr[0] + 1
	ocspReq.SerialNumber.SetString(string(serialStr), 16)
	test.AssertError(t, f.checkRequest(ocspReq), "Accepted ocsp request with bad serial prefix")
}

func TestResponseMatchesIssuer(t *testing.T) {
	f, err := newFilter([]string{"./testdata/test-ca.der.pem"}, []string{"00"})
	test.AssertNotError(t, err, "Errored when creating good filter")

	ocspReq, err := ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to prepare fake ocsp request")
	test.AssertEquals(t, f.responseMatchesIssuer(ocspReq, resp), true)

	ocspReq, err = ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to prepare fake ocsp request")
	fakeID := int64(123456)
	ocspResp := core.CertificateStatus{
		OCSPResponse:    mustRead("./testdata/ocsp.resp"),
		IsExpired:       false,
		OCSPLastUpdated: time.Now(),
		IssuerID:        fakeID,
	}
	test.AssertEquals(t, f.responseMatchesIssuer(ocspReq, ocspResp), false)
}

func TestDBHandler(t *testing.T) {
	f, err := newFilter([]string{"./testdata/test-ca.der.pem"}, nil)
	if err != nil {
		t.Fatalf("newFilter: %s", err)
	}
	src := &dbSource{mockSelector{}, f, time.Second, blog.NewMock()}

	h := bocsp.NewResponder(src, stats, blog.NewMock())
	w := httptest.NewRecorder()
	r, err := http.NewRequest("POST", "/", bytes.NewReader(req))
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Code: want %d, got %d", http.StatusOK, w.Code)
	}
	cacheTag := w.Result().Header["Edge-Cache-Tag"]
	expectedCacheTag := []string{"08"}
	if !reflect.DeepEqual(cacheTag, expectedCacheTag) {
		t.Errorf("Edge-Cache-Tag: expected %q, got %q", expectedCacheTag, cacheTag)
	}
	if !bytes.Equal(w.Body.Bytes(), resp.OCSPResponse) {
		t.Errorf("Mismatched body: want %#v, got %#v", resp, w.Body.Bytes())
	}

	// check response with zero OCSPLastUpdated is ignored
	resp.OCSPLastUpdated = time.Time{}
	defer func() { resp.OCSPLastUpdated = time.Now() }()
	w = httptest.NewRecorder()
	r, _ = http.NewRequest("POST", "/", bytes.NewReader(req))
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Code: want %d, got %d", http.StatusOK, w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), ocsp.UnauthorizedErrorResponse) {
		t.Errorf("Mismatched body: want %#v, got %#v", ocsp.UnauthorizedErrorResponse, w.Body.Bytes())
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
	outputPtr, ok := output.(*core.CertificateStatus)
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
	f, err := newFilter([]string{"./testdata/test-ca.der.pem"}, nil)
	if err != nil {
		t.Fatalf("newFilter: %s", err)
	}
	src := &dbSource{brokenSelector{}, f, time.Second, mockLog}

	ocspReq, err := ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to parse OCSP request")

	_, _, err = src.Response(ocspReq)
	test.AssertEquals(t, err.Error(), "Failure!")

	test.AssertEquals(t, len(mockLog.GetAllMatching("Looking up OCSP response")), 1)
}

func TestRequiredSerialPrefix(t *testing.T) {
	f, err := newFilter([]string{"./testdata/test-ca.der.pem"}, []string{"nope"})
	if err != nil {
		t.Fatalf("newFilter: %s", err)
	}
	src := &dbSource{mockSelector{}, f, time.Second, blog.NewMock()}

	ocspReq, err := ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to parse OCSP request")

	_, _, err = src.Response(ocspReq)
	test.AssertErrorIs(t, err, bocsp.ErrNotFound)

	fmt.Println(core.SerialToString(ocspReq.SerialNumber))

	f, err = newFilter([]string{"./testdata/test-ca.der.pem"}, []string{"00", "nope"})
	if err != nil {
		t.Fatalf("newFilter: %s", err)
	}
	src = &dbSource{mockSelector{}, f, time.Second, blog.NewMock()}
	_, _, err = src.Response(ocspReq)
	test.AssertNotError(t, err, "src.Response failed with acceptable prefix")
}

type expiredSelector struct {
	mockSqlExecutor
}

func (es expiredSelector) SelectOne(obj interface{}, _ string, _ ...interface{}) error {
	rows := obj.(*core.CertificateStatus)
	rows.IsExpired = true
	rows.OCSPLastUpdated = time.Time{}.Add(time.Hour)
	issuerID = int64(123456)
	rows.IssuerID = issuerID
	return nil
}

func (es expiredSelector) WithContext(context.Context) gorp.SqlExecutor {
	return es
}

func TestExpiredUnauthorized(t *testing.T) {
	f, err := newFilter([]string{"./testdata/test-ca.der.pem"}, []string{"00"})
	if err != nil {
		t.Fatalf("newFilter: %s", err)
	}
	src := &dbSource{expiredSelector{}, f, time.Second, blog.NewMock()}

	ocspReq, err := ocsp.ParseRequest(req)
	test.AssertNotError(t, err, "Failed to parse OCSP request")

	_, _, err = src.Response(ocspReq)
	test.AssertErrorIs(t, err, bocsp.ErrNotFound)
}
