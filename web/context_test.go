package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

type myHandler struct{}

func (m myHandler) ServeHTTP(e *RequestEvent, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(201)
	_, _ = w.Write([]byte("hi"))
}

func TestLogCode(t *testing.T) {
	mockLog := blog.UseMock()
	th := NewTopHandler(mockLog, myHandler{})
	req, err := http.NewRequest("GET", "/", &bytes.Reader{})
	if err != nil {
		t.Fatal(err)
	}
	th.ServeHTTP(httptest.NewRecorder(), req)
	test.AssertEquals(t, 1, len(mockLog.GetAllMatching(`"Code":201`)))
}
