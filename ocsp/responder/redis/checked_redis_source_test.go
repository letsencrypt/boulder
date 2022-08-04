package redis

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/go-gorp/gorp/v3"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/ocsp/responder"
	ocsp_test "github.com/letsencrypt/boulder/ocsp/test"
	"github.com/letsencrypt/boulder/test"
	"golang.org/x/crypto/ocsp"
)

// echoSource implements rocspSourceInterface, returning the provided response
// and panicking if signAndSave is called.
type echoSource struct {
	resp *ocsp.Response
}

func (es echoSource) Response(ctx context.Context, req *ocsp.Request) (*responder.Response, error) {
	return &responder.Response{Response: es.resp, Raw: es.resp.Raw}, nil
}

func (es echoSource) signAndSave(ctx context.Context, req *ocsp.Request, cause string) (*responder.Response, error) {
	panic("should not happen")
}

// recordingEchoSource acts like echoSource, but instead of panicking on signAndSave,
// it records the serial number it was called with and returns the given secondResp.
type recordingEchoSource struct {
	echoSource
	secondResp *responder.Response
	ch         chan string
}

func (res recordingEchoSource) signAndSave(ctx context.Context, req *ocsp.Request, cause string) (*responder.Response, error) {
	res.ch <- req.SerialNumber.String()
	return res.secondResp, nil
}

// errorSource implements rocspSourceInterface, and always returns an error.
type errorSource struct{}

func (es errorSource) Response(ctx context.Context, req *ocsp.Request) (*responder.Response, error) {
	return nil, errors.New("sad trombone")
}

func (es errorSource) signAndSave(ctx context.Context, req *ocsp.Request, cause string) (*responder.Response, error) {
	panic("should not happen")
}

// echoSelector always returns the given certificateStatus.
type echoSelector struct {
	db.MockSqlExecutor
	status core.CertificateStatus
}

func (s echoSelector) WithContext(context.Context) gorp.SqlExecutor {
	return s
}

func (s echoSelector) SelectOne(output interface{}, _ string, _ ...interface{}) error {
	outputPtr, ok := output.(*core.CertificateStatus)
	if !ok {
		return fmt.Errorf("incorrect output type %T", output)
	}
	*outputPtr = s.status
	return nil
}

// errorSelector always returns an error.
type errorSelector struct {
	db.MockSqlExecutor
}

func (s errorSelector) SelectOne(_ interface{}, _ string, _ ...interface{}) error {
	return errors.New("oops")
}

func (s errorSelector) WithContext(context.Context) gorp.SqlExecutor {
	return s
}

func TestCheckedRedisSourceSuccess(t *testing.T) {
	serial := big.NewInt(17777)
	thisUpdate := time.Now().Truncate(time.Second).UTC()

	resp, _, err := ocsp_test.FakeResponse(ocsp.Response{
		SerialNumber: serial,
		Status:       ocsp.Good,
		ThisUpdate:   thisUpdate,
	})
	test.AssertNotError(t, err, "making fake response")

	status := core.CertificateStatus{
		Status: "good",
	}
	src := newCheckedRedisSource(echoSource{resp: resp}, echoSelector{status: status}, metrics.NoopRegisterer, blog.NewMock())
	responderResponse, err := src.Response(context.Background(), &ocsp.Request{
		SerialNumber: serial,
	})
	test.AssertNotError(t, err, "getting response")
	test.AssertEquals(t, responderResponse.SerialNumber.String(), resp.SerialNumber.String())
}

func TestCheckedRedisSourceDBError(t *testing.T) {
	serial := big.NewInt(404040)
	thisUpdate := time.Now().Truncate(time.Second).UTC()

	resp, _, err := ocsp_test.FakeResponse(ocsp.Response{
		SerialNumber: serial,
		Status:       ocsp.Good,
		ThisUpdate:   thisUpdate,
	})
	test.AssertNotError(t, err, "making fake response")

	src := newCheckedRedisSource(echoSource{resp: resp}, errorSelector{}, metrics.NoopRegisterer, blog.NewMock())
	_, err = src.Response(context.Background(), &ocsp.Request{
		SerialNumber: serial,
	})
	test.AssertError(t, err, "getting response")
}

func TestCheckedRedisSourceRedisError(t *testing.T) {
	serial := big.NewInt(314159262)

	status := core.CertificateStatus{
		Status: "good",
	}
	src := newCheckedRedisSource(errorSource{}, echoSelector{status: status}, metrics.NoopRegisterer, blog.NewMock())
	_, err := src.Response(context.Background(), &ocsp.Request{
		SerialNumber: serial,
	})
	test.AssertError(t, err, "getting response")
}

func TestCheckedRedisStatusDisagreement(t *testing.T) {
	serial := big.NewInt(2718)
	thisUpdate := time.Now().Truncate(time.Second).UTC()

	resp, _, err := ocsp_test.FakeResponse(ocsp.Response{
		SerialNumber: serial,
		Status:       ocsp.Good,
		ThisUpdate:   thisUpdate.Add(-time.Minute),
	})
	test.AssertNotError(t, err, "making fake response")

	secondResp, _, err := ocsp_test.FakeResponse(ocsp.Response{
		SerialNumber:     serial,
		Status:           ocsp.Revoked,
		RevokedAt:        thisUpdate,
		RevocationReason: ocsp.KeyCompromise,
		ThisUpdate:       thisUpdate,
	})
	test.AssertNotError(t, err, "making fake response")
	status := core.CertificateStatus{
		Status:        "revoked",
		RevokedDate:   thisUpdate,
		RevokedReason: ocsp.KeyCompromise,
	}
	source := recordingEchoSource{
		echoSource: echoSource{resp: resp},
		secondResp: &responder.Response{Response: secondResp, Raw: secondResp.Raw},
		ch:         make(chan string, 1),
	}
	src := newCheckedRedisSource(source, echoSelector{status: status}, metrics.NoopRegisterer, blog.NewMock())
	fetchedResponse, err := src.Response(context.Background(), &ocsp.Request{
		SerialNumber: serial,
	})
	test.AssertNotError(t, err, "getting re-signed response")
	test.Assert(t, fetchedResponse.ThisUpdate.Equal(thisUpdate), "thisUpdate not updated")
	test.AssertEquals(t, fetchedResponse.SerialNumber.String(), serial.String())
	test.AssertEquals(t, fetchedResponse.RevokedAt, thisUpdate)
	test.AssertEquals(t, fetchedResponse.RevocationReason, ocsp.KeyCompromise)
	test.AssertEquals(t, fetchedResponse.ThisUpdate, thisUpdate)
}
