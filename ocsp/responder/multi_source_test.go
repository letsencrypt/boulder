package responder

import (
	"context"
	"errors"
	"testing"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
	"golang.org/x/crypto/ocsp"
)

type succeedSource struct {
	resp *Response
}

func (src *succeedSource) Response(context.Context, *ocsp.Request) (*Response, error) {
	if src.resp != nil {
		return src.resp, nil
	}
	// We can't just return nil, as the multiSource checks the Statuses from each
	// Source to ensure they agree.
	return &Response{&ocsp.Response{Status: ocsp.Good}, []byte{}}, nil
}

type failSource struct{}

func (src *failSource) Response(context.Context, *ocsp.Request) (*Response, error) {
	return nil, errors.New("failure")
}

func TestBothGood(t *testing.T) {
	src, err := NewMultiSource(&succeedSource{}, &succeedSource{}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create multiSource")

	_, err = src.Response(context.Background(), &ocsp.Request{})
	test.AssertNotError(t, err, "unexpected error")
}

func TestPrimaryGoodSecondaryErr(t *testing.T) {
	src, err := NewMultiSource(&succeedSource{}, &failSource{}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create multiSource")

	_, err = src.Response(context.Background(), &ocsp.Request{})
	test.AssertNotError(t, err, "unexpected error")
}

func TestPrimaryErrSecondaryGood(t *testing.T) {
	src, err := NewMultiSource(&failSource{}, &succeedSource{}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create multiSource")

	_, err = src.Response(context.Background(), &ocsp.Request{})
	test.AssertError(t, err, "expected error")
}

func TestBothErr(t *testing.T) {
	src, err := NewMultiSource(&failSource{}, &failSource{}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create multiSource")

	_, err = src.Response(context.Background(), &ocsp.Request{})
	test.AssertError(t, err, "expected error")
}

func TestBothSucceedButDisagree(t *testing.T) {
	otherResp := &Response{&ocsp.Response{Status: ocsp.Revoked}, []byte{}}
	src, err := NewMultiSource(&succeedSource{otherResp}, &succeedSource{}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create multiSource")

	resp, err := src.Response(context.Background(), &ocsp.Request{})
	test.AssertNotError(t, err, "unexpected error")
	test.AssertEquals(t, resp.Status, ocsp.Revoked)
}

// blockingSource doesn't return until its channel is closed.
// Use `defer close(signal)` to cause it to block until the test is done.
type blockingSource struct {
	signal chan struct{}
}

func (src *blockingSource) Response(context.Context, *ocsp.Request) (*Response, error) {
	<-src.signal
	return nil, nil
}

func TestPrimaryGoodSecondaryTimeout(t *testing.T) {
	signal := make(chan struct{})
	defer close(signal)

	src, err := NewMultiSource(&succeedSource{}, &blockingSource{signal}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create multiSource")

	_, err = src.Response(context.Background(), &ocsp.Request{})
	test.AssertNotError(t, err, "unexpected error")
}

func TestPrimaryTimeoutSecondaryGood(t *testing.T) {
	signal := make(chan struct{})
	defer close(signal)

	src, err := NewMultiSource(&blockingSource{signal}, &succeedSource{}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create multiSource")

	// We use cancellation instead of timeout so we don't have to wait on real time.
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	errChan := make(chan error)
	go func() {
		_, err = src.Response(ctx, &ocsp.Request{})
		errChan <- err
	}()
	cancel()
	err = <-errChan

	test.AssertError(t, err, "expected error")
}

func TestBothTimeout(t *testing.T) {
	signal := make(chan struct{})
	defer close(signal)

	src, err := NewMultiSource(&blockingSource{signal}, &blockingSource{signal}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create multiSource")

	// We use cancellation instead of timeout so we don't have to wait on real time.
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	errChan := make(chan error)
	go func() {
		_, err = src.Response(ctx, &ocsp.Request{})
		errChan <- err
	}()
	cancel()
	err = <-errChan

	test.AssertError(t, err, "expected error")
}
