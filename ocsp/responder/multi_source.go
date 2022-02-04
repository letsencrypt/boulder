package responder

import (
	"context"
	"errors"
	"fmt"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

type multiSource struct {
	primary   Source
	secondary Source
	counter   *prometheus.CounterVec
	log       blog.Logger
}

func NewMultiSource(primary, secondary Source, stats prometheus.Registerer, log blog.Logger) (*multiSource, error) {
	if primary == nil || secondary == nil {
		return nil, errors.New("must provide both primary and secondary sources")
	}
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ocsp_multiplex_responses",
		Help: "Count of OCSP requests/responses by action taken by the multiSource",
	}, []string{"result"})
	return &multiSource{
		primary:   primary,
		secondary: secondary,
		counter:   counter,
		log:       log,
	}, nil
}

// Response implements the Source interface. It performs lookups using both the
// primary and secondary wrapped Sources. It returns whichever response arrives
// first, with the caveat that if the secondary Source responds quicker, it will
// wait for the result from the primary to ensure that they agree.
func (src *multiSource) Response(ctx context.Context, req *ocsp.Request) (*Response, error) {
	serialString := core.SerialToString(req.SerialNumber)

	primaryChan := getResponse(ctx, src.primary, req)
	secondaryChan := getResponse(ctx, src.secondary, req)

	// If the primary source returns first, check the output and return
	// it. If the secondary source wins, then wait for the primary so the
	// results from the secondary can be verified. It is important that we
	// never return a response from the secondary source that is good if the
	// primary has a revoked status. If the secondary source wins the race and
	// passes these checks, return its response instead.
	select {
	case <-ctx.Done():
		src.counter.WithLabelValues("timed_out").Inc()
		return nil, fmt.Errorf("looking up OCSP response for serial: %s err: %w", serialString, ctx.Err())

	case primaryResult := <-primaryChan:
		src.counter.WithLabelValues("primary_result").Inc()
		return primaryResult.resp, primaryResult.err

	case secondaryResult := <-secondaryChan:
		// If secondary returns first, wait for primary to return for
		// comparison.
		var primaryResult responseResult

		// Listen for cancellation or timeout waiting for primary result.
		select {
		case <-ctx.Done():
			src.counter.WithLabelValues("timed_out").Inc()
			return nil, fmt.Errorf("looking up OCSP response for serial: %s err: %w", serialString, ctx.Err())

		case primaryResult = <-primaryChan:
		}

		// Check for error returned from the primary lookup, return on error.
		if primaryResult.err != nil {
			src.counter.WithLabelValues("primary_error").Inc()
			return nil, primaryResult.err
		}

		// Check for error returned from the secondary lookup. If error return
		// primary lookup result.
		if secondaryResult.err != nil {
			src.counter.WithLabelValues("secondary_error").Inc()
			return primaryResult.resp, nil
		}

		// If the secondary response status doesn't match primary, return
		// primary response.
		if secondaryResult.resp.Status != primaryResult.resp.Status {
			src.counter.WithLabelValues("mismatch").Inc()
			return primaryResult.resp, nil
		}

		// The secondary response has passed checks, return it.
		src.counter.WithLabelValues("secondary_result").Inc()
		return secondaryResult.resp, nil
	}
}

type responseResult struct {
	resp *Response
	err  error
}

// getResponse provides a thin wrapper around an underlying Source's Response
// method, calling it in a goroutine and passing the result back on a channel.
func getResponse(ctx context.Context, src Source, req *ocsp.Request) chan responseResult {
	responseChan := make(chan responseResult)

	go func() {
		defer close(responseChan)

		resp, err := src.Response(ctx, req)
		responseChan <- responseResult{resp, err}
	}()

	return responseChan
}
