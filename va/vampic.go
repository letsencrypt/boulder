package va

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

// performRemoteValidation coordinates the whole process of kicking off and
// collecting results from calls to remote VAs' PerformValidation function. It
// returns a problem if too many remote perspectives failed to corroborate
// domain control, or nil if enough succeeded to surpass our corroboration
// threshold.
func (va *ValidationAuthorityImpl) performRemoteValidation(
	ctx context.Context,
	req *vapb.PerformValidationRequest,
) *probs.ProblemDetails {
	remoteVACount := len(va.remoteVAs)
	if remoteVACount == 0 {
		return nil
	}

	type response struct {
		addr        string
		perspective string
		rir         string
		result      *vapb.ValidationResult
		err         error
	}

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	responses := make(chan *response, remoteVACount)
	for _, i := range rand.Perm(remoteVACount) {
		go func(rva RemoteVA) {
			res, err := rva.PerformValidation(subCtx, req)
			if err != nil {
				responses <- &response{rva.Address, rva.Perspective, rva.RIR, res, err}
				return
			}
			if res.Perspective != rva.Perspective || res.Rir != rva.RIR {
				err = fmt.Errorf(
					"Remote VA %q.PerformValidation result included mismatched Perspective remote=[%q] local=[%q] and/or RIR remote=[%q] local=[%q]",
					rva.Perspective, res.Perspective, rva.Perspective, res.Rir, rva.RIR,
				)
				responses <- &response{rva.Address, rva.Perspective, rva.RIR, res, err}
				return
			}
			responses <- &response{rva.Address, rva.Perspective, rva.RIR, res, err}
		}(va.remoteVAs[i])
	}

	required := remoteVACount - va.maxRemoteFailures
	var passed []string
	var failed []string
	var firstProb *probs.ProblemDetails

	for resp := range responses {
		var currProb *probs.ProblemDetails

		if resp.err != nil {
			// Failed to communicate with the remote VA.
			failed = append(failed, resp.perspective)

			if core.IsCanceled(resp.err) {
				currProb = probs.ServerInternal("Secondary domain validation RPC canceled")
			} else {
				va.log.Errf("Remote VA %q.PerformValidation failed: %s", resp.addr, resp.err)
				currProb = probs.ServerInternal("Secondary domain validation RPC failed")
			}
		} else if resp.result.Problems != nil {
			// The remote VA returned a problem.
			failed = append(failed, resp.perspective)

			var err error
			currProb, err = bgrpc.PBToProblemDetails(resp.result.Problems)
			if err != nil {
				va.log.Errf("Remote VA %q.PerformValidation returned malformed problem: %s", resp.addr, err)
				currProb = probs.ServerInternal("Secondary domain validation RPC returned malformed result")
			}
		} else {
			// The remote VA returned a successful result.
			passed = append(passed, resp.perspective)
		}

		if firstProb == nil && currProb != nil {
			// A problem was encountered for the first time.
			firstProb = currProb
		}

		// To respond faster, if we get enough successes or too many failures, we cancel remaining RPCs.
		// Finish the loop to collect remaining responses into `failed` so we can rely on having a response
		// for every request we made.
		if len(passed) >= required {
			cancel()
		}
		if len(failed) > va.maxRemoteFailures {
			cancel()
		}

		// Once all the VAs have returned a result, break the loop.
		if len(passed)+len(failed) >= remoteVACount {
			break
		}
	}

	if len(passed) >= required {
		return nil
	} else if len(failed) > va.maxRemoteFailures {
		firstProb.Detail = fmt.Sprintf("During secondary domain validation: %s", firstProb.Detail)
		return firstProb
	} else {
		// This condition should not occur - it indicates the passed/failed counts
		// neither met the required threshold nor the maxRemoteFailures threshold.
		return probs.ServerInternal("Too few remote PerformValidation RPC results")
	}
}

// performLocalValidation performs primary domain control validation and then
// checks CAA. If either step fails, it immediately returns a bare error so
// that our audit logging can include the underlying error.
func (va *ValidationAuthorityImpl) performLocalValidation(
	ctx context.Context,
	ident identifier.ACMEIdentifier,
	regid int64,
	kind core.AcmeChallenge,
	token string,
	keyAuthorization string,
) ([]core.ValidationRecord, error) {
	// Do primary domain control validation. Any kind of error returned by this
	// counts as a validation error, and will be converted into an appropriate
	// probs.ProblemDetails by the calling function.
	records, err := va.validateChallenge(ctx, ident, kind, token, keyAuthorization)
	if err != nil {
		return records, err
	}

	// Do primary CAA checks. Any kind of error returned by this counts as not
	// receiving permission to issue, and will be converted into an appropriate
	// probs.ProblemDetails by the calling function.
	err = va.checkCAA(ctx, ident, &caaParams{
		accountURIID:     regid,
		validationMethod: kind,
	})
	if err != nil {
		return records, err
	}

	return records, nil
}

// PerformValidation conducts a local Domain Control Validation (DCV) and CAA
// check for the specified challenge and dnsName. When invoked on the primary
// Validation Authority (VA) and the local validation succeeds, it also performs
// DCV and CAA checks using the configured remote VAs. Failed validations are
// indicated by a non-nil Problems in the returned ValidationResult.
// PerformValidation returns error only for internal logic errors (and the
// client may receive errors from gRPC in the event of a communication problem).
// ValidationResult always includes a list of ValidationRecords, even when it
// also contains Problems. This method does NOT implement Multi-Perspective
// Issuance Corroboration as defined in BRs Sections 3.2.2.9 and 5.4.1.
func (va *ValidationAuthorityImpl) PerformValidation(ctx context.Context, req *vapb.PerformValidationRequest) (*vapb.ValidationResult, error) {
	if core.IsAnyNilOrZero(req, req.DnsName, req.Challenge, req.Authz, req.ExpectedKeyAuthorization) {
		return nil, berrors.InternalServerError("Incomplete validation request")
	}

	chall, err := bgrpc.PBToChallenge(req.Challenge)
	if err != nil {
		return nil, errors.New("challenge failed to deserialize")
	}

	err = chall.CheckPending()
	if err != nil {
		return nil, berrors.MalformedError("challenge failed consistency check: %s", err)
	}

	// Set up variables and a deferred closure to report validation latency
	// metrics and log validation errors. Below here, do not use := to redeclare
	// `prob`, or this will fail.
	var prob *probs.ProblemDetails
	var localLatency time.Duration
	start := va.clk.Now()
	logEvent := verificationRequestEvent{
		AuthzID:    req.Authz.Id,
		Requester:  req.Authz.RegID,
		Identifier: req.DnsName,
		Challenge:  chall,
	}
	defer func() {
		probType := ""
		outcome := fail
		if prob != nil {
			probType = string(prob.Type)
			logEvent.Error = prob.Error()
			logEvent.Challenge.Error = prob
			logEvent.Challenge.Status = core.StatusInvalid
		} else {
			logEvent.Challenge.Status = core.StatusValid
			outcome = pass
		}
		// Observe local validation latency (primary|remote).
		va.observeLatency(opChallAndCAA, va.perspective, string(chall.Type), probType, outcome, localLatency)
		if va.isPrimaryVA() {
			// Observe total validation latency (primary+remote).
			va.observeLatency(opChallAndCAA, allPerspectives, string(chall.Type), probType, outcome, va.clk.Since(start))
		}

		// Log the total validation latency.
		logEvent.Latency = time.Since(start).Round(time.Millisecond).Seconds()
		va.log.AuditObject("Validation result", logEvent)
	}()

	// Do local validation. Note that we process the result in a couple ways
	// *before* checking whether it returned an error. These few checks are
	// carefully written to ensure that they work whether the local validation
	// was successful or not, and cannot themselves fail.
	records, err := va.performLocalValidation(
		ctx,
		identifier.NewDNS(req.DnsName),
		req.Authz.RegID,
		chall.Type,
		chall.Token,
		req.ExpectedKeyAuthorization)

	// Stop the clock for local validation latency.
	localLatency = va.clk.Since(start)

	// Check for malformed ValidationRecords
	logEvent.Challenge.ValidationRecord = records
	if err == nil && !logEvent.Challenge.RecordsSane() {
		err = errors.New("records from local validation failed sanity check")
	}

	if err != nil {
		logEvent.InternalError = err.Error()
		prob = detailedError(err)
		return bgrpc.ValidationResultToPB(records, filterProblemDetails(prob), va.perspective, va.rir)
	}

	// Do remote validation. We do this after local validation is complete to
	// avoid wasting work when validation will fail anyway. This only returns a
	// singular problem, because the remote VAs have already audit-logged their
	// own validation records, and it's not helpful to present multiple large
	// errors to the end user.
	prob = va.performRemoteValidation(ctx, req)
	return bgrpc.ValidationResultToPB(records, filterProblemDetails(prob), va.perspective, va.rir)
}
