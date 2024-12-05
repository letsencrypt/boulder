package va

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	vapb "github.com/letsencrypt/boulder/va/proto"
	"google.golang.org/protobuf/proto"
)

// performRemoteOperation concurrently calls the provided operation with `req` and a
// RemoteVA once for each configured RemoteVA. It cancels remaining operations and returns
// early if either the required number of successful results is obtained or the number of
// failures exceeds va.maxRemoteFailures.
//
// Internal logic errors are logged. If the number of operation failures exceeds
// va.maxRemoteFailures, the first encountered problem is returned as a
// *probs.ProblemDetails.
func (va *ValidationAuthorityImpl) performRemoteOperation(ctx context.Context, op remoteOperation, req proto.Message) *probs.ProblemDetails {
	remoteVACount := len(va.remoteVAs)
	if remoteVACount == 0 {
		return nil
	}
	isCAAValidReq, isCAACheck := req.(*vapb.IsCAAValidRequest)

	type response struct {
		addr        string
		perspective string
		rir         string
		result      remoteResult
		err         error
	}

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	responses := make(chan *response, remoteVACount)
	for _, i := range rand.Perm(remoteVACount) {
		go func(rva RemoteVA) {
			res, err := op(subCtx, rva, req)
			if err != nil {
				responses <- &response{rva.Address, rva.Perspective, rva.RIR, res, err}
				return
			}
			if res.GetPerspective() != rva.Perspective || res.GetRir() != rva.RIR {
				err = fmt.Errorf(
					"Expected perspective %q (%q) but got reply from %q (%q) - misconfiguration likely", rva.Perspective, rva.RIR, res.GetPerspective(), res.GetRir(),
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
				currProb = probs.ServerInternal("Secondary validation RPC canceled")
			} else {
				va.log.Errf("Operation on remote VA (%s) failed: %s", resp.addr, resp.err)
				currProb = probs.ServerInternal("Secondary validation RPC failed")
			}
		} else if resp.result.GetProblem() != nil {
			// The remote VA returned a problem.
			failed = append(failed, resp.perspective)

			var err error
			currProb, err = bgrpc.PBToProblemDetails(resp.result.GetProblem())
			if err != nil {
				va.log.Errf("Operation on Remote VA (%s) returned malformed problem: %s", resp.addr, err)
				currProb = probs.ServerInternal("Secondary validation RPC returned malformed result")
			}
			if isCAACheck {
				// We're checking CAA, log the problem.
				va.log.Errf("Operation on Remote VA (%s) returned a problem: %s", resp.addr, currProb)
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

	if isCAACheck {
		// We're checking CAA, log the results.
		va.logRemoteResults(isCAAValidReq, len(passed), len(failed))
	}

	if len(passed) >= required {
		return nil
	} else if len(failed) > va.maxRemoteFailures {
		firstProb.Detail = fmt.Sprintf("During secondary validation: %s", firstProb.Detail)
		return firstProb
	} else {
		// This condition should not occur - it indicates the passed/failed counts
		// neither met the required threshold nor the maxRemoteFailures threshold.
		return probs.ServerInternal("Too few remote RPC results")
	}
}

// verificationRequestEvent is logged once for each validation attempt. Its
// fields are exported for logging purposes.
type verificationRequestEvent struct {
	AuthzID       string
	Requester     int64
	Identifier    string
	Challenge     core.Challenge
	Error         string `json:",omitempty"`
	InternalError string `json:",omitempty"`
	Latency       float64
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
		logEvent.Latency = va.clk.Since(start).Round(time.Millisecond).Seconds()
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
	op := func(ctx context.Context, remoteva RemoteVA, req proto.Message) (remoteResult, error) {
		validationRequest, ok := req.(*vapb.PerformValidationRequest)
		if !ok {
			return nil, fmt.Errorf("got type %T, want *vapb.PerformValidationRequest", req)
		}
		return remoteva.PerformValidation(ctx, validationRequest)
	}
	prob = va.performRemoteOperation(ctx, op, req)
	return bgrpc.ValidationResultToPB(records, filterProblemDetails(prob), va.perspective, va.rir)
}

// IsCAAValid checks requested CAA records from a VA, and recursively any RVAs
// configured in the VA. It returns a response or an error.
func (va *ValidationAuthorityImpl) IsCAAValid(ctx context.Context, req *vapb.IsCAAValidRequest) (*vapb.IsCAAValidResponse, error) {
	if core.IsAnyNilOrZero(req.Domain, req.ValidationMethod, req.AccountURIID) {
		return nil, berrors.InternalServerError("incomplete IsCAAValid request")
	}
	logEvent := verificationRequestEvent{
		// TODO(#7061) Plumb req.Authz.Id as "AuthzID:" through from the RA to
		// correlate which authz triggered this request.
		Requester:  req.AccountURIID,
		Identifier: req.Domain,
	}

	challType := core.AcmeChallenge(req.ValidationMethod)
	if !challType.IsValid() {
		return nil, berrors.InternalServerError("unrecognized validation method %q", req.ValidationMethod)
	}

	acmeID := identifier.NewDNS(req.Domain)
	params := &caaParams{
		accountURIID:     req.AccountURIID,
		validationMethod: challType,
	}

	var prob *probs.ProblemDetails
	var internalErr error
	var localLatency time.Duration
	start := va.clk.Now()

	defer func() {
		probType := ""
		outcome := fail
		if prob != nil {
			// CAA check failed.
			probType = string(prob.Type)
			logEvent.Error = prob.Error()
		} else {
			// CAA check passed.
			outcome = pass
		}
		// Observe local check latency (primary|remote).
		va.observeLatency(opCAA, va.perspective, string(challType), probType, outcome, localLatency)
		if va.isPrimaryVA() {
			// Observe total check latency (primary+remote).
			va.observeLatency(opCAA, allPerspectives, string(challType), probType, outcome, va.clk.Since(start))
		}
		// Log the total check latency.
		logEvent.Latency = va.clk.Since(start).Round(time.Millisecond).Seconds()

		va.log.AuditObject("CAA check result", logEvent)
	}()

	internalErr = va.checkCAA(ctx, acmeID, params)

	// Stop the clock for local check latency.
	localLatency = va.clk.Since(start)

	if internalErr != nil {
		logEvent.InternalError = internalErr.Error()
		prob = detailedError(internalErr)
		prob.Detail = fmt.Sprintf("While processing CAA for %s: %s", req.Domain, prob.Detail)
	}

	if features.Get().EnforceMultiCAA {
		op := func(ctx context.Context, remoteva RemoteVA, req proto.Message) (remoteResult, error) {
			checkRequest, ok := req.(*vapb.IsCAAValidRequest)
			if !ok {
				return nil, fmt.Errorf("got type %T, want *vapb.IsCAAValidRequest", req)
			}
			return remoteva.IsCAAValid(ctx, checkRequest)
		}
		remoteProb := va.performRemoteOperation(ctx, op, req)
		// If the remote result was a non-nil problem then fail the CAA check
		if remoteProb != nil {
			prob = remoteProb
			va.log.Infof("CAA check failed due to remote failures: identifier=%v err=%s",
				req.Domain, remoteProb)
		}
	}

	if prob != nil {
		// The ProblemDetails will be serialized through gRPC, which requires UTF-8.
		// It will also later be serialized in JSON, which defaults to UTF-8. Make
		// sure it is UTF-8 clean now.
		prob = filterProblemDetails(prob)
		return &vapb.IsCAAValidResponse{
			Problem: &corepb.ProblemDetails{
				ProblemType: string(prob.Type),
				Detail:      replaceInvalidUTF8([]byte(prob.Detail)),
			},
			Perspective: va.perspective,
			Rir:         va.rir,
		}, nil
	} else {
		return &vapb.IsCAAValidResponse{
			Perspective: va.perspective,
			Rir:         va.rir,
		}, nil
	}
}
