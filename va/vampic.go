package va

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	vapb "github.com/letsencrypt/boulder/va/proto"
	"google.golang.org/protobuf/proto"
)

const (
	// requiredRIRs is the minimum number of distinct Regional Internet
	// Registries required for MPIC-compliant validation. Per BRs Section
	// 3.2.2.9, starting March 15, 2026, the required number is 2.
	requiredRIRs = 2
)

// mpicSummary is returned by doRemoteOperation and contains a summary of the
// validation results for logging purposes. To ensure that the JSON output does
// not contain nil slices, and to ensure deterministic output use the
// summarizeMPIC function to prepare an mpicSummary.
type mpicSummary struct {
	// Passed are the perspectives that passed validation.
	Passed []string `json:"passedPerspectives"`

	// Failed are the perspectives that failed validation.
	Failed []string `json:"failedPerspectives"`

	// PassedRIRs are the Regional Internet Registries that the passing
	// perspectives reside in.
	PassedRIRs []string `json:"passedRIRs"`

	// QuorumResult is the Multi-Perspective Issuance Corroboration quorum
	// result, per BRs Section 5.4.1, Requirement 2.7 (i.e., "3/4" which should
	// be interpreted as "Three (3) out of four (4) attempted Network
	// Perspectives corroborated the determinations made by the Primary Network
	// Perspective".
	QuorumResult string `json:"quorumResult"`
}

// summarizeMPIC prepares an *mpicSummary for logging, ensuring there are no nil
// slices and output is deterministic.
func summarizeMPIC(passed, failed []string, passedRIRSet map[string]struct{}) *mpicSummary {
	if passed == nil {
		passed = []string{}
	}
	slices.Sort(passed)
	if failed == nil {
		failed = []string{}
	}
	slices.Sort(failed)

	passedRIRs := []string{}
	if passedRIRSet != nil {
		for rir := range maps.Keys(passedRIRSet) {
			passedRIRs = append(passedRIRs, rir)
		}
	}
	slices.Sort(passedRIRs)

	return &mpicSummary{
		Passed:       passed,
		Failed:       failed,
		PassedRIRs:   passedRIRs,
		QuorumResult: fmt.Sprintf("%d/%d", len(passed), len(passed)+len(failed)),
	}
}

// doRemoteOperation concurrently calls the provided operation with `req` and a
// RemoteVA once for each configured RemoteVA. It cancels remaining operations
// and returns early if either the required number of successful results is
// obtained or the number of failures exceeds va.maxRemoteFailures.
//
// Internal logic errors are logged. If the number of operation failures exceeds
// va.maxRemoteFailures, the first encountered problem is returned as a
// *probs.ProblemDetails.
func (va *ValidationAuthorityImpl) doRemoteOperation(ctx context.Context, op remoteOperation, req proto.Message) (*mpicSummary, *probs.ProblemDetails) {
	remoteVACount := len(va.remoteVAs)
	//  - Mar 15, 2026: MUST implement using at least 3 perspectives
	//  - Jun 15, 2026: MUST implement using at least 4 perspectives
	//  - Dec 15, 2026: MUST implement using at least 5 perspectives
	// See "Phased Implementation Timeline" in
	// https://github.com/cabforum/servercert/blob/main/docs/BR.md#3229-multi-perspective-issuance-corroboration
	if remoteVACount < 3 {
		return nil, probs.ServerInternal("Insufficient remote perspectives: need at least 3")
	}

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
	var passedRIRs = map[string]struct{}{}
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
		} else {
			// The remote VA returned a successful result.
			passed = append(passed, resp.perspective)
			passedRIRs[resp.rir] = struct{}{}
		}

		if firstProb == nil && currProb != nil {
			// A problem was encountered for the first time.
			firstProb = currProb
		}

		// To respond faster, if we get enough successes or too many failures, we cancel remaining RPCs.
		// Finish the loop to collect remaining responses into `failed` so we can rely on having a response
		// for every request we made.
		if len(passed) >= required && len(passedRIRs) >= requiredRIRs {
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
	if len(passed) >= required && len(passedRIRs) >= requiredRIRs {
		return summarizeMPIC(passed, failed, passedRIRs), nil
	}
	if firstProb == nil {
		// This should never happen. If we didn't meet the thresholds above we
		// should have seen at least one error.
		return summarizeMPIC(passed, failed, passedRIRs), probs.ServerInternal(
			"During secondary validation: validation failed but the problem is unavailable")
	}
	firstProb.Detail = fmt.Sprintf("During secondary validation: %s", firstProb.Detail)
	return summarizeMPIC(passed, failed, passedRIRs), firstProb
}

// validationLogEvent is a struct that contains the information needed to log
// the results of DoCAA and DoDCV.
type validationLogEvent struct {
	AuthzID       string
	Requester     int64
	Identifier    string
	Challenge     core.Challenge
	Error         string `json:",omitempty"`
	InternalError string `json:",omitempty"`
	Latency       float64
	Summary       *mpicSummary `json:",omitempty"`
}

// DoDCV conducts a local Domain Control Validation (DCV) for the specified
// challenge. When invoked on the primary Validation Authority (VA) and the
// local validation succeeds, it also performs DCV validations using the
// configured remote VAs. Failed validations are indicated by a non-nil Problems
// in the returned ValidationResult. DoDCV returns error only for internal logic
// errors (and the client may receive errors from gRPC in the event of a
// communication problem). ValidationResult always includes a list of
// ValidationRecords, even when it also contains Problems. This method
// implements the DCV portion of Multi-Perspective Issuance Corroboration as
// defined in BRs Sections 3.2.2.9 and 5.4.1.
func (va *ValidationAuthorityImpl) DoDCV(ctx context.Context, req *vapb.PerformValidationRequest) (*vapb.ValidationResult, error) {
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

	// Initialize variables and a deferred function to handle validation latency
	// metrics, log validation errors, and log an MPIC summary. Avoid using :=
	// to redeclare `prob`, `localLatency`, or `summary` below this point.
	var prob *probs.ProblemDetails
	var summary *mpicSummary
	var localLatency time.Duration
	start := va.clk.Now()
	logEvent := validationLogEvent{
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
		va.observeLatency(opDCV, va.perspective, string(chall.Type), probType, outcome, localLatency)
		if va.isPrimaryVA() {
			// Observe total validation latency (primary+remote).
			va.observeLatency(opDCV, allPerspectives, string(chall.Type), probType, outcome, va.clk.Since(start))
			logEvent.Summary = summary
		}

		// Log the total validation latency.
		logEvent.Latency = va.clk.Since(start).Round(time.Millisecond).Seconds()
		va.log.AuditObject("Validation result", logEvent)
	}()

	// Do local validation. Note that we process the result in a couple ways
	// *before* checking whether it returned an error. These few checks are
	// carefully written to ensure that they work whether the local validation
	// was successful or not, and cannot themselves fail.
	records, err := va.validateChallenge(
		ctx,
		identifier.NewDNS(req.DnsName),
		chall.Type,
		chall.Token,
		req.ExpectedKeyAuthorization,
	)

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

	if va.isPrimaryVA() {
		// Do remote validation. We do this after local validation is complete
		// to avoid wasting work when validation will fail anyway. This only
		// returns a singular problem, because the remote VAs have already
		// logged their own validationLogEvent, and it's not helpful to present
		// multiple large errors to the end user.
		op := func(ctx context.Context, remoteva RemoteVA, req proto.Message) (remoteResult, error) {
			validationRequest, ok := req.(*vapb.PerformValidationRequest)
			if !ok {
				return nil, fmt.Errorf("got type %T, want *vapb.PerformValidationRequest", req)
			}
			return remoteva.DoDCV(ctx, validationRequest)
		}
		summary, prob = va.doRemoteOperation(ctx, op, req)
	}
	return bgrpc.ValidationResultToPB(records, filterProblemDetails(prob), va.perspective, va.rir)
}

// DoCAA conducts a CAA check for the specified dnsName. When invoked on the
// primary Validation Authority (VA) and the local check succeeds, it also
// performs CAA checks using the configured remote VAs. Failed checks are
// indicated by a non-nil Problems in the returned ValidationResult. DoCAA
// returns error only for internal logic errors (and the client may receive
// errors from gRPC in the event of a communication problem). This method
// implements the CAA portion of Multi-Perspective Issuance Corroboration as
// defined in BRs Sections 3.2.2.9 and 5.4.1.
func (va *ValidationAuthorityImpl) DoCAA(ctx context.Context, req *vapb.IsCAAValidRequest) (*vapb.IsCAAValidResponse, error) {
	if core.IsAnyNilOrZero(req.Domain, req.ValidationMethod, req.AccountURIID) {
		return nil, berrors.InternalServerError("incomplete IsCAAValid request")
	}
	logEvent := validationLogEvent{
		AuthzID:    req.AuthzID,
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

	// Initialize variables and a deferred function to handle check latency
	// metrics, log check errors, and log an MPIC summary. Avoid using := to
	// redeclare `prob`, `localLatency`, or `summary` below this point.
	var prob *probs.ProblemDetails
	var summary *mpicSummary
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
			logEvent.Summary = summary
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

	if va.isPrimaryVA() {
		op := func(ctx context.Context, remoteva RemoteVA, req proto.Message) (remoteResult, error) {
			checkRequest, ok := req.(*vapb.IsCAAValidRequest)
			if !ok {
				return nil, fmt.Errorf("got type %T, want *vapb.IsCAAValidRequest", req)
			}
			return remoteva.DoCAA(ctx, checkRequest)
		}
		var remoteProb *probs.ProblemDetails
		summary, remoteProb = va.doRemoteOperation(ctx, op, req)
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
