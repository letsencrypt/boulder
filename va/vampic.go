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
	berrors "github.com/letsencrypt/boulder/errors"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

// mpicSummary is returned by remoteDoDCV and contains a summary of the
// validation results for logging purposes. Use prepareSummary() to create a
// final summary to avoid "null" in JSON output.
type mpicSummary struct {
	// Passed are the distinct perspectives that Passed validation.
	Passed []string `json:"passedPerspectives"`

	// Failed are the disctint perspectives that Failed validation.
	Failed []string `json:"failedPerspectives"`

	// RIRs are the distinct Regional Internet Registries that passing
	// perspectives belonged to.
	RIRs []string `json:"passedRIRs"`

	// QuorumResult is the Multi-Perspective Issuance Corroboration quorum
	// result, per BRs Section 5.4.1, Requirement 2.7 (i.e., "3/4" which should
	// be interpreted as "Three (3) out of four (4) attempted Network
	// Perspectives corroborated the determinations made by the Primary Network
	// Perspective).
	QuorumResult string `json:"quorumResult"`
}

// prepareSummary prepares a summary of the validation results for logging
// purposes. Sets empty slices to []string{} to avoid "null" in JSON output.
func prepareSummary(passed, failed []string, passedRIRs map[string]struct{}, remoteVACount int) mpicSummary {
	if passed == nil {
		passed = []string{}
	}
	if failed == nil {
		failed = []string{}
	}

	rirs := []string{}
	if passedRIRs != nil {
		for rir := range maps.Keys(passedRIRs) {
			rirs = append(rirs, rir)
		}
		slices.Sort(rirs)
	}

	return mpicSummary{
		Passed:       passed,
		Failed:       failed,
		RIRs:         rirs,
		QuorumResult: fmt.Sprintf("%d/%d", len(passed), remoteVACount),
	}
}

// doDCVAuditLog is logged once for each validation attempt. Its
// fields are exported for logging purposes.
type doDCVAuditLog struct {
	AuthzID       string
	Requester     int64
	Identifier    string
	Challenge     core.Challenge
	Error         string `json:",omitempty"`
	InternalError string `json:",omitempty"`
	Latency       float64
	MPICSummary   mpicSummary
}

// remoteValidateChallenge performs an MPIC-compliant remote validation of the
// challenge using the configured remote VAs. It returns a summary of the
// validation results and a problem if the validation failed. The summary is
// mandatory and must be returned even if the validation failed.
func (va *ValidationAuthorityImpl) remoteDoDCV(ctx context.Context, req *vapb.DCVRequest) (mpicSummary, *probs.ProblemDetails) {
	// Mar 15, 2026: MUST implement using at least 3 perspectives
	// Jun 15, 2026: MUST implement using at least 4 perspectives
	// Dec 15, 2026: MUST implement using at least 5 perspectives
	remoteVACount := len(va.remoteVAs)
	if remoteVACount < 3 {
		return mpicSummary{}, probs.ServerInternal("Insufficient remote perspectives: need at least 3")
	}

	type response struct {
		addr   string
		result *vapb.ValidationResult
		err    error
	}

	responses := make(chan *response, remoteVACount)
	for _, i := range rand.Perm(remoteVACount) {
		go func(rva RemoteVA) {
			res, err := rva.DoDCV(ctx, req)
			responses <- &response{rva.Address, res, err}
		}(va.remoteVAs[i])
	}

	var passed []string
	var failed []string
	passedRIRs := make(map[string]struct{})

	var firstProb *probs.ProblemDetails
	for i := 0; i < remoteVACount; i++ {
		resp := <-responses

		var currProb *probs.ProblemDetails
		if resp.err != nil {
			// Failed to communicate with the remote VA.
			failed = append(failed, resp.addr)
			if errors.Is(resp.err, context.Canceled) {
				currProb = probs.ServerInternal("Secondary domain validation RPC canceled")
			} else {
				va.log.Errf("Remote VA %q.ValidateChallenge failed: %s", resp.addr, resp.err)
				currProb = probs.ServerInternal("Secondary domain validation RPC failed")
			}

		} else if resp.result.Problems != nil {
			// The remote VA returned a problem.
			failed = append(failed, resp.result.Perspective)

			var err error
			currProb, err = bgrpc.PBToProblemDetails(resp.result.Problems)
			if err != nil {
				va.log.Errf("Remote VA %q.ValidateChallenge returned a malformed problem: %s", resp.addr, err)
				currProb = probs.ServerInternal("Secondary domain validation RPC returned malformed result")
			}

		} else {
			// The remote VA returned a successful result.
			passed = append(passed, resp.result.Perspective)
			passedRIRs[resp.result.Rir] = struct{}{}
		}

		if firstProb == nil && currProb != nil {
			// A problem was encountered for the first time.
			firstProb = currProb
		}
	}

	// Prepare the summary, this MUST be returned even if the validation failed.
	summary := prepareSummary(passed, failed, passedRIRs, remoteVACount)

	maxRemoteFailures := maxAllowedFailures(remoteVACount)
	if len(failed) > maxRemoteFailures {
		// Too many failures to reach quorum.
		if firstProb != nil {
			firstProb.Detail = fmt.Sprintf("During secondary domain validation: %s", firstProb.Detail)
			return summary, firstProb
		}
		return summary, probs.ServerInternal("Secondary domain validation failed due to too many failures")
	}

	if len(passed) < (remoteVACount - maxRemoteFailures) {
		// Too few successful responses to reach quorum.
		if firstProb != nil {
			firstProb.Detail = fmt.Sprintf("During secondary domain validation: %s", firstProb.Detail)
			return summary, firstProb
		}
		return summary, probs.ServerInternal("Secondary domain validation failed due to insufficient successful responses")
	}

	if len(passedRIRs) < 2 {
		// Too few successful responses from distinct RIRs to reach quorum.
		if firstProb != nil {
			firstProb.Detail = fmt.Sprintf("During secondary domain validation: %s", firstProb.Detail)
			return summary, firstProb
		}
		return summary, probs.Unauthorized("Secondary domain validation failed to receive enough corroborations from distinct RIRs")
	}

	// Enough successful responses from distinct RIRs to reach quorum.
	return summary, nil
}

// DoDCV performs a local Domain Control Validation (DCV) for the provided
// challenge. If called on the primary VA and local validation passes, it will
// also perform an MPIC-compliant DCV using the configured remote VAs. It
// returns a validation result and an error if the validation failed. The
// returned result will always contain a list of validation records, even when
// it also contains a problem. This method does not check CAA records and should
// not be used as a replacement for VA.PerformValidation.
//
// Note: When called on the primary VA, this method will also call itself over
// gRPC on each remote VA.
func (va *ValidationAuthorityImpl) DoDCV(ctx context.Context, req *vapb.DCVRequest) (*vapb.ValidationResult, error) {
	if core.IsAnyNilOrZero(req, req.Identifier, req.Challenge, req.AuthzID, req.RegID, req.ExpectedKeyAuthorization) {
		return nil, berrors.InternalServerError("Incomplete validation request")
	}

	identifier := identifier.NewDNS(req.Identifier.Value)
	chall, err := bgrpc.PBToChallenge(req.Challenge)
	if err != nil {
		return nil, errors.New("challenge failed to deserialize")
	}
	err = chall.CheckPending()
	if err != nil {
		return nil, berrors.MalformedError("challenge failed consistency check: %s", err)
	}

	auditLog := doDCVAuditLog{
		AuthzID:    req.AuthzID,
		Requester:  req.RegID,
		Identifier: req.Identifier.Value,
		Challenge:  chall,
	}

	var prob *probs.ProblemDetails
	var localLatency time.Duration
	summary := mpicSummary{[]string{}, []string{}, []string{}, ""}
	start := va.clk.Now()

	defer func() {
		probType := ""
		outcome := fail
		if prob != nil {
			// Failed to validate the challenge.
			probType = string(prob.Type)
			auditLog.Error = prob.Error()
			auditLog.Challenge.Error = prob
			auditLog.Challenge.Status = core.StatusInvalid
		} else {
			// Successfully validated the challenge.
			outcome = pass
			auditLog.Challenge.Status = core.StatusValid
		}
		// Observe local validation latency (primary|remote).
		va.observeLatency(opChall, va.perspective, string(chall.Type), probType, outcome, localLatency)
		if va.isPrimaryVA() {
			// Observe total validation latency (primary+remote).
			va.observeLatency(opChall, allPerspectives, string(chall.Type), probType, outcome, va.clk.Since(start))
			auditLog.MPICSummary = summary
		}
		// Log the total validation latency.
		auditLog.Latency = va.clk.Since(start).Round(time.Millisecond).Seconds()
		va.log.AuditObject("Challenge validation result", auditLog)
	}()

	// Validate the challenge locally.
	records, localErr := va.validateChallenge(ctx, identifier, chall.Type, chall.Token, req.ExpectedKeyAuthorization)

	// Stop the clock for local validation latency.
	localLatency = va.clk.Since(start)

	// The following checks are performed in a specific order to ensure that the
	// most relevant problem is returned to the subscriber.

	auditLog.Challenge.ValidationRecord = records
	if localErr == nil && !auditLog.Challenge.RecordsSane() {
		localErr = errors.New("records from local validation failed sanity check")
	}

	if localErr != nil {
		// Failed to validate the challenge locally.
		auditLog.InternalError = localErr.Error()
		prob = detailedError(localErr)
		return bgrpc.ValidationResultToPB(records, filterProblemDetails(prob), va.perspective, va.rir)
	}

	if va.isPrimaryVA() {
		// Attempt to validate the challenge remotely.
		summary, prob = va.remoteDoDCV(ctx, req)
	}

	return bgrpc.ValidationResultToPB(records, filterProblemDetails(prob), va.perspective, va.rir)
}
