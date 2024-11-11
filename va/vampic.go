package va

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	vapb "github.com/letsencrypt/boulder/va/proto"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// requiredPerspectives is the minimum number of perspectives required to
	// perform an MPIC-compliant validation.
	//
	// Timeline:
	//  - Mar 15, 2026: MUST implement using at least 3 perspectives
	//  - Jun 15, 2026: MUST implement using at least 4 perspectives
	//  - Dec 15, 2026: MUST implement using at least 5 perspectives
	requiredPerspectives = 3

	PrimaryPerspective = "primary"
	all                = "all"

	opChallenge = "challenge"
	opCAA       = "caa"

	pass = "pass"
	fail = "fail"
)

// observeLatency records entries in the validationLatency histogram of the
// latency to perform validations from the primary and remote VA perspectives.
// The labels are:
//   - operation: VA.ValidateChallenge or VA.CheckCAA as [challenge|caa]
//   - perspective: [ValidationAuthorityImpl.perspective|all]
//   - challenge_type: core.Challenge.Type
//   - problem_type: probs.ProblemType
//   - result: the result of the validation as [pass|fail]
func (va *ValidationAuthorityImpl) observeLatency(op, perspective, challType, probType, result string, latency time.Duration) {
	labels := prometheus.Labels{
		"operation":      op,
		"perspective":    perspective,
		"challenge_type": challType,
		"problem_type":   probType,
		"result":         result,
	}
	va.metrics.validationLatency.With(labels).Observe(latency.Seconds())
}

// isPrimaryVA returns true if the VA is the primary validation perspective.
func (va *ValidationAuthorityImpl) isPrimaryVA() bool {
	return va.perspective == PrimaryPerspective
}

// mpicSummary contains multiple fields that are exported for logging purposes.
// To initialize an empty mpicSummary, use newSummary(). The prepare a final
// summary, use prepareSummary().
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

// newSummary returns a new mpicSummary with empty slices to avoid "null" in the
// JSON output. Fields are exported for logging purposes.
func newSummary() mpicSummary {
	return mpicSummary{[]string{}, []string{}, []string{}, ""}
}

// prepareSummary prepares a summary of the validation results for logging
// purposes. Sets empty slices to []string{} to avoid "null" in JSON output.
func prepareSummary(passed, failed []string, passedRIRs map[string]struct{}, remoteVACount int) mpicSummary {
	summary := mpicSummary{
		Passed: append([]string{}, passed...),
		Failed: append([]string{}, failed...),
		RIRs:   []string{},
	}
	for rir := range maps.Keys(passedRIRs) {
		summary.RIRs = append(summary.RIRs, rir)
	}
	slices.Sort(summary.RIRs)
	summary.QuorumResult = fmt.Sprintf("%d/%d", len(passed), remoteVACount)

	return summary
}

// validateChallengeAuditLog contains multiple fields that are exported for
// logging purposes.
type validateChallengeAuditLog struct {
	AuthzID       string         `json:",omitempty"`
	Requester     int64          `json:",omitempty"`
	Identifier    string         `json:",omitempty"`
	Challenge     core.Challenge `json:",omitempty"`
	Error         string         `json:",omitempty"`
	InternalError string         `json:",omitempty"`
	Latency       float64        `json:",omitempty"`
	MPICSummary   mpicSummary
}

// determineMaxAllowedFailures returns the maximum number of allowed failures
// for a given number of remote perspectives, according to the "Quorum
// Requirements" table in BRs Section 3.2.2.9, as follows:
//
//	| # of Distinct Remote Network Perspectives Used | # of Allowed non-Corroborations |
//	| --- | --- |
//	| 2-5 |  1  |
//	| 6+  |  2  |
func determineMaxAllowedFailures(perspectiveCount int) int {
	if perspectiveCount < 2 {
		return 0
	}
	if perspectiveCount < 6 {
		return 1
	}
	return 2
}

// remoteValidateChallenge performs an MPIC-compliant remote validation of the
// challenge using the configured remote VAs. It returns a summary of the
// validation results and a problem if the validation failed. The summary is
// mandatory and must be returned even if the validation failed.
func (va *ValidationAuthorityImpl) remoteValidateChallenge(ctx context.Context, req *vapb.ValidationRequest) (mpicSummary, *probs.ProblemDetails) {
	remoteVACount := len(va.remoteVAs)
	if remoteVACount < requiredPerspectives {
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
			res, err := rva.ValidateChallenge(ctx, req)
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

	maxRemoteFailures := determineMaxAllowedFailures(remoteVACount)
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

// ValidateChallenge performs a local validation of a challenge using the
// configured local VA. If the local validation passes, it will also perform an
// MPIC-compliant validation of the challenge using the configured remote VAs.
//
// Note: This method calls itself recursively to perform remote validation.
func (va *ValidationAuthorityImpl) ValidateChallenge(ctx context.Context, req *vapb.ValidationRequest) (*vapb.ValidationResult, error) {
	if core.IsAnyNilOrZero(req, req.Identifier, req.Challenge, req.AuthzID, req.RegID, req.KeyAuthorization) {
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

	auditLog := validateChallengeAuditLog{
		AuthzID:    req.AuthzID,
		Requester:  req.RegID,
		Identifier: req.Identifier.Value,
		Challenge:  chall,
	}

	var prob *probs.ProblemDetails
	var localLatency time.Duration
	var summary = newSummary()
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
		va.observeLatency(opChallenge, va.perspective, string(chall.Type), probType, outcome, localLatency)
		if va.isPrimaryVA() {
			// Observe total validation latency (primary+remote).
			va.observeLatency(opChallenge, all, string(chall.Type), probType, outcome, va.clk.Since(start))
			auditLog.MPICSummary = summary
		}
		// Log the total validation latency.
		auditLog.Latency = va.clk.Since(start).Round(time.Millisecond).Seconds()
		va.log.AuditObject("Challenge validation result", auditLog)
	}()

	// Validate the challenge locally.
	records, localErr := va.validateChallenge(ctx, identifier, chall.Type, chall.Token, req.KeyAuthorization)

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
		summary, prob = va.remoteValidateChallenge(ctx, req)
	}

	return bgrpc.ValidationResultToPB(records, filterProblemDetails(prob), va.perspective, va.rir)
}

// remoteValidateChallenge performs an MPIC-compliant remote validation of the
// challenge using the configured remote VAs. It returns a summary of the
// validation results and a problem if the validation failed. The summary is
// mandatory and must be returned even if the validation failed.
func (va *ValidationAuthorityImpl) remoteCheckCAA(ctx context.Context, req *vapb.CheckCAARequest) (mpicSummary, *probs.ProblemDetails) {
	remoteVACount := len(va.remoteVAs)
	if remoteVACount < requiredPerspectives {
		return mpicSummary{}, probs.ServerInternal("Insufficient remote perspectives: need at least 3")
	}

	type response struct {
		addr   string
		result *vapb.CheckCAAResult
		err    error
	}

	responses := make(chan *response, remoteVACount)
	for _, i := range rand.Perm(remoteVACount) {
		go func(rva RemoteVA) {
			res, err := rva.CheckCAA(ctx, req)
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
				currProb = probs.ServerInternal("Secondary CAA check RPC canceled")
			} else {
				va.log.Errf("Remote VA %q.CheckCAA failed: %s", resp.addr, resp.err)
				currProb = probs.ServerInternal("Secondary CAA check RPC failed")
			}

		} else if resp.result.Problem != nil {
			// The remote VA returned a problem.
			failed = append(failed, resp.result.Perspective)

			var err error
			currProb, err = bgrpc.PBToProblemDetails(resp.result.Problem)
			if err != nil {
				va.log.Errf("Remote VA %q.CheckCAA returned a malformed problem: %s", resp.addr, err)
				currProb = probs.ServerInternal("Secondary CAA check RPC returned malformed result")
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

	// Prepare the summary, this MUST be returned even if the check failed.
	summary := prepareSummary(passed, failed, passedRIRs, remoteVACount)

	maxRemoteFailures := determineMaxAllowedFailures(remoteVACount)
	if len(failed) > maxRemoteFailures {
		// Too many failures to reach quorum.
		if firstProb != nil {
			firstProb.Detail = fmt.Sprintf("During secondary CAA check: %s", firstProb.Detail)
			return summary, firstProb
		}
		return summary, probs.ServerInternal("Secondary CAA check failed due to too many failures")
	}

	if len(passed) < (remoteVACount - maxRemoteFailures) {
		// Too few successful responses to reach quorum.
		if firstProb != nil {
			firstProb.Detail = fmt.Sprintf("During secondary CAA check: %s", firstProb.Detail)
			return summary, firstProb
		}
		return summary, probs.ServerInternal("Secondary CAA check failed due to insufficient successful responses")
	}

	if len(passedRIRs) < 2 {
		// Too few successful responses from distinct RIRs to reach quorum.
		if firstProb != nil {
			firstProb.Detail = fmt.Sprintf("During secondary CAA check: %s", firstProb.Detail)
			return summary, firstProb
		}
		return summary, probs.Unauthorized("Secondary CAA check failed to receive enough corroborations from distinct RIRs")
	}

	// Enough successful responses from distinct RIRs to reach quorum.
	return summary, nil
}

// checkCAAAuditLog contains multiple fields that are exported for logging
// purposes.
type checkCAAAuditLog struct {
	AuthzID       string             `json:",omitempty"`
	Requester     int64              `json:",omitempty"`
	Identifier    string             `json:",omitempty"`
	ChallengeType core.AcmeChallenge `json:",omitempty"`
	Error         string             `json:",omitempty"`
	InternalError string             `json:",omitempty"`
	Latency       float64            `json:",omitempty"`
	MPICSummary   mpicSummary
}

func prepareCAACheckResult(prob *probs.ProblemDetails, perspective, rir string) (*vapb.CheckCAAResult, error) {
	pbProb, err := bgrpc.ProblemDetailsToPB(prob)
	if err != nil {
		return &vapb.CheckCAAResult{}, errors.New("failed to serialize problem")
	}
	return &vapb.CheckCAAResult{Problem: pbProb, Perspective: perspective, Rir: rir}, nil
}

// CheckCAA performs a local CAA check using the configured local VA. If the
// local CAA check passes, it will also perform an MPIC-compliant CAA check
// using the configured remote VAs.
//
// Note: This method calls itself recursively to perform remote caa checks.
func (va *ValidationAuthorityImpl) CheckCAA(ctx context.Context, req *vapb.CheckCAARequest) (*vapb.CheckCAAResult, error) {
	if core.IsAnyNilOrZero(req, req.Identifier, req.ChallengeType, req.RegID, req.AuthzID) {
		return nil, berrors.InternalServerError("Incomplete CAA check request")
	}

	acmeIdent := identifier.NewDNS(req.Identifier.Value)
	challType := core.AcmeChallenge(req.ChallengeType)
	if !challType.IsValid() {
		return nil, berrors.InternalServerError("Invalid challenge type")
	}

	auditLog := checkCAAAuditLog{
		AuthzID:       req.AuthzID,
		Requester:     req.RegID,
		Identifier:    req.Identifier.Value,
		ChallengeType: challType,
	}

	var prob *probs.ProblemDetails
	var localLatency time.Duration
	var summary = newSummary()
	start := va.clk.Now()

	defer func() {
		probType := ""
		outcome := fail
		if prob != nil {
			// CAA check failed.
			probType = string(prob.Type)
			auditLog.Error = prob.Error()
		} else {
			// CAA check passed.
			outcome = pass
		}
		// Observe local check latency (primary|remote).
		va.observeLatency(opCAA, va.perspective, string(challType), probType, outcome, localLatency)
		if va.isPrimaryVA() {
			// Observe total check latency (primary+remote).
			va.observeLatency(opCAA, all, string(challType), probType, outcome, va.clk.Since(start))
			auditLog.MPICSummary = summary
		}
		// Log the total check latency.
		auditLog.Latency = va.clk.Since(start).Round(time.Millisecond).Seconds()

		va.log.AuditObject("CAA check result", auditLog)
	}()

	var localErr error

	if req.IsRecheck && va.isPrimaryVA() {
		// Perform local and remote checks in parallel.
		var localWG sync.WaitGroup
		var remoteWG sync.WaitGroup
		localWG.Add(1)
		remoteWG.Add(1)

		var remoteProb *probs.ProblemDetails
		var remoteSummary mpicSummary

		go func() {
			defer localWG.Done()
			localErr = va.checkCAA(ctx, acmeIdent, &caaParams{req.RegID, challType})
		}()

		go func() {
			defer remoteWG.Done()
			remoteSummary, remoteProb = va.remoteCheckCAA(ctx, req)
		}()

		// Wait for local check to complete.
		localWG.Wait()

		// Stop the clock for local check latency.
		localLatency = va.clk.Since(start)

		// Wait for remote check to complete.
		remoteWG.Wait()

		if localErr != nil {
			// Local check failed.
			auditLog.InternalError = localErr.Error()
			prob = detailedError(localErr)
			return prepareCAACheckResult(prob, va.perspective, va.rir)
		}
		summary = remoteSummary
		if remoteProb != nil {
			// Remote check failed.
			prob = remoteProb
		}

	} else {
		// Perform local check.
		localErr = va.checkCAA(ctx, acmeIdent, &caaParams{req.RegID, challType})

		// Stop the clock for local check latency.
		localLatency = va.clk.Since(start)

		if localErr != nil {
			// Local check failed.
			auditLog.InternalError = localErr.Error()
			prob = detailedError(localErr)
			return prepareCAACheckResult(prob, va.perspective, va.rir)
		}

		if va.isPrimaryVA() {
			// Attempt to check CAA remotely.
			summary, prob = va.remoteCheckCAA(ctx, req)
		}
	}

	return prepareCAACheckResult(prob, va.perspective, va.rir)
}
