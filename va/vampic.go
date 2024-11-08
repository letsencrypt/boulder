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
	"github.com/prometheus/client_golang/prometheus"
)

const (
	PrimaryPerspective = "primary"

	challenge = "challenge"
	caa       = "caa"
	all       = "all"
	pass      = "pass"
	fail      = "fail"
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

func (va *ValidationAuthorityImpl) onPrimaryVA() bool {
	return va.perspective == PrimaryPerspective
}

// mpicSummary contains multiple fields that are exported for logging purposes.
type mpicSummary struct {
	// Passed is the list of distinct perspectives that Passed validation.
	Passed []string `json:"passedPerspectives"`

	// Failed is the list of distinct perspectives that Failed validation.
	Failed []string `json:"failedPerspectives"`

	// RIRs is the list of distinct RIRs that passing perspectives belonged to.
	RIRs []string `json:"passedRIRs"`

	// QuorumResult is the Multi-Perspective Issuance Corroboration quorum
	// result, per BRs Section 5.4.1, Requirement 2.7 (i.e., "3/4" which should
	// be interpreted as "Three (3) out of four (4) attempted Network
	// Perspectives corroborated the determinations made by the Primary Network
	// Perspective).
	QuorumResult string `json:"quorumResult"`
}

// newSummary returns a new mpicSummary with empty slices to avoid "null" in
// JSON output.
func newSummary() mpicSummary {
	return mpicSummary{
		Passed: []string{},
		Failed: []string{},
		RIRs:   []string{},
	}
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
	MPICSummary   mpicSummary    `json:",omitempty"`
}

// determineMaxAllowedFailures returns the maximum number of allowed failures
// for a given number of remote perspectives, according to the "Quorum
// Requirements" table in BRs Section 3.2.2.9, as follows:
//
//	| # of Distinct Remote Network Perspectives Used | # of Allowed non-Corroborations |
//	| --- | --- |
//	| 2-5 |  1  |
//	| 6+  |  2  |
func determineMaxAllowedFailures(perspectives int) int {
	if perspectives < 2 {
		return 0
	}
	if perspectives < 6 {
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
	if remoteVACount < 3 {
		return mpicSummary{}, probs.ServerInternal("Insufficient remote perspectives: need at least 3")
	}

	type remoteResult struct {
		// rvaAddr is only used for logging.
		rvaAddr  string
		response *vapb.ValidationResult
		err      error
	}

	responses := make(chan *remoteResult, remoteVACount)
	for _, i := range rand.Perm(remoteVACount) {
		rva := va.remoteVAs[i]

		go func(rva RemoteVA) {
			res, err := rva.ValidateChallenge(ctx, req)
			responses <- &remoteResult{
				rvaAddr:  rva.Address,
				response: res,
				err:      err,
			}
		}(rva)
	}

	passed := []string{}
	failed := []string{}
	passedRIRs := make(map[string]struct{})

	maxRemoteFailures := determineMaxAllowedFailures(remoteVACount)
	required := remoteVACount - maxRemoteFailures

	var firstProb *probs.ProblemDetails
	for i := 0; i < remoteVACount; i++ {
		res := <-responses

		var currProb *probs.ProblemDetails
		if res.err != nil {
			// The remote VA failed to respond. With no response, we cannot know
			// the perspective name, so we use the remote VA address.
			failed = append(failed, res.rvaAddr)
			if errors.Is(res.err, context.Canceled) {
				currProb = probs.ServerInternal("Secondary domain validation RPC canceled")
			} else {
				va.log.Errf("Remote VA %q.ValidateChallenge failed: %s", res.rvaAddr, res.err)
				currProb = probs.ServerInternal("Secondary domain validation RPC failed")
			}

		} else if res.response.Problems != nil {
			// The remote VA returned a problem.
			failed = append(failed, res.response.Perspective)

			var err error
			currProb, err = bgrpc.PBToProblemDetails(res.response.Problems)
			if err != nil {
				va.log.Errf("Remote VA %q.ValidateChallenge returned malformed problem: %s", res.rvaAddr, err)
				currProb = probs.ServerInternal("Secondary domain validation RPC returned malformed result")
			}

		} else {
			// The remote VA returned a successful response.
			passed = append(passed, res.response.Perspective)
			passedRIRs[res.response.Rir] = struct{}{}
		}

		if firstProb == nil && currProb != nil {
			// A problem was encountered for the first time.
			firstProb = currProb
		}
	}

	// Prepare the summary, this MUST be returned even if the validation failed.
	summary := prepareSummary(passed, failed, passedRIRs, remoteVACount)

	if len(passed) >= required {
		// We may have enough successful responses.
		if len(passedRIRs) < 2 {
			if firstProb != nil {
				firstProb.Detail = fmt.Sprintf("During secondary domain validation: %s", firstProb.Detail)
				return summary, firstProb
			}
			return summary, probs.Unauthorized("Secondary domain validation failed to receive enough responses from disctinct RIRs")
		}
		// We have enough successful responses from distinct perspectives.
		return summary, nil
	}

	if len(failed) > maxRemoteFailures {
		// We have too many failed responses.
		if firstProb != nil {
			firstProb.Detail = fmt.Sprintf("During secondary domain validation: %s", firstProb.Detail)
			return summary, firstProb
		}
	}
	// This return is unreachable because for any number of remote VAs (n),
	// either at least (n - maxFailures) perspectives pass, or more than
	// maxFailures fail. Thus, one of the above conditions is always satisfied.
	return summary, probs.ServerInternal("Secondary domain validation failed to receive all responses")
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

	var prob *probs.ProblemDetails
	var localLatency time.Duration
	var latency time.Duration
	var summary = newSummary()
	start := va.clk.Now()

	auditLog := validateChallengeAuditLog{
		AuthzID:    req.AuthzID,
		Requester:  req.RegID,
		Identifier: req.Identifier.Value,
		Challenge:  chall,
	}

	defer func() {
		probType := ""
		outcome := fail
		if prob != nil {
			// Validation failed.
			probType = string(prob.Type)
			auditLog.Error = prob.Error()
			auditLog.Challenge.Error = prob
			auditLog.Challenge.Status = core.StatusInvalid

		} else {
			// Validation passed.
			outcome = pass
			auditLog.Challenge.Status = core.StatusValid
		}
		// Always observe local latency (primary|remote).
		va.observeLatency(challenge, va.perspective, string(chall.Type), probType, outcome, localLatency)
		if va.onPrimaryVA() {
			// Log the MPIC summary.
			auditLog.MPICSummary = summary

			if latency > 0 {
				// Observe total latency (primary+remote).
				va.observeLatency(challenge, all, string(chall.Type), probType, outcome, va.clk.Since(start))
			}
		}

		// No matter what, log the audit log.
		auditLog.Latency = va.clk.Since(start).Round(time.Millisecond).Seconds()
		va.log.AuditObject("Challenge validation result", auditLog)
	}()

	// Perform local validation.
	records, localErr := va.validateChallenge(ctx, identifier, chall.Type, chall.Token, req.KeyAuthorization)

	// Stop the clock for local validation latency (this may be remote).
	localLatency = va.clk.Since(start)

	// Log the validation records, even if validation failed.
	auditLog.Challenge.ValidationRecord = records

	// The following checks are in a specific order to ensure that the most
	// pertinent problems are returned first.

	if localErr == nil && !auditLog.Challenge.RecordsSane() {
		// Validation was successful, but the records failed sanity check.
		localErr = errors.New("records from local validation failed sanity check")
	}

	if localErr != nil {
		// Validation failed locally.
		auditLog.InternalError = localErr.Error()
		prob = detailedError(localErr)
		return bgrpc.ValidationResultToPB(records, filterProblemDetails(prob), va.perspective, va.rir)
	}

	if va.onPrimaryVA() {
		// Perform remote validation.
		summary, prob = va.remoteValidateChallenge(ctx, req)

		// Stop the clock for total validation latency.
		latency = va.clk.Since(start)
	}
	return bgrpc.ValidationResultToPB(records, filterProblemDetails(prob), va.perspective, va.rir)
}
