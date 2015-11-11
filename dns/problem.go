package dns

import (
	"fmt"
	"net"

	"github.com/letsencrypt/boulder/core"
)

const detailDNSTimeout = "DNS query timed out"
const detailTemporaryError = "Temporary network connectivity error"
const detailDNSNetFailure = "DNS networking error"
const detailServerFailure = "Server failure at resolver"

// ProblemDetailsFromDNSError checks the error returned from Lookup...
// methods and tests if the error was an underlying net.OpError or an error
// caused by resolver returning SERVFAIL or other invalid Rcodes and returns
// the relevant core.ProblemDetails.
func ProblemDetailsFromDNSError(err error) *core.ProblemDetails {
	problem := &core.ProblemDetails{Type: core.ConnectionProblem}
	if netErr, ok := err.(*net.OpError); ok {
		if netErr.Timeout() {
			problem.Detail = detailDNSTimeout
		} else if netErr.Temporary() {
			problem.Detail = detailTemporaryError
		} else {
			problem.Detail = detailDNSNetFailure
		}
	} else {
		problem.Detail = detailServerFailure
	}
	fmt.Println(problem)
	return problem
}
