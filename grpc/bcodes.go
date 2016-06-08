package grpc

import (
	"google.golang.org/grpc/codes"

	"github.com/letsencrypt/boulder/probs"
)

// gRPC error codes used by Boulder. While the gRPC codes
// end at 16 we start at 100 to provide a little leeway
// in case they ever decide to add more
const (
	// DNSQueryTimeout is used when DNS queries timeout
	DNSQueryTimeout codes.Code = 100

	// DNSError is used when DNS queries fail for some reason
	DNSError codes.Code = 101
)

// CodeToProblem takes a gRPC error code and translates it to
// a Boulder ProblemType
func CodeToProblem(c codes.Code) probs.ProblemType {
	switch c {
	case DNSQueryTimeout:
		return probs.ConnectionProblem
	case DNSError:
		return probs.ConnectionProblem
	default:
		return probs.ServerInternalProblem
	}
}
