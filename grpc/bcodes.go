package grpc

import (
	"google.golang.org/grpc/codes"

	"github.com/letsencrypt/boulder/probs"
)

//go:generate stringer -type=BCode bcodes.go

// BCode is an alias so we can use a stringer
type BCode codes.Code

// GRPCCode returns the gRPC version of the error code
func (b BCode) GRPCCode() codes.Code {
	return codes.Code(b)
}

// gRPC error codes used by Boulder. While the gRPC codes
// end at 16 we start at 100 to provide a little leeway
// in case they ever decide to add more
const (
	// DNSQueryTimeout is used when DNS queries timeout
	DNSQueryTimeout BCode = 100

	// DNSError is used when DNS queries fail for some reason
	DNSError BCode = 101
)

// CodeToProblem takes a gRPC error code and translates it to
// a Boulder ProblemType
func CodeToProblem(c codes.Code) probs.ProblemType {
	switch BCode(c) {
	case DNSQueryTimeout:
		return probs.ConnectionProblem
	case DNSError:
		return probs.ConnectionProblem
	default:
		return probs.ServerInternalProblem
	}
}
