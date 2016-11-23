package grpc

import (
	"fmt"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/letsencrypt/boulder/probs"
)

// gRPC error codes used by Boulder. While the gRPC codes
// end at 16 we start at 100 to provide a little leeway
// in case they ever decide to add more
const (
	DNSQueryTimeout codes.Code = iota + 100 // DNSQueryTimeout is used when DNS queries timeout
	DNSError                                // DNSError is used when DNS queries fail for some reason
	MalformedRequestError
	NotSupportedError
	UnauthorizedError
	NotFoundError
	LengthRequiredError
	SignatureValidationError
	RateLimitedError
	BadNonceError
)

// CodeToProblem takes a gRPC error code and translates it to
// a Boulder ProblemType
func CodeToProblem(c codes.Code) probs.ProblemType {
	switch c {
	case DNSQueryTimeout, DNSError:
		return probs.ConnectionProblem
	case MalformedRequestError, LengthRequiredError, SignatureValidationError:
		return probs.MalformedProblem
	case UnauthorizedError:
		return probs.UnauthorizedProblem
	case RateLimitedError:
		return probs.RateLimitedProblem
	case BadNonceError:
		return probs.BadNonceProblem
	default:
		return probs.ServerInternalProblem
	}
}

// ErrorToProb converts a error returned by a gRPC call to a
// probs.ProblemDetails
func ErrorToProb(err error) *probs.ProblemDetails {
	return &probs.ProblemDetails{
		Type:   CodeToProblem(grpc.Code(err)),
		Detail: grpc.ErrorDesc(err),
	}
}

func ProblemDetailsForError(err error, msg string) *probs.ProblemDetails {
	switch grpc.Code(err) {
	case MalformedRequestError:
		return probs.Malformed(fmt.Sprintf("%s :: %s", msg, err))
	case NotSupportedError:
		return &probs.ProblemDetails{
			Type:       probs.ServerInternalProblem,
			Detail:     fmt.Sprintf("%s :: %s", msg, err),
			HTTPStatus: http.StatusNotImplemented,
		}
	case UnauthorizedError:
		return probs.Unauthorized(fmt.Sprintf("%s :: %s", msg, err))
	case NotFoundError:
		return probs.NotFound(fmt.Sprintf("%s :: %s", msg, err))
	case LengthRequiredError:
		prob := probs.Malformed("missing Content-Length header")
		prob.HTTPStatus = http.StatusLengthRequired
		return prob
	case SignatureValidationError:
		return probs.Malformed(fmt.Sprintf("%s :: %s", msg, err))
	case RateLimitedError:
		return probs.RateLimited(fmt.Sprintf("%s :: %s", msg, err))
	case BadNonceError:
		return probs.BadNonce(fmt.Sprintf("%s :: %s", msg, err))
	default:
		// Internal server error messages may include sensitive data, so we do
		// not include it.
		return probs.ServerInternal(msg)
	}
}
