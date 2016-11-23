package grpc

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/letsencrypt/boulder/core"
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
	NoSuchRegistrationError
	InternalServerError
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

func errorToCode(err error) codes.Code {
	switch err.(type) {
	case core.MalformedRequestError:
		return MalformedRequestError
	case core.NotSupportedError:
		return NotSupportedError
	case core.UnauthorizedError:
		return UnauthorizedError
	case core.NotFoundError:
		return NotFoundError
	case core.LengthRequiredError:
		return LengthRequiredError
	case core.SignatureValidationError:
		return SignatureValidationError
	case core.RateLimitedError:
		return RateLimitedError
	case core.BadNonceError:
		return BadNonceError
	case core.NoSuchRegistrationError:
		return NoSuchRegistrationError
	default:
		return codes.Unknown
	}
}

func wrapError(err error) error {
	return grpc.Errorf(errorToCode(err), err.Error())
}

func unwrapError(err error) error {
	code := grpc.Code(err)
	errBody := grpc.ErrorDesc(err)
	switch code {
	case InternalServerError:
		return core.InternalServerError(errBody)
	case NotSupportedError:
		return core.NotSupportedError(errBody)
	case MalformedRequestError:
		return core.MalformedRequestError(errBody)
	case UnauthorizedError:
		return core.UnauthorizedError(errBody)
	case NotFoundError:
		return core.NotFoundError(errBody)
	case SignatureValidationError:
		return core.SignatureValidationError(errBody)
	case NoSuchRegistrationError:
		return core.NoSuchRegistrationError(errBody)
	case RateLimitedError:
		return core.RateLimitedError(errBody)
	default:
		return err
	}
}
