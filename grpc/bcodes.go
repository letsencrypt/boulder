package grpc

import (
	"encoding/json"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/probs"
)

// gRPC error codes used by Boulder. While the gRPC codes
// end at 16 we start at 100 to provide a little leeway
// in case they ever decide to add more
const (
	MalformedRequestError = iota + 100
	NotSupportedError
	UnauthorizedError
	NotFoundError
	LengthRequiredError
	SignatureValidationError
	RateLimitedError
	BadNonceError
	NoSuchRegistrationError
	InternalServerError
	ProblemDetails
)

var (
	errIncompleteRequest  = errors.New("Incomplete gRPC request message")
	errIncompleteResponse = errors.New("Incomplete gRPC response message")
)

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
	case core.InternalServerError:
		return InternalServerError
	case *probs.ProblemDetails:
		return ProblemDetails
	default:
		return codes.Unknown
	}
}

func wrapError(err error) error {
	code := errorToCode(err)
	var body string
	if code == ProblemDetails {
		pd := err.(*probs.ProblemDetails)
		bodyBytes, jsonErr := json.Marshal(pd)
		if jsonErr != nil {
			// Since gRPC will wrap this itself using grpc.Errorf(codes.Unknown, ...)
			// we just pass the original error back to the caller
			return err
		}
		body = string(bodyBytes)
	} else {
		body = err.Error()
	}
	return grpc.Errorf(code, body)
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
	case LengthRequiredError:
		return core.LengthRequiredError(errBody)
	case BadNonceError:
		return core.BadNonceError(errBody)
	case ProblemDetails:
		pd := probs.ProblemDetails{}
		if json.Unmarshal([]byte(errBody), &pd) != nil {
			return err
		}
		return &pd
	default:
		return err
	}
}
