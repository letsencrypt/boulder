package grpc

import (
	"encoding/json"
	"errors"
	"strconv"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/probs"
)

// gRPC error codes used by Boulder. While the gRPC codes
// end at 16 we start at 100 to provide a little leeway
// in case they ever decide to add more
// TODO(#2507): Depreciated, remove once boulder/errors code is deployed
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

// wrapError wraps the internal error types we use for transport across the gRPC
// layer. core.XXXError and probs.ProblemDetails error types are encoded using the gRPC
// error status code which has been deprecated (#2507). errors.BoulderError error types
// are encoded using the grpc/metadata in the context.Context for the RPC which is
// considered to be the 'proper' method of encoding custom error types (grpc/grpc#4543
// and grpc/grpc-go#478)
func wrapError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if berr, ok := err.(*berrors.BoulderError); ok {
		// If setting the metadata fails ignore the returned error and
		// return the BoulderError detail so we still see the actual
		// reason on the other side with the default InternalServer
		// error type
		_ = grpc.SetTrailer(ctx, metadata.Pairs("errortype", strconv.Itoa(int(berr.Type))))
		return grpc.Errorf(codes.Unknown, err.Error())
	}
	// TODO(2589): deprecated, remove once boulder/errors code has been deployed
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

// unwrapError unwraps errors returned from gRPC client calls which were wrapped
// with wrapError to their proper internal error type. If the error is a
// BoulderError the grpc/metadata taken from the call context.Context is used to
// determine the error type. If the error is a core.XXXError or a
// probs.ProblemDetails the type is determined using the gRPC error code which
// has been deprecated (#2507).
func unwrapError(err error, md metadata.MD) error {
	if err == nil {
		return nil
	}
	if errTypeStrs, ok := md["errortype"]; ok {
		unwrappedErr := grpc.ErrorDesc(err)
		if len(errTypeStrs) != 1 {
			return berrors.InternalServerError(
				"boulder/grpc.unwrapError: multiple errorType metadata, wrapped error %q",
				unwrappedErr,
			)
		}
		errType, decErr := strconv.Atoi(errTypeStrs[0])
		if decErr != nil {
			return berrors.InternalServerError(
				"boulder/grpc.unwrapError: failed to decode error type, decoding error %q, wrapped error %q",
				decErr,
				unwrappedErr,
			)
		}
		return berrors.New(berrors.ErrorType(errType), unwrappedErr)
	}
	// TODO(2589): deprecated, remove once boulder/errors code has been deployed
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
