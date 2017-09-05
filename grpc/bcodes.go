package grpc

import (
	"encoding/json"
	"errors"
	"strconv"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/probs"
)

// gRPC error codes used by Boulder. While the gRPC codes
// end at 16 we start at 100 to provide a little leeway
// in case they ever decide to add more
// TODO(#2507): Deprecated, remove once boulder/errors code is deployed
const (
	MalformedRequestError = iota + 100
	_
	UnauthorizedError
	NotFoundError
	_
	RateLimitedError
	_
	_
	InternalServerError
	ProblemDetails
)

var (
	errIncompleteRequest  = errors.New("Incomplete gRPC request message")
	errIncompleteResponse = errors.New("Incomplete gRPC response message")
)

func errorToCode(err error) codes.Code {
	switch err.(type) {
	case *probs.ProblemDetails:
		return ProblemDetails
	default:
		return codes.Unknown
	}
}

// wrapError wraps the internal error types we use for transport across the gRPC
// layer and appends an appropriate errortype to the gRPC trailer via the provided
// context. core.XXXError and probs.ProblemDetails error types are encoded using the gRPC
// error status code which has been deprecated (#2507). errors.BoulderError error types
// are encoded using the grpc/metadata in the context.Context for the RPC which is
// considered to be the 'proper' method of encoding custom error types (grpc/grpc#4543
// and grpc/grpc-go#478)
func wrapError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if berr, ok := err.(*berrors.BoulderError); ok {
		// Ignoring the error return here is safe because if setting the metadata
		// fails, we'll still return an error, but it will be interpreted on the
		// other side as an InternalServerError instead of a more specific one.
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
// with wrapError to their proper internal error type. If the provided metadata
// object has an "errortype" field, that will be used to set the type of the
// error. If the error is a core.XXXError or a probs.ProblemDetails the type
// is determined using the gRPC error code which has been deprecated (#2507).
func unwrapError(err error, md metadata.MD) error {
	if err == nil {
		return nil
	}
	if errTypeStrs, ok := md["errortype"]; ok {
		unwrappedErr := grpc.ErrorDesc(err)
		if len(errTypeStrs) != 1 {
			return berrors.InternalServerError(
				"multiple errorType metadata, wrapped error %q",
				unwrappedErr,
			)
		}
		errType, decErr := strconv.Atoi(errTypeStrs[0])
		if decErr != nil {
			return berrors.InternalServerError(
				"failed to decode error type, decoding error %q, wrapped error %q",
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
