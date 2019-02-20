package grpc

import (
	"errors"
	"strconv"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	berrors "github.com/letsencrypt/boulder/errors"
)

var (
	ErrIncompleteRequest  = errors.New("Incomplete gRPC request message")
	ErrIncompleteResponse = errors.New("Incomplete gRPC response message")
)

// wrapError wraps the internal error types we use for transport across the gRPC
// layer and appends an appropriate errortype to the gRPC trailer via the provided
// context. errors.BoulderError error types are encoded using the grpc/metadata
// in the context.Context for the RPC which is considered to be the 'proper'
// method of encoding custom error types (grpc/grpc#4543 and grpc/grpc-go#478)
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
	return grpc.Errorf(codes.Unknown, err.Error())
}

// unwrapError unwraps errors returned from gRPC client calls which were wrapped
// with wrapError to their proper internal error type. If the provided metadata
// object has an "errortype" field, that will be used to set the type of the
// error.
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
	return err
}
