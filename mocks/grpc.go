package mocks

import (
	"io"

	"google.golang.org/grpc"
)

// ServerStreamClient is a mock which satisfies the grpc.ClientStream interface,
// allowing it to be returned by methods where the server returns a stream of
// results. This simple mock will always return zero results.
type ServerStreamClient[T any] struct {
	grpc.ClientStream
}

// Recv immediately returns the EOF error, indicating that the stream is done.
func (c *ServerStreamClient[T]) Recv() (*T, error) {
	return nil, io.EOF
}
