package grpc

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/google.golang.org/grpc"
)

// CodedError is a alias required to appease go vet
var CodedError = grpc.Errorf
