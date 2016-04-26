package grpc

import (
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
	"golang.org/x/net/context"
)

// PublisherClient is a wrapper needed to satisfy the interfaces
// in core/interfaces.go
type PublisherClientWrapper struct {
	Inner pubPB.PublisherClient
}

// SubmitToCT makes a call to the gRPC version of the publisher
func (pc *PublisherClientWrapper) SubmitToCT(ctx context.Context, der []byte) error {
	_, err := pc.Inner.SubmitToCT(ctx, &pubPB.Request{Der: der})
	return err
}
