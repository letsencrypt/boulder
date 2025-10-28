package inmemnonce

import (
	"context"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/nonce"
	noncepb "github.com/letsencrypt/boulder/nonce/proto"
)

// NonceService implements noncepb.NonceServiceClient for tests.
type NonceService struct {
	noncepb.NonceServiceClient
	Impl *nonce.NonceService
}

var _ noncepb.NonceServiceClient = &NonceService{}

func (ns *NonceService) Nonce(ctx context.Context, req *emptypb.Empty, opts ...grpc.CallOption) (*noncepb.NonceMessage, error) {
	return ns.Impl.Nonce(ctx, req)
}

func (ns *NonceService) Redeem(ctx context.Context, req *noncepb.NonceMessage, opts ...grpc.CallOption) (*noncepb.ValidMessage, error) {
	return ns.Impl.Redeem(ctx, req)
}

// AsSource returns a wrapper type that implements jose.NonceSource using this
// inmemory service. This is useful so that tests can get nonces for signing
// their JWS that will be accepted by the test WFE configured using this service.
func (ns *NonceService) AsSource() jose.NonceSource {
	return nonceServiceAdapter{ns}
}

// nonceServiceAdapter changes the gRPC nonce service interface to the one
// required by jose. Used only for tests.
type nonceServiceAdapter struct {
	noncepb.NonceServiceClient
}

// Nonce returns a nonce, implementing the jose.NonceSource interface
func (nsa nonceServiceAdapter) Nonce() (string, error) {
	resp, err := nsa.NonceServiceClient.Nonce(context.Background(), &emptypb.Empty{})
	if err != nil {
		return "", err
	}
	return resp.Nonce, nil
}

var _ jose.NonceSource = nonceServiceAdapter{}
