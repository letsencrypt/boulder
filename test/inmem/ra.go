package inmem

import (
	"context"

	"github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/ra"
	rapb "github.com/letsencrypt/boulder/ra/proto"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// RA meets the `rapb.RegistrationAuthorityClient` interface and acts as a
// wrapper for an inner `*ra.RegistrationAuthorityImpl`. Only methods used by
// unit tests need to be implemented.
type RA struct {
	rapb.RegistrationAuthorityClient
	Impl *ra.RegistrationAuthorityImpl
}

// AdministrativelyRevokeCertificate is a wrapper for `*ra.RegistrationAuthorityImpl.AdministrativelyRevokeCertificate`.
func (ra RA) AdministrativelyRevokeCertificate(ctx context.Context, in *rapb.AdministrativelyRevokeCertificateRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return ra.Impl.AdministrativelyRevokeCertificate(ctx, in)
}

// NewCertificate is a wrapper for `*ra.RegistrationAuthorityImpl.NewCertificate`.
func (ra RA) NewCertificate(ctx context.Context, in *rapb.NewCertificateRequest, _ ...grpc.CallOption) (*proto.Certificate, error) {
	return ra.Impl.NewCertificate(ctx, in)
}
