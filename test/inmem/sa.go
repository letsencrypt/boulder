package inmem

import (
	"context"

	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"

	"google.golang.org/grpc"
)

// SA meets the `sapb.RegistrationAuthorityClient` interface and acts as a
// wrapper for an inner `sa.SQLStorageAuthority`. Only methods used by unit
// tests need to be implemented.
type SA struct {
	sapb.StorageAuthorityClient
	Impl sa.SQLStorageAuthority
}

// GetCertificateStatus is a wrapper for `sa.SQLStorageAuthority.GetCertificateStatus`.
func (sa SA) GetCertificateStatus(ctx context.Context, in *sapb.Serial, _ ...grpc.CallOption) (*corepb.CertificateStatus, error) {
	return sa.Impl.GetCertificateStatus(ctx, in)
}
