package sa

import (
	"golang.org/x/net/context"

	corepb "github.com/letsencrypt/boulder/core/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// AddSerail writes a
func (ssa *SQLStorageAuthority) AddSerial(ctx context.Context, req *sapb.AddSerialRequest) (*corepb.Empty, error) {
	return nil, nil
}

func (ssa *SQLStorageAuthority) AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*corepb.Empty, error) {
	return nil, nil
}
