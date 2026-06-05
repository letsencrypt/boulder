package mtca

import (
	"context"
	"fmt"

	"github.com/letsencrypt/boulder/issuance"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
)

var _ mtcapb.MTCAServer = &mtca{}

func New(issuer *issuance.Issuer) *mtca {
	return &mtca{
		issuer: issuer,
	}
}

type mtca struct {
	mtcapb.UnimplementedMTCAServer
	issuer *issuance.Issuer
}

func (m *mtca) Issue(ctx context.Context, req *mtcapb.IssueRequest) (*mtcapb.IssueResponse, error) {
	return nil, fmt.Errorf("not implemented")
}
