package mtca

import (
	"context"
	"sync"

	"github.com/letsencrypt/boulder/issuance"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
)

var _ mtcapb.MTCAServer = &mtca{}

func New(issuer *issuance.Issuer) *mtca {
	return &mtca{
		issuer: issuer,
		logID:  issuer.Cert.Subject.String(),
	}
}

type mtca struct {
	mtcapb.UnimplementedMTCAServer

	issuer     *issuance.Issuer
	logID      string
	entryIndex int64

	sequencing sync.Mutex
}

func (m *mtca) Issue(ctx context.Context, req *mtcapb.IssueRequest) (*mtcapb.IssueResponse, error) {
	m.sequencing.Lock()
	defer m.sequencing.Unlock()
	m.entryIndex++

	return &mtcapb.IssueResponse{
		MtcLogID:      m.logID,
		MtcEntryIndex: m.entryIndex,
	}, nil
}
