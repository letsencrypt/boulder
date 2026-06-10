package mtca

import (
	"context"
	"fmt"
	"sync"

	"github.com/letsencrypt/boulder/issuance"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
)

var _ mtcapb.MTCAServer = &mtca{}

func New(issuer *issuance.Issuer) *mtca {
	return &mtca{
		issuer: issuer,
		mtcaID: issuer.Cert.Subject.String(),
		// TODO: collect this from config
		logNumber:        0,
		latestEntryIndex: 0,
	}
}

type mtca struct {
	mtcapb.UnimplementedMTCAServer

	issuer    *issuance.Issuer
	mtcaID    string
	logNumber uint16

	// This is just a dummy for testing; in reality this will come from the DB.
	latestEntryIndex int64

	sequencing sync.Mutex
}

func (m *mtca) mtcLogID() string {
	return fmt.Sprintf("%s.0.%d", m.mtcaID, m.logNumber)
}

func (m *mtca) Issue(ctx context.Context, req *mtcapb.IssueRequest) (*mtcapb.IssueResponse, error) {
	m.sequencing.Lock()
	defer m.sequencing.Unlock()
	m.latestEntryIndex++

	return &mtcapb.IssueResponse{
		MtcLogID:      m.mtcLogID(),
		MtcEntryIndex: m.latestEntryIndex,
	}, nil
}
