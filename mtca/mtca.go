//go:build go1.27

package mtca

import (
	"context"
	"encoding/asn1"
	"fmt"
	"sync"

	"github.com/letsencrypt/boulder/issuance"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
)

var _ mtcapb.MTCAServer = &mtca{}

func New(issuer *issuance.Issuer) *mtca {
	var mtcaID string
	testingTrustAnchorIDOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	for _, attribute := range issuer.Cert.Subject.Names {
		if attribute.Type.Equal(testingTrustAnchorIDOID) {
			mtcaID, _ = attribute.Value.(string)
			break
		}
	}
	return &mtca{
		issuer: issuer,
		mtcaID: mtcaID,
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

// mtcLogID returns the string-formatted relative OID for this log.
// The .0. arc relative to the MTCA ID contains log numbers.
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#ca-ids
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
