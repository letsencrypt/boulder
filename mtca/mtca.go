//go:build go1.27

package mtca

import (
	"context"
	"encoding/asn1"
	"fmt"
	"sync"
	"time"

	corepb "github.com/letsencrypt/boulder/core/proto"
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
		pool:             &pool{maxSize: 100},
	}
}

type mtca struct {
	mtcapb.UnimplementedMTCAServer

	issuer    *issuance.Issuer
	mtcaID    string
	logNumber uint16

	// This is just a dummy for testing; in reality this will come from the DB.
	latestEntryIndex int64

	maxPoolSize int
	pool        *pool

	sequencingMu sync.Mutex
	drainWG      sync.WaitGroup
}

type entry struct {
	pubkey      []byte
	identifiers []*corepb.Identifier
	ch          chan<- int64
}

type pool struct {
	sync.Mutex
	entries []entry
	maxSize int
}

func (p *pool) take() []entry {
	p.Lock()
	defer p.Unlock()
	ret := p.entries
	p.entries = nil
	return ret
}

func (p *pool) close() {
	p.maxSize = 0
}

func (p *pool) append(e entry) error {
	p.Lock()
	defer p.Unlock()
	if p.maxSize == 0 {
		return fmt.Errorf("pool is closed")
	}
	if len(p.entries) >= p.maxSize {
		return fmt.Errorf("pool is full")
	}
	p.entries = append(p.entries, e)
	return nil
}

// mtcLogID returns the string-formatted relative OID for this log.
// The .0. arc relative to the MTCA ID contains log numbers.
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#ca-ids
func (m *mtca) mtcLogID() string {
	return fmt.Sprintf("%s.0.%d", m.mtcaID, m.logNumber)
}

func (m *mtca) Issue(ctx context.Context, req *mtcapb.IssueRequest) (*mtcapb.IssueResponse, error) {
	ch := make(chan int64, 1)
	err := m.pool.append(entry{
		pubkey:      req.Pubkey,
		identifiers: req.Identifiers,
		ch:          ch,
	})
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case entryIndex := <-ch:
		return &mtcapb.IssueResponse{
			MtcLogID:      m.mtcLogID(),
			MtcEntryIndex: entryIndex,
		}, nil
	}

}

// Drain blocks until any in-progress sequencing is done.
//
// It should be called after the gRPC server has stopped accepting new requests.
func (m *mtca) Drain() {
	m.pool.close()
	m.drainWG.Wait()
}

func (m *mtca) Loop(ctx context.Context) {
	ticker := time.NewTicker(50 * time.Millisecond)
	for {
		<-ticker.C
		m.sequence(ctx)
	}
}

func (m *mtca) sequence(_ context.Context) {
	m.sequencingMu.Lock()
	defer m.sequencingMu.Unlock()
	m.drainWG.Go(func() {
		entries := m.pool.take()
		if len(entries) == 0 {
			// sequence an empty entry
			entries = append(entries, entry{})
		}
		for _, e := range entries {
			if e.ch != nil {
				e.ch <- m.latestEntryIndex
			}
			fmt.Printf("issuing %d\n", m.latestEntryIndex)
			m.latestEntryIndex++
		}
	})
	m.drainWG.Wait()
}
