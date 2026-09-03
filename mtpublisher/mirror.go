//go:build go1.27

package mtpublisher

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/mldsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/mirror"
)

// maxMirrorResponseSize caps how much of a mirror's response body the client
// reads. The largest expected body is a few ML-DSA-44 signature lines of under
// 4KB each.
const maxMirrorResponseSize = 64 << 10

// maxErrorBodySize caps how much of an unexpected mirror response body is
// quoted in an error.
const maxErrorBodySize = 400

// errorBody returns respBody trimmed for quoting in an error.
func errorBody(respBody []byte) string {
	body := strings.TrimSpace(string(respBody))
	if len(body) > maxErrorBodySize {
		return body[:maxErrorBodySize] + "..."
	}
	return body
}

var _ Mirror = (*MirrorClient)(nil)

// MirrorClient is a Mirror that uses the c2sp.org/tlog-mirror submission
// protocol, submitting the checkpoint to add-checkpoint and uploading the log's
// entries to add-entries until the mirror cosigns.
type MirrorClient struct {
	submissionPrefix string
	client           *http.Client
	src              *Source
	mirrorID         string
	verifier         *cosignature.Verifier

	// oldSize is the tree size of the mirror's latest cosigned checkpoint, the
	// old size of the next add-checkpoint request.
	oldSize int64
	// nextEntry is the next entry the mirror expects to receive.
	nextEntry int64
	// ticket is the opaque value from the mirror's last mirror-info response,
	// to be sent back in the next add-entries request.
	ticket []byte
}

// NewMirrorClient returns a MirrorClient that submits to the mirror's endpoints
// under baseURL, giving each request timeout to complete.
func NewMirrorClient(baseURL string, src *Source, mirrorID string, mirrorPublicKey *mldsa.PublicKey, timeout time.Duration) (*MirrorClient, error) {
	if baseURL == "" {
		return nil, errors.New("empty mirror base URL")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive, got %s", timeout)
	}
	verifier, err := cosignature.NewVerifier(mirrorID, mirrorPublicKey)
	if err != nil {
		return nil, fmt.Errorf("creating mirror verifier: %s", err)
	}
	return &MirrorClient{
		submissionPrefix: baseURL,
		client:           &http.Client{Timeout: timeout},
		src:              src,
		mirrorID:         mirrorID,
		verifier:         verifier,
	}, nil
}

// ID returns the mirror's cosigner ID.
func (m *MirrorClient) ID() string {
	return m.mirrorID
}

// post sends body to the endpoint at path and returns the response status and
// body. If compress is true, the body is gzip compressed.
func (m *MirrorClient) post(ctx context.Context, path, contentType string, compress bool, body []byte) (int, []byte, error) {
	if compress {
		var compressed bytes.Buffer
		zw := gzip.NewWriter(&compressed)
		_, err := zw.Write(body)
		if err != nil {
			return 0, nil, err
		}
		err = zw.Close()
		if err != nil {
			return 0, nil, err
		}
		body = compressed.Bytes()
	}
	endpoint, err := url.JoinPath(m.submissionPrefix, path)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if compress {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, maxMirrorResponseSize))
	if err != nil {
		return 0, nil, fmt.Errorf("reading mirror response: %s", err)
	}
	return resp.StatusCode, respBody, nil
}

// addCheckpoint submits the log's signed checkpoint note with a consistency
// proof from the mirror's last known size, updating the mirror's pending
// checkpoint. On a "409 Conflict" it adopts the size the mirror advertises and
// retries once. An up-to-date mirror still receives the checkpoint, with an
// empty proof, since that is the only way to obtain its cosignature.
func (m *MirrorClient) addCheckpoint(ctx context.Context, tree tlog.Tree, signedNote []byte) error {
	for range 2 {
		if m.oldSize > tree.N {
			return fmt.Errorf("mirror already holds size %d, checkpoint size is %d", m.oldSize, tree.N)
		}
		var proof []tlog.Hash
		if m.oldSize > 0 && m.oldSize < tree.N {
			treeProof, err := m.src.consistencyProof(ctx, tree, m.oldSize)
			if err != nil {
				return fmt.Errorf("proving consistency from size %d: %s", m.oldSize, err)
			}
			proof = treeProof
		}
		body, err := mirror.AddCheckpointRequest(m.oldSize, proof, signedNote)
		if err != nil {
			return err
		}
		status, respBody, err := m.post(ctx, "/add-checkpoint", "", false, body)
		if err != nil {
			return err
		}
		switch status {
		case http.StatusOK:
			m.oldSize = tree.N
			return nil
		case http.StatusConflict:
			mirrorSize, err := mirror.ParseSizeResponse(respBody)
			if err != nil {
				return err
			}
			m.oldSize = mirrorSize
		default:
			return fmt.Errorf("mirror returned status %d: %s", status, errorBody(respBody))
		}
	}
	return fmt.Errorf("add-checkpoint at tree size %d got 409 with mirror tree size %d after retrying", tree.N, m.oldSize)
}

// maxAddEntriesRequests bounds one Cosign call's add-entries requests, each of
// up to MaxPackagesPerRequest entry packages, so an upload terminates against a
// mirror that never makes progress.
const maxAddEntriesRequests = 100

// addEntries uploads the entries the mirror is missing, up to the tree size,
// and returns the cosignature lines from the mirror's "200 Success" response.
// On "202 Accepted" and "409 Conflict" it resumes from the next entry and
// ticket the mirror advertises.
func (m *MirrorClient) addEntries(ctx context.Context, origin string, tree tlog.Tree) ([]byte, error) {
	for range maxAddEntriesRequests {
		packages, err := mirror.Packages(m.nextEntry, tree.N, mirror.MaxPackagesPerRequest)
		if err != nil {
			return nil, err
		}
		var bodies [][]byte
		for _, p := range packages {
			body, err := m.src.entryPackage(ctx, tree, p)
			if err != nil {
				return nil, err
			}
			bodies = append(bodies, body)
		}
		reqBody, err := mirror.AddEntriesRequest(origin, m.nextEntry, tree.N, m.ticket, bodies)
		if err != nil {
			return nil, err
		}
		status, respBody, err := m.post(ctx, "/add-entries", "application/octet-stream", true, reqBody)
		if err != nil {
			return nil, err
		}
		switch status {
		case http.StatusOK:
			if len(respBody) == 0 {
				return nil, errors.New("mirror returned no cosignature lines")
			}
			m.nextEntry = tree.N
			m.ticket = nil
			return respBody, nil

		case http.StatusAccepted, http.StatusConflict:
			info, err := mirror.ParseMirrorInfo(respBody)
			if err != nil {
				return nil, err
			}
			if info.TreeSize != tree.N {
				// The spec has the client adopt the advertised tree size, but
				// Cosign set the mirror's pending checkpoint to tree.N with
				// add-checkpoint before uploading, so the mirror SHOULD have
				// echoed it, and a cosignature over any other tree size is no
				// use here.
				return nil, fmt.Errorf("mirror wants upload_end %d, checkpoint size is %d", info.TreeSize, tree.N)
			}
			if info.NextEntry > tree.N {
				return nil, fmt.Errorf("mirror wants upload_start %d, checkpoint size is %d", info.NextEntry, tree.N)
			}
			m.nextEntry = info.NextEntry
			m.ticket = bytes.Clone(info.Ticket)

		default:
			return nil, fmt.Errorf("mirror returned status %d: %s", status, errorBody(respBody))
		}
	}
	return nil, fmt.Errorf("upload incomplete after %d add-entries requests", maxAddEntriesRequests)
}

// signSubtree requests the mirror's zero timestamp signature over the whole
// tree from the c2sp.org/tlog-witness sign-subtree endpoint, presenting the
// checkpoint note carrying the cosignature lines add-entries returned.
func (m *MirrorClient) signSubtree(ctx context.Context, tree tlog.Tree, signedNote []byte) ([]byte, error) {
	body, err := mirror.SignSubtreeRequest(0, tree.N, tree.Hash, nil, signedNote)
	if err != nil {
		return nil, err
	}
	status, respBody, err := m.post(ctx, "/sign-subtree", "", false, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("mirror returned status %d: %s", status, errorBody(respBody))
	}
	return respBody, nil
}

// Cosign runs the c2sp.org/tlog-mirror submission protocol for the checkpoint
// and returns the mirror's raw signature over the whole tree from sign-subtree,
// verified against the mirror's key. A mirror that is already up to date,
// whether from an earlier submission whose cosignature was never stored or
// from another submitter, still gets the full exchange, since that is the only
// way to obtain its cosignature.
func (m *MirrorClient) Cosign(ctx context.Context, cp *checkpoint.Checkpoint, signedNoteForMirror []byte) ([]byte, error) {
	// Submit the checkpoint to the mirror.
	err := m.addCheckpoint(ctx, cp.Tree, signedNoteForMirror)
	if err != nil {
		return nil, fmt.Errorf("add-checkpoint: %w", err)
	}

	// Upload the checkpoint's entries to the mirror until it cosigns.
	mirrorCosignatureLines, err := m.addEntries(ctx, cp.Origin, cp.Tree)
	if err != nil {
		return nil, fmt.Errorf("add-entries: %w", err)
	}

	// Exchange the mirror's cosignature for its subtree signature.
	noteForSignSubtree, err := cp.SignedNote(mirrorCosignatureLines)
	if err != nil {
		return nil, fmt.Errorf("assembling the sign-subtree note: %w", err)
	}
	subtreeCosignatureLines, err := m.signSubtree(ctx, cp.Tree, noteForSignSubtree)
	if err != nil {
		return nil, fmt.Errorf("sign-subtree: %w", err)
	}

	// Verify the mirror's signature.
	noteText, err := cp.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling the checkpoint: %w", err)
	}
	zeroTimestampMirrorCosignature, err := m.verifier.FilterByVerify(noteText, subtreeCosignatureLines)
	if err != nil {
		return nil, fmt.Errorf("cosignature failed verification: %w", err)
	}

	// Finally, extract the raw cosignature we store in the database.
	rawMirrorCosignature, err := cosignature.RawSignature(zeroTimestampMirrorCosignature)
	if err != nil {
		return nil, fmt.Errorf("cosignature: %w", err)
	}
	return rawMirrorCosignature, nil
}
