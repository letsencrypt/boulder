//go:build go1.27

// Command tlog-mirror-test-srv is a fake C2SP tlog-mirror, for integration
// tests of the MTC publisher. It implements the submission endpoints
// (add-checkpoint, add-entries) with real verification and real ML-DSA-44
// mirror cosignatures, writes a tlog-tiles store to disk, and serves it. It is
// not for production use.
package main

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/mirror"
	"github.com/letsencrypt/boulder/trees/subtree"
	"github.com/letsencrypt/boulder/trees/tilestore"
	"github.com/letsencrypt/boulder/trees/tilestore/fs"
)

// logConfig configures one log the mirror accepts submissions for.
type logConfig struct {
	// Origin is the log's checkpoint origin line.
	Origin string
	// VerifierKey is a c2sp.org/signed-note verifier key for the log's
	// checkpoint signature.
	VerifierKey string
}

type config struct {
	// ListenAddr is the address to listen on, e.g. ":4700". The --addr flag
	// overrides it.
	ListenAddr string
	// StorageDir is the root directory of the on-disk tlog-tiles store.
	StorageDir string
	// MirrorName is the cosigner key name in the mirror's signature lines.
	MirrorName string
	// MirrorKeySeed is the base64 of the 32-byte ML-DSA-44 seed the mirror
	// cosigns with.
	MirrorKeySeed string
	Logs          []logConfig
}

// pendingCheckpoint is a log-signed checkpoint the mirror has accepted via
// add-checkpoint but whose entries it has not yet fully mirrored. It is held in
// memory and re-established by re-submission after a restart.
type pendingCheckpoint struct {
	root   tlog.Hash
	signed []byte // the signed note, carrying the log's signature
	body   []byte // the checkpoint note text the mirror cosigns
}

// logState is the mirror's in-memory index for one origin. The tree itself, and
// its size and root, live in the store. It is guarded by server.mu.
type logState struct {
	verifiers note.Verifiers
	store     *tilestore.Store
	pending   map[int64]pendingCheckpoint
}

func newLogState(verifiers note.Verifiers, store *tilestore.Store) *logState {
	return &logState{
		verifiers: verifiers,
		store:     store,
		pending:   make(map[int64]pendingCheckpoint),
	}
}

type server struct {
	mu       sync.Mutex
	cosigner *cosignature.MLDSACosigner
	logs     map[string]*logState
}

// newServer builds a mirror server from config: it loads the ML-DSA-44
// cosigner, a verifier per log, and a tilestore for each log over a shared
// filesystem backend. Each log's size and root are recovered from its store on
// demand, so there is no explicit recovery step.
func newServer(c config, clk clock.Clock) (*server, error) {
	seed, err := base64.StdEncoding.DecodeString(c.MirrorKeySeed)
	if err != nil {
		return nil, fmt.Errorf("decoding mirror key seed: %w", err)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		return nil, fmt.Errorf("loading mirror key: %w", err)
	}
	cosigner, err := cosignature.NewMLDSACosigner(c.MirrorName, key, clk)
	if err != nil {
		return nil, fmt.Errorf("building cosigner: %w", err)
	}

	backend := fs.New(c.StorageDir)
	logs := make(map[string]*logState)
	for _, lc := range c.Logs {
		v, err := note.NewVerifier(lc.VerifierKey)
		if err != nil {
			return nil, fmt.Errorf("verifier for %q: %w", lc.Origin, err)
		}
		logs[lc.Origin] = newLogState(note.VerifierList(v), tilestore.New(backend, lc.Origin))
	}
	return &server{cosigner: cosigner, logs: logs}, nil
}

func (s *server) writeSize(w http.ResponseWriter, size int64) {
	b, err := mirror.MarshalSize(size)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", mirror.ContentTypeSize)
	w.WriteHeader(http.StatusConflict)
	_, err = w.Write(b)
	if err != nil {
		log.Printf("writing size response: %s", err)
	}
}

func (s *server) writeMirrorInfo(w http.ResponseWriter, ls *logState, size int64, status int) {
	// Advertise the largest pending checkpoint size as the upload target.
	target := size
	for sz := range ls.pending {
		if sz > target {
			target = sz
		}
	}
	info := mirror.Info{TreeSize: target, NextEntry: size}
	b, err := info.Marshal()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", mirror.ContentTypeMirrorInfo)
	w.WriteHeader(status)
	_, err = w.Write(b)
	if err != nil {
		log.Printf("writing mirror-info response: %s", err)
	}
}

// handleAddCheckpoint verifies a submitted checkpoint and records it as a
// pending checkpoint. Like a witness it checks the log signature and a
// consistency proof from the mirror's current size, but it does not cosign.
func (s *server) handleAddCheckpoint(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}
	req, err := mirror.ParseAddCheckpointRequest(body)
	if err != nil {
		http.Error(w, "malformed add-checkpoint request", http.StatusBadRequest)
		return
	}
	// The origin is the checkpoint note's first line; it selects which log's
	// verifiers and mirror state to use.
	origin, _, ok := bytes.Cut(req.Checkpoint, []byte("\n"))
	if !ok {
		http.Error(w, "malformed checkpoint", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	s.mu.Lock()
	defer s.mu.Unlock()

	ls, ok := s.logs[string(origin)]
	if !ok {
		http.Error(w, "unknown log origin", http.StatusNotFound)
		return
	}
	tree, err := ls.store.Tree(ctx)
	if err != nil {
		http.Error(w, "reading tree state", http.StatusInternalServerError)
		return
	}

	cp, n, err := checkpoint.Open(req.Checkpoint, ls.verifiers)
	if err != nil {
		http.Error(w, "checkpoint signature does not verify", http.StatusForbidden)
		return
	}

	newSize := cp.Tree.N
	newRoot := cp.Tree.Hash
	if req.OldSize > newSize {
		http.Error(w, "old size exceeds checkpoint size", http.StatusBadRequest)
		return
	}
	if req.OldSize != tree.N {
		s.writeSize(w, tree.N)
		return
	}
	if req.OldSize == newSize {
		if newRoot != tree.Hash {
			http.Error(w, "old size equals checkpoint size but roots differ", http.StatusConflict)
			return
		}
	} else if req.OldSize > 0 {
		err = tlog.CheckTree(req.Proof, newSize, newRoot, tree.N, tree.Hash)
		if err != nil {
			http.Error(w, "consistency proof does not verify", http.StatusUnprocessableEntity)
			return
		}
	}

	ls.pending[newSize] = pendingCheckpoint{
		root:   newRoot,
		signed: bytes.Clone(req.Checkpoint),
		body:   []byte(n.Text),
	}
	w.WriteHeader(http.StatusOK)
}

// handleAddEntries authenticates the uploaded entry packages against a pending
// checkpoint, commits them to the store, and once the tree catches up to the
// pending checkpoint, cosigns it and returns the mirror's cosignature.
func (s *server) handleAddEntries(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}
	req, truncated, err := mirror.ParseAddEntriesRequest(body)
	if err != nil {
		http.Error(w, "malformed add-entries request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	s.mu.Lock()
	defer s.mu.Unlock()

	ls, ok := s.logs[req.Origin]
	if !ok {
		http.Error(w, "unknown log origin", http.StatusNotFound)
		return
	}
	tree, err := ls.store.Tree(ctx)
	if err != nil {
		http.Error(w, "reading tree state", http.StatusInternalServerError)
		return
	}

	pend, ok := ls.pending[req.UploadEnd]
	if !ok || req.UploadEnd < tree.N {
		s.writeMirrorInfo(w, ls, tree.N, http.StatusConflict)
		return
	}
	if req.UploadStart != tree.N {
		s.writeMirrorInfo(w, ls, tree.N, http.StatusConflict)
		return
	}

	var newEntries [][]byte
	for i, pkg := range req.Packages {
		canonical, ok := mirror.EntryPackageAt(req.UploadStart, req.UploadEnd, int64(i))
		if !ok {
			http.Error(w, "more packages than the canonical sequence holds", http.StatusBadRequest)
			return
		}
		leaves := make([]tlog.Hash, 0, canonical.End-canonical.SubtreeStart)
		if canonical.SubtreeStart < canonical.EntriesStart {
			// A ragged first package proves a subtree whose leading entries the
			// mirror already holds; read that prefix of leaves from the store.
			prefix, err := ls.store.ReadLeaves(ctx, canonical.SubtreeStart, canonical.EntriesStart, tree.N)
			if err != nil {
				http.Error(w, "reading stored leaves", http.StatusInternalServerError)
				return
			}
			leaves = append(leaves, prefix...)
		}
		for _, e := range pkg.Entries {
			leaves = append(leaves, tlog.RecordHash(e))
		}
		subtreeHash := subtree.HashLeaves(leaves)
		if !subtree.VerifyConsistency(canonical.SubtreeStart, canonical.End, req.UploadEnd, pkg.Proof, subtreeHash, pend.root) {
			http.Error(w, "subtree consistency proof does not verify", http.StatusUnprocessableEntity)
			return
		}
		newEntries = append(newEntries, pkg.Entries...)
	}

	if len(req.Packages) == 0 && truncated {
		http.Error(w, "no complete entry package", http.StatusBadRequest)
		return
	}

	currentSize := tree.N
	if len(newEntries) > 0 {
		newTree, err := ls.store.Append(ctx, tree.N, newEntries)
		if err != nil {
			http.Error(w, "committing entries", http.StatusInternalServerError)
			return
		}
		currentSize = newTree.N
	}

	if currentSize != req.UploadEnd {
		s.writeMirrorInfo(w, ls, currentSize, http.StatusAccepted)
		return
	}

	// Caught up to the pending checkpoint: cosign it and write it as the mirror
	// checkpoint. The store already holds the matching root.
	line, err := s.cosigner.Cosign(pend.body)
	if err != nil {
		http.Error(w, "cosigning", http.StatusInternalServerError)
		return
	}
	err = ls.store.WriteCheckpoint(ctx, append(bytes.Clone(pend.signed), line...))
	if err != nil {
		http.Error(w, "writing checkpoint", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err = io.WriteString(w, line)
	if err != nil {
		log.Printf("writing cosignature response: %s", err)
	}
}

// serve answers a monitoring GET for /<percent-encoded origin>/<resource>,
// where resource is "checkpoint" or a tlog-tiles path, from that origin's
// store.
func (s *server) serve(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.EscapedPath(), "/")
	originSeg, resource, ok := strings.Cut(rel, "/")
	if !ok || originSeg == "" {
		http.NotFound(w, r)
		return
	}
	origin, err := url.PathUnescape(originSeg)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	s.mu.Lock()
	ls, ok := s.logs[origin]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	data, err := ls.store.Fetch(r.Context(), resource)
	if errors.Is(err, tilestore.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resource == "checkpoint" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	_, err = w.Write(data)
	if err != nil {
		log.Printf("writing served %s: %s", resource, err)
	}
}

// handler returns the mirror's HTTP routes: the two submission endpoints and a
// catch-all serving the monitoring GETs (checkpoint and tiles) from the stores.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /add-checkpoint", s.handleAddCheckpoint)
	mux.HandleFunc("POST /add-entries", s.handleAddEntries)
	mux.HandleFunc("GET /", s.serve)
	return mux
}

func main() {
	addr := flag.String("addr", "", "Address to listen on, overriding the config")
	configFile := flag.String("config", "", "Path to the JSON config file")
	flag.Parse()

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "reading config")
	if *addr != "" {
		c.ListenAddr = *addr
	}

	srv, err := newServer(c, clock.New())
	cmd.FailOnError(err, "building mirror")

	httpSrv := &http.Server{
		Addr:        c.ListenAddr,
		Handler:     srv.handler(),
		ReadTimeout: 30 * time.Second,
	}
	go func() {
		err := httpSrv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			cmd.FailOnError(err, "running tlog-mirror-test-srv")
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := httpSrv.Shutdown(ctx)
		if err != nil {
			log.Printf("shutting down: %s", err)
		}
	}()

	log.Printf("tlog-mirror-test-srv listening on %s", c.ListenAddr)
	cmd.WaitForSignal()
}
