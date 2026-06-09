// Package tlog provides the primitives shared by a tiled transparency log
// and its cosigners: the C2SP tlog-checkpoint and entry-bundle codecs, the
// tlog-tiles path encoding, the Ed25519 tlog-cosignature signer and
// verifier, and the MTC subtree consistency proof and verifier. It is a thin
// layer over golang.org/x/mod/sumdb/tlog (RFC 6962 hashing, proofs, and tile
// reading) and golang.org/x/mod/sumdb/note (signed notes).
//
// Validated against C2SP/C2SP@01194db, davidben/C2SP@96b748a (mtc-tlog),
// and ietf-plants-wg/merkle-tree-certs@0b45981.
//
// Parsers enforce the specs strictly (canonical encodings, signed-note's
// character rules), so parse-then-serialize round-trips exactly and two
// encoded forms never name one value. Producers validate symmetrically:
// Checkpoint.Marshal checks before serializing, and the cosigner refuses
// non-canonical bodies.
//
// Signing lives behind note.Signer, so verification paths are keyless.
// Cosignatures cross storage as raw timestamped_signature blobs:
// CosignatureLine rebuilds a signature line from a stored blob, and
// Cosignature extracts one from a verified note. Index and size types are
// int64 and hashes are tlog.Hash, matching x/mod; alias that import to
// xtlog:
//
//	import (
//		"github.com/letsencrypt/boulder/tlog"
//		xtlog "golang.org/x/mod/sumdb/tlog"
//	)
package tlog
