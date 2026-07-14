//go:build !go1.27

package main

import "log"

// The real server uses crypto/mldsa (Go 1.27) for its cosignatures, so on
// earlier toolchains this binary is a stub.
func main() {
	log.Fatal("tlog-mirror-test-srv requires go1.27 (ML-DSA-44 cosignatures)")
}
