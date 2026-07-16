// Package main provides a tool to parse MTC entry bundles and print
// them in a human-readable format.
//
// For each file provided on the commandline (or stdout if there are
// no arguments), it parses the contents into a sequence of
// MerkleTreeCertEntry and pretty-prints the corresponding TBSCertificateLogEntry
// or null_entry as appropriate.
//
// It will transparently decompress gzipped tiles when applicable.
package main

import (
	"bytes"
	"compress/gzip"
	encoding_asn1 "encoding/asn1"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/letsencrypt/boulder/trees/entry"
)

func main() {
	err := main2()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func main2() error {
	for _, filename := range os.Args[1:] {
		body, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		err = cat(body)
		if err != nil {
			return err
		}
	}
	if len(os.Args) == 1 {
		body, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		err = cat(body)
		if err != nil {
			return err
		}
	}
	return nil
}

func tryGunzip(body []byte) ([]byte, error) {
	// Try gunzip; fall back to uncompressed.
	gzipReader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	return io.ReadAll(gzipReader)
}

func cat(body []byte) error {
	uncompressed, err := tryGunzip(body)
	if err == nil {
		body = uncompressed
	}

	var i int
	br := entry.NewBundleReader(body)
	for {
		mtce, _, err := br.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		f, err := formatTBS(mtce.TBS())
		if err != nil {
			return err
		}
		fmt.Printf("%d:\n%s\n", i, f)
		i++
	}
}

func formatTBS(in []byte) (string, error) {
	if len(in) == 0 {
		return "  null_entry\n", nil
	}
	var ret strings.Builder
	tbs := cryptobyte.String(in)
	var version cryptobyte.String
	if !tbs.ReadASN1(&version, asn1.Tag(0).Constructed().ContextSpecific()) {
		return "", fmt.Errorf("malformed version")
	}
	fmt.Fprintf(&ret, "  version:  %x\n", version)

	var issuer cryptobyte.String
	if !tbs.ReadASN1(&issuer, asn1.SEQUENCE) {
		return "", fmt.Errorf("malformed issuer")
	}
	fmt.Fprintf(&ret, "  issuer:   %x\n", issuer)

	var validity cryptobyte.String
	if !tbs.ReadASN1(&validity, asn1.SEQUENCE) {
		return "", fmt.Errorf("malformed validity")
	}
	fmt.Fprintf(&ret, "  validity: %x\n", validity)

	var subject cryptobyte.String
	if !tbs.ReadASN1(&subject, asn1.SEQUENCE) {
		return "", fmt.Errorf("malformed subject")
	}
	fmt.Fprintf(&ret, "  subject:  %x\n", subject)

	var spka cryptobyte.String
	if !tbs.ReadASN1(&spka, asn1.SEQUENCE) {
		return "", fmt.Errorf("malformed subjectPublicKeyAlgorithm")
	}
	fmt.Fprintf(&ret, "  subjectPublicKeyAlgorithm:  %x\n", spka)

	var spkiHash cryptobyte.String
	if !tbs.ReadASN1(&spkiHash, asn1.OCTET_STRING) {
		return "", fmt.Errorf("malformed subjectPublicKeyInfoHash")
	}
	fmt.Fprintf(&ret, "  subjectPublicKeyInfoHash:   %x\n", spkiHash)

	var extensions cryptobyte.String
	if !tbs.ReadASN1(&extensions, asn1.Tag(3).Constructed().ContextSpecific()) {
		return "", fmt.Errorf("malformed extensions")
	}
	if !extensions.ReadASN1(&extensions, asn1.SEQUENCE) {
		return "", fmt.Errorf("malformed extensions")
	}

	fmt.Fprintf(&ret, "  extensions:\n")
	for !extensions.Empty() {
		var ext cryptobyte.String
		if !extensions.ReadASN1(&ext, asn1.SEQUENCE) {
			return "", fmt.Errorf("malformed extension")
		}

		var oid encoding_asn1.ObjectIdentifier
		if !ext.ReadASN1ObjectIdentifier(&oid) {
			return "", fmt.Errorf("malformed extnID")
		}

		var critical cryptobyte.String
		var critPresent bool
		if !ext.ReadOptionalASN1(&critical, &critPresent, asn1.BOOLEAN) {
			return "", fmt.Errorf("malformed critical")
		}

		var extnValue cryptobyte.String
		if !ext.ReadASN1(&extnValue, asn1.OCTET_STRING) {
			return "", fmt.Errorf("malformed extnValue")
		}
		var crit string
		if critPresent && bytes.Equal([]byte{0xFF}, critical) {
			crit = "!! "
		}
		fmt.Fprintf(&ret, "    - %s %s%x\n", extnName(oid), crit, extnValue)
	}
	return ret.String(), nil
}

func extnName(oid encoding_asn1.ObjectIdentifier) string {
	str := oid.String()
	switch str {
	case "2.5.29.15":
		return "keyUsage"
	case "2.5.29.37":
		return "extKeyUsage"
	case "2.5.29.19":
		return "basicConstraints"
	case "1.3.6.1.5.5.7.1.1":
		return "authorityInfoAccess"
	case "2.5.29.17":
		return "subjectAltName"
	case "2.5.29.32":
		return "certificatePolicies"
	case "2.5.29.31":
		return "crlDistributionPoints"
	case "1.3.6.1.4.1.11129.2.4.3":
		return "CT poison"
	case "1.3.6.1.4.1.11129.2.4.2":
		return "SCT list"
	default:
		return str
	}
}
