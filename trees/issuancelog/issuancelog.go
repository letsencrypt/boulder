package issuancelog

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/core/reloid"
)

// oidPrefix begins every mtc-tlog log origin, the IANA private enterprise arc
// an MTC ID is relative to.
//
// https://c2sp.org/mtc-tlog
const oidPrefix = "oid/1.3.6.1.4.1."

// Config is how a service can configure a log ID, identifying one issuance log
// by the CA ID of the CA operating it and the log's log number. The mtca and
// the mtpublisher derive the names they configure themselves with from it.
//
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-issuance-logs
type Config struct {
	// CAID is the CA ID, a trust anchor ID, in its ASCII representation (e.g.
	// "44947.4.1").
	CAID string `validate:"required"`
	// LogNumber is the log number, a positive integer that identifies the log
	// within the CA's series of issuance logs.
	LogNumber uint16 `validate:"required"`
}

// Load converts a Config to an ID, checking that the configured CA ID and Log
// Number form valid relative OIDs.
func (c Config) Load() (*ID, error) {
	caID, err := reloid.FromString(c.CAID)
	if err != nil {
		return nil, fmt.Errorf("invalid CA ID: %w", err)
	}
	logID, err := reloid.FromString(fmt.Sprintf("%s.0.%d", c.CAID, c.LogNumber))
	if err != nil {
		return nil, fmt.Errorf("invalid log number: %w", err)
	}
	return &ID{caID: caID, logID: logID, logNum: c.LogNumber}, nil
}

// ID represents a Log ID.
type ID struct {
	caID   *reloid.RelativeOID
	logID  *reloid.RelativeOID
	logNum uint16
}

// CAID returns the CA ID as a relative OID.
func (id *ID) CAID() *reloid.RelativeOID {
	return id.caID
}

// LogNumber returns the Log ID's log number (the last component of its OID).
func (id *ID) LogNumber() uint16 {
	return id.logNum
}

// String returns the log ID in its ASCII representation, the CA ID followed by
// the constant 0 and the log number. For instance, the log ID of CA ID
// "44947.4.1" and log number 44 is "44947.4.1.0.44".
//
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-issuance-logs
func (id *ID) String() string {
	return id.logID.String()
}

// ParseID parses a log ID from its ASCII representation, the inverse of
// ID.String. It rejects anything ID.String would not have produced.
func ParseID(s string) (*ID, error) {
	arcs := strings.Split(s, ".")
	if len(arcs) < 3 {
		return nil, fmt.Errorf("log ID %q must have at least three arcs", s)
	}
	if arcs[len(arcs)-2] != "0" {
		return nil, fmt.Errorf("log ID %q must have 0 before its log number, got %q", s, arcs[len(arcs)-2])
	}
	logNumber, err := strconv.ParseUint(arcs[len(arcs)-1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parsing log number of log ID %q: %w", s, err)
	}
	if strconv.FormatUint(logNumber, 10) != arcs[len(arcs)-1] {
		return nil, fmt.Errorf("log number of log ID %q has a leading zero", s)
	}
	if logNumber == 0 {
		return nil, fmt.Errorf("log ID %q has log number 0, but log numbers start at 1", s)
	}
	return Config{CAID: strings.Join(arcs[:len(arcs)-2], "."), LogNumber: uint16(logNumber)}.Load()
}

// Origin returns the log origin per mtc-tlog, the log ID as an origin. For
// instance, the log origin of CA ID "44947.4.1" and log number 44 is
// "oid/1.3.6.1.4.1.44947.4.1.0.44".
//
// https://c2sp.org/mtc-tlog
func (id *ID) Origin() string {
	return oidPrefix + id.String()
}

// CACosignerName returns the CA's cosigner name per mtc-tlog. For instance,
// the CA cosigner name of CA ID "44947.4.1" is "oid/1.3.6.1.4.1.44947.4.1".
//
// https://c2sp.org/mtc-tlog
func (id ID) CACosignerName() string {
	return oidPrefix + id.CAID().String()
}

// TilePrefix returns the path within a bucket where the log's tiles and
// checkpoint are stored.
//
// https://github.com/C2SP/C2SP/blob/main/mtc-tlog.md#serving-issuance-logs
//
// "Each log's prefix URL is the concatenation of the CA prefix URL and the log
// number, encoded as an ASCII decimal integer with no additional leading zeros:
//
// <CA prefix URL>/<log number>"
//
// We assume we will serve directly from tile storage (likely sync'ed
// somewhere), so we want to store tiles compatible with that pattern, with log
// number as the last component of the path before "tile/".
//
// As a matter of local convention we will put the CA ID as the path component
// right before log number. For instance, the prefix of CA ID "44947.4.1" and
// log number 44 is "44947.4.1/44".
func (id *ID) TilePrefix() string {
	return fmt.Sprintf("%s/%d", id.caID.String(), id.logNum)
}

// CheckpointPath returns the path of the checkpoint file for this log within tile storage.
func (id ID) CheckpointPath() string {
	return path.Join(id.TilePrefix(), "checkpoint")
}

// MTCAID returns the trust anchor ID from this issuer certificate's Subject. It
// returns an error for issuers that are not MTC CAs.
func MTCAID(caCert *x509.Certificate) (*reloid.RelativeOID, error) {
	idRDNATrustAnchorID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}
	for _, attribute := range caCert.Subject.Names {
		if attribute.Type.Equal(idRDNATrustAnchorID) {
			caID, ok := attribute.Value.(asn1.RawValue)
			if !ok {
				return nil, fmt.Errorf("invalid trust anchor attribute type %T", attribute.Value)
			}
			if len(caID.FullBytes) == 0 {
				return nil, fmt.Errorf("empty mtcaID")
			}
			if caID.FullBytes[0] != 0x0d { // Universal Primitive Relative-OID (13)
				return nil, fmt.Errorf("invalid mtcaID asn1 tag byte %x", caID.FullBytes[0])
			}
			ret, err := reloid.FromBytes(caID.Bytes)
			if err != nil {
				return nil, fmt.Errorf("invalid mtcaID relative OID: %w", err)
			}
			return ret, nil
		}
	}
	return nil, fmt.Errorf("issuer subject %q did not contain trust anchor ID OID %q",
		caCert.Subject, idRDNATrustAnchorID)
}
