package issuancelog

import "fmt"

// oidPrefix begins every mtc-tlog log origin, the IANA private enterprise arc
// an MTC ID is relative to.
//
// https://c2sp.org/mtc-tlog
const oidPrefix = "oid/1.3.6.1.4.1."

// ID is a log ID, identifying one issuance log by the CA ID of the CA operating
// it and the log's log number. The mtca and the mtpublisher derive the names
// they configure themselves with from it.
//
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-issuance-logs
type ID struct {
	// CAID is the CA ID, a trust anchor ID, in its ASCII representation (e.g.
	// "44947.4.1").
	CAID string `validate:"required"`
	// LogNumber is the log number, a positive integer that identifies the log
	// within the CA's series of issuance logs.
	LogNumber uint16 `validate:"required"`
}

// String returns the log ID in its ASCII representation, the CA ID followed by
// the constant 0 and the log number. For instance, the log ID of CA ID
// "44947.4.1" and log number 44 is "44947.4.1.0.44".
//
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-issuance-logs
func (id ID) String() string {
	return fmt.Sprintf("%s.0.%d", id.CAID, id.LogNumber)
}

// Origin returns the log origin per mtc-tlog, the log ID as an origin. For
// instance, the log origin of CA ID "44947.4.1" and log number 44 is
// "oid/1.3.6.1.4.1.44947.4.1.0.44".
//
// https://c2sp.org/mtc-tlog
func (id ID) Origin() string {
	return oidPrefix + id.String()
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
func (id ID) TilePrefix() string {
	return fmt.Sprintf("%s/%d", id.CAID, id.LogNumber)
}
