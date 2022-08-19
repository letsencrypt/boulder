package crl

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/letsencrypt/boulder/issuance"
)

// number must be constructed by calling `NewNumber`. It represents the
// 'crlNumber' field of a CRL.
type number *big.Int

// Number derives the 'CRLNumber' field for a CRL from the value of the
// 'thisUpdate' field provided in Unix nanoseconds.
func Number(thisUpdate int64) number {
	// Per RFC 5280 Section 5.2.3, 'CRLNumber' is a monotonically increasing
	// sequence number for a given CRL scope and CRL that MUST be at most 20
	// octets. A 64-bit (8-byte) integer will never exceed that requirement but
	// let's guarantee this.
	return number(big.NewInt(thisUpdate))
}

// id is a unique identifier for a CRL which is primarily used for logging. This
// identifier is composed of the 'Issuer', 'CRLNumber', and the shard index
// (e.g. {"issuerID": 123, "crlNum": 456, "shardIdx": 78})
type id string

// Id is a utility function which constructs a new `id`.
func Id(issuerID issuance.IssuerNameID, crlNumber number, shardIdx int) (id, error) {
	type info struct {
		IssuerID  issuance.IssuerNameID `json:"issuerID"`
		CRLNumber number                `json:"crlNumber"`
		ShardIdx  int                   `json:"shardIdx"`
	}
	jsonBytes, err := json.Marshal(info{issuerID, crlNumber, shardIdx})
	if err != nil {
		return "", fmt.Errorf("computing CRL Id: %w", err)
	}
	return id(jsonBytes), nil
}
