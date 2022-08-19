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

// NewNumber derives the 'CRLNumber' field for a CRL from the value of the
// 'thisUpdate' field provided in Unix nanoseconds.
func NewNumber(thisUpdate int64) number {
	// Per RFC 5280 Section 5.2.3, 'CRLNumber' is a monotonically increasing
	// sequence number for a given CRL scope and CRL that MUST be at most 20
	// octets. A 64-bit (8-byte) integer will never exceed that requirement but
	// let's guarantee this.
	return number(big.NewInt(thisUpdate))
}

// id is a wrapper around a unique identifier, used primarily for logging, which
// combines the 'Issuer', 'CRLNumber', and shard index of a CRL.
type id struct {
	crlId string
}

// NewID is a utility function which constructs a new `id`.
func NewId(issuerID issuance.IssuerNameID, crlNum number, shardIdx int) (id, error) {
	type info struct {
		IssuerID issuance.IssuerNameID `json:"issuerID"`
		CRLNum   number                `json:"crlNum"`
		ShardIdx int                   `json:"shardIdx"`
	}
	jsonBytes, err := json.Marshal(info{issuerID, crlNum, shardIdx})
	if err != nil {
		return id{}, fmt.Errorf("computing CRL Id: %w", err)
	}
	return id{string(jsonBytes)}, nil
}

func (c id) String() string {
	return c.crlId
}
