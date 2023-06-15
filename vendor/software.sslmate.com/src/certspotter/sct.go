// Copyright (C) 2017 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package certspotter

import (
	"software.sslmate.com/src/certspotter/ct"
)

func VerifyX509SCT(sct *ct.SignedCertificateTimestamp, cert []byte, verify *ct.SignatureVerifier) error {
	entry := ct.LogEntry{
		Leaf: ct.MerkleTreeLeaf{
			Version:  0,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: ct.TimestampedEntry{
				Timestamp:  sct.Timestamp,
				EntryType:  ct.X509LogEntryType,
				X509Entry:  cert,
				Extensions: sct.Extensions,
			},
		},
	}
	return verify.VerifySCTSignature(*sct, entry)
}

func VerifyPrecertSCT(sct *ct.SignedCertificateTimestamp, precert ct.PreCert, verify *ct.SignatureVerifier) error {
	entry := ct.LogEntry{
		Leaf: ct.MerkleTreeLeaf{
			Version:  0,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: ct.TimestampedEntry{
				Timestamp:  sct.Timestamp,
				EntryType:  ct.PrecertLogEntryType,
				PrecertEntry:  precert,
				Extensions: sct.Extensions,
			},
		},
	}
	return verify.VerifySCTSignature(*sct, entry)
}
