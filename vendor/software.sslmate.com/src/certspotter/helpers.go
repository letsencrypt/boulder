// Copyright (C) 2016 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package certspotter

import (
	"fmt"
	"math/big"

	"software.sslmate.com/src/certspotter/ct"
)

func IsPrecert(entry *ct.LogEntry) bool {
	return entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType
}

type CertInfo struct {
	TBS *TBSCertificate

	Subject                RDNSequence
	SubjectParseError      error
	Issuer                 RDNSequence
	IssuerParseError       error
	SANs                   []SubjectAltName
	SANsParseError         error
	SerialNumber           *big.Int
	SerialNumberParseError error
	Validity               *CertValidity
	ValidityParseError     error
	IsCA                   *bool
	IsCAParseError         error
	IsPreCert              bool
}

func MakeCertInfoFromTBS(tbs *TBSCertificate) *CertInfo {
	info := &CertInfo{TBS: tbs}

	info.Subject, info.SubjectParseError = tbs.ParseSubject()
	info.Issuer, info.IssuerParseError = tbs.ParseIssuer()
	info.SANs, info.SANsParseError = tbs.ParseSubjectAltNames()
	info.SerialNumber, info.SerialNumberParseError = tbs.ParseSerialNumber()
	info.Validity, info.ValidityParseError = tbs.ParseValidity()
	info.IsCA, info.IsCAParseError = tbs.ParseBasicConstraints()
	info.IsPreCert = len(tbs.GetExtension(oidExtensionCTPoison)) > 0

	return info
}

func MakeCertInfoFromRawTBS(tbsBytes []byte) (*CertInfo, error) {
	tbs, err := ParseTBSCertificate(tbsBytes)
	if err != nil {
		return nil, err
	}
	return MakeCertInfoFromTBS(tbs), nil
}

func MakeCertInfoFromRawCert(certBytes []byte) (*CertInfo, error) {
	cert, err := ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return MakeCertInfoFromRawTBS(cert.GetRawTBSCertificate())
}

func MakeCertInfoFromLogEntry(entry *ct.LogEntry) (*CertInfo, error) {
	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		return MakeCertInfoFromRawCert(entry.Leaf.TimestampedEntry.X509Entry)

	case ct.PrecertLogEntryType:
		return MakeCertInfoFromRawTBS(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)

	default:
		return nil, fmt.Errorf("MakeCertInfoFromCTEntry: unknown CT entry type (neither X509 nor precert)")
	}
}

func MatchesWildcard(dnsName string, pattern string) bool {
	for len(pattern) > 0 {
		if pattern[0] == '*' {
			if len(dnsName) > 0 && dnsName[0] != '.' && MatchesWildcard(dnsName[1:], pattern) {
				return true
			}
			pattern = pattern[1:]
		} else {
			if len(dnsName) == 0 || pattern[0] != dnsName[0] {
				return false
			}
			pattern = pattern[1:]
			dnsName = dnsName[1:]
		}
	}
	return len(dnsName) == 0
}
