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
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

var (
	oidExtensionSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidCountry                   = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrganization              = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit        = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCommonName                = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSerialNumber              = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidLocality                  = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidProvince                  = asn1.ObjectIdentifier{2, 5, 4, 8}
	oidStreetAddress             = asn1.ObjectIdentifier{2, 5, 4, 9}
	oidPostalCode                = asn1.ObjectIdentifier{2, 5, 4, 17}
)

type CertValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

type Extension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

const (
	sanOtherName     = 0
	sanRfc822Name    = 1
	sanDNSName       = 2
	sanX400Address   = 3
	sanDirectoryName = 4
	sanEdiPartyName  = 5
	sanURI           = 6
	sanIPAddress     = 7
	sanRegisteredID  = 8
)

type SubjectAltName struct {
	Type  int
	Value []byte
}

type RDNSequence []RelativeDistinguishedNameSET
type RelativeDistinguishedNameSET []AttributeTypeAndValue
type AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

func ParseRDNSequence(rdnsBytes []byte) (RDNSequence, error) {
	var rdns RDNSequence
	if rest, err := asn1.Unmarshal(rdnsBytes, &rdns); err != nil {
		return nil, errors.New("failed to parse RDNSequence: " + err.Error())
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after RDNSequence: %v", rest) // XXX: too strict?
	}
	return rdns, nil
}

func MarshalRDNSequence(rdns RDNSequence) ([]byte, error) {
	return asn1.Marshal(rdns)
}

type TBSCertificate struct {
	Raw asn1.RawContent

	Version            int `asn1:"optional,explicit,default:1,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	UniqueId           asn1.BitString `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString `asn1:"optional,tag:2"`
	Extensions         []Extension    `asn1:"optional,explicit,tag:3"`
}

type Certificate struct {
	Raw asn1.RawContent

	TBSCertificate     asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.RawValue
}

func (rdns RDNSequence) ParseCNs() ([]string, error) {
	var cns []string

	for _, rdn := range rdns {
		if len(rdn) == 0 {
			continue
		}
		atv := rdn[0]
		if atv.Type.Equal(oidCommonName) {
			cnString, err := decodeASN1String(&atv.Value)
			if err != nil {
				return nil, errors.New("Error decoding CN: " + err.Error())
			}
			cns = append(cns, cnString)
		}
	}

	return cns, nil
}

func rdnLabel(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidCountry):
		return "C"
	case oid.Equal(oidOrganization):
		return "O"
	case oid.Equal(oidOrganizationalUnit):
		return "OU"
	case oid.Equal(oidCommonName):
		return "CN"
	case oid.Equal(oidSerialNumber):
		return "serialNumber"
	case oid.Equal(oidLocality):
		return "L"
	case oid.Equal(oidProvince):
		return "ST"
	case oid.Equal(oidStreetAddress):
		return "street"
	case oid.Equal(oidPostalCode):
		return "postalCode"
	}
	return oid.String()
}

func (rdns RDNSequence) String() string {
	var buf bytes.Buffer

	for _, rdn := range rdns {
		if len(rdn) == 0 {
			continue
		}
		atv := rdn[0]

		if buf.Len() != 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(rdnLabel(atv.Type))
		buf.WriteString("=")
		valueString, err := decodeASN1String(&atv.Value)
		if err == nil {
			buf.WriteString(valueString) // TODO: escape non-printable characters, '\', and ','
		} else {
			fmt.Fprintf(&buf, "%v", atv.Value.FullBytes)
		}
	}

	return buf.String()
}

func (san SubjectAltName) String() string {
	switch san.Type {
	case sanDNSName:
		return "DNS:" + string(san.Value) // TODO: escape non-printable characters, '\', and ','
	case sanIPAddress:
		if len(san.Value) == 4 || len(san.Value) == 16 {
			return "IP:" + net.IP(san.Value).String()
		} else {
			return fmt.Sprintf("IP:%v", san.Value)
		}
	default:
		// TODO: support other types of SANs
		return fmt.Sprintf("%d:%v", san.Type, san.Value)
	}
}

func ParseTBSCertificate(tbsBytes []byte) (*TBSCertificate, error) {
	var tbs TBSCertificate
	if rest, err := asn1.Unmarshal(tbsBytes, &tbs); err != nil {
		return nil, errors.New("failed to parse TBS: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after TBS: %v", rest) // XXX: too strict?
	}
	return &tbs, nil
}

func (tbs *TBSCertificate) ParseValidity() (*CertValidity, error) {
	var rawValidity struct {
		NotBefore asn1.RawValue
		NotAfter  asn1.RawValue
	}
	if rest, err := asn1.Unmarshal(tbs.Validity.FullBytes, &rawValidity); err != nil {
		return nil, errors.New("failed to parse validity: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after validity: %v", rest)
	}

	var validity CertValidity
	var err error
	if validity.NotBefore, err = decodeASN1Time(&rawValidity.NotBefore); err != nil {
		return nil, errors.New("failed to decode notBefore time: " + err.Error())
	}
	if validity.NotAfter, err = decodeASN1Time(&rawValidity.NotAfter); err != nil {
		return nil, errors.New("failed to decode notAfter time: " + err.Error())
	}

	return &validity, nil
}

func (tbs *TBSCertificate) ParseBasicConstraints() (*bool, error) {
	isCA := false
	isNotCA := false

	// Some certs in the wild have multiple BasicConstraints extensions (is there anything
	// that CAs haven't screwed up???), so we process all of them and only choke if they
	// are contradictory (which has not been observed...yet).
	for _, ext := range tbs.GetExtension(oidExtensionBasicConstraints) {
		var constraints basicConstraints
		if rest, err := asn1.Unmarshal(ext.Value, &constraints); err != nil {
			return nil, errors.New("failed to parse Basic Constraints: " + err.Error())
		} else if len(rest) > 0 {
			return nil, fmt.Errorf("trailing data after Basic Constraints: %v", rest)
		}

		if constraints.IsCA {
			isCA = true
		} else {
			isNotCA = true
		}
	}

	if !isCA && !isNotCA {
		return nil, nil
	} else if isCA && !isNotCA {
		trueValue := true
		return &trueValue, nil
	} else if !isCA && isNotCA {
		falseValue := false
		return &falseValue, nil
	} else {
		return nil, fmt.Errorf("Certificate has more than one Basic Constraints extension and they are contradictory")
	}
}

func (tbs *TBSCertificate) ParseSerialNumber() (*big.Int, error) {
	serialNumber := big.NewInt(0)
	if rest, err := asn1.Unmarshal(tbs.SerialNumber.FullBytes, &serialNumber); err != nil {
		return nil, errors.New("failed to parse serial number: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after serial number: %v", rest)
	}
	return serialNumber, nil
}

func (tbs *TBSCertificate) GetRawPublicKey() []byte {
	return tbs.PublicKey.FullBytes
}

func (tbs *TBSCertificate) GetRawSubject() []byte {
	return tbs.Subject.FullBytes
}

func (tbs *TBSCertificate) GetRawIssuer() []byte {
	return tbs.Issuer.FullBytes
}

func (tbs *TBSCertificate) ParseSubject() (RDNSequence, error) {
	subject, err := ParseRDNSequence(tbs.GetRawSubject())
	if err != nil {
		return nil, errors.New("failed to parse certificate subject: " + err.Error())
	}
	return subject, nil
}

func (tbs *TBSCertificate) ParseIssuer() (RDNSequence, error) {
	issuer, err := ParseRDNSequence(tbs.GetRawIssuer())
	if err != nil {
		return nil, errors.New("failed to parse certificate issuer: " + err.Error())
	}
	return issuer, nil
}

func (tbs *TBSCertificate) ParseSubjectCommonNames() ([]string, error) {
	subject, err := tbs.ParseSubject()
	if err != nil {
		return nil, err
	}
	cns, err := subject.ParseCNs()
	if err != nil {
		return nil, errors.New("failed to process certificate subject: " + err.Error())
	}

	return cns, nil
}

func (tbs *TBSCertificate) ParseSubjectAltNames() ([]SubjectAltName, error) {
	sans := []SubjectAltName{}

	for _, sanExt := range tbs.GetExtension(oidExtensionSubjectAltName) {
		var err error
		sans, err = parseSANExtension(sans, sanExt.Value)
		if err != nil {
			return nil, err
		}
	}

	return sans, nil
}

func (tbs *TBSCertificate) GetExtension(id asn1.ObjectIdentifier) []Extension {
	var exts []Extension
	for _, ext := range tbs.Extensions {
		if ext.Id.Equal(id) {
			exts = append(exts, ext)
		}
	}
	return exts
}

func ParseCertificate(certBytes []byte) (*Certificate, error) {
	var cert Certificate
	if rest, err := asn1.Unmarshal(certBytes, &cert); err != nil {
		return nil, errors.New("failed to parse certificate: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after certificate: %v", rest) // XXX: too strict?
	}
	return &cert, nil
}

func (cert *Certificate) GetRawTBSCertificate() []byte {
	return cert.TBSCertificate.FullBytes
}

func (cert *Certificate) ParseTBSCertificate() (*TBSCertificate, error) {
	return ParseTBSCertificate(cert.GetRawTBSCertificate())
}

func (cert *Certificate) ParseSignatureAlgorithm() (*pkix.AlgorithmIdentifier, error) {
	signatureAlgorithm := new(pkix.AlgorithmIdentifier)
	if rest, err := asn1.Unmarshal(cert.SignatureAlgorithm.FullBytes, signatureAlgorithm); err != nil {
		return nil, errors.New("failed to parse signature algorithm: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after signature algorithm: %v", rest)
	}
	return signatureAlgorithm, nil
}

func (cert *Certificate) ParseSignatureValue() ([]byte, error) {
	var signatureValue asn1.BitString
	if rest, err := asn1.Unmarshal(cert.SignatureValue.FullBytes, &signatureValue); err != nil {
		return nil, errors.New("failed to parse signature value: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after signature value: %v", rest)
	}
	return signatureValue.RightAlign(), nil
}

func parseSANExtension(sans []SubjectAltName, value []byte) ([]SubjectAltName, error) {
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(value, &seq); err != nil {
		return nil, errors.New("failed to parse subjectAltName extension: " + err.Error())
	} else if len(rest) != 0 {
		// Don't complain if the SAN is followed by exactly one zero byte,
		// which is a common error.
		if !(len(rest) == 1 && rest[0] == 0) {
			return nil, fmt.Errorf("trailing data in subjectAltName extension: %v", rest) // XXX: too strict?
		}
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return nil, errors.New("failed to parse subjectAltName extension: bad SAN sequence") // XXX: too strict?
	}

	rest := seq.Bytes
	for len(rest) > 0 {
		var val asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &val)
		if err != nil {
			return nil, errors.New("failed to parse subjectAltName extension item: " + err.Error())
		}
		sans = append(sans, SubjectAltName{Type: val.Tag, Value: val.Bytes})
	}

	return sans, nil
}
