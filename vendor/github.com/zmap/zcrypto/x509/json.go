// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/json"
	"net"

	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	jsonKeys "github.com/zmap/zcrypto/json"
	"github.com/zmap/zcrypto/x509/pkix"
)

var kMinTime, kMaxTime time.Time

func init() {
	var err error
	kMinTime, err = time.Parse(time.RFC3339, "0001-01-01T00:00:00Z")
	if err != nil {
		panic(err)
	}
	kMaxTime, err = time.Parse(time.RFC3339, "9999-12-31T23:59:59Z")
	if err != nil {
		panic(err)
	}
}

type auxKeyUsage struct {
	DigitalSignature  bool   `json:"digital_signature,omitempty"`
	ContentCommitment bool   `json:"content_commitment,omitempty"`
	KeyEncipherment   bool   `json:"key_encipherment,omitempty"`
	DataEncipherment  bool   `json:"data_encipherment,omitempty"`
	KeyAgreement      bool   `json:"key_agreement,omitempty"`
	CertificateSign   bool   `json:"certificate_sign,omitempty"`
	CRLSign           bool   `json:"crl_sign,omitempty"`
	EncipherOnly      bool   `json:"encipher_only,omitempty"`
	DecipherOnly      bool   `json:"decipher_only,omitempty"`
	Value             uint32 `json:"value"`
}

// MarshalJSON implements the json.Marshaler interface
func (k KeyUsage) MarshalJSON() ([]byte, error) {
	var enc auxKeyUsage
	enc.Value = uint32(k)
	if k&KeyUsageDigitalSignature > 0 {
		enc.DigitalSignature = true
	}
	if k&KeyUsageContentCommitment > 0 {
		enc.ContentCommitment = true
	}
	if k&KeyUsageKeyEncipherment > 0 {
		enc.KeyEncipherment = true
	}
	if k&KeyUsageDataEncipherment > 0 {
		enc.DataEncipherment = true
	}
	if k&KeyUsageKeyAgreement > 0 {
		enc.KeyAgreement = true
	}
	if k&KeyUsageCertSign > 0 {
		enc.CertificateSign = true
	}
	if k&KeyUsageCRLSign > 0 {
		enc.CRLSign = true
	}
	if k&KeyUsageEncipherOnly > 0 {
		enc.EncipherOnly = true
	}
	if k&KeyUsageDecipherOnly > 0 {
		enc.DecipherOnly = true
	}
	return json.Marshal(&enc)
}

// UnmarshalJSON implements the json.Unmarshler interface
func (k *KeyUsage) UnmarshalJSON(b []byte) error {
	var aux auxKeyUsage
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	// TODO: validate the flags match
	v := int(aux.Value)
	*k = KeyUsage(v)
	return nil
}

type auxSignatureAlgorithm struct {
	Name string      `json:"name,omitempty"`
	OID  pkix.AuxOID `json:"oid"`
}

// MarshalJSON implements the json.Marshaler interface
func (s *SignatureAlgorithm) MarshalJSON() ([]byte, error) {
	aux := auxSignatureAlgorithm{
		Name: s.String(),
	}
	for _, val := range signatureAlgorithmDetails {
		if val.algo == *s {
			aux.OID = make([]int, len(val.oid))
			for idx := range val.oid {
				aux.OID[idx] = val.oid[idx]
			}
		}
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshler interface
func (s *SignatureAlgorithm) UnmarshalJSON(b []byte) error {
	var aux auxSignatureAlgorithm
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*s = UnknownSignatureAlgorithm
	oid := asn1.ObjectIdentifier(aux.OID.AsSlice())
	for _, val := range signatureAlgorithmDetails {
		if val.oid.Equal(oid) {
			*s = val.algo
			break
		}
	}
	return nil
}

type auxPublicKeyAlgorithm struct {
	Name string      `json:"name,omitempty"`
	OID  pkix.AuxOID `json:"oid,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface
func (p *PublicKeyAlgorithm) MarshalJSON() ([]byte, error) {
	aux := auxPublicKeyAlgorithm{
		Name: p.String(),
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (p *PublicKeyAlgorithm) UnmarshalJSON(b []byte) error {
	var aux auxPublicKeyAlgorithm
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	panic("unimplemented")
}

func clampTime(t time.Time) time.Time {
	if t.Before(kMinTime) {
		return kMinTime
	}
	if t.After(kMaxTime) {
		return kMaxTime
	}
	return t
}

type auxValidity struct {
	Start          string `json:"start"`
	End            string `json:"end"`
	ValidityPeriod int    `json:"length"`
}

func (v *validity) MarshalJSON() ([]byte, error) {
	aux := auxValidity{
		Start:          clampTime(v.NotBefore.UTC()).Format(time.RFC3339),
		End:            clampTime(v.NotAfter.UTC()).Format(time.RFC3339),
		ValidityPeriod: int(v.NotAfter.Sub(v.NotBefore).Seconds()),
	}
	return json.Marshal(&aux)
}

func (v *validity) UnmarshalJSON(b []byte) error {
	var aux auxValidity
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	var err error
	if v.NotBefore, err = time.Parse(time.RFC3339, aux.Start); err != nil {
		return err
	}
	if v.NotAfter, err = time.Parse(time.RFC3339, aux.End); err != nil {
		return err
	}

	return nil
}

type jsonSubjectKeyInfo struct {
	KeyAlgorithm    PublicKeyAlgorithm     `json:"key_algorithm"`
	RSAPublicKey    *jsonKeys.RSAPublicKey `json:"rsa_public_key,omitempty"`
	DSAPublicKey    interface{}            `json:"dsa_public_key,omitempty"`
	ECDSAPublicKey  interface{}            `json:"ecdsa_public_key,omitempty"`
	SPKIFingerprint CertificateFingerprint `json:"fingerprint_sha256"`
}

type jsonSignature struct {
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	Value              []byte             `json:"value"`
	Valid              bool               `json:"valid"`
	SelfSigned         bool               `json:"self_signed"`
}

type fullValidity struct {
	validity
	ValidityPeriod int
}

type jsonCertificate struct {
	Version                   int                          `json:"version"`
	SerialNumber              string                       `json:"serial_number"`
	SignatureAlgorithm        SignatureAlgorithm           `json:"signature_algorithm"`
	Issuer                    pkix.Name                    `json:"issuer"`
	IssuerDN                  string                       `json:"issuer_dn,omitempty"`
	Validity                  fullValidity                 `json:"validity"`
	Subject                   pkix.Name                    `json:"subject"`
	SubjectDN                 string                       `json:"subject_dn,omitempty"`
	SubjectKeyInfo            jsonSubjectKeyInfo           `json:"subject_key_info"`
	Extensions                *CertificateExtensions       `json:"extensions,omitempty"`
	UnknownExtensions         UnknownCertificateExtensions `json:"unknown_extensions,omitempty"`
	Signature                 jsonSignature                `json:"signature"`
	FingerprintMD5            CertificateFingerprint       `json:"fingerprint_md5"`
	FingerprintSHA1           CertificateFingerprint       `json:"fingerprint_sha1"`
	FingerprintSHA256         CertificateFingerprint       `json:"fingerprint_sha256"`
	FingerprintNoCT           CertificateFingerprint       `json:"tbs_noct_fingerprint"`
	SPKISubjectFingerprint    CertificateFingerprint       `json:"spki_subject_fingerprint"`
	TBSCertificateFingerprint CertificateFingerprint       `json:"tbs_fingerprint"`
	ValidationLevel           CertValidationLevel          `json:"validation_level"`
	Names                     []string                     `json:"names,omitempty"`
	Redacted                  bool                         `json:"redacted"`
}

func AddECDSAPublicKeyToKeyMap(keyMap map[string]interface{}, key *ecdsa.PublicKey) {
	params := key.Params()
	keyMap["p"] = params.P.Bytes()
	keyMap["n"] = params.N.Bytes()
	keyMap["b"] = params.B.Bytes()
	keyMap["gx"] = params.Gx.Bytes()
	keyMap["gy"] = params.Gy.Bytes()
	keyMap["x"] = key.X.Bytes()
	keyMap["y"] = key.Y.Bytes()
	keyMap["curve"] = key.Curve.Params().Name
	keyMap["length"] = key.Curve.Params().BitSize
}

func AddDSAPublicKeyToKeyMap(keyMap map[string]interface{}, key *dsa.PublicKey) {
	keyMap["p"] = key.P.Bytes()
	keyMap["q"] = key.Q.Bytes()
	keyMap["g"] = key.G.Bytes()
	keyMap["y"] = key.Y.Bytes()
}

func (c *Certificate) MarshalJSON() ([]byte, error) {
	// Fill out the certificate
	jc := new(jsonCertificate)
	jc.Version = c.Version
	jc.SerialNumber = c.SerialNumber.String()
	jc.SignatureAlgorithm = c.SignatureAlgorithm
	jc.Issuer = c.Issuer
	jc.IssuerDN = c.Issuer.String()

	jc.Validity.NotBefore = c.NotBefore
	jc.Validity.NotAfter = c.NotAfter
	jc.Validity.ValidityPeriod = c.ValidityPeriod
	jc.Subject = c.Subject
	jc.SubjectDN = c.Subject.String()
	jc.SubjectKeyInfo.KeyAlgorithm = c.PublicKeyAlgorithm

	if isValidName(c.Subject.CommonName) {
		jc.Names = append(jc.Names, c.Subject.CommonName)
	}

	for _, name := range c.DNSNames {
		if isValidName(name) {
			jc.Names = append(jc.Names, name)
		} else if !strings.Contains(name, ".") { //just a TLD
			jc.Names = append(jc.Names, name)
		}

	}

	for _, name := range c.URIs {
		if govalidator.IsURL(name) {
			jc.Names = append(jc.Names, name)
		}
	}

	for _, name := range c.IPAddresses {
		str := name.String()
		if govalidator.IsURL(str) {
			jc.Names = append(jc.Names, str)
		}
	}

	jc.Names = purgeNameDuplicates(jc.Names)
	jc.Redacted = false
	for _, name := range jc.Names {
		if strings.HasPrefix(name, "?") {
			jc.Redacted = true
		}
	}

	// Pull out the key
	keyMap := make(map[string]interface{})

	jc.SubjectKeyInfo.SPKIFingerprint = c.SPKIFingerprint
	switch key := c.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaKey := new(jsonKeys.RSAPublicKey)
		rsaKey.PublicKey = key
		jc.SubjectKeyInfo.RSAPublicKey = rsaKey
	case *dsa.PublicKey:
		AddDSAPublicKeyToKeyMap(keyMap, key)
		jc.SubjectKeyInfo.DSAPublicKey = keyMap
	case *ecdsa.PublicKey:
		AddECDSAPublicKeyToKeyMap(keyMap, key)
		jc.SubjectKeyInfo.ECDSAPublicKey = keyMap
	case *AugmentedECDSA:
		pub := key.Pub
		keyMap["pub"] = key.Raw.Bytes
		params := pub.Params()
		keyMap["p"] = params.P.Bytes()
		keyMap["n"] = params.N.Bytes()
		keyMap["b"] = params.B.Bytes()
		keyMap["gx"] = params.Gx.Bytes()
		keyMap["gy"] = params.Gy.Bytes()
		keyMap["x"] = pub.X.Bytes()
		keyMap["y"] = pub.Y.Bytes()
		keyMap["curve"] = pub.Curve.Params().Name
		keyMap["length"] = pub.Curve.Params().BitSize

		//keyMap["asn1_oid"] = c.SignatureAlgorithmOID.String()

		jc.SubjectKeyInfo.ECDSAPublicKey = keyMap
	}

	jc.Extensions, jc.UnknownExtensions = c.jsonifyExtensions()

	// TODO: Handle the fact this might not match
	jc.Signature.SignatureAlgorithm = jc.SignatureAlgorithm
	jc.Signature.Value = c.Signature
	jc.Signature.Valid = c.validSignature
	jc.Signature.SelfSigned = c.SelfSigned
	jc.FingerprintMD5 = c.FingerprintMD5
	jc.FingerprintSHA1 = c.FingerprintSHA1
	jc.FingerprintSHA256 = c.FingerprintSHA256
	jc.FingerprintNoCT = c.FingerprintNoCT
	jc.SPKISubjectFingerprint = c.SPKISubjectFingerprint
	jc.TBSCertificateFingerprint = c.TBSCertificateFingerprint
	jc.ValidationLevel = c.ValidationLevel

	return json.Marshal(jc)
}

func purgeNameDuplicates(names []string) (out []string) {
	hashset := make(map[string]bool, len(names))
	for _, name := range names {
		if _, inc := hashset[name]; !inc {
			hashset[name] = true
		}
	}

	out = make([]string, 0, len(hashset))
	for key := range hashset {
		out = append(out, key)
	}
	return
}

func isValidName(name string) (ret bool) {

	// Check for wildcards and redacts, ignore malformed urls
	if strings.HasPrefix(name, "?.") || strings.HasPrefix(name, "*.") {
		ret = isValidName(name[2:])
	} else {
		ret = govalidator.IsURL(name)
	}
	return
}

func orMask(ip net.IP, mask net.IPMask) net.IP {
	if len(ip) == 0 || len(mask) == 0 {
		return nil
	}
	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return nil
	}
	if len(ip) != len(mask) {
		return nil
	}
	out := make([]byte, len(ip))
	for idx := range ip {
		out[idx] = ip[idx] | mask[idx]
	}
	return out
}

func invertMask(mask net.IPMask) net.IPMask {
	if mask == nil {
		return nil
	}
	out := make([]byte, len(mask))
	for idx := range mask {
		out[idx] = ^mask[idx]
	}
	return out
}

type auxGeneralSubtreeIP struct {
	CIDR  string `json:"cidr,omitempty"`
	Begin string `json:"begin,omitempty"`
	End   string `json:"end,omitempty"`
	Mask  string `json:"mask,omitempty"`
}

func (g *GeneralSubtreeIP) MarshalJSON() ([]byte, error) {
	aux := auxGeneralSubtreeIP{}
	aux.CIDR = g.Data.String()
	// Check to see if the subnet is valid. An invalid subnet will return 0,0
	// from Size(). If the subnet is invalid, only output the CIDR.
	ones, bits := g.Data.Mask.Size()
	if ones == 0 && bits == 0 {
		return json.Marshal(&aux)
	}
	// The first IP in the range should be `ip & mask`.
	begin := g.Data.IP.Mask(g.Data.Mask)
	if begin != nil {
		aux.Begin = begin.String()
	}
	// The last IP (inclusive) is `ip & (^mask)`.
	inverseMask := invertMask(g.Data.Mask)
	end := orMask(g.Data.IP, inverseMask)
	if end != nil {
		aux.End = end.String()
	}
	// Output the mask as an IP, but enforce it can be formatted correctly.
	// net.IP.String() only works on byte arrays of the correct length.
	maskLen := len(g.Data.Mask)
	if maskLen == net.IPv4len || maskLen == net.IPv6len {
		maskAsIP := net.IP(g.Data.Mask)
		aux.Mask = maskAsIP.String()
	}
	return json.Marshal(&aux)
}

func (g *GeneralSubtreeIP) UnmarshalJSON(b []byte) error {
	aux := auxGeneralSubtreeIP{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	ip, ipNet, err := net.ParseCIDR(aux.CIDR)
	if err != nil {
		return err
	}
	g.Data.IP = ip
	g.Data.Mask = ipNet.Mask
	g.Min = 0
	g.Max = 0
	return nil
}
