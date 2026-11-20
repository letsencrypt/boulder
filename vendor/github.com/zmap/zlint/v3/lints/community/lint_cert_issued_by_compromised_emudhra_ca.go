/*
 * ZLint Copyright 2026 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package community

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cert_issued_by_compromised_emudhra_ca",
			Description:   "Certificates signed by one of the eMudhra intermediate CA keys that were compromised are untrustworthy",
			Citation:      compromisedEmudhraBugURL + " (eMudhra: Private key compromise of Intermediate Certificates), comment 0 lists the eight affected intermediates and comment 2 their Sectigo cross-signs",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewCertIssuedByCompromisedEmudhraCA,
	})
}

type certIssuedByCompromisedEmudhraCA struct{}

func NewCertIssuedByCompromisedEmudhraCA() lint.LintInterface {
	return &certIssuedByCompromisedEmudhraCA{}
}

const compromisedEmudhraBugURL = "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449"

// compromisedEmudhraKeys are the public keys of the eight compromised eMudhra
// intermediate CAs, as P-384 (X, Y) coordinates. Each key was certified twice,
// once by the emSign root and once cross-signed by Sectigo, so one entry
// covers both.
var compromisedEmudhraKeys = map[string]*ecdsa.PublicKey{
	"EM EV TLS CA - G3B": p384Key(
		"25dba85a64d397da0b1052e9ea546e487befea9c9d9d68a0c5eadcfeef75a69bb5d6fc01f42bfbca6eb40bcd64c0767e",
		"36ffd05d97a813c5aa0c6c9530e79cf5f0866468f13806420aa5c851840b1e252540e790e4b654c3852ed64af1e8657d"),
	"EM OV TLS CA - G3B": p384Key(
		"73897aa0eb3cfdca8b12402ffaf0abc4e1212baf8dee778ac9ee2d6db83fac280c5e05638ae7a2acd71c322a8e361cde",
		"b9f69c4302b9dd8d73d1cc6caab2cc0aee4e216ce979dd518a4af4b626e5684cdd658037ed0c854e4cc12f4cf8646d0d"),
	"EM DV TLS CA - G3B": p384Key(
		"e79ed9c04a9773c4735e51111da85ac2bd5e64ab374b80e12cbc2038ec1e4f0e3b812fc9859e1e67afb04e2f8bc97f74",
		"85ba65aa911ee8a4e45b62d5cc03d56be678b3c38cb4dc937ca2460e238453c892935d29d44f91e15606b63ccedab468"),
	"EM EV TLS CA - G3C": p384Key(
		"2d56e829a6fb82c64a4697d960af951e9067ae91f926d34306da48a8aaeb7869b6a67e6d27426e0442aa03b36e1988df",
		"f636514ee1cf07f5ba4b3ff2a06645ae7d31d5866ad31aa3d246eb0b3177ee99cb7566c516ce74808a668f91f0c47fca"),
	"EM OV TLS CA - G3C": p384Key(
		"138251cd52ac9298c1c8aad977321deb97e709bd0b4ca0aca55dc8ad51dcfc9d1589a1597e3a5120e1efd631c63e1835",
		"cacae29869a62e1631e8a28181ab56616dc45d918abc09f3ab0e63cf792aa4dced7387be37bba569549f1c02b270ed67"),
	"EM DV TLS CA - G3C": p384Key(
		"3a7a7862c8c44d324ddd69033a6782c0efeefe4055e68a123fa0371ba3bd9194514ee172a433e3630f02bd188037d9e5",
		"149f9b77db94a281df987b2fea888b74bdfe8fda4c1099ee6ca19566fe3ef0e5f6b09a556ccc8ba50561df1b2a441d01"),
	"EM OV CS CA - G3B": p384Key(
		"aabb0fb0666acfcf01fad52bfcfd4c2bf2cb3c3497de73950e5819b61fe695098741c8c491439b34a0431caffe5bf9b4",
		"c1c8e8ae0001f9f4dc8ad82c59f3639e96cd6c3d4db0cefec26c3d62517b37761372743f8e8add77b10064f2abe5e050"),
	"EM OV CS CA - G3C": p384Key(
		"b9f0e0634702a69ca6aadd443cfd62c41b9ba4b20924697d7974e7691a126fb96afb3e34c2fd3bc5f483061f265dc2a5",
		"8436347323510436b28f04f3862363067980e2503e02532d6546235a7165a259a1ef496f741b5fdee7787208e4b8faef"),
}

func p384Key(x, y string) *ecdsa.PublicKey {
	X, _ := new(big.Int).SetString(x, 16)
	Y, _ := new(big.Int).SetString(y, 16)
	return &ecdsa.PublicKey{Curve: elliptic.P384(), X: X, Y: Y}
}

// CheckApplies admits only ECDSA signatures, the only kind these keys can have
// produced. CA certificates are included. Certificates further down a chain are
// not visible to a lint, so only the one signed directly by a key is caught.
func (l *certIssuedByCompromisedEmudhraCA) CheckApplies(c *x509.Certificate) bool {
	switch c.SignatureAlgorithm {
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return true
	}
	return false
}

func (l *certIssuedByCompromisedEmudhraCA) Execute(c *x509.Certificate) *lint.LintResult {
	for name, key := range compromisedEmudhraKeys {
		if x509.CheckSignatureFromKey(key, c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
			return &lint.LintResult{
				Status: lint.Error,
				Details: fmt.Sprintf("signed by the private key of %q, an eMudhra intermediate CA whose private key was compromised; see %s",
					name, compromisedEmudhraBugURL),
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
