// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mocks

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"

	"github.com/letsencrypt/boulder/core"
)

// MockDNS is a mock
type MockDNS struct {
}

// ExchangeOne is a mock
func (mock *MockDNS) ExchangeOne(hostname string, qt uint16) (rsp *dns.Msg, rtt time.Duration, err error) {
	return nil, 0, nil
}

// LookupTXT is a mock
func (mock *MockDNS) LookupTXT(hostname string) ([]string, time.Duration, error) {
	if hostname == "_acme-challenge.servfail.com" {
		return nil, 0, fmt.Errorf("SERVFAIL")
	}
	return []string{"hostname"}, 0, nil
}

// LookupHost is a mock
func (mock *MockDNS) LookupHost(hostname string) ([]net.IP, time.Duration, error) {
	if hostname == "always.invalid" || hostname == "invalid.invalid" {
		return []net.IP{}, 0, nil
	}
	ip := net.ParseIP("127.0.0.1")
	return []net.IP{ip}, 0, nil
}

// LookupCNAME is a mock
func (mock *MockDNS) LookupCNAME(domain string) (string, time.Duration, error) {
	switch strings.TrimRight(domain, ".") {
	case "cname-absent.com":
		return "absent.com.", 30, nil
	case "cname-critical.com":
		return "critical.com.", 30, nil
	case "cname-present.com", "cname-and-dname.com":
		return "cname-target.present.com.", 30, nil
	case "cname2-present.com":
		return "cname-present.com.", 30, nil
	case "a.cname-loop.com":
		return "b.cname-loop.com.", 30, nil
	case "b.cname-loop.com":
		return "a.cname-loop.com.", 30, nil
	case "www.caa-loop.com":
		// nothing wrong with CNAME, but prevents CAA algorithm from terminating
		return "oops.www.caa-loop.com.", 30, nil
	case "cname2servfail.com":
		return "servfail.com.", 30, nil
	case "cname-servfail.com":
		return "", 0, fmt.Errorf("SERVFAIL")
	case "cname2dname.com":
		return "dname2cname.com.", 30, nil
	default:
		return "", 0, nil
	}
}

// LookupDNAME is a mock
func (mock *MockDNS) LookupDNAME(domain string) (string, time.Duration, error) {
	switch strings.TrimRight(domain, ".") {
	case "cname-and-dname.com", "dname-present.com":
		return "dname-target.present.com.", time.Minute, nil
	case "a.dname-loop.com":
		return "b.dname-loop.com.", time.Minute, nil
	case "b.dname-loop.com":
		return "a.dname-loop.com.", time.Minute, nil
	case "dname2cname.com":
		return "cname2-present.com.", time.Minute, nil
	case "dname-servfail.com":
		return "", time.Minute, fmt.Errorf("SERVFAIL")
	default:
		return "", 0, nil
	}
}

// LookupCAA is a mock
func (mock *MockDNS) LookupCAA(domain string) ([]*dns.CAA, time.Duration, error) {
	var results []*dns.CAA
	var record dns.CAA
	switch strings.TrimRight(domain, ".") {
	case "reserved.com":
		record.Tag = "issue"
		record.Value = "symantec.com"
		results = append(results, &record)
	case "critical.com":
		record.Flag = 1
		record.Tag = "issue"
		record.Value = "symantec.com"
		results = append(results, &record)
	case "present.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org"
		results = append(results, &record)
	case "servfail.com":
		return results, 0, fmt.Errorf("SERVFAIL")
	}
	return results, 0, nil
}

// LookupMX is a mock
func (mock *MockDNS) LookupMX(domain string) ([]string, time.Duration, error) {
	switch strings.TrimRight(domain, ".") {
	case "letsencrypt.org":
		fallthrough
	case "email.com":
		return []string{"mail.email.com"}, 0, nil
	}
	return nil, 0, nil
}

// MockSA is a mock
type MockSA struct {
	authorizedDomains map[string]bool
}

const (
	test1KeyPublicJSON = `
{
	"kty":"RSA",
	"n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
	"e":"AAEAAQ"
}`
	test2KeyPublicJSON = `{
		"kty":"RSA",
		"n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw",
		"e":"AAEAAQ"
	}`
	agreementURL = "http://example.invalid/terms"
)

// GetRegistration is a mock
func (sa *MockSA) GetRegistration(id int64) (core.Registration, error) {
	if id == 100 {
		// Tag meaning "Missing"
		return core.Registration{}, errors.New("missing")
	}
	if id == 101 {
		// Tag meaning "Malformed"
		return core.Registration{}, nil
	}

	keyJSON := []byte(test1KeyPublicJSON)
	var parsedKey jose.JsonWebKey
	parsedKey.UnmarshalJSON(keyJSON)

	return core.Registration{ID: id, Key: parsedKey, Agreement: agreementURL}, nil
}

// GetRegistrationByKey is a mock
func (sa *MockSA) GetRegistrationByKey(jwk jose.JsonWebKey) (core.Registration, error) {
	var test1KeyPublic jose.JsonWebKey
	var test2KeyPublic jose.JsonWebKey
	test1KeyPublic.UnmarshalJSON([]byte(test1KeyPublicJSON))
	test2KeyPublic.UnmarshalJSON([]byte(test2KeyPublicJSON))

	if core.KeyDigestEquals(jwk, test1KeyPublic) {
		return core.Registration{ID: 1, Key: jwk, Agreement: agreementURL}, nil
	}

	if core.KeyDigestEquals(jwk, test2KeyPublic) {
		// No key found
		return core.Registration{ID: 2}, core.NoSuchRegistrationError("reg not found")
	}

	// Return a fake registration. Make sure to fill the key field to avoid marshaling errors.
	return core.Registration{ID: 1, Key: test1KeyPublic, Agreement: agreementURL}, nil
}

// GetAuthorization is a mock
func (sa *MockSA) GetAuthorization(id string) (core.Authorization, error) {
	if id == "valid" {
		exp := time.Now().AddDate(100, 0, 0)
		return core.Authorization{
			ID:             "valid",
			Status:         core.StatusValid,
			RegistrationID: 1,
			Expires:        &exp,
			Identifier:     core.AcmeIdentifier{Type: "dns", Value: "not-an-example.com"},
			Challenges: []core.Challenge{
				core.Challenge{
					ID:   23,
					Type: "dns",
					URI:  "http://localhost:4300/acme/challenge/valid/23",
				},
			},
		}, nil
	}
	return core.Authorization{}, nil
}

// GetCertificate is a mock
func (sa *MockSA) GetCertificate(serial string) (core.Certificate, error) {
	// Serial ee == 238.crt
	if serial == "0000000000000000000000000000000000ee" {
		certPemBytes, _ := ioutil.ReadFile("test/238.crt")
		certBlock, _ := pem.Decode(certPemBytes)
		return core.Certificate{
			RegistrationID: 1,
			DER:            certBlock.Bytes,
		}, nil
	} else if serial == "0000000000000000000000000000000000b2" {
		certPemBytes, _ := ioutil.ReadFile("test/178.crt")
		certBlock, _ := pem.Decode(certPemBytes)
		return core.Certificate{
			RegistrationID: 1,
			DER:            certBlock.Bytes,
		}, nil
	} else {
		return core.Certificate{}, errors.New("No cert")
	}
}

// GetCertificateStatus is a mock
func (sa *MockSA) GetCertificateStatus(serial string) (core.CertificateStatus, error) {
	// Serial ee == 238.crt
	if serial == "0000000000000000000000000000000000ee" {
		return core.CertificateStatus{
			Status: core.OCSPStatusGood,
		}, nil
	} else if serial == "0000000000000000000000000000000000b2" {
		return core.CertificateStatus{
			Status: core.OCSPStatusRevoked,
		}, nil
	} else {
		return core.CertificateStatus{}, errors.New("No cert status")
	}
}

// AlreadyDeniedCSR is a mock
func (sa *MockSA) AlreadyDeniedCSR([]string) (bool, error) {
	return false, nil
}

// AddCertificate is a mock
func (sa *MockSA) AddCertificate(certDER []byte, regID int64) (digest string, err error) {
	return
}

// FinalizeAuthorization is a mock
func (sa *MockSA) FinalizeAuthorization(authz core.Authorization) (err error) {
	return
}

// MarkCertificateRevoked is a mock
func (sa *MockSA) MarkCertificateRevoked(serial string, ocspResponse []byte, reasonCode core.RevocationCode) (err error) {
	return
}

// UpdateOCSP is a mock
func (sa *MockSA) UpdateOCSP(serial string, ocspResponse []byte) (err error) {
	return
}

// NewPendingAuthorization is a mock
func (sa *MockSA) NewPendingAuthorization(authz core.Authorization) (output core.Authorization, err error) {
	return
}

// NewRegistration is a mock
func (sa *MockSA) NewRegistration(reg core.Registration) (regR core.Registration, err error) {
	return
}

// UpdatePendingAuthorization is a mock
func (sa *MockSA) UpdatePendingAuthorization(authz core.Authorization) (err error) {
	return
}

// UpdateRegistration is a mock
func (sa *MockSA) UpdateRegistration(reg core.Registration) (err error) {
	return
}

// GetSCTReceipt  is a mock
func (sa *MockSA) GetSCTReceipt(serial string, logID string) (sct core.SignedCertificateTimestamp, err error) {
	return
}

// AddSCTReceipt is a mock
func (sa *MockSA) AddSCTReceipt(sct core.SignedCertificateTimestamp) (err error) {
	if sct.Signature == nil {
		err = fmt.Errorf("Bad times")
	}
	return
}

// GetLatestValidAuthorization is a mock
func (sa *MockSA) GetLatestValidAuthorization(registrationId int64, identifier core.AcmeIdentifier) (authz core.Authorization, err error) {
	if registrationId == 1 && identifier.Type == "dns" {
		if sa.authorizedDomains[identifier.Value] || identifier.Value == "not-an-example.com" {
			exp := time.Now().AddDate(100, 0, 0)
			return core.Authorization{Status: core.StatusValid, RegistrationID: 1, Expires: &exp, Identifier: identifier}, nil
		}
	}
	return core.Authorization{}, errors.New("no authz")
}

// CountCertificatesRange is a mock
func (sa *MockSA) CountCertificatesRange(_, _ time.Time) (int64, error) {
	return 0, nil
}

// CountCertificatesByNames is a mock
func (sa *MockSA) CountCertificatesByNames(_ []string, _, _ time.Time) (ret map[string]int, err error) {
	return
}

// MockPublisher is a mock
type MockPublisher struct {
	// empty
}

// SubmitToCT is a mock
func (*MockPublisher) SubmitToCT([]byte) error {
	return nil
}
