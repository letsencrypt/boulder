// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/url"
	"testing"
	"text/template"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
)

type mockMail struct {
	Messages []string
}

func (m *mockMail) Clear() {
	m.Messages = []string{}
}

func (m *mockMail) SendMail(to []string, msg string) (err error) {
	m.Messages = append(m.Messages, msg)
	return
}

const testTmpl = `hi, cert for common name {{.CommonName}} (and DNSNames {{.DNSNames}}) is going to expire in {{.DaysToExpiration}} days ({{.ExpirationDate}})`

func TestSendWarning(t *testing.T) {
	tmpl, err := template.New("expiry-email").Parse(testTmpl)
	test.AssertNotError(t, err, "Couldn't parse test email template")
	stats, _ := statsd.NewNoopClient(nil)
	mc := mockMail{}
	m := mailer{
		stats:         stats,
		Mailer:        &mc,
		EmailTemplate: tmpl,
	}

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy",
		},
		NotAfter: time.Now().AddDate(0, 0, 2),
		DNSNames: []string{"example.com"},
	}

	email, _ := url.Parse("mailto:rolandshoemaker@gmail.com")
	emailB, _ := url.Parse("mailto:test@gmail.com")

	err = m.sendWarning(cert, []core.AcmeURL{core.AcmeURL(*email)})
	test.AssertNotError(t, err, "Failed to send warning messages")
	test.AssertEquals(t, len(mc.Messages), 1)
	test.AssertEquals(t, fmt.Sprintf(`hi, cert for common name happy (and DNSNames example.com) is going to expire in 1 days (%s)`, cert.NotAfter), mc.Messages[0])

	err = m.sendWarning(cert, []core.AcmeURL{core.AcmeURL(*email), core.AcmeURL(*emailB)})
	test.AssertNotError(t, err, "Failed to send warning messages")
	test.AssertEquals(t, len(mc.Messages), 2)
	test.AssertEquals(t, fmt.Sprintf(`hi, cert for common name happy (and DNSNames example.com) is going to expire in 1 days (%s)`, cert.NotAfter), mc.Messages[0])
	test.AssertEquals(t, fmt.Sprintf(`hi, cert for common name happy (and DNSNames example.com) is going to expire in 1 days (%s)`, cert.NotAfter), mc.Messages[1])

	mc.Clear()
	err = m.sendWarning(cert, []core.AcmeURL{})
	test.AssertNotError(t, err, "Not an error to pass no email contacts")
	test.AssertEquals(t, len(mc.Messages), 0)
}
