// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mail

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/smtp"
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
)

// Mailer provides the interface for a mailer
type Mailer interface {
	SendMail([]string, string, string) error
}

// MailerImpl defines a mail transfer agent to use for sending mail
type MailerImpl struct {
	Server string
	Port   string
	Auth   smtp.Auth
	From   string
	clk    clock.Clock
}

// New constructs a Mailer to represent an account on a particular mail
// transfer agent.
func New(server, port, username, password string) MailerImpl {
	auth := smtp.PlainAuth("", username, password, server)
	return MailerImpl{
		Server: server,
		Port:   port,
		Auth:   auth,
		From:   username,
		clk:    clock.Default(),
	}
}

var maxBigInt = big.NewInt(1000000000) // idk

func (m *MailerImpl) generateMessage(to []string, subject, body string) ([]byte, error) {
	mid, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		return nil, err
	}
	now := m.clk.Now().UTC()
	headers := []string{
		fmt.Sprintf("To: %s", strings.Join(to, ", ")),
		fmt.Sprintf("From: %s", m.From),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Date: %s", now.Format("Mon Jan 2 2006 15:04:05 -0700")),
		fmt.Sprintf("Message-Id: <%s.%s.%s>", now.Format("20060102T150405"), mid.String(), m.From),
	}
	return []byte(fmt.Sprintf("%s\r\n\r\n%s\r\n", strings.Join(headers, "\r\n"), body)), nil
}

// SendMail sends an email to the provided list of recipients. The email body
// is simple text.
func (m *MailerImpl) SendMail(to []string, subject, msg string) error {
	body, err := m.generateMessage(to, subject, msg)
	if err != nil {
		return err
	}
	return smtp.SendMail(
		net.JoinHostPort(m.Server, m.Port),
		m.Auth,
		m.From,
		to,
		body,
	)
}
