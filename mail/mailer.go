// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mail

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/smtp"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
)

type csprg interface {
	Int(io.Reader, *big.Int) (*big.Int, error)
}

type realSource struct{}

func (s realSource) Int(reader io.Reader, max *big.Int) (*big.Int, error) {
	return rand.Int(reader, max)
}

// Mailer provides the interface for a mailer
type Mailer interface {
	SendMail([]string, string, string) error
}

// MailerImpl defines a mail transfer agent to use for sending mail
type MailerImpl struct {
	Server      string
	Port        string
	Auth        smtp.Auth
	From        string
	clk         clock.Clock
	csprgSource csprg
}

// New constructs a Mailer to represent an account on a particular mail
// transfer agent.
func New(server, port, username, password string) MailerImpl {
	auth := smtp.PlainAuth("", username, password, server)
	return MailerImpl{
		Server:      server,
		Port:        port,
		Auth:        auth,
		From:        username,
		clk:         clock.Default(),
		csprgSource: realSource{},
	}
}

var maxBigInt = big.NewInt(math.MaxInt64) // ???

func (m *MailerImpl) generateMessage(to []string, subject, body string) ([]byte, error) {
	mid, err := m.csprgSource.Int(rand.Reader, maxBigInt)
	if err != nil {
		return nil, err
	}
	now := m.clk.Now().UTC()
	addrs := []string{}
	for _, a := range to {
		addrs = append(addrs, strconv.QuoteToASCII(a))
	}
	headers := []string{
		fmt.Sprintf("To: %s", strings.Join(addrs, ", ")),
		fmt.Sprintf("From: %s", m.From),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Date: %s", now.Format("Mon Jan 2 2006 15:04:05 -0700")),
		fmt.Sprintf("Message-Id: <%s.%s.%s>", now.Format("20060102T150405"), mid.String(), m.From),
	}
	for _, h := range headers[1:] {
		quoted := strconv.QuoteToASCII(h)
		h = quoted[1 : len(quoted)-1] // remove forced "" quotes
	}
	quotedBody := strconv.QuoteToASCII(body)
	return []byte(fmt.Sprintf(
		"%s\r\n\r\n%s\r\n",
		strings.Join(headers, "\r\n"),
		quotedBody[1:len(quotedBody)-1],
	)), nil
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
