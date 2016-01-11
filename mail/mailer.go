// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mail

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
)

type idGenerator interface {
	generate() *big.Int
}

var maxBigInt = big.NewInt(math.MaxInt64)

type realSource struct{}

func (s realSource) generate() *big.Int {
	randInt, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		panic(err)
	}
	return randInt
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
	csprgSource idGenerator
}

func isASCII(str string) bool {
	for _, r := range str {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// New constructs a Mailer to represent an account on a particular mail
// transfer agent.
func New(server, port, username, password, from string) MailerImpl {
	auth := smtp.PlainAuth("", username, password, server)
	return MailerImpl{
		Server:      server,
		Port:        port,
		Auth:        auth,
		From:        from,
		clk:         clock.Default(),
		csprgSource: realSource{},
	}
}

func (m *MailerImpl) generateMessage(to []string, subject, body string) ([]byte, error) {
	mid := m.csprgSource.generate()
	now := m.clk.Now().UTC()
	addrs := []string{}
	for _, a := range to {
		if !isASCII(a) {
			return nil, fmt.Errorf("Non-ASCII email address")
		}
		addrs = append(addrs, strconv.Quote(a))
	}
	headers := []string{
		fmt.Sprintf("To: %s", strings.Join(addrs, ", ")),
		fmt.Sprintf("From: %s", m.From),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Date: %s", now.Format(time.RFC822)),
		fmt.Sprintf("Message-Id: <%s.%s.%s>", now.Format("20060102T150405"), mid.String(), m.From),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: quoted-printable",
	}
	for i := range headers[1:] {
		// strip LFs
		headers[i] = strings.Replace(headers[i], "\n", "", -1)
	}
	bodyBuf := new(bytes.Buffer)
	mimeWriter := quotedprintable.NewWriter(bodyBuf)
	_, err := mimeWriter.Write([]byte(body))
	if err != nil {
		return nil, err
	}
	err = mimeWriter.Close()
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(
		"%s\r\n\r\n%s\r\n",
		strings.Join(headers, "\r\n"),
		bodyBuf.String(),
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
