// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mail

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
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
	Close() error
}

// MailerImpl defines a mail transfer agent to use for sending mail
type MailerImpl struct {
	server      string
	port        string
	auth        smtp.Auth
	from        string
	client      *smtp.Client
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
		server:      server,
		port:        port,
		auth:        auth,
		from:        from,
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
		fmt.Sprintf("From: %s", m.from),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Date: %s", now.Format(time.RFC822)),
		fmt.Sprintf("Message-Id: <%s.%s.%s>", now.Format("20060102T150405"), mid.String(), m.from),
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

// Connect opens a connection to the specified mail server. It must be called
// before SendMail.
func (m *MailerImpl) Connect() error {
	hostport := net.JoinHostPort(m.server, m.port)
	var conn net.Conn
	var err error
	// By convention, port 465 is TLS-wrapped SMTP, while 587 is plaintext SMTP
	// (with STARTTLS as best-effort).
	if m.port == "465" {
		conn, err = tls.Dial("tcp", hostport, nil)
	} else {
		conn, err = net.Dial("tcp", hostport)
	}
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, m.server)
	if err != nil {
		return err
	}
	if err = client.Auth(m.auth); err != nil {
		return err
	}
	m.client = client
	return nil
}

// SendMail sends an email to the provided list of recipients. The email body
// is simple text.
func (m *MailerImpl) SendMail(to []string, subject, msg string) error {
	if m.client == nil {
		return errors.New("call Connect before SendMail")
	}
	body, err := m.generateMessage(to, subject, msg)
	if err != nil {
		return err
	}
	if m.client.Mail(m.from); err != nil {
		return err
	}
	for _, t := range to {
		if m.client.Rcpt(t); err != nil {
			return err
		}
	}
	w, err := m.client.Data()
	if err != nil {
		return err
	}

	_, err = w.Write(body)
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}
	return nil
}

// Close closes the connection.
func (m *MailerImpl) Close() error {
	if m.client == nil {
		return errors.New("call Connect before Close")
	}
	return m.client.Close()
}
