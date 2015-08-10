// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mail

import (
	"net"
	"net/smtp"
)

// Mailer provides the interface for a mailer
type Mailer interface {
	SendMail([]string, string) error
}

// MailerImpl defines a mail transfer agent to use for sending mail
type MailerImpl struct {
	Server string
	Port   string
	Auth   smtp.Auth
	From   string
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
	}
}

// SendMail sends an email to the provided list of recipients. The email body
// is simple text.
func (m *MailerImpl) SendMail(to []string, msg string) (err error) {
	err = smtp.SendMail(net.JoinHostPort(m.Server, m.Port), m.Auth, m.From, to, []byte(msg))
	return
}
