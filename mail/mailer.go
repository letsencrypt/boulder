// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mail

import (
	"net/smtp"
)

type Mailer struct {
	Server string
	Port   string
	Auth   smtp.Auth
	From   string
}

func NewMailer(server, port, username, password string) Mailer {
	auth := smtp.PlainAuth("", username, password, server)
	return Mailer{
		Server: server,
		Port:   port,
		Auth:   auth,
		From:   username,
	}
}

func (m *Mailer) SendMail(to []string, msg string) (err error) {
	err = smtp.SendMail(m.Server+":"+m.Port, m.Auth, m.From, to, []byte(msg))
	return
}
