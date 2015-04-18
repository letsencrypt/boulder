// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mail

import (
	"net/smtp"
)

type Mailer struct {
	server string
	port   string
	auth   smtp.Auth
	from   string
}

func NewMailer(server, port, username, password string) Mailer {
	auth := smtp.PlainAuth("", username, password, server)
	return Mailer{
		server: server,
		port: port,
		auth: auth,
		from: username,
	}
}

func (m *Mailer) SendMail(to []string, msg string) (err error) {
	err = smtp.SendMail(m.server+":"+m.port, m.auth, m.from, to, []byte(msg))
	return
}
