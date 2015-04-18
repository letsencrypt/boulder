package mailer

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
