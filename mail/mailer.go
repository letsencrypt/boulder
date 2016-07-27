package mail

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
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
	Connect() error
	Close() error
}

// MailerImpl defines a mail transfer agent to use for sending mail. It is not
// safe for concurrent access.
type MailerImpl struct {
	log         blog.Logger
	dialer      dialer
	from        mail.Address
	client      smtpClient
	clk         clock.Clock
	csprgSource idGenerator
	stats       *metrics.StatsdScope
}

type dialer interface {
	Dial() (smtpClient, error)
}

type smtpClient interface {
	Mail(string) error
	Rcpt(string) error
	Data() (io.WriteCloser, error)
	Close() error
}

type dryRunClient struct {
	log blog.Logger
}

func (d dryRunClient) Dial() (smtpClient, error) {
	return d, nil
}

func (d dryRunClient) Mail(from string) error {
	d.log.Debug(fmt.Sprintf("MAIL FROM:<%s>", from))
	return nil
}

func (d dryRunClient) Rcpt(to string) error {
	d.log.Debug(fmt.Sprintf("RCPT TO:<%s>", to))
	return nil
}

func (d dryRunClient) Close() error {
	return nil
}

func (d dryRunClient) Data() (io.WriteCloser, error) {
	return d, nil
}

func (d dryRunClient) Write(p []byte) (n int, err error) {
	d.log.Debug(fmt.Sprintf("data: %s", string(p)))
	return len(p), nil
}

// New constructs a Mailer to represent an account on a particular mail
// transfer agent.
func New(
	server,
	port,
	username,
	password string,
	from mail.Address,
	logger blog.Logger,
	stats statsd.Statter) *MailerImpl {
	return &MailerImpl{
		dialer: &dialerImpl{
			username: username,
			password: password,
			server:   server,
			port:     port,
		},
		log:         logger,
		from:        from,
		clk:         clock.Default(),
		csprgSource: realSource{},
		stats:       metrics.NewStatsdScope(stats, "Mailer"),
	}
}

// New constructs a Mailer suitable for doing a dry run. It simply logs each
// command that would have been run, at debug level.
func NewDryRun(from mail.Address, logger blog.Logger) *MailerImpl {
	return &MailerImpl{
		dialer:      dryRunClient{logger},
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
		if !core.IsASCII(a) {
			return nil, fmt.Errorf("Non-ASCII email address")
		}
		addrs = append(addrs, strconv.Quote(a))
	}
	headers := []string{
		fmt.Sprintf("To: %s", strings.Join(addrs, ", ")),
		fmt.Sprintf("From: %s", m.from.String()),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Date: %s", now.Format(time.RFC822)),
		fmt.Sprintf("Message-Id: <%s.%s.%s>", now.Format("20060102T150405"), mid.String(), m.from.Address),
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
	client, err := m.dialer.Dial()
	if err != nil {
		return err
	}
	m.client = client
	return nil
}

type dialerImpl struct {
	username, password, server, port string
}

func (di *dialerImpl) Dial() (smtpClient, error) {
	hostport := net.JoinHostPort(di.server, di.port)
	var conn net.Conn
	var err error
	// By convention, port 465 is TLS-wrapped SMTP, while 587 is plaintext SMTP
	// (with STARTTLS as best-effort).
	if di.port == "465" {
		conn, err = tls.Dial("tcp", hostport, nil)
	} else {
		conn, err = net.Dial("tcp", hostport)
	}
	if err != nil {
		return nil, err
	}
	client, err := smtp.NewClient(conn, di.server)
	if err != nil {
		return nil, err
	}
	auth := smtp.PlainAuth("", di.username, di.password, di.server)
	if err = client.Auth(auth); err != nil {
		return nil, err
	}
	return client, nil
}

func (m *MailerImpl) sendOne(to []string, subject, msg string) error {
	if m.client == nil {
		return errors.New("call Connect before SendMail")
	}
	body, err := m.generateMessage(to, subject, msg)
	if err != nil {
		return err
	}
	if err = m.client.Mail(m.from.String()); err != nil {
		return err
	}
	for _, t := range to {
		if err = m.client.Rcpt(t); err != nil {
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

// SendMail sends an email to the provided list of recipients. The email body
// is simple text.
func (m *MailerImpl) SendMail(to []string, subject, msg string) error {
	m.stats.Inc("SendMail.Attempts", 1)

	err := m.sendOne(to, subject, msg)
	if err != nil {
		m.stats.Inc("SendMail.Errors", 1)
		return err
	}

	m.stats.Inc("SendMail.Successes", 1)
	return nil
}

// Close closes the connection.
func (m *MailerImpl) Close() error {
	if m.client == nil {
		return errors.New("call Connect before Close")
	}
	return m.client.Close()
}
