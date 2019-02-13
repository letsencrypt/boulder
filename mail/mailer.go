package mail

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

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
	log           blog.Logger
	dialer        dialer
	from          mail.Address
	client        smtpClient
	clk           clock.Clock
	csprgSource   idGenerator
	stats         metrics.Scope
	reconnectBase time.Duration
	reconnectMax  time.Duration
}

type dialer interface {
	Dial() (smtpClient, error)
}

type smtpClient interface {
	Mail(string) error
	Rcpt(string) error
	Data() (io.WriteCloser, error)
	Reset() error
	Close() error
}

type dryRunClient struct {
	log blog.Logger
}

func (d dryRunClient) Dial() (smtpClient, error) {
	return d, nil
}

func (d dryRunClient) Mail(from string) error {
	d.log.Debugf("MAIL FROM:<%s>", from)
	return nil
}

func (d dryRunClient) Rcpt(to string) error {
	d.log.Debugf("RCPT TO:<%s>", to)
	return nil
}

func (d dryRunClient) Close() error {
	return nil
}

func (d dryRunClient) Data() (io.WriteCloser, error) {
	return d, nil
}

func (d dryRunClient) Write(p []byte) (n int, err error) {
	d.log.Debugf("data: %s", string(p))
	return len(p), nil
}

func (d dryRunClient) Reset() (err error) {
	d.log.Debugf("RESET")
	return nil
}

// New constructs a Mailer to represent an account on a particular mail
// transfer agent.
func New(
	server,
	port,
	username,
	password string,
	rootCAs *x509.CertPool,
	from mail.Address,
	logger blog.Logger,
	stats metrics.Scope,
	reconnectBase time.Duration,
	reconnectMax time.Duration) *MailerImpl {
	return &MailerImpl{
		dialer: &dialerImpl{
			username: username,
			password: password,
			server:   server,
			port:     port,
			rootCAs:  rootCAs,
		},
		log:           logger,
		from:          from,
		clk:           clock.Default(),
		csprgSource:   realSource{},
		stats:         stats.NewScope("Mailer"),
		reconnectBase: reconnectBase,
		reconnectMax:  reconnectMax,
	}
}

// New constructs a Mailer suitable for doing a dry run. It simply logs each
// command that would have been run, at debug level.
func NewDryRun(from mail.Address, logger blog.Logger) *MailerImpl {
	stats := metrics.NewNoopScope()
	return &MailerImpl{
		dialer:      dryRunClient{logger},
		from:        from,
		clk:         clock.Default(),
		csprgSource: realSource{},
		stats:       stats,
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

func (m *MailerImpl) reconnect() {
	for i := 0; ; i++ {
		sleepDuration := core.RetryBackoff(i, m.reconnectBase, m.reconnectMax, 2)
		m.log.Infof("sleeping for %s before reconnecting mailer", sleepDuration)
		m.clk.Sleep(sleepDuration)
		m.log.Info("attempting to reconnect mailer")
		err := m.Connect()
		if err != nil {
			m.log.Warningf("reconnect error: %s", err)
			continue
		}
		break
	}
	m.log.Info("reconnected successfully")
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
	rootCAs                          *x509.CertPool
}

func (di *dialerImpl) Dial() (smtpClient, error) {
	hostport := net.JoinHostPort(di.server, di.port)
	var conn net.Conn
	var err error
	conn, err = tls.Dial("tcp", hostport, &tls.Config{
		RootCAs: di.rootCAs,
	})
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

// resetAndError resets the current mail transaction and then returns its
// argument as an error. If the reset command also errors, it combines both
// errors and returns them. Without this we would get `nested MAIL command`.
// https://github.com/letsencrypt/boulder/issues/3191
func (m *MailerImpl) resetAndError(err error) error {
	if err == io.EOF {
		return err
	}
	if err2 := m.client.Reset(); err2 != nil {
		return fmt.Errorf("%s (also, on sending RSET: %s)", err, err2)
	}
	return err
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
			return m.resetAndError(err)
		}
	}
	w, err := m.client.Data()
	if err != nil {
		return m.resetAndError(err)
	}
	_, err = w.Write(body)
	if err != nil {
		return m.resetAndError(err)
	}
	err = w.Close()
	if err != nil {
		return m.resetAndError(err)
	}
	return nil
}

// RecoverableSMTPError is returned by SendMail when the server rejects a message
// but for a reason that doesn't prevent us from continuing to send mail. The
// error message contains the error code and the error message returned from the
// server.
type RecoverableSMTPError struct {
	Message string
}

func (e RecoverableSMTPError) Error() string {
	return e.Message
}

// Based on reading of various SMTP documents these are a handful
// of errors we are likely to be able to continue sending mail after
// receiving. The majority of these errors boil down to 'bad address'.
var recoverableErrorCodes = map[int]bool{
	401: true, // Invalid recipient
	422: true, // Recipient mailbox is full
	441: true, // Recipient server is not responding
	450: true, // User's mailbox is not available
	510: true, // Invalid recipient
	511: true, // Invalid recipient
	513: true, // Address type invalid
	541: true, // Recipient rejected message
	550: true, // Non-existent address
	553: true, // Non-existent address
}

// SendMail sends an email to the provided list of recipients. The email body
// is simple text.
func (m *MailerImpl) SendMail(to []string, subject, msg string) error {
	m.stats.Inc("SendMail.Attempts", 1)

	for {
		err := m.sendOne(to, subject, msg)
		if err == nil {
			// If the error is nil, we sent the mail without issue. nice!
			break
		} else if err == io.EOF {
			// If the error is an EOF, we should try to reconnect on a backoff
			// schedule, sleeping between attempts.
			m.stats.Inc("SendMail.Errors.EOF", 1)
			m.reconnect()
			// After reconnecting, loop around and try `sendOne` again.
			m.stats.Inc("SendMail.Reconnects", 1)
			continue
		} else if err != nil {
			// Check if the err is a textProto.Error. If it is we can handle
			// the error differently based on its SMTP code.
			if protoErr, ok := err.(*textproto.Error); ok {
				/*
				 *  If the error has a SMTP error code of 421 then treat this as
				 *  a reconnect-able event.
				 *
				 *  The SMTP RFC defines this error code as:
				 *   421 <domain> Service not available, closing transmission channel
				 *   (This may be a reply to any command if the service knows it
				 *   must shut down)
				 *
				 * In practice we see this code being used by our production SMTP server
				 * when the connection has gone idle for too long. For more information
				 * see issue #2249[0].
				 *
				 * [0] - https://github.com/letsencrypt/boulder/issues/2249
				 */
				if protoErr.Code == 421 {
					m.stats.Inc("SendMail.Errors.SMTP.421", 1)
					m.reconnect()
					m.stats.Inc("SendMail.Reconnects", 1)
				} else if _, ok := recoverableErrorCodes[protoErr.Code]; ok {
					// Otherwise, if the error code isn't 421 but it is a code we
					// considerable recoverable, then return a recoverable smtp error.
					m.stats.Inc(fmt.Sprintf("SendMail.Errors.SMTP.%d", protoErr.Code), 1)
					return RecoverableSMTPError{fmt.Sprintf("%d: %s", protoErr.Code, protoErr.Msg)}
				} else {
					// The error was a textproto error but its code isn't
					// a recoverableErrorCode.
					m.stats.Inc("SendMail.Errors", 1)
					return err
				}
			} else {
				// If it wasn't a textproto error just return from SendMail() with the
				// error
				m.stats.Inc("SendMail.Errors", 1)
				return err
			}
		}
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
