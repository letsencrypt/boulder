package mail

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

type fakeSource struct{}

func (f fakeSource) generate() *big.Int {
	return big.NewInt(1991)
}

func TestGenerateMessage(t *testing.T) {
	fc := clock.NewFake()
	stats := metrics.NewNoopScope()
	fromAddress, _ := mail.ParseAddress("happy sender <send@email.com>")
	log := blog.UseMock()
	m := New("", "", "", "", nil, *fromAddress, log, stats, 0, 0)
	m.clk = fc
	m.csprgSource = fakeSource{}
	messageBytes, err := m.generateMessage([]string{"recv@email.com"}, "test subject", "this is the body\n")
	test.AssertNotError(t, err, "Failed to generate email body")
	message := string(messageBytes)
	fields := strings.Split(message, "\r\n")
	test.AssertEquals(t, len(fields), 12)
	fmt.Println(message)
	test.AssertEquals(t, fields[0], "To: \"recv@email.com\"")
	test.AssertEquals(t, fields[1], "From: \"happy sender\" <send@email.com>")
	test.AssertEquals(t, fields[2], "Subject: test subject")
	test.AssertEquals(t, fields[3], "Date: 01 Jan 70 00:00 UTC")
	test.AssertEquals(t, fields[4], "Message-Id: <19700101T000000.1991.send@email.com>")
	test.AssertEquals(t, fields[5], "MIME-Version: 1.0")
	test.AssertEquals(t, fields[6], "Content-Type: text/plain; charset=UTF-8")
	test.AssertEquals(t, fields[7], "Content-Transfer-Encoding: quoted-printable")
	test.AssertEquals(t, fields[8], "")
	test.AssertEquals(t, fields[9], "this is the body")
}

func TestFailNonASCIIAddress(t *testing.T) {
	log := blog.UseMock()
	stats := metrics.NewNoopScope()
	fromAddress, _ := mail.ParseAddress("send@email.com")
	m := New("", "", "", "", nil, *fromAddress, log, stats, 0, 0)
	_, err := m.generateMessage([]string{"遗憾@email.com"}, "test subject", "this is the body\n")
	test.AssertError(t, err, "Allowed a non-ASCII to address incorrectly")
}

func expect(t *testing.T, buf *bufio.Reader, expected string) error {
	line, _, err := buf.ReadLine()
	if err != nil {
		t.Errorf("readline: %s expected: %s\n", err, expected)
		return err
	}
	if string(line) != expected {
		t.Errorf("Expected %s, got %s", expected, line)
		return fmt.Errorf("Expected %s, got %s", expected, line)
	}
	return nil
}

type connHandler func(int, *testing.T, net.Conn)

func listenForever(l net.Listener, t *testing.T, handler connHandler) {
	connID := 0
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		connID++
		go handler(connID, t, conn)
	}
}

func authenticateClient(t *testing.T, conn net.Conn) {
	buf := bufio.NewReader(conn)
	// we can ignore write errors because any
	// failures will be caught on the connecting
	// side
	_, _ = conn.Write([]byte("220 smtp.example.com ESMTP\n"))
	if err := expect(t, buf, "EHLO localhost"); err != nil {
		return
	}

	_, _ = conn.Write([]byte("250-PIPELINING\n"))
	_, _ = conn.Write([]byte("250-AUTH PLAIN LOGIN\n"))
	_, _ = conn.Write([]byte("250 8BITMIME\n"))
	// Base64 encoding of "\0user@example.com\0passwd"
	if err := expect(t, buf, "AUTH PLAIN AHVzZXJAZXhhbXBsZS5jb20AcGFzc3dk"); err != nil {
		return
	}
	_, _ = conn.Write([]byte("235 2.7.0 Authentication successful\n"))
}

// The normal handler authenticates the client and then disconnects without
// further command processing. It is sufficient for TestConnect()
func normalHandler(connID int, t *testing.T, conn net.Conn) {
	defer func() {
		err := conn.Close()
		if err != nil {
			t.Errorf("conn.Close: %s", err)
		}
	}()
	authenticateClient(t, conn)
}

// The disconnectHandler authenticates the client like the normalHandler but
// additionally processes an email flow (e.g. MAIL, RCPT and DATA commands).
// When the `connID` is <= `closeFirst` the connection is closed immediately
// after the MAIL command is received and prior to issuing a 250 response. If
// a `goodbyeMsg` is provided, it is written to the client immediately before
// closing. In this way the first `closeFirst` connections will not complete
// normally and can be tested for reconnection logic.
func disconnectHandler(closeFirst int, goodbyeMsg string) connHandler {
	return func(connID int, t *testing.T, conn net.Conn) {
		defer func() {
			err := conn.Close()
			if err != nil {
				t.Errorf("conn.Close: %s", err)
			}
		}()
		authenticateClient(t, conn)

		buf := bufio.NewReader(conn)
		if err := expect(t, buf, "MAIL FROM:<<you-are-a-winner@example.com>> BODY=8BITMIME"); err != nil {
			return
		}

		if connID <= closeFirst {
			// If there was a `goodbyeMsg` specified, write it to the client before
			// closing the connection. This is a good way to deliver a SMTP error
			// before closing
			if goodbyeMsg != "" {
				_, _ = fmt.Fprintf(conn, "%s\r\n", goodbyeMsg)
				fmt.Printf("Wrote goodbye msg: %s\n", goodbyeMsg)
			}
			fmt.Printf("Cutting off client early\n")
			return
		}
		_, _ = conn.Write([]byte("250 Sure. Go on. \r\n"))

		if err := expect(t, buf, "RCPT TO:<hi@bye.com>"); err != nil {
			return
		}
		_, _ = conn.Write([]byte("250 Tell Me More \r\n"))

		if err := expect(t, buf, "DATA"); err != nil {
			return
		}
		_, _ = conn.Write([]byte("354 Cool Data\r\n"))
		_, _ = conn.Write([]byte("250 Peace Out\r\n"))
	}
}

func badEmailHandler(messagesToProcess int) connHandler {
	return func(_ int, t *testing.T, conn net.Conn) {
		defer func() {
			err := conn.Close()
			if err != nil {
				t.Errorf("conn.Close: %s", err)
			}
		}()
		authenticateClient(t, conn)

		buf := bufio.NewReader(conn)
		if err := expect(t, buf, "MAIL FROM:<<you-are-a-winner@example.com>> BODY=8BITMIME"); err != nil {
			return
		}

		_, _ = conn.Write([]byte("250 Sure. Go on. \r\n"))

		if err := expect(t, buf, "RCPT TO:<hi@bye.com>"); err != nil {
			return
		}
		_, _ = conn.Write([]byte("401 4.1.3 Bad recipient address syntax\r\n"))
	}
}

func setup(t *testing.T) (*MailerImpl, net.Listener, func()) {
	stats := metrics.NewNoopScope()
	fromAddress, _ := mail.ParseAddress("you-are-a-winner@example.com")
	log := blog.UseMock()

	keyPair, err := tls.LoadX509KeyPair("../test/mail-test-srv/localhost/cert.pem", "../test/mail-test-srv/localhost/key.pem")
	if err != nil {
		t.Fatalf("loading keypair: %s", err)
	}
	// Listen on port 0 to get any free available port
	l, err := tls.Listen("tcp", ":0", &tls.Config{
		Certificates: []tls.Certificate{keyPair},
	})
	if err != nil {
		t.Fatalf("listen: %s", err)
	}
	cleanUp := func() {
		err := l.Close()
		if err != nil {
			t.Errorf("listen.Close: %s", err)
		}
	}

	pem, err := ioutil.ReadFile("../test/mail-test-srv/minica.pem")
	if err != nil {
		t.Fatalf("loading smtp root: %s", err)
	}
	smtpRoots := x509.NewCertPool()
	ok := smtpRoots.AppendCertsFromPEM(pem)
	if !ok {
		t.Fatal("failed parsing SMTP root")
	}

	// We can look at the listener Addr() to figure out which free port was
	// assigned by the operating system
	addr := l.Addr().(*net.TCPAddr)
	port := addr.Port

	m := New(
		"localhost",
		strconv.Itoa(port),
		"user@example.com",
		"passwd",
		smtpRoots,
		*fromAddress,
		log,
		stats,
		time.Second*2, time.Second*10)

	return m, l, cleanUp
}

func TestConnect(t *testing.T) {
	m, l, cleanUp := setup(t)
	defer cleanUp()

	go listenForever(l, t, normalHandler)
	err := m.Connect()
	if err != nil {
		t.Errorf("Failed to connect: %s", err)
	}
	err = m.Close()
	if err != nil {
		t.Errorf("Failed to clean up: %s", err)
	}
}

func TestReconnectSuccess(t *testing.T) {
	m, l, cleanUp := setup(t)
	defer cleanUp()
	const closedConns = 5

	// Configure a test server that will disconnect the first `closedConns`
	// connections after the MAIL cmd
	go listenForever(l, t, disconnectHandler(closedConns, ""))

	// With a mailer client that has a max attempt > `closedConns` we expect no
	// error. The message should be delivered after `closedConns` reconnect
	// attempts.
	err := m.Connect()
	if err != nil {
		t.Errorf("Failed to connect: %s", err)
	}
	err = m.SendMail([]string{"hi@bye.com"}, "You are already a winner!", "Just kidding")
	if err != nil {
		t.Errorf("Expected SendMail() to not fail. Got err: %s", err)
	}
}

func TestBadEmailError(t *testing.T) {
	m, l, cleanUp := setup(t)
	defer cleanUp()
	const messages = 3

	go listenForever(l, t, badEmailHandler(messages))

	err := m.Connect()
	if err != nil {
		t.Errorf("Failed to connect: %s", err)
	}

	err = m.SendMail([]string{"hi@bye.com"}, "You are already a winner!", "Just kidding")
	// We expect there to be an error
	if err == nil {
		t.Errorf("Expected SendMail() to return an InvalidRcptError, got nil")
	}
	if rcptErr, ok := err.(InvalidRcptError); !ok {
		t.Errorf("Expected SendMail() to return an InvalidRcptError, got a %T error: %v", err, err)
	} else if rcptErr.Message != "4.1.3 Bad recipient address syntax" {
		t.Errorf("SendMail() returned InvalidRcptError with wrong message: %q\n", rcptErr.Message)
	}
}

func TestReconnectSMTP421(t *testing.T) {
	m, l, cleanUp := setup(t)
	defer cleanUp()
	const closedConns = 5

	// A SMTP 421 can be generated when the server times out an idle connection.
	// For more information see https://github.com/letsencrypt/boulder/issues/2249
	smtp421 := "421 1.2.3 green.eggs.and.spam Error: timeout exceeded"

	// Configure a test server that will disconnect the first `closedConns`
	// connections after the MAIL cmd with a SMTP 421 error
	go listenForever(l, t, disconnectHandler(closedConns, smtp421))

	// With a mailer client that has a max attempt > `closedConns` we expect no
	// error. The message should be delivered after `closedConns` reconnect
	// attempts.
	err := m.Connect()
	if err != nil {
		t.Errorf("Failed to connect: %s", err)
	}
	err = m.SendMail([]string{"hi@bye.com"}, "You are already a winner!", "Just kidding")
	if err != nil {
		t.Errorf("Expected SendMail() to not fail. Got err: %s", err)
	}
}
