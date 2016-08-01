package mail

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/jmhodges/clock"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

type fakeSource struct{}

func (f fakeSource) generate() *big.Int {
	return big.NewInt(1991)
}

func TestGenerateMessage(t *testing.T) {
	fc := clock.NewFake()
	stats, _ := statsd.NewNoopClient(nil)
	fromAddress, _ := mail.ParseAddress("happy sender <send@email.com>")
	log := blog.UseMock()
	m := New("", "", "", "", *fromAddress, log, stats, 0, 0, 0)
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
	stats, _ := statsd.NewNoopClient(nil)
	fromAddress, _ := mail.ParseAddress("send@email.com")
	m := New("", "", "", "", *fromAddress, log, stats, 0, 0, 0)
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
		return errors.New("")
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
	// Base64 encoding of "user@example.com\0paswd"
	if err := expect(t, buf, "AUTH PLAIN AHVzZXJAZXhhbXBsZS5jb20AcGFzd2Q="); err != nil {
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

// The disconnectHandler authenticates the client like the normalHandler but additionally processes an email flow (e.g. MAIL, RCPT and DATA commands). When the connID is < maxConnects
func disconnectHandler(closeFirst int) connHandler {
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

func setup(t *testing.T) (*MailerImpl, net.Listener, func()) {
	const port = "16632"
	stats, _ := statsd.NewNoopClient(nil)
	fromAddress, _ := mail.ParseAddress("you-are-a-winner@example.com")
	log := blog.UseMock()

	m := New(
		"localhost",
		port,
		"user@example.com",
		"paswd",
		*fromAddress,
		log,
		stats,
		time.Second*2, time.Second*10, 100)

	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		t.Fatalf("listen: %s", err)
	}
	cleanUp := func() {
		err := l.Close()
		if err != nil {
			t.Errorf("listen.Close: %s", err)
		}
	}

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

func TestReconnectFailure(t *testing.T) {
	m, l, cleanUp := setup(t)
	defer cleanUp()
	const closedConns = 5

	// Configure a test server that will disconnect the first `closedConns`
	// connections after the MAIL cmd
	go listenForever(l, t, disconnectHandler(closedConns))

	// With a mailer client that has a max attempt < `closedConns` we expect an
	// EOF error. The client should give up before the server stops closing its
	// connections.
	m.retryMaxAttempts = closedConns - 1
	err := m.Connect()
	if err != nil {
		t.Errorf("Failed to connect: %s", err)
	}
	err = m.SendMail([]string{"hi@bye.com"}, "You are already a winner!", "Just kidding")
	if err != io.EOF {
		t.Errorf("Expected SendMail() to fail with EOF err, got %s", err)
	}
}

func TestReconnectSuccess(t *testing.T) {
	m, l, cleanUp := setup(t)
	defer cleanUp()
	const closedConns = 5

	// Configure a test server that will disconnect the first `closedConns`
	// connections after the MAIL cmd
	go listenForever(l, t, disconnectHandler(closedConns))

	// With a mailer client that has a max attempt > `closedConns` we expect no
	// error. The message should be delivered after `closedConns` reconnect
	// attempts.
	m.retryMaxAttempts = closedConns + 1
	err := m.Connect()
	if err != nil {
		t.Errorf("Failed to connect: %s", err)
	}
	err = m.SendMail([]string{"hi@bye.com"}, "You are already a winner!", "Just kidding")
	if err != nil {
		t.Errorf("Expected SendMail() to not fail. Got err: %s", err)
	}
}
