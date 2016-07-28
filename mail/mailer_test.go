package mail

import (
	"bufio"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"strings"
	"testing"

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
	m := New("", "", "", "", *fromAddress, log, stats, 0, 0)
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
	m := New("", "", "", "", *fromAddress, log, stats, 0, 0)
	_, err := m.generateMessage([]string{"遗憾@email.com"}, "test subject", "this is the body\n")
	test.AssertError(t, err, "Allowed a non-ASCII to address incorrectly")
}

func expect(t *testing.T, buf *bufio.Reader, expected string) error {
	line, _, err := buf.ReadLine()
	if err != nil {
		t.Errorf("readline: %s\n", err)
		return err
	}
	if string(line) != expected {
		t.Errorf("Expected %s, got %s", expected, line)
		return errors.New("")
	}
	return nil
}

func TestConnect(t *testing.T) {
	port := "16632"
	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		t.Errorf("listen: %s", err)
	}
	go func() {
		defer func() {
			err := l.Close()
			if err != nil {
				t.Errorf("listen.Close: %s", err)
			}
		}()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() {
					err := conn.Close()
					if err != nil {
						t.Errorf("conn.Close: %s", err)
					}
				}()
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
			}()
		}
	}()
	stats, _ := statsd.NewNoopClient(nil)
	fromAddress, _ := mail.ParseAddress("send@email.com")
	log := blog.UseMock()
	m := New(
		"localhost",
		port,
		"user@example.com",
		"paswd",
		*fromAddress,
		log,
		stats,
		0, 0)
	err = m.Connect()
	if err != nil {
		t.Errorf("Failed to connect: %s", err)
	}
	err = m.Close()
	if err != nil {
		t.Errorf("Failed to clean up: %s", err)
	}
}
