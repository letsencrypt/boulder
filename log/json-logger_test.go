// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"
)

const TimeoutIndicator = "<TIMEOUT>"

func readChanWithTimeout(outChan <-chan string) string {
	timeout := time.After(time.Second)

	select {
	case line := <-outChan:
		return line
	case <-timeout:
		return TimeoutIndicator
	}
}

func awaitMessage(t *testing.T, scheme string, address string) (net.Listener, <-chan string) {
	outChan := make(chan string)

	socket, err := net.Listen(scheme, address)
	test.AssertNotError(t, err, "Could not listen")

	recvLog := func() {
		conn, err := socket.Accept()

		if conn == nil {
			t.Error("Conn nil; programmer error in test.")
			return
		}

		defer func() {
			conn.Close()
			fmt.Println("Exiting")
		}()

		test.AssertNotError(t, err, "Could not accept")

		reader := bufio.NewReader(conn)

		for {
			conn.SetDeadline(time.Now().Add(time.Second))
			line, _ := reader.ReadString('\n')

			// Emit the line if it's not-empty.
			if line != "" {
				outChan <- line
			}
		}

	}

	go recvLog()

	// Let the caller close the socket
	return socket, outChan
}

func TestWriteTcp(t *testing.T) {
	const Scheme = "tcp"
	const Address = "127.0.0.1:9999"
	socket, outChan := awaitMessage(t, Scheme, Address)
	defer socket.Close()

	log := NewJSONLogger("just a test")
	log.SetEndpoint(Scheme, Address)

	msg := "Test " + Scheme + " " + Address
	log.Critical(msg, nil)

	rsp := <-outChan
	test.AssertContains(t, rsp, msg)
	test.AssertSeverity(t, rsp, CRITICAL)
}

func TestWriteNoNetwork(t *testing.T) {
	log := NewJSONLogger("just a test")
	log.Debug("Check", nil)
	// Nothing to assert

	log.EnableStdOut(true)
	log.Debug("Check", nil)
	// Nothing to assert
}

func TestWriteUnMarshallable(t *testing.T) {
	const Scheme = "tcp"
	const Address = "127.0.0.1:9998"
	socket, outChan := awaitMessage(t, Scheme, Address)
	defer socket.Close()

	log := NewJSONLogger("please don't work")
	log.SetEndpoint(Scheme, Address)
	log.Connect()

	log.Debug("Check", func() {})
	rsp := readChanWithTimeout(outChan)

	test.AssertEquals(t, rsp, TimeoutIndicator)

}

func TestWriteTcpAllLevels(t *testing.T) {
	const Scheme = "tcp"
	const Address = "127.0.0.1:9997"
	socket, outChan := awaitMessage(t, Scheme, Address)
	defer socket.Close()

	log := NewJSONLogger("just a test")
	log.SetEndpoint(Scheme, Address)

	msg := "Test " + Scheme + " " + Address
	{
		log.Critical(msg, msg)
		rsp := <-outChan
		test.AssertSeverity(t, rsp, CRITICAL)
		test.AssertContains(t, rsp, msg)
	}

	{
		log.Alert(msg, msg)
		rsp := <-outChan
		test.AssertSeverity(t, rsp, ALERT)
		test.AssertContains(t, rsp, msg)
	}

	{
		log.Emergency(msg, msg)
		rsp := <-outChan
		test.AssertSeverity(t, rsp, EMERGENCY)
		test.AssertContains(t, rsp, msg)
	}

	{
		log.Error(msg, msg)
		rsp := <-outChan
		test.AssertSeverity(t, rsp, ERROR)
		test.AssertContains(t, rsp, msg)
	}

	{
		log.Warning(msg, msg)
		rsp := <-outChan
		test.AssertSeverity(t, rsp, WARNING)
		test.AssertContains(t, rsp, msg)
	}

	{
		log.Notice(msg, msg)
		rsp := <-outChan
		test.AssertSeverity(t, rsp, NOTICE)
		test.AssertContains(t, rsp, msg)
	}

	{
		log.Info(msg, msg)
		rsp := <-outChan
		test.AssertSeverity(t, rsp, INFO)
		test.AssertContains(t, rsp, msg)
	}

	{
		log.Debug(msg, msg)
		rsp := <-outChan
		test.AssertSeverity(t, rsp, DEBUG)
		test.AssertContains(t, rsp, msg)
	}
}

func TestLevelMasking(t *testing.T) {
	const Scheme = "tcp"
	const Address = "127.0.0.1:9996"
	socket, outChan := awaitMessage(t, Scheme, Address)
	defer socket.Close()

	log := NewJSONLogger("just a test")
	log.SetEndpoint(Scheme, Address)

	msg := "Test " + Scheme + " " + Address

	{
		log.Info(msg, msg)
		rsp := readChanWithTimeout(outChan)
		test.AssertSeverity(t, rsp, INFO)
		test.AssertContains(t, rsp, msg)
	}

	// Notice and lower numbers should emit; Info should not.
	log.SetLevel(NOTICE)

	{
		log.Info(msg, msg)
		rsp := readChanWithTimeout(outChan)
		test.AssertEquals(t, rsp, TimeoutIndicator)
	}

	// Warning, being lower than Notice, should emit.
	{
		log.Warning(msg, msg)

		rsp := readChanWithTimeout(outChan)
		test.AssertSeverity(t, rsp, WARNING)
		test.AssertContains(t, rsp, msg)
	}
}

func TestEmbeddedNewline(t *testing.T) {
	const Scheme = "tcp"
	const Address = "127.0.0.1:9995"
	socket, outChan := awaitMessage(t, Scheme, Address)
	defer socket.Close()

	log := NewJSONLogger("embedded newline")
	log.SetEndpoint(Scheme, Address)

	payload := struct {
		One string
		Two string
	}{
		One: "A\nTOYOTA'S\nA\nTOYOTA",
		Two: "\n\n\n\n\n",
	}

	msg := "There's a newline in the payload:"
	log.Critical(msg, payload)

	rsp := <-outChan
	test.AssertContains(t, rsp, msg)
	test.AssertSeverity(t, rsp, CRITICAL)

	// I can't do an test.AssertContains directly because rsp is escaped, while the
	// payload values are not. Since escaping routines are not so easy to find,
	// payload I can't just JSON-marshal (because that is a loopback test),
	// I do it manually.
	test.AssertContains(t, rsp, strings.Replace(payload.One, "\n", "\\n", -1))
	test.AssertContains(t, rsp, strings.Replace(payload.Two, "\n", "\\n", -1))
}
