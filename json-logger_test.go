// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package boulder

import (
  "bufio"
  "strings"
  "fmt"
  "net"
  "testing"
  "time"
)

const TimeoutIndicator = "<TIMEOUT>"

func AssertNotError(t *testing.T, err error, message string) {
  if err != nil {
    t.Error(message, err)
  }
}

func AssertEquals(t *testing.T, one string, two string) {
  if one != two {
    t.Errorf("String [%s] != [%s]", one, two)
  }
}

func AssertContains(t *testing.T, haystack string, needle string) {
  if ! strings.Contains(haystack, needle) {
    t.Errorf("String [%s] does not contain [%s]", haystack, needle)
  }
}

func AssertSeverity(t *testing.T, data string, severity int) {
  expected := fmt.Sprintf("\"severity\":%d", severity)
  AssertContains(t, data, expected)
}

func readChanWithTimeout(outChan <-chan string) string {
  timeout := time.After(time.Second)

  select {
  case line := <-outChan:
    return line
  case <-timeout:
    return TimeoutIndicator
  }
}

func awaitMessage(t *testing.T, scheme string, address string)  (net.Listener, <-chan string) {
  outChan := make(chan string)

  socket, err := net.Listen(scheme, address)
  AssertNotError(t, err, "Could not listen")

  recvLog := func() {
    conn, err := socket.Accept()

    if conn == nil {
      t.Error("Conn nil; programmer error in test.")
      return
    }

    defer func(){
      conn.Close()
      fmt.Println("Exiting")
    }()

    AssertNotError(t, err, "Could not accept")

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

  log := NewJsonLogger("just a test")
  log.SetEndpoint(Scheme, Address)

  msg := "Test " + Scheme + " " + Address
  log.Critical(msg, nil)

  rsp := <-outChan
  AssertContains(t, rsp, msg)
  AssertSeverity(t, rsp, CRITICAL)
}

func TestWriteNoNetwork(t *testing.T) {
  log := NewJsonLogger("just a test")
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

  log := NewJsonLogger("please don't work")
  log.SetEndpoint(Scheme, Address)
  log.Connect()

  log.Debug("Check", func(){})
  rsp := readChanWithTimeout(outChan)

  AssertEquals(t, rsp, TimeoutIndicator)

}

func TestWriteTcpAllLevels(t *testing.T) {
  const Scheme = "tcp"
  const Address = "127.0.0.1:9997"
  socket, outChan := awaitMessage(t, Scheme, Address)
  defer socket.Close()

  log := NewJsonLogger("just a test")
  log.SetEndpoint(Scheme, Address)

  msg := "Test " + Scheme + " " + Address
  {
    log.Critical(msg, msg)
    rsp := <-outChan
    AssertSeverity(t, rsp, CRITICAL)
    AssertContains(t, rsp, msg)
  }

  {
    log.Alert(msg, msg)
    rsp := <-outChan
    AssertSeverity(t, rsp, ALERT)
    AssertContains(t, rsp, msg)
  }

  {
    log.Emergency(msg, msg)
    rsp := <-outChan
    AssertSeverity(t, rsp, EMERGENCY)
    AssertContains(t, rsp, msg)
  }

  {
    log.Error(msg, msg)
    rsp := <-outChan
    AssertSeverity(t, rsp, ERROR)
    AssertContains(t, rsp, msg)
  }

  {
    log.Warning(msg, msg)
    rsp := <-outChan
    AssertSeverity(t, rsp, WARNING)
    AssertContains(t, rsp, msg)
  }

  {
    log.Notice(msg, msg)
    rsp := <-outChan
    AssertSeverity(t, rsp, NOTICE)
    AssertContains(t, rsp, msg)
  }

  {
    log.Info(msg, msg)
    rsp := <-outChan
    AssertSeverity(t, rsp, INFO)
    AssertContains(t, rsp, msg)
  }

  {
    log.Debug(msg, msg)
    rsp := <-outChan
    AssertSeverity(t, rsp, DEBUG)
    AssertContains(t, rsp, msg)
  }
}

func TestLevelMasking(t *testing.T) {
  const Scheme = "tcp"
  const Address = "127.0.0.1:9996"
  socket, outChan := awaitMessage(t, Scheme, Address)
  defer socket.Close()

  log := NewJsonLogger("just a test")
  log.SetEndpoint(Scheme, Address)

  msg := "Test " + Scheme + " " + Address

  {
    log.Info(msg, msg)
    rsp := readChanWithTimeout(outChan)
    AssertSeverity(t, rsp, INFO)
    AssertContains(t, rsp, msg)
  }

  // Notice and lower numbers should emit; Info should not.
  log.SetLevel(NOTICE)

  {
    log.Info(msg, msg)
    rsp := readChanWithTimeout(outChan)
    AssertEquals(t, rsp, TimeoutIndicator)
  }

  // Warning, being lower than Notice, should emit.
  {
    log.Warning(msg, msg)

    rsp := readChanWithTimeout(outChan)
    AssertSeverity(t, rsp, WARNING)
    AssertContains(t, rsp, msg)
  }
}

func TestEmbeddedNewline(t *testing.T) {
  const Scheme = "tcp"
  const Address = "127.0.0.1:9995"
  socket, outChan := awaitMessage(t, Scheme, Address)
  defer socket.Close()

  log := NewJsonLogger("embedded newline")
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
  AssertContains(t, rsp, msg)
  AssertSeverity(t, rsp, CRITICAL)

  // I can't do an AssertContains directly because rsp is escaped, while the
  // payload values are not. Since escaping routines are not so easy to find,
  // payload I can't just JSON-marshal (because that is a loopback test),
  // I do it manually.
  AssertContains(t, rsp, strings.Replace(payload.One, "\n", "\\n", -1))
  AssertContains(t, rsp, strings.Replace(payload.Two, "\n", "\\n", -1))
}

