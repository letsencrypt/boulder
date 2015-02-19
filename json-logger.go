// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package boulder

import (
  "encoding/json"
  "fmt"
  "log"
  "net"
  "bytes"
  "sync"
)

// This package transmits JSON data over IP. It is designed to follow
// general conventions for syslog, but uses JSON encoding instead of
// the RFC 5424 strings.
//
// The JSON encoding is suitable for import by Logstash's "json_lines" CODEC
// module.
//
// NOTE: In TCP mode, this package attempts to retransmit in the event of a
// channel failure. If the retransmission fails, it aborts and expects to
// be restarted by the process controller.


// Use the same severity levels as RFC 5424.
// Note: Facility is not used.
const (
  EMERGENCY = 0
  ALERT     = 1
  CRITICAL  = 2
  ERROR     = 3
  WARNING   = 4
  NOTICE    = 5
  INFO      = 6
  DEBUG     = 7
)

// JSON Schema for the Log Messages on the wire.
type LogMessage struct {
  // User-readable descriptive message; may be null.
  Message  string      `json:"message"`
  // Sub-object; must be JSON-formattable.
  Payload  interface{} `json:"payload"`
  // Logger identifier
  Program  string      `json:"program"`
  // RFC 5424 severity level
  Severity int         `json:"severity"`
}

// Structure to hold logger details.
type JsonLogger struct {
  stdout    bool        // True if logging to stdout
  online    bool        // True if the remote endpoint has been setup
  scheme    string      // Golang net URI scheme (tcp/udp)
  host      string      // "address:port"
  level     int         // Maximum-transmitted log level
  conn      net.Conn    // Socket representation
  mu        sync.Mutex  // guards conn
  program   string      // Defines the 'program' field in JSON
}

func NewJsonLogger(programName string) (*JsonLogger) {
  return &JsonLogger{
    program: programName,
    level: 7, // Default to all
  }
}

func (jl *JsonLogger) EnableStdOut(stdout bool) {
  jl.stdout = stdout
}

func (jl *JsonLogger) SetLevel(level int) {
  jl.level = level
}

func (jl *JsonLogger) SetEndpoint(scheme string, host string) {
  jl.scheme = scheme
  jl.host = host
  jl.online = true
}

func (jl *JsonLogger) Connect() (error) {
  conn, err := net.Dial(jl.scheme, jl.host)
  if err == nil {
    jl.conn = conn
  }
  return err
}

// Log at the Critical severity level.
func (jl *JsonLogger) Critical(messageStr string, payloadObj interface{}) {
  jl.Write(CRITICAL, messageStr, payloadObj)
}

// Log at the Alert severity level.
func (jl *JsonLogger) Alert(messageStr string, payloadObj interface{}) {
  jl.Write(ALERT, messageStr, payloadObj)
}

// Log at the Emergency severity level.
func (jl *JsonLogger) Emergency(messageStr string, payloadObj interface{}) {
  jl.Write(EMERGENCY, messageStr, payloadObj)
}

// Log at the Error severity level.
func (jl *JsonLogger) Error(messageStr string, payloadObj interface{}) {
  jl.Write(ERROR, messageStr, payloadObj)
}

// Log at the Warning severity level.
func (jl *JsonLogger) Warning(messageStr string, payloadObj interface{}) {
  jl.Write(WARNING, messageStr, payloadObj)
}

// Log at the Notice severity level.
func (jl *JsonLogger) Notice(messageStr string, payloadObj interface{}) {
  jl.Write(NOTICE, messageStr, payloadObj)
}

// Log at the Info severity level.
func (jl *JsonLogger) Info(messageStr string, payloadObj interface{}) {
  jl.Write(INFO, messageStr, payloadObj)
}

// Log at the Debug severity level.
func (jl *JsonLogger) Debug(messageStr string, payloadObj interface{}) {
  jl.Write(DEBUG, messageStr, payloadObj)
}


// Combines a message, payload, and severity to a LogMessage struct and
// serializes it to the wire. If the send via WriteAndRetry() fails, this method
// calls log.Fatalf() which will abort the program, leaving the system to restart
// the process.
func (jl *JsonLogger) Write(severity int, messageStr string, payloadObj interface{}) {
  if severity > jl.level {
    return
  }

  data := LogMessage{
    Program:  jl.program,
    Payload:  payloadObj,
    Message:  messageStr,
    Severity: severity}

  encoded, err := json.Marshal(data)

  if err != nil {
    log.Printf("Could not marshal log message: %s\n", err)
    return
  }

  buf := bytes.NewBuffer(encoded)
  buf.WriteByte('\n') // Append a newline

  if jl.stdout {
    log.Println(fmt.Sprintf("<%d> %s", severity, buf.String()))
  }

  if jl.online {
    // If we've been told to be connected, write to the socket.
    _, err = jl.WriteAndRetry(buf.Bytes())
    if err != nil {
      log.Fatalf("Failed to send log message, even with retry, exiting: %s\n", buf.String())
      return
    }
  }
}

// Send the provided data on the connection; if there is an error,
// it will retry to connect and transmit again, once. If that fails,
// it returns an error.
func (jl *JsonLogger) WriteAndRetry(data []byte) (int, error) {
  jl.mu.Lock()
  defer jl.mu.Unlock()

  if jl.conn != nil {
    if n, err := jl.conn.Write(data); err == nil {
      return n, err
    }
  }
  if err := jl.Connect(); err != nil {
    return 0, err
  }
  return jl.conn.Write(data)
}


