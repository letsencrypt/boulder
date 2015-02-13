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
  "sync"
)

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

type LogMessage struct {
  Message  string      `json:"message"`
  Payload  interface{} `json:"payload"`
  Program  string      `json:"program"`
  Severity int         `json:"severity"`
}

type JsonLogger struct {
  debug     bool
  scheme    string
  host      string
  level     int
  conn      net.Conn
  mu        sync.Mutex // guards conn
  program   string // Defines the 'program' field in JSON
}

func (jl *JsonLogger) SetDebugToStdOut(debug bool) {
  jl.debug = debug
}

func (jl *JsonLogger) SetLevel(level int) {
  jl.level = level
}

func (jl *JsonLogger) SetEndpoint(scheme string, host string) {
  jl.scheme = scheme
  jl.host = host
}

func (jl *JsonLogger) Connect() (error) {
  conn, err := net.Dial(jl.scheme, jl.host)
  if err == nil {
    jl.conn = conn
  }
  return err
}

func (jl *JsonLogger) Critical(messageStr string, payloadObj interface{}) {
  jl.Write(CRITICAL, messageStr, payloadObj)
}

func (jl *JsonLogger) Alert(messageStr string, payloadObj interface{}) {
  jl.Write(ALERT, messageStr, payloadObj)
}

func (jl *JsonLogger) Emergency(messageStr string, payloadObj interface{}) {
  jl.Write(EMERGENCY, messageStr, payloadObj)
}

func (jl *JsonLogger) Error(messageStr string, payloadObj interface{}) {
  jl.Write(ERROR, messageStr, payloadObj)
}

func (jl *JsonLogger) Warning(messageStr string, payloadObj interface{}) {
  jl.Write(WARNING, messageStr, payloadObj)
}

func (jl *JsonLogger) Notice(messageStr string, payloadObj interface{}) {
  jl.Write(NOTICE, messageStr, payloadObj)
}

func (jl *JsonLogger) Info(messageStr string, payloadObj interface{}) {
  jl.Write(INFO, messageStr, payloadObj)
}

func (jl *JsonLogger) Debug(messageStr string, payloadObj interface{}) {
  jl.Write(DEBUG, messageStr, payloadObj)
}

func (jl *JsonLogger) Write(severity int, messageStr string, payloadObj interface{}) {
  if severity > jl.level {
    return
  }

  data := LogMessage{
    Program:  "am",
    Payload:  payloadObj,
    Message:  messageStr,
    Severity: severity}

  encoded, err := json.Marshal(data)

  // s, err := json.Marshal(lm)
  if err != nil {
    log.Fatalf("Could not marshal log message: %s", err)
    return
  }

  if jl.debug {
    log.Println(fmt.Sprintf("<%d> %s", severity, string(encoded)))
  }

  _, err = jl.WriteAndRetry(string(encoded))
  if err != nil {
    log.Fatalf("Failed to send log message, even with retry: %s", encoded)
    return
  }
}

func (jl *JsonLogger) Transmit(s string) (int, error) {
  return fmt.Fprintln(jl.conn, s)
}

func (jl *JsonLogger) WriteAndRetry(s string) (int, error) {
  jl.mu.Lock()
  defer jl.mu.Unlock()

  if jl.conn != nil {
    if n, err := jl.Transmit(s); err == nil {
      return n, err
    }
  }
  if err := jl.Connect(); err != nil {
    return 0, err
  }
  return jl.Transmit(s)
}
