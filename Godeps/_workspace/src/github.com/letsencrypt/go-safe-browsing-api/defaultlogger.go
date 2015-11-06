/*
Copyright (c) 2013, Richard Johnson
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package safebrowsing

import (
	"fmt"
	"time"
)

// logger interface deliberatly matches the log4go.Logger signature
// to allow for drop-in injection.
type logger interface {
	Finest(arg0 interface{}, args ...interface{})
	Fine(arg0 interface{}, args ...interface{})
	Debug(arg0 interface{}, args ...interface{})
	Trace(arg0 interface{}, args ...interface{})
	Info(arg0 interface{}, args ...interface{})
	Warn(arg0 interface{}, args ...interface{}) error
	Error(arg0 interface{}, args ...interface{}) error
	Critical(arg0 interface{}, args ...interface{}) error
}

// Default logger provides a simple console output implementation of the logger
// interface.  This is intended for logger dependency injection, such as log4go.
type DefaultLogger struct{}

func (dl *DefaultLogger) log(level string, arg0 interface{}, args ...interface{}) {
	prefix := fmt.Sprintf(
		"[%v] [%s] ",
		time.Now().Format("2006-01-02 15:04:05"),
		level)
	fmt.Printf(prefix+arg0.(string)+"\n", args...)
}
func (dl *DefaultLogger) Finest(arg0 interface{}, args ...interface{}) {
	dl.log("FINE", arg0, args...)
}
func (dl *DefaultLogger) Fine(arg0 interface{}, args ...interface{}) {
	dl.log("FINE", arg0, args...)
}
func (dl *DefaultLogger) Debug(arg0 interface{}, args ...interface{}) {
	dl.log("DEBG", arg0, args...)
}
func (dl *DefaultLogger) Trace(arg0 interface{}, args ...interface{}) {
	dl.log("TRAC", arg0, args...)
}
func (dl *DefaultLogger) Info(arg0 interface{}, args ...interface{}) {
	dl.log("INFO", arg0, args...)
}
func (dl *DefaultLogger) Warn(arg0 interface{}, args ...interface{}) error {
	dl.log("WARN", arg0, args...)
	return nil
}
func (dl *DefaultLogger) Error(arg0 interface{}, args ...interface{}) error {
	dl.log("EROR", arg0, args...)
	return nil
}
func (dl *DefaultLogger) Critical(arg0 interface{}, args ...interface{}) error {
	dl.log("CRIT", arg0, args...)
	return nil
}
