// This file contains adapters which can be used
package blog

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/go-logr/stdr"
	"github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/grpclog"
)

func InitAdapters(lc *LogContext) {
	_ = mysql.SetLogger(mysqlLogger{lc.logger})
	grpclog.SetLoggerV2(grpcLogger{lc.logger})
	log.SetOutput(logWriter{lc.logger})
	redis.SetLogger(redisLogger{lc.logger})
	otel.SetLogger(stdr.New(logOutput{lc.logger}))
}

// mysqlLogger implements the mysql.Logger interface.
type mysqlLogger struct {
	*slog.Logger
}

func (log mysqlLogger) Print(v ...any) {
	log.Error(fmt.Sprintf("[mysql] %s", fmt.Sprint(v...)))
}

// grpcLogger implements the grpclog.LoggerV2 interface.
type grpcLogger struct {
	*slog.Logger
}

// Ensure that fatal logs exit, because we use neither the gRPC default logger
// nor the stdlib default logger, both of which would call os.Exit(1) for us.
func (log grpcLogger) Fatal(args ...any) {
	log.Error(args...)
	os.Exit(1)
}
func (log grpcLogger) Fatalf(format string, args ...any) {
	log.Errorf(format, args...)
	os.Exit(1)
}
func (log grpcLogger) Fatalln(args ...any) {
	log.Errorln(args...)
	os.Exit(1)
}

// Pass through all Error level logs.
func (log grpcLogger) Error(args ...any) {
	log.Logger.Error(fmt.Sprint(args...))
}
func (log grpcLogger) Errorf(format string, args ...any) {
	log.Logger.Error(fmt.Sprintf(format, args...))
}
func (log grpcLogger) Errorln(args ...any) {
	log.Logger.Error(fmt.Sprintln(args...))
}

// Pass through most Warnings, but filter out a few noisy ones.
func (log grpcLogger) Warning(args ...any) {
	log.Logger.Warn(fmt.Sprint(args...))
}
func (log grpcLogger) Warningf(format string, args ...any) {
	log.Logger.Warn(fmt.Sprintf(format, args...))
}
func (log grpcLogger) Warningln(args ...any) {
	msg := fmt.Sprintln(args...)
	// See https://github.com/letsencrypt/boulder/issues/4628
	if strings.Contains(msg, `ccResolverWrapper: error parsing service config: no JSON service config provided`) {
		return
	}
	// See https://github.com/letsencrypt/boulder/issues/4379
	if strings.Contains(msg, `Server.processUnaryRPC failed to write status: connection error: desc = "transport is closing"`) {
		return
	}
	// Since we've already formatted the message, just pass through to .Warning()
	log.Logger.Warn(msg)
}

// Don't log any INFO-level gRPC stuff. In practice this is all noise, like
// failed TXT lookups for service discovery (we only use A records).
func (log grpcLogger) Info(args ...any)                 {}
func (log grpcLogger) Infof(format string, args ...any) {}
func (log grpcLogger) Infoln(args ...any)               {}

// V returns true if the verbosity level l is less than the verbosity we want to
// log at.
func (log grpcLogger) V(l int) bool {
	// We always return false. This causes gRPC to not log some things which are
	// only logged conditionally if the logLevel is set below a certain value.
	// TODO: Use the wrapped log.Logger.stdoutLevel and log.Logger.syslogLevel
	// to determine a correct return value here.
	return false
}

// redisLogger implements the redis internal.Logging interface.
type redisLogger struct {
	*slog.Logger
}

func (rl redisLogger) Printf(ctx context.Context, format string, v ...any) {
	rl.Info(fmt.Sprintf(format, v...))
}

// logWriter implements the io.Writer interface.
type logWriter struct {
	*slog.Logger
}

func (lw logWriter) Write(p []byte) (int, error) {
	// Lines received by logWriter will always have a trailing newline.
	lw.Logger.Info(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

// logOutput implements the log.Logger interface's Output method for use with logr
type logOutput struct {
	*slog.Logger
}

func (l logOutput) Output(calldepth int, logline string) error {
	l.Logger.Info(logline)
	return nil
}
