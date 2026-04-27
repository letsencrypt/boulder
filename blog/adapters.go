package blog

// This file contains adapters which can be used

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-logr/stdr"
	"github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/grpclog"
)

func InitAdapters(l Logger) {
	_ = mysql.SetLogger(mysqlLogger{l})
	grpclog.SetLoggerV2(grpcLogger{l})
	log.SetOutput(logWriter{l})
	redis.SetLogger(redisLogger{l})
	otel.SetLogger(stdr.New(logOutput{l}))
}

// mysqlLogger implements the mysql.Logger interface.
type mysqlLogger struct {
	Logger
}

func (l mysqlLogger) Print(v ...any) {
	// The mysql package only uses the logger to output errors.
	l.Error(context.Background(), "mysql error", errors.New(fmt.Sprint(v...)))
}

// grpcLogger implements the grpclog.LoggerV2 interface.
type grpcLogger struct {
	Logger
}

// Ensure that fatal logs exit, because we use neither the gRPC default logger
// nor the stdlib default logger, both of which would call os.Exit(1) for us.
func (l grpcLogger) Fatal(args ...any) {
	l.Error(args...)
	os.Exit(1)
}
func (l grpcLogger) Fatalf(format string, args ...any) {
	l.Errorf(format, args...)
	os.Exit(1)
}
func (l grpcLogger) Fatalln(args ...any) {
	l.Errorln(args...)
	os.Exit(1)
}

// Pass through all Error level logs.
func (l grpcLogger) Error(args ...any) {
	l.Logger.Error(context.Background(), "grpc error", errors.New(fmt.Sprint(args...)))
}
func (l grpcLogger) Errorf(format string, args ...any) {
	l.Logger.Error(context.Background(), "grpc error", fmt.Errorf(format, args...))
}
func (l grpcLogger) Errorln(args ...any) {
	l.Logger.Error(context.Background(), "grpc error", errors.New(fmt.Sprintln(args...)))
}

// Pass through most Warnings, but filter out a few noisy ones.
func (l grpcLogger) Warning(args ...any) {
	l.Logger.Warn(context.Background(), fmt.Sprint(args...))
}
func (l grpcLogger) Warningf(format string, args ...any) {
	l.Logger.Warn(context.Background(), fmt.Sprintf(format, args...))
}
func (l grpcLogger) Warningln(args ...any) {
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
	l.Logger.Warn(context.Background(), msg)
}

// Don't log any INFO-level gRPC stuff. In practice this is all noise, like
// failed TXT lookups for service discovery (we only use A records).
func (l grpcLogger) Info(args ...any)                 {}
func (l grpcLogger) Infof(format string, args ...any) {}
func (l grpcLogger) Infoln(args ...any)               {}

// V returns true if the verbosity level is less than the verbosity we want to
// log at.
func (l grpcLogger) V(_ int) bool {
	// We always return false. This causes gRPC to not log some things which are
	// only logged conditionally if the logLevel is set below a certain value.
	// TODO: Use the wrapped log.Logger.stdoutLevel and log.Logger.syslogLevel
	// to determine a correct return value here.
	return false
}

// redisLogger implements the redis internal.Logging interface.
type redisLogger struct {
	Logger
}

func (rl redisLogger) Printf(ctx context.Context, format string, v ...any) {
	rl.Info(ctx, fmt.Sprintf(format, v...))
}

// logWriter implements the io.Writer interface.
type logWriter struct {
	Logger
}

func (lw logWriter) Write(p []byte) (int, error) {
	// Lines received by logWriter will always have a trailing newline.
	lw.Logger.Info(context.Background(), strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

// logOutput implements the log.Logger interface's Output method for use with logr
type logOutput struct {
	Logger
}

func (l logOutput) Output(calldepth int, logline string) error {
	l.Logger.Info(context.Background(), logline)
	return nil
}
