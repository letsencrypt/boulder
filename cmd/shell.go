// Package cmd provides utilities that underlie the specific commands.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"

	"github.com/letsencrypt/boulder/blog"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/strictyaml"
	"github.com/letsencrypt/validator/v10"
)

// Because we don't know when this init will be called with respect to
// flag.Parse() and other flag definitions, we can't rely on the regular
// flag mechanism. But this one is fine.
func init() {
	for _, v := range os.Args {
		if v == "--version" || v == "-version" {
			fmt.Printf("%+v", info())
			os.Exit(0)
		}
	}
}

// promLogger implements the promhttp.Logger interface. This adapter is here
// instead of in blog/adapters.go because it is used at the individual handler
// level, rather than at the package-global level.
type promLogger struct {
	*blog.LogContext
}

func (log promLogger) Println(args ...any) {
	blog.Error(log.New(), "Prometheus error", errors.New(fmt.Sprint(args...)))
}

// singletonLogger can only be initialized once, then never overwritten.
type singletonLogger struct {
	once sync.Once
	log  *blog.LogContext
}

func (s *singletonLogger) init(l *blog.LogContext) {
	s.once.Do(func() {
		s.log = l
	})
}

// backupLogger is used only by AuditPanic, which is deferred before we've had a
// chance to build a real logger. If NewLogger is called, it initializes this
// backup to be the same as the real logger it returns. Otherwise, AuditPanic
// will construct its own logger with a known-good config.
var backupLogger singletonLogger

// StatsAndLogging sets up an AuditLogger, Prometheus Registerer, and
// OpenTelemetry tracing.  It returns the Registerer and AuditLogger, along
// with a graceful shutdown function to be deferred.
//
// It spawns off an HTTP server on the provided port to report the stats and
// provide pprof profiling handlers.
//
// The constructed AuditLogger as the default logger, and configures the mysql
// and grpc packages to use our logger. This must be called before any gRPC code
// is called, because gRPC's SetLogger doesn't use any locking.
//
// This function does not return an error, and will panic on problems.
func StatsAndLogging(logConf blog.Config, otConf OpenTelemetryConfig, addr string) (prometheus.Registerer, *blog.LogContext, func(context.Context)) {
	logctx := NewLogger(logConf)

	shutdown := NewOpenTelemetry(logctx.New(), otConf)

	return newStatsRegistry(addr, logctx), logctx, shutdown
}

// NewLogger creates a LogContext with the provided settings and returns it. It
// also installs this logger as the default logger for third-party packages,
// and sets up a periodic log event for the current timestamp.
func NewLogger(logConf blog.Config) *blog.LogContext {
	logctx, err := blog.NewLogContext(logConf)
	FailOnError(err, "While constructing loggers")

	blog.InitAdapters(logctx)
	backupLogger.init(logctx)

	// Periodically log the current timestamp, to ensure syslog timestamps match
	// Boulder's conception of time.
	go func() {
		for {
			time.Sleep(time.Hour)
			blog.Info(logctx.New(), "heartbeat")
		}
	}()
	return logctx
}

func newVersionCollector() prometheus.Collector {
	buildTime := core.Unspecified
	if core.GetBuildTime() != core.Unspecified {
		// core.BuildTime is set by our Makefile using the shell command 'date
		// -u' which outputs in a consistent format across all POSIX systems.
		bt, err := time.Parse(time.UnixDate, core.BuildTime)
		if err != nil {
			// Should never happen unless the Makefile is changed.
			buildTime = "Unparsable"
		} else {
			buildTime = bt.Format(time.RFC3339)
		}
	}
	return prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "version",
			Help: fmt.Sprintf(
				"A metric with a constant value of '1' labeled by the short commit-id (buildId), build timestamp in RFC3339 format (buildTime), and Go release tag like 'go1.3' (goVersion) from which %s was built.",
				core.Command(),
			),
			ConstLabels: prometheus.Labels{
				"buildId":   core.GetBuildID(),
				"buildTime": buildTime,
				"goVersion": runtime.Version(),
			},
		},
		func() float64 { return 1 },
	)
}

func newStatsRegistry(addr string, logctx *blog.LogContext) prometheus.Registerer {
	registry := prometheus.NewRegistry()

	if addr == "" {
		blog.Debug(logctx.New(), "No debug listen address specified")
		return registry
	}

	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(
		collectors.ProcessCollectorOpts{}))
	registry.MustRegister(newVersionCollector())
	registry.MustRegister(version.NewCollector("boulder"))

	mux := http.NewServeMux()
	// Register the available pprof handlers. These are all registered on
	// DefaultServeMux just by importing pprof, but since we eschew
	// DefaultServeMux, we need to explicitly register them on our own mux.
	mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
	mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	mux.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	// These handlers are defined in runtime/pprof instead of net/http/pprof, and
	// have to be accessed through net/http/pprof's Handler func.
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	mux.Handle("/debug/vars", expvar.Handler())
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		ErrorLog: promLogger{logctx},
	}))

	blog.Debug(logctx.New(), "Debug server listening", slog.String("addr", addr))

	server := http.Server{
		Addr:        addr,
		Handler:     mux,
		ReadTimeout: time.Minute,
	}
	go func() {
		err := server.ListenAndServe()
		FailOnError(err, "Unable to boot debug server")
	}()
	return registry
}

// NewOpenTelemetry sets up our OpenTelemetry tracing
// It returns a graceful shutdown function to be deferred.
func NewOpenTelemetry(ctx context.Context, config OpenTelemetryConfig) func(ctx context.Context) {
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) { blog.Error(ctx, "OpenTelemetry error", err) }))

	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(core.Command()),
		semconv.ServiceVersion(core.GetBuildID()),
		semconv.ProcessPID(os.Getpid()),
	)

	opts := []trace.TracerProviderOption{
		trace.WithResource(resources),
		// Use a ParentBased sampler to respect the sample decisions on incoming
		// traces, and TraceIDRatioBased to randomly sample new traces.
		trace.WithSampler(trace.ParentBased(trace.TraceIDRatioBased(config.SampleRatio))),
	}

	if config.Endpoint != "" {
		exporter, err := otlptracegrpc.New(
			context.Background(),
			otlptracegrpc.WithInsecure(),
			otlptracegrpc.WithEndpoint(config.Endpoint))
		if err != nil {
			FailOnError(err, "Could not create OpenTelemetry OTLP exporter")
		}

		opts = append(opts, trace.WithBatcher(exporter))
	}

	tracerProvider := trace.NewTracerProvider(opts...)
	otel.SetTracerProvider(tracerProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	return func(ctx context.Context) {
		err := tracerProvider.Shutdown(ctx)
		if err != nil {
			blog.Error(ctx, "Failed to shut down OpenTelemetry", err)
		}
	}
}

// AuditPanic catches and logs panics, then exits with exit code 1.
// This method should be called in a defer statement as early as possible.
func AuditPanic() {
	if backupLogger.log == nil {
		// We're so early in the process that a real logger hasn't been built yet.
		// Create one with a sane default config that cannot error during creation.
		logger, _ := blog.NewLogContext(blog.Config{StdoutLevel: 6, SyslogLevel: -1})
		backupLogger.init(logger)
	}
	ctx := backupLogger.log.New()

	err := recover()
	// No panic, no problem
	if err == nil {
		blog.AuditInfo(ctx, "Process exiting normally", info()...)
		return
	}
	// For the special type `failure`, audit log the message and exit quietly
	fail, ok := err.(failure)
	if ok {
		blog.AuditError(ctx, "Command failed", errors.New(fail.msg))
	} else {
		// For all other values (which might not be an error) passed to `panic`, log
		// them and a stack trace
		blog.AuditError(ctx, "Panic", fmt.Errorf("%#v", err), slog.String("stack", string(debug.Stack())))
	}
	// Because this function is deferred as early as possible, there's no further defers to run after this one
	// So it is safe to os.Exit to set the exit code and exit without losing any defers we haven't executed.
	os.Exit(1)
}

// failure is a sentinel type that `Fail` passes to `panic` so `AuditPanic` can exit
// quietly and print the msg.
type failure struct {
	msg string
}

func (f failure) String() string {
	return f.msg
}

// Fail raises a panic with a special type that causes `AuditPanic` to audit log the provided message
// and then exit nonzero (without printing a stack trace).
func Fail(msg string) {
	panic(failure{msg})
}

// FailOnError calls Fail if the provided error is non-nil.
// This is useful for one-line error handling in top-level executables,
// but should generally be avoided in libraries. The message argument is optional.
func FailOnError(err error, msg string) {
	if err == nil {
		return
	}
	if msg == "" {
		Fail(err.Error())
	} else {
		Fail(fmt.Sprintf("%s: %s", msg, err))
	}
}

func decodeJSONStrict(in io.Reader, out any) error {
	decoder := json.NewDecoder(in)
	decoder.DisallowUnknownFields()

	return decoder.Decode(out)
}

// ReadConfigFile takes a file path as an argument and attempts to
// unmarshal the content of the file into a struct containing a
// configuration of a boulder component. Any config keys in the JSON
// file which do not correspond to expected keys in the config struct
// will result in errors.
func ReadConfigFile(filename string, out any) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return decodeJSONStrict(file, out)
}

// ValidateJSONConfig takes a *ConfigValidator and an io.Reader containing a
// JSON representation of a config. The JSON data is unmarshaled into the
// *ConfigValidator's inner Config and then validated according to the
// 'validate' tags for on each field. Callers can use cmd.LookupConfigValidator
// to get a *ConfigValidator for a given Boulder component. This is exported for
// use in SRE CI tooling.
func ValidateJSONConfig(cv *ConfigValidator, in io.Reader) error {
	if cv == nil {
		return errors.New("config validator cannot be nil")
	}

	// Initialize the validator and load any custom tags.
	validate := validator.New()
	for tag, v := range cv.Validators {
		err := validate.RegisterValidation(tag, v)
		if err != nil {
			return err
		}
	}

	// Register custom types for use with existing validation tags.
	validate.RegisterCustomTypeFunc(config.DurationCustomTypeFunc, config.Duration{})

	err := decodeJSONStrict(in, cv.Config)
	if err != nil {
		return err
	}
	err = validate.Struct(cv.Config)
	if err != nil {
		errs, ok := err.(validator.ValidationErrors)
		if !ok {
			// This should never happen.
			return err
		}
		if len(errs) > 0 {
			allErrs := []string{}
			for _, e := range errs {
				allErrs = append(allErrs, e.Error())
			}
			return errors.New(strings.Join(allErrs, ", "))
		}
	}
	return nil
}

// ValidateYAMLConfig takes a *ConfigValidator and an io.Reader containing a
// YAML representation of a config. The YAML data is unmarshaled into the
// *ConfigValidator's inner Config and then validated according to the
// 'validate' tags for on each field. Callers can use cmd.LookupConfigValidator
// to get a *ConfigValidator for a given Boulder component. This is exported for
// use in SRE CI tooling.
func ValidateYAMLConfig(cv *ConfigValidator, in io.Reader) error {
	if cv == nil {
		return errors.New("config validator cannot be nil")
	}

	// Initialize the validator and load any custom tags.
	validate := validator.New()
	for tag, v := range cv.Validators {
		err := validate.RegisterValidation(tag, v)
		if err != nil {
			return err
		}
	}

	// Register custom types for use with existing validation tags.
	validate.RegisterCustomTypeFunc(config.DurationCustomTypeFunc, config.Duration{})

	inBytes, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	err = strictyaml.Unmarshal(inBytes, cv.Config)
	if err != nil {
		return err
	}
	err = validate.Struct(cv.Config)
	if err != nil {
		errs, ok := err.(validator.ValidationErrors)
		if !ok {
			// This should never happen.
			return err
		}
		if len(errs) > 0 {
			allErrs := []string{}
			for _, e := range errs {
				allErrs = append(allErrs, e.Error())
			}
			return errors.New(strings.Join(allErrs, ", "))
		}
	}
	return nil
}

// info produces build information about this binary
func info() []slog.Attr {
	return []slog.Attr{
		slog.String("command", core.Command()),
		slog.String("buildID", core.GetBuildID()),
		slog.String("buildTime", core.GetBuildTime()),
		slog.String("goVersion", runtime.Version()),
		slog.String("buildHost", core.GetBuildHost()),
	}
}

func LogStartup(logctx *blog.LogContext) {
	blog.AuditInfo(logctx.New(), "Process starting", info()...)
}

// CatchSignals blocks until a SIGTERM, SIGINT, or SIGHUP is received, then
// executes the given callback. The callback should not block, it should simply
// signal other goroutines (particularly the main goroutine) to clean themselves
// up and exit. This function is intended to be called in its own goroutine,
// while the main goroutine waits for an indication that the other goroutines
// have exited cleanly.
func CatchSignals(callback func()) {
	WaitForSignal()
	callback()
}

// WaitForSignal blocks until a SIGTERM, SIGINT, or SIGHUP is received. It then
// returns, allowing execution to resume, generally allowing a main() function
// to return and trigger and deferred cleanup functions. This function is
// intended to be called directly from the main goroutine, while a gRPC or HTTP
// server runs in a background goroutine.
func WaitForSignal() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGINT)
	signal.Notify(sigChan, syscall.SIGHUP)
	<-sigChan
}
