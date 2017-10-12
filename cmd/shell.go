// This package provides utilities that underlie the specific commands.
// The idea is to make the specific command files very small, e.g.:
//
//    func main() {
//      app := cmd.NewAppShell("command-name")
//      app.Action = func(c cmd.Config) {
//        // command logic
//      }
//      app.Run()
//    }
//
// All commands share the same invocation pattern.  They take a single
// parameter "-config", which is the name of a JSON file containing
// the configuration for the app.  This JSON file is unmarshalled into
// a Config object, which is provided to the app.

package cmd

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc/grpclog"

	cfsslLog "github.com/cloudflare/cfssl/log"
	"github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
)

// Because we don't know when this init will be called with respect to
// flag.Parse() and other flag definitions, we can't rely on the regular
// flag mechanism. But this one is fine.
func init() {
	for _, v := range os.Args {
		if v == "--version" || v == "-version" {
			fmt.Println(VersionString())
			os.Exit(0)
		}
	}
}

// mysqlLogger proxies blog.AuditLogger to provide a Print(...) method.
type mysqlLogger struct {
	blog.Logger
}

func (m mysqlLogger) Print(v ...interface{}) {
	m.AuditErr(fmt.Sprintf("[mysql] %s", fmt.Sprint(v...)))
}

// cfsslLogger provides two additional methods that are expected by CFSSL's
// logger but not supported by Boulder's Logger.
type cfsslLogger struct {
	blog.Logger
}

func (cl cfsslLogger) Crit(msg string) {
	cl.AuditErr(msg)
}

func (cl cfsslLogger) Emerg(msg string) {
	cl.AuditErr(msg)
}

type grpcLogger struct {
	blog.Logger
}

func (log grpcLogger) Fatal(args ...interface{}) {
	log.Print(args...)
	os.Exit(1)
}
func (log grpcLogger) Fatalf(format string, args ...interface{}) {
	log.Printf(format, args...)
	os.Exit(1)
}
func (log grpcLogger) Fatalln(args ...interface{}) {
	log.Println(args...)
	os.Exit(1)
}
func (log grpcLogger) Print(args ...interface{}) {
	log.AuditErr(fmt.Sprint(args...))
}
func (log grpcLogger) Printf(format string, args ...interface{}) {
	log.AuditErr(fmt.Sprintf(format, args...))
}
func (log grpcLogger) Println(args ...interface{}) {
	log.AuditErr(fmt.Sprintln(args...))
}

type promLogger struct {
	blog.Logger
}

func (log promLogger) Println(args ...interface{}) {
	log.AuditErr(fmt.Sprintln(args...))
}

// StatsAndLogging constructs a metrics.Scope and an AuditLogger based on its config
// parameters, and return them both. It also spawns off an HTTP server on the
// provided port to report the stats and provide pprof profiling handlers.
// Crashes if any setup fails.
// Also sets the constructed AuditLogger as the default logger, and configures
// the cfssl, mysql, and grpc packages to use our logger.
// This must be called before any gRPC code is called, because gRPC's SetLogger
// doesn't use any locking.
func StatsAndLogging(logConf SyslogConfig, addr string) (metrics.Scope, blog.Logger) {
	logger := MakeLogger(logConf)
	scope := makeStats(addr, logger)
	return scope, logger
}

func MakeLogger(logConf SyslogConfig) blog.Logger {
	tag := path.Base(os.Args[0])
	syslogger, err := syslog.Dial(
		"",
		"",
		syslog.LOG_INFO, // default, not actually used
		tag)
	FailOnError(err, "Could not connect to Syslog")
	syslogLevel := int(syslog.LOG_INFO)
	if logConf.SyslogLevel != 0 {
		syslogLevel = logConf.SyslogLevel
	}
	logger, err := blog.New(syslogger, logConf.StdoutLevel, syslogLevel)
	FailOnError(err, "Could not connect to Syslog")

	_ = blog.Set(logger)
	cfsslLog.SetLogger(cfsslLogger{logger})
	_ = mysql.SetLogger(mysqlLogger{logger})
	grpclog.SetLogger(grpcLogger{logger})
	return logger
}

func makeStats(addr string, logger blog.Logger) metrics.Scope {
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGoCollector())
	registry.MustRegister(prometheus.NewProcessCollector(os.Getpid(), "boulder"))

	mux := http.NewServeMux()
	reg := func(name string) {
		mux.Handle("/debug/pprof/"+name, pprof.Handler(name))
	}
	reg("block")
	reg("goroutine")
	reg("heap")
	reg("mutex")
	reg("profile")
	reg("threadcreate")
	reg("trace")
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		ErrorLog: promLogger{logger},
	}))

	server := http.Server{
		Addr:    addr,
		Handler: mux,
	}
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			log.Fatalf("unable to boot debug server on %s: %v", addr, err)
		}
	}()
	return metrics.NewPromScope(registry)
}

// FailOnError exits and prints an error message if we encountered a problem
func FailOnError(err error, msg string) {
	if err != nil {
		logger := blog.Get()
		logger.AuditErr(fmt.Sprintf("%s: %s", msg, err))
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}

// ProfileCmd runs forever, sending Go runtime statistics to StatsD.
func ProfileCmd(stats metrics.Scope) {
	stats = stats.NewScope("Gostats")
	var memoryStats runtime.MemStats
	prevNumGC := int64(0)
	c := time.Tick(1 * time.Second)
	for range c {
		runtime.ReadMemStats(&memoryStats)

		// Gather goroutine count
		stats.Gauge("Goroutines", int64(runtime.NumGoroutine()))

		// Gather various heap metrics
		stats.Gauge("Heap.Alloc", int64(memoryStats.HeapAlloc))
		stats.Gauge("Heap.Objects", int64(memoryStats.HeapObjects))
		stats.Gauge("Heap.Idle", int64(memoryStats.HeapIdle))
		stats.Gauge("Heap.InUse", int64(memoryStats.HeapInuse))
		stats.Gauge("Heap.Released", int64(memoryStats.HeapReleased))

		// Gather various GC related metrics
		if memoryStats.NumGC > 0 {
			totalRecentGC := uint64(0)
			realBufSize := uint32(256)
			if memoryStats.NumGC < 256 {
				realBufSize = memoryStats.NumGC
			}
			for _, pause := range memoryStats.PauseNs {
				totalRecentGC += pause
			}
			gcPauseAvg := totalRecentGC / uint64(realBufSize)
			lastGC := memoryStats.PauseNs[(memoryStats.NumGC+255)%256]
			stats.Timing("Gc.PauseAvg", int64(gcPauseAvg))
			stats.Gauge("Gc.LastPause", int64(lastGC))
		}
		stats.Gauge("Gc.NextAt", int64(memoryStats.NextGC))
		// Send both a counter and a gauge here we can much more easily observe
		// the GC rate (versus the raw number of GCs) in graphing tools that don't
		// like deltas
		stats.Gauge("Gc.Count", int64(memoryStats.NumGC))
		gcInc := int64(memoryStats.NumGC) - prevNumGC
		stats.Inc("Gc.Rate", gcInc)
		prevNumGC += gcInc
	}
}

// LoadCert loads a PEM-formatted certificate from the provided path, returning
// it as a byte array, or an error if it couldn't be decoded.
func LoadCert(path string) (cert []byte, err error) {
	if path == "" {
		err = errors.New("Issuer certificate was not provided in config.")
		return
	}
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		err = errors.New("Invalid certificate value returned")
		return
	}

	cert = block.Bytes
	return
}

// ReadConfigFile takes a file path as an argument and attempts to
// unmarshal the content of the file into a struct containing a
// configuration of a boulder component.
func ReadConfigFile(filename string, out interface{}) error {
	configData, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(configData, out)
}

// VersionString produces a friendly Application version string.
func VersionString() string {
	name := path.Base(os.Args[0])
	return fmt.Sprintf("Versions: %s=(%s %s) Golang=(%s) BuildHost=(%s)", name, core.GetBuildID(), core.GetBuildTime(), runtime.Version(), core.GetBuildHost())
}

var signalToName = map[os.Signal]string{
	syscall.SIGTERM: "SIGTERM",
	syscall.SIGINT:  "SIGINT",
	syscall.SIGHUP:  "SIGHUP",
}

// CatchSignals catches SIGTERM, SIGINT, SIGHUP and executes a callback
// method before exiting
func CatchSignals(logger blog.Logger, callback func()) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGINT)
	signal.Notify(sigChan, syscall.SIGHUP)

	sig := <-sigChan
	if logger != nil {
		logger.Info(fmt.Sprintf("Caught %s", signalToName[sig]))
	}

	if callback != nil {
		callback()
	}

	if logger != nil {
		logger.Info("Exiting")
	}
	os.Exit(0)
}

// FilterShutdownErrors returns the input error, with the exception of "use of
// closed network connection," on which it returns nil
// Per https://github.com/grpc/grpc-go/issues/1017, a gRPC server's `Serve()`
// will always return an error, even when GracefulStop() is called. We don't
// want to log graceful stops as errors, so we filter out the meaningless
// error we get in that situation.
func FilterShutdownErrors(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}
