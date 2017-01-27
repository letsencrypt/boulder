package main

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	cfocsp "github.com/cloudflare/cfssl/ocsp"
	"github.com/facebookgo/httpdown"
	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
)

/*
DBSource maps a given Database schema to a CA Key Hash, so we can pick
from among them when presented with OCSP requests for different certs.

We assume that OCSP responses are stored in a very simple database table,
with two columns: serialNumber and response

  CREATE TABLE ocsp_responses (serialNumber TEXT, response BLOB);

The serialNumber field may have any type to which Go will match a string,
so you can be more efficient than TEXT if you like.  We use it to store the
serial number in base64.  You probably want to have an index on the
serialNumber field, since we will always query on it.

*/
type DBSource struct {
	dbMap     dbSelector
	caKeyHash []byte
	log       blog.Logger
}

// Since the only thing we use from gorp is the SelectOne method on the
// gorp.DbMap object, we just define the interface an interface with that method
// instead of importing all of gorp. This also allows us to simulate MySQL failures
// by mocking the interface.
type dbSelector interface {
	SelectOne(holder interface{}, query string, args ...interface{}) error
}

// NewSourceFromDatabase produces a DBSource representing the binding of a
// given DB schema to a CA key.
func NewSourceFromDatabase(dbMap dbSelector, caKeyHash []byte, log blog.Logger) (src *DBSource, err error) {
	src = &DBSource{dbMap: dbMap, caKeyHash: caKeyHash, log: log}
	return
}

type dbResponse struct {
	OCSPResponse    []byte
	OCSPLastUpdated time.Time
}

// Response is called by the HTTP server to handle a new OCSP request.
func (src *DBSource) Response(req *ocsp.Request) ([]byte, bool) {
	// Check that this request is for the proper CA
	if bytes.Compare(req.IssuerKeyHash, src.caKeyHash) != 0 {
		src.log.Debug(fmt.Sprintf("Request intended for CA Cert ID: %s", hex.EncodeToString(req.IssuerKeyHash)))
		return nil, false
	}

	serialString := core.SerialToString(req.SerialNumber)
	src.log.Debug(fmt.Sprintf("Searching for OCSP issued by us for serial %s", serialString))

	var response dbResponse
	defer func() {
		if len(response.OCSPResponse) != 0 {
			src.log.Debug(fmt.Sprintf("OCSP Response sent for CA=%s, Serial=%s", hex.EncodeToString(src.caKeyHash), serialString))
		}
	}()
	err := src.dbMap.SelectOne(
		&response,
		"SELECT ocspResponse, ocspLastUpdated FROM certificateStatus WHERE serial = :serial",
		map[string]interface{}{"serial": serialString},
	)
	if err != nil && err != sql.ErrNoRows {
		src.log.AuditErr(fmt.Sprintf("Failed to retrieve response from certificateStatus table: %s", err))
	}
	if err != nil {
		return nil, false
	}
	if response.OCSPLastUpdated.IsZero() {
		src.log.Debug(fmt.Sprintf("OCSP Response not sent (ocspLastUpdated is zero) for CA=%s, Serial=%s", hex.EncodeToString(src.caKeyHash), serialString))
		return nil, false
	}

	return response.OCSPResponse, true
}

func makeDBSource(dbMap dbSelector, issuerCert string, log blog.Logger) (*DBSource, error) {
	// Load the CA's key so we can store its SubjectKey in the DB
	caCertDER, err := cmd.LoadCert(issuerCert)
	if err != nil {
		return nil, fmt.Errorf("Could not read issuer cert %s: %s", issuerCert, err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("Could not parse issuer cert %s: %s", issuerCert, err)
	}
	if len(caCert.SubjectKeyId) == 0 {
		return nil, fmt.Errorf("Empty subjectKeyID")
	}

	// Construct source from DB
	return NewSourceFromDatabase(dbMap, caCert.SubjectKeyId, log)
}

type config struct {
	OCSPResponder struct {
		cmd.ServiceConfig
		cmd.DBConfig

		// Source indicates the source of pre-signed OCSP responses to be used. It
		// can be a DBConnect string or a file URL. The file URL style is used
		// when responding from a static file for intermediates and roots.
		// If DBConfig has non-empty fields, it takes precedence over this.
		Source string

		Path          string
		ListenAddress string
		// MaxAge is the max-age to set in the Cache-Control response
		// header. It is a time.Duration formatted string.
		MaxAge cmd.ConfigDuration

		ShutdownStopTimeout string
		ShutdownKillTimeout string

		Features map[string]bool
	}

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig

	Common struct {
		IssuerCert string
	}
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		fmt.Fprintf(os.Stderr, `Usage of %s:
Config JSON should contain either a DBConnectFile or a Source value containing a file: URL.
If Source is a file: URL, the file should contain a list of OCSP responses in base64-encoded DER,
as generated by Boulder's single-ocsp command.
`, os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")
	err = features.Set(c.OCSPResponder.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	scope := metrics.NewStatsdScope(stats, "OCSPResponder")
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString("ocsp-responder"))

	config := c.OCSPResponder
	var source cfocsp.Source

	if strings.HasPrefix(config.Source, "file:") {
		url, err := url.Parse(config.Source)
		cmd.FailOnError(err, "Source was not a URL")
		filename := url.Path
		// Go interprets cwd-relative file urls (file:test/foo.txt) as having the
		// relative part of the path in the 'Opaque' field.
		if filename == "" {
			filename = url.Opaque
		}
		source, err = cfocsp.NewSourceFromFile(filename)
		cmd.FailOnError(err, fmt.Sprintf("Couldn't read file: %s", url.Path))
	} else {
		// For databases, DBConfig takes precedence over Source, if present.
		dbConnect, err := config.DBConfig.URL()
		cmd.FailOnError(err, "Reading DB config")
		if dbConnect == "" {
			dbConnect = config.Source
		}
		logger.Info(fmt.Sprintf("Loading OCSP Database for CA Cert: %s", c.Common.IssuerCert))
		dbMap, err := sa.NewDbMap(dbConnect, config.DBConfig.MaxDBConns)
		cmd.FailOnError(err, "Could not connect to database")
		sa.SetSQLDebug(dbMap, logger)
		go sa.ReportDbConnCount(dbMap, scope)
		source, err = makeDBSource(dbMap, c.Common.IssuerCert, logger)
		cmd.FailOnError(err, "Couldn't load OCSP DB")
	}

	stopTimeout, err := time.ParseDuration(c.OCSPResponder.ShutdownStopTimeout)
	cmd.FailOnError(err, "Couldn't parse shutdown stop timeout")
	killTimeout, err := time.ParseDuration(c.OCSPResponder.ShutdownKillTimeout)
	cmd.FailOnError(err, "Couldn't parse shutdown kill timeout")
	m := mux(scope, c.OCSPResponder.Path, source)
	srv := &http.Server{
		Addr:    c.OCSPResponder.ListenAddress,
		Handler: m,
	}

	go cmd.DebugServer(c.OCSPResponder.DebugAddr)
	go cmd.ProfileCmd(scope)

	hd := &httpdown.HTTP{
		StopTimeout: stopTimeout,
		KillTimeout: killTimeout,
		Stats:       metrics.NewFBAdapter(scope, clock.Default()),
	}
	hdSrv, err := hd.ListenAndServe(srv)
	cmd.FailOnError(err, "Error starting HTTP server")

	go cmd.CatchSignals(logger, func() { _ = hdSrv.Stop() })

	forever := make(chan struct{}, 1)
	<-forever
}

func mux(scope metrics.Scope, responderPath string, source cfocsp.Source) http.Handler {
	m := http.StripPrefix(responderPath, cfocsp.NewResponder(source))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "max-age=43200") // Cache for 12 hours
			w.WriteHeader(200)
			return
		}
		m.ServeHTTP(w, r)
	})
	return metrics.NewHTTPMonitor(scope, h)
}
