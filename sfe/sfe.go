package sfe

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics/measured_http"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sfe/zendesk"
	"github.com/letsencrypt/boulder/unpause"
)

var (
	//go:embed all:static
	staticFS embed.FS

	//go:embed all:templates all:pages all:static
	dynamicFS embed.FS
)

// SelfServiceFrontEndImpl provides all the logic for Boulder's selfservice
// frontend web-facing interface, i.e., a portal where a subscriber can unpause
// their account. Its methods are primarily handlers for HTTPS requests for the
// various non-ACME functions.
type SelfServiceFrontEndImpl struct {
	ra rapb.RegistrationAuthorityClient
	sa sapb.StorageAuthorityReadOnlyClient

	log blog.Logger
	clk clock.Clock

	// requestTimeout is the per-request overall timeout.
	requestTimeout time.Duration

	unpauseHMACKey []byte
	zendeskClient  *zendesk.Client //nolint:unused // TODO(#8166): For periodic Zendesk sync.

	templatePages *template.Template
}

// NewSelfServiceFrontEndImpl constructs a web service for Boulder
func NewSelfServiceFrontEndImpl(
	stats prometheus.Registerer,
	clk clock.Clock,
	logger blog.Logger,
	requestTimeout time.Duration,
	rac rapb.RegistrationAuthorityClient,
	sac sapb.StorageAuthorityReadOnlyClient,
	unpauseHMACKey []byte,
	zendeskClient *zendesk.Client,
) (SelfServiceFrontEndImpl, error) {

	// Parse the files once at startup to avoid each request causing the server
	// to JIT parse. The pages are stored in an in-memory embed.FS to prevent
	// unnecessary filesystem I/O on a physical HDD.
	tmplPages := template.Must(template.New("pages").ParseFS(dynamicFS, "templates/*", "pages/*"))

	sfe := SelfServiceFrontEndImpl{
		log:            logger,
		clk:            clk,
		requestTimeout: requestTimeout,
		ra:             rac,
		sa:             sac,
		unpauseHMACKey: unpauseHMACKey,
		zendeskClient:  zendeskClient,
		templatePages:  tmplPages,
	}

	return sfe, nil
}

// handleWithTimeout registers a handler with a timeout using an
// http.TimeoutHandler.
func (sfe *SelfServiceFrontEndImpl) handleWithTimeout(mux *http.ServeMux, path string, handler http.HandlerFunc) {
	timeout := sfe.requestTimeout
	if timeout <= 0 {
		// Default to 5 minutes if no timeout is set.
		timeout = 5 * time.Minute
	}
	timeoutHandler := http.TimeoutHandler(handler, timeout, "Request timed out")
	mux.Handle(path, timeoutHandler)
}

// Handler returns an http.Handler that uses various functions for various
// non-ACME-specified paths. Each endpoint should have a corresponding HTML
// page that shares the same name as the endpoint.
func (sfe *SelfServiceFrontEndImpl) Handler(stats prometheus.Registerer, oTelHTTPOptions ...otelhttp.Option) http.Handler {
	mux := http.NewServeMux()

	sfs, _ := fs.Sub(staticFS, "static")
	staticAssetsHandler := http.StripPrefix("/static/", http.FileServerFS(sfs))
	mux.Handle("GET /static/", staticAssetsHandler)

	sfe.handleWithTimeout(mux, "/", sfe.Index)
	sfe.handleWithTimeout(mux, "GET /build", sfe.BuildID)

	// Unpause
	sfe.handleWithTimeout(mux, "GET "+unpause.GetForm, sfe.UnpauseForm)
	sfe.handleWithTimeout(mux, "POST "+unpausePostForm, sfe.UnpauseSubmit)
	sfe.handleWithTimeout(mux, "GET "+unpauseStatus, sfe.UnpauseStatus)

	// Rate Limit Overrides
	sfe.handleWithTimeout(mux, "POST /override/validate-field", sfe.ValidateOverrideFieldHandler)
	sfe.handleWithTimeout(mux, "GET /override/new-orders-per-account", sfe.NewOrderPerAccountOverrideRequestHandler)
	sfe.handleWithTimeout(mux, "GET /override/certificates-per-domain", sfe.CertificatesPerDomainOverrideRequestHandler)
	sfe.handleWithTimeout(mux, "GET /override/certificates-per-ip", sfe.CertificatesPerIPOverrideRequestHandler)
	sfe.handleWithTimeout(mux, "GET /override/certificates-per-domain-per-account", sfe.CertificatesPerDomainPerAccountOverrideRequestHandler)
	sfe.handleWithTimeout(mux, "POST /override/submit-override-request", sfe.SubmitOverrideRequestHandler)
	sfe.handleWithTimeout(mux, "GET /override/success", sfe.OverrideSuccessHandler)

	return measured_http.New(mux, sfe.clk, stats, oTelHTTPOptions...)
}

// renderTemplate takes the name of an HTML template and optional dynamicData
// which are rendered and served back to the client via the response writer.
func (sfe *SelfServiceFrontEndImpl) renderTemplate(w http.ResponseWriter, filename string, dynamicData any) {
	if len(filename) == 0 {
		http.Error(w, "Template page does not exist", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := sfe.templatePages.ExecuteTemplate(w, filename, dynamicData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Index is the homepage of the SFE
func (sfe *SelfServiceFrontEndImpl) Index(response http.ResponseWriter, request *http.Request) {
	sfe.renderTemplate(response, "index.html", nil)
}

// BuildID tells the requester what boulder build version is running.
func (sfe *SelfServiceFrontEndImpl) BuildID(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "text/plain")
	response.WriteHeader(http.StatusOK)
	detailsString := fmt.Sprintf("Boulder=(%s %s)", core.GetBuildID(), core.GetBuildTime())
	if _, err := fmt.Fprintln(response, detailsString); err != nil {
		sfe.log.Warningf("Could not write response: %s", err)
	}
}
