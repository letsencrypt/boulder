package sfe

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics/measured_http"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/unpause"
)

const (
	unpausePostForm = unpause.APIPrefix + "/do-unpause"
	unpauseStatus   = unpause.APIPrefix + "/unpause-status"
)

var (
	//go:embed all:static
	staticFS embed.FS

	//go:embed all:templates all:pages
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
	templatePages  *template.Template
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
) (SelfServiceFrontEndImpl, error) {

	// Parse the files once at startup to avoid each request causing the server
	// to JIT parse. The pages are stored in an in-memory embed.FS to prevent
	// unnecessary filesystem I/O on a physical HDD.
	tmplPages := template.Must(template.New("pages").ParseFS(dynamicFS, "templates/layout.html", "pages/*"))

	sfe := SelfServiceFrontEndImpl{
		log:            logger,
		clk:            clk,
		requestTimeout: requestTimeout,
		ra:             rac,
		sa:             sac,
		unpauseHMACKey: unpauseHMACKey,
		templatePages:  tmplPages,
	}

	return sfe, nil
}

// Handler returns an http.Handler that uses various functions for various
// non-ACME-specified paths. Each endpoint should have a corresponding HTML
// page that shares the same name as the endpoint.
func (sfe *SelfServiceFrontEndImpl) Handler(stats prometheus.Registerer, oTelHTTPOptions ...otelhttp.Option) http.Handler {
	m := http.NewServeMux()

	sfs, _ := fs.Sub(staticFS, "static")
	staticAssetsHandler := http.StripPrefix("/static/", http.FileServerFS(sfs))

	m.Handle("GET /static/", staticAssetsHandler)
	m.HandleFunc("/", sfe.Index)
	m.HandleFunc("GET /build", sfe.BuildID)
	m.HandleFunc("GET "+unpause.GetForm, sfe.UnpauseForm)
	m.HandleFunc("POST "+unpausePostForm, sfe.UnpauseSubmit)
	m.HandleFunc("GET "+unpauseStatus, sfe.UnpauseStatus)

	return measured_http.New(m, sfe.clk, stats, oTelHTTPOptions...)
}

// renderTemplate takes the name of an HTML template and optional dynamicData
// which are rendered and served back to the client via the response writer.
func (sfe *SelfServiceFrontEndImpl) renderTemplate(w http.ResponseWriter, filename string, dynamicData any) {
	if len(filename) == 0 {
		http.Error(w, "Template page does not exist", http.StatusInternalServerError)
		return
	}

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

// UnpauseForm allows a requester to unpause their account via a form present on
// the page. The Subscriber's client will receive a log line emitted by the WFE
// which contains a URL pre-filled with a JWT that will populate a hidden field
// in this form.
func (sfe *SelfServiceFrontEndImpl) UnpauseForm(response http.ResponseWriter, request *http.Request) {
	incomingJWT := request.URL.Query().Get("jwt")
	if incomingJWT == "" {
		sfe.unpauseInvalidRequest(response)
		return
	}

	regID, identifiers, err := sfe.parseUnpauseJWT(incomingJWT)
	if err != nil {
		sfe.unpauseStatusHelper(response, false)
		return
	}

	type tmplData struct {
		UnpauseFormRedirectionPath string
		JWT                        string
		AccountID                  int64
		Identifiers                []string
	}

	// Serve the actual unpause page given to a Subscriber. Populates the
	// unpause form with the JWT from the URL.
	sfe.renderTemplate(response, "unpause-form.html", tmplData{unpausePostForm, incomingJWT, regID, identifiers})
}

// UnpauseSubmit serves a page indicating if the unpause form submission
// succeeded or failed upon clicking the unpause button. We are explicitly
// choosing to not address CSRF at this time because we control creation and
// redemption of the JWT.
func (sfe *SelfServiceFrontEndImpl) UnpauseSubmit(response http.ResponseWriter, request *http.Request) {
	incomingJWT := request.URL.Query().Get("jwt")
	if incomingJWT == "" {
		sfe.unpauseInvalidRequest(response)
		return
	}

	_, _, err := sfe.parseUnpauseJWT(incomingJWT)
	if err != nil {
		sfe.unpauseStatusHelper(response, false)
		return
	}

	// TODO(#7536) Send gRPC request to the RA informing it to unpause
	// the account specified in the claim. At this point we should wait
	// for the RA to process the request before returning to the client,
	// just in case the request fails.

	// Success, the account has been unpaused.
	http.Redirect(response, request, unpauseStatus, http.StatusFound)
}

// unpauseInvalidRequest is a helper that displays a page indicating the
// Subscriber perform basic troubleshooting due to lack of JWT in the data
// object.
func (sfe *SelfServiceFrontEndImpl) unpauseInvalidRequest(response http.ResponseWriter) {
	sfe.renderTemplate(response, "unpause-invalid-request.html", nil)
}

type unpauseStatusTemplateData struct {
	UnpauseSuccessful bool
}

// unpauseStatus is a helper that, by default, displays a failure message to the
// Subscriber indicating that their account has failed to unpause. For failure
// scenarios, only when the JWT validation should call this. Other types of
// failures should use unpauseInvalidRequest. For successes, call UnpauseStatus
// instead.
func (sfe *SelfServiceFrontEndImpl) unpauseStatusHelper(response http.ResponseWriter, status bool) {
	sfe.renderTemplate(response, "unpause-status.html", unpauseStatusTemplateData{status})
}

// UnpauseStatus displays a success message to the Subscriber indicating that
// their account has been unpaused.
func (sfe *SelfServiceFrontEndImpl) UnpauseStatus(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodHead && request.Method != http.MethodGet {
		response.Header().Set("Access-Control-Allow-Methods", "GET, HEAD")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// TODO(#7580) This should only be reachable after a client has clicked the
	// "Please unblock my account" button and that request succeeding. No one
	// should be able to access this page otherwise.
	sfe.unpauseStatusHelper(response, true)
}

// parseUnpauseJWT extracts and returns the subscriber's registration ID and a
// slice of paused identifiers from the claims. If the JWT cannot be parsed or
// is otherwise invalid, an error is returned.
func (sfe *SelfServiceFrontEndImpl) parseUnpauseJWT(incomingJWT string) (int64, []string, error) {
	slug := strings.Split(unpause.APIPrefix, "/")
	if len(slug) != 3 {
		return 0, nil, errors.New("failed to parse API version")
	}

	claims, err := unpause.RedeemJWT(incomingJWT, sfe.unpauseHMACKey, slug[2], sfe.clk)
	if err != nil {
		return 0, nil, err
	}

	account, convErr := strconv.ParseInt(claims.Subject, 10, 64)
	if convErr != nil {
		// This should never happen as this was just validated by the call to
		// unpause.RedeemJWT().
		return 0, nil, errors.New("failed to parse account ID from JWT")
	}

	return account, strings.Split(claims.I, ","), nil
}
