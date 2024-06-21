package sfe

import (
	"crypto"
	"crypto/ed25519"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/letsencrypt/boulder/core"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics/measured_http"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

const (
	// The API version should be checked when parsing parameters to quickly deny
	// a client request. Can be used to mass-invalidate URLs.
	unpausePath = "/sfe/v1/unpause"
)

var (
	//go:embed all:static
	staticFS embed.FS

	//go:embed all:templates all:pages
	dynamicFS embed.FS

	// HTML pages to-be-served by the SFE
	tmplPages *template.Template
)

// Parse the files once at startup to avoid each request causing the server to
// JIT parse. The pages are stored in an in-memory embed.FS to prevent
// unnecessary filesystem I/O on a physical HDD.
func init() {
	tmplPages = template.Must(template.New("pages").ParseFS(dynamicFS, "templates/layout.html", "pages/*"))
}

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

	// unpausePubKey is a x/crypto/ed25519 public key derived from a seed value
	// shared by the SFE and WFE. It is used to validate incoming JWT signatures
	// on the unpause endpoint.
	unpausePubKey crypto.PublicKey
}

// NewSelfServiceFrontEndImpl constructs a web service for Boulder
func NewSelfServiceFrontEndImpl(
	stats prometheus.Registerer,
	clk clock.Clock,
	logger blog.Logger,
	requestTimeout time.Duration,
	rac rapb.RegistrationAuthorityClient,
	sac sapb.StorageAuthorityReadOnlyClient,
	unpauseSeed string,
) (SelfServiceFrontEndImpl, error) {
	// The seed is used to generate an x/crypto/ed25519 keypair which
	// requires a SeedSize of 32 bytes or the generator will panic.
	if len(unpauseSeed) != 32 {
		return SelfServiceFrontEndImpl{}, errors.New("unpauseSeed should be 32 hexadecimal characters e.g. the output of 'openssl rand -hex 16'")
	}

	// We only need the public key to check the JWT signature and it only needs
	// to be generate at startup.
	unpausePubKey := ed25519.NewKeyFromSeed([]byte(unpauseSeed)).Public()

	sfe := SelfServiceFrontEndImpl{
		log:            logger,
		clk:            clk,
		requestTimeout: requestTimeout,
		ra:             rac,
		sa:             sac,
		unpausePubKey:  unpausePubKey,
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
	m.HandleFunc(unpausePath, sfe.Unpause)

	return measured_http.New(m, sfe.clk, stats, oTelHTTPOptions...)
}

// renderTemplate takes an HTML template instantiated by the SFE init() and an
// optional dynamicData which are rendered and served back to the client via the
// response writer.
func renderTemplate(w http.ResponseWriter, subTmpl string, dynamicData any) {
	if len(subTmpl) == 0 {
		http.Error(w, "Template page does not exist", http.StatusInternalServerError)
		return
	}

	err := tmplPages.ExecuteTemplate(w, subTmpl, dynamicData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Index is the homepage of the SFE
func (sfe *SelfServiceFrontEndImpl) Index(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Access-Control-Allow-Methods", "GET, HEAD")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	renderTemplate(response, "index.html", nil)
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

// unpauseJWT is generated by a WFE and is used to round-trip back to the WFE to
// unpause the requester's account.
type unpauseJWT string

func (sfe *SelfServiceFrontEndImpl) getHelper(response http.ResponseWriter, incomingJWT unpauseJWT) {
	if incomingJWT != "" {
		type tmplData struct {
			UnpausePath string
			JWT         string
		}

		// Serve the actual unpause page given to a Subscriber. Populates the
		// unpause form with the JWT from the URL. That JWT itself may be
		// invalid or expired, but that validation will be performed only after
		// submitting the form.
		renderTemplate(response, "unpause-params.html", tmplData{unpausePath, string(incomingJWT)})
	} else {
		// We only want to accept requests containing the JWT param.
		renderTemplate(response, "unpause-noParams.html", nil)
	}
}

// posthelper After clicking unpause, serve a page indicating if the unpause succeeded or failed.
func (sfe *SelfServiceFrontEndImpl) postHelper(response http.ResponseWriter, incomingJWT unpauseJWT) {
	if incomingJWT != "" {
		type tmplData struct {
			ShouldUnpause bool
			AccountID     string
		}

		claims, err := sfe.validateJWTforAccount(incomingJWT)
		if err != nil {
			renderTemplate(response, "unpause-post.html", nil)
		}

		// TODO(#7356) Declare a registration ID variable to populate an
		// rapb unpause account request message.
		_, innerErr := strconv.ParseInt(claims.Subject, 10, 64)
		if innerErr != nil {
			renderTemplate(response, "unpause-noParams.html", nil)
		}

		// TODO(#7536) Send gRPC request to the RA informing it to unpause
		// the account specified in the claim. At this point we should wait
		// for the RA to process the request before returning to the client,
		// just in case the request fails.

		// Success, the account has been unpaused.
		renderTemplate(response, "unpause-post.html", tmplData{true, claims.Subject})
	} else {
		renderTemplate(response, "unpause-noParams.html", nil)
	}
}

// Unpause allows a requester to unpause their account via a form present on the
// page.
func (sfe *SelfServiceFrontEndImpl) Unpause(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodHead:
		return
	case http.MethodGet:
		sfe.getHelper(response, unpauseJWT(request.URL.Query().Get("jwt")))
	case http.MethodPost:
		sfe.postHelper(response, unpauseJWT(request.URL.Query().Get("jwt")))
	default:
		response.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

type sfeJWTClaims struct {
	jwt.Claims

	// Version is a custom claim used to mass invalidate existing JWTs by
	// changing the API version via unpausePath.
	Version string `json:"apiVersion,omitempty"`
}

// validateJWT derives a ed25519 public key from a seed shared by the SFE and
// WFE. The public key is used to validate the signature and contents of an
// unpauseJWT and verify that the its claims match a set of expected claims.
// Passing validations returns the claims or an error.
func (sfe *SelfServiceFrontEndImpl) validateJWTforAccount(incomingJWT unpauseJWT) (sfeJWTClaims, error) {
	slug := strings.Split(unpausePath, "/")
	if len(slug) != 4 {
		return sfeJWTClaims{}, errors.New("Could not parse API version")
	}

	token, err := jwt.ParseSigned(string(incomingJWT), []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return sfeJWTClaims{}, fmt.Errorf("parsing JWT: %s", err)
	}

	incomingClaims := sfeJWTClaims{}
	err = token.Claims(sfe.unpausePubKey, &incomingClaims)
	if err != nil {
		return sfeJWTClaims{}, err
	}

	expectedClaims := jwt.Expected{
		Issuer:      "WFE",
		AnyAudience: jwt.Audience{"SFE Unpause"},
		// Time is passed into the jwt package for tests to manipulate time.
		Time: sfe.clk.Now(),
	}

	err = incomingClaims.Validate(expectedClaims)
	if err != nil {
		return sfeJWTClaims{}, err
	}

	if len(incomingClaims.Subject) == 0 {
		return sfeJWTClaims{}, errors.New("Account ID required for account unpausing")
	}

	if incomingClaims.Version == "" {
		return sfeJWTClaims{}, errors.New("Incoming JWT was created with no API version")
	}

	if incomingClaims.Version != slug[2] {
		return sfeJWTClaims{}, fmt.Errorf("JWT created for unpause API version %s was provided to the incompatible API version %s", incomingClaims.Version, slug[2])
	}

	return incomingClaims, nil
}
