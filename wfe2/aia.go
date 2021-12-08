//go:build integration

package wfe2

import (
	"context"
	"net/http"
	"strconv"

	"github.com/honeycombio/beeline-go/wrappers/hnynethttp"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/metrics/measured_http"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/web"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	aiaIssuerPath = "/aia/issuer/"
)

// Handler returns an http.Handler that uses various functions for
// various ACME-specified paths.
func (wfe *WebFrontEndImpl) Handler(stats prometheus.Registerer) http.Handler {
	m := http.NewServeMux()
	// Boulder specific endpoints
	wfe.HandleFunc(m, buildIDPath, wfe.BuildID, "GET")

	// POSTable ACME endpoints
	wfe.HandleFunc(m, newAcctPath, wfe.NewAccount, "POST")
	wfe.HandleFunc(m, acctPath, wfe.Account, "POST")
	wfe.HandleFunc(m, revokeCertPath, wfe.RevokeCertificate, "POST")
	wfe.HandleFunc(m, rolloverPath, wfe.KeyRollover, "POST")
	wfe.HandleFunc(m, newOrderPath, wfe.NewOrder, "POST")
	wfe.HandleFunc(m, finalizeOrderPath, wfe.FinalizeOrder, "POST")

	// GETable and POST-as-GETable ACME endpoints
	wfe.HandleFunc(m, directoryPath, wfe.Directory, "GET", "POST")
	wfe.HandleFunc(m, newNoncePath, wfe.Nonce, "GET", "POST")
	// POST-as-GETable ACME endpoints
	// TODO(@cpu): After November 1st, 2020 support for "GET" to the following
	// endpoints will be removed, leaving only POST-as-GET support.
	wfe.HandleFunc(m, orderPath, wfe.GetOrder, "GET", "POST")
	wfe.HandleFunc(m, authzPath, wfe.Authorization, "GET", "POST")
	wfe.HandleFunc(m, challengePath, wfe.Challenge, "GET", "POST")
	wfe.HandleFunc(m, certPath, wfe.Certificate, "GET", "POST")
	// Boulder-specific GET-able resource endpoints
	wfe.HandleFunc(m, getOrderPath, wfe.GetOrder, "GET")
	wfe.HandleFunc(m, getAuthzPath, wfe.Authorization, "GET")
	wfe.HandleFunc(m, getChallengePath, wfe.Challenge, "GET")
	wfe.HandleFunc(m, getCertPath, wfe.Certificate, "GET")

	// Endpoint for draft-aaron-ari
	if features.Enabled(features.ServeRenewalInfo) {
		wfe.HandleFunc(m, renewalInfoPath, wfe.RenewalInfo, "GET")
	}

	// TEST ONLY
	wfe.HandleFunc(m, aiaIssuerPath, wfe.Issuer, "GET")

	// We don't use our special HandleFunc for "/" because it matches everything,
	// meaning we can wind up returning 405 when we mean to return 404. See
	// https://github.com/letsencrypt/boulder/issues/717
	m.Handle("/", web.NewTopHandler(wfe.log, web.WFEHandlerFunc(wfe.Index)))
	return hnynethttp.WrapHandler(measured_http.New(m, wfe.clk, stats))
}

// Issuer returns the Issuer Cert identified by the path (its IssuerNameID).
// Used by integration tests to handle requests for the AIA Issuer URL.
func (wfe *WebFrontEndImpl) Issuer(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	idStr := request.URL.Path
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Issuer ID must be an integer"), err)
		return
	}

	issuer, ok := wfe.issuerCertificates[issuance.IssuerNameID(id)]
	if !ok {
		wfe.sendError(response, logEvent, probs.NotFound("Issuer ID did not match any known issuer"), nil)
		return
	}

	response.Header().Set("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusOK)
	_, err = response.Write(issuer.Certificate.Raw)
	if err != nil {
		wfe.log.Warningf("Could not write response: %s", err)
	}
}
