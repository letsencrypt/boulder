//go:build !integration

package wfe2

import (
	"net/http"

	"github.com/honeycombio/beeline-go/wrappers/hnynethttp"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/metrics/measured_http"
	"github.com/letsencrypt/boulder/web"
	"github.com/prometheus/client_golang/prometheus"
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

	// We don't use our special HandleFunc for "/" because it matches everything,
	// meaning we can wind up returning 405 when we mean to return 404. See
	// https://github.com/letsencrypt/boulder/issues/717
	m.Handle("/", web.NewTopHandler(wfe.log, web.WFEHandlerFunc(wfe.Index)))
	return hnynethttp.WrapHandler(measured_http.New(m, wfe.clk, stats))
}
