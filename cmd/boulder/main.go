// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"net/http"
	"os"

	// Load both drivers to allow configuring either
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"

	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/va"
	"github.com/letsencrypt/boulder/wfe"
)

func main() {
	app := cmd.NewAppShell("boulder")
	app.Action = func(c cmd.Config) {
		// Create the components
		wfe := wfe.NewWebFrontEndImpl()
		sa, err := sa.NewSQLStorageAuthority(c.SA.DBDriver, c.SA.DBName)
		cmd.FailOnError(err, "Unable to create SA")
		err = sa.InitTables()
		cmd.FailOnError(err, "Unable to initialize SA")
		ra := ra.NewRegistrationAuthorityImpl()
		va := va.NewValidationAuthorityImpl()
		ca, err := ca.NewCertificateAuthorityImpl(c.CA.Server, c.CA.AuthKey, c.CA.Profile)
		cmd.FailOnError(err, "Unable to create CA")

		// Wire them up
		wfe.RA = &ra
		wfe.SA = sa
		ra.CA = ca
		ra.SA = sa
		ra.VA = &va
		va.RA = &ra
		ca.SA = sa

		// Go!
		newRegPath := "/acme/new-reg"
		regPath := "/acme/reg/"
		newAuthzPath := "/acme/new-authz"
		authzPath := "/acme/authz/"
		newCertPath := "/acme/new-cert"
		certPath := "/acme/cert/"
		wfe.NewReg = c.WFE.BaseURL + newRegPath
		wfe.RegBase = c.WFE.BaseURL + regPath
		wfe.NewAuthz = c.WFE.BaseURL + newAuthzPath
		wfe.AuthzBase = c.WFE.BaseURL + authzPath
		wfe.NewCert = c.WFE.BaseURL + newCertPath
		wfe.CertBase = c.WFE.BaseURL + certPath
		http.HandleFunc(newRegPath, wfe.NewRegistration)
		http.HandleFunc(newAuthzPath, wfe.NewAuthorization)
		http.HandleFunc(newCertPath, wfe.NewCertificate)
		http.HandleFunc(regPath, wfe.Registration)
		http.HandleFunc(authzPath, wfe.Authorization)
		http.HandleFunc(certPath, wfe.Certificate)

		// Add a simple ToS
		termsPath := "/terms"
		http.HandleFunc(termsPath, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "You agree to do the right thing")
		})
		wfe.SubscriberAgreementURL = c.WFE.BaseURL + termsPath

		// We need to tell the RA how to make challenge URIs
		// XXX: Better way to do this?  Part of improved configuration
		ra.AuthzBase = wfe.AuthzBase

		fmt.Fprintf(os.Stderr, "Server running, listening on %s...\n", c.WFE.ListenAddress)
		err = http.ListenAndServe(c.WFE.ListenAddress, nil)
		cmd.FailOnError(err, "Error starting HTTP server")
	}

	app.Run()
}
