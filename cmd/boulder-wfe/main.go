// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"net/http"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/wfe"
)

func main() {
	app := cmd.NewAppShell("boulder-wfe")
	app.Action = func(c cmd.Config) {
		ch := cmd.AmqpChannel(c.AMQP.Server)

		rac, err := rpc.NewRegistrationAuthorityClient(c.AMQP.RA.Client, c.AMQP.RA.Server, ch)
		cmd.FailOnError(err, "Unable to create RA client")

		sac, err := rpc.NewStorageAuthorityClient(c.AMQP.SA.Client, c.AMQP.SA.Server, ch)
		cmd.FailOnError(err, "Unable to create SA client")

		// Create the front-end and wire in its resources
		wfe := wfe.NewWebFrontEndImpl()
		wfe.RA = &rac
		wfe.SA = &sac

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

		err = http.ListenAndServe(c.WFE.ListenAddress, nil)
		cmd.FailOnError(err, "Error starting HTTP server")
	}

	app.Run()
}
