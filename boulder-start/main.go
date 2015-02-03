// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder"
	"github.com/streadway/amqp"
	"net/http"
	"os"
)

// Exit and print error message if we encountered a problem
func failOnError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}

// This is the same as amqpConnect in boulder, but with even
// more aggressive error dropping
func amqpChannel(url string) (ch *amqp.Channel) {
	conn, err := amqp.Dial(url)
	failOnError(err, "Unable to connect to AMQP server")

	ch, err = conn.Channel()
	failOnError(err, "Unable to establish channel to AMQP server")
	return
}

// Start the server and wait around
func runForever(server *boulder.AmqpRpcServer) {
	forever := make(chan bool)
	server.Start()
	fmt.Fprintf(os.Stderr, "Server running...\n")
	<-forever
}

func main() {
	app := cli.NewApp()
	app.Name = "boulder-start"
	app.Usage = "Command-line utility to start Boulder's servers in stand-alone mode"
	app.Version = "0.0.0"


	// Specify AMQP Server
	app.Flags = []cli.Flag{
		cli.StringFlag{
				Name: "amqp",
				Value: "amqp://guest:guest@localhost:5672",
				Usage: "AMQP Broker String",
			},
	}

	// One command per element of the system
	// * WebFrontEnd
	// * RegistrationAuthority
	// * ValidationAuthority
	// * CertificateAuthority
	// * StorageAuthority
	//
	// Once started, we just run until killed
	//
	// AMQP queue names are hard-coded for now
	app.Commands = []cli.Command{
		{
			Name:  "monolithic",
			Usage: "Start the CA in monolithic mode, without using AMQP",
			Action: func(c *cli.Context) {
				// Create the components
				wfe := boulder.NewWebFrontEndImpl()
				sa := boulder.NewSimpleStorageAuthorityImpl()
				ra := boulder.NewRegistrationAuthorityImpl()
				va := boulder.NewValidationAuthorityImpl()
				ca, err := boulder.NewCertificateAuthorityImpl()
				failOnError(err, "Unable to create CA")

				// Wire them up
				wfe.RA = &ra
				wfe.SA = &sa
				ra.CA = &ca
				ra.SA = &sa
				ra.VA = &va
				va.RA = &ra

				// Go!
				authority := "localhost:4000"
				authzPath := "/acme/authz/"
				certPath := "/acme/cert/"
				wfe.SetAuthzBase("http://" + authority + authzPath)
				wfe.SetCertBase("http://" + authority + certPath)
				http.HandleFunc("/acme/new-authz", wfe.NewAuthz)
				http.HandleFunc("/acme/new-cert", wfe.NewCert)
				http.HandleFunc("/acme/authz/", wfe.Authz)
				http.HandleFunc("/acme/cert/", wfe.Cert)

				fmt.Fprintf(os.Stderr, "Server running...\n")
				err = http.ListenAndServe(authority, nil)
				failOnError(err, "Error starting HTTP server")
			},
		},
		{
			Name:  "monolithic-amqp",
			Usage: "Start the CA in monolithic mode, using AMQP",
			Action: func(c *cli.Context) {
				// Create an AMQP channel
				ch := amqpChannel(c.GlobalString("amqp"))

				// Create AMQP-RPC clients for CA, VA, RA, SA
				cac, err := boulder.NewCertificateAuthorityClient("CA.client", "CA.server", ch)
				failOnError(err, "Failed to create CA client")
				vac, err := boulder.NewValidationAuthorityClient("VA.client", "VA.server", ch)
				failOnError(err, "Failed to create VA client")
				rac, err := boulder.NewRegistrationAuthorityClient("RA.client", "RA.server", ch)
				failOnError(err, "Failed to create RA client")
				sac, err := boulder.NewStorageAuthorityClient("SA.client", "SA.server", ch)
				failOnError(err, "Failed to create SA client")

				// ... and corresponding servers
				// (We need this order so that we can give the servers
				//  references to the clients)
				cas, err := boulder.NewCertificateAuthorityServer("CA.server", ch)
				failOnError(err, "Failed to create CA server")
				vas, err := boulder.NewValidationAuthorityServer("VA.server", ch, &rac)
				failOnError(err, "Failed to create VA server")
				ras, err := boulder.NewRegistrationAuthorityServer("RA.server", ch, &vac, &cac, &sac)
				failOnError(err, "Failed to create RA server")
				sas := boulder.NewStorageAuthorityServer("SA.server", ch)

				// Start the servers
				cas.Start()
				vas.Start()
				ras.Start()
				sas.Start()

				// Wire up the front end (wrappers are already wired)
				wfe := boulder.NewWebFrontEndImpl()
				wfe.RA = &rac
				wfe.SA = &sac

				// Go!
				authority := "localhost:4000"
				authzPath := "/acme/authz/"
				certPath := "/acme/cert/"
				wfe.SetAuthzBase("http://" + authority + authzPath)
				wfe.SetCertBase("http://" + authority + certPath)
				http.HandleFunc("/acme/new-authz", wfe.NewAuthz)
				http.HandleFunc("/acme/new-cert", wfe.NewCert)
				http.HandleFunc("/acme/authz/", wfe.Authz)
				http.HandleFunc("/acme/cert/", wfe.Cert)

				fmt.Fprintf(os.Stderr, "Server running...\n")
				err = http.ListenAndServe(authority, nil)
				failOnError(err, "Error starting HTTP server")
			},
		},
		{
			Name:  "wfe",
			Usage: "Start the WebFrontEnd",
			Action: func(c *cli.Context) {
				// Create necessary clients
				ch := amqpChannel(c.GlobalString("amqp"))

				rac, err := boulder.NewRegistrationAuthorityClient("RA.client", "RA.server", ch)
				failOnError(err, "Unable to create RA client")

				sac, err := boulder.NewStorageAuthorityClient("SA.client", "SA.server", ch)
				failOnError(err, "Unable to create SA client")

				// Create the front-end and wire in its resources
				wfe := boulder.NewWebFrontEndImpl()
				wfe.RA = &rac
				wfe.SA = &sac

				// Connect the front end to HTTP
				authority := "localhost:4000"
				authzPath := "/acme/authz/"
				certPath := "/acme/cert/"
				wfe.SetAuthzBase("http://" + authority + authzPath)
				wfe.SetCertBase("http://" + authority + certPath)
				http.HandleFunc("/acme/new-authz", wfe.NewAuthz)
				http.HandleFunc("/acme/new-cert", wfe.NewCert)
				http.HandleFunc("/acme/authz/", wfe.Authz)
				http.HandleFunc("/acme/cert/", wfe.Cert)

				fmt.Fprintf(os.Stderr, "Server running...\n")
				http.ListenAndServe(authority, nil)
			},
		},
		{
			Name:  "ca",
			Usage: "Start the CertificateAuthority",
			Action: func(c *cli.Context) {
				ch := amqpChannel(c.GlobalString("amqp"))

				cas, err := boulder.NewCertificateAuthorityServer("CA.server", ch)
				failOnError(err, "Unable to create CA server")
				runForever(cas)
			},
		},
		{
			Name:  "sa",
			Usage: "Start the StorageAuthority",
			Action: func(c *cli.Context) {
				ch := amqpChannel(c.GlobalString("amqp"))

				sas := boulder.NewStorageAuthorityServer("SA.server", ch)
				runForever(sas)
			},
		},
		{
			Name:  "va",
			Usage: "Start the ValidationAuthority",
			Action: func(c *cli.Context) {
				ch := amqpChannel(c.GlobalString("amqp"))

				rac, err := boulder.NewRegistrationAuthorityClient("RA.client", "RA.server", ch)
				failOnError(err, "Unable to create RA client")

				vas, err := boulder.NewValidationAuthorityServer("VA.server", ch, &rac)
				failOnError(err, "Unable to create VA server")
				runForever(vas)
			},
		},
		{
			Name:  "ra",
			Usage: "Start the RegistrationAuthority",
			Action: func(c *cli.Context) {
				// TODO
				ch := amqpChannel(c.GlobalString("amqp"))

				vac, err := boulder.NewValidationAuthorityClient("VA.client", "VA.server", ch)
				failOnError(err, "Unable to create VA client")

				cac, err := boulder.NewCertificateAuthorityClient("CA.client", "CA.server", ch)
				failOnError(err, "Unable to create CA client")

				sac, err := boulder.NewStorageAuthorityClient("SA.client", "SA.server", ch)
				failOnError(err, "Unable to create SA client")

				ras, err := boulder.NewRegistrationAuthorityServer("RA.server", ch, &vac, &cac, &sac)
				failOnError(err, "Unable to create RA server")
				runForever(ras)
			},
		},
	}

	err := app.Run(os.Args)
	failOnError(err, "Failed to run application")
}
