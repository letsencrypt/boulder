// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/helpers"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/pkcs11key"
	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

const clientName = "CA"

func loadPrivateKey(keyConfig cmd.KeyConfig) (crypto.Signer, error) {
	if keyConfig.File != "" {
		keyBytes, err := ioutil.ReadFile(keyConfig.File)
		if err != nil {
			return nil, fmt.Errorf("Could not read key file %s", keyConfig.File)
		}

		return helpers.ParsePrivateKeyPEM(keyBytes)
	}

	var pkcs11Config *pkcs11key.Config
	if keyConfig.ConfigFile != "" {
		contents, err := ioutil.ReadFile(keyConfig.ConfigFile)
		if err != nil {
			return nil, err
		}
		pkcs11Config = new(pkcs11key.Config)
		err = json.Unmarshal(contents, pkcs11Config)
		if err != nil {
			return nil, err
		}
	} else {
		pkcs11Config = keyConfig.PKCS11
	}
	if pkcs11Config.Module == "" ||
		pkcs11Config.TokenLabel == "" ||
		pkcs11Config.PIN == "" ||
		pkcs11Config.PrivateKeyLabel == "" {
		return nil, fmt.Errorf("Missing a field in pkcs11Config %#v", pkcs11Config)
	}
	return pkcs11key.New(pkcs11Config.Module,
		pkcs11Config.TokenLabel, pkcs11Config.PIN, pkcs11Config.PrivateKeyLabel)
}

func main() {
	app := cmd.NewAppShell("boulder-ca", "Handles issuance operations")
	app.Action = func(c cmd.Config, stats statsd.Statter, auditlogger *blog.AuditLogger) {
		// Validate PA config and set defaults if needed
		cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.CA.DebugAddr)

		dbURL, err := c.PA.DBConfig.URL()
		cmd.FailOnError(err, "Couldn't load DB URL")
		paDbMap, err := sa.NewDbMap(dbURL)
		cmd.FailOnError(err, "Couldn't connect to policy database")
		pa, err := policy.New(paDbMap, c.PA.EnforcePolicyWhitelist, c.PA.Challenges)
		cmd.FailOnError(err, "Couldn't create PA")

		priv, err := loadPrivateKey(c.CA.Key)
		cmd.FailOnError(err, "Couldn't load private key")

		issuer, err := core.LoadCert(c.Common.IssuerCert)
		cmd.FailOnError(err, "Couldn't load issuer cert")

		cai, err := ca.NewCertificateAuthorityImpl(
			c.CA,
			clock.Default(),
			stats,
			issuer,
			priv,
			c.KeyPolicy())
		cmd.FailOnError(err, "Failed to create CA impl")
		cai.PA = pa

		go cmd.ProfileCmd("CA", stats)

		amqpConf := c.CA.AMQP
		cai.SA, err = rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Failed to create SA client")

		cai.Publisher, err = rpc.NewPublisherClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Failed to create Publisher client")

		cas, err := rpc.NewAmqpRPCServer(amqpConf, c.CA.MaxConcurrentRPCServerRequests, stats)
		cmd.FailOnError(err, "Unable to create CA RPC server")
		rpc.NewCertificateAuthorityServer(cas, cai)

		err = cas.Start(amqpConf)
		cmd.FailOnError(err, "Unable to run CA RPC server")
	}

	app.Run()
}
