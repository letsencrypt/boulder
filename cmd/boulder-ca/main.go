// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/helpers"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/pkcs11key"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

const clientName = "CA"

func loadIssuers(c cmd.Config) ([]ca.Issuer, error) {
	if c.CA.Key != nil {
		issuerConfig := *c.CA.Key
		issuerConfig.CertFile = c.Common.IssuerCert
		priv, cert, err := loadIssuer(issuerConfig)
		return []ca.Issuer{{
			Signer: priv,
			Cert:   cert,
		}}, err
	}
	var issuers []ca.Issuer
	for _, issuerConfig := range c.CA.Issuers {
		priv, cert, err := loadIssuer(issuerConfig)
		cmd.FailOnError(err, "Couldn't load private key")
		issuers = append(issuers, ca.Issuer{
			Signer: priv,
			Cert:   cert,
		})
	}
	return issuers, nil
}

func loadIssuer(issuerConfig cmd.IssuerConfig) (crypto.Signer, *x509.Certificate, error) {
	cert, err := core.LoadCert(issuerConfig.CertFile)
	if err != nil {
		return nil, nil, err
	}

	signer, err := loadSigner(issuerConfig)
	if err != nil {
		return nil, nil, err
	}

	if !core.KeyDigestEquals(signer.Public(), cert.PublicKey) {
		return nil, nil, fmt.Errorf("Issuer key did not match issuer cert %s", issuerConfig.CertFile)
	}
	return signer, cert, err
}

func loadSigner(issuerConfig cmd.IssuerConfig) (crypto.Signer, error) {
	if issuerConfig.File != "" {
		keyBytes, err := ioutil.ReadFile(issuerConfig.File)
		if err != nil {
			return nil, fmt.Errorf("Could not read key file %s", issuerConfig.File)
		}

		signer, err := helpers.ParsePrivateKeyPEM(keyBytes)
		if err != nil {
			return nil, err
		}
		return signer, nil
	}

	var pkcs11Config *pkcs11key.Config
	if issuerConfig.ConfigFile != "" {
		contents, err := ioutil.ReadFile(issuerConfig.ConfigFile)
		if err != nil {
			return nil, err
		}
		pkcs11Config = new(pkcs11key.Config)
		err = json.Unmarshal(contents, pkcs11Config)
		if err != nil {
			return nil, err
		}
	} else {
		pkcs11Config = issuerConfig.PKCS11
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
	app.Action = func(c cmd.Config, stats metrics.Statter, auditlogger *blog.AuditLogger) {
		// Validate PA config and set defaults if needed
		cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")

		go cmd.DebugServer(c.CA.DebugAddr)

		var paDbMap *gorp.DbMap
		if c.CA.HostnamePolicyFile == "" {
			dbURL, err := c.PA.DBConfig.URL()
			cmd.FailOnError(err, "Couldn't load DB URL")
			paDbMap, err = sa.NewDbMap(dbURL)
			cmd.FailOnError(err, "Couldn't connect to policy database")
		}
		pa, err := policy.New(paDbMap, c.PA.EnforcePolicyWhitelist, c.PA.Challenges)
		cmd.FailOnError(err, "Couldn't create PA")

		if c.CA.HostnamePolicyFile != "" {
			err = pa.SetHostnamePolicyFile(c.CA.HostnamePolicyFile)
			cmd.FailOnError(err, "Couldn't load hostname policy file")
		}

		issuers, err := loadIssuers(c)
		cmd.FailOnError(err, "Couldn't load issuers")

		cai, err := ca.NewCertificateAuthorityImpl(
			c.CA,
			clock.Default(),
			stats,
			issuers,
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
