// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package publisher

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

// LogDescription tells you how to connect to a log and verify its statements.
type LogDescription struct {
	ID        string
	URI       string
	PublicKey *ecdsa.PublicKey
}

type rawLogDescription struct {
	URI       string `json:"uri"`
	PublicKey string `json:"key"`
}

// UnmarshalJSON parses a simple JSON format for log descriptions.  Both the
// URI and the public key are expected to be strings.  The public key is a
// base64-encoded PKIX public key structure.
func (logDesc *LogDescription) UnmarshalJSON(data []byte) error {
	var rawLogDesc rawLogDescription
	if err := json.Unmarshal(data, &rawLogDesc); err != nil {
		return fmt.Errorf("Failed to unmarshal log description, %s", err)
	}
	logDesc.URI = rawLogDesc.URI
	// Load Key
	pkBytes, err := base64.StdEncoding.DecodeString(rawLogDesc.PublicKey)
	if err != nil {
		return fmt.Errorf("Failed to decode base64 log public key")
	}
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		return fmt.Errorf("Failed to parse log public key")
	}
	ecdsaKey, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Failed to unmarshal log description for %s, unsupported public key type", logDesc.URI)
	}
	logDesc.PublicKey = ecdsaKey

	// Generate key hash for log ID
	pkHash := sha256.Sum256(pkBytes)
	logDesc.ID = base64.StdEncoding.EncodeToString(pkHash[:])
	if len(logDesc.ID) != 44 {
		return fmt.Errorf("Invalid log ID length [%d]", len(logDesc.ID))
	}

	return nil
}

// CTConfig defines the JSON configuration file schema
type CTConfig struct {
	Logs                       []LogDescription `json:"logs"`
	SubmissionRetries          int              `json:"submissionRetries"`
	SubmissionBackoffString    string           `json:"submissionBackoff"`
	IntermediateBundleFilename string           `json:"intermediateBundleFilename"`
}

type ctSubmissionRequest struct {
	Chain []string `json:"chain"`
}

const (
	sctVersion       = 0
	sctSigType       = 0
	sctX509EntryType = 0
)

// PublisherImpl defines a Publisher
type PublisherImpl struct {
	log               *blog.AuditLogger
	client            *http.Client
	submissionBackoff time.Duration
	submissionRetries int
	issuerBundle      []string
	ctLogs            []LogDescription

	SA core.StorageAuthority
}

// NewPublisherImpl creates a Publisher that will submit certificates
// to any CT logs configured in CTConfig
func NewPublisherImpl(ctConfig CTConfig) (pub PublisherImpl, err error) {
	logger := blog.GetAuditLogger()
	logger.Notice("Publisher Authority Starting")

	if ctConfig.IntermediateBundleFilename == "" {
		err = fmt.Errorf("No CT submission bundle provided")
		return
	}
	bundle, err := core.LoadCertBundle(ctConfig.IntermediateBundleFilename)
	if err != nil {
		return
	}
	for _, cert := range bundle {
		pub.issuerBundle = append(pub.issuerBundle, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	ctBackoff, err := time.ParseDuration(ctConfig.SubmissionBackoffString)
	if err != nil {
		return
	}
	for _, log := range ctConfig.Logs {
		if !strings.HasPrefix(log.URI, "https://") && !strings.HasPrefix(log.URI, "http://") {
			err = fmt.Errorf("Log URI [%s] is not absolute", log.URI)
			return
		}
	}

	pub.log = logger
	pub.client = &http.Client{}
	pub.submissionBackoff = ctBackoff
	pub.submissionRetries = ctConfig.SubmissionRetries
	pub.ctLogs = ctConfig.Logs

	return
}

func (pub *PublisherImpl) submitToCTLog(serial string, jsonSubmission []byte, log LogDescription) error {
	done := false
	var sct core.SignedCertificateTimestamp
	backoff := pub.submissionBackoff
	var retries int
	for retries = 0; retries <= pub.submissionRetries; retries++ {
		if retries > 0 {
			time.Sleep(backoff)
		}
		resp, err := postJSON(pub.client, fmt.Sprintf("%s%s", log.URI, "/ct/v1/add-chain"), jsonSubmission, &sct)
		if err != nil {
			// Retry the request, log the error
			pub.log.Warning(fmt.Sprintf("Error POSTing JSON to CT log submission endpoint [%s]: %s", log.URI, err))
			backoff = pub.submissionBackoff
			continue
		} else if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusServiceUnavailable {
			// Retry the request after either the configured backoff period or the period
			// specified by the Retry-After header
			backoff = pub.submissionBackoff
			if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
				backoff = time.Second * time.Duration(seconds)
			}
			continue
		} else if resp.StatusCode != http.StatusOK {
			// If we hit an otherwise unexpected status code break the loop and return
			// an error immediately
			return fmt.Errorf("Unexpected status code returned from CT log: %d", resp.StatusCode)
		}
		done = true
		break
	}

	if !done {
		err := fmt.Errorf(
			"Unable to submit certificate to CT log [Serial: %s, Log URI: %s, Retries: %d]",
			serial,
			log.URI,
			retries,
		)
		return err
	}

	if err := sct.CheckSignature(); err != nil {
		return err
	}

	pub.log.Debug(fmt.Sprintf(
		"Submitted certificate to CT log [Serial: %s, Log URI: %s, Retries: %d, Signature: %x]",
		serial,
		log.URI,
		retries, sct.Signature,
	))

	// Set certificate serial and add SCT to DB
	sct.CertificateSerial = serial
	err := pub.SA.AddSCTReceipt(sct)
	if err != nil {
		if _, ok := err.(sa.ErrDuplicateReceipt); ok {
			pub.log.Warning(fmt.Sprintf(
				"SCT receipt for [Serial: %s, Log URI: %s] already exists in database",
				serial,
				log.URI,
			))
			return nil
		} else if err != nil {
			err = fmt.Errorf(
				"Error adding SCT receipt for [%s to %s]: %s",
				sct.CertificateSerial,
				log.URI,
				err,
			)
			return err
		}
	}
	pub.log.Info(fmt.Sprintf(
		"Stored SCT receipt from CT log submission [Serial: %s, Log URI: %s]",
		serial,
		log.URI,
	))
	return nil
}

// SubmitToCT will submit the certificate represented by certDER to any CT
// logs configured in pub.CT.Logs
func (pub *PublisherImpl) SubmitToCT(der []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		pub.log.Err(fmt.Sprintf("Unable to parse certificate, %s", err))
		return err
	}

	submission := ctSubmissionRequest{Chain: []string{base64.StdEncoding.EncodeToString(cert.Raw)}}
	// Add all intermediate certificates needed for submission
	submission.Chain = append(submission.Chain, pub.issuerBundle...)
	jsonSubmission, err := json.Marshal(submission)
	if err != nil {
		pub.log.Err(fmt.Sprintf("Unable to marshal CT submission, %s", err))
		return err
	}

	for _, ctLog := range pub.ctLogs {
		err = pub.submitToCTLog(core.SerialToString(cert.SerialNumber), jsonSubmission, ctLog)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.AuditErr(err)
			continue
		}
	}

	return nil
}

func postJSON(client *http.Client, uri string, data []byte, respObj interface{}) (*http.Response, error) {
	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Creating request failed, %s", err)
	}
	req.Header.Set("Keep-Alive", "timeout=15, max=100")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Request failed, %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("Failed to read response body, %s", err)
		}

		err = json.Unmarshal(body, respObj)
		if err != nil {
			return nil, fmt.Errorf("Failed to unmarshal SCT receipt, %s", err)
		}
	}
	return resp, nil
}
