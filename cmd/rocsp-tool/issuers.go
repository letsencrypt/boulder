package notmain

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/letsencrypt/boulder/issuance"
	"golang.org/x/crypto/ocsp"
)

type shortIDIssuer struct {
	*issuance.Certificate
	subject      pkix.RDNSequence
	shortID      byte
	issuerID     issuance.IssuerID
	issuerNameID issuance.IssuerNameID
}

func loadIssuers(input map[string]int) ([]shortIDIssuer, error) {
	var issuers []shortIDIssuer
	for issuerFile, shortID := range input {
		if shortID > 255 || shortID < 0 {
			return nil, fmt.Errorf("invalid shortID %d (must be byte)", shortID)
		}
		cert, err := issuance.LoadCertificate(issuerFile)
		if err != nil {
			return nil, fmt.Errorf("reading issuer: %w", err)
		}
		var subject pkix.RDNSequence
		_, err = asn1.Unmarshal(cert.Certificate.RawSubject, &subject)
		if err != nil {
			return nil, fmt.Errorf("parsing issuer.RawSubject: %w", err)
		}
		var shortID byte = byte(shortID)
		for _, issuer := range issuers {
			if issuer.shortID == shortID {
				return nil, fmt.Errorf("duplicate shortID in config file: %d (for %q and %q)", shortID, issuer.subject, subject)
			}
			if !issuer.IsCA {
				return nil, fmt.Errorf("certificate for %q is not a CA certificate", subject)
			}
		}
		issuers = append(issuers, shortIDIssuer{
			Certificate:  cert,
			subject:      subject,
			shortID:      shortID,
			issuerID:     cert.ID(),
			issuerNameID: cert.NameID(),
		})
	}
	return issuers, nil
}

func findIssuerByID(longID int64, issuers []shortIDIssuer) (*shortIDIssuer, error) {
	for _, iss := range issuers {
		if iss.issuerNameID == issuance.IssuerNameID(longID) || iss.issuerID == issuance.IssuerID(longID) {
			return &iss, nil
		}
	}
	return nil, fmt.Errorf("no issuer found for an ID in certificateStatus: %d", longID)
}

func findIssuerByName(resp *ocsp.Response, issuers []shortIDIssuer) (*shortIDIssuer, error) {
	var responder pkix.RDNSequence
	_, err := asn1.Unmarshal(resp.RawResponderName, &responder)
	if err != nil {
		return nil, fmt.Errorf("parsing resp.RawResponderName: %w", err)
	}
	var responders strings.Builder
	for _, issuer := range issuers {
		fmt.Fprintf(&responders, "%s\n", issuer.subject)
		if bytes.Equal(issuer.RawSubject, resp.RawResponderName) {
			return &issuer, nil
		}
	}
	return nil, fmt.Errorf("no issuer found matching OCSP response for %s. Available issuers:\n%s\n", responder, responders.String())
}
