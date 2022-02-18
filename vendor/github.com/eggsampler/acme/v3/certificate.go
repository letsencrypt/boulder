package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
)

func (c Client) decodeCertificateChain(body []byte, resp *http.Response, account Account) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var p *pem.Block
		p, body = pem.Decode(body)
		if p == nil {
			break
		}
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return certs, fmt.Errorf("acme: error parsing certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	up := fetchLink(resp, "up")
	if up != "" {
		upCerts, err := c.FetchCertificates(account, up)
		if err != nil {
			return certs, fmt.Errorf("acme: error fetching up cert: %v", err)
		}
		if len(upCerts) != 0 {
			certs = append(certs, upCerts...)
		}
	}

	return certs, nil
}

// FetchCertificates downloads a certificate chain from a url given in an order certificate.
func (c Client) FetchCertificates(account Account, certificateURL string) ([]*x509.Certificate, error) {
	resp, body, err := c.postRaw(0, certificateURL, account.URL, account.PrivateKey, "", []int{http.StatusOK})
	if err != nil {
		return nil, err
	}

	return c.decodeCertificateChain(body, resp, account)
}

// FetchAllCertificates downloads a certificate chain from a url given in an order certificate, as well as any alternate certificates if provided.
// Returns a mapping of certificate urls to the certificate chain.
func (c Client) FetchAllCertificates(account Account, certificateURL string) (map[string][]*x509.Certificate, error) {
	resp, body, err := c.postRaw(0, certificateURL, account.URL, account.PrivateKey, "", []int{http.StatusOK})
	if err != nil {
		return nil, err
	}

	certChain, err := c.decodeCertificateChain(body, resp, account)
	if err != nil {
		return nil, err
	}

	certs := map[string][]*x509.Certificate{
		certificateURL: certChain,
	}

	alternates := fetchLinks(resp, "alternate")

	for _, altURL := range alternates {
		altResp, altBody, err := c.postRaw(0, altURL, account.URL, account.PrivateKey, "", []int{http.StatusOK})
		if err != nil {
			return certs, fmt.Errorf("acme: error fetching alt cert chain at %q - %v", altURL, err)
		}
		altCertChain, err := c.decodeCertificateChain(altBody, altResp, account)
		if err != nil {
			return certs, fmt.Errorf("acme: error decoding alt cert chain at %q - %v", altURL, err)
		}
		certs[altURL] = altCertChain
	}

	return certs, nil

}

// RevokeCertificate revokes a given certificate given the certificate key or account key, and a reason.
func (c Client) RevokeCertificate(account Account, cert *x509.Certificate, key crypto.Signer, reason int) error {
	revokeReq := struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason"`
	}{
		Certificate: base64.RawURLEncoding.EncodeToString(cert.Raw),
		Reason:      reason,
	}

	kid := ""
	if key == account.PrivateKey {
		kid = account.URL
	}

	if _, err := c.post(c.dir.RevokeCert, kid, key, revokeReq, nil, http.StatusOK); err != nil {
		return err
	}

	return nil
}
