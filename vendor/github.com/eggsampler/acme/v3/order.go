package acme

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// NewOrder initiates a new order for a new certificate. This method does not
// use ACME Renewal Info.
func (c Client) NewOrder(account Account, identifiers []Identifier) (*Order, error) {
	newOrderResp, err := c.postNewOrder(account, identifiers, nil)
	if err != nil {
		return newOrderResp, err
	}

	return newOrderResp, nil
}

// NewOrderDomains is a wrapper for NewOrder(AcmeAccount, []AcmeIdentifiers). It
// creates a dns identifier for each provided domain. This method does not use
// ACME Renewal Info.
func (c Client) NewOrderDomains(account Account, domains ...string) (*Order, error) {
	ids, err := domainsToIds(domains)
	if err != nil {
		return nil, err
	}

	return c.NewOrder(account, ids)
}

type ariRequest struct {
	certID string
}

// NewOrderRenewal takes an existing *x509.Certificate and initiates a new order
// for a new certificate, but with the order being marked as a replacement.
// Replacement orders are exempt from Let's Encrypt NewOrder rate limits. It
// creates a dns identifier for each provided domain. At least one identifier
// must match the list of identifiers from the parent order to be considered as
// a valid replacment order.
// See https://datatracker.ietf.org/doc/html/draft-ietf-acme-ari-03#section-5
func (c Client) NewOrderRenewal(account Account, oldCert *x509.Certificate, domains ...string) (*Order, error) {
	if c.dir.RenewalInfo == "" {
		return nil, ErrRenewalInfoNotSupported
	}

	if oldCert == nil {
		return nil, fmt.Errorf("certificate not found")
	}

	certID, err := generateARICertID(oldCert)
	if err != nil {
		return nil, fmt.Errorf("acme: error generating certificate id: %v", err)
	}

	ids, err := domainsToIds(domains)
	if err != nil {
		return nil, err
	}

	ari := &ariRequest{certID: certID}
	newOrderResp, err := c.postNewOrder(account, ids, ari)
	if err != nil {
		return nil, err
	}

	return newOrderResp, nil
}

// postNewOrder handles the logic of POSTing either 1) an ACME Renewal Info (ARI)
// replacement order or 2) a standard RFC 8555 order to the ACME server and returns an
// error.
func (c Client) postNewOrder(account Account, ids []Identifier, ari *ariRequest) (*Order, error) {
	type newOrderRequest interface{}
	var newOrderReq newOrderRequest

	// This order object will be returned to the client.
	order := Order{}
	if ari != nil {
		order.Replaces = ari.certID
		ariNewOrderReq := struct {
			Identifiers []Identifier `json:"identifiers"`
			Replaces    string
		}{
			Identifiers: ids,
			Replaces:    ari.certID,
		}
		newOrderReq = ariNewOrderReq
	} else {
		nonARINewOrderReq := struct {
			Identifiers []Identifier `json:"identifiers"`
		}{
			Identifiers: ids,
		}
		newOrderReq = nonARINewOrderReq
	}

	// Submit the order
	resp, err := c.post(c.dir.NewOrder, account.URL, account.PrivateKey, newOrderReq, &order, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	order.URL = resp.Header.Get("Location")

	return &order, nil
}

// domainsToIds takes a slice of strings representing domain names and returns a
// slice of Identifiers or an error.
func domainsToIds(domains []string) ([]Identifier, error) {
	if len(domains) == 0 {
		return nil, errors.New("acme: no domains provided")
	}

	var ids []Identifier
	for _, d := range domains {
		ids = append(ids, Identifier{Type: "dns", Value: d})
	}

	return ids, nil
}

// FetchOrder fetches an existing order given an order url.
func (c Client) FetchOrder(account Account, orderURL string) (*Order, error) {
	orderResp := &Order{
		URL: orderURL, // boulder response doesn't seem to contain location header for this request
	}
	_, err := c.post(orderURL, account.URL, account.PrivateKey, "", &orderResp, http.StatusOK)

	return orderResp, err
}

// Helper function to determine whether an order is "finished" by it's status.
func checkFinalizedOrderStatus(order *Order) (bool, error) {
	if order == nil {
		return false, errors.New("acme: nil order")
	}

	switch order.Status {
	case "invalid":
		// "invalid": The certificate will not be issued.  Consider this
		//      order process abandoned.
		if order.Error.Type != "" {
			return true, order.Error
		}
		return true, errors.New("acme: finalized order is invalid, no error provided")

	case "pending":
		// "pending": The server does not believe that the client has
		//      fulfilled the requirements.  Check the "authorizations" array for
		//      entries that are still pending.
		return true, errors.New("acme: authorizations not fulfilled")

	case "ready":
		// "ready": The server agrees that the requirements have been
		//      fulfilled, and is awaiting finalization.  Submit a finalization
		//      request.
		return true, errors.New("acme: unexpected 'ready' state")

	case "processing":
		// "processing": The certificate is being issued.  Send a GET request
		//      after the time given in the "Retry-After" header field of the
		//      response, if any.
		return false, nil

	case "valid":
		// "valid": The server has issued the certificate and provisioned its
		//      URL to the "certificate" field of the order.  Download the
		//      certificate.
		return true, nil

	default:
		return true, fmt.Errorf("acme: unknown order status: %s", order.Status)
	}
}

// FinalizeOrder indicates to the acme server that the client considers an order complete and "finalizes" it.
// If the server believes the authorizations have been filled successfully, a certificate should then be available.
// This function assumes that the order status is "ready".
func (c Client) FinalizeOrder(account Account, order *Order, csr *x509.CertificateRequest) (*Order, error) {
	finaliseReq := struct {
		Csr string `json:"csr"`
	}{
		Csr: base64.RawURLEncoding.EncodeToString(csr.Raw),
	}

	resp, err := c.post(order.Finalize, account.URL, account.PrivateKey, finaliseReq, &order, http.StatusOK)
	if err != nil {
		return order, err
	}

	order.URL = resp.Header.Get("Location")

	updateOrder := func(resp *http.Response) (bool, error) {
		if finished, err := checkFinalizedOrderStatus(order); finished {
			return true, err
		}

		retryAfter, err := parseRetryAfter(resp.Header.Get("Retry-After"))
		if err != nil {
			return false, fmt.Errorf("acme: error parsing retry-after header: %v", err)
		}
		order.RetryAfter = retryAfter

		return false, nil
	}

	if finished, err := updateOrder(resp); finished || err != nil {
		return order, err
	}

	fetchOrder := func() (bool, error) {
		resp, err := c.post(order.URL, account.URL, account.PrivateKey, "", &order, http.StatusOK)
		if err != nil {
			return false, nil
		}

		return updateOrder(resp)
	}

	if !c.IgnoreRetryAfter && !order.RetryAfter.IsZero() {
		_, pollTimeout := c.getPollingDurations()
		end := time.Now().Add(pollTimeout)

		for {
			if time.Now().After(end) {
				return order, errors.New("acme: finalized order timeout")
			}

			diff := time.Until(order.RetryAfter)
			_, pollTimeout := c.getPollingDurations()
			if diff > pollTimeout {
				return order, fmt.Errorf("acme: Retry-After (%v) longer than poll timeout (%v)", diff, c.PollTimeout)
			}
			if diff > 0 {
				time.Sleep(diff)
			}

			if finished, err := fetchOrder(); finished || err != nil {
				return order, err
			}
		}
	}

	if !c.IgnoreRetryAfter {
		pollInterval, pollTimeout := c.getPollingDurations()
		end := time.Now().Add(pollTimeout)
		for {
			if time.Now().After(end) {
				return order, errors.New("acme: finalized order timeout")
			}
			time.Sleep(pollInterval)

			if finished, err := fetchOrder(); finished || err != nil {
				return order, err
			}
		}
	}

	return order, err
}
