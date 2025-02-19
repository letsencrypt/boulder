package acme

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type OrderExtension struct {
	Profile string
}

// NewOrder initiates a new order for a new certificate. This method does not use ACME Renewal Info.
func (c Client) NewOrder(account Account, identifiers []Identifier) (Order, error) {
	return c.ReplacementOrder(account, nil, identifiers)
}

// NewOrderDomains takes a list of domain dns identifiers for a new certificate. Essentially a helper function.
func (c Client) NewOrderDomains(account Account, domains ...string) (Order, error) {
	var identifiers []Identifier
	for _, d := range domains {
		identifiers = append(identifiers, Identifier{Type: "dns", Value: d})
	}
	return c.ReplacementOrder(account, nil, identifiers)
}

// NewOrderExtension takes a struct providing any extensions onto the order
func (c Client) NewOrderExtension(account Account, identifiers []Identifier, ext OrderExtension) (Order, error) {
	return c.ReplacementOrderExtension(account, nil, identifiers, ext)
}

// ReplacementOrder takes an existing *x509.Certificate and initiates a new
// order for a new certificate, but with the order being marked as a
// replacement. Replacement orders which are valid replacements are (currently)
// exempt from Let's Encrypt NewOrder rate limits, but may not be exempt from
// other ACME CAs ACME Renewal Info implementations. At least one identifier
// must match the list of identifiers from the parent order to be considered as
// a valid replacement order.
// See https://datatracker.ietf.org/doc/html/draft-ietf-acme-ari-03#section-5
func (c Client) ReplacementOrder(account Account, oldCert *x509.Certificate, identifiers []Identifier) (Order, error) {
	return c.ReplacementOrderExtension(account, oldCert, identifiers, OrderExtension{})
}

// ReplacementOrderExtension takes a struct providing any extensions onto the order
func (c Client) ReplacementOrderExtension(account Account, oldCert *x509.Certificate, identifiers []Identifier, ext OrderExtension) (Order, error) {
	// If an old cert being replaced is present and the acme directory doesn't list a RenewalInfo endpoint,
	// throw an error. This endpoint being present indicates support for ARI.
	if oldCert != nil && c.dir.RenewalInfo == "" {
		return Order{}, ErrRenewalInfoNotSupported
	}

	// optional fields are listed as 'omitempty' so the json encoder doesn't
	// include those keys if their values are not provided.
	newOrderReq := struct {
		Identifiers []Identifier `json:"identifiers"`
		Replaces    string       `json:"replaces,omitempty"`
		Profile     string       `json:"Profile,omitempty"`
	}{
		Identifiers: identifiers,
	}

	newOrderResp := Order{}

	if ext.Profile != "" {
		_, ok := c.Directory().Meta.Profiles[ext.Profile]
		if !ok {
			return Order{}, fmt.Errorf("requested Profile not advertised by directory: %v", ext.Profile)
		}
		newOrderReq.Profile = ext.Profile
	}

	// If present, add the ari cert ID from the original/old certificate
	if oldCert != nil {
		replacesCertID, err := GenerateARICertID(oldCert)
		if err != nil {
			return Order{}, fmt.Errorf("acme: error generating replacement certificate id: %v", err)
		}

		newOrderReq.Replaces = replacesCertID
		newOrderResp.Replaces = replacesCertID // server does not appear to set this currently?
	}

	// Submit the order
	resp, err := c.post(c.dir.NewOrder, account.URL, account.PrivateKey, newOrderReq, &newOrderResp, http.StatusCreated)
	if err != nil {
		return newOrderResp, err
	}
	defer resp.Body.Close()

	newOrderResp.URL = resp.Header.Get("Location")
	return newOrderResp, nil
}

// FetchOrder fetches an existing order given an order url.
func (c Client) FetchOrder(account Account, orderURL string) (Order, error) {
	orderResp := Order{
		URL: orderURL, // boulder response doesn't seem to contain location header for this request
	}
	_, err := c.post(orderURL, account.URL, account.PrivateKey, "", &orderResp, http.StatusOK)

	return orderResp, err
}

// Helper function to determine whether an order is "finished" by its status.
func checkFinalizedOrderStatus(order Order) (bool, error) {
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
func (c Client) FinalizeOrder(account Account, order Order, csr *x509.CertificateRequest) (Order, error) {
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
