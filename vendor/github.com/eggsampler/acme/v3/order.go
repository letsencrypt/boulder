package acme

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// NewOrder initiates a new order for a new certificate.
func (c Client) NewOrder(account Account, identifiers []Identifier) (Order, error) {
	newOrderReq := struct {
		Identifiers []Identifier `json:"identifiers"`
	}{
		Identifiers: identifiers,
	}
	newOrderResp := Order{}
	resp, err := c.post(c.dir.NewOrder, account.URL, account.PrivateKey, newOrderReq, &newOrderResp, http.StatusCreated)
	if err != nil {
		return newOrderResp, err
	}

	newOrderResp.URL = resp.Header.Get("Location")

	return newOrderResp, nil
}

// NewOrderDomains is a wrapper for NewOrder(AcmeAccount, []AcmeIdentifiers)
// Creates a dns identifier for each provided domain
func (c Client) NewOrderDomains(account Account, domains ...string) (Order, error) {
	if len(domains) == 0 {
		return Order{}, errors.New("acme: no domains provided")
	}

	var ids []Identifier
	for _, d := range domains {
		ids = append(ids, Identifier{Type: "dns", Value: d})
	}

	return c.NewOrder(account, ids)
}

// FetchOrder fetches an existing order given an order url.
func (c Client) FetchOrder(account Account, orderURL string) (Order, error) {
	orderResp := Order{
		URL: orderURL, // boulder response doesn't seem to contain location header for this request
	}
	_, err := c.post(orderURL, account.URL, account.PrivateKey, "", &orderResp, http.StatusOK)

	return orderResp, err
}

// Helper function to determine whether an order is "finished" by it's status.
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

	if finished, err := checkFinalizedOrderStatus(order); finished {
		return order, err
	}

	pollInterval, pollTimeout := c.getPollingDurations()
	end := time.Now().Add(pollTimeout)
	for {
		if time.Now().After(end) {
			return order, errors.New("acme: finalized order timeout")
		}
		time.Sleep(pollInterval)

		if _, err := c.post(order.URL, account.URL, account.PrivateKey, "", &order, http.StatusOK); err != nil {
			// i dont think it's worth exiting the loop on this error
			// it could just be connectivity issue thats resolved before the timeout duration
			continue
		}

		order.URL = resp.Header.Get("Location")

		if finished, err := checkFinalizedOrderStatus(order); finished {
			return order, err
		}
	}
}
