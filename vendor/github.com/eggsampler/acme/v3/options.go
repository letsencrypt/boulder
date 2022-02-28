package acme

import (
	"crypto"
	"crypto/hmac"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// OptionFunc function prototype for passing options to NewClient
type OptionFunc func(client *Client) error

// WithHTTPTimeout sets a timeout on the http client used by the Client
func WithHTTPTimeout(duration time.Duration) OptionFunc {
	return func(client *Client) error {
		client.httpClient.Timeout = duration
		return nil
	}
}

// WithInsecureSkipVerify sets InsecureSkipVerify on the http client transport tls client config used by the Client
func WithInsecureSkipVerify() OptionFunc {
	return func(client *Client) error {
		client.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		return nil
	}
}

// WithUserAgentSuffix appends a user agent suffix for http requests to acme resources
func WithUserAgentSuffix(userAgentSuffix string) OptionFunc {
	return func(client *Client) error {
		client.userAgentSuffix = userAgentSuffix
		return nil
	}
}

// WithAcceptLanguage sets an Accept-Language header on http requests
func WithAcceptLanguage(acceptLanguage string) OptionFunc {
	return func(client *Client) error {
		client.acceptLanguage = acceptLanguage
		return nil
	}
}

// WithRetryCount sets the number of times the acme client retries when receiving an api error (eg, nonce failures, etc).
// Default: 5
func WithRetryCount(retryCount int) OptionFunc {
	return func(client *Client) error {
		if retryCount < 1 {
			return errors.New("retryCount must be > 0")
		}
		client.retryCount = retryCount
		return nil
	}
}

// WithHTTPClient Allows setting a custom http client for acme connections
func WithHTTPClient(httpClient *http.Client) OptionFunc {
	return func(client *Client) error {
		if httpClient == nil {
			return errors.New("client must not be nil")
		}
		client.httpClient = httpClient
		return nil
	}
}

// WithRootCerts sets the httpclient transport to use a given certpool for root certs
func WithRootCerts(pool *x509.CertPool) OptionFunc {
	return func(client *Client) error {
		client.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		}
		return nil
	}
}

// NewAccountOptionFunc function prototype for passing options to NewClient
type NewAccountOptionFunc func(crypto.Signer, *Account, *NewAccountRequest, Client) error

// NewAcctOptOnlyReturnExisting sets the new client request to only return existing accounts
func NewAcctOptOnlyReturnExisting() NewAccountOptionFunc {
	return func(privateKey crypto.Signer, account *Account, request *NewAccountRequest, client Client) error {
		request.OnlyReturnExisting = true
		return nil
	}
}

// NewAcctOptAgreeTOS sets the new account request as agreeing to the terms of service
func NewAcctOptAgreeTOS() NewAccountOptionFunc {
	return func(privateKey crypto.Signer, account *Account, request *NewAccountRequest, client Client) error {
		request.TermsOfServiceAgreed = true
		return nil
	}
}

// NewAcctOptWithContacts adds contacts to a new account request
func NewAcctOptWithContacts(contacts ...string) NewAccountOptionFunc {
	return func(privateKey crypto.Signer, account *Account, request *NewAccountRequest, client Client) error {
		request.Contact = contacts
		return nil
	}
}

// NewAcctOptExternalAccountBinding adds an external account binding to the new account request
// Code adopted from jwsEncodeJSON
func NewAcctOptExternalAccountBinding(binding ExternalAccountBinding) NewAccountOptionFunc {
	return func(privateKey crypto.Signer, account *Account, request *NewAccountRequest, client Client) error {
		if binding.KeyIdentifier == "" {
			return errors.New("acme: NewAcctOptExternalAccountBinding has no KeyIdentifier set")
		}
		if binding.MacKey == "" {
			return errors.New("acme: NewAcctOptExternalAccountBinding has no MacKey set")
		}
		if binding.Algorithm == "" {
			return errors.New("acme: NewAcctOptExternalAccountBinding has no Algorithm set")
		}
		if binding.HashFunc == 0 {
			return errors.New("acme: NewAcctOptExternalAccountBinding has no HashFunc set")
		}

		jwk, err := jwkEncode(privateKey.Public())
		if err != nil {
			return fmt.Errorf("acme: external account binding error encoding public key: %v", err)
		}
		payload := base64.RawURLEncoding.EncodeToString([]byte(jwk))

		phead := fmt.Sprintf(`{"alg":%q,"kid":%q,"url":%q}`,
			binding.Algorithm, binding.KeyIdentifier, client.Directory().NewAccount)
		phead = base64.RawURLEncoding.EncodeToString([]byte(phead))

		decodedAccountMac, err := base64.RawURLEncoding.DecodeString(binding.MacKey)
		if err != nil {
			return fmt.Errorf("acme: external account binding error decoding mac key: %v", err)
		}
		macHash := hmac.New(binding.HashFunc.New, decodedAccountMac)

		if _, err := macHash.Write([]byte(phead + "." + payload)); err != nil {
			return err
		}

		enc := struct {
			Protected string `json:"protected"`
			Payload   string `json:"payload"`
			Sig       string `json:"signature"`
		}{
			Protected: phead,
			Payload:   payload,
			Sig:       base64.RawURLEncoding.EncodeToString(macHash.Sum(nil)),
		}

		jwsEab, err := json.Marshal(&enc)
		if err != nil {
			return fmt.Errorf("acme: external account binding error marshalling struct: %v", err)
		}

		request.ExternalAccountBinding = jwsEab
		account.ExternalAccountBinding = binding
		return nil
	}
}
