package acme

// Similar to golang.org/x/crypto/acme/autocert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"sync"
)

// HostCheck function prototype to implement for checking hosts against before issuing certificates
type HostCheck func(host string) error

// WhitelistHosts implements a simple whitelist HostCheck
func WhitelistHosts(hosts ...string) HostCheck {
	m := map[string]bool{}
	for _, v := range hosts {
		m[v] = true
	}

	return func(host string) error {
		if !m[host] {
			return errors.New("autocert: host not whitelisted")
		}
		return nil
	}
}

// AutoCert is a stateful certificate manager for issuing certificates on connecting hosts
type AutoCert struct {
	// Acme directory Url
	// If nil, uses `LetsEncryptStaging`
	DirectoryURL string

	// Options contains the options used for creating the acme client
	Options []OptionFunc

	// A function to check whether a host is allowed or not
	// If nil, all hosts allowed
	// Use `WhitelistHosts(hosts ...string)` for a simple white list of hostnames
	HostCheck HostCheck

	// Cache dir to store account data and certificates
	// If nil, does not write cache data to file
	CacheDir string

	// When using a staging environment, include a root certificate for verification purposes
	RootCert string

	// Called before updating challenges
	PreUpdateChallengeHook func(Account, Challenge)

	// Mapping of token -> keyauth
	// Protected by a mutex, but not rwmutex because tokens are deleted once read
	tokensLock sync.RWMutex
	tokens     map[string][]byte

	// Mapping of cache key -> value
	cacheLock sync.Mutex
	cache     map[string][]byte

	// read lock around getting existing certs
	// write lock around issuing new certificate
	certLock sync.RWMutex

	client Client
}

// HTTPHandler Wraps a handler and provides serving of http-01 challenge tokens from /.well-known/acme-challenge/
// If handler is nil, will redirect all traffic otherwise to https
func (m *AutoCert) HTTPHandler(handler http.Handler) http.Handler {
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			handler.ServeHTTP(w, r)
			return
		}

		if err := m.checkHost(r.Host); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		token := path.Base(r.URL.Path)
		m.tokensLock.RLock()
		defer m.tokensLock.RUnlock()
		keyAuth := m.tokens[token]
		if len(keyAuth) == 0 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}

		_, _ = w.Write(keyAuth)
	})
}

// GetCertificate implements a tls.Config.GetCertificate hook
func (m *AutoCert) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.TrimSuffix(hello.ServerName, ".")

	if name == "" {
		return nil, errors.New("autocert: missing server name")
	}
	if !strings.Contains(strings.Trim(name, "."), ".") {
		return nil, errors.New("autocert: server name component count invalid")
	}
	if strings.ContainsAny(name, `/\`) {
		return nil, errors.New("autocert: server name contains invalid character")
	}

	// check the hostname is allowed
	if err := m.checkHost(name); err != nil {
		return nil, err
	}

	// check if there's an existing cert
	m.certLock.RLock()
	existingCert := m.getExistingCert(name)
	m.certLock.RUnlock()
	if existingCert != nil {
		return existingCert, nil
	}

	// if not, attempt to issue a new cert
	m.certLock.Lock()
	defer m.certLock.Unlock()
	return m.issueCert(name)
}

func (m *AutoCert) getDirectoryURL() string {
	if m.DirectoryURL != "" {
		return m.DirectoryURL
	}

	return LetsEncryptStaging
}

func (m *AutoCert) getCache(keys ...string) []byte {
	key := strings.Join(keys, "-")

	m.cacheLock.Lock()
	defer m.cacheLock.Unlock()

	b := m.cache[key]
	if len(b) > 0 {
		return b
	}

	if m.CacheDir == "" {
		return nil
	}

	b, _ = ioutil.ReadFile(path.Join(m.CacheDir, key))
	if len(b) == 0 {
		return nil
	}

	if m.cache == nil {
		m.cache = map[string][]byte{}
	}
	m.cache[key] = b
	return b
}

func (m *AutoCert) putCache(data []byte, keys ...string) context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	key := strings.Join(keys, "-")

	m.cacheLock.Lock()
	defer m.cacheLock.Unlock()

	if m.cache == nil {
		m.cache = map[string][]byte{}
	}
	m.cache[key] = data

	if m.CacheDir == "" {
		cancel()
		return ctx
	}

	go func() {
		_ = ioutil.WriteFile(path.Join(m.CacheDir, key), data, 0700)
		cancel()
	}()

	return ctx
}

func (m *AutoCert) checkHost(name string) error {
	if m.HostCheck == nil {
		return nil
	}
	return m.HostCheck(name)
}

func (m *AutoCert) getExistingCert(name string) *tls.Certificate {
	// check for a stored cert
	certData := m.getCache("cert", name)
	if len(certData) == 0 {
		// no cert
		return nil
	}

	privBlock, pubData := pem.Decode(certData)
	if len(pubData) == 0 {
		// no public key data (cert/issuer), ignore
		return nil
	}

	// decode pub chain
	var pubDER [][]byte
	var pub []byte
	for len(pubData) > 0 {
		var b *pem.Block
		b, pubData = pem.Decode(pubData)
		if b == nil {
			break
		}
		pubDER = append(pubDER, b.Bytes)
		pub = append(pub, b.Bytes...)
	}
	if len(pubData) > 0 {
		// leftover data in file - possibly corrupt, ignore
		return nil
	}

	certs, err := x509.ParseCertificates(pub)
	if err != nil {
		// bad certificates, ignore
		return nil
	}

	leaf := certs[0]

	// add any intermediate certs if present
	var intermediates *x509.CertPool
	if len(certs) > 1 {
		intermediates = x509.NewCertPool()
		for i := 1; i < len(certs); i++ {
			intermediates.AddCert(certs[i])
		}
	}

	// add a root certificate if present
	var roots *x509.CertPool
	if m.RootCert != "" {
		roots = x509.NewCertPool()
		rootBlock, _ := pem.Decode([]byte(m.RootCert))
		rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
		if err != nil {
			return nil
		}
		roots.AddCert(rootCert)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Intermediates: intermediates, Roots: roots}); err != nil {
		// invalid certificates , ignore
		return nil
	}

	privKey, err := x509.ParseECPrivateKey(privBlock.Bytes)
	if err != nil {
		// invalid private key, ignore
		return nil
	}

	return &tls.Certificate{
		Certificate: pubDER,
		PrivateKey:  privKey,
		Leaf:        leaf,
	}
}

func (m *AutoCert) issueCert(domainName string) (*tls.Certificate, error) {
	// attempt to load an existing account key
	var privKey *ecdsa.PrivateKey
	if keyData := m.getCache("account"); len(keyData) > 0 {
		block, _ := pem.Decode(keyData)
		x509Encoded := block.Bytes
		privKey, _ = x509.ParseECPrivateKey(x509Encoded)
	}

	// otherwise generate a new one
	if privKey == nil {
		var err error
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("autocert: error generating new account key: %v", err)
		}

		x509Encoded, _ := x509.MarshalECPrivateKey(privKey)
		pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded})

		m.putCache(pemEncoded, "account")
	}

	// create a new client if one doesn't exist
	if m.client.Directory().URL == "" {
		var err error
		m.client, err = NewClient(m.getDirectoryURL(), m.Options...)
		if err != nil {
			return nil, err
		}
	}

	// create/fetch acme account
	account, err := m.client.NewAccount(privKey, false, true)
	if err != nil {
		return nil, fmt.Errorf("autocert: error creating/fetching account: %v", err)
	}

	// start a new order process
	order, err := m.client.NewOrderDomains(account, domainName)
	if err != nil {
		return nil, fmt.Errorf("autocert: error creating new order for domain %s: %v", domainName, err)
	}

	// loop through each of the provided authorization Urls
	for _, authURL := range order.Authorizations {
		auth, err := m.client.FetchAuthorization(account, authURL)
		if err != nil {
			return nil, fmt.Errorf("autocert: error fetching authorization Url %q: %v", authURL, err)
		}

		if auth.Status == "valid" {
			continue
		}

		chal, ok := auth.ChallengeMap[ChallengeTypeHTTP01]
		if !ok {
			return nil, fmt.Errorf("autocert: unable to find http-01 challenge for auth %s, Url: %s", auth.Identifier.Value, authURL)
		}

		m.tokensLock.Lock()
		if m.tokens == nil {
			m.tokens = map[string][]byte{}
		}
		m.tokens[chal.Token] = []byte(chal.KeyAuthorization)
		m.tokensLock.Unlock()

		if m.PreUpdateChallengeHook != nil {
			m.PreUpdateChallengeHook(account, chal)
		}

		chal, err = m.client.UpdateChallenge(account, chal)
		if err != nil {
			return nil, fmt.Errorf("autocert: error updating authorization %s challenge (Url: %s) : %v", auth.Identifier.Value, authURL, err)
		}

		m.tokensLock.Lock()
		delete(m.tokens, chal.Token)
		m.tokensLock.Unlock()
	}

	// generate private key for cert
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("autocert: error generating certificate key for %s: %v", domainName, err)
	}
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, fmt.Errorf("autocert: error encoding certificate key for %s: %v", domainName, err)
	}
	certKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	})

	// create the new csr template
	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domainName},
		DNSNames:           []string{domainName},
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		return nil, fmt.Errorf("autocert: error creating certificate request for %s: %v", domainName, err)
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return nil, fmt.Errorf("autocert: error parsing certificate request for %s: %v", domainName, err)
	}

	// finalize the order with the acme server given a csr
	order, err = m.client.FinalizeOrder(account, order, csr)
	if err != nil {
		return nil, fmt.Errorf("autocert: error finalizing order for %s: %v", domainName, err)
	}

	// fetch the certificate chain from the finalized order provided by the acme server
	certs, err := m.client.FetchCertificates(account, order.Certificate)
	if err != nil {
		return nil, fmt.Errorf("autocert: error fetching order certificates for %s: %v", domainName, err)
	}

	certPem := certKeyPem
	// var certDer [][]byte
	for _, c := range certs {
		b := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})
		certPem = append(certPem, b...)
		// certDer = append(certDer, c.Raw)
	}
	m.putCache(certPem, "cert", domainName)

	return m.getExistingCert(domainName), nil
}
