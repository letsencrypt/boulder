package wfe

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"

	"github.com/letsencrypt/boulder/core"
)

var termsURL = "http://127.0.0.1:4001/terms/v1"

func (s *State) newRegistration(_ *registration) {
	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	signer, err := jose.NewSigner(jose.RS256, signKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	// create the registration object
	regStr := []byte(`{"resource":"new-reg","contact":[]}`)
	// build the JWS object
	requestPayload, err := s.signWithNonce(regStr, signer)
	if err != nil {
		fmt.Printf("[FAILED] new-reg, sign failed: %s\n", err)
		return
	}

	started := time.Now()
	resp, err := s.post(fmt.Sprintf("%s/acme/new-reg", s.apiBase), requestPayload)
	s.callLatency.Add("POST /acme/new-reg", time.Since(started))
	if err != nil {
		fmt.Printf("[FAILED] new-reg, post failed: %s\n", err)
		return
	}
	if resp.StatusCode != 201 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			return
		}
		fmt.Printf("[FAILED] new-reg, bad response: %s\n", string(body))
		return
	}

	// agree to terms
	regStr = []byte(fmt.Sprintf(`{"resource":"reg","agreement":"%s"}`, termsURL))

	// build the JWS object
	requestPayload, err = s.signWithNonce(regStr, signer)
	if err != nil {
		fmt.Printf("[FAILED] reg, sign failed: %s\n", err)
		return
	}

	started = time.Now()
	resp, err = s.post(resp.Header.Get("Location"), requestPayload)
	s.callLatency.Add("POST /acme/reg/", time.Since(started))
	if err != nil {
		fmt.Printf("[FAILED] reg, post failed: %s\n", err)
		return
	}
	if resp.StatusCode != 202 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			return
		}
		fmt.Printf("[FAILED] reg, bad response: %s\n", string(body))
		return
	}

	s.addReg(&registration{key: signKey, signer: signer, iMu: new(sync.RWMutex)})
}

func (s *State) solveHTTPOne(reg *registration, chall core.Challenge, signer jose.Signer, authURI string) error {
	keyAuthz, err := core.NewKeyAuthorization(chall.Token, &jose.JsonWebKey{Key: &reg.key.PublicKey})
	if err != nil {
		return err
	}
	authStr := fmt.Sprintf("%s.%s", keyAuthz.Token, keyAuthz.Thumbprint)
	s.addHTTPOneChallenge(
		chall.Token,
		authStr,
	)

	update := fmt.Sprintf(`{"resource":"challenge","keyAuthorization":"%s"}`, authStr)
	requestPayload, err := s.signWithNonce([]byte(update), signer)
	if err != nil {
		return err
	}

	started := time.Now()
	resp, err := s.post(chall.URI, requestPayload)
	s.callLatency.Add("POST /acme/challenge/", time.Since(started))
	if err != nil {
		return err
	}
	if resp.StatusCode != 202 {
		return fmt.Errorf("Unexpected error code")
	}
	// Sit and spin until status valid or invalid
	var newAuthz core.Authorization
	for {
		started = time.Now()
		resp, err = s.client.Get(authURI)
		s.callLatency.Add("GET /acme/authz/", time.Since(started))
		if err != nil {
			fmt.Printf("[FAILED] authzer: %s\n", err)
			return err
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			return err
		}
		err = json.Unmarshal(body, &newAuthz)
		if err != nil {
			fmt.Printf("[FAILED] authz: %s\n", string(body))
			return err
		}
		if newAuthz.Status == "valid" {
			break
		}
		time.Sleep(3 * time.Second) // XXX: Mimics client behaviour
	}
	reg.iMu.Lock()
	reg.auths = append(reg.auths, newAuthz)
	reg.iMu.Unlock()
	return nil
}

var dnsLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func (s *State) newAuthorization(reg *registration) {
	// generate a random domain name
	var buff bytes.Buffer
	mrand.Seed(time.Now().UnixNano())
	randLen := mrand.Intn(60 - len(s.domainBase))
	for i := 0; i < randLen; i++ {
		buff.WriteByte(dnsLetters[mrand.Intn(len(dnsLetters))])
	}
	randomDomain := fmt.Sprintf("%s.%s", buff.String(), s.domainBase)

	// create the registration object
	initAuth := fmt.Sprintf(`{"resource":"new-authz","identifier":{"type":"dns","value":"%s"}}`, randomDomain)

	// build the JWS object
	requestPayload, err := s.signWithNonce([]byte(initAuth), reg.signer)
	if err != nil {
		fmt.Printf("[FAILED] new-authz: %s\n", err)
		return
	}

	started := time.Now()
	resp, err := s.post(fmt.Sprintf("%s/acme/new-authz", s.apiBase), requestPayload)
	s.callLatency.Add("POST /acme/new-authz", time.Since(started))
	if err != nil {
		fmt.Printf("[FAILED] new-authz: %s\n", err)
		return
	}
	if resp.StatusCode != 201 {
		// something
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			return
		}
		fmt.Printf("[FAILED] new-authz: %s\n", string(body))
		return
	}
	location := resp.Header.Get("Location")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// just fail
		return
	}

	var authz core.Authorization
	err = json.Unmarshal(body, &authz)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, c := range authz.Challenges {
		switch c.Type {
		case "http-01":
			err = s.solveHTTPOne(reg, c, reg.signer, location)
			if err != nil {
				fmt.Printf("Failed to solve http-0 challenge: %s\n", err)
				return
			}
		}
	}
}

func (s *State) newCertificate(reg *registration) {
	// woot, almost done...
	authsLen := len(reg.auths)
	num := mrand.Intn(authsLen)
	dnsNames := []string{}
	for i := 0; i <= num; i++ {
		dnsNames = append(dnsNames, reg.auths[mrand.Intn(authsLen)].Identifier.Value)
	}
	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{DNSNames: dnsNames},
		s.certKey,
	)
	if err != nil {
		fmt.Printf("[FAILED] new-cert: %s\n", err)
		return
	}

	request := fmt.Sprintf(
		`{"resource":"new-cert","csr":"%s"}`,
		core.B64enc(csr),
	)

	// build the JWS object
	requestPayload, err := s.signWithNonce([]byte(request), reg.signer)
	if err != nil {
		fmt.Printf("[FAILED] new-cert: %s\n", err)
		return
	}

	started := time.Now()
	resp, err := s.post(fmt.Sprintf("%s/acme/new-cert", s.apiBase), requestPayload)
	s.callLatency.Add("POST /acme/new-cert", time.Since(started))
	if err != nil {
		fmt.Printf("[FAILED] new-cert: %s\n", err)
		return
	}
	if resp.StatusCode != 201 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("WELP, bad body: %s\n", err)
			return
		}
		fmt.Printf("[FAILED] new-cert: %s\n", string(body))
		return
	}

	if certLoc := resp.Header.Get("Location"); certLoc != "" {
		reg.iMu.Lock()
		reg.certs = append(reg.certs, certLoc)
		reg.iMu.Unlock()
	} else {
		fmt.Println(resp.Header)
	}

	return
}

func (s *State) revokeCertificate(reg *registration) {
	// randomly select a cert to revoke
	reg.iMu.Lock()
	defer reg.iMu.Unlock()
	if len(reg.certs) == 0 {
		fmt.Println("WELP, no certs")
		return
	}

	index := mrand.Intn(len(reg.certs))
	resp, err := s.client.Get(reg.certs[index])
	if err != nil {
		fmt.Printf("[FAILED] cert: %s\n", err)
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("WELP, bad body: %s\n", err)
		return
	}

	request := fmt.Sprintf(`{"resource":"revoke-cert","certificate":"%s"}`, core.B64enc(body))
	requestPayload, err := s.signWithNonce([]byte(request), reg.signer)
	if err != nil {
		fmt.Printf("[FAILED] revoke-cert: %s\n", err)
		return
	}

	started := time.Now()
	resp, err = s.post(fmt.Sprintf("%s/acme/revoke-cert", s.apiBase), requestPayload)
	s.callLatency.Add("POST /acme/revoke-cert", time.Since(started))
	if err != nil {
		fmt.Printf("[FAILED] revoke-cert: %s\n", err)
		return
	}
	if resp.StatusCode != 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("WELP, bad body: %s\n", err)
			return
		}
		fmt.Printf("[FAILED] revoke-cert: %s\n", string(body))
		return
	}

	reg.certs = append(reg.certs[:index], reg.certs[index+1:]...)
}
