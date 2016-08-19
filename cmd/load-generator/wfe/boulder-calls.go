package wfe

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/square/go-jose"

	"github.com/letsencrypt/boulder/core"
)

var plainReg = []byte(`{"resource":"new-reg"}`)

func (s *State) newRegistration(_ *registration) {
	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	signKey.Precompute()
	signer, err := jose.NewSigner(jose.RS256, signKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	signer.SetNonceSource(s)

	// create the registration object
	var regStr []byte
	if s.email != "" {
		regStr = []byte(fmt.Sprintf(`{"resource":"new-reg","contact":["mailto:%s"]}`, s.email))
	} else {
		regStr = plainReg
	}
	// build the JWS object
	requestPayload, err := s.signWithNonce("/acme/new-reg", true, regStr, signer)
	if err != nil {
		fmt.Printf("[FAILED] new-reg, sign failed: %s\n", err)
		return
	}

	nStarted := time.Now()
	resp, err := s.post(fmt.Sprintf("%s/acme/new-reg", s.apiBase), requestPayload)
	nFinished := time.Now()
	nState := "good"
	defer func() { s.callLatency.Add("POST /acme/new-reg", nStarted, nFinished, nState) }()
	if err != nil {
		fmt.Printf("[FAILED] new-reg, post failed: %s\n", err)
		nState = "error"
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		body, err := ioutil.ReadAll(resp.Body)
		nState = "error"
		if err != nil {
			// just fail
			return
		}
		fmt.Printf("[FAILED] new-reg, bad response: %s\n", string(body))
		return
	}

	// get terms
	links := resp.Header[http.CanonicalHeaderKey("link")]
	terms := ""
	for _, l := range links {
		if strings.HasSuffix(l, ">;rel=\"terms-of-service\"") {
			terms = l[1 : len(l)-len(">;rel=\"terms-of-service\"")]
			break
		}
	}

	// agree to terms
	regStr = []byte(fmt.Sprintf(`{"resource":"reg","agreement":"%s"}`, terms))

	// build the JWS object
	requestPayload, err = s.signWithNonce("/acme/reg", false, regStr, signer)
	if err != nil {
		fmt.Printf("[FAILED] reg, sign failed: %s\n", err)
		return
	}

	tStarted := time.Now()
	resp, err = s.post(resp.Header.Get("Location"), requestPayload)
	tFinished := time.Now()
	tState := "good"
	defer func() { s.callLatency.Add("POST /acme/reg/{ID}", tStarted, tFinished, tState) }()
	if err != nil {
		fmt.Printf("[FAILED] reg, post failed: %s\n", err)
		tState = "error"
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			tState = "error"
			return
		}
		tState = "status"
		fmt.Printf("[FAILED] reg, bad response: %s\n", string(body))
		return
	}

	s.addReg(&registration{key: signKey, signer: signer, iMu: new(sync.RWMutex)})
}

func (s *State) sendHTTPOneChallenge(token, content string) error {
	resp, err := s.client.Post(fmt.Sprintf("http://%s/ho", s.challRPCAddr), "application/text", bytes.NewBufferString(fmt.Sprintf("%s;;%s", token, content)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Invalid response code for http-0 RPC call: %d", resp.StatusCode)
	}
	return nil
}

func (s *State) solveHTTPOne(reg *registration, chall core.Challenge, signer jose.Signer, authURI string) error {
	jwk := &jose.JsonWebKey{Key: &reg.key.PublicKey}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	authStr := fmt.Sprintf("%s.%s", chall.Token, base64.RawURLEncoding.EncodeToString(thumbprint))
	err = s.sendHTTPOneChallenge(
		chall.Token,
		authStr,
	)
	if err != nil {
		return err
	}

	update := fmt.Sprintf(`{"resource":"challenge","keyAuthorization":"%s"}`, authStr)
	requestPayload, err := s.signWithNonce("/acme/challenge", false, []byte(update), signer)
	if err != nil {
		return err
	}

	cStarted := time.Now()
	resp, err := s.post(chall.URI, requestPayload)
	cFinished := time.Now()
	cState := "good"
	defer func() { s.callLatency.Add("POST /acme/challenge/{ID}", cStarted, cFinished, cState) }()
	if err != nil {
		cState = "error"
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		cState = "error"
		return fmt.Errorf("Unexpected error code")
	}
	// Sit and spin until status valid or invalid
	ident := ""
	for i := 0; i < 3; i++ {
		aStarted := time.Now()
		resp, err = s.client.Get(authURI)
		aFinished := time.Now()
		aState := "good"
		defer func() { s.callLatency.Add("GET /acme/authz/{ID}", aStarted, aFinished, aState) }()
		if err != nil {
			fmt.Printf("[FAILED] authzer: %s\n", err)
			aState = "error"
			return err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			aState = "error"
			return err
		}
		var newAuthz core.Authorization
		err = json.Unmarshal(body, &newAuthz)
		if err != nil {
			fmt.Printf("[FAILED] authz: %s\n", string(body))
			aState = "error"
			return err
		}
		if newAuthz.Status == "valid" {
			ident = newAuthz.Identifier.Value
			break
		}
		if newAuthz.Status == "invalid" {
			break
		}
		time.Sleep(3 * time.Second) // XXX: Mimics certbot behaviour
	}
	if ident == "" {
		return nil
	}
	reg.iMu.Lock()
	reg.auths = append(reg.auths, ident)
	reg.iMu.Unlock()
	return nil
}

var dnsLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func (s *State) newAuthorization(reg *registration) {
	// generate a random domain name
	var buff bytes.Buffer
	mrand.Seed(time.Now().UnixNano())
	randLen := mrand.Intn(59-len(s.domainBase)) + 1
	for i := 0; i < randLen; i++ {
		buff.WriteByte(dnsLetters[mrand.Intn(len(dnsLetters))])
	}
	randomDomain := fmt.Sprintf("%s.%s", buff.String(), s.domainBase)

	// create the registration object
	initAuth := fmt.Sprintf(`{"resource":"new-authz","identifier":{"type":"dns","value":"%s"}}`, randomDomain)

	// build the JWS object
	getNew := false
	if mrand.Intn(1) == 0 {
		getNew = true
	}
	requestPayload, err := s.signWithNonce("/acme/new-authz", getNew, []byte(initAuth), reg.signer)
	if err != nil {
		fmt.Printf("[FAILED] new-authz: %s\n", err)
		return
	}

	started := time.Now()
	resp, err := s.post(fmt.Sprintf("%s/acme/new-authz", s.apiBase), requestPayload)
	finished := time.Now()
	state := "good"
	defer func() { s.callLatency.Add("POST /acme/new-authz", started, finished, state) }()
	if err != nil {
		fmt.Printf("[FAILED] new-authz: %s\n", err)
		state = "error"
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		// something
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			state = "error"
			return
		}
		state = "error"
		fmt.Printf("[FAILED] new-authz: %s\n", string(body))
		return
	}
	location := resp.Header.Get("Location")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		state = "error"
		// just fail
		return
	}

	var authz core.Authorization
	err = json.Unmarshal(body, &authz)
	if err != nil {
		fmt.Println(err)
		state = "error"
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
			// case "tls-sni-02":
			// case "dns-01":
		}
	}
}

func (s *State) newCertificate(reg *registration) {
	// woot, almost done...
	authsLen := len(reg.auths)
	num := mrand.Intn(authsLen)
	dnsNames := []string{}
	for i := 0; i <= num; i++ {
		dnsNames = append(dnsNames, reg.auths[mrand.Intn(authsLen)])
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
		base64.URLEncoding.EncodeToString(csr),
	)

	// build the JWS object
	requestPayload, err := s.signWithNonce("/acme/new-cert", false, []byte(request), reg.signer)
	if err != nil {
		fmt.Printf("[FAILED] new-cert: %s\n", err)
		return
	}

	started := time.Now()
	resp, err := s.post(fmt.Sprintf("%s/acme/new-cert", s.apiBase), requestPayload)
	finished := time.Now()
	state := "good"
	defer func() { s.callLatency.Add("POST /acme/new-cert", started, finished, state) }()
	if err != nil {
		fmt.Printf("[FAILED] new-cert: %s\n", err)
		state = "error"
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("WELP, bad body: %s\n", err)
			state = "error"
			return
		}
		state = "error"
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
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("WELP, bad body: %s\n", err)
		return
	}

	request := fmt.Sprintf(`{"resource":"revoke-cert","certificate":"%s"}`, base64.URLEncoding.EncodeToString(body))
	requestPayload, err := s.signWithNonce("/acme/revoke-cert", false, []byte(request), reg.signer)
	if err != nil {
		fmt.Printf("[FAILED] revoke-cert: %s\n", err)
		return
	}

	started := time.Now()
	resp, err = s.post(fmt.Sprintf("%s/acme/revoke-cert", s.apiBase), requestPayload)
	finished := time.Now()
	state := "good"
	s.callLatency.Add("POST /acme/revoke-cert", started, finished, state)
	if err != nil {
		fmt.Printf("[FAILED] revoke-cert: %s\n", err)
		state = "error"
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("WELP, bad body: %s\n", err)
			state = "error"
			return
		}
		state = "error"
		fmt.Printf("[FAILED] revoke-cert: %s\n", string(body))
		return
	}

	reg.certs = append(reg.certs[:index], reg.certs[index+1:]...)
}
