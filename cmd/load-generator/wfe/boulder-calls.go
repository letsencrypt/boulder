package wfe

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/core"

	"gopkg.in/square/go-jose.v1"
)

// not entirely sure this will actually work...?
var (
	stringToOperation = map[string]func(*State, *context) error{
		"newRegistration":   newRegistration,
		"getRegistration":   getRegistration,
		"newAuthorization":  newAuthorization,
		"solveHTTPOne":      solveHTTPOne,
		"solveTLSOne":       solveTLSOne,
		"newCertificate":    newCertificate,
		"revokeCertificate": revokeCertificate,
	}
)
var plainReg = []byte(`{"resource":"new-reg"}`)

func newRegistration(s *State, ctx *context) error {
	// if we have generated the max number of registrations just become getRegistration
	if s.maxRegs != 0 && s.numRegs() >= s.maxRegs {
		return getRegistration(s, ctx)
	}
	// signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	// signKey.Precompute()
	signer, err := jose.NewSigner(jose.ES256, signKey)
	if err != nil {
		return err
	}
	ctx.ns = &nonceSource{s: s}
	signer.SetNonceSource(ctx.ns)

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
		return err
	}

	nStarted := time.Now()
	resp, err := s.post(fmt.Sprintf("%s/acme/new-reg", s.apiBase), requestPayload, ctx.ns)
	nFinished := time.Now()
	nState := "good"
	defer func() { s.callLatency.Add("POST /acme/new-reg", nStarted, nFinished, nState) }()
	if err != nil {
		fmt.Printf("[FAILED] new-reg, post failed: %s\n", err)
		nState = "error"
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		body, err := ioutil.ReadAll(resp.Body)
		nState = "error"
		if err != nil {
			// just fail
			return fmt.Errorf("bad response: %s", err)
		}
		return fmt.Errorf("bad response, status %d: %s", resp.StatusCode, body)
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
		return err
	}

	tStarted := time.Now()
	resp, err = s.post(resp.Header.Get("Location"), requestPayload, ctx.ns)
	tFinished := time.Now()
	tState := "good"
	defer func() { s.callLatency.Add("POST /acme/reg/{ID}", tStarted, tFinished, tState) }()
	if err != nil {
		fmt.Printf("[FAILED] reg, post failed: %s\n", err)
		tState = "error"
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			tState = "error"
			return err
		}
		tState = "error"
		fmt.Printf("[FAILED] reg, bad response: %s\n", string(body))
		return fmt.Errorf("bad response, status %d: %s", resp.StatusCode, err)
	}

	ctx.reg = &registration{key: signKey, signer: signer}
	s.addRegistration(ctx.reg)
	return nil
}

func newAuthorization(s *State, ctx *context) error {
	// generate a random(-ish) domain name,  will cause some multiples but not enough to make rate limits annoying!
	n := time.Now().UnixNano()
	b := new(bytes.Buffer)
	binary.Write(b, binary.LittleEndian, n)
	randomDomain := fmt.Sprintf("%x.%s", sha1.Sum(b.Bytes()), s.domainBase)

	// create the registration object
	initAuth := fmt.Sprintf(`{"resource":"new-authz","identifier":{"type":"dns","value":"%s"}}`, randomDomain)

	// build the JWS object
	getNew := false
	if mrand.Intn(1) == 0 {
		getNew = true
	}
	requestPayload, err := s.signWithNonce("/acme/new-authz", getNew, []byte(initAuth), ctx.reg.signer)
	if err != nil {
		return err
	}

	started := time.Now()
	resp, err := s.post(fmt.Sprintf("%s/acme/new-authz", s.apiBase), requestPayload, ctx.ns)
	finished := time.Now()
	state := "good"
	defer func() { s.callLatency.Add("POST /acme/new-authz", started, finished, state) }()
	if err != nil {
		state = "error"
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		// something
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			state = "error"
			return err
		}
		state = "error"
		return fmt.Errorf("bad response, status %d: %s", resp.StatusCode, body)
	}
	// location := resp.Header.Get("Location")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		state = "error"
		// just fail
		return err
	}

	var authz core.Authorization
	err = json.Unmarshal(body, &authz)
	if err != nil {
		state = "error"
		return err
	}
	// populate authz ID from location header because we strip it
	paths := strings.Split(resp.Header.Get("Location"), "/")
	authz.ID = paths[len(paths)-1]

	ctx.pendingAuthz = append(ctx.pendingAuthz, &authz)
	return nil
}

func getPending(ctx *context) *core.Authorization {
	authzIndex := mrand.Intn(len(ctx.pendingAuthz))
	authz := ctx.pendingAuthz[authzIndex]
	ctx.pendingAuthz = append(ctx.pendingAuthz[:authzIndex], ctx.pendingAuthz[authzIndex+1:]...)
	return authz
}

func solveHTTPOne(s *State, ctx *context) error {
	if len(ctx.pendingAuthz) == 0 {
		return errors.New("no pending authorizations to complete")
	}
	authz := getPending(ctx)
	var chall *core.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			chall = &c
			break
		}
	}
	if chall == nil {
		return errors.New("no http-01 challenges to complete")
	}

	jwk := &jose.JsonWebKey{Key: &ctx.reg.key.PublicKey}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	authStr := fmt.Sprintf("%s.%s", chall.Token, base64.RawURLEncoding.EncodeToString(thumbprint))
	s.challSrv.addHTTPOneChallenge(chall.Token, authStr)

	update := fmt.Sprintf(`{"resource":"challenge","keyAuthorization":"%s"}`, authStr)
	requestPayload, err := s.signWithNonce("/acme/challenge", false, []byte(update), ctx.reg.signer)
	if err != nil {
		return err
	}

	cStarted := time.Now()
	resp, err := s.post(chall.URI, requestPayload, ctx.ns)
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
		resp, err = s.client.Get(fmt.Sprintf("%s/acme/authz/%s", s.apiBase, authz.ID))
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
			fmt.Printf("[FAILED] http-01 failed: %s\n", string(body))
			break
		}
		time.Sleep(3 * time.Second) // XXX: Mimics certbot behaviour
	}
	if ident == "" {
		return errors.New("failed to complete http-01 challenge")
	}

	ctx.finalizedAuthz = append(ctx.finalizedAuthz, ident)
	return nil
}

func solveTLSOne(s *State, ctx *context) error {
	if len(ctx.pendingAuthz) == 0 {
		return errors.New("no pending authorizations to complete")
	}
	authz := getPending(ctx)
	var chall *core.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "tls-sni-01" {
			chall = &c
			break
		}
	}
	if chall == nil {
		return errors.New("no http-01 challenges to complete")
	}

	jwk := &jose.JsonWebKey{Key: &ctx.reg.key.PublicKey}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	authStr := fmt.Sprintf("%s.%s", chall.Token, base64.RawURLEncoding.EncodeToString(thumbprint))

	update := fmt.Sprintf(`{"resource":"challenge","keyAuthorization":"%s"}`, authStr)
	requestPayload, err := s.signWithNonce("/acme/challenge", false, []byte(update), ctx.reg.signer)
	if err != nil {
		return err
	}

	cStarted := time.Now()
	resp, err := s.post(chall.URI, requestPayload, ctx.ns)
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
		resp, err = s.client.Get(fmt.Sprintf("%s/acme/authz/%s", s.apiBase, authz.ID))
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
			fmt.Printf("[FAILED] tls-sni-01 failed: %s\n", string(body))
			break
		}
		time.Sleep(3 * time.Second) // XXX: Mimics certbot behaviour
	}
	if ident == "" {
		return errors.New("failed to complete tls-sni-01 challenge")
	}

	ctx.finalizedAuthz = append(ctx.finalizedAuthz, ident)
	return nil
}

func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}

func newCertificate(s *State, ctx *context) error {
	authsLen := len(ctx.finalizedAuthz)
	num := min(mrand.Intn(authsLen), s.maxNamesPerCert)
	dnsNames := []string{}
	for i := 0; i <= num; i++ {
		dnsNames = append(dnsNames, ctx.finalizedAuthz[mrand.Intn(authsLen)])
	}
	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{DNSNames: dnsNames},
		s.certKey,
	)
	if err != nil {
		return err
	}

	request := fmt.Sprintf(
		`{"resource":"new-cert","csr":"%s"}`,
		base64.URLEncoding.EncodeToString(csr),
	)

	// build the JWS object
	requestPayload, err := s.signWithNonce("/acme/new-cert", false, []byte(request), ctx.reg.signer)
	if err != nil {
		return err
	}

	started := time.Now()
	resp, err := s.post(fmt.Sprintf("%s/acme/new-cert", s.apiBase), requestPayload, ctx.ns)
	finished := time.Now()
	state := "good"
	defer func() { s.callLatency.Add("POST /acme/new-cert", started, finished, state) }()
	if err != nil {
		state = "error"
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		state = "error"
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("bad response, status %d: %s", resp.StatusCode, body)
	}

	if certLoc := resp.Header.Get("Location"); certLoc != "" {
		ctx.certs = append(ctx.certs, certLoc)
	}

	return nil
}

func revokeCertificate(s *State, ctx *context) error {
	// randomly select a cert to revoke
	if len(ctx.certs) == 0 {
		return errors.New("no certificates to revoke")
	}

	index := mrand.Intn(len(ctx.certs))
	resp, err := s.client.Get(ctx.certs[index])
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	request := fmt.Sprintf(`{"resource":"revoke-cert","certificate":"%s"}`, base64.URLEncoding.EncodeToString(body))
	requestPayload, err := s.signWithNonce("/acme/revoke-cert", false, []byte(request), ctx.reg.signer)
	if err != nil {
		return err
	}

	started := time.Now()
	resp, err = s.post(fmt.Sprintf("%s/acme/revoke-cert", s.apiBase), requestPayload, ctx.ns)
	finished := time.Now()
	state := "good"
	s.callLatency.Add("POST /acme/revoke-cert", started, finished, state)
	if err != nil {
		state = "error"
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		state = "error"
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("bad response, status %d: %s", resp.StatusCode, body)
	}

	ctx.certs = append(ctx.certs[:index], ctx.certs[index+1:]...)
	return nil
}
