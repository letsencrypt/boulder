package publisher

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/letsencrypt/boulder/test"
)

var testLeaf = `-----BEGIN CERTIFICATE-----
MIIHAjCCBeqgAwIBAgIQfwAAAQAAAUtRVNy9a8fMcDANBgkqhkiG9w0BAQsFADBa
MQswCQYDVQQGEwJVUzESMBAGA1UEChMJSWRlblRydXN0MRcwFQYDVQQLEw5UcnVz
dElEIFNlcnZlcjEeMBwGA1UEAxMVVHJ1c3RJRCBTZXJ2ZXIgQ0EgQTUyMB4XDTE1
MDIwMzIxMjQ1MVoXDTE4MDIwMjIxMjQ1MVowfzEYMBYGA1UEAxMPbGV0c2VuY3J5
cHQub3JnMSkwJwYDVQQKEyBJTlRFUk5FVCBTRUNVUklUWSBSRVNFQVJDSCBHUk9V
UDEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzETMBEGA1UECBMKQ2FsaWZvcm5pYTEL
MAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGE6T8
LcmS6g8lH/1Y5orXeZOva4gthrS+VmJUWlz3K4Er5q8CmVFTmD/rYL6tA31JYCAi
p2bVQ8z/PgWYGosuMzox2OO9MqnLwTTG074sCHTZi4foFb6KacS8xVu25u8RRBd8
1WJNlw736FO0pJUkkE3gDSPz1QTpw3gc6n7SyppaFr40D5PpK3PPoNCPfoz2bFtH
m2KRsUH924LRfitUZdI68kxJP7QG1SAbdZxA/qDcfvDSgCYW5WNmMKS4v+GHuMkJ
gBe20tML+hItmF5S9mYm/GbkFLG8YwWZrytUZrSjxmuL9nj3MaBrAPQw3/T582ry
KM8+z188kbnA7A+BAgMBAAGjggOdMIIDmTAOBgNVHQ8BAf8EBAMCBaAwggInBgNV
HSAEggIeMIICGjCCAQsGCmCGSAGG+S8ABgMwgfwwQAYIKwYBBQUHAgEWNGh0dHBz
Oi8vc2VjdXJlLmlkZW50cnVzdC5jb20vY2VydGlmaWNhdGVzL3BvbGljeS90cy8w
gbcGCCsGAQUFBwICMIGqGoGnVGhpcyBUcnVzdElEIFNlcnZlciBDZXJ0aWZpY2F0
ZSBoYXMgYmVlbiBpc3N1ZWQgaW4gYWNjb3JkYW5jZSB3aXRoIElkZW5UcnVzdCdz
IFRydXN0SUQgQ2VydGlmaWNhdGUgUG9saWN5IGZvdW5kIGF0IGh0dHBzOi8vc2Vj
dXJlLmlkZW50cnVzdC5jb20vY2VydGlmaWNhdGVzL3BvbGljeS90cy8wggEHBgZn
gQwBAgIwgfwwQAYIKwYBBQUHAgEWNGh0dHBzOi8vc2VjdXJlLmlkZW50cnVzdC5j
b20vY2VydGlmaWNhdGVzL3BvbGljeS90cy8wgbcGCCsGAQUFBwICMIGqGoGnVGhp
cyBUcnVzdElEIFNlcnZlciBDZXJ0aWZpY2F0ZSBoYXMgYmVlbiBpc3N1ZWQgaW4g
YWNjb3JkYW5jZSB3aXRoIElkZW5UcnVzdCdzIFRydXN0SUQgQ2VydGlmaWNhdGUg
UG9saWN5IGZvdW5kIGF0IGh0dHBzOi8vc2VjdXJlLmlkZW50cnVzdC5jb20vY2Vy
dGlmaWNhdGVzL3BvbGljeS90cy8wHQYDVR0OBBYEFNLAuFI2ugD0U24OgEPtX6+p
/xJQMEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly92YWxpZGF0aW9uLmlkZW50cnVz
dC5jb20vY3JsL3RydXN0aWRjYWE1Mi5jcmwwgYQGCCsGAQUFBwEBBHgwdjAwBggr
BgEFBQcwAYYkaHR0cDovL2NvbW1lcmNpYWwub2NzcC5pZGVudHJ1c3QuY29tMEIG
CCsGAQUFBzAChjZodHRwOi8vdmFsaWRhdGlvbi5pZGVudHJ1c3QuY29tL2NlcnRz
L3RydXN0aWRjYWE1Mi5wN2MwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MB8GA1UdIwQYMBaAFKJWJDzQ1BW56L94oxMQWEguFlThMC8GA1UdEQQoMCaCD2xl
dHNlbmNyeXB0Lm9yZ4ITd3d3LmxldHNlbmNyeXB0Lm9yZzANBgkqhkiG9w0BAQsF
AAOCAQEAgEmnzpYncB/E5SCHa5cnGorvNNE6Xsp3YXK9fJBT2++chQTkyFYpE12T
TR+cb7CTdRiYErNHXV8Hl/XTK8mxGxK8KXM9zUDlfrl7yBnyGTl2Sk8qJwA2kGuu
X9KA1o3MFkKMD809ITAlvPoQpml1Ke0aFo4NLO/LJKnJpkyF8L+JQrkfLNHpKYn3
PvnyJnurVTXDOIwQw8HVXbw6UKAad87e1hKGLYOpsaaKCLaNw1vg8uI+O9mv1MC6
FTfP1pSlr11s+Ih4YancuJud41rT8lXCUbDs1Uws9pPdVzLt8zk5M0vbHmTCljbg
UC5XkUmEvadMfgWslIQD0r6+BRRS+A==
-----END CERTIFICATE-----`

var testIntermediate = `-----BEGIN CERTIFICATE-----
MIIG3zCCBMegAwIBAgIQAJv84kD9Vb7ZJp4MASwbdzANBgkqhkiG9w0BAQsFADBK
MQswCQYDVQQGEwJVUzESMBAGA1UEChMJSWRlblRydXN0MScwJQYDVQQDEx5JZGVu
VHJ1c3QgQ29tbWVyY2lhbCBSb290IENBIDEwHhcNMTQwMzIwMTgwNTM4WhcNMjIw
MzIwMTgwNTM4WjBaMQswCQYDVQQGEwJVUzESMBAGA1UEChMJSWRlblRydXN0MRcw
FQYDVQQLEw5UcnVzdElEIFNlcnZlcjEeMBwGA1UEAxMVVHJ1c3RJRCBTZXJ2ZXIg
Q0EgQTUyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl2nXmZiFAj/p
JkJ26PRzP6kyRCaQeC54V5EZoF12K0n5k1pdWs6C88LY5Uw2eisdDdump/6REnzt
cgG3jKHF2syd/gn7V+IURw/onpGPlC2AMpOTA/UoeGi6fg9CtDF6BRQiUzPko61s
j6++Y2uyMp/ZF7nJ4GB8mdYx4eSgtz+vsjKsfoyc3ALr4bwfFJy8kfey+0Lz4SAr
y7+P87NwY/r3dSgCq8XUsO3qJX+HzTcUloM8QAIboJ4ZR3/zsMzFJWC4NRLxUesX
3Pxbpdmb70BM13dx6ftFi37y42mwQmYXRpA6zUY98bAJb9z/7jNhyvzHLjztXgrR
vyISaYBLIwIDAQABo4ICrzCCAqswgYkGCCsGAQUFBwEBBH0wezAwBggrBgEFBQcw
AYYkaHR0cDovL2NvbW1lcmNpYWwub2NzcC5pZGVudHJ1c3QuY29tMEcGCCsGAQUF
BzAChjtodHRwOi8vdmFsaWRhdGlvbi5pZGVudHJ1c3QuY29tL3Jvb3RzL2NvbW1l
cmNpYWxyb290Y2ExLnA3YzAfBgNVHSMEGDAWgBTtRBnA0/AGi+6ke75C5yZUyI42
djAPBgNVHRMBAf8EBTADAQH/MIIBMQYDVR0gBIIBKDCCASQwggEgBgRVHSAAMIIB
FjBQBggrBgEFBQcCAjBEMEIWPmh0dHBzOi8vc2VjdXJlLmlkZW50cnVzdC5jb20v
Y2VydGlmaWNhdGVzL3BvbGljeS90cy9pbmRleC5odG1sMAAwgcEGCCsGAQUFBwIC
MIG0GoGxVGhpcyBUcnVzdElEIFNlcnZlciBDZXJ0aWZpY2F0ZSBoYXMgYmVlbiBp
c3N1ZWQgaW4gYWNjb3JkYW5jZSB3aXRoIElkZW5UcnVzdCdzIFRydXN0SUQgQ2Vy
dGlmaWNhdGUgUG9saWN5IGZvdW5kIGF0IGh0dHBzOi8vc2VjdXJlLmlkZW50cnVz
dC5jb20vY2VydGlmaWNhdGVzL3BvbGljeS90cy9pbmRleC5odG1sMEoGA1UdHwRD
MEEwP6A9oDuGOWh0dHA6Ly92YWxpZGF0aW9uLmlkZW50cnVzdC5jb20vY3JsL2Nv
bW1lcmNpYWxyb290Y2ExLmNybDA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUH
AwIGCCsGAQUFBwMFBggrBgEFBQcDBgYIKwYBBQUHAwcwDgYDVR0PAQH/BAQDAgGG
MB0GA1UdDgQWBBSiViQ80NQVuei/eKMTEFhILhZU4TANBgkqhkiG9w0BAQsFAAOC
AgEAm4oWcizMGDsjzYFKfWUKferHD1Vusclu4/dra0PCx3HctXJMnuXc4Ngvn6Ab
BcanG0Uht+bkuC4TaaS3QMCl0LwcsIzlfRzDJdxIpREWHH8yoNoPafVN3u2iGiyT
5qda4Ej4WQgOmmNiluZPk8a4d4MkAxyQdVF/AVVx6Or+9d+bkQenjPSxWVmi/bfW
RBXq2AcD8Ej7AIU15dRnLEkESmJm4xtV2aqmCd0SSBGhJHYLcInUPzWVg1zcB5EQ
78GOTue8UrZvbcYhOufHG0k5JX5HVoVZ6GSXKqn5kqbcHXT6adVoWT/BxZruZiKQ
qkryoZoSywt7dDdDhpC2+oAOC+XwX2HJp2mrPaAea1+E4LM9C9iEDtjsn5FfsBz0
VRbMRdaoayXzOlTRhF3pGU2LLCmrXy/pqpqAGYPxyHr3auRn9fjv77UMEqVFdfOc
CspkK71IGqM9UwwMtCZBp0fK/Xv9o1d85paXcJ/aH8zg6EK4UkuXDFnLsg1LrIru
+YHeHOeSaXJlcjzwWVY/Exe5HymtqGH8klMhy65bjtapNt76+j2CJgxOdPEiTy/l
9LH5ujlo5qgemXE3ePwYZ9D3iiJThTf3tWkvdbz2wCPJAy2EHS0FxHMfx5sXsFsa
OY8B7wwvZTLzU6WWs781TJXx2CE04PneeeArLpVLkiGIWjk=
-----END CERTIFICATE-----`

var log = blog.UseMock()
var ctx = context.Background()

func getPort(srvURL string) (int, error) {
	url, err := url.Parse(srvURL)
	if err != nil {
		return 0, err
	}
	_, portString, err := net.SplitHostPort(url.Host)
	if err != nil {
		return 0, err
	}
	port, err := strconv.ParseInt(portString, 10, 64)
	if err != nil {
		return 0, err
	}
	return int(port), nil
}

type testLogSrv struct {
	*httptest.Server
	submissions int64
}

func logSrv(k *ecdsa.PrivateKey) *testLogSrv {
	testLog := &testLogSrv{}
	m := http.NewServeMux()
	m.HandleFunc("/ct/", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var jsonReq ctSubmissionRequest
		err := decoder.Decode(&jsonReq)
		if err != nil {
			return
		}
		precert := false
		if r.URL.Path == "/ct/v1/add-pre-chain" {
			precert = true
		}
		sct := CreateTestingSignedSCT(jsonReq.Chain, k, precert, time.Now())
		fmt.Fprint(w, string(sct))
		atomic.AddInt64(&testLog.submissions, 1)
	})

	testLog.Server = httptest.NewUnstartedServer(m)
	testLog.Server.Start()
	return testLog
}

// lyingLogSrv always signs SCTs with the timestamp it was given.
func lyingLogSrv(k *ecdsa.PrivateKey, timestamp time.Time) *testLogSrv {
	testLog := &testLogSrv{}
	m := http.NewServeMux()
	m.HandleFunc("/ct/", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var jsonReq ctSubmissionRequest
		err := decoder.Decode(&jsonReq)
		if err != nil {
			return
		}
		precert := false
		if r.URL.Path == "/ct/v1/add-pre-chain" {
			precert = true
		}
		sct := CreateTestingSignedSCT(jsonReq.Chain, k, precert, timestamp)
		fmt.Fprint(w, string(sct))
		atomic.AddInt64(&testLog.submissions, 1)
	})

	testLog.Server = httptest.NewUnstartedServer(m)
	testLog.Server.Start()
	return testLog
}

func errorLogSrv() *httptest.Server {
	m := http.NewServeMux()
	m.HandleFunc("/ct/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	server := httptest.NewUnstartedServer(m)
	server.Start()
	return server
}

func errorBodyLogSrv() *httptest.Server {
	m := http.NewServeMux()
	m.HandleFunc("/ct/v1/", func(w http.ResponseWriter, r *http.Request) {
		buf, _ := httputil.DumpRequest(r, true)
		fmt.Printf("Req: \n%s\n", string(buf))
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("well this isn't good now is it."))
	})

	server := httptest.NewUnstartedServer(m)
	server.Start()
	return server
}

func retryableLogSrv(k *ecdsa.PrivateKey, retries int, after *int) *httptest.Server {
	hits := 0
	m := http.NewServeMux()
	m.HandleFunc("/ct/", func(w http.ResponseWriter, r *http.Request) {
		if hits >= retries {
			decoder := json.NewDecoder(r.Body)
			var jsonReq ctSubmissionRequest
			err := decoder.Decode(&jsonReq)
			if err != nil {
				return
			}
			sct := CreateTestingSignedSCT(jsonReq.Chain, k, false, time.Now())
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, string(sct))
		} else {
			hits++
			if after != nil {
				w.Header().Add("Retry-After", fmt.Sprintf("%d", *after))
				w.WriteHeader(503)
				return
			}
			w.WriteHeader(http.StatusRequestTimeout)
		}
	})

	server := httptest.NewUnstartedServer(m)
	server.Start()
	return server
}

func badLogSrv() *httptest.Server {
	m := http.NewServeMux()
	m.HandleFunc("/ct/", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var jsonReq ctSubmissionRequest
		err := decoder.Decode(&jsonReq)
		if err != nil {
			return
		}
		// Submissions should always contain at least one cert
		if len(jsonReq.Chain) >= 1 {
			fmt.Fprint(w, `{"signature":"BAMASDBGAiEAknaySJVdB3FqG9bUKHgyu7V9AdEabpTc71BELUp6/iECIQDObrkwlQq6Azfj5XOA5E12G/qy/WuRn97z7qMSXXc82Q=="}`)
		}
	})

	server := httptest.NewUnstartedServer(m)
	server.Start()
	return server
}

func setup(t *testing.T) (*Impl, *x509.Certificate, *ecdsa.PrivateKey) {
	intermediatePEM, _ := pem.Decode([]byte(testIntermediate))

	pub := New(nil,
		log,
		metrics.NewNoopScope())
	pub.issuerBundle = append(pub.issuerBundle, ct.ASN1Cert{Data: intermediatePEM.Bytes})

	leafPEM, _ := pem.Decode([]byte(testLeaf))
	leaf, err := x509.ParseCertificate(leafPEM.Bytes)
	test.AssertNotError(t, err, "Couldn't parse leafPEM.Bytes")

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "Couldn't generate test key")

	return pub, leaf, k
}

func addLog(t *testing.T, pub *Impl, port int, pubKey *ecdsa.PublicKey) *Log {
	uri := fmt.Sprintf("http://localhost:%d", port)
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	test.AssertNotError(t, err, "Failed to marshal key")
	newLog, err := NewLog(uri, base64.StdEncoding.EncodeToString(der), log)
	test.AssertNotError(t, err, "Couldn't create log")
	test.AssertEquals(t, newLog.uri, fmt.Sprintf("http://localhost:%d", port))
	return newLog
}

func makePrecert(k *ecdsa.PrivateKey) ([]ct.ASN1Cert, []byte, error) {
	rootTmpl := x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               pkix.Name{CommonName: "root"},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootBytes, err := x509.CreateCertificate(rand.Reader, &rootTmpl, &rootTmpl, k.Public(), k)
	if err != nil {
		return nil, nil, err
	}
	root, err := x509.ParseCertificate(rootBytes)
	if err != nil {
		return nil, nil, err
	}
	precertTmpl := x509.Certificate{
		SerialNumber: big.NewInt(0),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}, Critical: true, Value: []byte{0x05, 0x00}},
		},
	}
	precert, err := x509.CreateCertificate(rand.Reader, &precertTmpl, root, k.Public(), k)
	if err != nil {
		return nil, nil, err
	}
	return []ct.ASN1Cert{ct.ASN1Cert{Data: rootBytes}}, precert, err
}

func TestTimestampVerificationFuture(t *testing.T) {
	pub, _, k := setup(t)

	server := lyingLogSrv(k, time.Now().Add(time.Hour))
	defer server.Close()
	port, err := getPort(server.URL)
	test.AssertNotError(t, err, "Failed to get test server port")
	testLog := addLog(t, pub, port, &k.PublicKey)

	// Precert
	trueBool := true
	issuerBundle, precert, err := makePrecert(k)
	test.AssertNotError(t, err, "Failed to create test leaf")
	pub.issuerBundle = issuerBundle

	_, err = pub.SubmitToSingleCTWithResult(ctx, &pubpb.Request{LogURL: &testLog.uri, LogPublicKey: &testLog.logID, Der: precert, Precert: &trueBool})
	if err == nil {
		t.Fatal("Expected error for lying log server, got none")
	}
	if !strings.HasPrefix(err.Error(), "SCT Timestamp was too far in the future") {
		t.Fatalf("Got wrong error: %s", err)
	}
}

func TestTimestampVerificationPast(t *testing.T) {
	pub, _, k := setup(t)

	server := lyingLogSrv(k, time.Now().Add(-time.Hour))
	defer server.Close()
	port, err := getPort(server.URL)
	test.AssertNotError(t, err, "Failed to get test server port")
	testLog := addLog(t, pub, port, &k.PublicKey)

	// Precert
	trueBool := true
	issuerBundle, precert, err := makePrecert(k)
	test.AssertNotError(t, err, "Failed to create test leaf")
	pub.issuerBundle = issuerBundle

	_, err = pub.SubmitToSingleCTWithResult(ctx, &pubpb.Request{LogURL: &testLog.uri, LogPublicKey: &testLog.logID, Der: precert, Precert: &trueBool})
	if err == nil {
		t.Fatal("Expected error for lying log server, got none")
	}
	if !strings.HasPrefix(err.Error(), "SCT Timestamp was too far in the past") {
		t.Fatalf("Got wrong error: %s", err)
	}
}

func TestLogCache(t *testing.T) {
	cache := logCache{
		logs: make(map[string]*Log),
	}

	// Adding a log with an invalid base64 public key should error
	_, err := cache.AddLog("www.test.com", "1234", log)
	test.AssertError(t, err, "AddLog() with invalid base64 pk didn't error")

	// Adding a log with an invalid URI should error
	_, err = cache.AddLog(":", "", log)
	test.AssertError(t, err, "AddLog() with an invalid log URI didn't error")

	// Create one keypair & base 64 public key
	k1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "ecdsa.GenerateKey() failed for k1")
	der1, err := x509.MarshalPKIXPublicKey(&k1.PublicKey)
	test.AssertNotError(t, err, "x509.MarshalPKIXPublicKey(der1) failed")
	k1b64 := base64.StdEncoding.EncodeToString(der1)

	// Create a second keypair & base64 public key
	k2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "ecdsa.GenerateKey() failed for k2")
	der2, err := x509.MarshalPKIXPublicKey(&k2.PublicKey)
	test.AssertNotError(t, err, "x509.MarshalPKIXPublicKey(der2) failed")
	k2b64 := base64.StdEncoding.EncodeToString(der2)

	// Adding the first log should not produce an error
	l1, err := cache.AddLog("http://log.one.example.com", k1b64, log)
	test.AssertNotError(t, err, "cache.AddLog() failed for log 1")
	test.AssertEquals(t, cache.Len(), 1)
	test.AssertEquals(t, l1.uri, "http://log.one.example.com")
	test.AssertEquals(t, l1.logID, k1b64)

	// Adding it again should not produce any errors, or increase the Len()
	l1, err = cache.AddLog("http://log.one.example.com", k1b64, log)
	test.AssertNotError(t, err, "cache.AddLog() failed for second add of log 1")
	test.AssertEquals(t, cache.Len(), 1)
	test.AssertEquals(t, l1.uri, "http://log.one.example.com")
	test.AssertEquals(t, l1.logID, k1b64)

	// Adding a second log should not error and should increase the Len()
	l2, err := cache.AddLog("http://log.two.example.com", k2b64, log)
	test.AssertNotError(t, err, "cache.AddLog() failed for log 2")
	test.AssertEquals(t, cache.Len(), 2)
	test.AssertEquals(t, l2.uri, "http://log.two.example.com")
	test.AssertEquals(t, l2.logID, k2b64)
}

func TestProbeLogs(t *testing.T) {
	pub, _, k := setup(t)

	srvA := logSrv(k)
	defer srvA.Close()
	portA, err := getPort(srvA.URL)
	test.AssertNotError(t, err, "Failed to get test server port")
	srvB := errorBodyLogSrv()
	defer srvB.Close()
	portB, err := getPort(srvB.URL)
	test.AssertNotError(t, err, "Failed to get test server port")

	addLog := func(uri string) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		test.AssertNotError(t, err, "ecdsa.GenerateKey() failed for k")
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		test.AssertNotError(t, err, "x509.MarshalPKIXPublicKey(der) failed")
		kb64 := base64.StdEncoding.EncodeToString(der)
		_, err = pub.ctLogsCache.AddLog(uri, kb64, pub.log)
		test.AssertNotError(t, err, "Failed to add log to logCache")
	}

	addLog(fmt.Sprintf("http://localhost:%d", portA))
	addLog(fmt.Sprintf("http://localhost:%d", portB))
	addLog("http://blackhole:9999")

	pub.ProbeLogs()

	test.AssertEquals(t, test.CountHistogramSamples(pub.metrics.probeLatency.With(prometheus.Labels{
		"log":    fmt.Sprintf("http://localhost:%d", portA),
		"status": "200 OK",
	})), 1)
	test.AssertEquals(t, test.CountHistogramSamples(pub.metrics.probeLatency.With(prometheus.Labels{
		"log":    fmt.Sprintf("http://localhost:%d", portB),
		"status": "400 Bad Request",
	})), 1)
	test.AssertEquals(t, test.CountHistogramSamples(pub.metrics.probeLatency.With(prometheus.Labels{
		"log":    "http://blackhole:9999",
		"status": "error",
	})), 1)
}
