package va

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"time"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"

	"testing"
)

func TestNewHTTPClient(t *testing.T) {
	dummyRedirHandler := func(_ *http.Request, _ []*http.Request) error {
		return nil
	}
	client := newHTTPClient(dummyRedirHandler)

	// The client should have a HTTP Transport
	rawTransport := client.Transport
	if httpTrans, ok := rawTransport.(*http.Transport); !ok {
		t.Fatalf(
			"newHTTPClient returned a client with a Transport of the wrong type: "+
				"%t not http.Transport",
			rawTransport)
	} else {
		// The HTTP Transport should have a TLS config that skips verifying
		// certificates.
		test.AssertEquals(t, httpTrans.TLSClientConfig.InsecureSkipVerify, true)
		// Keep alives should be disabled
		test.AssertEquals(t, httpTrans.DisableKeepAlives, true)
		test.AssertEquals(t, httpTrans.MaxIdleConns, 1)
		test.AssertEquals(t, httpTrans.IdleConnTimeout.String(), "1s")
		test.AssertEquals(t, httpTrans.TLSHandshakeTimeout.String(), "10s")
	}
}

func TestHTTPValidationURL(t *testing.T) {
	egPath := "/.well-known/.less-known/.obscure"
	testCases := []struct {
		Name        string
		IP          string
		Path        string
		Port        int
		ExpectedURL string
	}{
		{
			Name:        "IPv4 Standard port",
			IP:          "10.10.10.10",
			Path:        egPath,
			Port:        80,
			ExpectedURL: fmt.Sprintf("http://10.10.10.10%s", egPath),
		},
		{
			Name:        "IPv4 Non-standard port",
			IP:          "15.15.15.15",
			Path:        egPath,
			Port:        8080,
			ExpectedURL: fmt.Sprintf("http://15.15.15.15:8080%s", egPath),
		},
		{
			Name:        "IPv6 Standard port",
			IP:          "::1",
			Path:        egPath,
			Port:        80,
			ExpectedURL: fmt.Sprintf("http://[::1]%s", egPath),
		},
		{
			Name:        "IPv6 Non-standard port",
			IP:          "::1",
			Path:        egPath,
			Port:        8080,
			ExpectedURL: fmt.Sprintf("http://[::1]:8080%s", egPath),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ipAddr := net.ParseIP(tc.IP)
			if ipAddr == nil {
				t.Fatalf("Failed to parse test case %q IP %q", tc.Name, tc.IP)
			}
			url := httpValidationURL(ipAddr, tc.Path, tc.Port)
			test.AssertEquals(t, url.String(), tc.ExpectedURL)
		})
	}
}

func TestHTTPValidationTarget(t *testing.T) {
	// NOTE(@cpu): See `bdns/mocks.go` and the mock `LookupHost` function for the
	// hostnames used in this test.
	testCases := []struct {
		Name          string
		Host          string
		ExpectedError error
		ExpectedIPs   []string
	}{
		{
			Name:          "No IPs for host",
			Host:          "always.invalid",
			ExpectedError: berrors.ConnectionFailureError("unknownHost :: No valid IP addresses found for always.invalid"),
		},
		{
			Name:        "Only IPv4 addrs for host",
			Host:        "some.example.com",
			ExpectedIPs: []string{"127.0.0.1"},
		},
		{
			Name:        "Only IPv6 addrs for host",
			Host:        "ipv6.localhost",
			ExpectedIPs: []string{"::1"},
		},
		{
			Name: "Both IPv6 and IPv4 addrs for host",
			Host: "ipv4.and.ipv6.localhost",
			// In this case we expect 1 IPv6 address first, and then 1 IPv4 address
			ExpectedIPs: []string{"::1", "127.0.0.1"},
		},
	}

	const (
		examplePort = 1234
		examplePath = "/.well-known/path/i/took"
	)

	va, _ := setup(nil, 0)
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			target, err := va.newHTTPValidationTarget(
				context.Background(),
				tc.Host,
				examplePort,
				examplePath)
			if err != nil && tc.ExpectedError == nil {
				t.Fatalf("Unexpected error from NewHTTPValidationTarget: %v", err)
			} else if err != nil && tc.ExpectedError != nil {
				test.AssertMarshaledEquals(t, err, tc.ExpectedError)
			} else if err == nil {
				// The target should be populated.
				test.AssertNotEquals(t, target.host, "")
				test.AssertNotEquals(t, target.port, 0)
				test.AssertNotEquals(t, target.path, "")
				// Calling ip() on the target should give the expected IPs in the right
				// order.
				for i, expectedIP := range tc.ExpectedIPs {
					gotIP := target.ip()
					if gotIP == nil {
						t.Errorf("Expected IP %d to be %s got nil", i, expectedIP)
					} else {
						test.AssertEquals(t, gotIP.String(), expectedIP)
					}
					// Advance to the next IP
					_ = target.nextIP()
				}
			}
		})
	}
}

func TestExtractRequestTarget(t *testing.T) {
	mustURL := func(t *testing.T, rawURL string) *url.URL {
		urlOb, err := url.Parse(rawURL)
		if err != nil {
			t.Fatalf("Unable to parse raw URL %q: %v", rawURL, err)
			return nil
		}
		return urlOb
	}

	testCases := []struct {
		Name          string
		Req           *http.Request
		ExpectedError error
		ExpectedHost  string
		ExpectedPort  int
	}{
		{
			Name:          "nil input req",
			ExpectedError: fmt.Errorf("redirect HTTP request was nil"),
		},
		{
			Name: "invalid protocal scheme",
			Req: &http.Request{
				URL: mustURL(t, "gopher://letsencrypt.org"),
			},
			ExpectedError: fmt.Errorf("Invalid protocol scheme in redirect target. " +
				`Only "http" and "https" protocol schemes are supported, ` +
				`not "gopher"`),
		},
		{
			Name: "invalid explicit port",
			Req: &http.Request{
				URL: mustURL(t, "https://weird.port.letsencrypt.org:9999"),
			},
			ExpectedError: fmt.Errorf("Invalid port in redirect target. Only ports 80 " +
				"and 443 are supported, not 9999"),
		},
		{
			Name: "bare IP",
			Req: &http.Request{
				URL: mustURL(t, "https://10.10.10.10"),
			},
			ExpectedError: fmt.Errorf(`Invalid host in redirect target "10.10.10.10". ` +
				"Only domain names are supported, not IP addresses"),
		},
		{
			Name: "valid HTTP redirect, explicit port",
			Req: &http.Request{
				URL: mustURL(t, "http://cpu.letsencrypt.org:80"),
			},
			ExpectedHost: "cpu.letsencrypt.org",
			ExpectedPort: 80,
		},
		{
			Name: "valid HTTP redirect, implicit port",
			Req: &http.Request{
				URL: mustURL(t, "http://cpu.letsencrypt.org"),
			},
			ExpectedHost: "cpu.letsencrypt.org",
			ExpectedPort: 80,
		},
		{
			Name: "valid HTTPS redirect, explicit port",
			Req: &http.Request{
				URL: mustURL(t, "https://cpu.letsencrypt.org:443/hello.world"),
			},
			ExpectedHost: "cpu.letsencrypt.org",
			ExpectedPort: 443,
		},
		{
			Name: "valid HTTPS redirect, implicit port",
			Req: &http.Request{
				URL: mustURL(t, "https://cpu.letsencrypt.org/hello.world"),
			},
			ExpectedHost: "cpu.letsencrypt.org",
			ExpectedPort: 443,
		},
	}

	va, _ := setup(nil, 0)
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			host, port, err := va.extractRequestTarget(tc.Req)
			if err != nil && tc.ExpectedError == nil {
				t.Errorf("Expected nil err got %v", err)
			} else if err != nil && tc.ExpectedError != nil {
				test.AssertEquals(t, err.Error(), tc.ExpectedError.Error())
			} else if err == nil && tc.ExpectedError != nil {
				t.Errorf("Expected err %v, got nil", tc.ExpectedError)
			} else {
				test.AssertEquals(t, host, tc.ExpectedHost)
				test.AssertEquals(t, port, tc.ExpectedPort)
			}
		})
	}
}

func TestSetupHTTPValidation(t *testing.T) {
	va, _ := setup(nil, 0)

	mustTarget := func(t *testing.T, host string, port int, path string) *httpValidationTarget {
		target, err := va.newHTTPValidationTarget(
			context.Background(),
			host,
			port,
			path)
		if err != nil {
			t.Fatalf("Failed to construct httpValidationTarget for %q", host)
			return nil
		}
		return target
	}

	inputURL, err := url.Parse("http://ipv4.and.ipv6.localhost/yellow/brick/road")
	if err != nil {
		t.Fatalf("Failed to construct test inputURL")
	}

	testCases := []struct {
		Name                string
		InputReq            *http.Request
		InputTarget         *httpValidationTarget
		ExpectedRequestHost string
		ExpectedRequestURL  string
		ExpectedRecord      core.ValidationRecord
		ExpectedError       error
	}{
		{
			Name:          "nil target",
			ExpectedError: fmt.Errorf("httpValidationTarget can not be nil"),
		},
		{
			Name: "target with no IPs",
			InputTarget: &httpValidationTarget{
				host: "foobar",
				port: va.httpPort,
				path: "idk",
			},
			// With a broken target no URL is added to the validation record because
			// there was no IP to construct it with.
			ExpectedRecord: core.ValidationRecord{
				Hostname: "foobar",
				Port:     strconv.Itoa(va.httpPort),
			},
			ExpectedError: fmt.Errorf(`host "foobar" has no IP addresses remaining to use`),
		},
		{
			Name:                "nil input req",
			InputTarget:         mustTarget(t, "example.com", 9999, "/.well-known/stuff"),
			ExpectedRequestHost: "example.com",
			ExpectedRequestURL:  "http://127.0.0.1:9999/.well-known/stuff",
			ExpectedRecord: core.ValidationRecord{
				Hostname:          "example.com",
				Port:              "9999",
				URL:               "http://127.0.0.1:9999/.well-known/stuff",
				AddressesResolved: []net.IP{net.ParseIP("127.0.0.1")},
				AddressUsed:       net.ParseIP("127.0.0.1"),
			},
		},
		{
			Name:        "non-nil input req",
			InputTarget: mustTarget(t, "ipv4.and.ipv6.localhost", 808, "/yellow/brick/road"),
			InputReq: &http.Request{
				URL: inputURL,
			},
			ExpectedRequestHost: "ipv4.and.ipv6.localhost",
			ExpectedRequestURL:  "http://[::1]:808/yellow/brick/road",
			ExpectedRecord: core.ValidationRecord{
				Hostname:          "ipv4.and.ipv6.localhost",
				Port:              "808",
				URL:               "http://[::1]:808/yellow/brick/road",
				AddressesResolved: []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")},
				AddressUsed:       net.ParseIP("::1"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			outReq, outRecord, err := va.setupHTTPValidation(
				context.Background(),
				tc.InputReq,
				tc.InputTarget)

			if err != nil && tc.ExpectedError == nil {
				t.Errorf("Expected nil error, got %v", err)
			} else if err == nil && tc.ExpectedError != nil {
				t.Errorf("Expected %v error, got nil", tc.ExpectedError)
			} else if err != nil && tc.ExpectedError != nil {
				test.AssertEquals(t, err.Error(), tc.ExpectedError.Error())
			} else {
				test.AssertEquals(t, outReq.Host, tc.ExpectedRequestHost)
				test.AssertEquals(t, outReq.URL.String(), tc.ExpectedRequestURL)
			}
			// In all cases we expect there to have been a validation record
			test.AssertMarshaledEquals(t, outRecord, tc.ExpectedRecord)
			// If the input request was nil then check that the constructed outReq has
			// the right UA and Accept header values.
			if tc.InputReq == nil && err == nil {
				test.AssertEquals(t, outReq.Header.Get("User-Agent"), va.userAgent)
				test.AssertEquals(t, outReq.Header.Get("Accept"), "*/*")
			} else if tc.InputReq != nil && err == nil {
				// Otherwise if there was an input req make sure its URL and Host were
				// mutated as expected.
				test.AssertEquals(t, tc.InputReq.Host, tc.ExpectedRequestHost)
				test.AssertEquals(t, tc.InputReq.URL.String(), tc.ExpectedRequestURL)
			}
		})
	}
}

// A more concise version of httpSrv() that supports http.go tests
func httpTestSrv(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)

	server.Start()
	httpPort := getPort(server)

	// A path that always returns an OK response
	mux.HandleFunc("/ok", func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(http.StatusOK)
		fmt.Fprint(resp, "ok")
	})

	// A path that always times out by sleeping longer than the validation context
	// allows
	mux.HandleFunc("/timeout", func(resp http.ResponseWriter, req *http.Request) {
		time.Sleep(time.Second)
		resp.WriteHeader(http.StatusOK)
		fmt.Fprint(resp, "sorry, I'm a slow server")
	})

	// A path that always redirects to itself, creating a loop that will terminate
	// after maxRedirect.
	mux.HandleFunc("/loop", func(resp http.ResponseWriter, req *http.Request) {
		http.Redirect(
			resp,
			req,
			fmt.Sprintf("http://example.com:%d/loop", httpPort),
			301)
	})

	// A path that always redirects to a URL with a non-HTTP/HTTPs protocol scheme
	mux.HandleFunc("/redir-bad-proto", func(resp http.ResponseWriter, req *http.Request) {
		http.Redirect(
			resp,
			req,
			"gopher://example.com",
			301,
		)
	})

	// A path that always redirects to a URL with a port other than the configured
	// HTTP/HTTPS port
	mux.HandleFunc("/redir-bad-port", func(resp http.ResponseWriter, req *http.Request) {
		http.Redirect(
			resp,
			req,
			"https://example.com:1987",
			301,
		)
	})

	// A path that always redirects to a URL with a bare IP address
	mux.HandleFunc("/redir-bad-host", func(resp http.ResponseWriter, req *http.Request) {
		http.Redirect(
			resp,
			req,
			"https://127.0.0.1",
			301,
		)
	})

	mux.HandleFunc("/bad-status-code", func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(http.StatusGone)
		fmt.Fprint(resp, "sorry, I'm gone")
	})

	tooLargeBuf := bytes.NewBuffer([]byte{})
	for i := 0; i < maxResponseSize+10; i++ {
		tooLargeBuf.WriteByte(byte(97))
	}
	mux.HandleFunc("/resp-too-big", func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(http.StatusOK)
		fmt.Fprint(resp, tooLargeBuf)
	})

	return server
}

type testNetErr struct{}

func (e *testNetErr) Error() string {
	return "testNetErr"
}

func (e *testNetErr) Temporary() bool {
	return false
}

func (e *testNetErr) Timeout() bool {
	return false
}

func TestFallbackErr(t *testing.T) {
	untypedErr := errors.New("the least interesting kind of error")
	berr := berrors.InternalServerError("code violet: class neptune")
	netOpErr := &net.OpError{
		Err: fmt.Errorf("port was clogged. please empty packets"),
	}
	netErr := &testNetErr{}

	testCases := []struct {
		Name           string
		Err            error
		ExpectFallback bool
	}{
		{
			Name: "Nil error",
			Err:  nil,
		},
		{
			Name: "Standard untyped error",
			Err:  untypedErr,
		},
		{
			Name: "A Boulder error instance",
			Err:  berr,
		},
		{
			Name:           "A net.OpError instance",
			Err:            netOpErr,
			ExpectFallback: true,
		},
		{
			Name:           "A net.Error instance",
			Err:            netErr,
			ExpectFallback: true,
		},
		{
			Name: "A URL error wrapping a standard error",
			Err: &url.Error{
				Op:  "ivy",
				URL: "https://en.wikipedia.org/wiki/Operation_Ivy_(band)",
				Err: errors.New("take warning"),
			},
		},
		{
			Name: "A URL error wrapping a nil error",
			Err: &url.Error{
				Err: nil,
			},
		},
		{
			Name: "A URL error wrapping a Boulder error instance",
			Err: &url.Error{
				Err: berr,
			},
		},
		{
			Name: "A URL error wrapping a net OpError",
			Err: &url.Error{
				Err: netOpErr,
			},
			ExpectFallback: true,
		},
		{
			Name: "A URL error wrapping a net Error",
			Err: &url.Error{
				Err: netErr,
			},
			ExpectFallback: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			if isFallback := fallbackErr(tc.Err); isFallback != tc.ExpectFallback {
				t.Errorf(
					"Expected fallbackErr for %t to be %v was %v\n",
					tc.Err, tc.ExpectFallback, isFallback)
			}
		})
	}
}

func TestFetchHTTPSimple(t *testing.T) {
	// Create a test server
	testSrv := httpTestSrv(t)
	defer testSrv.Close()

	// Setup a VA. By providing the testSrv to setup the VA will use the testSrv's
	// randomly assigned port as its HTTP port.
	va, _ := setup(testSrv, 0)

	// We need to know the randomly assigned HTTP port for testcases as well
	httpPort := getPort(testSrv)

	// For the looped test case we expect one validation record per redirect up to
	// maxRedirect (inclusive). There is also +1 record for the base lookup,
	// giving a termination criteria of > maxRedirect+1
	expectedLoopRecords := []core.ValidationRecord{}
	for i := 0; i <= maxRedirect+1; i++ {
		expectedLoopRecords = append(expectedLoopRecords,
			core.ValidationRecord{
				Hostname:          "example.com",
				Port:              strconv.Itoa(httpPort),
				URL:               fmt.Sprintf("http://127.0.0.1:%d/loop", httpPort),
				AddressesResolved: []net.IP{net.ParseIP("127.0.0.1")},
				AddressUsed:       net.ParseIP("127.0.0.1"),
			})
	}

	expectedTruncatedResp := bytes.NewBuffer([]byte{})
	for i := 0; i < maxResponseSize; i++ {
		expectedTruncatedResp.WriteByte(byte(97))
	}

	testCases := []struct {
		Name            string
		Host            string
		Path            string
		ExpectedBody    string
		ExpectedRecords []core.ValidationRecord
		ExpectedProblem *probs.ProblemDetails
	}{
		{
			Name: "No IPs for host",
			Host: "always.invalid",
			Path: "/.well-known/whatever",
			ExpectedProblem: probs.ConnectionFailure(
				"unknownHost :: No valid IP addresses found for always.invalid"),
			// There are no validation records in this case because the base record
			// is only constructed once a URL is made.
			ExpectedRecords: nil,
		},
		{
			Name: "Timeout for host",
			Host: "example.com",
			Path: "/timeout",
			ExpectedProblem: probs.ConnectionFailure(
				"Fetching http://127.0.0.1:%d/timeout: "+
					"Timeout after connect (your server may be slow or overloaded)", httpPort),
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "example.com",
					Port:              strconv.Itoa(httpPort),
					URL:               fmt.Sprintf("http://127.0.0.1:%d/timeout", httpPort),
					AddressesResolved: []net.IP{net.ParseIP("127.0.0.1")},
					AddressUsed:       net.ParseIP("127.0.0.1"),
				},
			},
		},
		{
			Name: "Redirect loop",
			Host: "example.com",
			Path: "/loop",
			ExpectedProblem: probs.ConnectionFailure(
				"Fetching http://example.com:%d/loop: Too many redirects", httpPort),
			ExpectedRecords: expectedLoopRecords,
		},
		{
			Name: "Redirect to bad protocol",
			Host: "example.com",
			Path: "/redir-bad-proto",
			ExpectedProblem: probs.ConnectionFailure(
				"Fetching gopher://example.com: Invalid protocol scheme in " +
					`redirect target. Only "http" and "https" protocol schemes ` +
					`are supported, not "gopher"`),
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "example.com",
					Port:              strconv.Itoa(httpPort),
					URL:               fmt.Sprintf("http://127.0.0.1:%d/redir-bad-proto", httpPort),
					AddressesResolved: []net.IP{net.ParseIP("127.0.0.1")},
					AddressUsed:       net.ParseIP("127.0.0.1"),
				},
			},
		},
		{
			Name: "Redirect to bad port",
			Host: "example.com",
			Path: "/redir-bad-port",
			ExpectedProblem: probs.ConnectionFailure(
				"Fetching https://example.com:1987: Invalid port in redirect target. "+
					"Only ports %d and 443 are supported, not 1987", httpPort),
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "example.com",
					Port:              strconv.Itoa(httpPort),
					URL:               fmt.Sprintf("http://127.0.0.1:%d/redir-bad-port", httpPort),
					AddressesResolved: []net.IP{net.ParseIP("127.0.0.1")},
					AddressUsed:       net.ParseIP("127.0.0.1"),
				},
			},
		},
		{
			Name: "Redirect to bad host (bare IP address)",
			Host: "example.com",
			Path: "/redir-bad-host",
			ExpectedProblem: probs.ConnectionFailure(
				"Fetching https://127.0.0.1: Invalid host in redirect target " +
					`"127.0.0.1". Only domain names are supported, not IP addresses`),
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "example.com",
					Port:              strconv.Itoa(httpPort),
					URL:               fmt.Sprintf("http://127.0.0.1:%d/redir-bad-host", httpPort),
					AddressesResolved: []net.IP{net.ParseIP("127.0.0.1")},
					AddressUsed:       net.ParseIP("127.0.0.1"),
				},
			},
		},
		{
			Name: "Wrong HTTP status code",
			Host: "example.com",
			Path: "/bad-status-code",
			ExpectedProblem: probs.Unauthorized(
				"Invalid response from http://127.0.0.1:%d/bad-status-code "+
					"[127.0.0.1]: 410",
				httpPort,
			),
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "example.com",
					Port:              strconv.Itoa(httpPort),
					URL:               fmt.Sprintf("http://127.0.0.1:%d/bad-status-code", httpPort),
					AddressesResolved: []net.IP{net.ParseIP("127.0.0.1")},
					AddressUsed:       net.ParseIP("127.0.0.1"),
				},
			},
		},
		{
			Name: "Response too large",
			Host: "example.com",
			Path: "/resp-too-big",
			ExpectedProblem: probs.Unauthorized(
				"Invalid response from http://127.0.0.1:%d/resp-too-big "+
					"[127.0.0.1]: %q", httpPort, expectedTruncatedResp.String(),
			),
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "example.com",
					Port:              strconv.Itoa(httpPort),
					URL:               fmt.Sprintf("http://127.0.0.1:%d/resp-too-big", httpPort),
					AddressesResolved: []net.IP{net.ParseIP("127.0.0.1")},
					AddressUsed:       net.ParseIP("127.0.0.1"),
				},
			},
		},
		{
			Name: "Broken IPv6 only",
			Host: "ipv6.localhost",
			Path: "/ok",
			ExpectedProblem: probs.ConnectionFailure(
				"Fetching http://[::1]:%d/ok: Error getting validation data", httpPort,
			),
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "ipv6.localhost",
					Port:              strconv.Itoa(httpPort),
					URL:               fmt.Sprintf("http://[::1]:%d/ok", httpPort),
					AddressesResolved: []net.IP{net.ParseIP("::1")},
					AddressUsed:       net.ParseIP("::1"),
				},
			},
		},
		{
			Name:         "Dual homed w/ broken IPv6, working IPv4",
			Host:         "ipv4.and.ipv6.localhost",
			Path:         "/ok",
			ExpectedBody: "ok",
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "ipv4.and.ipv6.localhost",
					Port:              strconv.Itoa(httpPort),
					URL:               fmt.Sprintf("http://[::1]:%d/ok", httpPort),
					AddressesResolved: []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")},
					// The first validation record should have used the IPv6 addr
					AddressUsed: net.ParseIP("::1"),
				},
				core.ValidationRecord{
					Hostname:          "ipv4.and.ipv6.localhost",
					Port:              strconv.Itoa(httpPort),
					URL:               fmt.Sprintf("http://127.0.0.1:%d/ok", httpPort),
					AddressesResolved: []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")},
					// The second validation record should have used the IPv4 addr as a fallback
					AddressUsed: net.ParseIP("127.0.0.1"),
				},
			},
		},
		{
			Name:         "Working IPv4 only",
			Host:         "example.com",
			Path:         "/ok",
			ExpectedBody: "ok",
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "example.com",
					Port:              strconv.Itoa(httpPort),
					URL:               fmt.Sprintf("http://127.0.0.1:%d/ok", httpPort),
					AddressesResolved: []net.IP{net.ParseIP("127.0.0.1")},
					AddressUsed:       net.ParseIP("127.0.0.1"),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
			defer cancel()
			body, records, prob := va.fetchHTTPSimple(ctx, tc.Host, tc.Path)
			if prob != nil && tc.ExpectedProblem == nil {
				t.Errorf("expected nil prob, got %#v\n", prob)
			} else if prob == nil && tc.ExpectedProblem != nil {
				t.Errorf("expected %#v prob, got nil", tc.ExpectedProblem)
			} else if prob != nil && tc.ExpectedProblem != nil {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			} else {
				test.AssertEquals(t, string(body), tc.ExpectedBody)
			}
			// in all cases we expect validation records to be present and matching expected
			test.AssertMarshaledEquals(t, records, tc.ExpectedRecords)
		})
	}
}
