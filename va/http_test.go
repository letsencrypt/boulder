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

func TestHTTPTransport(t *testing.T) {
	dummyDialerFunc := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, nil
	}
	transport := httpTransport(dummyDialerFunc)
	// The HTTP Transport should have a TLS config that skips verifying
	// certificates.
	test.AssertEquals(t, transport.TLSClientConfig.InsecureSkipVerify, true)
	// Keep alives should be disabled
	test.AssertEquals(t, transport.DisableKeepAlives, true)
	test.AssertEquals(t, transport.MaxIdleConns, 1)
	test.AssertEquals(t, transport.IdleConnTimeout.String(), "1s")
	test.AssertEquals(t, transport.TLSHandshakeTimeout.String(), "10s")
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
		examplePort  = 1234
		examplePath  = "/.well-known/path/i/took"
		exampleQuery = "my-path=was&my=own"
	)

	va, _ := setup(nil, 0)
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			target, err := va.newHTTPValidationTarget(
				context.Background(),
				tc.Host,
				examplePort,
				examplePath,
				exampleQuery)
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
			path,
			"")
		if err != nil {
			t.Fatalf("Failed to construct httpValidationTarget for %q", host)
			return nil
		}
		return target
	}

	httpInputURL := "http://ipv4.and.ipv6.localhost/yellow/brick/road"
	httpsInputURL := "https://ipv4.and.ipv6.localhost/yellow/brick/road"

	testCases := []struct {
		Name           string
		InputURL       string
		InputTarget    *httpValidationTarget
		ExpectedRecord core.ValidationRecord
		ExpectedDialer *preresolvedDialer
		ExpectedError  error
	}{
		{
			Name:          "nil target",
			InputURL:      httpInputURL,
			ExpectedError: fmt.Errorf("httpValidationTarget can not be nil"),
		},
		{
			Name:          "empty input URL",
			InputTarget:   &httpValidationTarget{},
			ExpectedError: fmt.Errorf("reqURL can not be nil"),
		},
		{
			Name:     "target with no IPs",
			InputURL: httpInputURL,
			InputTarget: &httpValidationTarget{
				host: "foobar",
				port: va.httpPort,
				path: "idk",
			},
			ExpectedRecord: core.ValidationRecord{
				URL:      "http://ipv4.and.ipv6.localhost/yellow/brick/road",
				Hostname: "foobar",
				Port:     strconv.Itoa(va.httpPort),
			},
			ExpectedError: fmt.Errorf(`host "foobar" has no IP addresses remaining to use`),
		},
		{
			Name:        "HTTP input req",
			InputTarget: mustTarget(t, "ipv4.and.ipv6.localhost", va.httpPort, "/yellow/brick/road"),
			InputURL:    httpInputURL,
			ExpectedRecord: core.ValidationRecord{
				Hostname:          "ipv4.and.ipv6.localhost",
				Port:              strconv.Itoa(va.httpPort),
				URL:               "http://ipv4.and.ipv6.localhost/yellow/brick/road",
				AddressesResolved: []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")},
				AddressUsed:       net.ParseIP("::1"),
			},
			ExpectedDialer: &preresolvedDialer{
				ip:   net.ParseIP("::1"),
				port: va.httpPort,
			},
		},
		{
			Name:        "HTTPS input req",
			InputTarget: mustTarget(t, "ipv4.and.ipv6.localhost", va.httpsPort, "/yellow/brick/road"),
			InputURL:    httpsInputURL,
			ExpectedRecord: core.ValidationRecord{
				Hostname:          "ipv4.and.ipv6.localhost",
				Port:              strconv.Itoa(va.httpsPort),
				URL:               "https://ipv4.and.ipv6.localhost/yellow/brick/road",
				AddressesResolved: []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")},
				AddressUsed:       net.ParseIP("::1"),
			},
			ExpectedDialer: &preresolvedDialer{
				ip:   net.ParseIP("::1"),
				port: va.httpsPort,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			outDialer, outRecord, err := va.setupHTTPValidation(
				context.Background(),
				tc.InputURL,
				tc.InputTarget)

			if err != nil && tc.ExpectedError == nil {
				t.Errorf("Expected nil error, got %v", err)
			} else if err == nil && tc.ExpectedError != nil {
				t.Errorf("Expected %v error, got nil", tc.ExpectedError)
			} else if err != nil && tc.ExpectedError != nil {
				test.AssertEquals(t, err.Error(), tc.ExpectedError.Error())
			}
			if tc.ExpectedDialer == nil && outDialer != nil {
				t.Errorf("Expected nil dialer, got %v", outDialer)
			} else if tc.ExpectedDialer != nil {
				test.AssertMarshaledEquals(t, outDialer, tc.ExpectedDialer)
			}
			// In all cases we expect there to have been a validation record
			test.AssertMarshaledEquals(t, outRecord, tc.ExpectedRecord)
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
		Op:  "siphon",
		Err: fmt.Errorf("port was clogged. please empty packets"),
	}
	netDialOpErr := &net.OpError{
		Op:  "dial",
		Err: fmt.Errorf("your call is important to us - please stay on the line"),
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
			Name: "A non-dial net.OpError instance",
			Err:  netOpErr,
		},
		{
			Name:           "A dial net.OpError instance",
			Err:            netDialOpErr,
			ExpectFallback: true,
		},
		{
			Name: "A generic net.Error instance",
			Err:  netErr,
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
			Name: "A URL error wrapping a non-dial net OpError",
			Err: &url.Error{
				Err: netOpErr,
			},
		},
		{
			Name: "A URL error wrapping a dial net.OpError",
			Err: &url.Error{
				Err: netDialOpErr,
			},
			ExpectFallback: true,
		},
		{
			Name: "A URL error wrapping a generic net Error",
			Err: &url.Error{
				Err: netErr,
			},
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
		// The first request will not have a port # in the URL.
		url := "http://example.com/loop"
		if i != 0 {
			url = fmt.Sprintf("http://example.com:%d/loop", httpPort)
		}
		expectedLoopRecords = append(expectedLoopRecords,
			core.ValidationRecord{
				Hostname:          "example.com",
				Port:              strconv.Itoa(httpPort),
				URL:               url,
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
				"Fetching http://example.com/timeout: " +
					"Timeout after connect (your server may be slow or overloaded)"),
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "example.com",
					Port:              strconv.Itoa(httpPort),
					URL:               "http://example.com/timeout",
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
					URL:               "http://example.com/redir-bad-proto",
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
					URL:               "http://example.com/redir-bad-port",
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
					URL:               "http://example.com/redir-bad-host",
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
				"Invalid response from http://example.com/bad-status-code " +
					"[127.0.0.1]: 410"),
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "example.com",
					Port:              strconv.Itoa(httpPort),
					URL:               "http://example.com/bad-status-code",
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
				"Invalid response from http://example.com/resp-too-big "+
					"[127.0.0.1]: %q", expectedTruncatedResp.String(),
			),
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "example.com",
					Port:              strconv.Itoa(httpPort),
					URL:               "http://example.com/resp-too-big",
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
				"Fetching http://ipv6.localhost/ok: Error getting validation data"),
			ExpectedRecords: []core.ValidationRecord{
				core.ValidationRecord{
					Hostname:          "ipv6.localhost",
					Port:              strconv.Itoa(httpPort),
					URL:               "http://ipv6.localhost/ok",
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
					URL:               "http://ipv4.and.ipv6.localhost/ok",
					AddressesResolved: []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")},
					// The first validation record should have used the IPv6 addr
					AddressUsed: net.ParseIP("::1"),
				},
				core.ValidationRecord{
					Hostname:          "ipv4.and.ipv6.localhost",
					Port:              strconv.Itoa(httpPort),
					URL:               "http://ipv4.and.ipv6.localhost/ok",
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
					URL:               "http://example.com/ok",
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
