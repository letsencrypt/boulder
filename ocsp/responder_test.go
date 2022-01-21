/*
This code was originally forked from https://github.com/cloudflare/cfssl/blob/1a911ca1b1d6e899bf97dcfa4a14b38db0d31134/ocsp/responder_test.go

Copyright (c) 2014 CloudFlare Inc.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package ocsp

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	goocsp "golang.org/x/crypto/ocsp"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

const (
	responseFile       = "testdata/resp64.pem"
	binResponseFile    = "testdata/response.der"
	brokenResponseFile = "testdata/response_broken.pem"
	mixResponseFile    = "testdata/response_mix.pem"
)

type testSource struct{}

func (ts testSource) Response(_ context.Context, r *goocsp.Request) ([]byte, http.Header, error) {
	resp, err := hex.DecodeString("3082031D0A0100A08203163082031206092B060105050730010104820303308202FF3081E8A1453043310B300906035504061302555331123010060355040A1309676F6F6420677579733120301E06035504031317434120696E7465726D6564696174652028525341292041180F32303230303631393030333730305A30818D30818A304C300906052B0E03021A0500041417779CF67D84CD4449A2FC7EAC431F9823D8575A04149F2970E80CF9C75ECC1F2871D8C390CD19F40108021300FF8B2AEC5293C6B31D0BC0BA329CF594E7BAA116180F32303230303631393030333733305AA0030A0101180F32303230303631393030303030305AA011180F32303230303632333030303030305A300D06092A864886F70D01010B0500038202010011688303203098FC522D2C599A234B136930E3C4680F2F3192188B98D6EE90E8479449968C51335FADD1636584ACEA9D01A30790BD90190FA35A47E793718128B19E9ED156382C1B68245A6887F547B0B86C44C2354B8DBA94D8BFCAA768EB55FA84AEB4026DBEFC687DB280D21C0B3497A11909804A20F402BDD95E4843C02E30435C2570FFC4EB152FE2785B8D268AC996619644AEC9CF50959D46DEB21DFE96B4D2881D61ABBCA9B6BFEC2DB9132801CAE737C862F0AEAB4948B63F35740CE93FCDBC148F5070790D7BBA1A87E15078CD8335F83686142CE8AC3AD21FAE45B87A7B12562D9F245352A83E3901E97E5EC77E9817990712D8BE60860ABA58804DDE4ECDCA6AEFD3D8764FDBABF0AB1902FA9A7C4C3F5814C25C5E78E0754469E087CAED81E50A5873CADFCAC42963AB38CFD11096BE4201DE4589B57EC48B3DA05A65800D654160E022F6748CD93B431A17270C1B27E313734FCF85F22547D060F23F594BD68C6330C2705190A04905FBD2389E2DD21C0188809E03D713F56BF95953C9897DA6D4D074D70F164270C41BFB386B69E86EB3B9192FEA8F43CE5368CC9AF8687DEE567672A8580BA6A9F76E6E6705DD2F76F48C2C180C763CF4C48AF78C25D40EA7278CB2FBC78958B3179301825B420A7CAE7ACE4C41B5BA7D567AABC9C2701EE75A28F9181E044EDAAA55A31538AA9C526D4C324B9AE58D2922")
	if err != nil {
		return nil, nil, err
	}
	return resp, nil, nil
}

type testCase struct {
	method, path string
	expected     int
}

func TestOCSP(t *testing.T) {
	cases := []testCase{
		{"OPTIONS", "/", http.StatusMethodNotAllowed},
		{"GET", "/", http.StatusBadRequest},
		// Bad URL encoding
		{"GET", "%ZZFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusBadRequest},
		// Bad URL encoding
		{"GET", "%%FQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusBadRequest},
		// Bad base64 encoding
		{"GET", "==MFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusBadRequest},
		// Bad OCSP DER encoding
		{"GET", "AAAMFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusBadRequest},
		// Good encoding all around, including a double slash
		{"GET", "MFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusOK},
		// Good request, leading slash
		{"GET", "/MFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusOK},
	}

	responder := Responder{
		Source: testSource{},
		responseTypes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ocspResponses-test",
			},
			[]string{"type"},
		),
		responseAges: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "ocspAges-test",
				Buckets: []float64{43200},
			},
		),
		clk: clock.NewFake(),
		log: blog.NewMock(),
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s %s", tc.method, tc.path), func(t *testing.T) {
			rw := httptest.NewRecorder()
			responder.responseTypes.Reset()

			responder.ServeHTTP(rw, &http.Request{
				Method: tc.method,
				URL: &url.URL{
					Path: tc.path,
				},
			})
			if rw.Code != tc.expected {
				t.Errorf("Incorrect response code: got %d, wanted %d", rw.Code, tc.expected)
			}
			if rw.Code == http.StatusOK {
				test.AssertMetricWithLabelsEquals(
					t, responder.responseTypes, prometheus.Labels{"type": "Success"}, 1)
			} else if rw.Code == http.StatusBadRequest {
				test.AssertMetricWithLabelsEquals(
					t, responder.responseTypes, prometheus.Labels{"type": "Malformed"}, 1)
			}
		})
	}
	// Exactly two of the cases above result in an OCSP response being sent.
	test.AssertMetricWithLabelsEquals(t, responder.responseAges, prometheus.Labels{}, 2)
}

func TestRequestTooBig(t *testing.T) {
	responder := Responder{
		Source: testSource{},
		responseTypes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ocspResponses-test",
			},
			[]string{"type"},
		),
		responseAges: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "ocspAges-test",
				Buckets: []float64{43200},
			},
		),
		clk: clock.NewFake(),
		log: blog.NewMock(),
	}

	rw := httptest.NewRecorder()

	responder.ServeHTTP(rw, httptest.NewRequest("POST", "/",
		bytes.NewBuffer([]byte(strings.Repeat("a", 10001)))))
	expected := 400
	if rw.Code != expected {
		t.Errorf("Incorrect response code: got %d, wanted %d", rw.Code, expected)
	}
}

var testResp = `308204f90a0100a08204f2308204ee06092b0601050507300101048204df308204db3081a7a003020100a121301f311d301b06035504030c146861707079206861636b65722066616b65204341180f32303135303932333231303630305a306c306a3042300906052b0e03021a0500041439e45eb0e3a861c7fa3a3973876be61f7b7d98860414fb784f12f96015832c9f177f3419b32e36ea41890209009cf1912ea8d509088000180f32303135303932333030303030305aa011180f32303330303832363030303030305a300d06092a864886f70d01010b05000382010100c17ed5f12c408d214092c86cb2d6ba9881637a9d5cafb8ddc05aed85806a554c37abdd83c2e00a4bb25b2d0dda1e1c0be65144377471bca53f14616f379ee0c0b436c697b400b7eba9513c5be6d92fbc817586d568156293cfa0099d64585146def907dee36eb650c424a00207b01813aa7ae90e65045339482eeef12b6fa8656315da8f8bb1375caa29ac3858f891adb85066c35b5176e154726ae746016e42e0d6016668ff10a8aa9637417d29be387a1bdba9268b13558034ab5f3e498a47fb096f2e1b39236b22956545884fbbed1884f1bc9686b834d8def4802bac8f79924a36867af87412f808977abaf6457f3cda9e7eccbd0731bcd04865b899ee41a08203193082031530820311308201f9a0030201020209009cf1912ea8d50908300d06092a864886f70d01010b0500301f311d301b06035504030c146861707079206861636b65722066616b65204341301e170d3135303430373233353033385a170d3235303430343233353033385a301f311d301b06035504030c146861707079206861636b65722066616b6520434130820122300d06092a864886f70d01010105000382010f003082010a0282010100c20a47799a05c512b27717633413d770f936bf99de62f130c8774d476deac0029aa6c9d1bb519605df32d34b336394d48e9adc9bbeb48652767dafdb5241c2fc54ce9650e33cb672298888c403642407270cc2f46667f07696d3dd62cfd1f41a8dc0ed60d7c18366b1d2cd462d34a35e148e8695a9a3ec62b656bd129a211a9a534847992d005b0412bcdffdde23085eeca2c32c2693029b5a79f1090fe0b1cb4a154b5c36bc04c7d5a08fa2a58700d3c88d5059205bc5560dc9480f1732b1ad29b030ed3235f7fb868f904fdc79f98ffb5c4e7d4b831ce195f171729ec3f81294df54e66bd3f83d81843b640aea5d7ec64d0905a9dbb03e6ff0e6ac523d36ab0203010001a350304e301d0603551d0e04160414fb784f12f96015832c9f177f3419b32e36ea4189301f0603551d23041830168014fb784f12f96015832c9f177f3419b32e36ea4189300c0603551d13040530030101ff300d06092a864886f70d01010b050003820101001df436be66ff938ccbfb353026962aa758763a777531119377845109e7c2105476c165565d5bbce1464b41bd1d392b079a7341c978af754ca9b3bd7976d485cbbe1d2070d2d4feec1e0f79e8fec9df741e0ea05a26a658d3866825cc1aa2a96a0a04942b2c203cc39501f917a899161dfc461717fe9301fce6ea1afffd7b7998f8941cf76f62def994c028bd1c4b49b17c4d243a6fb058c484968cf80501234da89347108b56b2640cb408e3c336fd72cd355c7f690a15405a7f4ba1e30a6be4a51d262b586f77f8472b207fdd194efab8d3a2683cc148abda7a11b9de1db9307b8ed5a9cd20226f668bd6ac5a3852fd449e42899b7bc915ee747891a110a971`

type testHeaderSource struct {
	headers http.Header
}

func (ts testHeaderSource) Response(_ context.Context, r *goocsp.Request) ([]byte, http.Header, error) {
	resp, _ := hex.DecodeString(testResp)
	return resp, ts.headers, nil
}

func TestOverrideHeaders(t *testing.T) {
	headers := http.Header(map[string][]string{
		"Content-Type":  {"yup"},
		"Cache-Control": {"nope"},
		"New":           {"header"},
		"Expires":       {"0"},
		"Last-Modified": {"now"},
		"Etag":          {"mhm"},
	})
	responder := Responder{
		Source: testHeaderSource{headers: headers},
		responseTypes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ocspResponses-test",
			},
			[]string{"type"},
		),
		responseAges: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "ocspAges-test",
				Buckets: []float64{43200},
			},
		),
		clk: clock.NewFake(),
		log: blog.NewMock(),
	}

	rw := httptest.NewRecorder()
	responder.ServeHTTP(rw, &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "MFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D"},
	})

	if !reflect.DeepEqual(rw.Header(), headers) {
		t.Fatalf("Unexpected Headers returned: wanted %s, got %s", headers, rw.Header())
	}
}

func TestCacheHeaders(t *testing.T) {
	source, err := NewMemorySourceFromFile(responseFile, blog.NewMock())
	if err != nil {
		t.Fatalf("Error constructing source: %s", err)
	}

	fc := clock.NewFake()
	fc.Set(time.Date(2015, 11, 12, 0, 0, 0, 0, time.UTC))
	responder := Responder{
		Source: source,
		responseTypes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ocspResponses-test",
			},
			[]string{"type"},
		),
		responseAges: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "ocspAges-test",
				Buckets: []float64{43200},
			},
		),
		clk: fc,
		log: blog.NewMock(),
	}

	rw := httptest.NewRecorder()
	responder.ServeHTTP(rw, &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "MEMwQTA/MD0wOzAJBgUrDgMCGgUABBSwLsMRhyg1dJUwnXWk++D57lvgagQU6aQ/7p6l5vLV13lgPJOmLiSOl6oCAhJN",
		},
	})
	if rw.Code != http.StatusOK {
		t.Errorf("Unexpected HTTP status code %d", rw.Code)
	}
	testCases := []struct {
		header string
		value  string
	}{
		{"Last-Modified", "Tue, 20 Oct 2015 00:00:00 UTC"},
		{"Expires", "Sun, 20 Oct 2030 00:00:00 UTC"},
		{"Cache-Control", "max-age=471398400, public, no-transform, must-revalidate"},
		{"Etag", "\"8169FB0843B081A76E9F6F13FD70C8411597BEACF8B182136FFDD19FBD26140A\""},
	}
	for _, tc := range testCases {
		headers, ok := rw.Result().Header[tc.header]
		if !ok {
			t.Errorf("Header %s missing from HTTP response", tc.header)
			continue
		}
		if len(headers) != 1 {
			t.Errorf("Wrong number of headers in HTTP response. Wanted 1, got %d", len(headers))
			continue
		}
		actual := headers[0]
		if actual != tc.value {
			t.Errorf("Got header %s: %s. Expected %s", tc.header, actual, tc.value)
		}
	}

	rw = httptest.NewRecorder()
	headers := http.Header{}
	headers.Add("If-None-Match", "\"8169FB0843B081A76E9F6F13FD70C8411597BEACF8B182136FFDD19FBD26140A\"")
	responder.ServeHTTP(rw, &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "MEMwQTA/MD0wOzAJBgUrDgMCGgUABBSwLsMRhyg1dJUwnXWk++D57lvgagQU6aQ/7p6l5vLV13lgPJOmLiSOl6oCAhJN",
		},
		Header: headers,
	})
	if rw.Code != http.StatusNotModified {
		t.Fatalf("Got wrong status code: expected %d, got %d", http.StatusNotModified, rw.Code)
	}
}

func TestNewSourceFromFile(t *testing.T) {
	logger := blog.NewMock()
	_, err := NewMemorySourceFromFile("", logger)
	if err == nil {
		t.Fatal("Didn't fail on non-file input")
	}

	// expected case
	_, err = NewMemorySourceFromFile(responseFile, logger)
	if err != nil {
		t.Fatal(err)
	}

	// binary-formatted file
	_, err = NewMemorySourceFromFile(binResponseFile, logger)
	if err != nil {
		t.Fatal(err)
	}

	// the response file from before, with stuff deleted
	_, err = NewMemorySourceFromFile(brokenResponseFile, logger)
	if err != nil {
		t.Fatal(err)
	}

	// mix of a correct and malformed responses
	_, err = NewMemorySourceFromFile(mixResponseFile, logger)
	if err != nil {
		t.Fatal(err)
	}
}
