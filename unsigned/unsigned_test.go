package unsigned

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDesign(t *testing.T) {
	input, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(`
MIIB4TCCAWegAwIBAgIIJuDkMteShO8wCgYIKoZIzj0EAwMwIDEeMBwGA1UEAxMV
bWluaWNhIHJvb3QgY2EgNGU0YjFkMB4XDTI2MDYyOTA1NDUyNloXDTI4MDcyOTA1
NDUyNlowFjEUMBIGA1UEAxMLd2ZlLmJvdWxkZXIwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATLkY1wBrGl9+jhR4+HSycRv5kvVV8LUO3xY1styu8+q9kaSi03wrdH7LUf
rJkRE6S60XzVXkeqL9N//jOXFsaM9JbsbeHFRoAx+mBEV68Vu69dblxtXIAKNlMM
5dav5XOjeDB2MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSA+ZfinkHdxJDZuRo1
zJ7mHOmaCDAWBgNVHREEDzANggt3ZmUuYm91bGRlcjAKBggqhkjOPQQDAwNoADBl
AjEApE8cwaAQ6hnGtUM/TWAb54E5/29ZVy5E/UY8mEzoE021pl3tq1fEof5qz5n/
KrL4AjAuEpVOjRrRWWMnRJxd05Pfxq7gZmxgwppjnE9JZ9P6WRP7ZWqZcc9p8YLM
YhKuXQo=`, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}

	out, err := Design(input, true)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(`
MIIBejCCAWegAwIBAgIIJuDkMteShO8wCgYIKwYBBQUHBiQwIDEeMBwGA1UEAxMV
bWluaWNhIHJvb3QgY2EgNGU0YjFkMB4XDTI2MDYyOTA1NDUyNloXDTI4MDcyOTA1
NDUyNlowFjEUMBIGA1UEAxMLd2ZlLmJvdWxkZXIwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATLkY1wBrGl9+jhR4+HSycRv5kvVV8LUO3xY1styu8+q9kaSi03wrdH7LUf
rJkRE6S60XzVXkeqL9N//jOXFsaM9JbsbeHFRoAx+mBEV68Vu69dblxtXIAKNlMM
5dav5XOjeDB2MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSA+ZfinkHdxJDZuRo1
zJ7mHOmaCDAWBgNVHREEDzANggt3ZmUuYm91bGRlcjAKBggrBgEFBQcGJAMBAA==
`, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, expected) {
		t.Errorf("got %x, want %x", out, expected)
	}

	_, err = x509.ParseCertificate(out)
	if err != nil {
		t.Fatal(err)
	}

	out, err = Design(input, false)
	if err != nil {
		t.Fatal(err)
	}
	expected, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(`
MIIBejCCAWegAwIBAgIIJuDkMteShO8wCgYIKoZIzj0EAwMwIDEeMBwGA1UEAxMV
bWluaWNhIHJvb3QgY2EgNGU0YjFkMB4XDTI2MDYyOTA1NDUyNloXDTI4MDcyOTA1
NDUyNlowFjEUMBIGA1UEAxMLd2ZlLmJvdWxkZXIwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATLkY1wBrGl9+jhR4+HSycRv5kvVV8LUO3xY1styu8+q9kaSi03wrdH7LUf
rJkRE6S60XzVXkeqL9N//jOXFsaM9JbsbeHFRoAx+mBEV68Vu69dblxtXIAKNlMM
5dav5XOjeDB2MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSA+ZfinkHdxJDZuRo1
zJ7mHOmaCDAWBgNVHREEDzANggt3ZmUuYm91bGRlcjAKBggqhkjOPQQDAwMBAA==
`, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, expected) {
		t.Errorf("got %x, want %x", out, expected)
	}

	_, err = x509.ParseCertificate(out)
	if err != nil {
		t.Fatal(err)
	}
}
