package ccadb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/crl/idp"
	"github.com/letsencrypt/boulder/test"
)

type testCA struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	record ccadbRecord
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// makeCA issues a CA certificate for name, signed by parent (or self-signed if
// parent is nil), and returns it along with a matching CCADB record.
func makeCA(t *testing.T, name string, parent *testCA, crldp string, notAfter time.Time) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "generating key")

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if crldp != "" {
		template.CRLDistributionPoints = []string{crldp}
	}

	issuerCert, issuerKey := template, key
	if parent != nil {
		issuerCert, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &key.PublicKey, issuerKey)
	test.AssertNotError(t, err, "creating certificate")
	cert, err := x509.ParseCertificate(der)
	test.AssertNotError(t, err, "parsing certificate")

	ca := &testCA{cert: cert, key: key, record: ccadbRecord{
		name:             name,
		skid:             string(cert.SubjectKeyId),
		fingerprint:      fingerprint(cert),
		revocationStatus: "Not Revoked",
	}}
	if parent != nil {
		ca.record.parentFingerprint = parent.record.fingerprint
	} else {
		ca.record.revocationStatus = ""
	}
	return ca
}

// makeCRL issues a CRL shaped like our root CRLs: an issuingDistributionPoint
// with onlyContainsCACerts and no distributionPoint.
func makeCRL(t *testing.T, ca *testCA, thisUpdate time.Time) []byte {
	t.Helper()
	idpExt, err := idp.MakeCACertsExt()
	test.AssertNotError(t, err, "creating IDP extension")
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:          big.NewInt(1),
		ThisUpdate:      thisUpdate,
		NextUpdate:      thisUpdate.AddDate(0, 12, 0).Add(-time.Second),
		ExtraExtensions: []pkix.Extension{*idpExt},
	}, ca.cert, ca.key)
	test.AssertNotError(t, err, "creating CRL")
	return der
}

func TestCheckCACRLs(t *testing.T) {
	t.Parallel()

	crls := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := crls[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	rootURL := srv.URL + "/root/"
	future := time.Now().AddDate(1, 0, 0)

	root := makeCA(t, "Root", nil, "", future.AddDate(5, 0, 0))
	root.record.fullCRLs = []string{rootURL}
	child := makeCA(t, "Child", root, rootURL, future)
	child.record.partitionedCRLs = []string{srv.URL + "/child/1.crl"}
	// Expired certificates don't count towards what must be disclosed.
	expired := makeCA(t, "Expired", root, srv.URL+"/old-root/", time.Now().Add(-time.Hour))
	expired.record.partitionedCRLs = []string{""}

	crls["/root/"] = makeCRL(t, root, time.Now().Add(-time.Hour))

	prober := CCADBProber{
		caCRLAgeLimit: 365 * 24 * time.Hour,
		caCRLRegexp:   regexp.MustCompile(`^` + regexp.QuoteMeta(srv.URL) + `/[a-z-]+/$`),
	}

	run := func(rootRecord ccadbRecord) error {
		cas := []*testCA{root, child, expired}
		records := []ccadbRecord{rootRecord, child.record, expired.record}
		bySKID := map[string]*x509.Certificate{}
		byFingerprint := map[string]*x509.Certificate{}
		for _, ca := range cas {
			bySKID[string(ca.cert.SubjectKeyId)] = ca.cert
			byFingerprint[ca.record.fingerprint] = ca.cert
		}
		return errors.Join(prober.checkCACRLs(context.Background(), records, bySKID, byFingerprint)...)
	}

	t.Run("matching disclosure", func(t *testing.T) {
		test.AssertNotError(t, run(root.record), "expected no errors")
	})

	t.Run("typo in disclosure", func(t *testing.T) {
		r := root.record
		r.fullCRLs = []string{strings.TrimSuffix(rootURL, "/")}
		err := run(r)
		test.AssertError(t, err, "expected errors")
		test.AssertContains(t, err.Error(), "are not disclosed in CCADB")
		test.AssertContains(t, err.Error(), "do not appear in any unexpired certificate")
		test.AssertContains(t, err.Error(), "does not match regexp")
	})

	t.Run("missing disclosure", func(t *testing.T) {
		r := root.record
		r.fullCRLs = nil
		err := run(r)
		test.AssertError(t, err, "expected errors")
		test.AssertContains(t, err.Error(), "are not disclosed in CCADB")
	})

	t.Run("revoked record is not checked", func(t *testing.T) {
		r := root.record
		r.fullCRLs = nil
		r.revocationStatus = "Revoked"
		test.AssertNotError(t, run(r), "expected no errors")
	})

	t.Run("stale CRL", func(t *testing.T) {
		crls["/stale/"] = makeCRL(t, root, time.Now().AddDate(0, -13, 0))
		r := root.record
		r.fullCRLs = []string{rootURL, srv.URL + "/stale/"}
		err := run(r)
		test.AssertError(t, err, "expected errors")
		test.AssertContains(t, err.Error(), "nextUpdate is in the past")
	})
}
