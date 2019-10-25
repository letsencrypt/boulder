// +build integration

package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var template = `[AUDIT] Failed RPC to store at SA, orphaning precertificate: serial=[%x] cert=[%x] err=[sa.StorageAuthority.AddCertificate timed out after 5000 ms], regID=[1], orderID=[1]
[AUDIT] Failed RPC to store at SA, orphaning certificate: serial=[%x] cert=[%x] err=[sa.StorageAuthority.AddCertificate timed out after 5000 ms], regID=[1], orderID=[1]`

// TestOrphanFinder runs the orphan-finder with an example input file. This must
// be run after other tests so the account ID 1 exists (since the inserted
// certificates will be associated with that account).
func TestOrphanFinder(t *testing.T) {
	precert, err := makeFakeCert(true)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := makeFakeCert(false)
	if err != nil {
		log.Fatal(err)
	}
	f, _ := ioutil.TempFile("", "orphaned.log")
	io.WriteString(f, fmt.Sprintf(template, precert.SerialNumber.Bytes(),
		precert.Raw, cert.SerialNumber.Bytes(), cert.Raw))
	f.Close()
	cmd := exec.Command("../../bin/orphan-finder", "parse-ca-log",
		"--config", "../../"+os.Getenv("BOULDER_CONFIG_DIR")+"/orphan-finder.json",
		"--log-file", f.Name())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("orphan finder failed (%s). Output was: %s", err, out)
	}
	if !strings.Contains(string(out), "Found 1 precertificate orphans and added 1 to the database") {
		t.Fatalf("Failed to insert orphaned precertificate. orphan-finder output was: %s", out)
	}
	if !strings.Contains(string(out), "Found 1 certificate orphans and added 1 to the database") {
		t.Fatalf("Failed to insert orphaned certificate. orphan-finder output was: %s", out)
	}
}

// makeFakeCert a unique fake cert for each run of TestOrphanFinder to avoid duplicate
// errors. This fake cert will have its issuer equal to the issuer we use in the
// general integration test setup, and will be signed by that issuer key.
// Otherwise, the request orphan-finder makes to sign OCSP would be rejected.
func makeFakeCert(precert bool) (*x509.Certificate, error) {
	serialBytes := make([]byte, 18)
	_, err := rand.Read(serialBytes[:])
	if err != nil {
		return nil, err
	}
	serial := big.NewInt(0)
	serial.SetBytes(serialBytes)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	issuerKeyBytes, err := ioutil.ReadFile("../test-ca.key")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(issuerKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM found")
	}
	issuerKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %s", err)
	}
	issuerTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "h2ppy h2cker fake CA",
		},
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "fake cert for TestOrphanFinder",
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 90, 0),
		DNSNames:     []string{"fakecert.example.com"},
	}
	if precert {
		template.ExtraExtensions = []pkix.Extension{
			pkix.Extension{
				Id:       OIDExtensionCTPoison,
				Critical: true,
				Value:    []byte{5, 0},
			},
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuerTemplate, key.Public(), issuerKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return cert, err
}
