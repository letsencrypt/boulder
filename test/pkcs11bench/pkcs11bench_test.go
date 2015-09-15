package pkcs11bench

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/crypto/pkcs11key"
	"math/big"
	"testing"
	"time"
)

// BenchmarkPKCS11 signs a certificate repeatedly using a PKCS11 token and
// measures speed. To run:
// go test -bench=. -benchtime 1m ./test/pkcs11bench/
// You can adjust benchtime if you want to run for longer or shorter.
// TODO: Parallel benchmarking. Currently if you try this with a Yubikey Neo,
// you will get a bunch of CKR_USER_ALREADY_LOGGED_IN errors. This is because
// pkcs11key logs into the token before each signing operation (which is probably a
// performance bug). Also note that some PKCS11 modules (opensc) are not
// threadsafe.
func BenchmarkPKCS11(b *testing.B) {
	// NOTE: To run this test, you will need to edit the following values to match
	// your PKCS11 token.
	p, err := pkcs11key.New(
		"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", // module
		"PIV_II (PIV Card Holder pin)",               // token label
		"123456",                                     // PIN
		"SIGN key",                                   // Private key label
		1)                                            // slot id
	if err != nil {
		fmt.Println(err)
		return
	}
	defer p.Destroy()

	// A minimal, bogus certificate to be signed.
	template := x509.Certificate{
		SerialNumber:       big.NewInt(1),
		PublicKeyAlgorithm: x509.RSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now(),

		PublicKey: &rsa.PublicKey{
			N: big.NewInt(1),
			E: 1,
		},
	}

	// Reset the benchmarking timer so we don't include setup time.
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = x509.CreateCertificate(rand.Reader, &template, &template, template.PublicKey, p)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}
