package goodkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

var testingPolicy = &KeyPolicy{
	AllowRSA:           true,
	AllowECDSANISTP256: true,
	AllowECDSANISTP384: true,
}

func TestUnknownKeyType(t *testing.T) {
	notAKey := struct{}{}
	test.AssertError(t, testingPolicy.GoodKey(notAKey), "Should have rejected a key of unknown type")
}

func TestSmallModulus(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2040)
	test.AssertNotError(t, err, "Error generating key")
	test.AssertError(t, testingPolicy.GoodKey(&private.PublicKey), "Should have rejected too-short key.")
	test.AssertError(t, testingPolicy.GoodKey(private.PublicKey), "Should have rejected too-short key.")
}

func TestLargeModulus(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 4097)
	test.AssertNotError(t, err, "Error generating key")
	test.AssertError(t, testingPolicy.GoodKey(&private.PublicKey), "Should have rejected too-long key.")
	test.AssertError(t, testingPolicy.GoodKey(private.PublicKey), "Should have rejected too-long key.")
}

func TestModulusModulo8(t *testing.T) {
	bigOne := big.NewInt(1)
	key := rsa.PublicKey{
		N: bigOne.Lsh(bigOne, 2049),
		E: 5,
	}
	test.AssertError(t, testingPolicy.GoodKey(&key), "Should have rejected modulus with length not divisible by 8.")
}

func TestSmallExponent(t *testing.T) {
	bigOne := big.NewInt(1)
	key := rsa.PublicKey{
		N: bigOne.Lsh(bigOne, 2048),
		E: 5,
	}
	test.AssertError(t, testingPolicy.GoodKey(&key), "Should have rejected small exponent.")
}

func TestEvenExponent(t *testing.T) {
	bigOne := big.NewInt(1)
	key := rsa.PublicKey{
		N: bigOne.Lsh(bigOne, 2048),
		E: 1 << 17,
	}
	test.AssertError(t, testingPolicy.GoodKey(&key), "Should have rejected even exponent.")
}

func TestEvenModulus(t *testing.T) {
	bigOne := big.NewInt(1)
	key := rsa.PublicKey{
		N: bigOne.Lsh(bigOne, 2048),
		E: (1 << 17) + 1,
	}
	test.AssertError(t, testingPolicy.GoodKey(&key), "Should have rejected even modulus.")
}

func TestModulusDivisibleBy752(t *testing.T) {
	N := big.NewInt(1)
	N.Lsh(N, 2048)
	N.Add(N, big.NewInt(1))
	N.Mul(N, big.NewInt(751))
	key := rsa.PublicKey{
		N: N,
		E: (1 << 17) + 1,
	}
	test.AssertError(t, testingPolicy.GoodKey(&key), "Should have rejected modulus divisible by 751.")
}

func TestGoodKey(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Error generating key")
	test.AssertNotError(t, testingPolicy.GoodKey(&private.PublicKey), "Should have accepted good key.")
}

func TestECDSABadCurve(t *testing.T) {
	for _, curve := range invalidCurves {
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")
		test.AssertError(t, testingPolicy.GoodKey(&private.PublicKey), "Should have rejected key with unsupported curve.")
		test.AssertError(t, testingPolicy.GoodKey(private.PublicKey), "Should have rejected key with unsupported curve.")
	}
}

var invalidCurves = []elliptic.Curve{
	elliptic.P224(),
	elliptic.P521(),
}

var validCurves = []elliptic.Curve{
	elliptic.P256(),
	elliptic.P384(),
}

func TestECDSAGoodKey(t *testing.T) {
	for _, curve := range validCurves {
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")
		test.AssertNotError(t, testingPolicy.GoodKey(&private.PublicKey), "Should have accepted good key.")
		test.AssertNotError(t, testingPolicy.GoodKey(private.PublicKey), "Should have accepted good key.")
	}
}

func TestECDSANotOnCurveX(t *testing.T) {
	for _, curve := range validCurves {
		// Change a public key so that it is no longer on the curve.
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")

		private.X.Add(private.X, big.NewInt(1))
		test.AssertError(t, testingPolicy.GoodKey(&private.PublicKey), "Should not have accepted key not on the curve.")
		test.AssertError(t, testingPolicy.GoodKey(private.PublicKey), "Should not have accepted key not on the curve.")
	}
}

func TestECDSANotOnCurveY(t *testing.T) {
	for _, curve := range validCurves {
		// Again with Y.
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")

		// Change the public key so that it is no longer on the curve.
		private.Y.Add(private.Y, big.NewInt(1))
		test.AssertError(t, testingPolicy.GoodKey(&private.PublicKey), "Should not have accepted key not on the curve.")
		test.AssertError(t, testingPolicy.GoodKey(private.PublicKey), "Should not have accepted key not on the curve.")
	}
}

func TestECDSANegative(t *testing.T) {
	for _, curve := range validCurves {
		// Check that negative X is not accepted.
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")

		private.X.Neg(private.X)
		test.AssertError(t, testingPolicy.GoodKey(&private.PublicKey), "Should not have accepted key with negative X.")
		test.AssertError(t, testingPolicy.GoodKey(private.PublicKey), "Should not have accepted key with negative X.")

		// Check that negative Y is not accepted.
		private.X.Neg(private.X)
		private.Y.Neg(private.Y)
		test.AssertError(t, testingPolicy.GoodKey(&private.PublicKey), "Should not have accepted key with negative Y.")
		test.AssertError(t, testingPolicy.GoodKey(private.PublicKey), "Should not have accepted key with negative Y.")
	}
}

func TestECDSANegativeUnmodulatedX(t *testing.T) {
	for _, curve := range validCurves {
		// Check that unmodulated X is not accepted.
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")

		private.X.Mul(private.X, private.Curve.Params().P)
		test.AssertError(t, testingPolicy.GoodKey(&private.PublicKey), "Should not have accepted key with unmodulated X.")
		test.AssertError(t, testingPolicy.GoodKey(private.PublicKey), "Should not have accepted key with unmodulated X.")
	}
}

func TestECDSANegativeUnmodulatedY(t *testing.T) {
	for _, curve := range validCurves {
		// Check that unmodulated Y is not accepted.
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")

		private.X.Mul(private.Y, private.Curve.Params().P)
		test.AssertError(t, testingPolicy.GoodKey(&private.PublicKey), "Should not have accepted key with unmodulated Y.")
		test.AssertError(t, testingPolicy.GoodKey(private.PublicKey), "Should not have accepted key with unmodulated Y.")
	}
}

func TestECDSAIdentity(t *testing.T) {
	for _, curve := range validCurves {
		// The point at infinity is 0,0, it should not be accepted.
		public := ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0),
			Y:     big.NewInt(0),
		}

		test.AssertError(t, testingPolicy.GoodKey(&public), "Should not have accepted key with point at infinity.")
		test.AssertError(t, testingPolicy.GoodKey(public), "Should not have accepted key with point at infinity.")
	}
}
