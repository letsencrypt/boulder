package goodkey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"

	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
)

var testingPolicy = &KeyPolicy{
	AllowRSA:           true,
	AllowECDSANISTP256: true,
	AllowECDSANISTP384: true,
}

func TestUnknownKeyType(t *testing.T) {
	notAKey := struct{}{}
	err := testingPolicy.GoodKey(context.Background(), notAKey)
	test.AssertError(t, err, "Should have rejected a key of unknown type")
	test.AssertEquals(t, err.Error(), "unsupported key type struct {}")

	// Check for early rejection and that no error is seen from blockedKeys.blocked.
	testingPolicyWithBlockedKeys := *testingPolicy
	testingPolicyWithBlockedKeys.blockedList = &blockedKeys{}
	err = testingPolicyWithBlockedKeys.GoodKey(context.Background(), notAKey)
	test.AssertError(t, err, "Should have rejected a key of unknown type")
	test.AssertEquals(t, err.Error(), "unsupported key type struct {}")
}

func TestNilKey(t *testing.T) {
	err := testingPolicy.GoodKey(context.Background(), nil)
	test.AssertError(t, err, "Should have rejected a nil key")
	test.AssertEquals(t, err.Error(), "unsupported key type <nil>")
}

func TestSmallModulus(t *testing.T) {
	pubKey := rsa.PublicKey{
		N: big.NewInt(0),
		E: 65537,
	}
	// 2040 bits
	_, ok := pubKey.N.SetString("104192126510885102608953552259747211060428328569316484779167706297543848858189721071301121307701498317286069484848193969810800653457088975832436062805901725915630417996487259956349018066196416400386483594314258078114607080545265502078791826837453107382149801328758721235866366842649389274931060463277516954884108984101391466769505088222180613883737986792254164577832157921425082478871935498631777878563742033332460445633026471887331001305450139473524438241478798689974351175769895824322173301257621327448162705637127373457350813027123239805772024171112299987923305882261194120410409098448380641378552305583392176287", 10)
	if !ok {
		t.Errorf("error parsing pubkey modulus")
	}
	err := testingPolicy.GoodKey(context.Background(), &pubKey)
	test.AssertError(t, err, "Should have rejected too-short key")
	test.AssertEquals(t, err.Error(), "key too small: 2040")
}

func TestLargeModulus(t *testing.T) {
	pubKey := rsa.PublicKey{
		N: big.NewInt(0),
		E: 65537,
	}
	// 4097 bits
	_, ok := pubKey.N.SetString("1528586537844618544364689295678280797814937047039447018548513699782432768815684971832418418955305671838918285565080181315448131784543332408348488544125812746629522583979538961638790013578302979210481729874191053412386396889481430969071543569003141391030053024684850548909056275565684242965892176703473950844930842702506635531145654194239072799616096020023445127233557468234181352398708456163013484600764686209741158795461806441111028922165846800488957692595308009319392149669715238691709012014980470238746838534949750493558807218940354555205690667168930634644030378921382266510932028134500172599110460167962515262077587741235811653717121760943005253103187409557573174347385738572144714188928416780963680160418832333908040737262282830643745963536624555340279793555475547508851494656512855403492456740439533790565640263514349940712999516725281940465613417922773583725174223806589481568984323871222072582132221706797917380250216291620957692131931099423995355390698925093903005385497308399692769135287821632877871068909305276870015125960884987746154344006895331078411141197233179446805991116541744285238281451294472577537413640009811940462311100056023815261650331552185459228689469446389165886801876700815724561451940764544990177661873073", 10)
	if !ok {
		t.Errorf("error parsing pubkey modulus")
	}
	err := testingPolicy.GoodKey(context.Background(), &pubKey)
	test.AssertError(t, err, "Should have rejected too-long key")
	test.AssertEquals(t, err.Error(), "key too large: 4097 > 4096")
}

func TestModulusModulo8(t *testing.T) {
	bigOne := big.NewInt(1)
	key := rsa.PublicKey{
		N: bigOne.Lsh(bigOne, 2048),
		E: 5,
	}
	err := testingPolicy.GoodKey(context.Background(), &key)
	test.AssertError(t, err, "Should have rejected modulus with length not divisible by 8")
	test.AssertEquals(t, err.Error(), "key length wasn't a multiple of 8: 2049")
}

var mod2048 = big.NewInt(0).Sub(big.NewInt(0).Lsh(big.NewInt(1), 2048), big.NewInt(1))

func TestNonStandardExp(t *testing.T) {
	evenMod := big.NewInt(0).Add(big.NewInt(1).Lsh(big.NewInt(1), 2047), big.NewInt(2))
	key := rsa.PublicKey{
		N: evenMod,
		E: (1 << 16),
	}
	err := testingPolicy.GoodKey(context.Background(), &key)
	test.AssertError(t, err, "Should have rejected non-standard exponent")
	test.AssertEquals(t, err.Error(), "key exponent must be 65537")
}

func TestEvenModulus(t *testing.T) {
	evenMod := big.NewInt(0).Add(big.NewInt(1).Lsh(big.NewInt(1), 2047), big.NewInt(2))
	key := rsa.PublicKey{
		N: evenMod,
		E: (1 << 16) + 1,
	}
	err := testingPolicy.GoodKey(context.Background(), &key)
	test.AssertError(t, err, "Should have rejected even modulus")
	test.AssertEquals(t, err.Error(), "key divisible by small prime")
}

func TestModulusDivisibleBySmallPrime(t *testing.T) {
	key := rsa.PublicKey{
		N: mod2048,
		E: (1 << 16) + 1,
	}
	err := testingPolicy.GoodKey(context.Background(), &key)
	test.AssertError(t, err, "Should have rejected modulus divisible by 3")
	test.AssertEquals(t, err.Error(), "key divisible by small prime")
}

func TestROCA(t *testing.T) {
	n, ok := big.NewInt(1).SetString("19089470491547632015867380494603366846979936677899040455785311493700173635637619562546319438505971838982429681121352968394792665704951454132311441831732124044135181992768774222852895664400681270897445415599851900461316070972022018317962889565731866601557238345786316235456299813772607869009873279585912430769332375239444892105064608255089298943707214066350230292124208314161171265468111771687514518823144499250339825049199688099820304852696380797616737008621384107235756455735861506433065173933123259184114000282435500939123478591192413006994709825840573671701120771013072419520134975733578923370992644987545261926257", 10)
	if !ok {
		t.Fatal("failed to parse")
	}
	key := rsa.PublicKey{
		N: n,
		E: 65537,
	}
	err := testingPolicy.GoodKey(context.Background(), &key)
	test.AssertError(t, err, "Should have rejected ROCA-weak key")
	test.AssertEquals(t, err.Error(), "key generated by vulnerable Infineon-based hardware")
}

func TestGoodKey(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Error generating key")
	test.AssertNotError(t, testingPolicy.GoodKey(context.Background(), &private.PublicKey), "Should have accepted good key")
}

func TestECDSABadCurve(t *testing.T) {
	for _, curve := range invalidCurves {
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")
		err = testingPolicy.GoodKey(context.Background(), &private.PublicKey)
		test.AssertError(t, err, "Should have rejected key with unsupported curve")
		test.AssertEquals(t, err.Error(), fmt.Sprintf("ECDSA curve %s not allowed", curve.Params().Name))
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
		test.AssertNotError(t, testingPolicy.GoodKey(context.Background(), &private.PublicKey), "Should have accepted good key")
	}
}

func TestECDSANotOnCurveX(t *testing.T) {
	for _, curve := range validCurves {
		// Change a public key so that it is no longer on the curve.
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")

		private.X.Add(private.X, big.NewInt(1))
		err = testingPolicy.GoodKey(context.Background(), &private.PublicKey)
		test.AssertError(t, err, "Should not have accepted key not on the curve")
		test.AssertEquals(t, err.Error(), "key point is not on the curve")
	}
}

func TestECDSANotOnCurveY(t *testing.T) {
	for _, curve := range validCurves {
		// Again with Y.
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")

		// Change the public key so that it is no longer on the curve.
		private.Y.Add(private.Y, big.NewInt(1))
		err = testingPolicy.GoodKey(context.Background(), &private.PublicKey)
		test.AssertError(t, err, "Should not have accepted key not on the curve")
		test.AssertEquals(t, err.Error(), "key point is not on the curve")
	}
}

func TestECDSANegative(t *testing.T) {
	for _, curve := range validCurves {
		// Check that negative X is not accepted.
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")

		private.X.Neg(private.X)
		err = testingPolicy.GoodKey(context.Background(), &private.PublicKey)
		test.AssertError(t, err, "Should not have accepted key with negative X")
		test.AssertEquals(t, err.Error(), "key x, y must not be negative")

		// Check that negative Y is not accepted.
		private.X.Neg(private.X)
		private.Y.Neg(private.Y)
		err = testingPolicy.GoodKey(context.Background(), &private.PublicKey)
		test.AssertError(t, err, "Should not have accepted key with negative Y")
		test.AssertEquals(t, err.Error(), "key x, y must not be negative")
	}
}

func TestECDSAXOutsideField(t *testing.T) {
	for _, curve := range validCurves {
		// Check that X outside [0, p-1] is not accepted.
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")

		private.X.Mul(private.X, private.Curve.Params().P)
		err = testingPolicy.GoodKey(context.Background(), &private.PublicKey)
		test.AssertError(t, err, "Should not have accepted key with a X > p-1")
		test.AssertEquals(t, err.Error(), "key x, y must not exceed P-1")
	}
}

func TestECDSAYOutsideField(t *testing.T) {
	for _, curve := range validCurves {
		// Check that Y outside [0, p-1] is not accepted.
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		test.AssertNotError(t, err, "Error generating key")

		private.X.Mul(private.Y, private.Curve.Params().P)
		err = testingPolicy.GoodKey(context.Background(), &private.PublicKey)
		test.AssertError(t, err, "Should not have accepted key with a Y > p-1")
		test.AssertEquals(t, err.Error(), "key x, y must not exceed P-1")
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

		err := testingPolicy.GoodKey(context.Background(), &public)
		test.AssertError(t, err, "Should not have accepted key with point at infinity")
		test.AssertEquals(t, err.Error(), "key x, y must not be the point at infinity")
	}
}

func TestNonRefKey(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Error generating key")
	test.AssertError(t, testingPolicy.GoodKey(context.Background(), private.PublicKey), "Accepted non-reference key")
}

func TestDBBlacklist(t *testing.T) {
	exists := false
	testCheck := func(context.Context, *sapb.KeyBlockedRequest) (*sapb.Exists, error) {
		return &sapb.Exists{Exists: &exists}, nil
	}

	policy, err := NewKeyPolicy("", "", testCheck)
	test.AssertNotError(t, err, "NewKeyPolicy failed")

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "ecdsa.GenerateKey failed")
	err = policy.GoodKey(context.Background(), k.Public())
	test.AssertNotError(t, err, "GoodKey failed with a non-blocked key")
	exists = true
	err = policy.GoodKey(context.Background(), k.Public())
	test.AssertError(t, err, "GoodKey didn't fail with a blocked key")
	test.Assert(t, berrors.Is(err, berrors.BadPublicKey), "returned error is wrong type")
	test.AssertEquals(t, err.Error(), "public key is forbidden")
}

func TestRSAStrangeSize(t *testing.T) {
	err := features.Set(map[string]bool{"RestrictRSAKeySizes": true})
	test.AssertNotError(t, err, "failed to set features")
	defer features.Reset()

	k := &rsa.PublicKey{N: big.NewInt(10)}
	err = testingPolicy.GoodKey(context.Background(), k)
	test.AssertError(t, err, "expected GoodKey to fail")
	test.AssertEquals(t, err.Error(), "key size not supported: 4")
}
