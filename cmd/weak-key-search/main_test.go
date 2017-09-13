package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/goodkey"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

func TestSearch(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSA, 0)
	test.AssertNotError(t, err, "sa.NewDbMap failed")
	fc := clock.NewFake()
	log := blog.UseMock()
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, log, metrics.NewNoopScope())
	test.AssertNotError(t, err, "sa.NewSQLStorageAuthority failed")
	defer test.ResetSATestDatabase(t)

	reg := satest.CreateWorkingRegistration(t, ssa)

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "rsa.GenerateKey failed")
	temp := x509.Certificate{SerialNumber: big.NewInt(1337), Subject: pkix.Name{CommonName: "yup"}}

	derA, err := x509.CreateCertificate(rand.Reader, &temp, &temp, &k.PublicKey, k)
	test.AssertNotError(t, err, "x509.CreateCertificate failed")
	// DER of a RSA private key generated in the flawed Debian PRNG
	wkBytes, err := hex.DecodeString("308204a30201000282010100d673252af6723c3f72529403eab7c30def3c52f97e799825f4a70191c616adcf1ece1113f1625971074c492c592025fdeadbdb146a081826bdf0d77c3c913dcf1b6f0b3b78f5108d2e493ad0eee8ca5c021711adc13d358e61133870fcd19c8e5c22403959782aa82e72aee53a3d491e3912ce27b27e1a85ea69c19a527d28f7934c9823b7e56fdd657dac83fdc65bb22a98d843df73238919781b714c81a5e2afec71f5c54aa2a27c590ad94c03c1062d50efcffac743e3c8a3ae056846a1d756eb862bf4224169d467c35215ade0afcc11e85fe629afb802c4786ff2e9c929bccf502b3d3b8876c6a11785cc398b389f1d86bdd9cb0bd4ec13956ec3fa270d0203010001028201007db89180a76c7f3f9ef1248f4b4aa212883f70518e4110dea7984506460043b35a56ea922b8041f94e92fd8eff4d2698bed8578e973ed991d4e6de1d9a907790f47f5c31688f1b3df975bb02841d7b8d0738a90799731df3b39b860a4f5d3f9002199e5740c97f108bf275f032fd7ce1380a7b4bb08bd756ccff651de8e03164284d9aaa31c849deaa8c092c516fe963abbff8dad1c4b54dc4f573388580ed1d9a48d0787562443bad1b9ea08f94e3df7364a845e2d17366d2650ab745a885c514eec68927f6d629b888e2e609cc42e686e5ab9c46c32f6708df75781096a54cd544e7ae42da373a551abe117877297d4fcb0ff95e97d2e07d3869b22ff4b8e102818100f3508098dc7be50795f95a58e7564f3b47adfd936aee8c71415af2e1e7756367d529ecf4c44d7706c99bf16144733e045b49d1f697cea6ea01fb41928d0f626a397f973a459150d3ec71d915dd0d3d5f03599babec1b9b9cef16bb3b4ec8a712fe9df0df2352b02ee447f63adafd95397867ac728e8c5dbbe9be045791e1793902818100e1a1637136fc530a12950a54f7a3c14146586c7371c18433462c18825492ec02a4eee3e74e38ccdfac0dbe6ade624eac67c5983b610b14e51bd1a3edf76bf82af767426cf0156ee2d895c05866b19219876a10d0ee89c87a9f6eaa25595f4b11e5273eaad6d468a87eec0ab94228b99eb051bc5593ee337153aba07dd41bc075028180409d544943e433023cb5a7648caac307bf15598dd88bd9080a8f18891d6a732793d83a7115e06c8784eac0c34fe63ac5f5683935ff4285d90705ae7838b5a931046bf9c123d05f62a81be3c68699897ebde9020a39fd6ae9d624773c5cc3b47abadb3ea8433d26448da2fea4ca9b2511ca03de2bdde730cd42598fd5a18bfb21028180102208083a544463bdfc6626b9263e553a806c10bd1b87265b681fc081e7977480f28bdd281cab997aa5e8ed9f450c370b9c774c179e413a3888feddaf094b4f572d4cf4991e0f35ad22d803fa23cc3c8310346f9bfec214f27d69310e78dfd741b952a3c8849b8f20b423f82720de54d86a9fbac6bf0b7298f6f69cc8a3cb59028181009d91baf2e82e83e9085b7fdd82c89ff3df2ec2a52aaf2bc31906470529f0e1b80254fd3b34b4372b50715c83ff4587159aee22a90ac4e2ad736651f33c9395efaf48fe57d0355d295f4cbca85249d3473632ff35cc29fff142fd7ab1c6e5b163909591a17054c3ff731f11549251dd2436fdf1bc969b91360eeb4e6f01c7e0b1")
	test.AssertNotError(t, err, "hex.DecodeString failed")
	wk, err := x509.ParsePKCS1PrivateKey(wkBytes)
	test.AssertNotError(t, err, "x509.ParsePKCS1PrivateKey failed")
	derB, err := x509.CreateCertificate(rand.Reader, &temp, &temp, &wk.PublicKey, wk)
	test.AssertNotError(t, err, "x509.CreateCertificate failed")

	now := time.Now()
	err = dbMap.Insert(
		&core.Certificate{RegistrationID: reg.ID, Serial: "cert-a", DER: derA, Issued: now.Add(time.Hour * -2)},
		&core.Certificate{RegistrationID: reg.ID, Serial: "cert-b", DER: derA, Issued: now},
		&core.Certificate{RegistrationID: reg.ID, Serial: "cert-c", DER: derB, Issued: now},
		&core.Certificate{RegistrationID: reg.ID, Serial: "cert-d", DER: derA, Issued: now.Add(time.Hour * 2)},
	)
	test.AssertNotError(t, err, "dbMap.Insert failed")

	limit = 1
	w := make(chan certInfo, 10)
	getCerts(w, now.Add(-time.Hour), now.Add(time.Hour), dbMap.Db)
	test.AssertEquals(t, len(w), 2)

	tempDir, err := ioutil.TempDir("", "weak-keys")
	test.AssertNotError(t, err, "Failed to create temporary directory")
	tempPath := filepath.Join(tempDir, "a.json")
	// Truncated SHA1 hash of the modulus of the above RSA key
	err = ioutil.WriteFile(tempPath, []byte("[\"8df20e6961a16398b85a\"]"), os.ModePerm)
	test.AssertNotError(t, err, "Failed to create temporary file")

	wkl, err := goodkey.LoadWeakRSASuffixes(tempPath)
	test.AssertNotError(t, err, "Failed to load suffixes from directory")
	doWork(w, 1, wkl, log)
	test.AssertEquals(t, len(w), 0)
	test.AssertDeepEquals(t, log.GetAllMatching("INFO: cert contains weak key: .*"), []string{"INFO: cert contains weak key: cert-c"})
}
