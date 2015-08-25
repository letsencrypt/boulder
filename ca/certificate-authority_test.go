// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	cfsslConfig "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/config"
	ocspConfig "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp/config"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/sa/satest"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
)

var CAkeyPEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
	"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\n" +
	"-----END RSA PRIVATE KEY-----"

var CAcertPEM = "-----BEGIN CERTIFICATE-----\n" +
	"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\n" +
	"-----END CERTIFICATE-----"

// CSR generated by Go:
// * Random public key
// * CN = not-example.com
// * DNSNames = not-example.com, www.not-example.com
var CNandSANCSRhex = "308202a130820189020100301a311830160603550403130f6e6f742d6578" +
	"616d706c652e636f6d30820122300d06092a864886f70d01010105000382" +
	"010f003082010a0282010100e56ccbe37003c150202e6f543f9eb1d0e590" +
	"76ac7f1f62654fa82fe131a23c66bd53a2f62ff7852015c84a394e36836d" +
	"2018eba278e0740c85c4c6102787400c2ef069b4a72e6eb8ad8d1da5d76b" +
	"f3e70dafc126578ed28cf40030e7fe5b5307ef630254726c639561b5445d" +
	"372847bdb02576aa3622a688158c6af09d3938dbeba4d670cec4325be73a" +
	"fa52a0a04dcba2f335f1e85020704db94ca125dce70b3209294c6c46ed4b" +
	"48b95d8d51ae2d2fd227116023a48ca7381e35fd302ad2999df625a4b5ee" +
	"82a0d0fefa88ac6a62b01674de75637ef83328202cda9930947d932000b0" +
	"e53b82e099ab60fec9c8b6d4eccdee508b6ebca7e6ca3f752046c8350203" +
	"010001a042304006092a864886f70d01090e31333031302f0603551d1104" +
	"283026820f6e6f742d6578616d706c652e636f6d82137777772e6e6f742d" +
	"6578616d706c652e636f6d300d06092a864886f70d01010b050003820101" +
	"008c4bf2ab4dfd28d768697eecc5be889a6275287c7dd24f9232ffad5675" +
	"de708c9cc911545d0e84f61b6584c5e237915bbf231d6518e7e228be2e65" +
	"b4d50bd9729ce9e6aee00482e014de4edd4b9a4f9a7777b8943ef3512dbf" +
	"940ac561c25b34ded9db1074136b978a65943ab1259608fb8109e008eac6" +
	"23d7b29b2f1fad3a8e358aa070ead688016d9efed6da43412b136903de07" +
	"137462d3f9203a344d84d7eb336999004e7e9972d5176001e2792f206e6c" +
	"7c70b86d312459f21751d29ea53b41f9d02a229f9d7615b2a7ac83e849d0" +
	"d0d9f8a08f8d7ba23295e77c95bc060c9227bfec0afb8c898e33c89903d7" +
	"bbde4cf059dcc3e6c4ae4eef207c499d62"

// CSR generated by Go:
// * Random public key
// * CN = not-example.com
// * DNSNames = [none]
var NoSANCSRhex = "3082025f30820147020100301a311830160603550403130f6e6f742d6578" +
	"616d706c652e636f6d30820122300d06092a864886f70d01010105000382" +
	"010f003082010a0282010100aa6e56ff24906f93b855e7871dc8411a3cf7" +
	"678d9563627e8ca37ab17dfe814ef7f828d6aa92b717f0da9df56990b953" +
	"989d5afc3f2dddacd2b504b89782b49e55a04a64a4370d8ab1b2688f2596" +
	"98132e5ce536f812ef5eb13824a922bbb89e30d6f2cace77462b9e65264a" +
	"32320a7b348f9903b16640bc8c1c5f1208c6b456fd85bfa96ee9b7642c68" +
	"3ab05b142d249525a730b230b39f2ba8d6f253263b5c3948b1a3d8a3467f" +
	"7cfcdd1fdd6bff7828fda12784fd277be8c680fcdf2cc4676acff5df759f" +
	"f4bc712ee1a560157233cbf6bb4bcb91dd1c5d2824b42f4913e4715c1ba4" +
	"001fde0d90c274bfa81a79e4a0d00a7ddcbfdd8de4183b497487a20d0203" +
	"010001a000300d06092a864886f70d01010b050003820101000ead204cfd" +
	"45d307dd49de6937d7e2d8abf17490a49a8cee5250ef7799ef53229f8cfc" +
	"735b9f65d789f898945f3d5536a09932e241050bd5473c47a4ac2493707f" +
	"1142bf9a06d047384ad463463acb3744d435b4cff8c8b0f9673e8700e13b" +
	"6bc99a486823fa85f7707e1bb8430e62541715ab6cb3fae3efb8356042a5" +
	"c9f493dd08eff690570cce65cffc4fe354aa40957dc16a37a833aa968f62" +
	"693d5059d53f6a96a159195d3fb7b558d462de63d945d4e3680d2b1f2c98" +
	"33c3bfd92a9235de3d345a431ee5a675e0e18308bd2729413acd84432da4" +
	"2410e1b87ae70227dd9a98e49ee6aeea9eaff67f968691918201e94697f2" +
	"da010d6f939cea40c26038"

// CSR generated by Go:
// * Random public key
// * C = US
// * CN = [none]
// * DNSNames = not-example.com
var NoCNCSRhex = "3082027f30820167020100300d310b300906035504061302555330820122" +
	"300d06092a864886f70d01010105000382010f003082010a0282010100d8" +
	"b3c11610ce17614f6d78de3f079db430e479c38978da8cd625b7c70dd445" +
	"57fd99b9831693e6b9b09fb7c74a82058a1f1a4e1e087f04f93aa73bc35a" +
	"688440205a6f5fd56ff478c5554b14c3b2a1a0b5eed1aef7189ad848e117" +
	"04b1eb6c29b47ada40a5719a38ce2f2869896bf5405c2bafd4c7dfb99c0e" +
	"9f26f80145e16b73bbacf67aedcd3b7ce57bb5b67cf692aec7956d23c236" +
	"2336c2408b65469630dccca3ca006f28e36ca8c95dda84b6586f29c8de63" +
	"661c09b58253e386a74707394cbba4de165f2745a65b717b9fd4b8b84c09" +
	"85583b5c17d3e88bbf71c88eeeccb5d552d61cde7835ec83d6ec9b41114a" +
	"0583f8eeae8a536cb3ca5786c22ab30203010001a02d302b06092a864886" +
	"f70d01090e311e301c301a0603551d1104133011820f6e6f742d6578616d" +
	"706c652e636f6d300d06092a864886f70d01010b05000382010100430239" +
	"8db6b64b94d93399db32335232967ca6a748048483db8cb2b387871f758c" +
	"6f7bf1593624b142127847cd2a511897bbadd8ad038468fb309fa2161031" +
	"949b9ba24931b0d363ad2f8dae56a4c908ba748d41c664aa129dcb1a6f88" +
	"0b90502cd244d9abd8dd5e78f763730660655a350f1c25af95cf1f89dda9" +
	"076f4e6b84b6da9a98ed87f538624e4338fa0ff1a404e763dd6800694a21" +
	"d28595927606308aefa1ac7e8f5600b05e33c0a7b25d3a9f5032c7c25264" +
	"026c039733b179315254af4f25e90a1d00facd69313b36fdc66a5818fb49" +
	"a0d90e0745d66a82d337289c9968b3ec4a4826c530c758cacecc18e06366" +
	"dd8962c451c3ce22c2aed33726"

// CSR generated by Go:
// * Random public key
// * C = US
// * CN = [none]
// * DNSNames = [none]
var NoNameCSRhex = "308202523082013a020100300d310b300906035504061302555330820122" +
	"300d06092a864886f70d01010105000382010f003082010a0282010100bc" +
	"fae49f68f02c42500b2faf251628ee19e8ef048a35fef311c9c419c80606" +
	"ab37340ad6e25cf4cc63c0283994b4ba705d86950ad5298094e0b9684647" +
	"8d67abc695741317b4ff8da9fd33120342559cfdaf9109ac403f0d0bf9ff" +
	"54dd79fa2256b218a9bdb17c608167c7fcad4cf839733c7eab9589fe6137" +
	"e99bb24c24b7eb74e19f51ffee4ea62c4ab756f099ff5197c5032f60edff" +
	"36022b8a99d35aeb706854fa9a31ea8a362a2251f08b93023b32e1df771a" +
	"970f08a30ced656950b8ef71600d65d6995a0b92903b179c05a76f702a08" +
	"0b41402c308d8ab57f14b5516b89fe317e38e13d7adad7f7025743610881" +
	"9fb60268f0773b08b62ac8c8c84f2d0203010001a000300d06092a864886" +
	"f70d01010b050003820101001eda9ce8253e8b933348851acd38ab63cd64" +
	"f833d7ffc711f1b6e6a37a7deb7ad44b5589d90533ed61dfd48cab2775e2" +
	"a19c41f5cb69faa9dde856606822a3bf798381836214154c17bc037f23ad" +
	"67c84d876855c0aea871dc55bd14b2cd267e49b734bc7a38c29c334611bf" +
	"ec7efdc56a1512e25fd12ca99a5809b1b6a808caf6a8baefff7fb2bda454" +
	"5c226849674900ce7a1f90287ab31be80a4e2b6d64765b9d973628e60299" +
	"6423edd74e7a58005bd520d4173f0c30d935de530477480d7725d9758f9a" +
	"58c004d9e1e55af59ea517dfbd2bccca58216d8130b9f77c90328b2aa54b" +
	"1778a629b584f2bc059489a236131de9b444adca90218c31a499a485"

// CSR generated by Go:
// * Random public key
// * CN = [none]
// * DNSNames = a.example.com, a.example.com
var DupeNameCSRhex = "308202943082017c020100300d310b300906035504061302555330820122" +
	"300d06092a864886f70d01010105000382010f003082010a0282010100ee" +
	"7d298c2a8237dd84e75e71dcfbbf8e1124327b103b01f3a99bc76b29be64" +
	"55329dc523ad1372ed12853dc74a775f2c79d1e4e28ae2a3ce69b78ec161" +
	"76b31056a72b5b87bcd7501ab9f15e83346e788c085e472718494849c012" +
	"ff6c25f12c040a0c68e99a46e8646523bf2b4103dcc7c4e583c6bf02c896" +
	"09b55e470beb15eaefc0bb6d57aca39e75312833e87faf2ba33e12a3204c" +
	"a19e5a1016c85b750619be9cb76fb93e653f3169b873dce42deab328a034" +
	"57454fd8e135e125bdb4529144a34bcc5ab20f25c6b33300ab2ad994d251" +
	"9261920da78e05b1c8847852e93a74000e7b29304ef2cccfa5315888150c" +
	"14e9d51e2c343de44e6bd2903740ef0203010001a042304006092a864886" +
	"f70d01090e31333031302f0603551d11042830268211612e6e6f742d6578" +
	"616d706c652e636f6d8211612e6e6f742d6578616d706c652e636f6d300d" +
	"06092a864886f70d01010b050003820101001358a156338bacd21bd66f35" +
	"83bf26afbaa6750f1d5d8e6285d062d5ae4f379000cd53568e8ef11bb542" +
	"97d906879614960266fece8f9060881c3b0ec34a1bb4b28f62cc444e5831" +
	"09c278d21265b2ef6f120ae8bc2554ba46b60e8d46a8cd3093ea6b72cb42" +
	"9d2d6072273e4a0c1a5ec3316cc2495a2776698f12cd4f4226f4b3e85f87" +
	"0b0f32785cf823b9dfa7116eec8a6f9bdc5cf01c1fff46afbb55e636ced4" +
	"0ccdf4cab09e7717aa2a67c5573590bb5d461cb13cc57b8451314ed3613e" +
	"21757aeb846f5b33f107a01f93a718b3a83539562e6486a72f114df898ed" +
	"c34e38d9bbdb96d0b8ab243c46da274cece70deb771985c477098468063a" +
	"8400ecb6"

// CSR generated by Go:
// * Random pulic key
// * CN = [none]
// * DNSNames = not-example.com, www.not-example.com, mail.example.com
var TooManyNameCSRhex = "308202aa30820192020100300d310b300906035504061302555330820122" +
	"300d06092a864886f70d01010105000382010f003082010a0282010100a7" +
	"75d8f833651d9a4cfa1fa0e134912b772366c7d070ca3183d3c79ffc99bb" +
	"c706d328c2389b360b99f60e9a447023a019931d410b4cea0eafb7869a6d" +
	"879d6a976163e3e8de715bcc6a0d80654484450a837b9abae0c5c2fa28dd" +
	"4f33d8043c32e2ecb9c41a0b6c7df60f9f6eaaef6cef38722db9b278b773" +
	"c8251c75d63c36c5708024d3ec67372c205342ad93a68cc4cc9f90a92789" +
	"b4fcdcbe050990b6e3edf2655c9df8365eb8be89a6ee4f80267e056e5cca" +
	"853094a96ec1d76a00cef8724ed3b402f602c30cfc16128abc25bab65a9c" +
	"f8a046b576e314a5d01e0887cfde86c01094b621e2230fc5db588ffd0e0e" +
	"2454e60e8b83a9e82f33419abc62710203010001a058305606092a864886" +
	"f70d01090e3149304730450603551d11043e303c820f6e6f742d6578616d" +
	"706c652e636f6d82137777772e6e6f742d6578616d706c652e636f6d8214" +
	"6d61696c2e6e6f742d6578616d706c652e636f6d300d06092a864886f70d" +
	"01010b05000382010100486c9cea322a3a81ec9b828ccb303524cc914e0b" +
	"81b45ea23214b0dd254a79cdc77d1a661c7de8dcfcc7d404c0ad8707a67a" +
	"1ecc43ed5b4a7d96fabe41cab5ad8fde18f894bd2e57c8291b3bb0220c95" +
	"7c178c1c4251be4252663a14e4c303a8563bb86056f8e07ab14082693f72" +
	"3a55efe017b15d22cd31b6aa7b1bb5e1078e6f7b7fb12962230b192e0d40" +
	"a4f4515d6f2922b587e3586ea7f61ae7196cfeab5b4e5f78e03de0dab5a6" +
	"a537e6740bbb2a72b32c94068b4b46766f94ab3d24a704869d127fab6fb9" +
	"9c470101aed4852cd7b3a0a5a489b264779118b30d51907dc745879a821b" +
	"85f19a24d20dc5b48141eff276aa73bb41141305905b0223ded7"

// CSR generated by Go:
// * Random public key -- 512 bits long
// * CN = (none)
// * DNSNames = not-example.com, www.not-example.com, mail.not-example.com
var ShortKeyCSRhex = "3082011f3081ca020100300d310b30090603550406130255" +
	"53305c300d06092a864886f70d0101010500034b00304802" +
	"4100ca8ff48b32197226bbe6398b6ba62dd4f09be06dc742" +
	"4b0c6321323d90c58e93cad2b3c91b5809493836f110dfc6" +
	"bbb3eca5575e6416a3a8189e782f41a29b990203010001a0" +
	"58305606092a864886f70d01090e3149304730450603551d" +
	"11043e303c820f6e6f742d6578616d706c652e636f6d8213" +
	"7777772e6e6f742d6578616d706c652e636f6d82146d6169" +
	"6c2e6e6f742d6578616d706c652e636f6d300d06092a8648" +
	"86f70d0101050500034100bfdc34a0a728918f4221413631" +
	"a70656db80ddb1b8126a02e6ca92c48301c350f29b6049b3" +
	"c4d70bf22ac273c951e60dd22f6f427b8d234e85f6881fba" +
	"35c288"

// CSR generated by Go:
// * Random public key
// * CN = (none)
// * DNSNames = not-example.com, www.not-example.com, mail.not-example.com
// * Signature algorithm: SHA1WithRSA
var BadAlgorithmCSRhex = "308202aa30820192020100300d310b300906035504061302" +
	"555330820122300d06092a864886f70d0101010500038201" +
	"0f003082010a02820101009f70f8d60b07f24b6960e18da8" +
	"aabdc993c583a6c43c81ae256a1d4328146f3e907fb65dc4" +
	"f30cb27c96d020e55bf116ef33f3696d2d957b9b408d6762" +
	"2fe562311c96023100985ed8bc10929e7c552d7674027b63" +
	"3973ede006b1ba338f9f4b7a88b4ea768c70632dde0f202a" +
	"f59d41bf9aaa841e022735cfb2822a919b2b9ada07bdd569" +
	"347894f1aa4908ee86d2019eb8980e819af20b5084eb11f7" +
	"2f4f51e77c99d09e556ae84a720fa728962c5f7db176ce0a" +
	"27b824fc63849ad5493ba790cd8f0c0aedf22d7979a95fce" +
	"f4dfa552f8f85e15f5e7e427002b56f03f040e7cd43145d7" +
	"7732ef9c4568b0f22aa91ca1e5a133f862939ed14c1859a1" +
	"fdd36f0203010001a058305606092a864886f70d01090e31" +
	"49304730450603551d11043e303c820f6e6f742d6578616d" +
	"706c652e636f6d82137777772e6e6f742d6578616d706c65" +
	"2e636f6d82146d61696c2e6e6f742d6578616d706c652e63" +
	"6f6d300d06092a864886f70d0101050500038201010056cf" +
	"65a690ef9d279caa0b5e44c51a1f97631c43e9f0c67fd329" +
	"6b0d33acf06a695130fbdb8842a40d690549ab05f44b1738" +
	"e8419b395563426d76cc5611d17ade13c96c92496a2ed008" +
	"a78687f25c892af274afd9518540300edd160dc47887b402" +
	"a0705b156e9b623f47a3bdaea93b84a4cf873ac1e9861b67" +
	"f742024eff40c7c8e33243a953e9874e678c3f4cd24b4699" +
	"28214425ef7b9181d8b10b7f07f557bef7c4b22689be4b2a" +
	"42a0b6f0aaefa4dc8913338785e7f8fc2b1b95c4d189d10f" +
	"72dbe575cdd6985e2d6eb0d0cbe962de0986cbcc8ca30dc8" +
	"fa254808b0ee8946253830c087da95404181cb88ec59d399" +
	"b4b3fcc21bbb1c9f3e1b29fd576a"

// Times for validity checking
var FarFuture = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
var FarPast = time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC)

var log = mocks.UseMockLog()

// CFSSL config
const profileName = "ee"
const caKeyFile = "../test/test-ca.key"
const caCertFile = "../test/test-ca.pem"

const (
	caDBConnStr = "mysql+tcp://boulder@localhost:3306/boulder_ca_test"
	saDBConnStr = "mysql+tcp://boulder@localhost:3306/boulder_sa_test"
)

type testCtx struct {
	caDB     core.CertificateAuthorityDatabase
	sa       core.StorageAuthority
	caConfig Config
	reg      core.Registration
	cleanUp  func()
}

func setup(t *testing.T) *testCtx {
	// Create an SA
	dbMap, err := sa.NewDbMap(saDBConnStr)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	ssa, err := sa.NewSQLStorageAuthority(dbMap)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}
	saDBCleanUp := test.ResetTestDatabase(t, dbMap.Db)
	cadb, caDBCleanUp := caDBImpl(t)
	cleanUp := func() {
		saDBCleanUp()
		caDBCleanUp()
	}

	// TODO(jmhodges): use of this pkg here is a bug caused by using a real SA
	reg := satest.CreateWorkingRegistration(t, ssa)

	// Create a CA
	caConfig := Config{
		Profile:      profileName,
		SerialPrefix: 17,
		Key: KeyConfig{
			File: caKeyFile,
		},
		TestMode:     true,
		Expiry:       "8760h",
		LifespanOCSP: "45m",
		MaxNames:     2,
		CFSSL: cfsslConfig.Config{
			Signing: &cfsslConfig.Signing{
				Profiles: map[string]*cfsslConfig.SigningProfile{
					profileName: &cfsslConfig.SigningProfile{
						Usage:     []string{"server auth"},
						CA:        false,
						IssuerURL: []string{"http://not-example.com/issuer-url"},
						OCSP:      "http://not-example.com/ocsp",
						CRL:       "http://not-example.com/crl",

						Policies: []cfsslConfig.CertificatePolicy{
							cfsslConfig.CertificatePolicy{
								ID: cfsslConfig.OID(asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}),
							},
						},
						ExpiryString: "8760h",
						Backdate:     time.Hour,
						CSRWhitelist: &cfsslConfig.CSRWhitelist{
							PublicKeyAlgorithm: true,
							PublicKey:          true,
							SignatureAlgorithm: true,
						},
					},
				},
				Default: &cfsslConfig.SigningProfile{
					ExpiryString: "8760h",
				},
			},
			OCSP: &ocspConfig.Config{
				CACertFile:        caCertFile,
				ResponderCertFile: caCertFile,
				KeyFile:           caKeyFile,
			},
		},
	}
	return &testCtx{cadb, ssa, caConfig, reg, cleanUp}
}

func TestFailNoSerial(t *testing.T) {
	ctx := setup(t)
	defer ctx.cleanUp()

	ctx.caConfig.SerialPrefix = 0
	_, err := NewCertificateAuthorityImpl(ctx.caDB, ctx.caConfig, caCertFile)
	test.AssertError(t, err, "CA should have failed with no SerialPrefix")
}

func TestRevoke(t *testing.T) {
	ctx := setup(t)
	defer ctx.cleanUp()
	ca, err := NewCertificateAuthorityImpl(ctx.caDB, ctx.caConfig, caCertFile)
	test.AssertNotError(t, err, "Failed to create CA")
	if err != nil {
		return
	}
	ca.SA = ctx.sa
	ca.MaxKeySize = 4096

	csrDER, _ := hex.DecodeString(CNandSANCSRhex)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	certObj, err := ca.IssueCertificate(*csr, ctx.reg.ID, FarFuture)
	test.AssertNotError(t, err, "Failed to sign certificate")
	if err != nil {
		return
	}
	cert, err := x509.ParseCertificate(certObj.DER)
	test.AssertNotError(t, err, "Certificate failed to parse")
	serialString := core.SerialToString(cert.SerialNumber)
	err = ca.RevokeCertificate(serialString, 0)
	test.AssertNotError(t, err, "Revocation failed")

	status, err := ctx.sa.GetCertificateStatus(serialString)
	test.AssertNotError(t, err, "Failed to get cert status")

	test.AssertEquals(t, status.Status, core.OCSPStatusRevoked)
	secondAgo := time.Now().Add(-time.Second)
	test.Assert(t, status.OCSPLastUpdated.After(secondAgo),
		fmt.Sprintf("OCSP LastUpdated was more than a second old: %v", status.OCSPLastUpdated))
}

func TestIssueCertificate(t *testing.T) {
	ctx := setup(t)
	defer ctx.cleanUp()
	ca, err := NewCertificateAuthorityImpl(ctx.caDB, ctx.caConfig, caCertFile)
	test.AssertNotError(t, err, "Failed to create CA")
	ca.SA = ctx.sa
	ca.MaxKeySize = 4096

	/*
		  // Uncomment to test with a local signer
			signer, _ := local.NewSigner(caKey, caCert, x509.SHA256WithRSA, nil)
			ca := CertificateAuthorityImpl{
				Signer: signer,
				SA:     sa,
			}
	*/

	csrs := []string{CNandSANCSRhex, NoSANCSRhex, NoCNCSRhex}
	for _, csrHEX := range csrs {
		csrDER, _ := hex.DecodeString(csrHEX)
		csr, _ := x509.ParseCertificateRequest(csrDER)

		// Sign CSR
		issuedCert, err := ca.IssueCertificate(*csr, ctx.reg.ID, FarFuture)
		test.AssertNotError(t, err, "Failed to sign certificate")
		if err != nil {
			continue
		}

		// Verify cert contents
		cert, err := x509.ParseCertificate(issuedCert.DER)
		test.AssertNotError(t, err, "Certificate failed to parse")

		test.AssertEquals(t, cert.Subject.CommonName, "not-example.com")

		switch len(cert.DNSNames) {
		case 1:
			if cert.DNSNames[0] != "not-example.com" {
				t.Errorf("Improper list of domain names %v", cert.DNSNames)
			}
		case 2:
			switch {
			case (cert.DNSNames[0] == "not-example.com" && cert.DNSNames[1] == "www.not-example.com"):
				t.Log("case 1")
			case (cert.DNSNames[0] == "www.not-example.com" && cert.DNSNames[1] == "not-example.com"):
				t.Log("case 2")
			default:
				t.Errorf("Improper list of domain names %v", cert.DNSNames)
			}

		default:
			t.Errorf("Improper list of domain names %v", cert.DNSNames)
		}

		// Test is broken by CFSSL Issue #156
		// https://github.com/cloudflare/cfssl/issues/156
		if len(cert.Subject.Country) > 0 {
			// Uncomment the Errorf as soon as upstream #156 is fixed
			// t.Errorf("Subject contained unauthorized values: %v", cert.Subject)
			t.Logf("Subject contained unauthorized values: %v", cert.Subject)
		}

		// Verify that the cert got stored in the DB
		serialString := core.SerialToString(cert.SerialNumber)
		storedCert, err := ctx.sa.GetCertificate(serialString)
		test.AssertNotError(t, err,
			fmt.Sprintf("Certificate %s not found in database", serialString))
		test.Assert(t, bytes.Equal(issuedCert.DER, storedCert.DER), "Retrieved cert not equal to issued cert.")

		certStatus, err := ctx.sa.GetCertificateStatus(serialString)
		test.AssertNotError(t, err,
			fmt.Sprintf("Error fetching status for certificate %s", serialString))
		test.Assert(t, certStatus.Status == core.OCSPStatusGood, "Certificate status was not good")
		test.Assert(t, certStatus.SubscriberApproved == false, "Subscriber shouldn't have approved cert yet.")
	}
}

func TestRejectNoName(t *testing.T) {
	ctx := setup(t)
	defer ctx.cleanUp()
	ca, err := NewCertificateAuthorityImpl(ctx.caDB, ctx.caConfig, caCertFile)
	test.AssertNotError(t, err, "Failed to create CA")
	ca.SA = ctx.sa
	ca.MaxKeySize = 4096

	// Test that the CA rejects CSRs with no names
	csrDER, _ := hex.DecodeString(NoNameCSRhex)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	_, err = ca.IssueCertificate(*csr, ctx.reg.ID, FarFuture)
	if err == nil {
		t.Errorf("CA improperly agreed to create a certificate with no name")
	}
}

func TestRejectTooManyNames(t *testing.T) {
	ctx := setup(t)
	defer ctx.cleanUp()
	ca, err := NewCertificateAuthorityImpl(ctx.caDB, ctx.caConfig, caCertFile)
	test.AssertNotError(t, err, "Failed to create CA")
	ca.SA = ctx.sa

	// Test that the CA rejects a CSR with too many names
	csrDER, _ := hex.DecodeString(TooManyNameCSRhex)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	_, err = ca.IssueCertificate(*csr, ctx.reg.ID, FarFuture)
	test.Assert(t, err != nil, "Issued certificate with too many names")
}

func TestDeduplication(t *testing.T) {
	ctx := setup(t)
	defer ctx.cleanUp()
	ca, err := NewCertificateAuthorityImpl(ctx.caDB, ctx.caConfig, caCertFile)
	test.AssertNotError(t, err, "Failed to create CA")
	ca.SA = ctx.sa
	ca.MaxKeySize = 4096

	// Test that the CA collapses duplicate names
	csrDER, _ := hex.DecodeString(DupeNameCSRhex)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	cert, err := ca.IssueCertificate(*csr, ctx.reg.ID, FarFuture)
	test.AssertNotError(t, err, "Failed to gracefully handle a CSR with duplicate names")
	if err != nil {
		return
	}

	parsedCert, err := x509.ParseCertificate(cert.DER)
	test.AssertNotError(t, err, "Error parsing certificate produced by CA")
	if err != nil {
		return
	}

	correctName := "a.not-example.com"
	correctNames := len(parsedCert.DNSNames) == 1 &&
		parsedCert.DNSNames[0] == correctName &&
		parsedCert.Subject.CommonName == correctName
	test.Assert(t, correctNames, "Incorrect set of names in deduplicated certificate")
}

func TestRejectValidityTooLong(t *testing.T) {
	ctx := setup(t)
	defer ctx.cleanUp()
	ca, err := NewCertificateAuthorityImpl(ctx.caDB, ctx.caConfig, caCertFile)
	test.AssertNotError(t, err, "Failed to create CA")
	ca.SA = ctx.sa
	ca.MaxKeySize = 4096

	// Test that the CA rejects CSRs that would expire after the intermediate cert
	csrDER, _ := hex.DecodeString(NoCNCSRhex)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	_, err = ca.IssueCertificate(*csr, ctx.reg.ID, FarPast)
	test.Assert(t, err == nil, "Can issue a certificate that expires after the underlying authorization.")

	// Test that the CA rejects CSRs that would expire after the intermediate cert
	csrDER, _ = hex.DecodeString(NoCNCSRhex)
	csr, _ = x509.ParseCertificateRequest(csrDER)
	ca.NotAfter = time.Now()
	_, err = ca.IssueCertificate(*csr, 1, FarFuture)
	test.AssertEquals(t, err.Error(), "Cannot issue a certificate that expires after the intermediate certificate.")
}

func TestShortKey(t *testing.T) {
	ctx := setup(t)
	defer ctx.cleanUp()
	ca, err := NewCertificateAuthorityImpl(ctx.caDB, ctx.caConfig, caCertFile)
	ca.SA = ctx.sa
	ca.MaxKeySize = 4096

	// Test that the CA rejects CSRs that would expire after the intermediate cert
	csrDER, _ := hex.DecodeString(ShortKeyCSRhex)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	_, err = ca.IssueCertificate(*csr, ctx.reg.ID, FarFuture)
	test.Assert(t, err != nil, "Issued a certificate with too short a key.")
}

func TestRejectBadAlgorithm(t *testing.T) {
	ctx := setup(t)
	defer ctx.cleanUp()
	ca, err := NewCertificateAuthorityImpl(ctx.caDB, ctx.caConfig, caCertFile)
	ca.SA = ctx.sa
	ca.MaxKeySize = 4096

	// Test that the CA rejects CSRs that would expire after the intermediate cert
	csrDER, _ := hex.DecodeString(BadAlgorithmCSRhex)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	_, err = ca.IssueCertificate(*csr, ctx.reg.ID, FarFuture)
	test.Assert(t, err != nil, "Issued a certificate based on a CSR with a weak algorithm.")
}
