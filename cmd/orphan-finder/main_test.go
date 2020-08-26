package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/jmhodges/clock"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
)

var log = blog.UseMock()

type mockSA struct {
	certificates    []core.Certificate
	precertificates []core.Certificate
	clk             clock.FakeClock
}

func (m *mockSA) AddCertificate(ctx context.Context, der []byte, regID int64, _ []byte, issued *time.Time) (string, error) {
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	cert := core.Certificate{
		DER:            der,
		RegistrationID: regID,
		Serial:         core.SerialToString(parsed.SerialNumber),
	}
	if issued == nil {
		cert.Issued = m.clk.Now()
	} else {
		cert.Issued = *issued
	}
	m.certificates = append(m.certificates, cert)
	return "", nil
}

func (m *mockSA) GetCertificate(ctx context.Context, s string) (core.Certificate, error) {
	if len(m.certificates) == 0 {
		return core.Certificate{}, berrors.NotFoundError("no certs stored")
	}
	for _, cert := range m.certificates {
		if cert.Serial == s {
			return cert, nil
		}
	}
	return core.Certificate{}, berrors.NotFoundError("no cert stored for requested serial")
}

func (m *mockSA) AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*corepb.Empty, error) {
	parsed, err := x509.ParseCertificate(req.Der)
	if err != nil {
		return nil, err
	}
	precert := core.Certificate{
		DER:            req.Der,
		RegistrationID: req.RegID,
		Serial:         core.SerialToString(parsed.SerialNumber),
	}
	if req.Issued == 0 {
		precert.Issued = m.clk.Now()
	} else {
		precert.Issued = time.Unix(0, req.Issued)
	}
	m.precertificates = append(m.precertificates, precert)
	return &corepb.Empty{}, nil
}

func (m *mockSA) GetPrecertificate(ctx context.Context, req *sapb.Serial) (*corepb.Certificate, error) {
	if len(m.precertificates) == 0 {
		return nil, berrors.NotFoundError("no precerts stored")
	}
	for _, precert := range m.precertificates {
		if precert.Serial == req.Serial {
			return bgrpc.CertToPB(precert), nil
		}
	}
	return nil, berrors.NotFoundError("no precert stored for requested serial")
}

type mockCA struct{}

func (ca *mockCA) GenerateOCSP(context.Context, *capb.GenerateOCSPRequest, ...grpc.CallOption) (*capb.OCSPResponse, error) {
	return &capb.OCSPResponse{
		Response: []byte("HI"),
	}, nil
}

func checkNoErrors(t *testing.T) {
	logs := log.GetAllMatching("ERR:")
	if len(logs) != 0 {
		t.Errorf("Found error logs:")
		for _, ll := range logs {
			t.Error(ll)
		}
	}
}

func TestParseLine(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	sa := &mockSA{}
	ca := &mockCA{}

	// Set an example backdate duration (this is normally read from config)
	backdateDuration = time.Hour

	testCertDER := "3082045b30820343a003020102021300ffa0160630d618b2eb5c0510824b14274856300d06092a864886f70d01010b0500301f311d301b06035504030c146861707079206861636b65722066616b65204341301e170d3135313030333035323130305a170d3136303130313035323130305a3018311630140603550403130d6578616d706c652e636f2e626e30820122300d06092a864886f70d01010105000382010f003082010a02820101009ea3f1d21fade5596e36a6a77095a94758e4b72466b7444ada4f7c4cf6fde9b1d470b93b65c1fdd896917f248ccae49b57c80dc21c64b010699432130d059d2d8392346e8a179c7c947835549c64a7a5680c518faf0a5cbea48e684fca6304775c8fa9239c34f1d5cb2d063b098bd1c17183c7521efc884641b2f0b41402ac87c7076848d4347cef59dd5a9c174ad25467db933c95ef48c578ba762f527b21666a198fb5e1fe2d8299b4dceb1791e96ad075e3ecb057c776d764fad8f0829d43c32ddf985a3a36fade6966cec89468721a1ec47ab38eac8da4514060ded51d283a787b7c69971bda01f49f76baa41b1f9b4348aa4279e0fa55645d6616441f0d0203010001a382019530820191300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e04160414369d0c100452b9eb3ffe7ae852e9e839a3ae5adb301f0603551d23041830168014fb784f12f96015832c9f177f3419b32e36ea4189306a06082b06010505070101045e305c302606082b06010505073001861a687474703a2f2f6c6f63616c686f73743a343030322f6f637370303206082b060105050730028626687474703a2f2f6c6f63616c686f73743a343030302f61636d652f6973737565722d6365727430180603551d110411300f820d6578616d706c652e636f2e626e30270603551d1f0420301e301ca01aa0188616687474703a2f2f6578616d706c652e636f6d2f63726c30630603551d20045c305a300a060667810c0102013000304c06032a03043045302206082b060105050702011616687474703a2f2f6578616d706c652e636f6d2f637073301f06082b0601050507020230130c11446f20576861742054686f752057696c74300d06092a864886f70d01010b05000382010100bbb4b994971cafa2e56e2258db46d88bfb361d8bfcd75521c03174e471eaa9f3ff2e719059bb57cc064079496d8550577c127baa84a18e792ddd36bf4f7b874b6d40d1d14288c15d38e4d6be25eb7805b1c3756b3735702eb4585d1886bc8af2c14086d3ce506e55184913c83aaaa8dfe6160bd035e42cda6d97697ed3ee3124c9bf9620a9fe6602191c1b746533c1d4a30023bbe902cb4aa661901177ed924eb836c94cc062dd0ce439c4ece9ee1dfe0499a42cbbcb2ea7243c59f4df4fdd7058229bacf9a640632dbd776b21633137b2df1c41f0765a66f448777aeec7ed4c0cdeb9d8a2356ff813820a287e11d52efde1aa543b4ef2ee992a7a9d5ccf7da4"

	testPreCertDER := "308204553082033da003020102021203e1dea6f3349009a90e0306dbb39c3e7ca2300d06092a864886f70d01010b0500304a310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074312330210603550403131a4c6574277320456e637279707420417574686f72697479205833301e170d3139313031363132353431375a170d3230303131343132353431375a30133111300f060355040313086a756e74732e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100c91926403839aadbf2a73af4f85e3884df553880c7e9d11943121b941f284a2c805b6329a93d7fb2357c1298d811cfce61faa863c334149f948ff52a55a516e56b2d31d137b1d0319f2aabdea0e9d5e8630b54d7e53597e094c323e24a7ec1ab0db5d85651a641ec3fd7841fe5cbc675315c49b714238ead757e55409fd68c4b48d42f14c2124d381800fd2ec417ed7f363b00ab23aaddaf9113d5cf889bbf391431bffb91d425d11a1e79318b7007b8e75cc56633662c3d6c58175b5cab6225aa495361b1124642f19584820d215f23f46bd9fafa3341a0f7f387bf7cdecbccd7fcbcb3e917becb41562771e579884a0d8a1b170536f82ba90b398e9a6932150203010001a382016a30820166300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e041604144d14d73117ca7f5a27394ed590b0d037eb5888a2301f0603551d23041830168014a84a6a63047dddbae6d139b7a64565eff3a8eca1306f06082b0601050507010104633061302e06082b060105050730018622687474703a2f2f6f6373702e696e742d78332e6c657473656e63727970742e6f7267302f06082b060105050730028623687474703a2f2f636572742e696e742d78332e6c657473656e63727970742e6f72672f30130603551d11040c300a82086a756e74732e696f304c0603551d20044530433008060667810c0102013037060b2b0601040182df130101013028302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727970742e6f72673013060a2b06010401d6790204030101ff04020500300d06092a864886f70d01010b0500038201010035f9d6620874966f2aa400f069c5f601dc11083f5859a15d20e9b1d2f9d87d3756a71a03cee0ab2a69b5173a4395b698163ba60394167c9eb4b66d20d9b3a76bf94995288e8d15c70bee969f77a71147718803e73df0a7832c1fcae1e3138601ebc61725bc7505c6d1e5b0eaf7797e09161d71e37d76370dc489312b1bf0600d1c952f846edb810c284c0d831f27481a8f2220ad178c87d8c4688023fa3798293dc9fdffa9e5b885a8107d8a2480226cd5f9121d6d7ea83b10292371ad6757e7729b27136a064f2901822b4f0ea52f8149a17860e37d3dc925488b1ba4aa26ef51e60de024e67e3d5e04ac97d8bd79a003e668ea2e1bd1c0b9d77c7cf7bfdc32"

	logLine := func(typ orphanType, der, regID, orderID string) string {
		return fmt.Sprintf(
			"0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: "+
				"[AUDIT] Failed RPC to store at SA, orphaning %s: "+
				"cert=[%s] err=[context deadline exceeded], regID=[%s], orderID=[%s]",
			typ, der, regID, orderID)
	}

	testCases := []struct {
		Name           string
		LogLine        string
		ExpectFound    bool
		ExpectAdded    bool
		ExpectNoErrors bool
		ExpectAddedDER string
		ExpectRegID    int
	}{
		{
			Name:           "Empty line",
			LogLine:        "",
			ExpectFound:    false,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Empty cert in line",
			LogLine:        logLine(certOrphan, "", "1337", "0"),
			ExpectFound:    true,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Invalid cert in line",
			LogLine:        logLine(certOrphan, "deadbeef", "", ""),
			ExpectFound:    true,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Valid cert in line",
			LogLine:        logLine(certOrphan, testCertDER, "1001", "0"),
			ExpectFound:    true,
			ExpectAdded:    true,
			ExpectAddedDER: testCertDER,
			ExpectRegID:    1001,
			ExpectNoErrors: true,
		},
		{
			Name:        "Already inserted cert in line",
			LogLine:     logLine(certOrphan, testCertDER, "1001", "0"),
			ExpectFound: true,
			// ExpectAdded is false because we have already added this cert in the
			// previous "Valid cert in line" test case.
			ExpectAdded:    false,
			ExpectNoErrors: true,
		},
		{
			Name:           "Empty precert in line",
			LogLine:        logLine(precertOrphan, "", "1337", "0"),
			ExpectFound:    true,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Invalid precert in line",
			LogLine:        logLine(precertOrphan, "deadbeef", "", ""),
			ExpectFound:    true,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Valid precert in line",
			LogLine:        logLine(precertOrphan, testPreCertDER, "9999", "0"),
			ExpectFound:    true,
			ExpectAdded:    true,
			ExpectAddedDER: testPreCertDER,
			ExpectRegID:    9999,
			ExpectNoErrors: true,
		},
		{
			Name:        "Already inserted precert in line",
			LogLine:     logLine(precertOrphan, testPreCertDER, "1001", "0"),
			ExpectFound: true,
			// ExpectAdded is false because we have already added this cert in the
			// previous "Valid cert in line" test case.
			ExpectAdded:    false,
			ExpectNoErrors: true,
		},
		{
			Name:           "Unknown orphan type",
			LogLine:        logLine(unknownOrphan, testPreCertDER, "1001", "0"),
			ExpectFound:    false,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			log.Clear()
			found, added, typ := storeParsedLogLine(sa, ca, log, tc.LogLine)
			test.AssertEquals(t, found, tc.ExpectFound)
			test.AssertEquals(t, added, tc.ExpectAdded)
			logs := log.GetAllMatching("ERR:")
			if tc.ExpectNoErrors {
				test.AssertEquals(t, len(logs), 0)
			}

			if tc.ExpectAdded {
				// Decode the precert/cert DER we expect the testcase added to get the
				// certificate serial
				der, _ := hex.DecodeString(tc.ExpectAddedDER)
				testCert, _ := x509.ParseCertificate(der)
				testCertSerial := core.SerialToString(testCert.SerialNumber)

				// Fetch the precert/cert using the correct mock SA function
				var storedCert core.Certificate
				switch typ {
				case precertOrphan:
					resp, err := sa.GetPrecertificate(context.Background(), &sapb.Serial{Serial: testCertSerial})
					test.AssertNotError(t, err, "Error getting test precert serial from SA")
					precert, err := bgrpc.PBToCert(resp)
					test.AssertNotError(t, err, "Error getting test precert from GetPrecertificate pb response")
					storedCert = precert
				case certOrphan:
					cert, err := sa.GetCertificate(context.Background(), testCertSerial)
					test.AssertNotError(t, err, "Error getting test cert serial from SA")
					storedCert = cert
				default:
					t.Fatalf("unknown orphan type returned: %s", typ)
				}
				// The orphan should have been added with the correct registration ID from the log line
				test.AssertEquals(t, storedCert.RegistrationID, int64(tc.ExpectRegID))
				// The Issued timestamp should be the certificate's NotBefore timestamp offset by the backdateDuration
				expectedIssued := testCert.NotBefore.Add(backdateDuration)
				test.Assert(t, storedCert.Issued.Equal(expectedIssued),
					fmt.Sprintf("stored cert issued date (%s) was not equal to expected (%s)",
						storedCert.Issued, expectedIssued))
			}
		})
	}
}

func TestNotOrphan(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	sa := &mockSA{}
	ca := &mockCA{}

	log.Clear()
	found, added, typ := storeParsedLogLine(sa, ca, log, "cert=fakeout")
	test.AssertEquals(t, found, false)
	test.AssertEquals(t, added, false)
	test.AssertEquals(t, typ, unknownOrphan)
	checkNoErrors(t)
}
