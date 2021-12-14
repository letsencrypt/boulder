package wfe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/nonce"
	"github.com/letsencrypt/boulder/probs"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
	vapb "github.com/letsencrypt/boulder/va/proto"
	"github.com/letsencrypt/boulder/web"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"gopkg.in/square/go-jose.v2"
)

const (
	agreementURL = "http://example.invalid/terms"

	test1KeyPrivatePEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyNWVhtYEKJR21y9xsHV+PD/bYwbXSeNuFal46xYxVfRL5mqh
a7vttvjB/vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K/klBYN8oYvTwwmeSkAz
6ut7ZxPv+nZaT5TJhGk0NT2kh/zSpdriEJ/3vW+mqxYbbBmpvHqsa1/zx9fSuHYc
tAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV+mzfMyboQjujPh7aNJxAWS
q4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF+w8hOTI3XXohUdu
29Se26k2B0PolDSuj0GIQU6+W9TdLXSjBb2SpQIDAQABAoIBAHw58SXYV/Yp72Cn
jjFSW+U0sqWMY7rmnP91NsBjl9zNIe3C41pagm39bTIjB2vkBNR8ZRG7pDEB/QAc
Cn9Keo094+lmTArjL407ien7Ld+koW7YS8TyKADYikZo0vAK3qOy14JfQNiFAF9r
Bw61hG5/E58cK5YwQZe+YcyBK6/erM8fLrJEyw4CV49wWdq/QqmNYU1dx4OExAkl
KMfvYXpjzpvyyTnZuS4RONfHsO8+JTyJVm+lUv2x+bTce6R4W++UhQY38HakJ0x3
XRfXooRv1Bletu5OFlpXfTSGz/5gqsfemLSr5UHncsCcFMgoFBsk2t/5BVukBgC7
PnHrAjkCgYEA887PRr7zu3OnaXKxylW5U5t4LzdMQLpslVW7cLPD4Y08Rye6fF5s
O/jK1DNFXIoUB7iS30qR7HtaOnveW6H8/kTmMv/YAhLO7PAbRPCKxxcKtniEmP1x
ADH0tF2g5uHB/zeZhCo9qJiF0QaJynvSyvSyJFmY6lLvYZsAW+C+PesCgYEA0uCi
Q8rXLzLpfH2NKlLwlJTi5JjE+xjbabgja0YySwsKzSlmvYJqdnE2Xk+FHj7TCnSK
KUzQKR7+rEk5flwEAf+aCCNh3W4+Hp9MmrdAcCn8ZsKmEW/o7oDzwiAkRCmLw/ck
RSFJZpvFoxEg15riT37EjOJ4LBZ6SwedsoGA/a8CgYEA2Ve4sdGSR73/NOKZGc23
q4/B4R2DrYRDPhEySnMGoPCeFrSU6z/lbsUIU4jtQWSaHJPu4n2AfncsZUx9WeSb
OzTCnh4zOw33R4N4W8mvfXHODAJ9+kCc1tax1YRN5uTEYzb2dLqPQtfNGxygA1DF
BkaC9CKnTeTnH3TlKgK8tUcCgYB7J1lcgh+9ntwhKinBKAL8ox8HJfkUM+YgDbwR
sEM69E3wl1c7IekPFvsLhSFXEpWpq3nsuMFw4nsVHwaGtzJYAHByhEdpTDLXK21P
heoKF1sioFbgJB1C/Ohe3OqRLDpFzhXOkawOUrbPjvdBM2Erz/r11GUeSlpNazs7
vsoYXQKBgFwFM1IHmqOf8a2wEFa/a++2y/WT7ZG9nNw1W36S3P04K4lGRNRS2Y/S
snYiqxD9nL7pVqQP2Qbqbn0yD6d3G5/7r86F7Wu2pihM8g6oyMZ3qZvvRIBvKfWo
eROL1ve1vmQF3kjrMPhhK2kr6qdWnTE5XlPllVSZFQenSTzj98AO
-----END RSA PRIVATE KEY-----
`

	test2KeyPublicJSON = `{
		"kty":"RSA",
		"n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw",
		"e":"AQAB"
	}`

	test2KeyPrivatePEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqnARLrT7Xz4gRcKyLdydmCr+ey9OuPImX4X40thk3on26FkM
znR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBr
hR6uIoO4jAzJZR+ChzZuSDt7iHN+3xUVspu5XGwXU/MVJZshTwp4TaFx5elHIT/O
bnTvTOU3Xhish07AbgZKmWsVbXh5s+CrIicU4OexJPgunWZ/YJJueOKmTvnLlTV4
MzKR2oZlBKZ27S0+SfdV/QDx/ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY/2Uzi5
eX0lTc7MPRwz6qR1kip+i59VcGcUQgqHV6FyqwIDAQABAoIBAG5m8Xpj2YC0aYtG
tsxmX9812mpJFqFOmfS+f5N0gMJ2c+3F4TnKz6vE/ZMYkFnehAT0GErC4WrOiw68
F/hLdtJM74gQ0LGh9dKeJmz67bKqngcAHWW5nerVkDGIBtzuMEsNwxofDcIxrjkr
G0b7AHMRwXqrt0MI3eapTYxby7+08Yxm40mxpSsW87FSaI61LDxUDpeVkn7kolSN
WifVat7CpZb/D2BfGAQDxiU79YzgztpKhbynPdGc/OyyU+CNgk9S5MgUX2m9Elh3
aXrWh2bT2xzF+3KgZdNkJQcdIYVoGq/YRBxlGXPYcG4Do3xKhBmH79Io2BizevZv
nHkbUGECgYEAydjb4rl7wYrElDqAYpoVwKDCZAgC6o3AKSGXfPX1Jd2CXgGR5Hkl
ywP0jdSLbn2v/jgKQSAdRbYuEiP7VdroMb5M6BkBhSY619cH8etoRoLzFo1GxcE8
Y7B598VXMq8TT+TQqw/XRvM18aL3YDZ3LSsR7Gl2jF/sl6VwQAaZToUCgYEA2Cn4
fG58ME+M4IzlZLgAIJ83PlLb9ip6MeHEhUq2Dd0In89nss7Acu0IVg8ES88glJZy
4SjDLGSiuQuoQVo9UBq/E5YghdMJFp5ovwVfEaJ+ruWqOeujvWzzzPVyIWSLXRQa
N4kedtfrlqldMIXywxVru66Q1NOGvhDHm/Q8+28CgYEAkhLCbn3VNed7A9qidrkT
7OdqRoIVujEDU8DfpKtK0jBP3EA+mJ2j4Bvoq4uZrEiBSPS9VwwqovyIstAfX66g
Qv95IK6YDwfvpawUL9sxB3ZU/YkYIp0JWwun+Mtzo1ZYH4V0DZfVL59q9of9hj9k
V+fHfNOF22jAC67KYUtlPxECgYEAwF6hj4L3rDqvQYrB/p8tJdrrW+B7dhgZRNkJ
fiGd4LqLGUWHoH4UkHJXT9bvWNPMx88YDz6qapBoq8svAnHfTLFwyGp7KP1FAkcZ
Kp4KG/SDTvx+QCtvPX1/fjAUUJlc2QmxxyiU3uiK9Tpl/2/FOk2O4aiZpX1VVUIz
kZuKxasCgYBiVRkEBk2W4Ia0B7dDkr2VBrz4m23Y7B9cQLpNAapiijz/0uHrrCl8
TkLlEeVOuQfxTadw05gzKX0jKkMC4igGxvEeilYc6NR6a4nvRulG84Q8VV9Sy9Ie
wk6Oiadty3eQqSBJv0HnpmiEdQVffIK5Pg4M8Dd+aOBnEkbopAJOuA==
-----END RSA PRIVATE KEY-----
`
	test3KeyPrivatePEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuTQER6vUA1RDixS8xsfCRiKUNGRzzyIK0MhbS2biClShbb0h
Sx2mPP7gBvis2lizZ9r+y9hL57kNQoYCKndOBg0FYsHzrQ3O9AcoV1z2Mq+XhHZb
FrVYaXI0M3oY9BJCWog0dyi3XC0x8AxC1npd1U61cToHx+3uSvgZOuQA5ffEn5L3
8Dz1Ti7OV3E4XahnRJvejadUmTkki7phLBUXm5MnnyFm0CPpf6ApV7zhLjN5W+nV
0WL17o7v8aDgV/t9nIdi1Y26c3PlCEtiVHZcebDH5F1Deta3oLLg9+g6rWnTqPbY
3knffhp4m0scLD6e33k8MtzxDX/D7vHsg0/X1wIDAQABAoIBAQCnFJpX3lhiuH5G
1uqHmmdVxpRVv9oKn/eJ63cRSzvZfgg0bE/A6Hq0xGtvXqDySttvck4zsGqqHnQr
86G4lfE53D1jnv4qvS5bUKnARwmFKIxU4EHE9s1QM8uMNTaV2nMqIX7TkVP6QHuw
yB70R2inq15dS7EBWVGFKNX6HwAAdj8pFuF6o2vIwmAfee20aFzpWWf81jOH9Ai6
hyJyV3NqrU1JzIwlXaeX67R1VroFdhN/lapp+2b0ZEcJJtFlcYFl99NjkQeVZyik
izNv0GZZNWizc57wU0/8cv+jQ2f26ltvyrPz3QNK61bFfzy+/tfMvLq7sdCmztKJ
tMxCBJOBAoGBAPKnIVQIS2nTvC/qZ8ajw1FP1rkvYblIiixegjgfFhM32HehQ+nu
3TELi3I3LngLYi9o6YSqtNBmdBJB+DUAzIXp0TdOihOweGiv5dAEWwY9rjCzMT5S
GP7dCWiJwoMUHrOs1Po3dwcjj/YsoAW+FC0jSvach2Ln2CvPgr5FP0ARAoGBAMNj
64qUCzgeXiSyPKK69bCCGtHlTYUndwHQAZmABjbmxAXZNYgp/kBezFpKOwmICE8R
kK8YALRrL0VWXl/yj85b0HAZGkquNFHPUDd1e6iiP5TrY+Hy4oqtlYApjH6f85CE
lWjQ1iyUL7aT6fcSgzq65ZWD2hUzvNtWbTt6zQFnAoGAWS/EuDY0QblpOdNWQVR/
vasyqO4ZZRiccKJsCmSioH2uOoozhBAfjJ9JqblOgyDr/bD546E6xD5j+zH0IMci
ZTYDh+h+J659Ez1Topl3O1wAYjX6q4VRWpuzkZDQxYznm/KydSVdwmn3x+uvBW1P
zSdjrjDqMhg1BCVJUNXy4YECgYEAjX1z+dwO68qB3gz7/9NnSzRL+6cTJdNYSIW6
QtAEsAkX9iw+qaXPKgn77X5HljVd3vQXU9QL3pqnloxetxhNrt+p5yMmeOIBnSSF
MEPxEkK7zDlRETPzfP0Kf86WoLNviz2XfFmOXqXIj2w5RuOvB/6DdmwOpr/aiPLj
EulwPw0CgYAMSzsWOt6vU+y/G5NyhUCHvY50TdnGOj2btBk9rYVwWGWxCpg2QF0R
pcKXgGzXEVZKFAqB8V1c/mmCo8ojPgmqGM+GzX2Bj4seVBW7PsTeZUjrHpADshjV
F7o5b7y92NlxO5kwQzRKEAhwS5PbKJdx90iCuG+JlI1YgWlA1VcJMw==
-----END RSA PRIVATE KEY-----
`

	test4KeyPrivatePEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqih+cx32M0wq8MhhN+kBi2xPE+wnw4/iIg1hWO5wtBfpt2Pt
WikgPuBT6jvK9oyQwAWbSfwqlVZatMPY/+3IyytMNb9R9OatNr6o5HROBoyZnDVS
iC4iMRd7bRl/PWSIqj/MjhPNa9cYwBdW5iC3jM5TaOgmp0+YFm4tkLGirDcIBDkQ
Ylnv9NKILvuwqkapZ7XBixeqdCcikUcTRXW5unqygO6bnapzw+YtPsPPlj4Ih3Sv
K4doyziPV96U8u5lbNYYEzYiW1mbu9n0KLvmKDikGcdOpf6+yRa/10kMZyYQatY1
eclIKI0xb54kbluEl0GQDaL5FxLmiKeVnsapzwIDAQABAoIBAQCYWNsmTHwjX53O
qUnJ2jfE0ftXNghAIvHvVRWEny+PPx3FUZWwNMQnJ4haXqCQ8DelhR+NNVYXERLz
Z6pBMm+l4CVCtgI2B9ar/jaPHMbDPF1IK8GyJcP9Oi4K91oh6IIoFCkcSASS+imx
yvPF5SMR0aWCduAsyqm743euZizkjIZ4ZzjJzhvtO17BLXpjD2Al8CBfeaaPFfPB
X86BRH5khuNaRbjG9MVg4h+D752/PuivE6+wBW+F2CYCbFMCYTFSFyHzrVdkw59C
RbHl6Pk7aTA9z0CR3zNI5k0bGd6z/o0rMei6tWO5OBTQRq5tpW9Gim0uVLH/XJlf
XmJoze+RAoGBAMNrcbPlWlSpd3C1fwYiztXwIe7TaaJIpQ+UhCZE2NuXmEZFGqD5
5mrZYV3iIq1cDdeV/BkzkB8ggEuQusZ4d7JfEw/j6I8C3ZRmw4W/bb8LPJMX3Ea7
SgzFv9e+PqqX/3oHZvUN+kH1FSI+UDpkIdegqUBUyWPvd98SDH0/HaY5AoGBAN7o
SfwWExIPEYQvpPjiSVxPuuv50z0BZB+vrQL6U2y4FIohuYSfBVvMiy/Q3Coo2yej
Js4M2bj79lGG86/E+ejdN/YExKWK7qiVnVkOjKnQeJ+bm0+aQWxgetN7RCosqu4T
Dp+Ih2fmhH9r5CInWjbY8js41c/KmYeMa9ZsehBHAoGAdNGg6eJ8KkoYDXdh1MAw
FvHyxvr4lbuJeJPWn63eWP75V2Bt97cLx+nk66OICUwTNkIBrusFB6Z9Ky78iDJx
k16EXaZnWj5jSRhZX3W83EySTHgiBOJm9NWtxgGDIqW0YjVUlb9iT9V7aboIaa98
D5OKOdu1fBkl9mKqtqBpT/kCgYAugjT9nfV4rSAwfmhjbYN0+UW8+rEyZ1nmqpbk
qipB4t6WO5cjrrJFhxX7cg6d1Ux0prvv/gpnaFrqg8fQgr7J8W49rJ0DFUvabO0Z
qcl7nP2t/5+WKk9AN5kpCu0cB5nadqt0ad4mtZgrpe1BmwhdrUJNTPx/kHwcJhZR
9Ow6/QKBgGzypcqehhIKPjOR7PR8uf0Lb8j5hlLH5akfxVDlUozr5j68cZA3nPW9
ikuuM4LqU1dlaAp+c51nye7t4hhIw+JtGSWI2fl5NXxB71LOTvN/sN6sGCbNG3pe
xxBoTncDuGtTpubGbzBrY5W1SlNm1gqu9oQa23WNViN2Rc4aIVm3
-----END RSA PRIVATE KEY-----
`

	testE1KeyPrivatePEM = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIH+p32RUnqT/iICBEGKrLIWFcyButv0S0lU/BLPOyHn2oAoGCCqGSM49
AwEHoUQDQgAEFwvSZpu06i3frSk/mz9HcD9nETn4wf3mQ+zDtG21GapLytH7R1Zr
ycBzDV9u6cX9qNLc9Bn5DAumz7Zp2AuA+Q==
-----END EC PRIVATE KEY-----
`

	testE2KeyPublicJSON = `{
    "kty":"EC",
    "crv":"P-256",
    "x":"S8FOmrZ3ywj4yyFqt0etAD90U-EnkNaOBSLfQmf7pNg",
    "y":"vMvpDyqFDRHjGfZ1siDOm5LS6xNdR5xTpyoQGLDOX2Q"
  }`
	testE2KeyPrivatePEM = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFRcPxQ989AY6se2RyIoF1ll9O6gHev4oY15SWJ+Jf5eoAoGCCqGSM49
AwEHoUQDQgAES8FOmrZ3ywj4yyFqt0etAD90U+EnkNaOBSLfQmf7pNi8y+kPKoUN
EeMZ9nWyIM6bktLrE11HnFOnKhAYsM5fZA==
-----END EC PRIVATE KEY-----`
)

type MockRegistrationAuthority struct {
	lastRevocationReason revocation.Reason
}

func (ra *MockRegistrationAuthority) NewRegistration(ctx context.Context, in *corepb.Registration, _ ...grpc.CallOption) (*corepb.Registration, error) {
	return in, nil
}

func (ra *MockRegistrationAuthority) NewAuthorization(ctx context.Context, in *rapb.NewAuthorizationRequest, _ ...grpc.CallOption) (*corepb.Authorization, error) {
	in.Authz.RegistrationID = in.RegID
	in.Authz.Id = "1"
	in.Authz.Status = string(core.StatusValid)
	in.Authz.Expires = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	return in.Authz, nil
}

func (ra *MockRegistrationAuthority) NewCertificate(context.Context, *rapb.NewCertificateRequest, ...grpc.CallOption) (*corepb.Certificate, error) {
	return &corepb.Certificate{}, nil
}

func (ra *MockRegistrationAuthority) UpdateRegistration(ctx context.Context, in *rapb.UpdateRegistrationRequest, _ ...grpc.CallOption) (*corepb.Registration, error) {
	if !bytes.Equal(in.Base.Key, in.Update.Key) {
		in.Base.Key = in.Update.Key
	}
	return in.Base, nil
}

func (ra *MockRegistrationAuthority) PerformValidation(context.Context, *rapb.PerformValidationRequest, ...grpc.CallOption) (*corepb.Authorization, error) {
	return nil, nil
}

func (ra *MockRegistrationAuthority) RevokeCertificateWithReg(ctx context.Context, in *rapb.RevokeCertificateWithRegRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	ra.lastRevocationReason = revocation.Reason(in.Code)
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) AdministrativelyRevokeCertificate(context.Context, *rapb.AdministrativelyRevokeCertificateRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) OnValidationUpdate(context.Context, core.Authorization, ...grpc.CallOption) error {
	return nil
}

func (ra *MockRegistrationAuthority) DeactivateAuthorization(context.Context, *corepb.Authorization, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) DeactivateRegistration(context.Context, *corepb.Registration, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) NewOrder(context.Context, *rapb.NewOrderRequest, ...grpc.CallOption) (*corepb.Order, error) {
	return nil, nil
}

func (ra *MockRegistrationAuthority) FinalizeOrder(context.Context, *rapb.FinalizeOrderRequest, ...grpc.CallOption) (*corepb.Order, error) {
	return nil, nil
}

type mockPA struct{}

func (pa *mockPA) ChallengesFor(identifier identifier.ACMEIdentifier) (challenges []core.Challenge, err error) {
	return
}

func (pa *mockPA) WillingToIssue(id identifier.ACMEIdentifier) error {
	return nil
}

func (pa *mockPA) WillingToIssueWildcards(idents []identifier.ACMEIdentifier) error {
	return nil
}

func (pa *mockPA) ChallengeTypeEnabled(t core.AcmeChallenge) bool {
	return true
}

func makeBody(s string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(s))
}

// loadPrivateKey loads a private key from PEM/DER-encoded data.
// Duplicates functionality from jose v1's util.LoadPrivateKey function. It was
// moved to the jose-util cmd's main package in v2.
func loadPrivateKey(t *testing.T, keyBytes []byte) interface{} {
	// pem.Decode does not return an error as its 2nd arg, but instead the "rest"
	// that was leftover from parsing the PEM block. We only care if the decoded
	// PEM block was empty for this test function.
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		t.Fatal("Unable to decode private key PEM bytes")
	}

	var privKey interface{}
	// Try decoding as an RSA private key
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privKey
	}

	// Try decoding as a PKCS8 private key
	privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return privKey
	}

	// Try as an ECDSA private key
	privKey, err = x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return privKey
	}

	// Nothing worked! Fail hard.
	t.Fatal("Unable to decode private key PEM bytes")
	// NOOP - the t.Fatal() call will abort before this return
	return nil
}

// newJoseSigner takes a key and a nonce service and constructs an appropriately
// configured jose.Signer. If anything goes wrong it uses the testing.T object
// to fail fatally.
func newJoseSigner(t *testing.T, key interface{}, ns *nonce.NonceService) jose.Signer {
	var algorithm jose.SignatureAlgorithm

	switch key.(type) {
	case *rsa.PrivateKey:
		algorithm = jose.RS256
	case *ecdsa.PrivateKey:
		algorithm = jose.ES256
	default:
		t.Fatal("Unsupported key type")
	}

	opts := &jose.SignerOptions{
		EmbedJWK: true,
	}
	if ns != nil {
		opts.NonceSource = ns
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Key:       key,
		Algorithm: algorithm,
	}, opts)
	test.AssertNotError(t, err, "Failed to make signer")
	return signer
}

func signRequest(t *testing.T, req string, nonceService *nonce.NonceService) string {
	accountKey := loadPrivateKey(t, []byte(test1KeyPrivatePEM))
	signer := newJoseSigner(t, accountKey, nonceService)
	result, err := signer.Sign([]byte(req))
	test.AssertNotError(t, err, "Failed to sign req")
	ret := result.FullSerialize()
	return ret
}

var testKeyPolicy = goodkey.KeyPolicy{
	AllowRSA:           true,
	AllowECDSANISTP256: true,
	AllowECDSANISTP384: true,
}

var ctx = context.Background()

func setupWFE(t *testing.T) (WebFrontEndImpl, clock.FakeClock) {
	features.Reset()

	fc := clock.NewFake()
	stats := metrics.NoopRegisterer

	wfe, err := NewWebFrontEndImpl(stats, fc, testKeyPolicy, nil, nil, blog.NewMock())
	test.AssertNotError(t, err, "Unable to create WFE")
	wfe.IssuerCert, err = issuance.LoadCertificate("../test/test-ca.pem")
	test.AssertNotError(t, err, "Unable to load issuer certificate")

	wfe.SubscriberAgreementURL = agreementURL

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = mocks.NewStorageAuthority(fc)

	return wfe, fc
}

// makePostRequest creates an http.Request with method POST, the provided body,
// and the correct Content-Length.
func makePostRequest(body string) *http.Request {
	return &http.Request{
		Method:     "POST",
		RemoteAddr: "1.1.1.1:7882",
		Header: map[string][]string{
			"Content-Length": {strconv.Itoa(len(body))},
		},
		Body: makeBody(body),
	}
}

func makePostRequestWithPath(path string, body string) *http.Request {
	request := makePostRequest(body)
	request.URL = mustParseURL(path)
	return request
}

func mustParseURL(s string) *url.URL {
	if u, err := url.Parse(s); err != nil {
		panic("Cannot parse URL " + s)
	} else {
		return u
	}
}

func sortHeader(s string) string {
	a := strings.Split(s, ", ")
	sort.Strings(a)
	return strings.Join(a, ", ")
}

func addHeadIfGet(s []string) []string {
	for _, a := range s {
		if a == "GET" {
			return append(s, "HEAD")
		}
	}
	return s
}

const randomKey = "random-key"

func replaceRandomKey(b []byte) []byte {
	var gotMap map[string]interface{}
	var _ = json.Unmarshal(b, &gotMap)
	var key string
	for k, v := range gotMap {
		if v == randomDirKeyExplanationLink {
			key = k
			break
		}
	}
	if key != "" {
		delete(gotMap, key)
		gotMap[randomKey] = randomDirKeyExplanationLink
		b, _ = json.Marshal(gotMap)
		return b
	}
	return b
}

func TestHandleFunc(t *testing.T) {
	wfe, _ := setupWFE(t)
	var mux *http.ServeMux
	var rw *httptest.ResponseRecorder
	var stubCalled bool
	runWrappedHandler := func(req *http.Request, allowed ...string) {
		mux = http.NewServeMux()
		rw = httptest.NewRecorder()
		stubCalled = false
		wfe.HandleFunc(mux, "/test", func(context.Context, *web.RequestEvent, http.ResponseWriter, *http.Request) {
			stubCalled = true
		}, allowed...)
		req.URL = mustParseURL("/test")
		mux.ServeHTTP(rw, req)
	}

	// Plain requests (no CORS)
	type testCase struct {
		allowed        []string
		reqMethod      string
		shouldCallStub bool
		shouldSucceed  bool
	}
	var lastNonce string
	for _, c := range []testCase{
		{[]string{"GET", "POST"}, "GET", true, true},
		{[]string{"GET", "POST"}, "POST", true, true},
		{[]string{"GET"}, "", false, false},
		{[]string{"GET"}, "POST", false, false},
		{[]string{"GET"}, "OPTIONS", false, true},
		{[]string{"GET"}, "MAKE-COFFEE", false, false}, // 405, or 418?
	} {
		runWrappedHandler(&http.Request{Method: c.reqMethod}, c.allowed...)
		test.AssertEquals(t, stubCalled, c.shouldCallStub)
		if c.shouldSucceed {
			test.AssertEquals(t, rw.Code, http.StatusOK)
		} else {
			test.AssertEquals(t, rw.Code, http.StatusMethodNotAllowed)
			test.AssertEquals(t, sortHeader(rw.Header().Get("Allow")), sortHeader(strings.Join(addHeadIfGet(c.allowed), ", ")))
			test.AssertUnmarshaledEquals(t,
				rw.Body.String(),
				`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Method not allowed","status":405}`)
		}
		nonce := rw.Header().Get("Replay-Nonce")
		test.AssertNotEquals(t, nonce, lastNonce)
		test.AssertNotEquals(t, nonce, "")
		lastNonce = nonce
	}

	// Disallowed method returns error JSON in body
	runWrappedHandler(&http.Request{Method: "PUT"}, "GET", "POST")
	test.AssertEquals(t, rw.Header().Get("Content-Type"), "application/problem+json")
	test.AssertUnmarshaledEquals(t, rw.Body.String(), `{"type":"`+probs.V1ErrorNS+`malformed","detail":"Method not allowed","status":405}`)
	test.AssertEquals(t, sortHeader(rw.Header().Get("Allow")), "GET, HEAD, POST")

	// Disallowed method special case: response to HEAD has got no body
	runWrappedHandler(&http.Request{Method: "HEAD"}, "GET", "POST")
	test.AssertEquals(t, stubCalled, true)
	test.AssertEquals(t, rw.Body.String(), "")

	// HEAD doesn't work with POST-only endpoints
	runWrappedHandler(&http.Request{Method: "HEAD"}, "POST")
	test.AssertEquals(t, stubCalled, false)
	test.AssertEquals(t, rw.Code, http.StatusMethodNotAllowed)
	test.AssertEquals(t, rw.Header().Get("Content-Type"), "application/problem+json")
	test.AssertEquals(t, rw.Header().Get("Allow"), "POST")
	test.AssertUnmarshaledEquals(t, rw.Body.String(), `{"type":"`+probs.V1ErrorNS+`malformed","detail":"Method not allowed","status":405}`)

	wfe.AllowOrigins = []string{"*"}
	testOrigin := "https://example.com"

	// CORS "actual" request for disallowed method
	runWrappedHandler(&http.Request{
		Method: "POST",
		Header: map[string][]string{
			"Origin": {testOrigin},
		},
	}, "GET")
	test.AssertEquals(t, stubCalled, false)
	test.AssertEquals(t, rw.Code, http.StatusMethodNotAllowed)

	// CORS "actual" request for allowed method
	runWrappedHandler(&http.Request{
		Method: "GET",
		Header: map[string][]string{
			"Origin": {testOrigin},
		},
	}, "GET", "POST")
	test.AssertEquals(t, stubCalled, true)
	test.AssertEquals(t, rw.Code, http.StatusOK)
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Methods"), "")
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "*")
	test.AssertEquals(t, sortHeader(rw.Header().Get("Access-Control-Expose-Headers")), "Link, Replay-Nonce")

	// CORS preflight request for disallowed method
	runWrappedHandler(&http.Request{
		Method: "OPTIONS",
		Header: map[string][]string{
			"Origin":                        {testOrigin},
			"Access-Control-Request-Method": {"POST"},
		},
	}, "GET")
	test.AssertEquals(t, stubCalled, false)
	test.AssertEquals(t, rw.Code, http.StatusOK)
	test.AssertEquals(t, rw.Header().Get("Allow"), "GET, HEAD")
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "")

	// CORS preflight request for allowed method
	runWrappedHandler(&http.Request{
		Method: "OPTIONS",
		Header: map[string][]string{
			"Origin":                         {testOrigin},
			"Access-Control-Request-Method":  {"POST"},
			"Access-Control-Request-Headers": {"X-Accept-Header1, X-Accept-Header2", "X-Accept-Header3"},
		},
	}, "GET", "POST")
	test.AssertEquals(t, rw.Code, http.StatusOK)
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "*")
	test.AssertEquals(t, rw.Header().Get("Access-Control-Max-Age"), "86400")
	test.AssertEquals(t, sortHeader(rw.Header().Get("Access-Control-Allow-Methods")), "GET, HEAD, POST")
	test.AssertEquals(t, sortHeader(rw.Header().Get("Access-Control-Expose-Headers")), "Link, Replay-Nonce")

	// OPTIONS request without an Origin header (i.e., not a CORS
	// preflight request)
	runWrappedHandler(&http.Request{
		Method: "OPTIONS",
		Header: map[string][]string{
			"Access-Control-Request-Method": {"POST"},
		},
	}, "GET", "POST")
	test.AssertEquals(t, rw.Code, http.StatusOK)
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "")
	test.AssertEquals(t, sortHeader(rw.Header().Get("Allow")), "GET, HEAD, POST")

	// CORS preflight request missing optional Request-Method
	// header. The "actual" request will be GET.
	for _, allowedMethod := range []string{"GET", "POST"} {
		runWrappedHandler(&http.Request{
			Method: "OPTIONS",
			Header: map[string][]string{
				"Origin": {testOrigin},
			},
		}, allowedMethod)
		test.AssertEquals(t, rw.Code, http.StatusOK)
		if allowedMethod == "GET" {
			test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "*")
			test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Methods"), "GET, HEAD")
		} else {
			test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "")
		}
	}

	// No CORS headers are given when configuration does not list
	// "*" or the client-provided origin.
	for _, wfe.AllowOrigins = range [][]string{
		{},
		{"http://example.com", "https://other.example"},
		{""}, // Invalid origin is never matched
	} {
		runWrappedHandler(&http.Request{
			Method: "OPTIONS",
			Header: map[string][]string{
				"Origin":                        {testOrigin},
				"Access-Control-Request-Method": {"POST"},
			},
		}, "POST")
		test.AssertEquals(t, rw.Code, http.StatusOK)
		for _, h := range []string{
			"Access-Control-Allow-Methods",
			"Access-Control-Allow-Origin",
			"Access-Control-Expose-Headers",
			"Access-Control-Request-Headers",
		} {
			test.AssertEquals(t, rw.Header().Get(h), "")
		}
	}

	// CORS headers are offered when configuration lists "*" or
	// the client-provided origin.
	for _, wfe.AllowOrigins = range [][]string{
		{testOrigin, "http://example.org", "*"},
		{"", "http://example.org", testOrigin}, // Invalid origin is harmless
	} {
		runWrappedHandler(&http.Request{
			Method: "OPTIONS",
			Header: map[string][]string{
				"Origin":                        {testOrigin},
				"Access-Control-Request-Method": {"POST"},
			},
		}, "POST")
		test.AssertEquals(t, rw.Code, http.StatusOK)
		test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), testOrigin)
		// http://www.w3.org/TR/cors/ section 6.4:
		test.AssertEquals(t, rw.Header().Get("Vary"), "Origin")
	}
}

func TestIndexPOST(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()
	url, _ := url.Parse("/")
	wfe.Index(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "POST",
		URL:    url,
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusMethodNotAllowed)
}

func TestPOST404(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()
	url, _ := url.Parse("/foobar")
	wfe.Index(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "POST",
		URL:    url,
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
}

func TestIndex(t *testing.T) {
	wfe, _ := setupWFE(t)

	responseWriter := httptest.NewRecorder()

	url, _ := url.Parse("/")
	wfe.Index(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
		URL:    url,
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertNotEquals(t, responseWriter.Body.String(), "404 page not found\n")
	test.Assert(t, strings.Contains(responseWriter.Body.String(), directoryPath),
		"directory path not found")
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")

	responseWriter.Body.Reset()
	responseWriter.Header().Del("Cache-Control")
	url, _ = url.Parse("/foo")
	wfe.Index(ctx, newRequestEvent(), responseWriter, &http.Request{
		URL: url,
	})
	//test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
	test.AssertEquals(t, responseWriter.Body.String(), "404 page not found\n")
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "")
}

func TestDirectory(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler(metrics.NoopRegisterer)

	responseWriter := httptest.NewRecorder()

	url, _ := url.Parse("/directory")
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    url,
		Host:   "localhost:4300",
	})
	test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/json")
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	body := replaceRandomKey(responseWriter.Body.Bytes())
	test.AssertUnmarshaledEquals(t, string(body), fmt.Sprintf(`{"key-change":"http://localhost:4300/acme/key-change","meta":{"terms-of-service":"http://example.invalid/terms"},"new-authz":"http://localhost:4300/acme/new-authz","new-cert":"http://localhost:4300/acme/new-cert","new-reg":"http://localhost:4300/acme/new-reg","%s":"%s","revoke-cert":"http://localhost:4300/acme/revoke-cert"}`, randomKey, randomDirKeyExplanationLink))

	responseWriter.Body.Reset()
	url, _ = url.Parse("/directory")
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    url,
		Host:   "localhost:4300",
	})
	test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/json")
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	body = replaceRandomKey(responseWriter.Body.Bytes())
	test.AssertUnmarshaledEquals(t, string(body), fmt.Sprintf(`{"key-change":"http://localhost:4300/acme/key-change","meta":{"terms-of-service":"http://example.invalid/terms"},"new-authz":"http://localhost:4300/acme/new-authz","new-cert":"http://localhost:4300/acme/new-cert","new-reg":"http://localhost:4300/acme/new-reg","%s":"%s","revoke-cert":"http://localhost:4300/acme/revoke-cert"}`, randomKey, randomDirKeyExplanationLink))

	// Configure a caaIdentity and website for the /directory meta
	wfe.DirectoryCAAIdentity = "Radiant Lock"
	wfe.DirectoryWebsite = "zombo.com"
	responseWriter = httptest.NewRecorder()
	url, _ = url.Parse("/directory")
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    url,
		Host:   "localhost:4300",
	})
	test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/json")
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	// The directory response should include the CAAIdentities and Website meta
	// elements as expected
	body = replaceRandomKey(responseWriter.Body.Bytes())
	test.AssertUnmarshaledEquals(t, string(body), fmt.Sprintf(`{
  "key-change": "http://localhost:4300/acme/key-change",
  "meta": {
    "caaIdentities": [
      "Radiant Lock"
    ],
    "terms-of-service": "http://example.invalid/terms",
   "website": "zombo.com"
  },
  "%s": "%s",
  "new-authz": "http://localhost:4300/acme/new-authz",
  "new-cert": "http://localhost:4300/acme/new-cert",
  "new-reg": "http://localhost:4300/acme/new-reg",
  "revoke-cert": "http://localhost:4300/acme/revoke-cert"
}`, randomKey, randomDirKeyExplanationLink))

	// if the UA is LetsEncryptPythonClient we expect to *not* see the meta entry,
	// even with the DirectoryCAAIdentity and DirectoryWebsite configured.
	responseWriter.Body.Reset()
	url, _ = url.Parse("/directory")
	headers := map[string][]string{
		"User-Agent": {"LetsEncryptPythonClient"},
	}
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    url,
		Host:   "localhost:4300",
		Header: headers,
	})
	test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/json")
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"new-authz":"http://localhost:4300/acme/new-authz","new-cert":"http://localhost:4300/acme/new-cert","new-reg":"http://localhost:4300/acme/new-reg","revoke-cert":"http://localhost:4300/acme/revoke-cert"}`)
}

func TestRandomDirectoryKey(t *testing.T) {
	wfe, _ := setupWFE(t)

	responseWriter := httptest.NewRecorder()
	url, _ := url.Parse("/directory")
	wfe.Directory(ctx, &web.RequestEvent{}, responseWriter, &http.Request{
		Method: "GET",
		URL:    url,
		Host:   "127.0.0.1:4300",
	})
	test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/json")
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	var dir map[string]interface{}
	if err := json.Unmarshal(responseWriter.Body.Bytes(), &dir); err != nil {
		t.Errorf("Failed to unmarshal directory: %s", err)
	}
	found := false
	for _, v := range dir {
		if v == randomDirKeyExplanationLink {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Failed to find random entry in directory: %s", responseWriter.Body.String())
	}

	responseWriter.Body.Reset()
	headers := map[string][]string{
		"User-Agent": {"LetsEncryptPythonClient"},
	}
	wfe.Directory(ctx, &web.RequestEvent{}, responseWriter, &http.Request{
		Method: "GET",
		URL:    url,
		Host:   "127.0.0.1:4300",
		Header: headers,
	})
	test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/json")
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	dir = map[string]interface{}{}
	if err := json.Unmarshal(responseWriter.Body.Bytes(), &dir); err != nil {
		t.Errorf("Failed to unmarshal directory: %s", err)
	}
	found = false
	for _, v := range dir {
		if v == randomDirKeyExplanationLink {
			found = true
			break
		}
	}
	if found {
		t.Error("Found random entry in directory with 'LetsEncryptPythonClient' UA")
	}
}

// noopCAA implements RA's caaChecker, always returning nil
type noopCAA struct{}

func (cr noopCAA) IsCAAValid(
	ctx context.Context,
	in *vapb.IsCAAValidRequest,
	opts ...grpc.CallOption,
) (*vapb.IsCAAValidResponse, error) {
	return &vapb.IsCAAValidResponse{}, nil
}

func TestRelativeDirectory(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler(metrics.NoopRegisterer)

	dirTests := []struct {
		host        string
		protoHeader string
		result      string
	}{
		// Test '' (No host header) with no proto header
		{"", "", `{"key-change":"http://localhost/acme/key-change","meta":{"terms-of-service": "http://example.invalid/terms"},"new-authz":"http://localhost/acme/new-authz","new-cert":"http://localhost/acme/new-cert","new-reg":"http://localhost/acme/new-reg","%s":"%s","revoke-cert":"http://localhost/acme/revoke-cert"}`},
		// Test localhost:4300 with no proto header
		{"localhost:4300", "", `{"key-change":"http://localhost:4300/acme/key-change","meta":{"terms-of-service": "http://example.invalid/terms"},"new-authz":"http://localhost:4300/acme/new-authz","new-cert":"http://localhost:4300/acme/new-cert","new-reg":"http://localhost:4300/acme/new-reg","%s":"%s","revoke-cert":"http://localhost:4300/acme/revoke-cert"}`},
		// Test 127.0.0.1:4300 with no proto header
		{"127.0.0.1:4300", "", `{"key-change":"http://127.0.0.1:4300/acme/key-change","meta":{"terms-of-service": "http://example.invalid/terms"},"new-authz":"http://127.0.0.1:4300/acme/new-authz","new-cert":"http://127.0.0.1:4300/acme/new-cert","new-reg":"http://127.0.0.1:4300/acme/new-reg","%s":"%s","revoke-cert":"http://127.0.0.1:4300/acme/revoke-cert"}`},
		// Test localhost:4300 with HTTP proto header
		{"localhost:4300", "http", `{"key-change":"http://localhost:4300/acme/key-change","meta":{"terms-of-service": "http://example.invalid/terms"},"new-authz":"http://localhost:4300/acme/new-authz","new-cert":"http://localhost:4300/acme/new-cert","new-reg":"http://localhost:4300/acme/new-reg","%s":"%s","revoke-cert":"http://localhost:4300/acme/revoke-cert"}`},
		// Test localhost:4300 with HTTPS proto header
		{"localhost:4300", "https", `{"key-change":"https://localhost:4300/acme/key-change","meta":{"terms-of-service": "http://example.invalid/terms"},"new-authz":"https://localhost:4300/acme/new-authz","new-cert":"https://localhost:4300/acme/new-cert","new-reg":"https://localhost:4300/acme/new-reg","%s":"%s","revoke-cert":"https://localhost:4300/acme/revoke-cert"}`},
	}

	for _, tt := range dirTests {
		var headers map[string][]string
		responseWriter := httptest.NewRecorder()

		if tt.protoHeader != "" {
			headers = map[string][]string{
				"X-Forwarded-Proto": {tt.protoHeader},
			}
		}

		mux.ServeHTTP(responseWriter, &http.Request{
			Method: "GET",
			Host:   tt.host,
			URL:    mustParseURL(directoryPath),
			Header: headers,
		})
		test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/json")
		test.AssertEquals(t, responseWriter.Code, http.StatusOK)
		body := replaceRandomKey(responseWriter.Body.Bytes())
		test.AssertUnmarshaledEquals(t, string(body), fmt.Sprintf(tt.result, randomKey, randomDirKeyExplanationLink))
	}
}

func TestGetChallenge(t *testing.T) {
	wfe, _ := setupWFE(t)

	challengeURL := "http://localhost/acme/chall-v3/1/-ZfxEw"

	for _, method := range []string{"GET", "HEAD"} {
		resp := httptest.NewRecorder()

		req, err := http.NewRequest(method, challengeURL, nil)
		req.URL.Path = "1/-ZfxEw"
		test.AssertNotError(t, err, "Could not make NewRequest")

		wfe.Challenge(ctx, newRequestEvent(), resp, req)
		test.AssertEquals(t,
			resp.Code,
			http.StatusAccepted)
		test.AssertEquals(t,
			resp.Header().Get("Location"),
			challengeURL)
		test.AssertEquals(t,
			resp.Header().Get("Content-Type"),
			"application/json")
		test.AssertEquals(t,
			resp.Header().Get("Link"),
			`<http://localhost/acme/authz-v3/1>;rel="up"`)
		// Body is only relevant for GET. For HEAD, body will
		// be discarded by HandleFunc() anyway, so it doesn't
		// matter what Challenge() writes to it.
		if method == "GET" {
			test.AssertUnmarshaledEquals(
				t, resp.Body.String(),
				`{"status":"pending","type":"dns","token":"token","uri":"http://localhost/acme/chall-v3/1/-ZfxEw"}`)
		}
	}
}

func TestGetChallengeV2UpRel(t *testing.T) {
	wfe, _ := setupWFE(t)

	challengeURL := "http://localhost/acme/chall-v3/1/-ZfxEw"
	resp := httptest.NewRecorder()

	req, err := http.NewRequest("GET", challengeURL, nil)
	req.URL.Path = "1/-ZfxEw"
	test.AssertNotError(t, err, "Could not make NewRequest")

	wfe.Challenge(ctx, newRequestEvent(), resp, req)
	test.AssertEquals(t,
		resp.Code,
		http.StatusAccepted)
	test.AssertEquals(t,
		resp.Header().Get("Link"),
		`<http://localhost/acme/authz-v3/1>;rel="up"`)
}

func TestChallenge(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	var key jose.JSONWebKey
	err := json.Unmarshal([]byte(`
		{
			"e": "AQAB",
			"kty": "RSA",
			"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
		}
	`), &key)
	test.AssertNotError(t, err, "Could not unmarshal testing key")

	challengeURL := "http://localhost/acme/chall-v3/1/-ZfxEw"
	path := "1/-ZfxEw"
	wfe.Challenge(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath(path,
			signRequest(t, `{"resource":"challenge"}`, wfe.nonceService)))

	test.AssertEquals(t, responseWriter.Code, 202)
	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		challengeURL)
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		`<http://localhost/acme/authz-v3/1>;rel="up"`)
	test.AssertUnmarshaledEquals(
		t, responseWriter.Body.String(),
		`{"status": "pending", "type":"dns","token":"token","uri":"http://localhost/acme/chall-v3/1/-ZfxEw"}`)

	// Expired challenges should be inaccessible
	challengeURL = "3/-ZfxEw"
	responseWriter = httptest.NewRecorder()
	wfe.Challenge(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath(challengeURL,
			signRequest(t, `{"resource":"challenge"}`, wfe.nonceService)))
	test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Expired authorization","status":404}`)

	// Challenge Not found
	challengeURL = ""
	responseWriter = httptest.NewRecorder()
	wfe.Challenge(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath(challengeURL,
			signRequest(t, `{"resource":"challenge"}`, wfe.nonceService)))
	test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"No such challenge","status":404}`)

	// Unspecified database error
	errorURL := "4/-ZfxEw"
	responseWriter = httptest.NewRecorder()
	wfe.Challenge(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath(errorURL,
			signRequest(t, `{"resource":"challenge"}`, wfe.nonceService)))
	test.AssertEquals(t, responseWriter.Code, http.StatusInternalServerError)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`serverInternal","detail":"Problem getting authorization","status":500}`)

}

// MockRAPerformValidationError is a mock RA that just returns an error on
// PerformValidation.
type MockRAPerformValidationError struct {
	MockRegistrationAuthority
}

func (ra *MockRAPerformValidationError) PerformValidation(context.Context, *rapb.PerformValidationRequest, ...grpc.CallOption) (*corepb.Authorization, error) {
	return nil, errors.New("broken on purpose")
}

// TestUpdateChallengeFinalizedAuthz tests that POSTing a challenge associated
// with an already valid authorization just returns the challenge without calling
// the RA.
func TestUpdateChallengeFinalizedAuthz(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.RA = &MockRAPerformValidationError{}
	responseWriter := httptest.NewRecorder()

	path := "1/-ZfxEw"
	wfe.Challenge(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath(path,
			signRequest(t, `{"resource":"challenge"}`, wfe.nonceService)))

	body := responseWriter.Body.String()
	test.AssertUnmarshaledEquals(t, body, `{
		"status": "pending",
		"type": "dns",
		"token":"token",
		"uri": "http://localhost/acme/chall-v3/1/-ZfxEw"
	  }`)
}

// TestUpdateChallengeRAError tests that when the RA returns an error from
// PerformValidation that the WFE returns an internal server error as expected
// and does not panic or otherwise bug out.
func TestUpdateChallengeRAError(t *testing.T) {
	wfe, _ := setupWFE(t)
	// Mock the RA to always fail PerformValidation
	wfe.RA = &MockRAPerformValidationError{}

	// Update a pending challenge
	path := "2/-ZfxEw"
	responseWriter := httptest.NewRecorder()
	wfe.Challenge(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath(path,
			signRequest(t, `{"resource":"challenge"}`, wfe.nonceService)))

	// The result should be an internal server error problem.
	body := responseWriter.Body.String()
	test.AssertUnmarshaledEquals(t, body, `{
		"type": "urn:acme:error:serverInternal",
	  "detail": "Unable to perform validation for challenge",
		"status": 500
	}`)
}

func TestBadNonce(t *testing.T) {
	wfe, _ := setupWFE(t)

	key := loadPrivateKey(t, []byte(test2KeyPrivatePEM))
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	// NOTE: We deliberately set the NonceSource to nil in the newJoseSigner
	// arguments for this test in order to provoke a bad nonce error
	signer := newJoseSigner(t, rsaKey, nil)
	responseWriter := httptest.NewRecorder()
	result, err := signer.Sign([]byte(`{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "Failed to sign body")
	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V1ErrorNS+`badNonce","detail":"JWS has no anti-replay nonce","status":400}`)
}

func TestNewECDSARegistration(t *testing.T) {
	wfe, _ := setupWFE(t)

	// E1 always exists; E2 never exists
	key := loadPrivateKey(t, []byte(testE2KeyPrivatePEM))
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load ECDSA key")
	signer := newJoseSigner(t, ecdsaKey, wfe.nonceService)
	responseWriter := httptest.NewRecorder()
	result, err := signer.Sign([]byte(`{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "Failed to sign")
	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter, makePostRequest(result.FullSerialize()))

	var reg core.Registration
	err = json.Unmarshal(responseWriter.Body.Bytes(), &reg)
	test.AssertNotError(t, err, "Couldn't unmarshal returned registration object")
	test.Assert(t, len(*reg.Contact) >= 1, "No contact field in registration")
	test.AssertEquals(t, (*reg.Contact)[0], "mailto:person@mail.com")
	test.AssertEquals(t, reg.Agreement, "http://example.invalid/terms")
	test.AssertEquals(t, reg.InitialIP.String(), "1.1.1.1")

	test.AssertEquals(t, responseWriter.Header().Get("Location"), "http://localhost/acme/reg/0")

	key = loadPrivateKey(t, []byte(testE1KeyPrivatePEM))
	ecdsaKey, ok = key.(*ecdsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load ECDSA key")

	signer = newJoseSigner(t, ecdsaKey, wfe.nonceService)

	// Reset the body and status code
	responseWriter = httptest.NewRecorder()
	// POST, Valid JSON, Key already in use
	result, err = signer.Sign([]byte(`{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "Failed to signer.Sign")

	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter, makePostRequest(result.FullSerialize()))
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V1ErrorNS+`malformed","detail":"Registration key is already in use","status":409}`)
	test.AssertEquals(t, responseWriter.Header().Get("Location"), "http://localhost/acme/reg/3")
	test.AssertEquals(t, responseWriter.Code, 409)
}

// Test that the WFE handling of the "empty update" POST is correct. The ACME
// spec describes how when clients wish to query the server for information
// about a registration an empty registration update should be sent, and
// a populated reg object will be returned.
func TestEmptyRegistration(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	// Test Key 1 is mocked in the mock StorageAuthority used in setupWFE to
	// return a populated registration for GetRegistrationByKey when test key 1 is
	// used.
	key := loadPrivateKey(t, []byte(test1KeyPrivatePEM))
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")

	signer := newJoseSigner(t, rsaKey, wfe.nonceService)
	emptyReg := `{"resource":"reg"}`
	emptyBody, err := signer.Sign([]byte(emptyReg))
	test.AssertNotError(t, err, "Unable to sign emptyBody")

	// Send a registration update with the trivial body
	wfe.Registration(
		ctx,
		newRequestEvent(),
		responseWriter,
		makePostRequestWithPath("1", emptyBody.FullSerialize()))

	// There should be no error
	test.AssertNotContains(t, responseWriter.Body.String(), probs.V1ErrorNS)

	// We should get back a populated Registration
	var reg core.Registration
	err = json.Unmarshal(responseWriter.Body.Bytes(), &reg)
	test.AssertNotError(t, err, "Couldn't unmarshal returned registration object")
	test.Assert(t, len(*reg.Contact) >= 1, "No contact field in registration")
	test.AssertEquals(t, (*reg.Contact)[0], "mailto:person@mail.com")
	test.AssertEquals(t, reg.Agreement, "http://example.invalid/terms")
	responseWriter.Body.Reset()
}

func TestNewRegistrationForbiddenWithAllowV1RegistrationDisabled(t *testing.T) {
	wfe, _ := setupWFE(t)
	_ = features.Set(map[string]bool{"AllowV1Registration": false})

	// The "test2KeyPrivatePEM" is not already registered, according to our mocks.
	key := loadPrivateKey(t, []byte(test2KeyPrivatePEM))
	signer := newJoseSigner(t, key, wfe.nonceService)
	// Reset the body and status code
	responseWriter := httptest.NewRecorder()
	result, err := signer.Sign([]byte(`{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "Failed to signer.Sign")

	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`unauthorized","detail":"Account creation on ACMEv1 is disabled. Please upgrade your ACME client to a version that supports ACMEv2 / RFC 8555. See https://community.letsencrypt.org/t/end-of-life-plan-for-acmev1/88430 for details.","status":403}`)
}

func TestNewRegistration409sWithAllowV1RegistrationDisabled(t *testing.T) {
	wfe, _ := setupWFE(t)
	_ = features.Set(map[string]bool{"AllowV1Registration": false})

	// The "test2KeyPrivatePEM" is not already registered, according to our mocks.
	key := loadPrivateKey(t, []byte(test1KeyPrivatePEM))
	signer := newJoseSigner(t, key, wfe.nonceService)
	// Reset the body and status code
	responseWriter := httptest.NewRecorder()
	// POST, Valid JSON, Key already in use
	result, err := signer.Sign([]byte(`{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "Failed to signer.Sign")

	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Registration key is already in use","status":409}`)
}

func TestNewRegistration(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler(metrics.NoopRegisterer)
	key := loadPrivateKey(t, []byte(test2KeyPrivatePEM))
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer := newJoseSigner(t, rsaKey, wfe.nonceService)
	fooBody, err := signer.Sign([]byte("foo"))
	test.AssertNotError(t, err, "Unable to sign")

	wrongAgreementBody, err := signer.Sign([]byte(`{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"https://letsencrypt.org/im-bad"}`))
	test.AssertNotError(t, err, "Unable to sign")

	type newRegErrorTest struct {
		r        *http.Request
		respBody string
	}
	regErrTests := []newRegErrorTest{
		// GET instead of POST should be rejected
		{
			&http.Request{
				Method: "GET",
				URL:    mustParseURL(newRegPath),
			},
			`{"type":"` + probs.V1ErrorNS + `malformed","detail":"Method not allowed","status":405}`,
		},

		// POST, but no body.
		{
			&http.Request{
				Method: "POST",
				URL:    mustParseURL(newRegPath),
				Header: map[string][]string{
					"Content-Length": {"0"},
				},
			},
			`{"type":"` + probs.V1ErrorNS + `malformed","detail":"No body on POST","status":400}`,
		},

		// POST, but body that isn't valid JWS
		{
			makePostRequestWithPath(newRegPath, "hi"),
			`{"type":"` + probs.V1ErrorNS + `malformed","detail":"Parse error reading JWS","status":400}`,
		},

		// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
		{
			makePostRequestWithPath(newRegPath, fooBody.FullSerialize()),
			`{"type":"` + probs.V1ErrorNS + `malformed","detail":"Request payload did not parse as JSON","status":400}`,
		},

		// Same signed body, but payload modified by one byte, breaking signature.
		// should fail JWS verification.
		{
			makePostRequestWithPath(newRegPath, `
			{
				"header": {
					"alg": "RS256",
					"jwk": {
						"e": "AQAB",
						"kty": "RSA",
						"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw"
					}
				},
				"payload": "xm9vCg",
				"signature": "RjUQ679fxJgeAJlxqgvDP_sfGZnJ-1RgWF2qmcbnBWljs6h1qp63pLnJOl13u81bP_bCSjaWkelGG8Ymx_X-aQ"
			}
		`),
			`{"type":"` + probs.V1ErrorNS + `malformed","detail":"JWS verification error","status":400}`,
		},
		{
			makePostRequestWithPath(newRegPath, wrongAgreementBody.FullSerialize()),
			`{"type":"` + probs.V1ErrorNS + `malformed","detail":"Provided agreement URL [https://letsencrypt.org/im-bad] does not match current agreement URL [` + agreementURL + `]","status":400}`,
		},
	}
	for _, rt := range regErrTests {
		responseWriter := httptest.NewRecorder()
		mux.ServeHTTP(responseWriter, rt.r)
		test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), rt.respBody)
	}

	responseWriter := httptest.NewRecorder()
	result, err := signer.Sign([]byte(`{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "signer.Sign failed")
	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))

	var reg core.Registration
	err = json.Unmarshal(responseWriter.Body.Bytes(), &reg)
	test.AssertNotError(t, err, "Couldn't unmarshal returned registration object")
	test.Assert(t, len(*reg.Contact) >= 1, "No contact field in registration")
	test.AssertEquals(t, (*reg.Contact)[0], "mailto:person@mail.com")
	test.AssertEquals(t, reg.Agreement, "http://example.invalid/terms")
	test.AssertEquals(t, reg.InitialIP.String(), "1.1.1.1")

	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"http://localhost/acme/reg/0")
	links := responseWriter.Header()["Link"]
	test.AssertEquals(t, contains(links, "<http://localhost/acme/new-authz>;rel=\"next\""), true)
	test.AssertEquals(t, contains(links, "<"+agreementURL+">;rel=\"terms-of-service\""), true)

	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		`<http://localhost/acme/new-authz>;rel="next"`)

	key = loadPrivateKey(t, []byte(test1KeyPrivatePEM))
	rsaKey, ok = key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer = newJoseSigner(t, rsaKey, wfe.nonceService)
	// Reset the body and status code
	responseWriter = httptest.NewRecorder()
	// POST, Valid JSON, Key already in use
	result, err = signer.Sign([]byte(`{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "Failed to signer.Sign")

	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Registration key is already in use","status":409}`)
	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"http://localhost/acme/reg/1")
	test.AssertEquals(t, responseWriter.Code, 409)
}

func makeRevokeRequestJSON(reason *revocation.Reason) ([]byte, error) {
	certPemBytes, err := ioutil.ReadFile("test/238.crt")
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPemBytes)
	if err != nil {
		return nil, err
	}
	revokeRequest := struct {
		Resource       string             `json:"resource"`
		CertificateDER core.JSONBuffer    `json:"certificate"`
		Reason         *revocation.Reason `json:"reason"`
	}{
		Resource:       "revoke-cert",
		CertificateDER: certBlock.Bytes,
		Reason:         reason,
	}
	revokeRequestJSON, err := json.Marshal(revokeRequest)
	if err != nil {
		return nil, err
	}
	return revokeRequestJSON, nil
}

// An SA mock that always returns a berrors.NotFound type error. This is necessary
// because the standard mock in our mocks package always returns a given test
// registration when GetRegistrationByKey is called, and we want to get a
// berrors.NotFound type error for tests that pass regCheck = false to verifyPOST.
type mockSANoSuchRegistration struct {
	sapb.StorageAuthorityGetterClient
}

func (msa mockSANoSuchRegistration) GetRegistrationByKey(_ context.Context, _ *sapb.JSONWebKey, _ ...grpc.CallOption) (*corepb.Registration, error) {
	return nil, berrors.NotFoundError("reg not found")
}

// Valid revocation request for existing, non-revoked cert, signed with cert
// key.
func TestRevokeCertificateCertKey(t *testing.T) {
	wfe, fc := setupWFE(t)

	keyPemBytes, err := ioutil.ReadFile("test/238.key")
	test.AssertNotError(t, err, "Failed to load key")
	key := loadPrivateKey(t, keyPemBytes)
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer := newJoseSigner(t, rsaKey, wfe.nonceService)
	test.AssertNotError(t, err, "Failed to make signer")
	revokeRequestJSON, err := makeRevokeRequestJSON(nil)
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	wfe.SA = &mockSANoSuchRegistration{mocks.NewStorageAuthority(fc)}
	responseWriter := httptest.NewRecorder()

	result, _ := signer.Sign(revokeRequestJSON)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
}

func TestRevokeCertificateReasons(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.SA = &mockSANoSuchRegistration{wfe.SA}
	ra := wfe.RA.(*MockRegistrationAuthority)

	keyPemBytes, err := ioutil.ReadFile("test/238.key")
	test.AssertNotError(t, err, "Failed to load key")
	key := loadPrivateKey(t, keyPemBytes)
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")

	signer := newJoseSigner(t, rsaKey, wfe.nonceService)

	// Valid reason
	responseWriter := httptest.NewRecorder()
	keyComp := revocation.Reason(1)
	revokeRequestJSON, err := makeRevokeRequestJSON(&keyComp)
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	result, _ := signer.Sign(revokeRequestJSON)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
	test.AssertEquals(t, ra.lastRevocationReason, revocation.Reason(1))

	// No reason
	responseWriter = httptest.NewRecorder()
	revokeRequestJSON, err = makeRevokeRequestJSON(nil)
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	result, _ = signer.Sign(revokeRequestJSON)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
	test.AssertEquals(t, ra.lastRevocationReason, revocation.Reason(0))

	// Unsupported reason
	responseWriter = httptest.NewRecorder()
	unsupported := revocation.Reason(2)
	revokeRequestJSON, err = makeRevokeRequestJSON(&unsupported)
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	result, _ = signer.Sign(revokeRequestJSON)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 400)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V1ErrorNS+`malformed","detail":"unsupported revocation reason code provided: cACompromise (2). Supported reasons: unspecified (0), keyCompromise (1), affiliationChanged (3), superseded (4), cessationOfOperation (5)","status":400}`)

	responseWriter = httptest.NewRecorder()
	unsupported = revocation.Reason(100)
	revokeRequestJSON, err = makeRevokeRequestJSON(&unsupported)
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	result, _ = signer.Sign(revokeRequestJSON)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 400)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V1ErrorNS+`malformed","detail":"unsupported revocation reason code provided: unknown (100). Supported reasons: unspecified (0), keyCompromise (1), affiliationChanged (3), superseded (4), cessationOfOperation (5)","status":400}`)
}

// Valid revocation request for existing, non-revoked cert, signed with account
// key.
func TestRevokeCertificateAccountKey(t *testing.T) {
	revokeRequestJSON, err := makeRevokeRequestJSON(nil)
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	test1JWK := loadPrivateKey(t, []byte(test1KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	test1Key, ok := test1JWK.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	accountKeySigner := newJoseSigner(t, test1Key, wfe.nonceService)
	result, _ := accountKeySigner.Sign(revokeRequestJSON)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
}

// A revocation request signed by an unauthorized key.
func TestRevokeCertificateWrongKey(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()
	test2JWK := loadPrivateKey(t, []byte(test2KeyPrivatePEM))
	test2Key, ok := test2JWK.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	accountKeySigner2 := newJoseSigner(t, test2Key, wfe.nonceService)
	revokeRequestJSON, err := makeRevokeRequestJSON(nil)
	test.AssertNotError(t, err, "Unable to create revoke request")

	result, _ := accountKeySigner2.Sign(revokeRequestJSON)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 403)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`unauthorized","detail":"Revocation request must be signed by private key of cert to be revoked, by the account key of the account that issued it, or by the account key of an account that holds valid authorizations for all names in the certificate.","status":403}`)
}

// Valid revocation request for already-revoked cert
func TestRevokeCertificateAlreadyRevoked(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.SA = &mockSANoSuchRegistration{wfe.SA}

	keyPemBytes, err := ioutil.ReadFile("test/178.key")
	test.AssertNotError(t, err, "Failed to load key")
	key := loadPrivateKey(t, keyPemBytes)
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer := newJoseSigner(t, rsaKey, wfe.nonceService)

	certPemBytes, err := ioutil.ReadFile("test/178.crt")
	test.AssertNotError(t, err, "Failed to load cert")
	certBlock, _ := pem.Decode(certPemBytes)
	test.Assert(t, certBlock != nil, "Failed to decode PEM")
	revokeRequest := struct {
		Resource       string          `json:"resource"`
		CertificateDER core.JSONBuffer `json:"certificate"`
	}{
		Resource:       "revoke-cert",
		CertificateDER: certBlock.Bytes,
	}
	revokeRequestJSON, err := json.Marshal(revokeRequest)
	test.AssertNotError(t, err, "Failed to marshal request")

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.

	responseWriter := httptest.NewRecorder()
	responseWriter.Body.Reset()
	result, _ := signer.Sign(revokeRequestJSON)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 409)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Certificate already revoked","status":409}`)
}

func TestRevokeCertificateExpired(t *testing.T) {
	wfe, fc := setupWFE(t)
	wfe.SA = &mockSANoSuchRegistration{wfe.SA}

	keyPemBytes, err := ioutil.ReadFile("test/178.key")
	test.AssertNotError(t, err, "Failed to load key")
	key := loadPrivateKey(t, keyPemBytes)
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer := newJoseSigner(t, rsaKey, wfe.nonceService)

	certPemBytes, err := ioutil.ReadFile("test/178.crt")
	test.AssertNotError(t, err, "Failed to load cert")
	certBlock, _ := pem.Decode(certPemBytes)
	test.Assert(t, certBlock != nil, "Failed to decode PEM")
	revokeRequest := struct {
		Resource       string          `json:"resource"`
		CertificateDER core.JSONBuffer `json:"certificate"`
	}{
		Resource:       "revoke-cert",
		CertificateDER: certBlock.Bytes,
	}
	revokeRequestJSON, err := json.Marshal(revokeRequest)
	test.AssertNotError(t, err, "Failed to marshal request")

	parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
	test.AssertNotError(t, err, "failed to parse test cert")
	fc.Set(parsedCert.NotAfter.Add(time.Hour))

	responseWriter := httptest.NewRecorder()
	responseWriter.Body.Reset()
	result, _ := signer.Sign(revokeRequestJSON)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 403)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`unauthorized","detail":"Certificate is expired","status":403}`)

}

func TestRevokeCertificateWithAuthz(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()
	test4JWK := loadPrivateKey(t, []byte(test4KeyPrivatePEM))
	test4Key, ok := test4JWK.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	accountKeySigner := newJoseSigner(t, test4Key, wfe.nonceService)
	revokeRequestJSON, err := makeRevokeRequestJSON(nil)
	test.AssertNotError(t, err, "Unable to create revoke request")

	result, _ := accountKeySigner.Sign(revokeRequestJSON)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
}

// TestAuthorization500 tests that internal errors on GetAuthorization result in
// a 500.
func TestAuthorization500(t *testing.T) {
	wfe, _ := setupWFE(t)

	responseWriter := httptest.NewRecorder()

	authzURL := mustParseURL(authzPath)
	authzURL.Path = "4"
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
		URL:    authzURL,
	})
	expected := `{
	  "type": "urn:acme:error:serverInternal",
		"detail": "Problem getting authorization",
		"status": 500
	}`
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), expected)

}

func TestNewAuthorizationEmptyDomain(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	wfe, _ := setupWFE(t)

	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter,
		makePostRequest(signRequest(t, `{
		  "resource":"new-authz",
			"identifier": {
				"Type": "dns",
				"Value": ""
			}
		}`, wfe.nonceService)))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Invalid new-authorization request: missing fields","status":400}`)
}

func TestNewAuthorizationEmptyType(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	wfe, _ := setupWFE(t)

	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter,
		makePostRequest(signRequest(t, `{
		  "resource":"new-authz",
			"identifier": {
				"Type": "",
				"Value": "example.com"
			}
		}`, wfe.nonceService)))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Invalid new-authorization request: missing fields","status":400}`)
}

func TestNewAuthorizationNonDNS(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	wfe, _ := setupWFE(t)

	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter,
		makePostRequest(signRequest(t, `{
		  "resource":"new-authz",
			"identifier": {
				"Type": "shibboleth",
				"Value": "example.com"
			}
		}`, wfe.nonceService)))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Invalid new-authorization request: wrong identifier type","status":400}`)
}

func TestAuthorization(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler(metrics.NoopRegisterer)

	responseWriter := httptest.NewRecorder()

	// GET instead of POST should be rejected
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(newAuthzPath),
	})
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V1ErrorNS+`malformed","detail":"Method not allowed","status":405}`)

	// POST, but no body.
	responseWriter.Body.Reset()
	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "POST",
		Header: map[string][]string{
			"Content-Length": {"0"},
		},
	})
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V1ErrorNS+`malformed","detail":"No body on POST","status":400}`)

	// POST, but body that isn't valid JWS
	responseWriter.Body.Reset()
	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter, makePostRequest("hi"))
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V1ErrorNS+`malformed","detail":"Parse error reading JWS","status":400}`)

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	responseWriter.Body.Reset()
	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter,
		makePostRequest(signRequest(t, "foo", wfe.nonceService)))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Request payload did not parse as JSON","status":400}`)

	// Same signed body, but payload modified by one byte, breaking signature.
	// should fail JWS verification.
	responseWriter.Body.Reset()
	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter, makePostRequest(`
			{
					"header": {
							"alg": "RS256",
							"jwk": {
									"e": "AQAB",
									"kty": "RSA",
									"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw"
							}
					},
					"payload": "xm9vCg",
					"signature": "RjUQ679fxJgeAJlxqgvDP_sfGZnJ-1RgWF2qmcbnBWljs6h1qp63pLnJOl13u81bP_bCSjaWkelGG8Ymx_X-aQ"
			}
		`))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"JWS verification error","status":400}`)

	responseWriter.Body.Reset()
	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter,
		makePostRequest(signRequest(t, `{"resource":"new-authz","identifier":{"type":"dns","value":"test.com"}}`, wfe.nonceService)))

	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"http://localhost/acme/authz-v3/1")
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		`<http://localhost/acme/new-cert>;rel="next"`)

	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"identifier":{"type":"dns","value":"test.com"},"status": "valid","expires":"2021-01-01T00:00:00Z"}`)

	var authz core.Authorization
	err := json.Unmarshal(responseWriter.Body.Bytes(), &authz)
	test.AssertNotError(t, err, "Couldn't unmarshal returned authorization object")

	// Expired authorizations should be inaccessible
	authzURL := "3"
	responseWriter = httptest.NewRecorder()
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(authzURL),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Expired authorization","status":404}`)
	responseWriter.Body.Reset()

	// Ensure that a valid authorization can't be reached with an invalid URL
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		URL:    mustParseURL("7"),
		Method: "GET",
	})
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"No such authorization","status":404}`)
}

func TestAuthorizationV2(t *testing.T) {
	wfe, _ := setupWFE(t)

	// Test retrieving a v2 style authorization
	responseWriter := httptest.NewRecorder()
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		URL:    mustParseURL("1"),
		Method: "GET",
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `
	{
		"identifier": {
			"type": "dns",
			"value": "not-an-example.com"
		},
		"status": "valid",
		"expires": "2070-01-01T00:00:00Z",
		"combinations": [[0]],
		"challenges": [
			{
			  "status": "pending",
				"type": "dns",
				"token":"token",
				"uri": "http://localhost/acme/chall-v3/1/-ZfxEw"
			}
		]
	}`)

	// Test that getting a v2 authorization with an invalid ID results in the
	// expected not found status.
	responseWriter = httptest.NewRecorder()
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		URL:    mustParseURL("1junkjunkjunk"),
		Method: "GET",
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusBadRequest)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `
	{
		"type": "urn:acme:error:malformed",
		"detail": "Invalid authorization ID",
		"status": 400
	}`)
}

// TestAuthorizationChallengeNamespace tests that the runtime prefixing of
// Challenge Problem Types works as expected
func TestAuthorizationChallengeNamespace(t *testing.T) {
	wfe, clk := setupWFE(t)
	wfe.SA = &mocks.SAWithFailedChallenges{Clk: clk}

	// For "oldNS" the SA mock returns an authorization with a failed challenge
	// that has an error with the type already prefixed by the v1 error NS
	authzURL := "55"
	responseWriter := httptest.NewRecorder()
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(authzURL),
	})

	var authz core.Authorization
	err := json.Unmarshal(responseWriter.Body.Bytes(), &authz)
	test.AssertNotError(t, err, "Couldn't unmarshal returned authorization object")
	test.AssertEquals(t, len(authz.Challenges), 1)
	// The Challenge Error Type should have its prefix unmodified
	test.AssertEquals(t, string(authz.Challenges[0].Error.Type), probs.V1ErrorNS+"things:are:whack")

	// For "failed" the SA mock returns an authorization with a failed challenge
	// that has an error with the type not prefixed by an error namespace.
	authzURL = "56"
	responseWriter = httptest.NewRecorder()
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(authzURL),
	})

	err = json.Unmarshal(responseWriter.Body.Bytes(), &authz)
	test.AssertNotError(t, err, "Couldn't unmarshal returned authorization object")
	test.AssertEquals(t, len(authz.Challenges), 1)
	// The Challenge Error Type should have had the probs.V1ErrorNS prefix added
	test.AssertEquals(t, string(authz.Challenges[0].Error.Type), probs.V1ErrorNS+"things:are:whack")
	responseWriter.Body.Reset()
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func TestRegistration(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler(metrics.NoopRegisterer)
	responseWriter := httptest.NewRecorder()

	// Test invalid method
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "MAKE-COFFEE",
		URL:    mustParseURL(regPath),
		Body:   makeBody("invalid"),
	})
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Method not allowed","status":405}`)
	responseWriter.Body.Reset()

	// Test GET proper entry returns 405
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(regPath),
	})
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Method not allowed","status":405}`)
	responseWriter.Body.Reset()

	// Test POST invalid JSON
	wfe.Registration(ctx, newRequestEvent(), responseWriter, makePostRequestWithPath("2", "invalid"))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Parse error reading JWS","status":400}`)
	responseWriter.Body.Reset()

	key := loadPrivateKey(t, []byte(test2KeyPrivatePEM))
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer := newJoseSigner(t, rsaKey, wfe.nonceService)

	// Test POST valid JSON but key is not registered
	result, err := signer.Sign([]byte(`{"resource":"reg","agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "Unable to sign")
	wfe.Registration(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("2", result.FullSerialize()))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`unauthorized","detail":"No registration exists matching provided key","status":403}`)
	responseWriter.Body.Reset()

	key = loadPrivateKey(t, []byte(test1KeyPrivatePEM))
	rsaKey, ok = key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer = newJoseSigner(t, rsaKey, wfe.nonceService)

	// Test POST valid JSON with registration up in the mock (with incorrect agreement URL)
	result, err = signer.Sign([]byte(`{"resource":"reg","agreement":"https://letsencrypt.org/im-bad"}`))
	test.AssertNotError(t, err, "signer.Sign failed")

	// Test POST valid JSON with registration up in the mock
	wfe.Registration(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("1", result.FullSerialize()))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V1ErrorNS+`malformed","detail":"Provided agreement URL [https://letsencrypt.org/im-bad] does not match current agreement URL [`+agreementURL+`]","status":400}`)
	responseWriter.Body.Reset()

	// Test POST valid JSON with registration up in the mock (with correct agreement URL)
	result, err = signer.Sign([]byte(`{"resource":"reg","agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "Couldn't sign")
	wfe.Registration(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("1", result.FullSerialize()))
	test.AssertNotContains(t, responseWriter.Body.String(), probs.V1ErrorNS)
	links := responseWriter.Header()["Link"]
	test.AssertEquals(t, contains(links, "<http://localhost/acme/new-authz>;rel=\"next\""), true)
	test.AssertEquals(t, contains(links, "<"+agreementURL+">;rel=\"terms-of-service\""), true)
	responseWriter.Body.Reset()

	// Test POST valid JSON with garbage in URL but valid registration ID
	result, err = signer.Sign([]byte(`{"resource":"reg","agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "Couldn't sign")
	wfe.Registration(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("/a/bunch/of/garbage/1", result.FullSerialize()))
	test.AssertContains(t, responseWriter.Body.String(), "400")
	test.AssertContains(t, responseWriter.Body.String(), probs.V1ErrorNS+"malformed")
	responseWriter.Body.Reset()

	// Test POST valid JSON with registration up in the mock (with old agreement URL)
	wfe.SubscriberAgreementURL = "http://example.invalid/new-terms"
	result, err = signer.Sign([]byte(`{"resource":"reg","agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "Couldn't sign")
	wfe.Registration(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("1", result.FullSerialize()))
	test.AssertNotContains(t, responseWriter.Body.String(), probs.V1ErrorNS)
	links = responseWriter.Header()["Link"]
	test.AssertEquals(t, contains(links, "<http://localhost/acme/new-authz>;rel=\"next\""), true)
	test.AssertEquals(t, contains(links, "<http://example.invalid/new-terms>;rel=\"terms-of-service\""), true)
	responseWriter.Body.Reset()
}

func TestTermsRedirect(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	path, _ := url.Parse("/terms")
	wfe.Terms(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
		URL:    path,
	})
	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		agreementURL)
	test.AssertEquals(t, responseWriter.Code, 302)
}

func TestIssuer(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	wfe.Issuer(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.Assert(t, bytes.Compare(responseWriter.Body.Bytes(), wfe.IssuerCert.Raw) == 0, "Incorrect bytes returned")
}

func TestGetCertificate(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler(metrics.NoopRegisterer)

	certPemBytes, _ := ioutil.ReadFile("test/178.crt")
	certBlock, _ := pem.Decode(certPemBytes)

	responseWriter := httptest.NewRecorder()

	mockLog := wfe.log.(*blog.Mock)
	mockLog.Clear()

	// Valid serial, cached
	req, _ := http.NewRequest("GET", "/acme/cert/0000000000000000000000000000000000b2", nil)
	req.RemoteAddr = "192.168.0.1"
	mux.ServeHTTP(responseWriter, req)
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")
	test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/pkix-cert")
	test.Assert(t, bytes.Compare(responseWriter.Body.Bytes(), certBlock.Bytes) == 0, "Certificates don't match")
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		`<http://localhost/acme/issuer-cert>;rel="up"`)

	// Unused serial, no cache
	mockLog.Clear()
	responseWriter = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/acme/cert/0000000000000000000000000000000000ff", nil)
	req.RemoteAddr = "192.168.0.1"
	req.Header.Set("X-Forwarded-For", "192.168.99.99")
	mux.ServeHTTP(responseWriter, req)
	test.AssertEquals(t, responseWriter.Code, 404)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V1ErrorNS+`malformed","detail":"Certificate not found","status":404}`)

	// Internal server error, no cache
	mockLog.Clear()
	responseWriter = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/acme/cert/000000000000000000000000000000626164", nil)
	req.RemoteAddr = "192.168.0.1"
	req.Header.Set("X-Forwarded-For", "192.168.99.99")
	mux.ServeHTTP(responseWriter, req)
	test.AssertEquals(t, responseWriter.Code, 500)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V1ErrorNS+`serverInternal","detail":"Failed to retrieve certificate","status":500}`)

	// Invalid serial, no cache
	responseWriter = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/acme/cert/nothex", nil)
	mux.ServeHTTP(responseWriter, req)
	test.AssertEquals(t, responseWriter.Code, 404)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V1ErrorNS+`malformed","detail":"Certificate not found","status":404}`)

	// Invalid serial, no cache
	responseWriter = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/acme/cert/00000000000000", nil)
	mux.ServeHTTP(responseWriter, req)
	test.AssertEquals(t, responseWriter.Code, 404)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V1ErrorNS+`malformed","detail":"Certificate not found","status":404}`)
}

func assertCsrLogged(t *testing.T, mockLog *blog.Mock) {
	matches := mockLog.GetAllMatching("^INFO: \\[AUDIT\\] Certificate request JSON=")
	test.Assert(t, len(matches) == 1,
		fmt.Sprintf("Incorrect number of certificate request log entries: %d",
			len(matches)))
}

func TestLengthRequired(t *testing.T) {
	wfe, _ := setupWFE(t)
	_, _, _, prob := wfe.verifyPOST(ctx, newRequestEvent(), &http.Request{
		Method: "POST",
		URL:    mustParseURL("/"),
	}, false, "resource")
	test.Assert(t, prob != nil, "No error returned for request body missing Content-Length.")
	test.AssertEquals(t, probs.MalformedProblem, prob.Type)
	test.AssertEquals(t, http.StatusLengthRequired, prob.HTTPStatus)
}

func TestRequestTooLong(t *testing.T) {
	wfe, _ := setupWFE(t)
	payload := fmt.Sprintf(`{"a":"%s"}`, strings.Repeat("a", 50000))

	_, _, _, prob := wfe.verifyPOST(ctx, newRequestEvent(), makePostRequest(signRequest(t,
		payload, wfe.nonceService)), false, "n/a")
	test.Assert(t, prob != nil, "No error returned for too-long request body.")
	test.AssertEquals(t, probs.UnauthorizedProblem, prob.Type)
	test.AssertEquals(t, "request body too large", prob.Detail)
	test.AssertEquals(t, http.StatusForbidden, prob.HTTPStatus)
}

type mockSAGetRegByKeyFails struct {
	sapb.StorageAuthorityGetterClient
}

func (sa *mockSAGetRegByKeyFails) GetRegistrationByKey(_ context.Context, _ *sapb.JSONWebKey, _ ...grpc.CallOption) (*corepb.Registration, error) {
	return nil, errors.New("whoops")
}

// When SA.GetRegistrationByKey errors (e.g. gRPC timeout), verifyPOST should
// return internal server errors.
func TestVerifyPOSTWhenGetRegByKeyFails(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.SA = &mockSAGetRegByKeyFails{wfe.SA}
	event := newRequestEvent()
	payload := `{"resource":"ima-payload"}`
	_, _, _, prob := wfe.verifyPOST(ctx, event, makePostRequest(signRequest(t,
		payload, wfe.nonceService)), false, "ima-payload")
	if prob == nil {
		t.Fatalf("No error returned when GetRegByKey failed with generic error.")
	}
	if prob.Type != probs.ServerInternalProblem {
		t.Errorf("Wrong type for returned problem: %#v", prob)
	}
}

// When SA.GetRegistrationByKey errors (e.g. gRPC timeout), NewRegistration should
// return internal server errors.
func TestNewRegWhenGetRegByKeyFails(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.SA = &mockSAGetRegByKeyFails{wfe.SA}
	payload := `{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`
	responseWriter := httptest.NewRecorder()
	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter,
		makePostRequest(signRequest(t, payload, wfe.nonceService)))
	var prob probs.ProblemDetails
	err := json.Unmarshal(responseWriter.Body.Bytes(), &prob)
	test.AssertNotError(t, err, "unmarshalling response")
	if prob.Type != probs.V1ErrorNS+probs.ServerInternalProblem {
		t.Errorf("Wrong type for returned problem: %#v", prob.Type)
	}
}

type mockSAGetRegByKeyNotFound struct {
	sapb.StorageAuthorityGetterClient
}

func (sa *mockSAGetRegByKeyNotFound) GetRegistrationByKey(_ context.Context, _ *sapb.JSONWebKey, _ ...grpc.CallOption) (*corepb.Registration, error) {
	return nil, berrors.NotFoundError("not found")
}

// When SA.GetRegistrationByKey returns berrors.NotFound, verifyPOST with
// regCheck = false (i.e. during a NewRegistration) should succeed.
func TestVerifyPOSTWhenGetRegByKeyNotFound(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.SA = &mockSAGetRegByKeyNotFound{wfe.SA}
	event := newRequestEvent()
	payload := `{"resource":"ima-payload"}`
	_, _, _, err := wfe.verifyPOST(ctx, event, makePostRequest(signRequest(t,
		payload, wfe.nonceService)), false, "ima-payload")
	if err != nil {
		t.Fatalf("Expected verifyPOST with regCheck=false to succeed when SA.GetRegistrationByKey returned NotFound, get %v", err)
	}
}

// When SA.GetRegistrationByKey returns NotFound, NewRegistration should
// succeed.
func TestNewRegWhenGetRegByKeyNotFound(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.SA = &mockSAGetRegByKeyNotFound{wfe.SA}
	payload := `{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`
	responseWriter := httptest.NewRecorder()
	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter,
		makePostRequest(signRequest(t, payload, wfe.nonceService)))
	if responseWriter.Code != http.StatusCreated {
		t.Errorf("Bad response to NewRegistration: %d, %s", responseWriter.Code, responseWriter.Body)
	}
}

// TestLogPayload ensures that verifyPOST sets the Payload field of the logEvent
// it is passed.
func TestLogPayload(t *testing.T) {
	wfe, _ := setupWFE(t)
	event := newRequestEvent()
	payload := `{"resource":"ima-payload"}`
	_, _, _, err := wfe.verifyPOST(ctx, event, makePostRequest(signRequest(t,
		payload, wfe.nonceService)), false, "ima-payload")
	if err != nil {
		t.Fatal(err)
	}

	test.AssertEquals(t, event.Payload, payload)
}

type mockSADifferentStoredKey struct {
	sapb.StorageAuthorityGetterClient
}

func (sa mockSADifferentStoredKey) GetRegistrationByKey(_ context.Context, _ *sapb.JSONWebKey, _ ...grpc.CallOption) (*corepb.Registration, error) {
	return &corepb.Registration{
		Key: []byte(test2KeyPublicJSON),
	}, nil
}

func TestVerifyPOSTUsesStoredKey(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.SA = &mockSADifferentStoredKey{wfe.SA}
	// signRequest signs with test1Key, but our special mock returns a
	// registration with test2Key
	_, _, _, err := wfe.verifyPOST(ctx, newRequestEvent(), makePostRequest(signRequest(t, `{"resource":"foo"}`, wfe.nonceService)), true, "foo")
	test.AssertError(t, err, "No error returned when provided key differed from stored key.")
}

// This uses httptest.NewServer because ServeMux.ServeHTTP won't prevent the
// body from being sent like the net/http Server's actually do.
func TestGetCertificateHEADHasCorrectBodyLength(t *testing.T) {
	wfe, _ := setupWFE(t)

	certPemBytes, _ := ioutil.ReadFile("test/178.crt")
	certBlock, _ := pem.Decode(certPemBytes)

	mockLog := wfe.log.(*blog.Mock)
	mockLog.Clear()

	mux := wfe.Handler(metrics.NoopRegisterer)
	s := httptest.NewServer(mux)
	defer s.Close()
	req, _ := http.NewRequest("HEAD", s.URL+"/acme/cert/0000000000000000000000000000000000b2", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		test.AssertNotError(t, err, "do error")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		test.AssertNotEquals(t, err, "readall error")
	}
	err = resp.Body.Close()
	if err != nil {
		test.AssertNotEquals(t, err, "readall error")
	}
	test.AssertEquals(t, resp.StatusCode, 200)
	test.AssertEquals(t, strconv.Itoa(len(certBlock.Bytes)), resp.Header.Get("Content-Length"))
	test.AssertEquals(t, 0, len(body))
}

func newRequestEvent() *web.RequestEvent {
	return &web.RequestEvent{Extra: make(map[string]interface{})}
}

func TestVerifyPOSTInvalidJWK(t *testing.T) {
	badJWS := `{"signatures":[{"header":{"jwk":{"kty":"RSA","n":"","e":""}}}],"payload":""}`
	wfe, _ := setupWFE(t)
	_, _, _, prob := wfe.verifyPOST(ctx, newRequestEvent(), makePostRequest(badJWS), false, "resource")
	test.Assert(t, prob != nil, "No error returned for request body with invalid JWS key.")
	test.AssertEquals(t, probs.MalformedProblem, prob.Type)
	test.AssertEquals(t, http.StatusBadRequest, prob.HTTPStatus)
}

func TestHeaderBoulderRequester(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler(metrics.NoopRegisterer)
	responseWriter := httptest.NewRecorder()

	// create a signed request
	key := loadPrivateKey(t, []byte(test1KeyPrivatePEM))
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer := newJoseSigner(t, rsaKey, wfe.nonceService)

	// requests that do not call sendError() have the requester header
	result, err := signer.Sign([]byte(`{"resource":"reg","agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "signer.Sign failed")
	request := makePostRequestWithPath(regPath+"1", result.FullSerialize())
	mux.ServeHTTP(responseWriter, request)
	test.AssertEquals(t, responseWriter.Header().Get("Boulder-Requester"), "1")

	// requests that do call sendError() also should have the requester header
	result, err = signer.Sign([]byte(`{"resource":"reg","agreement":"https://letsencrypt.org/im-bad"}`))
	test.AssertNotError(t, err, "Failed to signer.Sign")
	request = makePostRequestWithPath(regPath+"1", result.FullSerialize())
	mux.ServeHTTP(responseWriter, request)
	test.AssertEquals(t, responseWriter.Header().Get("Boulder-Requester"), "1")
}

func TestDeactivateAuthorization(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	responseWriter.Body.Reset()
	wfe.Authorization(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("1", signRequest(t, `{"resource":"authz","status":""}`, wfe.nonceService)))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type": "`+probs.V1ErrorNS+`malformed","detail": "Invalid status value","status": 400}`)

	responseWriter.Body.Reset()
	wfe.Authorization(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("1", signRequest(t, `{"resource":"authz","status":"deactivated"}`, wfe.nonceService)))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{
		  "identifier": {
		    "type": "dns",
		    "value": "not-an-example.com"
		  },
		  "status": "deactivated",
		  "expires": "2070-01-01T00:00:00Z",
			"combinations": [[0]],
		  "challenges": [
		    {
				"status": "pending",
			  "type": "dns",
			  "token":"token",
		      "uri": "http://localhost/acme/chall-v3/1/-ZfxEw"
		    }
		  ]
		}`)
}

func TestDeactivateRegistration(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	wfe, _ := setupWFE(t)

	responseWriter.Body.Reset()
	wfe.Registration(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("1", signRequest(t, `{"resource":"reg","status":"asd"}`, wfe.nonceService)))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type": "`+probs.V1ErrorNS+`malformed","detail": "Invalid value provided for status field","status": 400}`)

	responseWriter.Body.Reset()
	wfe.Registration(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("1", signRequest(t, `{"resource":"reg","status":"deactivated"}`, wfe.nonceService)))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{
		  "id": 1,
		  "key": {
		    "kty": "RSA",
		    "n": "yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
		    "e": "AQAB"
		  },
		  "contact": [
		    "mailto:person@mail.com"
		  ],
		  "agreement": "http://example.invalid/terms",
		  "initialIp": "",
		  "status": "deactivated"
		}`)

	responseWriter.Body.Reset()
	wfe.Registration(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("1", signRequest(t, `{"resource":"reg","status":"deactivated","contact":[]}`, wfe.nonceService)))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{
		  "id": 1,
		  "key": {
		    "kty": "RSA",
		    "n": "yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
		    "e": "AQAB"
		  },
		  "contact": [
		    "mailto:person@mail.com"
		  ],
		  "agreement": "http://example.invalid/terms",
		  "initialIp": "",
		  "status": "deactivated"
		}`)

	key := loadPrivateKey(t, []byte(test3KeyPrivatePEM))
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer := newJoseSigner(t, rsaKey, wfe.nonceService)

	result, err := signer.Sign([]byte(`{"resource":"reg","status":"deactivated"}`))
	test.AssertNotError(t, err, "Unable to sign")
	wfe.Registration(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("2", result.FullSerialize()))

	responseWriter.Body.Reset()
	wfe.Registration(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("2", result.FullSerialize()))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{
		  "type": "`+probs.V1ErrorNS+`unauthorized",
		  "detail": "Registration is not valid, has status 'deactivated'",
		  "status": 403
		}`)
}

func TestKeyRollover(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	wfe, _ := setupWFE(t)

	key := loadPrivateKey(t, []byte(test3KeyPrivatePEM))
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer := newJoseSigner(t, rsaKey, wfe.nonceService)

	wfe.KeyRollover(ctx, newRequestEvent(), responseWriter, makePostRequestWithPath("", "{}"))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{
		  "type": "`+probs.V1ErrorNS+`malformed",
		  "detail": "Parse error reading JWS",
		  "status": 400
		}`)

	for _, testCase := range []struct {
		payload          string
		expectedResponse string
	}{
		{
			// Missing account URL
			"{}",
			`{
		     "type": "` + probs.V1ErrorNS + `malformed",
		     "detail": "Incorrect account URL provided in payload",
		     "status": 400
		   }`,
		},
		// Missing new key
		{
			`{"account":"http://localhost/acme/reg/1"}`,
			`{
		     "type": "` + probs.V1ErrorNS + `malformed",
		     "detail": "Unable to marshal new JWK",
		     "status": 400
		   }`,
		},
		// Different key used to sign inner JWS
		{
			`{"newKey":{"kty":"RSA","n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ","e":"AQAB"},"account":"http://localhost/acme/reg/1"}`,
			`{
		     "type": "` + probs.V1ErrorNS + `malformed",
		     "detail": "New JWK in inner payload doesn't match key used to sign inner JWS",
		     "status": 400
		   }`,
		},
		// Valid request
		{
			`{"newKey":{"kty":"RSA","n":"uTQER6vUA1RDixS8xsfCRiKUNGRzzyIK0MhbS2biClShbb0hSx2mPP7gBvis2lizZ9r-y9hL57kNQoYCKndOBg0FYsHzrQ3O9AcoV1z2Mq-XhHZbFrVYaXI0M3oY9BJCWog0dyi3XC0x8AxC1npd1U61cToHx-3uSvgZOuQA5ffEn5L38Dz1Ti7OV3E4XahnRJvejadUmTkki7phLBUXm5MnnyFm0CPpf6ApV7zhLjN5W-nV0WL17o7v8aDgV_t9nIdi1Y26c3PlCEtiVHZcebDH5F1Deta3oLLg9-g6rWnTqPbY3knffhp4m0scLD6e33k8MtzxDX_D7vHsg0_X1w","e":"AQAB"},"account":"http://localhost/acme/reg/1"}`,
			`{
		     "id": 1,
		     "key": {
		       "kty": "RSA",
		       "n": "uTQER6vUA1RDixS8xsfCRiKUNGRzzyIK0MhbS2biClShbb0hSx2mPP7gBvis2lizZ9r-y9hL57kNQoYCKndOBg0FYsHzrQ3O9AcoV1z2Mq-XhHZbFrVYaXI0M3oY9BJCWog0dyi3XC0x8AxC1npd1U61cToHx-3uSvgZOuQA5ffEn5L38Dz1Ti7OV3E4XahnRJvejadUmTkki7phLBUXm5MnnyFm0CPpf6ApV7zhLjN5W-nV0WL17o7v8aDgV_t9nIdi1Y26c3PlCEtiVHZcebDH5F1Deta3oLLg9-g6rWnTqPbY3knffhp4m0scLD6e33k8MtzxDX_D7vHsg0_X1w",
		       "e": "AQAB"
		     },
		     "contact": [
		       "mailto:person@mail.com"
		     ],
		     "agreement": "http://example.invalid/terms",
		     "initialIp": "",
		     "status": "valid"
		   }`,
		},
	} {
		inner, err := signer.Sign([]byte(testCase.payload))
		test.AssertNotError(t, err, "Unable to sign")
		innerStr := inner.FullSerialize()
		innerStr = innerStr[:len(innerStr)-1] + `,"resource":"key-change"}` // awful
		outer := signRequest(t, innerStr, wfe.nonceService)

		responseWriter.Body.Reset()
		wfe.KeyRollover(ctx, newRequestEvent(), responseWriter, makePostRequestWithPath("", outer))
		test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), testCase.expectedResponse)
	}
}

func TestPrepChallengeForDisplay(t *testing.T) {
	req := &http.Request{
		Host: "example.com",
	}
	chall := &core.Challenge{
		Status: core.AcmeStatus("pending"),
		Token:  "asd",
		Type:   core.ChallengeTypeDNS01,
	}
	authz := core.Authorization{
		ID:     "eyup",
		Status: core.AcmeStatus("invalid"),
	}

	wfe, _ := setupWFE(t)
	wfe.prepChallengeForDisplay(req, authz, chall)
	if chall.Status != "invalid" {
		t.Errorf("Expected challenge status to be forced to invalid, got %#v", chall)
	}
	test.AssertEquals(t, chall.URI, "http://example.com/acme/chall-v3/eyup/iFVMwA")
}

type mockSAGetRegByKeyNotFoundAfterVerify struct {
	sapb.StorageAuthorityGetterClient
	verified bool
}

func (sa *mockSAGetRegByKeyNotFoundAfterVerify) GetRegistrationByKey(_ context.Context, req *sapb.JSONWebKey, _ ...grpc.CallOption) (*corepb.Registration, error) {
	if !sa.verified {
		sa.verified = true
		return sa.StorageAuthorityGetterClient.GetRegistrationByKey(ctx, req)
	}
	return nil, errors.New("broke")
}

// If GetRegistrationByKey returns a non berrors.NotFound error NewRegistration should fail
// out with an internal server error instead of continuing on and attempting to create a new
// account.
func TestNewRegistrationGetKeyBroken(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.SA = &mockSAGetRegByKeyNotFoundAfterVerify{wfe.SA, false}
	payload := `{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`
	responseWriter := httptest.NewRecorder()
	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter,
		makePostRequest(signRequest(t, payload, wfe.nonceService)))
	var prob probs.ProblemDetails
	err := json.Unmarshal(responseWriter.Body.Bytes(), &prob)
	test.AssertNotError(t, err, "unmarshalling response")
	if prob.Type != probs.V1ErrorNS+probs.ServerInternalProblem {
		t.Errorf("Wrong type for returned problem: %#v", prob.Type)
	}
}
