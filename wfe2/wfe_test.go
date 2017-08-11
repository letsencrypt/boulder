package wfe2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	"golang.org/x/net/context"
	"gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/nonce"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/revocation"
	"github.com/letsencrypt/boulder/test"
)

const (
	agreementURL = "http://example.invalid/terms"

	test1KeyPublicJSON = `
	{
		"kty":"RSA",
		"n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
		"e":"AQAB"
	}`

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

	testE1KeyPublicJSON = `{
    "kty":"EC",
    "crv":"P-256",
    "x":"FwvSZpu06i3frSk_mz9HcD9nETn4wf3mQ-zDtG21Gao",
    "y":"S8rR-0dWa8nAcw1fbunF_ajS3PQZ-QwLps-2adgLgPk"
  }`

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

func (ra *MockRegistrationAuthority) NewRegistration(ctx context.Context, reg core.Registration) (core.Registration, error) {
	return reg, nil
}

func (ra *MockRegistrationAuthority) NewAuthorization(ctx context.Context, authz core.Authorization, regID int64) (core.Authorization, error) {
	authz.RegistrationID = regID
	authz.ID = "bkrPh2u0JUf18-rVBZtOOWWb3GuIiliypL-hBM9Ak1Q"
	return authz, nil
}

func (ra *MockRegistrationAuthority) NewCertificate(ctx context.Context, req core.CertificateRequest, regID int64) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ra *MockRegistrationAuthority) UpdateRegistration(ctx context.Context, reg core.Registration, updated core.Registration) (core.Registration, error) {
	keysMatch, _ := core.PublicKeysEqual(reg.Key.Key, updated.Key.Key)
	if !keysMatch {
		reg.Key = updated.Key
	}
	return reg, nil
}

func (ra *MockRegistrationAuthority) UpdateAuthorization(ctx context.Context, authz core.Authorization, foo int, challenge core.Challenge) (core.Authorization, error) {
	return authz, nil
}

func (ra *MockRegistrationAuthority) RevokeCertificateWithReg(ctx context.Context, cert x509.Certificate, reason revocation.Reason, reg int64) error {
	ra.lastRevocationReason = reason
	return nil
}

func (ra *MockRegistrationAuthority) AdministrativelyRevokeCertificate(ctx context.Context, cert x509.Certificate, reason revocation.Reason, user string) error {
	return nil
}

func (ra *MockRegistrationAuthority) OnValidationUpdate(ctx context.Context, authz core.Authorization) error {
	return nil
}

func (ra *MockRegistrationAuthority) DeactivateAuthorization(ctx context.Context, authz core.Authorization) error {
	return nil
}

func (ra *MockRegistrationAuthority) DeactivateRegistration(ctx context.Context, _ core.Registration) error {
	return nil
}

type mockPA struct{}

func (pa *mockPA) ChallengesFor(identifier core.AcmeIdentifier) (challenges []core.Challenge, combinations [][]int) {
	return
}

func (pa *mockPA) WillingToIssue(id core.AcmeIdentifier) error {
	return nil
}

func makeBody(s string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(s))
}

// loadKeys loads a private key from PEM/DER-encoded data and returns
// a `crypto.Signer`.
func loadKeys(t *testing.T, keyBytes []byte) crypto.Signer {
	// pem.Decode does not return an error as its 2nd arg, but instead the "rest"
	// that was leftover from parsing the PEM block. We only care if the decoded
	// PEM block was empty for this test function.
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		t.Fatal("Unable to decode private key PEM bytes")
	}

	// Try decoding as an RSA private key
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey
	}

	// Try as an ECDSA private key
	if ecdsaKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ecdsaKey
	}

	// Nothing worked! Fail hard.
	t.Fatal(fmt.Sprintf("Unable to decode private key PEM bytes"))
	// NOOP - the t.Fatal() call will abort before this return
	return nil
}

var testKeyPolicy = goodkey.KeyPolicy{
	AllowRSA:           true,
	AllowECDSANISTP256: true,
	AllowECDSANISTP384: true,
}

var ctx = context.Background()

func setupWFE(t *testing.T) (WebFrontEndImpl, clock.FakeClock) {
	fc := clock.NewFake()
	stats := metrics.NewNoopScope()

	wfe, err := NewWebFrontEndImpl(stats, fc, testKeyPolicy, blog.NewMock())
	test.AssertNotError(t, err, "Unable to create WFE")

	wfe.SubscriberAgreementURL = agreementURL

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = mocks.NewStorageAuthority(fc)

	return wfe, fc
}

// makePostRequestWithPath creates an http.Request for localhost with method
// POST, the provided body, and the correct Content-Length. The path provided
// will be parsed as a URL and used to populate the request URL and RequestURI
func makePostRequestWithPath(path string, body string) *http.Request {
	request := &http.Request{
		Method:     "POST",
		RemoteAddr: "1.1.1.1:7882",
		Header: map[string][]string{
			"Content-Length": {fmt.Sprintf("%d", len(body))},
		},
		Body: makeBody(body),
		Host: "localhost",
	}
	url := mustParseURL(path)
	request.URL = url
	request.RequestURI = url.Path
	return request
}

// signAndPost constructs a JWS signed by the given account ID, over the given
// payload, with the protected URL set to the provided signedURL. An HTTP
// request constructed to the provided path with the encoded JWS body as the
// POST body is returned.
func signAndPost(t *testing.T, path, signedURL, payload string, accountID int64, ns *nonce.NonceService) *http.Request {
	_, _, body := signRequestKeyID(t, accountID, nil, signedURL, payload, ns)
	return makePostRequestWithPath(path, body)
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
	sort.Sort(sort.StringSlice(a))
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

func TestHandleFunc(t *testing.T) {
	wfe, _ := setupWFE(t)
	var mux *http.ServeMux
	var rw *httptest.ResponseRecorder
	var stubCalled bool
	runWrappedHandler := func(req *http.Request, allowed ...string) {
		mux = http.NewServeMux()
		rw = httptest.NewRecorder()
		stubCalled = false
		wfe.HandleFunc(mux, "/test", func(context.Context, *requestEvent, http.ResponseWriter, *http.Request) {
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
				`{"type":"urn:acme:error:malformed","detail":"Method not allowed","status":405}`)
		}
		nonce := rw.Header().Get("Replay-Nonce")
		test.AssertNotEquals(t, nonce, lastNonce)
		test.AssertNotEquals(t, nonce, "")
		lastNonce = nonce
	}

	// Disallowed method returns error JSON in body
	runWrappedHandler(&http.Request{Method: "PUT"}, "GET", "POST")
	test.AssertEquals(t, rw.Header().Get("Content-Type"), "application/problem+json")
	test.AssertUnmarshaledEquals(t, rw.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Method not allowed","status":405}`)
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
	test.AssertUnmarshaledEquals(t, rw.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Method not allowed","status":405}`)

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
	wfe.IndexCacheDuration = time.Second * 10

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

// randomDirectoryKeyPresent unmarshals the given buf of JSON and returns true
// if `randomDirKeyExplanationLink` appears as the value of a key in the directory
// object.
func randomDirectoryKeyPresent(t *testing.T, buf []byte) bool {
	var dir map[string]interface{}
	if err := json.Unmarshal(buf, &dir); err != nil {
		t.Errorf("Failed to unmarshal directory: %s", err)
	}
	for _, v := range dir {
		if v == randomDirKeyExplanationLink {
			return true
		}
	}
	return false
}

func TestDirectory(t *testing.T) {
	// Note: `TestDirectory` sets the `wfe.BaseURL` specifically to test the
	// that it overrides the relative /directory behaviour.
	// This ensures the `Host` value of `127.0.0.1` in the following
	// `http.Request` is not used in the response URLs that are tested against
	// `http://localhost:4300`
	wfe, _ := setupWFE(t)
	wfe.BaseURL = "http://localhost:4300"
	mux := wfe.Handler()

	const (
		oldUA = "LetsEncryptPythonClient"
	)

	// Directory with a key change endpoint but no meta endpoint or random entry
	noMetaJSONWithKeyChange := `{
		"key-change": "http://localhost:4300/acme/key-change",
		"new-authz": "http://localhost:4300/acme/new-authz",
		"new-cert": "http://localhost:4300/acme/new-cert",
		"new-reg": "http://localhost:4300/acme/new-reg",
		"revoke-cert": "http://localhost:4300/acme/revoke-cert"
}`

	// Directory without a key change endpoint or a random entry
	noMetaJSONWithoutKeyChange := `{
		"new-authz": "http://localhost:4300/acme/new-authz",
		"new-cert": "http://localhost:4300/acme/new-cert",
		"new-reg": "http://localhost:4300/acme/new-reg",
		"revoke-cert": "http://localhost:4300/acme/revoke-cert"
}`

	// Directory with a key change endpoint and a meta entry
	metaJSON := `{
  "key-change": "http://localhost:4300/acme/key-change",
  "meta": {
    "terms-of-service": "http://example.invalid/terms"
  },
  "new-authz": "http://localhost:4300/acme/new-authz",
  "new-cert": "http://localhost:4300/acme/new-cert",
  "new-reg": "http://localhost:4300/acme/new-reg",
  "revoke-cert": "http://localhost:4300/acme/revoke-cert"
}`

	// Directory with a meta entry but no key change endpoint
	metaNoKeyChangeJSON := `{
  "meta": {
    "terms-of-service": "http://example.invalid/terms"
  },
  "new-authz": "http://localhost:4300/acme/new-authz",
  "new-cert": "http://localhost:4300/acme/new-cert",
  "new-reg": "http://localhost:4300/acme/new-reg",
  "revoke-cert": "http://localhost:4300/acme/revoke-cert"
}`

	testCases := []struct {
		Name         string
		UserAgent    string
		SetFeatures  []string
		ExpectedJSON string
		RandomEntry  bool
	}{
		{
			Name:         "No meta feature enabled, no explicit user-agent",
			ExpectedJSON: noMetaJSONWithoutKeyChange,
		},
		{
			Name:         "Key change feature enabled, no explicit user-agent",
			SetFeatures:  []string{"AllowKeyRollover"},
			ExpectedJSON: noMetaJSONWithKeyChange,
		},
		{
			Name:         "DirectoryMeta feature enabled, no explicit user-agent",
			SetFeatures:  []string{"DirectoryMeta"},
			ExpectedJSON: metaNoKeyChangeJSON,
		},
		{
			Name:         "DirectoryMeta feature enabled, no key change enabled, explicit old Let's Encrypt user-agent",
			SetFeatures:  []string{"DirectoryMeta"},
			UserAgent:    oldUA,
			ExpectedJSON: noMetaJSONWithoutKeyChange,
		},
		{
			Name:         "DirectoryMeta feature enabled, key change enabled, explicit old Let's Encrypt user-agent",
			SetFeatures:  []string{"DirectoryMeta", "AllowKeyRollover"},
			UserAgent:    oldUA,
			ExpectedJSON: noMetaJSONWithoutKeyChange,
		},
		{
			Name:         "DirectoryMeta feature enabled, key change enabled, no explicit user-agent",
			SetFeatures:  []string{"DirectoryMeta", "AllowKeyRollover"},
			ExpectedJSON: metaJSON,
		},
		{
			Name:        "RandomDirectoryEntry feature enabled, no explicit user-agent",
			SetFeatures: []string{"RandomDirectoryEntry"},
			RandomEntry: true,
		},
		{
			Name:        "RandomDirectoryEntry feature enabled, explicit old Let's Encrypt user-agent",
			UserAgent:   oldUA,
			SetFeatures: []string{"RandomDirectoryEntry"},
			RandomEntry: false,
		},
	}

	for _, tc := range testCases {
		// Each test case will set zero or more feature flags
		for _, feature := range tc.SetFeatures {
			_ = features.Set(map[string]bool{feature: true})
		}
		t.Run(tc.Name, func(t *testing.T) {
			// NOTE: the req.URL will be modified and must be constructed per
			// testcase or things will break and you will be confused and sad.
			url, _ := url.Parse("/directory")
			req := &http.Request{
				Method: "GET",
				URL:    url,
				Host:   "127.0.0.1:4300",
			}
			// Set an explicit User-Agent header as directed by the test case
			if tc.UserAgent != "" {
				req.Header = map[string][]string{"User-Agent": []string{tc.UserAgent}}
			}
			// Serve the /directory response for this request into a recorder
			responseWriter := httptest.NewRecorder()
			mux.ServeHTTP(responseWriter, req)
			// We expect all directory requests to return a json object with a good HTTP status
			test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/json")
			test.AssertEquals(t, responseWriter.Code, http.StatusOK)
			// If the test case specifies exact JSON it expects, test that it matches
			if tc.ExpectedJSON != "" {
				test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), tc.ExpectedJSON)
			}
			// Check if there is a random directory key present and if so, that it is
			// expected to be present
			test.AssertEquals(t,
				randomDirectoryKeyPresent(t, responseWriter.Body.Bytes()),
				tc.RandomEntry)
		})
		// Reset the feature flags between test cases to get a blank slate
		features.Reset()
	}
}

func TestRelativeDirectory(t *testing.T) {
	_ = features.Set(map[string]bool{"AllowKeyRollover": true})
	defer features.Reset()
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()

	dirTests := []struct {
		host        string
		protoHeader string
		result      string
	}{
		// Test '' (No host header) with no proto header
		{"", "", `{"key-change":"http://localhost/acme/key-change","new-authz":"http://localhost/acme/new-authz","new-cert":"http://localhost/acme/new-cert","new-reg":"http://localhost/acme/new-reg","revoke-cert":"http://localhost/acme/revoke-cert"}`},
		// Test localhost:4300 with no proto header
		{"localhost:4300", "", `{"key-change":"http://localhost:4300/acme/key-change","new-authz":"http://localhost:4300/acme/new-authz","new-cert":"http://localhost:4300/acme/new-cert","new-reg":"http://localhost:4300/acme/new-reg","revoke-cert":"http://localhost:4300/acme/revoke-cert"}`},
		// Test 127.0.0.1:4300 with no proto header
		{"127.0.0.1:4300", "", `{"key-change":"http://127.0.0.1:4300/acme/key-change","new-authz":"http://127.0.0.1:4300/acme/new-authz","new-cert":"http://127.0.0.1:4300/acme/new-cert","new-reg":"http://127.0.0.1:4300/acme/new-reg","revoke-cert":"http://127.0.0.1:4300/acme/revoke-cert"}`},
		// Test localhost:4300 with HTTP proto header
		{"localhost:4300", "http", `{"key-change":"http://localhost:4300/acme/key-change","new-authz":"http://localhost:4300/acme/new-authz","new-cert":"http://localhost:4300/acme/new-cert","new-reg":"http://localhost:4300/acme/new-reg","revoke-cert":"http://localhost:4300/acme/revoke-cert"}`},
		// Test localhost:4300 with HTTPS proto header
		{"localhost:4300", "https", `{"key-change":"https://localhost:4300/acme/key-change","new-authz":"https://localhost:4300/acme/new-authz","new-cert":"https://localhost:4300/acme/new-cert","new-reg":"https://localhost:4300/acme/new-reg","revoke-cert":"https://localhost:4300/acme/revoke-cert"}`},
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
		test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), tt.result)
	}
}

func TestHTTPMethods(t *testing.T) {
	// Always allow key rollover to test the rolloverPath
	_ = features.Set(map[string]bool{"AllowKeyRollover": true})
	defer features.Reset()

	wfe, _ := setupWFE(t)
	mux := wfe.Handler()

	// NOTE: Boulder's muxer treats HEAD as implicitly allowed if GET is specified
	// so we include both here in `getOnly`
	getOnly := map[string]bool{http.MethodGet: true, http.MethodHead: true}
	postOnly := map[string]bool{http.MethodPost: true}
	getOrPost := map[string]bool{http.MethodGet: true, http.MethodHead: true, http.MethodPost: true}

	testCases := []struct {
		Name    string
		Path    string
		Allowed map[string]bool
	}{
		{
			Name:    "Index path should be GET only",
			Path:    "/",
			Allowed: getOnly,
		},
		{
			Name:    "Directory path should be GET only",
			Path:    directoryPath,
			Allowed: getOnly,
		},
		{
			Name:    "NewReg path should be POST only",
			Path:    newRegPath,
			Allowed: postOnly,
		},
		{
			Name:    "NewAuthz path should be POST only",
			Path:    newAuthzPath,
			Allowed: postOnly,
		},
		{
			Name:    "NewReg path should be POST only",
			Path:    newRegPath,
			Allowed: postOnly,
		},
		{
			Name:    "Reg path should be POST only",
			Path:    regPath,
			Allowed: postOnly,
		},
		{
			Name:    "Authz path should be GET or POST only",
			Path:    authzPath,
			Allowed: getOrPost,
		},
		{
			Name:    "Challenge path should be GET or POST only",
			Path:    challengePath,
			Allowed: getOrPost,
		},
		{
			Name:    "Certificate path should be GET only",
			Path:    certPath,
			Allowed: getOnly,
		},
		{
			Name:    "RevokeCert path should be POST only",
			Path:    revokeCertPath,
			Allowed: postOnly,
		},
		{
			Name:    "Terms path should be GET only",
			Path:    termsPath,
			Allowed: getOnly,
		},
		{
			Name:    "Issuer path should be GET only",
			Path:    issuerPath,
			Allowed: getOnly,
		},
		{
			Name:    "Build ID path should be GET only",
			Path:    buildIDPath,
			Allowed: getOnly,
		},
		{
			Name:    "Rollover path should be POST only",
			Path:    rolloverPath,
			Allowed: postOnly,
		},
	}

	// NOTE: We omit http.MethodOptions because all requests with this method are
	// redirected to a special endpoint for CORS headers
	allMethods := []string{
		http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodTrace,
	}

	responseWriter := httptest.NewRecorder()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// For every possible HTTP method check what the mux serves for the test
			// case path
			for _, method := range allMethods {
				responseWriter.Body.Reset()
				mux.ServeHTTP(responseWriter, &http.Request{
					Method: method,
					URL:    mustParseURL(tc.Path),
				})
				// If the method isn't one that is intended to be allowed by the path,
				// check that the response was the not allowed response
				if _, ok := tc.Allowed[method]; !ok {
					var prob probs.ProblemDetails
					// Unmarshal the body into a problem
					body := responseWriter.Body.String()
					err := json.Unmarshal([]byte(body), &prob)
					test.AssertNotError(t, err, fmt.Sprintf("Error unmarshalling resp body: %q", body))
					// TODO(@cpu): It seems like the mux should be returning
					// http.StatusMethodNotAllowed here, but instead it returns StatusOK
					// with a problem that has a StatusMethodNotAllowed HTTPStatus. Is
					// this a bug?
					test.AssertEquals(t, responseWriter.Code, http.StatusOK)
					test.AssertEquals(t, prob.HTTPStatus, http.StatusMethodNotAllowed)
					test.AssertEquals(t, prob.Detail, "Method not allowed")
				} else {
					// Otherwise if it was an allowed method, ensure that the response was
					// *not* StatusMethodNotAllowed
					test.AssertNotEquals(t, responseWriter.Code, http.StatusMethodNotAllowed)
				}
			}
		})
	}
}

// TODO: Write additional test cases for:
//  - RA returns with a failure
func TestIssueCertificate(t *testing.T) {
	wfe, fc := setupWFE(t)
	mockLog := wfe.log.(*blog.Mock)

	// The mock CA we use always returns the same test certificate, with a Not
	// Before of 2015-09-22. Since we're currently using a real RA instead of a
	// mock (see below), that date would trigger failures for excessive
	// backdating. So we set the fake clock's time to a time that matches that
	// test certificate.
	testTime := time.Date(2015, 9, 9, 22, 56, 0, 0, time.UTC)
	fc.Add(fc.Now().Sub(testTime))

	mockCertPEM, err := ioutil.ReadFile("test/not-an-example.com.crt")
	test.AssertNotError(t, err, "Could not load mock cert")

	// TODO: Use a mock RA so we can test various conditions of authorized, not
	// authorized, etc.
	stats := metrics.NewNoopScope()
	ra := ra.NewRegistrationAuthorityImpl(
		fc,
		wfe.log,
		stats,
		0,
		testKeyPolicy,
		0,
		true,
		false,
		300*24*time.Hour,
		7*24*time.Hour,
		nil,
	)
	ra.SA = mocks.NewStorageAuthority(fc)
	ra.CA = &mocks.MockCA{
		PEM: mockCertPEM,
	}
	ra.PA = &mockPA{}
	wfe.RA = ra

	targetHost := "localhost"
	targetPath := "new-cert"
	signedURL := fmt.Sprintf("http://%s/%s", targetHost, targetPath)

	// Valid, signed JWS body, payload has an invalid signature on CSR and no authorizations:
	// alias b64url="base64 -w0 | sed -e 's,+,-,g' -e 's,/,_,g'"
	// openssl req -outform der -new -nodes -key wfe/test/178.key -subj /CN=foo.com | \
	// sed 's/foo.com/fob.com/' | b64url
	brokenCSRSignaturePayload := `{
      "csr": "MIICVzCCAT8CAQAwEjEQMA4GA1UEAwwHZm9iLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKzHhqcMSTVjBu61vufGVmIYM4mMbWXgndHOUWnIqSKcNtFtPQ465tcZRT5ITIZWXGjsmgDrj31qvG3t5qLwyaF5hsTvFHK72nLMAQhdgM6481Qe9yaoaulWpkGr_9LVz4jQ9pGAaLVamXGpSxV-ipTOo79Sev4aZE8ksD9atEfWtcOD9w8_zj74vpWjTAHN49Q88chlChVqakn0zSfHPfS-jF8g0UTddBuF0Ti3sZChjxzbo6LwZ4182xX7XPnOLav3AGj0Su7j5XMl3OpenOrlWulWJeZIHq5itGW321j306XiGdbrdWH4K7JygICFds6oolwQRGBY6yinAtCgkTcCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBxPiHOtKuBxtvecMNtLkTSuTyEkusQGnjoFDaKe5oqwGYQgy0YBii2-BbaPmqS4ZaDc-vDz_RLeKH5ZiH-NliYR1V_CRtpFLQi18g_2pLQnZLVO3ENs-SM37nU_nBGn9O93t2bkssoM3fZmtgp3R2W7I_wvx7Z8oWKa4boTeBAg_q9Gmi6QskZBddK7A4S_vOR0frU6QSPK_ksPhvovp9fwb6CVKrlJWf556UwRPWgbkW39hvTxK2KHhrUEg3oawNkWde2jZtnZ9e-9zpw8-_5O0X7-YN0ucbFTfQybce_ReuLlGepiHT5bvVavBZoIvqw1XOgSMvGgZFU8tAWMBlj"
    }`

	// Valid, signed JWS body, payload has a valid CSR but no authorizations:
	// openssl req -outform der -new -nodes -key wfe/test/178.key -subj /CN=meep.com | b64url
	noAuthorizationsCSRPayload := `{
			"resource":"new-cert",
			"csr": "MIICWDCCAUACAQAwEzERMA8GA1UEAwwIbWVlcC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCaqzue57mgXEoGTZZoVkkCZraebWgXI8irX2BgQB1A3iZa9onxGPMcWQMxhSuUisbEJi4UkMcVST12HX01rUwhj41UuBxJvI1w4wvdstssTAaa9c9tsQ5-UED2bFRL1MsyBdbmCF_-pu3i-ZIYqWgiKbjVBe3nlAVbo77zizwp3Y4Tp1_TBOwTAuFkHePmkNT63uPm9My_hNzsSm1o-Q519Cf7ry-JQmOVgz_jIgFVGFYJ17EV3KUIpUuDShuyCFATBQspgJSN2DoXRUlQjXXkNTj23OxxdT_cVLcLJjytyG6e5izME2R2aCkDBWIc1a4_sRJ0R396auPXG6KhJ7o_AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEALu046p76aKgvoAEHFINkMTgKokPXf9mZ4IZx_BKz-qs1MPMxVtPIrQDVweBH6tYT7Hfj2naLry6SpZ3vUNP_FYeTFWgW1V03LiqacX-QQgbEYtn99Dt3ScGyzb7EH833ztb3vDJ_-ha_CJplIrg-kHBBrlLFWXhh-I9K1qLRTNpbhZ18ooFde4Sbhkw9o9fKivGhx9aYr7ZbjRsNtKit_DsG1nwEXz53TMJ2vB9IQY29coJv_n5NFLkvBfzbG5faRNiFcimPYBO2jFdaA2mWzfxltLtwMF_dBwzTXDpMo3TVT9zEdV8YpsWqr63igqGDZVpKenlkqvRTeGJVayVuMA"
		}`

	// CSR from an < 1.0.2 OpenSSL
	oldOpenSSLCSRPayload := `{
      "resource": "new-cert",
      "csr": "MIICWjCCAUICADAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMpwCSKfLhKC3SnvLNpVayAEyAHVixkusgProAPZRBH0VAog_r4JOfoJez7ABiZ2ZIXXA2gg65_05HkGNl9ww-sa0EY8eCty_8WcHxqzafUnyXOJZuLMPJjaJ2oiBv_3BM7PZgpFzyNZ0_0ZuRKdFGtEY-vX9GXZUV0A3sxZMOpce0lhHAiBk_vNARJyM2-O-cZ7WjzZ7R1T9myAyxtsFhWy3QYvIwiKVVF3lDp3KXlPZ_7wBhVIBcVSk0bzhseotyUnKg-aL5qZIeB1ci7IT5qA_6C1_bsCSJSbQ5gnQwIQ0iaUV_SgUBpKNqYbmnSdZmDxvvW8FzhuL6JSDLfBR2kCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBxxkchTXfjv07aSWU9brHnRziNYOLvsSNiOWmWLNlZg9LKdBy6j1xwM8IQRCfTOVSkbuxVV-kU5p-Cg9UF_UGoerl3j8SiupurTovK9-L_PdX0wTKbK9xkh7OUq88jp32Rw0eAT87gODJRD-M1NXlTvm-j896e60hUmL-DIe3iPbFl8auUS-KROAWjci-LJZYVdomm9Iw47E-zr4Hg27EdZhvCZvSyPMK8ioys9mNg5TthHB6ExepKP1YW3HpQa1EdUVYWGEvyVL4upQZOxuEA1WJqHv6iVDzsQqkl5kkahK87NKTPS59k1TFetjw2GLnQ09-g_L7kT8dpq3Bk5Wo="
    }`

	// openssl req -outform der -new -nodes -key wfe/test/178.key -subj /CN=not-an-example.com | b64url
	// a valid CSR with authorizations for all of its names
	goodCertCSRPayload := `{
			"resource":"new-cert",
			"csr": "MIICYjCCAUoCAQAwHTEbMBkGA1UEAwwSbm90LWFuLWV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmqs7nue5oFxKBk2WaFZJAma2nm1oFyPIq19gYEAdQN4mWvaJ8RjzHFkDMYUrlIrGxCYuFJDHFUk9dh19Na1MIY-NVLgcSbyNcOML3bLbLEwGmvXPbbEOflBA9mxUS9TLMgXW5ghf_qbt4vmSGKloIim41QXt55QFW6O-84s8Kd2OE6df0wTsEwLhZB3j5pDU-t7j5vTMv4Tc7EptaPkOdfQn-68viUJjlYM_4yIBVRhWCdexFdylCKVLg0obsghQEwULKYCUjdg6F0VJUI115DU49tzscXU_3FS3CyY8rchunuYszBNkdmgpAwViHNWuP7ESdEd_emrj1xuioSe6PwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE_T1nWU38XVYL28hNVSXU0rW5IBUKtbvr0qAkD4kda4HmQRTYkt-LNSuvxoZCC9lxijjgtJi-OJe_DCTdZZpYzewlVvcKToWSYHYQ6Wm1-fxxD_XzphvZOujpmBySchdiz7QSVWJmVZu34XD5RJbIcrmj_cjRt42J1hiTFjNMzQu9U6_HwIMmliDL-soFY2RTvvZf-dAFvOUQ-Wbxt97eM1PbbmxJNWRhbAmgEpe9PWDPTpqV5AK56VAa991cQ1P8ZVmPss5hvwGWhOtpnpTZVHN3toGNYFKqxWPboirqushQlfKiFqT9rpRgM3-mFjOHidGqsKEkTdmfSVlVEk3oo="
		}`

	cert, err := core.LoadCert("test/not-an-example.com.crt")
	test.AssertNotError(t, err, "Could not load cert")

	goodCertHeaders := map[string]string{
		"Location":     "http://localhost/acme/cert/0000ff0000000000000e4b4f67d86e818c46",
		"Link":         `<http://localhost/acme/issuer-cert>;rel="up"`,
		"Content-Type": "application/pkix-cert",
	}
	// NOTE(@cpu): Unlike the test case above this case expects
	// `localhost:4000` in the Link header value since the AIAIssuer flag
	// will have been true. The WFE will also promote it from HTTP to HTTPS.
	goodCertAIAHeaders := map[string]string{
		"Location":     "http://localhost/acme/cert/0000ff0000000000000e4b4f67d86e818c46",
		"Link":         `<https://localhost:4000/acme/issuer-cert>;rel="up"`,
		"Content-Type": "application/pkix-cert",
	}
	goodCertLogParts := []string{
		`INFO: `,
		`[AUDIT] `,
		`"CommonName":"not-an-example.com",`,
	}

	testCases := []struct {
		Name             string
		Request          *http.Request
		ExpectedProblem  string
		ExpectedCert     string
		AssertCSRLogged  bool
		ExpectedHeaders  map[string]string
		ExpectedLogParts []string
		UseAIAIssuer     bool
	}{
		{
			Name: "POST, but no body",
			Request: &http.Request{
				Method: "POST",
				Header: map[string][]string{
					"Content-Length": {"0"},
				},
			},
			ExpectedProblem: `{"type":"urn:acme:error:malformed","detail":"No body on POST","status":400}`,
		},
		{
			Name:            "POST, with an invalid JWS body",
			Request:         makePostRequestWithPath("hi", "hi"),
			ExpectedProblem: `{"type":"urn:acme:error:malformed","detail":"Parse error reading JWS","status":400}`,
		},
		{
			Name:            "POST, properly signed JWS, payload isn't valid",
			Request:         signAndPost(t, targetPath, signedURL, "foo", 1, wfe.nonceService),
			ExpectedProblem: `{"type":"urn:acme:error:malformed","detail":"Request payload did not parse as JSON","status":400}`,
		},
		{
			Name:            "POST, properly signed JWS, trivial JSON payload",
			Request:         signAndPost(t, targetPath, signedURL, "{}", 1, wfe.nonceService),
			ExpectedProblem: `{"type":"urn:acme:error:malformed","detail":"Error parsing certificate request: asn1: syntax error: sequence truncated","status":400}`,
		},
		{
			Name:            "POST, properly signed JWS, broken signature on CSR",
			Request:         signAndPost(t, targetPath, signedURL, brokenCSRSignaturePayload, 1, wfe.nonceService),
			ExpectedProblem: `{"type":"urn:acme:error:malformed","detail":"Error creating new cert :: invalid signature on CSR","status":400}`,
		},
		{
			Name:            "POST, properly signed JWS, CSR from an old OpenSSL",
			Request:         signAndPost(t, targetPath, signedURL, oldOpenSSLCSRPayload, 1, wfe.nonceService),
			ExpectedProblem: `{"type":"urn:acme:error:malformed","detail":"CSR generated using a pre-1.0.2 OpenSSL with a client that doesn't properly specify the CSR version. See https://community.letsencrypt.org/t/openssl-bug-information/19591","status":400}`,
		},
		{
			Name:            "POST, properly signed JWS, no authorizations for names in CSR",
			Request:         signAndPost(t, targetPath, signedURL, noAuthorizationsCSRPayload, 1, wfe.nonceService),
			ExpectedProblem: `{"type":"urn:acme:error:unauthorized","detail":"Error creating new cert :: authorizations for these names not found or expired: meep.com","status":403}`,
			AssertCSRLogged: true,
		},
		{
			Name:             "POST, properly signed JWS, authorizations for all names in CSR",
			Request:          signAndPost(t, targetPath, signedURL, goodCertCSRPayload, 1, wfe.nonceService),
			ExpectedCert:     string(cert.Raw),
			AssertCSRLogged:  true,
			ExpectedHeaders:  goodCertHeaders,
			ExpectedLogParts: goodCertLogParts,
		},
		{
			Name:             "POST, properly signed JWS, authorizations for all names in CSR, using AIAIssuer",
			Request:          signAndPost(t, targetPath, signedURL, goodCertCSRPayload, 1, wfe.nonceService),
			ExpectedCert:     string(cert.Raw),
			AssertCSRLogged:  true,
			UseAIAIssuer:     true,
			ExpectedHeaders:  goodCertAIAHeaders,
			ExpectedLogParts: goodCertLogParts,
		},
	}

	responseWriter := httptest.NewRecorder()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			responseWriter.Body.Reset()
			responseWriter.HeaderMap = http.Header{}
			mockLog.Clear()

			if tc.UseAIAIssuer {
				_ = features.Set(map[string]bool{"UseAIAIssuerURL": true})
			}

			wfe.NewCertificate(ctx, newRequestEvent(), responseWriter, tc.Request)
			if len(tc.ExpectedProblem) > 0 {
				test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), tc.ExpectedProblem)
			} else if len(tc.ExpectedCert) > 0 {
				test.AssertEquals(t, responseWriter.Body.String(), tc.ExpectedCert)
			}

			if tc.AssertCSRLogged {
				assertCsrLogged(t, mockLog)
			}

			headers := responseWriter.Header()
			for k, v := range tc.ExpectedHeaders {
				test.AssertEquals(t, headers.Get(k), v)
			}

			if len(tc.ExpectedLogParts) > 0 {
				reqlogs := mockLog.GetAllMatching(`Certificate request - successful`)
				test.AssertEquals(t, len(reqlogs), 1)
				for _, msg := range tc.ExpectedLogParts {
					test.AssertContains(t, reqlogs[0], msg)
				}
			}
			features.Reset()
		})
	}
}

func TestGetChallenge(t *testing.T) {
	wfe, _ := setupWFE(t)

	challengeURL := "http://localhost/acme/challenge/valid/23"

	for _, method := range []string{"GET", "HEAD"} {
		resp := httptest.NewRecorder()

		req, err := http.NewRequest(method, challengeURL, nil)
		req.URL.Path = "valid/23"
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
			`<http://localhost/acme/authz/valid>;rel="up"`)
		// Body is only relevant for GET. For HEAD, body will
		// be discarded by HandleFunc() anyway, so it doesn't
		// matter what Challenge() writes to it.
		if method == "GET" {
			test.AssertUnmarshaledEquals(
				t, resp.Body.String(),
				`{"type":"dns","uri":"http://localhost/acme/challenge/valid/23"}`)
		}
	}
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

	targetHost := "localhost"
	challengePath := "valid/23"
	signedURL := fmt.Sprintf("http://%s/%s", targetHost, challengePath)
	_, _, body := signRequestKeyID(t, 1, nil, signedURL, `{}`, wfe.nonceService)
	request := makePostRequestWithPath(challengePath, body)
	wfe.Challenge(ctx, newRequestEvent(), responseWriter, request)

	test.AssertEquals(t, responseWriter.Code, 202)
	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"http://localhost/acme/challenge/valid/23")
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		`<http://localhost/acme/authz/valid>;rel="up"`)
	test.AssertUnmarshaledEquals(
		t, responseWriter.Body.String(),
		`{"type":"dns","uri":"http://localhost/acme/challenge/valid/23"}`)

	// Expired challenges should be inaccessible
	challengePath = "expired/23"
	signedURL = fmt.Sprintf("http://%s/%s", targetHost, challengePath)
	responseWriter = httptest.NewRecorder()
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, `{}`, wfe.nonceService)
	request = makePostRequestWithPath(challengePath, body)
	wfe.Challenge(ctx, newRequestEvent(), responseWriter, request)
	test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Expired authorization","status":404}`)

	// Challenge Not found
	challengePath = ""
	signedURL = fmt.Sprintf("http://%s/%s", targetHost, challengePath)
	responseWriter = httptest.NewRecorder()
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, `{}`, wfe.nonceService)
	request = makePostRequestWithPath(challengePath, body)
	wfe.Challenge(ctx, newRequestEvent(), responseWriter, request)
	test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"No such challenge","status":404}`)

	// Unspecified database error
	errorPath := "error_result/24"
	signedURL = fmt.Sprintf("http://%s/%s", targetHost, errorPath)
	responseWriter = httptest.NewRecorder()
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, `{}`, wfe.nonceService)
	request = makePostRequestWithPath(errorPath, body)
	wfe.Challenge(ctx, newRequestEvent(), responseWriter, request)
	test.AssertEquals(t, responseWriter.Code, http.StatusInternalServerError)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"urn:acme:error:serverInternal","detail":"Problem getting authorization","status":500}`)

}

func TestBadNonce(t *testing.T) {
	wfe, _ := setupWFE(t)

	key := loadKeys(t, []byte(test2KeyPrivatePEM))
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	// NOTE: We deliberately do not set the NonceSource in the jose.SignerOptions
	// for this test in order to provoke a bad nonce error
	signer, err := jose.NewSigner(jose.SigningKey{
		Key:       rsaKey,
		Algorithm: jose.RS256,
	}, &jose.SignerOptions{
		EmbedJWK: true,
	})
	test.AssertNotError(t, err, "Failed to make signer")

	responseWriter := httptest.NewRecorder()
	result, err := signer.Sign([]byte(`{"contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`))
	test.AssertNotError(t, err, "Failed to sign body")
	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("nonce", result.FullSerialize()))
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:badNonce","detail":"JWS has no anti-replay nonce","status":400}`)
}

func TestNewECDSARegistration(t *testing.T) {
	wfe, _ := setupWFE(t)

	// E1 always exists; E2 never exists
	key := loadKeys(t, []byte(testE2KeyPrivatePEM))
	_, ok := key.(*ecdsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load ECDSA key")

	payload := `{"resource":"new-reg","contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`
	path := "new-reg"
	signedURL := fmt.Sprintf("http://localhost/%s", path)
	_, _, body := signRequestEmbed(t, key, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	responseWriter := httptest.NewRecorder()
	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter, request)

	var reg core.Registration
	responseBody := responseWriter.Body.String()
	err := json.Unmarshal([]byte(responseBody), &reg)
	test.AssertNotError(t, err, "Couldn't unmarshal returned registration object")
	test.Assert(t, len(*reg.Contact) >= 1, "No contact field in registration")
	test.AssertEquals(t, (*reg.Contact)[0], "mailto:person@mail.com")
	test.AssertEquals(t, reg.Agreement, "http://example.invalid/terms")
	test.AssertEquals(t, reg.InitialIP.String(), "1.1.1.1")

	test.AssertEquals(t, responseWriter.Header().Get("Location"), "http://localhost/acme/reg/0")

	key = loadKeys(t, []byte(testE1KeyPrivatePEM))
	_, ok = key.(*ecdsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load ECDSA key")

	_, _, body = signRequestEmbed(t, key, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	// Reset the body and status code
	responseWriter = httptest.NewRecorder()
	// POST, Valid JSON, Key already in use
	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter, request)
	responseBody = responseWriter.Body.String()
	test.AssertUnmarshaledEquals(t, responseBody, `{"type":"urn:acme:error:malformed","detail":"Registration key is already in use","status":409}`)
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
	key := loadKeys(t, []byte(test1KeyPrivatePEM))
	_, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")

	payload := `{}`
	path := "1"
	signedURL := "http://localhost/1"
	_, _, body := signRequestKeyID(t, 1, key, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	// Send a registration update with the trivial body
	wfe.Registration(
		ctx,
		newRequestEvent(),
		responseWriter,
		request)

	responseBody := responseWriter.Body.String()
	// There should be no error
	test.AssertNotContains(t, responseBody, "urn:acme:error")

	// We should get back a populated Registration
	var reg core.Registration
	err := json.Unmarshal([]byte(responseBody), &reg)
	test.AssertNotError(t, err, "Couldn't unmarshal returned registration object")
	test.Assert(t, len(*reg.Contact) >= 1, "No contact field in registration")
	test.AssertEquals(t, (*reg.Contact)[0], "mailto:person@mail.com")
	test.AssertEquals(t, reg.Agreement, "http://example.invalid/terms")
	responseWriter.Body.Reset()
}

func TestNewRegistration(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()
	key := loadKeys(t, []byte(test2KeyPrivatePEM))
	_, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load test2 key")

	path := newRegPath
	signedURL := fmt.Sprintf("http://localhost%s", newRegPath)

	wrongAgreementReg := `{"contact":["mailto:person@mail.com"],"agreement":"https://letsencrypt.org/im-bad"}`
	// A reg with the wrong agreement URL
	_, _, wrongAgreementBody := signRequestEmbed(t, key, signedURL, wrongAgreementReg, wfe.nonceService)

	// A non-JSON payload
	_, _, fooBody := signRequestEmbed(t, key, signedURL, `foo`, wfe.nonceService)

	type newRegErrorTest struct {
		r        *http.Request
		respBody string
	}

	regErrTests := []newRegErrorTest{
		// POST, but no body.
		{
			&http.Request{
				Method: "POST",
				URL:    mustParseURL(newRegPath),
				Header: map[string][]string{
					"Content-Length": {"0"},
				},
			},
			`{"type":"urn:acme:error:malformed","detail":"No body on POST","status":400}`,
		},

		// POST, but body that isn't valid JWS
		{
			makePostRequestWithPath(newRegPath, "hi"),
			`{"type":"urn:acme:error:malformed","detail":"Parse error reading JWS","status":400}`,
		},

		// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
		{
			makePostRequestWithPath(newRegPath, fooBody),
			`{"type":"urn:acme:error:malformed","detail":"Request payload did not parse as JSON","status":400}`,
		},

		// Same signed body, but payload modified by one byte, breaking signature.
		// should fail JWS verification.
		{
			makePostRequestWithPath(newRegPath,
				`{"payload":"Zm9x","protected":"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoicW5BUkxyVDdYejRnUmNLeUxkeWRtQ3ItZXk5T3VQSW1YNFg0MHRoazNvbjI2RmtNem5SM2ZSanM2NmVMSzdtbVBjQlo2dU9Kc2VVUlU2d0FhWk5tZW1vWXgxZE12cXZXV0l5aVFsZUhTRDdROHZCcmhSNnVJb080akF6SlpSLUNoelp1U0R0N2lITi0zeFVWc3B1NVhHd1hVX01WSlpzaFR3cDRUYUZ4NWVsSElUX09iblR2VE9VM1hoaXNoMDdBYmdaS21Xc1ZiWGg1cy1DcklpY1U0T2V4SlBndW5XWl9ZSkp1ZU9LbVR2bkxsVFY0TXpLUjJvWmxCS1oyN1MwLVNmZFZfUUR4X3lkbGU1b01BeUtWdGxBVjM1Y3lQTUlzWU53Z1VHQkNkWV8yVXppNWVYMGxUYzdNUFJ3ejZxUjFraXAtaTU5VmNHY1VRZ3FIVjZGeXF3IiwiZSI6IkFRQUIifSwia2lkIjoiIiwibm9uY2UiOiJyNHpuenZQQUVwMDlDN1JwZUtYVHhvNkx3SGwxZVBVdmpGeXhOSE1hQnVvIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdC9hY21lL25ldy1yZWcifQ","signature":"jcTdxSygm_cvD7KbXqsxgnoPApCTSkV4jolToSOd2ciRkg5W7Yl0ZKEEKwOc-dYIbQiwGiDzisyPCicwWsOUA1WSqHylKvZ3nxSMc6KtwJCW2DaOqcf0EEjy5VjiZJUrOt2c-r6b07tbn8sfOJKwlF2lsOeGi4s-rtvvkeQpAU-AWauzl9G4bv2nDUeCviAZjHx_PoUC-f9GmZhYrbDzAvXZ859ktM6RmMeD0OqPN7bhAeju2j9Gl0lnryZMtq2m0J2m1ucenQBL1g4ZkP1JiJvzd2cAz5G7Ftl2YeJJyWhqNd3qq0GVOt1P11s8PTGNaSoM0iR9QfUxT9A6jxARtg"}`),
			`{"type":"urn:acme:error:malformed","detail":"JWS verification error","status":400}`,
		},
		{
			makePostRequestWithPath(newRegPath, wrongAgreementBody),
			`{"type":"urn:acme:error:malformed","detail":"Provided agreement URL [https://letsencrypt.org/im-bad] does not match current agreement URL [` + agreementURL + `]","status":400}`,
		},
	}
	for _, rt := range regErrTests {
		responseWriter := httptest.NewRecorder()
		mux.ServeHTTP(responseWriter, rt.r)
		test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), rt.respBody)
	}

	responseWriter := httptest.NewRecorder()

	payload := `{"contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`
	_, _, body := signRequestEmbed(t, key, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter, request)

	var reg core.Registration
	responseBody := responseWriter.Body.String()
	err := json.Unmarshal([]byte(responseBody), &reg)
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

	key = loadKeys(t, []byte(test1KeyPrivatePEM))
	_, ok = key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load test1 key")

	// Reset the body and status code
	responseWriter = httptest.NewRecorder()

	// POST, Valid JSON, Key already in use
	_, _, body = signRequestEmbed(t, key, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	wfe.NewRegistration(ctx, newRequestEvent(), responseWriter, request)
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Registration key is already in use","status":409}`)
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

func TestAuthorization(t *testing.T) {
	wfe, _ := setupWFE(t)

	responseWriter := httptest.NewRecorder()

	// POST, but no body.
	responseWriter.Body.Reset()
	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "POST",
		Header: map[string][]string{
			"Content-Length": {"0"},
		},
	})
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:malformed","detail":"No body on POST","status":400}`)

	// POST, but body that isn't valid JWS
	responseWriter.Body.Reset()
	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter, makePostRequestWithPath("hi", "hi"))
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Parse error reading JWS","status":400}`)

	signedURL := fmt.Sprintf("http://localhost%s", authzPath)
	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	_, _, fooBody := signRequestKeyID(t, 1, nil, signedURL, `foo`, wfe.nonceService)
	request := makePostRequestWithPath(authzPath, fooBody)

	responseWriter.Body.Reset()
	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter, request)
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Request payload did not parse as JSON","status":400}`)

	// Same signed body, but payload modified by one byte, breaking signature.
	// should fail JWS verification.
	responseWriter.Body.Reset()
	request = makePostRequestWithPath(authzPath,
		`{"payload":"Zm9x","protected":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjEiLCJub25jZSI6ImdMTE90QlJCeXl4V3Y2RExQRUJFUERsS05DV294NzdjYzBRLXdTSVdYY1UiLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0L2FjbWUvYXV0aHovIn0","signature":"Xn2yTyn1eIgbv1HOnl8_OuDMrHRlacje_fhAYyOlVmFGrb9vzTTYQ-TXdXpjrtQzcIRX7z0v1Wv3DJJryMAMwm-I9DN-Gmd_h1HG6KXK61vHIqMWlUen2WoBBNdeE00S5UI0iP-zY5E_jfW0ByLzAqoZeMN_vTJG40Ji9hfvaPaQBGLEcz6xw0Mc7EgacY6m_JGPBkCDvrDstHTTqIu5tZ3Dw7tif33aakONDKXVE0WOHjfHNP-jW4tkeCrlIDajWpU074AGmCMyBDXK5ii6Pv6tztcMPqg8SvL9_I7RyCsjQGCymNCr_XoJkRwS6GBoaKS5Jqmb-qt-O_-rcpq-Fw"}`)
	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter, request)
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"JWS verification error","status":400}`)

	responseWriter.Body.Reset()
	payload := `{"identifier":{"type":"dns","value":"test.com"}}`
	_, _, body := signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(authzPath, body)

	wfe.NewAuthorization(ctx, newRequestEvent(), responseWriter, request)

	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"http://localhost/acme/authz/bkrPh2u0JUf18-rVBZtOOWWb3GuIiliypL-hBM9Ak1Q")
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		`<http://localhost/acme/new-cert>;rel="next"`)

	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"identifier":{"type":"dns","value":"test.com"}}`)

	var authz core.Authorization
	err := json.Unmarshal([]byte(responseWriter.Body.String()), &authz)
	test.AssertNotError(t, err, "Couldn't unmarshal returned authorization object")

	// Expired authorizations should be inaccessible
	authzURL := "expired"
	responseWriter = httptest.NewRecorder()
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(authzURL),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Expired authorization","status":404}`)
	responseWriter.Body.Reset()

	// Ensure that a valid authorization can't be reached with an invalid URL
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		URL:    mustParseURL("/a/bunch/of/garbage/valid"),
		Method: "GET",
	})
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Unable to find authorization","status":404}`)
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
	_ = features.Set(map[string]bool{"AllowKeyRollover": true})
	defer features.Reset()
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()
	responseWriter := httptest.NewRecorder()

	// Test GET proper entry returns 405
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(regPath),
	})
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Method not allowed","status":405}`)
	responseWriter.Body.Reset()

	// Test POST invalid JSON
	wfe.Registration(ctx, newRequestEvent(), responseWriter, makePostRequestWithPath("2", "invalid"))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Parse error reading JWS","status":400}`)
	responseWriter.Body.Reset()

	key := loadKeys(t, []byte(test2KeyPrivatePEM))
	_, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")

	signedURL := fmt.Sprintf("http://localhost%s%d", regPath, 102)
	path := fmt.Sprintf("%s%d", regPath, 102)
	payload := `{"resource":"reg","agreement":"` + agreementURL + `"}`
	// ID 102 is used by the mock for missing reg
	_, _, body := signRequestKeyID(t, 102, nil, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	// Test POST valid JSON but key is not registered
	wfe.Registration(ctx, newRequestEvent(), responseWriter, request)
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:ietf:params:acme:error:accountDoesNotExist","detail":"Account \"102\" not found","status":400}`)
	responseWriter.Body.Reset()

	key = loadKeys(t, []byte(test1KeyPrivatePEM))
	_, ok = key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")

	// Test POST valid JSON with registration up in the mock (with incorrect agreement URL)
	payload = `{"agreement":"https://letsencrypt.org/im-bad"}`
	path = "1"
	signedURL = "http://localhost/1"
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	wfe.Registration(ctx, newRequestEvent(), responseWriter, request)
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Provided agreement URL [https://letsencrypt.org/im-bad] does not match current agreement URL [`+agreementURL+`]","status":400}`)
	responseWriter.Body.Reset()

	// Test POST valid JSON with registration up in the mock (with correct agreement URL)
	payload = `{"resource":"reg","agreement":"` + agreementURL + `"}`
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	wfe.Registration(ctx, newRequestEvent(), responseWriter, request)
	test.AssertNotContains(t, responseWriter.Body.String(), "urn:acme:error")
	links := responseWriter.Header()["Link"]
	test.AssertEquals(t, contains(links, "<http://localhost/acme/new-authz>;rel=\"next\""), true)
	test.AssertEquals(t, contains(links, "<"+agreementURL+">;rel=\"terms-of-service\""), true)
	responseWriter.Body.Reset()

	// Test POST valid JSON with garbage in URL but valid registration ID
	payload = `{"resource":"reg","agreement":"` + agreementURL + `"}`
	signedURL = "http://localhost/a/bunch/of/garbage/1"
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath("/a/bunch/of/garbage/1", body)

	wfe.Registration(ctx, newRequestEvent(), responseWriter, request)
	test.AssertContains(t, responseWriter.Body.String(), "400")
	test.AssertContains(t, responseWriter.Body.String(), "urn:acme:error:malformed")
	responseWriter.Body.Reset()

	// Test POST valid JSON with registration up in the mock (with old agreement URL)
	responseWriter.HeaderMap = http.Header{}
	wfe.SubscriberAgreementURL = "http://example.invalid/new-terms"
	payload = `{"resource":"reg","agreement":"` + agreementURL + `"}`
	signedURL = "http://localhost/1"
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	wfe.Registration(ctx, newRequestEvent(), responseWriter, request)
	test.AssertNotContains(t, responseWriter.Body.String(), "urn:acme:error")
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
	wfe.IssuerCacheDuration = time.Second * 10
	wfe.IssuerCert = []byte{0, 0, 1}

	responseWriter := httptest.NewRecorder()

	wfe.Issuer(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.Assert(t, bytes.Compare(responseWriter.Body.Bytes(), wfe.IssuerCert) == 0, "Incorrect bytes returned")
}

func TestGetCertificate(t *testing.T) {
	_ = features.Set(map[string]bool{"UseAIAIssuerURL": false})
	defer features.Reset()
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()

	wfe.CertCacheDuration = time.Second * 10
	wfe.CertNoCacheExpirationWindow = time.Hour * 24 * 7

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

	// Valid serial, UseAIAIssuerURL: true
	mockLog.Clear()
	responseWriter = httptest.NewRecorder()
	_ = features.Set(map[string]bool{"UseAIAIssuerURL": true})
	req, _ = http.NewRequest("GET", "/acme/cert/0000000000000000000000000000000000b2", nil)
	req.RemoteAddr = "192.168.0.1"
	mux.ServeHTTP(responseWriter, req)
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		`<https://localhost:4000/acme/issuer-cert>;rel="up"`)

	reqlogs := mockLog.GetAllMatching(`Successful request`)
	test.AssertEquals(t, len(reqlogs), 1)
	test.AssertContains(t, reqlogs[0], `INFO: `)

	// Unused serial, no cache
	mockLog.Clear()
	responseWriter = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/acme/cert/0000000000000000000000000000000000ff", nil)
	req.RemoteAddr = "192.168.0.1"
	req.Header.Set("X-Forwarded-For", "192.168.99.99")
	mux.ServeHTTP(responseWriter, req)
	test.AssertEquals(t, responseWriter.Code, 404)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Certificate not found","status":404}`)

	reqlogs = mockLog.GetAllMatching(`Terminated request`)
	test.AssertEquals(t, len(reqlogs), 1)
	test.AssertContains(t, reqlogs[0], `INFO: `)

	// Invalid serial, no cache
	responseWriter = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/acme/cert/nothex", nil)
	mux.ServeHTTP(responseWriter, req)
	test.AssertEquals(t, responseWriter.Code, 404)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Certificate not found","status":404}`)

	// Invalid serial, no cache
	responseWriter = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/acme/cert/00000000000000", nil)
	mux.ServeHTTP(responseWriter, req)
	test.AssertEquals(t, responseWriter.Code, 404)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Certificate not found","status":404}`)
}

func assertCsrLogged(t *testing.T, mockLog *blog.Mock) {
	matches := mockLog.GetAllMatching("^INFO: \\[AUDIT\\] Certificate request JSON=")
	test.Assert(t, len(matches) == 1,
		fmt.Sprintf("Incorrect number of certificate request log entries: %d",
			len(matches)))
}

func TestLogCsrPem(t *testing.T) {
	const certificateRequestJSON = `{
		"csr": "MIICWTCCAUECAQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAycX3ca-fViOuRWF38mssORISFxbJvspDfhPGRBZDxJ63NIqQzupB-6dp48xkcX7Z_KDaRJStcpJT2S0u33moNT4FHLklQBETLhExDk66cmlz6Xibp3LGZAwhWuec7wJoEwIgY8oq4rxihIyGq7HVIJoq9DqZGrUgfZMDeEJqbphukQOaXGEop7mD-eeu8-z5EVkB1LiJ6Yej6R8MAhVPHzG5fyOu6YVo6vY6QgwjRLfZHNj5XthxgPIEETZlUbiSoI6J19GYHvLURBTy5Ys54lYAPIGfNwcIBAH4gtH9FrYcDY68R22rp4iuxdvkf03ZWiT0F2W1y7_C9B2jayTzvQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAHd6Do9DIZ2hvdt1GwBXYjsqprZidT_DYOMfYcK17KlvdkFT58XrBH88ulLZ72NXEpiFMeTyzfs3XEyGq_Bbe7TBGVYZabUEh-LOskYwhgcOuThVN7tHnH5rhN-gb7cEdysjTb1QL-vOUwYgV75CB6PE5JVYK-cQsMIVvo0Kz4TpNgjJnWzbcH7h0mtvub-fCv92vBPjvYq8gUDLNrok6rbg05tdOJkXsF2G_W-Q6sf2Fvx0bK5JeH4an7P7cXF9VG9nd4sRt5zd-L3IcyvHVKxNhIJXZVH0AOqh_1YrKI9R0QKQiZCEy0xN1okPlcaIVaFhb7IKAHPxTI3r5f72LXY"
	}`
	wfe, fc := setupWFE(t)
	var certificateRequest core.CertificateRequest
	err := json.Unmarshal([]byte(certificateRequestJSON), &certificateRequest)
	test.AssertNotError(t, err, "Unable to parse certificateRequest")

	mockSA := mocks.NewStorageAuthority(fc)
	reg, err := mockSA.GetRegistration(ctx, 789)
	test.AssertNotError(t, err, "Unable to get registration")

	req, err := http.NewRequest("GET", "http://[::1]/", nil)
	test.AssertNotError(t, err, "NewRequest failed")
	req.RemoteAddr = "12.34.98.76"
	req.Header.Set("X-Forwarded-For", "10.0.0.1,172.16.0.1")

	mockLog := wfe.log.(*blog.Mock)
	mockLog.Clear()

	wfe.logCsr(req, certificateRequest, reg)

	assertCsrLogged(t, mockLog)
}

func TestBadKeyCSR(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	payload := `{
			"resource":"new-cert",
			"csr": "MIHLMHcCAQAwEjEQMA4GA1UEAwwHZm9vLmNvbTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDCZftp4x4owgjBnwOKfzihIPedT-BUmV2fuQPMqaUlc8yJUp13vcO5uxUlaBm8leM7Dj_sgTDP_JgykorlYo73AgMBAAGgADANBgkqhkiG9w0BAQsFAANBAEaQ2QBhweK-kp1ejQCedUhMit_wG-uTBtKnc3M82f6_fztLkhg1vWQ782nmhbEI5orXp6QtNHgJYnBpqA9Ut00"
		}`
	signedURL := fmt.Sprintf("http://localhost%s", newCertPath)
	// Sign a request using test1key
	_, _, body := signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(newCertPath, body)

	// CSR with a bad (512 bit RSA) key.
	// openssl req -outform der -new -newkey rsa:512 -nodes -keyout foo.com.key
	//   -subj /CN=foo.com | base64 -w0 | sed -e 's,+,-,g' -e 's,/,_,g'
	wfe.NewCertificate(ctx, newRequestEvent(), responseWriter, request)

	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Invalid key in certificate request :: key too small: 512","status":400}`)
}

// This uses httptest.NewServer because ServeMux.ServeHTTP won't prevent the
// body from being sent like the net/http Server's actually do.
func TestGetCertificateHEADHasCorrectBodyLength(t *testing.T) {
	wfe, _ := setupWFE(t)

	certPemBytes, _ := ioutil.ReadFile("test/178.crt")
	certBlock, _ := pem.Decode(certPemBytes)

	mockLog := wfe.log.(*blog.Mock)
	mockLog.Clear()

	mux := wfe.Handler()
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

func newRequestEvent() *requestEvent {
	return &requestEvent{Extra: make(map[string]interface{})}
}

func TestHeaderBoulderRequestId(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()
	responseWriter := httptest.NewRecorder()

	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(directoryPath),
	})

	requestID := responseWriter.Header().Get("Boulder-Request-ID")
	test.Assert(t, len(requestID) > 0, "Boulder-Request-ID header is empty")
}

func TestHeaderBoulderRequester(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()
	responseWriter := httptest.NewRecorder()

	key := loadKeys(t, []byte(test1KeyPrivatePEM))
	_, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Failed to load test 1 RSA key")

	payload := `{"agreement":"` + agreementURL + `"}`
	path := fmt.Sprintf("%s%d", regPath, 1)
	signedURL := fmt.Sprintf("http://localhost%s", path)
	_, _, body := signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	mux.ServeHTTP(responseWriter, request)
	test.AssertEquals(t, responseWriter.Header().Get("Boulder-Requester"), "1")

	// requests that do call sendError() also should have the requester header
	payload = `{"agreement":"https://letsencrypt.org/im-bad"}`
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)
	mux.ServeHTTP(responseWriter, request)
	test.AssertEquals(t, responseWriter.Header().Get("Boulder-Requester"), "1")
}

func TestDeactivateAuthorization(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.AllowAuthzDeactivation = true
	responseWriter := httptest.NewRecorder()

	responseWriter.Body.Reset()

	payload := `{"status":""}`
	path := "valid"
	signedURL := fmt.Sprintf("http://localhost/%s", "valid")
	_, _, body := signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	wfe.Authorization(ctx, newRequestEvent(), responseWriter, request)
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type": "urn:acme:error:malformed","detail": "Invalid status value","status": 400}`)

	responseWriter.Body.Reset()
	payload = `{"status":"deactivated"}`
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	wfe.Authorization(ctx, newRequestEvent(), responseWriter, request)
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{
		  "identifier": {
		    "type": "dns",
		    "value": "not-an-example.com"
		  },
		  "status": "deactivated",
		  "expires": "2070-01-01T00:00:00Z",
		  "challenges": [
		    {
		      "type": "dns",
		      "uri": "http://localhost/acme/challenge/valid/23"
		    }
		  ]
		}`)
}

func TestDeactivateRegistration(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	wfe, _ := setupWFE(t)
	_ = features.Set(map[string]bool{"AllowAccountDeactivation": true})
	defer features.Reset()

	responseWriter.Body.Reset()
	payload := `{"status":"asd"}`
	signedURL := "http://localhost/1"
	path := "1"
	_, _, body := signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	wfe.Registration(ctx, newRequestEvent(), responseWriter, request)
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type": "urn:acme:error:malformed","detail": "Invalid value provided for status field","status": 400}`)

	responseWriter.Body.Reset()
	payload = `{"status":"deactivated"}`
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	wfe.Registration(ctx, newRequestEvent(), responseWriter, request)
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
		  "createdAt": "0001-01-01T00:00:00Z",
		  "Status": "deactivated"
		}`)

	responseWriter.Body.Reset()
	payload = `{"status":"deactivated", "contact":[]}`
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)
	wfe.Registration(ctx, newRequestEvent(), responseWriter, request)
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
		  "createdAt": "0001-01-01T00:00:00Z",
		  "Status": "deactivated"
		}`)

	responseWriter.Body.Reset()
	key := loadKeys(t, []byte(test3KeyPrivatePEM))
	_, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load test3 RSA key")

	payload = `{"status":"deactivated"}`
	path = "3"
	signedURL = "http://localhost/3"
	_, _, body = signRequestKeyID(t, 3, key, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	wfe.Registration(ctx, newRequestEvent(), responseWriter, request)

	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{
		  "type": "urn:acme:error:unauthorized",
		  "detail": "Account is not valid, has status \"deactivated\"",
		  "status": 403
		}`)
}
