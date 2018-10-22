package wfe2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
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
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/nonce"
	"github.com/letsencrypt/boulder/probs"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/revocation"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/web"
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

func (ra *MockRegistrationAuthority) NewRegistration(ctx context.Context, acct core.Registration) (core.Registration, error) {
	return acct, nil
}

func (ra *MockRegistrationAuthority) NewAuthorization(ctx context.Context, authz core.Authorization, acctID int64) (core.Authorization, error) {
	authz.RegistrationID = acctID
	authz.ID = "bkrPh2u0JUf18-rVBZtOOWWb3GuIiliypL-hBM9Ak1Q"
	return authz, nil
}

func (ra *MockRegistrationAuthority) NewCertificate(ctx context.Context, req core.CertificateRequest, acctID int64) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ra *MockRegistrationAuthority) UpdateRegistration(ctx context.Context, acct core.Registration, updated core.Registration) (core.Registration, error) {
	keysMatch, _ := core.PublicKeysEqual(acct.Key.Key, updated.Key.Key)
	if !keysMatch {
		acct.Key = updated.Key
	}
	return acct, nil
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

func (ra *MockRegistrationAuthority) NewOrder(ctx context.Context, req *rapb.NewOrderRequest) (*corepb.Order, error) {
	one := int64(1)
	zero := int64(0)
	status := string(core.StatusPending)
	return &corepb.Order{
		Id:             &one,
		RegistrationID: req.RegistrationID,
		Expires:        &zero,
		Names:          req.Names,
		Status:         &status,
		Authorizations: []string{"hello"},
	}, nil
}

func (ra *MockRegistrationAuthority) FinalizeOrder(ctx context.Context, req *rapb.FinalizeOrderRequest) (*corepb.Order, error) {
	statusProcessing := string(core.StatusProcessing)
	req.Order.Status = &statusProcessing
	return req.Order, nil
}

type mockPA struct{}

func (pa *mockPA) ChallengesFor(identifier core.AcmeIdentifier) (challenges []core.Challenge, combinations [][]int, err error) {
	return
}

func (pa *mockPA) WillingToIssue(id core.AcmeIdentifier) error {
	return nil
}

func (pa *mockPA) WillingToIssueWildcard(id core.AcmeIdentifier) error {
	return nil
}

func makeBody(s string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(s))
}

// loadKey loads a private key from PEM/DER-encoded data and returns
// a `crypto.Signer`.
func loadKey(t *testing.T, keyBytes []byte) crypto.Signer {
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

	// Try decoding as a PKCS8 private key
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		// Determine the key's true type and return it as a crypto.Signer
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k
		case *ecdsa.PrivateKey:
			return k
		}
	}

	// Try as an ECDSA private key
	if ecdsaKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ecdsaKey
	}

	// Nothing worked! Fail hard.
	t.Fatalf("Unable to decode private key PEM bytes")
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

	chainPEM, err := ioutil.ReadFile("../test/test-ca2.pem")
	test.AssertNotError(t, err, "Unable to read ../test/test-ca2.pem")

	certChains := map[string][]byte{
		"http://localhost:4000/acme/issuer-cert": append([]byte{'\n'}, chainPEM...),
	}

	wfe, err := NewWebFrontEndImpl(stats, fc, testKeyPolicy, certChains, blog.NewMock())
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
			"Content-Length": {strconv.Itoa(len(body))},
			"Content-Type":   []string{expectedJWSContentType},
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
	runWrappedHandler := func(req *http.Request, pattern string, allowed ...string) {
		mux = http.NewServeMux()
		rw = httptest.NewRecorder()
		stubCalled = false
		wfe.HandleFunc(mux, pattern, func(context.Context, *web.RequestEvent, http.ResponseWriter, *http.Request) {
			stubCalled = true
		}, allowed...)
		req.URL = mustParseURL(pattern)
		mux.ServeHTTP(rw, req)
	}

	// Plain requests (no CORS)
	type testCase struct {
		allowed        []string
		reqMethod      string
		shouldCallStub bool
		shouldSucceed  bool
		pattern        string
	}
	var lastNonce string
	for _, c := range []testCase{
		{[]string{"GET", "POST"}, "GET", true, true, "/test"},
		{[]string{"GET", "POST"}, "GET", true, true, newNoncePath},
		{[]string{"GET", "POST"}, "POST", true, true, "/test"},
		{[]string{"GET"}, "", false, false, "/test"},
		{[]string{"GET"}, "POST", false, false, "/test"},
		{[]string{"GET"}, "OPTIONS", false, true, "/test"},
		{[]string{"GET"}, "MAKE-COFFEE", false, false, "/test"}, // 405, or 418?
	} {
		runWrappedHandler(&http.Request{Method: c.reqMethod}, c.pattern, c.allowed...)
		test.AssertEquals(t, stubCalled, c.shouldCallStub)
		if c.shouldSucceed {
			test.AssertEquals(t, rw.Code, http.StatusOK)
		} else {
			test.AssertEquals(t, rw.Code, http.StatusMethodNotAllowed)
			test.AssertEquals(t, sortHeader(rw.Header().Get("Allow")), sortHeader(strings.Join(addHeadIfGet(c.allowed), ", ")))
			test.AssertUnmarshaledEquals(t,
				rw.Body.String(),
				`{"type":"`+probs.V2ErrorNS+`malformed","detail":"Method not allowed","status":405}`)
		}
		if c.reqMethod == "GET" && c.pattern != newNoncePath {
			nonce := rw.Header().Get("Replay-Nonce")
			test.AssertEquals(t, nonce, "")
		} else {
			nonce := rw.Header().Get("Replay-Nonce")
			test.AssertNotEquals(t, nonce, lastNonce)
			test.AssertNotEquals(t, nonce, "")
			lastNonce = nonce
		}
	}

	// Disallowed method returns error JSON in body
	runWrappedHandler(&http.Request{Method: "PUT"}, "/test", "GET", "POST")
	test.AssertEquals(t, rw.Header().Get("Content-Type"), "application/problem+json")
	test.AssertUnmarshaledEquals(t, rw.Body.String(), `{"type":"`+probs.V2ErrorNS+`malformed","detail":"Method not allowed","status":405}`)
	test.AssertEquals(t, sortHeader(rw.Header().Get("Allow")), "GET, HEAD, POST")

	// Disallowed method special case: response to HEAD has got no body
	runWrappedHandler(&http.Request{Method: "HEAD"}, "/test", "GET", "POST")
	test.AssertEquals(t, stubCalled, true)
	test.AssertEquals(t, rw.Body.String(), "")

	// HEAD doesn't work with POST-only endpoints
	runWrappedHandler(&http.Request{Method: "HEAD"}, "/test", "POST")
	test.AssertEquals(t, stubCalled, false)
	test.AssertEquals(t, rw.Code, http.StatusMethodNotAllowed)
	test.AssertEquals(t, rw.Header().Get("Content-Type"), "application/problem+json")
	test.AssertEquals(t, rw.Header().Get("Allow"), "POST")
	test.AssertUnmarshaledEquals(t, rw.Body.String(), `{"type":"`+probs.V2ErrorNS+`malformed","detail":"Method not allowed","status":405}`)

	wfe.AllowOrigins = []string{"*"}
	testOrigin := "https://example.com"

	// CORS "actual" request for disallowed method
	runWrappedHandler(&http.Request{
		Method: "POST",
		Header: map[string][]string{
			"Origin": {testOrigin},
		},
	}, "/test", "GET")
	test.AssertEquals(t, stubCalled, false)
	test.AssertEquals(t, rw.Code, http.StatusMethodNotAllowed)

	// CORS "actual" request for allowed method
	runWrappedHandler(&http.Request{
		Method: "GET",
		Header: map[string][]string{
			"Origin": {testOrigin},
		},
	}, "/test", "GET", "POST")
	test.AssertEquals(t, stubCalled, true)
	test.AssertEquals(t, rw.Code, http.StatusOK)
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Methods"), "")
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "*")
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
	test.AssertEquals(t, sortHeader(rw.Header().Get("Access-Control-Expose-Headers")), "Link, Location, Replay-Nonce")

	// CORS preflight request for disallowed method
	runWrappedHandler(&http.Request{
		Method: "OPTIONS",
		Header: map[string][]string{
			"Origin":                        {testOrigin},
			"Access-Control-Request-Method": {"POST"},
		},
	}, "/test", "GET")
	test.AssertEquals(t, stubCalled, false)
	test.AssertEquals(t, rw.Code, http.StatusOK)
	test.AssertEquals(t, rw.Header().Get("Allow"), "GET, HEAD")
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "")
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Headers"), "")

	// CORS preflight request for allowed method
	runWrappedHandler(&http.Request{
		Method: "OPTIONS",
		Header: map[string][]string{
			"Origin":                         {testOrigin},
			"Access-Control-Request-Method":  {"POST"},
			"Access-Control-Request-Headers": {"X-Accept-Header1, X-Accept-Header2", "X-Accept-Header3"},
		},
	}, "/test", "GET", "POST")
	test.AssertEquals(t, rw.Code, http.StatusOK)
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "*")
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
	test.AssertEquals(t, rw.Header().Get("Access-Control-Max-Age"), "86400")
	test.AssertEquals(t, sortHeader(rw.Header().Get("Access-Control-Allow-Methods")), "GET, HEAD, POST")
	test.AssertEquals(t, sortHeader(rw.Header().Get("Access-Control-Expose-Headers")), "Link, Location, Replay-Nonce")

	// OPTIONS request without an Origin header (i.e., not a CORS
	// preflight request)
	runWrappedHandler(&http.Request{
		Method: "OPTIONS",
		Header: map[string][]string{
			"Access-Control-Request-Method": {"POST"},
		},
	}, "/test", "GET", "POST")
	test.AssertEquals(t, rw.Code, http.StatusOK)
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "")
	test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Headers"), "")
	test.AssertEquals(t, sortHeader(rw.Header().Get("Allow")), "GET, HEAD, POST")

	// CORS preflight request missing optional Request-Method
	// header. The "actual" request will be GET.
	for _, allowedMethod := range []string{"GET", "POST"} {
		runWrappedHandler(&http.Request{
			Method: "OPTIONS",
			Header: map[string][]string{
				"Origin": {testOrigin},
			},
		}, "/test", allowedMethod)
		test.AssertEquals(t, rw.Code, http.StatusOK)
		if allowedMethod == "GET" {
			test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "*")
			test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
			test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Methods"), "GET, HEAD")
		} else {
			test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Origin"), "")
			test.AssertEquals(t, rw.Header().Get("Access-Control-Allow-Headers"), "")
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
		}, "/test", "POST")
		test.AssertEquals(t, rw.Code, http.StatusOK)
		for _, h := range []string{
			"Access-Control-Allow-Methods",
			"Access-Control-Allow-Origin",
			"Access-Control-Allow-Headers",
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
		}, "/test", "POST")
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

type fakeRand struct{}

func (fr fakeRand) Read(p []byte) (int, error) {
	return len(p), nil
}

func TestDirectory(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()
	core.RandReader = fakeRand{}
	defer func() { core.RandReader = rand.Reader }()

	// Directory with a key change endpoint and a meta entry
	metaJSON := `{
  "keyChange": "http://localhost:4300/acme/key-change",
  "meta": {
    "termsOfService": "http://example.invalid/terms"
  },
  "newNonce": "http://localhost:4300/acme/new-nonce",
  "newAccount": "http://localhost:4300/acme/new-acct",
  "newOrder": "http://localhost:4300/acme/new-order",
  "revokeCert": "http://localhost:4300/acme/revoke-cert",
  "AAAAAAAAAAA": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417"
}`

	// NOTE: the req.URL will be modified and must be constructed per
	// testcase or things will break and you will be confused and sad.
	url, _ := url.Parse("/directory")
	req := &http.Request{
		Method: "GET",
		URL:    url,
		Host:   "localhost:4300",
	}
	// Serve the /directory response for this request into a recorder
	responseWriter := httptest.NewRecorder()
	mux.ServeHTTP(responseWriter, req)
	// We expect all directory requests to return a json object with a good HTTP status
	test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/json")
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), metaJSON)
	// Check if there is a random directory key present and if so, that it is
	// expected to be present
	test.AssertEquals(t,
		randomDirectoryKeyPresent(t, responseWriter.Body.Bytes()),
		true)

	// Configure a caaIdentity and website for the /directory meta
	wfe.DirectoryCAAIdentity = "Radiant Lock"
	wfe.DirectoryWebsite = "zombo.com"

	// Expect directory with a key change endpoint and a meta entry that has both
	// a website and a caaIdentity
	metaJSON = `{
  "AAAAAAAAAAA": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
  "keyChange": "http://localhost:4300/acme/key-change",
  "meta": {
    "caaIdentities": [
      "Radiant Lock"
    ],
    "termsOfService": "http://example.invalid/terms",
    "website": "zombo.com"
  },
  "newAccount": "http://localhost:4300/acme/new-acct",
  "newNonce": "http://localhost:4300/acme/new-nonce",
  "newOrder": "http://localhost:4300/acme/new-order",
  "revokeCert": "http://localhost:4300/acme/revoke-cert"
}`
	// Serve the /directory response for this request into a recorder
	responseWriter = httptest.NewRecorder()
	mux.ServeHTTP(responseWriter, req)
	// We expect all directory requests to return a json object with a good HTTP status
	test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/json")
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), metaJSON)
	// Check if there is a random directory key present and if so, that it is
	// expected to be present
	test.AssertEquals(t,
		randomDirectoryKeyPresent(t, responseWriter.Body.Bytes()),
		true)
}

func TestRelativeDirectory(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()
	core.RandReader = fakeRand{}
	defer func() { core.RandReader = rand.Reader }()

	expectedDirectory := func(hostname string) string {
		expected := new(bytes.Buffer)

		fmt.Fprintf(expected, "{")
		fmt.Fprintf(expected, `"keyChange":"%s/acme/key-change",`, hostname)
		fmt.Fprintf(expected, `"newNonce":"%s/acme/new-nonce",`, hostname)
		fmt.Fprintf(expected, `"newAccount":"%s/acme/new-acct",`, hostname)
		fmt.Fprintf(expected, `"newOrder":"%s/acme/new-order",`, hostname)
		fmt.Fprintf(expected, `"revokeCert":"%s/acme/revoke-cert",`, hostname)
		fmt.Fprintf(expected, `"AAAAAAAAAAA":"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",`)
		fmt.Fprintf(expected, `"meta":{"termsOfService":"http://example.invalid/terms"}`)
		fmt.Fprintf(expected, "}")
		return expected.String()
	}

	dirTests := []struct {
		host        string
		protoHeader string
		result      string
	}{
		// Test '' (No host header) with no proto header
		{"", "", expectedDirectory("http://localhost")},
		// Test localhost:4300 with no proto header
		{"localhost:4300", "", expectedDirectory("http://localhost:4300")},
		// Test 127.0.0.1:4300 with no proto header
		{"127.0.0.1:4300", "", expectedDirectory("http://127.0.0.1:4300")},
		// Test localhost:4300 with HTTP proto header
		{"localhost:4300", "http", expectedDirectory("http://localhost:4300")},
		// Test localhost:4300 with HTTPS proto header
		{"localhost:4300", "https", expectedDirectory("https://localhost:4300")},
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

// TestNonceEndpoint tests the WFE2's new-nonce endpoint
func TestNonceEndpoint(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()

	responseWriter := httptest.NewRecorder()

	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(newNoncePath),
	})

	// Sending a GET request to the nonce endpoint should produce a HTTP response
	// with the correct status code
	test.AssertEquals(t, responseWriter.Code, http.StatusNoContent)
	// And the response should contain a valid nonce in the Replay-Nonce header
	nonce := responseWriter.Header().Get("Replay-Nonce")
	test.AssertEquals(t, wfe.nonceService.Valid(nonce), true)
}

func TestHTTPMethods(t *testing.T) {
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
			Name:    "NewAcct path should be POST only",
			Path:    newAcctPath,
			Allowed: postOnly,
		},
		{
			Name:    "Acct path should be POST only",
			Path:    acctPath,
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
		{
			Name:    "New order path should be POST only",
			Path:    newOrderPath,
			Allowed: postOnly,
		},
		{
			Name:    "Order path should be GET or POST only",
			Path:    orderPath,
			Allowed: getOrPost,
		},
		{
			Name:    "Nonce path should be GET only",
			Path:    newNoncePath,
			Allowed: getOnly,
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
			http.StatusOK)
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
				`{"type":"dns","url":"http://localhost/acme/challenge/valid/23"}`)
		}
	}
}

func TestChallenge(t *testing.T) {
	wfe, _ := setupWFE(t)

	// See mocks/mocks.go StorageAuthority.GetAuthorization for the "expired/"
	// "error_result/" path handling.
	testCases := []struct {
		Name            string
		Path            string
		ExpectedStatus  int
		ExpectedHeaders map[string]string
		ExpectedBody    string
	}{
		{
			Name:           "Valid challenge",
			Path:           "valid/23",
			ExpectedStatus: http.StatusOK,
			ExpectedHeaders: map[string]string{
				"Location": "http://localhost/acme/challenge/valid/23",
				"Link":     `<http://localhost/acme/authz/valid>;rel="up"`,
			},
			ExpectedBody: `{"type":"dns","url":"http://localhost/acme/challenge/valid/23"}`,
		},
		{
			Name:           "Expired challenge",
			Path:           "expired/23",
			ExpectedStatus: http.StatusNotFound,
			ExpectedBody:   `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Expired authorization","status":404}`,
		},
		{
			Name:           "Missing challenge",
			Path:           "",
			ExpectedStatus: http.StatusNotFound,
			ExpectedBody:   `{"type":"` + probs.V2ErrorNS + `malformed","detail":"No such challenge","status":404}`,
		},
		{
			Name:           "Unspecified database error",
			Path:           "error_result/24",
			ExpectedStatus: http.StatusInternalServerError,
			ExpectedBody:   `{"type":"` + probs.V2ErrorNS + `serverInternal","detail":"Problem getting authorization","status":500}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			responseWriter := httptest.NewRecorder()

			// Make a signed request to the Challenge endpoint
			signedURL := fmt.Sprintf("http://localhost/%s", tc.Path)
			_, _, jwsBody := signRequestKeyID(t, 1, nil, signedURL, `{}`, wfe.nonceService)
			request := makePostRequestWithPath(tc.Path, jwsBody)
			wfe.Challenge(ctx, newRequestEvent(), responseWriter, request)

			// Check the reponse code, headers and body match expected
			headers := responseWriter.Header()
			body := responseWriter.Body.String()
			test.AssertEquals(t, responseWriter.Code, tc.ExpectedStatus)
			for h, v := range tc.ExpectedHeaders {
				test.AssertEquals(t, headers.Get(h), v)
			}
			test.AssertUnmarshaledEquals(t, body, tc.ExpectedBody)
		})
	}
}

// MockRAStrictUpdateAuthz is a mock RA that enforces authz status in `UpdateAuthorization`
type MockRAStrictUpdateAuthz struct {
	MockRegistrationAuthority
}

// UpdateAuthorization for a MockRAStrictUpdateAuthz returns a
// berrors.WrongAuthorizationStateError when told to update a non-pending authz. It
// returns the authz unchanged for all other cases.
func (ra *MockRAStrictUpdateAuthz) UpdateAuthorization(_ context.Context, authz core.Authorization, _ int, _ core.Challenge) (core.Authorization, error) {
	if authz.Status != core.StatusPending {
		return core.Authorization{}, berrors.WrongAuthorizationStateError("authorization is not pending")
	}
	return authz, nil
}

// TestUpdateChallengeFinalizedAuthz tests that POSTing a challenge associated
// with an already valid authorization returns the expected Malformed problem.
func TestUpdateChallengeFinalizedAuthz(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.RA = &MockRAStrictUpdateAuthz{}
	responseWriter := httptest.NewRecorder()

	signedURL := "http://localhost/valid/23"
	_, _, jwsBody := signRequestKeyID(t, 1, nil, signedURL, `{}`, wfe.nonceService)
	request := makePostRequestWithPath("valid/23", jwsBody)
	wfe.Challenge(ctx, newRequestEvent(), responseWriter, request)

	body := responseWriter.Body.String()
	test.AssertUnmarshaledEquals(t, body, `{
  "type": "`+probs.V2ErrorNS+`malformed",
  "detail": "Unable to update challenge :: authorization is not pending",
  "status": 400
}`)
}

func TestBadNonce(t *testing.T) {
	wfe, _ := setupWFE(t)

	key := loadKey(t, []byte(test2KeyPrivatePEM))
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
	result, err := signer.Sign([]byte(`{"contact":["mailto:person@mail.com"]}`))
	test.AssertNotError(t, err, "Failed to sign body")
	wfe.NewAccount(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("nonce", result.FullSerialize()))
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `{"type":"`+probs.V2ErrorNS+`badNonce","detail":"JWS has no anti-replay nonce","status":400}`)
}

func TestNewECDSAAccount(t *testing.T) {
	wfe, _ := setupWFE(t)

	// E1 always exists; E2 never exists
	key := loadKey(t, []byte(testE2KeyPrivatePEM))
	_, ok := key.(*ecdsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load ECDSA key")

	payload := `{"contact":["mailto:person@mail.com"],"termsOfServiceAgreed":true}`
	path := newAcctPath
	signedURL := fmt.Sprintf("http://localhost%s", path)
	_, _, body := signRequestEmbed(t, key, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	responseWriter := httptest.NewRecorder()
	wfe.NewAccount(ctx, newRequestEvent(), responseWriter, request)

	var acct core.Registration
	responseBody := responseWriter.Body.String()
	err := json.Unmarshal([]byte(responseBody), &acct)
	test.AssertNotError(t, err, "Couldn't unmarshal returned account object")
	test.Assert(t, len(*acct.Contact) >= 1, "No contact field in account")
	test.AssertEquals(t, (*acct.Contact)[0], "mailto:person@mail.com")
	test.AssertEquals(t, acct.Agreement, "")
	test.AssertEquals(t, acct.InitialIP.String(), "1.1.1.1")

	test.AssertEquals(t, responseWriter.Header().Get("Location"), "http://localhost/acme/acct/0")

	key = loadKey(t, []byte(testE1KeyPrivatePEM))
	_, ok = key.(*ecdsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load ECDSA key")

	_, _, body = signRequestEmbed(t, key, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	// Reset the body and status code
	responseWriter = httptest.NewRecorder()
	// POST, Valid JSON, Key already in use
	wfe.NewAccount(ctx, newRequestEvent(), responseWriter, request)
	responseBody = responseWriter.Body.String()
	test.AssertEquals(t, responseWriter.Header().Get("Location"), "http://localhost/acme/acct/3")
	test.AssertEquals(t, responseWriter.Code, 200)
}

// Test that the WFE handling of the "empty update" POST is correct. The ACME
// spec describes how when clients wish to query the server for information
// about an account an empty account update should be sent, and
// a populated acct object will be returned.
func TestEmptyAccount(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	// Test Key 1 is mocked in the mock StorageAuthority used in setupWFE to
	// return a populated account for GetRegistrationByKey when test key 1 is
	// used.
	key := loadKey(t, []byte(test1KeyPrivatePEM))
	_, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")

	payload := `{}`
	path := "1"
	signedURL := "http://localhost/1"
	_, _, body := signRequestKeyID(t, 1, key, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	// Send an account update with the trivial body
	wfe.Account(
		ctx,
		newRequestEvent(),
		responseWriter,
		request)

	responseBody := responseWriter.Body.String()
	// There should be no error
	test.AssertNotContains(t, responseBody, probs.V2ErrorNS)

	// We should get back a populated Account
	var acct core.Registration
	err := json.Unmarshal([]byte(responseBody), &acct)
	test.AssertNotError(t, err, "Couldn't unmarshal returned account object")
	test.Assert(t, len(*acct.Contact) >= 1, "No contact field in account")
	test.AssertEquals(t, (*acct.Contact)[0], "mailto:person@mail.com")
	test.AssertEquals(t, acct.Agreement, "")
	responseWriter.Body.Reset()
}

func TestNewAccount(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()
	key := loadKey(t, []byte(test2KeyPrivatePEM))
	_, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load test2 key")

	path := newAcctPath
	signedURL := fmt.Sprintf("http://localhost%s", path)

	wrongAgreementAcct := `{"contact":["mailto:person@mail.com"],"termsOfServiceAgreed":false}`
	// An acct with the terms not agreed to
	_, _, wrongAgreementBody := signRequestEmbed(t, key, signedURL, wrongAgreementAcct, wfe.nonceService)

	// A non-JSON payload
	_, _, fooBody := signRequestEmbed(t, key, signedURL, `foo`, wfe.nonceService)

	type newAcctErrorTest struct {
		r        *http.Request
		respBody string
	}

	acctErrTests := []newAcctErrorTest{
		// POST, but no body.
		{
			&http.Request{
				Method: "POST",
				URL:    mustParseURL(newAcctPath),
				Header: map[string][]string{
					"Content-Length": {"0"},
					"Content-Type":   []string{expectedJWSContentType},
				},
			},
			`{"type":"` + probs.V2ErrorNS + `malformed","detail":"No body on POST","status":400}`,
		},

		// POST, but body that isn't valid JWS
		{
			makePostRequestWithPath(newAcctPath, "hi"),
			`{"type":"` + probs.V2ErrorNS + `malformed","detail":"Parse error reading JWS","status":400}`,
		},

		// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
		{
			makePostRequestWithPath(newAcctPath, fooBody),
			`{"type":"` + probs.V2ErrorNS + `malformed","detail":"Request payload did not parse as JSON","status":400}`,
		},

		// Same signed body, but payload modified by one byte, breaking signature.
		// should fail JWS verification.
		{
			makePostRequestWithPath(newAcctPath,
				`{"payload":"Zm9x","protected":"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoicW5BUkxyVDdYejRnUmNLeUxkeWRtQ3ItZXk5T3VQSW1YNFg0MHRoazNvbjI2RmtNem5SM2ZSanM2NmVMSzdtbVBjQlo2dU9Kc2VVUlU2d0FhWk5tZW1vWXgxZE12cXZXV0l5aVFsZUhTRDdROHZCcmhSNnVJb080akF6SlpSLUNoelp1U0R0N2lITi0zeFVWc3B1NVhHd1hVX01WSlpzaFR3cDRUYUZ4NWVsSElUX09iblR2VE9VM1hoaXNoMDdBYmdaS21Xc1ZiWGg1cy1DcklpY1U0T2V4SlBndW5XWl9ZSkp1ZU9LbVR2bkxsVFY0TXpLUjJvWmxCS1oyN1MwLVNmZFZfUUR4X3lkbGU1b01BeUtWdGxBVjM1Y3lQTUlzWU53Z1VHQkNkWV8yVXppNWVYMGxUYzdNUFJ3ejZxUjFraXAtaTU5VmNHY1VRZ3FIVjZGeXF3IiwiZSI6IkFRQUIifSwia2lkIjoiIiwibm9uY2UiOiJyNHpuenZQQUVwMDlDN1JwZUtYVHhvNkx3SGwxZVBVdmpGeXhOSE1hQnVvIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdC9hY21lL25ldy1yZWcifQ","signature":"jcTdxSygm_cvD7KbXqsxgnoPApCTSkV4jolToSOd2ciRkg5W7Yl0ZKEEKwOc-dYIbQiwGiDzisyPCicwWsOUA1WSqHylKvZ3nxSMc6KtwJCW2DaOqcf0EEjy5VjiZJUrOt2c-r6b07tbn8sfOJKwlF2lsOeGi4s-rtvvkeQpAU-AWauzl9G4bv2nDUeCviAZjHx_PoUC-f9GmZhYrbDzAvXZ859ktM6RmMeD0OqPN7bhAeju2j9Gl0lnryZMtq2m0J2m1ucenQBL1g4ZkP1JiJvzd2cAz5G7Ftl2YeJJyWhqNd3qq0GVOt1P11s8PTGNaSoM0iR9QfUxT9A6jxARtg"}`),
			`{"type":"` + probs.V2ErrorNS + `malformed","detail":"JWS verification error","status":400}`,
		},
		{
			makePostRequestWithPath(newAcctPath, wrongAgreementBody),
			`{"type":"` + probs.V2ErrorNS + `malformed","detail":"must agree to terms of service","status":400}`,
		},
	}
	for _, rt := range acctErrTests {
		responseWriter := httptest.NewRecorder()
		mux.ServeHTTP(responseWriter, rt.r)
		test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), rt.respBody)
	}

	responseWriter := httptest.NewRecorder()

	payload := `{"contact":["mailto:person@mail.com"],"termsOfServiceAgreed":true}`
	_, _, body := signRequestEmbed(t, key, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	wfe.NewAccount(ctx, newRequestEvent(), responseWriter, request)

	var acct core.Registration
	responseBody := responseWriter.Body.String()
	err := json.Unmarshal([]byte(responseBody), &acct)
	test.AssertNotError(t, err, "Couldn't unmarshal returned account object")
	test.Assert(t, len(*acct.Contact) >= 1, "No contact field in account")
	test.AssertEquals(t, (*acct.Contact)[0], "mailto:person@mail.com")
	test.AssertEquals(t, acct.InitialIP.String(), "1.1.1.1")
	// Agreement is an ACMEv1 field and should not be present
	test.AssertEquals(t, acct.Agreement, "")

	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"http://localhost/acme/acct/0")

	// Load an existing key
	key = loadKey(t, []byte(test1KeyPrivatePEM))
	_, ok = key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load test1 key")

	// Reset the body and status code
	responseWriter = httptest.NewRecorder()
	// POST, Valid JSON, Key already in use
	_, _, body = signRequestEmbed(t, key, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)
	// POST the NewAccount request
	wfe.NewAccount(ctx, newRequestEvent(), responseWriter, request)
	// We expect a Location header and a 200 response with an empty body
	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"http://localhost/acme/acct/1")
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "{\n  \"id\": 1,\n  \"key\": {\n    \"kty\": \"RSA\",\n    \"n\": \"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ\",\n    \"e\": \"AQAB\"\n  },\n  \"contact\": [\n    \"mailto:person@mail.com\"\n  ],\n  \"agreement\": \"http://example.invalid/terms\",\n  \"initialIp\": \"\",\n  \"createdAt\": \"0001-01-01T00:00:00Z\",\n  \"status\": \"valid\"\n}")
}

func TestGetAuthorization(t *testing.T) {
	wfe, _ := setupWFE(t)

	// Expired authorizations should be inaccessible
	authzURL := "expired"
	responseWriter := httptest.NewRecorder()
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(authzURL),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V2ErrorNS+`malformed","detail":"Expired authorization","status":404}`)
	responseWriter.Body.Reset()

	// Ensure that a valid authorization can't be reached with an invalid URL
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		URL:    mustParseURL("/a/bunch/of/garbage/valid"),
		Method: "GET",
	})
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V2ErrorNS+`malformed","detail":"No such authorization","status":404}`)
}

// An SA mock that always returns a berrors.ServerInternal error for
// GetAuthorization.
type mockSAGetAuthzError struct {
	core.StorageGetter
}

func (msa *mockSAGetAuthzError) GetAuthorization(ctx context.Context, id string) (core.Authorization, error) {
	return core.Authorization{}, berrors.InternalServerError("oops")
}

// TestAuthorization500 tests that internal errors on GetAuthorization result in
// a 500.
func TestAuthorization500(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.SA = &mockSAGetAuthzError{}
	mux := wfe.Handler()

	responseWriter := httptest.NewRecorder()

	// GET instead of POST should be rejected
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(authzPath),
	})
	expected := `{
         "type": "urn:ietf:params:acme:error:serverInternal",
				 "detail": "Problem getting authorization",
				 "status": 500
  }`
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), expected)
}

// TestAuthorizationChallengeNamespace tests that the runtime prefixing of
// Challenge Problem Types works as expected
func TestAuthorizationChallengeNamespace(t *testing.T) {
	wfe, clk := setupWFE(t)

	mockSA := &mocks.SAWithFailedChallenges{Clk: clk}
	wfe.SA = mockSA

	// For "oldNS" the SA mock returns an authorization with a failed challenge
	// that has an error with the type already prefixed by the v1 error NS
	authzURL := "oldNS"
	responseWriter := httptest.NewRecorder()
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(authzURL),
	})

	var authz core.Authorization
	err := json.Unmarshal([]byte(responseWriter.Body.String()), &authz)
	test.AssertNotError(t, err, "Couldn't unmarshal returned authorization object")
	test.AssertEquals(t, len(authz.Challenges), 1)
	// The Challenge Error Type should have its prefix unmodified
	test.AssertEquals(t, string(authz.Challenges[0].Error.Type), probs.V1ErrorNS+"things:are:whack")

	// For "failed" the SA mock returns an authorization with a failed challenge
	// that has an error with the type not prefixed by an error namespace.
	authzURL = "failed"
	responseWriter = httptest.NewRecorder()
	wfe.Authorization(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(authzURL),
	})

	err = json.Unmarshal([]byte(responseWriter.Body.String()), &authz)
	test.AssertNotError(t, err, "Couldn't unmarshal returned authorization object")
	test.AssertEquals(t, len(authz.Challenges), 1)
	// The Challenge Error Type should have had the probs.V2ErrorNS prefix added
	test.AssertEquals(t, string(authz.Challenges[0].Error.Type), probs.V2ErrorNS+"things:are:whack")
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

func TestAccount(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()
	responseWriter := httptest.NewRecorder()

	// Test GET proper entry returns 405
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(acctPath),
	})
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V2ErrorNS+`malformed","detail":"Method not allowed","status":405}`)
	responseWriter.Body.Reset()

	// Test POST invalid JSON
	wfe.Account(ctx, newRequestEvent(), responseWriter, makePostRequestWithPath("2", "invalid"))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V2ErrorNS+`malformed","detail":"Parse error reading JWS","status":400}`)
	responseWriter.Body.Reset()

	key := loadKey(t, []byte(test2KeyPrivatePEM))
	_, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")

	signedURL := fmt.Sprintf("http://localhost%s%d", acctPath, 102)
	path := fmt.Sprintf("%s%d", acctPath, 102)
	payload := `{}`
	// ID 102 is used by the mock for missing acct
	_, _, body := signRequestKeyID(t, 102, nil, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	// Test POST valid JSON but key is not registered
	wfe.Account(ctx, newRequestEvent(), responseWriter, request)
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V2ErrorNS+`accountDoesNotExist","detail":"Account \"http://localhost/acme/acct/102\" not found","status":400}`)
	responseWriter.Body.Reset()

	key = loadKey(t, []byte(test1KeyPrivatePEM))
	_, ok = key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")

	// Test POST valid JSON with account up in the mock
	payload = `{}`
	path = "1"
	signedURL = "http://localhost/1"
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	wfe.Account(ctx, newRequestEvent(), responseWriter, request)
	test.AssertNotContains(t, responseWriter.Body.String(), probs.V2ErrorNS)
	links := responseWriter.Header()["Link"]
	test.AssertEquals(t, contains(links, "<"+agreementURL+">;rel=\"terms-of-service\""), true)
	responseWriter.Body.Reset()

	// Test POST valid JSON with garbage in URL but valid account ID
	payload = `{}`
	signedURL = "http://localhost/a/bunch/of/garbage/1"
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath("/a/bunch/of/garbage/1", body)

	wfe.Account(ctx, newRequestEvent(), responseWriter, request)
	test.AssertContains(t, responseWriter.Body.String(), "400")
	test.AssertContains(t, responseWriter.Body.String(), probs.V2ErrorNS+"malformed")
	responseWriter.Body.Reset()
}

func TestIssuer(t *testing.T) {
	wfe, _ := setupWFE(t)
	wfe.IssuerCert = []byte{0, 0, 1}

	responseWriter := httptest.NewRecorder()

	wfe.Issuer(ctx, newRequestEvent(), responseWriter, &http.Request{
		Method: "GET",
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.Assert(t, bytes.Compare(responseWriter.Body.Bytes(), wfe.IssuerCert) == 0, "Incorrect bytes returned")
}

func TestGetCertificate(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()

	certPemBytes, _ := ioutil.ReadFile("test/178.crt")
	pkixContent := "application/pem-certificate-chain"

	chainPemBytes, err := ioutil.ReadFile("../test/test-ca2.pem")
	test.AssertNotError(t, err, "Error reading ../test/test-ca2.pem")

	noCache := "public, max-age=0, no-cache"
	goodSerial := "/acme/cert/0000000000000000000000000000000000b2"
	notFound := `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Certificate not found","status":404}`

	testCases := []struct {
		Name            string
		Path            string
		ExpectedStatus  int
		ExpectedHeaders map[string]string
		ExpectedBody    string
		ExpectedCert    []byte
	}{
		{
			Name:           "Valid serial",
			Path:           goodSerial,
			ExpectedStatus: http.StatusOK,
			ExpectedHeaders: map[string]string{
				"Content-Type": pkixContent,
			},
			ExpectedCert: append(certPemBytes, append([]byte("\n"), chainPemBytes...)...),
		},
		{
			Name:           "Unused serial, no cache",
			Path:           "/acme/cert/0000000000000000000000000000000000ff",
			ExpectedStatus: http.StatusNotFound,
			ExpectedBody:   notFound,
		},
		{
			Name:           "Invalid serial, no cache",
			Path:           "/acme/cert/nothex",
			ExpectedStatus: http.StatusNotFound,
			ExpectedBody:   notFound,
		},
		{
			Name:           "Another invalid serial, no cache",
			Path:           "/acme/cert/00000000000000",
			ExpectedStatus: http.StatusNotFound,
			ExpectedBody:   notFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			responseWriter := httptest.NewRecorder()
			mockLog := wfe.log.(*blog.Mock)
			mockLog.Clear()

			// Mux a request for a certificate
			req, _ := http.NewRequest("GET", tc.Path, nil)
			req.RemoteAddr = "192.168.0.1"
			mux.ServeHTTP(responseWriter, req)
			headers := responseWriter.Header()

			// Assert that the status code written is as expected
			test.AssertEquals(t, responseWriter.Code, tc.ExpectedStatus)

			// All of the responses should have the correct cache control header
			test.AssertEquals(t, headers.Get("Cache-Control"), noCache)

			// If the test cases expects additional headers, check those too
			for h, v := range tc.ExpectedHeaders {
				test.AssertEquals(t, headers.Get(h), v)
			}

			if len(tc.ExpectedCert) > 0 {
				// If the expectation was to return a certificate, check that it was the one expected
				bodyBytes := responseWriter.Body.Bytes()
				test.Assert(t, bytes.Compare(bodyBytes, tc.ExpectedCert) == 0, "Certificates don't match")

				// Successful requests should be logged as such
				reqlogs := mockLog.GetAllMatching(`INFO: JSON=.*"Code":200.*`)
				if len(reqlogs) != 1 {
					t.Errorf("Didn't find info logs with code 200. Instead got:\n%s\n",
						strings.Join(mockLog.GetAllMatching(`.*`), "\n"))
				}
			} else {
				// Otherwise if the expectation wasn't a certificate, check that the body matches the expected
				body := responseWriter.Body.String()
				test.AssertUnmarshaledEquals(t, body, tc.ExpectedBody)

				// Unsuccessful requests should be logged as such
				reqlogs := mockLog.GetAllMatching(`INFO: JSON=.*"Code":404.*`)
				if len(reqlogs) != 1 {
					t.Errorf("Didn't find info logs with code 404. Instead got:\n%s\n",
						strings.Join(mockLog.GetAllMatching(`.*`), "\n"))
				}
			}
		})
	}
}

// This uses httptest.NewServer because ServeMux.ServeHTTP won't prevent the
// body from being sent like the net/http Server's actually do.
func TestGetCertificateHEADHasCorrectBodyLength(t *testing.T) {
	wfe, _ := setupWFE(t)

	certPemBytes, _ := ioutil.ReadFile("test/178.crt")
	chainPemBytes, _ := ioutil.ReadFile("../test/test-ca2.pem")
	chain := fmt.Sprintf("%s\n%s", string(chainPemBytes), string(certPemBytes))
	chainLen := strconv.Itoa(len(chain))

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
	test.AssertEquals(t, chainLen, resp.Header.Get("Content-Length"))
	test.AssertEquals(t, 0, len(body))
}

func newRequestEvent() *web.RequestEvent {
	return &web.RequestEvent{Extra: make(map[string]interface{})}
}

func TestHeaderBoulderRequester(t *testing.T) {
	wfe, _ := setupWFE(t)
	mux := wfe.Handler()
	responseWriter := httptest.NewRecorder()

	key := loadKey(t, []byte(test1KeyPrivatePEM))
	_, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Failed to load test 1 RSA key")

	payload := `{}`
	path := fmt.Sprintf("%s%d", acctPath, 1)
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
		`{"type": "`+probs.V2ErrorNS+`malformed","detail": "Invalid status value","status": 400}`)

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
		      "url": "http://localhost/acme/challenge/valid/23"
		    }
		  ]
		}`)
}

func TestDeactivateAccount(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	wfe, _ := setupWFE(t)

	responseWriter.Body.Reset()
	payload := `{"status":"asd"}`
	signedURL := "http://localhost/1"
	path := "1"
	_, _, body := signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request := makePostRequestWithPath(path, body)

	wfe.Account(ctx, newRequestEvent(), responseWriter, request)
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type": "`+probs.V2ErrorNS+`malformed","detail": "Invalid value provided for status field","status": 400}`)

	responseWriter.Body.Reset()
	payload = `{"status":"deactivated"}`
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	wfe.Account(ctx, newRequestEvent(), responseWriter, request)
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
		  "status": "deactivated"
		}`)

	responseWriter.Body.Reset()
	payload = `{"status":"deactivated", "contact":[]}`
	_, _, body = signRequestKeyID(t, 1, nil, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)
	wfe.Account(ctx, newRequestEvent(), responseWriter, request)
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
		  "status": "deactivated"
		}`)

	responseWriter.Body.Reset()
	key := loadKey(t, []byte(test3KeyPrivatePEM))
	_, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load test3 RSA key")

	payload = `{"status":"deactivated"}`
	path = "3"
	signedURL = "http://localhost/3"
	_, _, body = signRequestKeyID(t, 3, key, signedURL, payload, wfe.nonceService)
	request = makePostRequestWithPath(path, body)

	wfe.Account(ctx, newRequestEvent(), responseWriter, request)

	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{
		  "type": "`+probs.V2ErrorNS+`unauthorized",
		  "detail": "Account is not valid, has status \"deactivated\"",
		  "status": 403
		}`)
}

func TestNewOrder(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	targetHost := "localhost"
	targetPath := "new-order"
	signedURL := fmt.Sprintf("http://%s/%s", targetHost, targetPath)

	nonDNSIdentifierBody := `
	{
		"Identifiers": [
		  {"type": "dns",    "value": "not-example.com"},
			{"type": "dns",    "value": "www.not-example.com"},
			{"type": "fakeID", "value": "www.i-am-21.com"}
		]
	}
	`

	validOrderBody := `
	{
		"Identifiers": [
		  {"type": "dns", "value": "not-example.com"},
			{"type": "dns", "value": "www.not-example.com"}
		]
	}`

	testCases := []struct {
		Name            string
		Request         *http.Request
		ExpectedBody    string
		ExpectedHeaders map[string]string
	}{
		{
			Name: "POST, but no body",
			Request: &http.Request{
				Method: "POST",
				Header: map[string][]string{
					"Content-Length": {"0"},
					"Content-Type":   []string{expectedJWSContentType},
				},
			},
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"No body on POST","status":400}`,
		},
		{
			Name:         "POST, with an invalid JWS body",
			Request:      makePostRequestWithPath("hi", "hi"),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Parse error reading JWS","status":400}`,
		},
		{
			Name:         "POST, properly signed JWS, payload isn't valid",
			Request:      signAndPost(t, targetPath, signedURL, "foo", 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Request payload did not parse as JSON","status":400}`,
		},
		{
			Name:         "POST, no identifiers in payload",
			Request:      signAndPost(t, targetPath, signedURL, "{}", 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"NewOrder request did not specify any identifiers","status":400}`,
		},
		{
			Name:         "POST, invalid identifier in payload",
			Request:      signAndPost(t, targetPath, signedURL, nonDNSIdentifierBody, 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"NewOrder request included invalid non-DNS type identifier: type \"fakeID\", value \"www.i-am-21.com\"","status":400}`,
		},
		{
			Name:         "POST, notAfter and notBefore in payload",
			Request:      signAndPost(t, targetPath, signedURL, `{"identifiers":[{"type": "dns", "value": "not-example.com"}], "notBefore":"now", "notAfter": "later"}`, 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"NotBefore and NotAfter are not supported","status":400}`,
		},
		{
			Name:    "POST, good payload",
			Request: signAndPost(t, targetPath, signedURL, validOrderBody, 1, wfe.nonceService),
			ExpectedBody: `
					{
						"status": "pending",
						"expires": "1970-01-01T00:00:00Z",
						"identifiers": [
							{ "type": "dns", "value": "not-example.com"},
							{ "type": "dns", "value": "www.not-example.com"}
						],
						"authorizations": [
							"http://localhost/acme/authz/hello"
						],
						"finalize": "http://localhost/acme/finalize/1/1"
					}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			responseWriter.Body.Reset()
			responseWriter.HeaderMap = http.Header{}

			wfe.NewOrder(ctx, newRequestEvent(), responseWriter, tc.Request)
			test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), tc.ExpectedBody)

			headers := responseWriter.Header()
			for k, v := range tc.ExpectedHeaders {
				test.AssertEquals(t, headers.Get(k), v)
			}
		})
	}
}

func TestFinalizeOrder(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	targetHost := "localhost"
	targetPath := "1/1"
	signedURL := fmt.Sprintf("http://%s/%s", targetHost, targetPath)

	// openssl req -outform der -new -nodes -key wfe/test/178.key -subj /CN=not-an-example.com | b64url
	// a valid CSR
	goodCertCSRPayload := `{
		"csr": "MIICYjCCAUoCAQAwHTEbMBkGA1UEAwwSbm90LWFuLWV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmqs7nue5oFxKBk2WaFZJAma2nm1oFyPIq19gYEAdQN4mWvaJ8RjzHFkDMYUrlIrGxCYuFJDHFUk9dh19Na1MIY-NVLgcSbyNcOML3bLbLEwGmvXPbbEOflBA9mxUS9TLMgXW5ghf_qbt4vmSGKloIim41QXt55QFW6O-84s8Kd2OE6df0wTsEwLhZB3j5pDU-t7j5vTMv4Tc7EptaPkOdfQn-68viUJjlYM_4yIBVRhWCdexFdylCKVLg0obsghQEwULKYCUjdg6F0VJUI115DU49tzscXU_3FS3CyY8rchunuYszBNkdmgpAwViHNWuP7ESdEd_emrj1xuioSe6PwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE_T1nWU38XVYL28hNVSXU0rW5IBUKtbvr0qAkD4kda4HmQRTYkt-LNSuvxoZCC9lxijjgtJi-OJe_DCTdZZpYzewlVvcKToWSYHYQ6Wm1-fxxD_XzphvZOujpmBySchdiz7QSVWJmVZu34XD5RJbIcrmj_cjRt42J1hiTFjNMzQu9U6_HwIMmliDL-soFY2RTvvZf-dAFvOUQ-Wbxt97eM1PbbmxJNWRhbAmgEpe9PWDPTpqV5AK56VAa991cQ1P8ZVmPss5hvwGWhOtpnpTZVHN3toGNYFKqxWPboirqushQlfKiFqT9rpRgM3-mFjOHidGqsKEkTdmfSVlVEk3oo="
	}`

	egUrl := mustParseURL("1/1")

	testCases := []struct {
		Name            string
		Request         *http.Request
		ExpectedHeaders map[string]string
		ExpectedBody    string
	}{
		{
			Name: "POST, but no body",
			Request: &http.Request{
				URL:        egUrl,
				RequestURI: targetPath,
				Method:     "POST",
				Header: map[string][]string{
					"Content-Length": {"0"},
					"Content-Type":   []string{expectedJWSContentType},
				},
			},
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"No body on POST","status":400}`,
		},
		{
			Name:         "POST, with an invalid JWS body",
			Request:      makePostRequestWithPath(targetPath, "hi"),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Parse error reading JWS","status":400}`,
		},
		{
			Name:         "POST, properly signed JWS, payload isn't valid",
			Request:      signAndPost(t, targetPath, signedURL, "foo", 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Request payload did not parse as JSON","status":400}`,
		},
		{
			Name:         "Invalid path",
			Request:      signAndPost(t, "1", "http://localhost/1", "{}", 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Invalid request path","status":404}`,
		},
		{
			Name:         "Bad acct ID in path",
			Request:      signAndPost(t, "a/1", "http://localhost/a/1", "{}", 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Invalid account ID","status":400}`,
		},
		{
			Name: "Mismatched acct ID in path/JWS",
			// Note(@cpu): We use "http://localhost/2/1" here not
			// "http://localhost/order/2/1" because we are calling the Order
			// handler directly and it normally has the initial path component
			// stripped by the global WFE2 handler. We need the JWS URL to match the request
			// URL so we fudge both such that the finalize-order prefix has been removed.
			Request:      signAndPost(t, "2/1", "http://localhost/2/1", "{}", 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"No order found for account ID 2","status":404}`,
		},
		{
			Name:         "Order ID is invalid",
			Request:      signAndPost(t, "1/okwhatever/finalize-order", "http://localhost/1/okwhatever/finalize-order", "{}", 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Invalid order ID","status":400}`,
		},
		{
			Name: "Order doesn't exist",
			// mocks/mocks.go's StorageAuthority's GetOrder mock treats ID 2 as missing
			Request:      signAndPost(t, "1/2", "http://localhost/1/2", "{}", 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"No order for ID 2","status":404}`,
		},
		{
			Name: "Order is already finalized",
			// mocks/mocks.go's StorageAuthority's GetOrder mock treats ID 1 as an Order with a Serial
			Request:      signAndPost(t, "1/1", "http://localhost/1/1", goodCertCSRPayload, 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Order's status (\"valid\") is not acceptable for finalization","status":400}`,
		},
		{
			Name: "Order is expired",
			// mocks/mocks.go's StorageAuthority's GetOrder mock treats ID 7 as an Order that has already expired
			Request:      signAndPost(t, "1/7", "http://localhost/1/7", goodCertCSRPayload, 1, wfe.nonceService),
			ExpectedBody: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Order 7 is expired","status":404}`,
		},
		{
			Name:            "Good CSR, Pending Order",
			Request:         signAndPost(t, "1/4", "http://localhost/1/4", goodCertCSRPayload, 1, wfe.nonceService),
			ExpectedHeaders: map[string]string{"Location": "http://localhost/acme/order/1/4"},
			ExpectedBody: `
{
  "status": "processing",
  "expires": "1970-01-01T00:00:00.9466848Z",
  "identifiers": [
    {"type":"dns","value":"example.com"}
  ],
  "authorizations": [
    "http://localhost/acme/authz/hello"
  ],
  "finalize": "http://localhost/acme/finalize/1/4"
}`,
		},
		{
			Name:            "Good CSR, Ready Order",
			Request:         signAndPost(t, "1/8", "http://localhost/1/8", goodCertCSRPayload, 1, wfe.nonceService),
			ExpectedHeaders: map[string]string{"Location": "http://localhost/acme/order/1/8"},
			ExpectedBody: `
{
  "status": "processing",
  "expires": "1970-01-01T00:00:00.9466848Z",
  "identifiers": [
    {"type":"dns","value":"example.com"}
  ],
  "authorizations": [
    "http://localhost/acme/authz/hello"
  ],
  "finalize": "http://localhost/acme/finalize/1/8"
}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			responseWriter.Body.Reset()
			responseWriter.HeaderMap = http.Header{}
			wfe.FinalizeOrder(ctx, newRequestEvent(), responseWriter, tc.Request)
			for k, v := range tc.ExpectedHeaders {
				got := responseWriter.Header().Get(k)
				if v != got {
					t.Errorf("Header %q: Expected %q, got %q", k, v, got)
				}
			}
			test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
				tc.ExpectedBody)
		})
	}

	// Check a bad CSR request separately from the above testcases. We don't want
	// to match the whole response body because the "detail" of a bad CSR problem
	// contains a verbose Go error message that can change between versions (e.g.
	// Go 1.10.4 to 1.11 changed the expected format)
	badCSRReq := signAndPost(t, "1/4", "http://localhost/1/4", `{"CSR": "ABCD"}`, 1, wfe.nonceService)
	responseWriter.Body.Reset()
	responseWriter.HeaderMap = http.Header{}
	wfe.FinalizeOrder(ctx, newRequestEvent(), responseWriter, badCSRReq)
	responseBody := responseWriter.Body.String()
	test.AssertContains(t, responseBody, "Error parsing certificate request")
}

func TestKeyRollover(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	wfe, _ := setupWFE(t)

	existingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Error creating random 2048 RSA key")

	existingJWK := &jose.JSONWebKey{
		Key:       &existingKey.PublicKey,
		Algorithm: keyAlgForKey(t, existingKey),
	}
	existingJWKJSON, err := existingJWK.MarshalJSON()
	test.AssertNotError(t, err, "Error marshaling random JWK")

	newKeyBytes, err := ioutil.ReadFile("../test/test-key-5.der")
	test.AssertNotError(t, err, "Failed to read ../test/test-key-5.der")
	newKeyPriv, err := x509.ParsePKCS1PrivateKey(newKeyBytes)
	test.AssertNotError(t, err, "Failed parsing private key")
	newJWKJSON, err := jose.JSONWebKey{Key: newKeyPriv.Public()}.MarshalJSON()
	test.AssertNotError(t, err, "Failed to marshal JWK JSON")

	wfe.KeyRollover(ctx, newRequestEvent(), responseWriter, makePostRequestWithPath("", "{}"))
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{
		  "type": "`+probs.V2ErrorNS+`malformed",
		  "detail": "Parse error reading JWS",
		  "status": 400
		}`)

	testCases := []struct {
		Name              string
		ACME13KeyRollover bool
		Payload           string
		ExpectedResponse  string
		NewKey            crypto.Signer
		ErrorStatType     string
	}{
		{
			Name:    "Missing account URL",
			Payload: `{"newKey":` + string(existingJWKJSON) + `}`,
			ExpectedResponse: `{
		     "type": "` + probs.V2ErrorNS + `malformed",
		     "detail": "Inner key rollover request specified Account \"\", but outer JWS has Key ID \"http://localhost/acme/acct/1\"",
		     "status": 400
		   }`,
			NewKey:        existingKey,
			ErrorStatType: "KeyRolloverMismatchedAccount",
		},
		{
			Name:    "Missing new key from inner payload",
			Payload: `{"account":"http://localhost/acme/acct/1"}`,
			ExpectedResponse: `{
		     "type": "` + probs.V2ErrorNS + `malformed",
		     "detail": "Inner JWS does not verify with specified new key",
		     "status": 400
		   }`,
			ErrorStatType: "KeyRolloverJWSNewKeyVerifyFailed",
		},
		{
			Name:    "New key is the same as the old key",
			Payload: `{"newKey":{"kty":"RSA","n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ","e":"AQAB"},"account":"http://localhost/acme/acct/1"}`,
			ExpectedResponse: `{
		     "type": "` + probs.V2ErrorNS + `malformed",
		     "detail": "New key specified by rollover request is the same as the old key",
		     "status": 400
		   }`,
			ErrorStatType: "KeyRolloverUnchangedKey",
		},
		{
			Name:    "Inner JWS signed by the wrong key",
			Payload: `{"newKey":` + string(existingJWKJSON) + `,"account":"http://localhost/acme/acct/1"}`,
			ExpectedResponse: `{
		     "type": "` + probs.V2ErrorNS + `malformed",
		     "detail": "Inner JWS does not verify with specified new key",
		     "status": 400
		   }`,
			ErrorStatType: "KeyRolloverJWSNewKeyVerifyFailed",
		},
		{
			Name:    "Valid key rollover request, key exists",
			Payload: `{"newKey":` + string(existingJWKJSON) + `,"account":"http://localhost/acme/acct/1"}`,
			ExpectedResponse: `{
                          "type": "urn:ietf:params:acme:error:malformed",
                          "detail": "New key is already in use for a different account",
                          "status": 409
                        }`,
			NewKey: existingKey,
		},
		{
			Name:    "Valid key rollover request",
			Payload: `{"newKey":` + string(newJWKJSON) + `,"account":"http://localhost/acme/acct/1"}`,
			ExpectedResponse: `{
		     "id": 1,
		     "key": ` + string(newJWKJSON) + `,
		     "contact": [
		       "mailto:person@mail.com"
		     ],
		     "agreement": "http://example.invalid/terms",
		     "initialIp": "",
		     "createdAt": "0001-01-01T00:00:00Z",
		     "status": "valid"
		   }`,
			NewKey: newKeyPriv,
		},
		{
			Name:    "Valid key rollover request, added ACME13KeyRollover compat",
			Payload: `{"newKey":` + string(newJWKJSON) + `, "oldKey":` + test1KeyPublicJSON + `, "account":"http://localhost/acme/acct/1"}`,
			ExpectedResponse: `{
		     "id": 1,
		     "key": ` + string(newJWKJSON) + `,
		     "contact": [
		       "mailto:person@mail.com"
		     ],
		     "agreement": "http://example.invalid/terms",
		     "initialIp": "",
		     "createdAt": "0001-01-01T00:00:00Z",
		     "status": "valid"
		   }`,
			NewKey: newKeyPriv,
		},
		{
			Name:              "ACME13KeyRollover, legacy rollover request",
			ACME13KeyRollover: true,
			Payload:           `{"newKey":` + string(newJWKJSON) + `,"account":"http://localhost/acme/acct/1"}`,
			ExpectedResponse: `{
		     "type": "` + probs.V2ErrorNS + `malformed",
		     "detail": "Inner JWS does not contain old key field matching current account key",
		     "status": 400
		   }`,
			NewKey:        newKeyPriv,
			ErrorStatType: "KeyRolloverWrongOldKey",
		},
		{
			Name:              "ACME13KeyRollover, Missing account URL",
			ACME13KeyRollover: true,
			Payload:           `{"oldKey":` + test1KeyPublicJSON + `}`,
			ExpectedResponse: `{
		     "type": "` + probs.V2ErrorNS + `malformed",
		     "detail": "Inner key rollover request specified Account \"\", but outer JWS has Key ID \"http://localhost/acme/acct/1\"",
		     "status": 400
		   }`,
			NewKey:        newKeyPriv,
			ErrorStatType: "KeyRolloverMismatchedAccount",
		},
		{
			Name:              "ACME13KeyRollover, incorrect old key",
			ACME13KeyRollover: true,
			Payload:           `{"oldKey":` + string(newJWKJSON) + `,"account":"http://localhost/acme/acct/1"}`,
			ExpectedResponse: `{
		     "type": "` + probs.V2ErrorNS + `malformed",
		     "detail": "Inner JWS does not contain old key field matching current account key",
		     "status": 400
		   }`,
			NewKey:        newKeyPriv,
			ErrorStatType: "KeyRolloverWrongOldKey",
		},
		{
			Name:              "ACME13KeyRollover, Valid key rollover request, key exists",
			ACME13KeyRollover: true,
			Payload:           `{"oldKey":` + test1KeyPublicJSON + `,"account":"http://localhost/acme/acct/1"}`,
			ExpectedResponse: `{
                          "type": "urn:ietf:params:acme:error:malformed",
                          "detail": "New key is already in use for a different account",
                          "status": 409
                        }`,
			NewKey: existingKey,
		},
		{
			Name:              "ACME13KeyRollover, Valid key rollover request",
			ACME13KeyRollover: true,
			Payload:           `{"oldKey":` + test1KeyPublicJSON + `,"account":"http://localhost/acme/acct/1"}`,
			ExpectedResponse: `{
		     "id": 1,
		     "key": ` + string(newJWKJSON) + `,
		     "contact": [
		       "mailto:person@mail.com"
		     ],
		     "agreement": "http://example.invalid/terms",
		     "initialIp": "",
		     "createdAt": "0001-01-01T00:00:00Z",
		     "status": "valid"
		   }`,
			NewKey: newKeyPriv,
		},
		{
			Name:              "ACME13KeyRollover, Valid key rollover request, legacy compat",
			ACME13KeyRollover: true,
			Payload:           `{"oldKey":` + test1KeyPublicJSON + `, "newKey":` + string(newJWKJSON) + `, "account":"http://localhost/acme/acct/1"}`,
			ExpectedResponse: `{
		     "id": 1,
		     "key": ` + string(newJWKJSON) + `,
		     "contact": [
		       "mailto:person@mail.com"
		     ],
		     "agreement": "http://example.invalid/terms",
		     "initialIp": "",
		     "createdAt": "0001-01-01T00:00:00Z",
		     "status": "valid"
		   }`,
			NewKey: newKeyPriv,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.ACME13KeyRollover {
				_ = features.Set(map[string]bool{"ACME13KeyRollover": true})
				defer features.Reset()
			}
			wfe.stats.joseErrorCount.Reset()
			responseWriter.Body.Reset()
			_, _, inner := signRequestEmbed(t, tc.NewKey, "http://localhost/key-change", tc.Payload, wfe.nonceService)
			_, _, outer := signRequestKeyID(t, 1, nil, "http://localhost/key-change", inner, wfe.nonceService)
			wfe.KeyRollover(ctx, newRequestEvent(), responseWriter, makePostRequestWithPath("key-change", outer))
			test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), tc.ExpectedResponse)
			if tc.ErrorStatType != "" {
				test.AssertEquals(t, test.CountCounterVec(
					"type", tc.ErrorStatType, wfe.stats.joseErrorCount), 1)
			}
		})
	}
}

func TestOrder(t *testing.T) {
	wfe, _ := setupWFE(t)

	testCases := []struct {
		Name     string
		Path     string
		Response string
	}{
		{
			Name:     "Good request",
			Path:     "1/1",
			Response: `{"status": "valid","expires": "1970-01-01T00:00:00.9466848Z","identifiers":[{"type":"dns", "value":"example.com"}], "authorizations":["http://localhost/acme/authz/hello"],"finalize":"http://localhost/acme/finalize/1/1","certificate":"http://localhost/acme/cert/serial"}`,
		},
		{
			Name:     "404 request",
			Path:     "1/2",
			Response: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"No order for ID 2", "status":404}`,
		},
		{
			Name:     "Invalid request path",
			Path:     "asd",
			Response: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Invalid request path","status":404}`,
		},
		{
			Name:     "Invalid account ID",
			Path:     "asd/asd",
			Response: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Invalid account ID","status":400}`,
		},
		{
			Name:     "Invalid order ID",
			Path:     "1/asd",
			Response: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"Invalid order ID","status":400}`,
		},
		{
			Name:     "Real request, wrong account",
			Path:     "2/1",
			Response: `{"type":"` + probs.V2ErrorNS + `malformed","detail":"No order found for account ID 2", "status":404}`,
		},
		{
			Name:     "Internal error request",
			Path:     "1/3",
			Response: `{"type":"` + probs.V2ErrorNS + `serverInternal","detail":"Failed to retrieve order for ID 3","status":500}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			responseWriter := httptest.NewRecorder()
			wfe.GetOrder(ctx, newRequestEvent(), responseWriter, &http.Request{URL: &url.URL{Path: tc.Path}, Method: "GET"})
			test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), tc.Response)
		})
	}
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
		CertificateDER core.JSONBuffer    `json:"certificate"`
		Reason         *revocation.Reason `json:"reason"`
	}{
		CertificateDER: certBlock.Bytes,
		Reason:         reason,
	}
	revokeRequestJSON, err := json.Marshal(revokeRequest)
	if err != nil {
		return nil, err
	}
	return revokeRequestJSON, nil
}

// A SA mock that always returns a berrors.NotFound type error. This is necessary
// because the standard mock in our mocks package always returns a given test
// registration when GetRegistrationByKey is called, and we want to get a
// berrors.NotFound type error for tests that pass regCheck = false to verifyPOST.
type mockSANoSuchRegistration struct {
	core.StorageGetter
}

func (msa mockSANoSuchRegistration) GetRegistrationByKey(ctx context.Context, jwk *jose.JSONWebKey) (core.Registration, error) {
	return core.Registration{}, berrors.NotFoundError("reg not found")
}

// Valid revocation request for existing, non-revoked cert, signed with cert
// key.
func TestRevokeCertificateCertKey(t *testing.T) {
	wfe, fc := setupWFE(t)
	wfe.AcceptRevocationReason = true
	wfe.SA = &mockSANoSuchRegistration{mocks.NewStorageAuthority(fc)}
	responseWriter := httptest.NewRecorder()

	keyPemBytes, err := ioutil.ReadFile("test/238.key")
	test.AssertNotError(t, err, "Failed to load key")
	key := loadKey(t, keyPemBytes)

	revokeRequestJSON, err := makeRevokeRequestJSON(nil)
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	_, _, jwsBody := signRequestEmbed(t,
		key, "http://localhost/revoke-cert", string(revokeRequestJSON), wfe.nonceService)

	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("revoke-cert", jwsBody))
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
}

func TestRevokeCertificateReasons(t *testing.T) {
	wfe, fc := setupWFE(t)
	wfe.AcceptRevocationReason = true
	ra := wfe.RA.(*MockRegistrationAuthority)
	wfe.SA = &mockSANoSuchRegistration{mocks.NewStorageAuthority(fc)}
	responseWriter := httptest.NewRecorder()

	keyPemBytes, err := ioutil.ReadFile("test/238.key")
	test.AssertNotError(t, err, "Failed to load key")
	key := loadKey(t, keyPemBytes)

	reason0 := revocation.Reason(0)
	reason1 := revocation.Reason(1)
	reason2 := revocation.Reason(2)
	reason100 := revocation.Reason(100)

	testCases := []struct {
		Name             string
		Reason           *revocation.Reason
		ExpectedHTTPCode int
		ExpectedBody     string
		ExpectedReason   *revocation.Reason
	}{
		{
			Name:             "Valid reason",
			Reason:           &reason1,
			ExpectedHTTPCode: http.StatusOK,
			ExpectedReason:   &reason1,
		},
		{
			Name:             "No reason",
			ExpectedHTTPCode: http.StatusOK,
			ExpectedReason:   &reason0,
		},
		{
			Name:             "Unsupported reason",
			Reason:           &reason2,
			ExpectedHTTPCode: http.StatusBadRequest,
			ExpectedBody:     `{"type":"` + probs.V2ErrorNS + `malformed","detail":"unsupported revocation reason code provided","status":400}`,
		},
		{
			Name:             "Non-existent reason",
			Reason:           &reason100,
			ExpectedHTTPCode: http.StatusBadRequest,
			ExpectedBody:     `{"type":"` + probs.V2ErrorNS + `malformed","detail":"unsupported revocation reason code provided","status":400}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			responseWriter = httptest.NewRecorder()
			revokeRequestJSON, err := makeRevokeRequestJSON(tc.Reason)
			test.AssertNotError(t, err, "Failed to make revokeRequestJSON")
			_, _, jwsBody := signRequestEmbed(t, key, "http://localhost/revoke-cert", string(revokeRequestJSON), wfe.nonceService)
			wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
				makePostRequestWithPath("revoke-cert", jwsBody))

			test.AssertEquals(t, responseWriter.Code, tc.ExpectedHTTPCode)
			if tc.ExpectedBody != "" {
				test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), tc.ExpectedBody)
			} else {
				test.AssertEquals(t, responseWriter.Body.String(), tc.ExpectedBody)
			}
			if tc.ExpectedReason != nil {
				test.AssertEquals(t, ra.lastRevocationReason, *tc.ExpectedReason)
			}
		})
	}
}

// Valid revocation request for existing, non-revoked cert, signed with account
// that issued the cert.
func TestRevokeCertificateIssuingAccount(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()
	revokeRequestJSON, err := makeRevokeRequestJSON(nil)
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	// NOTE: this account doesn't have any authorizations for the
	// names in the cert, but it is the account that issued it
	// originally
	_, _, jwsBody := signRequestKeyID(t, 1, nil, "http://localhost/revoke-cert", string(revokeRequestJSON), wfe.nonceService)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("revoke-cert", jwsBody))

	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
}

// Valid revocation request for existing, non-revoked cert, signed with account
// that has authorizations for names in cert
func TestRevokeCertificateWithAuthorizations(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()
	revokeRequestJSON, err := makeRevokeRequestJSON(nil)
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	// NOTE(@cpu): Account ID #5 is specifically handled in mocks.go
	// GetValidAuthorizations to have the authz for the certificate used in
	// `makeRevokeRequestJSON`
	_, _, jwsBody := signRequestKeyID(t, 5, nil, "http://localhost/revoke-cert", string(revokeRequestJSON), wfe.nonceService)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("revoke-cert", jwsBody))

	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
}

// A revocation request signed by an unauthorized key.
func TestRevokeCertificateWrongKey(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()
	revokeRequestJSON, err := makeRevokeRequestJSON(nil)
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	test2JWK := loadKey(t, []byte(test2KeyPrivatePEM))
	_, _, jwsBody := signRequestKeyID(t, 2, test2JWK, "http://localhost/revoke-cert", string(revokeRequestJSON), wfe.nonceService)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("revoke-cert", jwsBody))

	test.AssertEquals(t, responseWriter.Code, 403)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V2ErrorNS+`unauthorized","detail":"The key ID specified in the revocation request does not hold valid authorizations for all names in the certificate to be revoked","status":403}`)
}

// Valid revocation request for already-revoked cert
func TestRevokeCertificateAlreadyRevoked(t *testing.T) {
	wfe, fc := setupWFE(t)
	wfe.SA = &mockSANoSuchRegistration{mocks.NewStorageAuthority(fc)}

	keyPemBytes, err := ioutil.ReadFile("test/178.key")
	test.AssertNotError(t, err, "Failed to load key")
	key := loadKey(t, keyPemBytes)

	certPemBytes, err := ioutil.ReadFile("test/178.crt")
	test.AssertNotError(t, err, "Failed to load cert")
	certBlock, _ := pem.Decode(certPemBytes)
	test.Assert(t, certBlock != nil, "Failed to decode PEM")

	revokeRequest := struct {
		CertificateDER core.JSONBuffer `json:"certificate"`
	}{
		CertificateDER: certBlock.Bytes,
	}
	revokeRequestJSON, err := json.Marshal(revokeRequest)
	test.AssertNotError(t, err, "Failed to marshal request")

	responseWriter := httptest.NewRecorder()
	responseWriter.Body.Reset()

	_, _, jwsBody := signRequestEmbed(t, key, "http://localhost/revoke-cert", string(revokeRequestJSON), wfe.nonceService)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("revoke-cert", jwsBody))

	test.AssertEquals(t, responseWriter.Code, 400)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(),
		`{"type":"`+probs.V2ErrorNS+`alreadyRevoked","detail":"Certificate already revoked","status":400}`)
}

func TestRevokeCertificateWithAuthz(t *testing.T) {
	wfe, _ := setupWFE(t)
	responseWriter := httptest.NewRecorder()
	test4JWK := loadKey(t, []byte(test4KeyPrivatePEM))
	revokeRequestJSON, err := makeRevokeRequestJSON(nil)
	test.AssertNotError(t, err, "Unable to create revoke request")

	// NOTE(@cpu): Account ID #4 is specifically handled in mocks.go
	// GetValidAuthorizations to have an authz for "bad.example.com"
	_, _, jwsBody := signRequestKeyID(t, 4, test4JWK, "http://localhost/revoke-cert", string(revokeRequestJSON), wfe.nonceService)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("revoke-cert", jwsBody))

	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
}

func TestRevokeCertificateExpired(t *testing.T) {
	wfe, fc := setupWFE(t)
	responseWriter := httptest.NewRecorder()
	test4JWK := loadKey(t, []byte(test4KeyPrivatePEM))

	certPemBytes, err := ioutil.ReadFile("test/238.crt")
	test.AssertNotError(t, err, "failed to read test/238.crt")
	certBlock, _ := pem.Decode(certPemBytes)
	test.AssertNotError(t, err, "failed to parse test/238.crt")
	reason := revocation.Reason(0)
	revokeRequest := struct {
		CertificateDER core.JSONBuffer    `json:"certificate"`
		Reason         *revocation.Reason `json:"reason"`
	}{
		CertificateDER: certBlock.Bytes,
		Reason:         &reason,
	}
	revokeRequestJSON, err := json.Marshal(revokeRequest)
	test.AssertNotError(t, err, "failed to marshal revocation request")

	parsedCertificate, err := x509.ParseCertificate(certBlock.Bytes)
	test.AssertNotError(t, err, "failed to parse test cert")
	fc.Set(parsedCertificate.NotAfter.Add(time.Hour))

	_, _, jwsBody := signRequestKeyID(t, 4, test4JWK, "http://localhost/revoke-cert", string(revokeRequestJSON), wfe.nonceService)
	wfe.RevokeCertificate(ctx, newRequestEvent(), responseWriter,
		makePostRequestWithPath("revoke-cert", jwsBody))

	test.AssertEquals(t, responseWriter.Code, 403)
	test.AssertEquals(t, responseWriter.Body.String(), "{\n  \"type\": \"urn:ietf:params:acme:error:unauthorized\",\n  \"detail\": \"Certificate is expired\",\n  \"status\": 403\n}")
}

type mockSAGetRegByKeyFails struct {
	core.StorageGetter
}

func (sa *mockSAGetRegByKeyFails) GetRegistrationByKey(ctx context.Context, jwk *jose.JSONWebKey) (core.Registration, error) {
	return core.Registration{}, fmt.Errorf("whoops")
}

// When SA.GetRegistrationByKey errors (e.g. gRPC timeout), NewAccount should
// return internal server errors.
func TestNewAccountWhenGetRegByKeyFails(t *testing.T) {
	wfe, fc := setupWFE(t)
	wfe.SA = &mockSAGetRegByKeyFails{mocks.NewStorageAuthority(fc)}
	key := loadKey(t, []byte(testE2KeyPrivatePEM))
	_, ok := key.(*ecdsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load ECDSA key")
	payload := `{"contact":["mailto:person@mail.com"],"agreement":"` + agreementURL + `"}`
	responseWriter := httptest.NewRecorder()
	_, _, body := signRequestEmbed(t, key, "http://localhost/new-account", payload, wfe.nonceService)
	wfe.NewAccount(ctx, newRequestEvent(), responseWriter, makePostRequestWithPath("/new-account", body))
	if responseWriter.Code != 500 {
		t.Fatalf("Wrong response code %d for NewAccount with failing GetRegByKey (wanted 500)", responseWriter.Code)
	}
	var prob probs.ProblemDetails
	err := json.Unmarshal(responseWriter.Body.Bytes(), &prob)
	test.AssertNotError(t, err, "unmarshalling response")
	if prob.Type != probs.V2ErrorNS+probs.ServerInternalProblem {
		t.Errorf("Wrong type for returned problem: %#v", prob.Type)
	}
}

type mockSAGetRegByKeyNotFound struct {
	core.StorageGetter
}

func (sa *mockSAGetRegByKeyNotFound) GetRegistrationByKey(ctx context.Context, jwk *jose.JSONWebKey) (core.Registration, error) {
	return core.Registration{}, berrors.NotFoundError("not found")
}

func TestNewAccountWhenGetRegByKeyNotFound(t *testing.T) {
	wfe, fc := setupWFE(t)
	wfe.SA = &mockSAGetRegByKeyNotFound{mocks.NewStorageAuthority(fc)}
	key := loadKey(t, []byte(testE2KeyPrivatePEM))
	_, ok := key.(*ecdsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load ECDSA key")
	// When SA.GetRegistrationByKey returns NotFound, and no onlyReturnExisting
	// field is sent, NewAccount should succeed.
	payload := `{"contact":["mailto:person@mail.com"],"termsOfServiceAgreed":true}`
	signedURL := "http://localhost/new-account"
	responseWriter := httptest.NewRecorder()
	_, _, body := signRequestEmbed(t, key, signedURL, payload, wfe.nonceService)
	wfe.NewAccount(ctx, newRequestEvent(), responseWriter, makePostRequestWithPath("/new-account", body))
	if responseWriter.Code != http.StatusCreated {
		t.Errorf("Bad response to NewRegistration: %d, %s", responseWriter.Code, responseWriter.Body)
	}

	// When SA.GetRegistrationByKey returns NotFound, and onlyReturnExisting
	// field **is** sent, NewAccount should fail with the expected error.
	payload = `{"contact":["mailto:person@mail.com"],"termsOfServiceAgreed":true,"onlyReturnExisting":true}`
	responseWriter = httptest.NewRecorder()
	_, _, body = signRequestEmbed(t, key, signedURL, payload, wfe.nonceService)
	// Process the new account request
	wfe.NewAccount(ctx, newRequestEvent(), responseWriter, makePostRequestWithPath("/new-account", body))
	test.AssertEquals(t, responseWriter.Code, http.StatusBadRequest)
	test.AssertUnmarshaledEquals(t, responseWriter.Body.String(), `
	{
		"type": "urn:ietf:params:acme:error:accountDoesNotExist",
		"detail": "No account exists with the provided key",
		"status": 400
	}`)
}

func TestPrepAuthzForDisplay(t *testing.T) {
	wfe, _ := setupWFE(t)

	// Make an authz for a wildcard identifier
	authz := &core.Authorization{
		ID:             "12345",
		Status:         core.StatusPending,
		RegistrationID: 1,
		Identifier:     core.AcmeIdentifier{Type: "dns", Value: "*.example.com"},
		Challenges: []core.Challenge{
			{
				ID:   12345,
				Type: "dns",
				ProvidedKeyAuthorization: "	🔑",
			},
		},
		Combinations: [][]int{{1, 2, 3}, {4}, {5, 6}},
	}

	// Prep the wildcard authz for display
	wfe.prepAuthorizationForDisplay(&http.Request{Host: "localhost"}, authz)

	// The authz should not have a wildcard prefix in the identifier value
	test.AssertEquals(t, strings.HasPrefix(authz.Identifier.Value, "*."), false)
	// The authz should be marked as corresponding to a wildcard name
	test.AssertEquals(t, authz.Wildcard, true)
	// The authz should not have any combinations
	// NOTE(@cpu): We don't use test.AssertNotNil here because its use of
	// interface{} types makes a comparsion of [][]int{nil} and nil fail.
	if authz.Combinations != nil {
		t.Errorf("Authz had a non-nil combinations")
	}

	// We expect the authz challenge has its URL set and the URI emptied.
	chal := authz.Challenges[0]
	test.AssertEquals(t, chal.URL, "http://localhost/acme/challenge/12345/12345")
	test.AssertEquals(t, chal.URI, "")
	// We also expect the ProvidedKeyAuthorization is not echoed back in the
	// challenge
	test.AssertEquals(t, chal.ProvidedKeyAuthorization, "")
}

// noSCTMockRA is a mock RA that always returns a `berrors.MissingSCTsError` from `FinalizeOrder`
type noSCTMockRA struct {
	MockRegistrationAuthority
}

func (ra *noSCTMockRA) FinalizeOrder(ctx context.Context, req *rapb.FinalizeOrderRequest) (*corepb.Order, error) {
	return nil, berrors.MissingSCTsError("noSCTMockRA missing scts error")
}

func TestFinalizeSCTError(t *testing.T) {
	wfe, _ := setupWFE(t)

	// Set up an RA mock that always returns a berrors.MissingSCTsError from
	// `FinalizeOrder`
	wfe.RA = &noSCTMockRA{}

	// Create a response writer to capture the WFE response
	responseWriter := httptest.NewRecorder()

	// Example CSR payload taken from `TestFinalizeOrder`
	// openssl req -outform der -new -nodes -key wfe/test/178.key -subj /CN=not-an-example.com | b64url
	// a valid CSR
	goodCertCSRPayload := `{
		"csr": "MIICYjCCAUoCAQAwHTEbMBkGA1UEAwwSbm90LWFuLWV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmqs7nue5oFxKBk2WaFZJAma2nm1oFyPIq19gYEAdQN4mWvaJ8RjzHFkDMYUrlIrGxCYuFJDHFUk9dh19Na1MIY-NVLgcSbyNcOML3bLbLEwGmvXPbbEOflBA9mxUS9TLMgXW5ghf_qbt4vmSGKloIim41QXt55QFW6O-84s8Kd2OE6df0wTsEwLhZB3j5pDU-t7j5vTMv4Tc7EptaPkOdfQn-68viUJjlYM_4yIBVRhWCdexFdylCKVLg0obsghQEwULKYCUjdg6F0VJUI115DU49tzscXU_3FS3CyY8rchunuYszBNkdmgpAwViHNWuP7ESdEd_emrj1xuioSe6PwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE_T1nWU38XVYL28hNVSXU0rW5IBUKtbvr0qAkD4kda4HmQRTYkt-LNSuvxoZCC9lxijjgtJi-OJe_DCTdZZpYzewlVvcKToWSYHYQ6Wm1-fxxD_XzphvZOujpmBySchdiz7QSVWJmVZu34XD5RJbIcrmj_cjRt42J1hiTFjNMzQu9U6_HwIMmliDL-soFY2RTvvZf-dAFvOUQ-Wbxt97eM1PbbmxJNWRhbAmgEpe9PWDPTpqV5AK56VAa991cQ1P8ZVmPss5hvwGWhOtpnpTZVHN3toGNYFKqxWPboirqushQlfKiFqT9rpRgM3-mFjOHidGqsKEkTdmfSVlVEk3oo="
	}`

	// Create a finalization request with the above payload
	request := signAndPost(t, "1/4", "http://localhost/1/4", goodCertCSRPayload, 1, wfe.nonceService)

	// POST the finalize order request.
	wfe.FinalizeOrder(ctx, newRequestEvent(), responseWriter, request)

	// We expect the berrors.MissingSCTsError error to have been converted into
	// a serverInternal error with the right message.
	test.AssertUnmarshaledEquals(t,
		responseWriter.Body.String(),
		`{"type":"`+probs.V2ErrorNS+`serverInternal","detail":"Error finalizing order :: Unable to meet CA SCT embedding requirements","status":500}`)
}
