package core

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"expvar"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/probs"
	jose "github.com/square/go-jose"
)

// Package Variables Variables

// BuildID is set by the compiler (using -ldflags "-X core.BuildID $(git rev-parse --short HEAD)")
// and is used by GetBuildID
var BuildID string

// BuildHost is set by the compiler and is used by GetBuildHost
var BuildHost string

// BuildTime is set by the compiler and is used by GetBuildTime
var BuildTime string

func init() {
	expvar.NewString("BuildID").Set(BuildID)
	expvar.NewString("BuildTime").Set(BuildTime)
}

// Errors

// InternalServerError indicates that something has gone wrong unrelated to the
// user's input, and will be considered by the Load Balancer as an indication
// that this Boulder instance may be malfunctioning. Minimally, returning this
// will cause an error page to be generated at the CDN/LB for the client.
// Consequently, you should only use this error when Boulder's internal
// constraints have been violated.
type InternalServerError string

// NotSupportedError indicates a method is not yet supported
type NotSupportedError string

// MalformedRequestError indicates the user data was improper
type MalformedRequestError string

// UnauthorizedError indicates the user did not satisfactorily prove identity
type UnauthorizedError string

// NotFoundError indicates the destination was unknown. Whoa oh oh ohhh.
type NotFoundError string

// LengthRequiredError indicates a POST was sent with no Content-Length.
type LengthRequiredError string

// SignatureValidationError indicates that the user's signature could not
// be verified, either through adversarial activity, or misconfiguration of
// the user client.
type SignatureValidationError string

// NoSuchRegistrationError indicates that a registration could not be found.
type NoSuchRegistrationError string

// RateLimitedError indicates the user has hit a rate limit
type RateLimitedError string

// TooManyRPCRequestsError indicates an RPC server has hit it's concurrent request
// limit
type TooManyRPCRequestsError string

// BadNonceError indicates an empty of invalid nonce was provided
type BadNonceError string

func (e InternalServerError) Error() string      { return string(e) }
func (e NotSupportedError) Error() string        { return string(e) }
func (e MalformedRequestError) Error() string    { return string(e) }
func (e UnauthorizedError) Error() string        { return string(e) }
func (e NotFoundError) Error() string            { return string(e) }
func (e LengthRequiredError) Error() string      { return string(e) }
func (e SignatureValidationError) Error() string { return string(e) }
func (e NoSuchRegistrationError) Error() string  { return string(e) }
func (e RateLimitedError) Error() string         { return string(e) }
func (e TooManyRPCRequestsError) Error() string  { return string(e) }
func (e BadNonceError) Error() string            { return string(e) }

// statusTooManyRequests is the HTTP status code meant for rate limiting
// errors. It's not currently in the net/http library so we add it here.
const statusTooManyRequests = 429

// ProblemDetailsForError turns an error into a ProblemDetails with the special
// case of returning the same error back if its already a ProblemDetails. If the
// error is of an type unknown to ProblemDetailsForError, it will return a
// ServerInternal ProblemDetails.
func ProblemDetailsForError(err error, msg string) *probs.ProblemDetails {
	switch e := err.(type) {
	case *probs.ProblemDetails:
		return e
	case MalformedRequestError:
		return probs.Malformed(fmt.Sprintf("%s :: %s", msg, err))
	case NotSupportedError:
		return &probs.ProblemDetails{
			Type:       probs.ServerInternalProblem,
			Detail:     fmt.Sprintf("%s :: %s", msg, err),
			HTTPStatus: http.StatusNotImplemented,
		}
	case UnauthorizedError:
		return probs.Unauthorized(fmt.Sprintf("%s :: %s", msg, err))
	case NotFoundError:
		return probs.NotFound(fmt.Sprintf("%s :: %s", msg, err))
	case LengthRequiredError:
		prob := probs.Malformed("missing Content-Length header")
		prob.HTTPStatus = http.StatusLengthRequired
		return prob
	case SignatureValidationError:
		return probs.Malformed(fmt.Sprintf("%s :: %s", msg, err))
	case RateLimitedError:
		return probs.RateLimited(fmt.Sprintf("%s :: %s", msg, err))
	case BadNonceError:
		return probs.BadNonce(fmt.Sprintf("%s :: %s", msg, err))
	default:
		// Internal server error messages may include sensitive data, so we do
		// not include it.
		return probs.ServerInternal(msg)
	}
}

// Random stuff

// RandomString returns a randomly generated string of the requested length.
func RandomString(byteLength int) string {
	b := make([]byte, byteLength)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(fmt.Sprintf("Error reading random bytes: %s", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewToken produces a random string for Challenges, etc.
func NewToken() string {
	return RandomString(32)
}

var tokenFormat = regexp.MustCompile("^[\\w-]{43}$")

// LooksLikeAToken checks whether a string represents a 32-octet value in
// the URL-safe base64 alphabet.
func LooksLikeAToken(token string) bool {
	return tokenFormat.MatchString(token)
}

// Fingerprints

// Fingerprint256 produces an unpadded, URL-safe Base64-encoded SHA256 digest
// of the data.
func Fingerprint256(data []byte) string {
	d := sha256.New()
	_, _ = d.Write(data) // Never returns an error
	return base64.RawURLEncoding.EncodeToString(d.Sum(nil))
}

// KeyDigest produces a padded, standard Base64-encoded SHA256 digest of a
// provided public key.
func KeyDigest(key crypto.PublicKey) (string, error) {
	switch t := key.(type) {
	case *jose.JsonWebKey:
		if t == nil {
			return "", fmt.Errorf("Cannot compute digest of nil key")
		}
		return KeyDigest(t.Key)
	case jose.JsonWebKey:
		return KeyDigest(t.Key)
	default:
		keyDER, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			logger := blog.Get()
			logger.Debug(fmt.Sprintf("Problem marshaling public key: %s", err))
			return "", err
		}
		spkiDigest := sha256.Sum256(keyDER)
		return base64.StdEncoding.EncodeToString(spkiDigest[0:32]), nil
	}
}

// KeyDigestEquals determines whether two public keys have the same digest.
func KeyDigestEquals(j, k crypto.PublicKey) bool {
	digestJ, errJ := KeyDigest(j)
	digestK, errK := KeyDigest(k)
	// Keys that don't have a valid digest (due to marshalling problems)
	// are never equal. So, e.g. nil keys are not equal.
	if errJ != nil || errK != nil {
		return false
	}
	return digestJ == digestK
}

// AcmeURL is a URL that automatically marshal/unmarshal to JSON strings
type AcmeURL url.URL

// ParseAcmeURL is just a wrapper around url.Parse that returns an *AcmeURL
func ParseAcmeURL(s string) (*AcmeURL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	return (*AcmeURL)(u), nil
}

func (u *AcmeURL) String() string {
	uu := (*url.URL)(u)
	return uu.String()
}

// PathSegments splits an AcmeURL into segments on the '/' characters
func (u *AcmeURL) PathSegments() (segments []string) {
	segments = strings.Split(u.Path, "/")
	if len(segments) > 0 && len(segments[0]) == 0 {
		segments = segments[1:]
	}
	return
}

// MarshalJSON encodes an AcmeURL for transfer
func (u *AcmeURL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// UnmarshalJSON decodes an AcmeURL from transfer
func (u *AcmeURL) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	uu, err := url.Parse(str)
	if err != nil {
		return err
	}
	*u = AcmeURL(*uu)
	return nil
}

// SerialToString converts a certificate serial number (big.Int) to a String
// consistently.
func SerialToString(serial *big.Int) string {
	return fmt.Sprintf("%036x", serial)
}

// StringToSerial converts a string into a certificate serial number (big.Int)
// consistently.
func StringToSerial(serial string) (*big.Int, error) {
	var serialNum big.Int
	if !ValidSerial(serial) {
		return &serialNum, errors.New("Invalid serial number")
	}
	_, err := fmt.Sscanf(serial, "%036x", &serialNum)
	return &serialNum, err
}

// ValidSerial tests whether the input string represents a syntactically
// valid serial number, i.e., that it is a valid hex string between 32
// and 36 characters long.
func ValidSerial(serial string) bool {
	// Originally, serial numbers were 32 hex characters long. We later increased
	// them to 36, but we allow the shorter ones because they exist in some
	// production databases.
	if len(serial) < 32 && len(serial) > 36 {
		return false
	}
	_, err := hex.DecodeString(serial)
	if err != nil {
		return false
	}
	return true
}

// GetBuildID identifies what build is running.
func GetBuildID() (retID string) {
	retID = BuildID
	if retID == "" {
		retID = "Unspecified"
	}
	return
}

// GetBuildTime identifies when this build was made
func GetBuildTime() (retID string) {
	retID = BuildTime
	if retID == "" {
		retID = "Unspecified"
	}
	return
}

// GetBuildHost identifies the building host
func GetBuildHost() (retID string) {
	retID = BuildHost
	if retID == "" {
		retID = "Unspecified"
	}
	return
}

// UniqueLowerNames returns the set of all unique names in the input after all
// of them are lowercased. The returned names will be in their lowercased form
// and sorted alphabetically.
func UniqueLowerNames(names []string) (unique []string) {
	nameMap := make(map[string]int, len(names))
	for _, name := range names {
		nameMap[strings.ToLower(name)] = 1
	}

	unique = make([]string, 0, len(nameMap))
	for name := range nameMap {
		unique = append(unique, name)
	}
	sort.Strings(unique)
	return
}

// LoadCertBundle loads a PEM bundle of certificates from disk
func LoadCertBundle(filename string) ([]*x509.Certificate, error) {
	bundleBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var bundle []*x509.Certificate
	var block *pem.Block
	rest := bundleBytes
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("Block has invalid type: %s", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		bundle = append(bundle, cert)
	}

	if len(bundle) == 0 {
		return nil, fmt.Errorf("Bundle doesn't contain any certificates")
	}

	return bundle, nil
}

// LoadCert loads a PEM certificate specified by filename or returns an error
func LoadCert(filename string) (cert *x509.Certificate, err error) {
	certPEM, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("No data in cert PEM file %s", filename)
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	return
}

// retryJitter is used to prevent bunched retried queries from falling into lockstep
const retryJitter = 0.2

// RetryBackoff calculates a backoff time based on number of retries, will always
// add jitter so requests that start in unison won't fall into lockstep. Because of
// this the returned duration can always be larger than the maximum by a factor of
// retryJitter. Adapted from https://github.com/grpc/grpc-go/blob/master/rpc_util.go#L311
func RetryBackoff(retries int, base, max time.Duration, factor float64) time.Duration {
	if retries == 0 {
		return 0
	}
	backoff, fMax := float64(base), float64(max)
	for backoff < fMax && retries > 1 {
		backoff *= factor
		retries--
	}
	if backoff > fMax {
		backoff = fMax
	}
	// Randomize backoff delays so that if a cluster of requests start at
	// the same time, they won't operate in lockstep.
	backoff *= (1 - retryJitter) + 2*retryJitter*mrand.Float64()
	return time.Duration(backoff)
}

// IsASCII determines if every character in a string is encoded in
// the ASCII character set.
func IsASCII(str string) bool {
	for _, r := range str {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}
