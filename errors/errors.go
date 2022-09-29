// Package errors provides internal-facing error types for use in Boulder. Many
// of these are transformed directly into Problem Details documents by the WFE.
// Some, like NotFound, may be handled internally. We avoid using Problem
// Details documents as part of our internal error system to avoid layering
// confusions.
//
// These errors are specifically for use in errors that cross RPC boundaries.
// An error type that does not need to be passed through an RPC can use a plain
// Go type locally. Our gRPC code is aware of these error types and will
// serialize and deserialize them automatically.
package errors

import (
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/identifier"
)

// ErrorType provides a coarse category for BoulderErrors.
// Objects of type ErrorType should never be directly returned by other
// functions; instead use the methods below to create an appropriate
// BoulderError wrapping one of these types.
type ErrorType int

// These numeric constants are used when sending berrors through gRPC.
const (
	// InternalServer is deprecated. Instead, pass a plain Go error. That will get
	// turned into a probs.InternalServerError by the WFE.
	InternalServer ErrorType = iota
	_
	Malformed
	Unauthorized
	NotFound
	RateLimit
	RejectedIdentifier
	InvalidEmail
	ConnectionFailure
	_ // Reserved, previously WrongAuthorizationState
	CAA
	MissingSCTs
	Duplicate
	OrderNotReady
	DNS
	BadPublicKey
	BadCSR
	AlreadyRevoked
	BadRevocationReason
)

func (ErrorType) Error() string {
	return "urn:ietf:params:acme:error"
}

// BoulderError represents internal Boulder errors
type BoulderError struct {
	Type      ErrorType
	Detail    string
	SubErrors []SubBoulderError

	// RetryAfter the duration a client should wait before retrying the request
	// which resulted in this error.
	RetryAfter time.Duration
}

// SubBoulderError represents sub-errors specific to an identifier that are
// related to a top-level internal Boulder error.
type SubBoulderError struct {
	*BoulderError
	Identifier identifier.ACMEIdentifier
}

func (be *BoulderError) Error() string {
	return be.Detail
}

func (be *BoulderError) Unwrap() error {
	return be.Type
}

// WithSubErrors returns a new BoulderError instance created by adding the
// provided subErrs to the existing BoulderError.
func (be *BoulderError) WithSubErrors(subErrs []SubBoulderError) *BoulderError {
	return &BoulderError{
		Type:       be.Type,
		Detail:     be.Detail,
		SubErrors:  append(be.SubErrors, subErrs...),
		RetryAfter: be.RetryAfter,
	}
}

// New is a convenience function for creating a new BoulderError
func New(errType ErrorType, retryAfter time.Duration, msg string, args ...interface{}) error {
	return &BoulderError{
		Type:       errType,
		Detail:     fmt.Sprintf(msg, args...),
		RetryAfter: retryAfter,
	}
}

func InternalServerError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(InternalServer, retryAfter, msg, args...)
}

func MalformedError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(Malformed, retryAfter, msg, args...)
}

func UnauthorizedError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(Unauthorized, retryAfter, msg, args...)
}

func NotFoundError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(NotFound, retryAfter, msg, args...)
}

func RateLimitError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(
		RateLimit,
		retryAfter,
		fmt.Sprintf(msg+": see https://letsencrypt.org/docs/rate-limits/", args...),
	)
}

func DuplicateCertificateError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(
		RateLimit,
		retryAfter,
		fmt.Sprintf(msg+": see https://letsencrypt.org/docs/duplicate-certificate-limit/", args...),
	)
}

func FailedValidationError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(
		RateLimit,
		retryAfter,
		fmt.Sprintf(msg+": see https://letsencrypt.org/docs/failed-validation-limit/", args...),
	)
}

func RegistrationsPerIPError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(
		RateLimit,
		retryAfter,
		fmt.Sprintf(msg+": see https://letsencrypt.org/docs/too-many-registrations-for-this-ip/", args...),
	)
}

func RejectedIdentifierError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(RejectedIdentifier, retryAfter, msg, args...)
}

func InvalidEmailError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(InvalidEmail, retryAfter, msg, args...)
}

func ConnectionFailureError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(ConnectionFailure, retryAfter, msg, args...)
}

func CAAError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(CAA, retryAfter, msg, args...)
}

func MissingSCTsError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(MissingSCTs, retryAfter, msg, args...)
}

func DuplicateError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(Duplicate, retryAfter, msg, args...)
}

func OrderNotReadyError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(OrderNotReady, retryAfter, msg, args...)
}

func DNSError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(DNS, retryAfter, msg, args...)
}

func BadPublicKeyError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(BadPublicKey, retryAfter, msg, args...)
}

func BadCSRError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(BadCSR, retryAfter, msg, args...)
}

func AlreadyRevokedError(retryAfter time.Duration, msg string, args ...interface{}) error {
	return New(AlreadyRevoked, retryAfter, msg, args...)
}

func BadRevocationReasonError(retryAfter time.Duration, reason int64) error {
	return New(BadRevocationReason, retryAfter, "disallowed revocation reason: %d", reason)
}
