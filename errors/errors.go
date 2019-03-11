package errors

import "fmt"

// ErrorType provides a coarse category for BoulderErrors
type ErrorType int

const (
	InternalServer ErrorType = iota
	_
	Malformed
	Unauthorized
	NotFound
	RateLimit
	RejectedIdentifier
	InvalidEmail
	ConnectionFailure
	WrongAuthorizationState
	CAA
	MissingSCTs
	Duplicate
	OrderNotReady
)

// BoulderError represents internal Boulder errors
type BoulderError struct {
	Type   ErrorType
	Detail string
}

func (be *BoulderError) Error() string {
	return be.Detail
}

// New is a convenience function for creating a new BoulderError
func New(errType ErrorType, msg string, args ...interface{}) error {
	return &BoulderError{
		Type:   errType,
		Detail: fmt.Sprintf(msg, args...),
	}
}

// Is is a convenience function for testing the internal type of an BoulderError
func Is(err error, errType ErrorType) bool {
	bErr, ok := err.(*BoulderError)
	if !ok {
		return false
	}
	return bErr.Type == errType
}

func InternalServerError(msg string, args ...interface{}) error {
	return New(InternalServer, msg, args...)
}

func MalformedError(msg string, args ...interface{}) error {
	return New(Malformed, msg, args...)
}

func UnauthorizedError(msg string, args ...interface{}) error {
	return New(Unauthorized, msg, args...)
}

func NotFoundError(msg string, args ...interface{}) error {
	return New(NotFound, msg, args...)
}

func RateLimitError(msg string, args ...interface{}) error {
	return &BoulderError{
		Type:   RateLimit,
		Detail: fmt.Sprintf(msg+": see https://letsencrypt.org/docs/rate-limits/", args...),
	}
}

func RejectedIdentifierError(msg string, args ...interface{}) error {
	return New(RejectedIdentifier, msg, args...)
}

func InvalidEmailError(msg string, args ...interface{}) error {
	return New(InvalidEmail, msg, args...)
}

func ConnectionFailureError(msg string, args ...interface{}) error {
	return New(ConnectionFailure, msg, args...)
}

func WrongAuthorizationStateError(msg string, args ...interface{}) error {
	return New(WrongAuthorizationState, msg, args...)
}

func CAAError(msg string, args ...interface{}) error {
	return New(CAA, msg, args...)
}

func MissingSCTsError(msg string, args ...interface{}) error {
	return New(MissingSCTs, msg, args...)
}

func DuplicateError(msg string, args ...interface{}) error {
	return New(Duplicate, msg, args...)
}

func OrderNotReadyError(msg string, args ...interface{}) error {
	return New(OrderNotReady, msg, args...)
}
