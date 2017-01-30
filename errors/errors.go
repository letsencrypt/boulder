package errors

import "fmt"

// ErrorType provides a coarse category for BoulderErrors
type ErrorType int

const (
	InternalServer ErrorType = iota
	NotSupported
	Malformed
	Unauthorized
	NotFound
	SignatureValidation
	RateLimit
	TooManyRequets
)

// BoulderError represents internal Boulder errors
type BoulderError struct {
	Type   ErrorType
	Detail string
}

func (be *BoulderError) Error() string {
	return be.Detail // add a stringer for the ErrorType?
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

func NotSupportedError(msg string, args ...interface{}) error {
	return New(NotSupported, msg, args...)
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

func SignatureValidationError(msg string, args ...interface{}) error {
	return New(SignatureValidation, msg, args...)
}

func RateLimitError(msg string, args ...interface{}) error {
	return New(RateLimit, msg, args...)
}

func TooManyRequestsError(msg string, args ...interface{}) error {
	return New(TooManyRequets, msg, args...)
}
