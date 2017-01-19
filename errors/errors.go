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
