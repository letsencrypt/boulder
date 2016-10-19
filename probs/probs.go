package probs

import (
	"fmt"
	"net/http"
)

// Error types that can be used in ACME payloads
const (
	ConnectionProblem            = ProblemType("urn:ietf:params:acme:error:connection")
	MalformedProblem             = ProblemType("urn:ietf:params:acme:error:malformed")
	ServerInternalProblem        = ProblemType("urn:ietf:params:acme:error:serverInternal")
	TLSProblem                   = ProblemType("urn:ietf:params:acme:error:tls")
	UnauthorizedProblem          = ProblemType("urn:ietf:params:acme:error:unauthorized")
	UnknownHostProblem           = ProblemType("urn:ietf:params:acme:error:unknownHost")
	RateLimitedProblem           = ProblemType("urn:ietf:params:acme:error:rateLimited")
	BadNonceProblem              = ProblemType("urn:ietf:params:acme:error:badNonce")
	InvalidEmailProblem          = ProblemType("urn:ietf:params:acme:error:invalidEmail")
	RejectedIdentifierProblem    = ProblemType("urn:ietf:params:acme:error:rejectedIdentifier")
	UnsupportedIdentifierProblem = ProblemType("urn:ietf:params:acme:error:unsupportedIdentifier")
)

// ProblemType defines the error types in the ACME protocol
type ProblemType string

// ProblemDetails objects represent problem documents
// https://tools.ietf.org/html/draft-ietf-appsawg-http-problem-00
type ProblemDetails struct {
	Type   ProblemType `json:"type,omitempty"`
	Detail string      `json:"detail,omitempty"`
	// HTTPStatus is the HTTP status code the ProblemDetails should probably be sent
	// as.
	HTTPStatus int `json:"status,omitempty"`
}

func (pd *ProblemDetails) Error() string {
	return fmt.Sprintf("%s :: %s", pd.Type, pd.Detail)
}

// statusTooManyRequests is the HTTP status code meant for rate limiting
// errors. It's not currently in the net/http library so we add it here.
const statusTooManyRequests = 429

// ProblemDetailsToStatusCode inspects the given ProblemDetails to figure out
// what HTTP status code it should represent. It should only be used by the WFE
// but is included in this package because of its reliance on ProblemTypes.
func ProblemDetailsToStatusCode(prob *ProblemDetails) int {
	if prob.HTTPStatus != 0 {
		return prob.HTTPStatus
	}
	switch prob.Type {
	case ConnectionProblem, MalformedProblem, TLSProblem, UnknownHostProblem, BadNonceProblem, InvalidEmailProblem, RejectedIdentifierProblem, UnsupportedIdentifierProblem:
		return http.StatusBadRequest
	case ServerInternalProblem:
		return http.StatusInternalServerError
	case UnauthorizedProblem:
		return http.StatusForbidden
	case RateLimitedProblem:
		return statusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

// BadNonce returns a ProblemDetails with a BadNonceProblem and a 400 Bad
// Request status code.
func BadNonce(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       BadNonceProblem,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

// RejectedIdentifier returns a ProblemDetails with a RejectedIdentifierProblem and a 400 Bad
// Request status code.
func RejectedIdentifier(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       RejectedIdentifierProblem,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

// UnsupportedIdentifier returns a ProblemDetails with a UnsupportedIdentifierProblem and a 400 Bad
// Request status code.
func UnsupportedIdentifier(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       UnsupportedIdentifierProblem,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

// Conflict returns a ProblemDetails with a MalformedProblem and a 409 Conflict
// status code.
func Conflict(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       MalformedProblem,
		Detail:     detail,
		HTTPStatus: http.StatusConflict,
	}
}

// Malformed returns a ProblemDetails with a MalformedProblem and a 400 Bad
// Request status code.
func Malformed(detail string, args ...interface{}) *ProblemDetails {
	if len(args) > 0 {
		detail = fmt.Sprintf(detail, args...)
	}
	return &ProblemDetails{
		Type:       MalformedProblem,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

// NotFound returns a ProblemDetails with a MalformedProblem and a 404 Not Found
// status code.
func NotFound(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       MalformedProblem,
		Detail:     detail,
		HTTPStatus: http.StatusNotFound,
	}
}

// ServerInternal returns a ProblemDetails with a ServerInternalProblem and a
// 500 Internal Server Failure status code.
func ServerInternal(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       ServerInternalProblem,
		Detail:     detail,
		HTTPStatus: http.StatusInternalServerError,
	}
}

// Unauthorized returns a ProblemDetails with an UnauthorizedProblem and a 403
// Forbidden status code.
func Unauthorized(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       UnauthorizedProblem,
		Detail:     detail,
		HTTPStatus: http.StatusForbidden,
	}
}

// MethodNotAllowed returns a ProblemDetails representing a disallowed HTTP
// method error.
func MethodNotAllowed() *ProblemDetails {
	return &ProblemDetails{
		Type:       MalformedProblem,
		Detail:     "Method not allowed",
		HTTPStatus: http.StatusMethodNotAllowed,
	}
}

// ContentLengthRequired returns a ProblemDetails representing a missing
// Content-Length header error
func ContentLengthRequired() *ProblemDetails {
	return &ProblemDetails{
		Type:       MalformedProblem,
		Detail:     "missing Content-Length header",
		HTTPStatus: http.StatusLengthRequired,
	}
}

// InvalidEmail returns a ProblemDetails representing an invalid email address
// error
func InvalidEmail(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       InvalidEmailProblem,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

// ConnectionFailure returns a ProblemDetails representing a ConnectionProblem
// error
func ConnectionFailure(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       ConnectionProblem,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

// UnknownHost returns a ProblemDetails representing an UnknownHostProblem error
func UnknownHost(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       UnknownHostProblem,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

// RateLimited returns a ProblemDetails representing a RateLimitedProblem error
func RateLimited(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       RateLimitedProblem,
		Detail:     detail,
		HTTPStatus: statusTooManyRequests,
	}
}

// TLSError returns a ProblemDetails representing a TLSProblem error
func TLSError(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       TLSProblem,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}
