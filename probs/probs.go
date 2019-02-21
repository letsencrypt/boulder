package probs

import (
	"fmt"
	"net/http"
)

// Error types that can be used in ACME payloads
const (
	ConnectionProblem          = ProblemType("connection")
	MalformedProblem           = ProblemType("malformed")
	ServerInternalProblem      = ProblemType("serverInternal")
	TLSProblem                 = ProblemType("tls")
	UnauthorizedProblem        = ProblemType("unauthorized")
	UnknownHostProblem         = ProblemType("unknownHost")
	RateLimitedProblem         = ProblemType("rateLimited")
	BadNonceProblem            = ProblemType("badNonce")
	InvalidEmailProblem        = ProblemType("invalidEmail")
	RejectedIdentifierProblem  = ProblemType("rejectedIdentifier")
	AccountDoesNotExistProblem = ProblemType("accountDoesNotExist")
	CAAProblem                 = ProblemType("caa")
	DNSProblem                 = ProblemType("dns")
	AlreadyRevokedProblem      = ProblemType("alreadyRevoked")
	OrderNotReadyProblem       = ProblemType("orderNotReady")

	V1ErrorNS = "urn:acme:error:"
	V2ErrorNS = "urn:ietf:params:acme:error:"
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
	case
		ConnectionProblem,
		MalformedProblem,
		TLSProblem,
		UnknownHostProblem,
		BadNonceProblem,
		InvalidEmailProblem,
		RejectedIdentifierProblem,
		AccountDoesNotExistProblem:
		return http.StatusBadRequest
	case ServerInternalProblem:
		return http.StatusInternalServerError
	case
		UnauthorizedProblem,
		CAAProblem:
		return http.StatusForbidden
	case RateLimitedProblem:
		return statusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

// BadNonce returns a ProblemDetails with a BadNonceProblem and a 400 Bad
// Request status code.
func BadNonce(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       BadNonceProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusBadRequest,
	}
}

// RejectedIdentifier returns a ProblemDetails with a RejectedIdentifierProblem and a 400 Bad
// Request status code.
func RejectedIdentifier(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       RejectedIdentifierProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusBadRequest,
	}
}

// Conflict returns a ProblemDetails with a MalformedProblem and a 409 Conflict
// status code.
func Conflict(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       MalformedProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusConflict,
	}
}

// AlreadyRevoked returns a ProblemDetails with a AlreadyRevokedProblem and a 400 Bad
// Request status code.
func AlreadyRevoked(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       AlreadyRevokedProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusBadRequest,
	}
}

// Malformed returns a ProblemDetails with a MalformedProblem and a 400 Bad
// Request status code.
func Malformed(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       MalformedProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusBadRequest,
	}
}

// NotFound returns a ProblemDetails with a MalformedProblem and a 404 Not Found
// status code.
func NotFound(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       MalformedProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusNotFound,
	}
}

// ServerInternal returns a ProblemDetails with a ServerInternalProblem and a
// 500 Internal Server Failure status code.
func ServerInternal(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       ServerInternalProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusInternalServerError,
	}
}

// Unauthorized returns a ProblemDetails with an UnauthorizedProblem and a 403
// Forbidden status code.
func Unauthorized(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       UnauthorizedProblem,
		Detail:     fmt.Sprintf(detail, a...),
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

// InvalidContentType returns a ProblemDetails suitable for a missing
// ContentType header, or an incorrect ContentType header
func InvalidContentType(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       MalformedProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusUnsupportedMediaType,
	}
}

// InvalidEmail returns a ProblemDetails representing an invalid email address
// error
func InvalidEmail(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       InvalidEmailProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusBadRequest,
	}
}

// ConnectionFailure returns a ProblemDetails representing a ConnectionProblem
// error
func ConnectionFailure(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       ConnectionProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusBadRequest,
	}
}

// UnknownHost returns a ProblemDetails representing an UnknownHostProblem error
func UnknownHost(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       UnknownHostProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusBadRequest,
	}
}

// RateLimited returns a ProblemDetails representing a RateLimitedProblem error
func RateLimited(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       RateLimitedProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: statusTooManyRequests,
	}
}

// TLSError returns a ProblemDetails representing a TLSProblem error
func TLSError(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       TLSProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusBadRequest,
	}
}

// AccountDoesNotExist returns a ProblemDetails representing an
// AccountDoesNotExistProblem error
func AccountDoesNotExist(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       AccountDoesNotExistProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusBadRequest,
	}
}

// CAA returns a ProblemDetails representing a CAAProblem
func CAA(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       CAAProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusForbidden,
	}
}

// DNS returns a ProblemDetails representing a DNSProblem
func DNS(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       DNSProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusBadRequest,
	}
}

// OrderNotReady returns a ProblemDetails representing a OrderNotReadyProblem
func OrderNotReady(detail string, a ...interface{}) *ProblemDetails {
	return &ProblemDetails{
		Type:       OrderNotReadyProblem,
		Detail:     fmt.Sprintf(detail, a...),
		HTTPStatus: http.StatusForbidden,
	}
}
