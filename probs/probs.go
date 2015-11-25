package probs

import "fmt"

// Error types that can be used in ACME payloads
const (
	ConnectionProblem     = ProblemType("urn:acme:error:connection")
	MalformedProblem      = ProblemType("urn:acme:error:malformed")
	ServerInternalProblem = ProblemType("urn:acme:error:serverInternal")
	TLSProblem            = ProblemType("urn:acme:error:tls")
	UnauthorizedProblem   = ProblemType("urn:acme:error:unauthorized")
	UnknownHostProblem    = ProblemType("urn:acme:error:unknownHost")
	RateLimitedProblem    = ProblemType("urn:acme:error:rateLimited")
	BadNonceProblem       = ProblemType("urn:acme:error:badNonce")
)

// ProblemType defines the error types in the ACME protocol
type ProblemType string

// ProblemDetails objects represent problem documents
// https://tools.ietf.org/html/draft-ietf-appsawg-http-problem-00
type ProblemDetails struct {
	Type   ProblemType `json:"type,omitempty"`
	Detail string      `json:"detail,omitempty"`
}

func (pd *ProblemDetails) Error() string {
	return fmt.Sprintf("%s :: %s", pd.Type, pd.Detail)
}
