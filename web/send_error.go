package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/probs"
)

func sendError(
	log blog.Logger,
	namespace string,
	response http.ResponseWriter,
	logEvent *RequestEvent,
	prob *probs.ProblemDetails,
	ierr error,
) {
	// Determine the HTTP status code to use for this problem
	code := probs.ProblemDetailsToStatusCode(prob)

	// Record details to the log event
	logEvent.AddError(fmt.Sprintf("%d :: %s :: %s", prob.HTTPStatus, prob.Type, prob.Detail))

	// Only audit log internal errors so users cannot purposefully cause
	// auditable events.
	if prob.Type == probs.ServerInternalProblem {
		if ierr != nil {
			log.AuditErr(fmt.Sprintf("Internal error - %s - %s", prob.Detail, ierr))
		} else {
			log.AuditErr(fmt.Sprintf("Internal error - %s", prob.Detail))
		}
	}

	// Prefix the problem type with the ACME V2 error namespace and marshal to JSON
	prob.Type = probs.ProblemType(namespace) + prob.Type
	problemDoc, err := json.MarshalIndent(prob, "", "  ")
	if err != nil {
		log.AuditErr(fmt.Sprintf("Could not marshal error message: %s - %+v", err, prob))
		problemDoc = []byte("{\"detail\": \"Problem marshalling error message.\"}")
	}

	// Write the JSON problem response
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(code)
	response.Write(problemDoc)
}
