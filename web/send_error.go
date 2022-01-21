package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/probs"
)

// SendError does a few things that we want for each error response:
//  - Adds both the external and the internal error to a RequestEvent.
//  - If the ProblemDetails provided is a ServerInternalProblem, audit logs the
//    internal error.
//  - Prefixes the Type field of the ProblemDetails with a namespace.
//  - Sends an HTTP response containing the error and an error code to the user.
func SendError(
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
	logEvent.Error = fmt.Sprintf("%d :: %s :: %s", prob.HTTPStatus, prob.Type, prob.Detail)
	if len(prob.SubProblems) > 0 {
		subDetails := make([]string, len(prob.SubProblems))
		for i, sub := range prob.SubProblems {
			subDetails[i] = fmt.Sprintf("\"%s :: %s :: %s\"", sub.Identifier.Value, sub.Type, sub.Detail)
		}
		logEvent.Error += fmt.Sprintf(" [%s]", strings.Join(subDetails, ", "))
	}
	if ierr != nil {
		logEvent.AddError(fmt.Sprintf("%s", ierr))
	}

	// Only audit log internal errors so users cannot purposefully cause
	// auditable events. Also, skip the audit log for deadline exceeded errors
	// since we don't need to keep those long-term. Note that they are still
	// included in the request logs.
	deadlineExceeded := ierr == context.DeadlineExceeded || status.Code(ierr) == codes.DeadlineExceeded
	if prob.Type == probs.ServerInternalProblem && !deadlineExceeded {
		if ierr != nil {
			log.AuditErrf("Internal error - %s - %s", prob.Detail, ierr)
		} else {
			log.AuditErrf("Internal error - %s", prob.Detail)
		}
	}

	// Set the proper namespace for the problem and any
	// sub-problems
	prob.Type = probs.ProblemType(namespace) + prob.Type
	for i := range prob.SubProblems {
		prob.SubProblems[i].Type = prob.Type
	}
	problemDoc, err := json.MarshalIndent(prob, "", "  ")
	if err != nil {
		log.AuditErrf("Could not marshal error message: %s - %+v", err, prob)
		problemDoc = []byte("{\"detail\": \"Problem marshalling error message.\"}")
	}

	// Write the JSON problem response
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(code)
	response.Write(problemDoc)
}
