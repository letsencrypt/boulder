package web

func (wfe *WebFrontEndImpl) sendError(
	namespace string,
	response http.ResponseWriter,
	logEvent *web.RequestEvent,
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
			wfe.log.AuditErr(fmt.Sprintf("Internal error - %s - %s", prob.Detail, ierr))
		} else {
			wfe.log.AuditErr(fmt.Sprintf("Internal error - %s", prob.Detail))
		}
	}

	// Increment a stat for this problem type
	wfe.stats.Inc(fmt.Sprintf("HTTP.ProblemTypes.%s", prob.Type), 1)

	// Prefix the problem type with the appropriate error namespace and marshal to JSON
	prob.Type = namespace + prob.Type
	problemDoc, err := marshalIndent(prob)
	if err != nil {
		wfe.log.AuditErr(fmt.Sprintf("Could not marshal error message: %s - %+v", err, prob))
		problemDoc = []byte("{\"detail\": \"Problem marshalling error message.\"}")
	}

	// Write the JSON problem response
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(code)
	response.Write(problemDoc)
}
