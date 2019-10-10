package web

import (
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/probs"
)

func problemDetailsForBoulderError(err *berrors.BoulderError, msg string) *probs.ProblemDetails {
	var outProb *probs.ProblemDetails

	switch err.Type {
	case berrors.Malformed:
		outProb = probs.Malformed("%s :: %s", msg, err)
	case berrors.Unauthorized:
		outProb = probs.Unauthorized("%s :: %s", msg, err)
	case berrors.NotFound:
		outProb = probs.NotFound("%s :: %s", msg, err)
	case berrors.RateLimit:
		outProb = probs.RateLimited("%s :: %s", msg, err)
	case berrors.InternalServer:
		// Internal server error messages may include sensitive data, so we do
		// not include it.
		outProb = probs.ServerInternal(msg)
	case berrors.RejectedIdentifier:
		outProb = probs.RejectedIdentifier("%s :: %s", msg, err)
	case berrors.InvalidEmail:
		outProb = probs.InvalidEmail("%s :: %s", msg, err)
	case berrors.WrongAuthorizationState:
		outProb = probs.Malformed("%s :: %s", msg, err)
	case berrors.CAA:
		outProb = probs.CAA("%s :: %s", msg, err)
	case berrors.MissingSCTs:
		// MissingSCTs are an internal server error, but with a specific error
		// message related to the SCT problem
		outProb = probs.ServerInternal("%s :: %s", msg, "Unable to meet CA SCT embedding requirements")
	case berrors.OrderNotReady:
		outProb = probs.OrderNotReady("%s :: %s", msg, err)
	case berrors.BadPublicKey:
		outProb = probs.BadPublicKey("%s :: %s", msg, err)
	case berrors.BadCSR:
		outProb = probs.BadCSR("%s :: %s", msg, err)
	default:
		// Internal server error messages may include sensitive data, so we do
		// not include it.
		outProb = probs.ServerInternal(msg)
	}

	if len(err.SubErrors) > 0 {
		var subProbs []probs.SubProblemDetails
		for _, subErr := range err.SubErrors {
			subProbs = append(subProbs, subProblemDetailsForSubError(subErr, msg))
		}
		return outProb.WithSubProblems(subProbs)
	}

	return outProb
}

// problemDetailsForError turns an error into a ProblemDetails with the special
// case of returning the same error back if its already a ProblemDetails. If the
// error is of an type unknown to ProblemDetailsForError, it will return a
// ServerInternal ProblemDetails.
func ProblemDetailsForError(err error, msg string) *probs.ProblemDetails {
	switch e := err.(type) {
	case *probs.ProblemDetails:
		return e
	case *berrors.BoulderError:
		return problemDetailsForBoulderError(e, msg)
	default:
		// Internal server error messages may include sensitive data, so we do
		// not include it.
		return probs.ServerInternal(msg)
	}
}

// subProblemDetailsForSubError converts a SubBoulderError into
// a SubProblemDetails using problemDetailsForBoulderError.
func subProblemDetailsForSubError(subErr berrors.SubBoulderError, msg string) probs.SubProblemDetails {
	return probs.SubProblemDetails{
		Identifier:     subErr.Identifier,
		ProblemDetails: *problemDetailsForBoulderError(subErr.BoulderError, msg),
	}
}
