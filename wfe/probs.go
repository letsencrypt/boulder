package wfe

import (
	"fmt"
	"net/http"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/probs"
)

func problemDetailsForBoulderError(err *berrors.BoulderError, msg string) *probs.ProblemDetails {
	switch err.Type {
	case berrors.NotSupported:
		return &probs.ProblemDetails{
			Type:       probs.ServerInternalProblem,
			Detail:     fmt.Sprintf("%s :: %s", msg, err),
			HTTPStatus: http.StatusNotImplemented,
		}
	case berrors.Malformed, berrors.SignatureValidation:
		return probs.Malformed(fmt.Sprintf("%s :: %s", msg, err))
	case berrors.Unauthorized:
		return probs.Unauthorized(fmt.Sprintf("%s :: %s", msg, err))
	case berrors.NotFound:
		return probs.NotFound(fmt.Sprintf("%s :: %s", msg, err))
	case berrors.RateLimit:
		return probs.RateLimited(fmt.Sprintf("%s :: %s", msg, err))
	case berrors.InternalServer, berrors.TooManyRequests:
		// Internal server error messages may include sensitive data, so we do
		// not include it.
		return probs.ServerInternal(msg)
	case berrors.RejectedIdentifier:
		return probs.RejectedIdentifier(fmt.Sprintf("%s :: %s", msg, err))
	case berrors.UnsupportedIdentifier:
		return probs.UnsupportedIdentifier(msg)
	case berrors.InvalidEmail:
		return probs.InvalidEmail(fmt.Sprintf("%s :: %s", msg, err))
	default:
		// Internal server error messages may include sensitive data, so we do
		// not include it.
		return probs.ServerInternal(msg)
	}
}

// problemDetailsForError turns an error into a ProblemDetails with the special
// case of returning the same error back if its already a ProblemDetails. If the
// error is of an type unknown to ProblemDetailsForError, it will return a
// ServerInternal ProblemDetails.
func problemDetailsForError(err error, msg string) *probs.ProblemDetails {
	switch e := err.(type) {
	case *probs.ProblemDetails:
		return e
	case *berrors.BoulderError:
		return problemDetailsForBoulderError(e, msg)
	case core.MalformedRequestError:
		return probs.Malformed(fmt.Sprintf("%s :: %s", msg, err))
	case core.NotSupportedError:
		return &probs.ProblemDetails{
			Type:       probs.ServerInternalProblem,
			Detail:     fmt.Sprintf("%s :: %s", msg, err),
			HTTPStatus: http.StatusNotImplemented,
		}
	case core.UnauthorizedError:
		return probs.Unauthorized(fmt.Sprintf("%s :: %s", msg, err))
	case core.NotFoundError:
		return probs.NotFound(fmt.Sprintf("%s :: %s", msg, err))
	case core.LengthRequiredError:
		prob := probs.Malformed("missing Content-Length header")
		prob.HTTPStatus = http.StatusLengthRequired
		return prob
	case core.SignatureValidationError:
		return probs.Malformed(fmt.Sprintf("%s :: %s", msg, err))
	case core.RateLimitedError:
		return probs.RateLimited(fmt.Sprintf("%s :: %s", msg, err))
	case core.BadNonceError:
		return probs.BadNonce(fmt.Sprintf("%s :: %s", msg, err))
	default:
		// Internal server error messages may include sensitive data, so we do
		// not include it.
		return probs.ServerInternal(msg)
	}
}
