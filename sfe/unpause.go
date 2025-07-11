package sfe

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"

	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/unpause"
)

const (
	unpausePostForm = unpause.APIPrefix + "/do-unpause"
	unpauseStatus   = unpause.APIPrefix + "/unpause-status"
)

// UnpauseForm allows a requester to unpause their account via a form present on
// the page. The Subscriber's client will receive a log line emitted by the WFE
// which contains a URL pre-filled with a JWT that will populate a hidden field
// in this form.
func (sfe *SelfServiceFrontEndImpl) UnpauseForm(response http.ResponseWriter, request *http.Request) {
	incomingJWT := request.URL.Query().Get("jwt")

	accountID, idents, err := sfe.parseUnpauseJWT(incomingJWT)
	if err != nil {
		if errors.Is(err, jwt.ErrExpired) {
			// JWT expired before the Subscriber visited the unpause page.
			sfe.unpauseTokenExpired(response)
			return
		}
		if errors.Is(err, unpause.ErrMalformedJWT) {
			// JWT is malformed. This could happen if the Subscriber failed to
			// copy the entire URL from their logs.
			sfe.unpauseRequestMalformed(response)
			return
		}
		sfe.unpauseFailed(response)
		return
	}

	// If any of these values change, ensure any relevant pages in //sfe/pages/
	// are also updated.
	type tmplData struct {
		PostPath  string
		JWT       string
		AccountID int64
		Idents    []string
	}

	// Present the unpause form to the Subscriber.
	sfe.renderTemplate(response, "unpause-form.html", tmplData{unpausePostForm, incomingJWT, accountID, idents})
}

// UnpauseSubmit serves a page showing the result of the unpause form submission.
// CSRF is not addressed because a third party causing submission of an unpause
// form is not harmful.
func (sfe *SelfServiceFrontEndImpl) UnpauseSubmit(response http.ResponseWriter, request *http.Request) {
	incomingJWT := request.URL.Query().Get("jwt")

	accountID, _, err := sfe.parseUnpauseJWT(incomingJWT)
	if err != nil {
		if errors.Is(err, jwt.ErrExpired) {
			// JWT expired before the Subscriber could click the unpause button.
			sfe.unpauseTokenExpired(response)
			return
		}
		if errors.Is(err, unpause.ErrMalformedJWT) {
			// JWT is malformed. This should never happen if the request came
			// from our form.
			sfe.unpauseRequestMalformed(response)
			return
		}
		sfe.unpauseFailed(response)
		return
	}

	unpaused, err := sfe.ra.UnpauseAccount(request.Context(), &rapb.UnpauseAccountRequest{
		RegistrationID: accountID,
	})
	if err != nil {
		sfe.unpauseFailed(response)
		return
	}

	// Redirect to the unpause status page with the count of unpaused
	// identifiers.
	params := url.Values{}
	params.Add("count", fmt.Sprintf("%d", unpaused.Count))
	http.Redirect(response, request, unpauseStatus+"?"+params.Encode(), http.StatusFound)
}

func (sfe *SelfServiceFrontEndImpl) unpauseRequestMalformed(response http.ResponseWriter) {
	sfe.renderTemplate(response, "unpause-invalid-request.html", nil)
}

func (sfe *SelfServiceFrontEndImpl) unpauseTokenExpired(response http.ResponseWriter) {
	sfe.renderTemplate(response, "unpause-expired.html", nil)
}

type unpauseStatusTemplate struct {
	Successful bool
	Limit      int64
	Count      int64
}

func (sfe *SelfServiceFrontEndImpl) unpauseFailed(response http.ResponseWriter) {
	sfe.renderTemplate(response, "unpause-status.html", unpauseStatusTemplate{Successful: false})
}

func (sfe *SelfServiceFrontEndImpl) unpauseSuccessful(response http.ResponseWriter, count int64) {
	sfe.renderTemplate(response, "unpause-status.html", unpauseStatusTemplate{
		Successful: true,
		Limit:      unpause.RequestLimit,
		Count:      count},
	)
}

// UnpauseStatus displays a success message to the Subscriber indicating that
// their account has been unpaused.
func (sfe *SelfServiceFrontEndImpl) UnpauseStatus(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodHead && request.Method != http.MethodGet {
		response.Header().Set("Access-Control-Allow-Methods", "GET, HEAD")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	count, err := strconv.ParseInt(request.URL.Query().Get("count"), 10, 64)
	if err != nil || count < 0 {
		sfe.unpauseFailed(response)
		return
	}

	sfe.unpauseSuccessful(response, count)
}

// parseUnpauseJWT extracts and returns the subscriber's registration ID and a
// slice of paused identifiers from the claims. If the JWT cannot be parsed or
// is otherwise invalid, an error is returned. If the JWT is missing or
// malformed, unpause.ErrMalformedJWT is returned.
func (sfe *SelfServiceFrontEndImpl) parseUnpauseJWT(incomingJWT string) (int64, []string, error) {
	if incomingJWT == "" || len(strings.Split(incomingJWT, ".")) != 3 {
		// JWT is missing or malformed. This could happen if the Subscriber
		// failed to copy the entire URL from their logs. This should never
		// happen if the request came from our form.
		return 0, nil, unpause.ErrMalformedJWT
	}

	claims, err := unpause.RedeemJWT(incomingJWT, sfe.unpauseHMACKey, unpause.APIVersion, sfe.clk)
	if err != nil {
		return 0, nil, err
	}

	account, convErr := strconv.ParseInt(claims.Subject, 10, 64)
	if convErr != nil {
		// This should never happen as this was just validated by the call to
		// unpause.RedeemJWT().
		return 0, nil, errors.New("failed to parse account ID from JWT")
	}

	return account, strings.Split(claims.I, ","), nil
}
