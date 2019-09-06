package acme

import "net/http"

// FetchAuthorization fetches an authorization from an authorization url provided in an order.
func (c Client) FetchAuthorization(account Account, authURL string) (Authorization, error) {
	authResp := Authorization{}
	_, err := c.post(authURL, account.URL, account.PrivateKey, "", &authResp, http.StatusOK)
	if err != nil {
		return authResp, err
	}

	for i := 0; i < len(authResp.Challenges); i++ {
		if authResp.Challenges[i].KeyAuthorization == "" {
			authResp.Challenges[i].KeyAuthorization = authResp.Challenges[i].Token + "." + account.Thumbprint
		}
	}

	authResp.ChallengeMap = map[string]Challenge{}
	authResp.ChallengeTypes = []string{}
	for _, c := range authResp.Challenges {
		authResp.ChallengeMap[c.Type] = c
		authResp.ChallengeTypes = append(authResp.ChallengeTypes, c.Type)
	}

	authResp.URL = authURL

	return authResp, nil
}

// DeactivateAuthorization deactivate a provided authorization url from an order.
func (c Client) DeactivateAuthorization(account Account, authURL string) (Authorization, error) {
	deactivateReq := struct {
		Status string `json:"status"`
	}{
		Status: "deactivated",
	}
	deactivateResp := Authorization{}

	_, err := c.post(authURL, account.URL, account.PrivateKey, deactivateReq, &deactivateResp, http.StatusOK)

	return deactivateResp, err
}
