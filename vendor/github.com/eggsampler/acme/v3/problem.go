package acme

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Problem document as defined in,
// https://tools.ietf.org/html/rfc7807

// Problem represents an error returned by an acme server.
type Problem struct {
	Type        string       `json:"type"`
	Detail      string       `json:"detail,omitempty"`
	Status      int          `json:"status,omitempty"`
	Instance    string       `json:"instance,omitempty"`
	SubProblems []SubProblem `json:"subproblems,omitempty"`
}

type SubProblem struct {
	Type       string     `json:"type"`
	Detail     string     `json:"detail"`
	Identifier Identifier `json:"identifier"`
}

// Returns a human readable error string.
func (err Problem) Error() string {
	s := fmt.Sprintf("acme: error code %d %q: %s", err.Status, err.Type, err.Detail)
	if len(err.SubProblems) > 0 {
		for _, v := range err.SubProblems {
			s += fmt.Sprintf(", problem %q: %s", v.Type, v.Detail)
		}
	}
	if err.Instance != "" {
		s += ", url: " + err.Instance
	}
	return s
}

// Helper function to determine if a response contains an expected status code, or otherwise an error object.
func checkError(resp *http.Response, expectedStatuses ...int) error {
	for _, statusCode := range expectedStatuses {
		if resp.StatusCode == statusCode {
			return nil
		}
	}

	if resp.StatusCode < 400 || resp.StatusCode >= 600 {
		return fmt.Errorf("acme: expected status codes: %d, got: %d %s", expectedStatuses, resp.StatusCode, resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("acme: error reading error body: %v", err)
	}

	acmeError := Problem{}
	if err := json.Unmarshal(body, &acmeError); err != nil {
		return fmt.Errorf("acme: parsing error body: %v - %s", err, string(body))
	}

	return acmeError
}
