package wfe

import (
	"fmt"
	"net/http"
	"strings"
)

func (s *State) addHTTPOneChallenge(token, content string) {
	s.hoMu.Lock()
	defer s.hoMu.Unlock()
	s.httpOneChallenges[token] = content
}

func (s *State) deleteHTTPOneChallenge(token string) {
	s.hoMu.Lock()
	defer s.hoMu.Unlock()
	if _, ok := s.httpOneChallenges[token]; ok {
		delete(s.httpOneChallenges, token)
	}
}

func (s *State) getHTTPOneChallenge(token string) (string, bool) {
	s.hoMu.RLock()
	defer s.hoMu.RUnlock()
	content, present := s.httpOneChallenges[token]
	return content, present
}

func (s *State) httpOneServer() error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requestPath := r.URL.Path
		if strings.HasPrefix(requestPath, "/.well-known/acme-challenge/") {
			token := requestPath[28:]
			if auth, found := s.getHTTPOneChallenge(token); found {
				// fmt.Printf("http-0 challenge request for %s\n", token)
				fmt.Fprintf(w, "%s", auth)
				s.deleteHTTPOneChallenge(token)
			}
		}
	})

	return http.ListenAndServe(fmt.Sprintf(":%d", s.httpOnePort), nil)
}
