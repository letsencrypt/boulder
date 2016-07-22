package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// toFilter filters mails based on the To: field.
// The zero value matches all mails.
type toFilter struct {
	To string
}

func (f *toFilter) Match(m rcvdMail) bool {
	if f.To != "" && f.To != m.To {
		return false
	}
	return true
}

/*
/count - number of mails
/count?to=foo@bar.com - number of mails for foo@bar.com
/clear - clear the mail list
/mail/0 - first mail
/mail/1 - second mail
/mail/0?to=foo@bar.com - first mail for foo@bar.com
/mail/1?to=foo@bar.com - second mail for foo@bar.com
*/

func (s mailSrv) setupHTTP(serveMux *http.ServeMux) {
	serveMux.HandleFunc("/count", s.httpCount)
	serveMux.HandleFunc("/clear", s.httpClear)
	serveMux.Handle("/mail/", http.StripPrefix("/mail/", http.HandlerFunc(s.httpGetMail)))
}

func (s mailSrv) httpClear(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		s.allMailMutex.Lock()
		s.allReceivedMail = nil
		s.allMailMutex.Unlock()
		w.WriteHeader(200)
	} else {
		w.WriteHeader(405)
	}
}

func (s mailSrv) httpCount(w http.ResponseWriter, r *http.Request) {
	count := 0
	s.iterMail(extractFilter(r), func(m rcvdMail) bool {
		count++
		return false
	})
	fmt.Fprintf(w, "%d\n", count)
}

var rgxGetMail = regexp.MustCompile(`^(\d+)/?$`)

func (s mailSrv) httpGetMail(w http.ResponseWriter, r *http.Request) {
	mailNum, err := strconv.Atoi(strings.Trim(r.URL.Path, "/"))
	if err != nil {
		w.WriteHeader(400)
		log.Println("mail-test-srv: bad request:", r.URL.Path, "-", err)
		return
	}
	idx := 0
	found := s.iterMail(extractFilter(r), func(m rcvdMail) bool {
		if mailNum == idx {
			printMail(w, m)
			return true
		}
		idx++
		return false
	})
	if !found {
		w.WriteHeader(404)
	}
}

func extractFilter(r *http.Request) toFilter {
	values := r.URL.Query()
	to := values.Get("to")
	return toFilter{To: to}
}

func (s mailSrv) iterMail(f toFilter, cb func(rcvdMail) bool) bool {
	s.allMailMutex.Lock()
	defer s.allMailMutex.Unlock()
	for _, v := range s.allReceivedMail {
		if !f.Match(v) {
			continue
		}
		if cb(v) {
			return true
		}
	}
	return false
}

func printMail(w io.Writer, mail rcvdMail) {
	fmt.Fprintf(w, "FROM %s\n", mail.From)
	fmt.Fprintf(w, "TO %s\n", mail.To)
	fmt.Fprintf(w, "\n%s\n", mail.Mail)
}
