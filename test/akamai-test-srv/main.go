package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"

	"github.com/letsencrypt/boulder/akamai"
	"github.com/letsencrypt/boulder/cmd"
)

func main() {
	listenAddr := flag.String("listen", "localhost:6789", "Address to listen on")
	secret := flag.String("secret", "", "Akamai client secret")
	flag.Parse()

	// v2
	v2Purges := [][]string{}
	v3Purges := [][]string{}
	mu := sync.Mutex{}

	http.HandleFunc("/debug/get-purges", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, err := json.Marshal(struct {
			V2 [][]string
			V3 [][]string
		}{V2: v2Purges, V3: v3Purges})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(body)
		return
	})

	http.HandleFunc("/debug/reset-purges", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		v2Purges, v3Purges = [][]string{}, [][]string{}
		w.WriteHeader(http.StatusOK)
		return
	})

	// Since v2 and v3 APIs share a bunch of logic just mash them into a single
	// handler.
	http.HandleFunc("/ccu/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Println("Wrong method:", r.Method)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		var purgeRequest struct {
			Objects []string `json:"objects"`
			Type    string   `json:"type"`
			Action  string   `json:"action"`
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Println("Can't read body:", err)
			return
		}
		if err = akamai.CheckSignature(*secret, "http://"+*listenAddr, r, body); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Println("Bad signature:", err)
			return
		}
		if err = json.Unmarshal(body, &purgeRequest); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Println("Can't unmarshal:", err)
			return
		}
		if r.URL.Path == "/ccu/v2/queues/default" {
			if purgeRequest.Type != "arl" || purgeRequest.Action != "remove" || len(purgeRequest.Objects) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Println("Bad parameters:", purgeRequest)
				return
			}
			v2Purges = append(v2Purges, purgeRequest.Objects)
		} else if r.URL.Path == "/ccu/v3/delete/url/staging" {
			if len(purgeRequest.Objects) == 0 || purgeRequest.Type != "" || purgeRequest.Action != "" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Println("Bad parameters:", purgeRequest)
				return
			}
			v3Purges = append(v3Purges, purgeRequest.Objects)
		}

		respObj := struct {
			PurgeID          string
			HTTPStatus       int
			EstimatedSeconds int
		}{
			PurgeID:          "welcome-to-the-purge",
			HTTPStatus:       http.StatusCreated,
			EstimatedSeconds: 153,
		}
		w.WriteHeader(http.StatusCreated)
		resp, err := json.Marshal(respObj)
		if err != nil {
			return
		}
		w.Write(resp)
	})

	go log.Fatal(http.ListenAndServe(*listenAddr, nil))
	cmd.CatchSignals(nil, nil)
}
