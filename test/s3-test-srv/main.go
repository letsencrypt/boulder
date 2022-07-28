package main

import (
	"flag"
	"io"
	"log"
	"net/http"

	"github.com/letsencrypt/boulder/cmd"
)

func main() {
	listenAddr := flag.String("listen", "localhost:7890", "Address to listen on")
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte("failed to read request body"))
			return
		}

		w.WriteHeader(200)
		w.Write([]byte("{}"))
	})

	go log.Fatal(http.ListenAndServe(*listenAddr, nil))
	cmd.CatchSignals(nil, nil)
}
