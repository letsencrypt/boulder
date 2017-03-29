package main

import (
	"flag"
	"log"
	"os"

	"github.com/letsencrypt/boulder/test/ocsp/helper"
)

func main() {
	flag.Parse()
	var errors bool
	for _, f := range flag.Args() {
		_, err := helper.Req(f)
		if err != nil {
			log.Printf("error for %s: %s\n", f, err)
			errors = true
		}
	}
	if errors {
		os.Exit(1)
	}
}
