package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/letsencrypt/boulder/issuance"
)

func usage() {
	fmt.Printf("Usage: %s [OPTIONS] [ISSUER CERTIFICATE(S)]\n", os.Args[0])
}

func main() {
	var shorthandFlag = flag.Bool("s", false, "Display only the nameid for each given certificate")
	flag.Parse()

	if len(os.Args) <= 1 {
		usage()
		os.Exit(1)
	}

	for _, certFile := range flag.Args() {
		issuer, err := issuance.LoadCertificate(certFile)
		if err != nil {
			if *shorthandFlag {
				fmt.Println(err)
			} else {
				fmt.Printf("%s\t- %v", certFile, err)
			}
			os.Exit(1)
		}

		if *shorthandFlag {
			fmt.Printf("%d\n", issuer.NameID())
		} else {
			fmt.Printf("%s\t- %d\n", certFile, issuer.NameID())
		}
	}
}
