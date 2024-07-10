package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/letsencrypt/boulder/issuance"
)

func usage() {
	fmt.Printf("Usage: %s [OPTIONS] cert1.pem certN.pem certN+1.pem\n", os.Args[0])
}

func main() {
	var shorthandFlag = flag.Bool("s", false, "Display only the nameid for each given certificate")
	flag.Parse()

	if len(os.Args) <= 1 {
		usage()
		os.Exit(1)
	}

	for _, cert := range flag.Args() {
		issuer, err := issuance.LoadCertificate(cert)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if *shorthandFlag {
			fmt.Printf("%d\n", issuer.NameID())
		} else {
			fmt.Printf("%s\t- %d\n", cert, issuer.NameID())
		}
	}
}
