package main

// https://www.unbound.net/documentation/libunbound-tutorial-6.html

import (
	"fmt"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/unbound"
	"log"
)

func main() {
	u := unbound.New()
	defer u.Destroy()

	if err := u.ResolvConf("/etc/resolv.conf"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}

	if err := u.Hosts("/etc/hosts"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}

	if err := u.AddTaFile("keys"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}

	r, err := u.Resolve("nlnetlabs.nl.", dns.TypeA, dns.ClassINET)
	if err != nil {
		log.Fatalf("error %s\n", err.Error())
	}

	// show first result
	if r.HaveData {
		fmt.Printf("The address is %v\n", r.Data[0])
		// show security status
		if r.Secure {
			fmt.Printf("Result is secure\n")
		} else if r.Bogus {
			fmt.Printf("Result is bogus: %s\n", r.WhyBogus)
		} else {
			fmt.Printf("Result is insecure\n")
		}
	}
}
