package main

// https://www.unbound.net/documentation/libunbound-tutorial-2.html

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
	r, err := u.Resolve("www.nlnetlabs.nl.", dns.TypeA, dns.ClassINET)
	if err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	fmt.Printf("%+v\n", r)
}
