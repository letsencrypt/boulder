package unbound

import (
	"fmt"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"runtime"
	"sync"
	"testing"
)

func ExampleLookupCNAME() {
	u := New()
	defer u.Destroy()
	if err := u.ResolvConf("/etc/resolv.conf"); err != nil {
		return
	}
	s, err := u.LookupCNAME("www.miek.nl.")
	// A en AAAA lookup get canoncal name
	if err != nil {
		return
	}
	fmt.Printf("%+v\n", s)
}

func ExampleLookupIP() {
	u := New()
	defer u.Destroy()
	if err := u.ResolvConf("/etc/resolv.conf"); err != nil {
		return
	}
	a, err := u.LookupIP("nlnetlabs.nl.")
	if err != nil {
		return
	}
	fmt.Printf("%+v\n", a)
}

func TestDotLess(t *testing.T) {
	u := New()
	defer u.Destroy()
	if err := u.ResolvConf("/etc/resolv.conf"); err != nil {
		return
	}
	a, err := u.LookupTXT("gmail.com")
	if err != nil {
		return
	}
	for _, r := range a {
		if len(r) == 0 {
			t.Log("Failure to get the TXT from gmail.com")
			t.Fail()
		}
	}
}

func TestUnicodeLookupHost(t *testing.T) {
	u := New()
	defer u.Destroy()
	if err := u.ResolvConf("/etc/resolv.conf"); err != nil {
		return
	}
	a, err := u.LookupHost("☁→❄→☃→☀→☺→☂→☹→✝.ws.")
	if err != nil {
		t.Logf("Failed to lookup host %s\n", err.Error())
		t.Fail()
	}
	if len(a) == 0 {
		t.Log("Failure to get the A for ☁→❄→☃→☀→☺→☂→☹→✝.ws.")
		t.Fail()
	}

	for _, r := range a {
		if len(r) == 0 {
			t.Log("Failure to get the A for ☁→❄→☃→☀→☺→☂→☹→✝.ws.")
			t.Fail()
			continue
		}
		t.Logf("Found %s\n", r)
	}
}

func TestUnicodeResolve(t *testing.T) {
	u := New()
	defer u.Destroy()
	if err := u.ResolvConf("/etc/resolv.conf"); err != nil {
		return
	}
	r, err := u.Resolve("☁→❄→☃→☀→☺→☂→☹→✝.ws.", dns.TypeA, dns.ClassINET)
	if err != nil {
		t.Log("Failure to get the A for ☁→❄→☃→☀→☺→☂→☹→✝.ws.")
		t.Fail()
	}
	if !r.HaveData {
		t.Log("Failure to get the A for ☁→❄→☃→☀→☺→☂→☹→✝.ws.")
		t.Fail()
	}
}

func TestStress(t *testing.T) {
	domains := []string{"www.google.com.", "www.isc.org.", "www.outlook.com.", "miek.nl.", "doesnotexist.miek.nl."}
	l := len(domains)
	max := 8
	procs := runtime.GOMAXPROCS(max)
	wg := new(sync.WaitGroup)
	wg.Add(max)
	u := New()
	defer u.Destroy()
	if err := u.ResolvConf("/etc/resolv.conf"); err != nil {
		return
	}
	for i := 0; i < max; i++ {
		go func() {
			for i := 0; i < 100; i++ {
				d := domains[int(dns.Id())%l]
				r, err := u.Resolve(d, dns.TypeA, dns.ClassINET)
				if err != nil {
					t.Log("failure to resolve: " + d)
					continue
				}
				if !r.HaveData && d != "doesnotexist.miek.nl." {
					t.Log("no data when resolving: " + d)
					continue
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()
	runtime.GOMAXPROCS(procs)
}
