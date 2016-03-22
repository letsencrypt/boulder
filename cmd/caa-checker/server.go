package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/metrics"
	pb "github.com/rolandshoemaker/caa-thing/proto"
)

type caaCheckerServer struct {
	issuer   string
	resolver bdns.DNSResolver
}

// CAASet consists of filtered CAA records
type CAASet struct {
	Issue     []*dns.CAA
	Issuewild []*dns.CAA
	Iodef     []*dns.CAA
	Unknown   []*dns.CAA
}

// returns true if any CAA records have unknown tag properties and are flagged critical.
func (caaSet CAASet) criticalUnknown() bool {
	if len(caaSet.Unknown) > 0 {
		for _, caaRecord := range caaSet.Unknown {
			// The critical flag is the bit with significance 128. However, many CAA
			// record users have misinterpreted the RFC and concluded that the bit
			// with significance 1 is the critical bit. This is sufficiently
			// widespread that that bit must reasonably be considered an alias for
			// the critical bit. The remaining bits are 0/ignore as proscribed by the
			// RFC.
			if (caaRecord.Flag & (128 | 1)) != 0 {
				return true
			}
		}
	}

	return false
}

// Filter CAA records by property
func newCAASet(CAAs []*dns.CAA) *CAASet {
	var filtered CAASet

	for _, caaRecord := range CAAs {
		switch caaRecord.Tag {
		case "issue":
			filtered.Issue = append(filtered.Issue, caaRecord)
		case "issuewild":
			filtered.Issuewild = append(filtered.Issuewild, caaRecord)
		case "iodef":
			filtered.Iodef = append(filtered.Iodef, caaRecord)
		default:
			filtered.Unknown = append(filtered.Unknown, caaRecord)
		}
	}

	return &filtered
}

func (ccs *caaCheckerServer) getCAASet(ctx context.Context, hostname string) (*CAASet, error) {
	hostname = strings.TrimRight(hostname, ".")
	labels := strings.Split(hostname, ".")

	// See RFC 6844 "Certification Authority Processing" for pseudocode.
	// Essentially: check CAA records for the FDQN to be issued, and all
	// parent domains.
	//
	// The lookups are performed in parallel in order to avoid timing out
	// the RPC call.
	//
	// We depend on our resolver to snap CNAME and DNAME records.

	type result struct {
		records []*dns.CAA
		err     error
	}
	results := make([]result, len(labels))

	var wg sync.WaitGroup

	for i := 0; i < len(labels); i++ {
		// Start the concurrent DNS lookup.
		wg.Add(1)
		go func(name string, r *result) {
			r.records, r.err = ccs.resolver.LookupCAA(ctx, hostname)
			wg.Done()
		}(strings.Join(labels[i:], "."), &results[i])
	}

	wg.Wait()

	// Return the first result
	for _, res := range results {
		if res.err != nil {
			return nil, res.err
		}
		if len(res.records) > 0 {
			return newCAASet(res.records), nil
		}
	}

	// no CAA records found
	return nil, nil
}

// Given a CAA record, assume that the Value is in the issue/issuewild format,
// that is, a domain name with zero or more additional key-value parameters.
// Returns the domain name, which may be "" (unsatisfiable).
func extractIssuerDomain(caa *dns.CAA) string {
	v := caa.Value
	v = strings.Trim(v, " \t") // Value can start and end with whitespace.
	idx := strings.IndexByte(v, ';')
	if idx < 0 {
		return v // no parameters; domain only
	}

	// Currently, ignore parameters. Unfortunately, the RFC makes no statement on
	// whether any parameters are critical. Treat unknown parameters as
	// non-critical.
	return strings.Trim(v[0:idx], " \t")
}

func (ccs *caaCheckerServer) checkCAA(ctx context.Context, hostname string) (bool, error) {
	hostname = strings.ToLower(hostname)
	caaSet, err := ccs.getCAASet(ctx, hostname)
	if err != nil {
		return false, err
	}

	if caaSet == nil {
		// No CAA records found, can issue
		return true, nil
	}

	if caaSet.criticalUnknown() {
		// Contains unknown critical directives.
		return false, nil
	}

	if len(caaSet.Issue) == 0 {
		// Although CAA records exist, none of them pertain to issuance in this case.
		// (e.g. there is only an issuewild directive, but we are checking for a
		// non-wildcard identifier, or there is only an iodef or non-critical unknown
		// directive.)
		return true, nil
	}

	// There are CAA records pertaining to issuance in our case. Note that this
	// includes the case of the unsatisfiable CAA record value ";", used to
	// prevent issuance by any CA under any circumstance.
	//
	// Our CAA identity must be found in the chosen checkSet.
	for _, caa := range caaSet.Issue {
		if extractIssuerDomain(caa) == ccs.issuer {
			return true, nil
		}
	}

	// The list of authorized issuers is non-empty, but we are not in it. Fail.
	return false, nil
}

func (ccs *caaCheckerServer) ValidForIssuance(ctx context.Context, domain *pb.Domain) (*pb.Valid, error) {
	valid, err := ccs.checkCAA(ctx, domain.Name)
	if err != nil {
		return nil, err
	}
	return &pb.Valid{valid}, nil
}

func main() {
	l, err := net.Listen("tcp", ":2020")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen on ':2020': %s\n", err)
		os.Exit(1)
	}
	s := grpc.NewServer()
	resolver := bdns.NewDNSResolverImpl(time.Second, []string{"8.8.8.8:53"}, metrics.NewNoopScope(), clock.Default(), 5)
	ccs := &caaCheckerServer{"letsencrypt.org", resolver}
	pb.RegisterCAACheckerServer(s, ccs)
	err = s.Serve(l)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gRPC server failed: %s\n", err)
		os.Exit(1)
	}
}
