package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/jmhodges/clock"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	grpcCodes "google.golang.org/grpc/codes"
	"gopkg.in/yaml.v2"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	pb "github.com/letsencrypt/boulder/cmd/caa-checker/proto"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
)

type caaCheckerServer struct {
	resolver bdns.DNSResolver
	stats    metrics.Scope
}

// caaSet consists of filtered CAA records
type caaSet struct {
	Issue     []*dns.CAA
	Issuewild []*dns.CAA
	Iodef     []*dns.CAA
	Unknown   []*dns.CAA
}

// returns true if any CAA records have unknown tag properties and are flagged critical.
func (caaSet caaSet) criticalUnknown() bool {
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
func newCAASet(CAAs []*dns.CAA) *caaSet {
	var filtered caaSet

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

func (ccs *caaCheckerServer) getCAASet(ctx context.Context, hostname string) (*caaSet, error) {
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
			r.records, r.err = ccs.resolver.LookupCAA(ctx, name)
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

func (ccs *caaCheckerServer) checkCAA(ctx context.Context, hostname string, issuer string) (present, valid bool, err error) {
	hostname = strings.ToLower(hostname)
	caaSet, err := ccs.getCAASet(ctx, hostname)
	if err != nil {
		return false, false, err
	}

	if caaSet == nil {
		// No CAA records found, can issue
		return false, true, nil
	}

	if caaSet.criticalUnknown() {
		// Contains unknown critical directives.
		ccs.stats.Inc("CCS.UnknownCritical", 1)
		return true, false, nil
	}

	if len(caaSet.Unknown) > 0 {
		ccs.stats.Inc("CCS.WithUnknownNoncritical", 1)
	}

	if len(caaSet.Issue) == 0 {
		// Although CAA records exist, none of them pertain to issuance in this case.
		// (e.g. there is only an issuewild directive, but we are checking for a
		// non-wildcard identifier, or there is only an iodef or non-critical unknown
		// directive.)
		ccs.stats.Inc("CCS.CAA.NoneRelevant", 1)
		return true, true, nil
	}

	// There are CAA records pertaining to issuance in our case. Note that this
	// includes the case of the unsatisfiable CAA record value ";", used to
	// prevent issuance by any CA under any circumstance.
	//
	// Our CAA identity must be found in the chosen checkSet.
	for _, caa := range caaSet.Issue {
		if extractIssuerDomain(caa) == issuer {
			ccs.stats.Inc("CCS.CAA.Authorized", 1)
			return true, true, nil
		}
	}

	// The list of authorized issuers is non-empty, but we are not in it. Fail.
	ccs.stats.Inc("CCS.CAA.Unauthorized", 1)
	return true, false, nil
}

func (ccs *caaCheckerServer) ValidForIssuance(ctx context.Context, check *pb.Check) (*pb.Result, error) {
	if check.Name == nil || check.IssuerDomain == nil {
		return nil, bgrpc.CodedError(grpcCodes.InvalidArgument, "Both name and issuerDomain are required")
	}
	present, valid, err := ccs.checkCAA(ctx, *check.Name, *check.IssuerDomain)
	if err != nil {
		if err == context.DeadlineExceeded || err == context.Canceled {
			return nil, bgrpc.CodedError(bgrpc.DNSQueryTimeout, err.Error())
		}
		if dnsErr, ok := err.(*bdns.DNSError); ok {
			if dnsErr.Timeout() {
				return nil, bgrpc.CodedError(bgrpc.DNSQueryTimeout, err.Error())
			}
			return nil, bgrpc.CodedError(bgrpc.DNSError, dnsErr.Error())
		}
		return nil, bgrpc.CodedError(bgrpc.DNSError, "server failure at resolver")
	}
	return &pb.Result{Present: &present, Valid: &valid}, nil
}

type config struct {
	GRPC   cmd.GRPCServerConfig
	Statsd cmd.StatsdConfig
	Syslog cmd.SyslogConfig

	DebugAddr             string             `yaml:"debug-addr"`
	DNSResolver           string             `yaml:"dns-resolver"`
	DNSNetwork            string             `yaml:"dns-network"`
	DNSTimeout            cmd.ConfigDuration `yaml:"dns-timeout"`
	CAASERVFAILExceptions string             `yaml:"caa-servfail-exceptions"`
}

func main() {
	configPath := flag.String("config", "config.yml", "Path to configuration file")
	flag.Parse()

	configBytes, err := ioutil.ReadFile(*configPath)
	cmd.FailOnError(err, fmt.Sprintf("Failed to read configuration file from '%s'", *configPath))
	var c config
	err = yaml.Unmarshal(configBytes, &c)
	cmd.FailOnError(err, fmt.Sprintf("Failed to parse configuration file from '%s'", *configPath))

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	scope := metrics.NewStatsdScope(stats, "CAAService")
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString("CAA-Checker"))

	caaSERVFAILExceptions, err := bdns.ReadHostList(c.CAASERVFAILExceptions)
	cmd.FailOnError(err, "Couldn't read CAASERVFAILExceptions file")

	resolver := bdns.NewDNSResolverImpl(
		c.DNSTimeout.Duration,
		[]string{c.DNSResolver},
		caaSERVFAILExceptions,
		scope,
		clock.Default(),
		5,
	)

	s, l, err := bgrpc.NewServer(&c.GRPC, scope)
	cmd.FailOnError(err, "Failed to setup gRPC server")
	ccs := &caaCheckerServer{resolver, scope}
	pb.RegisterCAACheckerServer(s, ccs)

	go cmd.CatchSignals(logger, s.GracefulStop)
	go cmd.DebugServer(c.DebugAddr)

	err = s.Serve(l)
	cmd.FailOnError(err, "gRPC service failed")
}
