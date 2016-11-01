package grpc

import (
	"errors"
	"fmt"
	"strings"

	"github.com/letsencrypt/boulder/metrics"

	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func cleanMethod(m string, trimService bool) string {
	m = strings.TrimLeft(m, "-")
	if trimService {
		s := strings.Split(m, "-")
		if len(s) == 1 {
			return m
		}
		return s[len(s)-1]
	}
	return strings.Replace(m, "-", "_", -1)
}

/*
 * serverWhiteListInterceptor implements the UnaryServerInterceptor interface to
 * validate a peer's TLS client certificate's subject common name against
 * a whitelist. Peers without a valid certificate with the correct name are
 * rejected. The whitelist interceptor allows chaining one additional "next"
 * interceptor to be called after the whitelist processing.
 */
type serverWhitelistInterceptor struct {
	stats     metrics.Scope
	whitelist map[string]struct{}
	next      grpc.UnaryServerInterceptor
}

func (si *serverWhitelistInterceptor) intercept(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {
	var ok bool

	if info == nil {
		si.stats.Inc("NoInfo", 1)
		return nil, errors.New("passed nil *grpc.UnaryServerInfo")
	}

	// First we need to find the Peer for this context
	var p *peer.Peer
	if p, ok = peer.FromContext(ctx); !ok {
		si.stats.Inc("NoPeer", 1)
		return nil, errors.New("passed context without *grpc.Peer")
	}

	// Next we need to make sure that the peer's auth info is a TLS auth info.
	var tlsInfo credentials.TLSInfo
	if tlsInfo, ok = p.AuthInfo.(credentials.TLSInfo); !ok {
		si.stats.Inc("NoPeerTLSInfo", 1)
		return nil, errors.New("peer did not have credentials.TLSInfo as AuthInfo")
	}

	// The peer must have at least one verified chain built from its
	// PeerCertificates.
	chains := tlsInfo.State.VerifiedChains
	if len(chains) < 1 {
		si.stats.Inc("NoPeerVerifiedChains", 1)
		return nil, errors.New("peer tlsInfo.State had zero VerifiedChains")
	}

	/*
	 * For each of the peer's verified chains we can look at the chain's leaf
	 * certificate and check whether the subject common name is in the whitelist.
	 * At least one chain must have a leaf certificate with a subject CN that
	 * matches the whitelist
	 *
	 * Its important we process `VerifiedChains` instead of processing
	 * PeerCertificates to ensure that we match the subject CN of the
	 * leaf certificate that the upper layers of the gRPC credentials code
	 * verified. To do otherwise would allow an attacker to include a whitelisted
	 * certificate in PeerCertificates that matched the whitelist but wasn't used
	 * in the chain the server validated.
	 */
	var whitelisted bool
	for _, chain := range chains {
		leafSubjectCN := chain[0].Subject.CommonName
		if _, ok = si.whitelist[leafSubjectCN]; ok {
			whitelisted = true
		}
	}

	// If none of the chains had a leaf certificate that matched the whitelist, we
	// reject the peer
	if !whitelisted {
		si.stats.Inc("PeerRejectedByWhitelist", 1)
		return nil, fmt.Errorf(
			"peer's verified TLS chains did not include a leaf certificate with whitelisted subject CN")
	}

	// If there is a next UnaryServerInterceptor, invoke it and return
	// This is a little bit clunky - in the future we may want to replace this
	// with a general chaining mechanism ala go-grpc-middleware
	if si.next != nil {
		return si.next(ctx, req, info, handler)
	} else {
		// Otherwise, invoke the handler and return
		return handler(ctx, req)
	}
}

type serverStatsInterceptor struct {
	stats metrics.Scope
	clk   clock.Clock
}

func (si *serverStatsInterceptor) intercept(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {
	if info == nil {
		si.stats.Inc("NoInfo", 1)
		return nil, errors.New("passed nil *grpc.UnaryServerInfo")
	}

	s := si.clk.Now()
	methodScope := si.stats.NewScope(cleanMethod(info.FullMethod, true))
	methodScope.Inc("Calls", 1)
	methodScope.GaugeDelta("InProgress", 1)
	resp, err := handler(ctx, req)
	methodScope.TimingDuration("Latency", si.clk.Since(s))
	methodScope.GaugeDelta("InProgress", -1)
	if err != nil {
		methodScope.Inc("Failed", 1)
	}
	return resp, err
}

type clientStatsInterceptor struct {
	stats metrics.Scope
	clk   clock.Clock
}

// intercept fulfils the grpc.UnaryClientInterceptor interface, it should be noted that while this API
// is currently experimental the metrics it reports should be kept as stable as can be, *within reason*.
func (ci *clientStatsInterceptor) intercept(
	ctx context.Context,
	method string,
	req, reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption) error {
	s := ci.clk.Now()
	methodScope := ci.stats.NewScope(cleanMethod(method, false))
	methodScope.Inc("Calls", 1)
	methodScope.GaugeDelta("InProgress", 1)
	err := invoker(ctx, method, req, reply, cc, opts...)
	methodScope.TimingDuration("Latency", ci.clk.Since(s))
	methodScope.GaugeDelta("InProgress", -1)
	if err != nil {
		methodScope.Inc("Failed", 1)
	}
	return err
}
