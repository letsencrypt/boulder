package ctpolicy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/ctpolicy/loglist"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/prometheus/client_golang/prometheus"
)

// CTPolicy is used to hold information about SCTs required from various
// groupings
type CTPolicy struct {
	pub       pubpb.PublisherClient
	sctLogs   loglist.List
	infoLogs  loglist.List
	finalLogs loglist.List
	stagger   time.Duration

	log           blog.Logger
	winnerCounter *prometheus.CounterVec
}

// New creates a new CTPolicy struct
func New(
	pub pubpb.PublisherClient,
	sctLogs loglist.List,
	infoLogs loglist.List,
	finalLogs loglist.List,
	stagger time.Duration,
	log blog.Logger,
	stats prometheus.Registerer,
) *CTPolicy {
	winnerCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sct_race_winner",
			Help: "Counter of logs that win SCT submission races.",
		},
		[]string{"log", "group"},
	)
	stats.MustRegister(winnerCounter)

	return &CTPolicy{
		pub:           pub,
		sctLogs:       sctLogs,
		infoLogs:      infoLogs,
		finalLogs:     finalLogs,
		stagger:       stagger,
		log:           log,
		winnerCounter: winnerCounter,
	}
}

// GetSCTs retrieves exactly two SCTs from the total collection of
// configured log groups, with at most one SCT coming from each group. It
// expects that all logs run by a single operator (e.g. Google) are in the same
// group, to guarantee that SCTs from logs in different groups do not end up
// coming from the same operator. As such, it enforces Google's current CT
// Policy, which requires that certs have two SCTs from logs run by different
// operators.
func (ctp *CTPolicy) GetSCTs(ctx context.Context, cert core.CertDER, expiration time.Time) (core.SCTDERs, error) {
	// We'll cancel this sub-context when we have the two SCTs we need, to cause
	// any other ongoing submission attempts to quit.
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		sct []byte
		op  string
		log string
		err error
	}

	// This closure will be called in parallel once for each operator group.
	getOne := func(i int, op string) result {
		res := result{op: op}

		// Sleep a little bit to stagger our requests to the later groups. Use `i-1`
		// to compute the stagger duration so that the first two groups (indices 0
		// and 1) get negative or zero (i.e. instant) sleep durations. If the
		// context gets cancelled (most likely because two logs from other operator
		// groups returned SCTs already) before the sleep is complete, quit instead.
		select {
		case <-subCtx.Done():
			res.err = subCtx.Err()
			return res
		case <-time.After(time.Duration(i-1) * ctp.stagger):
		}

		// Pick a random log from among those in the group. In practice, very few
		// operator groups have more than one log, so this loses little flexibility.
		l, err := ctp.sctLogs.PickOne(op, expiration)
		if err != nil {
			res.err = fmt.Errorf("unable to get log info: %w", err)
			return res
		}

		res.log = l.Url

		sct, err := ctp.pub.SubmitToSingleCTWithResult(ctx, &pubpb.Request{
			LogURL:       l.Url,
			LogPublicKey: l.Key,
			Der:          cert,
			Precert:      true,
		})
		if err != nil {
			res.err = fmt.Errorf("ct submission to %q (%q) failed: %w", op, l.Url, err)
			return res
		}

		res.sct = sct.Sct
		return res
	}

	// Ensure that this channel has a buffer equal to the number of goroutines
	// we're kicking off, so that they're all guaranteed to be able to write to
	// it and exit without blocking and leaking.
	results := make(chan result, len(ctp.sctLogs))

	// Kick off a collection of goroutines to try to submit the precert to each
	// log operator group. Randomize the order of the groups so that we're not
	// always trying to submit to the same two operators.
	for i, op := range ctp.sctLogs.Permute() {
		go func(i int, op string) {
			results <- getOne(i, op)
		}(i, op)
	}

	go ctp.submitPrecertInformational(cert, expiration)

	// Finally, collect SCTs and/or errors from our results channel.
	scts := make(core.SCTDERs, 0)
	errs := make([]string, 0)
	for i := 0; i < len(ctp.sctLogs); i++ {
		select {
		case <-ctx.Done():
			// We timed out (the calling function returned and canceled our context)
			// before getting two SCTs.
			ctp.winnerCounter.With(prometheus.Labels{"group": "timeout", "log": "timeout"}).Inc()
			return nil, berrors.MissingSCTsError("failed to get 2 SCTs before ctx finished: %s", ctx.Err())
		case res := <-results:
			if res.err != nil {
				errs = append(errs, res.err.Error())
				continue
			}
			scts = append(scts, res.sct)
			ctp.winnerCounter.With(prometheus.Labels{"group": res.op, "log": res.log}).Inc()
			if len(scts) >= 2 {
				return scts, nil
			}
		}
	}

	// If we made it to the end of that loop, that means we never got two SCTs
	// to return. Error out instead.
	ctp.winnerCounter.With(prometheus.Labels{"group": "all_failed", "log": "all_failed"}).Inc()
	if len(errs) == 0 {
		errs = []string{"no CT logs configured"}
	}
	return nil, berrors.MissingSCTsError("failed to get 2 SCTs, got error(s): %s", strings.Join(errs, "; "))
}

// submitPrecertInformational submits precertificates to any configured
// "informational" logs, but does not care about success or returned SCTs.
func (ctp *CTPolicy) submitPrecertInformational(cert core.CertDER, expiration time.Time) {
	ctp.submitAllBestEffort(cert, true, expiration)
}

// SubmitFinalCert submits finalized certificates created from precertificates
// to any configured "final" logs, but does not care about success.
func (ctp *CTPolicy) SubmitFinalCert(cert core.CertDER, expiration time.Time) {
	ctp.submitAllBestEffort(cert, false, expiration)
}

// submitAllBestEffort submits the given certificate or precertificate to every
// log ("informational" for precerts, "final" for certs) configured in the policy.
// It neither waits for these submission to complete, nor tracks their success.
func (ctp *CTPolicy) submitAllBestEffort(blob core.CertDER, precert bool, expiry time.Time) {
	logs := ctp.finalLogs
	if precert {
		logs = ctp.infoLogs
	}

	for _, group := range logs {
		for _, log := range group {
			if log.StartInclusive.After(expiry) || log.EndExclusive.Equal(expiry) || log.EndExclusive.Before(expiry) {
				continue
			}

			go func(log loglist.Log) {
				_, err := ctp.pub.SubmitToSingleCTWithResult(
					context.Background(),
					&pubpb.Request{
						LogURL:       log.Url,
						LogPublicKey: log.Key,
						Der:          blob,
						Precert:      precert,
					},
				)
				if err != nil {
					ctp.log.Warningf("ct submission of cert to log %q failed: %s", log.Url, err)
				}
			}(log)
		}
	}

}
