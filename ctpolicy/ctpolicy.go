package ctpolicy

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/canceled"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/ctpolicy/ctconfig"
	"github.com/letsencrypt/boulder/ctpolicy/loglist"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/prometheus/client_golang/prometheus"
)

// CTPolicy is used to hold information about SCTs required from various
// groupings
type CTPolicy struct {
	pub pubpb.PublisherClient
	// TODO(#5938): Fully replace `groups` with `operatorGroups`.
	groups         []ctconfig.CTGroup
	operatorGroups loglist.LogList
	informational  []ctconfig.LogDescription
	finalLogs      []ctconfig.LogDescription
	stagger        time.Duration
	log            blog.Logger

	winnerCounter *prometheus.CounterVec
}

// New creates a new CTPolicy struct
func New(
	pub pubpb.PublisherClient,
	groups []ctconfig.CTGroup,
	operatorGroups loglist.LogList,
	informational []ctconfig.LogDescription,
	stagger time.Duration,
	log blog.Logger,
	stats prometheus.Registerer,
) (*CTPolicy, error) {
	var finalLogs []ctconfig.LogDescription
	for _, group := range groups {
		for _, log := range group.Logs {
			if log.SubmitFinalCert {
				finalLogs = append(finalLogs, log)
			}
		}
	}
	for _, log := range informational {
		if log.SubmitFinalCert {
			finalLogs = append(finalLogs, log)
		}
	}

	winnerCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sct_race_winner",
			Help: "Counter of logs that win SCT submission races.",
		},
		[]string{"log", "group"},
	)
	stats.MustRegister(winnerCounter)

	return &CTPolicy{
		pub:            pub,
		groups:         groups,
		operatorGroups: operatorGroups,
		stagger:        stagger,
		informational:  informational,
		finalLogs:      finalLogs,
		log:            log,
		winnerCounter:  winnerCounter,
	}, nil
}

type result struct {
	sct []byte
	log string
	err error
}

// race submits an SCT to each log in a group and waits for the first response back,
// once it has the first SCT it cancels all of the other submissions and returns.
// It allows up to len(group)-1 of the submissions to fail as we only care about
// getting a single SCT.
// TODO(#5938): Remove this when it becomes dead code.
func (ctp *CTPolicy) race(ctx context.Context, cert core.CertDER, group ctconfig.CTGroup, expiration time.Time) ([]byte, error) {
	results := make(chan result, len(group.Logs))
	isPrecert := true
	// Randomize the order in which we send requests to the logs in a group
	// so we maximize the distribution of logs we get SCTs from.
	for i, logNum := range rand.Perm(len(group.Logs)) {
		ld := group.Logs[logNum]
		go func(i int, ld ctconfig.LogDescription) {
			// Each submission waits a bit longer than the previous one, to give the
			// previous log a chance to reply. If the context is already done by the
			// time we get here, don't bother submitting. That generally means the
			// context was canceled because another log returned a success already.
			time.Sleep(time.Duration(i) * group.Stagger.Duration)
			if ctx.Err() != nil {
				return
			}
			uri, key, err := ld.Info(expiration)
			if err != nil {
				ctp.log.Errf("unable to get log info: %s", err)
				return
			}
			sct, err := ctp.pub.SubmitToSingleCTWithResult(ctx, &pubpb.Request{
				LogURL:       uri,
				LogPublicKey: key,
				Der:          cert,
				Precert:      isPrecert,
			})
			if err != nil {
				// Only log the error if it is not a result of the context being canceled
				if !canceled.Is(err) {
					ctp.log.Warningf("ct submission to %q failed: %s", uri, err)
				}
				results <- result{err: err}
				return
			}
			results <- result{sct: sct.Sct, log: uri}
		}(i, ld)
	}

	for i := 0; i < len(group.Logs); i++ {
		select {
		case <-ctx.Done():
			ctp.winnerCounter.With(prometheus.Labels{"log": "timeout", "group": group.Name}).Inc()
			return nil, ctx.Err()
		case res := <-results:
			if res.sct != nil {
				ctp.winnerCounter.With(prometheus.Labels{"log": res.log, "group": group.Name}).Inc()
				// Return the very first SCT we get back. Returning triggers
				// the defer'd context cancellation method.
				return res.sct, nil
			}
			// We will continue waiting for an SCT until we've seen the same number
			// of errors as there are logs in the group as we may still get a SCT
			// back from another log.
		}
	}
	ctp.winnerCounter.With(prometheus.Labels{"log": "all_failed", "group": group.Name}).Inc()
	return nil, errors.New("all submissions failed")
}

// GetSCTs attempts to retrieve two SCTs from the configured log groups and
// returns the set of SCTs to the caller.
func (ctp *CTPolicy) GetSCTs(ctx context.Context, cert core.CertDER, expiration time.Time) (core.SCTDERs, error) {
	if len(ctp.operatorGroups) != 0 {
		return ctp.getOperatorSCTs(ctx, cert, expiration)
	}
	return ctp.getGoogleSCTs(ctx, cert, expiration)
}

// getGoogleSCTs retrieves exactly one SCT from each of the configured log
// groups. It expects that there are exactly 2 such groups, and that one of
// those groups contains only logs operated by Google. As such, it enforces
// Google's *old* CT Policy, which required that certs have two SCTs, one of
// which was from a Google log.
// DEPRECATED: Google no longer enforces the "one Google, one non-Google" log
// policy. Use getOperatorSCTs instead.
// TODO(#5938): Remove this after the configured groups have been rearranged.
func (ctp *CTPolicy) getGoogleSCTs(ctx context.Context, cert core.CertDER, expiration time.Time) (core.SCTDERs, error) {
	results := make(chan result, len(ctp.groups))
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i, g := range ctp.groups {
		go func(i int, g ctconfig.CTGroup) {
			sct, err := ctp.race(subCtx, cert, g, expiration)
			// Only one of these will be non-nil
			if err != nil {
				results <- result{err: berrors.MissingSCTsError("CT log group %q: %s", g.Name, err)}
			}
			results <- result{sct: sct}
		}(i, g)
	}

	go ctp.submitPrecertInformational(cert, expiration)

	var ret core.SCTDERs
	for i := 0; i < len(ctp.groups); i++ {
		res := <-results
		// If any one group fails to get a SCT then we fail out immediately
		// cancel any other in progress work as we can't continue
		if res.err != nil {
			// Returning triggers the defer'd context cancellation method
			return nil, res.err
		}
		ret = append(ret, res.sct)
	}
	return ret, nil
}

// getOperatorSCTs retrieves exactly two SCTs from the total collection of
// configured log groups, with at most one SCT coming from each group. It
// expects that all logs run by a single operator (e.g. Google) are in the same
// group, to guarantee that SCTs from logs in different groups do not end up
// coming from the same operator. As such, it enforces Google's current CT
// Policy, which requires that certs have two SCTs from logs run by different
// operators.
// TODO(#5938): Inline this into GetSCTs when getGoogleSCTs is removed.
func (ctp *CTPolicy) getOperatorSCTs(ctx context.Context, cert core.CertDER, expiration time.Time) (core.SCTDERs, error) {
	// We'll cancel this sub-context when we have the two SCTs we need, to cause
	// any other ongoing submission attempts to quit.
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan result, len(ctp.operatorGroups))

	// This closure will be called in parallel once for each operator group.
	getOne := func(i int, g string) {
		// If this goroutine isn't for one of the first two groups chosen, sleep a
		// little bit to stagger our requests to the later groups.
		if i > 1 {
			time.Sleep(time.Duration(i) * ctp.stagger)
		}

		// Quit if the context has errored out, most likely because two other
		// logs from other operator groups returned SCTs already and the context
		// has been canceled.
		if subCtx.Err() != nil {
			return
		}

		// Pick a random log from among those in the group. In practice, very few
		// operator groups have more than one log, so this loses little flexibility.
		uri, key, err := ctp.operatorGroups.PickOne(g, expiration)
		if err != nil {
			ctp.log.Errf("unable to get log info: %s", err)
			return
		}

		sct, err := ctp.pub.SubmitToSingleCTWithResult(ctx, &pubpb.Request{
			LogURL:       uri,
			LogPublicKey: key,
			Der:          cert,
			Precert:      true,
		})
		if err != nil {
			// Only log the error if it is not a result of the context being canceled
			if !canceled.Is(err) {
				ctp.log.Warningf("ct submission to %q (%q) failed: %s", g, uri, err)
			}

			results <- result{err: err}
			return
		}

		results <- result{sct: sct.Sct}
	}

	// Kick off a collection of goroutines to try to submit the precert to each
	// log operator group. Randomize the order of the groups so that we're not
	// always trying to submit to the same two operators.
	for i, group := range ctp.operatorGroups.Permute() {
		go getOne(i, group)
	}

	go ctp.submitPrecertInformational(cert, expiration)

	// Finally, collect SCTs and/or errors from our results channel.
	scts := make(core.SCTDERs, 0)
	errs := make([]string, 0)
	for i := 0; i < len(ctp.operatorGroups); i++ {
		select {
		case <-ctx.Done():
			// We timed out (the calling function returned and canceled our context)
			// before getting two SCTs.
			return nil, berrors.MissingSCTsError("failed to get 2 SCTs before ctx finished: %s", ctx.Err())
		case res := <-results:
			if res.err != nil {
				errs = append(errs, res.err.Error())
				continue
			}
			scts = append(scts, res.sct)
			if len(scts) >= 2 {
				return scts, nil
			}
		}
	}

	// If we made it to the end of that loop, that means we never got two SCTs
	// to return. Error out instead.
	return nil, berrors.MissingSCTsError("failed to get 2 SCTs, got error(s): %s", strings.Join(errs, "; "))
}

func (ctp *CTPolicy) submitPrecertInformational(cert core.CertDER, expiration time.Time) {
	for _, log := range ctp.informational {
		go func(l ctconfig.LogDescription) {
			// We use a context.Background() here instead of a context from the parent
			// because these submissions are running in a goroutine and we don't want
			// them to be cancelled when the caller of CTPolicy.GetSCTs returns and
			// cancels its RPC context.
			uri, key, err := l.Info(expiration)
			if err != nil {
				ctp.log.Errf("unable to get log info: %s", err)
				return
			}
			_, err = ctp.pub.SubmitToSingleCTWithResult(context.Background(), &pubpb.Request{
				LogURL:       uri,
				LogPublicKey: key,
				Der:          cert,
				Precert:      true,
			})
			if err != nil {
				ctp.log.Warningf("ct submission to informational log %q failed: %s", uri, err)
			}
		}(log)
	}
}

// SubmitFinalCert submits finalized certificates created from precertificates
// to any configured logs
func (ctp *CTPolicy) SubmitFinalCert(cert []byte, expiration time.Time) {
	for _, log := range ctp.finalLogs {
		go func(l ctconfig.LogDescription) {
			uri, key, err := l.Info(expiration)
			if err != nil {
				ctp.log.Errf("unable to get log info: %s", err)
				return
			}
			_, err = ctp.pub.SubmitToSingleCTWithResult(context.Background(), &pubpb.Request{
				LogURL:       uri,
				LogPublicKey: key,
				Der:          cert,
				Precert:      false,
			})
			if err != nil {
				ctp.log.Warningf("ct submission of final cert to log %q failed: %s", uri, err)
			}
		}(log)
	}
}
