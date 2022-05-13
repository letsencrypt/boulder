package ctpolicy

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/canceled"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/ctpolicy/ctconfig"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
)

// CTPolicy is used to hold information about SCTs required from various
// groupings
type CTPolicy struct {
	pub           pubpb.PublisherClient
	groups        []ctconfig.CTGroup
	informational []ctconfig.LogDescription
	finalLogs     []ctconfig.LogDescription
	log           blog.Logger

	winnerCounter *prometheus.CounterVec
}

// New creates a new CTPolicy struct
func New(pub pubpb.PublisherClient,
	groups []ctconfig.CTGroup,
	informational []ctconfig.LogDescription,
	log blog.Logger,
	stats prometheus.Registerer,
) *CTPolicy {
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
		pub:           pub,
		groups:        groups,
		informational: informational,
		finalLogs:     finalLogs,
		log:           log,
		winnerCounter: winnerCounter,
	}
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

// GetSCTs attempts to retrieve a SCT from each configured grouping of logs and returns
// the set of SCTs to the caller.
func (ctp *CTPolicy) GetSCTs(ctx context.Context, cert core.CertDER, expiration time.Time) (core.SCTDERs, error) {
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
	isPrecert := true
	for _, log := range ctp.informational {
		go func(l ctconfig.LogDescription) {
			// We use a context.Background() here instead of subCtx because these
			// submissions are running in a goroutine and we don't want them to be
			// cancelled when the caller of CTPolicy.GetSCTs returns and cancels
			// its RPC context.
			uri, key, err := l.Info(expiration)
			if err != nil {
				ctp.log.Errf("unable to get log info: %s", err)
				return
			}
			_, err = ctp.pub.SubmitToSingleCTWithResult(context.Background(), &pubpb.Request{
				LogURL:       uri,
				LogPublicKey: key,
				Der:          cert,
				Precert:      isPrecert,
			})
			if err != nil {
				ctp.log.Warningf("ct submission to informational log %q failed: %s", uri, err)
			}
		}(log)
	}

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
