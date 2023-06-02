package sa

import (
	"context"
	"os"
	"os/signal"
	"time"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// initDeepHealthCheck starts a goroutine that checks the health of the database
// connection at the specified interval. If the query fails, the service is
// marked unhealthy ('NOT_SERVING') in the health server. If the query succeeds,
// the service is marked as healthy ('SERVING'). If interval is 0 it defaults to
// 5 seconds. All other arguments are required.
func initDeepHealthCheck(service string, healthSrv *health.Server, dbMap *db.WrappedMap, interval time.Duration, log blog.Logger) {
	if healthSrv == nil || dbMap == nil || service == "" {
		// This should never happen.
		panic("nil argument provided to sa.initDeepHealthCheck()")
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}

	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Set the initial health status of the service.
		healthSrv.SetServingStatus(service, healthpb.HealthCheckResponse_NOT_SERVING)
		lastStatus := healthpb.HealthCheckResponse_NOT_SERVING

		check := func(tick time.Time) {
			nextStatus := healthpb.HealthCheckResponse_NOT_SERVING
			ctx, cancel := context.WithTimeout(context.Background(), interval*9/10)

			err := dbMap.WithContext(ctx).SelectOne(new(int), "SELECT 1")
			if err == nil {
				nextStatus = healthpb.HealthCheckResponse_SERVING
			}
			cancel()

			// Update the health status if necessary.
			if lastStatus != nextStatus {
				if nextStatus == healthpb.HealthCheckResponse_SERVING {
					log.Infof("transitioning health of %q from %q to %q", service, lastStatus, nextStatus)
				} else {
					log.Infof("transitioning health of %q from %q to %q, due to: %s", service, lastStatus, nextStatus, err)
				}
				healthSrv.SetServingStatus(service, nextStatus)
				lastStatus = nextStatus
			}
		}

		select {
		case <-interrupt:
			return
		default:
			// Check immediately.
			check(time.Now())
		}
		for {
			select {
			case <-interrupt:
				return
			case tick := <-ticker.C:
				// Check at the specified interval.
				check(tick)
			}
		}
	}()
}
