package sa

import (
	"sync"

	"golang.org/x/net/context"
)

type domainCount struct {
	domain string
	count  int
}

func doParallel(
	ctx context.Context,
	parallelism int,
	domains []string,
	workFunc func(context.Context, string) (int, error),
) ([]domainCount, error) {
	work := make(chan string, len(domains))
	type result struct {
		domainCount
		err error
	}
	results := make(chan result, len(domains))
	for _, domain := range domains {
		work <- domain
	}
	close(work)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range work {
				select {
				case <-ctx.Done():
					results <- result{err: ctx.Err()}
					return
				default:
				}
				count, err := workFunc(ctx, domain)
				if err != nil {
					results <- result{err: err}
					// Skip any further work
					cancel()
					return
				}
				results <- result{
					domainCount{count: count, domain: domain}, nil,
				}
			}
		}()
	}
	wg.Wait()
	close(results)
	var output []domainCount
	for r := range results {
		output = append(output, r.domainCount)
	}
	return output, nil
}
