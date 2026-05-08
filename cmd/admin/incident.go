package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type subcommandCreateIncident struct {
	incident string
	url      string
	renewBy  string
}

var _ subcommand = (*subcommandCreateIncident)(nil)

func (*subcommandCreateIncident) Desc() string {
	return "Create a new incident table and metadata row (starts disabled)."
}

func (s *subcommandCreateIncident) Flags(f *flag.FlagSet) {
	f.StringVar(&s.incident, "incident", "", "Incident name (must start with 'incident_'; required)")
	f.StringVar(&s.url, "url", "", "URL describing the incident (required)")
	f.StringVar(&s.renewBy, "renew-by", "", "RFC3339 timestamp by which affected certs should be renewed (required)")
}

func (s *subcommandCreateIncident) Run(ctx context.Context, a *admin) error {
	if s.incident == "" || s.url == "" || s.renewBy == "" {
		return errors.New("-incident, -url, and -renew-by are all required")
	}
	renewBy, err := time.Parse(time.RFC3339, s.renewBy)
	if err != nil {
		return fmt.Errorf("parsing -renew-by as RFC3339: %w", err)
	}

	inc, err := a.saac.CreateIncident(ctx, &sapb.CreateIncidentRequest{
		SerialTable: s.incident,
		Url:         s.url,
		RenewBy:     timestamppb.New(renewBy),
	})
	if err != nil {
		return fmt.Errorf("creating incident: %w", err)
	}
	a.log.Infof("Created incident %q url=%q renewBy=%s enabled=%t",
		inc.SerialTable, inc.Url, inc.RenewBy.AsTime(), inc.Enabled)
	return nil
}

type subcommandListIncidents struct{}

var _ subcommand = (*subcommandListIncidents)(nil)

func (*subcommandListIncidents) Desc() string {
	return "List all incidents and their enabled status."
}

func (*subcommandListIncidents) Flags(_ *flag.FlagSet) {}

func (*subcommandListIncidents) Run(ctx context.Context, a *admin) error {
	resp, err := a.saroc.ListIncidents(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("listing incidents: %w", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tENABLED\tRENEW BY\tURL")
	for _, inc := range resp.Incidents {
		fmt.Fprintf(w, "%s\t%t\t%s\t%s\n",
			inc.SerialTable, inc.Enabled,
			inc.RenewBy.AsTime().Format(time.RFC3339), inc.Url)
	}
	return w.Flush()
}

type subcommandUpdateIncident struct {
	incident string
	url      string
	renewBy  string
	enable   string
}

var _ subcommand = (*subcommandUpdateIncident)(nil)

func (*subcommandUpdateIncident) Desc() string {
	return "Update the url, renew-by, and/or enable fields of an existing incident."
}

func (s *subcommandUpdateIncident) Flags(f *flag.FlagSet) {
	f.StringVar(&s.incident, "incident", "", "Incident name (must start with 'incident_'; required)")
	f.StringVar(&s.url, "url", "", "URL describing the incident (leave unset to keep the existing value)")
	f.StringVar(&s.renewBy, "renew-by", "", "RFC3339 timestamp by which affected certs should be renewed (leave unset to keep the existing value)")
	f.StringVar(&s.enable, "enable", "", `"true" to enable, "false" to disable (leave unset to keep the existing value)`)
}

func (s *subcommandUpdateIncident) Run(ctx context.Context, a *admin) error {
	if s.incident == "" {
		return errors.New("-incident is required")
	}
	if s.url == "" && s.renewBy == "" && s.enable == "" {
		return errors.New("at least one of -url, -renew-by, or -enable must be set")
	}
	req := &sapb.UpdateIncidentRequest{SerialTable: s.incident, Url: s.url}
	if s.renewBy != "" {
		t, err := time.Parse(time.RFC3339, s.renewBy)
		if err != nil {
			return fmt.Errorf("parsing -renew-by as RFC3339: %w", err)
		}
		req.RenewBy = timestamppb.New(t)
	}
	if s.enable != "" {
		v, err := strconv.ParseBool(s.enable)
		if err != nil {
			return fmt.Errorf("parsing -enable as bool: %w", err)
		}
		req.Enabled = &v
	}
	_, err := a.saac.UpdateIncident(ctx, req)
	if err != nil {
		return fmt.Errorf("updating incident %q: %w", s.incident, err)
	}
	var changes []string
	if req.Url != "" {
		changes = append(changes, fmt.Sprintf("url=%q", req.Url))
	}
	if req.RenewBy != nil {
		changes = append(changes, fmt.Sprintf("renewBy=%s", req.RenewBy.AsTime()))
	}
	if req.Enabled != nil {
		changes = append(changes, fmt.Sprintf("enabled=%t", *req.Enabled))
	}
	a.log.AuditInfo(fmt.Sprintf("Updated incident %q: %s", s.incident, strings.Join(changes, " ")), nil)
	return nil
}

type subcommandLoadIncidentSerials struct {
	incident    string
	serialsFile string
	parallelism uint
	batchSize   uint
}

var _ subcommand = (*subcommandLoadIncidentSerials)(nil)

func (*subcommandLoadIncidentSerials) Desc() string {
	return "Load serials from a file into an existing incident."
}

func (s *subcommandLoadIncidentSerials) Flags(f *flag.FlagSet) {
	f.StringVar(&s.incident, "incident", "", "Incident name (must start with 'incident_'; required)")
	f.StringVar(&s.serialsFile, "serials-file", "", "File of hex serials, one per line; duplicates (within or across batches, including reruns) are tolerated and skipped (required)")
	f.UintVar(&s.parallelism, "parallelism", 10, "Parallel workers, each with its own stream to the SA")
	f.UintVar(&s.batchSize, "batch-size", 10000, "Number of serials per gRPC message (and per SA INSERT)")
}

func (s *subcommandLoadIncidentSerials) Run(ctx context.Context, a *admin) error {
	if s.incident == "" || s.serialsFile == "" {
		return errors.New("-incident and -serials-file are required")
	}
	if s.parallelism == 0 {
		return errors.New("-parallelism must be > 0")
	}
	if s.batchSize == 0 {
		return errors.New("-batch-size must be > 0")
	}

	file, err := os.Open(s.serialsFile)
	if err != nil {
		return fmt.Errorf("opening serials file: %w", err)
	}
	defer file.Close()

	a.log.Infof("Loading serials from %q into incident %q with parallelism=%d batch-size=%d.",
		s.serialsFile, s.incident, s.parallelism, s.batchSize)

	var totalSent atomic.Uint64
	work := make(chan []string, s.parallelism)
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer close(work)
		scanner := bufio.NewScanner(file)
		batch := make([]string, 0, s.batchSize)
		batchStart := 1
		lineNum := 0

		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			cleaned, err := cleanSerials(batch)
			if err != nil {
				return fmt.Errorf("malformed serial near lines %d-%d: %w", batchStart, lineNum, err)
			}
			select {
			case work <- cleaned:
			case <-gctx.Done():
				return gctx.Err()
			}
			batch = make([]string, 0, s.batchSize)
			batchStart = lineNum + 1
			return nil
		}

		for scanner.Scan() {
			lineNum++
			raw := scanner.Text()
			if strings.TrimSpace(raw) == "" {
				continue
			}
			batch = append(batch, raw)
			if uint(len(batch)) >= s.batchSize {
				err := flush()
				if err != nil {
					return err
				}
			}
		}

		err := flush()
		if err != nil {
			return err
		}
		return scanner.Err()
	})

	for range s.parallelism {
		g.Go(func() error {
			stream, err := a.saac.AddSerialsToIncident(gctx)
			if err != nil {
				return fmt.Errorf("opening stream: %w", err)
			}

			err = stream.Send(&sapb.AddSerialsToIncidentRequest{
				Payload: &sapb.AddSerialsToIncidentRequest_Metadata{
					Metadata: &sapb.AddSerialsToIncidentMetadata{SerialTable: s.incident},
				},
			})
			if err != nil {
				return fmt.Errorf("sending metadata: %w", err)
			}

			for chunk := range work {
				err := stream.Send(&sapb.AddSerialsToIncidentRequest{
					Payload: &sapb.AddSerialsToIncidentRequest_Batch{
						Batch: &sapb.AddSerialsToIncidentBatch{Serials: chunk},
					},
				})
				if err != nil {
					return fmt.Errorf("sending batch: %w", err)
				}

				// Log once per 100k serials. Add returns post-increment, so the
				// segment [prev, n) is owned by this worker and any given
				// multiple of 100k falls in exactly one worker's segment.
				n := totalSent.Add(uint64(len(chunk)))
				prev := n - uint64(len(chunk))
				if prev/100000 != n/100000 {
					a.log.Infof("Sent %d serials total", n)
				}
			}

			_, err = stream.CloseAndRecv()
			if err != nil {
				return fmt.Errorf("closing stream: %w", err)
			}

			return nil
		})
	}

	err = g.Wait()
	if err != nil {
		return fmt.Errorf("loading serials: %w", err)
	}

	a.log.Infof("Done. Sent %d serials from %q into incident %q.", totalSent.Load(), s.serialsFile, s.incident)
	return nil
}
