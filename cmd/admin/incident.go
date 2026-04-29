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

	"github.com/letsencrypt/boulder/sa"
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
	if !sa.ValidIncidentTableRegexp.MatchString(s.incident) {
		return fmt.Errorf("invalid incident %q (must match %s)", s.incident, sa.ValidIncidentTableRegexp)
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
	if !sa.ValidIncidentTableRegexp.MatchString(s.incident) {
		return fmt.Errorf("invalid incident %q (must match %s)", s.incident, sa.ValidIncidentTableRegexp)
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
	a.log.Infof("Updated incident %q", s.incident)
	return nil
}

type subcommandLoadIncidentSerials struct {
	incident    string
	serialsFile string
	parallelism uint
}

var _ subcommand = (*subcommandLoadIncidentSerials)(nil)

func (*subcommandLoadIncidentSerials) Desc() string {
	return "Load serials from a file into an existing incident."
}

func (s *subcommandLoadIncidentSerials) Flags(f *flag.FlagSet) {
	f.StringVar(&s.incident, "incident", "", "Incident name (must start with 'incident_'; required)")
	f.StringVar(&s.serialsFile, "serials-file", "", "File of hex serials, one per line (required)")
	f.UintVar(&s.parallelism, "parallelism", 10, "Parallel workers, each with its own stream to the SA")
}

// serialsBatchMax is the number of serials each worker accumulates before
// emitting one Send on its gRPC stream. Sized to match the SA's flush batch so
// each Recv on the server roughly maps to one transaction. Each message is
// ~320KB at full batch (10000 × ~32-byte serials), well under the gRPC default
// 4MB max.
const serialsBatchMax = 10000

func (s *subcommandLoadIncidentSerials) Run(ctx context.Context, a *admin) error {
	if s.incident == "" || s.serialsFile == "" {
		return errors.New("-incident and -serials-file are required")
	}
	if !sa.ValidIncidentTableRegexp.MatchString(s.incident) {
		return fmt.Errorf("invalid incident %q", s.incident)
	}
	if s.parallelism == 0 {
		return errors.New("-parallelism must be > 0")
	}

	file, err := os.Open(s.serialsFile)
	if err != nil {
		return fmt.Errorf("opening serials file: %w", err)
	}
	defer file.Close()

	a.log.Infof("Loading serials from %q into incident %q with parallelism=%d.",
		s.serialsFile, s.incident, s.parallelism)

	var totalSent atomic.Uint64
	work := make(chan string, s.parallelism)
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer close(work)
		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			raw := scanner.Text()
			if strings.TrimSpace(raw) == "" {
				continue
			}
			cleaned, err := cleanSerials([]string{raw})
			if err != nil {
				return fmt.Errorf("line %d: %w", lineNum, err)
			}
			select {
			case work <- cleaned[0]:
			case <-gctx.Done():
				return gctx.Err()
			}
		}
		return scanner.Err()
	})

	for range s.parallelism {
		g.Go(func() error {
			stream, err := a.saac.AddSerialsToIncident(gctx)
			if err != nil {
				return fmt.Errorf("opening stream: %w", err)
			}
			var buf []string
			flushSerials := func() error {
				if len(buf) == 0 {
					return nil
				}
				err := stream.Send(&sapb.AddSerialsToIncidentRequest{
					SerialTable: s.incident,
					Serial:      buf,
				})
				if err != nil {
					buf = buf[:0]
					return err
				}
				n := totalSent.Add(uint64(len(buf)))
				prev := n - uint64(len(buf))
				if prev/100000 != n/100000 {
					a.log.Infof("Sent %d serials total", n)
				}
				buf = buf[:0]
				return nil
			}
			for serial := range work {
				buf = append(buf, serial)
				if len(buf) >= serialsBatchMax {
					err := flushSerials()
					if err != nil {
						return fmt.Errorf("sending batch: %w", err)
					}
				}
			}
			err = flushSerials()
			if err != nil {
				return fmt.Errorf("sending final batch: %w", err)
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
	a.log.Infof("Done. Sent %d serials from %q into incident %q.",
		totalSent.Load(), s.serialsFile, s.incident)
	return nil
}
