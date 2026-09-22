package main

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
)

// fakeAddSerialsStream implements the client-streaming client returned by
// mockSAAdmin.AddSerialsToIncident. It records every Send(req).
type fakeAddSerialsStream struct {
	grpc.ClientStream
	sent []*sapb.AddSerialsToIncidentRequest
}

func (s *fakeAddSerialsStream) Send(req *sapb.AddSerialsToIncidentRequest) error {
	s.sent = append(s.sent, req)
	return nil
}

func (s *fakeAddSerialsStream) CloseAndRecv() (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// mockSAROIncidents implements just enough of StorageAuthorityReadOnlyClient
// to support the incident-related admin tests.
type mockSAROIncidents struct {
	sapb.StorageAuthorityReadOnlyClient
	listResp *sapb.Incidents
}

func (m *mockSAROIncidents) ListIncidents(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*sapb.Incidents, error) {
	return m.listResp, nil
}

// mockSAAdmin implements the StorageAuthorityAdmin client interface and
// records the requests received on each method.
type mockSAAdmin struct {
	sapb.StorageAuthorityAdminClient
	createReqs []*sapb.CreateIncidentRequest
	updateReqs []*sapb.UpdateIncidentRequest
	addStream  *fakeAddSerialsStream
}

func (m *mockSAAdmin) UpdateIncident(_ context.Context, req *sapb.UpdateIncidentRequest, _ ...grpc.CallOption) (*sapb.Incident, error) {
	m.updateReqs = append(m.updateReqs, req)
	out := &sapb.Incident{SerialTable: req.SerialTable, Url: req.Url, RenewBy: req.RenewBy}
	if req.Enabled != nil {
		out.Enabled = *req.Enabled
	}
	return out, nil
}

func (m *mockSAAdmin) CreateIncident(_ context.Context, req *sapb.CreateIncidentRequest, _ ...grpc.CallOption) (*sapb.Incident, error) {
	m.createReqs = append(m.createReqs, req)
	return &sapb.Incident{Id: 1, SerialTable: req.SerialTable, Url: req.Url, RenewBy: req.RenewBy}, nil
}

func (m *mockSAAdmin) AddSerialsToIncident(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[sapb.AddSerialsToIncidentRequest, emptypb.Empty], error) {
	m.addStream = &fakeAddSerialsStream{}
	return m.addStream, nil
}

func TestCreateIncidentSubcommand(t *testing.T) {
	t.Parallel()
	msa := &mockSAAdmin{}
	a := &admin{saac: msa, log: blog.NewMock()}

	s := &subcommandCreateIncident{
		incident: "incident_abc",
		url:      "https://example.com/foo",
		renewBy:  "2030-01-01T00:00:00Z",
	}
	err := s.Run(context.Background(), a)
	test.AssertNotError(t, err, "create-incident")
	test.AssertEquals(t, len(msa.createReqs), 1)
	test.AssertEquals(t, msa.createReqs[0].SerialTable, "incident_abc")
}

func TestCreateIncidentSubcommandValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		sub               subcommandCreateIncident
		expectErrContains string
	}{
		{
			name:              "missing flags",
			sub:               subcommandCreateIncident{},
			expectErrContains: "required",
		},
		{
			name:              "bad renewBy",
			sub:               subcommandCreateIncident{incident: "incident_x", url: "u", renewBy: "tomorrow"},
			expectErrContains: "renew-by",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msa := &mockSAAdmin{}
			a := &admin{saac: msa, log: blog.NewMock()}
			err := tc.sub.Run(context.Background(), a)
			test.AssertError(t, err, "expected error")
			test.AssertContains(t, err.Error(), tc.expectErrContains)
			test.AssertEquals(t, len(msa.createReqs), 0)
		})
	}
}

func TestListIncidentsSubcommand(t *testing.T) {
	t.Parallel()
	saroc := &mockSAROIncidents{
		listResp: &sapb.Incidents{
			Incidents: []*sapb.Incident{
				{Id: 1, SerialTable: "incident_one", Url: "https://example.com/1", Enabled: true, RenewBy: timestamppb.New(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))},
				{Id: 2, SerialTable: "incident_two", Url: "https://example.com/2", Enabled: false, RenewBy: timestamppb.New(time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC))},
			},
		},
	}
	a := &admin{saroc: saroc, log: blog.NewMock()}
	err := (&subcommandListIncidents{}).Run(context.Background(), a)
	test.AssertNotError(t, err, "list-incidents")
}

func TestUpdateIncidentSubcommand(t *testing.T) {
	t.Parallel()
	msa := &mockSAAdmin{}
	a := &admin{saac: msa, log: blog.NewMock()}

	err := (&subcommandUpdateIncident{incident: "incident_foo", url: "https://example.com/new"}).Run(context.Background(), a)
	test.AssertNotError(t, err, "update url only")
	test.AssertEquals(t, len(msa.updateReqs), 1)
	test.AssertEquals(t, msa.updateReqs[0].SerialTable, "incident_foo")
	test.AssertEquals(t, msa.updateReqs[0].Url, "https://example.com/new")
	test.Assert(t, msa.updateReqs[0].RenewBy == nil, "RenewBy should be nil when -renew-by is unset")
	test.Assert(t, msa.updateReqs[0].Enabled == nil, "Enabled should be nil when -enable is unset")

	err = (&subcommandUpdateIncident{incident: "incident_foo", renewBy: "2030-06-01T00:00:00Z"}).Run(context.Background(), a)
	test.AssertNotError(t, err, "update renewBy only")
	test.AssertEquals(t, len(msa.updateReqs), 2)
	test.AssertEquals(t, msa.updateReqs[1].Url, "")
	test.Assert(t, msa.updateReqs[1].RenewBy != nil, "RenewBy should be set")
	test.Assert(t, msa.updateReqs[1].Enabled == nil, "Enabled should be nil when -enable is unset")

	err = (&subcommandUpdateIncident{incident: "incident_foo", enable: "true"}).Run(context.Background(), a)
	test.AssertNotError(t, err, "update enable=true")
	test.AssertEquals(t, len(msa.updateReqs), 3)
	test.Assert(t, msa.updateReqs[2].Enabled != nil, "Enabled should be set")
	test.AssertEquals(t, *msa.updateReqs[2].Enabled, true)

	err = (&subcommandUpdateIncident{incident: "incident_foo", enable: "false"}).Run(context.Background(), a)
	test.AssertNotError(t, err, "update enable=false")
	test.AssertEquals(t, len(msa.updateReqs), 4)
	test.Assert(t, msa.updateReqs[3].Enabled != nil, "Enabled should be set")
	test.AssertEquals(t, *msa.updateReqs[3].Enabled, false)

	err = (&subcommandUpdateIncident{incident: "incident_foo", enable: "yes"}).Run(context.Background(), a)
	test.AssertError(t, err, "expected error for malformed -enable")

	err = (&subcommandUpdateIncident{incident: "incident_foo"}).Run(context.Background(), a)
	test.AssertError(t, err, "expected error when no fields set")

	err = (&subcommandUpdateIncident{url: "https://example.com/new"}).Run(context.Background(), a)
	test.AssertError(t, err, "expected error for missing -incident")
}

func TestLoadIncidentSerialsSubcommand(t *testing.T) {
	t.Parallel()

	a1 := strings.Repeat("a", 32)
	b1 := strings.Repeat("b", 32)
	c1 := strings.Repeat("Cc", 16)

	serialsFile := path.Join(t.TempDir(), "serials.txt")
	err := os.WriteFile(serialsFile, []byte(a1+"\n"+b1+"\n"+c1+"\n"), 0o600)
	test.AssertNotError(t, err, "writing serials file")

	msa := &mockSAAdmin{}
	a := &admin{saac: msa, log: blog.NewMock()}

	s := &subcommandLoadIncidentSerials{
		incident:    "incident_bulk",
		serialsFile: serialsFile,
		parallelism: 1,
		batchSize:   10,
	}
	err = s.Run(context.Background(), a)
	test.AssertNotError(t, err, "load-incident-serials")
	test.AssertEquals(t, len(msa.addStream.sent), 2)
	meta := msa.addStream.sent[0].GetMetadata()
	test.Assert(t, meta != nil, "first message should be metadata")
	test.AssertEquals(t, meta.SerialTable, "incident_bulk")
	batch := msa.addStream.sent[1].GetBatch()
	test.Assert(t, batch != nil, "second message should be a batch")

	got := map[string]bool{}
	for _, s := range batch.Serials {
		got[s] = true
	}
	test.Assert(t, got[a1], "expected "+a1)
	test.Assert(t, got[b1], "expected "+b1)
	test.Assert(t, got[c1], "expected "+c1)
}
