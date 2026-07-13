package sa

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/letsencrypt/boulder/db"
	berrors "github.com/letsencrypt/boulder/errors"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

// randomIncidentTable returns an incident_<random> name suitable for use as a
// per-incident table. Callers should register a t.Cleanup to DROP the table.
func randomIncidentTable(t *testing.T) string {
	t.Helper()
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		t.Fatalf("generating random incident name: %s", err)
	}
	return "incident_" + hex.EncodeToString(b[:])
}

// fakeClientStreamingServer is a minimal ServerStream-flavoured fake for
// testing client-streaming RPCs. It drains `input` via Recv() and records
// whatever the handler passes to SendAndClose().
type fakeClientStreamingServer[Req, Res any] struct {
	grpc.ServerStream
	input  []*Req
	cursor int
	sent   *Res
}

func (s *fakeClientStreamingServer[Req, Res]) Recv() (*Req, error) {
	if s.cursor >= len(s.input) {
		return nil, io.EOF
	}
	m := s.input[s.cursor]
	s.cursor++
	return m, nil
}

func (s *fakeClientStreamingServer[Req, Res]) SendAndClose(m *Res) error {
	s.sent = m
	return nil
}

func (s *fakeClientStreamingServer[Req, Res]) Context() context.Context {
	return context.Background()
}

// initSAAdmin constructs an SQLStorageAuthorityAdmin and returns it alongside
// the boulder_sa and incidents_sa read maps for use in test assertions.
func initSAAdmin(t *testing.T) (*SQLStorageAuthorityAdmin, *db.WrappedMap, *db.WrappedMap) {
	t.Helper()

	dbMap, err := DBMapForTest(vars.DBConnSA)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	dbIncidentsMap, err := DBMapForTest(vars.DBConnIncidents)
	if err != nil {
		t.Fatalf("Failed to create dbIncidentsMap: %s", err)
	}
	dbIncidentsAdminMap, err := DBMapForTest(vars.DBConnIncidentsAdmin)
	if err != nil {
		t.Fatalf("Failed to create dbIncidentsAdminMap: %s", err)
	}

	saa, err := NewSQLStorageAuthorityAdmin(dbMap, dbIncidentsAdminMap, log)
	if err != nil {
		t.Fatalf("Failed to create SA admin impl: %s", err)
	}

	t.Cleanup(test.ResetBoulderTestDatabase(t))
	return saa, dbMap, dbIncidentsMap
}

func TestCreateIncident(t *testing.T) {
	saa, _, _ := initSAAdmin(t)
	t.Cleanup(test.ResetIncidentsTestDatabase(t))

	testIncidentsDbMap, err := DBMapForTest(vars.DBConnIncidentsFullPerms)
	test.AssertNotError(t, err, "Couldn't create test dbMap")

	serialTable := randomIncidentTable(t)
	t.Cleanup(func() {
		_, err := testIncidentsDbMap.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", serialTable))
		if err != nil {
			t.Errorf("dropping incident table %q: %s", serialTable, err)
		}
	})

	renewBy := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	inc, err := saa.CreateIncident(ctx, &sapb.CreateIncidentRequest{
		SerialTable: serialTable,
		Url:         "https://example.com/i1",
		RenewBy:     timestamppb.New(renewBy),
	})
	test.AssertNotError(t, err, "CreateIncident")
	test.Assert(t, inc.Id != 0, "expected non-zero id")
	test.AssertEquals(t, inc.SerialTable, serialTable)
	test.AssertEquals(t, inc.Enabled, false)

	stream := &fakeClientStreamingServer[sapb.AddSerialsToIncidentRequest, emptypb.Empty]{
		input: []*sapb.AddSerialsToIncidentRequest{
			{Payload: &sapb.AddSerialsToIncidentRequest_Metadata{
				Metadata: &sapb.AddSerialsToIncidentMetadata{SerialTable: serialTable},
			}},
			{Payload: &sapb.AddSerialsToIncidentRequest_Batch{
				Batch: &sapb.AddSerialsToIncidentBatch{Serials: []string{"aa11"}},
			}},
		},
	}
	err = saa.AddSerialsToIncident(stream)
	test.AssertNotError(t, err, "AddSerialsToIncident on new table")
}

func TestCreateIncidentDuplicate(t *testing.T) {
	saa, _, _ := initSAAdmin(t)
	t.Cleanup(test.ResetIncidentsTestDatabase(t))

	testIncidentsDbMap, err := DBMapForTest(vars.DBConnIncidentsFullPerms)
	test.AssertNotError(t, err, "Couldn't create test dbMap")

	serialTable := randomIncidentTable(t)
	t.Cleanup(func() {
		_, err := testIncidentsDbMap.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", serialTable))
		if err != nil {
			t.Errorf("dropping incident table %q: %s", serialTable, err)
		}
	})

	req := &sapb.CreateIncidentRequest{
		SerialTable: serialTable,
		Url:         "https://example.com/dup",
		RenewBy:     timestamppb.New(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
	}
	_, err = saa.CreateIncident(ctx, req)
	test.AssertNotError(t, err, "first CreateIncident")

	_, err = saa.CreateIncident(ctx, req)
	test.AssertErrorIs(t, err, berrors.Duplicate)
}

func TestCreateIncidentMalformedName(t *testing.T) {
	saa, _, _ := initSAAdmin(t)

	cases := []struct {
		name  string
		input string
	}{
		{name: "wrong prefix", input: "something_foo"},
		{name: "empty suffix", input: "incident_"},
		{name: "bad chars", input: "incident_has spaces"},
		{name: "sql injection", input: "incident_foo; DROP TABLE users;--"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := saa.CreateIncident(ctx, &sapb.CreateIncidentRequest{
				SerialTable: tc.input,
				Url:         "https://example.com/x",
				RenewBy:     timestamppb.New(time.Now().Add(time.Hour)),
			})
			test.AssertError(t, err, "expected error for malformed name")
		})
	}
}

func TestAddSerialsToIncident(t *testing.T) {
	saa, _, dbIncidentsMap := initSAAdmin(t)
	t.Cleanup(test.ResetIncidentsTestDatabase(t))

	testIncidentsDbMap, err := DBMapForTest(vars.DBConnIncidentsFullPerms)
	test.AssertNotError(t, err, "Couldn't create test dbMap")

	serialTable := randomIncidentTable(t)
	t.Cleanup(func() {
		_, err := testIncidentsDbMap.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", serialTable))
		if err != nil {
			t.Errorf("dropping incident table %q: %s", serialTable, err)
		}
	})

	_, err = saa.CreateIncident(ctx, &sapb.CreateIncidentRequest{
		SerialTable: serialTable,
		Url:         "https://example.com/x",
		RenewBy:     timestamppb.New(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
	})
	test.AssertNotError(t, err, "CreateIncident")

	err = saa.AddSerialsToIncident(&fakeClientStreamingServer[sapb.AddSerialsToIncidentRequest, emptypb.Empty]{})
	test.AssertNotError(t, err, "AddSerialsToIncident with empty stream")

	// Include a within-batch duplicate ("aa11" twice) to exercise INSERT
	// IGNORE. This is the unit-testable proxy for cross-worker races, which
	// can't be reproduced with a single handler.
	stream := &fakeClientStreamingServer[sapb.AddSerialsToIncidentRequest, emptypb.Empty]{
		input: []*sapb.AddSerialsToIncidentRequest{
			{Payload: &sapb.AddSerialsToIncidentRequest_Metadata{
				Metadata: &sapb.AddSerialsToIncidentMetadata{SerialTable: serialTable},
			}},
			{Payload: &sapb.AddSerialsToIncidentRequest_Batch{
				Batch: &sapb.AddSerialsToIncidentBatch{Serials: []string{"aa11", "bb22", "aa11", "cc33"}},
			}},
		},
	}
	err = saa.AddSerialsToIncident(stream)
	test.AssertNotError(t, err, "AddSerialsToIncident with within-batch duplicate")

	// Rerunning with the same serials must be a no-op: INSERT IGNORE silently
	// skips the already-present rows.
	rerun := &fakeClientStreamingServer[sapb.AddSerialsToIncidentRequest, emptypb.Empty]{
		input: []*sapb.AddSerialsToIncidentRequest{
			{Payload: &sapb.AddSerialsToIncidentRequest_Metadata{
				Metadata: &sapb.AddSerialsToIncidentMetadata{SerialTable: serialTable},
			}},
			{Payload: &sapb.AddSerialsToIncidentRequest_Batch{
				Batch: &sapb.AddSerialsToIncidentBatch{Serials: []string{"aa11", "bb22", "cc33"}},
			}},
		},
	}
	err = saa.AddSerialsToIncident(rerun)
	test.AssertNotError(t, err, "AddSerialsToIncident rerun")

	var got []incidentSerialModel
	_, err = dbIncidentsMap.Select(ctx, &got,
		fmt.Sprintf(`SELECT serial, registrationID, orderID, lastNoticeSent FROM %s`, serialTable))
	test.AssertNotError(t, err, "selecting inserted rows")
	test.AssertEquals(t, len(got), 3)

	for _, r := range got {
		test.Assert(t, r.RegistrationID == nil, "registrationID should be NULL for "+r.Serial)
		test.Assert(t, r.OrderID == nil, "orderID should be NULL for "+r.Serial)
		test.Assert(t, r.LastNoticeSent == nil, "lastNoticeSent should be NULL for "+r.Serial)
	}
}

func TestUpdateIncident(t *testing.T) {
	saa, _, _ := initSAAdmin(t)
	t.Cleanup(test.ResetIncidentsTestDatabase(t))

	testIncidentsDbMap, err := DBMapForTest(vars.DBConnIncidentsFullPerms)
	test.AssertNotError(t, err, "Couldn't create test dbMap")

	serialTable := randomIncidentTable(t)
	t.Cleanup(func() {
		_, err := testIncidentsDbMap.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", serialTable))
		if err != nil {
			t.Errorf("dropping incident table %q: %s", serialTable, err)
		}
	})

	originalRenewBy := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err = saa.CreateIncident(ctx, &sapb.CreateIncidentRequest{
		SerialTable: serialTable,
		Url:         "https://example.com/v1",
		RenewBy:     timestamppb.New(originalRenewBy),
	})
	test.AssertNotError(t, err, "CreateIncident")

	got, err := saa.UpdateIncident(ctx, &sapb.UpdateIncidentRequest{
		SerialTable: serialTable,
		Url:         "https://example.com/v2",
	})
	test.AssertNotError(t, err, "UpdateIncident url-only")
	test.AssertEquals(t, got.SerialTable, serialTable)
	test.AssertEquals(t, got.Url, "https://example.com/v2")
	test.Assert(t, got.RenewBy.AsTime().Equal(originalRenewBy), "renewBy should be unchanged")
	test.AssertEquals(t, got.Enabled, false)

	newRenewBy := time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)
	got, err = saa.UpdateIncident(ctx, &sapb.UpdateIncidentRequest{
		SerialTable: serialTable,
		RenewBy:     timestamppb.New(newRenewBy),
	})
	test.AssertNotError(t, err, "UpdateIncident renewBy-only")
	test.AssertEquals(t, got.Url, "https://example.com/v2")
	test.Assert(t, got.RenewBy.AsTime().Equal(newRenewBy), "renewBy should be updated")
	test.AssertEquals(t, got.Enabled, false)

	enableTrue := true
	got, err = saa.UpdateIncident(ctx, &sapb.UpdateIncidentRequest{
		SerialTable: serialTable,
		Enabled:     &enableTrue,
	})
	test.AssertNotError(t, err, "UpdateIncident enabled=true")
	test.AssertEquals(t, got.Url, "https://example.com/v2")
	test.Assert(t, got.RenewBy.AsTime().Equal(newRenewBy), "renewBy should be unchanged")
	test.AssertEquals(t, got.Enabled, true)

	enableFalse := false
	got, err = saa.UpdateIncident(ctx, &sapb.UpdateIncidentRequest{
		SerialTable: serialTable,
		Enabled:     &enableFalse,
	})
	test.AssertNotError(t, err, "UpdateIncident enabled=false")
	test.AssertEquals(t, got.Enabled, false)

	_, err = saa.UpdateIncident(ctx, &sapb.UpdateIncidentRequest{SerialTable: serialTable})
	test.AssertError(t, err, "expected error when no fields set")

	_, err = saa.UpdateIncident(ctx, &sapb.UpdateIncidentRequest{
		SerialTable: "incident_does_not_exist",
		Enabled:     &enableTrue,
	})
	test.AssertErrorIs(t, err, berrors.NotFound)
}

func TestAddSerialsToIncidentMalformedName(t *testing.T) {
	saa, _, _ := initSAAdmin(t)
	stream := &fakeClientStreamingServer[sapb.AddSerialsToIncidentRequest, emptypb.Empty]{
		input: []*sapb.AddSerialsToIncidentRequest{
			{Payload: &sapb.AddSerialsToIncidentRequest_Metadata{
				Metadata: &sapb.AddSerialsToIncidentMetadata{SerialTable: "not_an_incident_table"},
			}},
			{Payload: &sapb.AddSerialsToIncidentRequest_Batch{
				Batch: &sapb.AddSerialsToIncidentBatch{Serials: []string{"aa"}},
			}},
		},
	}
	err := saa.AddSerialsToIncident(stream)
	test.AssertError(t, err, "expected error for malformed incident")
}

func TestAddSerialsToIncidentBatchBeforeMetadata(t *testing.T) {
	saa, _, _ := initSAAdmin(t)
	stream := &fakeClientStreamingServer[sapb.AddSerialsToIncidentRequest, emptypb.Empty]{
		input: []*sapb.AddSerialsToIncidentRequest{
			{Payload: &sapb.AddSerialsToIncidentRequest_Batch{
				Batch: &sapb.AddSerialsToIncidentBatch{Serials: []string{"aa11"}},
			}},
		},
	}
	err := saa.AddSerialsToIncident(stream)
	test.AssertError(t, err, "expected error for batch before metadata")
}

func TestAddSerialsToIncidentSecondMetadata(t *testing.T) {
	saa, _, _ := initSAAdmin(t)
	stream := &fakeClientStreamingServer[sapb.AddSerialsToIncidentRequest, emptypb.Empty]{
		input: []*sapb.AddSerialsToIncidentRequest{
			{Payload: &sapb.AddSerialsToIncidentRequest_Metadata{
				Metadata: &sapb.AddSerialsToIncidentMetadata{SerialTable: "incident_one"},
			}},
			{Payload: &sapb.AddSerialsToIncidentRequest_Metadata{
				Metadata: &sapb.AddSerialsToIncidentMetadata{SerialTable: "incident_two"},
			}},
		},
	}
	err := saa.AddSerialsToIncident(stream)
	test.AssertError(t, err, "expected error for second metadata message")
	test.AssertContains(t, err.Error(), "second metadata message")
}
