package sa

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// SQLStorageAuthorityAdmin implements the StorageAuthorityAdmin service.
type SQLStorageAuthorityAdmin struct {
	sapb.UnsafeStorageAuthorityAdminServer

	dbMap               *db.WrappedMap
	dbIncidentsAdminMap *db.WrappedMap
	log                 blog.Logger
}

var _ sapb.StorageAuthorityAdminServer = (*SQLStorageAuthorityAdmin)(nil)

// NewSQLStorageAuthorityAdmin constructs an *SQLStorageAuthorityAdmin.
func NewSQLStorageAuthorityAdmin(dbMap *db.WrappedMap, dbIncidentsAdminMap *db.WrappedMap, logger blog.Logger) (*SQLStorageAuthorityAdmin, error) {
	return &SQLStorageAuthorityAdmin{
		dbMap:               dbMap,
		dbIncidentsAdminMap: dbIncidentsAdminMap,
		log:                 logger,
	}, nil
}

// CreateIncident creates a new per-incident serials table and records its
// metadata row. The new incident starts with enabled=false.
func (ssa *SQLStorageAuthorityAdmin) CreateIncident(ctx context.Context, req *sapb.CreateIncidentRequest) (*sapb.Incident, error) {
	if core.IsAnyNilOrZero(req.SerialTable, req.Url, req.RenewBy) {
		return nil, errIncompleteRequest
	}
	if !validIncidentTableRegexp.MatchString(req.SerialTable) {
		return nil, fmt.Errorf("malformed incident %q", req.SerialTable)
	}

	// The incidents table has no UNIQUE constraint on serialTable, so check for
	// existing rows application-side. There is a small TOCTOU window if two
	// CreateIncident calls race on the same name; the admin tool is
	// operator-driven and single-user in practice, so we accept it.
	var exists bool
	err := ssa.dbMap.SelectOne(ctx, &exists,
		`SELECT EXISTS (SELECT id FROM incidents WHERE serialTable = ? LIMIT 1)`,
		req.SerialTable)
	if err != nil {
		return nil, fmt.Errorf("checking for existing incident: %w", err)
	}
	if exists {
		return nil, berrors.DuplicateError("incident %q already exists", req.SerialTable)
	}

	// Safety note: req.SerialTable is interpolated directly into DDL, which
	// cannot be parameterized in MySQL. The regex check above restricts it to
	// [a-zA-Z0-9_]. IF NOT EXISTS makes this step idempotent so that a crash
	// between DDL and the metadata INSERT below can be recovered by rerunning.
	_, err = ssa.dbIncidentsAdminMap.ExecContext(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		serial varchar(255) NOT NULL,
		registrationID bigint(20) unsigned NULL,
		orderID bigint(20) unsigned NULL,
		lastNoticeSent datetime NULL,
		PRIMARY KEY (serial),
		KEY registrationID_idx (registrationID),
		KEY orderID_idx (orderID)
	) CHARSET=utf8mb4`, req.SerialTable))
	if err != nil {
		return nil, fmt.Errorf("creating incident %q: %w", req.SerialTable, err)
	}

	incident := &incidentModel{
		SerialTable: req.SerialTable,
		URL:         req.Url,
		RenewBy:     req.RenewBy.AsTime(),
		Enabled:     false,
	}
	err = ssa.dbMap.Insert(ctx, incident)
	if err != nil {
		return nil, fmt.Errorf("inserting incident metadata row for %q: %w", req.SerialTable, err)
	}

	pb := incidentModelToPB(*incident)

	return &pb, nil
}

// UpdateIncident updates the url, renewBy, and/or enabled fields on the
// incidents metadata row identified by serialTable and returns the resulting
// row. An empty req.Url, nil req.RenewBy, and nil req.Enabled all leave their
// respective fields unchanged. At least one of them must be set.
func (ssa *SQLStorageAuthorityAdmin) UpdateIncident(ctx context.Context, req *sapb.UpdateIncidentRequest) (*sapb.Incident, error) {
	if core.IsAnyNilOrZero(req.SerialTable) {
		return nil, errIncompleteRequest
	}
	if req.Url == "" && req.RenewBy == nil && req.Enabled == nil {
		return nil, errors.New("at least one of url, renewBy, or enabled must be set")
	}

	var sets []string
	var args []any
	if req.Url != "" {
		sets = append(sets, "url = ?")
		args = append(args, req.Url)
	}
	if req.RenewBy != nil {
		sets = append(sets, "renewBy = ?")
		args = append(args, req.RenewBy.AsTime())
	}
	if req.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, *req.Enabled)
	}
	args = append(args, req.SerialTable)

	res, err := ssa.dbMap.ExecContext(ctx,
		fmt.Sprintf("UPDATE incidents SET %s WHERE serialTable = ?", strings.Join(sets, ", ")),
		args...)
	if err != nil {
		return nil, fmt.Errorf("updating incident %q: %w", req.SerialTable, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("reading rows affected: %w", err)
	}
	if affected == 0 {
		return nil, berrors.NotFoundError("no incident found with serialTable %q", req.SerialTable)
	}

	var updated incidentModel
	err = ssa.dbMap.SelectOne(ctx, &updated,
		`SELECT id, serialTable, url, renewBy, enabled FROM incidents WHERE serialTable = ?`,
		req.SerialTable)
	if err != nil {
		return nil, fmt.Errorf("reading back updated incident %q: %w", req.SerialTable, err)
	}
	pb := incidentModelToPB(updated)
	return &pb, nil
}

// AddSerialsToIncident streams serials into an existing per-incident table. The
// client sends one Metadata message naming the target table, then any number of
// Batch messages each carrying a slice of serials. Each Batch is inserted in
// its own transaction; the client picks the batch size. Only the serial column
// is populated; other metadata columns are left NULL.
func (ssa *SQLStorageAuthorityAdmin) AddSerialsToIncident(stream sapb.StorageAuthorityAdmin_AddSerialsToIncidentServer) error {
	ctx := stream.Context()

	var incidentTable string

	insert := func(serials []string) error {
		if len(serials) == 0 {
			return nil
		}

		// Safety note: incidentTable is interpolated directly into the query
		// text, which cannot be parameterized for an identifier. It was
		// validated against validIncidentTableRegexp when the metadata message
		// arrived, so it contains only [a-zA-Z0-9_].
		valuesPlaceholders := strings.TrimRight(strings.Repeat("(?, NULL, NULL, NULL),", len(serials)), ",")
		insertArgs := make([]any, len(serials))
		for i, s := range serials {
			insertArgs[i] = s
		}

		// INSERT IGNORE no-ops duplicate-key violations from concurrent or
		// repeated inserts, avoiding the next-key locks ON DUPLICATE KEY UPDATE
		// would take. Only the serial PK can fire today; revisit if the schema
		// gains a FK, CHECK, or NOT NULL column we do not populate.
		query := fmt.Sprintf(
			"INSERT IGNORE INTO %s (serial, registrationID, orderID, lastNoticeSent) VALUES %s",
			incidentTable, valuesPlaceholders,
		)
		var inserted int64
		_, err := db.WithTransaction(ctx, ssa.dbIncidentsAdminMap, func(tx db.Executor) (any, error) {
			res, err := tx.ExecContext(ctx, query, insertArgs...)
			if err != nil {
				return nil, err
			}
			inserted, err = res.RowsAffected()
			return nil, err
		})
		if err != nil {
			return fmt.Errorf("inserting batch into %q: %w", incidentTable, err)
		}
		ssa.log.Infof("AddSerialsToIncident %q: batch of %d, %d inserted", incidentTable, len(serials), inserted)
		return nil
	}

	for {
		req, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		switch payload := req.Payload.(type) {
		case *sapb.AddSerialsToIncidentRequest_Metadata:
			if incidentTable != "" {
				return errors.New("received a second metadata message; only one is allowed per stream")
			}
			if !validIncidentTableRegexp.MatchString(payload.Metadata.SerialTable) {
				return fmt.Errorf("malformed incident %q", payload.Metadata.SerialTable)
			}
			incidentTable = payload.Metadata.SerialTable

		case *sapb.AddSerialsToIncidentRequest_Batch:
			if incidentTable == "" {
				return errors.New("received a batch message before any metadata")
			}
			if slices.Contains(payload.Batch.Serials, "") {
				return errors.New("empty serial in stream")
			}
			err := insert(payload.Batch.Serials)
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("unexpected payload type %T", payload)
		}
	}

	return stream.SendAndClose(&emptypb.Empty{})
}
