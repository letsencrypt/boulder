package sa

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// incidentSerialsBatchSize is the number of rows accumulated before flushing a
// single INSERT transaction during AddSerialsToIncident.
const incidentSerialsBatchSize = 10000

// SQLStorageAuthorityAdmin implements the StorageAuthorityAdmin service.
type SQLStorageAuthorityAdmin struct {
	sapb.UnsafeStorageAuthorityAdminServer

	dbMap               *db.WrappedMap
	dbIncidentsWriteMap *db.WrappedMap
	log                 blog.Logger
}

var _ sapb.StorageAuthorityAdminServer = (*SQLStorageAuthorityAdmin)(nil)

// NewSQLStorageAuthorityAdmin constructs an *SQLStorageAuthorityAdmin.
func NewSQLStorageAuthorityAdmin(dbMap *db.WrappedMap, dbIncidentsWriteMap *db.WrappedMap, logger blog.Logger) (*SQLStorageAuthorityAdmin, error) {
	return &SQLStorageAuthorityAdmin{
		dbMap:               dbMap,
		dbIncidentsWriteMap: dbIncidentsWriteMap,
		log:                 logger,
	}, nil
}

// CreateIncident creates a new per-incident serials table and records its
// metadata row. The new incident starts with enabled=false.
func (ssa *SQLStorageAuthorityAdmin) CreateIncident(ctx context.Context, req *sapb.CreateIncidentRequest) (*sapb.Incident, error) {
	if core.IsAnyNilOrZero(req.SerialTable, req.Url, req.RenewBy) {
		return nil, errIncompleteRequest
	}
	if !ValidIncidentTableRegexp.MatchString(req.SerialTable) {
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
	_, err = ssa.dbIncidentsWriteMap.ExecContext(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
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
// incidents metadata row identified by serialTable. An empty req.Url, nil
// req.RenewBy, and nil req.Enabled all leave their respective fields
// unchanged. At least one of them must be set.
func (ssa *SQLStorageAuthorityAdmin) UpdateIncident(ctx context.Context, req *sapb.UpdateIncidentRequest) (*emptypb.Empty, error) {
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

	return &emptypb.Empty{}, nil
}

// AddSerialsToIncident streams serials into an existing per-incident table. The
// client sends a batch of serials per message. The server accumulates up to
// incidentSerialsBatchSize across messages and inserts each batch in a single
// transaction. Only the serial field is populated; other metadata is left NULL.
func (ssa *SQLStorageAuthorityAdmin) AddSerialsToIncident(stream sapb.StorageAuthorityAdmin_AddSerialsToIncidentServer) error {
	ctx := stream.Context()

	var incidentTable string
	var buf []string

	flush := func() error {
		if len(buf) == 0 {
			return nil
		}

		// Safety note: incidentTable is interpolated directly into the query
		// text, which cannot be parameterized for an identifier. It was
		// validated against ValidIncidentTableRegexp when the first message
		// arrived, so it contains only [a-zA-Z0-9_].
		valuesPlaceholders := strings.TrimRight(strings.Repeat("(?, NULL, NULL, NULL),", len(buf)), ",")
		insertArgs := make([]any, len(buf))
		for i, s := range buf {
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
		_, err := db.WithTransaction(ctx, ssa.dbIncidentsWriteMap, func(tx db.Executor) (any, error) {
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
		ssa.log.Infof("AddSerialsToIncident %q: batch of %d, %d inserted", incidentTable, len(buf), inserted)
		buf = nil
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

		if incidentTable == "" {
			if !ValidIncidentTableRegexp.MatchString(req.SerialTable) {
				return fmt.Errorf("malformed incident %q", req.SerialTable)
			}
			incidentTable = req.SerialTable
		} else if req.SerialTable != incidentTable {
			return fmt.Errorf("serialTable changed mid-stream: %q -> %q", incidentTable, req.SerialTable)
		}

		for _, serial := range req.Serial {
			if serial == "" {
				return errors.New("empty serial in stream")
			}
			buf = append(buf, serial)

			if len(buf) >= incidentSerialsBatchSize {
				err := flush()
				if err != nil {
					return err
				}
			}
		}
	}

	err := flush()
	if err != nil {
		return err
	}

	return stream.SendAndClose(&emptypb.Empty{})
}
