// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/casdoor/casdoor/auditsnapshot"
	"github.com/casdoor/casdoor/conf"
)

// auditSnapshotPageSize bounds the IN-list of every page fetched from the
// already frozen ID set. Pages never re-run the selection query, so rows
// inserted after the freeze cannot appear and the page order is stable.
const auditSnapshotPageSize = 500

// auditRecordColumns lists the record columns in the exact order rows are
// scanned. It mirrors the xorm snake mapping of Record and quotes every
// identifier so reserved words like "user" work on every dialect.
var auditRecordColumns = []string{
	"id", "owner", "name", "created_time", "organization", "client_ip",
	"user", "method", "request_uri", "action", "language", "object",
	"response", "status_code", "detail", "is_triggered",
}

// sqlQueryer is satisfied by both *sql.DB and *sql.Tx.
type sqlQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// snapshotTxOptions chooses an isolation level under which the transaction
// sees one fixed read snapshot for its whole lifetime. MySQL/PostgreSQL use
// REPEATABLE READ; SQLite and MSSQL use SERIALIZABLE. MSSQL rejects read-only
// transactions through its driver, so the flag is omitted there.
func snapshotTxOptions(driverName string) *sql.TxOptions {
	switch driverName {
	case "mysql", "postgres":
		return &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	case "mssql":
		return &sql.TxOptions{Isolation: sql.LevelSerializable}
	default: // sqlite/sqlite3 and unknown drivers
		return &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true}
	}
}

func auditSnapshotTableName() string {
	// TableName applies the configured table-name prefix mapper.
	return ormer.Engine.TableName(new(Record))
}

// freezeAuditRecordIDs materializes the finite, ordered set of IDs selected by
// filter inside the caller's read snapshot. It selects actual IDs rather than
// a maximum auto-increment ID: gaps and deletions are part of the truth.
// Every condition is parameterized.
func freezeAuditRecordIDs(ctx context.Context, q sqlQueryer, driverName, table string, filter auditsnapshot.SnapshotFilter) ([]int64, error) {
	idCol := ormer.Engine.Quote("id")
	quotedTable := ormer.Engine.Quote(table)

	conditions := []string{ormer.Engine.Quote("organization") + " = ?"}
	args := []any{filter.Organization}
	if filter.Action != "" {
		conditions = append(conditions, ormer.Engine.Quote("action")+" = ?")
		args = append(args, filter.Action)
	}
	if filter.CreatedTimeFrom != "" {
		conditions = append(conditions, ormer.Engine.Quote("created_time")+" >= ?")
		args = append(args, filter.CreatedTimeFrom)
	}
	if filter.CreatedTimeTo != "" {
		conditions = append(conditions, ormer.Engine.Quote("created_time")+" < ?")
		args = append(args, filter.CreatedTimeTo)
	}
	where := strings.Join(conditions, " AND ")

	var query string
	var queryArgs []any
	if driverName == "mssql" {
		// TOP binds before the WHERE conditions.
		query = fmt.Sprintf("SELECT TOP (?) %s FROM %s WHERE %s ORDER BY %s ASC", idCol, quotedTable, where, idCol)
		queryArgs = append([]any{filter.MaxRecords}, args...)
	} else {
		query = fmt.Sprintf("SELECT %s FROM %s WHERE %s ORDER BY %s ASC LIMIT ?", idCol, quotedTable, where, idCol)
		queryArgs = append(args, filter.MaxRecords)
	}

	rows, err := q.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to freeze audit record ids: %w", err)
	}
	defer rows.Close()

	ids := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan audit record id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to freeze audit record ids: %w", err)
	}
	return ids, nil
}

func scanAuditRecord(rows *sql.Rows) (*Record, error) {
	var (
		record       Record
		statusCode   int64
		isTriggered  int64
		owner        sql.NullString
		name         sql.NullString
		createdTime  sql.NullString
		organization sql.NullString
		clientIP     sql.NullString
		user         sql.NullString
		method       sql.NullString
		requestURI   sql.NullString
		action       sql.NullString
		language     sql.NullString
		object       sql.NullString
		response     sql.NullString
		detail       sql.NullString
	)
	if err := rows.Scan(
		&record.Id, &owner, &name, &createdTime, &organization, &clientIP,
		&user, &method, &requestURI, &action, &language, &object,
		&response, &statusCode, &detail, &isTriggered,
	); err != nil {
		return nil, err
	}
	record.Owner = owner.String
	record.Name = name.String
	record.CreatedTime = createdTime.String
	record.Organization = organization.String
	record.ClientIp = clientIP.String
	record.User = user.String
	record.Method = method.String
	record.RequestUri = requestURI.String
	record.Action = action.String
	record.Language = language.String
	record.Object = object.String
	record.Response = response.String
	record.StatusCode = int(statusCode)
	record.Detail = detail.String
	record.IsTriggered = isTriggered != 0
	return &record, nil
}

// fetchAuditRecordsPage reads one page of full rows by the frozen IDs, within
// the same read snapshot. The result is ordered by ID and must match the
// requested frozen window exactly: a vanished row is an export error, never a
// silently shorter snapshot.
func fetchAuditRecordsPage(ctx context.Context, q sqlQueryer, table string, frozenIDs []int64) ([]*Record, error) {
	if len(frozenIDs) == 0 {
		return []*Record{}, nil
	}

	quotedCols := make([]string, 0, len(auditRecordColumns))
	for _, col := range auditRecordColumns {
		quotedCols = append(quotedCols, ormer.Engine.Quote(col))
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(frozenIDs)), ",")
	args := make([]any, len(frozenIDs))
	for i, id := range frozenIDs {
		args[i] = id
	}

	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s IN (%s) ORDER BY %s ASC",
		strings.Join(quotedCols, ", "),
		ormer.Engine.Quote(table),
		ormer.Engine.Quote("id"),
		placeholders,
		ormer.Engine.Quote("id"),
	)

	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch audit records page: %w", err)
	}
	defer rows.Close()

	records := []*Record{}
	for rows.Next() {
		record, err := scanAuditRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit record: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to fetch audit records page: %w", err)
	}
	return records, nil
}

func recordToCanonical(record *Record) auditsnapshot.CanonicalRecord {
	return auditsnapshot.CanonicalRecord{
		ID:           int64(record.Id),
		Owner:        record.Owner,
		Name:         record.Name,
		CreatedTime:  record.CreatedTime,
		Organization: record.Organization,
		ClientIP:     record.ClientIp,
		User:         record.User,
		Method:       record.Method,
		RequestURI:   record.RequestUri,
		Action:       record.Action,
		Language:     record.Language,
		Object:       record.Object,
		Response:     record.Response,
		StatusCode:   record.StatusCode,
		Detail:       record.Detail,
		IsTriggered:  record.IsTriggered,
	}
}

// NewConfiguredSnapshotSigner loads the dedicated audit snapshot key from the
// file named by the "auditSnapshotSigningKeyFile" config. There is no default
// key: when unset, exporting fails rather than signing with an implicit secret.
func NewConfiguredSnapshotSigner() (*auditsnapshot.FileSigner, error) {
	path := conf.GetConfigString("auditSnapshotSigningKeyFile")
	if path == "" {
		return nil, errors.New("audit snapshot signing key is not configured: set auditSnapshotSigningKeyFile")
	}
	return auditsnapshot.NewFileSigner(path)
}

// ExportAuditSnapshot selects the finite record set described by filter inside
// a single fixed read snapshot, freezes the actual ID set, pages the rows from
// that frozen set only, and returns the signed snapshot bundle.
//
// The caller is responsible for authorization: organization must already be
// constrained to the requester's administration scope.
func ExportAuditSnapshot(filter auditsnapshot.SnapshotFilter, signer auditsnapshot.Signer) (*auditsnapshot.SnapshotBundle, error) {
	if err := filter.Validate(); err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, errors.New("audit snapshot signer is required")
	}
	if ormer == nil || ormer.Engine == nil {
		return nil, errors.New("database is not initialized")
	}

	driverName := ormer.driverName
	if driverName == "sqlite3" {
		driverName = "sqlite"
	}
	table := auditSnapshotTableName()

	ctx := context.Background()
	tx, err := ormer.Engine.DB().DB.BeginTx(ctx, snapshotTxOptions(driverName))
	if err != nil {
		return nil, fmt.Errorf("failed to open audit snapshot read transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Freeze the complete selection as actual IDs within the read snapshot.
	ids, err := freezeAuditRecordIDs(ctx, tx, driverName, table, filter)
	if err != nil {
		return nil, err
	}
	if len(ids) > filter.MaxRecords {
		return nil, errors.New("frozen audit record set exceeds the filter limit")
	}

	// Page strictly over the frozen IDs; the selection query is never re-run.
	records := make([]auditsnapshot.CanonicalRecord, 0, len(ids))
	for start := 0; start < len(ids); start += auditSnapshotPageSize {
		end := start + auditSnapshotPageSize
		if end > len(ids) {
			end = len(ids)
		}
		page, err := fetchAuditRecordsPage(ctx, tx, table, ids[start:end])
		if err != nil {
			return nil, err
		}
		if len(page) != end-start {
			return nil, errors.New("audit snapshot row vanished during export")
		}
		for i, record := range page {
			if int64(record.Id) != ids[start+i] || record.Organization != filter.Organization {
				return nil, errors.New("audit snapshot page does not match the frozen id set")
			}
			records = append(records, recordToCanonical(record))
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit audit snapshot read transaction: %w", err)
	}
	committed = true

	return auditsnapshot.BuildBundle(filter, records, signer, time.Now(), "")
}
