package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/javiyt/safeops-mcp/internal/domain/alert"
	"github.com/javiyt/safeops-mcp/internal/domain/approval"
	"github.com/javiyt/safeops-mcp/internal/domain/audit"
	"github.com/javiyt/safeops-mcp/internal/domain/backup"
	"github.com/javiyt/safeops-mcp/internal/domain/deployment"
	"github.com/javiyt/safeops-mcp/internal/ports"
	"github.com/javiyt/safeops-mcp/migrations"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	entries, err := migrations.Files.ReadDir(".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := migrations.Files.ReadFile(entry.Name())
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, string(data)); err != nil {
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
	}
	return s.ensureApprovalColumns(ctx)
}

func (s *Store) ensureApprovalColumns(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(approvals)`)
	if err != nil {
		return err
	}
	defer func() {
		_ = rows.Close()
	}()
	exists := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &defaultValue, &pk); err != nil {
			return err
		}
		exists[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	columns := map[string]string{
		"resource_kind":    "TEXT NOT NULL DEFAULT 'service'",
		"resource_alias":   "TEXT NOT NULL DEFAULT ''",
		"operation_id":     "TEXT NOT NULL DEFAULT ''",
		"execution_result": "TEXT NOT NULL DEFAULT ''",
	}
	for name, definition := range columns {
		if exists[name] {
			continue
		}
		if _, err := s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE approvals ADD COLUMN %s %s", name, definition)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Create(ctx context.Context, a approval.Approval) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO approvals
(id, user_id, tool, action, resource_kind, resource_alias, operation_id, normalized_arguments, arguments_hash, confirmation_code_hash, status, created_at, expires_at, error_summary, result_summary, attempts)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.UserID, a.Tool, a.Action, a.ResourceKind, a.ResourceAlias, a.OperationID, a.NormalizedArguments, a.ArgumentsHash, a.ConfirmationCodeHash, a.Status,
		a.CreatedAt.UTC().Format(time.RFC3339Nano), a.ExpiresAt.UTC().Format(time.RFC3339Nano), a.ErrorSummary, a.ResultSummary, a.Attempts)
	return err
}

func (s *Store) Get(ctx context.Context, id string) (approval.Approval, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, user_id, tool, action, resource_kind, resource_alias, operation_id, normalized_arguments, arguments_hash, confirmation_code_hash,
status, created_at, expires_at, executed_at, error_summary, result_summary, attempts FROM approvals WHERE id = ?`, id)
	return scanApproval(row)
}

func (s *Store) MarkExecuting(ctx context.Context, id string, now time.Time) (approval.Approval, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return approval.Approval{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	res, err := tx.ExecContext(ctx, `UPDATE approvals SET status = ?, attempts = attempts + 1 WHERE id = ? AND status = ? AND expires_at > ?`,
		approval.StatusExecuting, id, approval.StatusPending, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return approval.Approval{}, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return approval.Approval{}, err
	}
	if affected != 1 {
		return approval.Approval{}, errors.New("approval is not pending or has expired")
	}
	row := tx.QueryRowContext(ctx, `SELECT id, user_id, tool, action, resource_kind, resource_alias, operation_id, normalized_arguments, arguments_hash, confirmation_code_hash,
status, created_at, expires_at, executed_at, error_summary, result_summary, attempts FROM approvals WHERE id = ?`, id)
	a, err := scanApproval(row)
	if err != nil {
		return approval.Approval{}, err
	}
	if err := tx.Commit(); err != nil {
		return approval.Approval{}, err
	}
	return a, nil
}

func (s *Store) MarkDone(ctx context.Context, id string, status approval.Status, resultSummary, errorSummary string, executedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE approvals SET status = ?, result_summary = ?, error_summary = ?, executed_at = ? WHERE id = ?`,
		status, resultSummary, errorSummary, executedAt.UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) Cancel(ctx context.Context, id string, userID string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE approvals SET status = ? WHERE id = ? AND user_id = ? AND status = ? AND expires_at > ?`,
		approval.StatusRejected, id, userID, approval.StatusPending, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return errors.New("approval cannot be canceled")
	}
	return nil
}

func (s *Store) List(ctx context.Context, limit int) ([]approval.Approval, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, tool, action, resource_kind, resource_alias, operation_id, normalized_arguments, arguments_hash, confirmation_code_hash,
status, created_at, expires_at, executed_at, error_summary, result_summary, attempts FROM approvals ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()
	var out []approval.Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) AcquireOperationLock(ctx context.Context, resourceKind, resourceAlias, operationID string, expiresAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `DELETE FROM operation_locks WHERE expires_at <= ?`, now); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO operation_locks (resource_kind, resource_alias, operation_id, expires_at) VALUES (?, ?, ?, ?)`,
		resourceKind, resourceAlias, operationID, expiresAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("resource %s/%s already has an executing operation", resourceKind, resourceAlias)
	}
	return tx.Commit()
}

func (s *Store) ReleaseOperationLock(ctx context.Context, resourceKind, resourceAlias, operationID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM operation_locks WHERE resource_kind = ? AND resource_alias = ? AND operation_id = ?`,
		resourceKind, resourceAlias, operationID)
	return err
}

func (s *Store) CountOperationsInProgress(ctx context.Context) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM operation_locks WHERE expires_at <= ?`, now); err != nil {
		return 0, err
	}
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_locks`).Scan(&count)
	return count, err
}

func (s *Store) PruneRecords(ctx context.Context, before time.Time, minRecords int, dryRun bool) (ports.PruneRecordsResponse, error) {
	countEligible := func(table string) (int64, error) {
		var count int64
		err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE created_at < ?`, formatTime(before)).Scan(&count)
		if table == "audit_events" {
			err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE timestamp < ?`, formatTime(before)).Scan(&count)
		}
		return count, err
	}
	countTotal := func(table string) (int64, error) {
		var count int64
		err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count)
		return count, err
	}
	auditEligible, err := countEligible("audit_events")
	if err != nil {
		return ports.PruneRecordsResponse{}, err
	}
	approvalEligible, err := countEligible("approvals")
	if err != nil {
		return ports.PruneRecordsResponse{}, err
	}
	auditTotal, err := countTotal("audit_events")
	if err != nil {
		return ports.PruneRecordsResponse{}, err
	}
	approvalTotal, err := countTotal("approvals")
	if err != nil {
		return ports.PruneRecordsResponse{}, err
	}
	total := auditTotal + approvalTotal
	eligible := auditEligible + approvalEligible
	maxDelete := total - int64(minRecords)
	if maxDelete < 0 {
		maxDelete = 0
	}
	toDelete := min(eligible, maxDelete)
	out := ports.PruneRecordsResponse{Status: "simulated", RecordsToDelete: toDelete, RecordsRemaining: total - toDelete, DryRun: dryRun}
	if dryRun || toDelete == 0 {
		return out, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ports.PruneRecordsResponse{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	remaining := toDelete
	auditDelete := min(auditEligible, remaining)
	if auditDelete > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE timestamp < ? ORDER BY timestamp ASC LIMIT ?)`, formatTime(before), auditDelete); err != nil {
			return ports.PruneRecordsResponse{}, err
		}
		remaining -= auditDelete
	}
	if remaining > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM approvals WHERE id IN (SELECT id FROM approvals WHERE created_at < ? ORDER BY created_at ASC LIMIT ?)`, formatTime(before), remaining); err != nil {
			return ports.PruneRecordsResponse{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return ports.PruneRecordsResponse{}, err
	}
	out.Status = "executed"
	out.RecordsDeleted = toDelete
	return out, nil
}

func (s *Store) AppendDeployment(ctx context.Context, record deployment.HistoryRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO deployment_history
(id, application_alias, version, deployed_at, deployment_type, triggered_by, image_digest, commit_hash, status, previous_version, next_version, metadata, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.ApplicationAlias,
		record.Version,
		formatTime(record.DeployedAt),
		record.DeploymentType,
		record.TriggeredBy,
		record.ImageDigest,
		record.CommitHash,
		record.Status,
		record.PreviousVersion,
		record.NextVersion,
		record.Metadata,
		formatTime(record.CreatedAt),
	)
	return err
}

func (s *Store) ListDeployments(ctx context.Context, applicationAlias string, limit int) ([]deployment.HistoryRecord, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, application_alias, version, deployed_at, deployment_type, triggered_by, image_digest, commit_hash, status, previous_version, next_version, metadata, created_at
FROM deployment_history WHERE application_alias = ? ORDER BY deployed_at DESC LIMIT ?`, applicationAlias, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []deployment.HistoryRecord
	for rows.Next() {
		record, err := scanDeployment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (s *Store) LatestSuccessfulDeployment(ctx context.Context, applicationAlias string) (deployment.HistoryRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, application_alias, version, deployed_at, deployment_type, triggered_by, image_digest, commit_hash, status, previous_version, next_version, metadata, created_at
FROM deployment_history WHERE application_alias = ? AND status = 'success' ORDER BY deployed_at DESC LIMIT 1`, applicationAlias)
	return scanDeployment(row)
}

func (s *Store) PruneDeployments(ctx context.Context, applicationAlias string, keep int) error {
	if keep <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM deployment_history
WHERE application_alias = ? AND id NOT IN (
  SELECT id FROM deployment_history WHERE application_alias = ? ORDER BY deployed_at DESC LIMIT ?
)`, applicationAlias, applicationAlias, keep)
	return err
}

func scanDeployment(scanner interface {
	Scan(dest ...any) error
}) (deployment.HistoryRecord, error) {
	var record deployment.HistoryRecord
	var deployedAt, createdAt string
	if err := scanner.Scan(
		&record.ID,
		&record.ApplicationAlias,
		&record.Version,
		&deployedAt,
		&record.DeploymentType,
		&record.TriggeredBy,
		&record.ImageDigest,
		&record.CommitHash,
		&record.Status,
		&record.PreviousVersion,
		&record.NextVersion,
		&record.Metadata,
		&createdAt,
	); err != nil {
		return deployment.HistoryRecord{}, err
	}
	record.DeployedAt, _ = time.Parse(time.RFC3339Nano, deployedAt)
	record.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return record, nil
}

func (s *Store) AppendBackup(ctx context.Context, record backup.Record) error {
	var endTime, integrityCheckedAt any
	if record.EndTime != nil {
		endTime = formatTime(*record.EndTime)
	}
	if record.IntegrityCheckedAt != nil {
		integrityCheckedAt = formatTime(*record.IntegrityCheckedAt)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO backups
(id, backup_alias, source_alias, backend, snapshot_id, status, start_time, end_time, duration_seconds, size_bytes, integrity_verified, integrity_checked_at, error_message, metadata, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.BackupAlias,
		record.SourceAlias,
		record.Backend,
		record.SnapshotID,
		record.Status,
		formatTime(record.StartTime),
		endTime,
		record.DurationSeconds,
		record.SizeBytes,
		boolToInt(record.IntegrityVerified),
		integrityCheckedAt,
		record.ErrorMessage,
		record.Metadata,
		formatTime(record.CreatedAt),
	)
	return err
}

func (s *Store) ListBackups(ctx context.Context, filter backup.ListFilter, limit int) ([]backup.Record, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	query := `SELECT id, backup_alias, source_alias, backend, snapshot_id, status, start_time, end_time, duration_seconds, size_bytes, integrity_verified, integrity_checked_at, error_message, metadata, created_at FROM backups`
	var args []any
	switch {
	case filter.BackupID != "":
		query += ` WHERE id = ?`
		args = append(args, filter.BackupID)
	case filter.BackupAlias != "":
		query += ` WHERE backup_alias = ?`
		args = append(args, filter.BackupAlias)
	}
	query += ` ORDER BY start_time DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []backup.Record
	for rows.Next() {
		record, err := scanBackup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (s *Store) LatestBackup(ctx context.Context, backupAlias string) (backup.Record, error) {
	query := `SELECT id, backup_alias, source_alias, backend, snapshot_id, status, start_time, end_time, duration_seconds, size_bytes, integrity_verified, integrity_checked_at, error_message, metadata, created_at FROM backups`
	var args []any
	if backupAlias != "" {
		query += ` WHERE backup_alias = ?`
		args = append(args, backupAlias)
	}
	query += ` ORDER BY start_time DESC LIMIT 1`
	row := s.db.QueryRowContext(ctx, query, args...)
	return scanBackup(row)
}

func (s *Store) GetBackup(ctx context.Context, id string) (backup.Record, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, backup_alias, source_alias, backend, snapshot_id, status, start_time, end_time, duration_seconds, size_bytes, integrity_verified, integrity_checked_at, error_message, metadata, created_at FROM backups WHERE id = ?`, id)
	return scanBackup(row)
}

func (s *Store) BackupInProgress(ctx context.Context, backupAlias string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM backups WHERE backup_alias = ? AND status IN ('pending', 'running')`, backupAlias).Scan(&count)
	return count > 0, err
}

func scanBackup(scanner interface {
	Scan(dest ...any) error
}) (backup.Record, error) {
	var record backup.Record
	var status string
	var startTime, createdAt string
	var endTime, integrityCheckedAt sql.NullString
	var integrityVerified int
	if err := scanner.Scan(
		&record.ID,
		&record.BackupAlias,
		&record.SourceAlias,
		&record.Backend,
		&record.SnapshotID,
		&status,
		&startTime,
		&endTime,
		&record.DurationSeconds,
		&record.SizeBytes,
		&integrityVerified,
		&integrityCheckedAt,
		&record.ErrorMessage,
		&record.Metadata,
		&createdAt,
	); err != nil {
		return backup.Record{}, err
	}
	parsedStart, err := parseTime(startTime)
	if err != nil {
		return backup.Record{}, err
	}
	parsedCreated, err := parseTime(createdAt)
	if err != nil {
		return backup.Record{}, err
	}
	record.StartTime = parsedStart
	record.CreatedAt = parsedCreated
	record.Status = backup.Status(status)
	record.IntegrityVerified = integrityVerified == 1
	if endTime.Valid && endTime.String != "" {
		parsed, err := parseTime(endTime.String)
		if err != nil {
			return backup.Record{}, err
		}
		record.EndTime = &parsed
	}
	if integrityCheckedAt.Valid && integrityCheckedAt.String != "" {
		parsed, err := parseTime(integrityCheckedAt.String)
		if err != nil {
			return backup.Record{}, err
		}
		record.IntegrityCheckedAt = &parsed
	}
	return record, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (s *Store) Append(ctx context.Context, e audit.Event) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events
(id, timestamp, user_id, component, event_type, tool, action, arguments, risk, policy_decision, status, duration_millis, result_summary, error_summary, approval_id, operation_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Timestamp.UTC().Format(time.RFC3339Nano), e.UserID, e.Component, e.EventType, e.Tool, e.Action, e.Arguments,
		e.Risk, e.PolicyDecision, e.Status, e.DurationMillis, e.ResultSummary, e.ErrorSummary, e.ApprovalID, e.OperationID)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]audit.Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, timestamp, user_id, component, event_type, tool, action, arguments,
risk, policy_decision, status, duration_millis, result_summary, error_summary, approval_id, operation_id
FROM audit_events ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()
	var out []audit.Event
	for rows.Next() {
		var e audit.Event
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.UserID, &e.Component, &e.EventType, &e.Tool, &e.Action, &e.Arguments, &e.Risk,
			&e.PolicyDecision, &e.Status, &e.DurationMillis, &e.ResultSummary, &e.ErrorSummary, &e.ApprovalID, &e.OperationID); err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, err
		}
		e.Timestamp = parsed.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) UpsertObserved(ctx context.Context, finding alert.Finding, now time.Time) (alert.Alert, bool, error) {
	id := alertID(finding)
	stored, err := s.GetAlert(ctx, id)
	if err == nil {
		status := stored.Status
		if status != alert.StatusAcknowledged && status != alert.StatusSuppressed {
			status = alert.StatusActive
		}
		_, err = s.db.ExecContext(ctx, `UPDATE alerts SET severity = ?, status = ?, message = ?, last_observed = ?, count = count + 1, metadata = ?, updated_at = ? WHERE id = ?`,
			finding.Severity, status, finding.Message, formatTime(now), finding.Metadata, formatTime(now), id)
		if err != nil {
			return alert.Alert{}, false, err
		}
		updated, err := s.GetAlert(ctx, id)
		return updated, false, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return alert.Alert{}, false, err
	}
	a := alert.Alert{
		ID:            id,
		ResourceKind:  finding.ResourceKind,
		ResourceAlias: finding.ResourceAlias,
		Type:          finding.Type,
		Severity:      finding.Severity,
		Status:        alert.StatusNew,
		Message:       finding.Message,
		FirstObserved: now.UTC(),
		LastObserved:  now.UTC(),
		Count:         1,
		Metadata:      finding.Metadata,
		CreatedAt:     now.UTC(),
		UpdatedAt:     now.UTC(),
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO alerts
(id, resource_kind, resource_alias, alert_type, severity, status, message, first_observed, last_observed, count, metadata, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.ResourceKind, a.ResourceAlias, a.Type, a.Severity, a.Status, a.Message, formatTime(a.FirstObserved), formatTime(a.LastObserved),
		a.Count, a.Metadata, formatTime(a.CreatedAt), formatTime(a.UpdatedAt))
	return a, true, err
}

func (s *Store) ResolveMissing(ctx context.Context, observedIDs map[string]bool, now time.Time) ([]alert.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM alerts WHERE status IN ('new', 'active', 'acknowledged', 'suppressed')`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if observedIDs[id] {
			continue
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var resolved []alert.Alert
	for _, id := range ids {
		a, err := s.ResolveAlert(ctx, id, now)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, a)
	}
	return resolved, nil
}

func (s *Store) ListAlerts(ctx context.Context, filter alert.ListFilter, limit int) ([]alert.Alert, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `SELECT id, resource_kind, resource_alias, alert_type, severity, status, message, first_observed, last_observed, last_notified, count,
acknowledged_by, acknowledged_at, suppressed_until, resolved_at, metadata, created_at, updated_at FROM alerts`
	var args []any
	var where []string
	if filter.Status != "" {
		where = append(where, "status = ?")
		args = append(args, filter.Status)
	}
	if filter.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, filter.Severity)
	}
	if len(where) > 0 {
		query += " WHERE " + joinWhere(where)
	}
	query += " ORDER BY updated_at DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()
	var out []alert.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAlert(ctx context.Context, id string) (alert.Alert, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, resource_kind, resource_alias, alert_type, severity, status, message, first_observed, last_observed, last_notified, count,
acknowledged_by, acknowledged_at, suppressed_until, resolved_at, metadata, created_at, updated_at FROM alerts WHERE id = ?`, id)
	return scanAlert(row)
}

func (s *Store) CheckAlertStorage(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	id := "alert_probe_sqlite_writable"
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO alerts
(id, resource_kind, resource_alias, alert_type, severity, status, message, first_observed, last_observed, count, metadata, created_at, updated_at)
VALUES (?, 'system', 'sqlite', 'sqlite_writable_probe', 'info', 'resolved', 'SQLite write probe.', ?, ?, 1, '{}', ?, ?)`,
		id, formatTime(now), formatTime(now), formatTime(now), formatTime(now)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM alerts WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) MarkAlertNotified(ctx context.Context, id string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET last_notified = ?, status = CASE WHEN status = 'new' THEN 'active' ELSE status END, updated_at = ? WHERE id = ?`,
		formatTime(now), formatTime(now), id)
	return err
}

func (s *Store) AcknowledgeAlert(ctx context.Context, id, userID string, now time.Time) (alert.Alert, error) {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET status = ?, acknowledged_by = ?, acknowledged_at = ?, updated_at = ? WHERE id = ? AND status IN ('new', 'active')`,
		alert.StatusAcknowledged, userID, formatTime(now), formatTime(now), id)
	if err != nil {
		return alert.Alert{}, err
	}
	return s.GetAlert(ctx, id)
}

func (s *Store) SilenceAlert(ctx context.Context, id string, until time.Time, now time.Time) (alert.Alert, error) {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET status = ?, suppressed_until = ?, updated_at = ? WHERE id = ? AND status IN ('new', 'active', 'acknowledged', 'suppressed')`,
		alert.StatusSuppressed, formatTime(until), formatTime(now), id)
	if err != nil {
		return alert.Alert{}, err
	}
	return s.GetAlert(ctx, id)
}

func (s *Store) ResolveAlert(ctx context.Context, id string, now time.Time) (alert.Alert, error) {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET status = ?, resolved_at = ?, updated_at = ? WHERE id = ?`,
		alert.StatusResolved, formatTime(now), formatTime(now), id)
	if err != nil {
		return alert.Alert{}, err
	}
	return s.GetAlert(ctx, id)
}

func (s *Store) PruneResolvedAlerts(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM alerts WHERE status = ? AND updated_at < ?`, alert.StatusResolved, formatTime(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type approvalScanner interface {
	Scan(dest ...any) error
}

type alertScanner interface {
	Scan(dest ...any) error
}

func scanApproval(row approvalScanner) (approval.Approval, error) {
	var a approval.Approval
	var created, expires string
	var executed sql.NullString
	if err := row.Scan(&a.ID, &a.UserID, &a.Tool, &a.Action, &a.ResourceKind, &a.ResourceAlias, &a.OperationID, &a.NormalizedArguments, &a.ArgumentsHash, &a.ConfirmationCodeHash,
		&a.Status, &created, &expires, &executed, &a.ErrorSummary, &a.ResultSummary, &a.Attempts); err != nil {
		return approval.Approval{}, err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return approval.Approval{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return approval.Approval{}, err
	}
	a.CreatedAt = createdAt.UTC()
	a.ExpiresAt = expiresAt.UTC()
	if executed.Valid {
		executedAt, err := time.Parse(time.RFC3339Nano, executed.String)
		if err != nil {
			return approval.Approval{}, err
		}
		utc := executedAt.UTC()
		a.ExecutedAt = &utc
	}
	return a, nil
}

func scanAlert(row alertScanner) (alert.Alert, error) {
	var a alert.Alert
	var firstObserved, lastObserved, createdAt, updatedAt string
	var lastNotified, acknowledgedAt, suppressedUntil, resolvedAt sql.NullString
	if err := row.Scan(&a.ID, &a.ResourceKind, &a.ResourceAlias, &a.Type, &a.Severity, &a.Status, &a.Message, &firstObserved, &lastObserved, &lastNotified,
		&a.Count, &a.AcknowledgedBy, &acknowledgedAt, &suppressedUntil, &resolvedAt, &a.Metadata, &createdAt, &updatedAt); err != nil {
		return alert.Alert{}, err
	}
	var err error
	if a.FirstObserved, err = parseTime(firstObserved); err != nil {
		return alert.Alert{}, err
	}
	if a.LastObserved, err = parseTime(lastObserved); err != nil {
		return alert.Alert{}, err
	}
	if a.CreatedAt, err = parseTime(createdAt); err != nil {
		return alert.Alert{}, err
	}
	if a.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return alert.Alert{}, err
	}
	if lastNotified.Valid {
		parsed, err := parseTime(lastNotified.String)
		if err != nil {
			return alert.Alert{}, err
		}
		a.LastNotified = &parsed
	}
	if acknowledgedAt.Valid {
		parsed, err := parseTime(acknowledgedAt.String)
		if err != nil {
			return alert.Alert{}, err
		}
		a.AcknowledgedAt = &parsed
	}
	if suppressedUntil.Valid {
		parsed, err := parseTime(suppressedUntil.String)
		if err != nil {
			return alert.Alert{}, err
		}
		a.SuppressedUntil = &parsed
	}
	if resolvedAt.Valid {
		parsed, err := parseTime(resolvedAt.String)
		if err != nil {
			return alert.Alert{}, err
		}
		a.ResolvedAt = &parsed
	}
	return a, nil
}

func alertID(f alert.Finding) string {
	return fmt.Sprintf("alert_%s_%s_%s", f.ResourceKind, f.ResourceAlias, f.Type)
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err == nil {
		return t.UTC(), nil
	}
	t, err = time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func joinWhere(parts []string) string {
	out := ""
	for i, part := range parts {
		if i > 0 {
			out += " AND "
		}
		out += part
	}
	return out
}
