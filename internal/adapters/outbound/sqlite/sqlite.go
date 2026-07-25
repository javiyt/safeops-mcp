package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/javiyt/safeops-mcp/internal/domain/approval"
	"github.com/javiyt/safeops-mcp/internal/domain/audit"
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
	return nil
}

func (s *Store) Create(ctx context.Context, a approval.Approval) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO approvals
(id, user_id, tool, action, normalized_arguments, arguments_hash, confirmation_code_hash, status, created_at, expires_at, error_summary, result_summary, attempts)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.UserID, a.Tool, a.Action, a.NormalizedArguments, a.ArgumentsHash, a.ConfirmationCodeHash, a.Status,
		a.CreatedAt.UTC().Format(time.RFC3339Nano), a.ExpiresAt.UTC().Format(time.RFC3339Nano), a.ErrorSummary, a.ResultSummary, a.Attempts)
	return err
}

func (s *Store) Get(ctx context.Context, id string) (approval.Approval, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, user_id, tool, action, normalized_arguments, arguments_hash, confirmation_code_hash,
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
	row := tx.QueryRowContext(ctx, `SELECT id, user_id, tool, action, normalized_arguments, arguments_hash, confirmation_code_hash,
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
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, tool, action, normalized_arguments, arguments_hash, confirmation_code_hash,
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

type approvalScanner interface {
	Scan(dest ...any) error
}

func scanApproval(row approvalScanner) (approval.Approval, error) {
	var a approval.Approval
	var created, expires string
	var executed sql.NullString
	if err := row.Scan(&a.ID, &a.UserID, &a.Tool, &a.Action, &a.NormalizedArguments, &a.ArgumentsHash, &a.ConfirmationCodeHash,
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
