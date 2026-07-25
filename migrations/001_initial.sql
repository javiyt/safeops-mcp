CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  action TEXT NOT NULL,
  normalized_arguments TEXT NOT NULL,
  arguments_hash TEXT NOT NULL,
  confirmation_code_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  executed_at TEXT,
  error_summary TEXT NOT NULL DEFAULT '',
  result_summary TEXT NOT NULL DEFAULT '',
  attempts INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  user_id TEXT NOT NULL,
  component TEXT NOT NULL,
  event_type TEXT NOT NULL,
  tool TEXT NOT NULL,
  action TEXT NOT NULL,
  arguments TEXT NOT NULL,
  risk TEXT NOT NULL,
  policy_decision TEXT NOT NULL,
  status TEXT NOT NULL,
  duration_millis INTEGER NOT NULL,
  result_summary TEXT NOT NULL,
  error_summary TEXT NOT NULL,
  approval_id TEXT NOT NULL,
  operation_id TEXT NOT NULL
);
