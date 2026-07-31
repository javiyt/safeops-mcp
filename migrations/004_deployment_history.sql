CREATE TABLE IF NOT EXISTS deployment_history (
  id TEXT PRIMARY KEY,
  application_alias TEXT NOT NULL,
  version TEXT NOT NULL,
  deployed_at TEXT NOT NULL,
  deployment_type TEXT NOT NULL,
  triggered_by TEXT NOT NULL,
  image_digest TEXT NOT NULL DEFAULT '',
  commit_hash TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  previous_version TEXT NOT NULL DEFAULT '',
  next_version TEXT NOT NULL DEFAULT '',
  metadata TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_deployment_history_application
ON deployment_history(application_alias, deployed_at DESC);

CREATE INDEX IF NOT EXISTS idx_deployment_history_success
ON deployment_history(application_alias, status, deployed_at DESC);
