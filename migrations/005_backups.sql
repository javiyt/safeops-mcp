CREATE TABLE IF NOT EXISTS backups (
  id TEXT PRIMARY KEY,
  backup_alias TEXT NOT NULL,
  source_alias TEXT NOT NULL DEFAULT '',
  backend TEXT NOT NULL,
  snapshot_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT,
  duration_seconds INTEGER NOT NULL DEFAULT 0,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  integrity_verified INTEGER NOT NULL DEFAULT 0,
  integrity_checked_at TEXT,
  error_message TEXT NOT NULL DEFAULT '',
  metadata TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_backups_alias_start
ON backups(backup_alias, start_time DESC);

CREATE INDEX IF NOT EXISTS idx_backups_status
ON backups(backup_alias, status, start_time DESC);
