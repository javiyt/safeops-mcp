CREATE TABLE IF NOT EXISTS operation_locks (
  resource_kind TEXT NOT NULL,
  resource_alias TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (resource_kind, resource_alias)
);
