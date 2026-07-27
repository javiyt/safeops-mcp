CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  resource_kind TEXT NOT NULL,
  resource_alias TEXT NOT NULL,
  alert_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT NOT NULL,
  first_observed TEXT NOT NULL,
  last_observed TEXT NOT NULL,
  last_notified TEXT,
  count INTEGER NOT NULL DEFAULT 1,
  acknowledged_by TEXT NOT NULL DEFAULT '',
  acknowledged_at TEXT,
  suppressed_until TEXT,
  resolved_at TEXT,
  metadata TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_open_key
ON alerts(resource_kind, resource_alias, alert_type)
WHERE status IN ('new', 'active', 'acknowledged', 'suppressed');

CREATE INDEX IF NOT EXISTS idx_alerts_status
ON alerts(status, severity, updated_at);
