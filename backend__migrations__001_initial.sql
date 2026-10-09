CREATE TABLE IF NOT EXISTS targets (
  id CHAR(36) PRIMARY KEY,
  name VARCHAR(160) NOT NULL,
  kind VARCHAR(32) NOT NULL DEFAULT 'website',
  url VARCHAR(2048) NOT NULL,
  scope_notes TEXT NOT NULL,
  authorization_ref VARCHAR(255) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  INDEX idx_targets_enabled (enabled)
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id CHAR(36) PRIMARY KEY,
  target_id CHAR(36) NOT NULL,
  status VARCHAR(32) NOT NULL,
  check_family VARCHAR(64) NOT NULL DEFAULT 'safe_web_posture',
  summary TEXT,
  started_at DATETIME,
  finished_at DATETIME,
  created_at DATETIME NOT NULL,
  CONSTRAINT fk_scan_target FOREIGN KEY (target_id) REFERENCES targets(id),
  INDEX idx_scan_created (created_at),
  INDEX idx_scan_target (target_id)
);

CREATE TABLE IF NOT EXISTS findings (
  id CHAR(36) PRIMARY KEY,
  target_id CHAR(36) NOT NULL,
  scan_job_id CHAR(36),
  title VARCHAR(255) NOT NULL,
  severity VARCHAR(16) NOT NULL,
  confidence VARCHAR(16) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'open',
  evidence TEXT NOT NULL,
  remediation TEXT NOT NULL,
  risk_score DECIMAL(6,2) NOT NULL DEFAULT 0,
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  CONSTRAINT fk_finding_target FOREIGN KEY (target_id) REFERENCES targets(id),
  CONSTRAINT fk_finding_scan FOREIGN KEY (scan_job_id) REFERENCES scan_jobs(id),
  INDEX idx_finding_status (status),
  INDEX idx_finding_severity (severity)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id CHAR(36) PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  actor VARCHAR(255) NOT NULL,
  target_id CHAR(36),
  detail TEXT NOT NULL,
  created_at DATETIME NOT NULL,
  INDEX idx_audit_created (created_at),
  INDEX idx_audit_target (target_id)
);
