PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  original_filename TEXT NOT NULL,
  sha256 TEXT NOT NULL UNIQUE,
  sha1 TEXT,
  md5 TEXT,
  file_size INTEGER,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  publisher TEXT,
  signature_status TEXT
);
CREATE TABLE IF NOT EXISTS virustotal_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sample_id INTEGER NOT NULL,
  lookup_time TEXT NOT NULL,
  malicious_count INTEGER,
  suspicious_count INTEGER,
  harmless_count INTEGER,
  undetected_count INTEGER,
  raw_json TEXT NOT NULL,
  FOREIGN KEY(sample_id) REFERENCES samples(id)
);
CREATE TABLE IF NOT EXISTS analysis_runs (
  id TEXT PRIMARY KEY,
  sample_id INTEGER NOT NULL,
  version_label TEXT,
  sandbox_profile TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  duration_seconds INTEGER NOT NULL,
  status TEXT NOT NULL,
  notes TEXT,
  raw_summary_json TEXT,
  FOREIGN KEY(sample_id) REFERENCES samples(id)
);
CREATE TABLE IF NOT EXISTS resource_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  process_name TEXT,
  pid INTEGER,
  cpu_percent REAL,
  memory_working_set_mb REAL,
  disk_read_bytes INTEGER,
  disk_write_bytes INTEGER,
  FOREIGN KEY(run_id) REFERENCES analysis_runs(id)
);
CREATE TABLE IF NOT EXISTS file_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  path TEXT NOT NULL,
  size_bytes INTEGER,
  sha256 TEXT,
  FOREIGN KEY(run_id) REFERENCES analysis_runs(id)
);
CREATE TABLE IF NOT EXISTS registry_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  key_path TEXT NOT NULL,
  value_name TEXT,
  value_data TEXT,
  FOREIGN KEY(run_id) REFERENCES analysis_runs(id)
);
CREATE TABLE IF NOT EXISTS network_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  timestamp TEXT,
  protocol TEXT,
  local_address TEXT,
  local_port INTEGER,
  remote_address TEXT,
  remote_port INTEGER,
  state TEXT,
  owning_process TEXT,
  FOREIGN KEY(run_id) REFERENCES analysis_runs(id)
);
CREATE TABLE IF NOT EXISTS firewall_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  rule_name TEXT,
  action TEXT,
  direction TEXT,
  protocol TEXT,
  local_port TEXT,
  remote_address TEXT,
  enabled TEXT,
  FOREIGN KEY(run_id) REFERENCES analysis_runs(id)
);
