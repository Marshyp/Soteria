use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

fn db_path() -> Result<PathBuf, String> {
    let base = dirs::data_dir().ok_or("Unable to locate data directory")?.join("SandboxAnalyzer");
    fs::create_dir_all(&base).map_err(|e| format!("Unable to create data directory: {e}"))?;
    Ok(base.join("sandbox-analyzer.sqlite"))
}

fn open_db() -> Result<Connection, String> {
    let conn = Connection::open(db_path()?).map_err(|e| format!("Unable to open database: {e}"))?;
    conn.execute_batch(include_str!("../../db/schema.sql")).map_err(|e| format!("Unable to initialise schema: {e}"))?;
    Ok(conn)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SampleInput {
    pub original_filename: String,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub file_size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IngestRequest {
    pub run_id: String,
    pub sample: SampleInput,
    pub version_label: Option<String>,
    pub sandbox_profile: String,
    pub duration_seconds: u64,
    pub status: String,
    pub raw_summary_json: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct RunListItem {
    pub id: String,
    pub original_filename: String,
    pub sha256: String,
    pub version_label: Option<String>,
    pub sandbox_profile: String,
    pub started_at: String,
    pub status: String,
}

#[tauri::command]
pub fn init_database() -> Result<String, String> {
    let _ = open_db()?;
    Ok(db_path()?.display().to_string())
}

#[tauri::command]
pub fn clear_database() -> Result<(), String> {
    let path = db_path()?;
    if path.exists() {
        fs::remove_file(path).map_err(|e| format!("Unable to remove database: {e}"))?;
    }
    let _ = open_db()?;
    Ok(())
}

#[tauri::command]
pub fn ingest_run(request: IngestRequest) -> Result<(), String> {
    let conn = open_db()?;
    let now = Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO samples (original_filename, sha256, sha1, md5, file_size, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(sha256) DO UPDATE SET last_seen=excluded.last_seen",
        params![request.sample.original_filename, request.sample.sha256, request.sample.sha1, request.sample.md5, request.sample.file_size as i64, now],
    ).map_err(|e| format!("Unable to upsert sample: {e}"))?;

    let sample_id: i64 = conn.query_row(
        "SELECT id FROM samples WHERE sha256=?1",
        params![request.sample.sha256],
        |row| row.get(0),
    ).map_err(|e| format!("Unable to retrieve sample id: {e}"))?;

    conn.execute(
        "INSERT OR REPLACE INTO analysis_runs (id, sample_id, version_label, sandbox_profile, started_at, ended_at, duration_seconds, status, raw_summary_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8)",
        params![request.run_id, sample_id, request.version_label, request.sandbox_profile, now, request.duration_seconds as i64, request.status, request.raw_summary_json.to_string()],
    ).map_err(|e| format!("Unable to insert analysis run: {e}"))?;

    ingest_summary_tables(&conn, &request.run_id, &request.raw_summary_json)?;
    Ok(())
}

fn ingest_summary_tables(conn: &Connection, run_id: &str, raw: &serde_json::Value) -> Result<(), String> {
    if let Some(files) = raw.pointer("/file_changes/created").and_then(|v| v.as_array()) {
        for f in files {
            conn.execute(
                "INSERT INTO file_events (run_id, operation, path, size_bytes, sha256) VALUES (?1, 'created', ?2, ?3, ?4)",
                params![run_id, f.get("path").and_then(|x| x.as_str()).unwrap_or_default(), f.get("size_bytes").and_then(|x| x.as_i64()), f.get("sha256").and_then(|x| x.as_str())],
            ).map_err(|e| format!("Unable to insert file event: {e}"))?;
        }
    }
    if let Some(regs) = raw.pointer("/registry_changes/created_or_changed").and_then(|v| v.as_array()) {
        for r in regs {
            conn.execute(
                "INSERT INTO registry_events (run_id, operation, key_path, value_name, value_data) VALUES (?1, 'created_or_changed', ?2, ?3, ?4)",
                params![run_id, r.get("key_path").and_then(|x| x.as_str()).unwrap_or_default(), r.get("value_name").and_then(|x| x.as_str()), r.get("value_data").and_then(|x| x.as_str())],
            ).map_err(|e| format!("Unable to insert registry event: {e}"))?;
        }
    }
    if let Some(nets) = raw.pointer("/network_connections").and_then(|v| v.as_array()) {
        for n in nets {
            conn.execute(
                "INSERT INTO network_events (run_id, timestamp, protocol, local_address, local_port, remote_address, remote_port, state, owning_process) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![run_id, n.get("timestamp").and_then(|x| x.as_str()), n.get("protocol").and_then(|x| x.as_str()), n.get("local_address").and_then(|x| x.as_str()), n.get("local_port").and_then(|x| x.as_i64()), n.get("remote_address").and_then(|x| x.as_str()), n.get("remote_port").and_then(|x| x.as_i64()), n.get("state").and_then(|x| x.as_str()), n.get("owning_process").and_then(|x| x.as_str())],
            ).map_err(|e| format!("Unable to insert network event: {e}"))?;
        }
    }
    Ok(())
}

#[tauri::command]
pub fn list_runs() -> Result<Vec<RunListItem>, String> {
    let conn = open_db()?;
    let mut stmt = conn.prepare(
        "SELECT r.id, s.original_filename, s.sha256, r.version_label, r.sandbox_profile, r.started_at, r.status
         FROM analysis_runs r JOIN samples s ON s.id = r.sample_id
         ORDER BY r.started_at DESC LIMIT 100"
    ).map_err(|e| e.to_string())?;

    let rows = stmt.query_map([], |row| Ok(RunListItem {
        id: row.get(0)?,
        original_filename: row.get(1)?,
        sha256: row.get(2)?,
        version_label: row.get(3)?,
        sandbox_profile: row.get(4)?,
        started_at: row.get(5)?,
        status: row.get(6)?,
    })).map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for row in rows { out.push(row.map_err(|e| e.to_string())?); }
    Ok(out)
}

#[tauri::command]
pub fn get_run(run_id: String) -> Result<serde_json::Value, String> {
    let conn = open_db()?;
    let raw: String = conn.query_row(
        "SELECT raw_summary_json FROM analysis_runs WHERE id=?1",
        params![run_id],
        |row| row.get(0),
    ).map_err(|e| format!("Run not found: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("Stored run JSON is invalid: {e}"))
}
