use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs, io::Read, path::{Path, PathBuf}, process::Command, thread, time::Duration};
use sysinfo::System;
use walkdir::WalkDir;

#[derive(Debug, Deserialize)]
struct Manifest {
    run_id: String,
    sample_file: String,
    duration_seconds: u64,
    networking_enabled: bool,
    version_label: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct FileRecord {
    path: String,
    size_bytes: u64,
    sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProcessMetric {
    timestamp: String,
    process_name: String,
    pid: String,
    cpu_percent: f32,
    memory_kb: u64,
}

#[derive(Debug, Serialize)]
struct Summary {
    run_id: String,
    started_at: String,
    ended_at: String,
    sample_file: String,
    duration_seconds: u64,
    networking_enabled: bool,
    version_label: Option<String>,
    execution_status: String,
    file_changes: serde_json::Value,
    registry_changes: serde_json::Value,
    network_connections: serde_json::Value,
    firewall_rules_before: serde_json::Value,
    firewall_rules_after: serde_json::Value,
    process_metrics: Vec<ProcessMetric>,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let manifest_path = arg_value(&args, "--manifest").unwrap_or_else(|| "C:\\SandboxInput\\manifest.json".into());
    let output_dir = PathBuf::from(arg_value(&args, "--output").unwrap_or_else(|| "C:\\SandboxOutput".into()));
    fs::create_dir_all(&output_dir)?;
    log(&output_dir, "agent started")?;

    let manifest: Manifest = serde_json::from_str(&fs::read_to_string(&manifest_path).context("read manifest")?)?;
    let started_at = Utc::now().to_rfc3339();

    let watched_paths = vec![
        PathBuf::from("C:\\Program Files"),
        PathBuf::from("C:\\Program Files (x86)"),
        PathBuf::from("C:\\ProgramData"),
        PathBuf::from("C:\\Windows\\Temp"),
        PathBuf::from("C:\\Users\\WDAGUtilityAccount\\AppData\\Local"),
        PathBuf::from("C:\\Users\\WDAGUtilityAccount\\AppData\\Roaming"),
    ];

    log(&output_dir, "snapshot before")?;
    let files_before = snapshot_files(&watched_paths);
    let reg_before = registry_snapshot(&output_dir, "registry-before.json")?;
    let fw_before = powershell_json("Get-NetFirewallRule | Select-Object DisplayName,Enabled,Direction,Action,Profile,Program,Service | ConvertTo-Json -Depth 4").unwrap_or(serde_json::Value::Null);

    let sample_path = format!("C:\\SandboxInput\\{}", manifest.sample_file);
    log(&output_dir, &format!("executing {sample_path}"))?;
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &format!("Start-Process -FilePath '{}' -PassThru", sample_path.replace("'", "''"))])
        .spawn()
        .context("launch sample")?;

    let mut metrics = Vec::new();
    for _ in 0..manifest.duration_seconds {
        collect_process_metrics(&mut metrics);
        thread::sleep(Duration::from_secs(1));
    }

    let _ = child.kill();
    let _ = Command::new("powershell.exe").args(["-NoProfile", "-Command", "Get-Process | Where-Object {$_.Path -like 'C:\\SandboxInput*'} | Stop-Process -Force"]).status();

    log(&output_dir, "snapshot after")?;
    let files_after = snapshot_files(&watched_paths);
    let reg_after = registry_snapshot(&output_dir, "registry-after.json")?;
    let fw_after = powershell_json("Get-NetFirewallRule | Select-Object DisplayName,Enabled,Direction,Action,Profile,Program,Service | ConvertTo-Json -Depth 4").unwrap_or(serde_json::Value::Null);
    let network = powershell_json("Get-NetTCPConnection | Select-Object CreationTime,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Depth 4").unwrap_or(serde_json::Value::Null);

    let summary = Summary {
        run_id: manifest.run_id,
        started_at,
        ended_at: Utc::now().to_rfc3339(),
        sample_file: manifest.sample_file,
        duration_seconds: manifest.duration_seconds,
        networking_enabled: manifest.networking_enabled,
        version_label: manifest.version_label,
        execution_status: "completed".into(),
        file_changes: diff_files(files_before, files_after),
        registry_changes: diff_registry(reg_before, reg_after),
        network_connections: normalise_array(network),
        firewall_rules_before: fw_before,
        firewall_rules_after: fw_after,
        process_metrics: metrics,
    };

    fs::write(output_dir.join("summary.json"), serde_json::to_string_pretty(&summary)?)?;
    log(&output_dir, "agent finished")?;
    Ok(())
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == key).map(|w| w[1].clone())
}

fn log(output: &Path, message: &str) -> Result<()> {
    let line = format!("{} {}\n", Utc::now().to_rfc3339(), message);
    fs::OpenOptions::new().create(true).append(true).open(output.join("agent.log"))?.write_all_ext(line.as_bytes())?;
    Ok(())
}

trait WriteAllExt { fn write_all_ext(&mut self, buf: &[u8]) -> std::io::Result<()>; }
impl WriteAllExt for fs::File { fn write_all_ext(&mut self, buf: &[u8]) -> std::io::Result<()> { use std::io::Write; self.write_all(buf) } }

fn snapshot_files(paths: &[PathBuf]) -> BTreeMap<String, FileRecord> {
    let mut map = BTreeMap::new();
    for root in paths {
        if !root.exists() { continue; }
        for entry in WalkDir::new(root).max_depth(8).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() { continue; }
            let path = entry.path().display().to_string();
            if path.contains("C:\\ProgramData\\Microsoft\\Windows Defender") { continue; }
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let sha256 = if size <= 50 * 1024 * 1024 { hash_file(entry.path()).ok() } else { None };
            map.insert(path.clone(), FileRecord { path, size_bytes: size, sha256 });
        }
    }
    map
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn diff_files(before: BTreeMap<String, FileRecord>, after: BTreeMap<String, FileRecord>) -> serde_json::Value {
    let before_keys: BTreeSet<_> = before.keys().cloned().collect();
    let after_keys: BTreeSet<_> = after.keys().cloned().collect();
    let created: Vec<_> = after_keys.difference(&before_keys).filter_map(|k| after.get(k)).cloned().collect();
    let deleted: Vec<_> = before_keys.difference(&after_keys).filter_map(|k| before.get(k)).cloned().collect();
    let changed: Vec<_> = after_keys.intersection(&before_keys).filter_map(|k| {
        let b = before.get(k)?; let a = after.get(k)?;
        if b.sha256 != a.sha256 || b.size_bytes != a.size_bytes { Some(a.clone()) } else { None }
    }).collect();
    serde_json::json!({"created": created, "deleted": deleted, "changed": changed})
}

fn registry_snapshot(output: &Path, file_name: &str) -> Result<serde_json::Value> {
    let script = r#"$roots = @(
'HKCU:\Software',
'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
'HKLM:\System\CurrentControlSet\Services',
'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
)
$result = foreach ($root in $roots) {
  if (Test-Path $root) {
    Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
      $item = $_
      $props = Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue
      foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -notmatch '^PS') {
          [pscustomobject]@{ key_path=$item.Name; value_name=$p.Name; value_data=[string]$p.Value }
        }
      }
    }
  }
}
$result | ConvertTo-Json -Depth 4"#;
    let value = powershell_json(script).unwrap_or(serde_json::json!([]));
    fs::write(output.join(file_name), serde_json::to_string_pretty(&value)?)?;
    Ok(normalise_array(value))
}

fn diff_registry(before: serde_json::Value, after: serde_json::Value) -> serde_json::Value {
    let b = before.as_array().cloned().unwrap_or_default();
    let a = after.as_array().cloned().unwrap_or_default();
    let key = |v: &serde_json::Value| format!("{}|{}|{}", v.get("key_path").and_then(|x| x.as_str()).unwrap_or(""), v.get("value_name").and_then(|x| x.as_str()).unwrap_or(""), v.get("value_data").and_then(|x| x.as_str()).unwrap_or(""));
    let bset: BTreeSet<String> = b.iter().map(key).collect();
    let created_or_changed: Vec<_> = a.into_iter().filter(|v| !bset.contains(&key(v))).collect();
    serde_json::json!({"created_or_changed": created_or_changed})
}

fn powershell_json(script: &str) -> Result<serde_json::Value> {
    let output = Command::new("powershell.exe").args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]).output()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { return Ok(serde_json::json!([])); }
    let value: serde_json::Value = serde_json::from_str(&text)?;
    Ok(value)
}

fn normalise_array(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(_) => value,
        serde_json::Value::Null => serde_json::json!([]),
        other => serde_json::json!([other]),
    }
}

fn collect_process_metrics(metrics: &mut Vec<ProcessMetric>) {
    let mut sys = System::new_all();
    sys.refresh_all();
    let timestamp = Utc::now().to_rfc3339();
    for (pid, proc_) in sys.processes() {
        let name = proc_.name().to_string();
        if name.eq_ignore_ascii_case("sandbox-agent.exe") || name.eq_ignore_ascii_case("sample.exe") || proc_.exe().map(|p| p.display().to_string().contains("SandboxInput")).unwrap_or(false) {
            metrics.push(ProcessMetric {
                timestamp: timestamp.clone(),
                process_name: name,
                pid: pid.to_string(),
                cpu_percent: proc_.cpu_usage(),
                memory_kb: proc_.memory(),
            });
        }
    }
}
