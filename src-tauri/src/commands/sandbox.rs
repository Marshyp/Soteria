use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}, process::Command};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct LaunchRequest {
    pub sample_path: String,
    pub duration_seconds: u64,
    pub networking_enabled: bool,
    pub version_label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LaunchResult {
    pub run_id: String,
    pub run_folder: String,
    pub wsb_path: String,
    pub output_folder: String,
    pub launched: bool,
}

fn runs_root() -> Result<PathBuf, String> {
    let base = dirs::data_dir().ok_or("Unable to locate data directory")?.join("SandboxAnalyzer").join("runs");
    fs::create_dir_all(&base).map_err(|e| format!("Unable to create runs directory: {e}"))?;
    Ok(base)
}

#[tauri::command]
pub fn prepare_and_launch_sandbox(request: LaunchRequest) -> Result<LaunchResult, String> {
    let sample_path = PathBuf::from(&request.sample_path);
    if !sample_path.exists() { return Err("Selected file does not exist".into()); }

    let run_id = Uuid::new_v4().to_string();
    let run_folder = runs_root()?.join(&run_id);
    let input = run_folder.join("input");
    let agent = run_folder.join("agent");
    let output = run_folder.join("output");
    fs::create_dir_all(&input).map_err(|e| e.to_string())?;
    fs::create_dir_all(&agent).map_err(|e| e.to_string())?;
    fs::create_dir_all(&output).map_err(|e| e.to_string())?;

    let file_name = sample_path.file_name().ok_or("Invalid sample filename")?.to_string_lossy().to_string();
    fs::copy(&sample_path, input.join(&file_name)).map_err(|e| format!("Unable to copy sample: {e}"))?;

    let manifest = serde_json::json!({
        "run_id": run_id,
        "sample_file": file_name,
        "duration_seconds": request.duration_seconds,
        "networking_enabled": request.networking_enabled,
        "version_label": request.version_label,
        "created_at": Utc::now().to_rfc3339()
    });
    fs::write(input.join("manifest.json"), serde_json::to_string_pretty(&manifest).unwrap()).map_err(|e| e.to_string())?;

    write_bootstrap(&agent)?;
    let bundled_agent = current_exe_sibling("sandbox-agent.exe");
    if bundled_agent.exists() {
        fs::copy(&bundled_agent, agent.join("sandbox-agent.exe")).map_err(|e| format!("Unable to copy sandbox-agent.exe: {e}"))?;
    } else {
        fs::write(agent.join("README-agent-missing.txt"), "Build sandbox-agent and copy sandbox-agent.exe into this folder or next to the host executable before launching real analyses.\n").map_err(|e| e.to_string())?;
    }

    let wsb_path = run_folder.join(format!("{run_id}.wsb"));
    fs::write(&wsb_path, generate_wsb(&input, &agent, &output, request.networking_enabled)?).map_err(|e| e.to_string())?;

    let status = Command::new("cmd")
        .args(["/C", "start", "", &wsb_path.display().to_string()])
        .status()
        .map_err(|e| format!("Unable to launch Windows Sandbox: {e}"))?;

    Ok(LaunchResult {
        run_id,
        run_folder: run_folder.display().to_string(),
        wsb_path: wsb_path.display().to_string(),
        output_folder: output.display().to_string(),
        launched: status.success(),
    })
}

fn current_exe_sibling(name: &str) -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(|x| x.join(name))).unwrap_or_else(|| PathBuf::from(name))
}

fn write_bootstrap(agent_dir: &Path) -> Result<(), String> {
    let ps1 = r#"$ErrorActionPreference = 'Continue'
$agent = 'C:\SandboxAgent\sandbox-agent.exe'
$out = 'C:\SandboxOutput\bootstrap.log'
"Starting Sandbox Analyzer bootstrap at $(Get-Date -Format o)" | Out-File -FilePath $out -Encoding utf8
if (Test-Path $agent) {
  Start-Process -FilePath $agent -ArgumentList @('--manifest','C:\SandboxInput\manifest.json','--output','C:\SandboxOutput') -Wait -NoNewWindow
} else {
  "sandbox-agent.exe not found" | Out-File -FilePath $out -Append -Encoding utf8
}
"Bootstrap finished at $(Get-Date -Format o)" | Out-File -FilePath $out -Append -Encoding utf8
"#;
    fs::write(agent_dir.join("bootstrap.ps1"), ps1).map_err(|e| format!("Unable to write bootstrap.ps1: {e}"))
}

fn generate_wsb(input: &Path, agent: &Path, output: &Path, networking: bool) -> Result<String, String> {
    let networking_value = if networking { "Enable" } else { "Disable" };
    Ok(format!(r#"<Configuration>
  <Networking>{networking_value}</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <MappedFolders>
    <MappedFolder><HostFolder>{}</HostFolder><SandboxFolder>C:\SandboxInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>{}</HostFolder><SandboxFolder>C:\SandboxAgent</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>{}</HostFolder><SandboxFolder>C:\SandboxOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SandboxAgent\bootstrap.ps1</Command></LogonCommand>
</Configuration>"#, input.display(), agent.display(), output.display()))
}
