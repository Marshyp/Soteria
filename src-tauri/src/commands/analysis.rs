use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CompareRequest {
    pub baseline: serde_json::Value,
    pub candidate: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct CompareResult {
    pub file_created_delta: i64,
    pub registry_delta: i64,
    pub network_delta: i64,
    pub summary: Vec<String>,
}

#[tauri::command]
pub fn compare_runs(request: CompareRequest) -> Result<CompareResult, String> {
    let b_files = count(&request.baseline, "/file_changes/created");
    let c_files = count(&request.candidate, "/file_changes/created");
    let b_reg = count(&request.baseline, "/registry_changes/created_or_changed");
    let c_reg = count(&request.candidate, "/registry_changes/created_or_changed");
    let b_net = count(&request.baseline, "/network_connections");
    let c_net = count(&request.candidate, "/network_connections");

    let mut summary = Vec::new();
    summary.push(format!("File creations changed by {}", c_files as i64 - b_files as i64));
    summary.push(format!("Registry changes changed by {}", c_reg as i64 - b_reg as i64));
    summary.push(format!("Network observations changed by {}", c_net as i64 - b_net as i64));

    Ok(CompareResult {
        file_created_delta: c_files as i64 - b_files as i64,
        registry_delta: c_reg as i64 - b_reg as i64,
        network_delta: c_net as i64 - b_net as i64,
        summary,
    })
}

fn count(v: &serde_json::Value, ptr: &str) -> usize {
    v.pointer(ptr).and_then(|x| x.as_array()).map(|x| x.len()).unwrap_or(0)
}
