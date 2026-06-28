use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppSettings {
    pub theme: String,
    pub default_duration_seconds: u64,
    pub default_networking_enabled: bool,
    pub virustotal_api_key: String,
    pub allow_unknown_file_upload: bool,
    pub keep_raw_run_folders: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            default_duration_seconds: 60,
            default_networking_enabled: false,
            virustotal_api_key: String::new(),
            allow_unknown_file_upload: false,
            keep_raw_run_folders: true,
        }
    }
}

fn settings_path() -> Result<PathBuf, String> {
    let base = dirs::config_dir().ok_or("Unable to locate config directory")?.join("SandboxAnalyzer");
    fs::create_dir_all(&base).map_err(|e| format!("Unable to create config directory: {e}"))?;
    Ok(base.join("settings.json"))
}

#[tauri::command]
pub fn get_settings() -> Result<AppSettings, String> {
    let path = settings_path()?;
    if !path.exists() {
        let settings = AppSettings::default();
        save_settings(settings.clone())?;
        return Ok(settings);
    }
    let data = fs::read_to_string(path).map_err(|e| format!("Unable to read settings: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("Unable to parse settings: {e}"))
}

#[tauri::command]
pub fn save_settings(settings: AppSettings) -> Result<(), String> {
    let path = settings_path()?;
    let json = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| format!("Unable to write settings: {e}"))
}
