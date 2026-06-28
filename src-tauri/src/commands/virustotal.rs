use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct VtEnvelope {
    data: Option<VtData>,
}

#[derive(Debug, Deserialize)]
struct VtData {
    attributes: VtAttributes,
}

#[derive(Debug, Deserialize)]
struct VtAttributes {
    last_analysis_stats: Option<VtStats>,
    reputation: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VtStats {
    pub harmless: Option<u64>,
    pub malicious: Option<u64>,
    pub suspicious: Option<u64>,
    pub undetected: Option<u64>,
    pub timeout: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct VirusTotalResult {
    pub found: bool,
    pub sha256: String,
    pub stats: Option<VtStats>,
    pub reputation: Option<i64>,
    pub raw_json: serde_json::Value,
}

#[tauri::command]
pub async fn lookup_hash(api_key: String, sha256: String) -> Result<VirusTotalResult, String> {
    if api_key.trim().is_empty() {
        return Err("VirusTotal API key is not configured".into());
    }

    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .header("x-apikey", api_key)
        .send()
        .await
        .map_err(|e| format!("VirusTotal request failed: {e}"))?;

    let status = response.status();
    let raw: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("VirusTotal response was not valid JSON: {e}"))?;

    if status.as_u16() == 404 {
        return Ok(VirusTotalResult { found: false, sha256, stats: None, reputation: None, raw_json: raw });
    }
    if !status.is_success() {
        return Err(format!("VirusTotal returned HTTP {status}: {raw}"));
    }

    let parsed: VtEnvelope = serde_json::from_value(raw.clone())
        .map_err(|e| format!("Unable to parse VirusTotal response: {e}"))?;
    let Some(data) = parsed.data else {
        return Ok(VirusTotalResult { found: false, sha256, stats: None, reputation: None, raw_json: raw });
    };

    Ok(VirusTotalResult {
        found: true,
        sha256,
        stats: data.attributes.last_analysis_stats,
        reputation: data.attributes.reputation,
        raw_json: raw,
    })
}
