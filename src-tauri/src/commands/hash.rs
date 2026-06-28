use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use md5::Md5;
use std::{fs::File, io::{BufReader, Read}, path::PathBuf};

#[derive(Debug, Serialize)]
pub struct HashResult {
    pub path: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

#[tauri::command]
pub fn hash_file(path: String) -> Result<HashResult, String> {
    let path_buf = PathBuf::from(&path);
    let file = File::open(&path_buf).map_err(|e| format!("Unable to open file: {e}"))?;
    let metadata = file.metadata().map_err(|e| format!("Unable to read metadata: {e}"))?;
    let mut reader = BufReader::new(file);

    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut md5 = Md5::new();
    let mut buffer = [0u8; 1024 * 128];

    loop {
        let read = reader.read(&mut buffer).map_err(|e| format!("Unable to read file: {e}"))?;
        if read == 0 { break; }
        sha256.update(&buffer[..read]);
        sha1.update(&buffer[..read]);
        md5.update(&buffer[..read]);
    }

    Ok(HashResult {
        path: path.clone(),
        file_name: path_buf.file_name().unwrap_or_default().to_string_lossy().to_string(),
        size_bytes: metadata.len(),
        sha256: hex::encode(sha256.finalize()),
        sha1: hex::encode(sha1.finalize()),
        md5: hex::encode(md5.finalize()),
    })
}
