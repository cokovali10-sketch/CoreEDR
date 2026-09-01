use crate::error::{CoreError, Result};
use sha2::{Sha256, Digest};
use std::path::Path;
use tokio::fs;
use tokio::io::AsyncWriteExt;

pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;

pub async fn download_file(
    url: &str,
    output: &Path,
    progress_callback: Option<&ProgressCallback>,
) -> Result<()> {
    let response = reqwest::get(url)
        .await
        .map_err(|e| CoreError::NetworkError(format!("Download failed: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(CoreError::NetworkError(format!(
            "Download request failed with status: {}",
            response.status()
        )));
    }
    
    let total_size = response.content_length().unwrap_or(0);
    let mut downloaded: u64 = 0;
    
    let tmp_path = output.with_extension("tmp");
    let mut file = fs::File::create(&tmp_path)
        .await
        .map_err(|e| CoreError::IoError(format!("Failed to create temp file: {}", e)))?;
    
    let mut stream = response.bytes_stream();
    use futures::StreamExt;
    
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| CoreError::NetworkError(format!("Download stream error: {}", e)))?;
        file.write_all(&chunk)
            .await
            .map_err(|e| CoreError::IoError(format!("Failed to write chunk: {}", e)))?;
        
        downloaded += chunk.len() as u64;
        
        if let Some(callback) = progress_callback {
            callback(downloaded, total_size);
        }
    }
    
    file.flush()
        .await
        .map_err(|e| CoreError::IoError(format!("Failed to flush file: {}", e)))?;
    
    drop(file);
    
    fs::rename(&tmp_path, output)
        .await
        .map_err(|e| CoreError::IoError(format!("Failed to rename temp file: {}", e)))?;
    
    Ok(())
}

pub async fn verify_hash(path: &Path, expected_hash: &str) -> Result<bool> {
    let data = fs::read(path)
        .await
        .map_err(|e| CoreError::IoError(format!("Failed to read file: {}", e)))?;
    
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let result = hasher.finalize();
    let computed_hash = hex::encode(result);
    
    Ok(computed_hash.eq_ignore_ascii_case(expected_hash))
}

pub async fn download_with_verification(
    url: &str,
    output: &Path,
    expected_hash: Option<&str>,
    progress_callback: Option<&ProgressCallback>,
) -> Result<()> {
    download_file(url, output, progress_callback).await?;
    
    if let Some(hash) = expected_hash {
        let valid = verify_hash(output, hash).await?;
        if !valid {
            fs::remove_file(output)
                .await
                .map_err(|e| CoreError::IoError(format!("Failed to remove invalid file: {}", e)))?;
            return Err(CoreError::IntegrityError("Hash verification failed".to_string()));
        }
    }
    
    Ok(())
}
