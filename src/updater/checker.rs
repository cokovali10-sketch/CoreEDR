use super::{UpdateInfo, UpdateManifest};
use crate::error::{CoreError, Result};
use semver::Version;

pub async fn check_for_updates(manifest_url: &str) -> Result<UpdateManifest> {
    let response = reqwest::get(manifest_url)
        .await
        .map_err(|e| CoreError::NetworkError(format!("Failed to fetch manifest: {}", e)))?;

    if !response.status().is_success() {
        return Err(CoreError::NetworkError(format!(
            "Manifest request failed with status: {}",
            response.status()
        )));
    }

    let manifest: UpdateManifest = response
        .json()
        .await
        .map_err(|e| CoreError::ParseError(format!("Failed to parse manifest: {}", e)))?;

    Ok(manifest)
}

pub fn is_update_available(current_version: &str, manifest: &UpdateManifest) -> Result<bool> {
    let current = Version::parse(current_version)
        .map_err(|e| CoreError::ParseError(format!("Invalid current version: {}", e)))?;

    let latest = Version::parse(&manifest.version)
        .map_err(|e| CoreError::ParseError(format!("Invalid manifest version: {}", e)))?;

    Ok(latest > current)
}

pub fn check_version_compatibility(current_version: &str, min_version: &str) -> Result<bool> {
    let current = Version::parse(current_version)
        .map_err(|e| CoreError::ParseError(format!("Invalid current version: {}", e)))?;

    let min = Version::parse(min_version)
        .map_err(|e| CoreError::ParseError(format!("Invalid min version: {}", e)))?;

    Ok(current >= min)
}

pub async fn get_update_info(current_version: &str, manifest_url: &str) -> Result<UpdateInfo> {
    let manifest = check_for_updates(manifest_url).await?;
    let update_available = is_update_available(current_version, &manifest)?;

    Ok(UpdateInfo {
        current_version: current_version.to_string(),
        latest_version: manifest.version.clone(),
        update_available,
        manifest: if update_available {
            Some(manifest)
        } else {
            None
        },
    })
}
