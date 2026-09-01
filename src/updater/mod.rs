pub mod checker;
pub mod downloader;
pub mod signature;

use crate::error::CoreError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub yara_rules_url: Option<String>,
    pub yara_rules_hash: Option<String>,
    pub model_url: Option<String>,
    pub model_hash: Option<String>,
    pub min_coreedr_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub manifest: Option<UpdateManifest>,
}
