pub mod features;
pub mod model;
pub mod threat_scorer;
pub mod trainer;

use crate::error::CoreError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPrediction {
    pub is_malicious: bool,
    pub confidence: f64,
    pub probability: f64,
    pub features_used: Vec<String>,
}
