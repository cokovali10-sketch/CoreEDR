use std::path::Path;

use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use super::features::FeatureVector;
use super::ThreatPrediction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModel {
    pub weights: Vec<f64>,
    pub bias: f64,
    pub feature_means: Vec<f64>,
    pub feature_stds: Vec<f64>,
    pub threshold: f64,
    pub version: u32,
}

impl ThreatModel {
    pub fn new(feature_count: usize) -> Self {
        Self {
            weights: vec![0.0; feature_count],
            bias: 0.0,
            feature_means: vec![0.0; feature_count],
            feature_stds: vec![1.0; feature_count],
            threshold: 0.5,
            version: 1,
        }
    }

    pub fn predict(&self, features: &FeatureVector) -> Result<ThreatPrediction> {
        let raw = features.to_array();
        let normalized = self.normalize(&raw);

        let z: f64 = normalized.iter()
            .zip(self.weights.iter())
            .map(|(x, w)| x * w)
            .sum::<f64>() + self.bias;

        let probability = sigmoid(z);
        let is_malicious = probability >= self.threshold;
        let confidence = if is_malicious {
            probability
        } else {
            1.0 - probability
        };

        Ok(ThreatPrediction {
            is_malicious,
            confidence,
            probability,
            features_used: FeatureVector::feature_names()
                .into_iter()
                .map(String::from)
                .collect(),
        })
    }

    pub fn predict_batch(&self, features_list: &[FeatureVector]) -> Result<Vec<ThreatPrediction>> {
        features_list.iter().map(|f| self.predict(f)).collect()
    }

    pub fn save_model(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| CoreError::Ml(format!("Failed to serialize model: {e}")))?;

        std::fs::write(path, json)
            .map_err(|e| CoreError::Ml(format!("Failed to write model: {e}")))?;

        Ok(())
    }

    pub fn load_model(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| CoreError::Ml(format!("Failed to read model: {e}")))?;

        serde_json::from_str(&data)
            .map_err(|e| CoreError::Ml(format!("Failed to deserialize model: {e}")))
    }

    fn normalize(&self, raw: &[f64]) -> Vec<f64> {
        raw.iter()
            .zip(self.feature_means.iter())
            .zip(self.feature_stds.iter())
            .map(|((x, mean), std)| {
                if *std > 1e-10 {
                    (x - mean) / std
                } else {
                    0.0
                }
            })
            .collect()
    }

    pub fn to_feature_matrix(&self, features_list: &[FeatureVector]) -> Result<Array2<f64>> {
        let n = features_list.len();
        let m = features_list.first()
            .map(|f| f.to_array().len())
            .unwrap_or(0);

        let mut data = Vec::with_capacity(n * m);
        for features in features_list {
            let normalized = self.normalize(&features.to_array());
            data.extend(normalized);
        }

        Array2::from_shape_vec((n, m), data)
            .map_err(|e| CoreError::Ml(format!("Failed to create feature matrix: {e}")))
    }

    pub fn to_feature_vector(&self, features: &FeatureVector) -> Result<Array1<f64>> {
        let normalized = self.normalize(&features.to_array());
        Array1::from_vec(normalized)
            .map_err(|e| CoreError::Ml(format!("Failed to create feature vector: {e}")))
    }
}

fn sigmoid(x: f64) -> f64 {
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let ex = x.exp();
        ex / (1.0 + ex)
    }
}

pub fn naive_bayes_predict(
    features: &FeatureVector,
    class_priors: &[f64],
    class_means: &[Vec<f64>],
    class_stds: &[Vec<f64>],
) -> Result<ThreatPrediction> {
    let raw = features.to_array();
    let n_classes = class_priors.len();

    if n_classes == 0 || class_means.len() != n_classes || class_stds.len() != n_classes {
        return Err(CoreError::Ml("Invalid model parameters".to_string()));
    }

    let mut log_probs = Vec::with_capacity(n_classes);

    for c in 0..n_classes {
        let mut log_prob = (class_priors[c] + 1e-10).ln();

        for (i, &x) in raw.iter().enumerate() {
            let mean = class_means[c][i];
            let std = class_stds[c][i].max(1e-10);
            let exponent = -0.5 * ((x - mean) / std).powi(2);
            let norm = 1.0 / (std * (2.0 * std::f64::consts::PI).sqrt());
            log_prob += (norm + 1e-10).ln() + exponent;
        }

        log_probs.push(log_prob);
    }

    let max_log = log_probs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let exps: Vec<f64> = log_probs.iter().map(|lp| (lp - max_log).exp()).collect();
    let sum_exp: f64 = exps.iter().sum();
    let probs: Vec<f64> = exps.iter().map(|e| e / sum_exp).collect();

    let malicious_prob = probs.last().copied().unwrap_or(0.0);
    let is_malicious = malicious_prob >= 0.5;
    let confidence = if is_malicious {
        malicious_prob
    } else {
        1.0 - malicious_prob
    };

    Ok(ThreatPrediction {
        is_malicious,
        confidence,
        probability: malicious_prob,
        features_used: FeatureVector::feature_names()
            .into_iter()
            .map(String::from)
            .collect(),
    })
}
