use serde::{Deserialize, Serialize};

use crate::error::Result;
use super::features::FeatureVector;
use super::model::ThreatModel;
use super::ThreatPrediction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScorerWeights {
    pub ml_weight: f64,
    pub heuristic_weight: f64,
    pub yara_weight: f64,
}

impl Default for ScorerWeights {
    fn default() -> Self {
        Self {
            ml_weight: 0.5,
            heuristic_weight: 0.3,
            yara_weight: 0.2,
        }
    }
}

pub struct ThreatScorer {
    model: Option<ThreatModel>,
    weights: ScorerWeights,
}

impl ThreatScorer {
    pub fn new() -> Self {
        Self {
            model: None,
            weights: ScorerWeights::default(),
        }
    }

    pub fn with_model(model: ThreatModel) -> Self {
        Self {
            model: Some(model),
            weights: ScorerWeights::default(),
        }
    }

    pub fn with_weights(weights: ScorerWeights) -> Self {
        Self {
            model: None,
            weights,
        }
    }

    pub fn set_model(&mut self, model: ThreatModel) {
        self.model = Some(model);
    }

    pub fn set_weights(&mut self, weights: ScorerWeights) {
        self.weights = weights;
    }

    pub fn combine(ml_score: f64, heuristic_score: u32, yara_matches: usize) -> f64 {
        let ml = ml_score.clamp(0.0, 1.0);
        let heuristic = (heuristic_score as f64 / 10.0).clamp(0.0, 1.0);
        let yara = (yara_matches as f64 / 5.0).clamp(0.0, 1.0);

        let weights = ScorerWeights::default();
        let combined = ml * weights.ml_weight
            + heuristic * weights.heuristic_weight
            + yara * weights.yara_weight;

        combined.clamp(0.0, 1.0)
    }

    pub fn score_file(
        &self,
        features: &FeatureVector,
        heuristic_score: u32,
        yara_matches: usize,
    ) -> Result<ScoredThreat> {
        let ml_score = if let Some(ref model) = self.model {
            let prediction = model.predict(features)?;
            prediction.probability
        } else {
            0.5
        };

        let ml = ml_score.clamp(0.0, 1.0);
        let heuristic = (heuristic_score as f64 / 10.0).clamp(0.0, 1.0);
        let yara = (yara_matches as f64 / 5.0).clamp(0.0, 1.0);

        let combined = ml * self.weights.ml_weight
            + heuristic * self.weights.heuristic_weight
            + yara * self.weights.yara_weight;

        let final_score = combined.clamp(0.0, 1.0);
        let verdict = classify_threat(final_score);

        Ok(ScoredThreat {
            score: final_score,
            ml_score: ml,
            heuristic_score: heuristic,
            yara_score: yara,
            verdict,
        })
    }

    pub fn score_prediction(
        &self,
        prediction: &ThreatPrediction,
        heuristic_score: u32,
        yara_matches: usize,
    ) -> ScoredThreat {
        let ml = prediction.probability.clamp(0.0, 1.0);
        let heuristic = (heuristic_score as f64 / 10.0).clamp(0.0, 1.0);
        let yara = (yara_matches as f64 / 5.0).clamp(0.0, 1.0);

        let combined = ml * self.weights.ml_weight
            + heuristic * self.weights.heuristic_weight
            + yara * self.weights.yara_weight;

        let final_score = combined.clamp(0.0, 1.0);
        let verdict = classify_threat(final_score);

        ScoredThreat {
            score: final_score,
            ml_score: ml,
            heuristic_score: heuristic,
            yara_score: yara,
            verdict,
        }
    }
}

impl Default for ThreatScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredThreat {
    pub score: f64,
    pub ml_score: f64,
    pub heuristic_score: f64,
    pub yara_score: f64,
    pub verdict: ThreatVerdict,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatVerdict {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatVerdict::Clean => "clean",
            ThreatVerdict::Low => "low",
            ThreatVerdict::Medium => "medium",
            ThreatVerdict::High => "high",
            ThreatVerdict::Critical => "critical",
        }
    }
}

fn classify_threat(score: f64) -> ThreatVerdict {
    if score < 0.2 {
        ThreatVerdict::Clean
    } else if score < 0.4 {
        ThreatVerdict::Low
    } else if score < 0.6 {
        ThreatVerdict::Medium
    } else if score < 0.8 {
        ThreatVerdict::High
    } else {
        ThreatVerdict::Critical
    }
}
