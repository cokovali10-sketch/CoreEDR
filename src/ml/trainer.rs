use std::path::Path;

use rand::seq::SliceRandom;

use crate::error::{CoreError, Result};
use super::features::FeatureVector;
use super::model::ThreatModel;

#[derive(Debug, Clone)]
pub struct TrainingMetrics {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub confusion_matrix: [[u64; 2]; 2],
}

pub fn train_model(labeled_data: &[(FeatureVector, bool)]) -> Result<ThreatModel> {
    if labeled_data.is_empty() {
        return Err(CoreError::Ml("No training data provided".to_string()));
    }

    let feature_count = labeled_data[0].0.to_array().len();
    let mut model = ThreatModel::new(feature_count);

    let (feature_means, feature_stds) = compute_statistics(labeled_data);
    model.feature_means = feature_means;
    model.feature_stds = feature_stds;

    let learning_rate = 0.01;
    let epochs = 100;

    for _ in 0..epochs {
        for (features, label) in labeled_data {
            let raw = features.to_array();
            let normalized = normalize_with_stats(&raw, &model.feature_means, &model.feature_stds);

            let z: f64 = normalized.iter()
                .zip(model.weights.iter())
                .map(|(x, w)| x * w)
                .sum::<f64>() + model.bias;

            let prediction = sigmoid(z);
            let error = prediction - *label as f64;

            for (w, x) in model.weights.iter_mut().zip(normalized.iter()) {
                *w -= learning_rate * error * x;
            }
            model.bias -= learning_rate * error;
        }
    }

    Ok(model)
}

pub fn train_with_cross_validation(
    labeled_data: &[(FeatureVector, bool)],
    k_folds: usize,
) -> Result<(ThreatModel, Vec<TrainingMetrics>)> {
    if labeled_data.len() < k_folds {
        return Err(CoreError::Ml(format!(
            "Not enough data for {}-fold cross-validation (need at least {} samples)",
            k_folds,
            k_folds
        )));
    }

    let mut indices: Vec<usize> = (0..labeled_data.len()).collect();
    let mut rng = rand::thread_rng();
    indices.shuffle(&mut rng);

    let fold_size = labeled_data.len() / k_folds;
    let mut all_metrics = Vec::new();

    let mut best_f1 = 0.0;
    let mut best_model = None;

    for fold in 0..k_folds {
        let test_start = fold * fold_size;
        let test_end = if fold == k_folds - 1 {
            labeled_data.len()
        } else {
            (fold + 1) * fold_size
        };

        let train_data: Vec<&(FeatureVector, bool)> = labeled_data.iter()
            .enumerate()
            .filter(|(i, _)| *i < test_start || *i >= test_end)
            .map(|(_, item)| item)
            .collect();

        let test_data: Vec<&(FeatureVector, bool)> = labeled_data.iter()
            .enumerate()
            .filter(|(i, _)| *i >= test_start && *i < test_end)
            .map(|(_, item)| item)
            .collect();

        let train_vec: Vec<(FeatureVector, bool)> = train_data.into_iter().cloned().collect();
        let model = train_model(&train_vec)?;
        let metrics = evaluate_model(&model, &test_data);

        if metrics.f1 > best_f1 {
            best_f1 = metrics.f1;
            best_model = Some(model);
        }

        all_metrics.push(metrics);
    }

    let final_model = train_model(labeled_data)?;
    Ok((final_model, all_metrics))
}

pub fn evaluate_model(
    model: &ThreatModel,
    test_data: &[&(FeatureVector, bool)],
) -> TrainingMetrics {
    let mut tp = 0u64;
    let mut fp = 0u64;
    let mut tn = 0u64;
    let mut fn_ = 0u64;

    for (features, label) in test_data {
        if let Ok(prediction) = model.predict(features) {
            match (prediction.is_malicious, *label) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                (false, false) => tn += 1,
                (false, true) => fn_ += 1,
            }
        }
    }

    let total = tp + fp + tn + fn_;
    let accuracy = if total > 0 { (tp + tn) as f64 / total as f64 } else { 0.0 };
    let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 0.0 };
    let recall = if tp + fn_ > 0 { tp as f64 / (tp + fn_) as f64 } else { 0.0 };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    TrainingMetrics {
        accuracy,
        precision,
        recall,
        f1,
        confusion_matrix: [[tp, fp], [fn_, tn]],
    }
}

pub fn save_model(model: &ThreatModel, path: &Path) -> Result<()> {
    model.save_model(path)
}

pub fn load_model(path: &Path) -> Result<ThreatModel> {
    ThreatModel::load_model(path)
}

fn compute_statistics(data: &[(FeatureVector, bool)]) -> (Vec<f64>, Vec<f64>) {
    if data.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let feature_count = data[0].0.to_array().len();
    let n = data.len() as f64;

    let mut means = vec![0.0; feature_count];
    let mut variances = vec![0.0; feature_count];

    for (features, _) in data {
        let raw = features.to_array();
        for (i, &x) in raw.iter().enumerate() {
            means[i] += x;
        }
    }

    for m in means.iter_mut() {
        *m /= n;
    }

    for (features, _) in data {
        let raw = features.to_array();
        for (i, &x) in raw.iter().enumerate() {
            let diff = x - means[i];
            variances[i] += diff * diff;
        }
    }

    let stds: Vec<f64> = variances.iter()
        .map(|v| (v / n).sqrt().max(1e-10))
        .collect();

    (means, stds)
}

fn normalize_with_stats(raw: &[f64], means: &[f64], stds: &[f64]) -> Vec<f64> {
    raw.iter()
        .zip(means.iter())
        .zip(stds.iter())
        .map(|((x, mean), std)| (x - mean) / std)
        .collect()
}

fn sigmoid(x: f64) -> f64 {
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let ex = x.exp();
        ex / (1.0 + ex)
    }
}
