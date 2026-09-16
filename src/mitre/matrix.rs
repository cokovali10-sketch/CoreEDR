use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::techniques::{Tactic, TechniqueId, build_technique_database};
use super::mapper::MitreMapping;

#[derive(Debug, Serialize, Deserialize)]
pub struct MitreCell {
    pub technique_id: String,
    pub name: String,
    pub detections: u32,
    pub max_confidence: f64,
    pub last_seen: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MitreMatrix {
    pub tactics: Vec<String>,
    pub cells: HashMap<String, Vec<MitreCell>>,
    pub total_detections: u32,
    pub covered_techniques: usize,
    pub total_techniques: usize,
}

impl MitreMatrix {
    pub fn new() -> Self {
        let db = build_technique_database();
        let tactics: Vec<String> = Tactic::all().iter().map(|t| t.name().to_string()).collect();

        let mut cells: HashMap<String, Vec<MitreCell>> = HashMap::new();
        for tactic in Tactic::all() {
            let techs: Vec<MitreCell> = db.values()
                .filter(|t| t.tactic == tactic)
                .map(|t| MitreCell {
                    technique_id: t.id.0.clone(),
                    name: t.name.clone(),
                    detections: 0,
                    max_confidence: 0.0,
                    last_seen: String::new(),
                })
                .collect();
            cells.insert(tactic.name().to_string(), techs);
        }

        MitreMatrix {
            tactics,
            cells,
            total_detections: 0,
            covered_techniques: 0,
            total_techniques: db.len(),
        }
    }

    pub fn apply_mappings(&mut self, mappings: &[MitreMapping]) {
        let mut technique_detections: HashMap<String, (u32, f64, String)> = HashMap::new();

        for mapping in mappings {
            let entry = technique_detections
                .entry(mapping.technique_id.clone())
                .or_insert((0, 0.0, mapping.timestamp.clone()));
            entry.0 += 1;
            entry.1 = entry.1.max(mapping.confidence);
            entry.2 = mapping.timestamp.clone();
        }

        self.total_detections = mappings.len() as u32;
        self.covered_techniques = technique_detections.len();

        for (tactic_name, cells) in &mut self.cells {
            for cell in cells.iter_mut() {
                if let Some((count, max_conf, last_seen)) = technique_detections.get(&cell.technique_id) {
                    cell.detections = *count;
                    cell.max_confidence = *max_conf;
                    cell.last_seen = last_seen.clone();
                }
            }
        }
    }

    pub fn get_coverage_percentage(&self) -> f64 {
        if self.total_techniques == 0 {
            return 0.0;
        }
        (self.covered_techniques as f64 / self.total_techniques as f64) * 100.0
    }

    pub fn get_high_confidence_techniques(&self, threshold: f64) -> Vec<&MitreCell> {
        self.cells.values()
            .flatten()
            .filter(|c| c.max_confidence >= threshold && c.detections > 0)
            .collect()
    }

    pub fn get_uncovored_tactics(&self) -> Vec<String> {
        self.tactics.iter()
            .filter(|t| {
                if let Some(cells) = self.cells.get(t.as_str()) {
                    cells.iter().all(|c| c.detections == 0)
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }
}

impl Default for MitreMatrix {
    fn default() -> Self {
        Self::new()
    }
}
