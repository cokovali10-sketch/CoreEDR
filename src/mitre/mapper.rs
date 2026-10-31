use super::techniques::{build_technique_database, Tactic, Technique, TechniqueId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String,
    pub tactic: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub event_type: String,
    pub severity: String,
    pub source: String,
    pub details: HashMap<String, String>,
    pub timestamp: String,
}

pub struct MitreMapper {
    technique_db: HashMap<TechniqueId, Technique>,
    keyword_map: Vec<(Vec<String>, TechniqueId, f64)>,
}

impl MitreMapper {
    pub fn new() -> Self {
        let technique_db = build_technique_database();
        let keyword_map = Self::build_keyword_map();

        MitreMapper {
            technique_db,
            keyword_map,
        }
    }

    fn build_keyword_map() -> Vec<(Vec<String>, TechniqueId, f64)> {
        vec![
            // PowerShell
            (
                vec!["powershell".into(), "-encodedcommand".into()],
                TechniqueId::new("T1059.001"),
                0.9,
            ),
            (
                vec!["powershell".into(), "download".into()],
                TechniqueId::new("T1059.001"),
                0.85,
            ),
            (
                vec!["invoke-webrequest".into()],
                TechniqueId::new("T1059.001"),
                0.8,
            ),
            (
                vec!["net.webclient".into(), "downloadstring".into()],
                TechniqueId::new("T1059.001"),
                0.85,
            ),
            (vec!["-enc".into()], TechniqueId::new("T1059.001"), 0.7),
            // Command Shell
            (
                vec!["cmd.exe".into(), "/c".into()],
                TechniqueId::new("T1059.003"),
                0.6,
            ),
            (
                vec!["cmd.exe".into(), "net".into()],
                TechniqueId::new("T1059.003"),
                0.5,
            ),
            // Credential Dumping
            (vec!["mimikatz".into()], TechniqueId::new("T1003.001"), 0.95),
            (
                vec!["lsass".into(), "access".into()],
                TechniqueId::new("T1003.001"),
                0.85,
            ),
            (
                vec!["procdump".into(), "lsass".into()],
                TechniqueId::new("T1003.001"),
                0.9,
            ),
            (
                vec!["sam".into(), "database".into()],
                TechniqueId::new("T1003"),
                0.8,
            ),
            (vec!["/etc/shadow".into()], TechniqueId::new("T1003"), 0.9),
            (vec!["ntds.dit".into()], TechniqueId::new("T1003"), 0.9),
            (vec!["lazagne".into()], TechniqueId::new("T1003"), 0.85),
            // Persistence
            (
                vec!["currentversion\\run".into()],
                TechniqueId::new("T1547.001"),
                0.9,
            ),
            (
                vec!["startup".into(), "folder".into()],
                TechniqueId::new("T1547.001"),
                0.7,
            ),
            (
                vec!["schtasks".into(), "/create".into()],
                TechniqueId::new("T1053"),
                0.85,
            ),
            (vec!["crontab".into()], TechniqueId::new("T1053"), 0.8),
            (
                vec!["systemd".into(), "service".into()],
                TechniqueId::new("T1543"),
                0.7,
            ),
            // Defense Evasion
            (
                vec!["wevtutil".into(), "cl".into()],
                TechniqueId::new("T1070"),
                0.9,
            ),
            (
                vec!["history".into(), "delete".into()],
                TechniqueId::new("T1070"),
                0.7,
            ),
            (vec!["timestomp".into()], TechniqueId::new("T1070"), 0.85),
            (
                vec!["process".into(), "inject".into()],
                TechniqueId::new("T1055"),
                0.85,
            ),
            (vec!["remotethread".into()], TechniqueId::new("T1055"), 0.8),
            (
                vec!["virtualallocex".into()],
                TechniqueId::new("T1055"),
                0.75,
            ),
            (
                vec!["createremotethread".into()],
                TechniqueId::new("T1055"),
                0.8,
            ),
            // Privilege Escalation
            (
                vec!["uac".into(), "bypass".into()],
                TechniqueId::new("T1548"),
                0.8,
            ),
            (
                vec!["sudo".into(), "abuse".into()],
                TechniqueId::new("T1548"),
                0.7,
            ),
            (vec!["setuid".into()], TechniqueId::new("T1548"), 0.6),
            // Discovery
            (vec!["systeminfo".into()], TechniqueId::new("T1082"), 0.7),
            (vec!["tasklist".into()], TechniqueId::new("T1057"), 0.7),
            (vec!["netstat".into()], TechniqueId::new("T1049"), 0.7),
            // Lateral Movement
            (vec!["psexec".into()], TechniqueId::new("T1021"), 0.85),
            (
                vec!["wmi".into(), "remote".into()],
                TechniqueId::new("T1021"),
                0.7,
            ),
            // C2
            (
                vec!["curl".into(), "executable".into()],
                TechniqueId::new("T1105"),
                0.7,
            ),
            (
                vec!["wget".into(), "executable".into()],
                TechniqueId::new("T1105"),
                0.7,
            ),
            (
                vec!["certutil".into(), "urlcache".into()],
                TechniqueId::new("T1105"),
                0.85,
            ),
            (
                vec!["dns".into(), "tunnel".into()],
                TechniqueId::new("T1572"),
                0.8,
            ),
            // Ransomware
            (
                vec!["vssadmin".into(), "delete".into()],
                TechniqueId::new("T1486"),
                0.9,
            ),
            (
                vec!["bcdedit".into(), "recoveryenabled".into(), "no".into()],
                TechniqueId::new("T1486"),
                0.85,
            ),
            (
                vec!["ransom".into(), "note".into()],
                TechniqueId::new("T1486"),
                0.95,
            ),
            (vec![".locked".into()], TechniqueId::new("T1486"), 0.8),
            (vec![".encrypted".into()], TechniqueId::new("T1486"), 0.75),
            // Process Injection
            (
                vec!["createremotethread".into()],
                TechniqueId::new("T1055"),
                0.85,
            ),
            (
                vec!["writeprocessmemory".into()],
                TechniqueId::new("T1055"),
                0.8,
            ),
            (
                vec!["ntmapviewofsection".into()],
                TechniqueId::new("T1055"),
                0.8,
            ),
            // Webshell
            (
                vec!["eval".into(), "base64_decode".into()],
                TechniqueId::new("T1505.003"),
                0.8,
            ),
            (
                vec!["<?php".into(), "shell_exec".into()],
                TechniqueId::new("T1505.003"),
                0.85,
            ),
            (
                vec!["cmd.exe".into(), "/c".into(), "whoami".into()],
                TechniqueId::new("T1059.003"),
                0.7,
            ),
        ]
    }

    pub fn map_event(&self, event: &DetectionEvent) -> Vec<MitreMapping> {
        let mut mappings = Vec::new();
        let mut seen_techniques = std::collections::HashSet::new();

        // Combine all text fields for keyword matching
        let mut search_text = format!("{} {} {}", event.event_type, event.severity, event.source);
        for (key, value) in &event.details {
            search_text.push_str(&format!(" {} {}", key, value));
        }
        let search_lower = search_text.to_lowercase();

        for (keywords, technique_id, confidence) in &self.keyword_map {
            let all_match = keywords.iter().all(|kw| search_lower.contains(kw.as_str()));
            if all_match && !seen_techniques.contains(technique_id) {
                if let Some(technique) = self.technique_db.get(technique_id) {
                    let evidence: Vec<String> = keywords
                        .iter()
                        .filter(|kw| search_lower.contains(kw.as_str()))
                        .cloned()
                        .collect();

                    mappings.push(MitreMapping {
                        technique_id: technique_id.0.clone(),
                        tactic: technique.tactic.name().to_string(),
                        confidence: *confidence,
                        evidence,
                        timestamp: event.timestamp.clone(),
                    });
                    seen_techniques.insert(technique_id.clone());
                }
            }
        }

        // Add parent technique if sub-technique matched
        let parent_map: Vec<(&str, &str)> = vec![
            ("T1059.001", "T1059"),
            ("T1059.003", "T1059"),
            ("T1059.006", "T1059"),
            ("T1547.001", "T1547"),
            ("T1003.001", "T1003"),
            ("T1505.003", "T1505"),
        ];

        for (sub, parent) in parent_map {
            if seen_techniques.contains(&TechniqueId::new(sub)) {
                let parent_id = TechniqueId::new(parent);
                if !seen_techniques.contains(&parent_id) {
                    if let Some(technique) = self.technique_db.get(&parent_id) {
                        mappings.push(MitreMapping {
                            technique_id: parent.to_string(),
                            tactic: technique.tactic.name().to_string(),
                            confidence: 0.6,
                            evidence: vec!["inferred from sub-technique".into()],
                            timestamp: event.timestamp.clone(),
                        });
                        seen_techniques.insert(parent_id);
                    }
                }
            }
        }

        mappings.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        mappings
    }

    pub fn map_process_event(
        &self,
        process_name: &str,
        command_line: &str,
        parent_name: &str,
        timestamp: &str,
    ) -> Vec<MitreMapping> {
        let mut details = HashMap::new();
        details.insert("process_name".into(), process_name.to_string());
        details.insert("command_line".into(), command_line.to_string());
        details.insert("parent_process".into(), parent_name.to_string());

        let event = DetectionEvent {
            event_type: "process_creation".into(),
            severity: "medium".into(),
            source: "process_monitor".into(),
            details,
            timestamp: timestamp.to_string(),
        };

        self.map_event(&event)
    }

    pub fn map_file_event(
        &self,
        file_path: &str,
        event_type: &str,
        timestamp: &str,
    ) -> Vec<MitreMapping> {
        let mut details = HashMap::new();
        details.insert("file_path".into(), file_path.to_string());
        details.insert("event_type".into(), event_type.to_string());

        let event = DetectionEvent {
            event_type: "file_event".into(),
            severity: "medium".into(),
            source: "file_monitor".into(),
            details,
            timestamp: timestamp.to_string(),
        };

        self.map_event(&event)
    }

    pub fn map_network_event(
        &self,
        remote_ip: &str,
        remote_port: u16,
        protocol: &str,
        process_name: &str,
        timestamp: &str,
    ) -> Vec<MitreMapping> {
        let mut details = HashMap::new();
        details.insert("remote_ip".into(), remote_ip.to_string());
        details.insert("remote_port".into(), remote_port.to_string());
        details.insert("protocol".into(), protocol.to_string());
        details.insert("process_name".into(), process_name.to_string());

        let event = DetectionEvent {
            event_type: "network_connection".into(),
            severity: "medium".into(),
            source: "network_monitor".into(),
            details,
            timestamp: timestamp.to_string(),
        };

        self.map_event(&event)
    }

    pub fn get_technique(&self, id: &str) -> Option<&Technique> {
        self.technique_db.get(&TechniqueId::new(id))
    }

    pub fn get_techniques_by_tactic(&self, tactic: Tactic) -> Vec<&Technique> {
        self.technique_db
            .values()
            .filter(|t| t.tactic == tactic)
            .collect()
    }

    pub fn get_technique_count(&self) -> usize {
        self.technique_db.len()
    }

    pub fn get_tactic_summary(&self) -> HashMap<String, usize> {
        let mut summary = HashMap::new();
        for technique in self.technique_db.values() {
            *summary
                .entry(technique.tactic.name().to_string())
                .or_insert(0) += 1;
        }
        summary
    }
}

impl Default for MitreMapper {
    fn default() -> Self {
        Self::new()
    }
}
