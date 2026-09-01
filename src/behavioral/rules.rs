use std::collections::{HashMap, HashSet};
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::Result;
use super::BehavioralEvent;
use super::alerts::{BehavioralAlert, Severity};

pub trait BehavioralRule: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn severity(&self) -> Severity;
    fn evaluate(&self, events: &[BehavioralEvent]) -> Option<BehavioralAlert>;
}

pub struct OfficeAppNetworkSpawn;

impl BehavioralRule for OfficeAppNetworkSpawn {
    fn name(&self) -> &str {
        "OfficeAppNetworkSpawn"
    }

    fn description(&self) -> &str {
        "Office application spawned a child process that opened a network connection"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, events: &[BehavioralEvent]) -> Option<BehavioralAlert> {
        let office_apps: HashSet<&str> = [
            "winword.exe", "excel.exe", "powerpnt.exe", "msaccess.exe",
            "outlook.exe", "mspub.exe", "visio.exe", "onenote.exe",
        ].iter().cloned().collect();

        let mut parent_to_children: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut spawned_pids: HashSet<u32> = HashSet::new();

        for event in events {
            if let BehavioralEvent::ProcessSpawn { parent_pid, child_pid, child_name, .. } = event {
                let parent_name_lower = child_name.to_lowercase();
                if office_apps.iter().any(|app| parent_name_lower.contains(app)) {
                    parent_to_children.entry(*parent_pid).or_default().push(*child_pid);
                }
                spawned_pids.insert(*child_pid);
            }
        }

        let network_pids: HashSet<u32> = events.iter()
            .filter_map(|e| match e {
                BehavioralEvent::NetworkConnection { pid, .. } => Some(*pid),
                _ => None,
            })
            .collect();

        for (office_pid, children) in &parent_to_children {
            let bad_children: Vec<u32> = children.iter()
                .filter(|child| network_pids.contains(child))
                .cloned()
                .collect();

            if !bad_children.is_empty() {
                let involved: Vec<BehavioralEvent> = events.iter()
                    .filter(|e| match e {
                        BehavioralEvent::ProcessSpawn { parent_pid, child_pid, .. } => {
                            parent_pid == office_pid && bad_children.contains(child_pid)
                        }
                        BehavioralEvent::NetworkConnection { pid, .. } => bad_children.contains(pid),
                        _ => false,
                    })
                    .cloned()
                    .collect();

                return Some(BehavioralAlert {
                    id: uuid_v4_simple(),
                    timestamp: Utc::now(),
                    rule_name: self.name().to_string(),
                    severity: self.severity(),
                    confidence: 0.75,
                    description: format!(
                        "Office application (PID {office_pid}) spawned process(es) that opened network connections"
                    ),
                    events: involved,
                    recommended_action: "Investigate spawned process and network destination. Consider blocking outbound connection.".to_string(),
                });
            }
        }

        None
    }
}

pub struct PowerShellDownloadExec;

impl BehavioralRule for PowerShellDownloadExec {
    fn name(&self) -> &str {
        "PowerShellDownloadExec"
    }

    fn description(&self) -> &str {
        "PowerShell downloaded a file and then executed it"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn evaluate(&self, events: &[BehavioralEvent]) -> Option<BehavioralAlert> {
        let ps_pids: HashSet<u32> = events.iter()
            .filter_map(|e| match e {
                BehavioralEvent::ProcessSpawn { child_pid, child_name, .. } => {
                    if child_name.to_lowercase().contains("powershell") ||
                       child_name.to_lowercase().contains("pwsh") {
                        Some(*child_pid)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect();

        if ps_pids.is_empty() {
            return None;
        }

        let network_pids: HashSet<u32> = events.iter()
            .filter_map(|e| match e {
                BehavioralEvent::NetworkConnection { pid, .. } => Some(*pid),
                _ => None,
            })
            .filter(|pid| ps_pids.contains(pid))
            .collect();

        let write_pids: HashSet<u32> = events.iter()
            .filter_map(|e| match e {
                BehavioralEvent::FileAccess { pid, write: true, .. } => Some(*pid),
                BehavioralEvent::FileModification { pid, .. } => Some(*pid),
                _ => None,
            })
            .filter(|pid| network_pids.contains(pid))
            .collect();

        let exec_pids: HashSet<u32> = events.iter()
            .filter_map(|e| match e {
                BehavioralEvent::ProcessSpawn { parent_pid, .. } => Some(*parent_pid),
                _ => None,
            })
            .filter(|pid| write_pids.contains(pid))
            .collect();

        if !exec_pids.is_empty() {
            let involved: Vec<BehavioralEvent> = events.iter()
                .filter(|e| match e {
                    BehavioralEvent::ProcessSpawn { child_pid, .. } => ps_pids.contains(child_pid),
                    BehavioralEvent::NetworkConnection { pid, .. } => ps_pids.contains(pid),
                    BehavioralEvent::FileAccess { pid, write, .. } => write_pids.contains(pid) && *write,
                    BehavioralEvent::FileModification { pid, .. } => write_pids.contains(pid),
                    _ => false,
                })
                .cloned()
                .collect();

            return Some(BehavioralAlert {
                id: uuid_v4_simple(),
                timestamp: Utc::now(),
                rule_name: self.name().to_string(),
                severity: self.severity(),
                confidence: 0.85,
                description: "PowerShell downloaded a file and executed it — likely malicious staging".to_string(),
                events: involved,
                recommended_action: "Terminate PowerShell process. Quarantine downloaded file. Scan for IOCs.".to_string(),
            });
        }

        None
    }
}

pub struct RapidFileModification;

impl BehavioralRule for RapidFileModification {
    fn name(&self) -> &str {
        "RapidFileModification"
    }

    fn description(&self) -> &str {
        "Process modified files rapidly across multiple directories"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, events: &[BehavioralEvent]) -> Option<BehavioralAlert> {
        let modifications: Vec<(u32, String, DateTime<Utc>)> = events.iter()
            .filter_map(|e| match e {
                BehavioralEvent::FileModification { pid, path, timestamp, .. } => {
                    Some((*pid, path.clone(), *timestamp))
                }
                _ => None,
            })
            .collect();

        let mut pid_mods: HashMap<u32, Vec<&str>> = HashMap::new();
        for (pid, path, _) in &modifications {
            pid_mods.entry(*pid).or_default().push(path.as_str());
        }

        for (pid, paths) in &pid_mods {
            if paths.len() < 10 {
                continue;
            }

            let mut dirs: HashSet<String> = HashSet::new();
            for path in paths {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    dirs.insert(parent.display().to_string());
                }
            }

            if dirs.len() >= 5 {
                let involved: Vec<BehavioralEvent> = events.iter()
                    .filter(|e| match e {
                        BehavioralEvent::FileModification { pid: p, .. } => p == pid,
                        _ => false,
                    })
                    .cloned()
                    .collect();

                return Some(BehavioralAlert {
                    id: uuid_v4_simple(),
                    timestamp: Utc::now(),
                    rule_name: self.name().to_string(),
                    severity: self.severity(),
                    confidence: 0.6,
                    description: format!(
                        "PID {pid} modified {} files across {} directories — possible ransomware or worm",
                        paths.len(),
                        dirs.len()
                    ),
                    events: involved,
                    recommended_action: "Check if process is authorized. Monitor for encryption patterns.".to_string(),
                });
            }
        }

        None
    }
}

pub struct SuspiciousProcessChain;

impl BehavioralRule for SuspiciousProcessChain {
    fn name(&self) -> &str {
        "SuspiciousProcessChain"
    }

    fn description(&self) -> &str {
        "Unusual parent-child process relationships detected"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, events: &[BehavioralEvent]) -> Option<BehavioralAlert> {
        let suspicious_chains: &[(&[&str], &[&str])] = &[
            (&["winword.exe", "excel.exe"], &["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]),
            (&["outlook.exe"], &["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe"]),
            (&["iexplore.exe", "msedge.exe", "chrome.exe"], &["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe"]),
            (&["svchost.exe"], &["cmd.exe", "powershell.exe"]),
        ];

        for event in events {
            if let BehavioralEvent::ProcessSpawn { parent_pid, child_pid, child_name, .. } = event {
                let child_lower = child_name.to_lowercase();

                for (_, children) in suspicious_chains {
                    if children.iter().any(|c| child_lower.contains(c)) {
                        let parent_events: Vec<BehavioralEvent> = events.iter()
                            .filter(|e| match e {
                                BehavioralEvent::ProcessSpawn { child_pid: p, child_name, .. } => {
                                    p == parent_pid
                                }
                                _ => false,
                            })
                            .cloned()
                            .collect();

                        let mut involved = parent_events;
                        involved.push(event.clone());

                        return Some(BehavioralAlert {
                            id: uuid_v4_simple(),
                            timestamp: Utc::now(),
                            rule_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: 0.7,
                            description: format!(
                                "Suspicious process chain: PID {parent_pid} spawned {child_name} (PID {child_pid})"
                            ),
                            events: involved,
                            recommended_action: "Inspect parent process. Check for macro execution or exploit delivery.".to_string(),
                        });
                    }
                }
            }
        }

        None
    }
}

pub struct CredentialAccessPattern;

impl BehavioralRule for CredentialAccessPattern {
    fn name(&self) -> &str {
        "CredentialAccessPattern"
    }

    fn description(&self) -> &str {
        "Process accessed credential stores or sensitive registry keys"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn evaluate(&self, events: &[BehavioralEvent]) -> Option<BehavioralAlert> {
        let sensitive_keys: &[&str] = &[
            "hkey_local_machine\\sam",
            "hkey_local_machine\\system\\currentcontrolset\\lsa",
            "hkey_current_user\\software\\microsoft\\windows\\currentversion\\run",
            "hkey_local_machine\\software\\microsoft\\windows nt\\currentversion\\winlogon",
        ];

        let sensitive_files: &[&str] = &[
            "\\windows\\system32\\config\\sam",
            "\\windows\\system32\\config\\system",
            "\\windows\\ntds\\",
            "/etc/shadow",
            "/etc/passwd",
            ".ssh/id_rsa",
            ".ssh/authorized_keys",
        ];

        let mut pid_evidence: HashMap<u32, Vec<BehavioralEvent>> = HashMap::new();

        for event in events {
            match event {
                BehavioralEvent::RegistryAccess { pid, key, .. } => {
                    let key_lower = key.to_lowercase();
                    if sensitive_keys.iter().any(|k| key_lower.contains(k)) {
                        pid_evidence.entry(*pid).or_default().push(event.clone());
                    }
                }
                BehavioralEvent::FileAccess { pid, path, read: true, .. } => {
                    let path_lower = path.to_lowercase();
                    if sensitive_files.iter().any(|f| path_lower.contains(f)) {
                        pid_evidence.entry(*pid).or_default().push(event.clone());
                    }
                }
                BehavioralEvent::FileAccess { pid, path, write: true, .. } => {
                    let path_lower = path.to_lowercase();
                    if sensitive_files.iter().any(|f| path_lower.contains(f)) {
                        pid_evidence.entry(*pid).or_default().push(event.clone());
                    }
                }
                _ => {}
            }
        }

        for (pid, evidence) in &pid_evidence {
            if evidence.len() >= 2 {
                return Some(BehavioralAlert {
                    id: uuid_v4_simple(),
                    timestamp: Utc::now(),
                    rule_name: self.name().to_string(),
                    severity: self.severity(),
                    confidence: 0.9,
                    description: format!(
                        "PID {pid} accessed {} sensitive credential resource(s) — likely credential theft",
                        evidence.len()
                    ),
                    events: evidence.clone(),
                    recommended_action: "Terminate process immediately. Isolate machine. Audit credential stores.".to_string(),
                });
            }
        }

        None
    }
}

pub struct PersistenceCreation;

impl BehavioralRule for PersistenceCreation {
    fn name(&self) -> &str {
        "PersistenceCreation"
    }

    fn description(&self) -> &str {
        "Process created persistence mechanism (scheduled task, run key, service)"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, events: &[BehavioralEvent]) -> Option<BehavioralAlert> {
        let persistence_keys: &[&str] = &[
            "\\currentversion\\run",
            "\\currentversion\\runonce",
            "\\currentversion\\explorer\\browser helper objects",
            "\\windows\\currentversion\\explorer\\shell Folders",
        ];

        let persistence_files: &[&str] = &[
            "\\start menu\\programs\\startup\\",
            "\\appdata\\microsoft\\windows\\start menu\\programs\\startup\\",
            "\\system32\\tasks\\",
            "\\windows\\system32\\tasks\\",
        ];

        let mut pid_evidence: HashMap<u32, Vec<BehavioralEvent>> = HashMap::new();

        for event in events {
            match event {
                BehavioralEvent::RegistryAccess { pid, key, value, .. } => {
                    let key_lower = key.to_lowercase();
                    if persistence_keys.iter().any(|k| key_lower.contains(k)) {
                        pid_evidence.entry(*pid).or_default().push(event.clone());
                    }
                }
                BehavioralEvent::FileAccess { pid, path, write: true, .. }
                | BehavioralEvent::FileModification { pid, path, .. } => {
                    let path_lower = path.to_lowercase();
                    if persistence_files.iter().any(|f| path_lower.contains(f)) {
                        pid_evidence.entry(*pid).or_default().push(event.clone());
                    }
                }
                _ => {}
            }
        }

        for (pid, evidence) in &pid_evidence {
            if evidence.len() >= 1 {
                return Some(BehavioralAlert {
                    id: uuid_v4_simple(),
                    timestamp: Utc::now(),
                    rule_name: self.name().to_string(),
                    severity: self.severity(),
                    confidence: 0.7,
                    description: format!(
                        "PID {pid} created {} persistence artifact(s) — likely maintaining access after reboot",
                        evidence.len()
                    ),
                    events: evidence.clone(),
                    recommended_action: "Remove persistence entries. Scan for additional indicators.".to_string(),
                });
            }
        }

        None
    }
}

fn uuid_v4_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        t.as_secs(),
        t.subsec_nanos() & 0xFFFF,
        (t.subsec_nanos() >> 12) & 0xFFF,
        (t.subsec_millis()) & 0xFFFF,
        t.as_nanos() & 0xFFFFFFFFFFFF
    )
}
