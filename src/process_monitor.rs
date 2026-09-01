use std::collections::HashMap;
use std::process::Command;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub parent_pid: u32,
    pub user: String,
    pub memory_usage_kb: u64,
    pub cpu_percent: f64,
    pub start_time: DateTime<Utc>,
    pub hash: Option<String>,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDelta {
    pub new_processes: Vec<ProcessInfo>,
    pub terminated_processes: Vec<u32>,
    pub modified_processes: Vec<ProcessInfo>,
}

pub struct ProcessMonitor {
    known_processes: HashMap<u32, ProcessInfo>,
    scan_interval_ms: u64,
}

impl ProcessMonitor {
    pub fn new(scan_interval_ms: u64) -> Self {
        Self {
            known_processes: HashMap::new(),
            scan_interval_ms,
        }
    }

    pub fn scan_processes(&mut self) -> Result<ProcessDelta, crate::error::CoreError> {
        let current = self.get_all_processes()?;
        let mut delta = ProcessDelta {
            new_processes: Vec::new(),
            terminated_processes: Vec::new(),
            modified_processes: Vec::new(),
        };

        let current_pids: Vec<u32> = current.keys().cloned().collect();

        for (pid, proc_info) in &current {
            if let Some(old) = self.known_processes.get(pid) {
                if old.memory_usage_kb != proc_info.memory_usage_kb
                    || old.cpu_percent != proc_info.cpu_percent
                {
                    delta.modified_processes.push(proc_info.clone());
                }
            } else {
                delta.new_processes.push(proc_info.clone());
            }
        }

        for old_pid in self.known_processes.keys() {
            if !current.contains_key(old_pid) {
                delta.terminated_processes.push(*old_pid);
            }
        }

        self.known_processes = current;
        Ok(delta)
    }

    fn get_all_processes(&self) -> Result<HashMap<u32, ProcessInfo>, crate::error::CoreError> {
        let mut processes = HashMap::new();

        #[cfg(target_os = "windows")]
        {
            processes = self.get_windows_processes()?;
        }

        #[cfg(target_os = "linux")]
        {
            processes = self.get_linux_processes()?;
        }

        #[cfg(target_os = "macos")]
        {
            processes = self.get_macos_processes()?;
        }

        Ok(processes)
    }

    #[cfg(target_os = "windows")]
    fn get_windows_processes(&self) -> Result<HashMap<u32, ProcessInfo>, crate::error::CoreError> {
        let output = Command::new("wmic")
            .args([
                "process",
                "get",
                "ProcessId,Name,ExecutablePath,CommandLine,ParentProcessId,WorkingSetSize",
                "/format:csv",
            ])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut processes = HashMap::new();

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 6 {
                if let Ok(pid) = parts[5].trim().parse::<u32>() {
                    let name = parts[1].trim().to_string();
                    let path = parts[2].trim().to_string();
                    let cmd = parts[3].trim().to_string();
                    let parent = parts[4].trim().parse::<u32>().unwrap_or(0);
                    let memory = parts[5].trim().parse::<u64>().unwrap_or(0);

                    processes.insert(
                        pid,
                        ProcessInfo {
                            pid,
                            name,
                            path,
                            command_line: cmd,
                            parent_pid: parent,
                            user: "N/A".to_string(),
                            memory_usage_kb: memory / 1024,
                            cpu_percent: 0.0,
                            start_time: Utc::now(),
                            hash: None,
                            risk_score: 0,
                        },
                    );
                }
            }
        }

        Ok(processes)
    }

    #[cfg(target_os = "linux")]
    fn get_linux_processes(&self) -> Result<HashMap<u32, ProcessInfo>, crate::error::CoreError> {
        let output = Command::new("ps")
            .args(["-eo", "pid,ppid,user,%cpu,rss,comm", "--no-headers"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut processes = HashMap::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                if let Ok(pid) = parts[0].parse::<u32>() {
                    let parent = parts[1].parse::<u32>().unwrap_or(0);
                    let user = parts[2].to_string();
                    let cpu = parts[3].parse::<f64>().unwrap_or(0.0);
                    let rss = parts[4].parse::<u64>().unwrap_or(0);
                    let name = parts[5].to_string();

                    let path = format!("/proc/{}", pid);

                    processes.insert(
                        pid,
                        ProcessInfo {
                            pid,
                            name,
                            path,
                            command_line: String::new(),
                            parent_pid: parent,
                            user,
                            memory_usage_kb: rss,
                            cpu_percent: cpu,
                            start_time: Utc::now(),
                            hash: None,
                            risk_score: 0,
                        },
                    );
                }
            }
        }

        Ok(processes)
    }

    #[cfg(target_os = "macos")]
    fn get_macos_processes(&self) -> Result<HashMap<u32, ProcessInfo>, crate::error::CoreError> {
        let output = Command::new("ps")
            .args(["-eo", "pid,ppid,user,%cpu,rss,comm", "-x"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut processes = HashMap::new();

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                if let Ok(pid) = parts[0].parse::<u32>() {
                    let parent = parts[1].parse::<u32>().unwrap_or(0);
                    let user = parts[2].to_string();
                    let cpu = parts[3].parse::<f64>().unwrap_or(0.0);
                    let rss = parts[4].parse::<u64>().unwrap_or(0);
                    let name = parts[5].to_string();

                    processes.insert(
                        pid,
                        ProcessInfo {
                            pid,
                            name,
                            path: String::new(),
                            command_line: String::new(),
                            parent_pid: parent,
                            user,
                            memory_usage_kb: rss,
                            cpu_percent: cpu,
                            start_time: Utc::now(),
                            hash: None,
                            risk_score: 0,
                        },
                    );
                }
            }
        }

        Ok(processes)
    }

    pub fn get_process_by_pid(&self, pid: u32) -> Option<&ProcessInfo> {
        self.known_processes.get(&pid)
    }

    pub fn get_all_known(&self) -> &HashMap<u32, ProcessInfo> {
        &self.known_processes
    }

    pub fn scan_interval(&self) -> u64 {
        self.scan_interval_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_monitor_creation() {
        let monitor = ProcessMonitor::new(5000);
        assert_eq!(monitor.scan_interval(), 5000);
        assert!(monitor.get_all_known().is_empty());
    }

    #[test]
    fn test_scan_returns_delta() {
        let mut monitor = ProcessMonitor::new(5000);
        let delta = monitor.scan_processes().unwrap();
        assert!(!delta.new_processes.is_empty() || !delta.terminated_processes.is_empty());
    }
}
