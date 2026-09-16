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
    pub chain_depth: u32,
    pub root_pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessChain {
    pub root_pid: u32,
    pub root_name: String,
    pub nodes: Vec<ProcessChainNode>,
    pub total_descendants: u32,
    pub max_depth: u32,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessChainNode {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
    pub depth: u32,
    pub risk_score: u32,
    pub children: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDelta {
    pub new_processes: Vec<ProcessInfo>,
    pub terminated_processes: Vec<u32>,
    pub modified_processes: Vec<ProcessInfo>,
    pub new_chains: Vec<ProcessChain>,
}

pub struct ProcessMonitor {
    known_processes: HashMap<u32, ProcessInfo>,
    process_chains: HashMap<u32, ProcessChain>,
    children_map: HashMap<u32, Vec<u32>>,
    scan_interval_ms: u64,
}

impl ProcessMonitor {
    pub fn new(scan_interval_ms: u64) -> Self {
        Self {
            known_processes: HashMap::new(),
            process_chains: HashMap::new(),
            children_map: HashMap::new(),
            scan_interval_ms,
        }
    }

    pub fn scan_processes(&mut self) -> Result<ProcessDelta, crate::error::CoreError> {
        let current = self.get_all_processes()?;
        let mut delta = ProcessDelta {
            new_processes: Vec::new(),
            terminated_processes: Vec::new(),
            modified_processes: Vec::new(),
            new_chains: Vec::new(),
        };

        let current_pids: Vec<u32> = current.keys().cloned().collect();

        for (pid, proc_info) in &current {
            self.children_map
                .entry(proc_info.parent_pid)
                .or_insert_with(Vec::new)
                .push(*pid);
        }

        for (pid, proc_info) in &current {
            if let Some(old) = self.known_processes.get(pid) {
                if old.memory_usage_kb != proc_info.memory_usage_kb
                    || old.cpu_percent != proc_info.cpu_percent
                {
                    delta.modified_processes.push(proc_info.clone());
                }
            } else {
                let chain_depth = self.calculate_chain_depth(proc_info.parent_pid);
                let root_pid = self.find_root_pid(proc_info.parent_pid);
                let mut new_proc = proc_info.clone();
                new_proc.chain_depth = chain_depth;
                new_proc.root_pid = root_pid;

                if chain_depth == 0 && !self.process_chains.contains_key(pid) {
                    let chain = self.build_chain_for_process(*pid, &current);
                    if chain.total_descendants > 0 {
                        delta.new_chains.push(chain.clone());
                        self.process_chains.insert(*pid, chain);
                    }
                }

                delta.new_processes.push(new_proc);
            }
        }

        for old_pid in self.known_processes.keys() {
            if !current.contains_key(old_pid) {
                delta.terminated_processes.push(*old_pid);
                self.process_chains.remove(old_pid);
                if let Some(children) = self.children_map.get_mut(old_pid) {
                    children.clear();
                }
            }
        }

        self.known_processes = current;
        Ok(delta)
    }

    fn calculate_chain_depth(&self, parent_pid: u32) -> u32 {
        if parent_pid == 0 || !self.known_processes.contains_key(&parent_pid) {
            return 0;
        }
        1 + self.calculate_chain_depth(self.known_processes[&parent_pid].parent_pid)
    }

    fn find_root_pid(&self, pid: u32) -> u32 {
        if pid == 0 || !self.known_processes.contains_key(&pid) {
            return pid;
        }
        self.find_root_pid(self.known_processes[&pid].parent_pid)
    }

    fn build_chain_for_process(&self, root_pid: u32, all: &HashMap<u32, ProcessInfo>) -> ProcessChain {
        let root_name = all.get(&root_pid)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "unknown".into());

        let mut nodes = Vec::new();
        self.build_chain_nodes(root_pid, 0, all, &mut nodes);

        let max_depth = nodes.iter().map(|n| n.depth).max().unwrap_or(0);

        ProcessChain {
            root_pid,
            root_name,
            nodes,
            total_descendants: self.count_descendants(root_pid, all),
            max_depth,
            risk_score: 0,
        }
    }

    fn build_chain_nodes(
        &self,
        pid: u32,
        depth: u32,
        all: &HashMap<u32, ProcessInfo>,
        nodes: &mut Vec<ProcessChainNode>,
    ) {
        let name = all.get(&pid).map(|p| p.name.clone()).unwrap_or_else(|| "unknown".into());
        let parent_pid = all.get(&pid).map(|p| p.parent_pid).unwrap_or(0);
        let risk_score = all.get(&pid).map(|p| p.risk_score).unwrap_or(0);
        let children = self.children_map.get(&pid).cloned().unwrap_or_default();

        nodes.push(ProcessChainNode {
            pid,
            name,
            parent_pid,
            depth,
            risk_score,
            children: children.clone(),
        });

        for child_pid in children {
            self.build_chain_nodes(child_pid, depth + 1, all, nodes);
        }
    }

    fn count_descendants(&self, pid: u32, all: &HashMap<u32, ProcessInfo>) -> u32 {
        let children = self.children_map.get(&pid).cloned().unwrap_or_default();
        let mut count = children.len() as u32;
        for child in &children {
            count += self.count_descendants(*child, all);
        }
        count
    }

    pub fn get_chain(&self, root_pid: u32) -> Option<&ProcessChain> {
        self.process_chains.get(&root_pid)
    }

    pub fn get_all_chains(&self) -> &HashMap<u32, ProcessChain> {
        &self.process_chains
    }

    pub fn get_process_children(&self, pid: u32) -> Vec<u32> {
        self.children_map.get(&pid).cloned().unwrap_or_default()
    }

    pub fn get_process_tree(&self, pid: u32, depth: usize) -> Vec<(u32, String, usize)> {
        let mut result = Vec::new();
        self.get_tree_recursive(pid, depth, &mut result);
        result
    }

    fn get_tree_recursive(&self, pid: u32, depth: usize, result: &mut Vec<(u32, String, usize)>) {
        if depth == 0 {
            return;
        }
        let name = self.known_processes.get(&pid)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "unknown".into());
        result.push((pid, name, depth));

        if let Some(children) = self.children_map.get(&pid) {
            for &child in children {
                self.get_tree_recursive(child, depth - 1, result);
            }
        }
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
        assert!(monitor.get_all_chains().is_empty());
    }

    #[test]
    fn test_scan_returns_delta() {
        let mut monitor = ProcessMonitor::new(5000);
        let delta = monitor.scan_processes().unwrap();
        assert!(!delta.new_processes.is_empty() || !delta.terminated_processes.is_empty());
    }

    #[test]
    fn test_process_depth_calculation() {
        let monitor = ProcessMonitor::new(5000);
        assert_eq!(monitor.calculate_chain_depth(0), 0);
    }

    #[test]
    fn test_get_process_tree() {
        let monitor = ProcessMonitor::new(5000);
        let tree = monitor.get_process_tree(1, 3);
        assert!(!tree.is_empty());
    }
}
