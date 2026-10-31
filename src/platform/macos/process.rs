use crate::error::{CoreError, Result};
use crate::platform::ProcessOps;
use crate::process_monitor::ProcessInfo;
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct MacosProcessOps;

impl ProcessOps for MacosProcessOps {
    fn list_processes() -> Result<HashMap<u32, ProcessInfo>> {
        let proc_dir = Path::new("/proc");
        let mut processes = HashMap::new();

        if !proc_dir.exists() {
            return list_processes_via_sysctl();
        }

        let entries = fs::read_dir(proc_dir)
            .map_err(|e| CoreError::Platform(format!("Failed to read /proc: {e}")))?;

        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(pid_str) = name.to_str() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if let Ok(info) = read_process_info(pid) {
                        processes.insert(pid, info);
                    }
                }
            }
        }

        if processes.is_empty() {
            return list_processes_via_sysctl();
        }

        Ok(processes)
    }

    fn kill_process(pid: u32) -> Result<()> {
        unsafe {
            let result = libc::kill(pid as i32, libc::SIGTERM);
            if result == -1 {
                let err = std::io::Error::last_os_error();
                return Err(CoreError::Platform(format!(
                    "Failed to kill process {pid}: {err}"
                )));
            }
        }
        Ok(())
    }

    fn get_process_info(pid: u32) -> Result<Option<ProcessInfo>> {
        if Path::new("/proc").exists() {
            match read_process_info(pid) {
                Ok(info) => return Ok(Some(info)),
                Err(CoreError::Platform(_)) => {}
                Err(e) => return Err(e),
            }
        }

        match get_process_info_via_sysctl(pid) {
            Ok(info) => Ok(Some(info)),
            Err(CoreError::Platform(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn read_process_info(pid: u32) -> Result<ProcessInfo> {
    let stat_path = format!("/proc/{pid}/stat");
    let stat_content = fs::read_to_string(&stat_path)
        .map_err(|e| CoreError::Platform(format!("Failed to read {stat_path}: {e}")))?;

    let (comm, stat_fields) = parse_stat_file(&stat_content);

    let ppid = stat_fields.get(3).copied().unwrap_or(0) as u32;

    let status_path = format!("/proc/{pid}/status");
    let status_content = fs::read_to_string(&status_path).unwrap_or_default();
    let vm_rss = parse_status_field(&status_content, "VmRSS").unwrap_or(0);

    let cmdline_path = format!("/proc/{pid}/cmdline");
    let cmdline_bytes = fs::read(&cmdline_path).unwrap_or_default();
    let cmdline = String::from_utf8_lossy(&cmdline_bytes)
        .replace('\0', " ")
        .trim()
        .to_string();

    let exe_path = format!("/proc/{pid}/exe");
    let path = fs::read_link(&exe_path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| format!("/proc/{pid}"));

    Ok(ProcessInfo {
        pid,
        name: comm,
        path,
        command_line: cmdline,
        parent_pid: ppid,
        user: String::new(),
        memory_usage_kb: vm_rss,
        cpu_percent: 0.0,
        start_time: Utc::now(),
        hash: None,
        risk_score: 0,
        chain_depth: 0,
        root_pid: ppid,
    })
}

fn parse_stat_file(content: &str) -> (String, Vec<u64>) {
    let open_paren = content.find('(').unwrap_or(0);
    let close_paren = content.rfind(')').unwrap_or(content.len());

    let comm = content[open_paren + 1..close_paren].to_string();

    let after_comm = &content[close_paren + 2..];
    let fields: Vec<u64> = after_comm
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();

    (comm, fields)
}

fn parse_status_field(content: &str, field: &str) -> Option<u64> {
    for line in content.lines() {
        if line.starts_with(field) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }
    None
}

fn list_processes_via_sysctl() -> Result<HashMap<u32, ProcessInfo>> {
    let output = std::process::Command::new("ps")
        .args(["-eo", "pid,ppid,comm", "-x"])
        .output()
        .map_err(|e| CoreError::Platform(format!("Failed to run ps: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CoreError::Platform(format!("ps failed: {stderr}")));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes = HashMap::new();

    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            if let Ok(pid) = parts[0].parse::<u32>() {
                let ppid = parts[1].parse::<u32>().unwrap_or(0);
                let name = parts[2..].join(" ");

                processes.insert(
                    pid,
                    ProcessInfo {
                        pid,
                        name,
                        path: String::new(),
                        command_line: String::new(),
                        parent_pid: ppid,
                        user: String::new(),
                        memory_usage_kb: 0,
                        cpu_percent: 0.0,
                        start_time: Utc::now(),
                        hash: None,
                        risk_score: 0,
                        chain_depth: 0,
                        root_pid: ppid,
                    },
                );
            }
        }
    }

    Ok(processes)
}

fn get_process_info_via_sysctl(pid: u32) -> Result<ProcessInfo> {
    let output = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid,ppid,comm"])
        .output()
        .map_err(|e| CoreError::Platform(format!("Failed to run ps: {e}")))?;

    if !output.status.success() {
        return Err(CoreError::Platform(format!("Process {pid} not found")));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();

    if lines.len() < 2 {
        return Err(CoreError::Platform(format!(
            "Unexpected ps output for pid {pid}"
        )));
    }

    let parts: Vec<&str> = lines[1].split_whitespace().collect();
    if parts.len() < 3 {
        return Err(CoreError::Platform(format!(
            "Unexpected ps output format for pid {pid}"
        )));
    }

    let ppid = parts[1].parse::<u32>().unwrap_or(0);
    let name = parts[2..].join(" ");

    Ok(ProcessInfo {
        pid,
        name,
        path: String::new(),
        command_line: String::new(),
        parent_pid: ppid,
        user: String::new(),
        memory_usage_kb: 0,
        cpu_percent: 0.0,
        start_time: Utc::now(),
        hash: None,
        risk_score: 0,
        chain_depth: 0,
        root_pid: ppid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_processes() {
        let result = MacosProcessOps::list_processes();
        assert!(result.is_ok());
        let processes = result.unwrap();
        assert!(!processes.is_empty());
    }
}
