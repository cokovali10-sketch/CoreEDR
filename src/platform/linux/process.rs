use crate::error::{CoreError, Result};
use crate::platform::ProcessOps;
use crate::process_monitor::ProcessInfo;
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct LinuxProcessOps;

impl ProcessOps for LinuxProcessOps {
    fn list_processes() -> Result<HashMap<u32, ProcessInfo>> {
        let proc_dir = Path::new("/proc");
        let mut processes = HashMap::new();

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
        match read_process_info(pid) {
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

    let utime = stat_fields.get(13).copied().unwrap_or(0);
    let stime = stat_fields.get(14).copied().unwrap_or(0);
    let cpu_time = utime + stime;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_processes() {
        let result = LinuxProcessOps::list_processes();
        assert!(result.is_ok());
        let processes = result.unwrap();
        assert!(!processes.is_empty());
        assert!(processes.contains_key(&1));
    }

    #[test]
    fn test_get_init_process() {
        let info = LinuxProcessOps::get_process_info(1).unwrap();
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.pid, 1);
    }
}
