use crate::error::{CoreError, Result};
use crate::platform::ProcessOps;
use crate::process_monitor::ProcessInfo;
use chrono::Utc;
use std::collections::HashMap;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::*;

pub struct WindowsProcessOps;

impl ProcessOps for WindowsProcessOps {
    fn list_processes() -> Result<HashMap<u32, ProcessInfo>> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|e| {
                CoreError::Platform(format!("CreateToolhelp32Snapshot failed: {e}"))
            })?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..std::mem::zeroed()
            };

            let mut processes = HashMap::new();

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    if pid != 0 {
                        let name = extract_name_from_entry(&entry);
                        let (path, memory) = query_process_details(pid);
                        let parent_pid = entry.th32ParentProcessID;

                        processes.insert(
                            pid,
                            ProcessInfo {
                                pid,
                                name,
                                path,
                                command_line: String::new(),
                                parent_pid,
                                user: String::new(),
                                memory_usage_kb: memory,
                                cpu_percent: 0.0,
                                start_time: Utc::now(),
                                hash: None,
                                risk_score: 0,
                                chain_depth: 0,
                                root_pid: parent_pid,
                            },
                        );
                    }

                    if !Process32NextW(snapshot, &mut entry).is_ok() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
            Ok(processes)
        }
    }

    fn kill_process(pid: u32) -> Result<()> {
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|e| {
                CoreError::Platform(format!("OpenProcess failed for pid {pid}: {e}"))
            })?;

            let result = TerminateProcess(handle, 1);
            let _ = CloseHandle(handle);

            result.map_err(|e| {
                CoreError::Platform(format!("TerminateProcess failed for pid {pid}: {e}"))
            })?;
            Ok(())
        }
    }

    fn get_process_info(pid: u32) -> Result<Option<ProcessInfo>> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|e| {
                CoreError::Platform(format!("CreateToolhelp32Snapshot failed: {e}"))
            })?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..std::mem::zeroed()
            };

            let mut found = None;

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID == pid {
                        let name = extract_name_from_entry(&entry);
                        let (path, memory) = query_process_details(pid);
                        let parent_pid = entry.th32ParentProcessID;

                        found = Some(ProcessInfo {
                            pid,
                            name,
                            path,
                            command_line: String::new(),
                            parent_pid,
                            user: String::new(),
                            memory_usage_kb: memory,
                            cpu_percent: 0.0,
                            start_time: Utc::now(),
                            hash: None,
                            risk_score: 0,
                            chain_depth: 0,
                            root_pid: parent_pid,
                        });
                        break;
                    }

                    if !Process32NextW(snapshot, &mut entry).is_ok() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
            Ok(found)
        }
    }
}

fn extract_name_from_entry(entry: &PROCESSENTRY32W) -> String {
    let name_end = entry
        .szExeFile
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(entry.szExeFile.len());
    String::from_utf16_lossy(&entry.szExeFile[..name_end])
}

fn query_process_details(pid: u32) -> (String, u64) {
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(_) => return (String::new(), 0),
        };

        let path = query_process_path(handle);
        let memory = query_process_memory(handle);

        let _ = CloseHandle(handle);
        (path, memory)
    }
}

fn query_process_path(handle: HANDLE) -> String {
    unsafe {
        let mut buf = [0u16; 260];
        let mut size = buf.len() as u32;
        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut size,
        );

        if result.is_ok() {
            String::from_utf16_lossy(&buf[..size as usize])
        } else {
            String::new()
        }
    }
}

fn query_process_memory(handle: HANDLE) -> u64 {
    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(handle, &mut counters, counters.cb).is_ok() {
            (counters.WorkingSetSize / 1024) as u64
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_processes() {
        let result = WindowsProcessOps::list_processes();
        assert!(result.is_ok());
        let processes = result.unwrap();
        assert!(!processes.is_empty());
    }

    #[test]
    fn test_get_process_info_self() {
        let processes = WindowsProcessOps::list_processes().unwrap();
        if let Some((&pid, _)) = processes.iter().next() {
            let info = WindowsProcessOps::get_process_info(pid).unwrap();
            assert!(info.is_some());
        }
    }
}
