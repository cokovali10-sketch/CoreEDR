use crate::error::{CoreError, Result};
use crate::platform::ProcessOps;
use crate::process_monitor::ProcessInfo;
use chrono::Utc;
use std::collections::HashMap;
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::ToolHelp::*;
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};

pub struct WindowsProcessOps;

impl ProcessOps for WindowsProcessOps {
    fn list_processes() -> Result<HashMap<u32, ProcessInfo>> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|e| CoreError::Platform(format!("CreateToolhelp32Snapshot failed: {e}")))?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..std::mem::zeroed()
            };

            let mut processes = HashMap::new();

            if Process32FirstW(snapshot, &mut entry).as_bool() {
                loop {
                    let pid = entry.th32ProcessID;
                    if pid != 0 {
                        let name = extract_name_from_entry(&entry);
                        let (path, memory, parent_pid) = query_process_details(pid);

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
                            },
                        );
                    }

                    if !Process32NextW(snapshot, &mut entry).as_bool() {
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
            let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
                .map_err(|e| CoreError::Platform(format!("OpenProcess failed for pid {pid}: {e}")))?;

            let result = TerminateProcess(handle, 1);
            let _ = CloseHandle(handle);

            result
                .map_err(|e| CoreError::Platform(format!("TerminateProcess failed for pid {pid}: {e}")))?;
            Ok(())
        }
    }

    fn get_process_info(pid: u32) -> Result<Option<ProcessInfo>> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|e| CoreError::Platform(format!("CreateToolhelp32Snapshot failed: {e}")))?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..std::mem::zeroed()
            };

            let mut found = None;

            if Process32FirstW(snapshot, &mut entry).as_bool() {
                loop {
                    if entry.th32ProcessID == pid {
                        let name = extract_name_from_entry(&entry);
                        let (path, memory, parent_pid) = query_process_details(pid);

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
                        });
                        break;
                    }

                    if !Process32NextW(snapshot, &mut entry).as_bool() {
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

fn query_process_details(pid: u32) -> (String, u64, u32) {
    unsafe {
        let handle = match OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        ) {
            Ok(h) => h,
            Err(_) => return (String::new(), 0, 0),
        };

        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let status = NtQueryInformationProcess(
            handle,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        );

        let parent_pid = if status.is_ok() {
            pbi.InheritedFromUniqueProcessId as u32
        } else {
            0
        };

        let path = query_process_path(handle);
        let memory = query_process_memory(handle);

        let _ = CloseHandle(handle);
        (path, memory, parent_pid)
    }
}

fn query_process_path(handle: HANDLE) -> String {
    unsafe {
        let mut buf = [0u16; 260];
        let mut size = buf.len() as u32;
        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            &mut buf,
            &mut size,
        );

        if result.as_bool() {
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
        if GetProcessMemoryInfo(handle, &mut counters, counters.cb).as_bool() {
            counters.WorkingSetSize / 1024
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
