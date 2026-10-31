use crate::error::{CoreError, Result};
use std::path::Path;

use super::{rules::tag_to_severity, YaraManager, YaraMatch};

impl YaraManager {
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let mut matches = Vec::new();

        for rules in &self.rules {
            let mut scanner = yara_x::Scanner::new(rules);

            let scan_results = scanner
                .scan(data)
                .map_err(|e| CoreError::Yara(format!("Scan error: {}", e)))?;

            for m in scan_results.matching_rules() {
                let rule_name = m.identifier().to_string();
                let namespace = m.namespace().to_string();
                let tags: Vec<String> = m.tags().map(|t| t.identifier().to_string()).collect();
                let severity = tag_to_severity(&tags);

                let description = m
                    .metadata()
                    .find(|(k, _)| *k == "description")
                    .map(|(_, v)| match v {
                        yara_x::MetaValue::String(s) => s.to_string(),
                        _ => String::new(),
                    })
                    .unwrap_or_default();

                matches.push(YaraMatch {
                    rule_name,
                    namespace,
                    severity,
                    description,
                    matched_strings: Vec::new(),
                    process_pid: None,
                    file_path: None,
                });
            }
        }

        Ok(matches)
    }


    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>> {
        let data = std::fs::read(path).map_err(|e| {
            CoreError::Yara(format!(
                "Failed to read file for scanning {}: {}",
                path.display(),
                e
            ))
        })?;

        let mut matches = self.scan_bytes(&data)?;
        for m in &mut matches {
            m.file_path = Some(path.display().to_string());
        }
        Ok(matches)
    }

    pub fn scan_process(&self, pid: u32) -> Result<Vec<YaraMatch>> {
        let data = read_process_memory(pid)?;
        let mut matches = self.scan_bytes(&data)?;
        for m in &mut matches {
            m.process_pid = Some(pid);
        }
        Ok(matches)
    }
}

#[cfg(target_os = "linux")]
fn read_process_memory(pid: u32) -> Result<Vec<u8>> {
    use std::io::Read;

    let mem_path = format!("/proc/{}/mem", pid);
    let maps_path = format!("/proc/{}/maps", pid);

    let maps = std::fs::read_to_string(&maps_path).map_err(|e| {
        CoreError::Yara(format!(
            "Failed to read process maps for PID {}: {}",
            pid, e
        ))
    })?;

    let mut data = Vec::new();
    let mut file = std::fs::File::open(&mem_path).map_err(|e| {
        CoreError::Yara(format!(
            "Failed to open process memory for PID {}: {}",
            pid, e
        ))
    })?;

    for line in maps.lines() {
        if let Some(range) = line.split_whitespace().next() {
            if let Some((start_str, end_str)) = range.split_once('-') {
                if let (Ok(start), Ok(end)) = (
                    u64::from_str_radix(start_str, 16),
                    u64::from_str_radix(end_str, 16),
                ) {
                    let size = (end - start) as usize;
                    if size > 0 && size < 100 * 1024 * 1024 {
                        let _ = file.seek(std::io::SeekFrom::Start(start));
                        let mut buf = vec![0u8; size.min(4096)];
                        if file.read(&mut buf).is_ok() {
                            data.extend_from_slice(&buf);
                        }
                    }
                }
            }
        }
    }

    Ok(data)
}

#[cfg(target_os = "windows")]
fn read_process_memory(pid: u32) -> Result<Vec<u8>> {
    use std::mem;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let handle =
            OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid).map_err(|e| {
                CoreError::Yara(format!("Failed to open process with PID {}: {}", pid, e))
            })?;

        if handle == INVALID_HANDLE_VALUE {
            return Err(CoreError::Yara(format!(
                "Invalid handle for process PID {}",
                pid
            )));
        }

        let mut data = Vec::new();
        let mut address: usize = 0;
        let mut mbi: windows::Win32::System::SystemInformation::SYSTEM_INFO = mem::zeroed();

        windows::Win32::System::SystemInformation::GetSystemInfo(&mut mbi);

        let min_addr = mbi.lpMinimumApplicationAddress as usize;
        let max_addr = mbi.lpMaximumApplicationAddress as usize;

        while address < max_addr {
            let mut info: windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION = mem::zeroed();

            let result = windows::Win32::System::Memory::VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut info,
                mem::size_of::<windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                address += 4096;
                continue;
            }

            if info.State == windows::Win32::System::Memory::MEM_COMMIT {
                let region_size = info.RegionSize;
                if region_size > 0 && region_size < 100 * 1024 * 1024 {
                    let mut buf = vec![0u8; region_size.min(4096)];
                    let mut bytes_read = 0usize;

                    let read_result = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                        handle,
                        address as *const _,
                        buf.as_mut_ptr() as _,
                        buf.len(),
                        Some(&mut bytes_read),
                    );

                    if read_result.is_ok() {
                        buf.truncate(bytes_read);
                        data.extend_from_slice(&buf);
                    }
                }
            }

            address += info.RegionSize.max(4096);
        }

        CloseHandle(handle).ok();
        Ok(data)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn read_process_memory(pid: u32) -> Result<Vec<u8>> {
    Err(CoreError::Yara(format!(
        "Process memory scanning not supported on this platform for PID {}",
        pid
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_bytes_empty_rules() {
        let m = YaraManager::new();
        let r = m.scan_bytes(b"hello").unwrap();
        assert!(r.is_empty());
    }
}
