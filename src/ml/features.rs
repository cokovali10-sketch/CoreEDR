use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    pub entropy: f64,
    pub file_size: u64,
    pub string_ratio: f64,
    pub import_count: usize,
    pub section_count: usize,
    pub has_debug_info: bool,
    pub has_overlay: bool,
    pub timestamp_anomaly: bool,
    pub high_entropy_sections: usize,
    pub suspicious_imports: usize,
    pub pe_characteristics: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub compilation_timestamp: u32,
    pub rich_header_present: bool,
    pub tls_callbacks: usize,
    pub resources_count: usize,
    pub avg_section_entropy: f64,
    pub max_section_entropy: f64,
    pub suspicious_strings_count: usize,
}

impl FeatureVector {
    pub fn to_array(&self) -> Vec<f64> {
        vec![
            self.entropy,
            self.file_size as f64,
            self.string_ratio,
            self.import_count as f64,
            self.section_count as f64,
            self.has_debug_info as u8 as f64,
            self.has_overlay as u8 as f64,
            self.timestamp_anomaly as u8 as f64,
            self.high_entropy_sections as f64,
            self.suspicious_imports as f64,
            self.pe_characteristics as f64,
            self.subsystem as f64,
            self.dll_characteristics as f64,
            self.compilation_timestamp as f64,
            self.rich_header_present as u8 as f64,
            self.tls_callbacks as f64,
            self.resources_count as f64,
            self.avg_section_entropy,
            self.max_section_entropy,
            self.suspicious_strings_count as f64,
        ]
    }

    pub fn feature_names() -> Vec<&'static str> {
        vec![
            "entropy",
            "file_size",
            "string_ratio",
            "import_count",
            "section_count",
            "has_debug_info",
            "has_overlay",
            "timestamp_anomaly",
            "high_entropy_sections",
            "suspicious_imports",
            "pe_characteristics",
            "subsystem",
            "dll_characteristics",
            "compilation_timestamp",
            "rich_header_present",
            "tls_callbacks",
            "resources_count",
            "avg_section_entropy",
            "max_section_entropy",
            "suspicious_strings_count",
        ]
    }
}

pub fn extract_features_from_file(path: &Path) -> Result<FeatureVector> {
    let data = fs::read(path)
        .map_err(|e| CoreError::Ml(format!("Failed to read file {}: {e}", path.display())))?;
    extract_features_from_bytes(&data)
}

pub fn extract_features_from_bytes(data: &[u8]) -> Result<FeatureVector> {
    if data.len() < 64 {
        return Err(CoreError::Ml("File too small to analyze".to_string()));
    }

    let entropy = compute_entropy(data);
    let file_size = data.len() as u64;
    let string_ratio = compute_string_ratio(data);
    let (section_count, avg_section_entropy, max_section_entropy, high_entropy_sections) =
        analyze_sections(data);
    let (import_count, suspicious_imports) = analyze_imports(data);
    let has_debug_info = check_debug_info(data);
    let has_overlay = check_overlay(data, section_count);
    let timestamp_anomaly = check_timestamp_anomaly(data);
    let pe_characteristics = get_pe_characteristics(data);
    let subsystem = get_subsystem(data);
    let dll_characteristics = get_dll_characteristics(data);
    let compilation_timestamp = get_compilation_timestamp(data);
    let rich_header_present = check_rich_header(data);
    let tls_callbacks = count_tls_callbacks(data);
    let resources_count = count_resources(data);
    let suspicious_strings_count = count_suspicious_strings(data);

    Ok(FeatureVector {
        entropy,
        file_size,
        string_ratio,
        import_count,
        section_count,
        has_debug_info,
        has_overlay,
        timestamp_anomaly,
        high_entropy_sections,
        suspicious_imports,
        pe_characteristics,
        subsystem,
        dll_characteristics,
        compilation_timestamp,
        rich_header_present,
        tls_callbacks,
        resources_count,
        avg_section_entropy,
        max_section_entropy,
        suspicious_strings_count,
    })
}

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn compute_string_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7E).contains(&b) || b == 0x09 || b == 0x0A || b == 0x0D)
        .count();

    printable as f64 / data.len() as f64
}

fn analyze_sections(data: &[u8]) -> (usize, f64, f64, usize) {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return (0, 0.0, 0.0, 0);
    }

    let pe_offset = read_u32_le(data, 0x3C) as usize;
    if pe_offset + 6 >= data.len() {
        return (0, 0.0, 0.0, 0);
    }

    if data[pe_offset] != b'P' || data[pe_offset + 1] != b'E' {
        return (0, 0.0, 0.0, 0);
    }

    let num_sections = read_u16_le(data, pe_offset + 6) as usize;
    let optional_header_size = read_u16_le(data, pe_offset + 20) as usize;
    let section_header_offset = pe_offset + 24 + optional_header_size;

    let mut entropies = Vec::new();
    let mut high_count = 0;

    for i in 0..num_sections {
        let offset = section_header_offset + (i * 40);
        if offset + 40 > data.len() {
            break;
        }

        let raw_size = read_u32_le(data, offset + 16) as usize;
        let raw_ptr = read_u32_le(data, offset + 20) as usize;

        if raw_size > 0 && raw_ptr + raw_size <= data.len() {
            let section_data = &data[raw_ptr..raw_ptr + raw_size];
            let ent = compute_entropy(section_data);
            entropies.push(ent);
            if ent > 7.0 {
                high_count += 1;
            }
        }
    }

    let section_count = num_sections;
    let avg = if entropies.is_empty() {
        0.0
    } else {
        entropies.iter().sum::<f64>() / entropies.len() as f64
    };
    let max = entropies.iter().cloned().fold(0.0f64, f64::max);

    (section_count, avg, max, high_count)
}

fn analyze_imports(data: &[u8]) -> (usize, usize) {
    let suspicious_names: &[&str] = &[
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "GetTickCount",
        "Sleep",
        "URLDownloadToFile",
        "WinHttpOpen",
        "InternetOpenA",
        "CryptEncrypt",
        "CryptDecrypt",
        "OpenProcess",
    ];

    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return (0, 0);
    }

    let pe_offset = read_u32_le(data, 0x3C) as usize;
    if pe_offset + 24 >= data.len() {
        return (0, 0);
    }

    let optional_header_offset = pe_offset + 24;
    let magic = read_u16_le(data, optional_header_offset);
    let import_rva_offset = if magic == 0x20B {
        optional_header_offset + 112
    } else {
        optional_header_offset + 104
    };

    if import_rva_offset + 8 > data.len() {
        return (0, 0);
    }

    let _import_rva = read_u32_le(data, import_rva_offset);
    let import_size = read_u32_le(data, import_rva_offset + 4);

    let import_count = (import_size / 20) as usize;
    let suspicious = count_suspicious_import_names(data, suspicious_names);

    (import_count, suspicious)
}

fn count_suspicious_import_names(data: &[u8], names: &[&str]) -> usize {
    let text = String::from_utf8_lossy(data);
    names.iter().filter(|name| text.contains(*name)).count()
}

fn check_debug_info(data: &[u8]) -> bool {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return false;
    }

    let pe_offset = read_u32_le(data, 0x3C) as usize;
    if pe_offset + 96 > data.len() {
        return false;
    }

    let debug_rva = read_u32_le(data, pe_offset + 120);
    debug_rva != 0
}

fn check_overlay(data: &[u8], section_count: usize) -> bool {
    if section_count == 0 || data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return false;
    }

    let pe_offset = read_u32_le(data, 0x3C) as usize;
    if pe_offset + 6 >= data.len() {
        return false;
    }

    let num_sections = read_u16_le(data, pe_offset + 6) as usize;
    let optional_header_size = read_u16_le(data, pe_offset + 20) as usize;
    let section_header_offset = pe_offset + 24 + optional_header_size;

    let mut max_end = 0;
    for i in 0..num_sections {
        let offset = section_header_offset + (i * 40);
        if offset + 40 > data.len() {
            break;
        }

        let raw_size = read_u32_le(data, offset + 16) as usize;
        let raw_ptr = read_u32_le(data, offset + 20) as usize;
        let end = raw_ptr + raw_size;
        if end > max_end {
            max_end = end;
        }
    }

    max_end > 0 && max_end < data.len()
}

fn check_timestamp_anomaly(data: &[u8]) -> bool {
    let ts = get_compilation_timestamp(data);
    if ts == 0 {
        return false;
    }

    let now = chrono::Utc::now().timestamp() as u32;
    let thirty_years = 30 * 365 * 24 * 3600;

    ts > now + 86400 || ts < now.saturating_sub(thirty_years)
}

fn get_pe_characteristics(data: &[u8]) -> u16 {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return 0;
    }
    let pe_offset = read_u32_le(data, 0x3C) as usize;
    if pe_offset + 22 >= data.len() {
        return 0;
    }
    read_u16_le(data, pe_offset + 22)
}

fn get_subsystem(data: &[u8]) -> u16 {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return 0;
    }
    let pe_offset = read_u32_le(data, 0x3C) as usize;
    let optional_header_offset = pe_offset + 24;
    if optional_header_offset + 68 > data.len() {
        return 0;
    }
    read_u16_le(data, optional_header_offset + 68)
}

fn get_dll_characteristics(data: &[u8]) -> u16 {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return 0;
    }
    let pe_offset = read_u32_le(data, 0x3C) as usize;
    let optional_header_offset = pe_offset + 24;
    if optional_header_offset + 46 > data.len() {
        return 0;
    }
    read_u16_le(data, optional_header_offset + 46)
}

fn get_compilation_timestamp(data: &[u8]) -> u32 {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return 0;
    }
    let pe_offset = read_u32_le(data, 0x3C) as usize;
    if pe_offset + 8 >= data.len() {
        return 0;
    }
    read_u32_le(data, pe_offset + 8)
}

fn check_rich_header(data: &[u8]) -> bool {
    data.len() >= 0x80 && data.windows(4).any(|w| w == *b"Rich")
}

fn count_tls_callbacks(data: &[u8]) -> usize {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return 0;
    }
    let pe_offset = read_u32_le(data, 0x3C) as usize;
    let optional_header_offset = pe_offset + 24;
    if optional_header_offset + 92 > data.len() {
        return 0;
    }
    let tls_rva = read_u32_le(data, optional_header_offset + 92);
    if tls_rva == 0 {
        return 0;
    }
    1
}

fn count_resources(data: &[u8]) -> usize {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return 0;
    }
    let pe_offset = read_u32_le(data, 0x3C) as usize;
    let optional_header_offset = pe_offset + 24;
    let magic = read_u16_le(data, optional_header_offset);
    let resource_rva_offset = if magic == 0x20B {
        optional_header_offset + 108
    } else {
        optional_header_offset + 96
    };

    if resource_rva_offset + 8 > data.len() {
        return 0;
    }

    let resource_rva = read_u32_le(data, resource_rva_offset);
    let resource_size = read_u32_le(data, resource_rva_offset + 4);

    if resource_rva == 0 || resource_size == 0 {
        return 0;
    }

    (resource_size / 8) as usize
}

fn count_suspicious_strings(data: &[u8]) -> usize {
    let suspicious = [
        "cmd.exe",
        "powershell",
        "wscript",
        "cscript",
        "mshta",
        "regsvr32",
        "rundll32",
        "certutil",
        "bitsadmin",
        "wmic",
        "net.exe",
        "net1.exe",
        "sc.exe",
        "at.exe",
        "schtasks",
        "hkey_local_machine",
        "hkey_current_user",
        "/etc/passwd",
        "/etc/shadow",
        ".ssh/",
        "mimikatz",
        "lazagne",
        "procdump",
    ];

    let text = String::from_utf8_lossy(data).to_lowercase();
    suspicious.iter().filter(|s| text.contains(**s)).count()
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}
