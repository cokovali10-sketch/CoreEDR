use crate::error::{CoreError, Result};
use std::path::Path;

use super::YaraManager;

impl YaraManager {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
        }
    }

    pub fn compile_rules(&mut self, source: &str) -> Result<()> {
        let mut compiler = yara_x::Compiler::new()
            .map_err(|e| CoreError::Yara(format!("Failed to create compiler: {}", e)))?;

        compiler
            .add_rules(source.as_bytes())
            .map_err(|e| CoreError::Yara(format!("Failed to add rules: {}", e)))?;

        let compiled = compiler
            .compile_rules()
            .map_err(|e| CoreError::Yara(format!("Failed to compile rules: {}", e)))?;

        self.rules.push(compiled);
        Ok(())
    }

    pub fn compile_rules_from_file(&mut self, path: &Path) -> Result<()> {
        let source = std::fs::read_to_string(path).map_err(|e| {
            CoreError::Yara(format!(
                "Failed to read rules file {}: {}",
                path.display(),
                e
            ))
        })?;
        self.compile_rules(&source)
    }

    pub fn compile_rules_from_dir(&mut self, dir: &Path) -> Result<()> {
        let entries = std::fs::read_dir(dir).map_err(|e| {
            CoreError::Yara(format!(
                "Failed to read rules directory {}: {}",
                dir.display(),
                e
            ))
        })?;

        let mut compiled_count = 0u32;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "yar" || e == "yara").unwrap_or(false) {
                match self.compile_rules_from_file(&path) {
                    Ok(()) => compiled_count += 1,
                    Err(e) => {
                        eprintln!("Warning: skipping {}: {}", path.display(), e);
                    }
                }
            }
        }

        if compiled_count == 0 {
            return Err(CoreError::Yara(format!(
                "No valid YARA rules found in {}",
                dir.display()
            )));
        }

        Ok(())
    }

    pub fn load_default_rules(&mut self) -> Result<()> {
        let rule_sources = vec![
            ("malware_generic", super::default_rules::MALWARE_GENERIC),
            (
                "suspicious_powershell",
                super::default_rules::SUSPICIOUS_POWERSHELL,
            ),
            (
                "credential_dumping",
                super::default_rules::CREDENTIAL_DUMPING,
            ),
            ("ransomware", super::default_rules::RANSOMWARE),
            ("webshell", super::default_rules::WEBSHELL),
            ("encoded_exec", super::default_rules::ENCODED_EXEC),
        ];

        for (name, source) in rule_sources {
            match self.compile_rules(source) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Warning: failed to compile default rule {}: {}", name, e);
                }
            }
        }

        Ok(())
    }

    pub fn save_compiled(&self, path: &Path) -> Result<()> {
        if self.rules.is_empty() {
            return Err(CoreError::Yara("No compiled rules to save".to_string()));
        }

        let mut combined = Vec::new();
        for rule in &self.rules {
            let bytes = rule
                .serialize()
                .map_err(|e| CoreError::Yara(format!("Failed to serialize rule: {}", e)))?;
            combined.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            combined.extend_from_slice(&bytes);
        }
        std::fs::write(path, combined)?;
        Ok(())
    }

    pub fn load_compiled(&mut self, path: &Path) -> Result<()> {
        let bytes = std::fs::read(path).map_err(|e| {
            CoreError::Yara(format!(
                "Failed to read compiled rules {}: {}",
                path.display(),
                e
            ))
        })?;

        let rules = yara_x::Rules::deserialize(&bytes)
            .map_err(|e| CoreError::Yara(format!("Failed to deserialize rules: {}", e)))?;

        self.rules.push(rules);
        Ok(())
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}
