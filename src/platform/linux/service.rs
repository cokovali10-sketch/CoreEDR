use crate::error::{CoreError, Result};
use crate::platform::ServiceOps;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

pub struct LinuxServiceOps;

const SERVICE_NAME: &str = "coreedr";
const SERVICE_DESCRIPTION: &str = "CoreEDR Endpoint Detection and Response";
const SERVICE_EXEC_START: &str = "/usr/local/bin/coreedr --service";

impl ServiceOps for LinuxServiceOps {
    fn install_service() -> Result<()> {
        let unit_content = generate_unit_file();
        let unit_path = PathBuf::from(format!("/etc/systemd/system/{SERVICE_NAME}.service"));

        fs::write(&unit_path, &unit_content)
            .map_err(|e| CoreError::Platform(format!("Failed to write unit file: {e}")))?;

        let output = Command::new("systemctl")
            .args(["daemon-reload"])
            .output()
            .map_err(|e| CoreError::Platform(format!("Failed to run daemon-reload: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CoreError::Platform(format!(
                "daemon-reload failed: {stderr}"
            )));
        }

        let output = Command::new("systemctl")
            .args(["enable", SERVICE_NAME])
            .output()
            .map_err(|e| CoreError::Platform(format!("Failed to enable service: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CoreError::Platform(format!(
                "Failed to enable service: {stderr}"
            )));
        }

        Ok(())
    }

    fn uninstall_service() -> Result<()> {
        let _ = Command::new("systemctl")
            .args(["stop", SERVICE_NAME])
            .output();

        let output = Command::new("systemctl")
            .args(["disable", SERVICE_NAME])
            .output()
            .map_err(|e| CoreError::Platform(format!("Failed to disable service: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CoreError::Platform(format!(
                "Failed to disable service: {stderr}"
            )));
        }

        let unit_path = PathBuf::from(format!("/etc/systemd/system/{SERVICE_NAME}.service"));
        if unit_path.exists() {
            fs::remove_file(&unit_path)
                .map_err(|e| CoreError::Platform(format!("Failed to remove unit file: {e}")))?;
        }

        let output = Command::new("systemctl")
            .args(["daemon-reload"])
            .output()
            .map_err(|e| CoreError::Platform(format!("Failed to run daemon-reload: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CoreError::Platform(format!(
                "daemon-reload failed: {stderr}"
            )));
        }

        Ok(())
    }

    fn start_service() -> Result<()> {
        let output = Command::new("systemctl")
            .args(["start", SERVICE_NAME])
            .output()
            .map_err(|e| CoreError::Platform(format!("Failed to start service: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CoreError::Platform(format!(
                "Failed to start service: {stderr}"
            )));
        }

        Ok(())
    }

    fn stop_service() -> Result<()> {
        let output = Command::new("systemctl")
            .args(["stop", SERVICE_NAME])
            .output()
            .map_err(|e| CoreError::Platform(format!("Failed to stop service: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CoreError::Platform(format!(
                "Failed to stop service: {stderr}"
            )));
        }

        Ok(())
    }

    fn is_service_running() -> Result<bool> {
        let output = Command::new("systemctl")
            .args(["is-active", SERVICE_NAME])
            .output()
            .map_err(|e| CoreError::Platform(format!("Failed to check service status: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.trim() == "active")
    }
}

fn generate_unit_file() -> String {
    format!(
        r#"[Unit]
Description={SERVICE_DESCRIPTION}
After=network.target

[Service]
Type=simple
ExecStart={SERVICE_EXEC_START}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier={SERVICE_NAME}

[Install]
WantedBy=multi-user.target
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_unit_file() {
        let content = generate_unit_file();
        assert!(content.contains("[Unit]"));
        assert!(content.contains("[Service]"));
        assert!(content.contains("[Install]"));
        assert!(content.contains(SERVICE_DESCRIPTION));
    }
}
