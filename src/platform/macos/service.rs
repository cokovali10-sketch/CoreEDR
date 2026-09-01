use crate::error::{CoreError, Result};
use crate::platform::ServiceOps;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

pub struct MacosServiceOps;

const SERVICE_LABEL: &str = "com.coreedr.agent";
const SERVICE_DESCRIPTION: &str = "CoreEDR Endpoint Detection and Response";
const PLIST_PATH: &str = "/Library/LaunchDaemons/com.coreedr.agent.plist";
const PROGRAM_PATH: &str = "/usr/local/bin/coreedr";

impl ServiceOps for MacosServiceOps {
    fn install_service() -> Result<()> {
        let plist_content = generate_plist();
        let plist_path = PathBuf::from(PLIST_PATH);

        fs::write(&plist_path, &plist_content)
            .map_err(|e| CoreError::Platform(format!("Failed to write plist: {e}")))?;

        let output = Command::new("launchctl")
            .args(["load", PLIST_PATH])
            .output()
            .map_err(|e| CoreError::Platform(format!("Failed to load service: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CoreError::Platform(format!(
                "Failed to load service: {stderr}"
            )));
        }

        Ok(())
    }

    fn uninstall_service() -> Result<()> {
        let _ = Command::new("launchctl")
            .args(["unload", PLIST_PATH])
            .output();

        let plist_path = PathBuf::from(PLIST_PATH);
        if plist_path.exists() {
            fs::remove_file(&plist_path)
                .map_err(|e| CoreError::Platform(format!("Failed to remove plist: {e}")))?;
        }

        Ok(())
    }

    fn start_service() -> Result<()> {
        let output = Command::new("launchctl")
            .args(["start", SERVICE_LABEL])
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
        let output = Command::new("launchctl")
            .args(["stop", SERVICE_LABEL])
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
        let output = Command::new("launchctl")
            .args(["list", SERVICE_LABEL])
            .output()
            .map_err(|e| CoreError::Platform(format!("Failed to check service status: {e}")))?;

        if !output.status.success() {
            return Ok(false);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.contains(SERVICE_LABEL))
    }
}

fn generate_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{SERVICE_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{PROGRAM_PATH}</string>
        <string>--service</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/var/log/coreedr.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/coreedr.err</string>

    <key>Description</key>
    <string>{SERVICE_DESCRIPTION}</string>

    <key>ProcessType</key>
    <string>Background</string>

    <key>HardResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>1024</integer>
    </dict>

    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>1024</integer>
    </dict>
</dict>
</plist>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_plist() {
        let content = generate_plist();
        assert!(content.contains("com.coreedr.agent"));
        assert!(content.contains("RunAtLoad"));
        assert!(content.contains("KeepAlive"));
        assert!(content.contains(PROGRAM_PATH));
    }
}
