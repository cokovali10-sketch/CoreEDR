#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

use crate::error::CoreError;
use crate::process_monitor::ProcessInfo;
use std::collections::HashMap;

pub trait ProcessOps {
    fn list_processes() -> Result<HashMap<u32, ProcessInfo>, CoreError>;
    fn kill_process(pid: u32) -> Result<(), CoreError>;
    fn get_process_info(pid: u32) -> Result<Option<ProcessInfo>, CoreError>;
}

pub trait ServiceOps {
    fn install_service() -> Result<(), CoreError>;
    fn uninstall_service() -> Result<(), CoreError>;
    fn start_service() -> Result<(), CoreError>;
    fn stop_service() -> Result<(), CoreError>;
    fn is_service_running() -> Result<bool, CoreError>;
}
