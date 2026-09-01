use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::error::{CoreError, Result};

pub struct AntiKill {
    protected: Arc<AtomicBool>,
    health_running: Arc<AtomicBool>,
}

impl AntiKill {
    pub fn new() -> Self {
        Self {
            protected: Arc::new(AtomicBool::new(false)),
            health_running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn detect_debugger(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            detect_debugger_windows()
        }

        #[cfg(target_os = "linux")]
        {
            detect_debugger_linux()
        }

        #[cfg(target_os = "macos")]
        {
            detect_debugger_macos()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    pub fn protect_process(&self) -> Result<()> {
        if self.protected.load(Ordering::Relaxed) {
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        {
            protect_process_windows()?;
        }

        self.protected.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub fn monitor_health(&self) -> Result<()> {
        if self.health_running.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.health_running.store(true, Ordering::Relaxed);
        let running = self.health_running.clone();

        thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                if detect_debugger() {
                    eprintln!("[TamperGuard] Debugger detected — terminating process");
                    std::process::exit(1);
                }
                thread::sleep(Duration::from_secs(5));
            }
        });

        Ok(())
    }

    pub fn stop_monitoring(&self) {
        self.health_running.store(false, Ordering::Relaxed);
    }

    pub fn restart_on_crash(&self) -> Result<()> {
        let exe_path = std::env::current_exe()
            .map_err(|e| CoreError::Platform(format!("Failed to get exe path: {e}")))?;

        thread::spawn(move || {
            thread::sleep(Duration::from_secs(2));
            let _ = std::process::Command::new(exe_path)
                .spawn();
        });

        Ok(())
    }
}

impl Default for AntiKill {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
fn detect_debugger_windows() -> bool {
    use std::ffi::CString;

    extern "system" {
        fn IsDebuggerPresent() -> i32;
        fn CheckRemoteDebuggerPresent(h_process: *mut std::ffi::c_void, is_debugger: *mut i32) -> i32;
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
    }

    unsafe {
        if IsDebuggerPresent() != 0 {
            return true;
        }

        let mut is_debugger = 0i32;
        let result = CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut is_debugger);
        if result != 0 && is_debugger != 0 {
            return true;
        }
    }

    false
}

#[cfg(target_os = "linux")]
fn detect_debugger_linux() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|s| s.lines().any(|l| l.starts_with("TracerPid:") && !l.ends_with("TracerPid:\t0")))
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn detect_debugger_macos() -> bool {
    extern "C" {
        fn ptrace(request: i32, pid: i32, addr: *mut std::ffi::c_void, data: i32) -> i32;
    }

    const PT_TRACE_ME: i32 = 1;

    unsafe {
        let result = ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0);
        result == -1
    }
}

#[cfg(target_os = "windows")]
fn protect_process_windows() -> Result<()> {
    use std::ffi::c_void;

    extern "system" {
        fn SetProcessMitigationPolicy(
            policy: u32,
            lp_buffer: *const c_void,
            dw_length: usize,
        ) -> i32;
    }

    const PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY: u32 = 8;

    #[repr(C)]
    struct BinarySignaturePolicy {
        flags: u32,
    }

    unsafe {
        let policy = BinarySignaturePolicy {
            flags: 0x1 | 0x2 | 0x4,
        };

        let result = SetProcessMitigationPolicy(
            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY,
            &policy as *const _ as *const c_void,
            std::mem::size_of::<BinarySignaturePolicy>(),
        );

        if result == 0 {
            return Err(CoreError::Platform(
                "Failed to set process mitigation policy".to_string(),
            ));
        }
    }

    Ok(())
}
