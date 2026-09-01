use crate::error::{CoreError, Result};

pub struct ElevationChecker;

impl ElevationChecker {
    pub fn new() -> Self {
        Self
    }

    pub fn is_elevated(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            is_elevated_windows()
        }

        #[cfg(target_os = "linux")]
        {
            is_elevated_unix()
        }

        #[cfg(target_os = "macos")]
        {
            is_elevated_unix()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    pub fn request_elevation(&self) -> Result<()> {
        if self.is_elevated() {
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        {
            request_elevation_windows()
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(CoreError::PermissionDenied(
                "Please run with sudo or as root".to_string(),
            ))
        }
    }

    pub fn ensure_elevated(&self) -> Result<()> {
        if !self.is_elevated() {
            return Err(CoreError::PermissionDenied(
                "Root/administrator privileges required".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for ElevationChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
fn is_elevated_windows() -> bool {
    use std::ffi::c_void;

    extern "system" {
        fn OpenProcessToken(
            process_handle: *mut c_void,
            desired_access: u32,
            token_handle: *mut *mut c_void,
        ) -> i32;

        fn GetCurrentProcess() -> *mut c_void;

        fn GetTokenInformation(
            token_handle: *mut c_void,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        fn CloseHandle(hObject: *mut c_void) -> i32;
    }

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION: u32 = 20;

    unsafe {
        let mut token_handle: *mut c_void = std::ptr::null_mut();

        let result = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token_handle,
        );

        if result == 0 {
            return false;
        }

        let mut elevation: u32 = 0;
        let mut return_length: u32 = 0;

        let result = GetTokenInformation(
            token_handle,
            TOKEN_ELEVATION,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<u32>() as u32,
            &mut return_length,
        );

        CloseHandle(token_handle);

        result != 0 && elevation != 0
    }
}

#[cfg(target_os = "linux")]
fn is_elevated_unix() -> bool {
    extern "C" {
        fn geteuid() -> u32;
    }

    unsafe { geteuid() == 0 }
}

#[cfg(target_os = "windows")]
fn request_elevation_windows() -> Result<()> {
    use std::ffi::CString;

    extern "system" {
        fn ShellExecuteA(
            hwnd: *mut std::ffi::c_void,
            lp_operation: *const i8,
            lp_file: *const i8,
            lp_parameters: *const i8,
            lp_directory: *const i8,
            n_show_cmd: i32,
        ) -> *mut std::ffi::c_void;
    }

    let exe_path = std::env::current_exe()
        .map_err(|e| CoreError::Platform(format!("Failed to get exe path: {e}")))?;

    let path_str = CString::new(exe_path.to_string_lossy().as_bytes().to_vec())
        .map_err(|e| CoreError::Platform(format!("Invalid path: {e}")))?;

    let verb = CString::new("runas").unwrap();

    unsafe {
        let result = ShellExecuteA(
            std::ptr::null_mut(),
            verb.as_ptr(),
            path_str.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        );

        let handle = result as isize;
        if handle <= 32 {
            return Err(CoreError::PermissionDenied(
                "Failed to request UAC elevation".to_string(),
            ));
        }
    }

    std::process::exit(0);
}
