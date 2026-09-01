use crate::error::{CoreError, Result};
use crate::platform::ServiceOps;
use std::ffi::OsString;
use std::time::Duration;
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult, ServiceStatus};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub struct WindowsServiceOps;

const SERVICE_NAME: &str = "CoreEDR";
const SERVICE_DISPLAY_NAME: &str = "CoreEDR Endpoint Detection and Response";
const SERVICE_DESCRIPTION: &str = "Real-time endpoint detection, threat analysis, and containment service";

impl ServiceOps for WindowsServiceOps {
    fn install_service() -> Result<()> {
        let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
        let manager = ServiceManager::local_computer(None::<&str>, manager_access)
            .map_err(|e| CoreError::Platform(format!("Failed to open service manager: {e}")))?;

        let exe_path = std::env::current_exe()
            .map_err(|e| CoreError::Platform(format!("Failed to get exe path: {e}")))?;

        let service_info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe_path,
            launch_arguments: vec![OsString::from("--service")],
            dependencies: vec![],
            account_name: None,
            account_password: None,
            ..Default::default()
        };

        let service = manager
            .create_service(&service_info, ServiceAccess::ALL_ACCESS)
            .map_err(|e| CoreError::Platform(format!("Failed to create service: {e}")))?;

        service
            .set_description(SERVICE_DESCRIPTION)
            .map_err(|e| CoreError::Platform(format!("Failed to set service description: {e}")))?;

        Ok(())
    }

    fn uninstall_service() -> Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT,
        )
        .map_err(|e| CoreError::Platform(format!("Failed to open service manager: {e}")))?;

        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::ALL_ACCESS)
            .map_err(|e| CoreError::Platform(format!("Failed to open service: {e}")))?;

        let status = service
            .query_status()
            .map_err(|e| CoreError::Platform(format!("Failed to query service status: {e}")))?;

        if status.current_state != ServiceState::Stopped {
            service
                .stop()
                .map_err(|e| CoreError::Platform(format!("Failed to stop service: {e}")))?;

            std::thread::sleep(Duration::from_secs(2));
        }

        service
            .delete()
            .map_err(|e| CoreError::Platform(format!("Failed to delete service: {e}")))?;

        Ok(())
    }

    fn start_service() -> Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT,
        )
        .map_err(|e| CoreError::Platform(format!("Failed to open service manager: {e}")))?;

        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::START)
            .map_err(|e| CoreError::Platform(format!("Failed to open service: {e}")))?;

        service
            .start(&[OsString::from("--service")])
            .map_err(|e| CoreError::Platform(format!("Failed to start service: {e}")))?;

        Ok(())
    }

    fn stop_service() -> Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT,
        )
        .map_err(|e| CoreError::Platform(format!("Failed to open service manager: {e}")))?;

        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::STOP)
            .map_err(|e| CoreError::Platform(format!("Failed to open service: {e}")))?;

        let status = service
            .query_status()
            .map_err(|e| CoreError::Platform(format!("Failed to query service status: {e}")))?;

        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }

        service
            .stop()
            .map_err(|e| CoreError::Platform(format!("Failed to stop service: {e}")))?;

        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .map_err(|e| CoreError::Platform(format!("Failed to open service for status: {e}")))?;

        let mut last_status = service
            .query_status()
            .map_err(|e| CoreError::Platform(format!("Failed to query status: {e}")))?;

        while last_status.current_state != ServiceState::Stopped {
            std::thread::sleep(Duration::from_secs(1));
            last_status = service
                .query_status()
                .map_err(|e| CoreError::Platform(format!("Failed to query status: {e}")))?;

            if last_status.current_state == ServiceState::StopPending {
                continue;
            }

            if last_status.current_state != ServiceState::Stopped {
                return Err(CoreError::Platform(format!(
                    "Service stopped with unexpected state: {:?}",
                    last_status.current_state
                )));
            }
        }

        Ok(())
    }

    fn is_service_running() -> Result<bool> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT,
        )
        .map_err(|e| CoreError::Platform(format!("Failed to open service manager: {e}")))?;

        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .map_err(|e| CoreError::Platform(format!("Failed to open service: {e}")))?;

        let status = service
            .query_status()
            .map_err(|e| CoreError::Platform(format!("Failed to query service status: {e}")))?;

        Ok(status.current_state == ServiceState::Running)
    }
}

pub fn run_service() -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel::<ServiceControl>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = tx.send(ServiceControl::Stop);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Pause => ServiceControlHandlerResult::NotImplemented,
            ServiceControl::Continue => ServiceControlHandlerResult::NotImplemented,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(|e| CoreError::Platform(format!("Failed to register control handler: {e}")))?;

    let _ = status_handle
        .set_service_status(&ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::ServiceSpecific(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|e| CoreError::Platform(format!("Failed to set running status: {e}")))?;

    loop {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(ServiceControl::Stop) => {
                let _ = status_handle
                    .set_service_status(&ServiceStatus {
                        service_type: ServiceType::OWN_PROCESS,
                        current_state: ServiceState::StopPending,
                        controls_accepted: ServiceControlAccept::empty(),
                        exit_code: ServiceExitCode::ServiceSpecific(0),
                        checkpoint: 0,
                        wait_hint: Duration::from_secs(10),
                        process_id: None,
                    });
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            _ => {}
        }
    }

    let _ = status_handle
        .set_service_status(&ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::ServiceSpecific(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });

    Ok(())
}
