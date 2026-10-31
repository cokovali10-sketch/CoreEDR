pub mod rotation;

use std::path::Path;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_logging(log_level: &str, json_format: bool, log_path: Option<&Path>) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    let builder = fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true);

    if json_format {
        let subscriber = builder.json().finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set logging subscriber");
    } else if let Some(path) = log_path {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("Failed to open log file");

        let subscriber = builder.with_writer(std::sync::Mutex::new(file)).finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set logging subscriber");
    } else {
        let subscriber = builder.with_ansi(true).finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set logging subscriber");
    }
}

pub fn init_logging_from_config(config: &crate::config::Config) {
    init_logging(
        &config.logging.log_level,
        config.logging.json_format,
        Some(&config.logging.log_path),
    );
}
