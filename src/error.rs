use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Configuration file not found: {path}")]
    ConfigNotFound { path: PathBuf },

    #[error("Scanner error: {0}")]
    Scanner(String),

    #[error("Process monitor error: {0}")]
    ProcessMonitor(String),

    #[error("Heuristic engine error: {0}")]
    Heuristic(String),

    #[error("Rule engine error: {0}")]
    RuleEngine(String),

    #[error("Quarantine error: {0}")]
    Quarantine(String),

    #[error("Alert error: {0}")]
    Alert(String),

    #[error("Logger error: {0}")]
    Logger(String),

    #[error("Hash engine error: {0}")]
    HashEngine(String),

    #[error("YARA error: {0}")]
    Yara(String),

    #[error("ML error: {0}")]
    Ml(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Platform error: {0}")]
    Platform(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Integrity error: {0}")]
    IntegrityError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("IO error: {0}")]
    IoError(String),
}

impl From<Box<dyn std::error::Error>> for CoreError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        CoreError::Internal(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
