pub mod anti_kill;
pub mod elevation;
pub mod integrity;
pub mod watchdog;

use crate::error::CoreError;

pub struct TamperGuard {
    pub integrity_checker: integrity::IntegrityChecker,
    pub anti_kill: anti_kill::AntiKill,
    pub elevation: elevation::ElevationChecker,
}

impl TamperGuard {
    pub fn new() -> Self {
        Self {
            integrity_checker: integrity::IntegrityChecker::new(),
            anti_kill: anti_kill::AntiKill::new(),
            elevation: elevation::ElevationChecker::new(),
        }
    }

    pub fn initialize(&self) -> crate::error::Result<()> {
        self.integrity_checker.store_current_hash()?;
        self.anti_kill.protect_process()?;
        Ok(())
    }

    pub fn verify_integrity(&self) -> crate::error::Result<bool> {
        self.integrity_checker.verify_self_integrity()
    }
}

impl Default for TamperGuard {
    fn default() -> Self {
        Self::new()
    }
}
