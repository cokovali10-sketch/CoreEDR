# Changelog

All notable changes to CoreEDR are documented in this file.

## [0.2.1] - 2026-10-31

### Fixed
- Project now compiles on Windows (GNU toolchain) and Linux.
- Replaced nonexistent `windows` crate feature `Win32_ToolHelp32` with `Win32_System_Diagnostics_ToolHelp`.
- Corrected WinAPI module paths (`System::ToolHelp` -> `System::Diagnostics::ToolHelp`).
- Fixed `ProcessInfo` literals missing `chain_depth`/`root_pid` fields.
- Fixed missing `Clone` derives on `ThreatSummary`, `AlertStats`, `LoggerStats`.
- Fixed enum derives for `Protocol`/`ConnectionState`.
- Fixed `.severity()` calls (field access) in behavioral analyzer.
- Fixed ML trainer label cast and feature string matching.
- Fixed MITRE mapper parent technique reference.
- Fixed benchmark compilation against real APIs.
- Fixed quarantine restore encryption gating.
- Fixed logger JSON output flushing.
- Fixed Windows process enumeration (removed dependency on `wmic`).
- Fixed YARA scanner WinAPI paths and yara-x 0.14 API usage.
- Fixed updater (reqwest/hmac APIs).

### Added
- CI workflow with lint, test, security audit, benchmark jobs.
- Criterion benchmarks (`benches/detection_benchmarks.rs`).
- Coverage job in CI.

### Tests
- All 33 unit/integration tests pass.