mod alert;
mod behavioral;
mod config;
mod containment;
mod error;
mod hash_engine;
mod heuristic_engine;
mod logger;
mod logging;
mod ml;
mod monitoring;
mod network;
mod platform;
mod process_monitor;
mod quarantine;
mod rule_engine;
mod scanner;
mod tamper;
mod yara;

#[cfg(feature = "api")]
mod api;

#[cfg(feature = "auto-update")]
mod updater;

use config::Config;
use scanner::Scanner;
use std::process;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(clap::Parser)]
#[command(name = "coreedr", version = "0.2.0", about = "Production-grade EDR/Antivirus Engine")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Run in daemon mode (continuous monitoring)
    Daemon {
        #[arg(short, long, default_value = "config.json")]
        config: String,
    },
    /// Run a single scan
    Scan {
        #[arg(long)]
        full: bool,
        #[arg(short, long, default_value = "config.json")]
        config: String,
    },
    /// Show current status
    Status {
        #[arg(short, long, default_value = "config.json")]
        config: String,
    },
    /// Generate default configuration
    Config,
    /// List quarantined items
    Quarantine {
        #[arg(short, long, default_value = "config.json")]
        config: String,
    },
    /// Start REST API server with web UI
    #[cfg(feature = "api")]
    Server {
        #[arg(short, long, default_value = "8080")]
        port: u16,
        #[arg(short, long, default_value = "config.json")]
        config: String,
    },
    /// Check for updates
    #[cfg(feature = "auto-update")]
    Update {
        #[arg(short, long, default_value = "https://api.coreedr.example.com/manifest.json")]
        manifest_url: String,
    },
}

fn print_banner() {
    println!(
        r#"
   _____ _______ ______   ______ _             _____  _____
  / ____|__   __|  ____| |  ____| |           |  __ \|  __ \
 | |       | |  | |__    | |__  | | __ _  __ _| |__) | |__) |
 | |       | |  |  __|   |  __| | |/ _` |/ _` |  ___/|  ___/
 | |____   | |  | |      | |    | | (_| | (_| | |    | |
  \_____|  |_|  |_|      |_|    |_|\__,_|\__, |_|    |_|
                                           __/ |
                                          |___/  v0.2.0
    "#
    );
    println!("  Production-grade EDR/Antivirus Engine");
    println!("  Real-time monitoring | Heuristic + YARA + ML | Threat containment");
    println!("  Features: api={}, yara={}, ml={}, quarantine-encrypt={}\n",
        cfg!(feature = "api"),
        cfg!(feature = "yara"),
        cfg!(feature = "ml"),
        cfg!(feature = "quarantine-encrypt"),
    );
}

fn load_config(path: &str) -> Config {
    match Config::load(path) {
        Ok(config) => {
            println!("[*] Loaded config from: {}", path);
            config
        }
        Err(_) => {
            println!("[*] Using default configuration");
            Config::default_config()
        }
    }
}

fn print_report(report: &scanner::ScanReport) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                    SCAN REPORT                          ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║ Scan #:        {:<40}║", report.scan_number);
    println!("║ Timestamp:     {:<40}║", report.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("║ Duration:      {:<38}ms║", report.duration_ms);
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║ PROCESSES                                               ║");
    println!("║   New:           {:<38}║", report.new_processes);
    println!("║   Terminated:    {:<38}║", report.terminated_processes);
    println!("║   Modified:      {:<38}║", report.modified_processes);
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║ THREATS                                                 ║");
    println!("║   Detected:      {:<38}║", report.threats_detected);
    println!("║   Contained:     {:<38}║", report.threats_contained);
    println!("║   Critical:      {:<38}║", report.threat_summary.critical);
    println!("║   High:          {:<38}║", report.threat_summary.high);
    println!("║   Medium:        {:<38}║", report.threat_summary.medium);
    println!("║   Low:           {:<38}║", report.threat_summary.low);
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║ ALERTS                                                  ║");
    println!("║   Total:         {:<38}║", report.alert_stats.total);
    println!("║   Critical:      {:<38}║", report.alert_stats.critical);
    println!("║   High:          {:<38}║", report.alert_stats.high);
    println!("║   Acknowledged:  {:<38}║", report.alert_stats.acknowledged);
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║ LOGGING                                                 ║");
    println!("║   Total events:  {:<38}║", report.logger_stats.total_events);
    println!("║   Errors:        {:<38}║", report.logger_stats.error_count);
    println!("║   Critical:      {:<38}║", report.logger_stats.critical_count);
    println!("╚══════════════════════════════════════════════════════════╝");

    if !report.containment_actions.is_empty() {
        println!("\n[*] Containment Actions:");
        for action in &report.containment_actions {
            println!("  - PID {} ({}): {:?} -> {:?}",
                action.pid,
                action.process_name,
                action.action_type,
                action.result
            );
        }
    }

    println!();
}

#[tokio::main]
async fn main() {
    print_banner();

    let cli = <Cli as clap::Parser>::parse();

    match cli.command {
        Commands::Daemon { config } => {
            let config = load_config(&config);
            logging::init_logging_from_config(&config);
            println!("[*] Starting CoreEDR daemon...");
            println!("[*] Scan interval: {}ms", config.general.scan_interval_ms);
            println!("[*] Press Ctrl+C to stop\n");

            match Scanner::new(config) {
                Ok(mut scanner) => {
                    if let Err(e) = scanner.run_daemon() {
                        eprintln!("[!] Daemon error: {}", e);
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("[!] Failed to initialize scanner: {}", e);
                    process::exit(1);
                }
            }
        }

        Commands::Scan { full: _, config } => {
            let config = load_config(&config);
            logging::init_logging_from_config(&config);
            println!("[*] Running single scan...\n");

            match Scanner::new(config) {
                Ok(mut scanner) => {
                    match scanner.run_scan() {
                        Ok(report) => print_report(&report),
                        Err(e) => {
                            eprintln!("[!] Scan error: {}", e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[!] Failed to initialize scanner: {}", e);
                    process::exit(1);
                }
            }
        }

        Commands::Status { config } => {
            let config = load_config(&config);
            println!("[*] CoreEDR Status\n");

            match Scanner::new(config) {
                Ok(scanner) => {
                    let stats = scanner.get_stats();
                    println!("  Scanner Statistics:");
                    println!("    Total scans: {}", stats.scan_count);
                    println!("    Threats detected: {}", stats.total_threats_detected);
                    println!("    Threats contained: {}", stats.total_threats_contained);
                }
                Err(e) => {
                    eprintln!("[!] Failed to initialize: {}", e);
                    process::exit(1);
                }
            }
        }

        Commands::Config => {
            let config = Config::default_config();
            println!("{}", serde_json::to_string_pretty(&config).unwrap());
        }

        Commands::Quarantine { config } => {
            let config = load_config(&config);
            let qm = quarantine::QuarantineManager::new(config.general.quarantine_path);
            let entries = qm.list_entries();

            if entries.is_empty() {
                println!("[*] No quarantined items.");
            } else {
                println!("[*] Quarantined items:\n");
                for entry in &entries {
                    println!("  ID: {}", entry.id);
                    println!("  Process: {} (PID: {})", entry.process_name, entry.pid);
                    println!("  Risk Score: {}", entry.risk_score);
                    println!("  Reason: {}", entry.reason);
                    println!("  Time: {}", entry.quarantine_time);
                    println!();
                }
            }
        }

        #[cfg(feature = "api")]
        Commands::Server { port, config } => {
            let config = load_config(&config);
            logging::init_logging_from_config(&config);

            println!("[*] Starting CoreEDR API server on port {}...", port);
            println!("[*] Web UI: http://localhost:{}", port);

            let scanner = Scanner::new(config.clone())
                .expect("Failed to initialize scanner");
            let state = api::AppState {
                scanner: Arc::new(RwLock::new(scanner)),
                config: Arc::new(RwLock::new(config)),
            };

            let app = api::create_router(state);

            let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
                .await
                .unwrap();
            println!("[*] Server listening on http://0.0.0.0:{}", port);
            axum::serve(listener, app).await.unwrap();
        }

        #[cfg(feature = "auto-update")]
        Commands::Update { manifest_url } => {
            println!("[*] Checking for updates...");
            match updater::checker::check_for_updates(&manifest_url).await {
                Ok(manifest) => {
                    println!("[*] Latest version: {}", manifest.version);
                    println!("[*] YARA rules: {}", manifest.yara_rules_url.is_some());
                    println!("[*] ML model: {}", manifest.model_url.is_some());
                }
                Err(e) => {
                    eprintln!("[!] Failed to check for updates: {}", e);
                }
            }
        }
    }
}
