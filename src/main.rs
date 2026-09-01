mod alert;
mod config;
mod containment;
mod hash_engine;
mod heuristic_engine;
mod logger;
mod process_monitor;
mod quarantine;
mod rule_engine;
mod scanner;

use config::Config;
use scanner::Scanner;
use std::env;
use std::process;

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
                                          |___/  v0.1.0
    "#
    );
    println!("  Lightweight EDR/Antivirus Engine");
    println!("  Real-time process monitoring | Heuristic analysis | Threat containment\n");
}

fn print_usage() {
    println!("Usage: coreedr [OPTIONS]");
    println!();
    println!("Options:");
    println!("  daemon          Run in daemon mode (continuous monitoring)");
    println!("  scan            Run a single scan");
    println!("  scan --full     Run full scan with all checks");
    println!("  status          Show current status");
    println!("  config          Generate default configuration");
    println!("  quarantine      List quarantined items");
    println!("  help            Show this help message");
    println!();
    println!("Examples:");
    println!("  coreedr daemon              Start continuous monitoring");
    println!("  coreedr scan                Run single scan");
    println!("  coreedr config > config.json Generate default config");
}

fn main() {
    print_banner();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "help" => print_usage(),

        "config" => {
            let config = Config::default_config();
            println!("{}", serde_json::to_string_pretty(&config).unwrap());
        }

        "daemon" => {
            let config = load_config();
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

        "scan" => {
            let config = load_config();
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

        "status" => {
            let config = load_config();
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

        "quarantine" => {
            let config = load_config();
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

        _ => {
            eprintln!("[!] Unknown command: {}", args[1]);
            print_usage();
            process::exit(1);
        }
    }
}

fn load_config() -> Config {
    let config_path = args().nth(2).unwrap_or_else(|| "config.json".to_string());

    match Config::load(&config_path) {
        Ok(config) => {
            println!("[*] Loaded config from: {}", config_path);
            config
        }
        Err(_) => {
            println!("[*] Using default configuration");
            Config::default_config()
        }
    }
}

fn args() -> Vec<String> {
    env::args().collect()
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
