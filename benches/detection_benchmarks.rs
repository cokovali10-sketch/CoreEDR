use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use coreedr::config::DetectionConfig;
use coreedr::heuristic_engine::HeuristicEngine;
use coreedr::mitre::mapper::{MitreMapper, DetectionEvent};
use coreedr::correlation::engine::{CorrelationEngine, CorrelatedEvent, EventType, Severity};
use coreedr::process_monitor::ProcessInfo;
use coreedr::yara::YaraManager;
use std::collections::HashMap;
use std::time::Duration;

fn make_process(name: &str, pid: u32, parent: u32, mem_kb: u64) -> ProcessInfo {
    ProcessInfo {
        pid,
        name: name.to_string(),
        path: format!("/usr/bin/{}", name),
        command_line: "powershell -encodedcommand".to_string(),
        parent_pid: parent,
        user: "root".to_string(),
        memory_usage_kb: mem_kb,
        cpu_percent: 5.0,
        start_time: chrono::Utc::now(),
        hash: None,
        risk_score: 0,
        chain_depth: 0,
        root_pid: parent,
    }
}

fn bench_heuristic_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("heuristic_engine");

    let process = make_process("suspicious.exe", 1234, 567, 100_000);

    group.bench_function("analyze_single_process", |b| {
        b.iter(|| {
            let mut engine = HeuristicEngine::new(DetectionConfig {
                enable_heuristic: true,
                enable_signature: true,
                enable_behavioral: false,
                entropy_threshold: 7.5,
                suspicious_api_threshold: 5,
                max_process_chain_depth: 10,
                yara_rules_path: std::path::PathBuf::from("/tmp/rules"),
            });
            engine.analyze(&process)
        })
    });

    group.finish();
}

fn bench_mitre_mapper(c: &mut Criterion) {
    let mut group = c.benchmark_group("mitre_mapper");

    let mut details = HashMap::new();
    details.insert("CommandLine".to_string(), "powershell -encodedcommand".to_string());

    let event = DetectionEvent {
        event_type: "process_creation".to_string(),
        severity: "high".to_string(),
        source: "coreedr".to_string(),
        details,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    group.bench_function("map_event", |b| {
        let mapper = MitreMapper::new();
        b.iter(|| mapper.map_event(&event))
    });

    group.finish();
}

fn bench_correlation_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_engine");

    group.bench_function("add_event", |b| {
        b.iter(|| {
            let mut engine = CorrelationEngine::new();
            let ev = CorrelatedEvent {
                id: "e1".to_string(),
                timestamp: chrono::Utc::now(),
                event_type: EventType::ProcessCreation,
                process_id: Some(1234),
                process_name: Some("test.exe".to_string()),
                parent_id: None,
                user: Some("root".to_string()),
                details: HashMap::new(),
                chain_id: None,
                severity: Severity::Medium,
            };
            engine.add_event(ev);
            engine.get_stats()
        })
    });

    group.finish();
}

fn bench_yara_scanner(c: &mut Criterion) {
    let mut group = c.benchmark_group("yara_scanner");
    let data = b"this is test data for yara scanning".to_vec();

    group.bench_function("scan_bytes", |b| {
        let scanner = YaraManager::new();
        b.iter(|| scanner.scan_bytes(&data))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_heuristic_engine,
    bench_mitre_mapper,
    bench_correlation_engine,
    bench_yara_scanner
);
criterion_main!(benches);