use crate::error::{CoreError, Result};
use crate::network::{Connection, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRuleConfig {
    pub allowed_ips: Vec<IpAddr>,
    pub blocked_ips: Vec<IpAddr>,
    pub allowed_ports: Vec<u16>,
    pub blocked_ports: Vec<u16>,
    pub suspicious_ports: Vec<u16>,
    pub beacon_threshold: u32,
    pub beacon_interval: Duration,
}

impl Default for NetworkRuleConfig {
    fn default() -> Self {
        Self {
            allowed_ips: Vec::new(),
            blocked_ips: Vec::new(),
            allowed_ports: vec![80, 443, 53],
            blocked_ports: Vec::new(),
            suspicious_ports: vec![4444, 5555, 1337, 31337, 1234, 6666, 8888],
            beacon_threshold: 5,
            beacon_interval: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAlert {
    pub alert_type: NetworkAlertType,
    pub connection: Connection,
    pub details: String,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkAlertType {
    BlockedIp,
    BlockedPort,
    SuspiciousPort,
    C2Beacon,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

pub struct NetworkRuleEngine {
    config: NetworkRuleConfig,
    connection_history: HashMap<IpAddr, VecDeque<Instant>>,
}

impl NetworkRuleEngine {
    pub fn new(config: NetworkRuleConfig) -> Self {
        Self {
            config,
            connection_history: HashMap::new(),
        }
    }

    pub fn check_connection(&mut self, conn: &Connection) -> Option<NetworkAlert> {
        if let Some(alert) = self.check_blocked_ip(conn) {
            return Some(alert);
        }

        if let Some(alert) = self.check_blocked_port(conn) {
            return Some(alert);
        }

        if let Some(alert) = self.check_suspicious_port(conn) {
            return Some(alert);
        }

        if let Some(alert) = self.check_c2_beacon(conn) {
            return Some(alert);
        }

        None
    }

    fn check_blocked_ip(&self, conn: &Connection) -> Option<NetworkAlert> {
        if self.config.blocked_ips.contains(&conn.remote_addr) {
            return Some(NetworkAlert {
                alert_type: NetworkAlertType::BlockedIp,
                connection: conn.clone(),
                details: format!("Connection to blocked IP: {}", conn.remote_addr),
                severity: AlertSeverity::High,
            });
        }
        None
    }

    fn check_blocked_port(&self, conn: &Connection) -> Option<NetworkAlert> {
        if self.config.blocked_ports.contains(&conn.remote_port) {
            return Some(NetworkAlert {
                alert_type: NetworkAlertType::BlockedPort,
                connection: conn.clone(),
                details: format!("Connection to blocked port: {}", conn.remote_port),
                severity: AlertSeverity::Medium,
            });
        }
        None
    }

    fn check_suspicious_port(&self, conn: &Connection) -> Option<NetworkAlert> {
        if self.config.suspicious_ports.contains(&conn.remote_port) {
            return Some(NetworkAlert {
                alert_type: NetworkAlertType::SuspiciousPort,
                connection: conn.clone(),
                details: format!("Connection to suspicious port: {}", conn.remote_port),
                severity: AlertSeverity::Medium,
            });
        }
        None
    }

    fn check_c2_beacon(&mut self, conn: &Connection) -> Option<NetworkAlert> {
        if conn.protocol != Protocol::Tcp
            || conn.state != crate::network::ConnectionState::Established
        {
            return None;
        }

        let now = Instant::now();
        let history = self
            .connection_history
            .entry(conn.remote_addr)
            .or_insert_with(VecDeque::new);

        history.push_back(now);

        while let Some(&front) = history.front() {
            if now.duration_since(front) > self.config.beacon_interval * 2 {
                history.pop_front();
            } else {
                break;
            }
        }

        if history.len() >= self.config.beacon_threshold as usize {
            return Some(NetworkAlert {
                alert_type: NetworkAlertType::C2Beacon,
                connection: conn.clone(),
                details: format!(
                    "Potential C2 beacon detected from {} ({} connections in {:?})",
                    conn.remote_addr,
                    history.len(),
                    self.config.beacon_interval
                ),
                severity: AlertSeverity::Critical,
            });
        }

        None
    }

    pub fn add_allowed_ip(&mut self, ip: IpAddr) {
        self.config.allowed_ips.push(ip);
    }

    pub fn add_blocked_ip(&mut self, ip: IpAddr) {
        self.config.blocked_ips.push(ip);
    }

    pub fn add_blocked_port(&mut self, port: u16) {
        self.config.blocked_ports.push(port);
    }

    pub fn add_suspicious_port(&mut self, port: u16) {
        self.config.suspicious_ports.push(port);
    }

    pub fn clear_history(&mut self) {
        self.connection_history.clear();
    }
}
