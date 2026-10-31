pub mod monitor;
pub mod rules;

use crate::error::CoreError;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub state: ConnectionState,
    pub pid: Option<u32>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    Established,
    Listening,
    TimeWait,
    CloseWait,
    SynSent,
    SynReceived,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEvent {
    NewConnection(Connection),
    ConnectionClosed(Connection),
    SuspiciousConnection(Connection, String),
}
