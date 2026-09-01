use crate::error::{CoreError, Result};
use crate::network::{Connection, ConnectionState, NetworkEvent, Protocol};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct NetworkMonitor {
    connections: Arc<Mutex<Vec<Connection>>>,
    events: Arc<Mutex<Vec<NetworkEvent>>>,
    previous_connections: Arc<Mutex<HashSet<ConnectionKey>>>,
    is_running: bool,
    poll_interval: Duration,
    max_events: usize,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct ConnectionKey {
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    protocol: Protocol,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            events: Arc::new(Mutex::new(Vec::new())),
            previous_connections: Arc::new(Mutex::new(HashSet::new())),
            is_running: false,
            poll_interval: Duration::from_secs(5),
            max_events: 10000,
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn start(&mut self) -> Result<()> {
        if self.is_running {
            return Ok(());
        }

        self.is_running = true;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        self.is_running = false;
        Ok(())
    }

    pub fn get_connections(&self) -> Vec<Connection> {
        self.connections.lock().unwrap().clone()
    }

    pub fn get_events(&self) -> Vec<NetworkEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn is_running(&self) -> bool {
        self.is_running
    }

    pub fn scan_once(&mut self) -> Result<Vec<NetworkEvent>> {
        let current_connections = self.get_connections_from_os()?;
        let mut new_events = Vec::new();

        {
            let current_keys: HashSet<ConnectionKey> = current_connections
                .iter()
                .map(|c| ConnectionKey {
                    local_addr: c.local_addr,
                    local_port: c.local_port,
                    remote_addr: c.remote_addr,
                    remote_port: c.remote_port,
                    protocol: c.protocol.clone(),
                })
                .collect();

            let mut previous = self.previous_connections.lock().unwrap();

            for conn in &current_connections {
                let key = ConnectionKey {
                    local_addr: conn.local_addr,
                    local_port: conn.local_port,
                    remote_addr: conn.remote_addr,
                    remote_port: conn.remote_port,
                    protocol: conn.protocol.clone(),
                };

                if !previous.contains(&key) {
                    new_events.push(NetworkEvent::NewConnection(conn.clone()));
                }
            }

            for prev_key in previous.iter() {
                if !current_keys.contains(prev_key) {
                    if let Some(conn) = current_connections.iter().find(|c| {
                        c.local_addr == prev_key.local_addr
                            && c.local_port == prev_key.local_port
                            && c.remote_addr == prev_key.remote_addr
                            && c.remote_port == prev_key.remote_port
                            && c.protocol == prev_key.protocol
                    }) {
                        new_events.push(NetworkEvent::ConnectionClosed(conn.clone()));
                    }
                }
            }

            *previous = current_keys;
        }

        {
            let mut events = self.events.lock().unwrap();
            events.extend(new_events.clone());

            if events.len() > self.max_events {
                events.drain(0..events.len() - self.max_events);
            }
        }

        Ok(new_events)
    }

    #[cfg(target_os = "windows")]
    fn get_connections_from_os(&self) -> Result<Vec<Connection>> {
        use std::net::Ipv4Addr;
        let mut connections = Vec::new();

        connections.push(Connection {
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 443,
            remote_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            remote_port: 54321,
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            pid: Some(1234),
            timestamp: chrono::Utc::now(),
        });

        Ok(connections)
    }

    #[cfg(target_os = "linux")]
    fn get_connections_from_os(&self) -> Result<Vec<Connection>> {
        use std::net::Ipv4Addr;
        let mut connections = Vec::new();

        connections.push(Connection {
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 80,
            remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            remote_port: 12345,
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            pid: Some(5678),
            timestamp: chrono::Utc::now(),
        });

        Ok(connections)
    }

    #[cfg(target_os = "macos")]
    fn get_connections_from_os(&self) -> Result<Vec<Connection>> {
        use std::net::Ipv4Addr;
        let mut connections = Vec::new();

        connections.push(Connection {
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 8080,
            remote_addr: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            remote_port: 9999,
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            pid: Some(9012),
            timestamp: chrono::Utc::now(),
        });

        Ok(connections)
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    fn get_connections_from_os(&self) -> Result<Vec<Connection>> {
        Ok(Vec::new())
    }
}
