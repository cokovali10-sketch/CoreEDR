use super::engine::{CorrelatedEvent, EventType, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub id: String,
    pub name: String,
    pub description: String,
    pub nodes: Vec<ChainNode>,
    pub links: Vec<ChainLink>,
    pub severity: Severity,
    pub mitre_techniques: Vec<MitreRef>,
    pub indicators: Vec<String>,
    pub kill_chain_phase: String,
    pub start_time: String,
    pub end_time: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainNode {
    pub id: String,
    pub event_type: String,
    pub timestamp: String,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub user: Option<String>,
    pub details: Vec<String>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLink {
    pub source: String,
    pub target: String,
    pub relationship: LinkRelationship,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LinkRelationship {
    Spawned,
    Accessed,
    Modified,
    Connected,
    Injected,
    Created,
    Deleted,
}

impl LinkRelationship {
    pub fn label(&self) -> &'static str {
        match self {
            LinkRelationship::Spawned => "spawned",
            LinkRelationship::Accessed => "accessed",
            LinkRelationship::Modified => "modified",
            LinkRelationship::Connected => "connected to",
            LinkRelationship::Injected => "injected into",
            LinkRelationship::Created => "created",
            LinkRelationship::Deleted => "deleted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreRef {
    pub technique_id: String,
    pub tactic: String,
    pub confidence: f64,
}

pub struct ChainBuilder {
    chain: AttackChain,
}

impl ChainBuilder {
    pub fn new(id: &str) -> Self {
        ChainBuilder {
            chain: AttackChain {
                id: id.to_string(),
                name: String::new(),
                description: String::new(),
                nodes: Vec::new(),
                links: Vec::new(),
                severity: Severity::Info,
                mitre_techniques: Vec::new(),
                indicators: Vec::new(),
                kill_chain_phase: String::new(),
                start_time: String::new(),
                end_time: String::new(),
                confidence: 0.0,
            },
        }
    }

    pub fn name(mut self, name: &str) -> Self {
        self.chain.name = name.to_string();
        self
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.chain.description = desc.to_string();
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.chain.severity = severity;
        self
    }

    pub fn kill_chain_phase(mut self, phase: &str) -> Self {
        self.chain.kill_chain_phase = phase.to_string();
        self
    }

    pub fn mitre_technique(mut self, technique_id: &str, tactic: &str, confidence: f64) -> Self {
        self.chain.mitre_techniques.push(MitreRef {
            technique_id: technique_id.to_string(),
            tactic: tactic.to_string(),
            confidence,
        });
        self
    }

    pub fn indicator(mut self, indicator: &str) -> Self {
        self.chain.indicators.push(indicator.to_string());
        self
    }

    pub fn add_node(mut self, node: ChainNode) -> Self {
        self.chain.nodes.push(node);
        self
    }

    pub fn add_link(mut self, link: ChainLink) -> Self {
        self.chain.links.push(link);
        self
    }

    pub fn build(mut self) -> AttackChain {
        if self.chain.nodes.len() > 1 {
            self.chain.start_time = self
                .chain
                .nodes
                .first()
                .map(|n| n.timestamp.clone())
                .unwrap_or_default();
            self.chain.end_time = self
                .chain
                .nodes
                .last()
                .map(|n| n.timestamp.clone())
                .unwrap_or_default();
        }

        self.chain.confidence = if self.chain.mitre_techniques.is_empty() {
            0.5
        } else {
            self.chain
                .mitre_techniques
                .iter()
                .map(|t| t.confidence)
                .sum::<f64>()
                / self.chain.mitre_techniques.len() as f64
        };

        self.chain
    }
}


pub fn build_chain_from_events(events: &[CorrelatedEvent], chain_id: &str) -> Option<AttackChain> {
    if events.is_empty() {
        return None;
    }

    let mut builder = ChainBuilder::new(chain_id);

    let first = &events[0];
    let last = &events[events.len() - 1];

    builder = builder
        .name(&format!(
            "Attack chain from {} to {}",
            first.process_name.as_deref().unwrap_or("unknown"),
            last.process_name.as_deref().unwrap_or("unknown")
        ))
        .severity(last.severity.clone());

    for event in events {
        let node = ChainNode {
            id: event.id.clone(),
            event_type: format!("{:?}", event.event_type),
            timestamp: event.timestamp.to_rfc3339(),
            process_id: event.process_id,
            process_name: event.process_name.clone(),
            user: event.user.clone(),
            details: event
                .details
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect(),
            risk_score: match event.severity {
                Severity::Critical => 1.0,
                Severity::High => 0.8,
                Severity::Medium => 0.5,
                Severity::Low => 0.3,
                Severity::Info => 0.1,
            },
        };
        builder = builder.add_node(node);
    }

    for i in 0..events.len().saturating_sub(1) {
        let relationship = match events[i + 1].event_type {
            EventType::ProcessCreation => LinkRelationship::Spawned,
            EventType::FileCreation => LinkRelationship::Created,
            EventType::FileModification => LinkRelationship::Modified,
            EventType::FileAccess => LinkRelationship::Accessed,
            EventType::FileDeletion => LinkRelationship::Deleted,
            EventType::NetworkConnection => LinkRelationship::Connected,
            _ => LinkRelationship::Accessed,
        };

        builder = builder.add_link(ChainLink {
            source: events[i].id.clone(),
            target: events[i + 1].id.clone(),
            relationship,
            confidence: 0.8,
        });
    }

    Some(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_builder_basic() {
        let chain = ChainBuilder::new("c1").name("Chain").build();
        assert_eq!(chain.id, "c1");
        assert_eq!(chain.name, "Chain");
    }
}
