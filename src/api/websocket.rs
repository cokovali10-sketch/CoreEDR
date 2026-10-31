use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::api::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    pub msg_type: String,
    pub payload: serde_json::Value,
    pub timestamp: String,
}

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.scanner.read().await.subscribe_to_events();
    let client_id = Uuid::new_v4().to_string();

    tracing::info!("WebSocket client connected: {}", client_id);

    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            let ws_msg = WsMessage {
                msg_type: msg.event_type.clone(),
                payload: msg.data.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            };

            if let Ok(json) = serde_json::to_string(&ws_msg) {
                if sender.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    if let Ok(cmd) = serde_json::from_str::<serde_json::Value>(&text) {
                        tracing::debug!("Received command from {}: {:?}", client_id, cmd);
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }

    tracing::info!("WebSocket client disconnected: {}", client_id);
}

pub struct EventBroadcaster {
    sender: broadcast::Sender<WsEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsEvent {
    pub event_type: String,
    pub data: serde_json::Value,
}

impl EventBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn broadcast(&self, event: WsEvent) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.sender.subscribe()
    }
}
