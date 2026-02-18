use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::blocklist::{normalize_domain, save_blocked_domains};
use crate::types::{AppState, BLOCKLIST_PATH};

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/blocklist", get(get_blocklist))
        .route("/blocklist", post(put_blocklist))
        .route("/blocklist", delete(delete_blocklist))
        .with_state(state)
}

#[derive(Serialize)]
struct BlocklistResponse {
    blocklist: Vec<String>,
}

async fn get_blocklist(State(state): State<Arc<AppState>>) -> Json<BlocklistResponse> {
    let reader = state.block_list.read().await;
    let mut blocklist: Vec<String> = reader.iter().cloned().collect();
    blocklist.sort();
    Json(BlocklistResponse { blocklist })
}

#[derive(Deserialize)]
struct BlocklistRequest {
    domain_name: String,
}

async fn put_blocklist(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BlocklistRequest>,
) -> StatusCode {
    let normalized = normalize_domain(&request.domain_name);
    let snapshot = {
        let mut writer = state.block_list.write().await;
        writer.insert(normalized);
        writer.clone()
    };

    if let Err(err) = save_blocked_domains(BLOCKLIST_PATH, &snapshot) {
        eprintln!("failed to save blocklist: {err}");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    StatusCode::ACCEPTED
}

async fn delete_blocklist(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BlocklistRequest>,
) -> StatusCode {
    let normalized = normalize_domain(&request.domain_name);
    let snapshot = {
        let mut writer = state.block_list.write().await;
        writer.remove(&normalized);
        writer.clone()
    };

    if let Err(err) = save_blocked_domains(BLOCKLIST_PATH, &snapshot) {
        eprintln!("failed to save blocklist {err}");
    }

    StatusCode::ACCEPTED
}
