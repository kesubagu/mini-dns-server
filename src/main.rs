mod blocklist;
mod dns;
mod http_api;
mod types;

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::blocklist::load_blocked_domains;
use crate::types::{
    AppState, BlockList, Cache, DynError, BLOCKLIST_PATH, HTTP_CONTROL_ADDR,
};

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let cache: Cache = Arc::new(DashMap::new());
    let blocked_domains: BlockList = Arc::new(RwLock::new(load_blocked_domains(BLOCKLIST_PATH)?));

    let blocked_count = blocked_domains.read().await.len();
    println!(
        "Loaded {} blocked domains from {}",
        blocked_count, BLOCKLIST_PATH
    );
    println!("HTTP control API is running on http://{}", HTTP_CONTROL_ADDR);

    let app_state = Arc::new(AppState {
        block_list: blocked_domains.clone(),
    });

    let app = http_api::router(app_state);

    let http_task = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(HTTP_CONTROL_ADDR).await?;
        axum::serve(listener, app).await?;
        Ok::<(), DynError>(())
    });

    let dns_task = tokio::spawn(async move { dns::run_dns_server(cache, blocked_domains).await });

    tokio::select! {
        result = http_task => {
            result??;
        }
        result = dns_task => {
            result??;
        }
    }

    Ok(())
}
