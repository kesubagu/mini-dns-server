use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub type DynError = Box<dyn std::error::Error + Send + Sync>;

pub const MAX_DNS_PACKET_SIZE: usize = 4096;
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
pub const DEFAULT_TTL_SECS: u64 = 30;
pub const BLOCKLIST_PATH: &str = "blocked_domains.txt";
pub const HTTP_CONTROL_ADDR: &str = "0.0.0.0:8080";
pub const DNS_LISTENER_ADDR: &str = "0.0.0.0:53";
pub const UPSTREAM_DNS_SERVER: &str = "1.1.1.1:53";

pub struct CacheEntry {
    pub response: Vec<u8>,
    pub expires_at: Instant,
}

pub struct AppState {
    pub block_list: Arc<RwLock<HashSet<String>>>,
}

pub type Cache = Arc<DashMap<String, CacheEntry>>;
pub type BlockList = Arc<RwLock<HashSet<String>>>;
