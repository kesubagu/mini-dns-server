use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::serialize::binary::BinDecodable;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;

type DynError = Box<dyn std::error::Error + Send + Sync>;
const MAX_DNS_PACKET_SIZE: usize = 4096;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_TTL_SECS: u64 = 30;
const BLOCKLIST_PATH: &str = "blocked_domains.txt";
const HTTP_CONTROL_ADDR: &str = "127.0.0.1:8080";

struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
}

struct AppState {
    block_list: Arc<RwLock<HashSet<String>>>,
}

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let cache = Arc::new(DashMap::<String, CacheEntry>::new());
    let blocked_domains = Arc::new(RwLock::new(load_blocked_domains(BLOCKLIST_PATH)?));
    let listener_addr = "0.0.0.0:53";
    let upstream_dns_server = "1.1.1.1:53";

    let socket = Arc::new(UdpSocket::bind(listener_addr).await?);
    println!("DNS cache is running on {}", listener_addr);
    println!(
        "HTTP control API is running on http://{}",
        HTTP_CONTROL_ADDR
    );
    let blocked_count = blocked_domains.read().await.len();
    println!(
        "Loaded {} blocked domains from {}",
        blocked_count, BLOCKLIST_PATH
    );

    let app_state = Arc::new(AppState {
        block_list: blocked_domains.clone(),
    });

    let app = Router::new()
        .route("/blocklist", get(get_blocklist))
        .route("/blocklist", post(put_blocklist))
        .with_state(app_state);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await?;

    let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let req_bytes = buf[..len].to_vec();
        let cache_clone = cache.clone();
        let socket_clone = socket.clone();
        let blocked_domains_clone = blocked_domains.clone();
        let upstream = upstream_dns_server.to_string();

        tokio::spawn(async move {
            if let Err(err) = handle_request(
                socket_clone,
                req_bytes,
                addr,
                cache_clone,
                blocked_domains_clone,
                upstream,
            )
            .await
            {
                eprintln!("Failed to handle request from {addr}: {err}");
            }
        });
    }
}

#[derive(Serialize)]
struct BlocklistResponse {
    blocklist: Vec<String>,
}

async fn get_blocklist(State(state): State<Arc<AppState>>) -> Json<BlocklistResponse> {
    let reader = state.block_list.read().await;
    let mut blocklist: Vec<String> = reader.iter().cloned().collect();
    blocklist.sort();
    Json(BlocklistResponse {
        blocklist: blocklist,
    })
}

#[derive(Deserialize)]
struct BlocklistRequest {
    domain_name: String,
}

async fn put_blocklist(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BlocklistRequest>,
) -> StatusCode {
    let mut writer = state.block_list.write().await;
    println!("Adding {} to blocklist", request.domain_name);
    writer.insert(request.domain_name);
    StatusCode::ACCEPTED
}

async fn handle_request(
    socket: Arc<UdpSocket>,
    req_bytes: Vec<u8>,
    src_addr: SocketAddr,
    cache: Arc<DashMap<String, CacheEntry>>,
    blocked_domains: Arc<RwLock<HashSet<String>>>,
    upstream_dns_server: String,
) -> Result<(), DynError> {
    let request = Message::from_bytes(&req_bytes)?;
    if request.message_type() != MessageType::Query {
        return Ok(());
    }

    let blocklist_guard = blocked_domains.read().await;
    if is_blocked(&request, &blocklist_guard) {
        let nxdomain = build_nxdomain_response(&request)?;
        socket.send_to(&nxdomain, src_addr).await?;
        return Ok(());
    }
    drop(blocklist_guard);

    let cache_key = cache_key(&request);
    if let Some(key) = &cache_key {
        if let Some(entry) = cache.get(key) {
            if entry.expires_at > Instant::now() {
                let mut cached_response = Message::from_bytes(&entry.response)?;
                cached_response.set_id(request.id());
                let response_bytes = cached_response.to_vec()?;
                socket.send_to(&response_bytes, src_addr).await?;
                return Ok(());
            }

            cache.remove(key);
        }
    }

    let upstream_response_bytes = query_upstream(&upstream_dns_server, &req_bytes).await?;
    let upstream_response = Message::from_bytes(&upstream_response_bytes)?;

    if let Some(key) = cache_key {
        let ttl_secs = response_ttl_seconds(&upstream_response);
        cache.insert(
            key,
            CacheEntry {
                response: upstream_response_bytes.clone(),
                expires_at: Instant::now() + Duration::from_secs(ttl_secs),
            },
        );
    }

    socket.send_to(&upstream_response_bytes, src_addr).await?;

    Ok(())
}

fn is_blocked(request: &Message, blocked_domains: &HashSet<String>) -> bool {
    request.queries().iter().any(|query| {
        let normalized = normalize_domain(query.name().to_ascii());
        blocked_domains.contains(&normalized)
    })
}

fn normalize_domain(domain: String) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn load_blocked_domains(path: &str) -> Result<HashSet<String>, DynError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut blocked_domains = HashSet::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        blocked_domains.insert(normalize_domain(trimmed.to_string()));
    }

    Ok(blocked_domains)
}

fn build_nxdomain_response(request: &Message) -> Result<Vec<u8>, DynError> {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(request.op_code());
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);
    response.set_response_code(ResponseCode::NXDomain);

    for query in request.queries() {
        response.add_query(query.clone());
    }

    Ok(response.to_vec()?)
}

fn cache_key(request: &Message) -> Option<String> {
    if request.queries().is_empty() {
        return None;
    }

    let key = request
        .queries()
        .iter()
        .map(|query| {
            format!(
                "{}|{:?}|{:?}",
                query.name().to_ascii(),
                query.query_type(),
                query.query_class()
            )
        })
        .collect::<Vec<_>>()
        .join(";");

    Some(key)
}

fn response_ttl_seconds(response: &Message) -> u64 {
    let mut min_ttl = u32::MAX;

    for record in response
        .answers()
        .iter()
        .chain(response.name_servers())
        .chain(response.additionals())
    {
        min_ttl = min_ttl.min(record.ttl());
    }

    if min_ttl == u32::MAX || min_ttl == 0 {
        DEFAULT_TTL_SECS
    } else {
        min_ttl as u64
    }
}

async fn query_upstream(upstream_dns_server: &str, req_bytes: &[u8]) -> Result<Vec<u8>, DynError> {
    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
    upstream_socket
        .send_to(req_bytes, upstream_dns_server)
        .await?;

    let mut upstream_buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    let (len, _) = timeout(
        UPSTREAM_TIMEOUT,
        upstream_socket.recv_from(&mut upstream_buf),
    )
    .await??;
    Ok(upstream_buf[..len].to_vec())
}
