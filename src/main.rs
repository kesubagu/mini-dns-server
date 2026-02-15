use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

type DynError = Box<dyn std::error::Error + Send + Sync>;
const MAX_DNS_PACKET_SIZE: usize = 4096;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_TTL_SECS: u64 = 30;

struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
}

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let cache = Arc::new(DashMap::<String, CacheEntry>::new());
    let listener_addr = "0.0.0.0:53";
    let upstream_dns_server = "1.1.1.1:53";

    let socket = Arc::new(UdpSocket::bind(listener_addr).await?);
    println!("DNS cache is running on {}", listener_addr);

    let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let req_bytes = buf[..len].to_vec();
        let cache_clone = cache.clone();
        let socket_clone = socket.clone();
        let upstream = upstream_dns_server.to_string();

        tokio::spawn(async move {
            if let Err(err) =
                handle_request(socket_clone, req_bytes, addr, cache_clone, upstream).await
            {
                eprintln!("Failed to handle request from {addr}: {err}");
            }
        });
    }
}

async fn handle_request(
    socket: Arc<UdpSocket>,
    req_bytes: Vec<u8>,
    src_addr: SocketAddr,
    cache: Arc<DashMap<String, CacheEntry>>,
    upstream_dns_server: String,
) -> Result<(), DynError> {
    println!("Received DNS request from {}", src_addr);

    let request = Message::from_bytes(&req_bytes)?;
    if request.message_type() != MessageType::Query {
        return Ok(());
    }

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
    println!("Forwarded response for request id {}", request.id());

    Ok(())
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
    upstream_socket.send_to(req_bytes, upstream_dns_server).await?;

    let mut upstream_buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    let (len, _) = timeout(UPSTREAM_TIMEOUT, upstream_socket.recv_from(&mut upstream_buf)).await??;
    Ok(upstream_buf[..len].to_vec())
}
