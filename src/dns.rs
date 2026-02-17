use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::serialize::binary::BinDecodable;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::blocklist::normalize_domain;
use crate::types::{
    BlockList, Cache, CacheEntry, DynError, DEFAULT_TTL_SECS, DNS_LISTENER_ADDR, MAX_DNS_PACKET_SIZE,
    UPSTREAM_DNS_SERVER, UPSTREAM_TIMEOUT,
};

pub async fn run_dns_server(cache: Cache, blocked_domains: BlockList) -> Result<(), DynError> {
    let socket = std::sync::Arc::new(UdpSocket::bind(DNS_LISTENER_ADDR).await?);
    println!("DNS cache is running on {}", DNS_LISTENER_ADDR);

    let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let req_bytes = buf[..len].to_vec();
        let cache_clone = cache.clone();
        let socket_clone = socket.clone();
        let blocked_domains_clone = blocked_domains.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_request(
                socket_clone,
                req_bytes,
                addr,
                cache_clone,
                blocked_domains_clone,
                UPSTREAM_DNS_SERVER.to_string(),
            )
            .await
            {
                eprintln!("Failed to handle request from {addr}: {err}");
            }
        });
    }
}

async fn handle_request(
    socket: std::sync::Arc<UdpSocket>,
    req_bytes: Vec<u8>,
    src_addr: SocketAddr,
    cache: Cache,
    blocked_domains: BlockList,
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
        let normalized = normalize_domain(&query.name().to_ascii());
        blocked_domains.contains(&normalized)
    })
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
    upstream_socket.send_to(req_bytes, upstream_dns_server).await?;

    let mut upstream_buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    let (len, _) = timeout(UPSTREAM_TIMEOUT, upstream_socket.recv_from(&mut upstream_buf)).await??;
    Ok(upstream_buf[..len].to_vec())
}
