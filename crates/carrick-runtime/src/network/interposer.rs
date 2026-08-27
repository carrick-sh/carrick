//! Network interposer and mocking layer for Carrick.
//!
//! Provides `NetworkInterposer`, a `NetworkProvider` decorator that allows
//! intercepting outbound network connections (`connect`) to specific IP addresses
//! or hostnames and routing them to in-memory `MockService` endpoints, or refusing
//! them with a designated `LinuxErrno`.
//!
//! Includes `HttpMock` for HTTP route matching and response generation, and
//! `ConnectionRecord` for bounded, ordered connection history with opt-in payload capture.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_abi::LinuxErrno;
use carrick_spec::{NetworkNamespaceId, NetworkNamespaceSpec, PortMapping, PortProtocol};
use parking_lot::Mutex;

use crate::network::{
    BindTarget, ConnectTarget, GuestSocketAddr, HostNetworkProvider, HostSocketAddr,
    NetworkCapabilities, NetworkHostsEntry, NetworkLease, NetworkLeaseId, NetworkProvider,
    SocketKey,
};

/// Trait for mock services that generate responses for intercepted connections.
pub trait MockService: Send + Sync {
    /// Handle incoming request bytes, returning response bytes to send back to the client.
    fn handle(&self, request: &[u8]) -> Vec<u8>;

    /// Optional hook called immediately when a connection is established (e.g. for server banners).
    fn on_connect(&self, _peer: SocketAddr) -> Option<Vec<u8>> {
        None
    }

    /// Whether the mock service signals stream EOF (shutdown write) after sending its response.
    fn should_close(&self) -> bool {
        true
    }
}

impl<F> MockService for F
where
    F: Fn(&[u8]) -> Vec<u8> + Send + Sync,
{
    fn handle(&self, request: &[u8]) -> Vec<u8> {
        self(request)
    }
}

#[derive(Clone, Debug)]
pub struct HttpRoute {
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A plaintext HTTP/1.0 and HTTP/1.1 mock service for intercepting HTTP requests.
#[derive(Clone, Debug)]
pub struct HttpMock {
    routes: Vec<HttpRoute>,
    fallback: (u16, String, Vec<(String, String)>, Vec<u8>),
    default_headers: Vec<(String, String)>,
}

impl Default for HttpMock {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpMock {
    /// Create a new HTTP mock with default 404 fallback.
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            fallback: (
                404,
                "Not Found".to_string(),
                vec![("Content-Type".to_string(), "text/plain".to_string())],
                b"404 Not Found".to_vec(),
            ),
            default_headers: vec![("Connection".to_string(), "close".to_string())],
        }
    }

    /// Add a route matching "METHOD /path" (e.g. "GET /health") with a status code and body.
    pub fn route(
        mut self,
        method_and_path: &str,
        status_code: u16,
        body: impl AsRef<[u8]>,
    ) -> Self {
        let (method, path) = parse_method_and_path(method_and_path);
        let status_text = status_code_text(status_code).to_string();
        self.routes.push(HttpRoute {
            method,
            path,
            status_code,
            status_text,
            headers: Vec::new(),
            body: body.as_ref().to_vec(),
        });
        self
    }

    /// Add a route matching "METHOD /path" with custom headers, status code, and body.
    pub fn route_with_headers(
        mut self,
        method_and_path: &str,
        status_code: u16,
        headers: Vec<(impl Into<String>, impl Into<String>)>,
        body: impl AsRef<[u8]>,
    ) -> Self {
        let (method, path) = parse_method_and_path(method_and_path);
        let status_text = status_code_text(status_code).to_string();
        let headers = headers
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self.routes.push(HttpRoute {
            method,
            path,
            status_code,
            status_text,
            headers,
            body: body.as_ref().to_vec(),
        });
        self
    }

    /// Set the fallback response when no configured route matches.
    pub fn fallback(mut self, status_code: u16, body: impl AsRef<[u8]>) -> Self {
        let status_text = status_code_text(status_code).to_string();
        self.fallback = (
            status_code,
            status_text,
            vec![("Content-Type".to_string(), "text/plain".to_string())],
            body.as_ref().to_vec(),
        );
        self
    }

    /// Add a default response header to include on every response.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.default_headers.push((key.into(), value.into()));
        self
    }

    fn build_response(
        &self,
        status_code: u16,
        status_text: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Vec<u8> {
        let mut resp = format!("HTTP/1.1 {status_code} {status_text}\r\n");
        resp.push_str(&format!("Content-Length: {}\r\n", body.len()));

        let mut has_conn = false;
        let mut has_content_type = false;
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("connection") {
                has_conn = true;
            }
            if k.eq_ignore_ascii_case("content-type") {
                has_content_type = true;
            }
            resp.push_str(&format!("{k}: {v}\r\n"));
        }
        for (k, v) in &self.default_headers {
            if k.eq_ignore_ascii_case("connection") && has_conn {
                continue;
            }
            if k.eq_ignore_ascii_case("content-type") && has_content_type {
                continue;
            }
            resp.push_str(&format!("{k}: {v}\r\n"));
        }
        resp.push_str("\r\n");
        let mut bytes = resp.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }
}

impl MockService for HttpMock {
    fn handle(&self, request: &[u8]) -> Vec<u8> {
        let Ok(req_str) = std::str::from_utf8(request) else {
            return self.build_response(
                400,
                "Bad Request",
                &[("Content-Type".to_string(), "text/plain".to_string())],
                b"400 Bad Request",
            );
        };

        // If request headers are not yet completely delivered (\r\n\r\n or \n\n), wait for more data.
        if !req_str.contains("\r\n\r\n") && !req_str.contains("\n\n") {
            return Vec::new();
        }

        let first_line = req_str.lines().next().unwrap_or("");
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or("GET");
        let raw_path = parts.next().unwrap_or("/");
        let path = raw_path.split('?').next().unwrap_or(raw_path);

        for route in &self.routes {
            if route.method.eq_ignore_ascii_case(method)
                && (route.path == path || route.path == raw_path)
            {
                return self.build_response(
                    route.status_code,
                    &route.status_text,
                    &route.headers,
                    &route.body,
                );
            }
        }

        let (status, ref text, ref headers, ref body) = self.fallback;
        self.build_response(status, text, headers, body)
    }

    fn should_close(&self) -> bool {
        true
    }
}

fn parse_method_and_path(input: &str) -> (String, String) {
    let input = input.trim();
    if let Some((m, p)) = input.split_once(' ') {
        (m.trim().to_uppercase(), p.trim().to_string())
    } else {
        ("GET".to_string(), input.to_string())
    }
}

fn status_code_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

/// Recorded connection information for test assertions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionRecord {
    pub id: u64,
    pub timestamp: std::time::SystemTime,
    pub peer_addr: SocketAddr,
    pub target: (String, u16),
    pub protocol: PortProtocol,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub sent_payload: Option<Vec<u8>>,
    pub received_payload: Option<Vec<u8>>,
    pub completed: bool,
    pub error: Option<LinuxErrno>,
}

#[derive(Debug)]
pub(crate) struct ConnectionRecordState {
    pub id: u64,
    pub timestamp: std::time::SystemTime,
    pub peer_addr: SocketAddr,
    pub target: (String, u16),
    pub protocol: PortProtocol,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub sent_payload: Option<Vec<u8>>,
    pub received_payload: Option<Vec<u8>>,
    pub completed: bool,
    pub error: Option<LinuxErrno>,
    pub capture_payload: bool,
}

impl ConnectionRecordState {
    pub fn snapshot(&self) -> ConnectionRecord {
        ConnectionRecord {
            id: self.id,
            timestamp: self.timestamp,
            peer_addr: self.peer_addr,
            target: self.target.clone(),
            protocol: self.protocol,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            sent_payload: self.sent_payload.clone(),
            received_payload: self.received_payload.clone(),
            completed: self.completed,
            error: self.error,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TargetSpec {
    Ip(IpAddr, u16),
    Host(String, u16),
}

pub trait IntoTargetSpec {
    fn into_target_spec(self) -> TargetSpec;
}

impl IntoTargetSpec for (IpAddr, u16) {
    fn into_target_spec(self) -> TargetSpec {
        TargetSpec::Ip(self.0, self.1)
    }
}

impl IntoTargetSpec for (Ipv4Addr, u16) {
    fn into_target_spec(self) -> TargetSpec {
        TargetSpec::Ip(IpAddr::V4(self.0), self.1)
    }
}

impl IntoTargetSpec for (&str, u16) {
    fn into_target_spec(self) -> TargetSpec {
        if let Ok(ip) = self.0.parse::<IpAddr>() {
            TargetSpec::Ip(ip, self.1)
        } else {
            TargetSpec::Host(self.0.to_string(), self.1)
        }
    }
}

impl IntoTargetSpec for (String, u16) {
    fn into_target_spec(self) -> TargetSpec {
        if let Ok(ip) = self.0.parse::<IpAddr>() {
            TargetSpec::Ip(ip, self.1)
        } else {
            TargetSpec::Host(self.0, self.1)
        }
    }
}

#[derive(Clone)]
pub(crate) enum InterceptRule {
    Mock(Arc<dyn MockService>),
    Refuse(LinuxErrno),
}

/// Builder for attaching an action (`intercept` or `refuse`) to a target connection rule.
pub struct InterceptRuleBuilder {
    interposer: NetworkInterposer,
    target: TargetSpec,
}

impl InterceptRuleBuilder {
    /// Intercept matching connections and serve them with the provided mock service.
    pub fn intercept(self, mock: Arc<dyn MockService>) -> NetworkInterposer {
        self.interposer
            .add_rule(self.target, InterceptRule::Mock(mock))
    }

    /// Intercept matching connections and serve them with the provided mock service instance.
    pub fn mock(self, mock: impl MockService + 'static) -> NetworkInterposer {
        self.intercept(Arc::new(mock))
    }

    /// Refuse matching connections immediately with the designated error.
    pub fn refuse(self, errno: impl Into<LinuxErrno>) -> NetworkInterposer {
        self.interposer
            .add_rule(self.target, InterceptRule::Refuse(errno.into()))
    }
}

/// Decorator for `NetworkProvider` that intercepts or refuses connections based on rules.
pub struct NetworkInterposer {
    inner: Option<Box<dyn NetworkProvider>>,
    rules: Arc<Mutex<HashMap<TargetSpec, InterceptRule>>>,
    synthetic_host_ips: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
    synthetic_ip_hosts: Arc<Mutex<HashMap<Ipv4Addr, String>>>,
    next_synthetic_ip: Arc<Mutex<u32>>,
    records: Arc<Mutex<VecDeque<Arc<Mutex<ConnectionRecordState>>>>>,
    record_connections: bool,
    capture_payloads: bool,
    max_records: usize,
    next_conn_id: Arc<AtomicU64>,
}

impl Default for NetworkInterposer {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkInterposer {
    /// Create a new network interposer decorating the default host network provider.
    pub fn new() -> Self {
        Self::wrap(Box::<HostNetworkProvider>::default())
    }

    /// Create a new network interposer decorating an existing `NetworkProvider`.
    pub fn wrap(inner: Box<dyn NetworkProvider>) -> Self {
        Self {
            inner: Some(inner),
            rules: Arc::new(Mutex::new(HashMap::new())),
            synthetic_host_ips: Arc::new(Mutex::new(HashMap::new())),
            synthetic_ip_hosts: Arc::new(Mutex::new(HashMap::new())),
            next_synthetic_ip: Arc::new(Mutex::new(1)),
            records: Arc::new(Mutex::new(VecDeque::new())),
            record_connections: true,
            capture_payloads: false,
            max_records: 1024,
            next_conn_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Replace or wrap the underlying `NetworkProvider`.
    pub fn with_inner(mut self, inner: Box<dyn NetworkProvider>) -> Self {
        self.inner = Some(inner);
        self
    }

    /// Begin configuring an interception or refusal rule for a connection target.
    pub fn on_connect(self, target: impl IntoTargetSpec) -> InterceptRuleBuilder {
        let spec = target.into_target_spec();
        InterceptRuleBuilder {
            interposer: self,
            target: spec,
        }
    }

    /// Control whether connection records are collected (default: true).
    pub fn record_connections(mut self, enabled: bool) -> Self {
        self.record_connections = enabled;
        self
    }

    /// Control whether sent and received payloads are captured in connection records (default: false).
    pub fn capture_payloads(mut self, enabled: bool) -> Self {
        self.capture_payloads = enabled;
        self
    }

    /// Set the maximum number of recorded connections retained in memory (default: 1024).
    pub fn max_records(mut self, limit: usize) -> Self {
        self.max_records = limit;
        self
    }

    /// Retrieve an ordered snapshot of all recorded connections.
    pub fn connections(&self) -> Vec<ConnectionRecord> {
        let records = self.records.lock();
        records.iter().map(|r| r.lock().snapshot()).collect()
    }

    /// Clear recorded connections.
    pub fn clear_records(&self) {
        self.records.lock().clear();
    }

    /// Finalize the builder (identity pass-through for ergonomic symmetry).
    pub fn build(self) -> Self {
        self
    }

    fn add_rule(self, target: TargetSpec, rule: InterceptRule) -> Self {
        if let TargetSpec::Host(ref host, _) = target {
            let mut host_ips = self.synthetic_host_ips.lock();
            let mut ip_hosts = self.synthetic_ip_hosts.lock();
            if !host_ips.contains_key(host) {
                let mut next = self.next_synthetic_ip.lock();
                let ip_val = *next;
                *next += 1;
                let b3 = (ip_val & 0xff) as u8;
                let b2 = ((ip_val >> 8) & 0xff) as u8;
                let synthetic_ip = Ipv4Addr::new(198, 18, b2, b3.max(1));
                host_ips.insert(host.clone(), synthetic_ip);
                ip_hosts.insert(synthetic_ip, host.clone());
            }
        }
        self.rules.lock().insert(target, rule);
        self
    }

    fn resolve_rule(
        &self,
        rule: &InterceptRule,
        peer_addr: SocketAddr,
        target: (String, u16),
        protocol: PortProtocol,
    ) -> Result<ConnectTarget, String> {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let error = match rule {
            InterceptRule::Refuse(errno) => Some(*errno),
            _ => None,
        };

        if self.record_connections {
            let record_state = Arc::new(Mutex::new(ConnectionRecordState {
                id,
                timestamp: std::time::SystemTime::now(),
                peer_addr,
                target,
                protocol,
                bytes_sent: 0,
                bytes_received: 0,
                sent_payload: self.capture_payloads.then(Vec::new),
                received_payload: self.capture_payloads.then(Vec::new),
                completed: error.is_some(),
                error,
                capture_payload: self.capture_payloads,
            }));
            let mut recs = self.records.lock();
            if recs.len() >= self.max_records {
                recs.pop_front();
            }
            recs.push_back(record_state);
        }

        match rule {
            InterceptRule::Mock(mock) => Ok(ConnectTarget::Intercept(Arc::clone(mock))),
            InterceptRule::Refuse(errno) => Ok(ConnectTarget::Denied(*errno)),
        }
    }
}

impl NetworkProvider for NetworkInterposer {
    fn create_namespace(&self, spec: &NetworkNamespaceSpec) -> Result<NetworkLease, String> {
        if let Some(inner) = &self.inner {
            inner.create_namespace(spec)
        } else {
            Ok(NetworkLease {
                id: NetworkLeaseId(0),
            })
        }
    }

    fn destroy_namespace(&self, lease_id: NetworkLeaseId) -> Result<(), String> {
        if let Some(inner) = &self.inner {
            inner.destroy_namespace(lease_id)
        } else {
            Ok(())
        }
    }

    fn capabilities(&self) -> NetworkCapabilities {
        if let Some(inner) = &self.inner {
            inner.capabilities()
        } else {
            NetworkCapabilities::default()
        }
    }

    fn publish_port(&self, lease_id: NetworkLeaseId, mapping: PortMapping) -> Result<(), String> {
        if let Some(inner) = &self.inner {
            inner.publish_port(lease_id, mapping)
        } else {
            Ok(())
        }
    }

    fn materialize_bind(
        &self,
        namespace_id: Option<&NetworkNamespaceId>,
        requested: GuestSocketAddr,
        protocol: PortProtocol,
    ) -> Result<BindTarget, String> {
        if let Some(inner) = &self.inner {
            inner.materialize_bind(namespace_id, requested, protocol)
        } else {
            Ok(BindTarget::Unchanged)
        }
    }

    fn resolve_connect(
        &self,
        namespace_id: Option<&NetworkNamespaceId>,
        requested: GuestSocketAddr,
        protocol: PortProtocol,
    ) -> Result<ConnectTarget, String> {
        let ip = requested.0.ip();
        let port = requested.0.port();

        // 1. Check direct IP match
        {
            let rules = self.rules.lock();
            if let Some(rule) = rules.get(&TargetSpec::Ip(ip, port)) {
                return self.resolve_rule(rule, requested.0, (ip.to_string(), port), protocol);
            }
        }

        // 2. Check synthetic IP match for hostname
        if let IpAddr::V4(v4) = ip {
            let synth = self.synthetic_ip_hosts.lock();
            if let Some(host) = synth.get(&v4) {
                let rules = self.rules.lock();
                if let Some(rule) = rules.get(&TargetSpec::Host(host.clone(), port)) {
                    return self.resolve_rule(rule, requested.0, (host.clone(), port), protocol);
                }
            }
        }

        // 3. Fall back to inner provider
        if let Some(inner) = &self.inner {
            inner.resolve_connect(namespace_id, requested, protocol)
        } else {
            Ok(ConnectTarget::Unchanged)
        }
    }

    fn guest_hosts_entries(
        &self,
        spec: &NetworkNamespaceSpec,
    ) -> Result<Vec<NetworkHostsEntry>, String> {
        let mut entries = if let Some(inner) = &self.inner {
            inner.guest_hosts_entries(spec)?
        } else {
            Vec::new()
        };

        let synth = self.synthetic_host_ips.lock();
        for (host, ip) in synth.iter() {
            entries.push(NetworkHostsEntry {
                addr: IpAddr::V4(*ip),
                names: vec![host.clone()],
            });
        }
        Ok(entries)
    }

    fn resolve_dns_name(
        &self,
        spec: &NetworkNamespaceSpec,
        name: &str,
    ) -> Result<Vec<Ipv4Addr>, String> {
        let clean_name = name.trim_end_matches('.');
        let synth = self.synthetic_host_ips.lock();
        for (host, ip) in synth.iter() {
            if host.eq_ignore_ascii_case(clean_name) {
                return Ok(vec![*ip]);
            }
        }
        drop(synth);

        if let Some(inner) = &self.inner {
            inner.resolve_dns_name(spec, name)
        } else {
            Ok(Vec::new())
        }
    }

    fn record_socket_addresses(
        &self,
        namespace_id: Option<&NetworkNamespaceId>,
        socket: SocketKey,
        guest_local: Option<GuestSocketAddr>,
        host_local: Option<HostSocketAddr>,
        guest_peer: Option<GuestSocketAddr>,
        protocol: PortProtocol,
    ) -> Result<(), String> {
        if let Some(inner) = &self.inner {
            inner.record_socket_addresses(
                namespace_id,
                socket,
                guest_local,
                host_local,
                guest_peer,
                protocol,
            )
        } else {
            Ok(())
        }
    }

    fn guest_visible_local_addr(&self, key: SocketKey) -> Result<Option<GuestSocketAddr>, String> {
        if let Some(inner) = &self.inner {
            inner.guest_visible_local_addr(key)
        } else {
            Ok(None)
        }
    }

    fn guest_visible_peer_addr(&self, key: SocketKey) -> Result<Option<GuestSocketAddr>, String> {
        if let Some(inner) = &self.inner {
            inner.guest_visible_peer_addr(key)
        } else {
            Ok(None)
        }
    }

    fn forget_socket_addresses(&self, key: SocketKey) {
        if let Some(inner) = &self.inner {
            inner.forget_socket_addresses(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_abi::LINUX_ECONNREFUSED;

    #[test]
    fn http_mock_route_matching() {
        let mock = HttpMock::new()
            .route("GET /health", 200, r#"{"status":"ok"}"#)
            .route("POST /submit", 201, "created")
            .fallback(404, "not found");

        let res = mock.handle(b"GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let res_str = String::from_utf8(res).unwrap();
        assert!(res_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(res_str.contains("Content-Length: 15\r\n"));
        assert!(res_str.ends_with(r#"{"status":"ok"}"#));

        let res_post = mock.handle(b"POST /submit HTTP/1.1\r\n\r\n");
        let res_post_str = String::from_utf8(res_post).unwrap();
        assert!(res_post_str.starts_with("HTTP/1.1 201 Created\r\n"));

        let res_404 = mock.handle(b"GET /unknown HTTP/1.1\r\n\r\n");
        let res_404_str = String::from_utf8(res_404).unwrap();
        assert!(res_404_str.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn interposer_ip_and_hostname_routing() {
        let mock_service =
            Arc::new(HttpMock::new().route("GET /api/test", 200, "hello interposer"));
        let interposer = NetworkInterposer::new()
            .on_connect(("api.example.com", 443))
            .intercept(mock_service)
            .on_connect(("10.0.0.1", 80))
            .refuse(LINUX_ECONNREFUSED)
            .capture_payloads(true)
            .build();

        // Hostname DNS resolution
        let spec = NetworkNamespaceSpec::default();
        let ips = interposer
            .resolve_dns_name(&spec, "api.example.com")
            .unwrap();
        assert_eq!(ips.len(), 1);
        let synthetic_ip = ips[0];

        // Hosts entries
        let hosts = interposer.guest_hosts_entries(&spec).unwrap();
        assert!(
            hosts
                .iter()
                .any(|h| h.names.contains(&"api.example.com".to_string()))
        );

        // Connect to synthetic IP on port 443 -> Intercept
        let target = GuestSocketAddr(SocketAddr::new(IpAddr::V4(synthetic_ip), 443));
        let res = interposer
            .resolve_connect(None, target, PortProtocol::Tcp)
            .unwrap();
        assert!(matches!(res, ConnectTarget::Intercept(_)));

        // Connect to 10.0.0.1:80 -> Denied(ECONNREFUSED)
        let refused_target =
            GuestSocketAddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80));
        let res_refused = interposer
            .resolve_connect(None, refused_target, PortProtocol::Tcp)
            .unwrap();
        assert_eq!(res_refused, ConnectTarget::Denied(LINUX_ECONNREFUSED));

        // Unmatched target -> delegates to inner provider (Unchanged)
        let other_target =
            GuestSocketAddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53));
        let res_other = interposer
            .resolve_connect(None, other_target, PortProtocol::Udp)
            .unwrap();
        assert_eq!(res_other, ConnectTarget::Unchanged);

        // Connections recorded
        let conns = interposer.connections();
        assert_eq!(conns.len(), 2);
    }
}
