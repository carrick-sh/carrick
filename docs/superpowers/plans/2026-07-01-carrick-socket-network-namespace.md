# Carrick Socket Network Namespace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Carrick's first `--net bridge` mode as a Docker-bridge-compatible socket namespace provider.

**Architecture:** Add a platform-neutral Linux network model to `carrick-spec`, flow it through CLI and engine into the runtime, and implement a macOS socket-namespace provider that maps virtual bridge endpoints to host loopback sockets. The provider advertises exact capabilities so richer providers such as PF, NetworkExtension, Linux netns, FreeBSD VNET, or packet-device backends can satisfy the same Linux ABI model later.

**Tech Stack:** Rust 2024, Cargo workspace, clap `ValueEnum`, serde, standard `std::net` address types, existing Carrick runtime socket dispatch, existing Docker oracle/conformance harness.

## Global Constraints

- First implementation avoids PF, NetworkExtension, vmnet, and user-space TCP/IP stacks.
- V1 targets application-level TCP/UDP bridge compatibility, not packet-level bridge fidelity.
- Host-routable container IPs, raw sockets, AF_PACKET, arbitrary ICMP, packet capture, multicast, broadcast, netfilter, iptables, nftables, and guest-created `CLONE_NEWNET` are out of scope.
- The Linux-visible network model must stay platform-neutral and provider-backed.
- Provider capability reporting must distinguish app-socket fidelity from packet-level semantics.
- Use `just check` for compile checks and `just test`/targeted `cargo test` for host tests. Use `just build` before any runtime guest execution because Carrick guest runs require codesigning on macOS.
- Keep commits narrow. Do not stage unrelated files such as `.scratch/`.

---

## File Structure

- Modify `crates/carrick-spec/src/lib.rs`: add `NetworkMode`, `NetworkNamespaceId`, `BridgeId`, `PortProtocol`, `PortMapping`, `NetworkNamespaceSpec`, and `RunSpec.network`.
- Modify `crates/carrick-engine/src/lib.rs`: add network and publish fields to `CliRunRequest`, resolve Docker-style bridge defaults, and copy resolved network specs into `RunSpec`.
- Modify `crates/carrick-cli/src/args.rs`: add `--network`/`--net` to `run` and `create`, keep `-p/--publish` accepted.
- Modify `crates/carrick-cli/src/runtime_util.rs`: replace host-only `validate_publish` with `parse_publish_specs` that returns typed `PortMapping` values and rejects unsupported shapes by network mode.
- Modify `crates/carrick-cli/src/commands.rs`: pass network mode and parsed published ports into `CliRunRequest`.
- Modify `crates/carrick-runtime/src/container.rs`: persist `network` and `published_ports` in `RunConfig`.
- Modify `crates/carrick-cli/src/lifecycle.rs`: store and rebuild `network` and `published_ports` for detached/create/start state.
- Create `crates/carrick-runtime/src/network/mod.rs`: provider traits, capabilities, bind/connect target types, and provider selection.
- Create `crates/carrick-runtime/src/network/socket_namespace.rs`: v1 socket provider, registry, virtual endpoint mapping, and TCP publish listener.
- Modify `crates/carrick-runtime/src/lib.rs`: expose the `network` module.
- Modify `crates/carrick-runtime/src/execute.rs`: initialize the selected provider lease from `RunSpec.network` before the guest dispatcher starts and release it after execution.
- Modify `crates/carrick-runtime/src/dispatch/net.rs`: call provider hooks in `bind`, `connect`, `getsockname`, `getpeername`, `accept4`, `sendto`, and `recvfrom` for INET/INET6 sockets.
- Modify `crates/carrick-runtime/src/dispatch/net/support.rs`: make rtnetlink generation read the active network model instead of hardcoding a single loopback-only view.
- Modify `crates/carrick-runtime/src/dispatch/fs/state.rs`: materialize bridge-aware `/etc/hosts` and `/etc/resolv.conf`.
- Add focused tests near the changed code and add conformance probes under `crates/carrick-cli/tests/probe-oracle/`.

---

### Task 1: Add Network Model Types To `carrick-spec`

**Files:**
- Modify: `crates/carrick-spec/src/lib.rs`
- Test: `crates/carrick-spec/src/lib.rs`

**Interfaces:**
- Produces: `NetworkMode`, `NetworkNamespaceId`, `BridgeId`, `PortProtocol`, `PortMapping`, `NetworkNamespaceSpec`, `RunSpec.network`.
- Consumes: existing `RunSpec`, serde defaults, clap `ValueEnum` pattern from `PidMode`.

- [ ] **Step 1: Write failing serde/default tests**

Add these tests to the existing `#[cfg(test)] mod tests` in `crates/carrick-spec/src/lib.rs`:

```rust
#[test]
fn run_spec_network_defaults_to_host() {
    let json = r#"{
        "executable": "/bin/sh",
        "argv": ["/bin/sh"],
        "envp": [],
        "cwd": "/",
        "rootfs_layers": [],
        "fs_backend": "Host",
        "mounts": [],
        "tty": false,
        "raw": true,
        "interactive": false,
        "max_traps": 100,
        "debug_state_path": null
    }"#;

    let spec: RunSpec = serde_json::from_str(json).expect("legacy spec should deserialize");
    assert_eq!(spec.network.mode, NetworkMode::Host);
    assert!(spec.network.namespace_id.is_none());
    assert!(spec.network.published_ports.is_empty());
}

#[test]
fn bridge_network_spec_round_trips() {
    let spec = NetworkNamespaceSpec::bridge_default(
        Some("web".to_string()),
        vec!["api".to_string()],
        vec![PortMapping {
            host_ip: None,
            host_port: Some(8080),
            container_port: 80,
            protocol: PortProtocol::Tcp,
        }],
    );

    let encoded = serde_json::to_string(&spec).expect("serialize");
    let decoded: NetworkNamespaceSpec = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded.mode, NetworkMode::Bridge);
    assert_eq!(decoded.bridge_id.as_str(), "carrick0");
    assert_eq!(decoded.ipv4.to_string(), "172.31.0.2");
    assert_eq!(decoded.gateway_v4.to_string(), "172.31.0.1");
    assert_eq!(decoded.aliases, vec!["api"]);
    assert_eq!(decoded.published_ports[0].container_port, 80);
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p carrick-spec run_spec_network_defaults_to_host bridge_network_spec_round_trips
```

Expected: compile failure naming missing `NetworkNamespaceSpec`, `NetworkMode`, and `PortMapping`.

- [ ] **Step 3: Add the model types**

In `crates/carrick-spec/src/lib.rs`, add imports near the existing imports:

```rust
use std::net::{IpAddr, Ipv4Addr};
```

Add these types after `PidMode`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum NetworkMode {
    #[default]
    Host,
    Bridge,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkNamespaceId(String);

impl NetworkNamespaceId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BridgeId(String);

impl BridgeId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn default_bridge() -> Self {
        Self("carrick0".to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_ip: Option<IpAddr>,
    pub host_port: Option<u16>,
    pub container_port: u16,
    pub protocol: PortProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkNamespaceSpec {
    pub mode: NetworkMode,
    pub namespace_id: Option<NetworkNamespaceId>,
    pub bridge_id: BridgeId,
    pub container_name: Option<String>,
    pub aliases: Vec<String>,
    pub ipv4: Ipv4Addr,
    pub gateway_v4: Ipv4Addr,
    pub dns_servers: Vec<IpAddr>,
    pub published_ports: Vec<PortMapping>,
}

impl NetworkNamespaceSpec {
    pub fn bridge_default(
        container_name: Option<String>,
        aliases: Vec<String>,
        published_ports: Vec<PortMapping>,
    ) -> Self {
        Self {
            mode: NetworkMode::Bridge,
            namespace_id: Some(NetworkNamespaceId::new("default")),
            bridge_id: BridgeId::default_bridge(),
            container_name,
            aliases,
            ipv4: Ipv4Addr::new(172, 31, 0, 2),
            gateway_v4: Ipv4Addr::new(172, 31, 0, 1),
            dns_servers: vec![IpAddr::V4(Ipv4Addr::new(172, 31, 0, 1))],
            published_ports,
        }
    }
}

impl Default for NetworkNamespaceSpec {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Host,
            namespace_id: None,
            bridge_id: BridgeId::default_bridge(),
            container_name: None,
            aliases: Vec::new(),
            ipv4: Ipv4Addr::new(0, 0, 0, 0),
            gateway_v4: Ipv4Addr::new(0, 0, 0, 0),
            dns_servers: Vec::new(),
            published_ports: Vec::new(),
        }
    }
}
```

Add the field to `RunSpec` after `pid`:

```rust
#[serde(default)]
pub network: NetworkNamespaceSpec,
```

- [ ] **Step 4: Run tests and verify they pass**

Run:

```bash
cargo test -p carrick-spec run_spec_network_defaults_to_host bridge_network_spec_round_trips
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-spec/src/lib.rs
git commit -m "feat(spec): add network namespace model" -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 2: Parse `--net bridge` And Docker Publish Specs

**Files:**
- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/runtime_util.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-engine/src/lib.rs`
- Test: `crates/carrick-cli/src/runtime_util.rs`
- Test: `crates/carrick-engine/src/lib.rs`

**Interfaces:**
- Consumes: `carrick_spec::{NetworkMode, PortMapping, PortProtocol}` from Task 1.
- Produces: `CliRunRequest.network`, `CliRunRequest.published_ports`, `parse_publish_specs`.

- [ ] **Step 1: Write failing publish parser tests**

Add to `crates/carrick-cli/src/runtime_util.rs`:

```rust
#[cfg(test)]
mod network_tests {
    use super::*;
    use carrick_spec::{NetworkMode, PortProtocol};

    #[test]
    fn bridge_publish_accepts_port_remap() {
        let mappings = parse_publish_specs(NetworkMode::Bridge, &["127.0.0.1:8080:80/tcp".to_string()])
            .expect("bridge publish should parse");
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].host_ip.unwrap().to_string(), "127.0.0.1");
        assert_eq!(mappings[0].host_port, Some(8080));
        assert_eq!(mappings[0].container_port, 80);
        assert_eq!(mappings[0].protocol, PortProtocol::Tcp);
    }

    #[test]
    fn host_publish_still_rejects_remap() {
        let err = parse_publish_specs(NetworkMode::Host, &["8080:80".to_string()])
            .expect_err("host networking cannot remap ports");
        assert!(err.to_string().contains("unsupported under carrick's host networking"));
    }

    #[test]
    fn bridge_publish_accepts_udp() {
        let mappings = parse_publish_specs(NetworkMode::Bridge, &["5353:53/udp".to_string()])
            .expect("udp publish should parse");
        assert_eq!(mappings[0].protocol, PortProtocol::Udp);
        assert_eq!(mappings[0].host_port, Some(5353));
        assert_eq!(mappings[0].container_port, 53);
    }
}
```

- [ ] **Step 2: Write failing engine merge test**

Add to the existing `#[cfg(test)] mod tests` in `crates/carrick-engine/src/lib.rs`:

```rust
#[test]
fn bridge_network_resolves_into_run_spec() {
    let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
    let mut req = base_req(None);
    req.network = NetworkMode::Bridge;
    req.name = Some("web".to_string());
    req.published_ports = vec![PortMapping {
        host_ip: None,
        host_port: Some(8080),
        container_port: 80,
        protocol: carrick_spec::PortProtocol::Tcp,
    }];

    let spec = resolve_run_spec(req, image).expect("resolve run spec");
    assert_eq!(spec.network.mode, NetworkMode::Bridge);
    assert_eq!(spec.network.container_name.as_deref(), Some("web"));
    assert_eq!(spec.network.bridge_id.as_str(), "carrick0");
    assert_eq!(spec.network.published_ports[0].host_port, Some(8080));
}
```

- [ ] **Step 3: Run tests and verify they fail**

Run:

```bash
cargo test -p carrick-cli network_tests
cargo test -p carrick-engine bridge_network_resolves_into_run_spec
```

Expected: compile failure for missing `parse_publish_specs`, `CliRunRequest.network`, and `CliRunRequest.published_ports`.

- [ ] **Step 4: Replace host-only validation with typed parsing**

In `crates/carrick-cli/src/runtime_util.rs`, replace `validate_publish` with:

```rust
pub(crate) fn parse_publish_specs(
    network: carrick_spec::NetworkMode,
    specs: &[String],
) -> anyhow::Result<Vec<carrick_spec::PortMapping>> {
    let mut mappings = Vec::new();
    for spec in specs {
        let (body, proto) = match spec.rsplit_once('/') {
            Some((body, "tcp")) => (body, carrick_spec::PortProtocol::Tcp),
            Some((body, "udp")) => (body, carrick_spec::PortProtocol::Udp),
            Some((_body, other)) => anyhow::bail!(
                "invalid -p {spec:?}: unsupported protocol {other:?}; expected tcp or udp"
            ),
            None => (spec.as_str(), carrick_spec::PortProtocol::Tcp),
        };
        let parts: Vec<&str> = body.split(':').collect();
        let (host_ip, host, container) = match parts.as_slice() {
            [c] => (None, None, *c),
            [h, c] => (None, Some(*h), *c),
            [ip, h, c] => {
                let ip = ip.parse().map_err(|_| {
                    anyhow::anyhow!("invalid -p {spec:?}: bad host ip {ip:?}")
                })?;
                (Some(ip), Some(*h), *c)
            }
            _ => anyhow::bail!("invalid -p {spec:?}: expected [ip:]hostPort:containerPort[/proto]"),
        };
        let container_port: u16 = container.parse().map_err(|_| {
            anyhow::anyhow!("invalid -p {spec:?}: bad container port {container:?}")
        })?;
        let host_port = match host {
            Some(h) => Some(
                h.parse()
                    .map_err(|_| anyhow::anyhow!("invalid -p {spec:?}: bad host port {h:?}"))?,
            ),
            None => None,
        };
        if network == carrick_spec::NetworkMode::Host {
            let Some(host_port) = host_port else {
                anyhow::bail!(
                    "-p {spec:?}: publishing to a random host port is unsupported under carrick's host networking (the guest binds the host directly); use -p {container_port}:{container_port} or drop -p"
                );
            };
            if host_port != container_port {
                anyhow::bail!(
                    "-p {spec:?}: port remapping {host_port}->{container_port} is unsupported under carrick's host networking; the container binds {container_port} on the host directly. Use -p {container_port}:{container_port} or drop -p"
                );
            }
        }
        mappings.push(carrick_spec::PortMapping {
            host_ip,
            host_port,
            container_port,
            protocol: proto,
        });
    }
    Ok(mappings)
}
```

- [ ] **Step 5: Add CLI fields**

In `crates/carrick-cli/src/args.rs`, import `NetworkMode`:

```rust
use carrick_spec::{FsBackendKind, NetworkMode, PidMode};
```

Add to `Commands::Run` near `pid`:

```rust
/// Container network mode. `host` is the current behavior; `bridge` uses Carrick's socket namespace provider.
#[arg(long = "net", alias = "network", value_enum, default_value_t = NetworkMode::Host)]
network: NetworkMode,
```

Add the same field to `Commands::Create` near `pid`.

- [ ] **Step 6: Flow fields into engine request**

In `crates/carrick-engine/src/lib.rs`, extend imports:

```rust
pub use carrick_spec::{
    FsBackendKind, ImageConfig, Mount, NetworkMode, NetworkNamespaceSpec, PidMode, Platform,
    PortMapping, RunSpec,
};
```

Add to `CliRunRequest`:

```rust
pub network: NetworkMode,
pub published_ports: Vec<PortMapping>,
```

In `resolve_run_spec`, before building `RunSpec`, add:

```rust
let network = match req.network {
    NetworkMode::Host => NetworkNamespaceSpec::default(),
    NetworkMode::Bridge => NetworkNamespaceSpec::bridge_default(
        req.name.clone(),
        Vec::new(),
        req.published_ports.clone(),
    ),
};
```

Add `network,` to the `RunSpec` initializer.

Update the `base_req` helper and explicit `CliRunRequest` literals in engine tests with:

```rust
network: NetworkMode::Host,
published_ports: Vec::new(),
```

- [ ] **Step 7: Update `commands.rs` request construction**

In `crates/carrick-cli/src/commands.rs`, destructure `network` from `Commands::Run`, replace `validate_publish(&publish)?;` with:

```rust
let published_ports = parse_publish_specs(network, &publish)?;
```

Add to `CliRunRequest`:

```rust
network,
published_ports,
```

Apply the same model to `Commands::Create`: destructure `network`, call `parse_publish_specs(network, &Vec::new())` for the first slice because `create` does not yet expose `publish`, and pass the empty `published_ports` vector into `CliRunRequest`.

- [ ] **Step 8: Update lifecycle rebuild defaults**

In `crates/carrick-runtime/src/container.rs`, add fields to `RunConfig`:

```rust
/// Container network mode.
#[serde(default)]
pub network: carrick_spec::NetworkMode,
/// Published ports requested at create/run time.
#[serde(default)]
pub published_ports: Vec<carrick_spec::PortMapping>,
```

Add defaults in `impl Default for RunConfig`:

```rust
network: carrick_spec::NetworkMode::Host,
published_ports: Vec::new(),
```

In `crates/carrick-cli/src/lifecycle.rs`, update `build_created_state`:

```rust
network: req.network,
published_ports: req.published_ports.clone(),
```

Update `rebuild_request_from_state`:

```rust
network: c.network,
published_ports: c.published_ports.clone(),
```

Update the exec request construction in `lifecycle.rs` to keep exec in the target container's network mode:

```rust
network: state.config.network,
published_ports: Vec::new(),
```

Update `sample_state()` test data in `lifecycle.rs` with:

```rust
network: carrick_spec::NetworkMode::Host,
published_ports: Vec::new(),
```

- [ ] **Step 9: Run tests and compile check**

Run:

```bash
cargo test -p carrick-cli network_tests
cargo test -p carrick-engine bridge_network_resolves_into_run_spec
just check
```

Expected: targeted tests pass and `just check` completes.

- [ ] **Step 10: Commit**

```bash
git add crates/carrick-cli/src/args.rs crates/carrick-cli/src/runtime_util.rs crates/carrick-cli/src/commands.rs crates/carrick-cli/src/lifecycle.rs crates/carrick-engine/src/lib.rs crates/carrick-runtime/src/container.rs
git commit -m "feat(cli): parse bridge network options" -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 3: Add Runtime Network Provider Trait And Capability Reporting

**Files:**
- Create: `crates/carrick-runtime/src/network/mod.rs`
- Modify: `crates/carrick-runtime/src/lib.rs`
- Test: `crates/carrick-runtime/src/network/mod.rs`

**Interfaces:**
- Consumes: `NetworkNamespaceSpec`, `NetworkMode`, `PortMapping`.
- Produces: `NetworkProvider`, `NetworkCapabilities`, `BindTarget`, `ConnectTarget`, `NetworkLease`.

- [ ] **Step 1: Write failing provider capability tests**

Create `crates/carrick-runtime/src/network/mod.rs` with the test module first:

```rust
use carrick_spec::NetworkNamespaceSpec;
use std::net::SocketAddr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_provider_reports_host_capabilities() {
        let provider = select_provider(&NetworkNamespaceSpec::default());
        let caps = provider.capabilities();
        assert!(caps.kernel_datapath);
        assert!(caps.outbound_connectivity);
        assert!(!caps.same_bridge_ip_connectivity);
        assert!(!caps.host_routable_container_ips);
        assert!(!caps.requires_privilege);
    }
}
```

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
cargo test -p carrick-runtime host_provider_reports_host_capabilities
```

Expected: compile failure for missing provider types.

- [ ] **Step 3: Implement the provider trait and host provider**

Replace the temporary file contents with:

```rust
use carrick_spec::{NetworkMode, NetworkNamespaceSpec, PortMapping};
use std::net::SocketAddr;

pub mod socket_namespace;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkCapabilities {
    pub same_bridge_ip_connectivity: bool,
    pub outbound_connectivity: bool,
    pub published_ports: bool,
    pub kernel_datapath: bool,
    pub host_routable_container_ips: bool,
    pub packet_level_isolation: bool,
    pub raw_socket_support: bool,
    pub multicast_or_broadcast: bool,
    pub requires_privilege: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkLeaseId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLease {
    pub id: NetworkLeaseId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindTarget {
    Host(SocketAddr),
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTarget {
    Host(SocketAddr),
    Unchanged,
    Denied(i32),
}

pub trait NetworkProvider: Send + Sync {
    fn capabilities(&self) -> NetworkCapabilities;
    fn create_namespace(&self, spec: &NetworkNamespaceSpec) -> Result<NetworkLease, String>;
    fn destroy_namespace(&self, lease_id: NetworkLeaseId) -> Result<(), String>;
    fn publish_port(&self, lease_id: NetworkLeaseId, mapping: PortMapping) -> Result<(), String>;
    fn materialize_bind(
        &self,
        namespace_id: Option<&carrick_spec::NetworkNamespaceId>,
        requested: SocketAddr,
    ) -> Result<BindTarget, String>;
    fn resolve_connect(
        &self,
        namespace_id: Option<&carrick_spec::NetworkNamespaceId>,
        requested: SocketAddr,
    ) -> Result<ConnectTarget, String>;
}

#[derive(Debug, Default)]
pub struct HostNetworkProvider;

impl NetworkProvider for HostNetworkProvider {
    fn capabilities(&self) -> NetworkCapabilities {
        NetworkCapabilities {
            same_bridge_ip_connectivity: false,
            outbound_connectivity: true,
            published_ports: false,
            kernel_datapath: true,
            host_routable_container_ips: false,
            packet_level_isolation: false,
            raw_socket_support: false,
            multicast_or_broadcast: false,
            requires_privilege: false,
        }
    }

    fn create_namespace(&self, _spec: &NetworkNamespaceSpec) -> Result<NetworkLease, String> {
        Ok(NetworkLease { id: NetworkLeaseId(0) })
    }

    fn destroy_namespace(&self, _lease_id: NetworkLeaseId) -> Result<(), String> {
        Ok(())
    }

    fn publish_port(&self, _lease_id: NetworkLeaseId, _mapping: PortMapping) -> Result<(), String> {
        Ok(())
    }

    fn materialize_bind(
        &self,
        _namespace_id: Option<&carrick_spec::NetworkNamespaceId>,
        _requested: SocketAddr,
    ) -> Result<BindTarget, String> {
        Ok(BindTarget::Unchanged)
    }

    fn resolve_connect(
        &self,
        _namespace_id: Option<&carrick_spec::NetworkNamespaceId>,
        _requested: SocketAddr,
    ) -> Result<ConnectTarget, String> {
        Ok(ConnectTarget::Unchanged)
    }
}

pub fn select_provider(spec: &NetworkNamespaceSpec) -> Box<dyn NetworkProvider> {
    match spec.mode {
        NetworkMode::Host => Box::<HostNetworkProvider>::default(),
        NetworkMode::Bridge => Box::new(socket_namespace::SocketNamespaceProvider::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_provider_reports_host_capabilities() {
        let provider = select_provider(&NetworkNamespaceSpec::default());
        let caps = provider.capabilities();
        assert!(caps.kernel_datapath);
        assert!(caps.outbound_connectivity);
        assert!(!caps.same_bridge_ip_connectivity);
        assert!(!caps.host_routable_container_ips);
        assert!(!caps.requires_privilege);
    }
}
```

Create `crates/carrick-runtime/src/network/socket_namespace.rs` with a minimal provider:

```rust
use super::{
    BindTarget, ConnectTarget, NetworkCapabilities, NetworkLease, NetworkLeaseId, NetworkProvider,
};
use carrick_spec::{NetworkNamespaceId, NetworkNamespaceSpec, PortMapping};
use std::net::SocketAddr;

#[derive(Debug, Default)]
pub struct SocketNamespaceProvider;

impl SocketNamespaceProvider {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkProvider for SocketNamespaceProvider {
    fn capabilities(&self) -> NetworkCapabilities {
        NetworkCapabilities {
            same_bridge_ip_connectivity: true,
            outbound_connectivity: true,
            published_ports: true,
            kernel_datapath: true,
            host_routable_container_ips: false,
            packet_level_isolation: false,
            raw_socket_support: false,
            multicast_or_broadcast: false,
            requires_privilege: false,
        }
    }

    fn create_namespace(&self, _spec: &NetworkNamespaceSpec) -> Result<NetworkLease, String> {
        Ok(NetworkLease { id: NetworkLeaseId(1) })
    }

    fn destroy_namespace(&self, _lease_id: NetworkLeaseId) -> Result<(), String> {
        Ok(())
    }

    fn publish_port(&self, _lease_id: NetworkLeaseId, _mapping: PortMapping) -> Result<(), String> {
        Ok(())
    }

    fn materialize_bind(
        &self,
        _namespace_id: Option<&NetworkNamespaceId>,
        _requested: SocketAddr,
    ) -> Result<BindTarget, String> {
        Ok(BindTarget::Unchanged)
    }

    fn resolve_connect(
        &self,
        _namespace_id: Option<&NetworkNamespaceId>,
        _requested: SocketAddr,
    ) -> Result<ConnectTarget, String> {
        Ok(ConnectTarget::Unchanged)
    }
}
```

In `crates/carrick-runtime/src/lib.rs`, add:

```rust
pub mod network;
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p carrick-runtime host_provider_reports_host_capabilities
just check
```

Expected: tests and compile check pass.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime/src/lib.rs crates/carrick-runtime/src/network/mod.rs crates/carrick-runtime/src/network/socket_namespace.rs
git commit -m "feat(runtime): add network provider interface" -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 4: Implement Socket Namespace Registry

**Files:**
- Modify: `crates/carrick-runtime/src/network/socket_namespace.rs`
- Test: `crates/carrick-runtime/src/network/socket_namespace.rs`

**Interfaces:**
- Consumes: provider trait from Task 3.
- Produces: `VirtualEndpoint`, `register_virtual_endpoint`, same-bridge lookup, cross-bridge deny.

- [ ] **Step 1: Write failing registry tests**

Append to `crates/carrick-runtime/src/network/socket_namespace.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use carrick_spec::{BridgeId, NetworkNamespaceId, PortProtocol};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn provider_with_endpoint() -> SocketNamespaceProvider {
        let provider = SocketNamespaceProvider::new();
        provider
            .register_virtual_endpoint(
                BridgeId::new("carrick0"),
                NetworkNamespaceId::new("a"),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2)), 80),
                PortProtocol::Tcp,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152),
            )
            .expect("register endpoint");
        provider
    }

    #[test]
    fn resolves_same_bridge_virtual_endpoint() {
        let provider = provider_with_endpoint();
        let target = provider
            .resolve_registered_connect(
                &BridgeId::new("carrick0"),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2)), 80),
                PortProtocol::Tcp,
            )
            .expect("lookup")
            .expect("registered target");
        assert_eq!(target, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152));
    }

    #[test]
    fn does_not_resolve_different_bridge_virtual_endpoint() {
        let provider = provider_with_endpoint();
        let target = provider
            .resolve_registered_connect(
                &BridgeId::new("carrick1"),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2)), 80),
                PortProtocol::Tcp,
            )
            .expect("lookup");
        assert!(target.is_none());
    }
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p carrick-runtime network::socket_namespace::tests
```

Expected: compile failure for missing registry methods.

- [ ] **Step 3: Implement registry state**

Replace `SocketNamespaceProvider` with:

```rust
#[derive(Debug, Default)]
pub struct SocketNamespaceProvider {
    registry: std::sync::Mutex<std::collections::HashMap<VirtualEndpoint, SocketAddr>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VirtualEndpoint {
    bridge_id: BridgeId,
    addr: SocketAddr,
    protocol: PortProtocol,
}
```

Add imports:

```rust
use carrick_spec::{BridgeId, NetworkNamespaceId, NetworkNamespaceSpec, PortMapping, PortProtocol};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
```

Add methods:

```rust
impl SocketNamespaceProvider {
    pub fn new() -> Self {
        Self {
            registry: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_virtual_endpoint(
        &self,
        bridge_id: BridgeId,
        _namespace_id: NetworkNamespaceId,
        virtual_addr: SocketAddr,
        protocol: PortProtocol,
        host_addr: SocketAddr,
    ) -> Result<(), String> {
        let key = VirtualEndpoint {
            bridge_id,
            addr: virtual_addr,
            protocol,
        };
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
        registry.insert(key, host_addr);
        Ok(())
    }

    pub fn resolve_registered_connect(
        &self,
        bridge_id: &BridgeId,
        virtual_addr: SocketAddr,
        protocol: PortProtocol,
    ) -> Result<Option<SocketAddr>, String> {
        let key = VirtualEndpoint {
            bridge_id: bridge_id.clone(),
            addr: virtual_addr,
            protocol,
        };
        let registry = self
            .registry
            .lock()
            .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
        Ok(registry.get(&key).copied())
    }
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p carrick-runtime network::socket_namespace::tests
```

Expected: registry tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime/src/network/socket_namespace.rs
git commit -m "feat(runtime): add socket namespace registry" -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 5: Initialize Network Lease During Runtime Execution

**Files:**
- Modify: `crates/carrick-runtime/src/execute.rs`
- Modify: `crates/carrick-runtime/src/network/mod.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Test: `crates/carrick-runtime/src/network/mod.rs`

**Interfaces:**
- Consumes: `select_provider(&spec.network)`.
- Produces: a runtime-owned provider handle available to socket dispatch code.

- [ ] **Step 1: Write failing lease lifecycle test**

Add to `crates/carrick-runtime/src/network/mod.rs` tests:

```rust
#[test]
fn bridge_provider_creates_nonzero_lease() {
    let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
    let provider = select_provider(&spec);
    let lease = provider.create_namespace(&spec).expect("create namespace");
    assert_ne!(lease.id, NetworkLeaseId(0));
    provider.destroy_namespace(lease.id).expect("destroy namespace");
}
```

- [ ] **Step 2: Run test**

Run:

```bash
cargo test -p carrick-runtime bridge_provider_creates_nonzero_lease
```

Expected: pass if Task 3 already returned `NetworkLeaseId(1)` for bridge; keep the test as the lifecycle guard.

- [ ] **Step 3: Add runtime network context**

In `crates/carrick-runtime/src/network/mod.rs`, add:

```rust
pub struct RuntimeNetwork {
    pub spec: NetworkNamespaceSpec,
    pub provider: Box<dyn NetworkProvider>,
    pub lease: NetworkLease,
}

impl RuntimeNetwork {
    pub fn create(spec: &NetworkNamespaceSpec) -> Result<Self, String> {
        let provider = select_provider(spec);
        let lease = provider.create_namespace(spec)?;
        for mapping in &spec.published_ports {
            provider.publish_port(lease.id, mapping.clone())?;
        }
        Ok(Self {
            spec: spec.clone(),
            provider,
            lease,
        })
    }
}

impl Drop for RuntimeNetwork {
    fn drop(&mut self) {
        let _ = self.provider.destroy_namespace(self.lease.id);
    }
}
```

- [ ] **Step 4: Thread context through execution**

In `crates/carrick-runtime/src/execute.rs`, near the start of `Runtime::execute`, create the context before dispatcher creation:

```rust
let runtime_network = std::sync::Arc::new(
    crate::network::RuntimeNetwork::create(&spec.network)
        .map_err(|e| RuntimeError::Unsupported(format!("network setup failed: {e}")))?,
);
```

In `crates/carrick-runtime/src/dispatch/mod.rs`, add this field to `SyscallDispatcher`:

```rust
network: std::sync::Arc<crate::network::RuntimeNetwork>,
```

Change `SyscallDispatcher::new()` to initialize host networking for tests and bare call sites:

```rust
network: std::sync::Arc::new(
    crate::network::RuntimeNetwork::create(&carrick_spec::NetworkNamespaceSpec::default())
        .expect("default host network provider must initialize"),
),
```

Add a constructor for runtime execution:

```rust
pub fn with_network(network: std::sync::Arc<crate::network::RuntimeNetwork>) -> Self {
    Self {
        network,
        ..Self::new()
    }
}
```

In `execute.rs`, replace the container dispatcher construction that currently calls `SyscallDispatcher::new()` with:

```rust
let dispatcher = SyscallDispatcher::with_network(runtime_network.clone());
```

Keep bare `run-elf` paths on `SyscallDispatcher::new()` so they stay host-networked.

- [ ] **Step 5: Compile**

Run:

```bash
just check
```

Expected: compile succeeds with the network context stored but not yet used by socket syscalls.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/execute.rs crates/carrick-runtime/src/network/mod.rs crates/carrick-runtime/src/dispatch/mod.rs
git commit -m "feat(runtime): initialize network provider leases" -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 6: Materialize Bridge Binds Onto Loopback

**Files:**
- Modify: `crates/carrick-runtime/src/network/socket_namespace.rs`
- Modify: `crates/carrick-runtime/src/dispatch/net.rs`
- Test: `crates/carrick-runtime/src/network/socket_namespace.rs`

**Interfaces:**
- Consumes: dispatcher `RuntimeNetwork` handle from Task 5.
- Produces: `bind(virtual_ip:port)` and `bind(0.0.0.0:port)` map to host loopback and register virtual endpoints.

- [ ] **Step 1: Write failing bind materialization tests**

Add to `socket_namespace.rs` tests:

```rust
#[test]
fn materialize_bind_maps_container_ip_to_loopback() {
    let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
    let provider = SocketNamespaceProvider::new();
    provider.create_namespace(&spec).expect("namespace");
    let requested = SocketAddr::new(IpAddr::V4(spec.ipv4), 80);
    let target = provider
        .materialize_bridge_bind(&spec, requested, PortProtocol::Tcp)
        .expect("bind target");
    match target {
        BindTarget::Host(host) => {
            assert_eq!(host.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert_eq!(host.port(), 0);
        }
        other => panic!("expected host bind target, got {other:?}"),
    }
}

#[test]
fn materialize_bind_rejects_foreign_container_ip() {
    let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
    let provider = SocketNamespaceProvider::new();
    let requested = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 99)), 80);
    let err = provider
        .materialize_bridge_bind(&spec, requested, PortProtocol::Tcp)
        .expect_err("foreign address should fail");
    assert!(err.contains("address is not assigned"));
}
```

- [ ] **Step 2: Run failing tests**

Run:

```bash
cargo test -p carrick-runtime materialize_bind_maps_container_ip_to_loopback materialize_bind_rejects_foreign_container_ip
```

Expected: compile failure for missing `materialize_bridge_bind`.

- [ ] **Step 3: Implement bind target logic**

In `socket_namespace.rs`, add:

```rust
impl SocketNamespaceProvider {
    pub fn materialize_bridge_bind(
        &self,
        spec: &NetworkNamespaceSpec,
        requested: SocketAddr,
        protocol: PortProtocol,
    ) -> Result<BindTarget, String> {
        match requested.ip() {
            std::net::IpAddr::V4(ip) if ip == spec.ipv4 || ip == std::net::Ipv4Addr::UNSPECIFIED => {
                let host = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
                if let Some(namespace_id) = spec.namespace_id.clone() {
                    let virtual_ip = if ip == std::net::Ipv4Addr::UNSPECIFIED {
                        spec.ipv4
                    } else {
                        ip
                    };
                    self.register_virtual_endpoint(
                        spec.bridge_id.clone(),
                        namespace_id,
                        SocketAddr::new(std::net::IpAddr::V4(virtual_ip), requested.port()),
                        protocol,
                        host,
                    )?;
                }
                Ok(BindTarget::Host(host))
            }
            std::net::IpAddr::V4(ip) if ip == std::net::Ipv4Addr::LOCALHOST => Ok(BindTarget::Unchanged),
            _ => Err(format!("address is not assigned to network namespace: {requested}")),
        }
    }
}
```

Update `NetworkProvider::materialize_bind` for `SocketNamespaceProvider` to load the active spec. If the provider does not store specs yet, add:

```rust
namespaces: Mutex<HashMap<NetworkNamespaceId, NetworkNamespaceSpec>>,
```

and populate it in `create_namespace`.

- [ ] **Step 4: Hook dispatch `bind`**

In `crates/carrick-runtime/src/dispatch/net.rs`, in the INET/INET6 `bind` path after `read_linux_sockaddr` returns but before `libc::bind`, convert the parsed host address into `SocketAddr`, call the provider, and replace the host sockaddr when `BindTarget::Host` is returned.

Use these helpers inside `net.rs`:

```rust
fn sockaddr_to_socket_addr(bytes: &[u8]) -> Option<std::net::SocketAddr> {
    if bytes.len() < 16 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    if family != crate::linux_abi::LINUX_AF_INET {
        return None;
    }
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let ip = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    Some(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port))
}

fn socket_addr_to_linux_sockaddr(addr: std::net::SocketAddr) -> Option<Vec<u8>> {
    let std::net::SocketAddr::V4(v4) = addr else {
        return None;
    };
    let mut out = vec![0_u8; 16];
    out[0..2].copy_from_slice(&(crate::linux_abi::LINUX_AF_INET as u16).to_ne_bytes());
    out[2..4].copy_from_slice(&v4.port().to_be_bytes());
    out[4..8].copy_from_slice(&v4.ip().octets());
    Some(out)
}
```

Support AF_INET only in this task and leave AF_INET6 unchanged because v1 bridge defaults are IPv4.

- [ ] **Step 5: Run tests and compile**

Run:

```bash
cargo test -p carrick-runtime materialize_bind_maps_container_ip_to_loopback materialize_bind_rejects_foreign_container_ip
just check
```

Expected: tests and compile pass.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/network/socket_namespace.rs crates/carrick-runtime/src/dispatch/net.rs
git commit -m "feat(runtime): map bridge binds to loopback" -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 7: Resolve Same-Bridge Connects

**Files:**
- Modify: `crates/carrick-runtime/src/network/socket_namespace.rs`
- Modify: `crates/carrick-runtime/src/dispatch/net.rs`
- Test: `crates/carrick-runtime/src/network/socket_namespace.rs`

**Interfaces:**
- Consumes: virtual endpoint registry from Task 4 and bind registration from Task 6.
- Produces: same-bridge `connect(container_ip:port)` rewrites to the registered host loopback target; cross-bridge virtual IPs are denied.

- [ ] **Step 1: Write failing connect resolution test**

Add to `socket_namespace.rs` tests:

```rust
#[test]
fn bridge_connect_to_registered_peer_rewrites_to_loopback() {
    let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
    let provider = SocketNamespaceProvider::new();
    provider.create_namespace(&spec).expect("namespace");
    let peer = SocketAddr::new(IpAddr::V4(spec.ipv4), 8080);
    provider
        .register_virtual_endpoint(
            spec.bridge_id.clone(),
            spec.namespace_id.clone().unwrap(),
            peer,
            PortProtocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50080),
        )
        .expect("register");

    let target = provider
        .resolve_bridge_connect(&spec, peer, PortProtocol::Tcp)
        .expect("resolve");
    assert_eq!(target, ConnectTarget::Host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50080)));
}
```

- [ ] **Step 2: Run failing test**

Run:

```bash
cargo test -p carrick-runtime bridge_connect_to_registered_peer_rewrites_to_loopback
```

Expected: compile failure for missing `resolve_bridge_connect`.

- [ ] **Step 3: Implement connect resolution**

Add:

```rust
impl SocketNamespaceProvider {
    pub fn resolve_bridge_connect(
        &self,
        spec: &NetworkNamespaceSpec,
        requested: SocketAddr,
        protocol: PortProtocol,
    ) -> Result<ConnectTarget, String> {
        if let Some(host) =
            self.resolve_registered_connect(&spec.bridge_id, requested, protocol)?
        {
            return Ok(ConnectTarget::Host(host));
        }

        match requested.ip() {
            std::net::IpAddr::V4(ip) if ip.octets()[0] == 172 && ip.octets()[1] == 31 => {
                Ok(ConnectTarget::Denied(crate::linux_abi::LINUX_ECONNREFUSED))
            }
            _ => Ok(ConnectTarget::Unchanged),
        }
    }
}
```

- [ ] **Step 4: Hook dispatch `connect`**

In `crates/carrick-runtime/src/dispatch/net.rs`, in the `connect` path after `read_linux_sockaddr` and before `libc::connect`, call the provider. For `ConnectTarget::Host`, replace the host sockaddr with the loopback endpoint. For `ConnectTarget::Denied(errno)`, return `DispatchOutcome::Errno { errno }`.

- [ ] **Step 5: Run tests and compile**

Run:

```bash
cargo test -p carrick-runtime bridge_connect_to_registered_peer_rewrites_to_loopback
just check
```

Expected: tests and compile pass.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/network/socket_namespace.rs crates/carrick-runtime/src/dispatch/net.rs
git commit -m "feat(runtime): resolve bridge connects" -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 8: Preserve Guest-Visible Socket Addresses

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/fd_table.rs`
- Modify: `crates/carrick-runtime/src/dispatch/net.rs`
- Modify: `crates/carrick-runtime/src/network/socket_namespace.rs`
- Test: `crates/carrick-runtime/src/network/socket_namespace.rs`

**Interfaces:**
- Consumes: bind/connect rewrites from Tasks 6 and 7.
- Produces: guest-visible address metadata for `getsockname`, `getpeername`, `accept4`, `recvfrom`.

- [ ] **Step 1: Write failing address metadata test**

Add to `socket_namespace.rs` tests:

```rust
#[test]
fn records_guest_visible_local_address_for_rewritten_bind() {
    let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
    let provider = SocketNamespaceProvider::new();
    let guest = SocketAddr::new(IpAddr::V4(spec.ipv4), 80);
    let host = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50080);
    provider
        .record_socket_addresses(7, Some(guest), Some(host), None)
        .expect("record");
    let visible = provider.guest_visible_local_addr(7).expect("visible addr");
    assert_eq!(visible, Some(guest));
}
```

- [ ] **Step 2: Run failing test**

Run:

```bash
cargo test -p carrick-runtime records_guest_visible_local_address_for_rewritten_bind
```

Expected: compile failure for missing address metadata methods.

- [ ] **Step 3: Add metadata registry**

In `SocketNamespaceProvider`, add:

```rust
socket_addrs: Mutex<HashMap<i32, SocketAddressState>>,
```

Define:

```rust
#[derive(Debug, Clone, Default)]
struct SocketAddressState {
    guest_local: Option<SocketAddr>,
    host_local: Option<SocketAddr>,
    guest_peer: Option<SocketAddr>,
}
```

Add methods:

```rust
pub fn record_socket_addresses(
    &self,
    guest_fd: i32,
    guest_local: Option<SocketAddr>,
    host_local: Option<SocketAddr>,
    guest_peer: Option<SocketAddr>,
) -> Result<(), String> {
    let mut socket_addrs = self
        .socket_addrs
        .lock()
        .map_err(|_| "socket address registry lock poisoned".to_string())?;
    socket_addrs.insert(
        guest_fd,
        SocketAddressState {
            guest_local,
            host_local,
            guest_peer,
        },
    );
    Ok(())
}

pub fn guest_visible_local_addr(&self, guest_fd: i32) -> Result<Option<SocketAddr>, String> {
    let socket_addrs = self
        .socket_addrs
        .lock()
        .map_err(|_| "socket address registry lock poisoned".to_string())?;
    Ok(socket_addrs.get(&guest_fd).and_then(|s| s.guest_local))
}

pub fn guest_visible_peer_addr(&self, guest_fd: i32) -> Result<Option<SocketAddr>, String> {
    let socket_addrs = self
        .socket_addrs
        .lock()
        .map_err(|_| "socket address registry lock poisoned".to_string())?;
    Ok(socket_addrs.get(&guest_fd).and_then(|s| s.guest_peer))
}
```

- [ ] **Step 4: Hook address-returning syscalls**

In `net.rs`:

- after rewritten `bind`, call `record_socket_addresses(fd, Some(guest_requested), Some(host_bound), None)`;
- after rewritten `connect`, call `record_socket_addresses(fd, existing_local, Some(host_target), Some(guest_requested))`;
- in `getsockname`, if provider returns a guest-visible local address for `fd`, write that Linux sockaddr instead of the host kernel result;
- in `getpeername`, if provider returns a guest-visible peer address for `fd`, write that Linux sockaddr instead of the host kernel result;
- in `accept4`, map accepted peer addresses through the registry when the listener was a virtual bridge listener;
- in `recvfrom`, preserve guest-visible datagram source addresses once UDP support is enabled.

Use existing `write_linux_sockaddr` and `host_to_linux_sockaddr` helpers; add a small `socket_addr_to_linux_sockaddr` helper for AF_INET.

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p carrick-runtime records_guest_visible_local_address_for_rewritten_bind
just check
```

Expected: tests and compile pass.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/dispatch/fd_table.rs crates/carrick-runtime/src/dispatch/net.rs crates/carrick-runtime/src/network/socket_namespace.rs
git commit -m "feat(runtime): preserve bridge socket addresses" -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 9: Report Bridge State Through rtnetlink And Guest Files

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/net/support.rs`
- Modify: `crates/carrick-runtime/src/dispatch/net.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fs/state.rs`
- Test: `crates/carrick-runtime/src/dispatch/net/support.rs`

**Interfaces:**
- Consumes: `NetworkNamespaceSpec`.
- Produces: bridge-shaped `RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`, `/etc/hosts`, and `/etc/resolv.conf` views.

- [ ] **Step 1: Write failing netlink test**

Add a test in `support.rs` near existing netlink tests:

```rust
#[test]
fn bridge_netlink_reports_eth0_address_and_default_route() {
    let spec = carrick_spec::NetworkNamespaceSpec::bridge_default(
        Some("web".to_string()),
        Vec::new(),
        Vec::new(),
    );
    let snapshot = NetworkLinkSnapshot::from_spec(&spec);
    assert!(snapshot.links.iter().any(|l| l.name == "eth0"));
    assert!(snapshot
        .addresses
        .iter()
        .any(|a| a.addr == std::net::IpAddr::V4(spec.ipv4)));
    assert!(snapshot
        .routes
        .iter()
        .any(|r| r.gateway == Some(std::net::IpAddr::V4(spec.gateway_v4))));
}
```

- [ ] **Step 2: Run failing test**

Run:

```bash
cargo test -p carrick-runtime bridge_netlink_reports_eth0_address_and_default_route
```

Expected: compile failure for missing `NetworkLinkSnapshot`.

- [ ] **Step 3: Add bridge-aware snapshot**

In `support.rs`, add:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NetworkLinkSnapshot {
    pub links: Vec<NetworkLink>,
    pub addresses: Vec<NetworkAddress>,
    pub routes: Vec<NetworkRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NetworkLink {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NetworkAddress {
    pub addr: std::net::IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NetworkRoute {
    pub destination: Option<std::net::IpAddr>,
    pub gateway: Option<std::net::IpAddr>,
}

impl NetworkLinkSnapshot {
    pub(super) fn from_spec(spec: &carrick_spec::NetworkNamespaceSpec) -> Self {
        if spec.mode == carrick_spec::NetworkMode::Bridge {
            Self {
                links: vec![
                    NetworkLink { name: "lo".to_string() },
                    NetworkLink { name: "eth0".to_string() },
                ],
                addresses: vec![
                    NetworkAddress {
                        addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        prefix_len: 8,
                    },
                    NetworkAddress {
                        addr: std::net::IpAddr::V4(spec.ipv4),
                        prefix_len: 24,
                    },
                ],
                routes: vec![NetworkRoute {
                    destination: None,
                    gateway: Some(std::net::IpAddr::V4(spec.gateway_v4)),
                }],
            }
        } else {
            Self {
                links: vec![NetworkLink { name: "lo".to_string() }],
                addresses: vec![NetworkAddress {
                    addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    prefix_len: 8,
                }],
                routes: vec![NetworkRoute {
                    destination: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                    gateway: None,
                }],
            }
        }
    }
}
```

Wire `build_netlink_reply` to accept a snapshot or network spec from the dispatcher instead of building only the hardcoded loopback view.

- [ ] **Step 4: Materialize guest files**

In `fs/state.rs`, adjust `/etc/hosts` and `/etc/resolv.conf` generation:

```text
127.0.0.1 localhost
172.31.0.2 <container-name>
```

and:

```text
nameserver 172.31.0.1
```

Only emit bridge values when `RunSpec.network.mode == NetworkMode::Bridge`; preserve the existing host-network behavior for `NetworkMode::Host`.

- [ ] **Step 5: Run tests and compile**

Run:

```bash
cargo test -p carrick-runtime bridge_netlink_reports_eth0_address_and_default_route
just check
```

Expected: test and compile pass.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/dispatch/net/support.rs crates/carrick-runtime/src/dispatch/net.rs crates/carrick-runtime/src/dispatch/fs/state.rs
git commit -m "feat(runtime): report bridge network state" -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 10: Add TCP Published Port Forwarding

**Files:**
- Modify: `crates/carrick-runtime/src/network/socket_namespace.rs`
- Test: `crates/carrick-runtime/src/network/socket_namespace.rs`

**Interfaces:**
- Consumes: `PortMapping`, registry lookup.
- Produces: TCP listener forwarding host port to registered virtual endpoint.

- [ ] **Step 1: Write failing conflict test**

Add:

```rust
#[test]
fn publish_tcp_rejects_missing_target_endpoint() {
    let spec = NetworkNamespaceSpec::bridge_default(
        None,
        Vec::new(),
        vec![carrick_spec::PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(18080),
            container_port: 80,
            protocol: PortProtocol::Tcp,
        }],
    );
    let provider = SocketNamespaceProvider::new();
    let lease = provider.create_namespace(&spec).expect("namespace");
    let err = provider
        .publish_port(lease.id, spec.published_ports[0].clone())
        .expect_err("target is not bound yet");
    assert!(err.contains("no registered TCP endpoint"));
}
```

- [ ] **Step 2: Run failing test**

Run:

```bash
cargo test -p carrick-runtime publish_tcp_rejects_missing_target_endpoint
```

Expected: current stub returns `Ok`, so the test fails.

- [ ] **Step 3: Implement TCP publish validation and listener ownership**

In `SocketNamespaceProvider`, add:

```rust
published_tcp: Mutex<HashMap<NetworkLeaseId, Vec<std::net::TcpListener>>>,
```

In `publish_port`, for TCP:

1. Look up the virtual endpoint `(bridge_id, spec.ipv4:mapping.container_port, Tcp)`.
2. If missing, return `Err(format!("no registered TCP endpoint for published port {}", mapping.container_port))`.
3. Bind `mapping.host_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)):mapping.host_port.unwrap_or(0)`.
4. Spawn a named thread that accepts host connections and copies bytes bidirectionally to the loopback target using `std::io::copy` on cloned streams.
5. Store the listener under `published_tcp` so dropping the provider closes it.

Use this helper for the copy loop:

```rust
fn proxy_tcp_stream(mut inbound: std::net::TcpStream, target: SocketAddr) -> std::io::Result<()> {
    let mut outbound = std::net::TcpStream::connect(target)?;
    let mut inbound_clone = inbound.try_clone()?;
    let mut outbound_clone = outbound.try_clone()?;
    let left = std::thread::spawn(move || std::io::copy(&mut inbound_clone, &mut outbound));
    let right = std::thread::spawn(move || std::io::copy(&mut outbound_clone, &mut inbound));
    let _ = left.join();
    let _ = right.join();
    Ok(())
}
```

- [ ] **Step 4: Run tests and compile**

Run:

```bash
cargo test -p carrick-runtime publish_tcp_rejects_missing_target_endpoint
just check
```

Expected: test and compile pass.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime/src/network/socket_namespace.rs
git commit -m "feat(runtime): add bridge tcp publishing" -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 11: Add App-Level Bridge Conformance Probes

**Files:**
- Add: `conformance-probes/src/bin/bridge_tcp_peer.rs`
- Add: `conformance-probes/src/bin/bridge_publish_tcp.rs`
- Add: `crates/carrick-cli/tests/probe-oracle/aarch64-gnu/bridge_tcp_peer`
- Add: `crates/carrick-cli/tests/probe-oracle/aarch64-musl/bridge_tcp_peer`
- Add: `crates/carrick-cli/tests/probe-oracle/aarch64-gnu/bridge_publish_tcp`
- Add: `crates/carrick-cli/tests/probe-oracle/aarch64-musl/bridge_publish_tcp`
- Modify: `crates/carrick-cli/tests/conformance.rs`

**Interfaces:**
- Consumes: implemented `--net bridge`, same-bridge connect, and published TCP forwarding.
- Produces: reproducible differential probes for bridge app semantics.

- [ ] **Step 1: Add probe source for same-bridge TCP**

Create `conformance-probes/src/bin/bridge_tcp_peer.rs`:

```rust
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:8080").expect("bind server");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).expect("read ping");
        stream.write_all(b"ok").expect("write ok");
    });

    thread::sleep(Duration::from_millis(100));
    let mut client = TcpStream::connect("172.31.0.2:8080").expect("connect peer");
    client.write_all(b"ping").expect("write ping");
    let mut reply = [0_u8; 2];
    client.read_exact(&mut reply).expect("read reply");
    server.join().expect("server thread");

    println!("bridge_tcp_connect_ok=true");
    println!("bridge_tcp_reply={}", std::str::from_utf8(&reply).expect("utf8 reply"));
}
```

This probe is single-process and same-namespace; it proves virtual bridge bind/connect rewriting before multi-container orchestration is added.

- [ ] **Step 2: Add expected oracle output**

Add expected output files under the matching `probe-oracle` architecture directories:

```text
bridge_tcp_connect_ok=true
bridge_tcp_reply=ok
```

- [ ] **Step 3: Add published-port probe**

Create `conformance-probes/src/bin/bridge_publish_tcp.rs`:

```rust
use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:8080").expect("bind published server");
    println!("bridge_publish_listener_ready=true");
    let (mut stream, _) = listener.accept().expect("accept host connection");
    let mut buf = [0_u8; 4];
    stream.read_exact(&mut buf).expect("read ping");
    stream.write_all(b"ok").expect("write ok");
    println!("bridge_publish_tcp_ok=true");
}
```

Add a host-side test in `crates/carrick-cli/tests/conformance.rs` that launches this probe with `--net bridge -p 18080:8080`, waits until stdout contains `bridge_publish_listener_ready=true`, connects to `127.0.0.1:18080`, writes `ping`, reads `ok`, and asserts the child exits successfully.

- [ ] **Step 4: Run targeted probes**

Run:

```bash
just build
target/release/carrick conformance --suite bridge-tcp
target/release/carrick conformance --suite bridge-publish-tcp
```

Expected: `bridge_tcp_peer` matches the committed oracle output, and the host-side published-port test receives `ok` through `127.0.0.1:18080`.

- [ ] **Step 5: Commit**

```bash
git add conformance-probes/src/bin/bridge_tcp_peer.rs conformance-probes/src/bin/bridge_publish_tcp.rs crates/carrick-cli/tests/conformance.rs crates/carrick-cli/tests/probe-oracle
git commit -m "test(conformance): cover bridge socket networking" -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 12: Documentation And Final Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/syscalls-emulation-map.md`
- Modify: `docs/support-matrix.md` if regenerated by the matrix tool
- Modify: `docs/superpowers/specs/2026-07-01-carrick-socket-network-namespace-design.md` only if implementation exposes a deliberate spec correction

**Interfaces:**
- Consumes: completed implementation and probe results.
- Produces: user-facing docs that distinguish socket-namespace bridge fidelity from packet-level bridge fidelity.

- [ ] **Step 1: Update docs wording**

In `README.md`, add a networking note:

```markdown
`--net bridge` uses Carrick's socket namespace provider on macOS: normal TCP/UDP
applications get Docker-style bridge addressing, same-bridge connectivity,
outbound connectivity, and published TCP ports. It is not a packet-level bridge:
container IPs are not host-routable, and raw sockets, AF_PACKET, arbitrary ICMP,
multicast, broadcast, and netfilter are not implemented.
```

In `docs/syscalls-emulation-map.md`, update networking rows to mention bridge-aware synthetic rtnetlink and the app-level socket namespace provider.

- [ ] **Step 2: Run local gate**

Run:

```bash
just fmt-check
just clippy
just check
just test
just test-integration
```

Expected: all pass.

- [ ] **Step 3: Run runtime smoke**

Run:

```bash
just build
target/release/carrick run --net bridge ubuntu:24.04 /bin/sh -lc 'ip addr; ip route; python3 - <<PY
import socket
s=socket.socket()
print("socket_ok=true")
PY'
```

Expected: output includes `eth0`, `172.31.0.2`, a default route via `172.31.0.1`, and `socket_ok=true`.

- [ ] **Step 4: Run targeted conformance**

Run:

```bash
target/release/carrick conformance --suite bridge-tcp
target/release/carrick conformance --suite bridge-publish-tcp
```

Expected: both suites match the Docker oracle.

- [ ] **Step 5: Commit docs and generated matrix**

```bash
git add README.md docs/syscalls-emulation-map.md docs/support-matrix.md docs/superpowers/specs/2026-07-01-carrick-socket-network-namespace-design.md
git commit -m "docs(network): document socket bridge semantics" -m "Co-Authored-By: Codex <codex@openai.com>"
```

- [ ] **Step 6: Final full CI gate**

Run:

```bash
just ci
```

Expected: full local gate passes.
