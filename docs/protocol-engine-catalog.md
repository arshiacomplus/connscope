# ConnScope Protocol and Engine Capability Catalog

## Overview

This catalog defines the scope inventory of network protocols, proxy/tunnel engines, transport layers, security/camouflage wrappers, and measurement capabilities targetable by ConnScope.

It establishes an architectural boundary: **engines, protocols, transports, and security layers are modeled as orthogonal dimensions**, enabling systematic measurement across varied combinations (e.g. VLESS over TCP with REALITY vs. VLESS over gRPC with TLS).

> [!NOTE]
> This catalog is a scope and capability inventory. It documents target architectures, prerequisites, and measurement dimensions. It does not claim that all listed protocols or engines are already implemented in ConnScope.

---

## 1. Classification Dimensions

| Dimension | Description | Examples |
|---|---|---|
| **Engine / Core** | Software runtime or kernel facility executing the client/server connection | Xray-core, sing-box, V2Ray-core, WireGuard, OpenVPN, SSH |
| **Protocol** | Application-level encapsulation or proxy framing | VLESS, VMess, Trojan, Shadowsocks, WireGuard, SSH |
| **Transport** | Underlying channel carrying the protocol stream/datagrams | TCP, UDP, WebSocket, gRPC, HTTPUpgrade, XHTTP (SplitHTTP), mKCP, QUIC |
| **Security / Camouflage** | Cryptographic envelope or active censorship-resistance layer | None, TLS, REALITY, ShadowTLS, Noise |
| **Measurement Capability** | Specific metric or state verifiable by ConnScope | TCP connect, TLS handshake, tunnel verification, post-tunnel data transfer, throughput, latency |

---

## 2. Multi-Protocol Engine Cores

| Engine Core | Implementation Type | Supported Protocols | Supported Transports | Supported Security Layers | Prerequisites & Privileges | Status |
|---|---|---|---|---|---|---|
| **Xray-core** | External Go binary (`xray`) | VLESS, VMess, Trojan, Shadowsocks, Dokodemo-door | TCP, mKCP, WebSocket, gRPC, HTTPUpgrade, XHTTP/SplitHTTP, QUIC | TLS, REALITY | User-space process; non-root | **Local real-binary checks passed** (host Xray 26.3.27: config syntax & process lifecycle verified; live tunnel & data transfer unverified; Phase 10: `XrayVlessTcpRealityAdapter`, Phase 13: `XrayVmessWebSocketTlsAdapter`) |
| **sing-box** | External Go binary (`sing-box`) | VLESS, VMess, Trojan, Shadowsocks, Shadowsocks-2022, Hysteria2, TUIC, WireGuard | TCP, UDP, WebSocket, gRPC, HTTPUpgrade | TLS, REALITY, ShadowTLS | User-space process; non-root | **Local real-binary checks passed** (host sing-box 1.12.12: config syntax & process lifecycle verified; live tunnel & data transfer unverified; requires 1.10.0+ for uTLS; Phase 12: `SingBoxVlessTcpRealityAdapter`, Phase 14: `SingBoxVmessWebSocketTlsAdapter`) |
| **V2Ray-core** | External Go binary (`v2ray`) | VMess, VLESS, Trojan, Shadowsocks | TCP, mKCP, WebSocket, gRPC, HTTP/2 | TLS | User-space process; non-root | **Catalogued** |

---

## 3. Proxy and Tunnel Protocols

| Protocol | Category | Typical Engines | Transport Combinations | Security Options | Intended Capabilities | Dependencies | Status |
|---|---|---|---|---|---|---|---|
| **VLESS** | Modern Proxy Protocol | Xray-core, sing-box | TCP, WebSocket, gRPC, HTTPUpgrade, XHTTP | TLS, REALITY, None | Connect, Handshake, Tunnel Verify, Data Transfer, Latency | Engine binary, target credentials (UUID) | **Mocked lifecycle tests passed** (Xray and sing-box VLESS+REALITY adapters; host Xray 26.3.27 & sing-box 1.12.12 config syntax & process lifecycle verified; live tunnel & data transfer unverified) |
| **VMess** | Legacy Authenticated Proxy | Xray-core, sing-box, V2Ray-core | TCP, mKCP, WebSocket, gRPC, HTTPUpgrade | TLS, None | Connect, Handshake, Tunnel Verify, Data Transfer, Latency | Engine binary, UUID, AlterID | **Mocked lifecycle tests passed** (Phase 13: `XrayVmessWebSocketTlsAdapter`, Phase 14: `SingBoxVmessWebSocketTlsAdapter`; host Xray 26.3.27 & sing-box 1.12.12 config syntax & process lifecycle verified; live tunnel & data transfer unverified) |
| **Trojan** | TLS-Mimicking Proxy | Xray-core, sing-box | TCP, WebSocket, gRPC | TLS | Connect, Handshake, Tunnel Verify, Latency | Engine binary, password | **Catalogued** |
| **Shadowsocks (AEAD)** | Stream/Datagram Proxy | Xray-core, sing-box, shadowsocks-rust | TCP, UDP | None (AEAD cipher built-in: ChaCha20-Poly1305, AES-256-GCM) | Connect, Tunnel Verify, Latency | Engine binary, method, password | **Catalogued** |
| **Shadowsocks-2022** | Modernized SS Protocol | sing-box, shadowsocks-rust | TCP, UDP | Built-in session authentication (2022-blake3-aes-128-gcm, etc.) | Connect, Tunnel Verify, Latency, Replay Protection | Engine binary, PSK | **Catalogued** |
| **Hysteria 2** | UDP-Based Congestion Control Proxy | sing-box, hysteria standalone | UDP / QUIC | TLS, Salamander camouflage | Connect, Handshake, Throughput, Loss Tolerance, Latency | Engine binary, port hopping rules | **Catalogued** |
| **TUIC (v5)** | QUIC-Based Proxy | sing-box, tuic standalone | UDP / QUIC | TLS | Connect, Handshake, Throughput, Latency | Engine binary, UUID, password | **Catalogued** |

---

## 4. Transport & Camouflage Variations

| Transport / Camouflage | Framing Layer | Target Engine | Purpose & Characterization | Status |
|---|---|---|---|---|
| **TCP** | Native L4 Stream | All | Direct socket streaming; baseline comparison | **Existing basic Probe** (`tcp_connect`) |
| **WebSocket** | HTTP/1.1 Upgrade Stream | Xray-core, sing-box, V2Ray-core | CDN compatibility, path multiplexing | **Mocked lifecycle tests passed** (Phase 13: `XrayVmessWebSocketTlsAdapter`, Phase 14: `SingBoxVmessWebSocketTlsAdapter`) |
| **gRPC** | HTTP/2 Framing | Xray-core, sing-box, V2Ray-core | Multiplexed RPC streaming over TLS | **Catalogued** |
| **HTTPUpgrade** | Standard HTTP Upgrade | Xray-core, sing-box | Lightweight reverse proxy compatibility | **Catalogued** |
| **XHTTP (SplitHTTP)** | Chunked Upload/Download | Xray-core | Asymmetric upload/download routing; CDN compatibility | **Catalogued** |
| **mKCP** | UDP ARQ Protocol | Xray-core, V2Ray-core | UDP-based loss recovery and congestion tuning | **Catalogued** |
| **REALITY** | TLS ClientHello Camouflage | Xray-core, sing-box | Eliminates server certificate footprint by forward-borrowing third-party TLS identities | **Mocked lifecycle tests passed** (Phase 10: `XrayVlessTcpRealityAdapter`, Phase 12: `SingBoxVlessTcpRealityAdapter`) |
| **ShadowTLS** | Dual-Session TLS SNI Hijack | sing-box | Mimics handshake with trusted SNI target before injecting payload | **Catalogued** |

---

## 5. Independent VPNs and Tunnel Implementations

| Implementation | Type | Protocol / Layer | Transport | Prerequisites & Privileges | Intended Capabilities | Status |
|---|---|---|---|---|---|---|
| **WireGuard** | Kernel Module / User-space Go (`wg`, `wireguard-go`) | UDP Layer 3 Tunnel | UDP | Root or `CAP_NET_ADMIN` for interface; private key | Connect, Handshake, Tunnel Verify, Throughput, Packet Loss | **Implemented (Netns & Origin-Netns)** |
| **OpenVPN** | User-space TUN process (`openvpn`) | SSL/TLS L3 Tunnel | UDP, TCP | Root or `CAP_NET_ADMIN`; certs / credentials | Connect, Handshake, Tunnel Verify, MTU, Throughput | **Implemented (Config Validation & Mocked Lifecycle)** |
| **IPsec (IKEv2)** | Kernel / strongSwan | L3 Security Association | UDP (500, 4500), ESP | Root; kernel IPsec support; pre-shared key or certs | Connect, SA Negotiation, Latency | **Planned** |
| **SSH Tunneling** | Native / OpenSSH | Encrypted L7/L4 Forwarding | TCP | OpenSSH client or Python `asyncssh`; credentials | Connect, Auth, Port Forward Verify, Throughput | **Planned** |
| **DNSTT** | User-space DNS Tunnel (`dnstt-client`) | DNS Tunneling | DoH, DoT, UDP/TCP DNS | Domain delegation (NS record), resolver, public key | Tunnel Verify, Query Latency, Throughput | **Planned** |
| **Slipstream** | User-space Tunnel | Obfuscated Transport | TCP / QUIC | Binary executable; credentials | Tunnel Verify, Censorship Resilience | **Experimental** |
| **TrustTunnel** | Custom L4/L7 Wrapper | Encrypted Stream | TCP | Binary / custom protocol wrapper | Tunnel Verify, Handshake Latency | **Experimental** |
| **MasterDnsVPN** | DNS-Based VPN | UDP DNS Datagrams | UDP 53 | Configured DNS NS server | Tunnel Verify, Packet Loss | **Experimental** |

---

## 6. DNS and Basic Network Transports

| Component | Target Layer | Protocol / Port | Measurement Metrics | Status in ConnScope |
|---|---|---|---|---|
| **DNS (Classic)** | Application (L7) | UDP 53, TCP 53 | Query latency, NXDOMAIN, answer record parsing | **Existing basic Probe** (`dns_resolve`) |
| **DNS over TLS (DoT)** | Encrypted Application (L7) | TCP 853 | TCP connect, TLS handshake, query latency, cert validation | **Planned** |
| **DNS over HTTPS (DoH)** | Encrypted Application (L7) | TCP 443 | HTTP/2, HTTP/3, query latency, wire-format parsing | **Planned** |
| **DNS over QUIC (DoQ)** | Encrypted Application (L7) | UDP 853 | QUIC handshake, query latency | **Planned** |
| **TCP Connect** | Transport (L4) | Any TCP port | Socket connect time, RST vs. Drop vs. Timeout, MSS | **Existing basic Probe** (`tcp_connect`) |
| **TLS Handshake** | Security (L5/L6) | Any TLS port | ClientHello, SNI control, cert chain verification, cipher selection | **Existing basic Probe** (`tls_handshake`) |
| **HTTP Request** | Application (L7) | HTTP/1.1 (80/443) | TTFB, HTTP status, headers, transfer duration | **Existing basic Probe** (`http_request`) |
| **UDP Connect / Datagram**| Transport (L4) | Any UDP port | Echo response, ICMP unreachable, packet loss | **Planned** |
| **MTU / Fragmentation** | Network (L3) | ICMP / Path MTU | Path MTU discovery, DF-bit drop detection | **Planned** |
| **Jitter & Packet Loss** | Network / Transport | UDP / ICMP | Packet delay variation, consecutive loss bursts | **Planned** |
| **Throughput & Goodput** | End-to-End | TCP, QUIC | Multi-stream bandwidth, bottleneck bandwidth, buffer bloat | **Planned** |

---

## 7. Status Taxonomy and Governance

Every entry in this catalog adheres to explicit, verifiable lifecycle statuses. Capabilities are never marked as verified merely because configuration can be generated or an external process can be started. In particular, automated tests utilizing mock binaries and loopback fixtures prove adapter lifecycle mechanics, not real-world network interoperation:

1. **`Catalogued`**: Formally specified architecture, parameter schemas, and orthogonal dimensions documented in this catalog.
2. **`Configuration validation implemented`**: Parameter schemas and credential validation logic implemented and unit-tested in code.
3. **`Adapter lifecycle implemented`**: Process management, safe workspace isolation, dynamic port allocation with collision retry, process group cleanup, and bounded stream reading implemented.
4. **`Mocked lifecycle tests passed`**: The full adapter lifecycle (process spawn, readiness polling, tunnel verification, data transfer) is verified using isolated mock binaries and local loopback test fixtures.
5. **`Real tunnel verification tested`**: L4/L7 handshake verified against a real server using a real engine binary.
6. **`Real end-to-end data transfer tested`**: Application-level data transfer (e.g. HTTP GET 204 or 200) verified end-to-end through a real tunnel using a real engine binary.
7. **`Real-engine integration tested`**: Full end-to-end integration verified against an external, production-grade engine installation and deployed endpoint.
8. **`Existing basic Probe`**: Natively implemented in `connscope.probes` using Python standard library without external dependencies.
9. **`Experimental`**: Prototype implementation; not yet stabilized for production agent deployment.
10. **`Unsupported / blocked`**: Evaluated but blocked due to documented security, kernel, or platform constraints.

> [!IMPORTANT]
> **Separation of Evidence Dimensions**:
> 1. **Configuration Validation & Syntax**: Both **Xray 26.3.27** (`xray run -test -c`) and **sing-box 1.12.12** (`sing-box check -c`) have verified real-binary configuration parsing locally across both VLESS REALITY and VMess WebSocket TLS schemas.
> 2. **Process Lifecycle & Cleanup**: Both **Xray 26.3.27** and **sing-box 1.12.12** have verified process spawning, local SOCKS5 listener readiness, timed teardown, and secret scrubbing against loopback targets for both adapters.
> 3. **Live Remote Tunnel Verification & Application Data Transfer**: Because automated tests strictly run without external network traffic or test servers, live remote tunnel handshakes and end-to-end data transfers remain **unverified on live networks** until explicitly tested against a configured test server.
> 4. **Version Specificity**: Real-binary validation was executed specifically on host versions **Xray 26.3.27** and **sing-box 1.12.12**. Other versions remain unverified without direct execution evidence. In particular, sing-box REALITY and VMess WS TLS adapters configure uTLS (introduced in sing-box 1.10.0), meaning earlier versions (1.8.0–1.9.x) cannot run the generated client schema.

---

## 8. Xray-core VLESS TCP REALITY Adapter Guide

The `XrayVlessTcpRealityAdapter` (`xray_vless_tcp_reality`) measures VLESS over TCP wrapped in REALITY TLS camouflage using an external Xray-core client process.

### Version Compatibility & REALITY Schema

- **Supported Versions**: Xray-core v1.8.0+ (REALITY was introduced in Xray-core v1.8.0).
- **Minimum Requirement**: `ExecutableRequirement(binary_name="xray", min_version="1.8.0")`.
- **REALITY Public Key Schema Compatibility**:
  - *Current Official Specification*: According to official Xray documentation ([xtls.github.io/en/config/transports/reality.html](https://xtls.github.io/en/config/transports/reality.html)), the client outbound `realitySettings` field for the server's Curve25519 public key is `password` (renamed from `publicKey` in v1.8.3+ to prevent configuration confusion with server-side keys).
  - *Legacy Specification*: Early Xray versions (v1.8.0–v1.8.2) used `publicKey`.
  - *Dual Field Generation*: The adapter emits both `"password"` and `"publicKey"` in `realitySettings`. Because Go's standard `json.Unmarshal` unmarshals into matching struct fields and safely ignores unrecognized keys, this guarantees compatibility across modern and legacy v1.8.0+ binaries.
  - *Adapter Input Flexibility*: In the Python configuration dictionary, callers may supply either `public_key` or `password`; the adapter validates and normalizes both keys.

### Endpoint Semantics

The adapter strictly distinguishes between three independent network endpoints:
1. **Remote Xray Server Endpoint** (`target.host:target.port`): The remote server running the VLESS TCP REALITY service, specified in the VLESS outbound `vnext[0].address` and `vnext[0].port`.
2. **Local Proxy Endpoint** (`127.0.0.1:local_socks_port`): The local SOCKS5 listener spawned by the adapter on loopback to expose the tunnel.
3. **Post-Tunnel Test Destination** (`test_url` host and port): The target host and port passed to SOCKS5 `CONNECT` through the tunnel (e.g., `cp.cloudflare.com:80` for HTTP or `con.acp.us.ci:443` for HTTPS). HTTP requests never target the local proxy port or the remote Xray server directly.

### Configuration Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `uuid` | string (UUID) | **Yes** | — | RFC 4122 client UUID |
| `public_key` / `password` | string | **Yes** | — | REALITY server public key (Curve25519, accepts either field) |
| `short_id` | string (hex) | **Yes** | — | REALITY short ID hex string (0 to 16 hex chars, even length) |
| `server_name` | string | **Yes** | — | SNI / ServerName target hostname |
| `fingerprint` | string | No | `"chrome"` | TLS ClientHello fingerprint (`chrome`, `safari`, `firefox`, `ios`, `android`, `edge`) |
| `spider_x` | string | No | `"/"` | REALITY spider path |
| `flow` | string | No | `""` | Flow control parameter (e.g. `""` or `"xtls-rprx-vision"`) |
| `test_url` | string (URL) | No | `"http://cp.cloudflare.com/generate_204"` | URL used to verify post-tunnel data transfer |
| `timeout_s` | float | No | `10.0` | Overall execution deadline in seconds |
| `startup_timeout_s` | float | No | `3.0` | Local proxy readiness polling timeout |
| `local_port` | integer | No | `0` (dynamic) | Local SOCKS5 proxy port (0 allocates dynamic free port) |
| `verify_cert` | boolean | No | `True` | Validate TLS certificate when `test_url` is HTTPS |
| `ssl_context` | SSLContext | No | `None` | Custom SSLContext for HTTPS test destination validation |

Target parameters:
- `target.host`: Server IP address or domain name.
- `target.port`: Server port (1–65535, typically 443).

### Adapter Execution Lifecycle

1. **Pre-flight & Configuration Validation**:
   - Validates `Target` and all configuration schema constraints.
   - Enforces strict `short_id` rules: hexadecimal characters only, even length representing complete bytes, and max 16 hex characters (8 bytes).
   - Resolves the `xray` binary using `resolve_safe_executable` from system allowlist paths (`/usr/local/bin`, `/usr/bin`, `/bin`). Fails at `FailureStage.PRE_FLIGHT` if binary is missing.
2. **Resource Allocation & Isolation**:
   - Allocates independent dynamic loopback ports (`127.0.0.1:0`) for local SOCKS5 and HTTP inbound listeners with bounded retry (up to 3 attempts) to eliminate port bind race conditions.
   - Creates a temporary directory with `0o700` permissions via `safe_temporary_workspace()`.
   - Generates client configuration matching official Xray-core REALITY schema with dual-compatibility fields (`realitySettings`: `serverName`, `fingerprint`, `password`, `publicKey`, `shortId`, `spiderX`, `show: false`) and writes `config.json` with `0o600` permissions.
3. **Process Spawning**:
   - Spawns `[executable, "run", "-c", config_path]` without a shell (`asyncio.create_subprocess_exec`, `start_new_session=True`).
   - Attaches background bounded output readers to avoid OS pipe deadlock by continually draining stdout/stderr while limiting stored memory to 64 KB.
4. **Local Proxy Readiness Check**:
   - Actively polls local TCP port until the local SOCKS listener accepts connections or the process exits. Fails at `FailureStage.PROCESS_SPAWN` on crash or timeout.
5. **Tunnel Establishment Verification**:
   - Initiates RFC 1928 SOCKS5 handshake to the local proxy and issues `CONNECT` command to destination host and port.
   - Xray performs the remote VLESS connection and REALITY TLS handshake.
   - If SOCKS5 replies with `0x00`, `tunnel_established = True` and `handshake_ms` is recorded.
   - If handshake fails, reports `FailureStage.HANDSHAKE` (`tunnel_established=False, data_transfer_completed=False`).
6. **HTTPS TLS Upgrade & Certificate Verification Semantics**:
   - If `test_url` uses HTTPS, the adapter initiates `writer.start_tls(ssl_context, server_hostname=dest_host)` over the SOCKS5 stream.
   - *Enforced Mode (`verify_cert: True`, default)*: Validates the destination server certificate against trust anchors. If verification fails, the probe fails closed at `FailureStage.HANDSHAKE` with `tunnel_established=True, tls_verified=False, verified_data_transfer=False, data_transfer_completed=False`. If valid, `tls_verified = True` and successful HTTP transfer yields `verified_data_transfer = True`.
   - *Disabled Mode (`verify_cert: False`)*: Bypasses certificate trust validation (`tls_verification_mode: "disabled"`). Successful TLS establishment and post-tunnel HTTP data transfer reports `ProbeStatus.SUCCESS` with `tunnel_established=True, data_transfer_completed=True, tls_verified=False, verified_data_transfer=False`. Disabling certificate verification never causes false probe failures or falsely claims certificate verification.
7. **End-to-End Data Transfer Verification**:
   - Sends an HTTP GET request to `test_url` over the established (and optionally TLS-upgraded) tunnel.
   - Reads and parses the HTTP status line. Status codes 200–399 confirm `data_transfer_completed = True` and record `data_transfer_ms`.
   - If data transfer fails (e.g. 502/504 or reset), reports `FailureStage.DATA_TRANSFER` (`tunnel_established=True, data_transfer_completed=False`).
8. **Cleanup**:
   - In all termination paths (success, failure, timeout, cancellation), sends `SIGTERM` to the process group, falls back to `SIGKILL` on timeout, and removes the temporary workspace.
   - Scrubs all credentials (`uuid`, `public_key`, `short_id`, tokens) from result dictionaries and error messages.

### Remote Agent Isolation

External engine adapters are strictly isolated from the Remote Agent:
- Remote Agent does not expose or register adapters by default.
- Remote measure requests for external-process adapters (`POST /v1/measure`) fail closed with HTTP 404 / `unknown_probe` or 403 `forbidden`.
- Remote execution of external binaries is prohibited without explicit server-side opt-in.

### Safe Local Integration Testing & Evidence Tiers

Phase 11 introduces a multi-tier, opt-in integration verification workflow that distinguishes between schema validation, process lifecycle execution, tunnel establishment, and live application data transfer:

| Verification Tier | Tested Component | Prerequisites | Evidence Level |
|---|---|---|---|
| **Tier 1: Binary Detection & Version** | `xray version` | Allowlisted `xray` binary (`/usr/local/bin`, `/usr/bin`, `/bin`) + `CONNSCOPE_TEST_REAL_XRAY=1` | Verified against host binary (`Xray 26.3.27`) |
| **Tier 2: Real Binary Config Validation** | `xray run -test -c <config>` | Allowlisted `xray` binary + `CONNSCOPE_TEST_REAL_XRAY=1` | Verified against host binary (`Xray 26.3.27`) |
| **Tier 3: Process Lifecycle & Cleanup** | Process spawn, local SOCKS5 bind, readiness polling, graceful teardown | Allowlisted `xray` binary + `CONNSCOPE_TEST_REAL_XRAY=1` (tested on loopback `127.0.0.1`) | Verified against host binary (`Xray 26.3.27`) |
| **Tier 4: Live Tunnel & Data Transfer** | Remote VLESS+REALITY handshake, SOCKS5 `CONNECT`, and HTTP/HTTPS transfer | Allowlisted `xray` binary + `CONNSCOPE_TEST_REAL_XRAY=1` + explicit test server configuration | Real engine verified *only* when an explicit test server is provided; skipped otherwise |

> [!IMPORTANT]
> - **Configuration Validation alone does not verify the tunnel or data transfer.** Successful syntax/schema validation through `xray run -test -c` establishes that the generated JSON satisfies the engine's config parser, but does not prove network connectivity.
> - **Binary Version Evidence**: Field naming compatibility was verified against the real host binary **Xray 26.3.27** (validating `password`, fallback `publicKey`, and dual emission). Because no legacy v1.8.0–v1.8.2 binary is installed and downloading external software is strictly forbidden, legacy binary execution is explicitly marked as **unverified on real binary**.

#### Running Integration Tests

1. **Local Binary Validation and Lifecycle Tests** (no external network needed):
```bash
CONNSCOPE_TEST_REAL_XRAY=1 .venv/bin/python -m pytest -rs tests/adapters/test_xray_real_integration.py
```
This detects the local allowlisted Xray binary, executes `xray run -test -c` against dual and single field configurations, and verifies process spawning, local port binding, readiness timing, and guaranteed teardown against loopback.

2. **Live Tunnel & Data Transfer Test** (against an explicitly configured test server):
```bash
# JSON configuration:
export CONNSCOPE_TEST_REAL_XRAY=1
export CONNSCOPE_REAL_XRAY_CONFIG='{
  "server_host": "198.51.100.1",
  "port": 443,
  "uuid": "<your-test-uuid>",
  "public_key": "<your-reality-public-key>",
  "short_id": "<your-short-id>",
  "server_name": "<your-reality-sni>",
  "test_url": "http://cp.cloudflare.com/generate_204"
}'

# Alternatively, via individual environment variables:
export CONNSCOPE_TEST_REAL_XRAY=1
export CONNSCOPE_REAL_XRAY_SERVER="198.51.100.1"
export CONNSCOPE_REAL_XRAY_PORT=443
export CONNSCOPE_REAL_XRAY_UUID="<your-test-uuid>"
export CONNSCOPE_REAL_XRAY_PUBLIC_KEY="<your-reality-public-key>"
export CONNSCOPE_REAL_XRAY_SHORT_ID="<your-short-id>"
export CONNSCOPE_REAL_XRAY_SERVER_NAME="<your-reality-sni>"

# Run the live test:
.venv/bin/python -m pytest -rs tests/adapters/test_xray_real_integration.py -k test_real_xray_tunnel_and_data_transfer
```

> [!CAUTION]
> - Never set test targets to the production VPS (`https://con.acp.us.ci`) or production endpoints.
> - Never hardcode or commit credentials into git or documentation.
> - When server configuration is missing, live tunnel tests skip cleanly and will never silently substitute default endpoints.

---

## 9. sing-box VLESS TCP REALITY Adapter Guide & Cross-Engine Comparison

The `SingBoxVlessTcpRealityAdapter` (`singbox_vless_tcp_reality`) implements ConnScope's second external-engine adapter for VLESS over TCP with REALITY security, establishing an apples-to-apples basis for measuring and comparing the two primary proxy cores under identical network conditions.

### Version Compatibility & Strict Schema Requirements

- **Verified Configuration-Parser & Lifecycle Version**: `sing-box v1.12.12` (locally verified with real host binary).
- **Architectural Requirement**: `ExecutableRequirement(binary_name="sing-box", min_version="1.10.0")`.
- **uTLS Compatibility Constraint**:
  Client REALITY in sing-box requires TLS fingerprinting through uTLS. Because uTLS configuration was introduced in sing-box **v1.10.0**, earlier versions (v1.8.0–v1.9.x) cannot parse or execute this client configuration. Versions from v1.10.0 through v1.12.11 remain unverified without direct execution evidence.
- **Strict JSON Unmarshaling**:
  Unlike Xray-core (which ignores unknown JSON fields during struct unmarshaling), sing-box strictly enables `DisallowUnknownFields` in its configuration parser.
  - The client outbound `tls.reality` block **MUST** use `"public_key"`.
  - Supplying `"password"` or `"publicKey"` inside `tls.reality` results in immediate fatal parsing failure:
    ```
    FATAL[0000] decode config: outbounds[0].tls.reality.password: json: unknown field "password"
    ```
  - In the Python configuration dictionary, `validate_config()` accepts either `"public_key"` or `"password"` to keep adapter invocation ergonomic, but `generate_singbox_client_config()` generates strictly `"public_key"`.
- **Mandatory uTLS Fingerprint**:
  The adapter explicitly configures `"utls": {"enabled": true, "fingerprint": "chrome"}` within the outbound `tls` block.

---

### Cross-Engine Schema & CLI Comparison: sing-box vs. Xray-core

| Feature / Dimension | sing-box (`SingBoxVlessTcpRealityAdapter`) | Xray-core (`XrayVlessTcpRealityAdapter`) |
|---|---|---|
| **Adapter ID** | `singbox_vless_tcp_reality` | `xray_vless_tcp_reality` |
| **Engine Identifier** | `EngineType.SING_BOX` (`"sing-box"`) | `EngineType.XRAY` (`"xray"`) |
| **Executable Name** | `sing-box` | `xray` |
| **Outbound Structure** | Flat: `{"type": "vless", "server": ..., "server_port": ..., "uuid": ...}` | Nested: `{"protocol": "vless", "settings": {"vnext": [...]}}` |
| **REALITY Block Location** | `outbounds[0].tls.reality` | `outbounds[0].streamSettings.realitySettings` |
| **REALITY Public Key Key** | Strictly `"public_key"` (`unknown field` fatal error if omitted or altered) | Dual-emitted: `"password"` (modern) and `"publicKey"` (legacy) |
| **uTLS Configuration** | `outbounds[0].tls.utls: {"enabled": true, "fingerprint": "chrome"}` | `streamSettings.realitySettings.fingerprint: "chrome"` |
| **Log Section** | `{"log": {"level": "warn"}}` | `{"log": {"loglevel": "warning"}}` |
| **Inbound Structure** | `[{"type": "socks", "tag": "socks-in", "listen": ..., "listen_port": ...}, {"type": "http", ...}]` | `[{"protocol": "socks", "port": ..., "listen": ...}, {"protocol": "http", ...}]` |
| **Syntax Test Command** | `sing-box check -c <config_path>` | `xray run -test -c <config_path>` |
| **Process Run Command** | `sing-box run -c <config_path> --disable-color` | `xray run -c <config_path>` |

---

### Shared Lifecycle and Process Safety Architecture

Both adapters reuse the unified process lifecycle and verification infrastructure implemented in `connscope.adapters.process`:

1. **Restricted Temporary Workspaces**:
   - Unique ephemeral directory created per execution via `safe_temporary_workspace()` with `0o700` permissions.
   - Configuration files generated with owner read/write permissions (`0o600`), automatically removed upon completion.
2. **Safe Subprocess Execution**:
   - Spawned using `asyncio.create_subprocess_exec` with `start_new_session=True` and `shell=False`.
   - Continuous non-blocking stream readers (`read_bounded_stream`) drain `stdout` and `stderr` concurrently, preventing OS pipe buffer deadlocks while limiting memory consumption to 64 KB.
3. **Dynamic Port Collision Retries**:
   - Loopback SOCKS5 and HTTP ports are allocated dynamically (`127.0.0.1:0`) with up to 3 bounded retry attempts if port bind conflicts occur during startup.
4. **Independent Endpoint Verification**:
   - Strict separation between the remote server endpoint, local proxy inbound, and post-tunnel test URL.
   - Measures distinct timing metrics: `local_ready_ms` (process readiness), `handshake_ms` (tunnel establishment), and `data_transfer_ms` (application payload).
   - Reports distinct failure stages: `PRE_FLIGHT`, `CONFIG_GENERATION`, `PROCESS_SPAWN`, `HANDSHAKE`, `DATA_TRANSFER`, or `TIMEOUT`.
5. **HTTPS Certificate Validation Semantics**:
   - Default `verify_cert: True` validates the test URL TLS certificate through the tunnel, failing at `FailureStage.HANDSHAKE` if untrusted.
   - Setting `verify_cert: False` explicitly records `tls_verification_mode: "disabled"` and `tls_verified: False`, avoiding false claims of certificate authenticity.
6. **Credential Scrubbing & Guaranteed Teardown**:
   - Sensitive fields (`uuid`, `public_key`, `password`, `short_id`, tokens) are scrubbed to `[REDACTED]` from all returned results, logs, and error messages.
   - Process groups receive `SIGTERM` followed by `SIGKILL` on timeout in a `finally` block, ensuring no orphan processes remain.

---

### Safe Integration Verification Tiers for sing-box

| Verification Tier | Tested Component | Prerequisites | Evidence Level |
|---|---|---|---|
| **Tier 1: Binary Detection & Version** | `sing-box version` | Allowlisted `sing-box` binary + `CONNSCOPE_TEST_REAL_SINGBOX=1` | Verified against host binary (`sing-box 1.12.12`) |
| **Tier 2: Real Binary Config Validation** | `sing-box check -c <config>` | Allowlisted `sing-box` binary + `CONNSCOPE_TEST_REAL_SINGBOX=1` | Verified against host binary (`sing-box 1.12.12`) |
| **Tier 3: Process Lifecycle & Cleanup** | Process spawn, local SOCKS5 bind, readiness polling, graceful teardown | Allowlisted `sing-box` binary + `CONNSCOPE_TEST_REAL_SINGBOX=1` (tested on loopback `127.0.0.1`) | Verified against host binary (`sing-box 1.12.12`) |
| **Tier 4: Live Tunnel & Data Transfer** | Remote VLESS+REALITY handshake, SOCKS5 `CONNECT`, and HTTP/HTTPS transfer | Allowlisted `sing-box` binary + `CONNSCOPE_TEST_REAL_SINGBOX=1` + explicit test server configuration | Real engine verified *only* when an explicit test server is provided; skipped otherwise |

#### Running sing-box Integration Tests

1. **Local Binary Validation and Lifecycle Tests** (no external network needed):
```bash
CONNSCOPE_TEST_REAL_SINGBOX=1 .venv/bin/python -m pytest -rs tests/adapters/test_singbox_real_integration.py
```
This detects the local allowlisted sing-box executable, executes `sing-box check -c` against valid and invalid schemas (confirming rejection of `password` and `publicKey`), and verifies process spawning, local port binding, readiness timing, and guaranteed teardown against loopback.

2. **Live Tunnel & Data Transfer Test** (against an explicitly configured test server):
```bash
# JSON configuration:
export CONNSCOPE_TEST_REAL_SINGBOX=1
export CONNSCOPE_REAL_SINGBOX_CONFIG='{
  "server_host": "198.51.100.1",
  "port": 443,
  "uuid": "<your-test-uuid>",
  "public_key": "<your-reality-public-key>",
  "short_id": "<your-short-id>",
  "server_name": "<your-reality-sni>",
  "test_url": "http://cp.cloudflare.com/generate_204"
}'

# Run the live test:
.venv/bin/python -m pytest -rs tests/adapters/test_singbox_real_integration.py -k test_real_singbox_tunnel_and_data_transfer
```

> [!CAUTION]
> - Never set test targets to the production VPS (`https://con.acp.us.ci`) or production endpoints.
> - Never hardcode or commit credentials into git or documentation.
> - When server configuration is missing, live tunnel tests skip cleanly and will never silently substitute default endpoints.

---

## 10. Xray-core VMess over WebSocket + TLS Adapter Guide

The `XrayVmessWebSocketTlsAdapter` (`xray_vmess_ws_tls`) implements ConnScope's adapter for VMess over WebSocket encapsulated in standard TLS encryption using an external Xray-core client process.

### Version Compatibility & Configuration Schema

- **Supported Versions**: Xray-core v1.8.0+ (compatible through current v26.x+).
- **Minimum Requirement**: `ExecutableRequirement(binary_name="xray", min_version="1.8.0")`.
- **JSON Configuration Schema**:
  - **Inbounds**: Local SOCKS5 and HTTP listeners on loopback `127.0.0.1`.
  - **Outbound Protocol**: `"vmess"` with target server address and port in `settings.vnext[0]`.
  - **User Authentication**: Client UUID in `settings.vnext[0].users[0].id`, `alterId` (typically `0`), and encryption cipher `security` (default `"auto"`).
  - **Transport Layer**: `streamSettings.network: "ws"` with `wsSettings` specifying `path` (e.g. `"/ws"`) and optional Host header via `host` and `headers.Host`.
  - **Security Layer**: `streamSettings.security: "tls"` with `tlsSettings` specifying `serverName` (SNI), `allowInsecure` (`False` when `verify_cert` is `True`), and TLS ClientHello `fingerprint`.
  - **No REALITY Settings**: Unlike VLESS REALITY, VMess WebSocket TLS contains no `realitySettings`, `password`, `publicKey`, `shortId`, or `spiderX` fields.

### Configuration Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `uuid` | string (UUID) | **Yes** | — | RFC 4122 client UUID |
| `server_name` | string | **Yes** | — | SNI / ServerName target hostname for TLS handshake |
| `path` | string | No | `"/"` | WebSocket HTTP path (e.g. `"/ws"`, auto-prepends `"/"`) |
| `host_header` | string | No | `None` | Optional HTTP Host header for WebSocket upgrade request |
| `alter_id` | integer | No | `0` | VMess alterId integer (0–65535, modern standard is 0) |
| `security` | string | No | `"auto"` | VMess encryption (`auto`, `aes-128-gcm`, `chacha20-poly1305`) |
| `fingerprint` | string | No | `"chrome"` | TLS ClientHello fingerprint (`chrome`, `safari`, `firefox`, `ios`, `android`, `edge`) |
| `timeout_s` | float | No | `10.0` | Overall execution deadline in seconds |
| `startup_timeout_s` | float | No | `3.0` | Local proxy readiness polling timeout |
| `local_port` | integer | No | `0` (dynamic) | Local SOCKS5 proxy port (0 allocates dynamic free port) |
| `verify_cert` | boolean | No | `True` | Validate TLS certificate on HTTPS test destinations and Xray TLS |
| `ssl_context` | SSLContext | No | `None` | Custom SSLContext for HTTPS test destination validation |

### VMess System-Clock Synchronization Requirement & Operational Impact

> [!WARNING]
> **Strict System-Clock Synchronization (±90s Window)**:
> VMess protocol authentication relies on an HMAC-MD5 16-byte request header computed over the client UUID and a 64-bit UTC epoch timestamp (in seconds).
>
> - **Anti-Replay Window**: Both Xray-core and sing-box servers enforce a strict tolerance window (typically **±90 seconds**) relative to the server's UTC time. Requests arriving with timestamps outside this window are unconditionally rejected.
> - **Failure Mode**: When clock drift exceeds ±90 seconds:
>   1. TCP connection establishes successfully (`local_ready_ms` records normal startup).
>   2. TLS handshake completes successfully (assuming the TLS certificate itself is not expired).
>   3. WebSocket upgrade handshake completes successfully (if an intermediate reverse proxy such as Nginx or Caddy handles the HTTP upgrade).
>   4. The server backend abruptly closes the WebSocket connection or drops the stream during VMess command header validation.
>   5. In ConnScope, the probe records `ProbeStatus.FAILED` at `failure_stage: "handshake"` with `tunnel_established: false`.
> - **Diagnostic Distinction**: Because this failure manifests identically to an invalid UUID, a blocked path, or deep packet inspection (DPI) blocking, operators must verify local host time synchronization (e.g. `timedatectl status` or `chronyc tracking`) before diagnosing network path or credential issues.

### Endpoint Semantics

The adapter strictly separates:
1. **Remote VMess Server Endpoint** (`target.host:target.port`): The remote server running the VMess WebSocket TLS service, configured in `outbounds[0].settings.vnext[0]`.
2. **Local Proxy Inbound** (`127.0.0.1:local_socks_port`): The local SOCKS5 listener used to interface with the running tunnel.
3. **Post-Tunnel Test Destination** (`test_url`): The target passed to SOCKS5 `CONNECT` through the tunnel to verify real application data transfer.

### Safe Local Integration Testing Tiers for VMess

| Verification Tier | Tested Component | Prerequisites | Evidence Level |
|---|---|---|---|
| **Tier 1: Binary Detection & Version** | `xray version` | Allowlisted `xray` binary + `CONNSCOPE_TEST_REAL_XRAY=1` | Verified against host binary (`Xray 26.3.27`) |
| **Tier 2: Real Binary Config Validation** | `xray run -test -c <config>` | Allowlisted `xray` binary + `CONNSCOPE_TEST_REAL_XRAY=1` | Verified against host binary (`Xray 26.3.27`) |
| **Tier 3: Process Lifecycle & Cleanup** | Process spawn, local SOCKS5 bind, readiness polling, graceful teardown | Allowlisted `xray` binary + `CONNSCOPE_TEST_REAL_XRAY=1` (tested on loopback `127.0.0.1`) | Verified against host binary (`Xray 26.3.27`) |
| **Tier 4: Live Tunnel & Data Transfer** | Remote VMess+WS+TLS handshake, SOCKS5 `CONNECT`, and HTTP/HTTPS transfer | Allowlisted `xray` binary + `CONNSCOPE_TEST_REAL_XRAY=1` + explicit VMess test server configuration | Unverified without explicit test server; skips cleanly |

#### Running VMess Local Tests
```bash
CONNSCOPE_TEST_REAL_XRAY=1 .venv/bin/python -m pytest -rs tests/adapters/test_xray_real_integration.py -k vmess
```

---

## 11. sing-box VMess over WebSocket + TLS Adapter Guide & Cross-Engine Comparison

The `SingBoxVmessWebSocketTlsAdapter` (`singbox_vmess_ws_tls`) implements ConnScope's fourth functional adapter, completing the 2x2 matrix of engines (Xray-core vs. sing-box) and protocol/transport stacks (VLESS+TCP+REALITY vs. VMess+WS+TLS).

### Version Compatibility & Strict Schema Requirements

- **Verified Configuration-Parser & Lifecycle Version**: `sing-box v1.12.12` (verified locally with real host binary).
- **Minimum Requirement**: `ExecutableRequirement(binary_name="sing-box", min_version="1.10.0")`.
- **uTLS Compatibility Constraint**: Client TLS configuration in sing-box uses the `utls` object (`tls.utls: {"enabled": true, "fingerprint": "chrome"}`). Because uTLS support was introduced in sing-box v1.10.0, earlier versions cannot run this configuration schema.
- **Strict JSON Unmarshaling & Schema Differences**:
  sing-box enables `DisallowUnknownFields` in its configuration decoder:
  - **TLS Insecure Flag**: Must be `"insecure": bool`. Passing the Xray field name `"allowInsecure"` causes a fatal error: `FATAL decode config: outbounds[0].tls.allowInsecure: json: unknown field "allowInsecure"`.
  - **Transport Block**: Encapsulates WebSocket settings under `outbounds[0].transport: {"type": "ws", "path": ..., "headers": ...}`.
  - **Supported Ciphers**: sing-box accepts `"auto"`, `"aes-128-gcm"`, `"chacha20-poly1305"`, `"none"`, and `"zero"`.
  - **Zero REALITY Fields**: The configuration strictly omits any REALITY-related fields (`reality`, `public_key`, `short_id`, `spider_x`).

### Configuration Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `uuid` | string (UUID) | **Yes** | — | RFC 4122 client UUID |
| `server_name` | string | **Yes** | — | SNI / ServerName target hostname for TLS handshake |
| `path` | string | No | `"/"` | WebSocket HTTP path (e.g. `"/ws"`, auto-prepends `"/"`) |
| `host_header` | string | No | `None` | Optional HTTP Host header for WebSocket upgrade request |
| `alter_id` | integer | No | `0` | VMess alterId integer (0–65535, modern standard is 0) |
| `security` | string | No | `"auto"` | VMess encryption (`auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero`) |
| `fingerprint` | string | No | `"chrome"` | TLS ClientHello fingerprint (`chrome`, `safari`, `firefox`, `ios`, `android`, `edge`) |
| `timeout_s` | float | No | `10.0` | Overall execution deadline in seconds |
| `startup_timeout_s` | float | No | `3.0` | Local proxy readiness polling timeout |
| `local_port` | integer | No | `0` (dynamic) | Local SOCKS5 proxy port (0 allocates dynamic free port) |
| `verify_cert` | boolean | No | `True` | Validate TLS certificate on HTTPS test destinations and sing-box TLS (`insecure: false`) |
| `ssl_context` | SSLContext | No | `None` | Custom SSLContext for HTTPS test destination validation |

### Cross-Engine Comparison: VMess over WebSocket + TLS

| Feature / Dimension | sing-box (`SingBoxVmessWebSocketTlsAdapter`) | Xray-core (`XrayVmessWebSocketTlsAdapter`) |
|---|---|---|
| **Adapter ID** | `singbox_vmess_ws_tls` | `xray_vmess_ws_tls` |
| **Engine Identifier** | `EngineType.SING_BOX` (`"sing-box"`) | `EngineType.XRAY` (`"xray"`) |
| **Executable Name** | `sing-box` | `xray` |
| **Outbound Structure** | Flat: `{"type": "vmess", "server": ..., "server_port": ..., "uuid": ...}` | Nested: `{"protocol": "vmess", "settings": {"vnext": [{"address": ..., "port": ..., "users": [{"id": ...}]}]}}` |
| **Transport Configuration** | `outbounds[0].transport: {"type": "ws", "path": ..., "headers": {"Host": ...}}` | `outbounds[0].streamSettings: {"network": "ws", "wsSettings": {"path": ..., "headers": {"Host": ...}}}` |
| **TLS Block** | `outbounds[0].tls: {"enabled": true, "server_name": ..., "insecure": bool}` | `outbounds[0].streamSettings.tlsSettings: {"serverName": ..., "allowInsecure": bool}` |
| **TLS Insecure Flag** | Strictly `"insecure"` (`unknown field` fatal error if `allowInsecure`) | `"allowInsecure"` |
| **uTLS Fingerprint** | `outbounds[0].tls.utls: {"enabled": true, "fingerprint": "chrome"}` | `streamSettings.tlsSettings.fingerprint: "chrome"` |
| **Supported Ciphers** | `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero` | `auto`, `aes-128-gcm`, `chacha20-poly1305` |
| **Log Section** | `{"log": {"level": "warn"}}` | `{"log": {"loglevel": "warning"}}` |
| **Inbound Structure** | `[{"type": "socks", "tag": "socks-in", "listen": ..., "listen_port": ...}, {"type": "http", ...}]` | `[{"protocol": "socks", "port": ..., "listen": ...}, {"protocol": "http", ...}]` |
| **Syntax Test Command** | `sing-box check -c <config_path>` | `xray run -test -c <config_path>` |
| **Process Run Command** | `sing-box run -c <config_path> --disable-color` | `xray run -c <config_path>` |

### Safe Local Integration Testing Tiers for sing-box VMess

| Verification Tier | Tested Component | Prerequisites | Evidence Level |
|---|---|---|---|
| **Tier 1: Binary Detection & Version** | `sing-box version` | Allowlisted `sing-box` binary + `CONNSCOPE_TEST_REAL_SINGBOX=1` | Verified against host binary (`sing-box 1.12.12`) |
| **Tier 2: Real Binary Config Validation** | `sing-box check -c <config>` | Allowlisted `sing-box` binary + `CONNSCOPE_TEST_REAL_SINGBOX=1` | Verified against host binary (`sing-box 1.12.12`) |
| **Tier 3: Process Lifecycle & Cleanup** | Process spawn, local SOCKS5 bind, readiness polling, graceful teardown | Allowlisted `sing-box` binary + `CONNSCOPE_TEST_REAL_SINGBOX=1` (tested on loopback `127.0.0.1`) | Verified against host binary (`sing-box 1.12.12`) |
| **Tier 4: Live Tunnel & Data Transfer** | Remote VMess+WS+TLS handshake, SOCKS5 `CONNECT`, and HTTP/HTTPS transfer | Allowlisted `sing-box` binary + `CONNSCOPE_TEST_REAL_SINGBOX=1` + explicit VMess test server configuration | Unverified without explicit test server; skips cleanly |

#### Running sing-box VMess Local Tests
```bash
CONNSCOPE_TEST_REAL_SINGBOX=1 .venv/bin/python -m pytest -rs tests/adapters/test_singbox_real_integration.py -k vmess
```

---

## 12. Declarative Protocol Catalog & Scenario Matrix Architecture (Phase 15)

Phase 15 transitions ConnScope from creating isolated adapter classes for individual protocol configurations into a **declarative, compatibility-aware measurement matrix framework**.

### 12.1 Separation of Dimensions

1. **Engine / Runtime (`EngineDefinition`)**:
   - Represents the execution runtime or external toolchain (e.g. `Xray-core`, `sing-box`, `WireGuard Tools`, `AmneziaWG`, `OpenVPN`, `Aether`).
   - Documents executable requirements, supported runtime operations, version constraints, tested versions, and verification evidence tiers.
   - Includes explicit upstream source tracking (`SourceReference`).
2. **Protocol Profile (`ProtocolProfile`)**:
   - Represents a concrete protocol stack configuration (e.g. `vless_tcp_reality`, `vmess_ws_tls`, `wireguard_standard`, `amnezia_wg_obfs`, `openvpn_udp`, `aether_tun`).
   - Declares the orthogonal protocol, transport, and security layers.
   - Defines parameter schemas as data rather than hardcoded class logic.
3. **Parameter Schema & Variant Profile (`ParameterDefinition`, `ParameterVariant`)**:
   - Defines configurable options with data types (`STRING`, `INT`, `FLOAT`, `BOOL`, `ENUM`, `HEX`, `UUID`), constraints, bounds, and defaults.
   - Restricts parameter applicability to engines that genuinely support them (`applicable_engines`).
   - Tracks sensitive parameters (`is_secret=True`), guaranteeing automatic redaction across previews, summaries, and JSON outputs.
   - Variants allow overriding selected parameters without duplicating adapter lifecycles.
4. **Network Vantage Points & Measurement Profiles (`MeasurementNode`, `MeasurementWorkload`)**:
   - Vantage points (`MeasurementNode`) record real execution environments and route contexts (`interface`, `asn`, `gateway`, `city`, `country`), preventing unverified labels from being treated as network proof.
   - Workloads (`MeasurementWorkload`) define post-tunnel verification tasks, request URLs, deadlines, repetition counts, and certificate policies.
5. **Deterministic Scenario Matrix (`Scenario`, `MatrixPlan`)**:
   - Combines engine, profile, variant, node, target, and workload into a reproducible scenario.
   - Produces stable scenario IDs derived from normalized configuration hashes.
   - Deduplicates identical configurations and validates compatibility before execution.

---

### 12.2 Declarative Protocol Profiles

1. **Standard WireGuard (`wireguard_standard`)**:
   - Native UDP L3 network-interface tunnel configuration.
   - Parameters: `private_key` (secret), `public_key`, `preshared_key` (secret), `endpoint`, `allowed_ips`, `address` (default `10.0.0.2/32`), `listen_port`, `mtu` (1280–1500, default 1420), `persistent_keepalive` (0–3600, default 25).
   - Variants: `baseline` (MTU 1420, keepalive 25s), `low_mtu` (MTU 1280), `keepalive_disabled` (keepalive 0s).
   - Execution Mode: `network_interface` ([`TunnelExecutionMode.NETWORK_INTERFACE`](../src/connscope/adapters/models.py)).
   - Adapter ID: `wireguard_standard` ([`WireGuardStandardAdapter`](../src/connscope/adapters/wireguard.py)).
   - Evidence Status: `CONFIG_VALIDATION_IMPLEMENTED` and `MOCKED_LIFECYCLE_TESTED`.
2. **AmneziaWG (`amnezia_wg_obfs`)**:
   - Dedicated obfuscated WireGuard fork (not merely a generic `noise=true` flag).
   - Protocol Parameters:
     - `jc`: Junk packet count (1–128, default 4).
     - `jmin`, `jmax`: Junk packet byte size bounds (0–1280, default 40–70).
     - `s1`, `s2`: Init and response packet junk padding bytes (0–1280, default 56 / 56).
     - `h1`, `h2`, `h3`, `h4`: Custom 4-byte packet header identifiers (1–4294967295, default 1, 2, 3, 4).
   - Variants: `baseline`, `mild_junk`, `heavy_junk`, `custom_headers`.
   - Execution Mode: `network_interface` ([`TunnelExecutionMode.NETWORK_INTERFACE`](../src/connscope/adapters/models.py)).
   - Adapter ID: `amnezia_wg_standard` ([`AmneziaWGStandardAdapter`](../src/connscope/adapters/amnezia_wg.py)).
   - Evidence Status: `CONFIG_VALIDATION_IMPLEMENTED` and `MOCKED_LIFECYCLE_TESTED`.
3. **OpenVPN (`openvpn_udp`, `openvpn_tcp`)**:
   - TLS-authenticated OpenVPN client operating over a virtual TUN device.
   - Parameters: `proto` (udp/tcp), `remote_host`, `remote_port`, `tun_mtu` (1280–1500), `ca_cert` (trusted CA in PEM), `client_cert`, `client_key`, `tls_auth_key`, `tls_crypt_key`, `cipher` (AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305), `remote_cert_tls` (enforced server cert check), `route_nopull` (enforced route non-interference).
   - Variants: `baseline` / `udp_baseline`, `tcp_baseline`, `low_mtu` (1280 bytes).
   - Execution Mode: `network_interface` ([`TunnelExecutionMode.NETWORK_INTERFACE`](../src/connscope/adapters/models.py)).
   - Adapter ID: `openvpn_standard` ([`OpenVPNStandardAdapter`](../src/connscope/adapters/openvpn.py)).
   - Evidence Status: `CONFIG_VALIDATION_IMPLEMENTED` and `MOCKED_LIFECYCLE_TESTED`.
4. **Aether Tunnel (`aether_tun`)**:
   - Runtime placeholder for experimental censorship-resistance implementation.
   - Source Reference: `requires_source_confirmation = True`.
   - Explicit Policy: Because multiple ambiguous implementations exist in anti-censorship ecosystems, the catalog records a requirement for upstream source confirmation (repository URL and pinned commit) before schema stabilization or adapter implementation.
   - Evidence Status: `CATALOGUED`.

---

### 12.3 Scenario Matrix Generation Strategies

| Strategy | Mode Key | Description & Behavior | Safety & Bounds |
|---|---|---|---|
| **Explicit Selection** | `explicit` | Evaluates selected engines, profiles, and variants | Bounded by Cartesian product of explicit inputs |
| **One-Factor-At-A-Time** | `ofat` | Generates variations altering exactly one factor (variant, engine, parameter) from a baseline control | $1 + \sum (N_i - 1)$ scenarios; ideal for sensitivity analysis |
| **Pairwise Coverage** | `pairwise` | Deterministic greedy 2-way combinatorial coverage of all factor option pairs | Significantly smaller than Cartesian product; explicitly tagged as 2-way coverage (NOT exhaustive) |
| **Exhaustive Cartesian** | `exhaustive` | Full Cartesian product across all parameter and variant dimensions | Enforces `max_scenarios` (default 100); requires `--allow-exhaustive` confirmation if threshold exceeded |

---

### 12.4 Backward Compatibility & Migration Path

The scenario architecture maintains 100% backward compatibility with ConnScope's four functional adapters:
- `xray_vless_tcp_reality` (`XrayVlessTcpRealityAdapter`)
- `singbox_vless_tcp_reality` (`SingBoxVlessTcpRealityAdapter`)
- `xray_vmess_ws_tls` (`XrayVmessWebSocketTlsAdapter`)
- `singbox_vmess_ws_tls` (`SingBoxVmessWebSocketTlsAdapter`)

Through [`AdapterMigrationBridge`](../src/connscope/scenarios/migration.py), any `Scenario` referencing an implemented adapter can:
- Map directly to the registered `EngineAdapter`.
- Convert scenario parameters into adapter-compatible configuration dictionaries.
- Validate parameters under the adapter's existing validation logic.
- Execute dry-run inspections verifying executable presence and syntax without starting external processes or transmitting live traffic.
- Preserve Remote Agent isolation (external process adapters remain strictly blocked on remote agents).

---

### 12.5 CLI Operations

1. **Catalog Validation & Inspection**:
```bash
# Validate catalog consistency
connscope catalog validate

# List all catalogued engines, profiles, and compatibility rules
connscope catalog list

# Inspect engine or profile details
connscope catalog show xray
connscope catalog show vless_tcp_reality
```

2. **Scenario Matrix Estimation & Dry-Run Preview**:
```bash
# Estimate scenario count
connscope matrix estimate --engine xray --profile vless_tcp_reality --mode explicit

# Preview scenario matrix (human-readable table with secret redaction)
connscope matrix preview --engine xray --profile vless_tcp_reality --target "example.com:443"

# Preview scenario matrix as JSON
connscope matrix preview --engine sing_box --profile vmess_ws_tls --mode ofat --json

# Run pairwise 2-way combinatorial preview
connscope matrix preview --profile vmess_ws_tls --mode pairwise
```

3. **Scenario Matrix Execution & Measurement**:
```bash
# Dry-run planning (default: zero processes spawned, validates schemas & executable availability)
connscope matrix run --engine xray --profile vless_tcp_reality --target "example.com:443"

# Opt-in live execution with 3 repetitions and bounded concurrency
connscope matrix run --engine xray --profile vless_tcp_reality \
  --target "example.com:443" \
  --config '{"uuid":"...","public_key":"...","server_name":"example.com"}' \
  --repetitions 3 \
  --concurrency 1 \
  --execute \
  --jsonl measurements.jsonl \
  --summary-file summary.json

# Stop on first scenario error
connscope matrix run --engine xray,sing_box --profile vless_tcp_reality \
  --target "example.com:443" \
  --config config.json \
  --failure-policy stop \
  --execute
```

---

## 13. Scenario Execution Coordinator and Measurement Results

### 13.1 Architecture Overview

The Scenario Execution Coordinator ([`ScenarioCoordinator`](../src/connscope/scenarios/coordinator.py)) connects the declarative scenario matrix framework with ConnScope's concrete engine adapters to provide safe, reproducible, and verifiable network measurements.

```
+-------------------------------------------------------------------------------+
|                             MatrixPlan                                        |
|  (Scenarios with Engine, Profile, Variant, MeasurementNode, Target, Workload) |
+-------------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------------+
|                       ScenarioCoordinator                                     |
|                                                                               |
|  1. Pre-Execution Validation:                                                 |
|     - Check Scenario validity and schema parameters                           |
|     - Resolve adapter via AdapterMigrationBridge                              |
|     - Verify engine binary in allowlisted path                                |
|     - Safely exclude unexecutable/catalog-only profiles                       |
|                                                                               |
|  2. Execution Control:                                                        |
|     - Dry-Run Planning by default (execute=False: 0 processes spawned)        |
|     - Opt-In Execution flag (execute=True required for process spawning)      |
|     - Repetition Loop (each repetition recorded independently with index)     |
|     - Concurrency Limiter (asyncio.Semaphore)                                 |
|     - Failure Policy: CONTINUE (default) or STOP_ON_ERROR                     |
|     - Zero Automatic Retries (prevents latency distribution distortion)       |
+-------------------------------------------------------------------------------+
                                    |
          +-------------------------+-------------------------+
          |                                                   |
          v                                                   v
+-----------------------------------+   +---------------------------------------+
|   MeasurementRecord (JSONL)       |   |      MatrixExecutionSummary           |
|                                   |   |                                       |
| - Schema version 1.0              |   | - Planned, Executed, Succeeded,       |
| - scenario_id, repetition_index   |   |   Failed, Excluded scenario counts    |
| - engine_id, profile_id, variant  |   | - Robust statistics (medians, min,    |
| - adapter_id, executable_version  |   |   max handshake & transfer ms)        |
| - target, workload, timing        |   | - Failure stage distribution          |
| - tunnel_established vs.          |   | - Workload comparability verification |
|   data_transfer_completed        |   |   (flags differing targets/workloads) |
| - secret redaction on all fields  |   | - Per-scenario aggregated metrics     |
+-----------------------------------+   +---------------------------------------+
```

### 13.2 Versioned Result Schema (`MeasurementRecord` v1.0)

Each scenario repetition emits an independent, immutable [`MeasurementRecord`](../src/connscope/scenarios/records.py) adhering to schema version 1.0.

#### Key Fields and Guarantees:

| Field | Type | Description |
|---|---|---|
| `schema_version` | `str` | `"1.0"` — enables version-tolerant analysis |
| `scenario_id` | `str` | Unique scenario ID from the execution plan |
| `repetition_index` | `int` | Zero-based index ($0, 1, \dots, N-1$) of the repetition |
| `engine_id` | `str` | Engine identifier (`xray`, `sing_box`, etc.) |
| `profile_id` | `str` | Protocol profile (`vless_tcp_reality`, `vmess_ws_tls`, etc.) |
| `variant_id` | `str` | Parameter variant name |
| `adapter_id` | `str \| None` | Resolved concrete adapter identifier |
| `executable_version` | `str \| None` | Engine version string if recorded |
| `node_id` | `str` | Measurement origin node (e.g., `local`) |
| `route_context` | `dict` | Network routing and interface metadata |
| `target` | `dict` | Remote target (`host`, `port`) |
| `workload` | `dict` | Workload definition (`workload_type`, `test_url`, `timeout_s`) |
| `started_at` / `ended_at` | `str` | ISO 8601 UTC timestamps |
| `duration_ms` | `float` | Total duration of the probe in milliseconds |
| `metrics` | `dict` | Fine-grained timings (`handshake_ms`, `data_transfer_ms`) |
| `status` | `str` | `"success"`, `"failed"`, or `"dry_run"` |
| `failure_stage` | `str \| None` | Stage where failure occurred (`process_start`, `socks5_connect`, etc.) |
| `tunnel_established` | `bool` | True only if SOCKS5/proxy tunnel established successfully |
| `data_transfer_completed` | `bool` | True only if payload/HTTP 204 transfer completed through proxy |
| `verified_data_transfer` | `bool` | True if verified real-engine end-to-end data transfer succeeded |
| `error` | `str \| None` | Error message (sanitized, secrets redacted) |
| `evidence_status` | `str` | Catalog evidence tier supported by this execution |
| `resolved_config` | `dict` | Configuration parameters used (all sensitive values redacted) |

#### Strict Outcome Separation:
ConnScope strictly separates `tunnel_established` from `data_transfer_completed`. A successful proxy handshake is recorded as `tunnel_established: true`, but `data_transfer_completed` remains `false` unless the HTTP/204 probe succeeds through the established tunnel.

#### Streaming Serialization:
Records are written in standard JSON Lines (`.jsonl`) format via `write_jsonl()` and `read_jsonl()`, ensuring that large multi-repetition benchmark runs can be streamed to disk without accumulating memory pressure.

### 13.3 Aggregation and Workload Comparability

Raw measurement observations are aggregated by [`aggregate_execution_records()`](../src/connscope/scenarios/aggregation.py) into [`MatrixExecutionSummary`](../src/connscope/scenarios/aggregation.py):

1. **Robust Non-Parametric Statistics**:
   - Computes medians, min, and max for total duration, handshake latency, and data transfer time.
   - Outliers and anomalous dropped connections do not skew the representative latency measure.
2. **Failure Analysis**:
   - Tracks success rates and counts.
   - Computes failure stage distributions (identifying whether failures stem from process startup, DNS resolution, handshake, or data transfer).
3. **Workload Comparability Check**:
   - Cross-scenario comparisons (e.g. comparing Xray vs sing-box performance) are only meaningful when both engines target the same server and execute equivalent workloads.
   - The coordinator verifies target consistency (`host:port`) and workload comparability (`workload_type` and `test_url`).
   - If scenarios differ in target or workload, `is_comparable` is set to `False` and explanatory warnings are attached to the summary.

### 13.4 Safety and Execution Controls

- **Dry-Run Planning by Default**:
  Running `connscope matrix run` without `--execute` performs complete plan generation, adapter resolution, configuration validation, and executable verification without spawning a single child process or opening network sockets.
- **Explicit Execution Opt-In (`--execute`)**:
  Process execution requires explicit `--execute`. This prevents accidental execution during automated scripting or inspection.
- **Safe Catalog-Only Profile Handling**:
  Profiles without adapters (e.g. OpenVPN, Aether) are gracefully identified during pre-execution checks and categorized as excluded with explicit machine-readable reasons (e.g. `"No executable adapter for profile 'openvpn_udp'"`). They never trigger runtime exceptions or crash the coordinator.
- **Bounded Concurrency**:
  An asynchronous semaphore bounds concurrent adapter processes. Default is sequential execution (`concurrency=1`) to eliminate inter-process CPU or socket contention during measurements.
- **No Automatic Retries**:
  Automatic retries silently distort latency distributions and survivorship metrics. If a measurement fails, the failure is recorded. The configured repetition count determines the exact number of observations.
- **Remote Agent Isolation**:
  Adapters spawning external processes remain restricted to local nodes. The Remote Agent strictly rejects scenario adapter execution requests over the wire.

---

## 14. Native WireGuard and Layer-3 Tunnel Backend

### 14.1 Explicit Execution-Mode Contract

ConnScope explicitly distinguishes two fundamental adapter execution modes via [`TunnelExecutionMode`](../src/connscope/adapters/models.py):

| Execution Mode | Enum Value | Architecture & Behavior | Existing & New Adapters |
|---|---|---|---|
| **Local Proxy Tunnel** | `local_proxy` | Spawns a child process exposing a local SOCKS5 or HTTP forwarder port; client connects via SOCKS5 handshake | Xray VLESS REALITY, sing-box VLESS REALITY, Xray VMess WS TLS, sing-box VMess WS TLS |
| **Network-Interface Tunnel** | `network_interface` | Creates/configures a Layer-3 virtual network interface (e.g. `wg0`) inside an isolated network namespace and routes test traffic through the interface | Native WireGuard (`wireguard_standard`) |

### 14.2 The Common Layer-3 Lifecycle Contract

The Layer-3 tunnel contract is formalized in [`Layer3TunnelAdapter`](../src/connscope/adapters/layer3.py), defining an 8-stage lifecycle:

```
+-----------------------------------------------------------------------------------+
|                            Layer-3 Lifecycle Contract                             |
+-----------------------------------------------------------------------------------+
  1. Validate Configuration        -> Enforce 32-byte Base64 keys, MTU, CIDRs
  2. Check Executables & Caps      -> Resolve 'wg'/'ip', check CAP_NET_ADMIN/opt-in
  3. Prepare Isolated Resources    -> Allocate isolated netns (cs-wg-<hex>)
  4. Establish Tunnel Interface    -> Create wireguard link, apply wg setconf (mode 0600)
  5. Verify Tunnel State           -> Query 'wg show' latest-handshakes timestamp
  6. Execute Workload              -> Monitor RX/TX counter deltas & HTTP 204 response
  7. Teardown Resources            -> Delete interface & netns (guaranteed in finally)
  8. Return Structured Result      -> Emit ProbeResult with granular L3 details & metrics
+-----------------------------------------------------------------------------------+
```

### 14.3 Native WireGuard Adapter Implementation

The Native WireGuard backend is implemented in [`WireGuardStandardAdapter`](../src/connscope/adapters/wireguard.py):

- **Adapter Identifier**: `wireguard_standard`
- **Supported Capabilities**: `UDP_CONNECT`, `HANDSHAKE`, `TUNNEL_VERIFY`, `DATA_TRANSFER`, `LATENCY`
- **Declarative Parameter Variants**:
  - `baseline`: MTU 1420 bytes, 25-second persistent keepalive.
  - `low_mtu`: MTU 1280 bytes (IPv6 minimum to prevent fragmentation), 25-second keepalive.
  - `keepalive_disabled`: MTU 1420 bytes, persistent keepalive disabled (0s).
- **Strict Configuration Schema**:
  - Enforces Curve25519 32-byte Base64 keys for `private_key`, `public_key`, and optional `preshared_key`.
  - Enforces MTU bounds: $[1280, 1500]$.
  - Enforces persistent keepalive bounds: $[0, 3600]$.
  - Enforces valid CIDR networks for `allowed_ips` and `address`.
  - Enforces `0o600` (read/write by owner only) file permissions on temporary configuration files.
  - Strictly rejects unknown or obfuscation-specific parameters (e.g. AmneziaWG junk parameters `jc`, `jmin`, `jmax`, `s1`).

### 14.4 Strict Isolation and Host Safety Guarantees

Host safety and operational non-interference are enforced by design:

1. **No Host Routing Alterations**:
   The adapter **never** executes `wg-quick up` in the host's default namespace. Default routes, host interfaces (`eth0`, `wlan0`), and existing system VPN connections are never modified.
2. **Network Namespace Isolation (`LinuxNetnsIsolationBackend`)**:
   Interface creation, address assignment, routing, and workload execution occur exclusively inside an ephemeral, dedicated Linux network namespace (`cs-wg-<uuid>`).
3. **Explicit Opt-In Required**:
   Real interface creation is disabled by default. It requires explicit opt-in via environment variable:
   `CONNSCOPE_ENABLE_REAL_WIREGUARD=1` (or `CONNSCOPE_TEST_REAL_WIREGUARD=1`).
4. **Fail-Closed Capability Verification**:
   If unprivileged (`geteuid() != 0`), or running on non-Linux platforms, or without allowlisted `wg` and `ip` binaries, the adapter fails closed with `FailureStage.PRE_FLIGHT` and descriptive feedback.
5. **Deterministic Mock Backend (`MockLayer3IsolationBackend`)**:
   Provides zero-privilege, deterministic verification of all lifecycle stages and failure paths without requiring root or kernel capabilities.

### 14.5 Layer-3 Measurement Semantics & Outcome Distinction

WireGuard is connectionless UDP: bringing an interface up does not prove that a remote peer exists or responded. ConnScope decomposes measurement outcomes into distinct verifiable states:

| Outcome State | Recorded Field | Verification Criterion |
|---|---|---|
| **Configuration Validity** | `is_valid: true` | Valid keys, MTU, CIDRs, and endpoint format |
| **Interface Readiness** | `interface_established: true` | Network interface successfully created and brought UP |
| **Peer Handshake** | `peer_handshake_completed: true` | `wg show <iface> latest-handshakes` returns a non-zero recent timestamp ($> 0$ and $\le 180$s) |
| **Traffic Traversal** | `traffic_traversed: true` | Interface RX and TX byte counters both increase during the workload ($\Delta \text{TX} > 0 \land \Delta \text{RX} > 0$) |
| **Application Data Transfer** | `data_transfer_completed: true` | HTTP 204 probe completes through the tunnel |

#### Missing Handshake Policy:
If no handshake timestamp is received within the timeout:
- `failure_stage` is recorded as `FailureStage.HANDSHAKE`.
- `tunnel_established` is set to `False`.
- `peer_handshake_completed` is set to `False`.
- `interface_established` remains `True` (recording that interface readiness succeeded).
- **Non-Guessing Principle**: A missing handshake is **not** interpreted as censorship. It is recorded objectively as an unacknowledged handshake.

### 14.6 Verification Evidence Breakdown and Runtime Correctness Audit

ConnScope Phase 17.1 audited the runtime correctness of WireGuard configuration semantics, interface addressing, MTU, route setup, and namespace egress reachability:

| Evidence Dimension | Status | Evidence & Runtime Audit Findings |
|---|---|---|
| **Configuration Validation** | **VERIFIED** | Enforces 32-byte Base64 keys, MTU bounds [1280, 1500], keepalive bounds [0, 3600], and CIDR formats. Strictly rejects AmneziaWG parameters (`jc`, `jmin`, etc.) and `wg-quick` hooks (`PreUp`, `PostUp`, `Table`). |
| **Configuration File Separation** | **VERIFIED** | Formally separates `generate_wireguard_wg_setconf_config` (containing ONLY keys supported by `wg setconf`) from `generate_wireguard_client_config` (wg-quick format). Verified that `Address`, `MTU`, and `DNS` are NEVER passed to `wg setconf`. |
| **Explicit Interface Operations** | **VERIFIED** | MTU is explicitly applied via `ip link set dev <iface> mtu <mtu>`. IP address is explicitly assigned via `ip addr add <addr> dev <iface>`. Interface is brought UP explicitly via `ip link set dev <iface> up`. |
| **Operating System Route Setup** | **VERIFIED** | Recognized that WireGuard's `AllowedIPs` configures device cryptographic routing only, NOT kernel routing tables. Operating system routes for `allowed_ips` are explicitly installed inside the namespace via `ip route add <cidr> dev <iface>`. |
| **Mocked Lifecycle Testing** | **VERIFIED** | Automated tests pass across all lifecycle stages: interface creation, handshake, traffic traversal, application transfer, partial setup failures, and cancellation recovery. |
| **Isolated Netns Interface Management** | **VERIFIED** | `LinuxNetnsIsolationBackend` implements safe network namespace isolation requiring explicit opt-in (`CONNSCOPE_ENABLE_REAL_WIREGUARD=1`). Cleanup removes only ephemeral resources (`cs-wg-<uuid>`). |
| **Origin-Namespace Socket Placement** | **VERIFIED** | `LinuxOriginNetnsIsolationBackend` implements the official WireGuard netns technique (device created in origin namespace, moved into test namespace). Outer UDP socket is anchored in the origin namespace without modifying host routes or firewalls. |
| **Host Non-Interference Verification** | **VERIFIED** | `HostNetworkSnapshot` strictly asserts zero leaked interfaces, unchanged host routing tables, and unmodified `net.ipv4.ip_forward` sysctl before and after execution. |
| **Outer UDP Endpoint Reachability** | **MITIGATED / VERIFIED via Origin Netns** | Origin-namespace socket placement allows outer UDP packets to use existing host physical routes without routing recursion or host NAT injection. Pure isolated netns without origin socket placement remains unrouted. |
| **Live Remote Tunnel Verification & Data Transfer** | **UNVERIFIED** | Kept explicitly UNCLAIMED. Real-world end-to-end data transfer requires a controlled remote WireGuard server endpoint and a verified, safe uplink mechanism. |

### 14.7 WireGuard Origin-Namespace Socket Placement (Phase 17.2)

ConnScope Phase 17.2 implements the official WireGuard network-namespace socket placement technique ([wireguard.com/netns](https://www.wireguard.com/netns/)), enabling the isolated test namespace to reach remote WireGuard endpoints without modifying host routes, firewall rules, NAT, forwarding settings, or physical interfaces.

#### Architecture and Socket Anchoring

```
┌─────────────────────────────────────────────────────────────────┐
│ ORIGIN (HOST) NAMESPACE                                         │
│                                                                 │
│   1. ip link add dev wg0 type wireguard                         │
│      (UDP socket binds to host network stack)                   │
│                                                                 │
│   2. ip link set wg0 netns <test_netns>                         │
│      (Device moves to test netns, socket stays in host ns)      │
│                                                                 │
│   Outer UDP Endpoint Traffic:                                   │
│   Encrypted UDP packets -> Host physical route -> Physical NIC  │
│   [No host route edits, no NAT / iptables, no ip_forward = 1]   │
└──────────────────────────────┬──────────────────────────────────┘
                               │ Interface moved
┌──────────────────────────────▼──────────────────────────────────┐
│ ISOLATED TEST NAMESPACE (<test_netns>)                          │
│                                                                 │
│   3. wg setconf wg0 <restricted_config>                         │
│   4. ip addr add <client_ip> dev wg0                            │
│   5. ip link set dev wg0 mtu <mtu> up                           │
│   6. ip route add default dev wg0                               │
│                                                                 │
│   Inner Payload Traffic:                                        │
│   curl / test workload -> default route -> wg0 device           │
│   [Zero routing recursion; completely isolated test traffic]    │
└─────────────────────────────────────────────────────────────────┘
```

#### Key Invariants and Guarantees

1. **Origin Socket Placement**:
   The WireGuard network interface is instantiated in the origin namespace before being moved into the test network namespace via [`LinuxOriginNetnsIsolationBackend`](../src/connscope/adapters/layer3.py#L728-L885). In the Linux kernel, WireGuard's UDP socket remains bound to the origin namespace's socket layer, while the network interface operates inside the isolated test namespace.
2. **Zero Host Network Mutation**:
   Outer UDP packets are routed by the kernel through the origin namespace's existing physical interface and default gateway. ConnScope never modifies host default routes, never installs host firewall or iptables MASQUERADE rules, and never alters `/proc/sys/net/ipv4/ip_forward`.
3. **Strict Host Verification via `HostNetworkSnapshot`**:
   Before and after any Layer-3 execution, [`HostNetworkSnapshot`](../src/connscope/adapters/layer3.py#L64-L136) captures:
   - Host network interface list (`/sys/class/net`)
   - Host WireGuard devices specifically
   - Host kernel routing table (`ip route show`)
   - Host IPv4 forwarding sysctl (`/proc/sys/net/ipv4/ip_forward`)
   Any divergence between snapshots raises an `AssertionError` identifying leaked interfaces or route modifications.
4. **Guaranteed Teardown across Partial Failures**:
   - If interface creation in the origin namespace succeeds but movement to the namespace fails, teardown explicitly deletes the interface from the origin namespace to prevent host interface leakage.
   - If the interface has been moved, teardown deletes the interface inside the namespace and deletes the ephemeral namespace.
   - Teardown is shielded (`asyncio.shield`) so cleanup completes even if the measurement task is cancelled.
5. **Opt-in Guard**:
   Activation of origin-namespace socket placement requires explicit opt-in via `CONNSCOPE_WIREGUARD_ORIGIN_NETNS=1` combined with `CONNSCOPE_ENABLE_REAL_WIREGUARD=1` (or `CONNSCOPE_TEST_REAL_WIREGUARD=1`). Without these flags, adapters fail closed or retain standard isolated netns semantics.
6. **Scenario and Measurement Record Grounding**:
   The scenario execution coordinator and [`MeasurementRecord`](../src/connscope/scenarios/records.py#L37-L148) record `isolation_strategy: "origin_netns"`, `socket_in_origin_namespace: True`, and the inspected `origin_endpoint_route` inside `record.route_context`.

---

## 15. AmneziaWG Backend with Versioned Parameter Profiles (Phase 18)

ConnScope Phase 18 implements AmneziaWG support within the Layer-3 tunnel framework, catalog scenario matrix, and execution coordinator. Rather than creating disparate adapter classes for every obfuscation combination, Phase 18 models parameter variations as data-driven declarative profiles executed by a unified adapter ([`AmneziaWGStandardAdapter`](../src/connscope/adapters/amnezia_wg.py)).

### 15.1 Target Implementation & Kernel Module Contract

The AmneziaWG backend targets the official Linux kernel module and user-space tooling:
- **Upstream Kernel Module**: [amnezia-vpn/amneziawg-linux-kernel-module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
- **User-space Tooling**: [amnezia-vpn/amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools) (`awg`)
- **Device Link Type**: `amneziawg` (created via `ip link add dev <iface> type amneziawg`)
- **Control Tool**: `awg setconf <iface> <config_file>`
- **Status & Telemetry**: `awg show <iface> latest-handshakes` and `awg show <iface> transfer`

#### Schema Versioning Distinction (v1.0 vs v2 Preview)
The target implementation corresponds to the **AmneziaWG v1.0 schema**. Newer preview specifications describe additional parameters:
- `I1`–`I5` (custom packet headers for rekeying / data)
- Header Protection / Cookie Obfuscation

These parameters belong to userspace implementations or preview revisions. The ConnScope AmneziaWG backend enforces strict schema gating: any configuration containing `i1`–`i5` or `header_protection` is fail-closed rejected with explicit diagnostics ([`UNSUPPORTED_AMNEZIAWG_V2_KEYS`](../src/connscope/adapters/amnezia_wg.py)).

### 15.2 Decoupled Layer-3 Architecture via Device Drivers

Phase 18 decouples protocol-specific network interface operations from the common network namespace lifecycle via the abstract [`Layer3DeviceDriver`](../src/connscope/adapters/layer3.py#L140-L245) interface:

```
                          ┌───────────────────────────┐
                          │    Layer3TunnelAdapter    │
                          └─────────────┬─────────────┘
                                        │ delegates to
                          ┌─────────────▼─────────────┐
                          │   Layer3IsolationBackend  │
                          │ (Netns, Routes, Workload) │
                          └─────────────┬─────────────┘
                                        │ calls driver
                ┌───────────────────────┴───────────────────────┐
                ▼                                               ▼
  ┌───────────────────────────┐                   ┌───────────────────────────┐
  │   WireGuardDeviceDriver   │                   │   AmneziaWGDeviceDriver   │
  ├───────────────────────────┤                   ├───────────────────────────┤
  │ link type: wireguard      │                   │ link type: amneziawg      │
  │ control: wg               │                   │ control: awg              │
  │ setconf: standard schema  │                   │ setconf: Jc, Jmin, S1, H1 │
  │ show: wg show             │                   │ show: awg show            │
  └───────────────────────────┘                   └───────────────────────────┘
```

Both [`LinuxNetnsIsolationBackend`](../src/connscope/adapters/layer3.py) and [`LinuxOriginNetnsIsolationBackend`](../src/connscope/adapters/layer3.py) consume drivers generically without duplicating:
- Network namespace creation and deletion
- Loopback interface initialization (`ip link set dev lo up`)
- IP address assignment (`ip addr add <ip> dev <iface>`)
- MTU configuration (`ip link set dev <iface> mtu <mtu>`)
- Operating system route installation (`ip route add <cidr> dev <iface>`)
- Workload execution and RX/TX traffic delta measurements
- Origin-to-netns interface migration and socket anchoring
- `HostNetworkSnapshot` verification and cancellation-shielded cleanup

### 15.3 Strict Schema Validation & Cross-Field Constraints

AmneziaWG configuration validation is implemented in [`validate_amneziawg_config`](../src/connscope/adapters/amnezia_wg.py#L48-L155):

| Parameter | Type | Valid Range / Bounds | Validation Rule |
|---|---|---|---|
| `private_key` | Base64 | Exactly 32 bytes (44 chars) | Curve25519 client private key (unconditionally redacted) |
| `public_key` | Base64 | Exactly 32 bytes (44 chars) | Remote peer public key |
| `preshared_key` | Base64 | Exactly 32 bytes (optional) | Post-quantum preshared symmetric key (unconditionally redacted) |
| `endpoint` | Host:Port | Valid hostname/IP + port | Remote peer UDP endpoint |
| `allowed_ips` | CIDR | Valid IPv4/IPv6 CIDR | Device allowed IP list |
| `mtu` | Integer | $1280 \le \text{MTU} \le 1500$ | Layer-3 maximum transmission unit (default 1420) |
| `jc` | Integer | $1 \le J_c \le 128$ | Junk packet count |
| `jmin`, `jmax` | Integer | $0 \le J_{min} < J_{max} \le 1280$ | Junk packet byte size bounds (**strict inequality $J_{min} < J_{max}$ enforced**) |
| `s1`, `s2` | Integer | $0 \le S_1, S_2 \le 1280$ | Init / response packet padding bytes |
| `s1` / `s2` Offset | Constraint | $S_1 + 56 \ne S_2$ | **Enforces $S_1 + 56 \ne S_2$** to prevent identical initiation ($148+S_1$) and response ($92+S_2$) packet lengths |
| `s1` MTU Padding | Constraint | $148 + S_1 \le \text{MTU}$ | Prevents handshake initiation packets exceeding link MTU |
| `s2` MTU Padding | Constraint | $92 + S_2 \le \text{MTU}$ | Prevents handshake response packets exceeding link MTU |
| `h1`, `h2`, `h3`, `h4` | Integer | $1 \le H_i \le 4294967295$ | **Hard validation bound**: 32-bit positive unsigned integer $[1, 4294967295]$ (recommended obfuscation range: $[5, 2147483647]$) |
| Header Distinctness | Constraint | $H_1 \ne H_2 \ne H_3 \ne H_4$ | Enforces mutual uniqueness across all 4 packet header types |

#### Header Constraint Clarification (Hard Bounds vs Recommended Ranges vs v2/v3 Rules)
1. **Hard Validation Bounds**:
   The Linux kernel module allocates a 32-bit integer per packet type marker. ConnScope strictly validates $H_i \in [1, 4294967295]$ and requires that all 4 header markers are distinct ($H_1 \ne H_2 \ne H_3 \ne H_4$). Configurations violating distinctness fail closed during validation.
2. **Recommended Obfuscation Range**:
   Upstream documentation recommends choosing values in the range $[5, 2147483647]$ ($[5, 2^{31}-1]$). This avoids collisions with standard WireGuard packet types ($1, 2, 3, 4$) and prevents negative value interpretation in tools that parse headers as signed integers.
3. **Exclusion of AmneziaWG 2.0 / 3.1 Rules**:
   Later versions of AmneziaWG introduce ranged header markers (`min-max`), dynamic headers, and Header Protection. These features are not recognized by the v1.0 Linux kernel module and are rejected by ConnScope to prevent configuration corruption.

### 15.4 Configuration Format Separation

Like WireGuard, `awg setconf` accepts only link-level interface parameters. ConnScope maintains a strict boundary between formats:

1. **`awg setconf` Format** ([`generate_amneziawg_awg_setconf_config`](../src/connscope/adapters/amnezia_wg.py#L160-L215)):
   - Generated with restricted mode `0o600`.
   - Places `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`, `H2`, `H3`, `H4` under `[Interface]`.
   - **Excludes `Address`, `MTU`, and `DNS`**. Passing these keys causes `awg setconf` to fail immediately.
2. **Client Export Format** ([`generate_amneziawg_client_config`](../src/connscope/adapters/amnezia_wg.py#L220-L280)):
   - Export format compatible with `awg-quick` or client imports.
   - Includes `Address`, `MTU`, `DNS`, `[Interface]` with obfuscation fields, and `[Peer]`.

### 15.5 Declarative Parameter Profiles (Variants)

Rather than maintaining four separate adapter implementations, [`AmneziaWGStandardAdapter`](../src/connscope/adapters/amnezia_wg.py) (`adapter_id="amnezia_wg_standard"`) executes all data-driven variants defined in the catalog:

| Variant ID | Profile Concept | Parameters | Use Case |
|---|---|---|---|
| `baseline` | Standard Obfuscation | MTU 1420, $J_c=4$, $J_{min}=40$, $J_{max}=70$, $S_1=56$, $S_2=56$, $H_1=1$, $H_2=2$, $H_3=3$, $H_4=4$ | Default anti-DPI baseline |
| `mild_junk` | Low Overhead | MTU 1420, $J_c=3$, $J_{min}=10$, $J_{max}=30$, $S_1=20$, $S_2=20$, $H_1=1$, $H_2=2$, $H_3=3$, $H_4=4$ | Reduced handshake latency & low overhead |
| `heavy_junk` | High Obfuscation | MTU 1380, $J_c=10$, $J_{min}=100$, $J_{max}=300$, $S_1=120$, $S_2=120$, $H_1=1001$, $H_2=1002$, $H_3=1003$, $H_4=1004$ | Aggressive DPI fingerprint evasion |
| `custom_headers` | Non-Standard Headers | MTU 1420, $J_c=4$, $J_{min}=40$, $J_{max}=70$, $S_1=56$, $S_2=56$, $H_1=2185794831$, $H_2=3492819402$, $H_3=1049285012$, $H_4=892374912$ | Unique pseudo-random packet signatures |

### 15.6 Origin-Namespace Socket Placement & Safety Verification

AmneziaWG integrates with [`LinuxOriginNetnsIsolationBackend`](../src/connscope/adapters/layer3.py#L728-L885) and [`AmneziaWGDeviceDriver`](../src/connscope/adapters/layer3.py#L310-L375):
1. The `amneziawg` interface is created in the origin namespace (`ip link add dev awg0 type amneziawg`).
2. The outer UDP socket binds to the origin network stack.
3. The interface is moved into the ephemeral test network namespace (`ip link set awg0 netns <test_netns>`).
4. Configuration and test workloads execute strictly within the test network namespace.
5. [`HostNetworkSnapshot`](../src/connscope/adapters/layer3.py#L64-L136) audits `DEVTYPE=amneziawg` and `awg*` interfaces, ensuring zero host interface leaks, zero host route changes, and unmodified `net.ipv4.ip_forward`.
6. Shielded teardown (`asyncio.shield`) deletes origin or namespace interfaces even if the measurement task is cancelled.

### 15.7 Evidence Tiers and Verification Breakdown

| Evidence Dimension | Status | Evidence & Runtime Findings |
|---|---|---|
| **Configuration Validation** | **VERIFIED** | Enforces 32-byte Base64 keys, MTU bounds [1280, 1500], $J_c$ [1, 128], strict inequality $J_{min} < J_{max}$, $S_1 + 56 \ne S_2$, $S_1/S_2$ bounds with MTU padding limits ($148+S_1 \le \text{MTU}$, $92+S_2 \le \text{MTU}$), and $H_1$–$H_4$ uniqueness. Fail-closed rejection of preview v2 parameters (`i1`–`i5`). |
| **Configuration File Separation** | **VERIFIED** | Formally separates `generate_amneziawg_awg_setconf_config` (containing ONLY keys supported by `awg setconf`) from `generate_amneziawg_client_config` (export format). `Address`, `MTU`, and `DNS` are strictly excluded from `awg setconf`. |
| **Layer-3 Device Driver Contract** | **VERIFIED** | Decoupled `Layer3DeviceDriver` abstraction cleanly separates link types (`amneziawg` vs `wireguard`) and tools (`awg` vs `wg`) while sharing all isolation, network namespace, routing, and metric collection infrastructure. |
| **Mocked Lifecycle Testing** | **VERIFIED** | Automated tests pass across all lifecycle stages: interface creation, AmneziaWG setconf parsing, handshake timing, traffic traversal deltas, application transfer, partial setup failures, and cancellation recovery. |
| **Origin-Namespace Socket Placement** | **VERIFIED** | `LinuxOriginNetnsIsolationBackend` supports `AmneziaWGDeviceDriver`. The AmneziaWG UDP socket is anchored in the origin namespace without modifying host routes, firewalls, or NAT. |
| **Host Non-Interference Verification** | **VERIFIED** | `HostNetworkSnapshot` detects `DEVTYPE=amneziawg` and asserts zero leaked interfaces, unchanged host routing tables, and unmodified `net.ipv4.ip_forward` sysctl. |
| **Scenario Matrix & Coordinator Execution** | **VERIFIED** | ScenarioGenerator generates all 4 declarative variants using `adapter_id="amnezia_wg_standard"`. ScenarioCoordinator executes them, aggregating and persisting redacted `MeasurementRecord`s. |
| **Remote Agent Isolation** | **VERIFIED** | Remote Agent strictly rejects `amnezia_wg_standard` over the wire, enforcing local-only execution boundaries. |
| **Real Kernel Module & Binary Execution** | **UNVERIFIED / SKIPPED** | Safely gated behind `CONNSCOPE_ENABLE_REAL_AMNEZIAWG=1`. Real kernel tests skip gracefully on hosts without `amneziawg` kernel module or `awg` binary installed. |
| **Live Remote Tunnel Verification & Data Transfer** | **UNVERIFIED** | Kept explicitly UNCLAIMED. Real-world end-to-end data transfer requires a controlled remote AmneziaWG server endpoint. |

---

## 16. OpenVPN Layer-3 Tunnel Adapter Architecture (Phase 19)

### 16.1 Target Implementation and Specification Reference

ConnScope targets standard OpenVPN client tunnels operating over virtual TUN character devices on Linux:
- **Reference Manual**: OpenVPN Reference Manual (v2.6 / v2.7 community editions).
- **Host Binary**: `/usr/sbin/openvpn` (OpenVPN 2.7_rc3) installed on the measurement host. ConnScope resolved binary discovery by extending default safe executable lookup paths to include `/usr/sbin` and `/sbin`.
- **Target Mode**: Client mode (`client`) establishing point-to-point Layer-3 IP tunnels over UDP or TCP using TLS for authentication and session key exchange.

### 16.2 Shared Layer-3 Architecture and Driver Decoupling

Rather than creating a standalone process adapter with duplicated lifecycle logic, OpenVPN integrates directly into the unified Layer-3 tunnel framework introduced in Phase 17:
- **[`Layer3DeviceDriver`](../src/connscope/adapters/layer3.py#L225)**: Implemented as [`OpenVPNDeviceDriver`](../src/connscope/adapters/layer3.py#L380-L450).
  - `driver_name = "openvpn"`
  - `link_type = "tun"`
  - `tool_binary = "openvpn"`
  - `supports_origin_netns = False` (reflecting userspace socket limitations).
- **Shared Lifecycle & Safety Guarantees**:
  - Pre-execution snapshot captures network interfaces, routes, and sysctl flags.
  - Device driver validates tool availability and operational capabilities.
  - Configuration generated securely in isolated temporary directories with mode `0o600`.
  - Tunnel setup, handshake verification, and workload execution monitored under strict timeouts.
  - Shielded teardown ensures cleanup even upon measurement cancellation.
  - Post-execution snapshot verifies zero leaked TUN/TAP interfaces, zero host route changes, and unmodified sysctls.

### 16.3 Strict Schema Validation and Security Hardening

OpenVPN configuration files support numerous directives, some of which present severe security risks (arbitrary command execution, host network takeover). [`validate_openvpn_config`](../src/connscope/adapters/openvpn.py#L80-L190) enforces a strict whitelist and hard safety constraints:

1. **Whitelisted Parameters**:
   - `remote_host`: Validated IPv4, IPv6, or RFC 1123 hostname.
   - `remote_port`: Integer in $[1, 65535]$.
   - `proto`: Enum `udp` or `tcp`.
   - `tun_mtu`: Integer bounded to $[1280, 1500]$ (default 1500).
   - `cipher`: Whitelist of AEAD ciphers (`AES-256-GCM`, `AES-128-GCM`, `CHACHA20-POLY1305`).
   - `ca_cert`: Mandatory trusted CA certificate in PEM format.
   - `client_cert`, `client_key`: Optional mutual TLS authentication materials.
   - `tls_auth_key`, `tls_crypt_key`: Optional HMAC/TLS encapsulation keys.
   - `remote_cert_tls`: Mandatory `True` (enforces `remote-cert-tls server`).
   - `route_nopull`: Mandatory `True` (enforces route non-interference).
2. **Strict Rejection of Dangerous Directives**:
   - **Script Execution**: `up`, `down`, `route-up`, `route-pre-down`, `ipchange`, `client-connect`, `client-disconnect`, `auth-user-pass-verify`, `tls-verify`.
   - **Plugin & Configuration Inclusion**: `plugin`, `config`.
   - **Script Security**: `script-security` is rejected; scripts are never permitted.
   - **Host Network Takeover**: `redirect-gateway` is rejected to guarantee zero disruption to host routing.
3. **Injection Prevention**:
   - Newlines (`\r`, `\n`) and shell command substitutions (`$()`, `` ` ``) in string values are strictly forbidden.

### 16.4 Hardened Configuration Generation

[`generate_openvpn_client_config`](../src/connscope/adapters/openvpn.py#L195-L260) generates self-contained `.ovpn` configuration text:
- Written with restricted permissions (`0o600`).
- Embeds all cryptographic materials inline (`<ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`), eliminating external path dependencies and preventing path traversal vulnerabilities.
- Enforces essential client options: `client`, `dev tun`, `nobind`, `persist-tun`, `persist-key`, `remote-cert-tls server`, and `route-nopull`.

### 16.5 Userspace Process vs Kernel Netns Migration & Outer-Endpoint Reachability

A critical architectural distinction exists between WireGuard and userspace VPN clients like OpenVPN:
1. **WireGuard (Kernel Link Netns Migration)**:
   WireGuard creates a kernel link in the origin namespace (`ip link add dev wg0 type wireguard`), binding the outer UDP socket to the host network stack. Moving the interface into an isolated test namespace (`ip link set wg0 netns <test_netns>`) preserves the outer socket in the origin namespace. Workloads inside the test namespace transmit through the tunnel without altering host routing or requiring host NAT.
2. **OpenVPN (Userspace Daemon)**:
   OpenVPN runs as a userspace process reading and writing from `/dev/net/tun` while managing its own network sockets. Moving a virtual TUN interface into an isolated namespace does not migrate userspace network sockets.
   If OpenVPN executes inside an isolated network namespace, its userspace TCP/UDP socket cannot reach external WAN endpoints unless the namespace is routed through the host via veth pairs and host NAT/forwarding (`iptables` / `ip_forward`). Because ConnScope strictly prohibits modifying host firewall rules, routes, or sysctls, automated creation of host NAT bridges is not permitted.
3. **Operational Policy**:
   ConnScope safely documents this limitation in [`OpenVPNDeviceDriver.check_capabilities`](../src/connscope/adapters/layer3.py#L425-L445) and gates real tunnel execution behind explicit capability checks. Mocked lifecycles, configuration generation, and declarative scenario execution are verified, while live unrouted network-namespace tunnel execution remains safely disabled and unclaimed.

### 16.6 Declarative Parameter Variants

A single adapter class, [`OpenVPNStandardAdapter`](../src/connscope/adapters/openvpn.py#L265-L330) (`adapter_id="openvpn_standard"`), serves both UDP and TCP profiles across all parameter variants:

| Variant ID | Profile Concept | Protocol | Cipher | MTU | Purpose |
|---|---|---|---|---|---|
| `baseline` / `udp_baseline` | Standard UDP Tunnel | UDP | AES-256-GCM | 1500 | Default low-latency OpenVPN baseline |
| `tcp_baseline` | TCP Transport | TCP | AES-256-GCM | 1500 | Fallback for restrictive UDP-blocking networks |
| `low_mtu` | Constrained Link MTU | UDP | AES-256-GCM | 1280 | Avoids IP packet fragmentation on cellular / nested tunnels |

### 16.7 Evidence Tiers and Verification Breakdown

| Evidence Dimension | Status | Evidence & Runtime Findings |
|---|---|---|
| **Binary Detection & Safe Paths** | **VERIFIED** | Safe executable resolution updated to include `/usr/sbin` and `/sbin`. OpenVPN binary (`/usr/sbin/openvpn` 2.7_rc3) correctly discovered and verified via `--version`. |
| **Configuration Validation** | **VERIFIED** | Enforces trusted CA, valid endpoint, MTU bounds [1280, 1500], whitelisted ciphers, `remote-cert-tls server`, and `route-nopull`. Strictly rejects script hooks, plugins, `redirect-gateway`, and newline injections. |
| **Hardened Configuration Generation** | **VERIFIED** | Generates valid `.ovpn` syntax with mode `0o600` and inline XML blocks (`<ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`). |
| **Layer-3 Device Driver Contract** | **VERIFIED** | `OpenVPNDeviceDriver` cleanly abstracts TUN device interactions and OpenVPN binary requirements under the shared `Layer3DeviceDriver` contract. |
| **Mocked Lifecycle Testing** | **VERIFIED** | 25 automated unit and mock tests pass covering interface creation, config generation, unsafe directive rejection, setup failures, handshake timeouts, traffic deltas, and cancellation cleanup. |
| **Host Non-Interference Verification** | **VERIFIED** | `HostNetworkSnapshot` extended to audit `tun_interfaces` (`/sys/class/net/tun*` / `tap*`), asserting zero leaked TUN devices, unchanged host routes, and unmodified `net.ipv4.ip_forward`. |
| **Scenario Matrix & Coordinator Execution** | **VERIFIED** | Declarative profiles (`openvpn_udp`, `openvpn_tcp`) and variants (`baseline`, `tcp_baseline`, `low_mtu`) generate scenarios executing via `ScenarioCoordinator` and `AdapterMigrationBridge`. |
| **Secret Redaction** | **VERIFIED** | Client keys, authentication passwords, and TLS auth/crypt keys are tracked as secrets and automatically redacted from records and JSON outputs. |
| **Remote Agent Isolation** | **VERIFIED** | Remote Agent strictly rejects `openvpn_standard` execution over the network wire, confining execution to local environments. |
| **Real Binary Execution (Opt-In)** | **VERIFIED** | Gated behind `CONNSCOPE_TEST_REAL_OPENVPN=1`. Real host binary runs `--version` and syntax checks cleanly. |
| **Live Remote Tunnel Verification & Data Transfer** | **UNVERIFIED / DISABLED** | Userspace socket isolation limitations documented. Kept explicitly UNCLAIMED to preserve host non-interference invariants. |

---

## 17. Multi-Node Measurement Orchestration & Agent Capability Policies (Phase 20)

### 17.1 Architecture & Distributed Measurement Vantage Points

Phase 20 extends ConnScope from a single-node execution environment to a multi-node measurement orchestration system. The core architecture enables evaluating the same declarative protocol matrix (profiles, variants, and parameter permutations) across multiple network vantage points without duplicating adapters, scenario generators, or measurement logic.

```
+-----------------------------------------------------------------------------------+
|                           Scenario Coordinator (Coordinator)                     |
|                                                                                   |
|  +---------------------------+    +--------------------------------------------+  |
|  |     Protocol Catalog      |    |        Node Registry (NodeRegistry)        |  |
|  | (Profiles, Variants, Prm) |    |  - local (NodeType.LOCAL)                  |  |
|  +-------------+-------------+    |  - remote-agent-frankfurt (REMOTE_AGENT)   |  |
|                |                  +---------------------+----------------------+  |
|                +----------------------------------------+                         |
|                                     |                                             |
|                        ScenarioGenerator.generate_*                               |
|                                     |                                             |
|                 MatrixPlan: [Scenarios x Vantage Nodes]                           |
+-------------------------------------+---------------------------------------------+
                                      |
         +----------------------------+----------------------------+
         |                                                         |
         v (Local Execution)                                       v (Remote Orchestration)
+---------------------------------+                       +---------------------------------+
|   Local Process / Netns Stack   |                       |    RemoteAgentClient (HTTPS)    |
| - Local proxy (Xray / sing-box) |                       | - Mutual Token Authentication   |
| - Layer-3 netns (WG, AWG, OVPN) |                       | - Pre-flight GET /v1/capabilit. |
+---------------------------------+                       | - Strict Fail-Closed Validation |
                                                          +----------------+----------------+
                                                                           |
                                                                           v HTTPS POST /v1/adapter/execute
                                                          +---------------------------------+
                                                          |    Remote Agent Server (Node)   |
                                                          | - Default-Deny Adapter Policy   |
                                                          | - Restricted Proxy Adapters Only|
                                                          | - Layer-3 Adapters PROHIBITED   |
                                                          +---------------------------------+
```

### 17.2 Measurement Node Data Model & Security Policies

A measurement node represents a concrete execution vantage point characterized by:
- **Node Identifier (`node_id`)**: Stable, non-empty string containing only alphanumeric characters, underscores, and hyphens (`^[a-zA-Z0-9_\-]+$`).
- **Node Type (`node_type`)**: [`NodeType.LOCAL`](../src/connscope/scenarios/models.py#L379-L384) (executes on the coordinator host), [`NodeType.REMOTE_AGENT`](../src/connscope/scenarios/models.py#L379-L384) (orchestrated over HTTPS), or [`NodeType.SANDBOX`](../src/connscope/scenarios/models.py#L379-L384).
- **Endpoint URL (`endpoint_url` / `agent_endpoint`)**: Required for remote agents. Must use HTTPS (`https://`) unless targeting loopback addresses (`127.0.0.1`, `::1`, `localhost`) for testing. Plaintext HTTP across non-loopback networks is strictly rejected. Embedded credentials (`https://user:pass@host`) are strictly forbidden.
- **Authentication Token Reference (`auth_token_ref`)**: An external identifier or environment variable name (e.g. `CONNSCOPE_AGENT_TOKEN_FRANKFURT`). **Plaintext tokens are strictly forbidden in catalogs and node definitions.**
- **Token Resolution Order ([`resolve_node_token`](../src/connscope/scenarios/nodes.py#L82-L115))**:
  1. Explicit caller-supplied token dictionary mapping `node_id -> token`.
  2. Custom token resolver callback.
  3. Environment variable referenced by `auth_token_ref`.
  4. Default environment variable fallback (`CONNSCOPE_AGENT_TOKEN`).
- **Grounded Route Context vs Descriptive Operator Labels**:
  - `route_context`: Grounded, verifiable network properties observed directly from interfaces, routing tables, and autonomous systems (e.g. `interface`, `asn`, `observed_ip`, `isolation_strategy`).
  - `operator_labels`: Descriptive, unverified heuristic tags supplied by operators (e.g. `city`, `datacenter`, `cluster`, `isp_label`).

### 17.3 Authenticated Agent Capability Discovery (`GET /v1/capabilities`)

Before executing any measurement scenario on a remote node, ConnScope conducts an authenticated pre-flight capability query:
- **Route**: `GET /v1/capabilities`
- **Authentication**: Strict HTTP `Authorization: Bearer <token>` required. Unauthenticated or invalid token requests return HTTP 401 `unauthorized`.
- **Response Schema ([`AgentCapabilities`](../src/connscope/agent/protocol.py#L98-L135))**:
  - `protocol_version`: Integer 1.
  - `api_version`: String `"1.0"`.
  - `supported_operations`: List of supported endpoints (`["measure", "adapter_execute"]`).
  - `allowlisted_adapters`: List of adapter IDs permitted for execution on this node.
  - `allowed_execution_modes`: List of allowed execution modes (`["local_proxy"]`).
  - `executable_versions`: Dictionary of installed engine binary versions (e.g. `{"xray": "26.3.27"}`).
  - `isolation_prerequisites`: Dictionary reporting availability of isolation backends (e.g. `{"network_namespaces": false}`).
- **Pre-Flight Exclusion Policy**: If a scenario requires an adapter that is not included in the remote node's `allowlisted_adapters`, the scenario is marked as `VerificationStatus.SKIPPED` with a clear explanation. **This exclusion is recorded as a capability constraint and is NEVER counted as a network probe failure.**

### 17.4 Server-Side Allowlist & Constrained Adapter Execution (`POST /v1/adapter/execute`)

The remote agent enforces a strict default-deny policy for adapter execution:
1. **Default-Deny Allowlist**:
   By default, [`AgentServer.allowlisted_adapters`](../src/connscope/agent/server.py#L65-L95) is empty (`()`). The agent strictly rejects any adapter execution request unless the operator explicitly allowlists that specific adapter ID.
2. **Permitted Remote Adapters ([`PERMITTED_REMOTE_ADAPTERS`](../src/connscope/agent/protocol.py#L21-L26))**:
   Only 4 userspace local proxy adapters may be allowlisted for remote execution:
   - `xray_vless_tcp_reality`
   - `singbox_vless_tcp_reality`
   - `xray_vmess_ws_tls`
   - `singbox_vmess_ws_tls`
3. **Strict Prohibition of Layer-3 Adapters ([`PROHIBITED_REMOTE_ADAPTERS`](../src/connscope/agent/protocol.py#L28-L33))**:
   Network-interface-based Layer-3 tunnel adapters are strictly prohibited from remote execution:
   - `wireguard_standard`
   - `amnezia_wg_standard`
   - `openvpn_standard`
   **Enforcement**:
   - `ScenarioGenerator` marks Layer-3 scenarios targeting remote nodes as invalid during planning (`is_valid=False`, `exclusion_reason="Layer-3 adapter ... is not supported for remote execution"`).
   - `RemoteAgentClient.execute_adapter` validates the adapter ID locally and raises `ClientConfigurationError` before sending any network request.
   - `AgentServer` validates the adapter ID upon receipt and returns HTTP 403 `forbidden` (`"Layer-3 adapter ... is strictly prohibited from remote execution"`).
4. **Untrusted Configuration Injection Prevention**:
   Remote adapter execution requests accept only configuration parameters declared in the protocol catalog. Arbitrary executable paths, shell commands, or plugin directives (e.g. `command`, `plugin`, `executable_path`) are strictly rejected with HTTP 400 `untrusted_config`.

### 17.5 Distributed Scenario Scheduling & Safe Orchestration Invariants

- **Multi-Node Generation**:
  `ScenarioGenerator.generate_explicit`, `generate_ofat`, `generate_pairwise`, and `generate_exhaustive` accept a sequence of [`MeasurementNode`](../src/connscope/scenarios/models.py#L386-L455) instances. Scenarios are planned across the Cartesian product of profiles, variants, and vantage nodes.
- **Node-Differentiated Scenario Signatures**:
  Scenario IDs and deduplication hashes incorporate `scn.node.node_id`. Identical protocol variants running on distinct nodes remain distinct and are never accidentally deduplicated.
- **Zero Local Fallback Policy**:
  If a remote agent encounters an error during pre-flight discovery or scenario execution (e.g. connection refused, network timeout, authentication failure, server crash), [`ScenarioCoordinator`](../src/connscope/scenarios/coordinator.py#L67-L140) records the failure against the remote node with an appropriate failure stage (`node_unavailable`, `capability_unavailable`, `timeout`, or `process`). **The coordinator NEVER silently falls back to local execution.** Local fallback would falsify vantage point data and invalidate measurement comparability.

### 17.6 Cross-Node Comparability & Aggregation

When aggregating multi-node measurement runs ([`aggregate_execution_records`](../src/connscope/scenarios/aggregation.py#L125-L295)):
- **Comparability Criteria**:
  Scenarios executed across distinct nodes are comparable if and only if they target the exact same remote endpoint (`host:port`) and utilize the exact same measurement workload (`workload_type`, `test_url`, `repetitions`). If targets or workloads differ, `is_comparable` is set to `False` and comparability warnings are recorded.
- **Summary Metadata**:
  Each [`ScenarioSummary`](../src/connscope/scenarios/aggregation.py#L25-L65) retains `node_id`, `route_context`, and `operator_labels`.
- **Terminal Summary Output**:
  [`render_execution_summary_table`](../src/connscope/scenarios/aggregation.py#L320-L360) renders a dedicated `NODE` column in the terminal matrix summary table, allowing immediate side-by-side comparison across vantage points:

```
+--------------------------------------------------------------------------------------------------------------------+
| SCENARIO ID                     | NODE        | ENGINE   | PROFILE           | VARIANT  | REPS | SUCCESS | MEDIAN (MS) |
+--------------------------------------------------------------------------------------------------------------------+
| scn_xray_vless_baseline_01     | local       | xray     | vless_tcp_reality | baseline | 5/5  | 100.0%  | 24.5 ms     |
| scn_xray_vless_baseline_02     | remote-fra  | xray     | vless_tcp_reality | baseline | 5/5  | 100.0%  | 42.1 ms     |
+--------------------------------------------------------------------------------------------------------------------+
```

### 17.7 Evidence Tiers and Verification Breakdown

| Evidence Dimension | Status | Evidence & Runtime Findings |
|---|---|---|
| **Measurement Node Model & Secret Safety** | **VERIFIED** | `MeasurementNode` enforces strict URL validation (HTTPS required, plaintext HTTP restricted to loopback), rejects embedded URL userinfo, rejects raw Bearer tokens, and separates grounded `route_context` from descriptive `operator_labels`. |
| **Node Registry & Credential Resolution** | **VERIFIED** | `NodeRegistry` manages registered nodes with eligibility filtering. `resolve_node_token` resolves tokens with strict precedence (token map > resolver > env var ref > fallback env var) without storing secrets in catalog files. |
| **Agent Capability Discovery API** | **VERIFIED** | `GET /v1/capabilities` requires Bearer token authentication and returns structured `AgentCapabilities`. Pre-flight discovery verifies remote allowlists and excludes unsupported adapters with `VerificationStatus.SKIPPED` without counting as probe failures. |
| **Default-Deny Remote Execution Policy** | **VERIFIED** | `AgentServer` defaults to empty allowlist (`allowlisted_adapters=()`). Unallowlisted adapters return HTTP 403 `forbidden`. Dangerous config keys (`command`, `plugin`) return HTTP 400 `untrusted_config`. |
| **Layer-3 Remote Execution Prohibition** | **VERIFIED** | Layer-3 adapters (`wireguard_standard`, `amnezia_wg_standard`, `openvpn_standard`) are prohibited by protocol constants (`PROHIBITED_REMOTE_ADAPTERS`), client-side local validation (`RemoteAgentClient`), and server-side policy enforcement (`AgentServer`). |
| **Multi-Node Scenario Matrix Scheduling** | **VERIFIED** | `ScenarioGenerator` generates scenarios across explicit node sequences with distinct scenario IDs and deduplication signatures incorporating `node_id`. |
| **Zero Local Fallback Policy** | **VERIFIED** | `ScenarioCoordinator` catches remote failures (`RemoteUnavailableError` -> `node_unavailable`, `RemotePolicyError` -> `capability_unavailable`, `RemoteTimeoutError` -> `timeout`), records failure stages, and strictly avoids calling local adapters as fallback. |
| **Comparability & Terminal Reporting** | **VERIFIED** | `aggregate_execution_records` verifies identical targets and workloads for cross-node validity. Terminal summary renders dedicated `NODE` column. JSONL records contain full node metadata with zero raw secrets. |

---

## 18. Profile-Driven Engine Adapters (Phase 21 Architecture)

### 18.1 Architecture and Purpose

Phase 21 introduces a profile-driven execution architecture for proxy engines (`Xray-core` and `sing-box`). Instead of declaring a separate Python adapter class for every permutation of protocol, transport, and security mode, execution is centralized into a unified, reusable implementation: [`ProfileDrivenAdapter`](../src/connscope/adapters/profile_adapter.py#L50-L450).

Protocol families, transports, security mechanisms, and parameter variants are decoupled and represented as validated declarative catalog entities, while trusted native configuration builders construct engine-conforming JSON configurations.

```mermaid
graph TD
    subgraph Catalog ["Declarative Protocol Catalog"]
        P1["vless_tcp_reality"]
        P2["vless_tcp_tls"]
        P3["vless_tcp_none"]
        P4["vless_ws_tls"]
        P5["vless_grpc_tls"]
        P6["vmess_ws_tls"]
        P7["trojan_tcp_tls"]
        P8["shadowsocks_tcp"]
    end

    subgraph Builders ["Native Configuration Builders"]
        VAL["validate_profile_config()"]
        BX["build_xray_config()"]
        BS["build_singbox_config()"]
    end

    subgraph Runtime ["ProfileDrivenAdapter Runtime Lifecycle"]
        PORT["find_free_loopback_port()"]
        WS["safe_temporary_workspace()"]
        SPAWN["asyncio.create_subprocess_exec()"]
        READY["wait_for_proxy_ready()"]
        VERIFY["verify_tunnel_and_data_transfer()"]
        TEARDOWN["terminate_process_tree()"]
    end

    P1 --> VAL
    P2 --> VAL
    P3 --> VAL
    P4 --> VAL
    P5 --> VAL
    P6 --> VAL
    P7 --> VAL
    P8 --> VAL

    VAL --> BX
    VAL --> BS

    BX --> SPAWN
    BS --> SPAWN
    PORT --> SPAWN
    WS --> SPAWN
    SPAWN --> READY
    READY --> VERIFY
    VERIFY --> TEARDOWN
```

### 18.2 Supported Protocol Profiles and Engine Matrix

ConnScope Phase 21 supports 8 distinct protocol profile families across both `xray` and `sing_box`:

| Profile ID | Protocol | Transport | Security | Description & Constraints | Tested Xray | Tested sing-box |
|---|---|---|---|---|---|---|
| `vless_tcp_reality` | VLESS | TCP | REALITY | VLESS with XTLS REALITY camouflage; uTLS fingerprinting; `flow` xtls-rprx-vision. | v26.3.27 | v1.12.12 |
| `vless_tcp_tls` | VLESS | TCP | TLS | Direct TCP transport with standard TLS encryption and ALPN negotiation. | v26.3.27 | v1.12.12 |
| `vless_tcp_none` | VLESS | TCP | NONE | Plaintext TCP transport strictly scoped for diagnostic tests. Flow control rejected. | v26.3.27 | v1.12.12 |
| `vless_ws_tls` | VLESS | WebSocket | TLS | HTTP/1.1 WebSocket upgrade stream encapsulated inside TLS. Flow control rejected. | v26.3.27 | v1.12.12 |
| `vless_grpc_tls` | VLESS | gRPC | TLS | Multiplexed gRPC transport over HTTP/2 inside TLS. Flow control rejected. | v26.3.27 | v1.12.12 |
| `vmess_ws_tls` | VMess | WebSocket | TLS | VMess authentication over WebSocket + TLS. Engine-specific cipher validation. | v26.3.27 | v1.12.12 |
| `trojan_tcp_tls` | Trojan | TCP | TLS | Password-authenticated Trojan over direct TCP with TLS encryption. | v26.3.27 | v1.12.12 |
| `shadowsocks_tcp` | Shadowsocks | TCP | NONE | Shadowsocks 2022 (BLAKE3-AES/ChaCha20) and legacy AEAD ciphers. | v26.3.27 | v1.12.12 |

### 18.3 Native Engine Builders and Schema Discrepancy Isolation

Configuration builders ([`build_xray_config`](../src/connscope/adapters/builders.py#L320-L450) and [`build_singbox_config`](../src/connscope/adapters/builders.py#L455-L580)) enforce strict engine isolation:
- **Xray-core Schema Rules**:
  - Outbound tag: defaults to `proxy`.
  - Stream settings: uses `streamSettings` object with `network` (`tcp`, `ws`, `grpc`), `security` (`reality`, `tls`, `none`).
  - TLS/REALITY settings: uses `tlsSettings` with `serverName`, `fingerprint`, and `allowInsecure: True` (when `verify_cert: False`).
  - Reality settings: uses `realitySettings` with `show: False`, `fingerprint`, `serverName`, `publicKey` / `password`, `shortId`, `spiderX`.
  - Flow: uses `flow: "xtls-rprx-vision"` on client user object.
  - VMess ciphers: restricts to `auto`, `aes-128-gcm`, `chacha20-poly1305` (rejecting `none` and `zero`).
- **sing-box Schema Rules**:
  - Outbound tag: uses `{protocol}-out` (e.g. `vless-out`, `vmess-out`, `trojan-out`, `shadowsocks-out`).
  - TLS settings: uses `tls` block with `enabled: True`, `server_name`, `insecure: True` (when `verify_cert: False`), and `utls` object (`enabled: True`, `fingerprint`).
  - Reality settings: uses `reality` nested inside `tls` block with `enabled: True`, `public_key`, `short_id`.
  - Rejection of unknown keys: sing-box's Go parser (`DisallowUnknownFields`) strictly rejects `publicKey` or `password` inside reality block; builder emits strictly conforming schema.
  - V2Ray transport: uses `transport` block (`type: "ws"` with `path`, `headers`; `type: "grpc"` with `service_name`).
  - Shadowsocks 2022 keys: enforces Base64-encoded keys matching cipher length (16 bytes for 128-bit, 32 bytes for 256-bit).

### 18.4 Reusable Process Lifecycle & Resilience

[`ProfileDrivenAdapter`](../src/connscope/adapters/profile_adapter.py#L50-L450) manages the complete measurement lifecycle:
1. **Dynamic Port Allocation & Bounded Retries**:
   Allocates free loopback ports via `find_free_loopback_port()` (OS `bind((host, 0))`). If proxy fails readiness on an OS-assigned port, up to 3 bounded retries are executed with fresh ports before returning `FailureStage.PROCESS_SPAWN`.
2. **Restricted Workspace Isolation**:
   Configurations are generated in unique, permissions-restricted (`0700`) temporary directories that are guaranteed to be cleaned up upon completion.
3. **Shell-Free Execution & Argument Validation**:
   Processes are spawned using direct argument lists with allowlisted binaries (`validate_command_args`), completely eliminating shell injection vectors.
4. **Proxy Readiness Detection**:
   Asynchronously polls the local SOCKS5 endpoint with small TCP probes (`wait_for_proxy_ready`) until accepting connections or process exit.
5. **Process Group Teardown & Pipe Deadlock Prevention**:
   On readiness failure or timeout, `terminate_process_tree` signals `SIGTERM` to the process group (`os.killpg`) before reading bounded streams, eliminating pipe deadlocks if child processes hang.
6. **Credential Scrubbing & Structured Failure Reporting**:
   All sensitive fields (`uuid`, `password`, `public_key`, `short_id`) are scrubbed from process error logs and stderr before constructing results. Failure stages distinguish `PRE_FLIGHT`, `CONFIG_GENERATION`, `PROCESS_SPAWN`, `HANDSHAKE`, and `DATA_TRANSFER`.

### 18.5 Backward Compatibility

All 4 concrete Phase 16/17 adapters inherit from `ProfileDrivenAdapter`:
- `XrayVlessTcpRealityAdapter` (`xray_vless_tcp_reality`)
- `SingBoxVlessTcpRealityAdapter` (`singbox_vless_tcp_reality`)
- `XrayVmessWebSocketTlsAdapter` (`xray_vmess_ws_tls`)
- `SingBoxVmessWebSocketTlsAdapter` (`singbox_vmess_ws_tls`)

All existing helper functions (`generate_xray_client_config`, `generate_singbox_client_config`, `generate_xray_vmess_ws_tls_client_config`, `generate_singbox_vmess_ws_tls_client_config`), constants (`VALID_VMESS_SECURITY`, `VALID_SINGBOX_VMESS_SECURITY`), and readiness test hooks remain fully intact and 100% backward compatible.

---

## 19. Phase 22 — Capability Catalog, Verification Tiers, and Parameter Coverage

### 19.1 Architecture and Six Independent Verification Tiers

Phase 22 establishes a structured capability catalog ([`ProtocolCatalog`](../src/connscope/scenarios/catalog.py#L30-L2380)) and verification tier model ([`CoverageTier`](../src/connscope/scenarios/models.py#L35-L42)) that prevents ambiguity between what is documented, what is validated by schema, what can be generated, what has been tested with real binaries, and what has completed live data transfer.

```mermaid
flowchart TD
    T1["Tier 1: catalogued<br/>(Authoritative upstream source confirmed)"]
    T2["Tier 2: schema_validated<br/>(Typed parameter definitions, boundary rules, constraints)"]
    T3["Tier 3: config_generated<br/>(Native config builder emits conforming engine JSON)"]
    T4["Tier 4: binary_validated<br/>(Real binary parser check / lifecycle spawn succeeds)"]
    T5["Tier 5: live_connected<br/>(Controlled network handshake with peer endpoint)"]
    T6["Tier 6: data_transferred<br/>(Post-tunnel application byte transfer verified)"]

    T1 --> T2
    T2 --> T3
    T3 --> T4
    T4 -.->|Opt-In Remote Peer| T5
    T5 -.->|Opt-In Remote Peer| T6
```

1. **`catalogued`**: Authoritative upstream documentation, repository commit, or specification exists and has been reviewed. Unresolved implementations (e.g. Aether) are marked with `requires_source_confirmation: True`.
2. **`schema_validated`**: Explicit parameter definition with typed validation, min/max bounds, allowed values, inter-parameter dependencies, and conflicts modeled in catalog data.
3. **`config_generated`**: Concrete configuration builder ([`build_xray_config`](../src/connscope/adapters/builders.py#L445-L600), [`build_singbox_config`](../src/connscope/adapters/builders.py#L605-L750)) exists and maps options to native engine syntax without field cross-contamination.
4. **`binary_validated`**: Configuration checked by actual engine binary parser (`xray run -test -c` or `sing-box check -c`) or executed in a local isolated test lifecycle.
5. **`live_connected`**: Handshake with a real, controlled remote test server verified. (Strict invariant: never claimed without an active, user-provided test server).
6. **`data_transferred`**: Post-tunnel payload bytes transmitted and verified (HTTP 204 or byte-counter). (Strict invariant: never claimed without an active, user-provided test server).

### 19.2 Host-Verified Binary Runtime Versions

ConnScope validates its configuration builders and adapters directly against the host binaries installed on the measurement node:
- **Xray-core**: `v26.3.27` (`/usr/local/bin/xray`)
- **sing-box**: `v1.12.12` (`/home/arshiacomplus/.local/share/v2rayN/bin/sing_box/sing-box`)

### 19.3 Empirical Parser & Compatibility Discoveries

Real binary testing on host binaries revealed critical schema rules that must be strictly enforced:
- **Xray-core v26.3.27 QUIC Removal**:
  Standalone QUIC transport (`streamSettings.network="quic"`) was officially deprecated and removed upstream (`common/errors: The feature QUIC transport has been removed, please use XHTTP with stream-one h3 instead`). ConnScope catalogues `xray_quic` as inventory only (`is_executable=False`) with an explicit unsupported reason.
- **sing-box v1.12.12 Schema Rigidity (`DisallowUnknownFields`)**:
  sing-box uses Go's `DisallowUnknownFields` decoder. It strictly rejects unknown fields:
  - Transport types: accepts `ws`, `grpc`, `httpupgrade`, and `quic`. Strictly rejects `splithttp` and `xhttp` (`unknown transport type: splithttp`).
  - Transport types: does not support `kcp` (`unknown transport type: kcp`).
  - REALITY: requires `utls.enabled: true` whenever `reality.enabled: true` is set. Rejects `spider_x` and `spiderX` in reality settings.
  - Shadowsocks: rejects `uot` in outbound configuration (`unknown field "uot"`). Rejects `packet_encoding` on shadowsocks outbounds (`unknown field "packet_encoding"`).
  - VMess / VLESS: supports `packet_encoding: "packetaddr"`.
  - gRPC: rejects `multi_mode: true`. Expects timeouts formatted as duration strings (e.g. `"25s"`, `"15s"`).
- **Xray-core Outbound Flexibility**:
  - Outbound mux: supports `mux: {"enabled": True, "concurrency": 16}`.
  - TCP Fast Open: supports `streamSettings.sockopt.tcpFastOpen = True`.
  - Shadowsocks: supports `uot: True` and `packetEncoding: "packetaddr"` on server entries.
  - WebSocket: supports `maxEarlyData` and `earlyDataHeaderName`.
  - gRPC: supports `multiMode: True`, `idle_timeout`, and `health_check_timeout`.

### 19.4 Exclave and Layer-3 Engines Status

- **Exclave (`https://github.com/ExclaveNetwork/Exclave`)**:
  Multi-protocol Android client runtime forked from the SagerNet ecosystem. Catalogued inventory covers VLESS, VMess, Trojan, and Shadowsocks over TUN (`exclave_vless`, `exclave_vmess`, `exclave_trojan`, `exclave_shadowsocks`, `exclave_tun`). Host execution on Linux nodes remains catalogued as inventory awaiting upstream headless engine extraction.
- **WireGuard (`wireguard_standard`)**:
  In-tree Linux kernel / userspace module. Requires root / `CAP_NET_ADMIN` privileges; isolated test fixtures verified in temporary network namespaces (`origin_netns`).
- **AmneziaWG (`amneziawg_obfs`)**:
  Obfuscated WireGuard fork with Jc/Jmin/Jmax padding and S1/S2/H1-H4 header randomized obfuscation. Requires kernel module and root privileges.
- **OpenVPN (`openvpn_udp`, `openvpn_tcp`)**:
  Full-featured SSL/TLS VPN. Config test validation implemented; userspace daemon socket migration across netns disabled by ConnScope host safety invariants.
- **Aether (`aether_tun`)**:
  Experimental censorship circumvention runtime. Pinned with `requires_source_confirmation: True` awaiting confirmation of canonical upstream repository and commit.

### 19.5 Coverage Statistics & Engine Matrix

Generated deterministically by `connscope catalog coverage`:

| Engine | Total Items | Executable | Catalogued | Schema Validated | Config Generated | Binary Validated | Live Handshake | Data Transfer |
|---|---|---|---|---|---|---|---|---|
| **xray** | 23 | 18 | 23 | 22 | 18 | 22 | 0 | 0 |
| **sing_box** | 23 | 19 | 23 | 21 | 19 | 21 | 0 | 0 |
| **exclave** | 5 | 0 | 5 | 0 | 0 | 0 | 0 | 0 |
| **wireguard** | 2 | 0 | 2 | 2 | 1 | 0 | 0 | 0 |
| **amnezia_wg** | 2 | 0 | 2 | 2 | 1 | 0 | 0 | 0 |
| **openvpn** | 4 | 0 | 4 | 4 | 2 | 0 | 0 | 0 |
| **aether** | 2 | 0 | 2 | 1 | 0 | 0 | 0 | 0 |
| **TOTAL** | **61** | **37** | **61** | **52** | **41** | **43** | **0** | **0** |

### 19.6 CLI Tooling

Two CLI commands provide deterministic inspection of the coverage matrix:
- `connscope catalog coverage`: Displays human-readable table or JSON (`--json`), with optional engine filtering (`--engine <id>`).
- `connscope matrix coverage`: Alias integrating capability coverage with scenario matrix generation.

---

## 20. Phase 23 — Exclave Capability & Parameter Coverage

### 20.1 Upstream Reference & Source Audit

ConnScope Phase 23 establishes a source-verified capability and parameter model for the Exclave client engine. Exclave is an Android client ecosystem forked and modernized from SagerNet.

Official Upstream Reference:
- **Repository**: `https://github.com/ExclaveNetwork/Exclave`
- **Reference Release**: `v0.17.66`
- **Pinned Commit**: `71ae3bc007018804c7760fa0f54546522c7104b2` (short: `71ae3bc`)
- **Source Access Date**: `2026-10-27`
- **Documentation Sources**:
  - Configuration Reference: `https://github.com/ExclaveNetwork/Exclave/wiki/Configuration`
  - Settings Reference: `https://github.com/ExclaveNetwork/Exclave/wiki/Settings`
  - Release Notes: `https://github.com/ExclaveNetwork/Exclave/releases/tag/v0.17.66`

All 27 Exclave capability entries record this exact reference in their `SourceReference` metadata.

### 20.2 Exclave Protocol Families Inventory

The Exclave capability catalog is expanded from 5 placeholder items to 27 detailed entries across all documented protocol families and system networking features:

1. **Shadowsocks AEAD (`exclave_shadowsocks`)**:
   - Modern AEAD ciphers: `chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-256-gcm`, `xchacha20-ietf-poly1305`.
   - Parameters: `method`, `password` (secret), `udp_relay`.
2. **Shadowsocks 2022 (`exclave_shadowsocks_2022`)**:
   - Modern AEAD 2022 ciphers: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`.
   - Mandatory Base64 pre-shared key validation (16 bytes for AES-128, 32 bytes for AES-256 and ChaCha20).
3. **Shadowsocks Legacy Stream (`exclave_shadowsocks_legacy`)**:
   - Legacy stream ciphers: `aes-128-cfb`, `aes-256-cfb`, `rc4-md5`, `chacha20-ietf`.
   - Parameters: `method`, `password`.
4. **Shadowsocks SIP003 Plugin (`exclave_shadowsocks_plugin`)**:
   - Outbound plugin abstraction: `v2ray-plugin`, `obfs-local`.
   - Parameters: `plugin`, `plugin_opts`.
5. **Trojan (`exclave_trojan`)**:
   - Trojan over TLS with uTLS fingerprinting (`chrome`, `firefox`, `safari`, `ios`, `android`, `edge`) and ALPN (`h2,http/1.1`).
   - Parameters: `password`, `server_name`, `alpn`, `fingerprint`, `verify_cert`.
6. **Hysteria 2 (`exclave_hysteria2`)**:
   - QUIC-based protocol supporting Brutal congestion control via bandwidth specification (`up_mbps`, `down_mbps`) or standard BBR/Reno when unspecified.
   - Obfuscation support: `salamander` obfs with required `obfs_password`.
   - Parameters: `password`, `ports` (port hopping), `up_mbps`, `down_mbps`, `obfs_type`, `obfs_password`, `server_name`, `alpn`, `chrome_parrot`, `insecure`.
7. **AnyTLS (`exclave_anytls`)**:
   - Camouflaged TLS stream with random or stream padding modes.
   - Parameters: `password`, `server_name`, `alpn`, `idle_timeout`, `padding_mode`.
8. **mieru v3 (`exclave_mieru`)**:
   - Obfuscated proxy protocol over TCP or UDP with dynamic port hopping and Base64 Protobuf traffic pattern configuration.
   - Parameters: `username`, `password`, `transport`, `port_range`, `multiplexing`, `traffic_pattern`, `mtu`.
9. **NaïveProxy (`exclave_naiveproxy`)**:
   - Chromium network stack proxying via standalone plugin executable.
   - Parameters: `username`, `password`, `server_name`, `protocol` (`https`, `quic`), `padding`, `plugin_path`.
10. **TUIC v5 (`exclave_tuic_v5`)**:
    - Modern QUIC proxying with RFC 4122 UUID authentication and native or quic UDP relay modes.
    - Parameters: `uuid` (UUID format), `password`, `congestion_control` (`bbr`, `cubic`, `new_reno`), `udp_relay_mode`, `zero_rtt_handshake`, `alpn`, `server_name`, `disable_sni`.
11. **Juicity (`exclave_juicity`)**:
    - QUIC-based protocol with RFC 4122 UUID auth and pinned certificate chain SHA-256 fingerprint verification.
    - Parameters: `uuid`, `password`, `congestion_control`, `server_name`, `pinned_certchain_sha256`.
12. **VLESS (`exclave_vless`)**:
    - VLESS proxying supporting Vision flow (`xtls-rprx-vision`), REALITY (`reality_public_key`, `reality_short_id`), and UDP packet encoding (`packetaddr`, `xudp`, `none`).
    - Parameters: `uuid`, `flow`, `encryption`, `packet_encoding`, `server_name`, `reality_public_key`, `reality_short_id`.
13. **VMess (`exclave_vmess`)**:
    - Encrypted VMess proxying with AEAD enforcement and packetaddr UDP support.
    - Parameters: `uuid`, `alter_id`, `security`, `packet_encoding`, `aead_enforced`.
14. **WireGuard (`exclave_wireguard`)**:
    - Userspace netstack WireGuard client supporting Base64 key validation and reserved client bytes obfuscation.
    - Parameters: `private_key`, `peer_public_key`, `preshared_key`, `local_address`, `reserved_bytes`, `mtu`.
15. **MASQUE / CONNECT-IP (`exclave_masque_connect_ip`)**:
    - RFC 9298 IP datagram proxying via HTTP Datagrams over HTTP/3 or Capsule Protocol over HTTP/2.
    - Parameters: `server_name`, `uri_template`, `auth_token`, `capsule_protocol`, `alpn`.
16. **TrustTunnel (`exclave_trusttunnel`)**:
    - AdGuard obfuscated tunnel using HTTP/2 or HTTP/3 CONNECT for TCP and private UDP-over-TCP.
    - Parameters: `username`, `password`, `server_name`, `transport` (`h2`, `h3`), `udp_over_tcp`.
17. **Snell v4 (`exclave_snell_v4`)**:
    - Version 4 Snell proxy with optional HTTP obfuscation and UDP relay.
    - Parameters: `psk`, `version` (4), `obfs` (`none`, `http`), `obfs_host`, `udp_relay`.
18. **Snell v6 (`exclave_snell_v6`)**:
    - Version 6 Snell proxy with modernized framing and HTTP obfuscation.
    - Parameters: `psk`, `version` (6), `obfs` (`none`, `http`), `obfs_host`, `udp_relay`.
19. **ShadowQUIC (`exclave_shadowquic`)**:
    - QUIC transport with custom obfuscation and 0-RTT support.
    - Parameters: `password`, `server_name`, `alpn`, `zero_rtt`.
20. **SSH (`exclave_ssh`)**:
    - SSH Dynamic Port Forwarding with password or OpenSSH private key authentication.
    - Parameters: `username`, `password`, `private_key`, `passphrase`, `host_key_check`.
21. **HTTP CONNECT (`exclave_http_connect`)**:
    - Standard HTTP proxying over HTTP/1.1, HTTP/2, or HTTP/3 with TLS encryption.
    - Parameters: `username`, `password`, `tls`, `http_version`.
22. **CONNECT-UDP (`exclave_connect_udp`)**:
    - RFC 9298 datagram proxying with Capsule Protocol framing over HTTP/2 or HTTP/3.
    - Parameters: `capsule_protocol`, `http_version`.
23. **SOCKS4/4a (`exclave_socks4`)**:
    - SOCKS4/4a client with remote DNS resolution support.
    - Parameters: `version` (`4`, `4a`), `user_id`, `remote_dns`.
24. **SOCKS5 (`exclave_socks5`)**:
    - SOCKS5 client with username/password authentication and UDP Associate support.
    - Parameters: `username`, `password`, `udp_associate`, `remote_dns`.
25. **Android TUN Mode - gVisor (`exclave_tun`)**:
    - Userspace packet capture using Google gVisor netstack.
    - Parameters: `tun_stack` (`gvisor`), `mtu`, `auto_route`, `strict_route`.
26. **Android TUN Mode - System (`exclave_tun_system`)**:
    - Kernel double-NAT packet capture using Android System netstack.
    - Parameters: `tun_stack` (`system`), `mtu`.
27. **Traffic Sniffing & DNS Strategy (`exclave_traffic_sniffing`)**:
    - Inbound protocol sniffing (TLS SNI, HTTP Host, QUIC SNI), Happy Eyeballs concurrent dial, and ICMP discard policy.
    - Parameters: `sniff_enabled`, `override_destination`, `sniff_tls_sni`, `sniff_http_host`, `sniff_quic_sni`, `dns_strategy`, `tcp_concurrent`, `discard_icmp`.

### 20.3 Parameter Validation and Safety Rules (`validate_exclave_config`)

To protect scenario planning and measurement pipelines from arbitrary code execution, `validate_exclave_config` provides strict verification:
- **Forbidden Execution Keys**: Explicitly blocks execution keys (`command`, `exec`, `binary`, `plugin_binary`, `shell`, `script`, `eval`, `so_path`, `native_lib`).
- **Disallow Unknown Fields**: Rejects any keys not defined in the capability's parameter schema.
- **Typed Bounds & Enum Verification**: Enforces types, integer bounds (`min_value`, `max_value`), allowed enum sets, and UUID formatting.
- **Protocol-Specific Checks**:
  - `exclave_shadowsocks_2022`: Base64 decoding check enforcing 16 bytes for `2022-blake3-aes-128-gcm` and 32 bytes for `2022-blake3-aes-256-gcm` / `2022-blake3-chacha20-poly1305`.
  - `exclave_hysteria2`: When `obfs_type == "salamander"`, requires non-empty `obfs_password`.
  - `exclave_ssh`: Enforces at least one authentication method (`password` or `private_key`).
  - `exclave_wireguard`: Enforces 32-byte Base64 encoding for `private_key` and `peer_public_key`.
  - `exclave_naiveproxy`: Sanitizes `plugin_path` against shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `\n`, `\r`).
  - `exclave_socks4`: Enforces maximum 255-character limit on `user_id`.
  - `exclave_tuic_v5` and `exclave_juicity`: Enforces RFC 4122 hex-and-dash UUID format (`8-4-4-4-12`).

### 20.4 Counting Model Reconciliation

Phase 22 reported "40 canonical capabilities" while the coverage table displayed 61 items. Phase 23 reconciles this counting model by formally distinguishing the separate catalog entities:

| Entity Unit | Phase 22 Count | Phase 23 Count | Definition |
|---|---|---|---|
| **Canonical Capabilities** | 22 | 45 | Distinct protocol/transport/security feature concepts independent of engine prefixes. |
| **Engine Capabilities** | 40 | 62 | Engine-specific capability definitions registered in the catalog (`len(catalog.list_capabilities())`). Phase 22 had 40 (15 Xray + 15 sing-box + 5 Exclave + 1 WireGuard + 1 AmneziaWG + 2 OpenVPN + 1 Aether); Phase 23 expands Exclave from 5 to 27 (+22), reaching 62. |
| **Profile Compatibilities** | 21 | 21 | Abstract engine-to-profile execution targets (`len(catalog.list_compatibilities())`): 8 Xray + 8 sing-box + 1 WireGuard + 1 AmneziaWG + 2 OpenVPN + 1 Aether = 21. |
| **Total Coverage Table Items** | **61** | **83** | Profile compatibilities (21) + Engine capabilities (62) = 83 items. In Phase 22: 21 + 40 = 61 items. |
| **Parameter Definitions** | ~170 | 260 | Unique scoped parameter definitions across all profiles and capabilities. |
| **Parameter Variants** | 36 | 36 | Pre-configured parameter variants across protocol profiles. |
| **Compatibility Rules** | ~26 | 53 | Parameter constraints, limitations, and engine conflict rules. |

Coverage reports generated via CLI table and JSON output now clearly distinguish these metrics in dedicated header blocks.

### 20.5 Host Execution Feasibility & Non-Executable Status

An execution audit of the local Linux host confirmed:
- Exclave is primarily an Android client application relying on Android's `VpnService` API, JNI bindings, and Android-specific package routing.
- No headless Linux CLI executable or daemon binary is currently packaged or installed on the host (`which exclave` returned empty).
- In accordance with ConnScope host safety principles, no external software was downloaded or installed.

Consequently, all 27 Exclave capabilities are marked:
- `is_executable = False`
- `status = VerificationStatus.CATALOGUED`
- `unsupported_reason = "Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction"` (or Android OS routing for TUN/sniffing).

**Roadmap for Future Headless Execution**:
Future phases may achieve live execution for Exclave via:
1. Extracting and compiling the underlying Go/Rust core proxy daemon with standard Linux tun/tap or loopback SOCKS inbounds.
2. Running the client inside a containerized Android runtime environment (e.g. Waydroid or headless emulator) with forwarded ADB ports.

### 20.6 CLI Verification & Coverage Filtering

The CLI commands `connscope catalog coverage` and `connscope matrix coverage` support deterministic filtering and JSON reporting:
- Filter by engine: `connscope catalog coverage --engine exclave`
- Filter by protocol: `connscope catalog coverage --protocol vless`
- Combined filtering: `connscope catalog coverage --engine xray --protocol vless`
- Deterministic JSON output: `connscope catalog coverage --engine exclave --json`

---

## 21. Source Integrity, Precise Taxonomy, and Capability Model Hardening (Phase 24)

### 21.1 Verification of Upstream Exclave Reference Baseline

An audit of the Phase 23 Exclave references against the public upstream git repository (`https://github.com/ExclaveNetwork/Exclave`) resolved critical provenance discrepancies:

1. **Tag Discrepancy**:
   - Phase 23 reported tag `v0.17.66`.
   - Primary upstream source verification via `git ls-remote --tags` confirmed that the upstream repository publishes release tags without a leading `v`. The exact tag is `0.17.66` (`refs/tags/0.17.66`).
2. **Commit Hash Discrepancy**:
   - Phase 23 cited commit `71ae3bc007018804c7760fa0f54546522c7104b2`.
   - Upstream git resolution revealed that `71ae3bc007018804c7760fa0f54546522c7104b2` was a malformed hash sharing only the 7-character short prefix `71ae3bc`.
   - The verified immutable commit hash resolving `refs/tags/0.17.66` (the HEAD of the `dev` branch) is `71ae3bca4217f78d704713dbb6328aad067404a1`.
3. **Documentation Reference**:
   - The upstream wiki repository (`https://github.com/ExclaveNetwork/Exclave.wiki.git`) was inspected at commit `6dba811e7a5b0bc45a6ee52978d975cb5d15b298`.
   - Both the code repository (`71ae3bca4217f78d704713dbb6328aad067404a1`) and the documentation repository are permanently recorded in `SourceReference`.

### 21.2 Correct Protocol Standards and RFC Mappings

Protocol specifications and RFC citations across the catalog were verified and corrected:
- **CONNECT-UDP**: Corrected to cite **RFC 9298** ("Proxying UDP in HTTP"). It previously suffered from confusion with CONNECT-IP and is verified to NOT cite RFC 9484.
- **CONNECT-IP / MASQUE**: Verified to cite **RFC 9484** ("Proxying IP in HTTP"). It is verified to NOT cite RFC 9298.
- **HTTP CONNECT**: Cites **RFC 7231 / RFC 9110**.
- **SOCKS5**: Cites **RFC 1928**.
- **SOCKS4/4a**: Cites canonical SOCKS Protocol Version 4/4A specification.
- **SSH**: Cites **RFC 4251 / RFC 4253**.
- **TUIC v5**: Cites TUIC v5 protocol and QUIC **RFC 9000**.
- **WireGuard**: Cites WireGuard protocol specification and **RFC 8439**.

Dedicated regression tests in `tests/scenarios/test_protocol_standards.py` enforce these standards assignments.

### 21.3 Capability Taxonomy and Category Architecture

Phase 24 establishes a formal capability taxonomy via `CapabilityCategory(StrEnum)` to replace loose string identifiers:
- `PROTOCOL`: Canonical wire transport and application protocols (e.g., Shadowsocks, Trojan, VLESS, VMess, Hysteria 2, WireGuard, SSH, SOCKS5, HTTP CONNECT).
- `PROTOCOL_VARIANT`: Derived or legacy protocol specifications (e.g., Shadowsocks 2022, Shadowsocks legacy ciphers, Snell v4/v6, SOCKS4).
- `PLUGIN`: External binaries and standard plugin specifications (e.g., SIP003, NaïveProxy).
- `RUNTIME_MODE`: Engine operational service modes (e.g., Exclave Android `VpnService` TUN capture mode).
- `NETWORK_STACK`: Userspace or kernel TCP/IP stack implementations (e.g., gVisor userspace netstack, System double-NAT kernel stack).
- `INBOUND_PROCESSING`: Ingress packet inspection and domain discovery (e.g., TLS SNI, HTTP Host, QUIC SNI traffic sniffing).
- `GLOBAL_SETTING`: Engine-wide behavioral policies and dials (e.g., Happy Eyeballs RFC 8305 dialer, ICMP discard policy).
- `TRANSPORT`, `SECURITY`, `MULTIPLEXING`, `PACKET_MANIPULATION`, `OBFUSCATION`, `DIAGNOSTIC`.

**Disambiguation of Exclave Capabilities**:
- TUN mode is classified as a `RUNTIME_MODE`, not a wire protocol.
- gVisor and System network stacks are classified as `NETWORK_STACK` alternatives.
- Inbound sniffing is categorized as `INBOUND_PROCESSING`.
- Happy Eyeballs and ICMP discard are categorized as `GLOBAL_SETTING`.
- Exclave wire protocol count is strictly 17 (with 5 variants, 2 plugins, 1 runtime mode, 2 network stacks, 1 inbound processing, and 2 global settings = 30 capabilities total).

### 21.4 Traceable Parameter Evidence

Every parameter definition in the catalog now supports traceable primary source evidence:
- `SourceReference`: Includes `source_file`, `section`, `line_range`, `reference_type`, `verification_status`, and `discrepancy`.
- `ParameterDefinition`: Includes `evidence_status`, `impact_scope` (`wire_format`, `local_routing`, `multiplexing`, `security_negotiation`, `tls_handshake`, `system_integration`, `diagnostic`, `network_behavior`), `is_source_confirmed`, and `uncertainty_notes`.
- Unconfirmed parameters are explicitly marked with `is_source_confirmed=False` to prevent presenting unverified assumptions as verified facts.

### 21.5 Reconciled Counting Model and Coverage

The addition of separated runtime mode, network stack, inbound processing, and global setting capabilities updates the canonical and engine metrics:

| Entity Unit | Phase 22 Count | Phase 23 Count | Phase 24 Count | Definition |
|---|---|---|---|---|
| **Canonical Capabilities** | 22 | 45 | **48** | Distinct protocol, stack, mode, and setting concepts independent of engine prefixes. |
| **Engine Capabilities** | 40 | 62 | **65** | Engine-specific capability entries (15 Xray + 15 sing-box + 30 Exclave + 1 WireGuard + 1 AmneziaWG + 2 OpenVPN + 1 Aether = 65). |
| **Profile Compatibilities** | 21 | 21 | **21** | Abstract engine-to-profile execution targets: 8 Xray + 8 sing-box + 1 WireGuard + 1 AmneziaWG + 2 OpenVPN + 1 Aether. |
| **Total Coverage Table Items** | **61** | **83** | **86** | Total coverage report entries (21 profile compatibilities + 65 engine capabilities). |
| **Parameter Definitions** | ~170 | 260 | **268** | Unique scoped parameter definitions across all profiles and capabilities. |
| **Parameter Variants** | 36 | 36 | **36** | Pre-configured parameter variants across protocol profiles. |
| **Compatibility Rules** | ~26 | 53 | **53** | Parameter constraints, limitations, and engine conflict rules. |

### 21.6 Category Filtering and CLI Enhancements

The CLI commands `connscope catalog coverage` and `connscope matrix coverage` support filtering by taxonomy category:
- Filter by category: `connscope catalog coverage --category runtime_mode`
- Filter by category and JSON: `connscope catalog coverage --category network_stack --json`
- The rendered table output includes a dedicated "Coverage Statistics by Category" summary table.
- All 30 Exclave capabilities maintain `is_executable = False` and `status = VerificationStatus.CATALOGUED` with documented host execution limitations.

---

## 22. Phase 25 — Parameter-Space Coverage and Executable Scenario Generation

### 22.1 Overview and Architecture

Building upon Phases 21–24, Phase 25 advances ConnScope from high-level profile compatibility to rigorous, engine-grounded **parameter-space coverage and executable scenario generation**. 

Rather than treating the catalog as a static specification, ConnScope now systematically exercises every applicable, source-verified parameter across the eight executable profile families for `Xray-core` and `sing-box`, within the bounds of real local engine versions.

Key architectural achievements in Phase 25:
1. **Accurate Parameter Denominators**: Establishes per-profile, engine-specific parameter denominators based strictly on what is architecturally applicable to that protocol, transport, and security mode.
2. **Nine Independent Verification Stages**: Parameter coverage is no longer binary; every parameter is tracked across nine verification milestones from source verification to live network testing.
3. **Deterministic Parameter Matrix Generation**: Reusable generation engines for One-Factor-At-A-Time (OFAT) and Pairwise (2-way combinatorial) parameter planning with rich metadata annotations and secret redaction.
4. **Offline Binary Validation Harness**: Automated configuration validation leveraging real local binaries (`xray run -test -c` and `sing-box check -c`) in isolated temporary workspaces without binding live network ports or disturbing background processes.
5. **CLI Integration**: Native commands `connscope catalog parameter-coverage` and `connscope matrix preview-parameters`.

### 22.2 The Nine Verification Stages

ConnScope defines nine independent, monotonically evaluated verification stages for every parameter via [`ParameterCoverageStage`](../src/connscope/scenarios/parameter_coverage.py):

| Stage | Identifier | Scope & Meaning |
|---|---|---|
| 1 | `source_verified` | Verified against authoritative upstream source code or official specification documents. |
| 2 | `schema_defined` | Formally modeled in ConnScope's `ParameterDefinition` schema with type, default, and allowed constraints. |
| 3 | `constraints_validated` | Type bounds, regex constraints, and enum sets are validated via `ParameterDefinition.validate()`. |
| 4 | `config_mapped` | Mapped to engine configuration keys in `XrayConfigBuilder` or `SingBoxConfigBuilder`. |
| 5 | `config_generated` | Successfully rendered into an engine-specific JSON configuration structure. |
| 6 | `binary_validated` | Validated by the real local engine binary (`xray run -test -c` or `sing-box check -c`). |
| 7 | `scenario_generated` | Integrated into executable test plans via `ScenarioGenerator` with full metadata annotations. |
| 8 | `invalid_tested` | Negative test variants verify that out-of-range or malformed inputs are correctly rejected. |
| 9 | `live_verified` | Validated end-to-end with live socket connectivity through active proxy servers. |

ConnScope strictly distinguishes offline configuration validation (`binary_validated`) from live network verification (`live_verified`), guaranteeing honest and verifiable reporting.

### 22.3 Genuine Parameter Denominators across Executable Profiles

Parameters belonging to other transports, protocols, or engine features are excluded from the denominator of a given profile. ConnScope evaluates 16 engine/profile combinations across the eight profile families:

| Engine | Protocol Profile | Evaluated | Applicable Denominator | Covered | Uncovered | Implementation Coverage |
|---|---|---|---|---|---|---|
| **sing-box** | `vless_tcp_reality` | 14 | **13** | 13 | 0 | 100.0% |
| **sing-box** | `vless_tcp_tls` | 11 | **11** | 11 | 0 | 100.0% |
| **sing-box** | `vless_tcp_none` | 4 | **4** | 4 | 0 | 100.0% |
| **sing-box** | `vless_ws_tls` | 13 | **13** | 13 | 0 | 100.0% |
| **sing-box** | `vless_grpc_tls` | 13 | **12** | 12 | 0 | 100.0% |
| **sing-box** | `vmess_ws_tls` | 16 | **16** | 16 | 0 | 100.0% |
| **sing-box** | `trojan_tcp_tls` | 10 | **10** | 10 | 0 | 100.0% |
| **sing-box** | `shadowsocks_tcp` | 6 | **5** | 5 | 0 | 100.0% |
| **Xray** | `vless_tcp_reality` | 14 | **14** | 14 | 0 | 100.0% |
| **Xray** | `vless_tcp_tls` | 11 | **11** | 11 | 0 | 100.0% |
| **Xray** | `vless_tcp_none` | 4 | **4** | 4 | 0 | 100.0% |
| **Xray** | `vless_ws_tls` | 13 | **13** | 13 | 0 | 100.0% |
| **Xray** | `vless_grpc_tls` | 13 | **13** | 13 | 0 | 100.0% |
| **Xray** | `vmess_ws_tls` | 16 | **16** | 16 | 0 | 100.0% |
| **Xray** | `trojan_tcp_tls` | 10 | **10** | 10 | 0 | 100.0% |
| **Xray** | `shadowsocks_tcp` | 6 | **6** | 6 | 0 | 100.0% |
| **TOTALS** | *(16 combinations)* | 174 | **171** | **171** | **0** | **100.0%** |

#### Parameter Breakdown by Category
- **Auth & Encryption** (26 parameters): `uuid`, `password`, `method`, `alter_id`, `security`.
- **Security & TLS** (73 parameters): `server_name`, `fingerprint`, `alpn`, `min_version`, `max_version`, `verify_cert`, `public_key`, `short_id`.
- **Transport** (33 parameters): `path`, `host_header`, `service_name`, `idle_timeout_s`, `ping_timeout_s`, `tcp_fast_open`, `max_early_data`, `early_data_header_name`, `spider_x`.
- **Multiplexing** (32 parameters): `mux_enabled`, `mux_concurrency`.
- **Network Behavior** (7 parameters): `flow`, `packet_encoding`, `uot`.

#### Engine-Specific Exclusions from Denominators
Three parameters are catalogued on specific profile families but are legitimately unsupported by sing-box outbounds, and thus properly excluded from sing-box's denominator:
1. `spider_x` on `vless_tcp_reality`: Unsupported in sing-box REALITY outbounds (sing-box does not accept crawler path configuration).
2. `multi_mode` on `vless_grpc_tls`: Unsupported in sing-box gRPC outbounds (sing-box standardizes on standard gRPC framing).
3. `uot` on `shadowsocks_tcp`: UDP-over-TCP is not implemented in sing-box Shadowsocks outbounds.

### 22.4 Engine-Specific Version Discoveries from Real-Binary Validation

ConnScope executes binary test validation against real local executables discovered in the execution environment:
- **Xray-core**: `v26.3.27` (`/usr/local/bin/xray`)
- **sing-box**: `v1.12.12` (`/home/arshiacomplus/ACP-Portable/tools/proxy/bin/sing-box`)

During real-binary configuration testing (`xray run -test -c` and `sing-box check -c`), several subtle engine-version characteristics were surfaced and accommodated:

1. **Xray v26+ TLS Insecure Deprecation**:
   - In modern Xray (v26.3.27+), `allowInsecure: true` in `tlsSettings` has been permanently removed upstream. Xray rejects configurations with `allowInsecure: true` with the error `tls: allowInsecure is removed, use pinnedPeerCertificateSha256List or pinnedPeerCertificateChainSha256List instead`.
   - Consequently, ConnScope maps `verify_cert: True` to `allowInsecure: false` (or omits it), while `verify_cert: False` cleanly triggers real binary validation failure.
2. **sing-box `packet_encoding` Values**:
   - In sing-box v1.12.12 VMess outbounds, `packet_encoding` accepts `""`, `"packetaddr"`, and `"xudp"`. The string literal `"none"` is strictly rejected as `unknown packet encoding: none`.
3. **Shadowsocks 2022 Key Enforcement**:
   - Shadowsocks 2022 ciphers strictly validate key lengths: 16 bytes (Base64) for `2022-blake3-aes-128-gcm` and 32 bytes for `2022-blake3-aes-256-gcm`. Standard non-2022 ciphers (`aes-128-gcm`) accept arbitrary passwords.
4. **REALITY Public Key Formatting**:
   - Xray requires a valid Curve25519 public key (Base64-URL encoded 32 bytes). Random ASCII strings trigger exit code 23 (`failed to parse REALITY public key`).

### 22.5 Systematic Parameter-Variant Generator

[`ScenarioGenerator`](../src/connscope/scenarios/generator.py) provides [`generate_parameter_matrix()`](../src/connscope/scenarios/generator.py#L615-L780) supporting both OFAT and Pairwise strategies:

- **OFAT Strategy**:
  - Sets all applicable parameters to profile baseline defaults.
  - Varies one parameter at a time across its discrete domain (e.g., trying all allowed TLS fingerprints: `chrome`, `safari`, `firefox`, `ios`, `android`, `edge`).
  - Annotates each scenario with rich metadata: `is_baseline`, `varied_factor`, `parameter_name`, `parameter_value`, `parameter_category`, `expected_validation_stage`, and `applicable_constraints`.
- **Pairwise Strategy**:
  - Implements orthogonal 2-way combinatorial parameter coverage.
  - Generates compact, bounded test suites covering all pairs of parameter settings across multiple dimensions simultaneously.
  - Annotates each scenario with `pairwise_vector` capturing the complete multi-factor assignment.
- **Negative Input & Rejection Testing**:
  - When `include_invalid=True`, deliberately generates invalid parameter scenarios (e.g., invalid UUID strings, odd-length hex short IDs, negative multiplexing concurrency).
  - Explicitly marks invalid scenarios with `is_valid=False`, captures the exact schema rejection reason in `exclusion_reason`, and sets `expected_validation_stage="pre_execution_validation"`.
- **Credential Protection**:
  - Secret fields (`uuid`, `password`, `public_key`) are automatically sanitized to `[REDACTED]` in scenario summaries and serialized payloads, preventing credential leakage in logs.

### 22.6 CLI Tooling and Automated Reports

Two CLI commands provide complete operator visibility into parameter coverage and matrix previewing:

```bash
# Display full parameter-space coverage report across all 8 profile families
connscope catalog parameter-coverage

# Filter coverage report to sing-box and output JSON
connscope catalog parameter-coverage --engine sing_box --json

# Preview OFAT parameter scenarios for Xray VLESS TCP REALITY
connscope matrix preview-parameters --engine xray --profile vless_tcp_reality --strategy ofat

# Preview OFAT scenarios including negative/invalid rejection tests
connscope matrix preview-parameters --engine xray --profile vless_tcp_reality --strategy ofat --include-invalid

# Preview pairwise parameter scenarios for sing-box VMess WS TLS as JSON
connscope matrix preview-parameters --engine sing_box --profile vmess_ws_tls --strategy pairwise --json
```

---

## 23. Phase 26: End-to-End MVP and Release Readiness

Phase 26 moves ConnScope toward its initial usable release by validating a complete, robust end-to-end measurement workflow. Rather than expanding protocol definitions broadly, Phase 26 hardens the execution pipeline from environment discovery and input validation to live external process management, proxy readiness probing, application-level transfer verification, structured metric extraction, secret redaction, and deterministic serialization.

### 23.1 Complete Measurement Workflow

The validated workflow follows a deterministic lifecycle:

```mermaid
flowchart TD
    A["1. Discovery: connscope catalog check"] --> B["2. Input & Compatibility Validation"]
    B --> C["3. Dry-Run Planning: connscope matrix preview"]
    C --> D["4. Authorized Execution: connscope matrix run --execute"]
    D --> E["5. Ephemeral Inbound / Outbound Setup"]
    E --> F["6. Proxy Readiness Verification (SOCKS5 Handshake)"]
    F --> G["7. Application Transfer (HTTP 204 via Proxy)"]
    G --> H["8. Metric Extraction & Secret Redaction"]
    H --> I["9. Export (JSON Lines & Summary JSON)"]
    I --> J["10. Operator Summary (Terminal Table)"]
```

1. **Environment Discovery**: [`connscope catalog check`](../src/connscope/cli/main.py#L243-L246) audits available host binaries (`xray`, `sing-box`), extracts their exact versions, and evaluates profile execution readiness across the 8 standard profile families.
2. **Pre-Execution Validation**: Ensures requested parameters conform to schema and engine capabilities before launching external binaries. Engine-specific unsupported flags (e.g. `verify_cert=False` on modern Xray v26+, Shadowsocks UOT on sing-box, gRPC `multi_mode` on sing-box) are rejected pre-execution with actionable error diagnostics.
3. **Dry-Run Planning**: By default, `connscope matrix run` and `connscope matrix preview` operate in dry-run mode, producing scenario counts and execution plans without spawning external processes.
4. **Authorized Execution**: External proxy client processes are spawned only when the `--execute` flag is explicitly provided.
5. **Proxy Readiness Verification**: Binds ephemeral loopback ports (avoiding any collision with system ports such as `10808`), starts the engine client, and performs a non-blocking SOCKS5 handshake probe to ensure proxy readiness within bounded timeouts.
6. **Application Transfer**: Sends an HTTP GET request to the test URL (defaulting to Cloudflare HTTP 204 endpoint or local diagnostic mock) through the local SOCKS5 proxy, verifying real end-to-end data transfer.
7. **Metric Extraction & Redaction**: Captures `local_ready_ms`, `handshake_ms`, `data_transfer_ms`, and `total_ms`. Masks sensitive credentials (`uuid`, `password`, `public_key`) to `[REDACTED]` in scenario summaries and serialized records.
8. **Deterministic Result Export**: Outputs records to JSON Lines format (`--jsonl`) and summary JSON (`--summary-file`) adhering to the existing measurement contracts.
9. **Human-Readable Summary**: Distinguishes successes, failures, timeouts, and excluded scenarios with failure stage categorization (`handshake`, `process`, `capability_unavailable`).

### 23.2 Local Diagnostic Harness

To validate the execution path locally without remote dependencies or external network requirements, [`LocalDiagnosticHarness`](../src/connscope/scenarios/diagnostic_harness.py) provides a controlled loopback test environment:

- **Ephemeral Port Allocation**: Uses OS-assigned dynamic ports (`bind(("127.0.0.1", 0))`) with a strict safety guard that asserts allocated ports never match protected local ports (`10808`).
- **Mock HTTP Server**: An in-process HTTP server listening on loopback that serves HTTP 204 responses to test URLs.
- **Inbound Protocol Server**: Spawns an isolated Xray or sing-box inbound receiver configured for `vless_tcp_none` with a synthetic diagnostic UUID (`23ad3b37-8de4-4e7b-a3e8-e538b30b4f70`).
- **Guaranteed Cleanup**: Employs context manager lifecycle hooks (`__enter__` / `__exit__`) that terminate process trees (`SIGTERM`, then `SIGKILL` on timeout) and close socket listeners upon completion or failure.
- **Diagnostic Transparency**: Clearly labels plaintext loopback testing as diagnostic (`vless_tcp_none`), explicitly separating local functional verification from encrypted production transports.

### 23.3 Parameter Verification & Engine Version Constraints

Phase 26 resolves parameter compatibility issues identified during real binary testing:

- **Xray v26+ TLS Deprecation**: Upstream Xray permanently removed `allowInsecure: true` in `tlsSettings`. Xray v26.3.27 strictly fails configuration checks when `allowInsecure: true` is passed. ConnScope rejects `verify_cert=False` on Xray TLS profiles pre-execution with the message:
  `Engine 'xray' (v26+) does not support disabling certificate verification ('verify_cert=False') because 'allowInsecure' was permanently removed upstream; certificate verification must remain enabled.`
- **sing-box Outbound Parameter Bounds**:
  - `uot=True`: Shadowsocks UOT (UDP over TCP) is rejected pre-execution for sing-box client outbounds.
  - `multi_mode=True`: gRPC multi_mode is rejected pre-execution for sing-box.
  - `packet_encoding='none'`: sing-box requires `packetaddr` or `xudp` for VMess packet encoding; literal `"none"` is rejected pre-execution.
  - `spiderX`: REALITY spider crawler paths other than `"/"` or `""` are rejected pre-execution for sing-box.
- **Invalid-Input Isolation**: Scenarios testing invalid inputs are tracked under negative validation rather than claimed as valid executable parameter coverage.

### 23.4 Operator Quick-Start Guide

Operators can run the verified workflow through the CLI:

```bash
# 1. Check local environment and engine readiness
connscope catalog check

# 2. Check environment in JSON format
connscope catalog check --json

# 3. Preview scenario execution plan (dry-run, 0 processes spawned)
connscope matrix preview --engine xray --profile vless_tcp_none

# 4. Dry-run planning with diagnostic harness
connscope matrix run --engine xray --profile vless_tcp_none --local-diagnostic

# 5. Execute end-to-end measurement with local diagnostic harness (verified HTTP 204 transfer)
connscope matrix run --engine xray --profile vless_tcp_none --local-diagnostic --execute

# 6. Execute sing-box local diagnostic measurement
connscope matrix run --engine sing_box --profile vless_tcp_none --local-diagnostic --execute

# 7. Execute with JSON Lines and summary file export
connscope matrix run --engine xray --profile vless_tcp_none --local-diagnostic --execute \
  --jsonl /tmp/records.jsonl --summary-file /tmp/summary.json

# 8. Execute against operator-supplied secure endpoint
connscope matrix run --engine xray --profile vless_tcp_reality \
  --target example.com:443 \
  --config '{"uuid": "...", "public_key": "...", "short_id": "...", "server_name": "example.com"}' \
  --test-url "http://cp.cloudflare.com/generate_204" \
  --execute
```

### 23.5 Evidence Hierarchy & Limitations

ConnScope maintains a strict taxonomy of evidence levels:

| Level | Identifier | Meaning |
|---|---|---|
| **Level 0** | `CATALOGUED` | Profile/parameter documented in catalog schemas. |
| **Level 1** | `CONFIG_VALIDATION_IMPLEMENTED` | Python configuration builder validates inputs against schema. |
| **Level 2** | `REAL_ENGINE_INTEGRATION_TESTED` | Engine binary (`xray run -test -c` or `sing-box check -c`) parses configuration successfully. |
| **Level 3** | `REAL_TUNNEL_VERIFIED` | Client proxy process launches and completes SOCKS5 loopback handshake. |
| **Level 4** | `REAL_DATA_TRANSFER_TESTED` | End-to-end application transfer (HTTP 204) completes through established proxy. |

**Known Limitations**:
- Local diagnostic execution uses `vless_tcp_none` for loopback functional testing; it does not replace secure TLS/REALITY testing against real servers.
- When evaluating TLS profiles without an operator-supplied server, live data transfer cannot be completed without a listening TLS server.
- Xray v26.3.27 and sing-box v1.12.12 binaries are verified on Linux x86_64; Windows/macOS execution paths remain mock-tested.

---

## 24. Phase 27: v0.1.0 Release Candidate and Packaging Validation

Phase 27 finalizes ConnScope for its first versioned release (`v0.1.0`). This phase establishes clean packaging, offline distribution validation, isolated virtual environment smoke tests, and precise evidence semantics.

### 24.1 Packaging Configuration and Distribution Artifacts

ConnScope packaging is configured via standard PEP 621 metadata in [`pyproject.toml`](../pyproject.toml) using the `setuptools.build_meta` build backend:

- **Built Distribution (Wheel)**: `dist/connscope-0.1.0-py3-none-any.whl` (pure-Python, platform-independent wheel).
- **Source Distribution (sdist)**: `dist/connscope-0.1.0.tar.gz`.
- **CLI Entry Points**:
  - Console script entry point: `connscope = connscope.cli.main:main`.
  - Module entry points: `python -m connscope` via [`src/connscope/__main__.py`](../src/connscope/__main__.py) and `python -m connscope.cli` via [`src/connscope/cli/__main__.py`](../src/connscope/cli/__main__.py).
- **Runtime Dependency Invariant**:
  - The core framework requires zero third-party dependencies (`dependencies = []`).
  - Development tools (`pytest`, `pytest-asyncio`) are optional extras (`[project.optional-dependencies] dev`).
- **Import Side-Effect Invariant**:
  - Importing `connscope`, `connscope.cli.main`, `connscope.adapters`, or `connscope.scenarios` binds zero network sockets, spawns zero subprocesses, and makes zero network calls.

### 24.2 Clean Installation Smoke Test

The packaged wheel was validated through an automated clean-installation smoke test in an isolated virtual environment (`/tmp/test_connscope_venv`) executed from an external directory (`/tmp`):

```bash
# 1. Build distribution artifacts offline
python3 -m pip wheel --no-deps --no-build-isolation -w dist .

# 2. Create isolated virtual environment
python3 -m venv /tmp/test_connscope_venv

# 3. Install wheel strictly offline without internet access
/tmp/test_connscope_venv/bin/pip install --no-index --find-links=dist connscope

# 4. Verify CLI from outside the repository
cd /tmp
/tmp/test_connscope_venv/bin/connscope --help
/tmp/test_connscope_venv/bin/connscope catalog check
/tmp/test_connscope_venv/bin/connscope catalog coverage
/tmp/test_connscope_venv/bin/connscope matrix preview --engine xray --profile vless_tcp_none
/tmp/test_connscope_venv/bin/connscope matrix run --engine xray --profile vless_tcp_none \
  --local-diagnostic --execute --jsonl /tmp/clean_records.jsonl --summary-file /tmp/clean_summary.json
```

**Verification Results**:
- Entry points execute reliably from directories outside the repository root.
- Python imports and version resolution (`__version__ == "0.1.0"`) work without editable install hooks.
- Output JSONL records and summary JSON files serialize deterministically with credential fields redacted (`[REDACTED]`).
- Unknown engine/profile arguments and missing binary prerequisites produce clean, actionable CLI errors.

### 24.3 Accurate Evidence Semantics & Status Disambiguation

Phase 27 hardens the evidence taxonomy by formally distinguishing local diagnostic loopback execution from live remote internet performance:

```mermaid
flowchart TD
    subgraph Offline_Validation["Offline & Syntactic Validation"]
        L0["Level 0: CATALOGUED<br/>(Schema entry present)"]
        L1["Level 1: CONFIG_VALIDATION_IMPLEMENTED<br/>(Python builder validates params)"]
        L2["Level 2: REAL_BINARY_CONFIG_VALIDATED<br/>(Engine check -c accepts config)"]
    end

    subgraph Local_Execution["Local Pipeline Validation"]
        L3["Level 3: LOCAL_DIAGNOSTIC_VERIFIED<br/>(Loopback proxy & HTTP 204 transfer)"]
    end

    subgraph Remote_Execution["Remote Internet Validation"]
        L4["Level 4: REAL_TUNNEL_VERIFIED<br/>(Proxy handshake with remote server)"]
        L5["Level 5: REAL_DATA_TRANSFER_TESTED<br/>(Application transfer through remote proxy)"]
    end

    L0 --> L1 --> L2 --> L3
    L2 -.->|Operator Endpoint| L4 --> L5
```

- **Formal Evidence Status**: Added [`VerificationStatus.LOCAL_DIAGNOSTIC_VERIFIED`](../src/connscope/scenarios/models.py#L27) (`"local_diagnostic_verified"`) and [`AdapterStatus.LOCAL_DIAGNOSTIC_VERIFIED`](../src/connscope/adapters/models.py#L96).
- **Execution Mode Tracking**: Records executed via `LocalDiagnosticHarness` set `execution_mode = "local_diagnostic"` and `evidence_status = "local_diagnostic_verified"`.
- **Timing Disclaimers**: Local diagnostic loopback timings reflect process startup and OS loopback overhead. ConnScope records clearly separate these from internet transit benchmarks.

### 24.4 Defined Scope for v0.1.0 Release

1. **Ready for General Local Use**:
   - Capability & parameter catalog (`connscope catalog list`, `show`, `coverage`, `parameter-coverage`, `check`).
   - Scenario matrix generator (`connscope matrix preview`, `estimate`, `preview-parameters`).
   - Basic network probes (`connscope run tcp|dns|tls|http`).
   - Input validation, dry-run planning, and configuration compilation for Xray and sing-box.
2. **Validated by Tests & Local Diagnostic Harness**:
   - End-to-end execution pipeline for Xray-core (`vless_tcp_none`) and sing-box (`vless_tcp_none`) with verified HTTP 204 data transfer on Linux x86_64.
3. **Requiring Operator-Supplied Remote Endpoint**:
   - Production encrypted proxy profiles (`vless_tcp_reality`, `vless_tcp_tls`, `vless_ws_tls`, `vless_grpc_tls`, `vmess_ws_tls`, `trojan_tcp_tls`, `shadowsocks_tcp`).
4. **Catalogued But Non-Executable on Linux Host**:
   - Android-specific Exclave features (requires Android routing or headless daemon extraction).
   - Aether declarative capabilities (awaiting upstream source confirmation).
   - Kernel WireGuard / AmneziaWG TUN interface creation (requires root/CAP_NET_ADMIN opt-in).














