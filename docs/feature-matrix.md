# ConnScope Feature & Profile Matrix

This document provides a comprehensive capability and support matrix across engines, profile families, parameters, probes, and verification levels in ConnScope v0.1.0.

---

## 1. Engine & Profile Compatibility Matrix

ConnScope currently models and supports 8 primary profile families across Xray-core and sing-box:

| Profile ID | Protocol | Transport | Security | Xray Support | sing-box Support | Config Validation | Binary Config Check | Local Diagnostic Execution |
|---|---|---|---|---|---|---|---|---|
| `vless_tcp_none` | VLESS | TCP | None (Plaintext) | Full | Full | Yes | Yes (v26.3.27) | Yes (v1.12.12) |
| `vless_tcp_reality` | VLESS | TCP | REALITY | Full | Full | Yes | Yes (v26.3.27) | Requires remote endpoint |
| `vmess_ws_tls` | VMess | WebSocket | TLS | Full | Full | Yes | Yes (v26.3.27) | Requires remote endpoint |
| `trojan_tcp_tls` | Trojan | TCP | TLS | Full | Full | Yes | Yes (v26.3.27) | Requires remote endpoint |
| `shadowsocks_tcp_none` | Shadowsocks | TCP | None (AEAD) | Full | Full | Yes | Yes (v26.3.27) | Requires remote endpoint |
| `wireguard_udp_none` | WireGuard | UDP | None (Noise) | Config / Adapter | Config / Adapter | Yes | Yes | Requires root / CAP_NET_ADMIN |
| `openvpn_tcp_none` | OpenVPN | TCP | TLS / OpenVPN | Config / Adapter | Config / Adapter | Yes | Yes | Safety policy disabled |
| `amneziawg_udp_none` | AmneziaWG | UDP | Obfuscated Noise | Config / Adapter | Config / Adapter | Yes | Yes | Requires root / CAP_NET_ADMIN |

---

## 2. Parameter Support by Profile

| Profile ID | Supported Parameters | Parameter Schema Constraints | Redacted in Logs |
|---|---|---|---|
| `vless_tcp_none` | `uuid`, `flow`, `packet_encoding` | Valid UUID format, flow empty or `xtls-rprx-vision` | `uuid` (`[REDACTED]`) |
| `vless_tcp_reality` | `uuid`, `flow`, `server_name`, `public_key`, `short_id`, `fingerprint`, `spider_x` | Non-empty strings, realistic base64 / hex formats | `uuid`, `public_key`, `short_id` |
| `vmess_ws_tls` | `uuid`, `alter_id`, `security`, `path`, `host`, `server_name`, `allow_insecure` | Valid UUID, integer `alter_id >= 0`, URI path | `uuid` |
| `trojan_tcp_tls` | `password`, `server_name`, `allow_insecure`, `alpn` | Non-empty password, valid hostname, ALPN list | `password` |
| `shadowsocks_tcp_none` | `method`, `password`, `plugin`, `plugin_opts` | Standard AEAD methods (`2022-blake3-aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`) | `password` |
| `wireguard_udp_none` | `private_key`, `public_key`, `local_address`, `endpoint`, `mtu` | Valid Base64 32-byte keys, valid CIDR / IP | `private_key`, `psk` |
| `openvpn_tcp_none` | `username`, `password`, `ca_cert`, `client_cert`, `client_key`, `cipher` | Non-empty credentials, valid OpenVPN ciphers | `username`, `password`, `client_key` |
| `amneziawg_udp_none` | `private_key`, `public_key`, `jc`, `jmin`, `jmax`, `s1`, `s2`, `h1`, `h2` | Base64 keys, junk packet integers within protocol bounds | `private_key` |

---

## 3. Protocol Catalog Taxonomy Coverage

Beyond the 8 executable profiles, ConnScope's catalog maintains source-verified capability schemas for extended protocol suites:

| Category | Canonical Protocols | Documented Engines | Status in v0.1.0 |
|---|---|---|---|
| **Proxy Protocols** | VLESS, VMess, Trojan, Shadowsocks, SOCKS5, HTTP | Xray-core, sing-box | Full schema modeling & execution |
| **Tunnel Protocols** | WireGuard, AmneziaWG, OpenVPN, TUN | WireGuard-tools, Amnezia-tools, OpenVPN | Schema modeled & mock tested |
| **Specialized Stacks** | Exclave (v0.17.66 / commit `71ae3bc007018804c7760fa0f54546522c7104b2`), Aether | Android native, Exclave CLI | Schema modeled; headless Linux execution awaiting upstream release |
| **Transport Layers** | TCP, UDP, WebSocket, gRPC, HTTP/2, QUIC | Xray-core, sing-box | Supported across applicable profiles |
| **Security Layers** | TLS, REALITY, ShadowTLS, None | Xray-core, sing-box | Supported across applicable profiles |

---

## 4. Measurement Probes Matrix

| Probe | Command / Alias | Target Specification | Measured Metrics | Execution Contexts |
|---|---|---|---|---|
| **TCP Connect** | `tcp`, `tcp_connect` | `host:port` (e.g. `1.1.1.1:443`) | Connect latency (ms), socket state, local port | Local, Remote Agent, Supervised Proxy |
| **DNS Resolve** | `dns`, `dns_resolve` | `hostname` (e.g. `example.com`) | Resolution latency (ms), A/AAAA records, TTL | Local, Remote Agent |
| **TLS Handshake** | `tls`, `tls_handshake` | `host:port` (e.g. `example.com:443`) | Handshake latency (ms), TLS version, cipher suite, cert expiration | Local, Remote Agent |
| **HTTP Request** | `http`, `http_request` | `http(s)://host/path` | TTFB, total duration, status code, response headers, body size | Local, Remote Agent, Supervised Proxy |

---

## 5. Evidence Verification Status Levels

ConnScope tags every measurement record with an explicit evidence status from the formal taxonomy:

| Level | Evidence Status | Applicable Command | Verification Guarantee |
|---|---|---|---|
| **Level 0** | `catalogued` | `connscope catalog list` | Capability is registered in canonical schemas. |
| **Level 1** | `config_validation_implemented` | `connscope catalog validate` | Configuration syntax, types, and constraints verified in Python. |
| **Level 2** | `real_binary_config_validated` | `connscope matrix preview-parameters --validate-binary` | Native engine executable (`xray run -test -c` or `sing-box check -c`) passed syntax validation. |
| **Level 3** | `local_diagnostic_verified` | `connscope matrix run --local-diagnostic --execute` | Subprocess launched, bound loopback SOCKS5 port, proxy handshake completed, and HTTP 204 received from local mock server. |
| **Level 4** | `real_tunnel_verified` | `connscope matrix run --execute` (with remote endpoint) | Proxy client completed handshake with remote server. |
| **Level 5** | `real_data_transfer_tested` | `connscope matrix run --execute` (with test URL) | Real payload transferred through remote proxy tunnel. |

---

## 6. Matrix Generation Strategies

| Strategy | Flag | Scenario Growth | Purpose |
|---|---|---|---|
| **Explicit** | `--mode explicit` | $N = 1$ | Test a single specific parameter combination or default configuration. |
| **OFAT** | `--mode ofat` | $O(\sum K_i)$ linear | One-Factor-At-A-Time: varies each parameter through allowed values while holding others at baseline. |
| **Pairwise** | `--mode pairwise` | $O(K^2)$ combinatorial | Orthogonal test coverage ensuring all 2-way parameter combinations are tested. |
| **Exhaustive** | `--mode exhaustive` | $\prod K_i$ exponential | Full Cartesian product across all parameter values (requires `--allow-exhaustive`). |
