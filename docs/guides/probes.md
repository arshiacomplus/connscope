# Basic Network Probes Guide

Comprehensive operational guide for ConnScope's standalone TCP, DNS, TLS, and HTTP network measurement probes.

---

## 1. Overview & Purpose

ConnScope includes four foundational network measurement probes implemented using standard Python libraries:
- **`tcp_connect`**: Measures socket connection time and verifies endpoint reachability at Layer 4.
- **`dns_resolve`**: Evaluates DNS resolution latency, query status, and record retrieval for A and AAAA records.
- **`tls_handshake`**: Measures TLS session negotiation duration, ALPN selection, and certificate validation.
- **`http_request`**: Measures application-layer metrics including Time To First Byte (TTFB), total transfer duration, response headers, and HTTP status codes.

These probes can be executed directly from the CLI against arbitrary internet hosts, delegated to remote Agent nodes, or routed through supervised proxy engine adapters.

---

## 2. Prerequisites & Dependencies

- Python 3.11+ standard library (`asyncio`, `socket`, `ssl`, `urllib`, `http.client`).
- Outbound network connectivity on the target ports (e.g. 53 for DNS, 80/443 for HTTP/TLS).
- No third-party packages or system daemon privileges are required.

---

## 3. Conceptual Model & Terminology

- **Target**: Structured representation of an endpoint. Formats include `host:port` (TCP/TLS), `hostname` (DNS), or `http(s)://host:port/path` (HTTP).
- **Timeout**: Floating-point value in seconds specifying the maximum allowable elapsed time before terminating the probe attempt.
- **Probe Result**: Immutable record capturing timestamp, duration, status (`SUCCESS`, `FAILED`, `TIMEOUT`), target, and probe-specific metric attributes.
- **SNI (Server Name Indication)**: TLS extension indicating the destination hostname during the handshake.

---

## 4. Supported vs. Unsupported Matrix

| Feature | TCP Connect | DNS Resolve | TLS Handshake | HTTP Request |
|---|---|---|---|---|
| IPv4 Targets | Supported | Supported | Supported | Supported |
| IPv6 Targets | Supported | Supported | Supported | Supported |
| Custom Timeout | Supported | Supported | Supported | Supported |
| SNI Customization | N/A | N/A | Supported (`--sni` / `--no-sni`) | Inherited from URL host |
| Custom HTTP Headers | N/A | N/A | N/A | Supported via `--config` |
| HTTP Methods | N/A | N/A | N/A | GET, POST, HEAD |
| SOCKS5 Inbound Routing | Supported | Supported | Supported | Supported |
| Raw ICMP Ping | Unsupported (requires raw sockets) | N/A | N/A | N/A |

---

## 5. Step-by-Step Usage & Commands

### Listing Available Probes

```bash
connscope probe list
# or
connscope list
```

### Running TCP Connect

```bash
# Connect to Cloudflare DNS over port 53
connscope run tcp 1.1.1.1:53

# Specify a 2.5 second timeout
connscope run tcp 1.1.1.1:53 --timeout 2.5
```

### Running DNS Resolution

```bash
connscope run dns example.com
```

### Running TLS Handshake

```bash
# Standard handshake with automatic SNI matching target
connscope run tls example.com:443

# Handshake with explicit custom SNI
connscope run tls 93.184.216.34:443 --sni example.com

# Handshake with SNI omitted
connscope run tls 93.184.216.34:443 --no-sni
```

### Running HTTP Request

```bash
# Basic HTTP GET
connscope run http https://example.com

# JSON formatted output
connscope run http https://example.com --json
```

---

## 6. Real-World Examples & Output Interpretation

### Example: TLS Handshake Output

Command:
```bash
connscope run tls example.com:443 --json
```

Output:
```json
{
  "probe": "tls_handshake",
  "target": "example.com:443",
  "status": "SUCCESS",
  "duration_ms": 34.2,
  "metrics": {
    "tls_version": "TLSv1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "alpn_protocol": "h2",
    "sni": "example.com",
    "cert_subject": "CN=example.com",
    "cert_valid_days_remaining": 82
  },
  "timestamp": "2026-10-28T12:00:00Z"
}
```

Interpretation:
- `duration_ms`: Total time elapsed in completing the cryptographic handshake.
- `alpn_protocol`: Negotiated application protocol (`h2` indicates HTTP/2 support).
- `status`: High-level execution status (`SUCCESS`).

---

## 7. Configuration & Parameter Reference

Probes accept configuration parameters via CLI flags or the `--config` option (JSON string or file path):

| Flag / Key | Type | Default | Description |
|---|---|---|---|
| `--timeout` | `float` | `5.0` | Socket/connection timeout in seconds. |
| `--sni` | `string` | Target host | Explicit TLS Server Name Indication. |
| `--no-sni` | `boolean` | `false` | Explicitly omit SNI extension in ClientHello. |
| `--node` | `string` | `None` | Remote Agent URL to execute probe remotely. |
| `--token` | `string` | `None` | Bearer token for Remote Agent authentication. |
| `method` (in `--config`) | `string` | `"GET"` | HTTP request method. |
| `headers` (in `--config`) | `object` | `{}` | Key-value mapping of custom HTTP headers. |

---

## 8. Error Handling & Common Failure Modes

| Error Condition | CLI Exit Code | Cause | Resolution |
|---|---|---|---|
| Target Connection Refused | `1` (`FAILED`) | Remote port closed or firewall rejected SYN | Verify remote host and port accessibility |
| Connection Timed Out | `2` (`TIMEOUT`) | Remote host dropped packets or routing blackhole | Increase `--timeout` or check network path |
| DNS NXDOMAIN | `1` (`FAILED`) | Hostname does not exist | Verify domain spelling and DNS server |
| TLS Certificate Invalid | `1` (`FAILED`) | Self-signed or expired certificate | Verify host domain or pass validation overrides |
| Malformed Target String | `3` (`USAGE_ERROR`) | Missing port in `host:port` format | Ensure target matches `host:port` or URL format |

---

## 9. Verification & Evidence Semantics

Standalone probe executions against direct internet endpoints yield standard Layer 4/7 measurements. When probes are run without proxy adapters, the evidence status is direct network observation. When probes are orchestrated via `connscope matrix run`, the probe results validate proxy readiness and application transfer according to the [Evidence Hierarchy](../reference/evidence-levels.md).

---

## 10. Related Guides & Next Steps

- [Remote Agent & Distributed Nodes](remote-agent.md) — Learn how to delegate probes to distributed remote worker agents.
- [CLI Reference Manual](../reference/cli.md) — Complete parameter and option reference.
- [Engine Adapters & Process Lifecycle](engine-adapters.md) — How probes are routed through local proxy instances.
