# Local Diagnostic Harness Guide

Comprehensive operational guide for ConnScope's hermetic loopback diagnostic testing harness.

---

## 1. Overview & Purpose

Testing proxy engine execution usually requires an external proxy server, incurring network variability, firewall interference, or dependency on live infrastructure.

ConnScope solves this with the **Local Diagnostic Harness** (`LocalDiagnosticHarness`). It establishes a self-contained, hermetic loopback testing pipeline entirely within the local host:
1. Allocates an ephemeral loopback port (`127.0.0.1:0`) and starts an in-memory HTTP mock server that responds immediately with HTTP `204 No Content`.
2. Generates an engine client configuration (`vless_tcp_none`) pointing to an ephemeral server inbound.
3. Allocates a second ephemeral port for the client's SOCKS5 inbound.
4. Launches the engine client subprocess, verifies inbound socket readiness, and executes an HTTP probe through the local SOCKS5 proxy to the local HTTP 204 mock endpoint.
5. Verifies end-to-end data transfer, records timing metrics, and terminates all processes and sockets cleanly.

---

## 2. Prerequisites & Dependencies

- Python 3.11+ standard library.
- Either `xray` (v26.3.27+) or `sing-box` (v1.12.12+) installed on `PATH`.
- Permission to bind sockets to `127.0.0.1`.
- **Zero internet access required** — all traffic remains strictly inside the loopback interface (`lo`).

---

## 3. Conceptual Model & Terminology

- **Hermetic Testing**: Completely isolated test execution where external network conditions cannot alter results.
- **Ephemeral Port**: Sockets bound with port `0`, instructing the operating system kernel to allocate an available dynamic port, eliminating port collision risks.
- **HTTP 204 Mock**: Lightweight HTTP server that returns `HTTP/1.1 204 No Content` upon receiving a valid GET request.
- **Evidence Level `local_diagnostic_verified`**: Formal verification status confirming the engine launched, bound ports, routed traffic, and completed application-level payload transfer, while explicitly denoting that results were gathered over loopback rather than the internet.

---

## 4. Supported vs. Unsupported Matrix

| Capability | Status | Notes |
|---|---|---|
| Zero Internet Dependency | Supported | Fully functional offline |
| Xray-core Client Verification | Supported | Verified with v26.3.27 |
| sing-box Client Verification | Supported | Verified with v1.12.12 |
| Port Collision Avoidance | Guaranteed | Dynamic OS-assigned ports only |
| Intercepting Existing Sockets | Prohibited | Never touches or binds active host ports (e.g. `10808`) |
| Real Remote Encrypted Handshakes | Unsupported | REALITY, TLS, and WS require live remote endpoints |
| Benchmarking Internet Latency | Prohibited | Loopback timings represent process overhead, not ISP latency |

---

## 5. Step-by-Step Usage & Commands

### Running Diagnostic with Xray

```bash
connscope matrix run \
  --engine xray \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute
```

### Running Diagnostic with sing-box

```bash
connscope matrix run \
  --engine sing_box \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute
```

### Previewing Diagnostic Plan (Dry-Run)

```bash
connscope matrix preview \
  --engine xray \
  --profile vless_tcp_none \
  --local-diagnostic
```

### Exporting Diagnostic Records and Summaries

```bash
connscope matrix run \
  --engine xray \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute \
  --output-file /tmp/diag.jsonl \
  --summary-file /tmp/diag-summary.json
```

---

## 6. Real-World Examples & Output Interpretation

### Example: Diagnostic Run Record

```json
{
  "scenario_id": "xray-vless_tcp_none-diagnostic-001",
  "engine": "xray",
  "profile": "vless_tcp_none",
  "status": "SUCCESS",
  "evidence_status": "local_diagnostic_verified",
  "execution_mode": "local_diagnostic",
  "target": "127.0.0.1:41893",
  "proxy_inbound_port": 38102,
  "timing_ms": {
    "engine_spawn_ms": 5.2,
    "port_ready_ms": 21.4,
    "tcp_handshake_ms": 0.8,
    "http_ttfb_ms": 1.9,
    "total_elapsed_ms": 412.0
  },
  "http_response": {
    "status_code": 204,
    "content_length": 0
  }
}
```

Interpretation:
- `evidence_status`: Strictly tagged as `local_diagnostic_verified`.
- `target`: The ephemeral port where the local HTTP 204 mock was listening.
- `proxy_inbound_port`: The ephemeral loopback port where Xray accepted SOCKS5 traffic.
- `http_response.status_code`: Confirms application transfer was complete and returned 204.

---

## 7. Configuration & Parameter Reference

Diagnostic mode uses standardized parameters:

| Parameter | Default Value | Description |
|---|---|---|
| `uuid` | Fixed diagnostic UUID | Deterministic test UUID |
| `target` | Dynamic (`127.0.0.1:<ephemeral>`) | Mock server address |
| `test_url` | `http://127.0.0.1:<ephemeral>/diagnostic_204` | Diagnostic endpoint URL |
| `proxy_type` | `socks5` | Local inbound protocol |

---

## 8. Error Handling & Common Failure Modes

| Error | Cause | Remediation |
|---|---|---|
| `MockServerBindError` | System denied loopback socket binding | Check firewall rules on `127.0.0.1` |
| `InboundTimeoutError` | Engine binary failed to start within timeout | Verify engine binary permissions |
| `HTTPStatusMismatch` | Mock returned unexpected status code | Check for local proxy interception |

---

## 9. Verification & Evidence Semantics

> [!IMPORTANT]
> Measurements gathered using `--local-diagnostic` verify **software integration and engine lifecycle correctness**. They prove that the engine binary runs, parses configurations, establishes local proxies, and handles application transfers.
>
> However, because latency is measured entirely across the kernel loopback device (`lo`), **these timings must never be presented as internet network performance metrics**.

---

## 10. Related Guides & Next Steps

- [Evidence Hierarchy & Verification Semantics](../reference/evidence-levels.md) — How diagnostic evidence maps to formal levels.
- [Engine Adapters & Process Lifecycle](engine-adapters.md) — Subprocess execution architecture.
- [Quickstart Guide](../quickstart.md) — 30-second quickstart using local diagnostics.
