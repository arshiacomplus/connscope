# Quickstart Guide

This walkthrough gets you from zero to a fully verified local measurement in under 30 seconds.

---

## The 3-Step Quickstart

### Step 1: Check Engine Readiness

Audit your local environment for installed proxy engine binaries (`xray` and `sing-box`):

```bash
connscope catalog check
```

Expected terminal output:
```text
Engine Readiness Audit:
  xray:      FOUND (/usr/local/bin/xray, version: 26.3.27)
  sing_box:  FOUND (/usr/local/bin/sing-box, version: 1.12.12)

Supported Profile Families:
  Profile ID                 Xray Status    sing-box Status
  -------------------------  -------------  ---------------
  vless_tcp_none             READY          READY
  vless_tcp_reality          READY          READY
  vmess_ws_tls               READY          READY
  trojan_tcp_tls             READY          READY
  shadowsocks_tcp_none       READY          READY
  wireguard_udp_none         READY          READY
  openvpn_tcp_none           READY          READY
  amneziawg_udp_none         READY          READY
```

---

### Step 2: Preview Measurement Plan (Dry-Run Mode)

By default, ConnScope operates in dry-run mode. It generates the exact execution matrix and configuration parameters without starting external processes or touching network sockets:

```bash
connscope matrix preview --engine xray --profile vless_tcp_none
```

Output:
```text
Scenario Matrix Plan (1 scenario):
  [1] ID: xray-vless_tcp_none-001 | Engine: xray | Profile: vless_tcp_none | Target: 127.0.0.1:443
      Parameters: uuid="auto-generated", flow=None, packet_encoding=None
      Workload: HTTP GET http://cp.cloudflare.com/generate_204 via SOCKS5 proxy
```

---

### Step 3: Run Local Diagnostic Measurement

Execute an authorized end-to-end measurement using the hermetic loopback diagnostic harness. This pipeline launches the proxy engine on an ephemeral loopback port, starts an ephemeral HTTP 204 mock endpoint, routes an HTTP probe through the local SOCKS5 inbound, and records application-level transfer latency:

```bash
connscope matrix run \
  --engine xray \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute
```

> [!IMPORTANT]
> The `--execute` flag is an explicit opt-in safety guard. Without `--execute`, `connscope matrix run` defaults to dry-run planning and will not launch processes.

Expected output:
```text
Execution Summary:
  Total Planned Scenarios:  1
  Executed Scenarios:       1
  Successful:               1
  Failed:                   0
  Success Rate:             100.0%
  Duration:                 0.42s

Detailed Records:
  Scenario ID:              xray-vless_tcp_none-001
  Status:                   SUCCESS
  Evidence Status:          local_diagnostic_verified
  Execution Mode:           local_diagnostic
  Engine:                   xray
  Profile:                  vless_tcp_none
  TCP Handshake Time:       0.85 ms
  HTTP TTFB:                2.10 ms
  HTTP Status Code:         204
```

To run the exact same diagnostic workflow with `sing-box`:

```bash
connscope matrix run \
  --engine sing_box \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute
```

---

## Exporting Structured Results

To save machine-readable results for analysis, automated regression testing, or archiving, use the `--output-file` (or `--jsonl`) and `--summary-file` options:

```bash
connscope matrix run \
  --engine xray \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute \
  --output-file diagnostic-records.jsonl \
  --summary-file diagnostic-summary.json
```

- `diagnostic-records.jsonl`: One JSON object per scenario containing full timing metrics, engine metadata, redacted configs, and evidence status.
- `diagnostic-summary.json`: Aggregated summary statistics, pass/fail counts, total duration, and timestamp.

---

## Next Steps

- Review the [Local Diagnostic Harness Guide](guides/local-diagnostic.md) for architecture details on the loopback testing pipeline.
- Read [Evidence Hierarchy & Verification Semantics](reference/evidence-levels.md) to understand why loopback diagnostics are distinct from internet benchmarks.
- Learn how to generate multi-parameter matrices in [Parameter Scenarios](guides/parameter-scenarios.md).
