# Scenario Execution Coordinator Guide

Comprehensive operational guide for ConnScope's scenario execution coordinator and runtime orchestrator.

---

## 1. Overview & Purpose

The `ScenarioCoordinator` is the central operational engine responsible for translating planned scenario matrices into real, supervised adapter runs.

It orchestrates:
- Pre-flight engine binary verification.
- Safe dry-run defaults (requiring explicit `--execute` opt-in).
- Controlled bounded concurrency across multiple scenarios.
- Granular failure stage isolation (pinpointing whether a run failed during config synthesis, process launch, port readiness, workload probing, or teardown).
- Flexible failure policies (`continue` to complete the matrix or `stop` for rapid abort).
- Emission of structured measurement records and summary statistics.

---

## 2. Prerequisites & Dependencies

- Python 3.11+ standard library.
- For live execution, installed and executable proxy binaries (`xray` or `sing-box`).
- Ephemeral network socket binding permissions on `127.0.0.1`.

---

## 3. Conceptual Model & Terminology

- **Execution Coordinator**: The supervisor coordinating engine adapters, probe engines, and result recorders.
- **Dry-Run Mode**: Default execution mode where the coordinator plans and validates scenarios without starting child processes or binding network sockets.
- **Authorized Execution**: Mode activated solely when `--execute` is provided on the command line.
- **Failure Stage**: Standardized lifecycle marker (`pre_flight`, `config_synthesis`, `process_launch`, `port_readiness`, `workload_probing`, `process_teardown`) identifying the exact step where an error occurred.
- **Failure Policy**: Determines whether a failed scenario immediately halts the matrix (`stop`) or records the error and proceeds (`continue`).

---

## 4. Supported vs. Unsupported Matrix

| Operational Feature | Status | Notes |
|---|---|---|
| Dry-Run Matrix Planning | Default | Prevents accidental process execution |
| Explicit Opt-in (`--execute`) | Mandatory | Required to spawn client processes |
| Failure Policy: `continue` | Supported (Default) | Runs full matrix to compute pass/fail ratios |
| Failure Policy: `stop` | Supported | Aborts immediately on first scenario failure |
| Concurrency Control | Supported | Governed by `--concurrency N` (default: 1) |
| Scenario Repetitions | Supported | Governed by `--repetitions N` |
| Streaming Record Output | Supported | Written incrementally to `--output-file` / `--jsonl` |
| Root Interface Hijacking | Disabled | Unprivileged execution only |

---

## 5. Step-by-Step Usage & Commands

### Planning Without Execution (Dry-Run Default)

```bash
connscope matrix run --engine xray --profile vless_tcp_none
```

Output:
```text
Dry-Run Scenario Plan:
  Scenarios Planned: 1
  Execution Opt-in:  SKIPPED (Pass --execute to launch processes)
```

### Executing with Explicit Authorization

```bash
connscope matrix run \
  --engine xray \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute
```

### Halting on First Failure

```bash
connscope matrix run \
  --engine sing_box \
  --profile vmess_ws_tls \
  --failure-policy stop \
  --execute
```

### Running with Multiple Repetitions

```bash
connscope matrix run \
  --engine xray \
  --profile vless_tcp_none \
  --local-diagnostic \
  --repetitions 5 \
  --execute
```

### Streaming Records to Disk

```bash
connscope matrix run \
  --engine xray \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute \
  --output-file results.jsonl \
  --summary-file summary.json
```

---

## 6. Real-World Examples & Output Interpretation

### Example: Execution Summary Output

Command:
```bash
connscope matrix run --engine xray --profile vless_tcp_none --local-diagnostic --execute --json
```

Output:
```json
{
  "summary": {
    "total_planned": 1,
    "total_executed": 1,
    "successful": 1,
    "failed": 0,
    "success_rate_percent": 100.0,
    "total_duration_seconds": 0.38,
    "failure_policy": "continue",
    "timestamp": "2026-10-28T12:00:00Z"
  },
  "records": [
    {
      "scenario_id": "xray-vless_tcp_none-001",
      "status": "SUCCESS",
      "evidence_status": "local_diagnostic_verified",
      "execution_mode": "local_diagnostic",
      "duration_ms": 381.4,
      "metrics": {
        "connect_ms": 0.82,
        "ttfb_ms": 2.15,
        "http_status": 204
      }
    }
  ]
}
```

Interpretation:
- `total_executed`: Count of scenarios that completed the execution pipeline.
- `evidence_status`: Formally tagged as `local_diagnostic_verified`.
- `metrics`: Granular breakdown of network timing.

---

## 7. Configuration & Parameter Reference

| CLI Option | Type | Default | Description |
|---|---|---|---|
| `--execute` | `bool` | `false` | Explicit opt-in flag required to launch processes. |
| `--local-diagnostic` | `bool` | `false` | Run through isolated loopback mock server. |
| `--concurrency` | `int` | `1` | Number of simultaneous adapter subprocesses. |
| `--failure-policy` | `string` | `"continue"` | Behavior on failure: `"continue"` or `"stop"`. |
| `--repetitions` | `int` | `1` | Number of measurement iterations per scenario. |
| `--output-file` / `--jsonl` | `path` | `None` | Path to stream JSON Lines measurement records. |
| `--summary-file` | `path` | `None` | Path to write aggregated JSON summary. |

---

## 8. Error Handling & Common Failure Modes

### Lifecycle Failure Stages

| Failure Stage | Description | Typical Causes |
|---|---|---|
| `pre_flight` | Engine discovery and readiness check | Missing binary in `PATH` or incompatible version |
| `config_synthesis` | Configuration JSON generation | Parameter validation failure or invalid schema |
| `process_launch` | Subprocess spawning via `Popen` | OS resource exhaustion or permission denial |
| `port_readiness` | Inbound SOCKS5 port socket check | Engine crashed on startup or port conflict |
| `workload_probing` | Probe traffic through proxy | Remote handshake failed or HTTP request timed out |
| `process_teardown` | Process cleanup and socket release | Zombie process requiring `SIGKILL` escalation |

---

## 9. Verification & Evidence Semantics

The coordinator tags records based on execution context:
- Dry-run planning yields `catalogued` (Level 0).
- Successful execution against a local diagnostic harness yields `local_diagnostic_verified` (Level 3).
- Successful execution through a remote proxy yields `real_data_transfer_tested` (Level 5).

---

## 10. Related Guides & Next Steps

- [Local Diagnostic Harness](local-diagnostic.md) — The loopback testing environment used for safe offline verification.
- [Measurement Reporting & Formats](measurement-reporting.md) — Schemas of records and summaries emitted by the coordinator.
- [Troubleshooting & Diagnostics](../troubleshooting.md) — Diagnosing failure stages.
