# Measurement Reporting & Formats Guide

Comprehensive operational guide for ConnScope's structured measurement records, streaming JSON Lines format, and summary reports.

---

## 1. Overview & Purpose

ConnScope implements a deterministic, machine-readable reporting pipeline. Every probe execution and matrix scenario emits structured records that can be:
- Inspected in real time in terminal tables.
- Streamed line-by-line to append-only JSON Lines (`.jsonl`) files for large matrix runs.
- Aggregated into comprehensive execution summaries (`summary.json`).
- Ingested directly into time-series databases, analytics pipelines, or CI/CD test runners.

---

## 2. Prerequisites & Dependencies

- Python 3.11+ standard library (`json`).
- Write permissions to output directories when saving records to disk.

---

## 3. Conceptual Model & Terminology

- **Measurement Record**: An atomic JSON object capturing the complete input parameters, execution lifecycle timings, result metrics, and verification status of a single scenario run.
- **JSON Lines (`.jsonl`)**: Format where each line is an independent, valid JSON document, ideal for streaming execution without buffering entire matrices in memory.
- **Execution Summary**: An aggregated document summarizing total scenarios, executed counts, success rates, failure distributions, and duration.
- **Timing Breakdown**: Hierarchical latency measurements separating process initialization overhead from network socket latency.

---

## 4. Supported vs. Unsupported Matrix

| Reporting Feature | CLI Support | JSON Output | JSON Lines (`.jsonl`) |
|---|---|---|---|
| Per-Scenario Metrics | Table View | Array in Summary | Line-by-Line Stream |
| Secret Redaction | Enforced | Enforced | Enforced |
| Summary Aggregation | Table View | Supported (`--summary-file`) | N/A |
| Failure Stage Tagging | Supported | Supported | Supported |
| Real-time Terminal Progress | Supported | Suppressed when `--json` | Supported |
| PDF / HTML Generation | Unsupported | N/A | N/A |

---

## 5. Step-by-Step Usage & Commands

### Emitting JSON to Standard Output

```bash
connscope matrix run \
  --engine xray \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute \
  --json
```

### Streaming Records to a File

Stream records incrementally as each scenario finishes:

```bash
connscope matrix run \
  --engine xray \
  --profile vless_tcp_reality \
  --mode ofat \
  --output-file /var/log/connscope/records.jsonl
```

### Generating Both JSONL Records and Summary JSON

```bash
connscope matrix run \
  --engine sing_box \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute \
  --jsonl /tmp/matrix-records.jsonl \
  --summary-file /tmp/matrix-summary.json
```

---

## 6. Real-World Examples & Output Interpretation

### Example: JSON Lines Atomic Record Schema

Each line in `.jsonl` adheres to this schema:

```json
{
  "scenario_id": "xray-vless_tcp_none-001",
  "engine": "xray",
  "engine_version": "26.3.27",
  "profile": "vless_tcp_none",
  "status": "SUCCESS",
  "evidence_status": "local_diagnostic_verified",
  "execution_mode": "local_diagnostic",
  "failure_stage": null,
  "error_message": null,
  "parameters": {
    "uuid": "[REDACTED]",
    "flow": null,
    "packet_encoding": null
  },
  "workload": {
    "type": "http_request",
    "target": "127.0.0.1:41893",
    "url": "http://127.0.0.1:41893/diagnostic_204"
  },
  "metrics": {
    "process_spawn_ms": 4.2,
    "port_ready_ms": 22.1,
    "tcp_connect_ms": 0.84,
    "http_ttfb_ms": 2.05,
    "http_status": 204,
    "total_duration_ms": 395.2
  },
  "timestamp": "2026-10-28T12:00:00Z"
}
```

### Example: Aggregated Summary JSON Schema

```json
{
  "summary": {
    "total_planned": 10,
    "total_executed": 10,
    "successful": 9,
    "failed": 1,
    "success_rate_percent": 90.0,
    "total_duration_seconds": 3.82,
    "failure_policy": "continue",
    "timestamp": "2026-10-28T12:00:00Z"
  },
  "failure_stages": {
    "workload_probing": 1
  }
}
```

---

## 7. Configuration & Parameter Reference

| Flag | Argument | Description |
|---|---|---|
| `--json` | None | Emits structured JSON to standard output. |
| `--output-file`, `--jsonl` | File Path | Destination file for streaming JSON Lines. |
| `--summary-file` | File Path | Destination file for aggregated JSON summary. |

---

## 8. Error Handling & Common Failure Modes

| Error Case | Behavior in Output |
|---|---|
| Subprocess crashes on startup | `status: FAILED`, `failure_stage: "port_readiness"`, `error_message` records stderr |
| HTTP request times out | `status: TIMEOUT`, `failure_stage: "workload_probing"`, `duration_ms` equals timeout |
| Configuration parameter invalid | `status: FAILED`, `failure_stage: "config_synthesis"`, `error_message` details validation constraint |

---

## 9. Verification & Evidence Semantics

The `evidence_status` attribute in every emitted record is immutable and categorizes the empirical depth of the test. Downstream consumers can filter records by `evidence_status` to ensure only real internet transfers (Level 5) are included in public connectivity dashboards.

---

## 10. Related Guides & Next Steps

- [Scenario Execution Coordinator](scenario-execution.md) — How records are generated during execution.
- [Evidence Hierarchy & Verification Semantics](../reference/evidence-levels.md) — Definitions of all verification levels.
- [Storage, Event Stream & Observatory API](storage-events-api.md) — Querying stored records programmatically.
