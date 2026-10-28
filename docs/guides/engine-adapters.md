# Engine Adapters & Process Lifecycle Guide

Comprehensive operational guide for ConnScope's client engine adapters for Xray-core and sing-box.

---

## 1. Overview & Purpose

ConnScope does not implement network protocol handshakes from scratch. Instead, it supervises official, battle-tested client proxy engines—specifically **Xray-core** and **sing-box**—through dedicated adapter abstractions (`XrayAdapter`, `SingBoxAdapter`).

The adapters automate:
- Synthesizing valid engine-native configuration files (`config.json`).
- Dynamic loopback port assignment (binding SOCKS5 inbounds to ephemeral ports).
- Subprocess lifecycle management (launching, stdout/stderr pipe capture, bounded readiness polling).
- Safe process termination (`SIGTERM` followed by bounded `SIGKILL`).
- Credential masking and log redaction.

---

## 2. Prerequisites & Dependencies

To execute real proxy instances, the corresponding engine executable must be installed and present on your system `PATH`:
- **Xray-core**: Verified with v26.3.27 (`xray`).
- **sing-box**: Verified with v1.12.12 (`sing-box`).

If an engine binary is not found, ConnScope supports full configuration generation, syntax validation, and dry-run planning, but rejects live process execution with a clear diagnostic message.

---

## 3. Conceptual Model & Terminology

- **Adapter**: Python class wrapping an external executable engine (`XrayAdapter`, `SingBoxAdapter`).
- **Inbound Proxy Port**: Ephemeral loopback port (`127.0.0.1:port`) bound by the engine client to accept SOCKS5 connections from ConnScope probes.
- **Readiness Polling**: Rapid TCP socket checks against the inbound proxy port until the engine indicates it is ready to accept traffic.
- **Graceful Teardown**: Sending `SIGTERM` to the engine subprocess, waiting up to `graceful_timeout` (default: 2.0s), and issuing `SIGKILL` if the process fails to terminate.
- **Secret Redaction**: Automatic replacement of sensitive tokens (`uuid`, `password`, `private_key`) with `[REDACTED]` in logs, error traces, and output records.

---

## 4. Supported vs. Unsupported Matrix

| Capability | Xray Adapter | sing-box Adapter | Notes |
|---|---|---|---|
| Binary Validation (`-test` / `check`) | Supported (`xray run -test -c`) | Supported (`sing-box check -c`) | Non-intrusive syntax checks |
| Dynamic Port Inbound | Supported | Supported | Avoids fixed port collisions |
| Subprocess Supervision | Supported | Supported | Clean process isolation |
| Stderr Warning Capture | Supported | Supported | Preserves engine warnings |
| Inbound Traffic Sniffing | Disabled | Disabled | Enforces pure proxy pass-through |
| Root / Kernel Privileges | Not Required | Not Required | Operates in unprivileged user space |
| Multi-Engine Concurrency | Supported | Supported | Governed by `--concurrency` |

---

## 5. Step-by-Step Usage & Commands

### Checking Installed Engine Versions

Inspect local engine binaries and catalog alignment:

```bash
connscope catalog check
```

### Running Configuration Validation with Native Binaries

Validate generated parameter variations against the installed engine binary without establishing tunnels:

```bash
connscope catalog parameter-coverage --engine xray --profile vless_tcp_reality --validate-binary
```

### Executing a Supervised Engine Scenario

Execute a scenario through the Xray adapter with explicit authorization:

```bash
connscope matrix run \
  --engine xray \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute
```

Execute through the sing-box adapter:

```bash
connscope matrix run \
  --engine sing_box \
  --profile vless_tcp_none \
  --local-diagnostic \
  --execute
```

---

## 6. Real-World Examples & Output Interpretation

### Example: Adapter Lifecycle Trace

When executed with verbose logging or inspected via JSON output:

```json
{
  "scenario_id": "xray-vless_tcp_none-001",
  "engine": "xray",
  "engine_version": "26.3.27",
  "inbound_port": 39821,
  "lifecycle": {
    "config_written_ms": 1.2,
    "process_spawned_ms": 4.5,
    "port_ready_ms": 22.8,
    "execution_status": "READY",
    "teardown_ms": 6.1
  },
  "warnings": []
}
```

Interpretation:
- `inbound_port`: The ephemeral loopback port allocated dynamically for this specific run.
- `port_ready_ms`: Total time elapsed between `Popen` and the first successful TCP handshake on the inbound port.
- `warnings`: Captured stderr logs that did not trigger a process failure.

---

## 7. Configuration & Parameter Reference

Adapters configure client processes based on the active profile family:

| Parameter Key | Engine | Injected Section | Redaction Rule |
|---|---|---|---|
| `uuid` | Xray / sing-box | `outbounds[].settings.vnext[].users[].id` | Masked as `[REDACTED]` |
| `flow` | Xray / sing-box | `outbounds[].settings.vnext[].users[].flow` | Retained (e.g. `xtls-rprx-vision`) |
| `server_name` | Xray / sing-box | `streamSettings.realitySettings.serverNames` | Retained (SNI target) |
| `public_key` | Xray / sing-box | `streamSettings.realitySettings.publicKey` | Masked as `[REDACTED]` |
| `short_id` | Xray / sing-box | `streamSettings.realitySettings.shortId` | Masked as `[REDACTED]` |
| `password` | Xray / sing-box | `outbounds[].settings.servers[].password` | Masked as `[REDACTED]` |

---

## 8. Error Handling & Common Failure Modes

| Error Stage | Symptom | Underlying Cause | Automatic Adapter Remedy |
|---|---|---|---|
| Pre-flight | `ExecutableNotFoundError` | Binary missing from system `PATH` | Fails fast before allocating ports or files |
| Syntax Validation | `ConfigurationSyntaxError` | Engine binary rejected generated JSON | Captures engine stderr and logs exact syntax error |
| Startup Readiness | `AdapterReadinessTimeout` | Inbound port did not open within timeout | Issues `SIGTERM`, then `SIGKILL`, records failure |
| Teardown | `ProcessZombieWarning` | Subprocess refused `SIGTERM` | Immediately escalates to `SIGKILL` |

---

## 9. Verification & Evidence Semantics

- **Binary Validation**: Achieving `real_binary_config_validated` confirms the engine binary parsed the configuration successfully without error.
- **Process Readiness**: Readiness verifies that the engine successfully allocated its socket and initialized its internal routing loop.
- **Application Transfer**: Achieving `local_diagnostic_verified` or `real_data_transfer_tested` proves that the full proxy chain transferred data end-to-end.

---

## 10. Related Guides & Next Steps

- [Local Diagnostic Harness](local-diagnostic.md) — How adapters pair with local mock endpoints.
- [Scenario Execution Coordinator](scenario-execution.md) — Concurrency, failure policies, and matrix orchestration.
- [Evidence Hierarchy & Verification Semantics](../reference/evidence-levels.md) — Detailed taxonomy of evidence levels.
