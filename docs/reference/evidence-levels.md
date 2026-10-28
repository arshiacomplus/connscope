# Evidence Hierarchy & Verification Semantics

Formal specification of ConnScope's evidence levels, verification states, and empirical guarantees.

---

## 1. Why an Evidence Hierarchy Is Necessary

Network measurement platforms frequently conflate configuration parsing with verified connectivity. A tool that produces a valid client configuration file cannot honestly claim that the protocol works across the internet.

To establish scientific rigor and eliminate false claims, ConnScope classifies every capability claim, scenario plan, and measurement record into an explicit, deterministic **Evidence Hierarchy**.

---

## 2. Formal Evidence Levels

```
Level 0: catalogued
   │
   ▼
Level 1: config_validation_implemented
   │
   ▼
Level 2: real_binary_config_validated
   │
   ▼
Level 3: local_diagnostic_verified
   │
   ▼
Level 4: real_tunnel_verified
   │
   ▼
Level 5: real_data_transfer_tested
```

### Level 0: `catalogued`
- **Definition**: The capability, protocol, or engine parameter is formally declared in ConnScope's schema catalog with documented source references.
- **Preconditions**: Schema modeling in Python.
- **Verification Guarantee**: Syntax existence only. No runtime verification performed.
- **Associated Commands**: `connscope catalog list`, `connscope matrix preview`.

### Level 1: `config_validation_implemented`
- **Definition**: ConnScope's Python configuration builder contains validation logic, type checks, and constraint checking for the profile.
- **Preconditions**: Unit test coverage for schema and parameter constraints.
- **Verification Guarantee**: Generated configurations conform to theoretical protocol constraints.
- **Associated Commands**: `connscope catalog validate`.

### Level 2: `real_binary_config_validated`
- **Definition**: The official native engine executable (`xray` or `sing-box`) executed its internal configuration syntax validator (`-test` or `check`) and accepted the generated configuration.
- **Preconditions**: Installed engine executable on system `PATH`.
- **Verification Guarantee**: The specific engine version recognizes all fields, options, and values as syntactically legal.
- **Associated Commands**: `connscope catalog parameter-coverage --validate-binary`, `connscope matrix preview-parameters --validate-binary`.

### Level 3: `local_diagnostic_verified`
- **Definition**: A local client process was launched, bound dynamic loopback ports, completed protocol handshakes, and transferred application data (HTTP 204) against an isolated local diagnostic harness.
- **Preconditions**: Installed engine executable, ephemeral socket binding permissions.
- **Verification Guarantee**: Complete client process lifecycle, socket binding, proxy protocol handshake, and application data transfer functioned end-to-end without errors.
- **Crucial Limitation**: Measured over kernel loopback (`lo`). Timings reflect process startup and memory IPC overhead; **they must never be reported as internet latency**.
- **Associated Commands**: `connscope matrix run --local-diagnostic --execute`.

### Level 4: `real_tunnel_verified`
- **Definition**: The engine established an authenticated tunnel handshake with an external remote server.
- **Preconditions**: Reachable remote proxy endpoint with valid credentials.
- **Verification Guarantee**: Handshake cryptographic negotiation succeeded across a real network link.
- **Associated Commands**: `connscope matrix run --execute --target <remote-host:port>`.

### Level 5: `real_data_transfer_tested`
- **Definition**: Application payload (such as an HTTP GET request to an internet endpoint) was successfully transmitted through the established remote tunnel and verified.
- **Preconditions**: Established remote proxy tunnel, reachable destination URL.
- **Verification Guarantee**: Full end-to-end bidirectional internet data transfer succeeded.
- **Associated Commands**: `connscope matrix run --execute --target <remote> --test-url <url>`.

---

## 3. Summary Comparison Table

| Level | Identifier | Scope | Process Spawning | Network Traffic | Internet Dependency |
|---|---|---|---|---|---|
| **0** | `catalogued` | Schema Model | None | None | None |
| **1** | `config_validation_implemented` | Python Logic | None | None | None |
| **2** | `real_binary_config_validated` | Engine Parser | Temporary (`-test`) | None | None |
| **3** | `local_diagnostic_verified` | Loopback Harness | Supervised Subprocess | Loopback (`lo`) | None |
| **4** | `real_tunnel_verified` | Remote Tunnel | Supervised Subprocess | L4 Network Sockets | Requires Remote Host |
| **5** | `real_data_transfer_tested` | Full Data Path | Supervised Subprocess | L7 End-to-End | Requires Internet Target |

---

## 4. Auditing and Reporting Guidelines

When publishing or consuming ConnScope telemetry:
1. Always display the `evidence_status` alongside any latency or success metrics.
2. Filter out Level 3 (`local_diagnostic_verified`) records when computing public WAN latency dashboards or ISP performance scorecards.
3. Use Level 2 and Level 3 for offline continuous integration (CI) tests and release regression gates.
