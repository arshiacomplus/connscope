# ConnScope

[![CI](https://github.com/ArshiaComPlus/connscope/actions/workflows/ci.yml/badge.svg)](https://github.com/ArshiaComPlus/connscope/actions/workflows/ci.yml)
[![Release](https://github.com/ArshiaComPlus/connscope/actions/workflows/release.yml/badge.svg)](https://github.com/ArshiaComPlus/connscope/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

ConnScope is a unified network measurement, protocol capability verification, and connectivity monitoring framework. It bridges declarative protocol and proxy engine capability catalogs with executable client adapters, combinatorial parameter scenario generation, safe process lifecycle supervision, proxy readiness probing, and deterministic measurement record emission.

---

## Key Features

- **Declarative Protocol & Engine Catalog**: Canonical definitions covering protocols (VLESS, VMess, Trojan, Shadowsocks, WireGuard, OpenVPN, AmneziaWG, Exclave, Aether), transports (TCP, WebSocket, gRPC), security layers (REALITY, TLS, Plaintext), and parameter constraints with traceable source provenance.
- **Engine Adapters & Lifecycle Supervision**: Profile-driven client execution for Xray-core and sing-box with dynamic loopback port assignment, process containment, bounded timeouts, and automated secret credential masking (`[REDACTED]`).
- **Combinatorial Scenario Matrix Planning**: Automated test planning supporting Explicit, OFAT (One-Factor-At-A-Time), Pairwise, and Exhaustive Cartesian parameter variations with strict size bounds and dry-run safety by default.
- **Hermetic Local Diagnostic Harness**: Self-contained loopback testing pipeline using ephemeral ports and an in-memory HTTP 204 mock endpoint to verify client execution without external internet access or port conflicts.
- **Built-in Measurement Probes**: Standalone TCP connection, DNS resolution, TLS handshake, and HTTP request probes for local testing or distributed delegation to remote Agent nodes.
- **Deterministic Record Contracts**: Structured measurement records exported to JSON Lines (`.jsonl`) and summary JSON formats adhering to a strict evidence hierarchy (Levels 0–5).
- **Zero Mandatory Runtime Dependencies**: Built entirely on standard Python libraries.

---

## Installation

ConnScope requires Python 3.11 or newer. It has zero mandatory third-party runtime dependencies.

### From Release Wheel
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install connscope-0.1.0-py3-none-any.whl
```

### From Source Distribution
```bash
pip install connscope-0.1.0.tar.gz
```

### For Development & Contribution
```bash
git clone https://github.com/ArshiaComPlus/connscope.git
cd connscope
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

---

## 30-Second Quickstart

### Step 1: Check Local Engine Readiness
Audit installed proxy engine binaries (`xray`, `sing-box`) and profile support:
```bash
connscope catalog check
```

### Step 2: Preview Scenario Matrix (Dry-Run Mode)
Preview parameter combinations without launching any external processes:
```bash
connscope matrix preview --engine xray --profile vless_tcp_none
```

### Step 3: Run Local Diagnostic Measurement
Execute an authorized end-to-end verification using the isolated loopback diagnostic harness:
```bash
connscope matrix run --engine xray --profile vless_tcp_none --local-diagnostic --execute
```

> [!NOTE]
> The `--execute` flag is an explicit opt-in requirement. Without `--execute`, ConnScope operates in dry-run planning mode.

---

## Architecture Overview

```text
User / CLI / API
       │
       ▼
Planning & Catalog Layer (ProtocolCatalog, ScenarioGenerator)
       │
       ▼
Execution Coordinator (ScenarioCoordinator, LocalDiagnosticHarness)
       ├── Configuration Builders (JSON Synthesis & Redaction)
       ├── Engine Adapters (XrayAdapter, SingBoxAdapter, Layer3)
       └── Probe Engine & Builtin Probes (TCP, DNS, TLS, HTTP)
       │
       ▼
Structured Measurement Records (.jsonl, summary.json)
```

For full architecture details and design diagrams, see the [Architecture Guide](docs/architecture.md).

---

## Documentation Index

Comprehensive documentation is available in the [`docs/`](docs/index.md) directory:

### Overview & Getting Started
- [Documentation Index](docs/index.md)
- [Getting Started Guide](docs/getting-started.md)
- [Quickstart Guide](docs/quickstart.md)
- [Architecture & System Design](docs/architecture.md)
- [Feature Support Matrix](docs/feature-matrix.md)

### Feature Guides
- [Basic Network Probes](docs/guides/probes.md)
- [Engine Adapters & Process Lifecycle](docs/guides/engine-adapters.md)
- [Declarative Capability Catalog](docs/guides/capability-catalog.md)
- [Parameter Scenarios & Combinatorics](docs/guides/parameter-scenarios.md)
- [Scenario Execution Coordinator](docs/guides/scenario-execution.md)
- [Local Diagnostic Harness](docs/guides/local-diagnostic.md)
- [Measurement Reporting & Formats](docs/guides/measurement-reporting.md)
- [Remote Agent & Distributed Nodes](docs/guides/remote-agent.md)
- [Layer 3 Interface Adapters](docs/guides/layer3-adapters.md)
- [Storage, Event Stream & Observatory API](docs/guides/storage-events-api.md)

### Technical Reference
- [CLI Reference Manual](docs/reference/cli.md)
- [Configuration & Schema Reference](docs/reference/configuration.md)
- [Evidence Hierarchy & Verification Semantics](docs/reference/evidence-levels.md)

### Operations & Contributing
- [Security, Isolation & Redaction](docs/security.md)
- [Troubleshooting & Diagnostics](docs/troubleshooting.md)
- [Development & Contribution Guide](docs/development.md)
- [Release Process & Artifact Verification](docs/release-process.md)
- [Glossary of Terms](docs/glossary.md)

---

## Status & Limitations (v0.1.0)

ConnScope v0.1.0 is an initial release candidate. Please note the following boundaries:
1. **Evidence Semantics**: Measurements marked as `local_diagnostic_verified` reflect loopback execution and client process startup; they must not be presented as internet network performance metrics.
2. **Encrypted Remote Profiles**: Profiles utilizing encryption or TLS/REALITY handshakes (`vless_tcp_reality`, `vmess_ws_tls`, `trojan_tcp_tls`, etc.) are validated locally via native binary syntax checks (`-test`/`check`); verified live data transfers require operator-supplied remote servers.
3. **Layer 3 Privileges**: WireGuard, AmneziaWG, and OpenVPN adapters are modeled and mock-tested; live creation of kernel network interfaces is disabled by default to prevent altering host routing.
4. **Android Execution**: Exclave and Aether protocols are schema-modeled and catalogued; headless Android daemon execution is not implemented in v0.1.0.

---

## License & Contributing

ConnScope is released under the [MIT License](LICENSE). Contributions, bug reports, and pull requests are welcome! Please review the [Development Guide](docs/development.md) and [Security Policy](docs/security.md) before submitting changes.
