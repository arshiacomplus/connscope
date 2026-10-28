# ConnScope Documentation

ConnScope is a unified network measurement, protocol capability verification, and connectivity monitoring framework.

It bridges declarative protocol capability definitions with executable client adapters, combinatorial parameter scenario generation, safe process lifecycle supervision, proxy readiness probing, and structured measurement record emission.

---

## Documentation Roadmap

### Getting Started & Overview
- [Getting Started](getting-started.md) — System prerequisites, runtime dependencies, installation, and environment configuration.
- [Quickstart Guide](quickstart.md) — Three-command quickstart walkthrough for local diagnostic measurement and report generation.
- [Architecture & Design](architecture.md) — Subsystem architecture, lifecycle flows, and Mermaid system diagram.
- [Feature Support Matrix](feature-matrix.md) — Comprehensive status of all 8 profile families across Xray-core and sing-box.

### Detailed Feature Guides
Each feature guide provides comprehensive documentation adhering to a standardized 10-section operational structure:
1. [Basic Network Probes](guides/probes.md) — Standalone TCP, DNS, TLS, and HTTP measurement probes.
2. [Engine Adapters & Process Lifecycle](guides/engine-adapters.md) — Safe execution adapters for Xray-core and sing-box with secret redaction.
3. [Declarative Capability Catalog](guides/capability-catalog.md) — Canonical vs engine capabilities, taxonomy categories, and evidence tracking.
4. [Parameter Scenarios & Combinatorics](guides/parameter-scenarios.md) — Systematic parameter variation via Explicit, OFAT, Pairwise, and Exhaustive strategies.
5. [Scenario Execution Coordinator](guides/scenario-execution.md) — Execution planning, concurrency, failure policies, timeouts, and dry-run safety.
6. [Local Diagnostic Harness](guides/local-diagnostic.md) — Hermetic loopback testing pipeline using ephemeral ports and HTTP 204 mock endpoints.
7. [Measurement Reporting & Formats](guides/measurement-reporting.md) — Deterministic record schemas, JSON Lines streaming, and summary statistics.
8. [Remote Agent & Distributed Nodes](guides/remote-agent.md) — Distributed probe delegation over HTTP Bearer authentication.
9. [Layer 3 Interface Adapters](guides/layer3-adapters.md) — Architectural design, privilege requirements, and mock test boundaries for WireGuard, AmneziaWG, and OpenVPN.
10. [Storage, Event Stream & Observatory API](guides/storage-events-api.md) — In-memory history, event subscription bus, and query endpoints.

### Command & Configuration Reference
- [CLI Reference Manual](reference/cli.md) — Complete specification of all CLI commands, arguments, defaults, and exit codes.
- [Configuration & Schema Reference](reference/configuration.md) — Parameter constraint rules, profile configurations, and builder schemas.
- [Evidence Hierarchy & Verification Semantics](reference/evidence-levels.md) — Formal taxonomy of verification states from catalogued definitions to live data transfers.

### Operations & Maintenance
- [Security, Isolation & Redaction](security.md) — Credential protection, execution boundaries, and safety policies.
- [Troubleshooting & Diagnostics](troubleshooting.md) — Real failure modes, root cause analyses, diagnostic commands, and remedies.
- [Development & Contribution Guide](development.md) — Code layout, test suite execution, and rules for extending profiles.
- [Release Process & Artifact Verification](release-process.md) — Automated GitHub Actions release pipeline and checksum verification.
- [Glossary of Terms](glossary.md) — Formal terminology definitions across ConnScope subsystems.
