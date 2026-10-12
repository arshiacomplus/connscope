# 0002. CLI Presentation Layer

## Context

With Core contracts (Phase 1) and basic network probes (Phase 2) established, ConnScope requires a command-line interface to allow users and automated scripts to run measurements and inspect available probes.

The CLI must strictly serve as a thin presentation layer: it must not contain network measurement logic, must not bypass `ProbeEngine`, and must remain decoupled from Core internals.

## Decision

We establish the following CLI architecture and presentation layer design:

1. **Presentation-Only Boundary**:
   The dependency flow is strictly one-directional:
   `CLI -> Core (ProbeEngine, Target, ProbeRegistry) -> Probes`
   The CLI translates user inputs into `Target` and configuration dictionaries, invokes `ProbeEngine.run()`, formats `ProbeResult` data for stdout, and maps outcomes to process exit codes.

2. **Standard-Library Foundation**:
   The CLI uses only the Python standard library (`argparse`, `ipaddress`, `urllib.parse`, `asyncio`). External CLI frameworks (Click, Typer, Rich) are excluded to maintain fast startup, zero external runtime dependencies, and high maintainability.

3. **Command Design & Aliases**:
   - `connscope run <probe> <target> [--timeout SECONDS]` executes a probe against a target.
   - `connscope probe list` (and alias `connscope list`) discovers registered builtin probes.
   - Short probe aliases are provided (`tcp` -> `tcp_connect`, `dns` -> `dns_resolve`, `tls` -> `tls_handshake`, `http` -> `http_request`), resolved case-insensitively while preserving full canonical names.

4. **Target Parsing Separation**:
   - Generic targets (`parse_target`) validate hostnames, IPv4, bracketed IPv6 (with optional ports), and bare IPv6 without network resolution.
   - HTTP targets (`parse_http_target`) handle `http://` and `https://` URLs using `urllib.parse.urlsplit`, extracting paths, queries, TLS settings, and ports while stripping URL fragments. Plain hostnames default to HTTPS on port 443.
   - Explicit domain constraints are enforced at the presentation boundary (e.g. TCP requires a port; DNS rejects ports).

5. **Deterministic Registry Bootstrap**:
   Each CLI invocation creates its own isolated `ProbeRegistry` populated via `register_builtin_probes()`. No global mutable state is introduced.

6. **Predictable Exit-Code Policy**:
   - `0`: Successful measurement (`ProbeStatus.SUCCESS`) or informational command (`--help`, `--version`, `probe list`).
   - `1`: Measurement failed (`ProbeStatus.FAILED`).
   - `2`: Measurement timed out (`ProbeStatus.TIMEOUT`).
   - `3`: Usage error (syntax error, malformed target, missing port for TCP, unknown probe).
   - `4`: Unexpected internal error.
   `argparse` error handling is customized so syntax errors also exit with code 3.

7. **Synchronous-to-Async Bridge**:
   The CLI entry point uses `asyncio.run()` to manage the event-loop lifecycle, ensuring clean shutdown and cancellation on `KeyboardInterrupt`.

## Consequences

- Core contracts and probe implementations remain completely independent of the CLI.
- All default CLI tests run fully offline using dummy probes.
- Adding structured JSON output in Phase 4 requires only adding a formatter in `output.py` without touching Core or probe code.
- Future frontends (Remote Agent, API, GUI) can reuse `ProbeEngine` and `register_builtin_probes()` using the same pattern established here.
