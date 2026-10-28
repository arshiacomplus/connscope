# CLI Reference Manual

Complete specification of all command-line interfaces, subcommands, options, arguments, environment variables, and exit codes for ConnScope v0.1.0.

---

## 1. Global Command Structure

The general invocation syntax for ConnScope is:

```bash
connscope [--version] [--help] <command> [<args>...]
```

### Global Options

| Option | Shorthand | Description |
|---|---|---|
| `--version` | `-V` | Print program version and exit. |
| `--help` | `-h` | Display help message and exit. |

---

## 2. Exit Codes

ConnScope returns deterministic standard exit codes:

| Exit Code | Name | Meaning |
|---|---|---|
| `0` | `OK` | All requested operations and measurements succeeded. |
| `1` | `FAILED` | Measurement completed with a failure or target was unreachable. |
| `2` | `TIMEOUT` | Operation exceeded the configured timeout limit. |
| `3` | `USAGE_ERROR` | Malformed CLI arguments, invalid options, or authentication error. |
| `4` | `INTERNAL_ERROR`| Unhandled internal exception occurred. |

---

## 3. Command: `probe list` and `list`

Lists all built-in network measurement probes.

### Syntax
```bash
connscope probe list
# or
connscope list
```

### Description
Outputs the names, canonical identifiers, and aliases for available probes (`tcp`, `dns`, `tls`, `http`).

---

## 4. Command: `run`

Executes a standalone probe against a specified target.

### Syntax
```bash
connscope run <probe> <target> [options]
```

### Positional Arguments
- `probe`: Probe name or alias (`tcp`, `tcp_connect`, `dns`, `dns_resolve`, `tls`, `tls_handshake`, `http`, `http_request`).
- `target`: Target address, hostname, `host:port`, or HTTP(S) URL.

### Options
| Option | Argument | Default | Description |
|---|---|---|---|
| `--timeout` | `FLOAT` | `5.0` | Maximum probe execution timeout in seconds. |
| `--json` | Flag | `false` | Output result as structured JSON. |
| `--node` | `URL` | `None` | Remote Agent base URL (overrides `CONNSCOPE_AGENT_URL`). |
| `--token` | `TOKEN` | `None` | Bearer token for Remote Agent (overrides `CONNSCOPE_AGENT_TOKEN`). |
| `--sni` | `HOST` | Target host | Explicit TLS Server Name Indication (SNI) hostname. Mutually exclusive with `--no-sni`. |
| `--no-sni` | Flag | `false` | Omit TLS Server Name Indication (SNI) extension. Mutually exclusive with `--sni`. |
| `--config` | `JSON_OR_PATH` | `None` | Probe configuration as a JSON string or path to a JSON file. |

---

## 5. Command: `catalog`

Commands for querying, inspecting, and validating the declarative capability catalog.

### Subcommand: `catalog validate`
Validates catalog schema integrity and consistency rules.
```bash
connscope catalog validate [path] [--json]
```
- `path`: Optional path to custom catalog JSON file.
- `--json`: Output validation result as JSON.

### Subcommand: `catalog list`
Lists all engines and protocol profile families defined in the catalog.
```bash
connscope catalog list [--catalog PATH] [--json]
```
- `--catalog PATH`: Optional path to custom catalog JSON file.
- `--json`: Output catalog list as JSON.

### Subcommand: `catalog show`
Shows detailed schemas, constraints, and source references for an engine or profile.
```bash
connscope catalog show <id> [--catalog PATH] [--json]
```
- `id`: Engine identifier (e.g. `xray`, `sing_box`) or Profile ID (e.g. `vless_tcp_reality`).
- `--catalog PATH`: Optional path to custom catalog JSON file.
- `--json`: Output details as JSON.

### Subcommand: `catalog coverage`
Displays a comprehensive capability coverage report across engines and protocols.
```bash
connscope catalog coverage [--catalog PATH] [--engine ID] [--protocol PROTO] [--category CAT] [--json]
```
- `--catalog PATH`: Optional path to custom catalog JSON file.
- `--engine ID`: Filter coverage report by engine ID.
- `--protocol PROTO`: Filter coverage report by protocol.
- `--category CAT`: Filter coverage report by taxonomy category.
- `--json`: Output coverage report as JSON.

### Subcommand: `catalog parameter-coverage`
Displays per-profile parameter-space coverage, constraints, and validation status.
```bash
connscope catalog parameter-coverage [--catalog PATH] [--engine ID] [--profile ID] [--validate-binary] [--json]
```
- `--catalog PATH`: Optional path to custom catalog JSON file.
- `--engine ID`: Filter report by engine ID.
- `--profile ID`: Filter report by profile ID.
- `--validate-binary`: Run real-binary syntax validation against parameter combinations.
- `--json`: Output coverage report as JSON.

### Subcommand: `catalog check`
Audits the local environment and checks system readiness for executable engines.
```bash
connscope catalog check [--catalog PATH] [--json]
```
- `--catalog PATH`: Optional path to custom catalog JSON file.
- `--json`: Output readiness check as JSON.

---

## 6. Command: `matrix`

Commands for planning, previewing, and executing scenario matrices.

### Subcommand: `matrix preview`
Previews the planned scenario matrix without executing any processes (dry-run).
```bash
connscope matrix preview [options]
```
Options:
- `--catalog PATH`: Custom catalog JSON path.
- `--engine ID`: Filter or specify engine ID (e.g. `xray`, `sing_box`).
- `--profile ID`: Filter or specify protocol profile ID.
- `--variant ID`: Filter or specify variant ID.
- `--mode {explicit,ofat,pairwise,exhaustive}`: Generation strategy (default: `explicit`).
- `--target HOST:PORT`: Target address (default: `127.0.0.1:443`).
- `--node ID`: Measurement node ID (default: `local`).
- `--config JSON_OR_PATH`: Parameter overrides as JSON string or file path.
- `--test-url URL`: Workload test URL (default: `http://cp.cloudflare.com/generate_204`).
- `--local-diagnostic`: Plan execution using the isolated loopback diagnostic harness.
- `--max-scenarios INT`: Maximum allowed scenarios (default: `100`).
- `--allow-exhaustive`: Explicitly permit large exhaustive Cartesian matrices.
- `--json`: Output matrix plan as JSON.

### Subcommand: `matrix estimate`
Calculates projected scenario counts before generating.
```bash
connscope matrix estimate [--catalog PATH] [--engine ID] [--profile ID] [--variant ID] [--mode {explicit,ofat,pairwise,exhaustive}] [--json]
```

### Subcommand: `matrix run`
Executes planned scenario matrix measurements through local engine adapters.
```bash
connscope matrix run [options]
```
Options:
- `--catalog PATH`: Custom catalog JSON path.
- `--engine ID`: Filter or specify engine ID (`xray`, `sing_box`).
- `--profile ID`: Filter or specify protocol profile ID.
- `--variant ID`: Filter or specify variant ID.
- `--mode {explicit,ofat,pairwise,exhaustive}`: Generation strategy (default: `explicit`).
- `--target HOST:PORT`: Target address (default: `127.0.0.1:443`).
- `--node ID`: Measurement node ID (default: `local`).
- `--config JSON_OR_PATH`: Parameter overrides as JSON string or file path.
- `--test-url URL`: Workload test URL (default: `http://cp.cloudflare.com/generate_204`).
- `--local-diagnostic`: Execute scenario using isolated loopback diagnostic harness.
- `--repetitions INT`: Repetitions count per scenario.
- `--concurrency INT`: Bounded concurrent adapter executions (default: `1`).
- `--failure-policy {continue,stop}`: Policy on individual measurement failure (default: `continue`).
- `--max-scenarios INT`: Maximum allowed scenarios (default: `100`).
- `--allow-exhaustive`: Explicitly permit large exhaustive Cartesian matrices.
- `--execute`: Explicit opt-in required to execute external adapter processes (defaults to dry-run planning).
- `--output-file PATH`, `--jsonl PATH`: Output file path for streaming JSON Lines records.
- `--summary-file PATH`: Output file path for JSON execution summary.
- `--json`: Output execution summary as JSON to stdout.

### Subcommand: `matrix coverage`
Displays capability and parameter coverage report (alias matching `catalog coverage`).
```bash
connscope matrix coverage [--catalog PATH] [--engine ID] [--protocol PROTO] [--category CAT] [--json]
```

### Subcommand: `matrix preview-parameters`
Previews planned parameter-space test scenarios.
```bash
connscope matrix preview-parameters [options]
```
Options:
- `--catalog PATH`: Custom catalog JSON path.
- `--engine ID`: Engine ID (default: `xray`).
- `--profile ID`: Profile ID (default: `vless_tcp_reality`).
- `--strategy {ofat,pairwise}`: Parameter variation strategy (default: `ofat`).
- `--target HOST:PORT`: Target address (default: `127.0.0.1:443`).
- `--node ID`: Measurement node ID (default: `local`).
- `--include-invalid`: Include intentional invalid parameter test cases.
- `--validate-binary`: Run real-binary parser validation on generated configurations.
- `--json`: Output scenarios as JSON.

---

## 7. Environment Variables

| Variable | Description |
|---|---|
| `CONNSCOPE_AGENT_URL` | Default remote Agent base URL when `--node` is omitted. |
| `CONNSCOPE_AGENT_TOKEN` | Bearer token for Remote Agent authentication (avoids exposing tokens in `ps`). |
