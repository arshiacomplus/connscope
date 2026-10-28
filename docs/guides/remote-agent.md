# Remote Agent & Distributed Nodes Guide

Comprehensive operational guide for ConnScope's remote agent client, server protocol, and distributed measurement node orchestration.

---

## 1. Overview & Purpose

Network vantage points are critical for accurate connectivity monitoring. Measuring latency or reachability from only a single developer machine or data center yields incomplete data.

The **ConnScope Remote Agent** subsystem (`connscope.agent`) enables distributed probing across diverse vantage points. An operator can deploy lightweight agent instances on remote edge servers, and the ConnScope CLI or coordinator can delegate probe executions to those nodes over a secure, authenticated HTTP API.

---

## 2. Prerequisites & Dependencies

- Python 3.11+ standard library.
- HTTP reachability between the coordinating client and the remote agent endpoint.
- Shared Bearer token configured on both the agent server and client.

---

## 3. Conceptual Model & Terminology

- **Remote Node**: A host running the `RemoteAgentServer` daemon exposing the agent HTTP API.
- **Node Identifier**: A name or URL referencing a specific vantage point (e.g. `agent-eu-central`, `https://node1.example.com:8443`).
- **Bearer Authentication**: HTTP `Authorization: Bearer <token>` header required for all non-health requests.
- **Probe Delegation**: Transmitting probe parameters (target, probe type, timeout) via JSON POST to `/probes/run`, and receiving the remote execution record in response.

---

## 4. Supported vs. Unsupported Matrix

| Feature | Local Execution | Remote Agent Execution |
|---|---|---|
| TCP Connect Probing | Supported | Supported |
| DNS Resolve Probing | Supported | Supported |
| TLS Handshake Probing | Supported | Supported |
| HTTP Request Probing | Supported | Supported |
| Authentication | N/A | HTTP Bearer Token |
| Custom Port / TLS | N/A | Supported (reverse proxy or HTTPS) |
| Live Engine Adapter Spawning | Supported | Local only (Agent runs standalone probes) |
| Anonymous Unauthenticated Access | N/A | Prohibited (rejects with 401 Unauthorized) |

---

## 5. Step-by-Step Usage & Commands

### Running a Remote Probe via CLI

Execute a TCP probe against a target from a remote agent node:

```bash
connscope run tcp 1.1.1.1:53 \
  --node https://agent1.example.com:8443 \
  --token "secret-bearer-token"
```

### Using Environment Variables for Secure Authentication

Avoid exposing sensitive tokens in process listings (`ps aux`):

```bash
export CONNSCOPE_AGENT_URL="https://agent1.example.com:8443"
export CONNSCOPE_AGENT_TOKEN="secret-bearer-token"

# CLI automatically uses environment variables
connscope run dns example.com
```

### Running Probes with SNI Customization via Remote Agent

```bash
connscope run tls 93.184.216.34:443 \
  --sni example.com \
  --node https://agent1.example.com:8443 \
  --token "$CONNSCOPE_AGENT_TOKEN"
```

---

## 6. Real-World Examples & Output Interpretation

### Example: Remote Probe JSON Output

Command:
```bash
connscope run tcp 8.8.8.8:53 --node https://agent1.example.com:8443 --json
```

Output:
```json
{
  "probe": "tcp_connect",
  "target": "8.8.8.8:53",
  "status": "SUCCESS",
  "duration_ms": 14.8,
  "node": "agent1.example.com:8443",
  "remote_execution": true,
  "metrics": {
    "local_address": "192.168.1.100",
    "connected_ms": 14.8
  },
  "timestamp": "2026-10-28T12:00:00Z"
}
```

Interpretation:
- `remote_execution`: Confirms the probe ran on the remote node.
- `duration_ms`: Latency measured from the remote node to `8.8.8.8:53`.

---

## 7. Configuration & Parameter Reference

### CLI Options

| Flag | Env Variable | Default | Description |
|---|---|---|---|
| `--node` | `CONNSCOPE_AGENT_URL` | `None` | Base URL of the remote agent server. |
| `--token` | `CONNSCOPE_AGENT_TOKEN` | `None` | Bearer token for authentication. |
| `--timeout` | N/A | `5.0` | Client request timeout in seconds. |

### Agent HTTP API Endpoints

| Endpoint | Method | Auth Required | Description |
|---|---|---|---|
| `/health` | `GET` | No | Basic health check; returns `{"status": "ok"}`. |
| `/probes/list` | `GET` | Yes | Returns list of supported probes on this node. |
| `/probes/run` | `POST` | Yes | Executes probe; body: `{"probe": "tcp", "target": "...", "timeout": 5.0}`. |

---

## 8. Error Handling & Common Failure Modes

The client maps HTTP status codes into typed Python exceptions and appropriate CLI exit codes:

| Condition | HTTP Status | Client Exception | Exit Code | Resolution |
|---|---|---|---|---|
| Missing/Invalid Token | `401 Unauthorized` | `RemoteAuthenticationError` | `3` (`USAGE_ERROR`) | Verify Bearer token credentials |
| Action Not Allowed | `403 Forbidden` | `RemotePolicyError` | `3` (`USAGE_ERROR`) | Check agent policy configuration |
| Agent Down / Unreachable | N/A | `RemoteConnectionError` | `1` (`FAILED`) | Check remote node firewall and DNS |
| Remote Execution Timed Out | `504 Gateway Timeout` | `RemoteTimeoutError` | `2` (`TIMEOUT`) | Increase probe timeout or inspect target |

---

## 9. Verification & Evidence Semantics

Probes executed through a remote agent reflect the network conditions of that remote vantage point. When aggregated, records include the `node` identifier to enable comparative multi-path latency analysis.

---

## 10. Related Guides & Next Steps

- [Basic Network Probes](probes.md) — Available probe types and parameter options.
- [Security, Isolation & Redaction](../security.md) — Hardening token storage and communication.
- [CLI Reference Manual](../reference/cli.md) — Complete command documentation.
