# Glossary of Terms

Comprehensive definitions of technical terms, acronyms, and domain concepts used throughout ConnScope.

---

### Adapter
A Python module wrapping an external executable engine (such as Xray-core or sing-box), responsible for configuration translation, subprocess management, socket readiness polling, and graceful termination.

### ALPN (Application-Layer Protocol Negotiation)
A TLS extension allowing client and server to negotiate which application protocol (e.g. `h2` or `http/1.1`) to speak over the secure connection.

### Authorized Execution Mode
The operational state enabled solely when `--execute` is supplied on the CLI, authorizing ConnScope to spawn child proxy processes.

### Canonical Capability
A protocol feature or specification attribute defined independently of any specific engine implementation (e.g. VLESS flow types or VMess AEAD encryption).

### Diagnostic Mock Server
An internal, in-memory HTTP server started by the Local Diagnostic Harness on an ephemeral loopback port that returns HTTP `204 No Content` to verify proxy data transfer without external network access.

### Dry-Run Mode
The default execution mode of ConnScope where scenario matrices are planned, validated, and displayed without starting child processes or modifying network sockets.

### Engine Capability
The concrete implementation of a protocol feature provided by a specific version of an engine (e.g. Xray-core's REALITY implementation).

### Ephemeral Port
A dynamic TCP or UDP port allocated automatically by the operating system kernel when a socket binds to port `0`.

### Evidence Level
A formal rank in ConnScope's verification hierarchy (Levels 0 through 5) defining the empirical certainty of a capability claim or measurement result.

### Exhaustive Strategy
A matrix generation mode that produces the complete Cartesian product across all parameter values.

### Failure Stage
A standardized lifecycle marker (`pre_flight`, `config_synthesis`, `process_launch`, `port_readiness`, `workload_probing`, `process_teardown`) identifying the exact step in which an error occurred.

### Local Diagnostic Harness
An isolated, loopback-only testing pipeline that verifies proxy client configuration, process launch, port binding, and HTTP transfer against an ephemeral mock endpoint.

### OFAT (One-Factor-At-A-Time)
A parameter matrix strategy that varies each parameter individually across its defined range while holding all other parameters at baseline defaults.

### Pairwise Testing
A combinatorial strategy that generates test configurations covering all possible 2-way interactions between parameters with minimal test cases.

### Profile Family
An executable proxy client template pairing a protocol, transport mode, and security layer (e.g. `vless_tcp_reality` or `vmess_ws_tls`).

### Readiness Polling
Rapid socket connection attempts against an engine's inbound proxy port to determine when the subprocess has initialized and is ready to accept traffic.

### Remote Agent
A distributed daemon exposing an authenticated HTTP API to allow remote vantage points to execute probes on behalf of a coordinator.

### Secret Redaction
The automatic replacement of sensitive credential values (`uuid`, `password`, `private_key`) with `[REDACTED]` in logs, error traces, and output records.

### SNI (Server Name Indication)
A TLS extension by which a client indicates the destination hostname it is attempting to connect to at the start of the handshake process.

### Target
A structured representation of an endpoint to probe, formatted as `host:port`, `hostname`, or an HTTP URL.

### TTFB (Time To First Byte)
The duration in milliseconds between sending an HTTP request and receiving the first byte of the HTTP response headers.
