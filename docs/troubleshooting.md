# Troubleshooting & Diagnostic Guide

Practical guide for diagnosing and resolving common errors, configuration mismatches, and execution failures in ConnScope.

---

## 1. Quick Diagnostic Checklist

When encountering unexpected behavior, run these diagnostic commands in order:

```bash
# 1. Check CLI version and Python environment
connscope --version

# 2. Audit installed engine binaries and profile readiness
connscope catalog check

# 3. Validate internal catalog schema consistency
connscope catalog validate

# 4. Preview scenario plan without execution
connscope matrix preview --engine xray --profile vless_tcp_none

# 5. Run hermetic local diagnostic with verbose error output
connscope matrix run --engine xray --profile vless_tcp_none --local-diagnostic --execute
```

---

## 2. Common Issues, Root Causes, and Remedies

### 1. `ExecutableNotFoundError: xray binary not found in PATH`

- **Symptom**: CLI reports `xray` or `sing-box` is missing during `matrix run --execute`.
- **Root Cause**: The engine binary is not installed, not marked executable, or located in a directory not included in the user's `$PATH`.
- **Diagnostic Command**:
  ```bash
  which xray
  which sing-box
  ```
- **Remedy**:
  - Install the engine binary into `/usr/local/bin` or `~/.local/bin`.
  - Ensure the executable bit is set: `chmod +x /usr/local/bin/xray`.
  - If testing without binaries, omit `--execute` to run in dry-run planning mode.

---

### 2. `MatrixSizeExceededError: generated scenario count exceeds limit`

- **Symptom**: `connscope matrix run` or `connscope matrix preview` fails with an error indicating scenario count exceeded 100.
- **Root Cause**: The `--mode exhaustive` strategy was selected on a profile with multiple multi-valued parameters, creating a large combinatorial Cartesian product.
- **Diagnostic Command**:
  ```bash
  connscope matrix estimate --profile vless_tcp_reality --mode exhaustive
  ```
- **Remedy**:
  - Use `--mode ofat` or `--mode pairwise` instead of `exhaustive`.
  - If an exhaustive test is genuinely intended, pass `--allow-exhaustive` and increase `--max-scenarios`:
    ```bash
    connscope matrix run --mode exhaustive --allow-exhaustive --max-scenarios 500
    ```

---

### 3. `AdapterReadinessTimeout: inbound proxy failed to open port within 2.0s`

- **Symptom**: The scenario fails at failure stage `port_readiness`.
- **Root Cause**: The engine client process started, but encountered a fatal configuration error or permission issue and exited before binding its SOCKS5 inbound port.
- **Diagnostic Command**:
  Run binary validation directly to capture the engine's internal error logs:
  ```bash
  connscope catalog parameter-coverage --engine xray --profile vless_tcp_none --validate-binary
  ```
- **Remedy**:
  - Inspect the captured stderr warnings in the measurement record JSON.
  - Verify that the local host allows loopback socket binding (`127.0.0.1`).

---

### 4. `RemoteAuthenticationError: 401 Unauthorized`

- **Symptom**: `connscope run <probe> <target> --node <url>` fails with exit code 3 (`USAGE_ERROR`).
- **Root Cause**: The remote agent requires a valid Bearer token, but either no token was supplied or the token does not match the agent configuration.
- **Diagnostic Command**:
  Test agent reachability:
  ```bash
  curl -i http://<agent-host>:8080/health
  ```
- **Remedy**:
  - Export the valid Bearer token in your environment:
    ```bash
    export CONNSCOPE_AGENT_TOKEN="your-secret-token"
    ```
  - Verify the agent's server token configuration.

---

### 5. `ConfigurationSyntaxError: engine binary rejected generated config`

- **Symptom**: Scenario fails at `config_synthesis` or during `--validate-binary`.
- **Root Cause**: An engine version mismatch. For example, using an older Xray version that does not support the configured `flow` or REALITY options.
- **Diagnostic Command**:
  ```bash
  xray version
  sing-box version
  ```
- **Remedy**:
  - Update Xray to v26.3.27+ or sing-box to v1.12.12+.
  - Refer to [Feature Support Matrix](feature-matrix.md) to check version compatibility for your profile.

---

## 3. Investigating Measurement Failures

When a scenario reports `FAILED`, inspect the structured JSON record:

```bash
connscope matrix run \
  --engine xray \
  --profile vless_tcp_reality \
  --target 127.0.0.1:443 \
  --json
```

Focus on these keys:
- `failure_stage`: Identifies which phase of the lifecycle failed (`pre_flight`, `config_synthesis`, `process_launch`, `port_readiness`, `workload_probing`, `process_teardown`).
- `error_message`: Full diagnostic string captured from the exception or engine stderr.
