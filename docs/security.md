# Security, Isolation & Redaction Architecture

This document describes the security model, credential protection, subprocess isolation, and network safety invariants implemented in ConnScope v0.1.0.

---

## 1. Threat Model & Boundaries

ConnScope executes network measurement probes and supervises third-party proxy engine binaries. Its security architecture addresses the following risks:
- Accidental credential exposure in command lines, system process tables (`ps`), or exported measurement records.
- Unbounded subprocess execution, process leaks, or denial of service caused by hung engine processes.
- Port collisions and unauthorized disruption of active production proxy daemons running on the host.
- Command or configuration injection via untrusted parameter inputs.
- Unintentional modification of host routing tables or default gateway interfaces.

---

## 2. Credential Redaction & Privacy

ConnScope treats client identifiers, private keys, passwords, and tokens as sensitive secrets:

### Automatic Record Redaction
Whenever scenario configurations or parameter variations are serialized to disk (`.jsonl`, `summary.json`) or displayed in terminal output:
- Fields designated as sensitive (`uuid`, `password`, `private_key`, `secret_key`, `psk`, `short_id`, `public_key`) are masked with `[REDACTED]`.
- Example:
  ```json
  "parameters": {
    "uuid": "[REDACTED]",
    "flow": "xtls-rprx-vision"
  }
  ```

### CLI Secret Hygiene
Passing Bearer tokens on the CLI via `--token` exposes the token in `/proc` and `ps` process trees to other unprivileged users on the host. ConnScope strongly recommends using the environment variable:
```bash
export CONNSCOPE_AGENT_TOKEN="my-secret-token"
```
The CLI automatically loads this environment variable, keeping tokens out of process arguments.

---

## 3. Subprocess Isolation & Lifecycle Supervision

Engine adapters (`XrayAdapter`, `SingBoxAdapter`) spawn engine binaries as isolated child processes under strict supervisor controls:
- **Pipes Redirection**: `stdout` and `stderr` are captured asynchronously via separate OS pipes, preventing engine noise from corrupting standard output streams.
- **Graceful Termination**: The supervisor sends `SIGTERM` upon test completion. If the child process does not exit within the grace timeout (default: 2.0s), the supervisor escalates to `SIGKILL`.
- **Process Group Cleanup**: Subprocesses are spawned in separate process groups (`os.setsid`) to ensure any spawned child daemons are cleaned up comprehensively.

---

## 4. Port Invariants & Non-Interference

A core guarantee of ConnScope is **zero disruption to host network infrastructure**:
- **Dynamic Port Allocation**: Inbound SOCKS5 listeners and diagnostic mock servers always bind to port `0`. The Linux kernel dynamically assigns an unused ephemeral port.
- **Fixed Port Protection**: ConnScope never attempts to bind or probe hardcoded system ports. Specifically, host proxy instances running on `127.0.0.1:10808` are completely isolated and untouched.

---

## 5. Input Validation & Configuration Injection Prevention

Engine configuration builders (`connscope.adapters.builders`) reject dangerous input keys:
- Any configuration dictionary key containing execution directives—including `"exec"`, `"command"`, `"shell"`, or `"spawn"`—causes immediate validation termination.
- All parameter inputs are checked against typed schemas with strict character whitelist constraints.

---

## 6. Layer 3 Interface & Privilege Boundaries

- **Unprivileged by Design**: ConnScope is architected to run as an unprivileged, non-root user.
- **No TUN Hijacking**: Live creation of kernel TUN/TAP interfaces for WireGuard, AmneziaWG, and OpenVPN is explicitly disabled by default. ConnScope refuses to overwrite host DNS settings (`/etc/resolv.conf`) or modify kernel routing tables (`ip route`).
- **Mock Verification**: Layer 3 protocols are tested using hermetic mock unit harnesses rather than invasive host modifications.
