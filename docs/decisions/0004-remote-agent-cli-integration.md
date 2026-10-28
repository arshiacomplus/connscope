# 0004. Remote Agent CLI Integration

## Context

Phase 5 introduced the ConnScope Remote Agent architecture, including the HTTP Server (`AgentServer`), security policies, execution engine, and synchronous remote measurement client (`RemoteAgentClient`).

Users and automated systems require the ability to run diagnostic measurements either locally from the machine hosting ConnScope or remotely via a distributed Agent node. The CLI must provide a unified entry point while maintaining backward compatibility, zero runtime dependencies, robust error handling, and strict credential security.

## Decision

We establish the following CLI remote integration architecture:

1. **Measurement Command Options**:
   The existing `connscope run <probe> <target>` measurement command is extended with optional parameters:
   - `--node URL`: Remote Agent base URL (overrides `CONNSCOPE_AGENT_URL`).
   - `--token TOKEN`: Remote Agent Bearer token (overrides `CONNSCOPE_AGENT_TOKEN`).

2. **Configuration Precedence & Validation**:
   - Explicit CLI options take precedence over environment variables.
   - If neither a CLI option nor an environment variable supplies a node URL, local measurement behavior is preserved.
   - If a node URL is provided without a token, execution fails with a configuration error before any connection attempt.
   - If a token is provided without a node URL, execution fails with a configuration error to prevent silent credential misconfiguration.
   - Remote execution never falls back to local execution upon failure.

3. **Presentation & Serialization Reuse**:
   - Target parsing (`parse_target`, `parse_http_target`), timeout validation, and domain constraints are fully shared across local and remote paths.
   - Remote measurement delegates directly to `RemoteAgentClient.measure(canonical, target, config)`.
   - Output presentation (`render_result`, `render_result_json`) and exit codes (`0` for success, `1` for failed, `2` for timeout) are completely reused.

4. **Exit Code Conventions & Error Mapping**:
   - Completed remote probes returning `FAILED` exit with `1` and print the probe result to stdout.
   - Completed remote probes returning `TIMEOUT` exit with `2` and print the probe result to stdout.
   - Configuration / usage errors (e.g. invalid URL, missing token, `ClientConfigurationError`) exit with `3` (`USAGE_ERROR`) and print an error message to stderr.
   - Remote client timeouts (`RemoteTimeoutError`) exit with `2` (`TIMEOUT`) and print an error message to stderr.
   - Remote transport and HTTP errors (`RemoteConnectionError`, `RemoteAuthenticationError`, `RemotePolicyError`, `RemoteUnavailableError`, `RemoteProtocolError`, `RemoteHttpError`) exit with `1` (`FAILED`) and print a concise error message to stderr.

5. **Security & Credential Protection**:
   - Authentication tokens are never printed to stdout or stderr.
   - Error messages are sanitized to ensure Bearer tokens are never reflected in diagnostic output.
   - Environment variables are recommended over command-line arguments to prevent token exposure in process listings (`ps aux`, `/proc`).
   - HTTPS certificate and hostname verification are strictly enforced for remote Agent connections.

## Consequences

- Backward compatibility with Phase 3 CLI commands and Phase 4 structured JSON results is completely maintained.
- Both human operators and automated monitoring agents can seamlessly direct network probes to edge nodes.
- Zero external runtime dependencies are introduced.
